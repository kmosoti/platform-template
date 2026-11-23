use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use platform_kernel::{
    AttestationLedger, DomainConfig, DomainEvaluation, DomainInputs, DomainTier, EngineCatalog,
    EvalMode, ExpectedOidcPolicy, GITHUB_OIDC_ISSUER, Observation, OidcClaims, PlanAction,
    TargetManifest, TrustRoot, TrustedCheckpoint, evaluate_domain, validate_catalog, verify_ledger,
};
use serde::{Deserialize, Serialize};

use crate::atomic_io::write_pretty_json_atomic;

#[derive(Debug, Default, Clone)]
pub struct SimOptions {
    pub mode: EvalMode,
    pub observations_dir: Option<PathBuf>,
    pub trust_root: Option<PathBuf>,
    pub ledger_file: Option<PathBuf>,
    pub checkpoint_file: Option<PathBuf>,
    pub oidc_claims_file: Option<PathBuf>,
    pub oidc_audience: Option<String>,
    pub oidc_repo: Option<String>,
    pub oidc_repo_id: Option<String>,
    pub now_epoch_s: Option<u64>,
    pub out_path: Option<PathBuf>,
}

pub struct DomainFiles {
    pub target: TargetManifest,
    pub config: DomainConfig,
    pub observed: Observation,
}

pub struct WorkspaceBundle {
    pub catalog: EngineCatalog,
    pub trust_root: TrustRoot,
    pub ledger: AttestationLedger,
    pub checkpoint: Option<TrustedCheckpoint>,
    pub oidc_claims: Option<OidcClaims>,
    pub now_epoch_s: u64,
    pub domains: BTreeMap<DomainTier, DomainFiles>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcilePlanReceipt {
    pub schema: String,
    pub artifact_kind: String,
    pub live_convergence_proven: bool,
    pub mode: EvalMode,
    pub all_valid: bool,
    pub domains: Vec<DomainEvaluation>,
}

pub fn parse_domain_tier(s: &str) -> Result<DomainTier, String> {
    match s {
        "dev" => Ok(DomainTier::Dev),
        "staging" => Ok(DomainTier::Staging),
        "prod" => Ok(DomainTier::Prod),
        other => Err(format!(
            "invalid domain `{other}` (expected `dev`, `staging`, or `prod`)"
        )),
    }
}

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read `{}`: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid JSON in `{}`: {e}", path.display()))
}

pub fn load_bundle(
    root: &Path,
    selected: &[DomainTier],
    opts: &SimOptions,
) -> Result<WorkspaceBundle, String> {
    if opts.mode == EvalMode::Live
        && (opts.observations_dir.is_none()
            || opts.trust_root.is_none()
            || opts.ledger_file.is_none()
            || opts.checkpoint_file.is_none()
            || opts.oidc_claims_file.is_none()
            || opts.oidc_audience.is_none()
            || opts.oidc_repo.is_none())
    {
        return Err(
            "`--mode live` requires `--observations-dir`, `--trust-root`, `--ledger-file`, `--trusted-checkpoint`, `--oidc-claims-file`, `--oidc-audience`, and `--oidc-repo`"
                .to_string(),
        );
    }

    let catalog: EngineCatalog = read_json(&root.join("catalog/engines.json"))?;
    let trust_path = opts
        .trust_root
        .clone()
        .unwrap_or_else(|| root.join("trust/verifiers.json"));
    let trust_root: TrustRoot = read_json(&trust_path)?;
    let ledger_path = opts
        .ledger_file
        .clone()
        .unwrap_or_else(|| root.join("attestations/ledger.json"));
    let ledger: AttestationLedger = read_json(&ledger_path)?;

    let cp_path = opts.checkpoint_file.clone().or_else(|| {
        let demo_cp = root.join("attestations/checkpoint.json");
        demo_cp.is_file().then_some(demo_cp)
    });
    let checkpoint = match cp_path {
        Some(p) => Some(read_json::<TrustedCheckpoint>(&p)?),
        None => None,
    };
    let oidc_claims = match &opts.oidc_claims_file {
        Some(p) => Some(read_json::<OidcClaims>(p)?),
        None => None,
    };

    let now_epoch_s = match (opts.mode, opts.now_epoch_s) {
        (_, Some(ts)) => ts,
        (EvalMode::Live, None) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("system clock error: {e}"))?
            .as_secs(),
        (EvalMode::Simulate, None) => ledger.demo_eval_epoch_s.unwrap_or(1_795_000_000),
    };

    let obs_dir = opts
        .observations_dir
        .clone()
        .unwrap_or_else(|| root.join("observations"));
    let mut domains = BTreeMap::new();
    for &tier in selected {
        let dir = root.join("domains").join(tier.as_str());
        let target: TargetManifest = read_json(&dir.join("target.json"))?;
        let config: DomainConfig = read_json(&dir.join("config.json"))?;
        let observed: Observation = read_json(&obs_dir.join(format!("{}.json", tier.as_str())))?;
        domains.insert(
            tier,
            DomainFiles {
                target,
                config,
                observed,
            },
        );
    }

    Ok(WorkspaceBundle {
        catalog,
        trust_root,
        ledger,
        checkpoint,
        oidc_claims,
        now_epoch_s,
        domains,
    })
}

pub fn evaluate_selected_domains(
    root: &Path,
    selected: &[DomainTier],
    opts: &SimOptions,
) -> Result<ReconcilePlanReceipt, String> {
    let bundle = load_bundle(root, selected, opts)?;
    let cat_errs = validate_catalog(&bundle.catalog);
    if !cat_errs.is_empty() {
        return Err(format!("engine catalog validation failed: {cat_errs:?}"));
    }
    let ledger_errs = verify_ledger(&bundle.ledger, &bundle.trust_root, opts.mode);
    if !ledger_errs.is_empty() {
        return Err(format!(
            "attestation ledger verification failed: {ledger_errs:?}"
        ));
    }

    let mut evaluations = Vec::with_capacity(selected.len());
    for &tier in selected {
        let files = &bundle.domains[&tier];
        let oidc_policy = match (&opts.oidc_audience, &opts.oidc_repo) {
            (Some(aud), Some(repo)) => Some(ExpectedOidcPolicy {
                expected_issuer: GITHUB_OIDC_ISSUER.to_string(),
                expected_audience: aud.clone(),
                expected_repository: repo.clone(),
                expected_repository_id: opts.oidc_repo_id.clone(),
                expected_ref: "refs/heads/main".to_string(),
                expected_environment: tier,
            }),
            _ => None,
        };
        let eval = evaluate_domain(&DomainInputs {
            tier,
            mode: opts.mode,
            now_epoch_s: bundle.now_epoch_s,
            target: &files.target,
            config: &files.config,
            observed: &files.observed,
            catalog: &bundle.catalog,
            ledger: &bundle.ledger,
            trust_root: &bundle.trust_root,
            checkpoint: bundle.checkpoint.as_ref(),
            oidc_policy: oidc_policy.as_ref(),
            oidc_claims: bundle.oidc_claims.as_ref(),
        });
        evaluations.push(eval);
    }

    let all_valid = evaluations.iter().all(DomainEvaluation::is_valid);
    Ok(ReconcilePlanReceipt {
        schema: "platform.simulation-prediction/v1".to_string(),
        artifact_kind: if opts.mode == EvalMode::Live {
            "live_reconcile_evaluation".to_string()
        } else {
            "simulation_prediction".to_string()
        },
        live_convergence_proven: false,
        mode: opts.mode,
        all_valid,
        domains: evaluations,
    })
}

pub fn cmd_simulate(root: &Path, domain_arg: &str, opts: &SimOptions) -> Result<(), String> {
    let selected: Vec<DomainTier> = if domain_arg == "all" {
        if opts.mode == EvalMode::Live {
            return Err("`--mode live` must target a single `--domain <dev|staging|prod>`".into());
        }
        DomainTier::ALL.to_vec()
    } else {
        vec![parse_domain_tier(domain_arg)?]
    };

    let receipt = evaluate_selected_domains(root, &selected, opts)?;
    if let Some(out) = &opts.out_path {
        write_pretty_json_atomic(out, &receipt)?;
    }

    let mut any_refused = false;
    for eval in &receipt.domains {
        let tgt_fmt = eval
            .target_state_format
            .map_or("?".into(), |n| n.to_string());
        println!(
            "[simulate:{:?}] domain={:<7} action={:<12?} gen={}->{} reader_min={} shards={}..={}->{} target={} attestations={}",
            eval.mode,
            eval.domain.as_str(),
            eval.action,
            eval.observed_generation,
            eval.generation,
            eval.min_active_reader_format,
            eval.min_shard_state_format,
            eval.max_shard_state_format,
            tgt_fmt,
            &eval.target_engine_digest[..19.min(eval.target_engine_digest.len())],
            eval.matched_attestations.join(",")
        );
        if !eval.is_valid() || eval.action == PlanAction::Refused {
            any_refused = true;
            for v in &eval.violations {
                eprintln!("  violation: {v:?}");
            }
        }
    }
    if any_refused {
        return Err("one or more domains refused reconciliation".to_string());
    }
    Ok(())
}
