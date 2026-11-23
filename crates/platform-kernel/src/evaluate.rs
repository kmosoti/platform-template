use crate::checkpoint_verify::verify_checkpoint;
use crate::continuity::{
    check_engine_config_compat, check_generation_and_continuity, classify_action, validate_catalog,
};
use crate::digest::{is_valid_sha256_digest, try_jcs_digest};
use crate::ledger_verify::{check_attestations, verify_ledger};
use crate::model::{
    AttestationLedger, CatalogEngine, DomainConfig, DomainEvaluation, DomainTier, EngineCatalog,
    EvalMode, ExpectedOidcPolicy, OBSERVATION_SCHEMA, Observation, OidcClaims, PlanAction,
    ProvenanceStatus, TARGET_SCHEMA, TargetManifest, TrustRoot, TrustedCheckpoint,
};
use crate::oidc::validate_oidc_claims;
use crate::scope::validate_domain_config;
use crate::violations::Violation;

pub struct DomainInputs<'a> {
    pub tier: DomainTier,
    pub mode: EvalMode,
    pub now_epoch_s: u64,
    pub target: &'a TargetManifest,
    pub config: &'a DomainConfig,
    pub observed: &'a Observation,
    pub catalog: &'a EngineCatalog,
    pub ledger: &'a AttestationLedger,
    pub trust_root: &'a TrustRoot,
    pub checkpoint: Option<&'a TrustedCheckpoint>,
    pub oidc_policy: Option<&'a ExpectedOidcPolicy>,
    pub oidc_claims: Option<&'a OidcClaims>,
}

pub fn evaluate_domain(inputs: &DomainInputs<'_>) -> DomainEvaluation {
    let mut violations = validate_catalog(inputs.catalog);
    violations.extend(verify_ledger(inputs.ledger, inputs.trust_root, inputs.mode));

    let active_len = verify_checkpoint_and_prefix(inputs, &mut violations);
    let computed_engine_cfg = try_jcs_digest(&inputs.config.engine_config).unwrap_or_default();
    let computed_domain_cfg = try_jcs_digest(inputs.config).unwrap_or_default();

    check_identities_and_mode(inputs, &mut violations);
    check_digests(
        inputs,
        &computed_engine_cfg,
        &computed_domain_cfg,
        &mut violations,
    );
    validate_domain_config(inputs.tier, inputs.config, &mut violations);
    check_oidc_if_required(inputs, &mut violations);

    let live_eng = lookup_engine(
        inputs.catalog,
        "observed.engine_digest",
        &inputs.observed.engine_digest,
        &mut violations,
    );
    let target_eng = lookup_engine(
        inputs.catalog,
        "target.engine_digest",
        &inputs.target.engine_digest,
        &mut violations,
    );

    if let (Some(live), Some(target)) = (live_eng, target_eng) {
        if inputs.mode == EvalMode::Live {
            if live.fixture_only || target.fixture_only {
                violations.push(Violation::FixtureInputInLiveMode {
                    source: "catalog/engines.json (fixture_only=true)".to_string(),
                });
            }
            for eng in [live, target] {
                if eng.provenance_status != ProvenanceStatus::Verified {
                    violations.push(Violation::UnverifiedProvenanceInLiveMode {
                        engine_digest: eng.engine_digest.clone(),
                    });
                }
            }
        }
        check_engine_config_compat(inputs.config, target, &mut violations);
        check_generation_and_continuity(
            inputs.config,
            inputs.observed,
            inputs.target,
            live,
            target,
            &mut violations,
        );
    }

    let prefix = &inputs.ledger.records[..active_len.min(inputs.ledger.records.len())];
    let matched_attestations = check_attestations(
        inputs.tier,
        inputs.now_epoch_s,
        inputs.target,
        prefix,
        &mut violations,
    );

    let action = if !violations.is_empty() {
        PlanAction::Refused
    } else {
        classify_action(
            inputs.observed,
            inputs.target,
            target_eng.expect("verified target engine"),
        )
    };

    DomainEvaluation {
        domain: inputs.tier,
        mode: inputs.mode,
        action,
        generation: inputs.target.generation,
        observed_generation: inputs.observed.generation,
        live_engine_digest: inputs.observed.engine_digest.clone(),
        target_engine_digest: inputs.target.engine_digest.clone(),
        computed_engine_config_digest: computed_engine_cfg,
        computed_domain_config_digest: computed_domain_cfg,
        min_active_reader_format: inputs.observed.min_active_reader_format,
        min_shard_state_format: inputs.observed.min_shard_state_format,
        max_shard_state_format: inputs.observed.max_shard_state_format,
        target_state_format: target_eng.map(|e| e.state_format_version),
        target_transition_mode: target_eng.map(|e| e.transition_mode),
        matched_attestations,
        violations,
    }
}

fn verify_checkpoint_and_prefix(
    inputs: &DomainInputs<'_>,
    violations: &mut Vec<Violation>,
) -> usize {
    match (inputs.mode, inputs.checkpoint) {
        (EvalMode::Live, None) => {
            violations.push(Violation::MissingOrInvalidCheckpoint {
                reason: "live mode requires a signed TrustedCheckpoint".to_string(),
            });
            0
        }
        (_, Some(cp)) => {
            let errs = verify_checkpoint(
                cp,
                inputs.ledger,
                inputs.trust_root,
                inputs.mode,
                inputs.now_epoch_s,
            );
            if errs.is_empty() {
                cp.ledger_len
            } else {
                violations.extend(errs);
                0
            }
        }
        (EvalMode::Simulate, None) => inputs.ledger.records.len(),
    }
}

fn check_identities_and_mode(inputs: &DomainInputs<'_>, violations: &mut Vec<Violation>) {
    if inputs.target.schema != TARGET_SCHEMA {
        violations.push(Violation::InvalidDomainConfig {
            field: "target.schema".to_string(),
            reason: format!("expected `{TARGET_SCHEMA}`"),
        });
    }
    if inputs.observed.schema != OBSERVATION_SCHEMA {
        violations.push(Violation::InvalidDomainConfig {
            field: "observed.schema".to_string(),
            reason: format!("expected `{OBSERVATION_SCHEMA}`"),
        });
    }
    if inputs.target.domain != inputs.tier {
        violations.push(Violation::DomainIdentityMismatch {
            expected: inputs.tier,
            found: inputs.target.domain,
            source: "target.json".to_string(),
        });
    }
    if inputs.observed.domain != inputs.tier {
        violations.push(Violation::DomainIdentityMismatch {
            expected: inputs.tier,
            found: inputs.observed.domain,
            source: "observation.json".to_string(),
        });
    }
    if inputs.mode == EvalMode::Live && inputs.observed.fixture_mode {
        violations.push(Violation::FixtureInputInLiveMode {
            source: format!("observations/{}.json", inputs.tier.as_str()),
        });
    }
}

fn check_digests(
    inputs: &DomainInputs<'_>,
    computed_engine_cfg: &str,
    computed_domain_cfg: &str,
    violations: &mut Vec<Violation>,
) {
    for (field, val) in [
        ("target.engine_digest", &inputs.target.engine_digest),
        (
            "target.engine_config_digest",
            &inputs.target.engine_config_digest,
        ),
        (
            "target.domain_config_digest",
            &inputs.target.domain_config_digest,
        ),
        ("observed.engine_digest", &inputs.observed.engine_digest),
        (
            "observed.engine_config_digest",
            &inputs.observed.engine_config_digest,
        ),
        (
            "observed.domain_config_digest",
            &inputs.observed.domain_config_digest,
        ),
    ] {
        if !is_valid_sha256_digest(val) {
            violations.push(Violation::UnpinnedDigest {
                field: field.to_string(),
                value: val.clone(),
            });
        }
    }
    if inputs.target.engine_config_digest != computed_engine_cfg {
        violations.push(Violation::EngineConfigDigestMismatch {
            expected: computed_engine_cfg.to_string(),
            actual: inputs.target.engine_config_digest.clone(),
        });
    }
    if inputs.target.domain_config_digest != computed_domain_cfg {
        violations.push(Violation::DomainConfigDigestMismatch {
            expected: computed_domain_cfg.to_string(),
            actual: inputs.target.domain_config_digest.clone(),
        });
    }
}

fn check_oidc_if_required(inputs: &DomainInputs<'_>, violations: &mut Vec<Violation>) {
    match (inputs.mode, inputs.oidc_policy, inputs.oidc_claims) {
        (EvalMode::Live, Some(pol), Some(claims))
        | (EvalMode::Simulate, Some(pol), Some(claims)) => {
            if pol.expected_environment != inputs.tier {
                violations.push(Violation::OidcClaimViolation {
                    domain: inputs.tier,
                    reason: "ExpectedOidcPolicy environment does not match evaluated domain"
                        .to_string(),
                });
            } else if let Err(v) = validate_oidc_claims(pol, inputs.now_epoch_s, claims) {
                violations.push(v);
            }
        }
        (EvalMode::Live, _, _) => violations.push(Violation::OidcClaimViolation {
            domain: inputs.tier,
            reason: "live mode requires both ExpectedOidcPolicy and verified OidcClaims"
                .to_string(),
        }),
        (EvalMode::Simulate, None, None) => {}
        (EvalMode::Simulate, _, _) => violations.push(Violation::OidcClaimViolation {
            domain: inputs.tier,
            reason: "oidc_policy and oidc_claims must be provided together".to_string(),
        }),
    }
}

fn lookup_engine<'a>(
    catalog: &'a EngineCatalog,
    field: &str,
    digest: &str,
    violations: &mut Vec<Violation>,
) -> Option<&'a CatalogEngine> {
    if !is_valid_sha256_digest(digest) {
        return None;
    }
    let found = catalog.find_by_digest(digest);
    if found.is_none() {
        violations.push(Violation::UnknownEngineDigest {
            field: field.to_string(),
            engine_digest: digest.to_string(),
        });
    }
    found
}
