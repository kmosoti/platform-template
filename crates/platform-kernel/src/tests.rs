use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    AttestationLedger, AttestationRecord, DomainConfig, DomainInputs, DomainTier, EngineCatalog,
    EvalMode, MAX_JCS_SAFE_UINT, Observation, PlanAction, Predicate, ProvenanceStatus,
    TargetManifest, TransitionMode, TrustRoot, TrustedCheckpoint, Violation,
    compute_domain_config_digest, compute_engine_config_digest, evaluate_domain, sha256_prefixed,
    sign_attestation_record, sign_checkpoint, try_canonical_json_string, validate_catalog,
    verify_checkpoint, verify_ledger,
};

pub(crate) struct RepoFixtures {
    pub catalog: EngineCatalog,
    pub trust_root: TrustRoot,
    pub ledger: AttestationLedger,
    pub checkpoint: TrustedCheckpoint,
    pub now_s: u64,
    pub dev: (TargetManifest, DomainConfig, Observation),
    pub staging: (TargetManifest, DomainConfig, Observation),
    pub prod: (TargetManifest, DomainConfig, Observation),
}

pub(crate) fn load_fixtures() -> RepoFixtures {
    let ledger: AttestationLedger =
        serde_json::from_str(include_str!("../../../attestations/ledger.json")).unwrap();
    let now_s = ledger.demo_eval_epoch_s.unwrap_or(1_795_000_000);
    RepoFixtures {
        catalog: serde_json::from_str(include_str!("../../../catalog/engines.json")).unwrap(),
        trust_root: serde_json::from_str(include_str!("../../../trust/verifiers.json")).unwrap(),
        checkpoint: serde_json::from_str(include_str!("../../../attestations/checkpoint.json"))
            .unwrap(),
        ledger,
        now_s,
        dev: (
            serde_json::from_str(include_str!("../../../domains/dev/target.json")).unwrap(),
            serde_json::from_str(include_str!("../../../domains/dev/config.json")).unwrap(),
            serde_json::from_str(include_str!("../../../observations/dev.json")).unwrap(),
        ),
        staging: (
            serde_json::from_str(include_str!("../../../domains/staging/target.json")).unwrap(),
            serde_json::from_str(include_str!("../../../domains/staging/config.json")).unwrap(),
            serde_json::from_str(include_str!("../../../observations/staging.json")).unwrap(),
        ),
        prod: (
            serde_json::from_str(include_str!("../../../domains/prod/target.json")).unwrap(),
            serde_json::from_str(include_str!("../../../domains/prod/config.json")).unwrap(),
            serde_json::from_str(include_str!("../../../observations/prod.json")).unwrap(),
        ),
    }
}

pub(crate) fn fixture_signing_seed(key_id: &str) -> [u8; 32] {
    let digest = Sha256::digest(format!("platform-template-fixture-demo-v1:{key_id}").as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) struct SignedRecordSpec<'a> {
    pub id: &'a str,
    pub predicate: Predicate,
    pub domain: Option<DomainTier>,
    pub target_generation: Option<u64>,
    pub engine_digest: &'a str,
    pub engine_config_digest: Option<&'a str>,
    pub domain_config_digest: Option<&'a str>,
    pub expires_at_epoch_s: Option<u64>,
    pub key_id: &'a str,
}

pub(crate) fn append_signed_record(
    ledger: &mut AttestationLedger,
    cp: &mut TrustedCheckpoint,
    now_s: u64,
    spec: SignedRecordSpec<'_>,
) {
    let prev = ledger
        .records
        .last()
        .map(|r| r.record_hash.clone())
        .unwrap();
    let mut rec = AttestationRecord {
        attestation_id: spec.id.to_string(),
        predicate: spec.predicate,
        domain: spec.domain,
        target_generation: spec.target_generation,
        engine_digest: spec.engine_digest.to_string(),
        engine_config_digest: spec.engine_config_digest.map(ToString::to_string),
        domain_config_digest: spec.domain_config_digest.map(ToString::to_string),
        evidence_digest: sha256_prefixed(spec.id.as_bytes()),
        issued_at_epoch_s: now_s - 100,
        expires_at_epoch_s: spec.expires_at_epoch_s,
        key_id: spec.key_id.to_string(),
        prev_hash: prev,
        record_hash: String::new(),
        signature: String::new(),
    };
    sign_attestation_record(&mut rec, &fixture_signing_seed(spec.key_id));
    cp.ledger_len = ledger.records.len() + 1;
    cp.head_record_hash = rec.record_hash.clone();
    sign_checkpoint(cp, &fixture_signing_seed(&cp.key_id));
    ledger.records.push(rec);
}

#[test]
fn rfc8785_jcs_sorts_utf16_code_units_and_enforces_53bit_integer_bounds() {
    // U+10000 encodes in UTF-16 as [0xD800, 0xDC00] < U+E000 [0xE000], opposite of UTF-8!
    let val = json!({ "\u{E000}": 2, "\u{10000}": 1 });
    let jcs = try_canonical_json_string(&val).unwrap();
    assert_eq!(
        jcs,
        "{\"\\u{10000}\":1,\"\\u{e000}\":2}"
            .replace("\\u{10000}", "\u{10000}")
            .replace("\\u{e000}", "\u{E000}")
    );

    let too_big = json!({ "n": MAX_JCS_SAFE_UINT + 1 });
    assert!(try_canonical_json_string(&too_big).is_err());
}

#[test]
fn committed_dev_staging_and_prod_domains_pass_invariants() {
    let fx = load_fixtures();
    assert!(validate_catalog(&fx.catalog).is_empty());
    assert!(verify_ledger(&fx.ledger, &fx.trust_root, EvalMode::Simulate).is_empty());
    assert!(
        verify_checkpoint(
            &fx.checkpoint,
            &fx.ledger,
            &fx.trust_root,
            EvalMode::Simulate,
            fx.now_s
        )
        .is_empty()
    );

    for (tier, (target, config, observed), expected_action) in [
        (DomainTier::Dev, &fx.dev, PlanAction::AdvanceTuple),
        (DomainTier::Staging, &fx.staging, PlanAction::NoOp),
        (DomainTier::Prod, &fx.prod, PlanAction::NoOp),
    ] {
        let eval = evaluate_domain(&DomainInputs {
            tier,
            mode: EvalMode::Simulate,
            now_epoch_s: fx.now_s,
            target,
            config,
            observed,
            catalog: &fx.catalog,
            ledger: &fx.ledger,
            trust_root: &fx.trust_root,
            checkpoint: Some(&fx.checkpoint),
            oidc_policy: None,
            oidc_claims: None,
        });
        assert!(
            eval.is_valid(),
            "{tier:?} violations: {:?}",
            eval.violations
        );
        assert_eq!(eval.action, expected_action);
    }
}

#[test]
fn rolling_reader_ceiling_and_budget_burst_or_cut_constraints_enforced() {
    let mut fx = load_fixtures();
    // H11: Active v1 reader in fleet blocks state_write_version = 2
    fx.staging.2.min_active_reader_format = 1;
    // H13: burst (101) > max_units_per_window (100) AND observed consumed (150) > budget (100)
    fx.staging.1.engine_config.max_burst_units = 101;
    fx.staging.2.max_observed_consumed_units = 150;
    fx.staging.0.engine_config_digest = compute_engine_config_digest(&fx.staging.1.engine_config);
    fx.staging.0.domain_config_digest = compute_domain_config_digest(&fx.staging.1);

    let eval = evaluate_domain(&DomainInputs {
        tier: DomainTier::Staging,
        mode: EvalMode::Simulate,
        now_epoch_s: fx.now_s,
        target: &fx.staging.0,
        config: &fx.staging.1,
        observed: &fx.staging.2,
        catalog: &fx.catalog,
        ledger: &fx.ledger,
        trust_root: &fx.trust_root,
        checkpoint: Some(&fx.checkpoint),
        oidc_policy: None,
        oidc_claims: None,
    });
    assert_eq!(eval.action, PlanAction::Refused);
    assert!(
        eval.violations
            .iter()
            .any(|v| matches!(v, Violation::ReaderFormatCeilingExceeded { .. }))
    );
    assert!(eval.violations.iter().any(
        |v| matches!(v, Violation::InvalidDomainConfig { field, .. } if field == "engine_config")
    ));
    assert!(
        eval.violations
            .iter()
            .any(|v| matches!(v, Violation::UnrestorableBudgetCut { .. }))
    );
}

#[test]
fn cas_generation_shard_continuity_and_steady_v2_successor() {
    let mut fx = load_fixtures();
    fx.dev.0.expected_observed_generation = 99;
    fx.dev.0.generation = fx.dev.2.generation;
    fx.dev.2.migrated_shards = 1;
    let eval_bad = evaluate_domain(&DomainInputs {
        tier: DomainTier::Dev,
        mode: EvalMode::Simulate,
        now_epoch_s: fx.now_s,
        target: &fx.dev.0,
        config: &fx.dev.1,
        observed: &fx.dev.2,
        catalog: &fx.catalog,
        ledger: &fx.ledger,
        trust_root: &fx.trust_root,
        checkpoint: Some(&fx.checkpoint),
        oidc_policy: None,
        oidc_claims: None,
    });
    assert!(
        eval_bad
            .violations
            .iter()
            .any(|v| matches!(v, Violation::CasGenerationMismatch { .. }))
    );
    assert!(
        eval_bad
            .violations
            .iter()
            .any(|v| matches!(v, Violation::NonMonotonicGeneration { .. }))
    );
    assert!(
        eval_bad
            .violations
            .iter()
            .any(|v| matches!(v, Violation::IncompleteShardMigration { .. }))
    );

    // Steady v2 -> v2 successor after forward_only/contract v2 release is allowed
    let mut fx2 = load_fixtures();
    let v3_digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
    fx2.catalog.engines[2].transition_mode = TransitionMode::ForwardOnly;
    let mut v3 = fx2.catalog.engines[2].clone();
    v3.engine_digest = v3_digest.to_string();
    v3.version = "0.3.0".to_string();
    v3.transition_mode = TransitionMode::Reversible;
    v3.provenance_status = ProvenanceStatus::UnverifiedLocal;
    fx2.catalog.engines.push(v3);

    fx2.dev.2.engine_digest = fx2.dev.0.engine_digest.clone();
    fx2.dev.2.generation = 3;
    fx2.dev.0.expected_observed_generation = 3;
    fx2.dev.0.generation = 4;
    fx2.dev.0.engine_digest = v3_digest.to_string();
    append_signed_record(
        &mut fx2.ledger,
        &mut fx2.checkpoint,
        fx2.now_s,
        SignedRecordSpec {
            id: "att-v030-sim",
            predicate: Predicate::SimPassed,
            domain: None,
            target_generation: None,
            engine_digest: v3_digest,
            engine_config_digest: Some(&fx2.dev.0.engine_config_digest),
            domain_config_digest: None,
            expires_at_epoch_s: Some(fx2.now_s + 3600),
            key_id: "ci-sim-bot",
        },
    );
    let eval_ok = evaluate_domain(&DomainInputs {
        tier: DomainTier::Dev,
        mode: EvalMode::Simulate,
        now_epoch_s: fx2.now_s,
        target: &fx2.dev.0,
        config: &fx2.dev.1,
        observed: &fx2.dev.2,
        catalog: &fx2.catalog,
        ledger: &fx2.ledger,
        trust_root: &fx2.trust_root,
        checkpoint: Some(&fx2.checkpoint),
        oidc_policy: None,
        oidc_claims: None,
    });
    assert!(eval_ok.is_valid(), "{:?}", eval_ok.violations);
}
