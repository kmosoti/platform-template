use crate::tests::{SignedRecordSpec, append_signed_record, load_fixtures};
use crate::{
    DomainInputs, DomainTier, EvalMode, ExpectedOidcPolicy, GITHUB_OIDC_ISSUER, OidcClaims,
    PlanAction, Predicate, Violation, compute_domain_config_digest, evaluate_domain,
    validate_oidc_claims, verify_ledger,
};

#[test]
fn ed25519_forgery_and_unauthorized_key_scope_fail_closed() {
    let mut fx = load_fixtures();
    fx.ledger.records[0].signature = "00".repeat(64);
    assert!(
        verify_ledger(&fx.ledger, &fx.trust_root, EvalMode::Simulate)
            .iter()
            .any(|v| matches!(v, Violation::LedgerIntegrityFailure { .. }))
    );

    let mut fx2 = load_fixtures();
    append_signed_record(
        &mut fx2.ledger,
        &mut fx2.checkpoint,
        fx2.now_s,
        SignedRecordSpec {
            id: "att-forged-policy",
            predicate: Predicate::PolicySigned,
            domain: Some(DomainTier::Prod),
            target_generation: Some(2),
            engine_digest: &fx2.prod.0.engine_digest,
            engine_config_digest: None,
            domain_config_digest: Some(&fx2.prod.0.domain_config_digest),
            expires_at_epoch_s: Some(fx2.now_s + 3600),
            key_id: "dev-reconciler",
        },
    );
    assert!(
        verify_ledger(&fx2.ledger, &fx2.trust_root, EvalMode::Simulate)
            .iter()
            .any(|v| matches!(v, Violation::UnauthorizedAttestationKey { .. }))
    );
}

#[test]
fn stale_checkpoint_expired_positive_predicate_and_permanent_revocation() {
    let fx = load_fixtures();
    // H5(a): Authentic checkpoint rejected once now_epoch_s exceeds checkpoint_epoch_s + max_staleness_s
    let stale_now = fx.checkpoint.checkpoint_epoch_s + fx.checkpoint.max_staleness_s + 1;
    let eval_stale_cp = evaluate_domain(&DomainInputs {
        tier: DomainTier::Dev,
        mode: EvalMode::Simulate,
        now_epoch_s: stale_now,
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
        eval_stale_cp
            .violations
            .iter()
            .any(|v| matches!(v, Violation::StaleLedgerCheckpoint { .. }))
    );

    // H5(b): Expired positive predicate rejected against authoritative now_epoch_s
    let eval_expired = evaluate_domain(&DomainInputs {
        tier: DomainTier::Dev,
        mode: EvalMode::Simulate,
        now_epoch_s: fx.now_s + 99_999_999,
        target: &fx.dev.0,
        config: &fx.dev.1,
        observed: &fx.dev.2,
        catalog: &fx.catalog,
        ledger: &fx.ledger,
        trust_root: &fx.trust_root,
        checkpoint: None,
        oidc_policy: None,
        oidc_claims: None,
    });
    assert!(
        eval_expired
            .violations
            .iter()
            .any(|v| matches!(v, Violation::AttestationExpired { .. }))
    );

    // H5(c): Permanent revocation NEVER expires even far in the future
    let mut fx3 = load_fixtures();
    append_signed_record(
        &mut fx3.ledger,
        &mut fx3.checkpoint,
        fx3.now_s,
        SignedRecordSpec {
            id: "att-revoke-permanent",
            predicate: Predicate::Revoked,
            domain: Some(DomainTier::Prod),
            target_generation: None,
            engine_digest: &fx3.dev.0.engine_digest,
            engine_config_digest: None,
            domain_config_digest: None,
            expires_at_epoch_s: None,
            key_id: "prod-release-approver",
        },
    );
    let far_future = fx3.now_s + 500_000;
    fx3.checkpoint.checkpoint_epoch_s = far_future;
    let cp_seed = crate::tests::fixture_signing_seed(&fx3.checkpoint.key_id);
    crate::sign_checkpoint(&mut fx3.checkpoint, &cp_seed);
    let eval_rev = evaluate_domain(&DomainInputs {
        tier: DomainTier::Dev,
        mode: EvalMode::Simulate,
        now_epoch_s: far_future,
        target: &fx3.dev.0,
        config: &fx3.dev.1,
        observed: &fx3.dev.2,
        catalog: &fx3.catalog,
        ledger: &fx3.ledger,
        trust_root: &fx3.trust_root,
        checkpoint: Some(&fx3.checkpoint),
        oidc_policy: None,
        oidc_claims: None,
    });
    assert!(
        eval_rev
            .violations
            .iter()
            .any(|v| matches!(v, Violation::EngineRevoked { .. }))
    );
}

#[test]
fn strict_telemetry_endpoint_and_secretref_enforced() {
    let mut fx = load_fixtures();
    fx.dev.1.telemetry_endpoint =
        "https://otel.dev.example.internal:4318/v1/traces?token=abc".to_string();
    fx.dev
        .1
        .secrets
        .insert("bad_p".into(), "secretref://bad-kms/dev/k#v1".into());
    fx.dev
        .1
        .secrets
        .insert("cross".into(), "secretref://gcp-sm/prod/k#v1".into());
    fx.dev.0.domain_config_digest = compute_domain_config_digest(&fx.dev.1);

    let eval = evaluate_domain(&DomainInputs {
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
    assert_eq!(eval.action, PlanAction::Refused);
    assert!(eval.violations.iter().any(|v| matches!(v, Violation::InvalidDomainConfig { field, .. } if field == "telemetry_endpoint")));
    assert!(
        eval.violations
            .iter()
            .any(|v| matches!(v, Violation::UnauthorizedSecretProvider { .. }))
    );
    assert!(
        eval.violations
            .iter()
            .any(|v| matches!(v, Violation::SecretDomainMismatch { .. }))
    );
}

#[test]
fn oidc_claims_accept_classic_and_post_july_2026_subjects_and_reject_mismatches() {
    let policy = ExpectedOidcPolicy {
        expected_issuer: GITHUB_OIDC_ISSUER.to_string(),
        expected_audience: "sts.platform.internal".to_string(),
        expected_repository: "acme/platform-ops".to_string(),
        expected_repository_id: Some("123456".to_string()),
        expected_ref: "refs/heads/main".to_string(),
        expected_environment: DomainTier::Prod,
    };

    let classic = OidcClaims {
        iss: GITHUB_OIDC_ISSUER.to_string(),
        aud: "sts.platform.internal".to_string(),
        sub: "repo:acme/platform-ops:environment:prod".to_string(),
        repository: "acme/platform-ops".to_string(),
        repository_id: Some("123456".to_string()),
        repository_owner_id: Some("654321".to_string()),
        r#ref: "refs/heads/main".to_string(),
        environment: "prod".to_string(),
        nbf: 1000,
        exp: 2000,
    };
    assert!(validate_oidc_claims(&policy, 1500, &classic).is_ok());

    let immutable_2026 = OidcClaims {
        sub: "repo:acme/platform-ops:environment:prod:repo_id:123456:repo_owner_id:654321"
            .to_string(),
        ..classic.clone()
    };
    assert!(validate_oidc_claims(&policy, 1500, &immutable_2026).is_ok());

    let wrong_repo_id = OidcClaims {
        sub: "repo:acme/platform-ops:environment:prod:repo_id:999999:repo_owner_id:654321"
            .to_string(),
        ..classic.clone()
    };
    assert!(validate_oidc_claims(&policy, 1500, &wrong_repo_id).is_err());

    let dev_env = OidcClaims {
        sub: "repo:acme/platform-ops:environment:dev:repo_id:123456:repo_owner_id:654321"
            .to_string(),
        environment: "dev".to_string(),
        ..classic
    };
    assert!(validate_oidc_claims(&policy, 1500, &dev_env).is_err());
}
