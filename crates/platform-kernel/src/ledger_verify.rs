use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::digest::{
    GENESIS_HASH, MAX_JCS_SAFE_UINT, compute_record_hash, decode_hex_exact, is_valid_sha256_digest,
    signing_payload_bytes,
};
use crate::model::{
    AttestationLedger, AttestationRecord, DomainTier, EvalMode, LEDGER_SCHEMA, Predicate,
    TRUST_ROOT_SCHEMA, TargetManifest, TrustRoot, TrustedVerifier,
};
use crate::violations::Violation;

pub fn verify_ledger(
    ledger: &AttestationLedger,
    trust_root: &TrustRoot,
    mode: EvalMode,
) -> Vec<Violation> {
    let mut violations = validate_trust_root(trust_root, mode);
    if ledger.schema != LEDGER_SCHEMA || ledger.stream_id.is_empty() {
        violations.push(Violation::LedgerIntegrityFailure {
            attestation_id: "<ledger>".to_string(),
            reason: "invalid ledger schema or empty stream_id".to_string(),
        });
    }
    if mode == EvalMode::Live && ledger.fixture_mode {
        violations.push(Violation::FixtureInputInLiveMode {
            source: "attestation_ledger".to_string(),
        });
    }

    let mut expected_prev = GENESIS_HASH.to_string();
    for rec in &ledger.records {
        verify_single_record(rec, &expected_prev, trust_root, &mut violations);
        expected_prev = rec.record_hash.clone();
    }
    violations
}

pub(crate) fn check_attestations(
    tier: DomainTier,
    now_epoch_s: u64,
    target: &TargetManifest,
    active_records: &[AttestationRecord],
    violations: &mut Vec<Violation>,
) -> Vec<String> {
    for rec in active_records {
        if rec.predicate == Predicate::Revoked && rec.engine_digest == target.engine_digest {
            violations.push(Violation::EngineRevoked {
                engine_digest: target.engine_digest.clone(),
                attestation_id: rec.attestation_id.clone(),
            });
        }
    }

    let mut matched = Vec::new();
    for &pred in tier.required_predicates() {
        let candidates: Vec<_> = active_records
            .iter()
            .filter(|rec| rec.predicate == pred && matches_predicate_subject(pred, rec, target))
            .collect();
        if let Some(valid) = candidates.iter().find(|rec| {
            rec.expires_at_epoch_s
                .is_some_and(|exp| rec.issued_at_epoch_s <= now_epoch_s && now_epoch_s <= exp)
        }) {
            matched.push(valid.attestation_id.clone());
        } else if let Some(expired) = candidates.first() {
            violations.push(Violation::AttestationExpired {
                attestation_id: expired.attestation_id.clone(),
                expires_at_epoch_s: expired.expires_at_epoch_s.unwrap_or(0),
                now_epoch_s,
            });
        } else {
            violations.push(Violation::MissingAttestation {
                domain: tier,
                predicate: pred,
                engine_digest: target.engine_digest.clone(),
            });
        }
    }
    matched
}

fn matches_predicate_subject(
    pred: Predicate,
    rec: &AttestationRecord,
    target: &TargetManifest,
) -> bool {
    if rec.engine_digest != target.engine_digest {
        return false;
    }
    match pred {
        Predicate::SimPassed => {
            rec.engine_config_digest.as_deref() == Some(target.engine_config_digest.as_str())
        }
        Predicate::DevConverged => {
            rec.domain == Some(DomainTier::Dev)
                && rec.engine_config_digest.as_deref() == Some(target.engine_config_digest.as_str())
        }
        Predicate::SoakWithinBounds => {
            rec.domain == Some(DomainTier::Staging)
                && rec.engine_config_digest.as_deref() == Some(target.engine_config_digest.as_str())
        }
        Predicate::PolicySigned => {
            rec.domain == Some(DomainTier::Prod)
                && rec.target_generation == Some(target.generation)
                && rec.domain_config_digest.as_deref() == Some(target.domain_config_digest.as_str())
        }
        Predicate::Revoked => true,
    }
}

fn validate_trust_root(trust_root: &TrustRoot, mode: EvalMode) -> Vec<Violation> {
    let mut violations = Vec::new();
    if trust_root.schema != TRUST_ROOT_SCHEMA {
        violations.push(Violation::TrustRootInvalid {
            reason: format!("invalid trust root schema `{}`", trust_root.schema),
        });
    }
    if mode == EvalMode::Live
        && (trust_root.fixture_mode || trust_root.trust_mode == "fixture-demo")
    {
        violations.push(Violation::FixtureInputInLiveMode {
            source: "trust_root".to_string(),
        });
    }
    let mut seen = BTreeSet::new();
    for v in &trust_root.verifiers {
        if !seen.insert(v.key_id.as_str()) {
            violations.push(Violation::TrustRootInvalid {
                reason: format!("duplicate verifier key_id `{}`", v.key_id),
            });
        }
        if v.algorithm != "ed25519" || decode_hex_exact::<32>(&v.public_key_hex).is_none() {
            violations.push(Violation::TrustRootInvalid {
                reason: format!("invalid ed25519 key on `{}`", v.key_id),
            });
        }
    }
    violations
}

fn verify_single_record(
    rec: &AttestationRecord,
    expected_prev: &str,
    trust_root: &TrustRoot,
    violations: &mut Vec<Violation>,
) {
    for (field, val) in [
        ("engine_digest", Some(rec.engine_digest.as_str())),
        ("evidence_digest", Some(rec.evidence_digest.as_str())),
        ("engine_config_digest", rec.engine_config_digest.as_deref()),
        ("domain_config_digest", rec.domain_config_digest.as_deref()),
    ] {
        if let Some(d) = val
            && !is_valid_sha256_digest(d)
        {
            violations.push(Violation::LedgerIntegrityFailure {
                attestation_id: rec.attestation_id.clone(),
                reason: format!("invalid {field} `{d}`"),
            });
        }
    }
    if rec.issued_at_epoch_s > MAX_JCS_SAFE_UINT {
        violations.push(Violation::LedgerIntegrityFailure {
            attestation_id: rec.attestation_id.clone(),
            reason: "issued_at_epoch_s exceeds JCS safe integer bound".to_string(),
        });
    }
    if rec.predicate != Predicate::Revoked
        && !rec
            .expires_at_epoch_s
            .is_some_and(|exp| rec.issued_at_epoch_s < exp && exp <= MAX_JCS_SAFE_UINT)
    {
        violations.push(Violation::LedgerIntegrityFailure {
            attestation_id: rec.attestation_id.clone(),
            reason: "positive attestation requires valid expires_at_epoch_s > issued_at_epoch_s"
                .to_string(),
        });
    }
    if rec.prev_hash != expected_prev || rec.record_hash != compute_record_hash(rec) {
        violations.push(Violation::LedgerIntegrityFailure {
            attestation_id: rec.attestation_id.clone(),
            reason: "prev_hash chain or record_hash mismatch".to_string(),
        });
    }
    let Some(verifier) = trust_root.verifiers.iter().find(|v| v.key_id == rec.key_id) else {
        violations.push(Violation::UnauthorizedAttestationKey {
            attestation_id: rec.attestation_id.clone(),
            key_id: rec.key_id.clone(),
            reason: "unknown key_id not present in trust root".to_string(),
        });
        return;
    };
    check_key_scope(rec, verifier, violations);
    if let Err(reason) = verify_raw_ed25519(
        &verifier.public_key_hex,
        &rec.signature,
        &signing_payload_bytes(rec),
    ) {
        violations.push(Violation::LedgerIntegrityFailure {
            attestation_id: rec.attestation_id.clone(),
            reason,
        });
    }
}

fn check_key_scope(
    rec: &AttestationRecord,
    verifier: &TrustedVerifier,
    violations: &mut Vec<Violation>,
) {
    if !verifier.allowed_predicates.contains(&rec.predicate) {
        violations.push(Violation::UnauthorizedAttestationKey {
            attestation_id: rec.attestation_id.clone(),
            key_id: rec.key_id.clone(),
            reason: format!("key not authorized for `{:?}`", rec.predicate),
        });
    }
    if let Some(dom) = rec.domain
        && !verifier.allowed_domains.contains(&dom)
    {
        violations.push(Violation::UnauthorizedAttestationKey {
            attestation_id: rec.attestation_id.clone(),
            key_id: rec.key_id.clone(),
            reason: format!("key not authorized for domain `{}`", dom.as_str()),
        });
    }
}

pub(crate) fn verify_raw_ed25519(pk_hex: &str, sig_hex: &str, msg: &[u8]) -> Result<(), String> {
    let pk_bytes =
        decode_hex_exact::<32>(pk_hex).ok_or_else(|| "invalid public key hex".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| "malformed Ed25519 public key".to_string())?;
    let sig_bytes = decode_hex_exact::<64>(sig_hex)
        .ok_or_else(|| "signature must be 128 lowercase hex chars".to_string())?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(msg, &sig)
        .map_err(|_| "Ed25519 signature verification failed".to_string())
}
