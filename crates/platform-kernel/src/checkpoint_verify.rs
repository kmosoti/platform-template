use crate::digest::checkpoint_signing_bytes;
use crate::ledger_verify::verify_raw_ed25519;
use crate::model::{AttestationLedger, CHECKPOINT_SCHEMA, EvalMode, TrustRoot, TrustedCheckpoint};
use crate::violations::Violation;

pub fn verify_checkpoint(
    checkpoint: &TrustedCheckpoint,
    ledger: &AttestationLedger,
    trust_root: &TrustRoot,
    mode: EvalMode,
    now_epoch_s: u64,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    if checkpoint.schema != CHECKPOINT_SCHEMA {
        violations.push(Violation::MissingOrInvalidCheckpoint {
            reason: format!("expected schema `{CHECKPOINT_SCHEMA}`"),
        });
    }
    if mode == EvalMode::Live && checkpoint.fixture_mode {
        violations.push(Violation::FixtureInputInLiveMode {
            source: "trusted_checkpoint".to_string(),
        });
    }
    if checkpoint.stream_id != ledger.stream_id {
        violations.push(Violation::MissingOrInvalidCheckpoint {
            reason: format!(
                "checkpoint stream_id `{}` != ledger stream_id `{}`",
                checkpoint.stream_id, ledger.stream_id
            ),
        });
    }
    if checkpoint.ledger_len == 0 || ledger.records.len() < checkpoint.ledger_len {
        violations.push(Violation::MissingOrInvalidCheckpoint {
            reason: format!(
                "checkpoint ledger_len {} invalid for ledger of length {}",
                checkpoint.ledger_len,
                ledger.records.len()
            ),
        });
    } else if ledger.records[checkpoint.ledger_len - 1].record_hash != checkpoint.head_record_hash {
        violations.push(Violation::MissingOrInvalidCheckpoint {
            reason: "checkpoint head_record_hash does not match ledger prefix".to_string(),
        });
    }

    let max_valid_ts = checkpoint
        .checkpoint_epoch_s
        .saturating_add(checkpoint.max_staleness_s);
    if now_epoch_s < checkpoint.checkpoint_epoch_s || now_epoch_s > max_valid_ts {
        violations.push(Violation::StaleLedgerCheckpoint {
            checkpoint_epoch_s: checkpoint.checkpoint_epoch_s,
            max_staleness_s: checkpoint.max_staleness_s,
            now_epoch_s,
        });
    }

    let Some(verifier) = trust_root
        .verifiers
        .iter()
        .find(|v| v.key_id == checkpoint.key_id)
    else {
        violations.push(Violation::MissingOrInvalidCheckpoint {
            reason: format!("unknown checkpoint key_id `{}`", checkpoint.key_id),
        });
        return violations;
    };
    if !verifier.can_sign_checkpoints {
        violations.push(Violation::MissingOrInvalidCheckpoint {
            reason: format!(
                "key `{}` is not authorized to sign checkpoints",
                verifier.key_id
            ),
        });
    }
    if verify_raw_ed25519(
        &verifier.public_key_hex,
        &checkpoint.signature,
        &checkpoint_signing_bytes(checkpoint),
    )
    .is_err()
    {
        violations.push(Violation::MissingOrInvalidCheckpoint {
            reason: "checkpoint Ed25519 signature verification failed".to_string(),
        });
    }
    violations
}
