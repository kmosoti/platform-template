use serde::{Deserialize, Serialize};

use crate::model::{DomainTier, Predicate, TransitionMode};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Violation {
    UnpinnedDigest {
        field: String,
        value: String,
    },
    DuplicateCatalogDigest {
        engine_digest: String,
    },
    DuplicateCatalogRelease {
        service_name: String,
        version: String,
        target: String,
    },
    InvalidCatalogEntry {
        engine_digest: String,
        reason: String,
    },
    UnverifiedProvenanceInLiveMode {
        engine_digest: String,
    },
    UnknownEngineDigest {
        field: String,
        engine_digest: String,
    },
    EngineConfigDigestMismatch {
        expected: String,
        actual: String,
    },
    DomainConfigDigestMismatch {
        expected: String,
        actual: String,
    },
    EngineSchemaMismatch {
        reason: String,
    },
    DomainIdentityMismatch {
        expected: DomainTier,
        found: DomainTier,
        source: String,
    },
    CasGenerationMismatch {
        expected_observed: u64,
        actual_observed: u64,
    },
    NonMonotonicGeneration {
        observed_generation: u64,
        target_generation: u64,
    },
    InvalidTargetGeneration {
        observed_generation: u64,
        target_generation: u64,
        reason: String,
    },
    ReaderFormatCeilingExceeded {
        state_write_version: u32,
        min_active_reader_format: u32,
        membership_epoch: u64,
    },
    UnrestorableBudgetCut {
        observed_consumed: u64,
        target_max_units: u64,
    },
    IncompatibleStateJump {
        min_shard_state_format: u32,
        target_min_readable: u32,
        target_mode: TransitionMode,
        reason: String,
    },
    IncompleteShardMigration {
        migrated_shards: u32,
        total_shards: u32,
        reason: String,
    },
    IrreversibleStateRollback {
        max_shard_state_format: u32,
        target_state_format: u32,
        reason: String,
    },
    FixtureInputInLiveMode {
        source: String,
    },
    TrustRootInvalid {
        reason: String,
    },
    MissingOrInvalidCheckpoint {
        reason: String,
    },
    StaleLedgerCheckpoint {
        checkpoint_epoch_s: u64,
        max_staleness_s: u64,
        now_epoch_s: u64,
    },
    LedgerIntegrityFailure {
        attestation_id: String,
        reason: String,
    },
    UnauthorizedAttestationKey {
        attestation_id: String,
        key_id: String,
        reason: String,
    },
    AttestationExpired {
        attestation_id: String,
        expires_at_epoch_s: u64,
        now_epoch_s: u64,
    },
    EngineRevoked {
        engine_digest: String,
        attestation_id: String,
    },
    MissingAttestation {
        domain: DomainTier,
        predicate: Predicate,
        engine_digest: String,
    },
    InvalidDomainConfig {
        field: String,
        reason: String,
    },
    RawSecretOrInvalidEnvelope {
        field: String,
        reason: String,
    },
    UnauthorizedSecretProvider {
        field: String,
        provider: String,
    },
    SecretDomainMismatch {
        field: String,
        expected: DomainTier,
        found: String,
    },
    OidcClaimViolation {
        domain: DomainTier,
        reason: String,
    },
}
