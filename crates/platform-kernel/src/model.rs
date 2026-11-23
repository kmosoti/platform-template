use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::violations::Violation;

pub const ENGINE_CATALOG_SCHEMA: &str = "platform.engine-catalog/v1";
pub const DOMAIN_CONFIG_SCHEMA: &str = "platform.domain-config/v1";
pub const TARGET_SCHEMA: &str = "platform.target/v1";
pub const OBSERVATION_SCHEMA: &str = "platform.observation/v1";
pub const TRUST_ROOT_SCHEMA: &str = "platform.trust-root/v1";
pub const LEDGER_SCHEMA: &str = "platform.attestation-ledger/v1";
pub const CHECKPOINT_SCHEMA: &str = "platform.ledger-checkpoint/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainTier {
    Dev,
    Staging,
    Prod,
}

impl DomainTier {
    pub const ALL: [Self; 3] = [Self::Dev, Self::Staging, Self::Prod];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Staging => "staging",
            Self::Prod => "prod",
        }
    }

    pub fn required_predicates(self) -> &'static [Predicate] {
        match self {
            Self::Dev => &[Predicate::SimPassed],
            Self::Staging => &[Predicate::SimPassed, Predicate::DevConverged],
            Self::Prod => &[
                Predicate::SimPassed,
                Predicate::DevConverged,
                Predicate::SoakWithinBounds,
                Predicate::PolicySigned,
            ],
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalMode {
    #[default]
    Simulate,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionMode {
    Reversible,
    Expand,
    Contract,
    ForwardOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceStatus {
    UnverifiedLocal,
    Verified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineCatalog {
    pub schema: String,
    pub engines: Vec<CatalogEngine>,
}

impl EngineCatalog {
    pub fn find_by_digest(&self, digest: &str) -> Option<&CatalogEngine> {
        self.engines.iter().find(|e| e.engine_digest == digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEngine {
    pub engine_digest: String,
    pub binary_digest: String,
    pub compatibility_digest: String,
    pub service_name: String,
    pub version: String,
    pub target: String,
    pub config_schema_version: u32,
    pub state_format_version: u32,
    pub min_readable_state_format: u32,
    pub oldest_writable_state_format: u32,
    pub transition_mode: TransitionMode,
    pub preserved_state_fields: Vec<String>,
    pub provenance_status: ProvenanceStatus,
    pub provenance_digest: Option<String>,
    pub fixture_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainConfig {
    pub schema: String,
    pub domain: DomainTier,
    pub replicas: u32,
    pub telemetry_endpoint: String,
    pub allowed_secret_providers: Vec<String>,
    pub secrets: BTreeMap<String, String>,
    pub engine_config: EngineConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub config_schema_version: u32,
    pub window_ms: u64,
    pub max_units_per_window: u64,
    pub max_burst_units: u64,
    pub state_write_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetManifest {
    pub schema: String,
    pub domain: DomainTier,
    pub generation: u64,
    pub expected_observed_generation: u64,
    pub engine_digest: String,
    pub engine_config_digest: String,
    pub domain_config_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub schema: String,
    pub fixture_mode: bool,
    pub domain: DomainTier,
    pub generation: u64,
    pub membership_epoch: u64,
    pub engine_digest: String,
    pub engine_config_digest: String,
    pub domain_config_digest: String,
    pub min_active_reader_format: u32,
    pub min_shard_state_format: u32,
    pub max_shard_state_format: u32,
    pub total_shards: u32,
    pub migrated_shards: u32,
    pub max_observed_consumed_units: u64,
    pub converged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    SimPassed,
    DevConverged,
    SoakWithinBounds,
    PolicySigned,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoot {
    pub schema: String,
    pub trust_mode: String,
    pub fixture_mode: bool,
    pub verifiers: Vec<TrustedVerifier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedVerifier {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_hex: String,
    pub allowed_predicates: Vec<Predicate>,
    pub allowed_domains: Vec<DomainTier>,
    pub can_sign_checkpoints: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationLedger {
    pub schema: String,
    pub stream_id: String,
    pub fixture_mode: bool,
    pub demo_eval_epoch_s: Option<u64>,
    pub records: Vec<AttestationRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRecord {
    pub attestation_id: String,
    pub predicate: Predicate,
    pub domain: Option<DomainTier>,
    pub target_generation: Option<u64>,
    pub engine_digest: String,
    pub engine_config_digest: Option<String>,
    pub domain_config_digest: Option<String>,
    pub evidence_digest: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: Option<u64>,
    pub key_id: String,
    pub prev_hash: String,
    pub record_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedCheckpoint {
    pub schema: String,
    pub fixture_mode: bool,
    pub stream_id: String,
    pub ledger_len: usize,
    pub head_record_hash: String,
    pub checkpoint_epoch_s: u64,
    pub max_staleness_s: u64,
    pub policy_version: u32,
    pub key_id: String,
    pub signature: String,
}

/// Decoded OIDC token claims produced after JWT JWS signature verification against GitHub's JWKS
/// at the external OIDC exchange boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub repository: String,
    #[serde(default)]
    pub repository_id: Option<String>,
    #[serde(default)]
    pub repository_owner_id: Option<String>,
    pub r#ref: String,
    pub environment: String,
    pub nbf: u64,
    pub exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOidcPolicy {
    pub expected_issuer: String,
    pub expected_audience: String,
    pub expected_repository: String,
    pub expected_repository_id: Option<String>,
    pub expected_ref: String,
    pub expected_environment: DomainTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum PlanAction {
    NoOp,
    AdvanceTuple,
    ExpandState,
    Refused,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEvaluation {
    pub domain: DomainTier,
    pub mode: EvalMode,
    pub action: PlanAction,
    pub generation: u64,
    pub observed_generation: u64,
    pub live_engine_digest: String,
    pub target_engine_digest: String,
    pub computed_engine_config_digest: String,
    pub computed_domain_config_digest: String,
    pub min_active_reader_format: u32,
    pub min_shard_state_format: u32,
    pub max_shard_state_format: u32,
    pub target_state_format: Option<u32>,
    pub target_transition_mode: Option<TransitionMode>,
    pub matched_attestations: Vec<String>,
    pub violations: Vec<Violation>,
}

impl DomainEvaluation {
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty() && self.action != PlanAction::Refused
    }
}
