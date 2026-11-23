//! Pure zero-I/O evaluator for the 5 platform invariants, RFC 8785 JCS digests,
//! Ed25519-signed attestations & checkpoints, shard/reader continuity, and OIDC scoping.

#![forbid(unsafe_code)]

pub mod checkpoint_verify;
pub mod continuity;
pub mod digest;
pub mod evaluate;
pub mod ledger_verify;
pub mod model;
pub mod oidc;
pub mod scope;
pub mod violations;

pub use checkpoint_verify::verify_checkpoint;
pub use continuity::validate_catalog;
pub use digest::{
    GENESIS_HASH, MAX_JCS_SAFE_UINT, canonical_json_string, checkpoint_signing_bytes,
    compute_domain_config_digest, compute_engine_config_digest, compute_jcs_digest,
    compute_record_hash, decode_hex_exact, encode_hex, is_valid_sha256_digest, sha256_prefixed,
    sign_attestation_record, sign_checkpoint, signing_payload_bytes, try_canonical_json_string,
    try_jcs_digest,
};
pub use evaluate::{DomainInputs, evaluate_domain};
pub use ledger_verify::verify_ledger;
pub use model::{
    AttestationLedger, AttestationRecord, CatalogEngine, DomainConfig, DomainEvaluation,
    DomainTier, EngineCatalog, EngineConfig, EvalMode, ExpectedOidcPolicy, Observation, OidcClaims,
    PlanAction, Predicate, ProvenanceStatus, TargetManifest, TransitionMode, TrustRoot,
    TrustedCheckpoint, TrustedVerifier,
};
pub use oidc::{GITHUB_OIDC_ISSUER, validate_oidc_claims};
pub use scope::{SecretRef, validate_domain_config};
pub use violations::Violation;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_security;
