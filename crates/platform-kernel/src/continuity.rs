use std::collections::BTreeSet;

use crate::digest::{MAX_JCS_SAFE_UINT, is_valid_sha256_digest};
use crate::model::{
    CatalogEngine, DomainConfig, ENGINE_CATALOG_SCHEMA, EngineCatalog, Observation, PlanAction,
    ProvenanceStatus, TargetManifest, TransitionMode,
};
use crate::violations::Violation;

pub fn validate_catalog(catalog: &EngineCatalog) -> Vec<Violation> {
    let mut violations = Vec::new();
    if catalog.schema != ENGINE_CATALOG_SCHEMA {
        violations.push(Violation::InvalidCatalogEntry {
            engine_digest: "<catalog>".to_string(),
            reason: format!("expected schema `{ENGINE_CATALOG_SCHEMA}`"),
        });
    }
    let mut seen_digests = BTreeSet::new();
    let mut seen_releases = BTreeSet::new();
    for eng in &catalog.engines {
        for (field, val) in [
            ("catalog.engine_digest", &eng.engine_digest),
            ("catalog.binary_digest", &eng.binary_digest),
            ("catalog.compatibility_digest", &eng.compatibility_digest),
        ] {
            if !is_valid_sha256_digest(val) {
                violations.push(Violation::UnpinnedDigest {
                    field: field.to_string(),
                    value: val.clone(),
                });
            }
        }
        if !seen_digests.insert(eng.engine_digest.as_str()) {
            violations.push(Violation::DuplicateCatalogDigest {
                engine_digest: eng.engine_digest.clone(),
            });
        }
        let rel_key = (
            eng.service_name.as_str(),
            eng.version.as_str(),
            eng.target.as_str(),
        );
        if !seen_releases.insert(rel_key) {
            violations.push(Violation::DuplicateCatalogRelease {
                service_name: eng.service_name.clone(),
                version: eng.version.clone(),
                target: eng.target.clone(),
            });
        }
        let prov_ok = match (eng.provenance_status, &eng.provenance_digest) {
            (ProvenanceStatus::Verified, Some(d)) => is_valid_sha256_digest(d),
            (ProvenanceStatus::Verified, None) => false,
            (ProvenanceStatus::UnverifiedLocal, None) => true,
            (ProvenanceStatus::UnverifiedLocal, Some(d)) => is_valid_sha256_digest(d),
        };
        if eng.service_name != "admission-engine"
            || eng.target.is_empty()
            || eng.preserved_state_fields.is_empty()
            || eng.min_readable_state_format == 0
            || eng.min_readable_state_format > eng.oldest_writable_state_format
            || eng.oldest_writable_state_format > eng.state_format_version
            || !prov_ok
        {
            violations.push(Violation::InvalidCatalogEntry {
                engine_digest: eng.engine_digest.clone(),
                reason: "invalid catalog metadata, provenance, or state_format ordering"
                    .to_string(),
            });
        }
    }
    violations
}

pub(crate) fn check_engine_config_compat(
    config: &DomainConfig,
    target: &CatalogEngine,
    violations: &mut Vec<Violation>,
) {
    if config.engine_config.config_schema_version != target.config_schema_version {
        violations.push(Violation::EngineSchemaMismatch {
            reason: format!(
                "engine_config schema {} != engine config_schema_version {}",
                config.engine_config.config_schema_version, target.config_schema_version
            ),
        });
    }
    let w = config.engine_config.state_write_version;
    if w < target.oldest_writable_state_format || w > target.state_format_version {
        violations.push(Violation::EngineSchemaMismatch {
            reason: format!(
                "state_write_version {w} outside engine writable range [{}..={}]",
                target.oldest_writable_state_format, target.state_format_version
            ),
        });
    }
}

pub(crate) fn check_generation_and_continuity(
    config: &DomainConfig,
    observed: &Observation,
    target_manifest: &TargetManifest,
    live: &CatalogEngine,
    target: &CatalogEngine,
    violations: &mut Vec<Violation>,
) {
    if observed.total_shards == 0
        || observed.migrated_shards > observed.total_shards
        || observed.min_shard_state_format == 0
        || observed.min_shard_state_format > observed.max_shard_state_format
        || observed.membership_epoch == 0
        || observed.min_active_reader_format == 0
        || observed.generation > MAX_JCS_SAFE_UINT
        || target_manifest.generation > MAX_JCS_SAFE_UINT
    {
        violations.push(Violation::IncompleteShardMigration {
            migrated_shards: observed.migrated_shards,
            total_shards: observed.total_shards,
            reason: "invalid shard/reader/epoch bounds in observation or target".to_string(),
        });
    }

    if config.engine_config.state_write_version > observed.min_active_reader_format {
        violations.push(Violation::ReaderFormatCeilingExceeded {
            state_write_version: config.engine_config.state_write_version,
            min_active_reader_format: observed.min_active_reader_format,
            membership_epoch: observed.membership_epoch,
        });
    }

    if target
        .preserved_state_fields
        .iter()
        .any(|f| f == "consumed_units")
        && observed.max_observed_consumed_units > config.engine_config.max_units_per_window
    {
        violations.push(Violation::UnrestorableBudgetCut {
            observed_consumed: observed.max_observed_consumed_units,
            target_max_units: config.engine_config.max_units_per_window,
        });
    }

    if target_manifest.expected_observed_generation != observed.generation {
        violations.push(Violation::CasGenerationMismatch {
            expected_observed: target_manifest.expected_observed_generation,
            actual_observed: observed.generation,
        });
    }

    let same_tuple = target_manifest.engine_digest == observed.engine_digest
        && target_manifest.domain_config_digest == observed.domain_config_digest
        && target_manifest.engine_config_digest == observed.engine_config_digest;
    if same_tuple {
        if target_manifest.generation != observed.generation {
            violations.push(Violation::InvalidTargetGeneration {
                observed_generation: observed.generation,
                target_generation: target_manifest.generation,
                reason: "unchanged tuple must keep target.generation == observed.generation"
                    .to_string(),
            });
        }
    } else if target_manifest.generation <= observed.generation {
        violations.push(Violation::NonMonotonicGeneration {
            observed_generation: observed.generation,
            target_generation: target_manifest.generation,
        });
    }

    check_shard_format_transitions(observed, live, target, violations);
}

fn check_shard_format_transitions(
    observed: &Observation,
    live: &CatalogEngine,
    target: &CatalogEngine,
    violations: &mut Vec<Violation>,
) {
    if observed.max_shard_state_format > target.state_format_version {
        violations.push(Violation::IrreversibleStateRollback {
            max_shard_state_format: observed.max_shard_state_format,
            target_state_format: target.state_format_version,
            reason: format!("live max_shard_state_format > target v{}", target.version),
        });
    } else if matches!(
        live.transition_mode,
        TransitionMode::Contract | TransitionMode::ForwardOnly
    ) && target.oldest_writable_state_format < observed.min_shard_state_format
    {
        violations.push(Violation::IrreversibleStateRollback {
            max_shard_state_format: observed.max_shard_state_format,
            target_state_format: target.state_format_version,
            reason: format!(
                "cannot re-open older writable format after v{}",
                live.version
            ),
        });
    }

    if observed.min_shard_state_format < target.min_readable_state_format {
        violations.push(Violation::IncompatibleStateJump {
            min_shard_state_format: observed.min_shard_state_format,
            target_min_readable: target.min_readable_state_format,
            target_mode: target.transition_mode,
            reason: format!("live min_shard_state_format < target v{}", target.version),
        });
    } else if matches!(
        target.transition_mode,
        TransitionMode::Contract | TransitionMode::ForwardOnly
    ) && target.engine_digest != live.engine_digest
    {
        if !observed.converged || observed.migrated_shards != observed.total_shards {
            violations.push(Violation::IncompleteShardMigration {
                migrated_shards: observed.migrated_shards,
                total_shards: observed.total_shards,
                reason: "all shards must converge before contract/forward_only".to_string(),
            });
        }
        if target.min_readable_state_format > 1
            && live.state_format_version < target.state_format_version
        {
            violations.push(Violation::IncompatibleStateJump {
                min_shard_state_format: observed.min_shard_state_format,
                target_min_readable: target.min_readable_state_format,
                target_mode: target.transition_mode,
                reason: "must converge expand release before contract/forward_only".to_string(),
            });
        }
    }
}

pub(crate) fn classify_action(
    observed: &Observation,
    target_manifest: &TargetManifest,
    target_eng: &CatalogEngine,
) -> PlanAction {
    let same_tuple = observed.converged
        && observed.migrated_shards == observed.total_shards
        && observed.engine_digest == target_manifest.engine_digest
        && observed.domain_config_digest == target_manifest.domain_config_digest
        && observed.engine_config_digest == target_manifest.engine_config_digest;
    if same_tuple {
        PlanAction::NoOp
    } else if target_eng.state_format_version > observed.min_shard_state_format {
        PlanAction::ExpandState
    } else {
        PlanAction::AdvanceTuple
    }
}
