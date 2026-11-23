use std::path::Path;

use platform_kernel::{EngineCatalog, ProvenanceStatus, validate_catalog};

use crate::archive_verify::verify_release_archive_and_manifest;
use crate::atomic_io::write_pretty_json_atomic;
use crate::ops::read_json;

/// Strictly append-only registration of a byte-verified `service-template` release into
/// `catalog/engines.json`. Never mutates `observations/`, `domains/`, `trust/`, or `attestations/`.
pub fn cmd_import_service_release(
    root: &Path,
    manifest_path: &Path,
    archive_path: &Path,
    provenance_status: ProvenanceStatus,
    provenance_digest: Option<String>,
) -> Result<(), String> {
    let candidate = verify_release_archive_and_manifest(
        manifest_path,
        archive_path,
        provenance_status,
        provenance_digest,
    )?;

    let cat_path = root.join("catalog/engines.json");
    let mut catalog: EngineCatalog = read_json(&cat_path)?;

    let matching_idx = catalog.engines.iter().position(|existing| {
        existing.engine_digest == candidate.engine_digest
            || (existing.service_name == candidate.service_name
                && existing.version == candidate.version
                && existing.target == candidate.target)
    });

    if let Some(idx) = matching_idx {
        let existing = &catalog.engines[idx];
        if existing == &candidate {
            println!(
                "[import-service-release] idempotent no-op: {} v{} ({}) already registered",
                candidate.service_name, candidate.version, candidate.engine_digest
            );
            return Ok(());
        }
        let mut upgraded = existing.clone();
        upgraded.provenance_status = candidate.provenance_status;
        if existing.provenance_status != candidate.provenance_status && upgraded == candidate {
            catalog.engines[idx] = candidate.clone();
            write_pretty_json_atomic(&cat_path, &catalog)?;
            println!(
                "[import-service-release] upgraded provenance status for {} v{} ({})",
                candidate.service_name, candidate.version, candidate.engine_digest
            );
            return Ok(());
        }
        return Err(format!(
            "ImmutableReleaseConflict: `{}` v{} ({}) conflicts with existing catalog entry (existing digest `{}` vs incoming `{}`)",
            candidate.service_name,
            candidate.version,
            candidate.target,
            existing.engine_digest,
            candidate.engine_digest
        ));
    }

    catalog.engines.push(candidate.clone());
    let errs = validate_catalog(&catalog);
    if !errs.is_empty() {
        return Err(format!("catalog validation failed after append: {errs:?}"));
    }

    write_pretty_json_atomic(&cat_path, &catalog)?;
    println!(
        "[import-service-release] appended {} v{} ({}) to `catalog/engines.json`",
        candidate.service_name, candidate.version, candidate.engine_digest
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use platform_kernel::{sha256_prefixed, try_jcs_digest};
    use serde_json::json;
    use tar::{Builder, Header};

    fn write_test_release_bundle(
        dir: &Path,
        version: &str,
        bin_payload: &[u8],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let compat = json!({
            "schema": "service.compatibility/v1",
            "service_name": "admission-engine",
            "config_schema_version": 1,
            "state_format_version": 2,
            "min_readable_state_format": 2,
            "oldest_writable_state_format": 2,
            "transition_mode": "contract",
            "preserved_state_fields": ["window_epoch_ms", "consumed_units", "last_sequence"]
        });
        let compat_bytes = serde_json::to_vec_pretty(&compat).unwrap();
        let compat_digest = try_jcs_digest(&compat).unwrap();
        let bin_digest = sha256_prefixed(bin_payload);

        let archive_path = dir.join(format!("admission-engine-v{version}.tar.gz"));
        let gz_file = fs::File::create(&archive_path).unwrap();
        let enc = GzEncoder::new(gz_file, Compression::default());
        let mut tar = Builder::new(enc);

        for (name, data) in [
            ("admission-engine", bin_payload),
            ("compatibility.json", compat_bytes.as_slice()),
        ] {
            let mut header = Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            tar.append_data(&mut header, name, data).unwrap();
        }
        let enc = tar.into_inner().unwrap();
        enc.finish().unwrap();

        let archive_bytes = fs::read(&archive_path).unwrap();
        let engine_digest = sha256_prefixed(&archive_bytes);
        let manifest = json!({
            "schema": "service.release-manifest/v1",
            "service_name": "admission-engine",
            "version": version,
            "target": "linux-x86_64",
            "archive_name": format!("admission-engine-v{version}.tar.gz"),
            "engine_digest": engine_digest,
            "binary_digest": bin_digest,
            "compatibility_digest": compat_digest,
            "compatibility": compat,
            "source_commit": "0000000000000000000000000000000000000000",
            "source_tree": "0000000000000000000000000000000000000000",
            "rustc_version": "rustc 1.100.0"
        });
        let manifest_path = dir.join(format!("release-{version}.json"));
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        (manifest_path, archive_path)
    }

    #[test]
    fn import_is_append_only_idempotent_and_rejects_conflicting_version_digest() {
        let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let tmp = std::env::temp_dir().join(format!("platform-import-test-{nanos}"));
        for sub in [
            "catalog",
            "domains/dev",
            "domains/staging",
            "domains/prod",
            "observations",
            "trust",
            "attestations",
        ] {
            fs::create_dir_all(tmp.join(sub)).unwrap();
        }
        let tracked = [
            "catalog/engines.json",
            "domains/dev/target.json",
            "domains/staging/target.json",
            "domains/prod/target.json",
            "observations/dev.json",
            "observations/staging.json",
            "observations/prod.json",
            "trust/verifiers.json",
            "attestations/ledger.json",
            "attestations/checkpoint.json",
        ];
        for rel in tracked {
            fs::copy(src_root.join(rel), tmp.join(rel)).unwrap();
        }

        let untouched = &tracked[1..];
        let before: Vec<Vec<u8>> = untouched
            .iter()
            .map(|r| fs::read(tmp.join(r)).unwrap())
            .collect();

        let (m1, a1) = write_test_release_bundle(&tmp, "0.3.0", b"elf-binary-v030-a");
        cmd_import_service_release(&tmp, &m1, &a1, ProvenanceStatus::UnverifiedLocal, None)
            .unwrap();

        let after: Vec<Vec<u8>> = untouched
            .iter()
            .map(|r| fs::read(tmp.join(r)).unwrap())
            .collect();
        assert_eq!(
            before, after,
            "non-catalog files must stay byte-for-byte identical"
        );

        // Re-importing identical release is a zero-write idempotent no-op
        let cat_after_first = fs::read(tmp.join("catalog/engines.json")).unwrap();
        cmd_import_service_release(&tmp, &m1, &a1, ProvenanceStatus::UnverifiedLocal, None)
            .unwrap();
        assert_eq!(
            cat_after_first,
            fs::read(tmp.join("catalog/engines.json")).unwrap()
        );

        // Importing a conflicting digest for 0.3.0 fails closed
        let (m_conflict, a_conflict) =
            write_test_release_bundle(&tmp, "0.3.0", b"elf-binary-v030-tampered");
        let err = cmd_import_service_release(
            &tmp,
            &m_conflict,
            &a_conflict,
            ProvenanceStatus::UnverifiedLocal,
            None,
        )
        .unwrap_err();
        assert!(err.contains("ImmutableReleaseConflict"));

        let _ = fs::remove_dir_all(&tmp);
    }
}
