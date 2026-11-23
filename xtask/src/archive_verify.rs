use std::fs;
use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use platform_kernel::{
    CatalogEngine, ProvenanceStatus, TransitionMode, is_valid_sha256_digest, sha256_prefixed,
    try_canonical_json_string, try_jcs_digest,
};
use serde_json::Value;
use tar::Archive;

pub const RELEASE_MANIFEST_SCHEMA: &str = "service.release-manifest/v1";
pub const SERVICE_COMPAT_SCHEMA: &str = "service.compatibility/v1";

pub fn verify_release_archive_and_manifest(
    manifest_path: &Path,
    archive_path: &Path,
    provenance_status: ProvenanceStatus,
    provenance_digest: Option<String>,
) -> Result<CatalogEngine, String> {
    if provenance_status == ProvenanceStatus::Verified
        && !provenance_digest
            .as_deref()
            .is_some_and(is_valid_sha256_digest)
    {
        return Err(
            "`--provenance-verified` requires valid `--provenance-digest sha256:...`".into(),
        );
    }
    if let Some(d) = &provenance_digest
        && !is_valid_sha256_digest(d)
    {
        return Err(format!("invalid `--provenance-digest` `{d}`"));
    }

    let raw_manifest = fs::read_to_string(manifest_path)
        .map_err(|e| format!("failed reading manifest `{}`: {e}", manifest_path.display()))?;
    let manifest: Value = serde_json::from_str(&raw_manifest)
        .map_err(|e| format!("invalid release manifest JSON: {e}"))?;

    if req_str(&manifest, "schema")? != RELEASE_MANIFEST_SCHEMA {
        return Err(format!(
            "manifest schema must equal `{RELEASE_MANIFEST_SCHEMA}`"
        ));
    }
    let service_name = req_str(&manifest, "service_name")?.to_string();
    let version = req_str(&manifest, "version")?.to_string();
    let target = req_str(&manifest, "target")?.to_string();
    let engine_digest = req_digest(&manifest, "engine_digest")?;
    let binary_digest = req_digest(&manifest, "binary_digest")?;
    let compatibility_digest = req_digest(&manifest, "compatibility_digest")?;

    let manifest_compat = manifest
        .get("compatibility")
        .ok_or_else(|| "release manifest missing `compatibility` object".to_string())?;
    if req_str(manifest_compat, "schema")? != SERVICE_COMPAT_SCHEMA {
        return Err(format!(
            "compatibility schema must equal `{SERVICE_COMPAT_SCHEMA}`"
        ));
    }
    if req_str(manifest_compat, "service_name")? != service_name {
        return Err("manifest.service_name != compatibility.service_name".to_string());
    }

    let archive_bytes = fs::read(archive_path)
        .map_err(|e| format!("failed reading archive `{}`: {e}", archive_path.display()))?;
    let computed_archive_sha = sha256_prefixed(&archive_bytes);
    if computed_archive_sha != engine_digest {
        return Err(format!(
            "archive digest mismatch: expected `{engine_digest}`, computed `{computed_archive_sha}`"
        ));
    }

    let (bin_bytes, compat_bytes) = extract_archive_members(&archive_bytes, &service_name)?;
    let computed_bin_sha = sha256_prefixed(&bin_bytes);
    if computed_bin_sha != binary_digest {
        return Err(format!(
            "binary_digest mismatch inside archive: expected `{binary_digest}`, computed `{computed_bin_sha}`"
        ));
    }

    let archive_compat: Value = serde_json::from_slice(&compat_bytes)
        .map_err(|e| format!("invalid `compatibility.json` inside archive: {e}"))?;
    let jcs_archive_compat = try_canonical_json_string(&archive_compat)?;
    let jcs_manifest_compat = try_canonical_json_string(manifest_compat)?;
    if jcs_archive_compat != jcs_manifest_compat {
        return Err(
            "archive `compatibility.json` differs from manifest `compatibility`".to_string(),
        );
    }
    let computed_compat_sha = try_jcs_digest(&archive_compat)?;
    if computed_compat_sha != compatibility_digest {
        return Err(format!(
            "RFC 8785 JCS compatibility_digest mismatch: expected `{compatibility_digest}`, computed `{computed_compat_sha}`"
        ));
    }

    parse_strict_compat_fields(
        engine_digest,
        binary_digest,
        compatibility_digest,
        service_name,
        version,
        target,
        &archive_compat,
        provenance_status,
        provenance_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_strict_compat_fields(
    engine_digest: String,
    binary_digest: String,
    compatibility_digest: String,
    service_name: String,
    version: String,
    target: String,
    compat: &Value,
    provenance_status: ProvenanceStatus,
    provenance_digest: Option<String>,
) -> Result<CatalogEngine, String> {
    let config_schema_version = req_u32(compat, "config_schema_version")?;
    let state_format_version = req_u32(compat, "state_format_version")?;
    let min_readable_state_format = req_u32(compat, "min_readable_state_format")?;
    let oldest_writable_state_format = req_u32(compat, "oldest_writable_state_format")?;

    let mode_raw = req_str(compat, "transition_mode")?;
    let transition_mode: TransitionMode =
        serde_json::from_value(Value::String(mode_raw.to_string()))
            .map_err(|_| format!("invalid `transition_mode` `{mode_raw}`"))?;

    let arr = compat
        .get("preserved_state_fields")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing `preserved_state_fields` array in compatibility".to_string())?;
    let mut preserved = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "invalid entry in `preserved_state_fields`".to_string())?;
        preserved.push(s.to_string());
    }
    if preserved.is_empty() {
        return Err("`preserved_state_fields` must not be empty".to_string());
    }

    Ok(CatalogEngine {
        engine_digest,
        binary_digest,
        compatibility_digest,
        service_name,
        version,
        target,
        config_schema_version,
        state_format_version,
        min_readable_state_format,
        oldest_writable_state_format,
        transition_mode,
        preserved_state_fields: preserved,
        provenance_status,
        provenance_digest,
        fixture_only: false,
    })
}

fn extract_archive_members(
    archive_bytes: &[u8],
    service_name: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let decoder = GzDecoder::new(archive_bytes);
    let mut archive = Archive::new(decoder);
    let mut bin_bytes = None;
    let mut compat_bytes = None;
    let exe_name = format!("{service_name}.exe");

    for entry in archive
        .entries()
        .map_err(|e| format!("tar header error: {e}"))?
    {
        let mut entry = entry.map_err(|e| format!("tar entry error: {e}"))?;
        let raw_path = entry
            .path()
            .map_err(|e| format!("invalid tar entry path: {e}"))?
            .to_string_lossy()
            .to_string();
        let clean = raw_path.strip_prefix("./").unwrap_or(&raw_path);
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed reading tar member `{clean}`: {e}"))?;

        if clean == "compatibility.json" {
            if compat_bytes.replace(buf).is_some() {
                return Err("duplicate `compatibility.json` in release archive".to_string());
            }
        } else if (clean == service_name || clean == exe_name) && bin_bytes.replace(buf).is_some() {
            return Err(format!(
                "duplicate `{service_name}` binary in release archive"
            ));
        }
    }

    let bin = bin_bytes.ok_or_else(|| format!("archive missing `{service_name}` binary"))?;
    let compat = compat_bytes.ok_or_else(|| "archive missing `compatibility.json`".to_string())?;
    Ok((bin, compat))
}

fn req_str<'a>(obj: &'a Value, key: &str) -> Result<&'a str, String> {
    obj.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing or empty string field `{key}`"))
}

fn req_digest(obj: &Value, key: &str) -> Result<String, String> {
    let val = req_str(obj, key)?;
    if !is_valid_sha256_digest(val) {
        return Err(format!("field `{key}` has invalid sha256 digest `{val}`"));
    }
    Ok(val.to_string())
}

fn req_u32(obj: &Value, key: &str) -> Result<u32, String> {
    let raw = obj
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing unsigned integer field `{key}`"))?;
    u32::try_from(raw).map_err(|_| format!("field `{key}` value {raw} overflows u32"))
}
