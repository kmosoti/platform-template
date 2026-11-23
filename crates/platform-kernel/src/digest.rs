use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::model::{AttestationRecord, DomainConfig, EngineConfig, TrustedCheckpoint};

pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// RFC 8785 / IEEE-754 maximum exact integer magnitude (`2^53 - 1`).
pub const MAX_JCS_SAFE_UINT: u64 = (1u64 << 53) - 1;
const MIN_JCS_SAFE_INT: i64 = -((1i64 << 53) - 1);

pub fn is_valid_sha256_digest(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex_exact<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = hex.as_bytes();
    for i in 0..N {
        let hi = nibble(bytes[i * 2])?;
        let lo = nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

pub fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", encode_hex(&digest))
}

/// Serializes `value` according to RFC 8785 JSON Canonicalization Scheme (JCS),
/// sorting object keys by UTF-16 code units and rejecting non-exact integers/floats.
pub fn try_canonical_json_string(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_jcs_value(value, &mut out)?;
    Ok(out)
}

pub fn canonical_json_string(value: &Value) -> String {
    try_canonical_json_string(value).expect("valid RFC 8785 JCS value")
}

fn write_jcs_value(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_JCS_SAFE_UINT {
                    return Err(format!("integer {u} exceeds RFC 8785 safe range 2^53-1"));
                }
                out.push_str(&u.to_string());
            } else if let Some(i) = n.as_i64() {
                if i < MIN_JCS_SAFE_INT {
                    return Err(format!("integer {i} below RFC 8785 safe range -(2^53-1)"));
                }
                out.push_str(&i.to_string());
            } else {
                return Err(format!("floating-point JSON numbers forbidden in JCS: {n}"));
            }
        }
        Value::String(s) => write_jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&str, &Value)> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (idx, (k, v)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_jcs_string(k, out);
                out.push(':');
                write_jcs_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_jcs_string(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let b = c as u8;
                out.push_str("\\u00");
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn try_jcs_digest<T: Serialize>(val: &T) -> Result<String, String> {
    let v = serde_json::to_value(val).map_err(|e| e.to_string())?;
    Ok(sha256_prefixed(try_canonical_json_string(&v)?.as_bytes()))
}

pub fn compute_jcs_digest<T: Serialize>(val: &T) -> String {
    try_jcs_digest(val).expect("valid RFC 8785 JCS structure")
}

pub fn compute_engine_config_digest(cfg: &EngineConfig) -> String {
    compute_jcs_digest(cfg)
}

pub fn compute_domain_config_digest(cfg: &DomainConfig) -> String {
    compute_jcs_digest(cfg)
}

pub fn compute_record_hash(rec: &AttestationRecord) -> String {
    let payload = json!({
        "attestation_id": rec.attestation_id,
        "domain": rec.domain,
        "domain_config_digest": rec.domain_config_digest,
        "engine_config_digest": rec.engine_config_digest,
        "engine_digest": rec.engine_digest,
        "evidence_digest": rec.evidence_digest,
        "expires_at_epoch_s": rec.expires_at_epoch_s,
        "issued_at_epoch_s": rec.issued_at_epoch_s,
        "key_id": rec.key_id,
        "predicate": rec.predicate,
        "prev_hash": rec.prev_hash,
        "target_generation": rec.target_generation,
    });
    sha256_prefixed(canonical_json_string(&payload).as_bytes())
}

pub fn signing_payload_bytes(rec: &AttestationRecord) -> Vec<u8> {
    let payload = json!({
        "schema": "platform.attestation-signing-payload/v1",
        "attestation_id": rec.attestation_id,
        "domain": rec.domain,
        "domain_config_digest": rec.domain_config_digest,
        "engine_config_digest": rec.engine_config_digest,
        "engine_digest": rec.engine_digest,
        "evidence_digest": rec.evidence_digest,
        "expires_at_epoch_s": rec.expires_at_epoch_s,
        "issued_at_epoch_s": rec.issued_at_epoch_s,
        "key_id": rec.key_id,
        "predicate": rec.predicate,
        "prev_hash": rec.prev_hash,
        "record_hash": rec.record_hash,
        "target_generation": rec.target_generation,
    });
    canonical_json_string(&payload).into_bytes()
}

pub fn checkpoint_signing_bytes(cp: &TrustedCheckpoint) -> Vec<u8> {
    let payload = json!({
        "schema": cp.schema,
        "fixture_mode": cp.fixture_mode,
        "stream_id": cp.stream_id,
        "ledger_len": cp.ledger_len,
        "head_record_hash": cp.head_record_hash,
        "checkpoint_epoch_s": cp.checkpoint_epoch_s,
        "max_staleness_s": cp.max_staleness_s,
        "policy_version": cp.policy_version,
        "key_id": cp.key_id,
    });
    canonical_json_string(&payload).into_bytes()
}

pub fn sign_attestation_record(rec: &mut AttestationRecord, signing_key_bytes: &[u8; 32]) {
    rec.record_hash = compute_record_hash(rec);
    let sk = SigningKey::from_bytes(signing_key_bytes);
    let sig: Signature = sk.sign(&signing_payload_bytes(rec));
    rec.signature = encode_hex(&sig.to_bytes());
}

pub fn sign_checkpoint(cp: &mut TrustedCheckpoint, signing_key_bytes: &[u8; 32]) {
    let sk = SigningKey::from_bytes(signing_key_bytes);
    let sig: Signature = sk.sign(&checkpoint_signing_bytes(cp));
    cp.signature = encode_hex(&sig.to_bytes());
}
