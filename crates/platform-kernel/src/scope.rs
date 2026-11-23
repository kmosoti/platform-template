use std::collections::BTreeSet;

use crate::digest::MAX_JCS_SAFE_UINT;
use crate::model::{DOMAIN_CONFIG_SCHEMA, DomainConfig, DomainTier};
use crate::violations::Violation;

const KNOWN_SECRET_PROVIDERS: &[&str] = &["gcp-sm", "aws-sm", "vault", "age-kms"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub provider: String,
    pub domain: String,
    pub name: String,
    pub version: u32,
}

impl SecretRef {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let Some(rest) = raw.strip_prefix("secretref://") else {
            return Err("must begin with `secretref://`".to_string());
        };
        let Some((path_part, ver_part)) = rest.split_once("#v") else {
            return Err("must end with `#v<int>` version pin".to_string());
        };
        if ver_part.is_empty()
            || ver_part.starts_with('0')
            || !ver_part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!("invalid secret version `#v{ver_part}`"));
        }
        let version: u32 = ver_part
            .parse()
            .map_err(|_| format!("invalid secret version `#v{ver_part}`"))?;

        let segs: Vec<&str> = path_part.split('/').collect();
        if segs.len() != 3 || segs.iter().any(|s| s.is_empty()) {
            return Err("expected `secretref://<provider>/<domain>/<name>#v<int>`".to_string());
        }
        let (provider, domain, name) = (segs[0], segs[1], segs[2]);
        if !is_kebab_slug(provider) || !is_kebab_slug(domain) || !is_kebab_slug(name) {
            return Err("secretref segments must be lowercase `[a-z0-9-]` identifiers".to_string());
        }
        Ok(Self {
            provider: provider.to_string(),
            domain: domain.to_string(),
            name: name.to_string(),
            version,
        })
    }
}

pub fn validate_domain_config(
    tier: DomainTier,
    config: &DomainConfig,
    violations: &mut Vec<Violation>,
) {
    if config.schema != DOMAIN_CONFIG_SCHEMA {
        violations.push(Violation::InvalidDomainConfig {
            field: "schema".to_string(),
            reason: format!("expected `{DOMAIN_CONFIG_SCHEMA}`"),
        });
    }
    if config.domain != tier {
        violations.push(Violation::DomainIdentityMismatch {
            expected: tier,
            found: config.domain,
            source: "config.json".to_string(),
        });
    }
    if config.replicas == 0 {
        violations.push(Violation::InvalidDomainConfig {
            field: "replicas".to_string(),
            reason: "replicas must be >= 1".to_string(),
        });
    }
    validate_telemetry_endpoint(&config.telemetry_endpoint, violations);
    validate_secret_providers_and_map(tier, config, violations);

    let ec = &config.engine_config;
    if ec.window_ms == 0
        || ec.max_units_per_window == 0
        || ec.max_burst_units == 0
        || ec.max_burst_units > ec.max_units_per_window
        || ec.window_ms > MAX_JCS_SAFE_UINT
        || ec.max_units_per_window > MAX_JCS_SAFE_UINT
        || ec.max_burst_units > MAX_JCS_SAFE_UINT
    {
        violations.push(Violation::InvalidDomainConfig {
            field: "engine_config".to_string(),
            reason:
                "require window_ms > 0, 0 < max_burst_units <= max_units_per_window, and <= 2^53-1"
                    .to_string(),
        });
    }
}

fn validate_secret_providers_and_map(
    tier: DomainTier,
    config: &DomainConfig,
    violations: &mut Vec<Violation>,
) {
    if config.allowed_secret_providers.is_empty() {
        violations.push(Violation::InvalidDomainConfig {
            field: "allowed_secret_providers".to_string(),
            reason: "allowed_secret_providers must not be empty".to_string(),
        });
    }
    let mut seen_providers = BTreeSet::new();
    for p in &config.allowed_secret_providers {
        if !KNOWN_SECRET_PROVIDERS.contains(&p.as_str()) {
            violations.push(Violation::UnauthorizedSecretProvider {
                field: "allowed_secret_providers".to_string(),
                provider: p.clone(),
            });
        }
        if !seen_providers.insert(p.as_str()) {
            violations.push(Violation::InvalidDomainConfig {
                field: "allowed_secret_providers".to_string(),
                reason: format!("duplicate secret provider `{p}`"),
            });
        }
    }
    if config.secrets.is_empty() {
        violations.push(Violation::RawSecretOrInvalidEnvelope {
            field: "secrets".to_string(),
            reason: "secrets map must not be empty".to_string(),
        });
    }
    for (key, raw_val) in &config.secrets {
        let field = format!("secrets.{key}");
        if !is_snake_case(key) {
            violations.push(Violation::InvalidDomainConfig {
                field: field.clone(),
                reason: "secret key must be non-empty snake_case".to_string(),
            });
        }
        match SecretRef::parse(raw_val) {
            Ok(parsed) => {
                if !config.allowed_secret_providers.contains(&parsed.provider) {
                    violations.push(Violation::UnauthorizedSecretProvider {
                        field: field.clone(),
                        provider: parsed.provider,
                    });
                }
                if parsed.domain != tier.as_str() {
                    violations.push(Violation::SecretDomainMismatch {
                        field,
                        expected: tier,
                        found: parsed.domain,
                    });
                }
            }
            Err(reason) => violations.push(Violation::RawSecretOrInvalidEnvelope { field, reason }),
        }
    }
}

/// Validates strict `https://<host>[:<port>]` without path, query, fragment, or userinfo.
fn validate_telemetry_endpoint(endpoint: &str, violations: &mut Vec<Violation>) {
    if endpoint.contains("secretref://") {
        violations.push(Violation::RawSecretOrInvalidEnvelope {
            field: "telemetry_endpoint".to_string(),
            reason: "telemetry_endpoint must not embed `secretref://`".to_string(),
        });
        return;
    }
    let Some(authority) = endpoint.strip_prefix("https://") else {
        violations.push(Violation::InvalidDomainConfig {
            field: "telemetry_endpoint".to_string(),
            reason: "telemetry_endpoint must start with `https://`".to_string(),
        });
        return;
    };
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.chars().any(char::is_whitespace)
    {
        violations.push(Violation::InvalidDomainConfig {
            field: "telemetry_endpoint".to_string(),
            reason: "telemetry_endpoint must be `https://<host>[:<port>]` with no path, query, fragment, or userinfo"
                .to_string(),
        });
        return;
    }
    let (host, port_opt) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(port_str) = port_opt {
        let valid_port = !port_str.is_empty()
            && !port_str.starts_with('0')
            && port_str.bytes().all(|b| b.is_ascii_digit())
            && port_str.parse::<u16>().is_ok_and(|p| p >= 1);
        if !valid_port {
            violations.push(Violation::InvalidDomainConfig {
                field: "telemetry_endpoint".to_string(),
                reason: format!("invalid port `:{port_str}` in telemetry_endpoint"),
            });
            return;
        }
    }
    let labels: Vec<&str> = host.split('.').collect();
    let host_ok = labels.len() >= 2
        && labels.iter().all(|lbl| {
            (1..=63).contains(&lbl.len())
                && !lbl.starts_with('-')
                && !lbl.ends_with('-')
                && lbl
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if !host_ok {
        violations.push(Violation::InvalidDomainConfig {
            field: "telemetry_endpoint".to_string(),
            reason: format!("invalid ASCII hostname `{host}` in telemetry_endpoint"),
        });
    }
}

fn is_snake_case(s: &str) -> bool {
    let mut chars = s.bytes();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && !s.ends_with('_')
        && !s.contains("__")
        && chars.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_kebab_slug(s: &str) -> bool {
    let mut chars = s.bytes();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && !s.ends_with('-')
        && chars.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
