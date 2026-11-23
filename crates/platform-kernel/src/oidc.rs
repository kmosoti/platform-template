use std::collections::BTreeSet;

use crate::model::{ExpectedOidcPolicy, OidcClaims};
use crate::violations::Violation;

pub const GITHUB_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Validates decoded GitHub Actions OIDC claims against an explicit `ExpectedOidcPolicy`,
/// accepting both classic `repo:<repo>:environment:<env>` and post-July-15-2026 immutable
/// `repo:<repo>:environment:<env>:repo_id:<id>:repo_owner_id:<owner_id>` subject strings.
pub fn validate_oidc_claims(
    policy: &ExpectedOidcPolicy,
    now_epoch_s: u64,
    claims: &OidcClaims,
) -> Result<(), Violation> {
    let domain = policy.expected_environment;
    if policy.expected_issuer != GITHUB_OIDC_ISSUER || claims.iss != GITHUB_OIDC_ISSUER {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("expected iss `{GITHUB_OIDC_ISSUER}`, got `{}`", claims.iss),
        });
    }
    if policy.expected_audience.is_empty() || claims.aud != policy.expected_audience {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("OIDC audience mismatch: got `{}`", claims.aud),
        });
    }
    if !policy.expected_repository.contains('/') || claims.repository != policy.expected_repository
    {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("OIDC repository mismatch: got `{}`", claims.repository),
        });
    }
    if policy.expected_ref != "refs/heads/main" || claims.r#ref != "refs/heads/main" {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("OIDC ref must be `refs/heads/main`, got `{}`", claims.r#ref),
        });
    }
    if claims.environment != domain.as_str() {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("OIDC environment mismatch: got `{}`", claims.environment),
        });
    }
    if now_epoch_s < claims.nbf || now_epoch_s >= claims.exp {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!(
                "OIDC token outside validity window [{}..{}) at {now_epoch_s}",
                claims.nbf, claims.exp
            ),
        });
    }
    if let Some(exp_id) = &policy.expected_repository_id
        && claims.repository_id.as_deref() != Some(exp_id.as_str())
    {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: "OIDC repository_id claim does not match ExpectedOidcPolicy".to_string(),
        });
    }
    validate_github_subject(policy, claims)
}

fn validate_github_subject(
    policy: &ExpectedOidcPolicy,
    claims: &OidcClaims,
) -> Result<(), Violation> {
    let domain = policy.expected_environment;
    let Some(after_scheme) = claims.sub.strip_prefix("repo:") else {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("OIDC sub `{}` missing `repo:` prefix", claims.sub),
        });
    };
    let Some((repo_seg, rest)) = after_scheme.split_once(':') else {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("malformed OIDC sub `{}`", claims.sub),
        });
    };
    validate_repo_segment(policy, claims, repo_seg)?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() < 2 || !parts.len().is_multiple_of(2) {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("malformed OIDC sub segments `{}`", claims.sub),
        });
    }
    let mut seen_keys = BTreeSet::new();
    let mut env_matched = false;
    for [k, v] in parts.as_chunks::<2>().0 {
        let (k, v) = (*k, *v);
        if v.is_empty() || !seen_keys.insert(k) {
            return Err(Violation::OidcClaimViolation {
                domain,
                reason: format!("duplicate or empty key `{k}` in OIDC sub"),
            });
        }
        match k {
            "environment" => {
                if v != domain.as_str() {
                    return Err(Violation::OidcClaimViolation {
                        domain,
                        reason: format!("OIDC sub environment `{v}` != `{}`", domain.as_str()),
                    });
                }
                env_matched = true;
            }
            "repo_id" => {
                if !v.bytes().all(|b| b.is_ascii_digit())
                    || policy
                        .expected_repository_id
                        .as_deref()
                        .is_some_and(|e| e != v)
                    || claims.repository_id.as_deref().is_some_and(|c| c != v)
                {
                    return Err(Violation::OidcClaimViolation {
                        domain,
                        reason: format!("invalid or mismatched OIDC sub repo_id `{v}`"),
                    });
                }
            }
            "repo_owner_id" => {
                if !v.bytes().all(|b| b.is_ascii_digit())
                    || claims
                        .repository_owner_id
                        .as_deref()
                        .is_some_and(|c| c != v)
                {
                    return Err(Violation::OidcClaimViolation {
                        domain,
                        reason: format!("invalid or mismatched OIDC sub repo_owner_id `{v}`"),
                    });
                }
            }
            other => {
                return Err(Violation::OidcClaimViolation {
                    domain,
                    reason: format!("unexpected OIDC sub attribute `{other}`"),
                });
            }
        }
    }
    if !env_matched {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: "OIDC sub missing `environment` attribute".to_string(),
        });
    }
    Ok(())
}

fn validate_repo_segment(
    policy: &ExpectedOidcPolicy,
    claims: &OidcClaims,
    repo_seg: &str,
) -> Result<(), Violation> {
    let domain = policy.expected_environment;
    if repo_seg == policy.expected_repository {
        return Ok(());
    }
    let Some((exp_owner, exp_repo)) = policy.expected_repository.split_once('/') else {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!(
                "invalid expected_repository `{}`",
                policy.expected_repository
            ),
        });
    };
    let Some((sub_owner_part, sub_repo_part)) = repo_seg.split_once('/') else {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("OIDC sub repo segment `{repo_seg}` missing `/`"),
        });
    };
    let Some((sub_owner, owner_id)) = sub_owner_part.split_once('@') else {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!(
                "OIDC sub repo segment `{repo_seg}` does not match `{}`",
                policy.expected_repository
            ),
        });
    };
    let Some((sub_repo, repo_id)) = sub_repo_part.split_once('@') else {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("OIDC sub repo segment `{repo_seg}` missing `@<repo_id>`"),
        });
    };
    let valid_ids = !owner_id.is_empty()
        && owner_id.bytes().all(|b| b.is_ascii_digit())
        && !repo_id.is_empty()
        && repo_id.bytes().all(|b| b.is_ascii_digit())
        && policy
            .expected_repository_id
            .as_deref()
            .is_none_or(|e| e == repo_id)
        && claims.repository_id.as_deref().is_none_or(|c| c == repo_id)
        && claims
            .repository_owner_id
            .as_deref()
            .is_none_or(|c| c == owner_id);
    if sub_owner != exp_owner || sub_repo != exp_repo || !valid_ids {
        return Err(Violation::OidcClaimViolation {
            domain,
            reason: format!("immutable OIDC sub repo segment `{repo_seg}` mismatch"),
        });
    }
    Ok(())
}
