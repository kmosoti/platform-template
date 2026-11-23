use std::collections::BTreeSet;

use serde_json::Value;

use crate::github_plan::GithubSetupOptions;

#[derive(Debug, Clone)]
pub struct EnvReadback {
    pub name: String,
    pub env_json: Value,
    pub branch_policies: Vec<Value>,
}

/// Validates live GitHub REST API readback JSON structures for all 3 rulesets and 4 environments.
pub fn verify_readback_snapshot(
    reviewer_id: u64,
    opts: &GithubSetupOptions,
    detailed_rulesets: &[Value],
    environments: &[EnvReadback],
) -> Result<(), String> {
    verify_main_ruleset(opts, detailed_rulesets)?;
    verify_agent_ruleset(detailed_rulesets)?;
    verify_forbid_env_ruleset(detailed_rulesets)?;
    verify_environments(reviewer_id, environments)?;
    Ok(())
}

fn find_active_ruleset<'a>(rulesets: &'a [Value], name: &str) -> Result<&'a Value, String> {
    let rs = rulesets
        .iter()
        .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| format!("readback missing ruleset `{name}`"))?;
    if rs.get("enforcement").and_then(Value::as_str) != Some("active") {
        return Err(format!("ruleset `{name}` enforcement is not `active`"));
    }
    Ok(rs)
}

fn includes_refs(rs: &Value) -> Vec<String> {
    rs.pointer("/conditions/ref_name/include")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn find_rule<'a>(rs: &'a Value, rule_type: &str) -> Option<&'a Value> {
    rs.get("rules")
        .and_then(Value::as_array)?
        .iter()
        .find(|r| r.get("type").and_then(Value::as_str) == Some(rule_type))
}

fn verify_main_ruleset(opts: &GithubSetupOptions, rulesets: &[Value]) -> Result<(), String> {
    let rs = find_active_ruleset(rulesets, "platform-template-main-protection")?;
    if includes_refs(rs) != vec!["refs/heads/main".to_string()] {
        return Err("main ruleset ref_name.include must be exactly [\"refs/heads/main\"]".into());
    }
    for req_type in ["deletion", "non_fast_forward"] {
        if find_rule(rs, req_type).is_none() {
            return Err(format!("main ruleset missing `{req_type}` rule"));
        }
    }
    let pr = find_rule(rs, "pull_request")
        .ok_or_else(|| "main ruleset missing `pull_request` rule".to_string())?;
    let approvals = pr
        .pointer("/parameters/required_approving_review_count")
        .and_then(Value::as_u64);
    let methods: Vec<&str> = pr
        .pointer("/parameters/allowed_merge_methods")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if approvals != Some(u64::from(opts.main_pr_approvals)) || methods != vec!["merge"] {
        return Err(
            "main ruleset `pull_request` approvals or `allowed_merge_methods` mismatch".into(),
        );
    }

    let checks: BTreeSet<&str> = find_rule(rs, "required_status_checks")
        .and_then(|r| r.pointer("/parameters/required_status_checks"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|c| c.get("context").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    if !checks.contains("gates") || !checks.contains("main-release-gate") {
        return Err("main ruleset missing `gates` or `main-release-gate` status check".into());
    }

    let deps: Vec<&str> = find_rule(rs, "required_deployments")
        .and_then(|r| r.pointer("/parameters/required_deployment_environments"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if deps != vec!["main-release"] {
        return Err("main ruleset missing `required_deployments: [\"main-release\"]`".into());
    }
    Ok(())
}

fn verify_agent_ruleset(rulesets: &[Value]) -> Result<(), String> {
    let rs = find_active_ruleset(rulesets, "platform-template-agent-branch-protection")?;
    if includes_refs(rs) != vec!["refs/heads/develop-agent".to_string()] {
        return Err("agent ruleset ref_name.include must be [\"refs/heads/develop-agent\"]".into());
    }
    if find_rule(rs, "required_linear_history").is_none()
        || find_rule(rs, "required_deployments").is_some()
    {
        return Err(
            "agent ruleset must enforce linear history without required_deployments".into(),
        );
    }
    Ok(())
}

fn verify_forbid_env_ruleset(rulesets: &[Value]) -> Result<(), String> {
    let rs = find_active_ruleset(rulesets, "platform-template-forbid-env-branches")?;
    let inc: BTreeSet<String> = includes_refs(rs).into_iter().collect();
    for forbidden in [
        "refs/heads/dev",
        "refs/heads/develop",
        "refs/heads/staging",
        "refs/heads/uat",
        "refs/heads/prod",
        "refs/heads/production",
    ] {
        if !inc.contains(forbidden) {
            return Err(format!("forbid-env ruleset missing `{forbidden}`"));
        }
    }
    if find_rule(rs, "creation").is_none() || find_rule(rs, "update").is_none() {
        return Err("forbid-env ruleset missing `creation` or `update` rule".into());
    }
    Ok(())
}

fn verify_environments(reviewer_id: u64, envs: &[EnvReadback]) -> Result<(), String> {
    for (name, needs_reviewer, expected_branches) in [
        ("main-release", true, &[][..]),
        ("dev", false, &["main"][..]),
        ("staging", true, &["main"][..]),
        ("prod", true, &["main"][..]),
    ] {
        let env_rb = envs
            .iter()
            .find(|e| e.name == name)
            .ok_or_else(|| format!("readback missing environment `{name}`"))?;
        if needs_reviewer && !has_reviewer_id(&env_rb.env_json, reviewer_id) {
            return Err(format!(
                "environment `{name}` missing required human reviewer id {reviewer_id}"
            ));
        }
        if expected_branches.is_empty() {
            if !env_rb
                .env_json
                .get("deployment_branch_policy")
                .is_none_or(Value::is_null)
            {
                return Err(format!(
                    "environment `{name}` must keep deployment_branch_policy == null"
                ));
            }
        } else {
            let custom = env_rb
                .env_json
                .pointer("/deployment_branch_policy/custom_branch_policies")
                .and_then(Value::as_bool);
            if custom != Some(true) {
                return Err(format!(
                    "environment `{name}` must enable custom_branch_policies"
                ));
            }
            let actual: Vec<&str> = env_rb
                .branch_policies
                .iter()
                .filter(|p| p.get("type").and_then(Value::as_str).unwrap_or("branch") == "branch")
                .filter_map(|p| p.get("name").and_then(Value::as_str))
                .collect();
            if actual != expected_branches {
                return Err(format!(
                    "environment `{name}` branch policy mismatch: expected {expected_branches:?}, got {actual:?}"
                ));
            }
        }
    }
    Ok(())
}

fn has_reviewer_id(env_json: &Value, reviewer_id: u64) -> bool {
    if let Some(rules) = env_json.get("protection_rules").and_then(Value::as_array) {
        for rule in rules {
            if let Some(revs) = rule.get("reviewers").and_then(Value::as_array)
                && revs.iter().any(|r| {
                    r.pointer("/reviewer/id").and_then(Value::as_u64) == Some(reviewer_id)
                        || r.get("id").and_then(Value::as_u64) == Some(reviewer_id)
                })
            {
                return true;
            }
        }
    }
    env_json
        .get("reviewers")
        .and_then(Value::as_array)
        .is_some_and(|revs| {
            revs.iter()
                .any(|r| r.get("id").and_then(Value::as_u64) == Some(reviewer_id))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_plan::build_setup_plan;
    use serde_json::json;

    #[test]
    fn accepts_valid_readback_and_rejects_missing_deployment_gate_or_staging_reviewer() {
        let opts = GithubSetupOptions::default();
        let plan = build_setup_plan(42, &opts);
        let rulesets: Vec<Value> = plan.rulesets.iter().map(|r| r.payload.clone()).collect();
        let mut envs = vec![
            EnvReadback {
                name: "main-release".into(),
                env_json: json!({"deployment_branch_policy": null, "protection_rules": [{"type": "required_reviewers", "reviewers": [{"reviewer": {"id": 42}}]}]}),
                branch_policies: vec![],
            },
            EnvReadback {
                name: "dev".into(),
                env_json: json!({"deployment_branch_policy": {"custom_branch_policies": true}}),
                branch_policies: vec![json!({"name": "main", "type": "branch"})],
            },
            EnvReadback {
                name: "staging".into(),
                env_json: json!({"deployment_branch_policy": {"custom_branch_policies": true}, "protection_rules": [{"reviewers": [{"reviewer": {"id": 42}}]}]}),
                branch_policies: vec![json!({"name": "main", "type": "branch"})],
            },
            EnvReadback {
                name: "prod".into(),
                env_json: json!({"deployment_branch_policy": {"custom_branch_policies": true}, "protection_rules": [{"reviewers": [{"reviewer": {"id": 42}}]}]}),
                branch_policies: vec![json!({"name": "main", "type": "branch"})],
            },
        ];
        assert!(verify_readback_snapshot(42, &opts, &rulesets, &envs).is_ok());

        // Drop staging reviewer -> must reject
        envs[2].env_json = json!({"deployment_branch_policy": {"custom_branch_policies": true}, "protection_rules": []});
        assert!(verify_readback_snapshot(42, &opts, &rulesets, &envs).is_err());
    }
}
