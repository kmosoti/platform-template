use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize)]
pub struct GithubSetupOptions {
    pub main_pr_approvals: u32,
    pub require_codeowners: bool,
    pub prevent_self_review: bool,
}

impl Default for GithubSetupOptions {
    fn default() -> Self {
        Self {
            main_pr_approvals: 1,
            require_codeowners: false,
            prevent_self_review: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentSpec {
    pub name: String,
    pub put_body: Value,
    pub custom_branches: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulesetSpec {
    pub name: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct GithubSetupPlan {
    pub repo_patch: Value,
    pub environments: Vec<EnvironmentSpec>,
    pub rulesets: Vec<RulesetSpec>,
}

pub fn parse_owner_repo(slug: &str) -> Result<(&str, &str), String> {
    let Some((owner, repo)) = slug.split_once('/') else {
        return Err(format!("expected `<OWNER/REPO>`, got `{slug}`"));
    };
    let valid_part = |s: &str| {
        !s.is_empty()
            && !s.contains('/')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    if !valid_part(owner) || !valid_part(repo) {
        return Err(format!("invalid `<OWNER/REPO>` identifier `{slug}`"));
    }
    Ok((owner, repo))
}

pub fn build_setup_plan(reviewer_id: u64, opts: &GithubSetupOptions) -> GithubSetupPlan {
    let reviewers = json!([{ "type": "User", "id": reviewer_id }]);
    let custom_policy = json!({
        "protected_branches": false,
        "custom_branch_policies": true
    });

    // Enable merge commits (for `main` promotions preserving ancestry) and squash/rebase
    // (for `develop-agent`); each branch ruleset restricts `allowed_merge_methods` specifically.
    let repo_patch = json!({
        "allow_merge_commit": true,
        "allow_squash_merge": true,
        "allow_rebase_merge": true,
        "allow_auto_merge": true,
        "delete_branch_on_merge": true
    });

    let environments = vec![
        EnvironmentSpec {
            name: "main-release".to_string(),
            put_body: json!({
                "prevent_self_review": opts.prevent_self_review,
                "reviewers": reviewers,
                "deployment_branch_policy": Value::Null
            }),
            custom_branches: vec![],
        },
        EnvironmentSpec {
            name: "dev".to_string(),
            put_body: json!({
                "reviewers": [],
                "deployment_branch_policy": custom_policy
            }),
            custom_branches: vec!["main".to_string()],
        },
        EnvironmentSpec {
            name: "staging".to_string(),
            put_body: json!({
                "prevent_self_review": opts.prevent_self_review,
                "reviewers": reviewers,
                "deployment_branch_policy": custom_policy
            }),
            custom_branches: vec!["main".to_string()],
        },
        EnvironmentSpec {
            name: "prod".to_string(),
            put_body: json!({
                "prevent_self_review": opts.prevent_self_review,
                "reviewers": reviewers,
                "deployment_branch_policy": custom_policy
            }),
            custom_branches: vec!["main".to_string()],
        },
    ];

    let rulesets = vec![
        RulesetSpec {
            name: "platform-template-main-protection".to_string(),
            payload: build_main_ruleset(opts),
        },
        RulesetSpec {
            name: "platform-template-agent-branch-protection".to_string(),
            payload: build_agent_ruleset(),
        },
        RulesetSpec {
            name: "platform-template-forbid-env-branches".to_string(),
            payload: build_forbid_env_ruleset(),
        },
    ];

    GithubSetupPlan {
        repo_patch,
        environments,
        rulesets,
    }
}

fn build_main_ruleset(opts: &GithubSetupOptions) -> Value {
    json!({
        "name": "platform-template-main-protection",
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": { "include": ["refs/heads/main"], "exclude": [] }
        },
        "rules": [
            { "type": "deletion" },
            { "type": "non_fast_forward" },
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": opts.main_pr_approvals,
                    "require_code_owner_review": opts.require_codeowners,
                    "dismiss_stale_reviews_on_push": true,
                    "require_last_push_approval": false,
                    "required_review_thread_resolution": true,
                    "allowed_merge_methods": ["merge"]
                }
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": false,
                    "required_status_checks": [
                        { "context": "gates" },
                        { "context": "main-release-gate" }
                    ]
                }
            },
            {
                "type": "required_deployments",
                "parameters": {
                    "required_deployment_environments": ["main-release"]
                }
            }
        ]
    })
}

fn build_agent_ruleset() -> Value {
    json!({
        "name": "platform-template-agent-branch-protection",
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": { "include": ["refs/heads/develop-agent"], "exclude": [] }
        },
        "rules": [
            { "type": "deletion" },
            { "type": "non_fast_forward" },
            { "type": "required_linear_history" },
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 0,
                    "require_code_owner_review": false,
                    "dismiss_stale_reviews_on_push": true,
                    "require_last_push_approval": false,
                    "required_review_thread_resolution": true,
                    "allowed_merge_methods": ["squash", "rebase"]
                }
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": true,
                    "required_status_checks": [{ "context": "gates" }]
                }
            }
        ]
    })
}

fn build_forbid_env_ruleset() -> Value {
    json!({
        "name": "platform-template-forbid-env-branches",
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {
                "include": [
                    "refs/heads/dev",
                    "refs/heads/develop",
                    "refs/heads/staging",
                    "refs/heads/uat",
                    "refs/heads/prod",
                    "refs/heads/production"
                ],
                "exclude": []
            }
        },
        "rules": [{ "type": "creation" }, { "type": "update" }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_main_and_agent_rulesets_and_enforces_staging_reviewer_and_main_release_deployment() {
        let plan = build_setup_plan(42, &GithubSetupOptions::default());
        assert_eq!(plan.environments.len(), 4);
        assert_eq!(plan.rulesets.len(), 3);

        let main_rs = &plan.rulesets[0].payload;
        let rules_str = serde_json::to_string(main_rs).unwrap();
        assert!(rules_str.contains("required_deployments"));
        assert!(rules_str.contains("main-release-gate"));
        assert!(rules_str.contains("\"allowed_merge_methods\":[\"merge\"]"));

        let agent_rs = &plan.rulesets[1].payload;
        let agent_str = serde_json::to_string(agent_rs).unwrap();
        assert!(!agent_str.contains("required_deployments"));
        assert!(agent_str.contains("\"squash\""));

        let staging_env = plan
            .environments
            .iter()
            .find(|e| e.name == "staging")
            .unwrap();
        assert_eq!(staging_env.put_body["reviewers"][0]["id"], 42);
        assert_eq!(staging_env.custom_branches, vec!["main".to_string()]);
    }
}
