use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::gh_http::{
    gh_get_with_status, gh_paginated_items, lease_push_develop_agent, run_gh_api, run_gh_json,
};
use crate::github_plan::{
    EnvironmentSpec, GithubSetupOptions, RulesetSpec, build_setup_plan, parse_owner_repo,
};
use crate::github_verify::{EnvReadback, verify_readback_snapshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefAlignAction {
    CreateAtMain,
    AlreadyAligned,
    LeaseAlignSameTreeRoot { expected_old_sha: String },
    FailClosed(String),
}

pub fn decide_develop_agent_alignment(
    main_sha: &str,
    main_tree: &str,
    dev_http_status: u16,
    dev_commit: Option<(&str, &str, usize)>,
) -> RefAlignAction {
    match dev_http_status {
        404 => RefAlignAction::CreateAtMain,
        200 => {
            let Some((agent_sha, agent_tree, parents_count)) = dev_commit else {
                return RefAlignAction::FailClosed(
                    "missing commit metadata on existing `develop-agent`".to_string(),
                );
            };
            if agent_sha == main_sha {
                RefAlignAction::AlreadyAligned
            } else if parents_count == 0 && agent_tree == main_tree {
                RefAlignAction::LeaseAlignSameTreeRoot {
                    expected_old_sha: agent_sha.to_string(),
                }
            } else {
                RefAlignAction::FailClosed(format!(
                    "refusing to overwrite `develop-agent` ({agent_sha}): parents={parents_count}, tree_matches_main={}",
                    agent_tree == main_tree
                ))
            }
        }
        code => RefAlignAction::FailClosed(format!(
            "unexpected HTTP status {code} reading `git/ref/heads/develop-agent`; failing closed"
        )),
    }
}

pub fn cmd_github_setup(
    repo_slug: &str,
    dry_run: bool,
    opts: &GithubSetupOptions,
) -> Result<(), String> {
    let (owner, repo) = parse_owner_repo(repo_slug)?;
    if dry_run {
        let plan = build_setup_plan(1, opts);
        let rendered = serde_json::to_string_pretty(&json!({
            "repository": format!("{owner}/{repo}"),
            "reconcile_mode": "idempotent-paginated-with-typed-readback",
            "pre_ruleset_branch_alignment": "404->create; 200 root+same-tree->lease-align; else fail-closed",
            "plan": plan,
        }))
        .map_err(|e| e.to_string())?;
        println!("{rendered}");
        return Ok(());
    }

    let reviewer_id = run_gh_json(&["api", "user"])?
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing numeric `id` in `gh api user`".to_string())?;
    let plan = build_setup_plan(reviewer_id, opts);
    let base = format!("repos/{owner}/{repo}");

    let repo_meta = run_gh_json(&["api", &base])?;
    if repo_meta.get("default_branch").and_then(Value::as_str) != Some("main") {
        return Err("repository `default_branch` must be `main`".to_string());
    }

    run_gh_api("PATCH", &base, Some(&plan.repo_patch))?;
    align_develop_agent_before_rulesets(owner, repo)?;

    for env_spec in &plan.environments {
        reconcile_environment(&base, env_spec)?;
    }

    let existing_rulesets = gh_paginated_items(&format!("{base}/rulesets"), ".[]")?;
    for rs_spec in &plan.rulesets {
        reconcile_ruleset(&base, rs_spec, &existing_rulesets)?;
    }

    verify_live_readback(&base, reviewer_id, opts, &plan.environments)?;
    println!(
        "[github-setup] reconciled and verified `{owner}/{repo}` (4 environments, 3 rulesets)"
    );
    Ok(())
}

fn align_develop_agent_before_rulesets(owner: &str, repo: &str) -> Result<(), String> {
    let base = format!("repos/{owner}/{repo}");
    let main_ref = run_gh_json(&["api", &format!("{base}/git/ref/heads/main")])?;
    let main_sha = main_ref
        .pointer("/object/sha")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `object.sha` on `refs/heads/main`".to_string())?;
    let main_commit = run_gh_json(&["api", &format!("{base}/git/commits/{main_sha}")])?;
    let main_tree = main_commit
        .pointer("/tree/sha")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing `tree.sha` on `main` commit".to_string())?;

    let (status, body) = gh_get_with_status(&format!("{base}/git/ref/heads/develop-agent"))?;
    let dev_info = if status == 200 {
        let sha = body
            .pointer("/object/sha")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing `object.sha` on `develop-agent`".to_string())?
            .to_string();
        let commit = run_gh_json(&["api", &format!("{base}/git/commits/{sha}")])?;
        let tree = commit
            .pointer("/tree/sha")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing `tree.sha` on `develop-agent` commit".to_string())?
            .to_string();
        let parents = commit
            .get("parents")
            .and_then(Value::as_array)
            .map_or(1, Vec::len);
        Some((sha, tree, parents))
    } else {
        None
    };

    let borrowed = dev_info
        .as_ref()
        .map(|(s, t, p)| (s.as_str(), t.as_str(), *p));
    match decide_develop_agent_alignment(main_sha, main_tree, status, borrowed) {
        RefAlignAction::AlreadyAligned => Ok(()),
        RefAlignAction::CreateAtMain => run_gh_api(
            "POST",
            &format!("{base}/git/refs"),
            Some(&json!({ "ref": "refs/heads/develop-agent", "sha": main_sha })),
        ),
        RefAlignAction::LeaseAlignSameTreeRoot { expected_old_sha } => {
            lease_push_develop_agent(owner, repo, &expected_old_sha, main_sha)
        }
        RefAlignAction::FailClosed(reason) => {
            if dev_info.as_ref().is_some_and(|(_, _, p)| *p > 0)
                && let Ok((200, cmp)) =
                    gh_get_with_status(&format!("{base}/compare/main...develop-agent"))
                && cmp
                    .pointer("/merge_base_commit/sha")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            {
                return Ok(());
            }
            Err(reason)
        }
    }
}

fn reconcile_environment(base: &str, spec: &EnvironmentSpec) -> Result<(), String> {
    let env_ep = format!("{base}/environments/{}", spec.name);
    run_gh_api("PUT", &env_ep, Some(&spec.put_body))?;
    if spec.custom_branches.is_empty() {
        return Ok(());
    }
    let pol_ep = format!("{env_ep}/deployment-branch-policies");
    let existing = gh_paginated_items(&pol_ep, ".branch_policies[]")?;
    let mut seen_desired = BTreeSet::new();

    for item in &existing {
        let id = item.get("id").and_then(Value::as_u64);
        let name = item.get("name").and_then(Value::as_str).unwrap_or("");
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("branch");
        let keep = kind == "branch"
            && spec.custom_branches.iter().any(|b| b == name)
            && seen_desired.insert(name.to_string());
        if !keep && let Some(policy_id) = id {
            run_gh_api("DELETE", &format!("{pol_ep}/{policy_id}"), None)?;
        }
    }
    for branch in &spec.custom_branches {
        if !seen_desired.contains(branch) {
            run_gh_api(
                "POST",
                &pol_ep,
                Some(&json!({ "name": branch, "type": "branch" })),
            )?;
        }
    }
    Ok(())
}

fn reconcile_ruleset(base: &str, spec: &RulesetSpec, existing: &[Value]) -> Result<(), String> {
    let found_id = existing.iter().find_map(|item| {
        (item.get("name").and_then(Value::as_str) == Some(spec.name.as_str()))
            .then(|| item.get("id").and_then(Value::as_u64))
            .flatten()
    });
    match found_id {
        Some(id) => run_gh_api("PUT", &format!("{base}/rulesets/{id}"), Some(&spec.payload)),
        None => run_gh_api("POST", &format!("{base}/rulesets"), Some(&spec.payload)),
    }
}

fn verify_live_readback(
    base: &str,
    reviewer_id: u64,
    opts: &GithubSetupOptions,
    envs: &[EnvironmentSpec],
) -> Result<(), String> {
    let summaries = gh_paginated_items(&format!("{base}/rulesets"), ".[]")?;
    let mut detailed_rulesets = Vec::new();
    for item in &summaries {
        if let Some(id) = item.get("id").and_then(Value::as_u64) {
            detailed_rulesets.push(run_gh_json(&["api", &format!("{base}/rulesets/{id}")])?);
        }
    }
    let mut env_readbacks = Vec::with_capacity(envs.len());
    for spec in envs {
        let ep = format!("{base}/environments/{}", spec.name);
        let env_json = run_gh_json(&["api", &ep])?;
        let branch_policies = if spec.custom_branches.is_empty() {
            vec![]
        } else {
            gh_paginated_items(
                &format!("{ep}/deployment-branch-policies"),
                ".branch_policies[]",
            )?
        };
        env_readbacks.push(EnvReadback {
            name: spec.name.clone(),
            env_json,
            branch_policies,
        });
    }
    verify_readback_snapshot(reviewer_id, opts, &detailed_rulesets, &env_readbacks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h2_alignment_creates_on_404_leases_same_tree_root_and_fails_closed_otherwise() {
        assert_eq!(
            decide_develop_agent_alignment("m1", "t1", 404, None),
            RefAlignAction::CreateAtMain
        );
        assert!(matches!(
            decide_develop_agent_alignment("m1", "t1", 403, None),
            RefAlignAction::FailClosed(_)
        ));
        assert_eq!(
            decide_develop_agent_alignment("m1", "t1", 200, Some(("a1", "t1", 0))),
            RefAlignAction::LeaseAlignSameTreeRoot {
                expected_old_sha: "a1".into()
            }
        );
        assert!(matches!(
            decide_develop_agent_alignment("m1", "t1", 200, Some(("a1", "t_other", 0))),
            RefAlignAction::FailClosed(_)
        ));
        assert!(matches!(
            decide_develop_agent_alignment("m1", "t1", 200, Some(("a1", "t1", 1))),
            RefAlignAction::FailClosed(_)
        ));
    }
}
