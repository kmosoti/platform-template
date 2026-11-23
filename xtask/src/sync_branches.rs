use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchSyncRelation {
    ExactMatch { sha: String },
    PromotedAncestor { agent_sha: String, main_sha: String },
    AgentAheadOfPromotedBase { main_sha: String, agent_sha: String },
    NonAncestorSameTree { main_sha: String, agent_sha: String },
    MainHasUnbackportedChanges { main_sha: String, agent_sha: String },
    MissingAgentBranch { main_sha: String },
}

pub fn classify_branch_topology(root: &Path) -> Result<BranchSyncRelation, String> {
    let main_ref =
        resolve_ref(root, "refs/heads/main", "refs/remotes/origin/main").unwrap_or("HEAD");
    let main_sha = git_stdout(root, &["rev-parse", main_ref])?;

    let Some(dev_ref) = resolve_ref(
        root,
        "refs/heads/develop-agent",
        "refs/remotes/origin/develop-agent",
    ) else {
        return Ok(BranchSyncRelation::MissingAgentBranch { main_sha });
    };
    let agent_sha = git_stdout(root, &["rev-parse", dev_ref])?;

    if main_sha == agent_sha {
        return Ok(BranchSyncRelation::ExactMatch { sha: main_sha });
    }

    let main_tree = git_stdout(root, &["rev-parse", &format!("{main_sha}^{{tree}}")])?;
    let agent_tree = git_stdout(root, &["rev-parse", &format!("{agent_sha}^{{tree}}")])?;
    let non_merges = git_stdout(
        root,
        &[
            "rev-list",
            "--no-merges",
            &format!("{agent_sha}..{main_sha}"),
        ],
    )?;

    if !non_merges.is_empty() {
        if main_tree == agent_tree {
            return Ok(BranchSyncRelation::NonAncestorSameTree {
                main_sha,
                agent_sha,
            });
        }
        return Ok(BranchSyncRelation::MainHasUnbackportedChanges {
            main_sha,
            agent_sha,
        });
    }

    if git_ok(
        root,
        &["merge-base", "--is-ancestor", &agent_sha, &main_sha],
    ) && main_tree == agent_tree
    {
        return Ok(BranchSyncRelation::PromotedAncestor {
            agent_sha,
            main_sha,
        });
    }
    if git_ok(
        root,
        &["merge-base", "--is-ancestor", &main_sha, &agent_sha],
    ) {
        return Ok(BranchSyncRelation::AgentAheadOfPromotedBase {
            main_sha,
            agent_sha,
        });
    }
    if let Ok(base) = git_stdout(root, &["merge-base", &main_sha, &agent_sha]) {
        let base_tree = git_stdout(root, &["rev-parse", &format!("{base}^{{tree}}")])?;
        if main_tree == base_tree {
            return Ok(BranchSyncRelation::AgentAheadOfPromotedBase {
                main_sha,
                agent_sha,
            });
        }
    }

    Ok(BranchSyncRelation::MainHasUnbackportedChanges {
        main_sha,
        agent_sha,
    })
}

pub fn cmd_sync_branches(root: &Path, apply: bool) -> Result<(), String> {
    let relation = classify_branch_topology(root)?;
    println!("[sync-branches] apply={apply} relation={relation:?}");

    match relation {
        BranchSyncRelation::ExactMatch { .. }
        | BranchSyncRelation::AgentAheadOfPromotedBase { .. } => Ok(()),
        BranchSyncRelation::PromotedAncestor { ref main_sha, .. } => {
            if apply {
                update_local_develop_agent(root, main_sha)?;
            }
            Ok(())
        }
        BranchSyncRelation::MissingAgentBranch { ref main_sha } => {
            if apply {
                git_run(root, &["branch", "develop-agent", main_sha])?;
                Ok(())
            } else {
                Err("`develop-agent` branch is missing; create it from `main` via `sync-branches --apply` or `github-setup`".into())
            }
        }
        BranchSyncRelation::NonAncestorSameTree { .. } => Err(
            "`main` and `develop-agent` have identical trees without Git ancestry (likely a squash/rebase onto `main`); promotions to `main` must use merge commits"
                .into(),
        ),
        BranchSyncRelation::MainHasUnbackportedChanges { .. } => Err(
            "`main` contains changes not present in `develop-agent`; open a backport PR onto `develop-agent`"
                .into(),
        ),
    }
}

fn resolve_ref<'a>(root: &Path, local: &'a str, remote: &'a str) -> Option<&'a str> {
    if git_ok(root, &["show-ref", "--verify", "--quiet", local]) {
        Some(local)
    } else if git_ok(root, &["show-ref", "--verify", "--quiet", remote]) {
        Some(remote)
    } else {
        None
    }
}

fn update_local_develop_agent(root: &Path, target_sha: &str) -> Result<(), String> {
    let current =
        git_stdout(root, &["symbolic-ref", "--quiet", "--short", "HEAD"]).unwrap_or_default();
    if current == "develop-agent" {
        git_run(root, &["merge", "--ff-only", target_sha])
    } else {
        git_run(root, &["branch", "-f", "develop-agent", target_sha])
    }
}

fn git_ok(root: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed spawning `git {}`: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn git_run(root: &Path, args: &[&str]) -> Result<(), String> {
    let _ = git_stdout(root, args)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_repo(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("platform-h1-{label}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        git_run(&dir, &["init", "-b", "main"]).unwrap();
        git_run(&dir, &["config", "user.name", "Test Bot"]).unwrap();
        git_run(&dir, &["config", "user.email", "bot@example.internal"]).unwrap();
        fs::write(dir.join("f.txt"), "v0\n").unwrap();
        git_run(&dir, &["add", "."]).unwrap();
        git_run(&dir, &["commit", "-m", "init"]).unwrap();
        git_run(&dir, &["branch", "develop-agent"]).unwrap();
        dir
    }

    #[test]
    fn tests_all_four_h1_branch_topology_graphs() {
        // Graph 1: ExactMatch -> PromotedAncestor via --no-ff merge onto main
        let g1 = make_repo("promoted");
        assert!(matches!(
            classify_branch_topology(&g1).unwrap(),
            BranchSyncRelation::ExactMatch { .. }
        ));
        git_run(&g1, &["checkout", "develop-agent"]).unwrap();
        fs::write(g1.join("f.txt"), "v1\n").unwrap();
        git_run(&g1, &["commit", "-am", "agent v1"]).unwrap();
        git_run(&g1, &["checkout", "main"]).unwrap();
        git_run(
            &g1,
            &["merge", "--no-ff", "develop-agent", "-m", "promote v1"],
        )
        .unwrap();
        assert!(cmd_sync_branches(&g1, false).is_ok());
        assert!(matches!(
            classify_branch_topology(&g1).unwrap(),
            BranchSyncRelation::PromotedAncestor { .. }
        ));

        // Graph 2: AgentAheadOfPromotedBase (agent adds v2 on develop-agent after M1 --no-ff promotion)
        git_run(&g1, &["checkout", "develop-agent"]).unwrap();
        fs::write(g1.join("f.txt"), "v2\n").unwrap();
        git_run(&g1, &["commit", "-am", "agent v2"]).unwrap();
        assert!(cmd_sync_branches(&g1, false).is_ok());
        assert!(matches!(
            classify_branch_topology(&g1).unwrap(),
            BranchSyncRelation::AgentAheadOfPromotedBase { .. }
        ));
        let _ = fs::remove_dir_all(&g1);

        // Graph 3: NonAncestorSameTree (squash-merge onto main breaks ancestry -> FAIL)
        let g3 = make_repo("squash");
        git_run(&g3, &["checkout", "develop-agent"]).unwrap();
        fs::write(g3.join("f.txt"), "squash\n").unwrap();
        git_run(&g3, &["commit", "-am", "agent commit"]).unwrap();
        git_run(&g3, &["checkout", "main"]).unwrap();
        git_run(&g3, &["merge", "--squash", "develop-agent"]).unwrap();
        git_run(&g3, &["commit", "-m", "squashed onto main"]).unwrap();
        assert!(matches!(
            classify_branch_topology(&g3).unwrap(),
            BranchSyncRelation::NonAncestorSameTree { .. }
        ));
        assert!(cmd_sync_branches(&g3, false).is_err());
        let _ = fs::remove_dir_all(&g3);

        // Graph 4: MainHasUnbackportedChanges (direct hotfix on main -> FAIL)
        let g4 = make_repo("hotfix");
        fs::write(g4.join("hotfix.txt"), "urgent\n").unwrap();
        git_run(&g4, &["add", "."]).unwrap();
        git_run(&g4, &["commit", "-m", "hotfix on main"]).unwrap();
        assert!(matches!(
            classify_branch_topology(&g4).unwrap(),
            BranchSyncRelation::MainHasUnbackportedChanges { .. }
        ));
        assert!(cmd_sync_branches(&g4, false).is_err());
        let _ = fs::remove_dir_all(&g4);
    }
}
