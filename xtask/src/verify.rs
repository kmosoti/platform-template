use std::fs;
use std::path::Path;
use std::process::Command;

use platform_kernel::{DomainTier, sha256_prefixed};
use serde::{Deserialize, Serialize};

use crate::agent_sync::check_agent_configs;
use crate::atomic_io::{write_bytes_atomic, write_pretty_json_atomic};
use crate::checks::{check_knowledge, check_line_caps, check_no_env_branches, check_workflow_pins};
use crate::fingerprint::{InputFingerprint, VerificationFingerprint, compute_input_fingerprint};
use crate::ops::{SimOptions, evaluate_selected_domains};
use crate::privacy::check_privacy;

pub const EXPECTED_GATES: &[&str] = &[
    "rustfmt",
    "clippy",
    "tests",
    "check-domains",
    "check-no-env-branches",
    "check-knowledge",
    "check-workflow-pins",
    "check-agent-configs",
    "check-line-caps",
    "check-privacy",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReceipt {
    pub gate: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReceipt {
    pub schema_version: u32,
    pub status: String,
    pub fingerprint: VerificationFingerprint,
    pub gates: Vec<GateReceipt>,
}

pub fn can_reuse_cached_receipt(
    existing: &VerificationReceipt,
    current_input: &InputFingerprint,
    actual_plan_sha256: &str,
) -> bool {
    if existing.status != "passed"
        || current_input.worktree_dirty
        || existing.fingerprint.input.worktree_dirty
        || existing.fingerprint.input.tree_hash.starts_with("dirty:")
    {
        return false;
    }
    let gates_match = existing.gates.len() == EXPECTED_GATES.len()
        && existing
            .gates
            .iter()
            .zip(EXPECTED_GATES.iter())
            .all(|(g, &expected)| g.passed && g.gate == expected);

    gates_match
        && &existing.fingerprint.input == current_input
        && existing.fingerprint.reconcile_plan_sha256 == actual_plan_sha256
}

pub fn cmd_verify(root: &Path, force: bool) -> Result<(), String> {
    let evidence_dir = root.join("evidence");
    let verify_path = evidence_dir.join("verification.json");
    let plan_path = evidence_dir.join("reconcile-plan.json");

    let pre_input = compute_input_fingerprint(root)?;
    if !force
        && let Ok(plan_bytes) = fs::read(&plan_path)
        && let Ok(raw_receipt) = fs::read_to_string(&verify_path)
        && let Ok(existing) = serde_json::from_str::<VerificationReceipt>(&raw_receipt)
        && can_reuse_cached_receipt(&existing, &pre_input, &sha256_prefixed(&plan_bytes))
    {
        println!(
            "[idempotent cache hit] verification receipt matches commit={} tree={} ({})",
            &pre_input.head_commit[..12.min(pre_input.head_commit.len())],
            &pre_input.tree_hash[..12.min(pre_input.tree_hash.len())],
            pre_input.rustc_version
        );
        return Ok(());
    }

    let mut gates = Vec::new();
    let clippy_args = [
        "clippy",
        "--offline",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ];
    let test_args = ["test", "--offline", "--workspace", "--locked"];
    run_gate(&mut gates, "rustfmt", || {
        run_cargo(root, &["fmt", "--all", "--", "--check"])
    })?;
    run_gate(&mut gates, "clippy", || run_cargo(root, &clippy_args))?;
    run_gate(&mut gates, "tests", || run_cargo(root, &test_args))?;

    let mut reconcile_plan = None;
    run_gate(&mut gates, "check-domains", || {
        let plan = evaluate_selected_domains(root, &DomainTier::ALL, &SimOptions::default())?;
        if !plan.all_valid {
            return Err(format!("domain evaluation failed: {:?}", plan.domains));
        }
        let n = plan.domains.len();
        reconcile_plan = Some(plan);
        Ok(format!(
            "verified {n} concurrent failure domains + Ed25519 attestation ledger & checkpoint"
        ))
    })?;
    let reconcile_plan = reconcile_plan.expect("populated reconcile_plan");

    run_gate(&mut gates, "check-no-env-branches", || {
        check_no_env_branches(root)
    })?;
    run_gate(&mut gates, "check-knowledge", || check_knowledge(root))?;
    run_gate(&mut gates, "check-workflow-pins", || {
        check_workflow_pins(root)
    })?;
    run_gate(&mut gates, "check-agent-configs", || {
        check_agent_configs(root)
    })?;
    run_gate(&mut gates, "check-line-caps", || check_line_caps(root))?;
    run_gate(&mut gates, "check-privacy", || check_privacy(root))?;

    let plan_bytes = format!(
        "{}\n",
        serde_json::to_string_pretty(&reconcile_plan).map_err(|e| e.to_string())?
    )
    .into_bytes();
    let plan_sha256 = sha256_prefixed(&plan_bytes);
    write_bytes_atomic(&plan_path, &plan_bytes)?;

    let post_input = compute_input_fingerprint(root)?;
    if pre_input != post_input {
        return Err(
            "repository inputs or git refs mutated during `cargo xtask verify`".to_string(),
        );
    }

    let receipt = VerificationReceipt {
        schema_version: 3,
        status: "passed".to_string(),
        fingerprint: VerificationFingerprint {
            input: post_input,
            reconcile_plan_sha256: plan_sha256,
        },
        gates,
    };
    write_pretty_json_atomic(&verify_path, &receipt)?;

    println!(
        "[verify] all {} gates passed (dirty={}); wrote `evidence/verification.json` and `evidence/reconcile-plan.json`",
        receipt.gates.len(),
        receipt.fingerprint.input.worktree_dirty
    );
    Ok(())
}

fn run_gate<F>(gates: &mut Vec<GateReceipt>, name: &str, f: F) -> Result<(), String>
where
    F: FnOnce() -> Result<String, String>,
{
    println!("[verify] running gate `{name}`...");
    let detail = f().map_err(|err| format!("gate `{name}` failed: {err}"))?;
    println!("  -> ok: {detail}");
    gates.push(GateReceipt {
        gate: name.to_string(),
        passed: true,
        detail,
    });
    Ok(())
}

fn run_cargo(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed spawning `cargo {}`: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "`cargo {}` failed:\n{}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(format!("`cargo {}` succeeded", args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn creating_forbidden_branch_ref_changes_refs_digest_and_invalidates_cached_receipt() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("platform-m4-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        let git = |args: &[&str]| {
            assert!(
                Command::new("git")
                    .args(args)
                    .current_dir(&dir)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        git(&["init", "-b", "main"]);
        git(&["config", "user.name", "Test"]);
        git(&["config", "user.email", "t@example.internal"]);
        fs::write(dir.join("Cargo.lock"), "lock\n").unwrap();
        fs::write(dir.join("rust-toolchain.toml"), "tc\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-m", "init"]);

        let base_in = compute_input_fingerprint(&dir).unwrap();
        let gates = EXPECTED_GATES
            .iter()
            .map(|&g| GateReceipt {
                gate: g.into(),
                passed: true,
                detail: "ok".into(),
            })
            .collect();
        let receipt = VerificationReceipt {
            schema_version: 3,
            status: "passed".into(),
            fingerprint: VerificationFingerprint {
                input: base_in.clone(),
                reconcile_plan_sha256: "sha256:plan".into(),
            },
            gates,
        };
        assert!(can_reuse_cached_receipt(&receipt, &base_in, "sha256:plan"));

        // Creating `git branch prod` (clean worktree, same HEAD & tree!) MUST invalidate cache!
        git(&["branch", "prod"]);
        let after_branch_in = compute_input_fingerprint(&dir).unwrap();
        assert_ne!(base_in.git_refs_sha256, after_branch_in.git_refs_sha256);
        assert!(!can_reuse_cached_receipt(
            &receipt,
            &after_branch_in,
            "sha256:plan"
        ));

        let _ = fs::remove_dir_all(&dir);
    }
}
