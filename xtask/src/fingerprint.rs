use std::fs;
use std::path::Path;
use std::process::Command;

use platform_kernel::{encode_hex, sha256_prefixed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputFingerprint {
    pub head_commit: String,
    pub tree_hash: String,
    pub git_refs_sha256: String,
    pub worktree_dirty: bool,
    pub cargo_lock_sha256: String,
    pub toolchain_sha256: String,
    pub rustc_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationFingerprint {
    pub input: InputFingerprint,
    pub reconcile_plan_sha256: String,
}

fn git_capture_or(root: &Path, args: &[&str], fallback: &str) -> String {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| fallback.to_string())
}

pub fn compute_input_fingerprint(root: &Path) -> Result<InputFingerprint, String> {
    let head_commit = git_capture_or(root, &["rev-parse", "HEAD"], "unborn");
    let head_tree = git_capture_or(root, &["rev-parse", "HEAD^{tree}"], "unborn-tree");

    // M4: Include sorted local + remote branch refs in InputFingerprint so adding/deleting
    // any branch ref (e.g., `git branch prod`) invalidates cached receipts immediately.
    let refs_out = Command::new("git")
        .args([
            "for-each-ref",
            "--sort=refname",
            "--format=%(refname) %(objectname)",
            "refs/heads",
            "refs/remotes",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed running git for-each-ref: {e}"))?;
    let mut ref_lines: Vec<String> = String::from_utf8_lossy(&refs_out.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(ToString::to_string)
        .collect();
    ref_lines.sort();
    let git_refs_sha256 = sha256_prefixed(ref_lines.join("\n").as_bytes());

    let porcelain_out = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed running git status: {e}"))?;
    let porcelain = String::from_utf8_lossy(&porcelain_out.stdout).to_string();
    let worktree_dirty = !porcelain.trim().is_empty() || head_commit == "unborn";

    let tree_hash = if worktree_dirty {
        let mut hasher = Sha256::new();
        hasher.update(head_tree.as_bytes());
        hasher.update(b"\n");
        let mut lines: Vec<&str> = porcelain.lines().collect();
        lines.sort_unstable();
        for line in lines {
            hasher.update(line.as_bytes());
            hasher.update(b"\n");
            if line.len() > 3 {
                let rel = line[3..].split(" -> ").last().unwrap_or(&line[3..]);
                if let Ok(bytes) = fs::read(root.join(rel)) {
                    hasher.update(sha256_prefixed(&bytes).as_bytes());
                    hasher.update(b"\n");
                }
            }
        }
        format!("dirty:{}", encode_hex(&hasher.finalize()))
    } else {
        head_tree
    };

    let read_sha = |p: &str| {
        fs::read(root.join(p))
            .map(|b| sha256_prefixed(&b))
            .map_err(|e| format!("missing `{p}`: {e}"))
    };
    let rustc_out = Command::new("rustc")
        .arg("--version")
        .current_dir(root)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(InputFingerprint {
        head_commit,
        tree_hash,
        git_refs_sha256,
        worktree_dirty,
        cargo_lock_sha256: read_sha("Cargo.lock")?,
        toolchain_sha256: read_sha("rust-toolchain.toml")?,
        rustc_version: String::from_utf8_lossy(&rustc_out.stdout)
            .trim()
            .to_string(),
    })
}
