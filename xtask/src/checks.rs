use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const FORBIDDEN_ENV_BRANCHES: &[&str] =
    &["dev", "develop", "staging", "uat", "prod", "production"];

pub const MAX_RS_LINES: usize = 350;

pub fn is_forbidden_env_branch(branch: &str) -> bool {
    let trimmed = branch
        .strip_prefix("refs/heads/")
        .or_else(|| branch.strip_prefix("origin/"))
        .unwrap_or(branch);
    FORBIDDEN_ENV_BRANCHES.contains(&trimmed)
}

pub fn validate_git_ref_names(refs: &[String]) -> Result<(), String> {
    let mut bad = Vec::new();
    for r in refs {
        let name = if let Some(local) = r.strip_prefix("refs/heads/") {
            local
        } else if let Some(remote_rest) = r.strip_prefix("refs/remotes/") {
            remote_rest.split_once('/').map_or(remote_rest, |(_, b)| b)
        } else {
            r.as_str()
        };
        if FORBIDDEN_ENV_BRANCHES.contains(&name) {
            bad.push(r.clone());
        }
    }
    if !bad.is_empty() {
        return Err(format!(
            "forbidden environment branches detected ({}); concurrent domains live under `domains/`",
            bad.join(", ")
        ));
    }
    Ok(())
}

pub fn check_no_env_branches(root: &Path) -> Result<String, String> {
    let out = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads",
            "refs/remotes",
        ])
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed running git for-each-ref: {e}"))?;
    if !out.status.success() {
        return Err("git for-each-ref failed".to_string());
    }
    let refs: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();
    validate_git_ref_names(&refs)?;

    let codeowners = fs::read_to_string(root.join(".github/CODEOWNERS"))
        .map_err(|e| format!("missing `.github/CODEOWNERS`: {e}"))?;
    for line in codeowners.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && trimmed.contains("@example-org") {
            return Err(
                "`.github/CODEOWNERS` must not contain un-commented fake `@example-org` handles"
                    .to_string(),
            );
        }
    }

    Ok(format!(
        "checked {} git ref(s) + CODEOWNERS hygiene",
        refs.len()
    ))
}

pub fn check_knowledge(root: &Path) -> Result<String, String> {
    if !root.join("knowledge/README.md").is_file() {
        return Err("missing `knowledge/README.md`".to_string());
    }
    let required = [
        "knowledge/decisions/D-0001-concurrent-domains-not-branches.md",
        "knowledge/research/R-0001-state-inertia-and-expand-contract.md",
        "knowledge/observations/O-0001-three-domain-staggered-topology.md",
    ];
    for rel in required {
        let content = fs::read_to_string(root.join(rel))
            .map_err(|e| format!("missing required knowledge node `{rel}`: {e}"))?;
        validate_knowledge_frontmatter(root, rel, &content)?;
    }
    if !root.join("docs/architecture.md").is_file() {
        return Err("missing `docs/architecture.md`".to_string());
    }
    Ok(format!(
        "verified {} epistemic knowledge nodes + docs",
        required.len()
    ))
}

pub fn validate_knowledge_frontmatter(
    root: &Path,
    rel_path: &str,
    content: &str,
) -> Result<(), String> {
    let Some(rest) = content.strip_prefix("---\n") else {
        return Err(format!(
            "`{rel_path}` missing YAML frontmatter opening `---`"
        ));
    };
    let Some((frontmatter, _)) = rest.split_once("\n---\n") else {
        return Err(format!(
            "`{rel_path}` missing YAML frontmatter closing `---`"
        ));
    };
    for key in ["id:", "kind:", "added_by:", "human_ratified:", "links:"] {
        if !frontmatter.lines().any(|l| l.trim_start().starts_with(key)) {
            return Err(format!("`{rel_path}` frontmatter missing `{key}`"));
        }
    }
    for line in frontmatter.lines() {
        if let Some(link) = line.trim().strip_prefix("- ") {
            let clean = link.trim_matches(|c| c == '"' || c == '\'');
            if !root.join(clean).is_file() {
                return Err(format!("`{rel_path}` links to non-existent `{clean}`"));
            }
        }
    }
    Ok(())
}

pub fn check_workflow_pins(root: &Path) -> Result<String, String> {
    let wf_dir = root.join(".github/workflows");
    let required = [
        "ci.yml",
        "main-human-gate.yml",
        "sync-develop-agent.yml",
        "reconcile-domains.yml",
    ];
    let mut pin_count = 0usize;
    for name in required {
        let path = wf_dir.join(name);
        let content =
            fs::read_to_string(&path).map_err(|e| format!("missing workflow `{name}`: {e}"))?;
        pin_count += verify_workflow_uses_pins(name, &content)?;
    }
    Ok(format!(
        "verified {} workflow files ({pin_count} SHA-pinned `uses:` steps)",
        required.len()
    ))
}

pub fn verify_workflow_uses_pins(file_label: &str, yaml: &str) -> Result<usize, String> {
    let mut count = 0usize;
    for (idx, line) in yaml.lines().enumerate() {
        let code = line.split('#').next().unwrap_or("").trim();
        let rest = code
            .strip_prefix("uses:")
            .or_else(|| code.strip_prefix("- uses:"));
        let Some(spec) = rest.map(str::trim) else {
            continue;
        };
        let spec = spec.trim_matches(|c| c == '"' || c == '\'');
        if spec.starts_with("./") {
            continue;
        }
        let Some((_, rev)) = spec.split_once('@') else {
            return Err(format!(
                "`{file_label}`:{} unpinned `uses: {spec}`",
                idx + 1
            ));
        };
        let is_40_hex = rev.len() == 40
            && rev
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !is_40_hex {
            return Err(format!(
                "`{file_label}`:{} action `{spec}` must pin a 40-char lowercase commit SHA",
                idx + 1
            ));
        }
        count += 1;
    }
    Ok(count)
}

pub fn collect_repo_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    walk_dir(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_dir(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        let top = rel.components().next().and_then(|c| c.as_os_str().to_str());
        if matches!(top, Some(".git" | "target" | "evidence")) {
            continue;
        }
        if path.is_dir() {
            walk_dir(root, &path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

pub fn check_line_caps(root: &Path) -> Result<String, String> {
    let files = collect_repo_files(root)?;
    let mut rs_count = 0usize;
    let mut max_lines = 0usize;
    for path in files {
        let rel = path.strip_prefix(root).unwrap_or(&path);
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            if ext == "sh" || ext == "py" {
                return Err(format!("forbidden `.{ext}` script `{}`", rel.display()));
            }
            if ext == "rs" {
                let lines = fs::read_to_string(&path)
                    .map_err(|e| e.to_string())?
                    .lines()
                    .count();
                if lines > MAX_RS_LINES {
                    return Err(format!(
                        "`{}` has {lines} lines > {MAX_RS_LINES}",
                        rel.display()
                    ));
                }
                rs_count += 1;
                max_lines = max_lines.max(lines);
            }
        }
    }
    Ok(format!(
        "verified {rs_count} `.rs` files (max {max_lines} <= {MAX_RS_LINES} lines); zero `.sh`/`.py` files"
    ))
}
