use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

pub fn lease_push_develop_agent(
    owner: &str,
    repo: &str,
    expected_old_sha: &str,
    main_sha: &str,
) -> Result<(), String> {
    let remote = format!("https://github.com/{owner}/{repo}.git");
    let out = Command::new("git")
        .args([
            "push",
            &format!("--force-with-lease=refs/heads/develop-agent:{expected_old_sha}"),
            &remote,
            &format!("{main_sha}:refs/heads/develop-agent"),
        ])
        .output()
        .map_err(|e| format!("failed spawning `git push --force-with-lease`: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "atomic lease alignment of `develop-agent` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

pub fn gh_get_with_status(endpoint: &str) -> Result<(u16, Value), String> {
    let out = Command::new("gh")
        .args(["api", "-i", endpoint])
        .output()
        .map_err(|e| format!("failed invoking `gh api -i {endpoint}`: {e}"))?;
    let raw = String::from_utf8_lossy(&out.stdout);
    let status_line = raw.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("failed parsing HTTP status from `gh api -i {endpoint}`"))?;
    let body_str = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .map_or("", |(_, b)| b.trim());
    let body = serde_json::from_str(body_str).unwrap_or(Value::Null);
    Ok((code, body))
}

pub fn gh_paginated_items(endpoint: &str, jq_expr: &str) -> Result<Vec<Value>, String> {
    let out = Command::new("gh")
        .args(["api", "--paginate", endpoint, "--jq", jq_expr])
        .output()
        .map_err(|e| format!("failed spawning `gh api --paginate {endpoint}`: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`gh api --paginate {endpoint}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| e.to_string()))
        .collect()
}

pub fn run_gh_json(args: &[&str]) -> Result<Value, String> {
    let out = Command::new("gh")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "`gh {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())
}

pub fn run_gh_api(method: &str, endpoint: &str, body: Option<&Value>) -> Result<(), String> {
    let mut cmd = Command::new("gh");
    cmd.args(["api", "--method", method, endpoint]);
    if body.is_some() {
        cmd.args(["--input", "-"]);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let (Some(payload), Some(mut stdin)) = (body, child.stdin.take()) {
        stdin
            .write_all(&serde_json::to_vec(payload).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "`gh api {method} {endpoint}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}
