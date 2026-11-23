use std::fs;
use std::path::Path;

use crate::checks::collect_repo_files;

const TOKEN_PREFIXES: &[(&str, &str)] = &[
    ("github_classic_pat", "ghp_"),
    ("github_fine_pat", "github_pat_"),
    ("github_oauth_token", "gho_"),
    ("aws_access_key_id", "AKIA"),
    ("slack_bot_token", "xoxb-"),
    ("api_live_key", "sk-live-"),
];

pub fn scan_text_for_leaks(rel_path: &str, text: &str) -> Result<(), String> {
    // Allow token prefix documentation inside privacy/scope modules themselves
    let is_scanner_source = matches!(
        rel_path,
        "xtask/src/privacy.rs" | "crates/platform-kernel/src/scope.rs"
    );

    if is_scanner_source {
        return Ok(());
    }

    for (idx, line) in text.lines().enumerate() {
        let line_no = idx + 1;
        if has_workstation_user_dir(line) {
            return Err(format!(
                "`{rel_path}`:{line_no} contains absolute workstation user directory path"
            ));
        }
        if line.trim_start().starts_with("-----BEGIN ")
            && line.trim_end().ends_with("PRIVATE KEY-----")
        {
            return Err(format!(
                "`{rel_path}`:{line_no} contains PEM private key header"
            ));
        }
        if has_embedded_url_credentials(line) {
            return Err(format!(
                "`{rel_path}`:{line_no} contains embedded basic-auth URL credentials"
            ));
        }
        for &(label, prefix) in TOKEN_PREFIXES {
            if has_populated_token(line, prefix) {
                return Err(format!(
                    "`{rel_path}`:{line_no} triggered credential hygiene check `{label}`"
                ));
            }
        }
    }
    Ok(())
}

fn has_workstation_user_dir(line: &str) -> bool {
    if line.contains(":\\Users\\") || line.contains(":/Users/") {
        return true;
    }
    for (pos, _) in line.match_indices('/') {
        let tail = &line[pos + 1..];
        for root_dir in ["Users/", "home/"] {
            if let Some(after) = tail.strip_prefix(root_dir) {
                let prev_ok = pos == 0
                    || !line.as_bytes()[pos - 1].is_ascii_alphanumeric()
                        && line.as_bytes()[pos - 1] != b'_';
                let user_seg = after.split('/').next().unwrap_or("");
                if prev_ok
                    && !user_seg.is_empty()
                    && after.contains('/')
                    && user_seg
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return true;
                }
            }
        }
    }
    false
}

fn has_embedded_url_credentials(line: &str) -> bool {
    for scheme in ["https://", "http://"] {
        for (pos, _) in line.match_indices(scheme) {
            let after = &line[pos + scheme.len()..];
            let authority = after.split(['/', ' ', '"', '\'', ')']).next().unwrap_or("");
            if let Some((userinfo, host)) = authority.split_once('@')
                && userinfo.contains(':')
                && !host.is_empty()
            {
                return true;
            }
        }
    }
    false
}

fn has_populated_token(line: &str, prefix: &str) -> bool {
    for (pos, _) in line.match_indices(prefix) {
        let rest = &line[pos + prefix.len()..];
        let token_chars = rest
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count();
        if token_chars >= 8 {
            return true;
        }
    }
    false
}

pub fn check_privacy(root: &Path) -> Result<String, String> {
    let files = collect_repo_files(root)?;
    let mut scanned = 0usize;
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path).map_err(|e| format!("failed reading `{rel}`: {e}"))?;
        if let Ok(text) = std::str::from_utf8(&bytes) {
            scan_text_for_leaks(&rel, text)?;
            scanned += 1;
        }
    }
    Ok(format!(
        "scanned {scanned} repository files with structural path & credential hygiene checks"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_scanner_catches_workstation_paths_pem_keys_and_url_creds() {
        assert!(scan_text_for_leaks("LICENSE-MIT", "Copyright (c) 2026 Kennedy Mosoti").is_ok());
        let win_path = "C:\\Users\\developer\\repo";
        assert!(scan_text_for_leaks("README.md", win_path).is_err());
        let url_cred = "endpoint = https://admin:secretpass@otel.example.internal";
        assert!(scan_text_for_leaks("config.toml", url_cred).is_err());
        let pem = format!("{}RSA {}", "-----BEGIN ", "PRIVATE KEY-----");
        assert!(scan_text_for_leaks("key.txt", &pem).is_err());
    }
}
