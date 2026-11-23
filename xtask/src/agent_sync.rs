use std::fs;
use std::path::Path;

use serde_json::Value;

const REQUIRED_SKILLS: &[&str] = &[
    "evidence-seeker",
    "idempotent-workflow",
    "tuple-promotion-and-compat",
];

const REQUIRED_AGENTS: &[&str] = &["adversarial-breaker", "stack-reviewer"];

const ALLOWED_PLUGIN_KEYS: &[&str] = &[
    "name",
    "displayName",
    "version",
    "description",
    "suggestedPrompts",
];

pub fn check_agent_configs(root: &Path) -> Result<String, String> {
    for doc in [
        "AGENTS.md",
        "CLAUDE.md",
        "SECURITY.md",
        ".github/copilot-instructions.md",
    ] {
        let text =
            fs::read_to_string(root.join(doc)).map_err(|e| format!("missing `{doc}`: {e}"))?;
        if !text.contains("develop-agent") || !text.contains("secretref://") {
            return Err(format!(
                "`{doc}` must document `develop-agent` isolation and `secretref://` envelopes"
            ));
        }
    }

    for skill in REQUIRED_SKILLS {
        for base in [".agents/skills", ".claude/skills"] {
            let rel = format!("{base}/{skill}/SKILL.md");
            let text = fs::read_to_string(root.join(&rel))
                .map_err(|e| format!("missing skill `{rel}`: {e}"))?;
            let expected_name = format!("name: {skill}");
            if !text.contains(&expected_name) {
                return Err(format!("`{rel}` missing frontmatter `{expected_name}`"));
            }
        }
    }

    validate_plugin_manifest(
        ".agents/plugin.json",
        &root.join(".agents/plugin.json"),
        "platform-template-workspace",
    )?;
    validate_plugin_manifest(
        ".agents/plugins/platform-forge/plugin.json",
        &root.join(".agents/plugins/platform-forge/plugin.json"),
        "platform-forge",
    )?;
    if root
        .join(".agents/plugins/platform-forge/hooks.json")
        .exists()
    {
        return Err(
            "duplicate `.agents/plugins/platform-forge/hooks.json` must not exist; keep single `.agents/hooks.json`"
                .to_string(),
        );
    }

    validate_antigravity_hooks(".agents/hooks.json", &root.join(".agents/hooks.json"))?;
    validate_claude_hooks(&root.join(".claude/settings.json"))?;
    validate_codex_hooks(&root.join(".codex/hooks.json"))?;
    validate_copilot_hooks(&root.join(".github/hooks/forge-guard.json"))?;

    for agent in REQUIRED_AGENTS {
        let ag_agent = format!(".agents/plugins/platform-forge/agents/{agent}.md");
        let cl_agent = format!(".claude/agents/{agent}.md");
        let cx_agent = format!(".codex/agents/{agent}.toml");
        for rel in [&ag_agent, &cl_agent, &cx_agent] {
            let text = fs::read_to_string(root.join(rel))
                .map_err(|e| format!("missing agent config `{rel}`: {e}"))?;
            if !text.contains(agent) {
                return Err(format!("`{rel}` must declare `{agent}`"));
            }
        }
    }

    Ok(format!(
        "verified 4-host hooks (antigravity/claude/codex/copilot), {} skills, and {} personas",
        REQUIRED_SKILLS.len(),
        REQUIRED_AGENTS.len()
    ))
}

fn validate_plugin_manifest(
    rel_label: &str,
    path: &Path,
    expected_name: &str,
) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("missing `{rel_label}`: {e}"))?;
    let val: Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid JSON in `{rel_label}`: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| format!("`{rel_label}` must be a JSON object"))?;

    if obj.get("name").and_then(Value::as_str) != Some(expected_name) {
        return Err(format!(
            "`{rel_label}` must declare `\"name\": \"{expected_name}\"`"
        ));
    }
    for key in obj.keys() {
        if !ALLOWED_PLUGIN_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "`{rel_label}` contains disallowed top-level key `{key}`"
            ));
        }
    }
    Ok(())
}

fn validate_antigravity_hooks(rel_label: &str, path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("missing `{rel_label}`: {e}"))?;
    let val: Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid JSON in `{rel_label}`: {e}"))?;
    let root_obj = val
        .as_object()
        .ok_or_else(|| format!("`{rel_label}` must be a JSON object"))?;
    if root_obj.is_empty() || root_obj.contains_key("hooks") {
        return Err(format!(
            "`{rel_label}` must group events under a named hook key"
        ));
    }
    let matched = root_obj.values().any(|events| {
        events
            .get("PreToolUse")
            .and_then(Value::as_array)
            .is_some_and(|pre_list| {
                pre_list.iter().any(|entry| {
                    entry.get("matcher").and_then(Value::as_str) == Some("run_command")
                        && entry
                            .get("hooks")
                            .and_then(Value::as_array)
                            .is_some_and(|arr| {
                                arr.iter().any(|h| {
                                    let cmd =
                                        h.get("command").and_then(Value::as_str).unwrap_or("");
                                    cmd.contains("--manifest-path ../Cargo.toml")
                                        && cmd.contains("hook pre-tool-use --format antigravity")
                                })
                            })
                })
            })
    });
    if !matched {
        return Err(format!(
            "`{rel_label}` missing valid `run_command` antigravity hook"
        ));
    }
    Ok(())
}

fn validate_claude_hooks(path: &Path) -> Result<(), String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("missing `.claude/settings.json`: {e}"))?;
    let _: Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid `.claude/settings.json`: {e}"))?;
    if !raw.contains("${CLAUDE_PROJECT_DIR:-.}/Cargo.toml") || !raw.contains("--format claude") {
        return Err("`.claude/settings.json` must use `${CLAUDE_PROJECT_DIR:-.}/Cargo.toml` and `--format claude`".into());
    }
    Ok(())
}

fn validate_codex_hooks(path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("missing `.codex/hooks.json`: {e}"))?;
    let _: Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid `.codex/hooks.json`: {e}"))?;
    let expected = "cargo run --quiet --package xtask -- hook pre-tool-use --format codex";
    if raw.contains("CODEX_PROJECT_DIR") || !raw.contains(expected) {
        return Err(format!(
            "`.codex/hooks.json` must use `{expected}` without CODEX_PROJECT_DIR"
        ));
    }
    Ok(())
}

fn validate_copilot_hooks(path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("missing `.github/hooks/forge-guard.json`: {e}"))?;
    let val: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid `.github/hooks/forge-guard.json`: {e}"))?;
    let expected = "cargo run --quiet --package xtask -- hook pre-tool-use --format copilot";
    let ok = val.pointer("/hooks/preToolUse/0").is_some_and(|entry| {
        entry.get("cwd").and_then(Value::as_str) == Some(".")
            && entry.get("bash").and_then(Value::as_str) == Some(expected)
            && entry.get("powershell").and_then(Value::as_str) == Some(expected)
    });
    if !ok {
        return Err("`.github/hooks/forge-guard.json` must set `cwd: \".\"` and matching `bash` + `powershell` commands".into());
    }
    Ok(())
}
