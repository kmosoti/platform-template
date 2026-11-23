use std::io::{self, Read};

use serde_json::{Value, json};

use crate::hooks_shell::evaluate_shell_command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFormat {
    Antigravity,
    Claude,
    Codex,
    Copilot,
}

impl HookFormat {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "antigravity" => Ok(Self::Antigravity),
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            "copilot" => Ok(Self::Copilot),
            other => Err(format!(
                "invalid hook format `{other}` (expected `antigravity`, `claude`, `codex`, or `copilot`)"
            )),
        }
    }
}

/// Reads stdin and ALWAYS exits 0, emitting a structured deny payload if stdin is empty/malformed.
pub fn cmd_hook_pre_tool_use(format: HookFormat) {
    let mut buf = String::new();
    let output = match io::stdin().read_to_string(&mut buf) {
        Ok(_) => handle_pre_tool_use_json(format, &buf),
        Err(e) => render_decision(format, Err(format!("failed reading hook stdin: {e}"))),
    };
    println!("{output}");
}

pub fn handle_pre_tool_use_json(format: HookFormat, raw_json: &str) -> String {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() {
        return render_decision(
            format,
            Err("empty PreToolUse hook payload; failing closed".to_string()),
        );
    }
    let Ok(payload) = serde_json::from_str::<Value>(trimmed) else {
        return render_decision(
            format,
            Err("malformed JSON in PreToolUse hook payload; failing closed".to_string()),
        );
    };

    let decision = match extract_shell_command(&payload) {
        CommandExtraction::ShellCommand(cmd) => evaluate_shell_command(&cmd),
        CommandExtraction::NonShellTool => Ok(()),
        CommandExtraction::MissingCommandOnShellTool => {
            Err("missing command field on shell tool invocation; failing closed".to_string())
        }
    };
    render_decision(format, decision)
}

enum CommandExtraction {
    ShellCommand(String),
    NonShellTool,
    MissingCommandOnShellTool,
}

fn extract_shell_command(payload: &Value) -> CommandExtraction {
    for ptr in [
        "/toolCall/args/CommandLine",
        "/toolCall/args/command",
        "/tool_input/command",
        "/tool_input/CommandLine",
        "/parameters/CommandLine",
        "/parameters/command",
        "/input/command",
        "/toolArgs/command",
        "/toolArgs/CommandLine",
        "/command",
    ] {
        if let Some(cmd) = payload.pointer(ptr).and_then(Value::as_str) {
            return CommandExtraction::ShellCommand(cmd.to_string());
        }
    }

    if let Some(raw_args) = payload.get("toolArgs").and_then(Value::as_str)
        && let Ok(inner) = serde_json::from_str::<Value>(raw_args)
    {
        for key in ["command", "CommandLine"] {
            if let Some(cmd) = inner.get(key).and_then(Value::as_str) {
                return CommandExtraction::ShellCommand(cmd.to_string());
            }
        }
    }

    let tool_name = ["/toolCall/name", "/tool_name", "/toolName", "/tool"]
        .iter()
        .find_map(|p| payload.pointer(p).and_then(Value::as_str));

    match tool_name {
        Some(name)
            if !matches!(
                name.to_ascii_lowercase().as_str(),
                "bash" | "sh" | "shell" | "run_command" | "exec_command" | "powershell"
            ) =>
        {
            CommandExtraction::NonShellTool
        }
        _ => CommandExtraction::MissingCommandOnShellTool,
    }
}

fn render_decision(format: HookFormat, decision: Result<(), String>) -> String {
    let response = match (format, decision) {
        (HookFormat::Antigravity, Ok(())) => json!({ "decision": "allow" }),
        (HookFormat::Antigravity, Err(reason)) => json!({
            "decision": "deny",
            "reason": reason
        }),
        // CRITICAL: Emit `{}` on neutral in Claude/Codex/Copilot (never `permissionDecision: "allow"`).
        // Both Claude Code and OpenAI Codex PreToolUse use nested `hookSpecificOutput.permissionDecision = "deny"`.
        (HookFormat::Claude | HookFormat::Codex, Ok(())) => json!({}),
        (HookFormat::Claude | HookFormat::Codex, Err(reason)) => json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason
            }
        }),
        (HookFormat::Copilot, Ok(())) => json!({}),
        (HookFormat::Copilot, Err(reason)) => json!({
            "permissionDecision": "deny",
            "permissionDecisionReason": reason
        }),
    };
    serde_json::to_string(&response).expect("hook response serialization cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_formats_deny_violations_with_exact_host_schemas_and_neutral_allow() {
        let ag_bad = r#"{"toolCall":{"name":"run_command","args":{"CommandLine":"git -C /tmp checkout -b prod"}}}"#;
        let ag_res: Value =
            serde_json::from_str(&handle_pre_tool_use_json(HookFormat::Antigravity, ag_bad))
                .unwrap();
        assert_eq!(ag_res["decision"], "deny");

        let neutral =
            r#"{"tool_name":"Bash","tool_input":{"command":"cargo xtask simulate --domain all"}}"#;
        for fmt in [HookFormat::Claude, HookFormat::Codex, HookFormat::Copilot] {
            assert_eq!(handle_pre_tool_use_json(fmt, neutral), "{}");
        }

        let codex_bad =
            r#"{"tool_name":"Bash","tool_input":{"command":"FOO=1 git push origin main"}}"#;
        let cx_res: Value =
            serde_json::from_str(&handle_pre_tool_use_json(HookFormat::Codex, codex_bad)).unwrap();
        assert_eq!(cx_res["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(cx_res["hookSpecificOutput"]["permissionDecision"], "deny");

        let copilot_bad =
            r#"{"toolName":"bash","toolArgs":"{\"command\":\"git switch -c staging\"}"}"#;
        let cp_res: Value =
            serde_json::from_str(&handle_pre_tool_use_json(HookFormat::Copilot, copilot_bad))
                .unwrap();
        assert_eq!(cp_res["permissionDecision"], "deny");
    }

    #[test]
    fn malformed_or_empty_hook_json_fails_closed() {
        for fmt in [
            HookFormat::Antigravity,
            HookFormat::Claude,
            HookFormat::Codex,
            HookFormat::Copilot,
        ] {
            assert!(handle_pre_tool_use_json(fmt, "{bad").contains("deny"));
            assert!(handle_pre_tool_use_json(fmt, "").contains("deny"));
        }
    }
}
