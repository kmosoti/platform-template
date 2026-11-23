use crate::checks::is_forbidden_env_branch;

/// Evaluates compound shell pipelines, subshells, `$(...)`, env assignments,
/// `sh -c`/`bash -c` wrappers, and `git -C` global flags against governance policy.
pub fn evaluate_shell_command(command: &str) -> Result<(), String> {
    evaluate_shell_depth(command, 0)
}

fn evaluate_shell_depth(command: &str, depth: usize) -> Result<(), String> {
    if depth > 6 {
        return Err("excessive nested shell `-c` recursion; failing closed".to_string());
    }
    for sub in extract_command_substitutions(command) {
        evaluate_shell_depth(&sub, depth + 1)?;
    }
    for segment in split_compound_commands(command)? {
        check_command_tokens(&segment, depth)?;
    }
    Ok(())
}

fn split_compound_commands(input: &str) -> Result<Vec<Vec<String>>, String> {
    let mut commands = Vec::new();
    let mut current_cmd = Vec::new();
    let mut tok = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                tok.push(c);
            }
            continue;
        }
        if in_double {
            match c {
                '"' => in_double = false,
                '\\' => {
                    if let Some(next) = chars.next() {
                        tok.push(next);
                    }
                }
                _ => tok.push(c),
            }
            continue;
        }
        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => {
                if let Some(next) = chars.next() {
                    tok.push(next);
                }
            }
            ';' | '\n' | '(' | ')' => {
                flush_tok(&mut tok, &mut current_cmd);
                flush_cmd(&mut current_cmd, &mut commands);
            }
            '&' | '|' => {
                if chars.peek() == Some(&c) {
                    let _ = chars.next();
                }
                flush_tok(&mut tok, &mut current_cmd);
                flush_cmd(&mut current_cmd, &mut commands);
            }
            ws if ws.is_whitespace() => flush_tok(&mut tok, &mut current_cmd),
            other => tok.push(other),
        }
    }

    if in_single || in_double {
        return Err("unterminated quote in shell command; failing closed".to_string());
    }
    flush_tok(&mut tok, &mut current_cmd);
    flush_cmd(&mut current_cmd, &mut commands);
    Ok(commands)
}

fn extract_command_substitutions(input: &str) -> Vec<String> {
    let mut subs = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'(' {
            let mut depth = 1usize;
            let start = i + 2;
            let mut j = start;
            while j < bytes.len() && depth > 0 {
                if bytes[j] == b'(' {
                    depth += 1;
                } else if bytes[j] == b')' {
                    depth -= 1;
                }
                j += 1;
            }
            if depth == 0 && j > start {
                subs.push(input[start..j - 1].to_string());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    subs
}

fn flush_tok(tok: &mut String, current_cmd: &mut Vec<String>) {
    if !tok.is_empty() {
        current_cmd.push(std::mem::take(tok));
    }
}

fn flush_cmd(current_cmd: &mut Vec<String>, commands: &mut Vec<Vec<String>>) {
    if !current_cmd.is_empty() {
        commands.push(std::mem::take(current_cmd));
    }
}

fn is_env_assignment(s: &str) -> bool {
    let Some((lhs, _)) = s.split_once('=') else {
        return false;
    };
    !lhs.is_empty()
        && lhs.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !lhs.as_bytes()[0].is_ascii_digit()
}

fn check_command_tokens(raw_tokens: &[String], depth: usize) -> Result<(), String> {
    let mut idx = 0;
    while idx < raw_tokens.len() && is_env_assignment(&raw_tokens[idx]) {
        idx += 1;
    }
    while idx < raw_tokens.len() {
        let head = raw_tokens[idx]
            .rsplit('/')
            .next()
            .unwrap_or(&raw_tokens[idx]);
        if matches!(head, "env" | "command" | "nohup" | "sudo") {
            idx += 1;
            while idx < raw_tokens.len()
                && (raw_tokens[idx].starts_with('-') || is_env_assignment(&raw_tokens[idx]))
            {
                idx += 1;
            }
            continue;
        }
        break;
    }
    if idx >= raw_tokens.len() {
        return Ok(());
    }

    let tokens = &raw_tokens[idx..];
    let head = tokens[0].rsplit('/').next().unwrap_or(&tokens[0]);
    if matches!(head, "sh" | "bash" | "zsh" | "dash") {
        for w in 1..tokens.len() {
            if (tokens[w] == "-c" || tokens[w] == "-lc")
                && let Some(script) = tokens.get(w + 1)
            {
                evaluate_shell_depth(script, depth + 1)?;
            }
        }
    } else if head == "gh" {
        check_gh_command(&tokens[1..])?;
    } else if head == "git" {
        check_git_command(skip_git_global_flags(&tokens[1..]))?;
    }
    Ok(())
}

fn skip_git_global_flags(args: &[String]) -> &[String] {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" => i += 2,
            s if s.starts_with("--git-dir=")
                || s.starts_with("--work-tree=")
                || s == "--no-pager"
                || s == "-P" =>
            {
                i += 1;
            }
            _ => break,
        }
    }
    if i <= args.len() { &args[i..] } else { &[] }
}

fn check_gh_command(args: &[String]) -> Result<(), String> {
    let joined = args.join(" ");
    if joined.contains("pending_deployments")
        || joined.contains("environments/production")
        || joined.contains("environments/prod")
        || joined.contains("environments/staging")
        || joined.contains("environments/main-release")
        || joined.contains("/rulesets")
    {
        return Err(
            "agents may never approve deployments or mutate protected GitHub Environments/Rulesets"
                .to_string(),
        );
    }

    if args.len() >= 2 && args[0] == "pr" && args[1] == "merge" {
        if args.iter().any(|a| a == "--admin" || a == "--merge") {
            return Err(
                "`gh pr merge` onto `develop-agent` must use `--rebase` or `--squash` (never `--admin`/`--merge`)"
                    .to_string(),
            );
        }
        if !args
            .iter()
            .any(|a| matches!(a.as_str(), "--rebase" | "-r" | "--squash" | "-s"))
        {
            return Err(
                "`gh pr merge` requires `--rebase` or `--squash` onto `develop-agent`".to_string(),
            );
        }
        if args.iter().any(|a| a == "main" || a.ends_with("/main")) {
            return Err(
                "agents cannot merge PRs targeting `main`; human approval required via `main-release`"
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn check_git_command(args: &[String]) -> Result<(), String> {
    let Some(sub) = args.first().map(String::as_str) else {
        return Ok(());
    };
    match sub {
        "checkout" | "switch" => {
            for i in 1..args.len() {
                if matches!(args[i].as_str(), "-b" | "-B" | "-c" | "-C" | "--create")
                    && let Some(branch) = args.get(i + 1)
                    && is_forbidden_env_branch(branch)
                {
                    return Err(format!(
                        "creating environment branch `{branch}` is forbidden; domains live under `domains/`"
                    ));
                }
            }
        }
        "branch" => {
            for arg in &args[1..] {
                if !arg.starts_with('-') && is_forbidden_env_branch(arg) {
                    return Err(format!(
                        "creating environment branch `{arg}` is forbidden; use `domains/{arg}/` on trunk"
                    ));
                }
            }
        }
        "push" => {
            let has_force = args
                .iter()
                .any(|a| a == "-f" || a == "--force" || a.starts_with("--force-with-lease"));
            for arg in &args[1..] {
                if arg.starts_with('-') {
                    continue;
                }
                let dst = arg.rsplit(':').next().unwrap_or(arg);
                let clean = dst.strip_prefix("refs/heads/").unwrap_or(dst);
                if is_forbidden_env_branch(clean) {
                    return Err(format!("pushing environment branch `{clean}` is forbidden"));
                }
                if clean == "main" {
                    return Err(
                        "direct `git push` to `main` is forbidden; open a PR via `develop-agent`"
                            .to_string(),
                    );
                }
                if has_force && clean == "develop-agent" {
                    return Err("force-pushing `develop-agent` is forbidden".to_string());
                }
            }
        }
        _ => {}
    }
    Ok(())
}
