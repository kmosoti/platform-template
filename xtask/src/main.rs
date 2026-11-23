#![forbid(unsafe_code)]

mod agent_sync;
mod archive_verify;
mod atomic_io;
mod checks;
mod cli_args;
mod fingerprint;
mod fixture_sign;
mod gh_http;
mod github;
mod github_plan;
mod github_verify;
mod hooks;
mod hooks_shell;
mod import_release;
mod ops;
mod privacy;
mod promote;
mod sync_branches;
mod verify;

use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask crate must live under workspace root")
        .to_path_buf()
}

pub(crate) fn usage() -> &'static str {
    "Usage:
  cargo xtask verify [--force]
  cargo xtask simulate --domain <dev|staging|prod|all> [--mode <simulate|live>] [--out <path>] [--observations-dir <dir>] [--trust-root <file>] [--ledger-file <file>] [--trusted-checkpoint <file>] [--oidc-claims-file <file>] [--oidc-audience <aud>] [--oidc-repo <owner/repo>] [--oidc-repo-id <id>] [--now-epoch-s <u64>]
  cargo xtask promote --domain <dev|staging|prod> --engine-digest <sha256:...> [--dry-run]
  cargo xtask import-service-release <manifest.json> --archive <archive.tar.gz> [--provenance-verified --provenance-digest <sha256:...>]
  cargo xtask seed-demo-fixtures [--manifest <manifest.json> --archive <archive.tar.gz>]
  cargo xtask sync-branches [--check | --apply]
  cargo xtask hook pre-tool-use --format <antigravity|claude|codex|copilot>
  cargo xtask github-setup <OWNER/REPO> [--dry-run] [--main-pr-approvals <N>] [--require-codeowners] [--prevent-self-review]"
}

fn run() -> Result<(), String> {
    let root = workspace_root();
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(sub) = args.first().map(String::as_str) else {
        return Err(usage().to_string());
    };

    match sub {
        "verify" => {
            let mut force = false;
            for arg in &args[1..] {
                match arg.as_str() {
                    "--force" => force = true,
                    other => return Err(format!("unknown verify flag `{other}`\n\n{}", usage())),
                }
            }
            verify::cmd_verify(&root, force)
        }
        "simulate" => cli_args::parse_and_run_simulate(&root, &args[1..]),
        "promote" => cli_args::parse_and_run_promote(&root, &args[1..]),
        "import-service-release" => cli_args::parse_and_run_import(&root, &args[1..]),
        "seed-demo-fixtures" => cli_args::parse_and_run_seed(&root, &args[1..]),
        "sync-branches" => {
            let mut apply = false;
            for arg in &args[1..] {
                match arg.as_str() {
                    "--check" => apply = false,
                    "--apply" => apply = true,
                    other => {
                        return Err(format!(
                            "unknown sync-branches flag `{other}`\n\n{}",
                            usage()
                        ));
                    }
                }
            }
            sync_branches::cmd_sync_branches(&root, apply)
        }
        "hook" => {
            if args.get(1).map(String::as_str) != Some("pre-tool-use") {
                return Err(format!("expected `hook pre-tool-use`\n\n{}", usage()));
            }
            let mut format = None;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--format" => {
                        i += 1;
                        let raw = args.get(i).ok_or("missing value after `--format`")?;
                        format = Some(hooks::HookFormat::parse(raw)?);
                    }
                    other => return Err(format!("unknown hook flag `{other}`\n\n{}", usage())),
                }
                i += 1;
            }
            let fmt = format.ok_or_else(|| format!("missing `--format`\n\n{}", usage()))?;
            hooks::cmd_hook_pre_tool_use(fmt);
            Ok(())
        }
        "github-setup" => cli_args::parse_and_run_github_setup(&args[1..]),
        "--help" | "-h" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}`\n\n{}", usage())),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
