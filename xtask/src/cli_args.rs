use std::path::{Path, PathBuf};

use platform_kernel::{EvalMode, ProvenanceStatus};

use crate::{fixture_sign, github, github_plan, import_release, ops, promote, usage};

pub fn parse_and_run_import(root: &Path, args: &[String]) -> Result<(), String> {
    let mut manifest = None;
    let mut archive = None;
    let mut prov_status = ProvenanceStatus::UnverifiedLocal;
    let mut prov_digest = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--archive" => {
                i += 1;
                archive = args.get(i).map(PathBuf::from);
            }
            "--provenance-verified" => prov_status = ProvenanceStatus::Verified,
            "--provenance-digest" => {
                i += 1;
                prov_digest = args.get(i).cloned();
            }
            s if !s.starts_with('-') && manifest.is_none() => manifest = Some(PathBuf::from(s)),
            other => {
                return Err(format!(
                    "unexpected import argument `{other}`\n\n{}",
                    usage()
                ));
            }
        }
        i += 1;
    }
    let manifest = manifest.ok_or_else(|| format!("missing `<manifest.json>`\n\n{}", usage()))?;
    let archive =
        archive.ok_or_else(|| format!("missing `--archive <archive.tar.gz>`\n\n{}", usage()))?;
    import_release::cmd_import_service_release(root, &manifest, &archive, prov_status, prov_digest)
}

pub fn parse_and_run_seed(root: &Path, args: &[String]) -> Result<(), String> {
    let mut manifest = None;
    let mut archive = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest" => {
                i += 1;
                manifest = args.get(i).map(PathBuf::from);
            }
            "--archive" => {
                i += 1;
                archive = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown seed-demo-fixtures flag `{other}`\n\n{}",
                    usage()
                ));
            }
        }
        i += 1;
    }
    if manifest.is_some() != archive.is_some() {
        return Err("`--manifest` and `--archive` must be passed together".into());
    }
    fixture_sign::cmd_seed_demo_fixtures(root, manifest.as_deref(), archive.as_deref())
}

pub fn parse_and_run_simulate(root: &Path, args: &[String]) -> Result<(), String> {
    let mut domain = None;
    let mut opts = ops::SimOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--domain" => {
                i += 1;
                domain = args.get(i).cloned();
            }
            "--mode" => {
                i += 1;
                opts.mode = match args.get(i).map(String::as_str) {
                    Some("simulate") => EvalMode::Simulate,
                    Some("live") => EvalMode::Live,
                    other => return Err(format!("invalid `--mode` `{other:?}`")),
                };
            }
            "--out" => {
                i += 1;
                opts.out_path = args.get(i).map(PathBuf::from);
            }
            "--observations-dir" => {
                i += 1;
                opts.observations_dir = args.get(i).map(PathBuf::from);
            }
            "--trust-root" => {
                i += 1;
                opts.trust_root = args.get(i).map(PathBuf::from);
            }
            "--ledger-file" => {
                i += 1;
                opts.ledger_file = args.get(i).map(PathBuf::from);
            }
            "--trusted-checkpoint" => {
                i += 1;
                opts.checkpoint_file = args.get(i).map(PathBuf::from);
            }
            "--oidc-claims-file" => {
                i += 1;
                opts.oidc_claims_file = args.get(i).map(PathBuf::from);
            }
            "--oidc-audience" => {
                i += 1;
                opts.oidc_audience = args.get(i).cloned();
            }
            "--oidc-repo" => {
                i += 1;
                opts.oidc_repo = args.get(i).cloned();
            }
            "--oidc-repo-id" => {
                i += 1;
                opts.oidc_repo_id = args.get(i).cloned();
            }
            "--now-epoch-s" => {
                i += 1;
                let raw = args.get(i).ok_or("missing u64 after `--now-epoch-s`")?;
                opts.now_epoch_s = Some(
                    raw.parse()
                        .map_err(|_| format!("invalid `--now-epoch-s` `{raw}`"))?,
                );
            }
            other => return Err(format!("unknown simulate flag `{other}`\n\n{}", usage())),
        }
        i += 1;
    }
    let dom = domain.ok_or_else(|| format!("missing `--domain`\n\n{}", usage()))?;
    ops::cmd_simulate(root, &dom, &opts)
}

pub fn parse_and_run_promote(root: &Path, args: &[String]) -> Result<(), String> {
    let mut domain = None;
    let mut engine_digest = None;
    let mut dry_run = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--domain" => {
                i += 1;
                domain = args.get(i).cloned();
            }
            "--engine-digest" => {
                i += 1;
                engine_digest = args.get(i).cloned();
            }
            "--dry-run" => dry_run = true,
            other => return Err(format!("unknown promote flag `{other}`\n\n{}", usage())),
        }
        i += 1;
    }
    let dom = domain.ok_or_else(|| format!("missing `--domain`\n\n{}", usage()))?;
    let dig = engine_digest.ok_or_else(|| format!("missing `--engine-digest`\n\n{}", usage()))?;
    promote::cmd_promote(root, &dom, &dig, dry_run)
}

pub fn parse_and_run_github_setup(args: &[String]) -> Result<(), String> {
    let mut repo = None;
    let mut dry_run = false;
    let mut opts = github_plan::GithubSetupOptions::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dry-run" => dry_run = true,
            "--require-codeowners" => opts.require_codeowners = true,
            "--prevent-self-review" => opts.prevent_self_review = true,
            "--main-pr-approvals" => {
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or("missing integer after `--main-pr-approvals`")?;
                opts.main_pr_approvals = raw
                    .parse()
                    .map_err(|_| format!("invalid `--main-pr-approvals` `{raw}`"))?;
            }
            s if !s.starts_with('-') && repo.is_none() => repo = Some(s.to_string()),
            other => return Err(format!("unexpected argument `{other}`\n\n{}", usage())),
        }
        i += 1;
    }
    let slug = repo.ok_or_else(|| format!("missing `<OWNER/REPO>`\n\n{}", usage()))?;
    github::cmd_github_setup(&slug, dry_run, &opts)
}
