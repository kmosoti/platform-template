# Contributing to `platform-template`

## Branch & Promotion Model

1. **Agent Integration (`develop-agent`) -> Human Promotion (`main`):**
   - Open short-lived feature branches (`feat/*`, `fix/*`) targeting `develop-agent` and merge via `--squash` or `--rebase`.
   - Promotions from `develop-agent` to `main` use **merge commits** (`allowed_merge_methods: ["merge"]`) gated by PR review, `gates`, `main-release-gate`, and `required_deployments: ["main-release"]`. Merge commits keep `develop-agent` a true Git ancestor of `main` so `cargo xtask sync-branches --apply` fast-forwards cleanly.
   - **Never** create branches named `dev`, `develop`, `staging`, `uat`, `prod`, or `production`.
2. **Pure-Rust Automation & Closed Schemas:**
   - Do not add `.sh` or `.py` scripts. Keep every `.rs` file `<= 300` lines (hard cap `<= 350`, `#![forbid(unsafe_code)]`).
   - All domain configs, targets, observations, catalogs, trust roots, and ledgers enforce `#[serde(deny_unknown_fields)]`.
3. **Secret & Credential Hygiene:**
   - Use `secretref://<provider>/<domain>/<name>#v<int>` handles inside `domains/<domain>/config.json`. Never commit raw tokens, PEM keys, or workstation paths.
4. **Pre-Submission Verification:**
   - Run `cargo xtask verify --force` and `cargo xtask simulate --domain all --mode simulate`, commit cleanly, and run `cargo xtask verify` a second time to confirm `[idempotent cache hit]`.
