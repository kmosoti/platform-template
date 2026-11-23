# Claude Code Instructions (`platform-template`)

Read and obey [AGENTS.md](AGENTS.md), [SECURITY.md](SECURITY.md), and [docs/architecture.md](docs/architecture.md) before modifying any domain manifest, kernel rule, or workflow.

## Essential Rules

1. **Trunk + `develop-agent` Isolation:** Merge agent PRs onto `develop-agent` with `--rebase` or `--squash`. Never create `dev`, `develop`, `staging`, `uat`, `prod`, or `production` branches, and never merge to `main` or approve `main-release`, `staging`, or `prod` Environments.
2. **Closed Schemas & Envelopes:** Pin `engine_digest`, `engine_config_digest`, and `domain_config_digest`; keep secrets strictly behind `secretref://<provider>/<domain>/<name>#v<int>`; and respect shard-level `expand` -> `contract` continuity + strict generation CAS fencing.
3. **Pure-Rust `xtask`:** Zero `.sh` or `.py` files anywhere. Keep every `.rs` file `<= 300` lines (`#![forbid(unsafe_code)]`).

## Key Commands

- `cargo xtask verify` — 10-gate verification (reuses cache only on clean worktrees matching `HEAD`, tree, lockfile, toolchain, all gates, and `reconcile-plan.json`).
- `cargo xtask simulate --domain all --mode simulate` — Compute deterministic reconciliation plan.
- `cargo xtask promote --domain <dev|staging|prod> --engine-digest <sha256:...> --dry-run` — Validate CAS generation, shard continuity, and Ed25519 attestations.
- `cargo xtask import-service-release <path>` — Import `service-template` `release-manifest.json`.
- `cargo xtask sync-branches --check` — Check `develop-agent` ancestry / patch equivalence against `main`.
