# `platform-template`

**Archetype 4 of 4** in the Rust engineering lifecycle suite (`research-template` -> `library-template` -> `service-template` -> `platform-template`).

`platform-template` governs **live stateful infrastructure & multi-domain operations** around five mechanically enforced platform invariants—eliminating floating tags, divergent environment branches, state-blind `git revert` rollbacks, unsigned promotions, and ambient CI credentials.

---

## Lifecycle & Domain Thread

`research-template`, `library-template`, and `service-template` share the quota/rate-admission problem domain **conceptually** as standalone, self-contained templates, whereas **`service-template` -> `platform-template`** forms a **concrete, byte-verified contract handoff**:

1. **`research-template`** — Explores and empirically falsifies admission-control and expand-contract migration hypotheses as an independent research workspace.
2. **`library-template`** — Demonstrates packaging pure, zero-I/O quota/window state machines into a standalone MSRV-verified library crate.
3. **`service-template`** — Builds the deployable `admission-engine` binary and emits a reproducible `.tar.gz` archive + `service.release-manifest/v1` (`service.compatibility/v1` with RFC 8785 JCS `compatibility_digest`).
4. **`platform-template` (this repo)** — Byte-verifies the `service-template` `.tar.gz` archive + manifest via append-only `cargo xtask import-service-release <manifest.json> --archive <archive.tar.gz>`, verifies Ed25519-signed attestations + `TrustedCheckpoint` freshness, and reconciles concurrent `dev`, `staging`, and `prod` failure domains on trunk.

---

## The 5 Platform Invariants

1. **Immutable Capabilities & RFC 8785 Dual Config Projection:** Every domain pins `engine_digest`, `engine_config_digest` (RFC 8785 JCS SHA-256 of candidate `engine_config`), and `domain_config_digest` (RFC 8785 JCS SHA-256 of closed `platform.domain-config/v1`). `import-service-release` verifies archive, binary, and JCS compatibility digests and appends strictly to `catalog/engines.json`.
2. **Concurrent Failure Domains on Trunk:** `domains/dev/`, `domains/staging/`, and `domains/prod/` coexist side-by-side on `main`. Environment branches (`dev`, `develop`, `staging`, `uat`, `prod`, `production`) are blocked across hooks, `xtask`, and GitHub Rulesets.
3. **Shard & Fleet Reader Continuity + CAS Fencing:** Transitions enforce `expected_observed_generation == observed.generation`, strict `target.generation > observed.generation` on tuple change, rolling fleet reader safety (`state_write_version <= min_active_reader_format`), budget-cut restorability (`max_observed_consumed_units <= max_units_per_window`), and full shard migration (`migrated_shards == total_shards`) prior to contraction.
4. **Ed25519-Signed Ledger, Signed Checkpoints & Permanent Revocation:** `attestations/ledger.json` and `attestations/checkpoint.json` verify against role-scoped Ed25519 keys in `trust/verifiers.json`. Positive predicates expire against authoritative `now_epoch_s`, while `revoked` engine records never expire.
5. **Capability-Scoped Execution & `secretref://` Envelopes:** Secrets use `secretref://<provider>/<domain>/<name>#v<int>` handles; `telemetry_endpoint` enforces strict `https://<host>[:<port>]`. `main` and `develop-agent` use split GitHub Rulesets (`main` requires PR review + `gates` + `main-release-gate` + `required_deployments: ["main-release"]` using merge commits), while `staging` and `prod` Environments enforce `main`-only policies, human reviewers, and classic + post-July-2026 GitHub OIDC `sub` claims.

---

## Pure-Rust `xtask` CLI

```bash
# Run all 10 verification gates (tracks HEAD, tree, git refs digest, and dirty file hashes)
cargo xtask verify

# Simulate single or all domains (single-domain mode loads ONLY observations/<domain>.json)
cargo xtask simulate --domain all --mode simulate

# Append-only byte-verified import of a service-template release archive + manifest
cargo xtask import-service-release path/to/release-manifest.json --archive path/to/admission-engine-v0.2.0-linux-x86_64.tar.gz

# Audit develop-agent vs main Git ancestry topology
cargo xtask sync-branches --check

# Configure split Rulesets and main-release/dev/staging/prod Environments with typed readback
cargo xtask github-setup owner/repo --dry-run
```

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option. Copyright (c) 2026 Kennedy Mosoti.
