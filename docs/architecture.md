# `platform-template` Architecture

## Role in the 4-Template Lifecycle Suite

`platform-template` is **Archetype 4 of 4** (`research-template` -> `library-template` -> `service-template` -> `platform-template`), governing how attested `admission-engine` releases advance across concurrent stateful failure domains.

### Why `service-template` and `platform-template` Are Separate Repositories

1. **Decoupled Cadence & Zero CI Feedback Loops:** Tuning `replicas` in `domains/prod/config.json` advances `domain_config_digest` without rebuilding `admission-engine`, while merging service code commits does not mutate live domain targets prior to soak evidence.
2. **Clean Promotion Ledger:** `git log` on `main` records atomic tuple promotions, config envelope updates, and Ed25519-signed attestations imported via `cargo xtask import-service-release`.
3. **Credential Separation:** Service builds require compiler/package tooling; domain reconciliation requires per-Environment OIDC tokens (`dev`, `staging`, `prod`) and external secret-manager access.

---

## Core Architectural Mechanisms

### 1. `service.compatibility/v1` Alignment & Dual Config Projection
- `catalog/engines.json` (`platform.engine-catalog/v1`, `#[serde(deny_unknown_fields)]`) mirrors `service-template`'s `service.compatibility/v1` descriptor (`service_name`, `version`, `config_schema_version`, `state_format_version`, `min_readable_state_format`, `oldest_writable_state_format`, `transition_mode`, `preserved_state_fields`, `fixture_only`) and rejects duplicate `engine_digest` entries.
- Each domain computes two JCS SHA-256 digests from `domains/<domain>/config.json`:
  - `engine_config_digest`: hashes `config.engine_config` (identical across `dev`, `staging`, and `prod` for a candidate release, enabling truthful cross-domain `sim_passed`, `dev_converged`, and `soak_within_bounds` reuse).
  - `domain_config_digest`: hashes the full `DomainConfig` (bound by `policy_signed` to `(domain: "prod", target_generation, engine_digest, domain_config_digest)`).

### 2. Optimistic CAS Generation Fencing & Shard Continuity
- Changing `(engine_digest, engine_config_digest, domain_config_digest)` requires `target.expected_observed_generation == observed.generation` AND `target.generation > observed.generation`.
- `observations/<domain>.json` tracks `min_shard_state_format`, `max_shard_state_format`, `total_shards`, and `migrated_shards`:
  - Rejects rollbacks where `max_shard_state_format > target.state_format_version` (`IrreversibleStateRollback`).
  - Rejects jumps where `min_shard_state_format < target.min_readable_state_format` (`IncompatibleStateJump`) or incomplete shard migrations (`migrated_shards < total_shards`) prior to `contract`/`forward_only`.
  - Allows steady `v2 -> v2` successors after a converged `contract`/`forward_only` release.

### 3. Ed25519 Attestation Chain & `--mode live` Boundary
- `attestations/ledger.json` chains `prev_hash -> record_hash` and verifies Ed25519 signatures against role-scoped verifiers in `trust/verifiers.json` (`ci-sim-bot`, `dev-reconciler`, `staging-soak-observer`, `prod-release-approver`), enforcing expiry and `revoked` records.
- `--mode live` requires external `--observations-dir`, `--trust-root`, and `--oidc-claims-file` (`iss == "https://token.actions.githubusercontent.com"`, `ref == "refs/heads/main"`, `environment == domain`, `sub == "repo:<repo>:environment:<domain>"`) and rejects any `fixture_mode: true` or `fixture_only: true` input.

### 4. Split GitHub Rulesets & Merge-Method Ancestry
- `platform-template-main-protection` (`refs/heads/main`) requires PR approval, `gates` + `main-release-gate`, `required_deployments: ["main-release"]`, and `allowed_merge_methods: ["merge"]` so `develop-agent` stays a fast-forwardable ancestor of `main`.
- `platform-template-agent-branch-protection` (`refs/heads/develop-agent`) enforces `required_linear_history`, `allowed_merge_methods: ["squash", "rebase"]`, and `gates`.
