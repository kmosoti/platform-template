# `platform-template` Agent Operating Instructions

You are operating inside **`platform-template`** (Archetype 4 of 4: live stateful infrastructure & multi-domain reconciliation).

## Non-Negotiable Platform Invariants

1. **Immutable Capabilities & RFC 8785 JCS Digests (`#[serde(deny_unknown_fields)]`):**
   - Pin exact `sha256:` digests for `engine_digest`, `engine_config_digest` (RFC 8785 JCS SHA-256 of candidate `engine_config`), and `domain_config_digest` (RFC 8785 JCS SHA-256 of `domains/<domain>/config.json`).
   - `cargo xtask import-service-release <manifest.json> --archive <archive.tar.gz>` verifies archive, binary, and RFC 8785 `compatibility_digest` bytes and appends **only** to `catalog/engines.json` (never rewriting `observations/`, `domains/`, `trust/`, or `attestations/`).
2. **Concurrent Failure Domains on Trunk (Zero Environment Branches):**
   - `domains/dev/`, `domains/staging/`, and `domains/prod/` coexist on `main`.
   - **NEVER** create or push Git branches named `dev`, `develop`, `staging`, `uat`, `prod`, or `production`.
   - Integrate agent PRs onto `develop-agent` (`--rebase` or `--squash`). Promotions from `develop-agent` to `main` use **merge commits** (`allowed_merge_methods: ["merge"]`), audited via `cargo xtask sync-branches --check`.
3. **Shard Continuity, Fleet Reader Ceiling & CAS Fencing:**
   - Changing a tuple requires `target.expected_observed_generation == observed.generation` AND `target.generation > observed.generation`.
   - Enforce rolling reader safety (`state_write_version <= observed.min_active_reader_format`), budget-cut restorability (`max_observed_consumed_units <= max_units_per_window`), and full shard migration (`migrated_shards == total_shards`) prior to `contract`/`forward_only`.
4. **Ed25519-Signed Ledger, Signed Checkpoints & Permanent Revocation:**
   - `attestations/ledger.json` and `attestations/checkpoint.json` are Ed25519-signed under role-scoped keys in `trust/verifiers.json`. Positive predicates expire against authoritative `now_epoch_s`; `revoked` records **never expire**.
5. **Capability-Scoped Execution & `secretref://` Envelopes:**
   - Secrets use `secretref://<provider>/<domain>/<name>#v<int>` handles (`telemetry_endpoint` must be strict `https://<host>[:<port>]` with no path/query/userinfo).

## `.agents/` Workspace vs. Plugin Scope & Boundary Honesty

- **Workspace `.agents/` (`.agents/hooks.json` + `.agents/skills/*`):** Loaded directly by Antigravity for this workspace (`PreToolUse` `run_command` guard + repository skills).
- **Redistributable `.agents/plugins/platform-forge/`:** Packages the `adversarial-breaker` and `stack-reviewer` personas (`plugin.json` + `agents/*`) without duplicating `hooks.json`.
- **Boundary Honesty:** Client-side `PreToolUse` hooks across Antigravity, Claude Code, Codex, and Copilot are cooperative guardrails (emitting `{}` on neutral commands and failing closed on malformed JSON). Authoritative enforcement lives in GitHub Rulesets, GitHub Environments (`main-release`, `dev`, `staging`, `prod`), OIDC JWKS verification, and `--mode live` external state/checkpoint stores (see [SECURITY.md](SECURITY.md)).
