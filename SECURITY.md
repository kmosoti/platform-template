# Security Policy & Trust Boundaries

## Defense-in-Depth Boundary Model

1. **Authoritative Server-Side & Cryptographic Boundaries:**
   - **GitHub Branch Rulesets (`cargo xtask github-setup`):**
     - `platform-template-main-protection` (`refs/heads/main`): enforces PR review, `allowed_merge_methods: ["merge"]`, `gates` + `main-release-gate`, and `required_deployments: ["main-release"]`.
     - `platform-template-agent-branch-protection` (`refs/heads/develop-agent`): enforces `required_linear_history`, `allowed_merge_methods: ["squash", "rebase"]`, and `gates`.
     - `platform-template-forbid-env-branches`: blocks `dev`, `develop`, `staging`, `uat`, `prod`, and `production` branches, verified post-apply via typed REST readback.
   - **GitHub Environments & OIDC Boundary:**
     - `main-release`, `staging`, and `prod` enforce human reviewer approval; `dev`, `staging`, and `prod` restrict deployments to `refs/heads/main`.
     - **OIDC JWKS Verification Boundary:** Raw GitHub Actions JWT JWS signature verification against `https://token.actions.githubusercontent.com/.well-known/jwks` occurs at the external OIDC token-exchange / STS adapter boundary before invoking `platform-kernel`. `platform-kernel` then validates the decoded `OidcClaims` against an explicit `ExpectedOidcPolicy` (`iss`, `aud`, `repository`, `ref == "refs/heads/main"`, `nbf <= now_epoch_s < exp`, `environment`, and both classic and post-July-15-2026 immutable GitHub `sub` formats).
   - **Live Mode, Signed Checkpoints & Permanent Revocation (`--mode live`):**
     - Committed `observations/*.json`, `trust/verifiers.json` (`trust_mode: "fixture-demo"`), `attestations/ledger.json`, and `attestations/checkpoint.json` carry `"fixture_mode": true`.
     - `--mode live` requires external state, trust root, ledger, Ed25519-signed `TrustedCheckpoint` (`now_epoch_s <= checkpoint_epoch_s + max_staleness_s`), authoritative `now_epoch_s` (never trusting clock fields inside the ledger), and `provenance_status: "verified"` catalog entries. `revoked` engine records never expire.

2. **Cooperative Client-Side Agent Guardrails (`PreToolUse` Hooks):**
   - Configured in `.agents/hooks.json` (Antigravity), `.claude/settings.json` (Claude Code), `.codex/hooks.json` (Codex CLI), and `.github/hooks/forge-guard.json` (GitHub Copilot).
   - Hooks emit `{}` on neutral commands and fail closed on empty/malformed JSON, acting as accidental-mistake guardrails rather than an unconfined-workstation security boundary.

3. **Secret Envelopes (`secretref://`):**
   - Configs accept only `secretref://<provider>/<domain>/<name>#v<int>` handles (`gcp-sm`, `aws-sm`, `vault`, `age-kms`) matching `config.domain`; `telemetry_endpoint` enforces `https://<host>[:<port>]` without paths, queries, or credentials.

## Reporting a Vulnerability

Report security findings privately through GitHub Security Advisories on your instantiated repository.
