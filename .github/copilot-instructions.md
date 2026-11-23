# GitHub Copilot Instructions for `platform-template`

Follow `AGENTS.md` and the 5 platform invariants enforced by `crates/platform-kernel`:

1. **Immutable Digests:** Use `sha256:<64 lowercase hex>` for all `engine_digest` and `config_digest` references; never use mutable tags (`latest`, `v0.1.0`).
2. **Concurrent Failure Domains:** Edit `domains/dev/`, `domains/staging/`, and `domains/prod/` side-by-side on trunk. Never suggest `dev`/`staging`/`prod` Git branches; agent integration uses `develop-agent` with `--rebase`.
3. **State Continuity:** Check `min_readable_state_format` and `max_supported_state_format` across `steady -> expand -> contract`. Never assume `git revert` reverts migrated `state_format`.
4. **Evidence-Gated Promotion:** Ensure `attestations/ledger.json` binds required predicates (`sim_passed`, `dev_converged`, `soak_within_bounds`, `policy_signed`) to `(engine_digest, config_digest)`.
5. **Capability Scopes & Envelopes:** Use `secretref://<provider>/admission-<domain>/<name>` for secrets; keep `staging` and `production` environments strictly locked to `refs/heads/main`.
6. **Pure-Rust Discipline:** Rust `1.100.0` (`edition = "2024"`, `#![forbid(unsafe_code)]`), zero `.sh` or `.py` files, `<= 300` lines per `.rs` file, and exact 40-hex SHA pins in `.github/workflows/*.yml`.
