---
name: tuple-promotion-and-compat
description: Guides safe (engine_digest, config_digest) promotion across dev, staging, and prod while enforcing expand-contract schema continuity and attestation gates.
---

# Tuple Promotion & Compatibility Skill

1. Inspect `catalog/engines.json` (`state_format`, `min_readable_state_format`, `max_supported_state_format`, `migration_class`, `phase`). Always converge `expand` before `contract`.
2. Ensure all `domains/<domain>/config.json` secrets use `secretref://<provider>/admission-<domain>/<name>`.
3. Confirm `attestations/ledger.json` contains required predicates (`dev`: `sim_passed`; `staging`: `+ dev_converged`; `prod`: `+ soak_within_bounds + policy_signed`).
4. Run `cargo xtask promote --domain <domain> --engine-digest <sha256:...> --dry-run` first, then apply and verify with `cargo xtask verify --force`.
