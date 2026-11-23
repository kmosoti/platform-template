---
name: tuple-promotion-and-compat
description: Guides safe (engine_digest, config_digest) promotion across dev, staging, and prod while enforcing expand-contract schema continuity and attestation gates.
---

# Tuple Promotion & Compatibility Skill

Use this skill whenever advancing an `engine_digest` or updating `domains/<domain>/config.json`.

## Promotion Sequence

1. **Check Release Metadata in `catalog/engines.json`:**
   - Verify `state_format`, `min_readable_state_format`, `max_supported_state_format`, `migration_class`, and `phase` (`steady` | `expand` | `contract`).
   - If advancing to a `contract` (`forward_only`) release, confirm `observed_state.last_phase == "expand"` and `observed_state.state_format >= min_readable_state_format`. Never skip `expand`!
2. **Validate Secret Envelopes & Config Digest:**
   - Ensure every secret in `domains/<domain>/config.json` uses `secretref://<provider>/admission-<domain>/<name>`.
3. **Verify Required Attestation Predicates in `attestations/ledger.json`:**
   - `dev`: `sim_passed`
   - `staging`: `sim_passed` + `dev_converged`
   - `prod`: `sim_passed` + `dev_converged` + `soak_within_bounds` + `policy_signed`
4. **Dry-Run Before Writing:**
   - Run `cargo xtask promote --domain <domain> --engine-digest <sha256:...> --dry-run`.
   - Only apply without `--dry-run` once dry-run succeeds, then run `cargo xtask simulate --domain all` and `cargo xtask verify --force`.
