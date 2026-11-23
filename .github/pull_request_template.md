## Summary

- **Target Domain(s):** `dev` / `staging` / `prod` / `kernel`
- **Tuple Transition:** `sha256:...` -> `sha256:...`
- **Migration Phase:** `steady` / `expand` / `contract`

## 5-Invariant Verification Checklist

- [ ] **1. Immutable Capabilities:** All `engine_digest` and `config_digest` fields pin exact `sha256:` digests (`target.config_digest == sha256(canonical_json(config.json))`).
- [ ] **2. Concurrent Domains on Trunk:** Changes target `domains/{dev,staging,prod}/` without introducing environment branches or cross-domain relative coupling.
- [ ] **3. State & Schema Continuity:** Transition respects `(min_readable_state_format, max_supported_state_format, migration_class)` and passes `expand` before `contract`.
- [ ] **4. Evidence-Gated Promotion:** Required attestations (`sim_passed`, `dev_converged`, `soak_within_bounds`, `policy_signed`) are recorded in `attestations/ledger.json`.
- [ ] **5. Capability-Scoped Envelopes:** All sensitive config values use domain-scoped `secretref://` handles; `staging`/`prod` execution scopes strictly require `refs/heads/main`.
- [ ] **Verification Receipt:** `cargo xtask verify --force` and `cargo xtask simulate --domain all` pass cleanly.
