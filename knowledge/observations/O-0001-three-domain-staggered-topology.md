---
id: O-0001
kind: observation
status: active
added_by: agent
human_ratified: false
links:
  - knowledge/decisions/D-0001-concurrent-domains-not-branches.md
  - knowledge/research/R-0001-state-inertia-and-expand-contract.md
  - attestations/ledger.json
  - attestations/checkpoint.json
  - trust/verifiers.json
---

# O-0001: Three-Domain Staggered Progression of `admission-engine`

## Topology Snapshot

The demo topology seeds `v0.1.0` directly from the byte-verified `service-template` release archive (`sha256:f88da3d5453c45f6609cf1bc26967cb9b8424f02fde91111a0958727ead1fbb7`, `fixture_only: false`, `transition_mode: "expand"`) across three concurrent failure domains on trunk:

| Domain | Observed Engine | Target Engine | Reader / Shard Formats | Transition Mode | Reconcile Plan | Verified Ed25519 Predicates |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `dev` | `v0.1.0` (`sha256:f88d...`, gen `2`) | `v0.2.0` (`sha256:3333...`, gen `3`) | reader `2`, shards `2..=2` (`2/2`) | `contract` | `AdvanceTuple` | `sim_passed` |
| `staging` | `v0.1.0` (`sha256:f88d...`, gen `2`) | `v0.1.0` (`sha256:f88d...`, gen `2`) | reader `2`, shards `2..=2` (`4/4`) | `expand` | `NoOp` | `sim_passed`, `dev_converged` |
| `prod` | `v0.1.0` (`sha256:f88d...`, gen `1`) | `v0.1.0` (`sha256:f88d...`, gen `1`) | reader `2`, shards `2..=2` (`8/8`) | `expand` | `NoOp` | `sim_passed`, `dev_converged`, `soak_within_bounds`, `policy_signed` |

## Key Properties Verified

1. **Append-Only Byte-Verified Handoff:** `import-service-release --archive` verifies archive SHA-256, binary SHA-256, and RFC 8785 JCS `compatibility_digest` and appends strictly to `catalog/engines.json` without touching `observations/`, `domains/`, `trust/`, or `attestations/`.
2. **Fleet Reader Ceiling & Budget Restorability:** Active `v1` readers (`min_active_reader_format: 1`) block `state_write_version: 2` until the fleet drains to `min_active_reader_format: 2`, and `max_observed_consumed_units <= max_units_per_window` prevents unrestorable quota cuts.
3. **Checkpoint Freshness & Permanent Revocation:** `attestations/checkpoint.json` binds `(stream_id, ledger_len, head_record_hash, checkpoint_epoch_s, max_staleness_s)` under `checkpoint-authority`, while `revoked` engine records never expire.
