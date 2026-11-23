---
id: R-0001
kind: research
status: active
added_by: agent
human_ratified: false
links:
  - knowledge/decisions/D-0001-concurrent-domains-not-branches.md
  - knowledge/observations/O-0001-three-domain-staggered-topology.md
  - catalog/engines.json
---

# R-0001: State Inertia and Expand-Contract Schema Continuity

## Problem Statement

Stateless artifacts (`engine_digest`) can be swapped instantaneously, whereas live durable state (`observed_state.state_format` across WAL segments, Raft logs, and relational/KV indexes) exhibits **state inertia**: once live writers emit records in format $F_{n+1}$, any binary whose `max_supported_state_format < F_{n+1}` crashes or corrupts data on startup.

Consequently, **Git history reversibility does not imply state reversibility**.

## Formal Compatibility Model

Every attested release in `catalog/engines.json` declares five state-continuity parameters:

- `state_format`: Durable state format written by this release once active.
- `min_readable_state_format`: Oldest live `state_format` this binary can safely read during upgrade.
- `max_supported_state_format`: Newest live `state_format` this binary can parse without data loss.
- `migration_class`: `reversible` (older steady engine can still read/coexist) vs. `forward_only` (irreversible contraction).
- `phase`: `steady` -> `expand` -> `contract`.

## Enforced Transition Laws in `platform-kernel`

1. **No Forward Jump Across Unreadable Formats (`IncompatibleStateJump`):**
   - Requires `observed.state_format >= target.min_readable_state_format`.
   - Requires passing through `MigrationPhase::Expand` before entering `MigrationPhase::Contract` (`Steady -> Contract` is rejected even if numbers appear adjacent).
2. **No Naive Git-Revert Rollback (`IrreversibleStateRollback`):**
   - Requires `observed.state_format <= target.max_supported_state_format`.
   - Rejects downgrading out of a `forward_only` `contract` release to an earlier `steady`/`expand` release; recovery must roll forward to a new attested digest.
