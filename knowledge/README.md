# Epistemic Knowledge Graph

This directory captures durable architectural decisions, domain research, and operational observations for `platform-template` as linked Markdown nodes with machine-verifiable YAML frontmatter.

## Node Categories

- `decisions/D-XXXX-*.md` — Normative governance and platform topology decisions.
- `research/R-XXXX-*.md` — Formal analysis of state continuity, failure domains, and reconciliation mechanics.
- `observations/O-XXXX-*.md` — Empirical measurements, topology snapshots, and operational findings.

## Frontmatter & Ratification Contract

Every node MUST begin with YAML frontmatter declaring:

```yaml
---
id: D-0001
kind: decision
status: proposed
added_by: agent
human_ratified: false
links:
  - knowledge/research/R-0001-state-inertia-and-expand-contract.md
---
```

1. **Provenance Honesty:** Nodes authored or updated by automated agents MUST record `added_by: agent` and `human_ratified: false`. Only a human reviewer merging to `main` may set `human_ratified: true`.
2. **Referential Integrity:** Every path listed under `links` is verified by `cargo xtask verify` (`check-knowledge`) to exist in the repository tree.
