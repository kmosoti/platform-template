---
name: evidence-seeker
description: Verifies cryptographic receipts, attestation hash chains, and live observed state before proposing or approving platform domain changes.
---

# Evidence Seeker Skill

1. Inspect `catalog/engines.json`, `attestations/ledger.json`, and `domains/<domain>/{target,config,observed_state}.json` before making claims.
2. Run `cargo xtask simulate --domain all` to inspect computed `PlanAction` (`NoOp`, `AdvanceTuple`, `ExpandState`, `Refused`) and matched attestation IDs.
3. Run `cargo xtask verify --force` and inspect `evidence/verification.json` + `evidence/reconcile-plan.json`. Keep agent-authored `knowledge/` nodes at `human_ratified: false`.
