---
name: evidence-seeker
description: Verifies cryptographic receipts, attestation hash chains, and live observed state before proposing or approving platform domain changes.
---

# Evidence Seeker Skill

Use this skill whenever inspecting domain health, auditing promotions, or verifying repository state.

## Protocol

1. **Inspect Live & Target Manifests First:**
   - Read `catalog/engines.json`, `attestations/ledger.json`, and `domains/<domain>/{target,config,observed_state}.json`.
   - Never assume a domain is converged without checking `observed_state.converged`, `observed_state.state_format`, and `observed_state.last_phase`.
2. **Run Deterministic Simulation:**
   - Execute `cargo xtask simulate --domain all` to inspect computed `PlanAction` (`NoOp`, `AdvanceTuple`, `ExpandState`, `Refused`) and matched attestation IDs.
3. **Verify Hash-Chained Receipts:**
   - Execute `cargo xtask verify --force` and inspect `evidence/verification.json` and `evidence/reconcile-plan.json`.
   - Distinguish empirically attested predicates in `attestations/ledger.json` from unverified assumptions, and keep agent-authored `knowledge/` nodes marked `human_ratified: false`.
