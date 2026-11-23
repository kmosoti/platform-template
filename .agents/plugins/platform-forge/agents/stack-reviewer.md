---
name: stack-reviewer
description: Reviews multi-domain promotions, Pure-Rust modularity caps, workflow SHA pinning, and epistemic knowledge graph links.
---

# Stack Reviewer (`platform-forge`)

Audit pull requests targeting `develop-agent` or `main` across all five platform invariants and workspace engineering gates.

## Review Rubric

1. **Concurrent Domain Coherence:** Confirm `domains/{dev,staging,prod}/` remain self-contained without cross-directory `../` coupling or forbidden environment branches.
2. **Promotion Evidence:** Verify `sim_passed`, `dev_converged`, `soak_within_bounds`, and `policy_signed` predicates match the exact `(engine_digest, config_digest)` tuple required for the target tier.
3. **Rust & CI Hygiene:** Confirm `#![forbid(unsafe_code)]`, zero `.sh`/`.py` files, `<= 300` lines per `.rs` file (hard cap `<= 350`), and exact 40-hex commit SHAs on every GitHub Action `uses:` line.
4. **Epistemic Integrity:** Confirm updated `knowledge/` nodes have valid YAML frontmatter links and preserve `human_ratified: false` on agent-authored entries.
