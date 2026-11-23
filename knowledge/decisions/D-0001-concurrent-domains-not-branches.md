---
id: D-0001
kind: decision
status: active
added_by: agent
human_ratified: false
links:
  - knowledge/research/R-0001-state-inertia-and-expand-contract.md
  - knowledge/observations/O-0001-three-domain-staggered-topology.md
  - docs/architecture.md
---

# D-0001: Concurrent Failure Domains on Trunk Instead of Environment Branches

## Context

Conventional branch-based GitOps models environments (`dev`, `staging`, `prod`) as long-lived Git branches promoted via merges or cherry-picks. In stateful platform operations, environment branches create systemic hazards:

1. **History Divergence:** Hotfixes or per-environment tuning (`replicas`, `rate_limit_rps`, KMS handles) cause `staging` and `prod` branches to diverge permanently from `main`.
2. **Hidden Drift:** Comparing what runs in `staging` vs. `prod` requires cross-branch diffs mixed with unrelated commits rather than inspecting a single atomic commit tree.
3. **Unsafe Rollback Reflex:** Operators run `git revert` on a branch assuming previous code restores previous live state, ignoring irreversible schema/WAL migrations.

## Decision

1. **Single Authoritative Trunk (`main`):** `domains/dev/`, `domains/staging/`, and `domains/prod/` live side-by-side in the same directory tree on `main`.
2. **Mechanical Branch Prohibition:** Local and remote branches named `dev`, `develop`, `staging`, `uat`, `prod`, or `production` are mechanically blocked in three layers:
   - Agent `PreToolUse` hook (`cargo xtask hook pre-tool-use`),
   - Repository verification gate (`check-no-env-branches`),
   - GitHub Repository Ruleset (`forbid-environment-branches`).
3. **Agent Integration Isolation (`develop-agent`):** Automated agents integrate changes on `develop-agent` via linear `--rebase`. On `develop-agent`, workflows execute deterministic simulation (`cargo xtask simulate --domain all`) without `staging` or `production` OIDC credentials. Human-approved promotion (`main-release`) advances `main`.
4. **Zero Unversioned Shared Bases:** Each domain owns a complete `config.json` hashed via canonical JSON (`target.config_digest`) with zero cross-directory inheritance (`../`).
