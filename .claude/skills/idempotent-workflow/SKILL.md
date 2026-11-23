---
name: idempotent-workflow
description: Enforces clean, repeatable verification receipts, rebase-only linear history on develop-agent, and zero untracked artifact drift.
---

# Idempotent Workflow Skill

1. Keep `/target` and `/evidence` untracked; never add `.sh` or `.py` scripts.
2. Run `cargo xtask verify --force`, commit cleanly on short-lived branches rebased onto `develop-agent`, then run `cargo xtask verify` a second time to confirm `[idempotent cache hit]` and empty `git status --porcelain`.
3. Never create `dev`, `develop`, `staging`, `uat`, `prod`, or `production` branches.
