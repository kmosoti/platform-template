---
name: idempotent-workflow
description: Enforces clean, repeatable verification receipts, rebase-only linear history on develop-agent, and zero untracked artifact drift.
---

# Idempotent Workflow Skill

Use this skill before committing, rebasing, or opening pull requests in `platform-template`.

## Protocol

1. **Isolated Build Targets & Clean Working Tree:**
   - Keep `/target` and `/evidence` untracked via `.gitignore`.
   - Never introduce `.sh` or `.py` scripts; implement all checks inside `xtask/`.
2. **Two-Pass Idempotency Check:**
   - Run `cargo xtask verify --force` to execute all 10 gates (`rustfmt`, `clippy`, `tests`, `check-domains`, `check-no-env-branches`, `check-knowledge`, `check-workflow-pins`, `check-agent-configs`, `check-line-caps`, `check-privacy`).
   - After committing on a clean tree, run `cargo xtask verify` a second time and confirm `[idempotent cache hit]` against `(HEAD^{tree}, Cargo.lock sha256, rustc --version)` with empty `git status --porcelain`.
3. **Linear Branch Hygiene:**
   - Branch short-lived work (`feat/...`, `fix/...`) from `develop-agent` and integrate via `--rebase`.
   - Never create `dev`, `develop`, `staging`, `uat`, `prod`, or `production` branches.
