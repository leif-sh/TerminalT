---
name: pre-commit-ci
description: Run and enforce TerminalT's complete local CI equivalent before committing source, test, build, or automation changes. Use after implementation is complete and before git commit whenever staged changes include program code, tests, build configuration, release scripts, or CI automation.
---

# Pre-commit CI

Run from the repository root. Do not create a source commit unless every required command succeeds.

## Scope decision

- Run this workflow for changes to `src`, `src-tauri`, tests, `package*.json`, Cargo files, scripts, Tauri configuration, or `.github/workflows`.
- Do not require it for documentation, images, design resources, ordinary text, skills, or process rules alone.
- If source and documentation are mixed, run the workflow.

## Required workflow

1. Inspect `git status --short` and identify only files belonging to the current request.
2. Confirm completed features or bug fixes have one synchronized version increment.
3. Run `npm run release:version`.
4. Run `npm run release:test`.
5. Run `npm run release:audit`.
6. Run any additional targeted integration, UI, protocol, migration, or packaging checks required by the change.
7. Run `git diff --check` and inspect the final diff for unrelated files, secrets, generated debris, and accidental lockfile edits.
8. Stage only current-request files, then re-check the staged diff before committing.

`npm run release:test` is the authoritative local CI aggregate and currently runs lint, frontend tests/build, Rust formatting, Clippy with warnings denied, and Rust tests.

## Failure handling

- Do not bypass, ignore, disable, or weaken a failing check.
- Diagnose and fix the root cause introduced or exposed by the current change.
- Re-run the failed focused command until it passes.
- Re-run the complete required workflow from `npm run release:version` onward.
- If a failure is caused by a confirmed unrelated external condition, report the blocker and do not create a misleading completion commit.

## Version handling

- Use `MAJOR.MINOR.PATCH-N`; normal work increments only `N` once per user request.
- Synchronize `package.json`, `package-lock.json`, `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock`, and `src-tauri/tauri.conf.json` using npm/Cargo commands for lockfiles.
- Do not increment for documentation-only, test-only, refactor-only, style-only, build-only, or toolchain-only work.
- Do not increment incomplete or unverified work.

## Commit gate

- All required commands succeeded in the current worktree.
- Targeted checks for the feature succeeded.
- The staged diff contains only current-request files.
- No secret, private key, credential, terminal正文, local cache, or build output is staged.
- Only then create a concise Conventional Commit. Do not push unless the user explicitly requested it.
