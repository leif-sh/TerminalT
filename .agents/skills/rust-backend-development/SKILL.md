---
name: rust-backend-development
description: Apply TerminalT's Rust backend architecture, security, cancellation, recovery, testing, versioning, and review rules. Use whenever adding or modifying Rust code under src-tauri, changing Tauri IPC implemented in Rust, or designing SSH, SFTP, tunnel, credential, persistence, diagnostic, or updater backend behavior.
---

# Rust Backend Development

Before editing Rust, read [`../../../docs/rust-backend-development-guidelines.md`](../../../docs/rust-backend-development-guidelines.md) completely and treat it as normative.

## Workflow

1. Inspect the owning module, adjacent tests, data model, IPC caller, and error mapping.
2. State the behavior, security boundary, cancellation behavior, and verification target.
3. Keep Tauri commands thin; put protocol and state-machine behavior in the owning Rust service.
4. Add or update tests for success, invalid input, failure, cancellation, resource release, and secret handling.
5. Run targeted Rust tests while iterating.
6. Synchronize frontend types and documentation when IPC or persisted data changes.
7. Apply the repository version rule for completed features or bug fixes.
8. Before committing source changes, invoke the project `pre-commit-ci` skill and complete every check.

## Non-negotiable checks

- Do not log, persist, export, or emit passwords, passphrases, OTPs, private keys, proxy secrets, Agent signatures, or terminal正文.
- Do not weaken host-key verification or silently enable insecure algorithms.
- Do not use unbounded channels for terminal, authentication, transfer, or tunnel paths.
- Do not leave network, file, listener, or prompt tasks waiting after cancel, timeout, close, or app exit.
- Do not use shell command construction for SFTP or local file operations.
- Do not change persisted or IPC models without migration and compatibility tests.
- Do not create a commit when required verification fails.

## Minimum verification

- Run focused `cargo test --manifest-path src-tauri/Cargo.toml <filter>` during development.
- Run `cargo fmt --manifest-path src-tauri/Cargo.toml -- --check` and Clippy before handoff.
- For protocol behavior, add deterministic loopback tests that require no public network or user credentials.
- Inspect logs, errors, serialized fixtures, and exports for secret leakage.
- Finish with the complete `pre-commit-ci` workflow when the change will be committed.
