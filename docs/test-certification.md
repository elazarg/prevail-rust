# Test Certification Design

## Summary

The repository supports local test certification via `cargo xtask test <suite>`.
Certification is a local cache and documentation mechanism for developer
workflows. It is not a replacement for CI test execution.

## Goals

- Enforce that required suites were run before push.
- Avoid redundant reruns when nothing relevant changed.
- Keep the mechanism auditable and easy to remove.

## Non-goals

- Do not make CI trust local results as proof of correctness.
- Do not change the behavior of plain `cargo test`.
- Do not rewrite arbitrary history beyond explicit certification attachment to `HEAD`.

## Commands and behavior

- `cargo test ...`
  - Runs tests directly.
  - Does not read/write certifications.
- `cargo xtask test <suite> [-- <args>]`
  - Checks suite cleanliness constraints.
  - Computes suite basis hash.
  - Reuses existing passing cert when basis matches.
  - Otherwise runs suite command and writes/updates cert on success.
  - The `all` suite runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`.
  - `all-no-parity` is a faster local alternative: it runs formatting/lint plus non-parity suites (`--lib`, `conformance_tests`, `elf_verify_tests`, `yaml_tests`).
  - By default, amends `HEAD` to attach/update the suite cert file.
    - opt out: `cargo xtask test <suite> --no-amend`

## Certification files

- Location: `tests/certs/<suite>.json`
- Current schema version: `2`
- Stored fields include:
  - suite name
  - basis hash
  - dependency mode
  - exact command and executed steps
  - clean requirements
  - toolchain string
  - timestamp
  - runner version

## Basis hash model

The basis hash is computed from:

- tracked files at `HEAD` (`git ls-tree -r --full-tree HEAD`)
- suite identity and resolved execution steps
- local Rust toolchain string (`rustc -V`)

Excluded paths are ignored for both basis hashing and cleanliness checks.

- default exclusions:
  - `tests/certs/**`
  - `*.md`
- additional exclusions:
  - repository-level `.certignore`

## Cleanliness constraints

Certification only runs when cleanliness requirements are met.

- Standard suites require repo cleanliness, excluding ignored paths.
- Parity-related suites additionally require `tests/upstream` cleanliness.

This keeps the certification claim explicit: the recorded basis corresponds to a
clean source state.

## Pre-push policy

`cargo xtask hook pre-push`:

1. Runs clippy (`--all-targets -D warnings`).
2. Verifies required suite certifications at `HEAD`.

Default required suites: `all`.

Override with:

```bash
PREVAIL_REQUIRED_CERT_SUITES=all,conformance,yaml
```

`all-no-parity` is available for local iteration, but should not replace `all`
when full parity coverage is required.

If a cert is missing or stale, pre-push fails and prints remediation commands.

## Amend behavior and certification identity

`xtask test` defaults to `git commit --amend --no-edit --only -- <cert-path>`.
This keeps certification attached to the commit being certified.

- if the commit was already pushed, updating certification may require `git push --force-with-lease`
- if you do not want history rewrites, use `--no-amend` and commit cert changes manually

Certification identity is content-based, not commit-ID-based. Verification
recomputes the expected basis hash and expected suite configuration from the
current `HEAD` tree and toolchain. A stale certificate from an older code state
fails verification because its basis hash and/or suite configuration will not
match current expectations.

## CI trust model

CI must not trust local certifications as test proof.

CI may validate that required certifications exist and are fresh relative to the
commit, but must still execute authoritative tests in CI.

This design avoids false confidence from locally cached state while preserving
developer productivity.

## Reversibility

The feature is intentionally isolated to `xtask`, `tests/certs/`, and docs.
Removing it requires:

1. remove `xtask` certification command/module
2. remove pre-push certification validation
3. remove `tests/certs/` artifacts and documentation references

No verifier/runtime behavior depends on certification.
