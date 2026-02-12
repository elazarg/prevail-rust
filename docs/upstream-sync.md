# Upstream Sync Workflow

This document describes the process for keeping the Rust port in sync with the
[upstream C++ repository](https://github.com/vbpf/prevail).

## Overview

The Rust port is a complete rewrite, not a line-for-line translation. Upstream
changes are reviewed and adapted by hand — there is no automated porting. The
goal is functional parity: the Rust verifier should accept and reject the same
programs as the upstream C++ verifier, and pass the same (or a superset of) test
cases.

## Tracking state

The `tests/upstream` submodule commit is the upstream sync anchor.
Updating the submodule pointer is how we record the synced upstream revision.
For submodule initialization, follow `CONTRIBUTING.md` (`Initial Setup`).

## Sync procedure

Run periodically or when upstream has interesting changes.

### 1. Review the upstream changelog

Use xtask to see what changed since the last sync:

```bash
cargo xtask upstream-diff
```

Or manually:

```bash
LAST=$(git rev-parse --short HEAD:tests/upstream)
git -C tests/upstream log --oneline "$LAST"..HEAD
```

### 2. Triage each commit

| Category | Action | Examples |
|----------|--------|---------|
| **Test data** (new/modified YAML) | Copy file, add Rust test if new | `observe.yaml`, modified `assign.yaml` |
| **Bug fix** (functional) | Port the fix to Rust equivalent | `ValidMapKeyValue` wording, `radix_substr` bounds |
| **Semantic change** (new feature, behavior) | Port logic, adapt to Rust idioms | observation checks, new helper prototypes |
| **Refactor/rename** (C++ internal) | Skip unless it reveals a better abstraction to adopt | SplitDBM rename |
| **Build/CI/deps** (CMake, submodule bumps) | Skip | `apt-get update`, Catch2 bump |
| **C++-only cleanup** (clang-format, dead code) | Skip | `clang format`, `remove dead code` |

### 3. Port changes in order

For each non-skipped commit, oldest first:

1. Read the upstream diff:
   ```bash
   git -C tests/upstream show <hash> --stat
   git -C tests/upstream show <hash> -- <relevant files>
   ```
2. Find the equivalent Rust code (usually the same module path, e.g.
   `src/crab/ebpf_checker.rs` corresponds to `src/crab/ebpf_checker.cpp`).
3. Apply the change using Rust idioms.
4. Run `cargo test` (subset during dev, full before finishing).
5. Commit with a message referencing the upstream hash:
   `Port upstream <short-hash>: <summary>`

### 4. Update submodule pointer

After all changes are ported and tests pass:

```bash
git -C tests/upstream fetch
git -C tests/upstream checkout <new-hash>
git add tests/upstream
git commit -s -m "Update upstream submodule to <new-hash>"
```

## Handling specific change types

### New YAML test files

- Add/update file in upstream `tests/upstream/test-data/`.
- Update this repo's submodule pointer to include that upstream commit.
- Add a `#[test] fn yaml_<name>` entry in `tests/yaml_tests.rs` (follow existing pattern).
- Run and verify.

### Modified YAML test files

- Diff against old/new upstream commits in the submodule.
- If changed, update the submodule pointer and run tests.
- If a test expectation changed (e.g. pass to fail), understand *why* before
  accepting it.

### Bug fixes

- Find the equivalent Rust code.
- Apply the fix with Rust idioms.
- Verify with the same test case if one exists.

### New BPF helpers / spec changes

- Update `src/linux/spec_prototypes.rs` and `src/spec/` as needed.
- These are typically mechanical (add a new entry to a match/map).

### Submodule bumps

- `tests/upstream` is the only submodule tracked directly in this repository.
- Its nested upstream submodules (including `ebpf-samples` and
  `external/bpf_conformance`) are updated by moving the `tests/upstream`
  pointer forward, then running `git submodule update --init --recursive`.

## Helper command

`cargo xtask upstream-diff` shows upstream commits since the last sync,
categorized by area (test data, source changes, overall file stats).
Defaults to `tests/upstream`; pass a custom path as positional argument:

```bash
cargo xtask upstream-diff /path/to/upstream
```

## Upstream Fixtures

- `tests/upstream/` is the pinned upstream C++ verifier (submodule), including
  canonical YAML fixtures and upstream tooling.
- `tests/upstream/external/bpf_conformance/` provides conformance test data (`.data` files
  with BPF assembly and expected results), actively used by
  `tests/conformance_tests.rs`.

## What this workflow does NOT do

- **No scripted porting** — upstream changes are always reviewed and adapted by hand.
- **No branch mirroring** — the Rust repo has its own commit history.
