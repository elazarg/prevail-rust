# Contributing to Prevail (Rust)

This document covers developer workflows for the Prevail Rust port.

## Initial Setup

Initialize submodules (including nested upstream fixtures):

```bash
git submodule update --init --recursive
```

## Toolchain Version Bump

`rust-toolchain.toml` is the single source of truth for the Rust version.
CI reads it via `rustup show` — no separate CI config needed.

**Before starting any work session**, check for a newer stable Rust release:

```bash
rustup check
```

If a new stable version is available, bump `rust-toolchain.toml` first:

1. Update the `channel` field (e.g. `"1.93"` → `"1.94"`)
2. `cargo fmt` — new formatting rules may apply
3. `cargo clippy -- -D warnings` — new lints may fire
4. `cargo test` — verify nothing regressed
5. Commit: `Bump Rust toolchain to 1.XX`

This ensures new language features are available and clippy stays current.

## Testing Infrastructure

### Unit tests

Module-level `#[cfg(test)]` blocks throughout `src/`.

```bash
cargo test --lib
```

### Conformance tests

`tests/conformance_tests.rs` — verify eBPF instruction semantics against the
BPF conformance suite. Test data lives in
`tests/upstream/external/bpf_conformance/`.

```bash
cargo test --test conformance_tests
```

### ELF verify tests

`tests/elf_verify_tests.rs` — end-to-end verification of ELF objects from
`tests/upstream/ebpf-samples/`. Tests cover cilium, linux, suricata, falco, ovs, and more.

```bash
cargo test elf_verify
```

### YAML tests

`tests/yaml_tests.rs` — YAML-driven verification fixtures in
`tests/upstream/test-data/` (from the upstream submodule). Schema:
`tests/upstream/test-schema.yaml`.

```bash
cargo test yaml_
```

### Running subsets

```bash
cargo test <pattern>          # match test name
cargo test --lib              # unit tests only
cargo test --test yaml_tests  # single test binary
```

### Certification-aware test runs

For day-to-day workflows, prefer running required suites via `xtask`:

```bash
cargo xtask test all
```

For the `all` suite, this runs:
- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`

The command reuses a local certification when valid, otherwise runs the suite
and updates `tests/certs/<suite>.json` on success.

For faster local iteration without parity suites:

```bash
cargo xtask test all-no-parity
```

- By default, `xtask test` amends `HEAD` to attach/update the suite certification.
  Use `--no-amend` to keep certification only in the worktree.
- Use plain `cargo test ...` when you explicitly want a direct, always-run invocation.
- `pre-push` validates required certifications at `HEAD` and fails if they are missing/stale.
- Default required suites: `all` (override with `PREVAIL_REQUIRED_CERT_SUITES`, comma-separated).
- Certification invalidation ignores `*.md` and `tests/certs/**` by default; add custom exclusions in `.certignore`.

Design rationale and trust model are documented in
[`docs/test-certification.md`](docs/test-certification.md).

### Adding tests

- **YAML**: Add/update fixtures in upstream `tests/upstream/test-data/`,
  then update the submodule pointer in this repo and add `#[test] fn yaml_foo`
  in `tests/yaml_tests.rs`.
- **Conformance**: Add `.data` file to
  `tests/upstream/external/bpf_conformance/tests/`, register in
  `tests/conformance_tests.rs`.
- **ELF verify**: Add entry in `tests/elf_verify_tests.rs` (follow existing patterns).
- **Unit**: Add `#[test]` fn in the relevant `src/` module's `#[cfg(test)]` block.

## Test Taxonomy

- **Conformance** = ISA-level behavior against the `bpf_conformance` suite.
  Primary command: `cargo test --test conformance_tests`.
- **Upstream parity** = exact functional mirroring of upstream Prevail C++ on
  shared fixtures/baselines.
  Primary command: `cargo xtask parity compare`.

Conformance and upstream parity are intentionally separate checks.

## Upstream Parity Testing

Compare Rust verifier output against the upstream C++ verifier.

- **`cargo xtask parity generate-baseline`** — run the C++ binary on all
  samples and cache the output. Run once after building the C++ verifier.
- **`cargo xtask parity compare`** — compare Rust output against the cached
  C++ baseline. No C++ binary needed at comparison time.
- **`cargo xtask parity compare-invariants`** — live side-by-side invariant comparison
  (requires both Rust and C++ binaries).

Baseline cache location:
- default: `target/xtask/upstream_parity/<upstream-hash>/`
- override: set `PREVAIL_PARITY_BASELINE_DIR=/your/cache/root`

## Performance Profiling

### Quick before/after

```bash
cargo xtask bench before-after save       # baseline
# ... make changes ...
cargo xtask bench before-after compare    # compare
```

### Hotspot identification

```bash
cargo build --profile profiling
cargo xtask profile
```

### Deeper analysis

```bash
perf report -i target/xtask/tmp/profile/perf.data --stdio --no-children --percent-limit=0.5
```

### Benchmark CSV format

Run `cargo xtask runperf --help` for usage and output format details.

## Fuzzing Workflow

Install cargo-fuzz once:

```bash
cargo install cargo-fuzz
```

Generate seed corpora from upstream fixtures:

```bash
cargo xtask gen-corpus
```

Run a fuzz target against its corpus:

```bash
cargo fuzz run fuzz_assembler fuzz/corpus/fuzz_assembler
```

Other targets and corpus directories:

- `fuzz_elf_parse` -> `fuzz/corpus/fuzz_elf_parse`
- `fuzz_end_to_end` -> `fuzz/corpus/fuzz_end_to_end`
- `fuzz_btf_parse` -> `fuzz/corpus/fuzz_btf_parse`
- `fuzz_unmarshal` -> `fuzz/corpus/fuzz_unmarshal` (empty by design; structured `Arbitrary` input)

## Upstream Sync

The Rust port tracks the [upstream C++ verifier](https://github.com/vbpf/prevail)
for functional parity. See [docs/upstream-sync.md](docs/upstream-sync.md) for the
full workflow. Summary:

- `tests/upstream` submodule commit is the sync anchor.
- `cargo xtask upstream-diff` shows what changed.
- Port bug fixes, new tests, and semantic changes, relevant architectural refactors; skip C++-specific refactors and CI.
- Commit format: `Port upstream <short-hash>: <summary>`

## Git Conventions

- **DCO sign-off required**: `git commit -s`
- **License headers**: `// SPDX-License-Identifier: MIT`
- **Install hooks**: `cargo xtask hook install` (installs pre-commit, pre-push, commit-msg)
- **CRLF on WSL**: run `dos2unix` on new shell scripts after creating them
- **Formatting**: run `cargo fmt` before committing
- **Linting**: run `cargo clippy` and address warnings
