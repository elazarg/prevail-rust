# PREVAIL - A new eBPF verifier (Rust port)

## a Polynomial-Runtime EBPF Verifier using an Abstract Interpretation Layer

This is a Rust port of the [original C++ implementation](https://github.com/vbpf/prevail).

The version discussed in the [PLDI paper](https://vbpf.github.io/assets/prevail-paper.pdf) is
available [here](https://github.com/vbpf/prevail/tree/d29fd26345c3126bf166cf1c45233a9b2f9fb0a0).

### CLI usage

```bash
prevail tests/upstream/ebpf-samples/cilium/bpf_lxc.o 2/1
```

The output is three comma-separated values:

* 1 or 0, for "pass" and "fail" respectively
* The runtime of the fixpoint algorithm (in seconds)
* The peak memory consumption, in kb, as reflected by the resident-set size (rss)

Additional flags: `--asm <file>` (disassembly), `--dot <file>` (CFG dot graph), `-v` (verbose invariants), `-f` (print first failure).

## Goals

- **Functional parity with upstream.** The Rust verifier should accept and reject
  the same programs as the [upstream C++ verifier](https://github.com/vbpf/prevail),
  and pass the same (or a superset of) test cases. Added features must be first accepted to upstream.
- **Idiomatic Rust.** use idiomatic Rust while preserving correctness.

## Test Taxonomy

The repository uses two distinct test concepts:

- **Conformance**: ISA semantics checks using the `bpf_conformance` corpus.
  Run with `cargo test --test conformance_tests`.
- **Upstream parity**: behavioral equivalence checks against the upstream C++
  Prevail verifier on shared fixtures/baselines.
  Run with `cargo xtask parity compare`.

## Upstream Sync

The `tests/upstream` submodule pins the upstream C++ commit used as
the sync anchor. See [docs/upstream-sync.md](docs/upstream-sync.md) for the
full sync workflow.

Quick check for new upstream changes:

```bash
cargo xtask upstream-diff
```

## Known Divergences From Upstream

These are intentional design/architecture differences that are useful to keep
in mind when bumping upstream:

- **Thread-local globals replaced by explicit context passing.**
  Rust uses `DomainContext` (thread-safe and explicit) instead of C++
  `thread_local_*` globals.
- **`Number` uses `i128` implementation detail.**
  Rust arithmetic uses `i128` for verifier numeric values rather than the
  previous BigInt-style representation.
- **BTF is ported and used natively in Rust.**
  Rust has its own `src/btf/` implementation used by ELF loading and CO-RE
  relocation handling; it is not a direct runtime link to upstream `libbtf`.
- **Canonical fixtures come from upstream submodule.**
  YAML tests and schema are read from `tests/upstream/test-data/` and
  `tests/upstream/test-schema.yaml`, not duplicated in this repo.
- **Test/CI infrastructure is Rust-repo specific.**
  Differential scripts and CI orchestration differ from upstream CMake/Catch2,
  while preserving parity goals.
- **Array offset map data structure differs.**
  Rust currently uses `BTreeMap` where upstream uses a radix/patricia tree.
  This is mostly a performance/design divergence and can affect bump effort.

If an upstream change touches one of these areas, a bump is likely to require
manual adaptation rather than mechanical porting.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (version pinned in `rust-toolchain.toml`)

### Building

```bash
cargo build --release
```

### Installing the CLI

To work from the local checkout:

```bash
cargo install --path .
```

To install the released crate with the `prevail` binary already wired up:

```bash
cargo install prevail
```

Both commands drop a `prevail` executable into your Cargo bin directory thanks to the default `prevail` binary entry in `Cargo.toml`.

### Running tests

```bash
cargo test
```

For final testing, before a push, prefer:

```bash
cargo xtask test all
```

This runs `fmt`, `clippy`, and tests through the local certification/cache workflow used by hooks.
By default it amends `HEAD` to attach certification metadata (`--no-amend` to opt out).
Use plain `cargo test` any time you want a direct, always-run test invocation.

For faster local iteration (without parity suites), use:

```bash
cargo xtask test all-no-parity
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflows.

### Fuzzing

```bash
cargo xtask gen-corpus
cargo fuzz run fuzz_assembler fuzz/corpus/fuzz_assembler
```

Seed corpora are generated under `fuzz/corpus/` from upstream conformance and
ELF sample fixtures.

## License

See [LICENSE.txt](LICENSE.txt).
