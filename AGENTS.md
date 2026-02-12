# Prevail repository guide for AI agents

## Soundness-first analysis principles
- **Soundness beats throughput.** When updating the analyser or verifier, favour transfer functions and abstractions with explicit, auditable invariants over heuristic shortcuts. If a micro-optimisation risks dropping constraints that protect against false negatives, keep the precise version and document why it is safe.
- **Prove invariants when possible.** Encode the assumptions an analysis relies on—preconditions, lattice properties, monotonicity—directly in types, assertions, or tests before trusting experiments. When you need executable evidence, add deterministic tests or YAML fixtures that demonstrate both the sound and the unsound outcomes you are ruling out.
- **Narrate the reasoning.** Any change that affects analysis results should spell out the argument for soundness: what inputs are assumed, what invariants are maintained, and how the change preserves them. Prefer control flow that makes this reasoning self-evident to future auditors.
- **Default to conservative behaviour.** Introduce new analysis features behind flags or with stricter defaults until you can show they do not compromise soundness; never silently relax checks or widen abstractions without justification.
- **Optimise for auditability.** Choose designs that are easy to step through and review by hand—even if they are marginally slower or more verbose—so that a future engineer can re-establish the soundness argument quickly.

## Quick project facts
- **Language:** Pure Rust, ported from the [upstream C++ verifier](https://github.com/vbpf/prevail).
- **Primary deliverables:**
  - `check` (binary, `--features bin`): command-line verifier for eBPF object files.
  - Test suite: `cargo test` regression suite (~1058 tests).
- **Dependencies:** Managed via `Cargo.toml`.

## Repository map
- `src/lib.rs` — Library entry point.
- `src/main.rs` — CLI binary (behind `--features bin`).
- `src/arith/` — Number (SmallNumber: i64 inline, BigInt overflow), ExtendedNumber, SafeI64, Variable, LinearExpression, LinearConstraint.
- `src/btf/` — BTF type parsing.
- `src/cfg/` — Label, Cfg, BasicBlock, WTO (Bourdoncle weak topological ordering).
- `src/crab/` — Abstract domain stack: SplitDBM, zone/finite/type domains, array domain, eBPF domain/transformer/checker.
- `src/elf_loader/` — ELF parser using the `object` crate.
- `src/fwd_analyzer/` — Forward fixpoint iterator.
- `src/ir/` — Instruction representation, parse, unmarshal, marshal, assertions, assembler.
- `src/linux/` — LinuxPlatform, BPF helper prototypes, type descriptors.
- `src/spec/` — VM ISA types, config, eBPF base types.
- `tests/upstream/external/bpf_conformance/` — BPF conformance test data and assembler reference (used by `tests/conformance_tests.rs`).
- `tests/upstream/ebpf-samples/` — Sample ELF objects for verification tests.
- `tests/upstream/test-data/` and `tests/upstream/test-schema.yaml` — YAML-driven verification fixtures (shared with upstream).
- `tests/` — Integration tests (conformance, ELF verify, YAML).
- `xtask/` — Rust-native developer task runner (`cargo xtask --help`).
- `docs/` — Architecture and workflow documentation.

## Build & test

```bash
cargo build                # build library
cargo build --features bin # build CLI
cargo test                 # run all ~1058 tests
cargo clippy               # lint
cargo fmt                  # format
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for testing infrastructure details,
upstream parity testing, performance profiling, and upstream sync workflow.

## Coding standards
- **Formatting:** Run `cargo fmt` before committing.
- **Linting:** Run `cargo clippy` and address warnings.
- **Use Rust idioms:** Prefer enums over integer constants, `Result`/`Option` over sentinel values, traits over inheritance hierarchies, newtypes for domain-specific values.
- **Review for soundness.** Before finishing a change, walk through the modified control-flow and data-flow manually to ensure no unsound analysis paths were introduced.

## Working efficiently
- **Toolchain first.** Before starting a work session, verify the Rust toolchain is current. See [CONTRIBUTING.md](CONTRIBUTING.md#toolchain-version-bump) for the version bump workflow.
- When touching YAML-driven fixtures, update schemas in `tests/upstream/test-schema.yaml` if new fields are introduced.
- Keep runtime/tooling flags documented by updating `README.md` if you introduce new CLI options.
- When in doubt, favour explicit error handling and early returns to surface problems instead of deferring to implicit behaviour.
- The upstream C++ source is available in the `tests/upstream` submodule and should be used as the canonical reference for parity work.
- Canonical divergence list for bumping lives in `README.md` under `Known Divergences From Upstream`.

## Next steps
- **Replace `OffsetMap` with a proper radix/patricia tree.** The Rust port currently
  uses `BTreeMap<u64, BTreeSet<Cell>>` in `src/crab/array_domain.rs` where upstream
  uses a patricia trie (`radix_tree<offset_t, cell_set_t>`) keyed on bit-prefixes
  of offsets. Find or write a Rust radix tree with the needed operations
  (prefix-based lookup, ordered iteration, merge) rather than porting the upstream
  C++ implementation, which is not high quality. This would improve performance
  on programs with dense stack access patterns.
