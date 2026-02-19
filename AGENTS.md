# Prevail repository guide for AI agents

## Soundness-first analysis principles
- **Soundness beats throughput.** When updating the analyzer or verifier, favor transfer functions and abstractions with explicit, auditable invariants over heuristic shortcuts. If a micro-optimization risks dropping constraints that protect against false negatives, keep the precise version and document why it is safe.
- **Prove invariants when possible.** Encode the assumptions an analysis relies on—preconditions, lattice properties, monotonicity—directly in types, assertions, or tests before trusting experiments. When you need executable evidence, add deterministic tests or YAML fixtures that demonstrate both the sound and the unsound outcomes you are ruling out.
- **Narrate the reasoning.** Any change that affects analysis results should spell out the argument for soundness: what inputs are assumed, what invariants are maintained, and how the change preserves them. Prefer control flow that makes this reasoning self-evident to future auditors.
- **Default to conservative behavior.** Introduce new analysis features behind flags or with stricter defaults until you can show they do not compromise soundness; never silently relax checks or widen abstractions without justification.
- **Optimize for auditability.** Choose designs that are easy to step through and review by hand—even if they are marginally slower or more verbose—so that a future engineer can re-establish the soundness argument quickly.

## Quick project facts
- **Language:** Pure Rust, ported from the [upstream C++ verifier](https://github.com/vbpf/prevail).
- **Primary deliverables:**
  - `prevail` (binary): command-line verifier for eBPF object files.
  - Test suite: `cargo test` regression suite (~1058 tests).
- **Dependencies:** Managed via `Cargo.toml`.

## Repository map
- `src/lib.rs` — Library entry point.
- `src/main.rs` — CLI binary (`prevail`).
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
cargo build --release      # build CLI
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
- When touching YAML-driven fixtures, update schemas in `tests/upstream/test-schema.yaml` if new fields are introduced.
- Keep runtime/tooling flags documented by updating `README.md` if you introduce new CLI options.
- When in doubt, favor explicit error handling and early returns to surface problems instead of deferring to implicit behavior.
- The upstream C++ source is available in the `tests/upstream` submodule and should be used as the canonical reference for parity work.
- Canonical divergence list for bumping lives in `README.md` under `Known Divergences From Upstream`.

## Upstream bump workflow
- Start with `cargo xtask bump` to sync/update submodules (including nested ones), or:
  - `cargo xtask bump <commit-or-ref>` to bump to a specific commit/ref.
  - `cargo xtask bump <N>` (e.g. `1`, `2`) to move N commits forward from current.
- Identify upstream changes with `cargo xtask upstream-diff`.
- Port changes **piecewise by feature area** (IR, finite domain, loop logic, CLI text, etc.), not as one giant patch.
- You do **not** need to port strictly commit-by-commit: if commit `A` fixes fallout from commit `B`, port `A+B` together.
- After each piece, run focused tests first, then parity checks.
- If a parity mismatch appears, first suspect stale upstream artifacts and rebuild/sync before changing analyzer logic.
- When unsure about cut points, port everything from the pinned commit up to current upstream `main`.
- After updating the `tests/upstream` submodule, run `git submodule update --init --recursive` inside it to sync nested submodules (e.g. `external/libbtf`, `external/bpf_conformance`).
- When `external/libbtf` is bumped, diff its changes and port any functional changes to `src/btf/`. CI-only or build-system-only libbtf changes can be skipped.
- When upstream bumps its project version (in `CMakeLists.txt`), update `version` in `Cargo.toml` to match.
