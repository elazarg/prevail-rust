# Security testing infrastructure

White-hat harness for finding security-relevant defects in **prevail-rust** (and,
by differential comparison, the upstream C++ **prevail**). It is designed so that
a human or a fleet of subagents can run focused campaigns against every attack
surface of the verifier and triage what comes back.

This directory is the home of the campaign: the tooling lives in the repo
(`xtask`, `fuzz/`), this folder documents how to drive it and collects findings.

## What we are protecting

prevail is an **eBPF static verifier**. Its job is to decide whether an untrusted
eBPF program is safe to run in the kernel. Two properties matter, in priority
order:

1. **Soundness** — the verifier must **never accept an unsafe program**. A
   soundness bug (verifier says "pass" on a program that performs an
   out-of-bounds access, leaks a pointer, divides by zero, loops forever, …) is
   a kernel-level security hole. This is the crown-jewel bug class.
2. **Robustness / availability** — the verifier must not **crash, hang, or blow
   up in memory** on adversarial input. prevail advertises a *polynomial-runtime*
   guarantee; a crafted program that makes analysis abort (panic) or run
   super-polynomially is a denial-of-service. The binary is built with
   `panic = "abort"`, so any reachable `panic!`/`assert!`/`debug_assert!` or
   slice-out-of-bounds is a hard crash.

Precision regressions (verifier rejects a *safe* program) are correctness bugs,
not security bugs, but the same differential machinery surfaces them for free.

## Attack surfaces

The verifier pipeline, from least to most processed, with the fuzz target that
covers each:

| Stage | Code | Fuzz target |
|-------|------|-------------|
| ELF container parsing | `elf_loader.rs` | `fuzz_elf_parse` (raw bytes), `fuzz_elf_build` (structured ELFs) |
| BTF type parsing | `btf/parse.rs` | `fuzz_btf_parse` |
| Instruction decode (unmarshal) | `ir/unmarshal.rs` | `fuzz_unmarshal` |
| Text assembler | `ir/assembler.rs` | `fuzz_assembler` |
| CFG build + **abstract analysis** | `ir/program.rs`, `crab/*`, `fwd_analyzer.rs` | `fuzz_program` (deepest) |
| Full ELF → verdict | whole pipeline | `fuzz_end_to_end` |

The abstract-interpretation core (`crab/`) is where **soundness** bugs live, and
it is the hardest to reach by random bytes — `fuzz_program` drives it directly
from a structured instruction stream.

## The two oracles

A fuzzer only finds what an *oracle* can flag. We have two:

1. **"Does not crash"** — libfuzzer + `panic = "abort"`. Any panic/abort/segv is
   caught automatically. Covers robustness. (`security/run_fuzz.sh`)

2. **"Agrees with the reference verifier"** — there is **no concrete eBPF
   interpreter** in this project, so the practical ground truth for soundness is
   the upstream **C++ verifier**, which both implementations are kept in parity
   with. `xtask security diff-fuzz` mutates real, loadable eBPF objects inside
   their instruction sections and runs both verifiers on every mutant, bucketing
   divergences by severity. The bucket that matters most:

   > **soundness** = *Rust accepts a program the C++ verifier rejects.*

   The Rust port may have missed a safety violation the reference caught.

   See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full bucket taxonomy and how
   to interpret each.

## Quick start

```bash
# 0. Build both verifiers once (release Rust + C++ upstream).
cargo build --release
cargo xtask run-upstream -- --help    # triggers the C++ auto-build if needed

# 1. Crash/robustness fuzzing — run every libfuzzer target for a budget.
security/run_fuzz.sh 300                # 300s per target, triage to findings/

# 2. Differential soundness fuzzing — Rust vs C++ on mutated real objects.
cargo xtask security diff-fuzz --time 600           # 10 min campaign
cargo xtask security diff-fuzz --iters 5000 --seed 42   # reproducible run

# 3. Reproduce a libfuzzer crash.
cd fuzz && cargo +nightly fuzz run fuzz_program path/to/crash-input
```

## Findings

Everything lands in [`findings/`](findings/), one subdirectory per class
(`crash-rust/`, `soundness/`, `precision/`, `termination/`, `loader/`,
`crash-cpp/`). Each finding is a self-contained reproducer (`.o` + a `.txt`
report with both verifiers' output and the exact reproduce commands). Generated
reproducers are git-ignored; promote a *confirmed* bug to a tracked regression
test before fixing.

See [`PLAYBOOK.md`](PLAYBOOK.md) for subagent mission templates.
