# Threat model & finding taxonomy

## Adversary

An attacker who can submit an eBPF object file (ELF) or program to the verifier.
This is the real deployment posture: the verifier exists precisely to gate
untrusted programs. The attacker fully controls every byte of the input —
malformed ELF headers, hostile section tables, adversarial BTF, illegal opcode
streams, and semantically valid programs crafted to defeat the analysis.

## Assets & the safety contract

The verifier enforces a fixed set of assertions (`crab/ebpf_checker.rs`). Each is
a safety property whose *false acceptance* is a soundness hole:

| Assertion | Property | Impact if falsely accepted |
|-----------|----------|----------------------------|
| `ValidAccess` | memory access within stack / packet / context / shared bounds | OOB read/write in kernel |
| `ValidStore` | stored value type matches location | pointer leak / type confusion |
| `Addable` / `Comparable` | only numbers added to / compared with pointers | pointer arithmetic escape |
| `ValidDivisor` | divisor non-zero (when required) | div-by-zero fault |
| `TypeConstraint` / `ZeroCtxOffset` | register has expected type / offset | pointer forgery |
| `ValidMapKeyValue` / `ValidMapType` | map key/value points to valid memory; map type allowed | OOB via map helper |
| `BoundedLoopCount` | loops bounded (≤100000) | non-termination in kernel |
| `FuncConstraint` | helper id resolved & usable | call to disallowed helper |

## Finding taxonomy (diff-fuzz buckets)

`xtask security diff-fuzz` runs the Rust and C++ verifiers on the same mutant and
classifies the `(rust, cpp)` verdict pair. Verdicts: `pass` (exit 0), `reject`
(exit 1), `load-error` (exit 64), `timeout`, `crash` (signal / 128+n), `other`.

| Bucket | Condition | Severity | Meaning |
|--------|-----------|----------|---------|
| **soundness** | rust=pass, cpp=reject | 🔴 critical | Rust accepted a program the reference rejected — candidate missed safety violation. |
| **crash-rust** | rust crashes | 🔴 high | Reachable panic/abort/segv — DoS, and a sign of a broken invariant. |
| **termination** | rust=timeout, cpp finished | 🟠 high | Analysis blow-up — candidate polynomial-runtime violation / DoS. |
| **precision** | rust=reject, cpp=pass | 🟡 medium | Rust over-rejects (precision regression) — *or* C++ is unsound. Inspect. |
| **unmarshal** | soundness/precision pair where the reference rejects at *decode* time | 🟡 medium | The two verifiers decoded the same bytes differently (one rejects an opcode). The verifier may analyze a different program than the kernel runs. Auto-split from soundness/precision so true verifier holes aren't buried. |
| **loader** | disagree on loadability / odd exit codes | 🟡 medium | Parser divergence; may hide a soundness or robustness issue. |
| **crash-cpp** | cpp crashes, rust survives | 🟢 report-upstream | Genuine upstream bug; report to vbpf/prevail. |

### Interpreting a `soundness` or `precision` hit

The C++ verifier is the **reference**, but it is not infallible. A `soundness`
bucket hit is a *candidate*, not a confirmed bug:

1. Reproduce both verdicts (`-v`) from the saved `.o`.
2. Read the program (disassemble: `prevail --asm - <file>`). Does the mutated
   program actually do something unsafe that Rust failed to catch?
3. If yes → confirmed Rust soundness bug. Promote to a tracked regression test
   and fix.
4. If the program is genuinely safe and C++ is the one being overly strict →
   the bucket is mislabeled (C++ false-reject); record under `precision` review.

Per project policy ([match upstream], [principled approach]): when Rust diverges
from C++ on a *valid* program, mirror C++ unless C++ is provably wrong — in which
case document the divergence in-place and report upstream rather than silently
"fixing" it.

[match upstream]: ../AGENTS.md
[principled approach]: ../AGENTS.md

## Out of scope

This harness targets the verifier as a parser/analyzer. It does **not** attempt
host exploitation, kernel interaction, or runtime execution of eBPF (there is no
interpreter). A future high-value addition would be a concrete eBPF interpreter
to serve as a *direct* soundness oracle (execute accepted programs on edge
inputs, flag any real OOB) — see PLAYBOOK mission "interpreter oracle".
