# Subagent playbook

Mission templates for security campaigns against prevail. Each mission is
self-contained: an objective, the exact commands, and what to report back. Spawn
one subagent per mission; they are independent and run in parallel. Findings all
land in `security/findings/<class>/`.

**Ground rules for every mission**
- The verifier must **never crash** (panic/abort/segv) and must **never disagree
  with the C++ reference on a soundness-relevant verdict**. Those are the bugs.
- A finding is only *confirmed* once reproduced from the saved `.o`. Report the
  reproduce command and both verifiers' output.
- Do **not** fix the verifier as part of a hunting mission — report. Fixing is a
  separate, reviewed task (project policy: match upstream / report rather than
  patch unilaterally).
- Build prerequisites once: `cargo build --release` (Rust) and ensure the C++
  binary exists at `tests/upstream/bin/prevail` (auto-built by parity tooling).

---

## Mission 1 — Differential soundness sweep (highest value)

**Objective:** find programs the Rust verifier accepts but the C++ reference
rejects (`soundness`), or where the two diverge (`precision`, `loader`).

```bash
# Run several reproducible shards in parallel (different seeds = different paths).
cargo xtask security diff-fuzz --iters 4000 --seed 1
cargo xtask security diff-fuzz --iters 4000 --seed 2
cargo xtask security diff-fuzz --iters 4000 --seed 3
```

**Report:** counts per bucket; for every `soundness` hit, disassemble the
reproducer (`target/release/prevail --asm - <file>`), explain what unsafe action
the program performs, and state whether C++ is right (→ confirmed Rust bug) or
C++ is over-strict (→ precision). Triage `crash-rust`/`termination` hits too.

---

## Mission 2 — Robustness fuzzing (crash hunt)

**Objective:** any reachable panic/abort/segfault/OOM/hang in the pipeline.

```bash
security/run_fuzz.sh 600                      # all targets, 10 min each
# or focus the deep analyzer surface:
security/run_fuzz.sh 1200 fuzz_program fuzz_end_to_end
```

**Report:** each crash artifact, the panic message + faulting source line
(`src/...:NN`), and the minimized input. Note whether the same input is handled
gracefully by C++ (run `tests/upstream/bin/prevail -q <artifact>`); a graceful
C++ + crashing Rust is a robustness gap specific to the port.

---

## Mission 3 — Malformed container fuzzing (ELF / BTF)

**Objective:** parser bugs in `elf_loader.rs` / `btf/parse.rs` reachable from
hostile but structurally plausible containers.

```bash
security/run_fuzz.sh 600 fuzz_elf_build fuzz_elf_parse fuzz_btf_parse
```

`fuzz_elf_build` synthesizes valid ELF skeletons with adversarial section names,
symbol tables, and instruction blobs — it reaches loader code that raw-byte
fuzzing cannot. **Report** any panic and whether it is a load-time vs
analysis-time failure.

---

## Mission 4 — Termination / complexity (polynomial-runtime guarantee)

**Objective:** inputs that make Rust analysis time or memory blow up
super-linearly (DoS), especially vs C++.

```bash
# diff-fuzz flags timeouts; tighten the budget to catch slow analyses.
cargo xtask security diff-fuzz --iters 3000 --timeout 4
```

Also hand-craft adversarial shapes: deep call chains, maximal-width CFGs, many
distinct stack offsets (stresses `array_domain` OffsetMap), long dependency
chains in the zone domain. Measure with `/usr/bin/time -v target/release/prevail
-q <file>` and compare against C++. **Report** any `termination` bucket hit or
>10× slowdown vs C++ with the program shape that triggers it.

---

## Mission 5 — Assertion-targeted analysis (soundness by construction)

**Objective:** for each safety assertion (see `THREAT_MODEL.md` table), try to
construct a program that *should* trip it but is accepted. Work from the YAML
test format (`tests/upstream/test-data/*.yaml`) — write a `pre:` state and a
`code:` block that performs the borderline-unsafe action, set the expected
verdict to reject, and check Rust agrees.

```bash
# Diff a single crafted YAML case between Rust and C++:
cargo xtask diff yaml-case tests/upstream/test-data/<file>.yaml "<case substring>"
```

Focus areas with known imprecision (from `MEMORY.md` / conformance notes):
atomic ops (`lock_*`), big-endian byte reconstruction, pointer-offset forgetting
on ALU32, packet bounds after arithmetic. **Report** any accepted program that
performs an action the assertion table says must be rejected.

---

## Mission 6 — Interpreter oracle (build, high-effort, future)

**Objective:** the strongest possible soundness oracle. Build a small concrete
eBPF interpreter (ALU + memory + jumps), then: generate random programs → verify
→ for every program the verifier **accepts**, execute it on randomized/edge
inputs and assert no real out-of-bounds access occurs. Verifier says safe +
interpreter hits OOB = a *direct* soundness bug, no C++ needed.

This does not exist yet. Scaffold it under `tests/` or a new `src/bin/`. Start
with the conformance instruction subset (`ir/assembler.rs` covers the encoding).
**Report** a design + a minimal working ALU/memory interpreter and any soundness
divergence it finds.

---

## Coordinating a fleet

- Shard mission 1 across N agents by seed (`--seed 1..N`); they explore disjoint
  mutation paths.
- Run missions 2–4 concurrently — different targets, no shared state besides the
  `findings/` directory (each writes its own class subdir / filenames).
- A final "triage" agent dedupes `findings/`, confirms each by reproduction,
  groups by root-cause source line, and writes `findings/SUMMARY.md`.
