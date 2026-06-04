# Findings

Reproducers and reports from security campaigns. Layout:

```
findings/
  crash-rust/   # Rust verifier panicked / aborted / segfaulted
  crash-cpp/    # C++ reference crashed (upstream bug — report to vbpf/prevail)
  soundness/    # Rust accepted a program C++ rejected (candidate missed violation)
  precision/    # Rust rejected a program C++ accepted (precision regression / C++ bug)
  termination/  # Rust timed out while C++ finished (complexity / DoS candidate)
  unmarshal/    # the two decode the same bytes differently (one rejects an opcode)
  loader/       # parser / loadability divergence
```

Each finding is `<run>_<NNNN>_<seed>.o` (reproducer) plus a `.txt` report (seed,
mutation, both verdicts, both verifiers' verbose output, reproduce commands).
The `.o`/`.txt` artifacts are **git-ignored** (generated in bulk). Confirmed
bugs are promoted to tracked regression tests, recorded below.

---

## Confirmed & fixed

All three were the same class — a hard `assert!`/`panic!` reachable on hostile
input where C++ degrades gracefully — and each fix mirrors graceful handling
already present elsewhere in the codebase (restoring robustness/parity, not
diverging). Each has a regression test.

### F-001 — `crash-rust`: inverted byte-range assert in the stack domain ✅ fixed
- **Was:** `src/crab/array_domain.rs:584` `assert!(min_lb <= max_ub)` aborted the
  verifier (exit 134) when a stack access (offset ≥ stack size, or negative
  width) drove `as_numbytes_range` to an inverted range.
- **Found by:** diff-fuzz (13 reproducers) and `fuzz_end_to_end` (6) — the
  single most common crash.
- **Fix:** `all_num_width` now returns `false` on an inverted range, mirroring
  its sibling `all_num_lb_ub`.
- **Regression:** `all_num_width_inverted_range_does_not_panic` (array_domain.rs).

### F-002 — `crash-rust`: out-of-range helper id assert ✅ fixed
- **Was:** `src/linux/spec_prototypes.rs:1386` `assert!` (via the *panicking*
  `get_helper_prototype`) aborted on a textual/YAML `call <N>` with N outside
  `[0, 212)`. `make_call_result` — documented as the *fallible* path — wrongly
  called the panicking lookup, and `ir/parse.rs:448` routed through it.
- **Found by:** source audit (the binary unmarshal path was already guarded).
- **Fix:** `make_call_result` now uses the fallible `try_get_helper_prototype`
  and returns `Err`; `parse.rs` emits `Undefined` (which the verifier rejects).
- **Regression:** `make_call_result_rejects_out_of_range_helper_id`,
  `parse_call_out_of_range_is_undefined_not_panic` (unmarshal_tests.rs).

### F-003 — `crash-rust`: local-call continuation assert ✅ fixed
- **Was:** `src/cfg/graph.rs:93` `get_child` `assert_eq!(children.len(), 1)`
  aborted when `ir/program.rs:1148` resolved the return target of a local call
  whose block did not have exactly one continuation (e.g. a local call as the
  last instruction).
- **Found by:** `fuzz_program` (analyzer-level fuzzing, 3 reproducers).
- **Fix:** `add_cfg_nodes` now checks `out_degree == 1` and returns
  `InvalidControlFlow` otherwise — in-pattern with its existing call-frame
  validation.

### D-001 — `unmarshal` divergence: JA with non-zero src register ✅ fixed
- **Was:** `bitflip@0x1b9^0x40` of `xdp1_kern.o` set the src-register nibble of
  instruction 47 (`05 40 02 00…` — a `JA +2` with src=4). C++ rejected it
  (`unmarshaling error at 47: bad instruction op 0x5`); Rust ignored the src
  field and decoded a plain `goto +2`, **analyzing a program the kernel would
  reject** (the harness first mis-bucketed this as `soundness`).
- **Found by:** diff-fuzz, after the F-001 fix stopped it crashing.
- **Cause:** the `JA` arm of `ir/unmarshal.rs` validated the dst field but not
  the src field; an unconditional jump never uses a source register.
- **Fix:** reject `JA` with a non-zero src register (mirrors the conditional-jump
  arm). Regression: `ja_with_nonzero_src_is_rejected` (unmarshal_tests.rs) +
  `security/regressions/elf/D001_ja_opcode_divergence.o`.
- The harness also now auto-reclassifies decode-time divergences into an
  `unmarshal` bucket so genuine soundness candidates aren't buried.
