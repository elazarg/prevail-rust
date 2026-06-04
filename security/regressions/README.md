# Crash reproducers (regression corpus)

Minimized inputs that used to crash the verifier, kept as durable regression
assets for findings whose triggers are awkward to express as Rust unit tests.
Replay them with:

```bash
security/regressions/check.sh        # asserts none of them crash
```

| File | Finding | Was | Fixed by |
|------|---------|-----|----------|
| `elf/F001_inverted_stack_range.o` | F-001 | abort at `array_domain.rs` `all_num_width` (inverted byte range) | graceful `return false` |
| `elf/D001_ja_opcode_divergence.o` | D-001 | Rust accepted a `JA` with non-zero src register that C++ rejects at decode | `src_raw()` guard in unmarshal's JA arm |
| `fuzz_program/F003_local_call_continuation` | F-003 | abort at `cfg/graph.rs` `get_child` (local call without single continuation) | `out_degree` guard in `add_cfg_nodes` |
| `fuzz_end_to_end/CFG01_instruction_at_missing_label` | C-001 | abort at `program.rs` `instruction_at` (local call into the middle of a wide `lddw`) | ValidateControlFlowTargets pass |
| `fuzz_end_to_end/CFG02_get_node_mut_missing_label` | C-002 | abort at `cfg/graph.rs` `get_node_mut` (jump to a non-instruction offset) | ValidateControlFlowTargets pass |
| `sdiv_negative_divisor_panic.yaml` | S-001 | abort at `zone_domain.rs` `assert!(!intv.is_bottom())` (`sdiv` by a negative constant collapsed to bottom) | swap endpoints in `Interval::sdiv` |

The ELF reproducers double as a parity check: `check.sh` only asserts no crash,
but `D001` should now produce exit 1 (reject), matching C++. `check.sh` replays
the `fuzz_end_to_end/` ELFs through the `fuzz_end_to_end` libfuzzer harness.

F-001 and F-002 also have fast Rust unit-test regressions
(`all_num_width_inverted_range_does_not_panic`,
`make_call_result_rejects_out_of_range_helper_id`,
`parse_call_out_of_range_is_undefined_not_panic`). F-003's trigger is a
deeply-nested local-call CFG shape that the fuzzer found; this minimized input
is the regression for it.
