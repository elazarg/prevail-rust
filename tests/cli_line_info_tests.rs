// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! With `--line-info`, the CLI prints an instruction's source line as a block
//! set off by a blank line on each side, including before a verification
//! error, and `--asm` prints no line info but ends with the map descriptors.
//! The expected texts are the upstream C++ verifier's output.

mod path_config;

use std::process::Command;

fn run_prevail(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_prevail"))
        .args(args)
        .output()
        .expect("failed to run the prevail binary");
    String::from_utf8(output.stdout).expect("non-UTF-8 output")
}

fn badmapptr() -> String {
    path_config::upstream_ebpf_sample_path("build/badmapptr.o")
}

#[test]
fn first_failure_is_preceded_by_its_source_line() {
    let expected = "
; /home/alanjo/ebpf-samples/src/badmapptr.c:25
;     uint32_t* value = bpf_map_lookup_elem(map + 1, &key);

4: Invalid type (r1.type in {number, ctx, stack, packet, shared})

FAIL: test/test_repro
";
    assert_eq!(run_prevail(&["--line-info", "-f", &badmapptr()]), expected);
}

#[test]
fn cfg_sets_each_source_line_apart() {
    let expected_prefix = "  from entry;
0:

; /home/alanjo/ebpf-samples/src/badmapptr.c:17
; test_repro(void* ctx)

  r6 = 1;

; /home/alanjo/ebpf-samples/src/badmapptr.c:19
;     uint32_t key = 1;

  *(u32 *)(r10 - 4) = r6;
";
    let output = run_prevail(&["--line-info", "--cfg", &badmapptr()]);
    assert!(output.starts_with(expected_prefix), "{output}");
}

#[test]
fn asm_ends_with_the_map_descriptors() {
    let output = run_prevail(&["--line-info", "--asm", "-", &badmapptr()]);
    let asm = output.split("FAIL: ").next().unwrap_or_default();
    assert!(
        !asm.contains("; /home/"),
        "--asm prints no line info:\n{asm}"
    );
    assert!(
        asm.ends_with(
            "map 0:(original_fd = 1, inner_map_fd = -1, type = 1, max_entries = 1, \
             value_size = 4, key_size = 4)\n"
        ),
        "{asm}"
    );
}
