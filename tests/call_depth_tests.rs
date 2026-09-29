// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! `AnalysisResult::max_call_depth` reports the deepest nesting of BPF-to-BPF
//! calls reachable from the entry, not counting the entry frame.
//!
//! Ports the call-depth cases of `src/test/test_cfg_builder_passes.cpp`.

mod asm_analysis;

use asm_analysis::analyze_asm;

#[test]
fn entry_frame_is_not_counted() {
    let result = analyze_asm("mov %r0, 0\nexit\n");
    assert_eq!(result.max_call_depth, 0);
}

#[test]
fn nested_local_calls_are_counted() {
    // entry -> call subprogram 1 -> call subprogram 2 -> exit.
    let result = analyze_asm(
        "\
call local +2
exit
mov %r0, 0
call local +1
exit
mov %r0, 0
exit
",
    );
    assert_eq!(result.max_call_depth, 2);
}

#[test]
fn unreachable_nested_local_calls_are_excluded() {
    // The calls are retained and inlined during CFG preparation, but are unreachable from entry.
    let result = analyze_asm(
        "\
mov %r0, 0
exit
call local +1
exit
call local +1
exit
mov %r0, 0
exit
",
    );
    assert_eq!(result.max_call_depth, 0);
}

#[test]
fn call_depth_is_kept_after_verification_failure() {
    let result = analyze_asm(
        "\
call local +2
exit
mov %r0, 0
call local +1
exit
stb [%r10-513], 0
mov %r0, 0
exit
",
    );
    // The store is one byte below the innermost 512-byte frame.
    assert!(result.failed);
    assert_eq!(result.max_call_depth, 2);
}
