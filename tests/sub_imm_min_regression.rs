// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! `dst -= 0x80000000` (an immediate that, sign-extended, equals i32::MIN)
//! is an ordinary, unmarshal-accepted encoding. Its negation, 2^31, does not
//! fit in an i32, so the transformer negates the immediate in 64 bits and
//! the program verifies with the exact result.

mod asm_analysis;

use asm_analysis::analyze_asm;
use prevail::crab::interval::Interval;
use prevail::result::AnalysisResult;

fn assert_exits_with(result: &AnalysisResult, expected: i64) {
    assert!(
        !result.failed,
        "expected successful verification: {:?}",
        result.find_first_error()
    );
    assert_eq!(result.exit_value, Interval::from_i64(expected));
}

/// `sub` (ALU64) with an immediate that sign-extends to i32::MIN.
#[test]
fn sub64_immediate_i32_min_verifies() {
    let result = analyze_asm("mov %r0, 0\nsub %r0, 0x80000000\nexit\n");
    assert_exits_with(&result, 0x8000_0000);
}

/// `sub32` (ALU) with the same immediate.
#[test]
fn sub32_immediate_i32_min_verifies() {
    let result = analyze_asm("mov32 %r0, 0\nsub32 %r0, 0x80000000\nexit\n");
    assert_exits_with(&result, 0x8000_0000);
}

/// A `sub` immediate one away from the i32::MIN edge.
#[test]
fn sub64_immediate_near_i32_min_verifies() {
    let result = analyze_asm("mov %r0, 0\nsub %r0, 0x7fffffff\nexit\n");
    assert_exits_with(&result, -0x7fff_ffff);
}
