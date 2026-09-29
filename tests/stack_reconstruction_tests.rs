// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! A load that no single stack cell covers is rebuilt from the numeric bytes
//! underneath it. An 8-byte rebuild yields a uvalue in [0, 2^64) and the
//! matching signed svalue, as upstream's `ArrayDomain::load` does.

mod asm_analysis;

use asm_analysis::analyze_asm_invariants;

#[test]
fn eight_byte_rebuild_keeps_uvalue_unsigned() {
    let invariants = analyze_asm_invariants(
        "\
stb [%r10-8], -1
stb [%r10-7], -1
stb [%r10-6], -1
stb [%r10-5], -1
stb [%r10-4], -1
stb [%r10-3], -1
stb [%r10-2], -1
stb [%r10-1], -1
ldxdw %r0, [%r10-8]
exit
",
    );
    assert!(
        invariants.contains("r0.uvalue=18446744073709551615"),
        "{invariants}"
    );
    assert!(invariants.contains("r0.svalue=-1"), "{invariants}");
}
