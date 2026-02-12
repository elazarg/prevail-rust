// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![no_main]

use libfuzzer_sys::fuzz_target;
use prevail_rs::ir::assembler::bpf_assemble;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = bpf_assemble(input);
});
