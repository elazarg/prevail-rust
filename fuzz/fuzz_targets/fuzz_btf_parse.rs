// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![no_main]

use libfuzzer_sys::fuzz_target;
use prevail_rs::btf::parse::parse_types;

fuzz_target!(|data: &[u8]| {
    if data.len() > 512_000 {
        return;
    }
    let _ = parse_types(data);
});
