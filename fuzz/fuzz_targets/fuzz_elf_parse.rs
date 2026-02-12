// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![no_main]

use libfuzzer_sys::fuzz_target;
use prevail_rs::elf_loader::read_elf;
use prevail_rs::linux::linux_platform::LinuxPlatform;
use prevail_rs::spec::config::EbpfVerifierOptions;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }
    let platform = LinuxPlatform::new();
    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        ..EbpfVerifierOptions::default()
    };
    let _ = read_elf(data, "fuzz.o", "", "", &opts, &platform);
});
