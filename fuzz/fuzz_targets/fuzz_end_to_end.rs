// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![no_main]

use libfuzzer_sys::fuzz_target;
use prevail_rs::crab::ebpf_domain::DomainContext;
use prevail_rs::crab::var_registry::VariableRegistry;
use prevail_rs::elf_loader::read_elf;
use prevail_rs::fwd_analyzer;
use prevail_rs::ir::program::Program;
use prevail_rs::ir::unmarshal;
use prevail_rs::linux::linux_platform::LinuxPlatform;
use prevail_rs::spec::config::EbpfVerifierOptions;

fuzz_target!(|data: &[u8]| {
    if data.len() > 512_000 {
        return;
    }

    let mut platform = LinuxPlatform::new();
    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        ..EbpfVerifierOptions::default()
    };

    let raw_progs = match read_elf(data, "fuzz.o", "", "", &opts, &platform) {
        Ok(progs) => progs,
        Err(_) => return,
    };

    for raw_prog in &raw_progs {
        platform.map_descriptors = raw_prog.info.map_descriptors.clone();
        platform.context_descriptor = raw_prog.info.program_type.context_descriptor;

        let info = &raw_prog.info;
        let mut notes = Vec::new();
        let inst_seq =
            match unmarshal::unmarshal(&raw_prog.prog, &mut notes, info, &platform, &opts) {
                Ok(seq) => seq,
                Err(_) => continue,
            };

        let program = match Program::from_sequence(&inst_seq, info, &opts) {
            Ok(prog) => prog,
            Err(_) => continue,
        };

        let ctx = DomainContext {
            program_info: info,
            options: &opts,
            platform: &platform,
        };

        let mut registry = VariableRegistry::new();
        let _ = fwd_analyzer::analyze(&program, &ctx, &mut registry);
    }
});
