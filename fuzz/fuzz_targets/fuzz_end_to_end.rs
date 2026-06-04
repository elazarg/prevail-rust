// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![no_main]

use libfuzzer_sys::fuzz_target;
use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader::read_elf;
use prevail::fwd_analyzer;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;

fuzz_target!(|data: &[u8]| {
    if data.len() > 512_000 {
        return;
    }

    let mut platform = LinuxPlatform::new();
    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        ..EbpfVerifierOptions::default()
    };

    let mut raw_progs = match read_elf(data, "fuzz.o", "", "", &opts, &mut platform) {
        Ok(progs) => progs,
        Err(_) => return,
    };

    for raw_prog in &mut raw_progs {
        platform.map_descriptors = raw_prog.info.map_descriptors.clone();

        let mut notes = Vec::new();
        let inst_seq = match unmarshal::unmarshal(
            &raw_prog.prog,
            &mut notes,
            &raw_prog.info,
            &platform,
            &opts,
        ) {
            Ok(seq) => seq,
            Err(_) => continue,
        };

        // `from_sequence` mutates `info` (callback-target sets); rebind read-only.
        let program = match Program::from_sequence(&inst_seq, &mut raw_prog.info, &platform, &opts)
        {
            Ok(prog) => prog,
            Err(_) => continue,
        };
        let info = &raw_prog.info;

        let ctx = DomainContext {
            program_info: info,
            program: &program,
            runtime: &opts.runtime,
            options: &opts,
            platform: &platform,
        };

        let mut registry = VariableRegistry::new();
        let _ = fwd_analyzer::analyze(&program, &ctx, &mut registry);
    }
});
