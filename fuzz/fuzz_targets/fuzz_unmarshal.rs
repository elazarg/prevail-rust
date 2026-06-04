// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use prevail::ir::unmarshal::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::ebpf_base::EbpfCtxDescriptor;
use prevail::spec::type_descriptors::{EbpfProgramType, ProgramInfo};
use prevail::spec::vm_isa::EbpfInst;

/// `'static` context descriptor borrowed by every iteration (no per-run leak).
static CTX_DESC: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: 0,
    data: -1,
    end: -1,
    meta: -1,
};

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    insts: Vec<FuzzInst>,
}

#[derive(Debug, Arbitrary)]
struct FuzzInst {
    opcode: u8,
    dst_src: u8,
    offset: i16,
    imm: i32,
}

fuzz_target!(|input: FuzzInput| {
    if input.insts.len() > 256 {
        return;
    }
    let insts: Vec<EbpfInst> = input
        .insts
        .iter()
        .map(|fi| EbpfInst {
            opcode: fi.opcode,
            dst_src: fi.dst_src,
            offset: fi.offset,
            imm: fi.imm,
        })
        .collect();

    let info = ProgramInfo {
        program_type: EbpfProgramType {
            name: "fuzz".to_string(),
            ctx_descriptor: Some(&CTX_DESC),
            platform_specific_data: 0,
            section_prefixes: vec![],
            is_privileged: false,
            is_sleepable: false,
        },
        ..ProgramInfo::default()
    };

    let platform = LinuxPlatform::new();
    let opts = EbpfVerifierOptions::default();
    let mut notes = Vec::new();
    let _ = unmarshal(&insts, &mut notes, &info, &platform, &opts);
});
