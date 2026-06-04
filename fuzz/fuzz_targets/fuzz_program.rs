// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Structured fuzzing of the abstract-interpretation core. Where `fuzz_unmarshal`
// stops after decoding instructions, this target drives an arbitrary instruction
// stream all the way through CFG construction and the forward fixpoint analysis —
// the abstract domain transformers and assertion checker, which is where a
// soundness bug would manifest as a panic, a debug-assert failure, or
// non-termination. The verifier must never crash on any input; it may only
// return a pass/reject verdict.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::ir::program::Program;
use prevail::ir::unmarshal::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::ebpf_base::EbpfCtxDescriptor;
use prevail::spec::type_descriptors::{EbpfProgramType, ProgramInfo};
use prevail::spec::vm_isa::EbpfInst;

/// `'static` context descriptor so each fuzz iteration borrows it without
/// leaking a fresh allocation (libfuzzer runs the body millions of times).
static CTX_DESC: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: 64,
    data: -1,
    end: -1,
    meta: -1,
};

#[derive(Debug, Arbitrary)]
struct FuzzInst {
    opcode: u8,
    dst_src: u8,
    offset: i16,
    imm: i32,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    insts: Vec<FuzzInst>,
    strict: bool,
    termination: bool,
}

fuzz_target!(|input: FuzzInput| {
    // Bound program size: the verifier is polynomial, but unbounded inputs make
    // the fuzzer spend all its time on a handful of huge programs.
    if input.insts.is_empty() || input.insts.len() > 512 {
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

    let mut info = ProgramInfo {
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
    let mut opts = EbpfVerifierOptions::default();
    opts.runtime.strict = input.strict;
    opts.runtime.check_for_termination = input.termination;

    let mut notes = Vec::new();
    let inst_seq = match unmarshal(&insts, &mut notes, &info, &platform, &opts) {
        Ok(seq) => seq,
        Err(_) => return,
    };

    let program = match Program::from_sequence(&inst_seq, &mut info, &platform, &opts) {
        Ok(prog) => prog,
        Err(_) => return,
    };

    let ctx = DomainContext {
        program_info: &info,
        program: &program,
        runtime: &opts.runtime,
        options: &opts,
        platform: &platform,
    };

    let mut registry = VariableRegistry::new();
    let _ = prevail::fwd_analyzer::analyze(&program, &ctx, &mut registry);
});
