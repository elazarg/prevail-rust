// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Shared helper for integration tests that verify a small assembly program
//! under default options.

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::fwd_analyzer;
use prevail::ir::assembler::bpf_assemble;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::result::AnalysisResult;
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::ebpf_base::EbpfCtxDescriptor;
use prevail::spec::type_descriptors::{EbpfProgramType, ProgramInfo};

/// A 64-byte context with no packet pointers.
static TEST_CTX: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: 64,
    data: -1,
    end: -1,
    meta: -1,
};

/// Assemble, unmarshal, and analyze `asm_text` under default verifier options.
pub fn analyze_asm(asm_text: &str) -> AnalysisResult {
    let insts = bpf_assemble(asm_text).expect("assembly failed");

    let program_type = EbpfProgramType {
        name: "asm_test".to_string(),
        ctx_descriptor: Some(&TEST_CTX),
        platform_specific_data: 0,
        section_prefixes: vec![],
        is_privileged: false,
        is_sleepable: false,
    };
    let mut info = ProgramInfo {
        program_type,
        ..ProgramInfo::default()
    };

    let mut platform = LinuxPlatform::new();
    platform.set_program_type(&info.program_type);
    let options = EbpfVerifierOptions::default();

    let mut notes = Vec::new();
    let inst_seq = unmarshal::unmarshal(&insts, &mut notes, &info, &platform, &options)
        .expect("unmarshal failed");
    let program = Program::from_sequence(&inst_seq, &mut info, &platform, &options)
        .expect("CFG build failed");

    let ctx = DomainContext {
        program_info: &info,
        program: &program,
        runtime: &options.runtime,
        options: &options,
        platform: &platform,
    };
    let mut registry = VariableRegistry::new();
    fwd_analyzer::analyze(&program, &ctx, &mut registry)
}
