// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Shared helpers for integration tests that verify a small assembly program
//! under default options.

// Each test binary that includes this module uses a different subset, so what
// is dead varies by target and `#[expect]` cannot hold for all.
#![allow(dead_code)]

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::fwd_analyzer;
use prevail::ir::assembler::bpf_assemble;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::printing;
use prevail::result::AnalysisResult;
use prevail::spec::config::{EbpfVerifierOptions, VerbosityOptions};
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
    with_analysis(asm_text, |result, _, _, _| result)
}

/// Analyze `asm_text` and render its invariants as `-v` prints them.
pub fn analyze_asm_invariants(asm_text: &str) -> String {
    with_analysis(asm_text, |result, program, info, registry| {
        let mut out = Vec::new();
        let verbosity = VerbosityOptions {
            simplify: false,
            ..VerbosityOptions::default()
        };
        printing::print_invariants(&mut out, program, info, &verbosity, &result, registry)
            .expect("print_invariants failed");
        String::from_utf8(out).expect("non-UTF-8 invariant output")
    })
}

fn with_analysis<R>(
    asm_text: &str,
    inspect: impl FnOnce(AnalysisResult, &Program, &ProgramInfo, &VariableRegistry) -> R,
) -> R {
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
        options: &options,
        platform: &platform,
    };
    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);
    inspect(result, &program, &info, &registry)
}
