// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Regression test: `dst -= 0x80000000` (an immediate that, sign-extended,
//! equals i32::MIN) must not crash the verifier.
//!
//! `-imm` on the truncated `i32` overflows exactly when `imm == i32::MIN`;
//! this instruction is otherwise a perfectly ordinary, unmarshal-accepted
//! encoding. Upstream C++ hits the same edge (`gsl::narrow<int>(-imm)`
//! throws) and reports it as a clean verification failure rather than
//! crashing (see `main.cpp`'s top-level `catch (const std::exception&)`).
//! The Rust port must fail the same way instead of panicking/aborting
//! (this crate builds with `panic = "abort"`, so an arithmetic-overflow
//! panic here would take down the whole process).

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::fwd_analyzer;
use prevail::ir::assembler::bpf_assemble;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::ebpf_base::EbpfCtxDescriptor;
use prevail::spec::type_descriptors::{EbpfProgramType, ProgramInfo};

fn analyze_asm(asm_text: &str) -> prevail::result::AnalysisResult {
    let insts = bpf_assemble(asm_text).expect("assembly failed");

    let ctx_descriptor: &'static EbpfCtxDescriptor = Box::leak(Box::new(EbpfCtxDescriptor {
        size: 64,
        data: -1,
        end: -1,
        meta: -1,
    }));
    let program_type = EbpfProgramType {
        name: "sub_imm_min_regression".to_string(),
        ctx_descriptor: Some(ctx_descriptor),
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

/// `sub` (ALU64) with an immediate that sign-extends to i32::MIN must not panic.
#[test]
fn sub64_immediate_i32_min_does_not_panic() {
    let result = analyze_asm("mov %r0, 0\nsub %r0, 0x80000000\nexit\n");
    // Matching upstream's gsl::narrow<int> throw, this immediate cannot be
    // modeled precisely and the program is rejected -- the important
    // invariant this test guards is that verification returns cleanly
    // instead of crashing the process.
    assert!(result.failed, "expected a clean verification failure");
}

/// `sub32` (ALU) with the same immediate must not panic either.
#[test]
fn sub32_immediate_i32_min_does_not_panic() {
    let result = analyze_asm("mov32 %r0, 0\nsub32 %r0, 0x80000000\nexit\n");
    assert!(result.failed, "expected a clean verification failure");
}

/// A `sub` immediate one away from the overflow edge must still verify
/// normally (guards against an overly broad fix).
#[test]
fn sub64_immediate_near_i32_min_still_verifies() {
    let result = analyze_asm("mov %r0, 0\nsub %r0, 0x7fffffff\nexit\n");
    assert!(
        !result.failed,
        "expected successful verification: {:?}",
        result.find_first_error()
    );
}
