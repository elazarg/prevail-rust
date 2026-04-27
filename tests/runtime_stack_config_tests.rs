// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! End-to-end tests exercising non-default `EbpfRuntimeConfig`
//! (`--stack-size`, `--max-call-stack-frames`) values.
//!
//! Confirms that stack-size and call-depth are truly runtime parameters:
//! a program accepted at 512-byte per-frame stack is rejected when the
//! per-frame stack is reduced below what the program needs.

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::fwd_analyzer;
use prevail::ir::assembler::bpf_assemble;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::{EbpfRuntimeConfig, EbpfVerifierOptions};
use prevail::spec::ebpf_base::EbpfCtxDescriptor;
use prevail::spec::type_descriptors::{EbpfProgramType, ProgramInfo};

static TEST_CTX: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: 32,
    data: 0,
    end: 8,
    meta: -1,
};

/// Verify an assembly program under the given options.
/// Returns `Ok(())` on accept, `Err(message)` on reject.
fn verify(asm: &str, options: &EbpfVerifierOptions) -> Result<(), String> {
    let instructions = bpf_assemble(asm).map_err(|e| format!("assemble error: {e}"))?;

    let program_type = EbpfProgramType {
        name: "test".to_string(),
        ctx_descriptor: Some(&TEST_CTX),
        platform_specific_data: 0,
        section_prefixes: vec![],
        is_privileged: false,
    };
    let mut info = ProgramInfo {
        program_type,
        ..ProgramInfo::default()
    };
    let platform = LinuxPlatform::new();

    let mut notes = Vec::new();
    let inst_seq = unmarshal::unmarshal(&instructions, &mut notes, &info, &platform, options)
        .map_err(|e| format!("unmarshal error: {e}"))?;

    let program = Program::from_sequence(&inst_seq, &mut info, &platform, options)
        .map_err(|e| format!("cfg build error: {e}"))?;

    let ctx = DomainContext {
        program_info: &info,
        program: &program,
        runtime: &options.runtime,
        options,
        platform: &platform,
    };
    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);

    if result.failed {
        let msg = result
            .find_first_error()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string());
        Err(msg)
    } else {
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

/// A program that writes one u32 at r10-4 — fits in any non-zero stack frame.
const SMALL_STACK_WRITE: &str = "\
mov %r1, 42
stxw [%r10-4], %r1
mov %r0, 0
exit
";

/// A program that writes at r10-400 — needs at least 400 bytes of per-frame stack.
const LARGE_STACK_WRITE: &str = "\
mov %r1, 42
stxw [%r10-400], %r1
mov %r0, 0
exit
";

#[test]
fn default_config_accepts_small_write() {
    let opts = EbpfVerifierOptions::default();
    verify(SMALL_STACK_WRITE, &opts).expect("small stack write should verify");
}

#[test]
fn default_config_accepts_large_write() {
    let opts = EbpfVerifierOptions::default();
    verify(LARGE_STACK_WRITE, &opts).expect("large stack write fits 512-byte default");
}

#[test]
fn reduced_stack_size_rejects_large_write() {
    // Shrink per-frame stack to 256 bytes; the program uses 400.
    let opts = EbpfVerifierOptions {
        runtime: EbpfRuntimeConfig {
            subprogram_stack_size: 256,
            max_call_stack_frames: 16,
            ..EbpfRuntimeConfig::default()
        },
        ..Default::default()
    };
    let err = verify(LARGE_STACK_WRITE, &opts)
        .expect_err("large write should be rejected when per-frame stack is 256");
    assert!(
        err.contains("subprogram_stack_size"),
        "error message should cite subprogram_stack_size: got {err}"
    );
}

#[test]
fn reduced_stack_size_still_accepts_small_write() {
    let opts = EbpfVerifierOptions {
        runtime: EbpfRuntimeConfig {
            subprogram_stack_size: 256,
            max_call_stack_frames: 16,
            ..EbpfRuntimeConfig::default()
        },
        ..Default::default()
    };
    verify(SMALL_STACK_WRITE, &opts).expect("small write still fits 256-byte per-frame");
}

#[test]
fn enlarged_stack_size_accepts_oversize_write() {
    // Per-frame stack = 1024 bytes; write 800 — rejected at default 512, accepted at 1024.
    let program = "\
mov %r1, 42
stxw [%r10-800], %r1
mov %r0, 0
exit
";
    let default_opts = EbpfVerifierOptions::default();
    verify(program, &default_opts)
        .expect_err("800-byte write should be rejected at default 512 per-frame");

    let enlarged = EbpfVerifierOptions {
        runtime: EbpfRuntimeConfig {
            subprogram_stack_size: 1024,
            max_call_stack_frames: 8,
            ..EbpfRuntimeConfig::default()
        },
        ..Default::default()
    };
    verify(program, &enlarged).expect("800-byte write fits 1024-byte per-frame");
}
