// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Integration tests for failure slicing.
//!
//! Ports `src/test/test_failure_slice.cpp`.

mod path_config;

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader;
use prevail::fwd_analyzer;
use prevail::ir::program::Program;
use prevail::ir::syntax::{Instruction, Reg};
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::result::{AnalysisResult, FailureSlice, SliceParams};
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::type_descriptors::ProgramInfo;

/// Full analysis state for further inspection.
struct AnalysisState {
    result: AnalysisResult,
    program: Program,
    info: ProgramInfo,
    registry: VariableRegistry,
    platform: LinuxPlatform,
    opts: EbpfVerifierOptions,
}

impl AnalysisState {
    /// Compute failure slices from the analysis result.
    fn compute_slices(&mut self) -> Vec<FailureSlice> {
        let ctx = DomainContext {
            program_info: &self.info,
            options: &self.opts,
            platform: &self.platform,
        };
        self.result.compute_failure_slices(
            &self.program,
            &ctx,
            &mut self.registry,
            SliceParams::default(),
        )
    }
}

/// Load, analyze with deps collection, and return full state.
fn analyze_with_deps(filename: &str, section: &str) -> AnalysisState {
    let resolved = path_config::upstream_ebpf_sample_path(filename);
    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        verbosity_opts: prevail::spec::config::VerbosityOptions {
            collect_instruction_deps: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut platform = LinuxPlatform::new();
    let raw_progs = elf_loader::read_elf_file(&resolved, section, "", &opts, &mut platform)
        .unwrap_or_else(|e| panic!("Failed to load ELF {resolved}: {e}"));
    assert_eq!(
        raw_progs.len(),
        1,
        "Expected 1 program in section '{section}'"
    );
    let raw_prog = &raw_progs[0];

    platform.map_descriptors = raw_prog.info.map_descriptors.clone();
    platform.set_program_type(&raw_prog.info.program_type);

    let info = raw_prog.info.clone();
    let insts = &raw_prog.prog;

    let mut notes = Vec::new();
    let inst_seq = unmarshal::unmarshal(insts, &mut notes, &info, &platform, &opts)
        .expect("Failed to unmarshal");

    let program = Program::from_sequence(&inst_seq, &info, &opts).expect("Failed to build CFG");

    let ctx = DomainContext {
        program_info: &info,
        options: &opts,
        platform: &platform,
    };
    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);

    AnalysisState {
        result,
        program,
        info,
        registry,
        platform,
        opts,
    }
}

fn sample_exists(relative: &str) -> bool {
    let path = path_config::upstream_ebpf_sample_path(relative);
    std::path::Path::new(&path).exists()
}

// ============================================================================
// Integration tests
// ============================================================================

#[test]
fn failure_slice_badmapptr() {
    let sample = "build/badmapptr.o";
    if !sample_exists(sample) {
        eprintln!("SKIP: sample file not found: {sample}");
        return;
    }
    let slices = analyze_with_deps(sample, "test").compute_slices();

    assert_eq!(slices.len(), 1);
    assert_eq!(slices[0].relevance.len(), 2);
    assert!(slices[0].relevance.contains_key(&slices[0].failing_label));

    // The failure is about r1 type
    let failing_rel = &slices[0].relevance[&slices[0].failing_label];
    assert_eq!(failing_rel.registers.len(), 1);
    assert!(failing_rel.registers.contains(&Reg { v: 1 }));
}

#[test]
fn failure_slice_exposeptr() {
    let sample = "build/exposeptr.o";
    if !sample_exists(sample) {
        eprintln!("SKIP: sample file not found: {sample}");
        return;
    }
    let slices = analyze_with_deps(sample, ".text").compute_slices();

    assert_eq!(slices.len(), 1);
    assert!(!slices[0].relevance.is_empty());

    let failing_rel = &slices[0].relevance[&slices[0].failing_label];
    assert!(!failing_rel.registers.is_empty());
}

#[test]
fn failure_slice_nullmapref() {
    let sample = "build/nullmapref.o";
    if !sample_exists(sample) {
        eprintln!("SKIP: sample file not found: {sample}");
        return;
    }
    let slices = analyze_with_deps(sample, "test").compute_slices();

    assert!(!slices.is_empty());
    assert!(!slices[0].relevance.is_empty());
}

#[test]
fn passing_program_no_slices() {
    let sample = "build/stackok.o";
    if !sample_exists(sample) {
        eprintln!("SKIP: sample file not found: {sample}");
        return;
    }
    let mut state = analyze_with_deps(sample, ".text");

    assert!(!state.result.failed);
    assert!(state.compute_slices().is_empty());
}

#[test]
fn print_failure_slices_structured_output() {
    let sample = "build/badmapptr.o";
    if !sample_exists(sample) {
        eprintln!("SKIP: sample file not found: {sample}");
        return;
    }
    let mut state = analyze_with_deps(sample, "test");
    let slices = state.compute_slices();

    let mut output = Vec::new();
    prevail::printing::print_failure_slices(
        &mut output,
        &state.program,
        &state.info,
        false,
        &state.result,
        &state.registry,
        &slices,
        false,
    )
    .unwrap();

    let output_str = String::from_utf8(output).unwrap();

    assert!(output_str.contains("[ERROR]"), "Missing [ERROR] section");
    assert!(
        output_str.contains("[LOCATION]"),
        "Missing [LOCATION] section"
    );
    assert!(
        output_str.contains("[RELEVANT REGISTERS]"),
        "Missing [RELEVANT REGISTERS] section"
    );
    assert!(
        output_str.contains("[SLICE SIZE]"),
        "Missing [SLICE SIZE] section"
    );
    assert!(
        output_str.contains("[CAUSAL TRACE]"),
        "Missing [CAUSAL TRACE] section"
    );
}

#[test]
fn assume_guard_registers_in_slice() {
    let sample = "build/dependent_read.o";
    if !sample_exists(sample) {
        eprintln!("SKIP: sample file not found: {sample}");
        return;
    }
    let mut state = analyze_with_deps(sample, "xdp");
    let slices = state.compute_slices();

    assert!(!slices.is_empty());
    let slice = &slices[0];
    assert!(!slice.relevance.is_empty());

    // Check that at least one Assume label is in the slice
    let mut found_assume_in_slice = false;
    for (label, relevance) in &slice.relevance {
        if matches!(state.program.instruction_at(label), Instruction::Assume(_)) {
            found_assume_in_slice = true;
            assert!(!relevance.registers.is_empty());
            break;
        }
    }
    assert!(found_assume_in_slice);
}

#[test]
fn empty_seed_includes_failing_label() {
    let sample = "build/bounded_loop.o";
    if !sample_exists(sample) {
        eprintln!("SKIP: sample file not found: {sample}");
        return;
    }
    let mut state = analyze_with_deps(sample, "test");
    let slices = state.compute_slices();
    if slices.is_empty() {
        // bounded_loop may pass verification depending on build
        eprintln!("SKIP: program passed verification (no failure slices)");
        return;
    }

    for slice in &slices {
        let labels = slice.impacted_labels();
        assert!(labels.contains(&slice.failing_label));
    }
}
