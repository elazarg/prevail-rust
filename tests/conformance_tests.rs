// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! BPF conformance test suite for the eBPF verifier.
//!
//! Each `.data` file in `tests/upstream/external/bpf_conformance/tests/`
//! contains BPF assembly,
//! an expected result, and optional memory contents. The test assembles the
//! instructions, runs the verifier, and checks the expected outcome.
//!
//! Ported from `src/test/test_conformance.cpp`.

mod path_config;

use std::collections::BTreeSet;
use std::path::Path;

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::interval::Interval;
use prevail::crab::string_constraints::StringInvariant;
use prevail::crab::var_registry::VariableRegistry;
use prevail::fwd_analyzer;
use prevail::ir::assembler::bpf_assemble;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;
use prevail::spec::ebpf_base::{EBPF_TOTAL_STACK_SIZE, EbpfContextDescriptor};
use prevail::spec::type_descriptors::{EbpfProgramType, ProgramInfo};

// ============================================================================
// .data file parser
// ============================================================================

struct ParsedDataFile {
    asm_text: String,
    result_value: u64,
    memory_bytes: Vec<u8>,
}

fn parse_data_file(path: &Path) -> ParsedDataFile {
    let content = std::fs::read_to_string(path).expect("Failed to read data file");

    #[derive(PartialEq)]
    enum State {
        Ignore,
        Assembly,
        Result,
        Memory,
    }

    let mut state = State::Ignore;
    let mut asm_text = String::new();
    let mut result_string = String::new();
    let mut mem_string = String::new();

    for line in content.lines() {
        // Strip trailing \r
        let line = line.trim_end_matches('\r');
        // Strip comments (for section directives, # is only stripped within content lines)
        let line = if let Some(pos) = line.find('#') {
            &line[..pos]
        } else {
            line
        };

        if line.contains("--") {
            if line.contains("asm") {
                state = State::Assembly;
                continue;
            } else if line.contains("result") {
                state = State::Result;
                continue;
            } else if line.contains("mem") {
                state = State::Memory;
                continue;
            } else {
                // Unknown directive (-- c, -- raw, -- no register offset, -- error): ignore
                state = State::Ignore;
                continue;
            }
        }

        if line.trim().is_empty() {
            continue;
        }

        match state {
            State::Assembly => {
                asm_text.push_str(line);
                asm_text.push('\n');
            }
            State::Result => {
                result_string = line.trim().to_string();
            }
            State::Memory => {
                if !mem_string.is_empty() {
                    mem_string.push(' ');
                }
                mem_string.push_str(line.trim());
            }
            State::Ignore => {}
        }
    }

    // Parse result value
    let result_value = if result_string.is_empty() {
        0
    } else if result_string.contains("0x") || result_string.contains("0X") {
        let hex = result_string
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        u64::from_str_radix(hex, 16).expect("Bad hex result")
    } else {
        result_string.parse::<u64>().expect("Bad decimal result")
    };

    // Parse memory bytes
    let mut memory_bytes = Vec::new();
    if !mem_string.is_empty() {
        for token in mem_string.split_whitespace() {
            if token.is_empty() {
                continue;
            }
            let byte = u8::from_str_radix(token, 16).expect("Bad hex memory byte");
            memory_bytes.push(byte);
        }
    }

    ParsedDataFile {
        asm_text,
        result_value,
        memory_bytes,
    }
}

// ============================================================================
// Stack contents invariant
// ============================================================================

fn add_stack_variable(
    constraints: &mut BTreeSet<String>,
    offset: &mut i32,
    memory_bytes: &[u8],
    size: usize,
) {
    let base = EBPF_TOTAL_STACK_SIZE - memory_bytes.len() as i32;
    let buf_offset = (*offset - base) as usize;
    let src = &memory_bytes[buf_offset..buf_offset + size];

    let range = format!("s[{}...{}]", offset, *offset + size as i32 - 1);

    match size {
        1 => {
            let svalue = src[0] as i8;
            let uvalue = src[0];
            constraints.insert(format!("{range}.svalue={svalue}"));
            constraints.insert(format!("{range}.uvalue={uvalue}"));
        }
        2 => {
            let svalue = i16::from_le_bytes([src[0], src[1]]);
            let uvalue = u16::from_le_bytes([src[0], src[1]]);
            constraints.insert(format!("{range}.svalue={svalue}"));
            constraints.insert(format!("{range}.uvalue={uvalue}"));
        }
        4 => {
            let svalue = i32::from_le_bytes([src[0], src[1], src[2], src[3]]);
            let uvalue = u32::from_le_bytes([src[0], src[1], src[2], src[3]]);
            constraints.insert(format!("{range}.svalue={svalue}"));
            constraints.insert(format!("{range}.uvalue={uvalue}"));
        }
        8 => {
            let svalue = i64::from_le_bytes([
                src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
            ]);
            let uvalue = u64::from_le_bytes([
                src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
            ]);
            constraints.insert(format!("{range}.svalue={svalue}"));
            constraints.insert(format!("{range}.uvalue={uvalue}"));
        }
        _ => unreachable!(),
    }

    *offset += size as i32;
}

fn stack_contents_invariant(memory_bytes: &[u8]) -> StringInvariant {
    let base = EBPF_TOTAL_STACK_SIZE - memory_bytes.len() as i32;
    let end = EBPF_TOTAL_STACK_SIZE;

    let mut constraints = BTreeSet::new();
    constraints.insert("r1.type=stack".to_string());
    constraints.insert(format!("r1.stack_offset={base}"));
    constraints.insert(format!("r1.stack_numeric_size={}", memory_bytes.len()));
    constraints.insert("r10.type=stack".to_string());
    constraints.insert(format!("r10.stack_offset={end}"));
    constraints.insert(format!("s[{base}...{}].type=number", end - 1));

    let mut offset = base;
    // Align to 2-byte boundary
    if offset % 2 != 0 {
        add_stack_variable(&mut constraints, &mut offset, memory_bytes, 1);
    }
    // Align to 4-byte boundary
    if offset % 4 != 0 {
        add_stack_variable(&mut constraints, &mut offset, memory_bytes, 2);
    }
    // Align to 8-byte boundary
    if offset % 8 != 0 {
        add_stack_variable(&mut constraints, &mut offset, memory_bytes, 4);
    }
    // Fill with 8-byte values
    while offset < EBPF_TOTAL_STACK_SIZE {
        add_stack_variable(&mut constraints, &mut offset, memory_bytes, 8);
    }

    StringInvariant::from_set(constraints)
}

// ============================================================================
// Conformance test runner
// ============================================================================

struct ConformanceTestResult {
    success: bool,
    r0_value: Interval,
}

fn run_conformance_test_case(data_file: &Path) -> ConformanceTestResult {
    let parsed = parse_data_file(data_file);

    // Assemble instructions
    let insts = match bpf_assemble(&parsed.asm_text) {
        Ok(insts) => insts,
        Err(e) => panic!("Assembly failed for {}: {e}", data_file.display()),
    };

    // Build conformance context descriptor: {size: 64, data: -1, end: -1, meta: -1}
    let context_descriptor = Box::new(EbpfContextDescriptor {
        size: 64,
        data: -1,
        end: -1,
        meta: -1,
    });

    let program_type = EbpfProgramType {
        name: "conformance_check".to_string(),
        context_descriptor: &*context_descriptor as *const _,
        platform_specific_data: 0,
        section_prefixes: vec![],
        is_privileged: false,
    };

    let info = ProgramInfo {
        program_type,
        ..ProgramInfo::default()
    };

    // Build pre-invariant with optional memory
    let pre_invariant = if !parsed.memory_bytes.is_empty() {
        assert!(
            parsed.memory_bytes.len() <= EBPF_TOTAL_STACK_SIZE as usize,
            "memory size overflow"
        );
        let stack_inv = stack_contents_invariant(&parsed.memory_bytes);
        StringInvariant::top() + stack_inv
    } else {
        StringInvariant::top()
    };

    // Build platform with callx support
    let mut platform = LinuxPlatform::new();
    platform.conformance_groups |= 0x80; // callx
    platform.context_descriptor = info.program_type.context_descriptor;

    let options = EbpfVerifierOptions::default();

    // Unmarshal
    let mut notes = Vec::new();
    let inst_seq = match unmarshal::unmarshal(&insts, &mut notes, &info, &platform, &options) {
        Ok(seq) => seq,
        Err(_) => {
            return ConformanceTestResult {
                success: false,
                r0_value: Interval::top(),
            };
        }
    };

    // Build program
    let prog = match Program::from_sequence(&inst_seq, &info, &options) {
        Ok(p) => p,
        Err(_) => {
            return ConformanceTestResult {
                success: false,
                r0_value: Interval::top(),
            };
        }
    };

    let ctx = DomainContext {
        program_info: &info,
        options: &options,
        platform: &platform,
    };

    let mut registry = VariableRegistry::new();

    let result = fwd_analyzer::analyze_with_entry(&prog, &pre_invariant, &ctx, &mut registry);

    ConformanceTestResult {
        success: !result.failed,
        r0_value: result.exit_value,
    }
}

// ============================================================================
// Test helpers
// ============================================================================

fn data_file_path(filename: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(path_config::UPSTREAM_BPF_CONFORMANCE_TESTS_DIR).join(filename)
}

fn assert_conformance_pass(filename: &str) {
    let path = data_file_path(filename);
    let parsed = parse_data_file(&path);
    let expected = parsed.result_value;
    let result = run_conformance_test_case(&path);
    assert!(
        result.success,
        "Expected verification to pass for {filename}, but it failed"
    );
    let singleton = result.r0_value.singleton();
    assert!(
        singleton.is_some(),
        "Expected singleton r0 for {filename}, got {:?}",
        result.r0_value
    );
    let r0_num = singleton.unwrap();
    // The verifier may store the value as signed. Cast to u64 for comparison,
    // matching the C++ `cast_to<uint64_t>()` behavior.
    let actual = if let Some(v) = r0_num.to_u64() {
        v
    } else if let Some(v) = r0_num.to_i64() {
        v as u64
    } else {
        panic!("r0 not representable as u64 for {filename}: {r0_num:?}");
    };
    assert_eq!(
        actual, expected,
        "r0 mismatch for {filename}: got {actual:#x}, expected {expected:#x}"
    );
}

fn assert_conformance_verification_failed(filename: &str) {
    let path = data_file_path(filename);
    let result = run_conformance_test_case(&path);
    assert!(
        !result.success,
        "Expected verification to fail for {filename}, but it passed"
    );
}

fn assert_conformance_top(filename: &str) {
    let path = data_file_path(filename);
    let result = run_conformance_test_case(&path);
    assert!(
        result.success,
        "Expected verification to pass for {filename}, but it failed"
    );
    assert!(
        result.r0_value.is_top(),
        "Expected r0 to be top for {filename}, got {:?}",
        result.r0_value
    );
}

fn assert_conformance_range(filename: &str) {
    let path = data_file_path(filename);
    let result = run_conformance_test_case(&path);
    assert!(
        result.success,
        "Expected verification to pass for {filename}, but it failed"
    );
    // r0 should not be a singleton — it's an imprecise range (safe over-approximation).
    assert!(
        result.r0_value.singleton().is_none(),
        "Expected r0 to be a range for {filename}, but got singleton"
    );
}

// ============================================================================
// Test macros
// ============================================================================

macro_rules! conformance_pass {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            assert_conformance_pass($file);
        }
    };
}

macro_rules! conformance_verification_failed {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            assert_conformance_verification_failed($file);
        }
    };
}

macro_rules! conformance_top {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            assert_conformance_top($file);
        }
    };
}

macro_rules! conformance_range {
    ($name:ident, $file:expr) => {
        #[test]
        fn $name() {
            assert_conformance_range($file);
        }
    };
}

// ============================================================================
// TEST_CONFORMANCE — verifier passes, r0 matches expected value
// ============================================================================

conformance_pass!(add, "add.data");
conformance_pass!(add64, "add64.data");
conformance_pass!(alu_arith, "alu-arith.data");
conformance_pass!(alu_bit, "alu-bit.data");
conformance_pass!(alu64_arith, "alu64-arith.data");
conformance_pass!(alu64_bit, "alu64-bit.data");
conformance_pass!(arsh32_imm, "arsh32-imm.data");
conformance_pass!(arsh32_imm_high, "arsh32-imm-high.data");
conformance_pass!(arsh32_imm_neg, "arsh32-imm-neg.data");
conformance_pass!(arsh32_reg, "arsh32-reg.data");
conformance_pass!(arsh32_reg_high, "arsh32-reg-high.data");
conformance_pass!(arsh32_reg_neg, "arsh32-reg-neg.data");
conformance_pass!(arsh64_imm, "arsh64-imm.data");
conformance_pass!(arsh64_imm_high, "arsh64-imm-high.data");
conformance_pass!(arsh64_imm_neg, "arsh64-imm-neg.data");
conformance_pass!(arsh64_reg, "arsh64-reg.data");
conformance_pass!(arsh64_reg_high, "arsh64-reg-high.data");
conformance_pass!(arsh64_reg_neg, "arsh64-reg-neg.data");
conformance_pass!(be16_high, "be16-high.data");
conformance_pass!(be16, "be16.data");
conformance_pass!(be32_high, "be32-high.data");
conformance_pass!(be32, "be32.data");
conformance_pass!(be64, "be64.data");
conformance_pass!(bswap16, "bswap16.data");
conformance_pass!(bswap32, "bswap32.data");
conformance_pass!(bswap64, "bswap64.data");
conformance_pass!(call_local, "call_local.data");
conformance_pass!(call_unwind_fail, "call_unwind_fail.data");
conformance_pass!(callx, "callx.data");
conformance_pass!(div32_by_zero_reg, "div32-by-zero-reg.data");
conformance_pass!(div32_by_zero_reg_2, "div32-by-zero-reg-2.data");
conformance_pass!(div32_high_divisor, "div32-high-divisor.data");
conformance_pass!(div32_imm, "div32-imm.data");
conformance_pass!(div32_reg, "div32-reg.data");
conformance_pass!(div64_by_zero_reg, "div64-by-zero-reg.data");
conformance_pass!(div64_imm, "div64-imm.data");
conformance_pass!(div64_negative_imm, "div64-negative-imm.data");
conformance_pass!(div64_negative_reg, "div64-negative-reg.data");
conformance_pass!(div64_reg, "div64-reg.data");
conformance_pass!(exit_not_last, "exit-not-last.data");
conformance_pass!(exit, "exit.data");
conformance_pass!(j_signed_imm, "j-signed-imm.data");
conformance_pass!(ja32, "ja32.data");
conformance_pass!(jeq_imm, "jeq-imm.data");
conformance_pass!(jeq_reg, "jeq-reg.data");
conformance_pass!(jeq32_imm, "jeq32-imm.data");
conformance_pass!(jeq32_reg, "jeq32-reg.data");
conformance_pass!(jge_imm, "jge-imm.data");
conformance_pass!(jge_reg, "jge-reg.data");
conformance_pass!(jge32_imm, "jge32-imm.data");
conformance_pass!(jge32_reg, "jge32-reg.data");
conformance_pass!(jgt_imm, "jgt-imm.data");
conformance_pass!(jgt_reg, "jgt-reg.data");
conformance_pass!(jgt32_imm, "jgt32-imm.data");
conformance_pass!(jgt32_reg, "jgt32-reg.data");
conformance_pass!(jit_bounce, "jit-bounce.data");
conformance_pass!(jle_imm, "jle-imm.data");
conformance_pass!(jle_reg, "jle-reg.data");
conformance_pass!(jle32_imm, "jle32-imm.data");
conformance_pass!(jle32_reg, "jle32-reg.data");
conformance_pass!(jlt_imm, "jlt-imm.data");
conformance_pass!(jlt_reg, "jlt-reg.data");
conformance_pass!(jlt32_imm, "jlt32-imm.data");
conformance_pass!(jlt32_reg, "jlt32-reg.data");
conformance_pass!(jne_reg, "jne-reg.data");
conformance_pass!(jne32_imm, "jne32-imm.data");
conformance_pass!(jne32_reg, "jne32-reg.data");
conformance_pass!(jset_imm, "jset-imm.data");
conformance_pass!(jset_reg, "jset-reg.data");
conformance_pass!(jset32_imm, "jset32-imm.data");
conformance_pass!(jset32_reg, "jset32-reg.data");
conformance_pass!(jsge_imm, "jsge-imm.data");
conformance_pass!(jsge_reg, "jsge-reg.data");
conformance_pass!(jsge32_imm, "jsge32-imm.data");
conformance_pass!(jsge32_reg, "jsge32-reg.data");
conformance_pass!(jsgt_imm, "jsgt-imm.data");
conformance_pass!(jsgt_reg, "jsgt-reg.data");
conformance_pass!(jsgt32_imm, "jsgt32-imm.data");
conformance_pass!(jsgt32_reg, "jsgt32-reg.data");
conformance_pass!(jsle_imm, "jsle-imm.data");
conformance_pass!(jsle_reg, "jsle-reg.data");
conformance_pass!(jsle32_imm, "jsle32-imm.data");
conformance_pass!(jsle32_reg, "jsle32-reg.data");
conformance_pass!(jslt_imm, "jslt-imm.data");
conformance_pass!(jslt_reg, "jslt-reg.data");
conformance_pass!(jslt32_imm, "jslt32-imm.data");
conformance_pass!(jslt32_reg, "jslt32-reg.data");
conformance_pass!(lddw, "lddw.data");
conformance_pass!(lddw2, "lddw2.data");
conformance_pass!(ldxb_all, "ldxb-all.data");
conformance_pass!(ldxb, "ldxb.data");
conformance_pass!(ldxdw, "ldxdw.data");
conformance_pass!(ldxh_all, "ldxh-all.data");
conformance_pass!(ldxh_all2, "ldxh-all2.data");
conformance_pass!(ldxh_same_reg, "ldxh-same-reg.data");
conformance_pass!(ldxh, "ldxh.data");
conformance_pass!(ldxw_all, "ldxw-all.data");
conformance_pass!(ldxw, "ldxw.data");
conformance_pass!(le16, "le16.data");
conformance_pass!(le16_high, "le16-high.data");
conformance_pass!(le32, "le32.data");
conformance_pass!(le32_high, "le32-high.data");
conformance_pass!(le64, "le64.data");
conformance_pass!(lock_add, "lock_add.data");
conformance_pass!(lock_add32, "lock_add32.data");
conformance_pass!(lock_and, "lock_and.data");
conformance_pass!(lock_and32, "lock_and32.data");
conformance_pass!(lock_fetch_add, "lock_fetch_add.data");
conformance_pass!(lock_fetch_add32, "lock_fetch_add32.data");
conformance_pass!(lock_fetch_and, "lock_fetch_and.data");
conformance_pass!(lock_fetch_and32, "lock_fetch_and32.data");
conformance_pass!(lock_fetch_or, "lock_fetch_or.data");
conformance_pass!(lock_fetch_or32, "lock_fetch_or32.data");
conformance_pass!(lock_fetch_xor, "lock_fetch_xor.data");
// Domain imprecision: 32-bit atomic fetch-xor on 64-bit stack value loses precision.
conformance_range!(lock_fetch_xor32, "lock_fetch_xor32.data");
conformance_pass!(lock_or, "lock_or.data");
conformance_pass!(lock_or32, "lock_or32.data");
conformance_pass!(lock_xchg, "lock_xchg.data");
conformance_pass!(lock_xchg32, "lock_xchg32.data");
conformance_pass!(lock_xor, "lock_xor.data");
// Domain imprecision: 32-bit atomic xor on 64-bit stack value loses precision.
conformance_range!(lock_xor32, "lock_xor32.data");
conformance_pass!(lsh32_imm, "lsh32-imm.data");
conformance_pass!(lsh32_imm_high, "lsh32-imm-high.data");
conformance_pass!(lsh32_imm_neg, "lsh32-imm-neg.data");
conformance_pass!(lsh32_reg, "lsh32-reg.data");
conformance_pass!(lsh32_reg_high, "lsh32-reg-high.data");
conformance_pass!(lsh32_reg_neg, "lsh32-reg-neg.data");
conformance_pass!(lsh64_imm, "lsh64-imm.data");
conformance_pass!(lsh64_imm_high, "lsh64-imm-high.data");
conformance_pass!(lsh64_imm_neg, "lsh64-imm-neg.data");
conformance_pass!(lsh64_reg, "lsh64-reg.data");
conformance_pass!(lsh64_reg_high, "lsh64-reg-high.data");
conformance_pass!(lsh64_reg_neg, "lsh64-reg-neg.data");
conformance_pass!(mod_by_zero_reg, "mod-by-zero-reg.data");
conformance_pass!(mod_, "mod.data");
conformance_pass!(mod32, "mod32.data");
conformance_pass!(mod64_by_zero_reg, "mod64-by-zero-reg.data");
conformance_pass!(mod64, "mod64.data");
conformance_pass!(mov, "mov.data");
conformance_pass!(mov64, "mov64.data");
conformance_pass!(mov64_sign_extend, "mov64-sign-extend.data");
conformance_pass!(movsx1632_reg, "movsx1632-reg.data");
conformance_pass!(movsx1664_reg, "movsx1664-reg.data");
conformance_pass!(movsx3264_reg, "movsx3264-reg.data");
conformance_pass!(movsx832_reg, "movsx832-reg.data");
conformance_pass!(movsx864_reg, "movsx864-reg.data");
conformance_pass!(mul32_imm, "mul32-imm.data");
conformance_pass!(
    mul32_intmin_by_negone_imm,
    "mul32-intmin-by-negone-imm.data"
);
conformance_pass!(
    mul32_intmin_by_negone_reg,
    "mul32-intmin-by-negone-reg.data"
);
conformance_pass!(mul32_reg_overflow, "mul32-reg-overflow.data");
conformance_pass!(mul32_reg, "mul32-reg.data");
conformance_pass!(mul64_imm, "mul64-imm.data");
conformance_pass!(
    mul64_intmin_by_negone_imm,
    "mul64-intmin-by-negone-imm.data"
);
conformance_pass!(
    mul64_intmin_by_negone_reg,
    "mul64-intmin-by-negone-reg.data"
);
conformance_pass!(mul64_reg, "mul64-reg.data");
conformance_pass!(neg, "neg.data");
conformance_pass!(neg32_intmin_imm, "neg32-intmin-imm.data");
conformance_pass!(neg32_intmin_reg, "neg32-intmin-reg.data");
conformance_pass!(neg64, "neg64.data");
conformance_pass!(neg64_intmin_imm, "neg64-intmin-imm.data");
conformance_pass!(neg64_intmin_reg, "neg64-intmin-reg.data");
conformance_pass!(rsh32_imm, "rsh32-imm.data");
conformance_pass!(rsh32_imm_high, "rsh32-imm-high.data");
conformance_pass!(rsh32_imm_neg, "rsh32-imm-neg.data");
conformance_pass!(rsh32_reg, "rsh32-reg.data");
conformance_pass!(rsh32_reg_high, "rsh32-reg-high.data");
conformance_pass!(rsh32_reg_neg, "rsh32-reg-neg.data");
conformance_pass!(rsh64_imm, "rsh64-imm.data");
conformance_pass!(rsh64_imm_high, "rsh64-imm-high.data");
conformance_pass!(rsh64_imm_neg, "rsh64-imm-neg.data");
conformance_pass!(rsh64_reg, "rsh64-reg.data");
conformance_pass!(rsh64_reg_high, "rsh64-reg-high.data");
conformance_pass!(rsh64_reg_neg, "rsh64-reg-neg.data");
conformance_pass!(sdiv32_by_zero_imm, "sdiv32-by-zero-imm.data");
conformance_pass!(sdiv32_by_zero_reg, "sdiv32-by-zero-reg.data");
conformance_pass!(sdiv32_imm, "sdiv32-imm.data");
conformance_pass!(
    sdiv32_intmin_by_negone_imm,
    "sdiv32-intmin-by-negone-imm.data"
);
conformance_pass!(
    sdiv32_intmin_by_negone_reg,
    "sdiv32-intmin-by-negone-reg.data"
);
conformance_pass!(sdiv32_reg, "sdiv32-reg.data");
conformance_pass!(sdiv64_by_zero_imm, "sdiv64-by-zero-imm.data");
conformance_pass!(sdiv64_by_zero_reg, "sdiv64-by-zero-reg.data");
conformance_pass!(sdiv64_imm, "sdiv64-imm.data");
conformance_pass!(
    sdiv64_intmin_by_negone_imm,
    "sdiv64-intmin-by-negone-imm.data"
);
conformance_pass!(
    sdiv64_intmin_by_negone_reg,
    "sdiv64-intmin-by-negone-reg.data"
);
conformance_pass!(sdiv64_reg, "sdiv64-reg.data");
conformance_pass!(
    smod32_intmin_by_negone_imm,
    "smod32-intmin-by-negone-imm.data"
);
conformance_pass!(
    smod32_intmin_by_negone_reg,
    "smod32-intmin-by-negone-reg.data"
);
conformance_pass!(smod32_neg_by_neg_imm, "smod32-neg-by-neg-imm.data");
conformance_pass!(smod32_neg_by_neg_reg, "smod32-neg-by-neg-reg.data");
conformance_pass!(smod32_neg_by_pos_imm, "smod32-neg-by-pos-imm.data");
conformance_pass!(smod32_neg_by_pos_reg, "smod32-neg-by-pos-reg.data");
conformance_pass!(smod32_neg_by_zero_imm, "smod32-neg-by-zero-imm.data");
conformance_pass!(smod32_neg_by_zero_reg, "smod32-neg-by-zero-reg.data");
conformance_pass!(smod32_pos_by_neg_imm, "smod32-pos-by-neg-imm.data");
conformance_pass!(smod32_pos_by_neg_reg, "smod32-pos-by-neg-reg.data");
conformance_pass!(
    smod64_intmin_by_negone_imm,
    "smod64-intmin-by-negone-imm.data"
);
conformance_pass!(
    smod64_intmin_by_negone_reg,
    "smod64-intmin-by-negone-reg.data"
);
conformance_pass!(smod64_neg_by_neg_imm, "smod64-neg-by-neg-imm.data");
conformance_pass!(smod64_neg_by_neg_reg, "smod64-neg-by-neg-reg.data");
conformance_pass!(smod64_neg_by_pos_imm, "smod64-neg-by-pos-imm.data");
conformance_pass!(smod64_neg_by_pos_reg, "smod64-neg-by-pos-reg.data");
conformance_pass!(smod64_neg_by_zero_imm, "smod64-neg-by-zero-imm.data");
conformance_pass!(smod64_neg_by_zero_reg, "smod64-neg-by-zero-reg.data");
conformance_pass!(smod64_pos_by_neg_imm, "smod64-pos-by-neg-imm.data");
conformance_pass!(smod64_pos_by_neg_reg, "smod64-pos-by-neg-reg.data");
conformance_pass!(stack, "stack.data");
conformance_pass!(stb, "stb.data");
conformance_pass!(stdw, "stdw.data");
conformance_pass!(sth, "sth.data");
conformance_pass!(stw, "stw.data");
conformance_pass!(stxb_all, "stxb-all.data");
conformance_pass!(stxb_all2, "stxb-all2.data");
conformance_pass!(stxb_chain, "stxb-chain.data");
conformance_pass!(stxb, "stxb.data");
conformance_pass!(stxdw, "stxdw.data");
conformance_pass!(stxh, "stxh.data");
conformance_pass!(stxw, "stxw.data");
conformance_pass!(swap16, "swap16.data");
conformance_pass!(swap32, "swap32.data");
conformance_pass!(swap64, "swap64.data");
conformance_pass!(subnet, "subnet.data");

// ── RFC 9669 generated tests ────────────────────────────────────────────────

conformance_pass!(rfc9669_add32, "rfc9669_add32.data");
conformance_pass!(rfc9669_add64, "rfc9669_add64.data");
conformance_pass!(rfc9669_and32, "rfc9669_and32.data");
conformance_pass!(rfc9669_and64, "rfc9669_and64.data");
conformance_pass!(rfc9669_arsh32, "rfc9669_arsh32.data");
conformance_pass!(rfc9669_arsh64, "rfc9669_arsh64.data");
conformance_pass!(rfc9669_be16, "rfc9669_be16.data");
conformance_pass!(rfc9669_be32, "rfc9669_be32.data");
// Domain imprecision: 64-bit byte swap produces high-bit-set value, comparison loses precision.
conformance_range!(rfc9669_be64, "rfc9669_be64.data");
conformance_pass!(rfc9669_bswap16, "rfc9669_bswap16.data");
conformance_pass!(rfc9669_bswap32, "rfc9669_bswap32.data");
// Domain imprecision: 64-bit byte swap produces high-bit-set value, comparison loses precision.
conformance_range!(rfc9669_bswap64, "rfc9669_bswap64.data");
conformance_pass!(rfc9669_call_local, "rfc9669_call_local.data");
conformance_pass!(rfc9669_div32, "rfc9669_div32.data");
conformance_pass!(rfc9669_div64, "rfc9669_div64.data");
conformance_pass!(rfc9669_exit, "rfc9669_exit.data");
conformance_pass!(rfc9669_ja, "rfc9669_ja.data");
conformance_pass!(rfc9669_ja32, "rfc9669_ja32.data");
conformance_pass!(rfc9669_jeq, "rfc9669_jeq.data");
conformance_pass!(rfc9669_jge, "rfc9669_jge.data");
conformance_pass!(rfc9669_jgt, "rfc9669_jgt.data");
conformance_pass!(rfc9669_jle, "rfc9669_jle.data");
conformance_pass!(rfc9669_jlt, "rfc9669_jlt.data");
conformance_pass!(rfc9669_jne, "rfc9669_jne.data");
conformance_pass!(rfc9669_jset, "rfc9669_jset.data");
conformance_pass!(rfc9669_jsge, "rfc9669_jsge.data");
conformance_pass!(rfc9669_jsgt, "rfc9669_jsgt.data");
conformance_pass!(rfc9669_jsle, "rfc9669_jsle.data");
conformance_pass!(rfc9669_jslt, "rfc9669_jslt.data");
conformance_pass!(rfc9669_lddw, "rfc9669_lddw.data");
conformance_pass!(rfc9669_ldxb, "rfc9669_ldxb.data");
conformance_pass!(rfc9669_ldxdw, "rfc9669_ldxdw.data");
conformance_pass!(rfc9669_ldxh, "rfc9669_ldxh.data");
conformance_pass!(rfc9669_ldxsb, "rfc9669_ldxsb.data");
conformance_pass!(rfc9669_ldxsh, "rfc9669_ldxsh.data");
conformance_pass!(rfc9669_ldxsw, "rfc9669_ldxsw.data");
conformance_pass!(rfc9669_ldxw, "rfc9669_ldxw.data");
conformance_pass!(rfc9669_le16, "rfc9669_le16.data");
conformance_pass!(rfc9669_le32, "rfc9669_le32.data");
conformance_pass!(rfc9669_le64, "rfc9669_le64.data");
conformance_pass!(rfc9669_lock_add32, "rfc9669_lock_add32.data");
conformance_pass!(rfc9669_lock_add64, "rfc9669_lock_add64.data");
conformance_pass!(rfc9669_lock_and32, "rfc9669_lock_and32.data");
conformance_pass!(rfc9669_lock_and64, "rfc9669_lock_and64.data");
conformance_pass!(rfc9669_lock_fetch_add32, "rfc9669_lock_fetch_add32.data");
conformance_pass!(rfc9669_lock_fetch_add64, "rfc9669_lock_fetch_add64.data");
conformance_pass!(rfc9669_lock_or32, "rfc9669_lock_or32.data");
conformance_pass!(rfc9669_lock_or64, "rfc9669_lock_or64.data");
conformance_pass!(rfc9669_lock_xchg32, "rfc9669_lock_xchg32.data");
conformance_pass!(rfc9669_lock_xchg64, "rfc9669_lock_xchg64.data");
conformance_pass!(rfc9669_lock_xor32, "rfc9669_lock_xor32.data");
conformance_pass!(rfc9669_lock_xor64, "rfc9669_lock_xor64.data");
conformance_pass!(rfc9669_lsh32, "rfc9669_lsh32.data");
conformance_pass!(rfc9669_lsh64, "rfc9669_lsh64.data");
conformance_pass!(rfc9669_mod32, "rfc9669_mod32.data");
conformance_pass!(rfc9669_mod64, "rfc9669_mod64.data");
conformance_pass!(rfc9669_mov32, "rfc9669_mov32.data");
conformance_pass!(rfc9669_mov64, "rfc9669_mov64.data");
conformance_pass!(rfc9669_movsx, "rfc9669_movsx.data");
conformance_pass!(rfc9669_mul32, "rfc9669_mul32.data");
conformance_pass!(rfc9669_mul64, "rfc9669_mul64.data");
conformance_pass!(rfc9669_neg32, "rfc9669_neg32.data");
conformance_pass!(rfc9669_neg64, "rfc9669_neg64.data");
conformance_pass!(rfc9669_or32, "rfc9669_or32.data");
conformance_pass!(rfc9669_or64, "rfc9669_or64.data");
conformance_pass!(rfc9669_rsh32, "rfc9669_rsh32.data");
conformance_pass!(rfc9669_rsh64, "rfc9669_rsh64.data");
conformance_pass!(rfc9669_sdiv32, "rfc9669_sdiv32.data");
conformance_pass!(rfc9669_sdiv64, "rfc9669_sdiv64.data");
conformance_pass!(rfc9669_smod32, "rfc9669_smod32.data");
conformance_pass!(rfc9669_smod64, "rfc9669_smod64.data");
conformance_pass!(rfc9669_stb, "rfc9669_stb.data");
conformance_pass!(rfc9669_stdw, "rfc9669_stdw.data");
conformance_pass!(rfc9669_sth, "rfc9669_sth.data");
conformance_pass!(rfc9669_stw, "rfc9669_stw.data");
conformance_pass!(rfc9669_stxb, "rfc9669_stxb.data");
conformance_pass!(rfc9669_stxdw, "rfc9669_stxdw.data");
conformance_pass!(rfc9669_stxh, "rfc9669_stxh.data");
conformance_pass!(rfc9669_stxw, "rfc9669_stxw.data");
conformance_pass!(rfc9669_sub32, "rfc9669_sub32.data");
conformance_pass!(rfc9669_sub64, "rfc9669_sub64.data");
conformance_pass!(rfc9669_swap16, "rfc9669_swap16.data");
conformance_pass!(rfc9669_swap32, "rfc9669_swap32.data");
// Domain imprecision: 64-bit byte swap produces high-bit-set value, comparison loses precision.
conformance_range!(rfc9669_swap64, "rfc9669_swap64.data");
conformance_pass!(rfc9669_xor32, "rfc9669_xor32.data");
conformance_pass!(rfc9669_xor64, "rfc9669_xor64.data");

// ============================================================================
// TEST_CONFORMANCE_VERIFICATION_FAILED — verifier correctly rejects
// ============================================================================

conformance_verification_failed!(mem_len, "mem-len.data");

// ============================================================================
// TEST_CONFORMANCE_TOP — r0 is top/unknown (imprecision, safe)
// ============================================================================

conformance_top!(lock_cmpxchg, "lock_cmpxchg.data");
conformance_top!(lock_cmpxchg32, "lock_cmpxchg32.data");

// ============================================================================
// TEST_CONFORMANCE_RANGE — r0 is a range [lo, hi] (imprecision, safe)
// ============================================================================

conformance_range!(prime, "prime.data");
conformance_range!(rfc9669_lock_cmpxchg32, "rfc9669_lock_cmpxchg32.data");
conformance_range!(rfc9669_lock_cmpxchg64, "rfc9669_lock_cmpxchg64.data");
