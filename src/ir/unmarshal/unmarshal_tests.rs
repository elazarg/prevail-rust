// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use super::*;
use crate::ir::syntax::{ArgSingleKind, BinOp, ConditionOp};
use crate::linux::linux_platform::LinuxPlatform;
use crate::spec::config::{PrepareCfgOptions, VerbosityOptions};
use crate::spec::vm_isa::{AccessSize, EbpfInst, INST_OP_EXIT};

fn get_test_options() -> EbpfVerifierOptions {
    EbpfVerifierOptions {
        cfg_opts: PrepareCfgOptions {
            check_for_termination: false,
            must_have_exit: false,
        },
        mock_map_fds: true,
        strict: false,
        allow_division_by_zero: true,
        setup_constraints: false,
        big_endian: false,
        verbosity_opts: VerbosityOptions::default(),
    }
}

fn check_unmarshal_succeed(ins: EbpfInst) -> InstructionSeq {
    let platform = LinuxPlatform::new();
    let info = ProgramInfo::default();
    let options = get_test_options();
    let mut notes = Vec::new();

    let exit = EbpfInst::new(INST_OP_EXIT, 0, 0, 0, 0);
    let insts = vec![ins, exit, exit];

    let res = unmarshal(&insts, &mut notes, &info, &platform, &options);
    assert!(res.is_ok(), "Unmarshal failed: {:?}", res.err());
    let prog = res.unwrap();
    // We expect 3 instructions: ins, exit, exit (plus fallthrough logic handled inside unmarshal which generates one Instruction per EbpfInst unless skipped)
    assert_eq!(prog.len(), 3);
    prog
}

fn check_unmarshal_fail(ins: EbpfInst, expected_msg_part: &str) {
    let platform = LinuxPlatform::new();
    let info = ProgramInfo::default();
    let options = get_test_options();
    let mut notes = Vec::new();

    // We need enough instructions to avoid "incomplete lddw" if testing lddw start, etc.
    // usage: check_unmarshal_fail(ins, "expected error")
    let exit = EbpfInst::new(INST_OP_EXIT, 0, 0, 0, 0);
    let insts = vec![ins, exit];

    let res = unmarshal(&insts, &mut notes, &info, &platform, &options);
    assert!(
        res.is_err(),
        "Expected error containing '{}', but got success",
        expected_msg_part
    );
    let err_msg = res.err().unwrap().to_string();
    assert!(
        err_msg.contains(expected_msg_part),
        "Expected error containing '{}', but got '{}'",
        expected_msg_part,
        err_msg
    );
}

#[test]
fn test_unmarshal_alu_basic() {
    // r1 = r2 + 10 (ALU64)
    let ins = EbpfInst::new(INST_CLS_ALU64 | INST_ALU_OP_ADD | INST_SRC_IMM, 1, 0, 0, 10);
    let prog = check_unmarshal_succeed(ins);
    match &prog[0].1 {
        Instruction::Bin(bin) => {
            assert_eq!(bin.op, BinOp::ADD);
            assert_eq!(bin.dst.v, 1);
            assert!(bin.is64);
            match bin.v {
                Value::Imm(imm) => assert_eq!(imm.v, 10),
                _ => panic!("Expected immediate"),
            }
        }
        _ => panic!("Expected Bin instruction"),
    }
}

#[test]
fn test_unmarshal_mov_reg() {
    // r1 = r2
    let ins = EbpfInst::new(INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_REG, 1, 2, 0, 0);
    let prog = check_unmarshal_succeed(ins);
    match &prog[0].1 {
        Instruction::Bin(bin) => {
            assert_eq!(bin.op, BinOp::MOV);
            assert_eq!(bin.dst.v, 1);
            match bin.v {
                Value::Reg(reg) => assert_eq!(reg.v, 2),
                _ => panic!("Expected register"),
            }
        }
        _ => panic!("Expected Bin instruction"),
    }
}

#[test]
fn test_unmarshal_fail_bad_reg() {
    // r11 = r1 (r11 is invalid dst)
    let ins = EbpfInst::new(INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_REG, 11, 1, 0, 0);
    check_unmarshal_fail(ins, "bad register");
}

#[test]
fn test_unmarshal_div_zero() {
    // r1 = r1 / 0
    // This is valid instruction syntax, but might trigger a note if checks enabled.
    // Unmarshaller should not fail, but maybe log a note.
    let ins = EbpfInst::new(INST_CLS_ALU64 | INST_ALU_OP_DIV | INST_SRC_IMM, 1, 0, 0, 0);

    let platform = LinuxPlatform::new();
    let info = ProgramInfo::default();
    let mut options = get_test_options();
    options.allow_division_by_zero = false; // Enable checking
    let mut notes = Vec::new();
    let insts = vec![ins, EbpfInst::new(INST_OP_EXIT, 0, 0, 0, 0)];

    let res = unmarshal(&insts, &mut notes, &info, &platform, &options);
    assert!(res.is_ok());
    // Check notes for division by zero
    let has_div_zero = notes.iter().flatten().any(|n| n == "division by zero");
    assert!(has_div_zero, "Expected division by zero note");
}

#[test]
fn test_unmarshal_packet_access() {
    // r0 = *(u32 *)skb[123] (ABS)
    // opcode: LD | ABS | W
    let ins = EbpfInst::new(INST_CLS_LD | INST_MODE_ABS | INST_SIZE_W, 0, 0, 0, 123);
    let prog = check_unmarshal_succeed(ins);
    match &prog[0].1 {
        Instruction::Packet(pkt) => {
            assert_eq!(pkt.width, AccessSize::Word);
            assert_eq!(pkt.offset, 123);
            assert!(pkt.regoffset.is_none());
        }
        _ => panic!("Expected Packet instruction"),
    }
}

#[test]
fn test_unmarshal_mem_load() {
    // r1 = *(u64 *)(r2 + 0)
    let ins = EbpfInst::new(INST_CLS_LDX | INST_MODE_MEM | INST_SIZE_DW, 1, 2, 0, 0);
    let prog = check_unmarshal_succeed(ins);
    match &prog[0].1 {
        Instruction::Mem(mem) => {
            assert!(mem.is_load);
            assert_eq!(mem.access.width, AccessSize::DWord);
            assert_eq!(mem.access.basereg.v, 2);
            assert_eq!(mem.access.offset, 0);
            match mem.value {
                Value::Reg(r) => assert_eq!(r.v, 1),
                _ => panic!("Expected reg value"),
            }
        }
        _ => panic!("Expected Mem instruction"),
    }
}

#[test]
fn test_unmarshal_jmp_eq() {
    // if r1 == 10 goto +1
    // JEQ imm: opcode 0x15
    let ins = EbpfInst::new(0x15, 1, 0, 1, 10);
    let prog = check_unmarshal_succeed(ins);
    match &prog[0].1 {
        Instruction::Jmp(jmp) => {
            assert_eq!(jmp.target.from, 2); // pc + 1 + offset = 0 + 1 + 1 = 2
            let cond = jmp.cond.as_ref().expect("Expected condition");
            assert_eq!(cond.op, ConditionOp::EQ);
            match cond.right {
                Value::Imm(imm) => assert_eq!(imm.v, 10),
                _ => panic!("Expected immediate"),
            }
        }
        _ => panic!("Expected Jmp instruction"),
    }
}

#[test]
fn test_unmarshal_exit() {
    let ins = EbpfInst::new(INST_OP_EXIT, 0, 0, 0, 0);
    let prog = check_unmarshal_succeed(ins);
    match &prog[0].1 {
        Instruction::Exit(_) => {}
        _ => panic!("Expected Exit instruction"),
    }
}

#[test]
fn test_make_call_supports_ptr_to_func_for_bpf_loop() {
    let platform = LinuxPlatform::new();
    let call = make_call_result(181, &platform).expect("bpf_loop helper must resolve");
    assert!(call.is_supported);
    assert!(
        call.singles
            .iter()
            .any(|arg| arg.kind == ArgSingleKind::PtrToFunc && arg.reg.v == 2)
    );
}
