// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use super::*;
use crate::crab::type_encoding::TypeGroup;
use crate::crab::type_encoding::{T_ALLOC_MEM, T_BTF_ID, T_SOCKET};
use crate::ir::assertions::get_assertions;
use crate::ir::syntax::{
    AccessType, ArgPairKind, ArgSingleKind, Assertion, BinOp, ConditionOp, Instruction, Reg,
    TypeConstraint, ValidAccess, ValidSize, Value,
};
use crate::linux::linux_platform::LinuxPlatform;
use crate::spec::config::EbpfRuntimeConfig;
use crate::spec::vm_isa::{
    AccessSize, EbpfInst, INST_LD_MODE_CODE_ADDR, INST_LD_MODE_MAP_BY_IDX, INST_LD_MODE_MAP_FD,
    INST_LD_MODE_MAP_VALUE, INST_LD_MODE_VARIABLE_ADDR, INST_OP_EXIT, INST_OP_JA16,
    INST_OP_LDDW_IMM,
};

fn get_test_options() -> EbpfVerifierOptions {
    EbpfVerifierOptions {
        mock_map_fds: true,
        runtime: EbpfRuntimeConfig {
            setup_constraints: false,
            ..Default::default()
        },
        ..Default::default()
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
        "Expected error containing '{expected_msg_part}', but got success"
    );
    let err_msg = res.err().unwrap().to_string();
    assert!(
        err_msg.contains(expected_msg_part),
        "Expected error containing '{expected_msg_part}', but got '{err_msg}'"
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
    options.runtime.allow_division_by_zero = false; // Enable checking
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
fn test_unmarshal_lddw_map_value_preserves_next_imm_payload() {
    let platform = LinuxPlatform::new();
    let info = ProgramInfo::default();
    let options = get_test_options();
    let mut notes = Vec::new();

    let insts = vec![
        EbpfInst::new(INST_OP_LDDW_IMM, 1, INST_LD_MODE_MAP_VALUE, 0, 7),
        EbpfInst::new(0, 0, 0, 0, 11),
        EbpfInst::new(INST_OP_EXIT, 0, 0, 0, 0),
    ];
    let prog = unmarshal(&insts, &mut notes, &info, &platform, &options).expect("lddw must parse");
    match &prog[0].1 {
        Instruction::LoadMapAddress(load) => {
            assert_eq!(load.dst.v, 1);
            assert_eq!(load.mapfd, 7);
            assert_eq!(load.offset, 11);
        }
        other => panic!("Expected LoadMapAddress, got {other:?}"),
    }
}

#[test]
fn test_unmarshal_lddw_rejects_reserved_next_imm_fields_for_pseudo_modes() {
    let platform = LinuxPlatform::new();
    let info = ProgramInfo::default();
    let options = get_test_options();

    for src in [
        INST_LD_MODE_MAP_FD,
        INST_LD_MODE_VARIABLE_ADDR,
        INST_LD_MODE_CODE_ADDR,
        INST_LD_MODE_MAP_BY_IDX,
    ] {
        let mut notes = Vec::new();
        let insts = vec![
            EbpfInst::new(INST_OP_LDDW_IMM, 1, src, 0, 7),
            EbpfInst::new(0, 0, 0, 0, 1),
            EbpfInst::new(INST_OP_EXIT, 0, 0, 0, 0),
        ];
        let err = unmarshal(&insts, &mut notes, &info, &platform, &options)
            .expect_err("mode with reserved next_imm must fail");
        assert!(
            err.to_string().contains("lddw uses reserved fields"),
            "unexpected error for src={src}: {err}"
        );
    }
}

#[test]
fn test_make_call_supports_ptr_to_func_for_bpf_loop() {
    let platform = LinuxPlatform::new();
    let call = make_call_result(181, &platform).expect("bpf_loop helper must resolve");
    assert!(call.is_supported);
    assert!(
        call.contract
            .singles
            .iter()
            .any(|arg| arg.kind == ArgSingleKind::PtrToFunc && arg.reg.v == 2)
    );
}

#[test]
fn test_make_call_maps_new_helper_abi_classes() {
    let platform = LinuxPlatform::new();
    let has_single = |call: &Call, kind: ArgSingleKind, reg: u8, or_null: bool| {
        call.contract
            .singles
            .iter()
            .any(|arg| arg.kind == kind && arg.reg.v == reg && arg.or_null == or_null)
    };

    let strtoul = make_call_result(106, &platform).expect("strtoul helper must resolve");
    assert!(strtoul.is_supported, "{}", strtoul.unsupported_reason);
    assert!(has_single(
        &strtoul,
        ArgSingleKind::PtrToWritableLong,
        4,
        false
    ));

    let ringbuf_reserve =
        make_call_result(131, &platform).expect("ringbuf_reserve helper must resolve");
    assert!(
        ringbuf_reserve.is_supported,
        "{}",
        ringbuf_reserve.unsupported_reason
    );
    assert_eq!(ringbuf_reserve.contract.return_ptr_type, Some(T_ALLOC_MEM));
    assert!(ringbuf_reserve.contract.return_nullable);
    assert!(has_single(
        &ringbuf_reserve,
        ArgSingleKind::ConstSizeOrZero,
        2,
        false
    ));

    let ringbuf_submit =
        make_call_result(132, &platform).expect("ringbuf_submit helper must resolve");
    assert!(
        ringbuf_submit.is_supported,
        "{}",
        ringbuf_submit.unsupported_reason
    );
    assert!(has_single(
        &ringbuf_submit,
        ArgSingleKind::PtrToAllocMem,
        1,
        false
    ));

    let per_cpu_ptr = make_call_result(153, &platform).expect("per_cpu_ptr helper must resolve");
    assert!(
        per_cpu_ptr.is_supported,
        "{}",
        per_cpu_ptr.unsupported_reason
    );
    assert_eq!(per_cpu_ptr.contract.return_ptr_type, Some(T_BTF_ID));
    assert!(per_cpu_ptr.contract.return_nullable);
    assert!(has_single(
        &per_cpu_ptr,
        ArgSingleKind::PtrToBtfId,
        1,
        false
    ));

    let this_cpu_ptr = make_call_result(154, &platform).expect("this_cpu_ptr helper must resolve");
    assert!(
        this_cpu_ptr.is_supported,
        "{}",
        this_cpu_ptr.unsupported_reason
    );
    assert_eq!(this_cpu_ptr.contract.return_ptr_type, Some(T_BTF_ID));
    assert!(!this_cpu_ptr.contract.return_nullable);
    assert!(has_single(
        &this_cpu_ptr,
        ArgSingleKind::PtrToBtfId,
        1,
        false
    ));

    let check_mtu = make_call_result(163, &platform).expect("check_mtu helper must resolve");
    assert!(check_mtu.is_supported, "{}", check_mtu.unsupported_reason);
    assert!(has_single(
        &check_mtu,
        ArgSingleKind::PtrToWritableInt,
        3,
        false
    ));

    let timer_init = make_call_result(169, &platform).expect("timer_init helper must resolve");
    assert!(timer_init.is_supported, "{}", timer_init.unsupported_reason);
    assert!(has_single(&timer_init, ArgSingleKind::PtrToTimer, 1, false));

    let sk_fullsock = make_call_result(95, &platform).expect("sk_fullsock helper must resolve");
    assert!(
        sk_fullsock.is_supported,
        "{}",
        sk_fullsock.unsupported_reason
    );
    assert_eq!(sk_fullsock.contract.return_ptr_type, Some(T_SOCKET));
    assert!(sk_fullsock.contract.return_nullable);
    assert!(has_single(
        &sk_fullsock,
        ArgSingleKind::PtrToSocket,
        1,
        false
    ));
}

#[test]
fn test_make_call_keeps_ptr_to_const_str_unsupported() {
    let platform = LinuxPlatform::new();
    let strncmp = make_call_result(182, &platform).expect("strncmp helper must resolve");
    assert!(!strncmp.is_supported);
    assert!(!strncmp.unsupported_reason.is_empty());
}

#[test]
fn test_unmarshal_builtin_calls_only_when_relocation_gated() {
    let platform = LinuxPlatform::new();
    let memset_id = platform
        .resolve_builtin_call("memset")
        .expect("memset builtin id should exist");

    let call_memset = EbpfInst::new(INST_OP_CALL, 0, INST_CALL_STATIC_HELPER, 0, memset_id);
    let exit = EbpfInst::new(INST_OP_EXIT, 0, 0, 0, 0);
    let insts = vec![call_memset, exit, exit];
    let opts = get_test_options();
    let mut notes = Vec::new();

    let info = ProgramInfo {
        program_type: platform.get_program_type("unspec", ""),
        ..ProgramInfo::default()
    };
    let ungated = unmarshal(&insts, &mut notes, &info, &platform, &opts).expect("must unmarshal");
    let Instruction::Call(ungated_call) = &ungated[0].1 else {
        panic!("expected Call")
    };
    assert!(!ungated_call.is_supported);
    assert_eq!(
        &*ungated_call.unsupported_reason,
        "helper function is unavailable on this platform"
    );

    let mut gated_info = ProgramInfo {
        program_type: platform.get_program_type("unspec", ""),
        ..ProgramInfo::default()
    };
    gated_info.builtin_call_offsets.insert(0);
    let gated =
        unmarshal(&insts, &mut notes, &gated_info, &platform, &opts).expect("must unmarshal");
    let Instruction::Call(gated_call) = &gated[0].1 else {
        panic!("expected Call")
    };
    assert!(gated_call.is_supported);
    assert_eq!(&*gated_call.name, "memset");
    assert_eq!(gated_call.func, memset_id);
    assert_eq!(gated_call.contract.singles.len(), 1);
    assert_eq!(gated_call.contract.pairs.len(), 1);
    assert_eq!(gated_call.contract.singles[0].kind, ArgSingleKind::Anything);
    assert_eq!(gated_call.contract.singles[0].reg.v, 2);
    assert_eq!(
        gated_call.contract.pairs[0].kind,
        ArgPairKind::PtrToWritableMem
    );
    assert_eq!(gated_call.contract.pairs[0].mem.v, 1);
    assert_eq!(gated_call.contract.pairs[0].size.v, 3);

    let assertions = get_assertions(
        &Instruction::Call(gated_call.clone()),
        &gated_info,
        &EbpfRuntimeConfig::default(),
        &Some(Label::new(0)),
    );
    assert!(assertions.iter().any(|a| {
        *a == Assertion::TypeConstraint(TypeConstraint {
            reg: Reg { v: 1 },
            types: TypeGroup::Mem,
        })
    }));
    assert!(assertions.iter().any(|a| {
        *a == Assertion::TypeConstraint(TypeConstraint {
            reg: Reg { v: 2 },
            types: TypeGroup::Number,
        })
    }));
    assert!(assertions.iter().any(|a| {
        *a == Assertion::TypeConstraint(TypeConstraint {
            reg: Reg { v: 3 },
            types: TypeGroup::Number,
        })
    }));
    assert!(assertions.iter().any(|a| {
        *a == Assertion::ValidSize(ValidSize {
            reg: Reg { v: 3 },
            can_be_zero: false,
        })
    }));
    assert!(assertions.iter().any(|a| {
        *a == Assertion::ValidAccess(ValidAccess {
            call_stack_depth: 1,
            reg: Reg { v: 1 },
            offset: 0,
            width: Value::Reg(Reg { v: 3 }),
            or_null: false,
            access_type: AccessType::Write,
        })
    }));
}

/// An unconditional jump never uses a source register, so a `JA` whose src
/// field is non-zero is malformed and must be rejected at unmarshal time.
#[test]
fn ja_with_nonzero_src_is_rejected() {
    // JA +1 with src register = 4.
    check_unmarshal_fail(EbpfInst::new(INST_OP_JA16, 0, 4, 1, 0), "bad instruction");
}

/// An out-of-range helper id must produce a structured error rather than abort
/// the process. `make_call_result` is the fallible path that
/// `parse_instruction_with_platform` (and other callers) rely on.
#[test]
fn make_call_result_rejects_out_of_range_helper_id() {
    let platform = LinuxPlatform::new();
    // Well past the prototype table.
    assert!(make_call_result(99999, &platform).is_err());
    assert!(make_call_result(-1, &platform).is_err());
    // A valid helper id still resolves.
    assert!(make_call_result(1, &platform).is_ok());
}

/// The textual parser must degrade an out-of-range `call <imm>` to `Undefined`
/// (which the verifier rejects) rather than panic.
#[test]
fn parse_call_out_of_range_is_undefined_not_panic() {
    use crate::ir::parse::parse_instruction_with_platform;
    use std::collections::BTreeMap;
    let platform = LinuxPlatform::new();
    let labels = BTreeMap::new();
    let inst = parse_instruction_with_platform("call 99999", &labels, Some(&platform));
    assert!(matches!(inst, Instruction::Undefined(_)));
}
