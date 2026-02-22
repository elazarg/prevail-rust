// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Pure helper functions ported from `src/ir/unmarshal.cpp`.

use std::rc::Rc;

use crate::cfg::label::Label;
use crate::crab::type_encoding::{T_ALLOC_MEM, T_BTF_ID, T_SOCKET};
use crate::ir::syntax::{
    ArgPair, ArgPairKind, ArgSingle, ArgSingleKind, Atomic, AtomicOp, Bin, BinOp, Call, CallBtf,
    CallKind, CallLocal, Callx, Condition, ConditionOp, Deref, Exit, Imm, Instruction,
    InstructionSeq, Jmp, LoadMapAddress, LoadMapFd, LoadPseudo, Mem, Packet, PseudoAddress,
    PseudoAddressKind, Reg, Un, UnOp, Value,
};
use crate::platform::EbpfPlatform;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::type_descriptors::ProgramInfo;
use crate::spec::vm_isa::*;

pub use crate::linux::linux_platform::conformance_groups;

/// Returns true if the opcode class is a load (LD/LDX), false for store (ST/STX).
fn get_mem_is_load(opcode: u8) -> bool {
    match opcode & INST_CLS_MASK {
        INST_CLS_LD | INST_CLS_LDX => true,
        INST_CLS_ST | INST_CLS_STX => false,
        _ => unreachable!("unexpected opcode class in {opcode:#04x}"),
    }
}

/// Sign-extend a 32-bit signed integer to a 64-bit unsigned integer.
fn sign_extend(imm: i32) -> u64 {
    imm as i64 as u64
}

/// Zero-extend a 32-bit signed integer to a 64-bit unsigned integer.
fn zero_extend(imm: i32) -> u64 {
    imm as u32 as u64
}

/// Map a `JmpOp` to the corresponding `ConditionOp` for conditional jumps.
///
/// JA, CALL, and EXIT are non-conditional and produce a default `ConditionOp::EQ`
/// (the caller handles these cases before reaching this function).
fn jmp_op_to_cond(op: JmpOp) -> ConditionOp {
    match op {
        JmpOp::JA => ConditionOp::EQ, // goto -- handled before reaching here
        JmpOp::JEQ => ConditionOp::EQ,
        JmpOp::JGT => ConditionOp::GT,
        JmpOp::JGE => ConditionOp::GE,
        JmpOp::JSET => ConditionOp::SET,
        JmpOp::JNE => ConditionOp::NE,
        JmpOp::JSGT => ConditionOp::SGT,
        JmpOp::JSGE => ConditionOp::SGE,
        JmpOp::CALL => ConditionOp::EQ, // call -- handled before reaching here
        JmpOp::EXIT => ConditionOp::EQ, // exit -- handled before reaching here
        JmpOp::JLT => ConditionOp::LT,
        JmpOp::JLE => ConditionOp::LE,
        JmpOp::JSLT => ConditionOp::SLT,
        JmpOp::JSLE => ConditionOp::SLE,
    }
}

#[derive(Debug, PartialEq)]
pub enum UnmarshalError {
    InvalidInstruction { pc: usize, message: String },
    ZeroLengthProgram,
}

impl std::fmt::Display for UnmarshalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnmarshalError::InvalidInstruction { pc, message } => write!(f, "{}: {}", pc, message),
            UnmarshalError::ZeroLengthProgram => write!(f, "Zero length programs are not allowed"),
        }
    }
}

impl std::error::Error for UnmarshalError {}

impl UnmarshalError {
    fn invalid(pc: usize, msg: impl Into<String>) -> Self {
        Self::InvalidInstruction {
            pc,
            message: msg.into(),
        }
    }

    fn invalid_opcode(pc: usize, msg: &str, opcode: u8) -> Self {
        Self::InvalidInstruction {
            pc,
            message: format!("{} op 0x{:x}", msg, opcode),
        }
    }
}

struct Unmarshaller<'a> {
    notes: &'a mut Vec<Vec<String>>,
    info: &'a ProgramInfo,
    platform: &'a dyn EbpfPlatform,
}

impl<'a> Unmarshaller<'a> {
    fn note(&mut self, what: String) {
        if let Some(last) = self.notes.last_mut() {
            last.push(what);
        }
    }

    fn note_next_pc(&mut self) {
        self.notes.push(Vec::new());
    }

    fn get_alu_op(
        &mut self,
        pc: usize,
        inst: &EbpfInst,
    ) -> Result<Result<BinOp, UnOp>, UnmarshalError> {
        let alu_op = AluOp::from_opcode(inst.opcode)
            .ok_or_else(|| UnmarshalError::invalid_opcode(pc, "bad instruction", inst.opcode))?;

        match alu_op {
            AluOp::DIV => match inst.offset {
                0 => Ok(Ok(BinOp::UDIV)),
                1 => Ok(Ok(BinOp::SDIV)),
                _ => Err(UnmarshalError::invalid_opcode(
                    pc,
                    "invalid offset for",
                    inst.opcode,
                )),
            },
            AluOp::MOD => match inst.offset {
                0 => Ok(Ok(BinOp::UMOD)),
                1 => Ok(Ok(BinOp::SMOD)),
                _ => Err(UnmarshalError::invalid_opcode(
                    pc,
                    "invalid offset for",
                    inst.opcode,
                )),
            },
            AluOp::MOV => {
                if inst.offset > 0 && (inst.opcode & INST_SRC_REG) == 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero offset for",
                        inst.opcode,
                    ));
                }
                match inst.offset {
                    0 => Ok(Ok(BinOp::MOV)),
                    8 => Ok(Ok(BinOp::MOVSX8)),
                    16 => Ok(Ok(BinOp::MOVSX16)),
                    32 => Ok(Ok(BinOp::MOVSX32)),
                    _ => Err(UnmarshalError::invalid_opcode(
                        pc,
                        "invalid offset for",
                        inst.opcode,
                    )),
                }
            }
            _ => {
                // All the rest require a zero offset
                if inst.offset != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero offset for",
                        inst.opcode,
                    ));
                }

                match alu_op {
                    AluOp::ADD => Ok(Ok(BinOp::ADD)),
                    AluOp::SUB => Ok(Ok(BinOp::SUB)),
                    AluOp::MUL => Ok(Ok(BinOp::MUL)),
                    AluOp::OR => Ok(Ok(BinOp::OR)),
                    AluOp::AND => Ok(Ok(BinOp::AND)),
                    AluOp::LSH => Ok(Ok(BinOp::LSH)),
                    AluOp::RSH => Ok(Ok(BinOp::RSH)),
                    AluOp::NEG => {
                        if (inst.opcode & INST_SRC_REG) != 0 || inst.src_raw() != 0 {
                            return Err(UnmarshalError::invalid_opcode(
                                pc,
                                "bad instruction",
                                inst.opcode,
                            ));
                        }
                        if inst.imm != 0 {
                            return Err(UnmarshalError::invalid_opcode(
                                pc,
                                "nonzero imm for",
                                inst.opcode,
                            ));
                        }
                        Ok(Err(UnOp::NEG))
                    }
                    AluOp::XOR => Ok(Ok(BinOp::XOR)),
                    AluOp::ARSH => {
                        if (inst.opcode & INST_CLS_MASK) == INST_CLS_ALU {
                            self.note("arsh32 is not allowed".to_string());
                        }
                        Ok(Ok(BinOp::ARSH))
                    }
                    AluOp::END => {
                        if inst.src_raw() != 0 {
                            return Err(UnmarshalError::invalid_opcode(
                                pc,
                                "bad instruction",
                                inst.opcode,
                            ));
                        }
                        if (inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64 {
                            if (inst.opcode & INST_END_BE) != 0 {
                                return Err(UnmarshalError::invalid_opcode(
                                    pc,
                                    "bad instruction",
                                    inst.opcode,
                                ));
                            }
                            match inst.imm {
                                16 => Ok(Err(UnOp::SWAP16)),
                                32 => Ok(Err(UnOp::SWAP32)),
                                64 => Ok(Err(UnOp::SWAP64)),
                                _ => Err(UnmarshalError::invalid(pc, "unsupported immediate")),
                            }
                        } else {
                            match inst.imm {
                                16 => Ok(Err(if (inst.opcode & INST_END_BE) != 0 {
                                    UnOp::BE16
                                } else {
                                    UnOp::LE16
                                })),
                                32 => Ok(Err(if (inst.opcode & INST_END_BE) != 0 {
                                    UnOp::BE32
                                } else {
                                    UnOp::LE32
                                })),
                                64 => Ok(Err(if (inst.opcode & INST_END_BE) != 0 {
                                    UnOp::BE64
                                } else {
                                    UnOp::LE64
                                })),
                                _ => Err(UnmarshalError::invalid(pc, "unsupported immediate")),
                            }
                        }
                    }
                    // DIV, MOD, MOV are handled above; this arm is unreachable
                    // but required for exhaustiveness.
                    AluOp::DIV | AluOp::MOD | AluOp::MOV => unreachable!(),
                }
            }
        }
    }

    fn make_alu_op(
        &mut self,
        pc: usize,
        inst: &EbpfInst,
        options: &EbpfVerifierOptions,
    ) -> Result<Instruction, UnmarshalError> {
        let is64 = (inst.opcode & INST_CLS_MASK) == INST_CLS_ALU64;

        if inst.dst() == R10_STACK_POINTER {
            return Err(UnmarshalError::invalid(pc, "invalid target r10"));
        }
        if inst.dst() > R10_STACK_POINTER || inst.src() > R10_STACK_POINTER {
            return Err(UnmarshalError::invalid(pc, "bad register"));
        }

        match self.get_alu_op(pc, inst)? {
            Err(op) => Ok(Instruction::Un(Un {
                op,
                dst: inst.dst(),
                is64,
            })),
            Ok(op) => {
                let v = if (inst.opcode & INST_SRC_REG) != 0 {
                    if inst.imm != 0 {
                        return Err(UnmarshalError::invalid_opcode(
                            pc,
                            "nonzero imm for",
                            inst.opcode,
                        ));
                    }
                    Value::Reg(inst.src())
                } else {
                    if inst.src_raw() != 0 {
                        return Err(UnmarshalError::invalid_opcode(
                            pc,
                            "bad instruction",
                            inst.opcode,
                        ));
                    }
                    Value::Imm(Imm {
                        v: sign_extend(inst.imm),
                    })
                };

                let ins = Bin {
                    op,
                    dst: inst.dst(),
                    v,
                    is64,
                    lddw: false,
                };

                if !options.allow_division_by_zero
                    && (op == BinOp::UDIV || op == BinOp::UMOD)
                    && let Value::Imm(imm) = ins.v
                    && imm.v == 0
                {
                    self.note("division by zero".to_string());
                }

                Ok(Instruction::Bin(ins))
            }
        }
    }

    fn make_mem_op(&mut self, pc: usize, inst: &EbpfInst) -> Result<Instruction, UnmarshalError> {
        if inst.dst() > R10_STACK_POINTER || inst.src() > R10_STACK_POINTER {
            return Err(UnmarshalError::invalid(pc, "bad register"));
        }

        let width = AccessSize::from_opcode(inst.opcode);

        let is_ld = (inst.opcode & INST_CLS_MASK) == INST_CLS_LD;

        match inst.opcode & INST_MODE_MASK {
            INST_MODE_IMM => Err(UnmarshalError::invalid_opcode(
                pc,
                "bad instruction",
                inst.opcode,
            )),
            INST_MODE_ABS => {
                if !is_ld || width == AccessSize::DWord {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.dst_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero dst for register",
                        inst.opcode,
                    ));
                }
                if inst.src_raw() > 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.offset != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero offset for",
                        inst.opcode,
                    ));
                }
                Ok(Instruction::Packet(Packet {
                    width,
                    offset: inst.imm,
                    regoffset: None,
                }))
            }
            INST_MODE_IND => {
                if !is_ld || width == AccessSize::DWord {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.dst_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero dst for register",
                        inst.opcode,
                    ));
                }
                if inst.src() > R10_STACK_POINTER {
                    return Err(UnmarshalError::invalid(pc, "bad register"));
                }
                if inst.offset != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero offset for",
                        inst.opcode,
                    ));
                }
                Ok(Instruction::Packet(Packet {
                    width,
                    offset: inst.imm,
                    regoffset: Some(inst.src()),
                }))
            }
            INST_MODE_MEM => {
                if is_ld {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                let is_load = get_mem_is_load(inst.opcode);
                if is_load && inst.dst() == R10_STACK_POINTER {
                    return Err(UnmarshalError::invalid(pc, "cannot modify r10"));
                }
                let is_imm = (inst.opcode & 1) == 0;
                if is_imm && inst.src_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if !is_imm && inst.imm != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero imm for",
                        inst.opcode,
                    ));
                }

                let basereg = if is_load { inst.src() } else { inst.dst() };

                // (CPP) TODO: Stack access bounds check
                // C++: if (basereg == R10_STACK_POINTER && (inst.offset + ...))

                Ok(Instruction::Mem(Mem {
                    access: Deref {
                        width,
                        basereg,
                        offset: inst.offset as i32,
                    },
                    value: if is_load {
                        Value::Reg(inst.dst())
                    } else if is_imm {
                        Value::Imm(Imm {
                            v: zero_extend(inst.imm),
                        })
                    } else {
                        Value::Reg(inst.src())
                    },
                    is_load,
                    is_signed: false,
                }))
            }
            INST_MODE_MEMSX => {
                // Sign-extending loads are only valid for LDX B/H/W forms.
                if (inst.opcode & INST_CLS_MASK) != INST_CLS_LDX || width == AccessSize::DWord {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.dst() == R10_STACK_POINTER {
                    return Err(UnmarshalError::invalid(pc, "cannot modify r10"));
                }
                if inst.imm != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero imm for",
                        inst.opcode,
                    ));
                }
                if inst.src() == R10_STACK_POINTER
                    && (inst.offset + width.bytes() as i16 > 0
                        || inst.offset < -EBPF_TOTAL_STACK_SIZE as i16)
                {
                    self.note("Stack access out of bounds".to_string());
                }
                Ok(Instruction::Mem(Mem {
                    access: Deref {
                        width,
                        basereg: inst.src(),
                        offset: i32::from(inst.offset),
                    },
                    value: Value::Reg(inst.dst()),
                    is_load: true,
                    is_signed: true,
                }))
            }
            INST_MODE_ATOMIC => {
                if (inst.opcode & INST_CLS_MASK) != INST_CLS_STX
                    || ((inst.opcode & INST_SIZE_MASK) != INST_SIZE_W
                        && (inst.opcode & INST_SIZE_MASK) != INST_SIZE_DW)
                {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }

                let op = match inst.imm & !INST_FETCH as i32 {
                    x if x == AtomicOp::ADD as i32 => AtomicOp::ADD,
                    x if x == AtomicOp::OR as i32 => AtomicOp::OR,
                    x if x == AtomicOp::AND as i32 => AtomicOp::AND,
                    x if x == AtomicOp::XOR as i32 => AtomicOp::XOR,
                    x if x == AtomicOp::XCHG as i32 => {
                        if (inst.imm & INST_FETCH as i32) == 0 {
                            return Err(UnmarshalError::invalid(pc, "unsupported immediate"));
                        }
                        AtomicOp::XCHG
                    }
                    x if x == AtomicOp::CMPXCHG as i32 => {
                        if (inst.imm & INST_FETCH as i32) == 0 {
                            return Err(UnmarshalError::invalid(pc, "unsupported immediate"));
                        }
                        AtomicOp::CMPXCHG
                    }
                    _ => return Err(UnmarshalError::invalid(pc, "unsupported immediate")),
                };

                Ok(Instruction::Atomic(Atomic {
                    op,
                    fetch: (inst.imm & INST_FETCH as i32) != 0,
                    access: Deref {
                        width,
                        basereg: inst.dst(),
                        offset: inst.offset as i32,
                    },
                    valreg: inst.src(),
                }))
            }
            _ => Err(UnmarshalError::invalid_opcode(
                pc,
                "bad instruction",
                inst.opcode,
            )),
        }
    }

    fn make_lddw(
        &self,
        pc: usize,
        inst: &EbpfInst,
        next_imm: i32,
        insts: &[EbpfInst],
    ) -> Result<Instruction, UnmarshalError> {
        if pc >= insts.len() - 1 {
            return Err(UnmarshalError::invalid(pc, "incomplete lddw"));
        }
        let next = &insts[pc + 1];
        if next.opcode != 0 || next.dst_raw() != 0 || next.src_raw() != 0 || next.offset != 0 {
            return Err(UnmarshalError::invalid(pc, "invalid lddw"));
        }
        if inst.offset != 0 {
            return Err(UnmarshalError::invalid_opcode(
                pc,
                "nonzero offset for",
                inst.opcode,
            ));
        }
        if inst.dst() > R10_STACK_POINTER {
            return Err(UnmarshalError::invalid(pc, "bad register"));
        }

        match inst.src_raw() {
            INST_LD_MODE_IMM => Ok(Instruction::Bin(Bin {
                op: BinOp::MOV,
                dst: inst.dst(),
                v: Value::Imm(Imm {
                    v: merge(inst.imm, next_imm),
                }),
                is64: true,
                lddw: true,
            })),
            INST_LD_MODE_MAP_FD => {
                if next.imm != 0 {
                    return Err(UnmarshalError::invalid(pc, "lddw uses reserved fields"));
                }
                Ok(Instruction::LoadMapFd(LoadMapFd {
                    dst: inst.dst(),
                    mapfd: inst.imm,
                }))
            }
            INST_LD_MODE_MAP_VALUE => Ok(Instruction::LoadMapAddress(LoadMapAddress {
                dst: inst.dst(),
                mapfd: inst.imm,
                offset: next_imm,
            })),
            INST_LD_MODE_VARIABLE_ADDR => {
                if next.imm != 0 {
                    return Err(UnmarshalError::invalid(pc, "lddw uses reserved fields"));
                }
                Ok(Instruction::LoadPseudo(LoadPseudo {
                    dst: inst.dst(),
                    addr: PseudoAddress {
                        kind: PseudoAddressKind::VariableAddr,
                        imm: inst.imm,
                        next_imm,
                    },
                }))
            }
            INST_LD_MODE_CODE_ADDR => {
                if next.imm != 0 {
                    return Err(UnmarshalError::invalid(pc, "lddw uses reserved fields"));
                }
                Ok(Instruction::LoadPseudo(LoadPseudo {
                    dst: inst.dst(),
                    addr: PseudoAddress {
                        kind: PseudoAddressKind::CodeAddr,
                        imm: inst.imm,
                        next_imm,
                    },
                }))
            }
            INST_LD_MODE_MAP_BY_IDX => {
                if next.imm != 0 {
                    return Err(UnmarshalError::invalid(pc, "lddw uses reserved fields"));
                }
                Ok(Instruction::LoadPseudo(LoadPseudo {
                    dst: inst.dst(),
                    addr: PseudoAddress {
                        kind: PseudoAddressKind::MapByIdx,
                        imm: inst.imm,
                        next_imm,
                    },
                }))
            }
            INST_LD_MODE_MAP_VALUE_BY_IDX => Ok(Instruction::LoadPseudo(LoadPseudo {
                dst: inst.dst(),
                addr: PseudoAddress {
                    kind: PseudoAddressKind::MapValueByIdx,
                    imm: inst.imm,
                    next_imm,
                },
            })),
            _ => Err(UnmarshalError::invalid_opcode(
                pc,
                "bad instruction",
                inst.opcode,
            )),
        }
    }

    fn make_jmp(
        &self,
        pc: usize,
        inst: &EbpfInst,
        insts: &[EbpfInst],
    ) -> Result<Instruction, UnmarshalError> {
        let jmp_op = JmpOp::from_opcode(inst.opcode)
            .ok_or_else(|| UnmarshalError::invalid_opcode(pc, "bad instruction", inst.opcode))?;
        match jmp_op {
            JmpOp::CALL => {
                if (inst.opcode & INST_CLS_MASK) != INST_CLS_JMP {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.src_raw() > INST_CALL_BTF_HELPER {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.offset != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero offset for",
                        inst.opcode,
                    ));
                }

                if inst.src_raw() == INST_CALL_LOCAL {
                    if (inst.opcode & INST_SRC_REG) != 0 {
                        return Err(UnmarshalError::invalid_opcode(
                            pc,
                            "bad instruction",
                            inst.opcode,
                        ));
                    }
                    if inst.dst_raw() != 0 {
                        return Err(UnmarshalError::invalid_opcode(
                            pc,
                            "nonzero dst for register",
                            inst.opcode,
                        ));
                    }
                    // (CPP) TODO: getJumpTarget validation
                    let target_pc = (pc as isize + 1 + inst.imm as isize) as usize;
                    if target_pc >= insts.len() {
                        return Err(UnmarshalError::invalid(pc, "jump out of bounds"));
                    }
                    // We don't check for lddw middle here as getting that info is expensive?
                    // C++ does `getJumpTarget`.
                    return Ok(Instruction::CallLocal(CallLocal {
                        target: Label::new(target_pc as i32),
                        stack_frame_prefix: Rc::from(""),
                    }));
                }

                if (inst.opcode & INST_SRC_REG) != 0 {
                    // Register-call opcode form is reserved for callx and must not be
                    // used for src-based call modes.
                    if inst.src_raw() != 0 {
                        return Err(UnmarshalError::invalid_opcode(
                            pc,
                            "bad instruction",
                            inst.opcode,
                        ));
                    }
                    // Callx
                    if inst.dst() > R10_STACK_POINTER {
                        return Err(UnmarshalError::invalid(pc, "bad register"));
                    }
                    if inst.imm != 0 {
                        if inst.dst_raw() > 0 {
                            return Err(UnmarshalError::invalid_opcode(
                                pc,
                                "nonzero imm for",
                                inst.opcode,
                            ));
                        }
                        if inst.imm < 0 || inst.imm > R10_STACK_POINTER.v as i32 {
                            return Err(UnmarshalError::invalid(pc, "bad register"));
                        }
                        return Ok(Instruction::Callx(Callx {
                            func: Reg { v: inst.imm as u8 },
                        }));
                    }
                    return Ok(Instruction::Callx(Callx { func: inst.dst() }));
                }

                if inst.src_raw() == INST_CALL_BTF_HELPER {
                    if inst.dst_raw() != 0 {
                        return Err(UnmarshalError::invalid_opcode(
                            pc,
                            "nonzero dst for register",
                            inst.opcode,
                        ));
                    }
                    return Ok(Instruction::CallBtf(CallBtf { btf_id: inst.imm }));
                }

                if inst.dst_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero dst for register",
                        inst.opcode,
                    ));
                }

                if self.info.builtin_call_offsets.contains(&pc) {
                    if let Some(builtin_call) = self.platform.get_builtin_call(inst.imm) {
                        return Ok(Instruction::Call(builtin_call));
                    }
                    return Ok(Instruction::Call(Call {
                        func: inst.imm,
                        kind: CallKind::Helper,
                        name: Rc::from(inst.imm.to_string()),
                        is_supported: false,
                        unsupported_reason: Rc::from(
                            "helper function is unavailable on this platform",
                        ),
                        is_map_lookup: false,
                        reallocate_packet: false,
                        return_ptr_type: None,
                        return_nullable: false,
                        singles: Vec::new(),
                        pairs: Vec::new(),
                        stack_frame_prefix: Rc::from(""),
                        alloc_size_reg: None,
                    }));
                }

                if !self.platform.is_helper_usable(inst.imm) {
                    let name = if inst.imm < 0 {
                        inst.imm.to_string()
                    } else {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            self.platform
                                .get_helper_prototype(inst.imm)
                                .name
                                .to_string()
                        }))
                        .unwrap_or_else(|_| inst.imm.to_string())
                    };
                    return Ok(Instruction::Call(Call {
                        func: inst.imm,
                        kind: CallKind::Helper,
                        name: Rc::from(name),
                        is_supported: false,
                        unsupported_reason: Rc::from(
                            "helper function is unavailable on this platform",
                        ),
                        is_map_lookup: false,
                        reallocate_packet: false,
                        return_ptr_type: None,
                        return_nullable: false,
                        singles: Vec::new(),
                        pairs: Vec::new(),
                        stack_frame_prefix: Rc::from(""),
                        alloc_size_reg: None,
                    }));
                }

                Ok(Instruction::Call(make_call(inst.imm, self.platform)))
            }
            JmpOp::EXIT => {
                if (inst.opcode & INST_CLS_MASK) != INST_CLS_JMP
                    || (inst.opcode & INST_SRC_REG) != 0
                {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.src_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if inst.dst_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero dst for register",
                        inst.opcode,
                    ));
                }
                if inst.imm != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero imm for",
                        inst.opcode,
                    ));
                }
                if inst.offset != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero offset for",
                        inst.opcode,
                    ));
                }
                Ok(Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }))
            }
            JmpOp::JA => {
                if (inst.opcode & INST_CLS_MASK) != INST_CLS_JMP
                    && (inst.opcode & INST_CLS_MASK) != INST_CLS_JMP32
                {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if (inst.opcode & INST_SRC_REG) != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if (inst.opcode & INST_CLS_MASK) == INST_CLS_JMP && inst.imm != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero imm for",
                        inst.opcode,
                    ));
                }
                if (inst.opcode & INST_CLS_MASK) == INST_CLS_JMP32 && inst.offset != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero offset for",
                        inst.opcode,
                    ));
                }
                if inst.dst_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero dst for register",
                        inst.opcode,
                    ));
                }

                let offset = if inst.opcode == INST_OP_JA32 {
                    inst.imm
                } else {
                    inst.offset as i32
                };
                let target_pc = (pc as isize + 1 + offset as isize) as usize;
                if target_pc >= insts.len() {
                    return Err(UnmarshalError::invalid(pc, "jump out of bounds"));
                }

                Ok(Instruction::Jmp(Jmp {
                    cond: None,
                    target: Label::new(target_pc as i32),
                }))
            }
            // All other JmpOp variants are conditional jumps
            _ => {
                let is64 = (inst.opcode & INST_CLS_MASK) == INST_CLS_JMP;

                let cond_op = jmp_op_to_cond(jmp_op);

                if (inst.opcode & INST_SRC_REG) == 0 && inst.src_raw() != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "bad instruction",
                        inst.opcode,
                    ));
                }
                if (inst.opcode & INST_SRC_REG) != 0 && inst.imm != 0 {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "nonzero imm for",
                        inst.opcode,
                    ));
                }

                let offset = i32::from(inst.offset);
                let target_pc = (pc as isize + 1 + offset as isize) as usize;
                if target_pc >= insts.len() {
                    return Err(UnmarshalError::invalid(pc, "jump out of bounds"));
                }

                if inst.dst() > R10_STACK_POINTER {
                    return Err(UnmarshalError::invalid(pc, "bad register"));
                }
                if (inst.opcode & INST_SRC_REG) != 0 && inst.src() > R10_STACK_POINTER {
                    return Err(UnmarshalError::invalid(pc, "bad register"));
                }

                Ok(Instruction::Jmp(Jmp {
                    cond: Some(Condition {
                        op: cond_op,
                        left: inst.dst(),
                        right: if (inst.opcode & INST_SRC_REG) != 0 {
                            Value::Reg(inst.src())
                        } else {
                            Value::Imm(Imm {
                                v: sign_extend(inst.imm),
                            })
                        },
                        is64,
                    }),
                    target: Label::new(target_pc as i32),
                }))
            }
        }
    }

    pub fn unmarshal(
        &mut self,
        insts: &[EbpfInst],
        options: &EbpfVerifierOptions,
    ) -> Result<InstructionSeq, UnmarshalError> {
        let mut prog = Vec::new();
        let mut exit_count = 0;
        if insts.is_empty() {
            return Err(UnmarshalError::ZeroLengthProgram);
        }

        let mut pc = 0;
        self.note_next_pc();

        while pc < insts.len() {
            let inst = &insts[pc];
            let new_ins;
            let mut skip_instruction = false;
            let mut fallthrough = true;

            match InstructionClass::from_opcode(inst.opcode) {
                Some(InstructionClass::LD) => {
                    if inst.opcode == INST_OP_LDDW_IMM {
                        let next_imm = if pc < insts.len() - 1 {
                            insts[pc + 1].imm
                        } else {
                            0
                        };
                        new_ins = self.make_lddw(pc, inst, next_imm, insts)?;
                        skip_instruction = true;
                    } else {
                        new_ins = self.make_mem_op(pc, inst)?;
                    }
                }
                Some(InstructionClass::LDX | InstructionClass::ST | InstructionClass::STX) => {
                    new_ins = self.make_mem_op(pc, inst)?;
                }
                Some(InstructionClass::ALU | InstructionClass::ALU64) => {
                    let mut ins = self.make_alu_op(pc, inst, options)?;

                    // Peephole opt: Merge (rX <<= 32; rX >>>= 32) into wX = rX
                    if pc < insts.len() - 1
                        && let Instruction::Bin(bin) = &ins
                        && bin.op == BinOp::LSH
                        && matches!(bin.v, Value::Imm(imm) if imm.v == 32)
                        && bin.is64
                    {
                        let next = &insts[pc + 1];
                        if InstructionClass::from_opcode(next.opcode)
                            == Some(InstructionClass::ALU64)
                            && let Ok(Instruction::Bin(next_bin)) =
                                self.make_alu_op(pc + 1, next, options)
                            && next_bin.dst == bin.dst
                            && matches!(next_bin.v, Value::Imm(imm) if imm.v == 32)
                            && next_bin.is64
                        {
                            if next_bin.op == BinOp::RSH {
                                ins = Instruction::Bin(Bin {
                                    op: BinOp::MOV,
                                    dst: bin.dst,
                                    v: Value::Reg(bin.dst),
                                    is64: false,
                                    lddw: false,
                                });
                                skip_instruction = true;
                            } else if next_bin.op == BinOp::ARSH {
                                ins = Instruction::Bin(Bin {
                                    op: BinOp::MOVSX32,
                                    dst: bin.dst,
                                    v: Value::Reg(bin.dst),
                                    is64: true,
                                    lddw: false,
                                });
                                skip_instruction = true;
                            }
                        }
                    }
                    new_ins = ins;
                }
                Some(InstructionClass::JMP | InstructionClass::JMP32) => {
                    new_ins = self.make_jmp(pc, inst, insts)?;
                    if matches!(new_ins, Instruction::Exit(_)) {
                        fallthrough = false;
                        exit_count += 1;
                    }
                    if let Instruction::Jmp(Jmp { cond: None, .. }) = &new_ins {
                        fallthrough = false;
                    }
                }
                None => {
                    return Err(UnmarshalError::invalid_opcode(
                        pc,
                        "invalid class",
                        inst.opcode & INST_CLS_MASK,
                    ));
                }
            }

            if pc == insts.len() - 1 && fallthrough {
                self.note("fallthrough in last instruction".to_string());
            }

            // TODO: BTF line info

            prog.push((Label::new(pc as i32), new_ins, None));

            pc += 1;
            self.note_next_pc();
            if skip_instruction {
                pc += 1;
                self.note_next_pc();
            }
        }

        if exit_count == 0 {
            self.note("no exit instruction".to_string());
        }

        Ok(prog)
    }
}

/// Main entry point for unmarshalling.
pub fn unmarshal(
    insts: &[EbpfInst],
    notes: &mut Vec<Vec<String>>,
    info: &ProgramInfo,
    platform: &dyn EbpfPlatform,
    options: &EbpfVerifierOptions,
) -> Result<InstructionSeq, UnmarshalError> {
    Unmarshaller {
        notes,
        info,
        platform,
    }
    .unmarshal(insts, options)
}

// ============================================================================
// make_call — convert helper prototype to Call instruction
// ============================================================================

use crate::spec::ebpf_base::{EBPF_TOTAL_STACK_SIZE, EbpfArgumentType, EbpfReturnType};

fn to_arg_single_kind(t: EbpfArgumentType) -> ArgSingleKind {
    use crate::ir::syntax::ArgSingleKind::*;
    match t {
        EbpfArgumentType::Anything => Anything,
        EbpfArgumentType::PtrToStack | EbpfArgumentType::PtrToStackOrNull => PtrToStack,
        EbpfArgumentType::PtrToMap | EbpfArgumentType::ConstPtrToMap => MapFd,
        EbpfArgumentType::PtrToMapOfPrograms => MapFdPrograms,
        EbpfArgumentType::PtrToMapKey => PtrToMapKey,
        EbpfArgumentType::PtrToMapValue | EbpfArgumentType::PtrToUninitMapValue => PtrToMapValue,
        EbpfArgumentType::PtrToCtx | EbpfArgumentType::PtrToCtxOrNull => PtrToCtx,
        EbpfArgumentType::PtrToFunc => PtrToFunc,
        _ => Anything, // fallback (matches C++ default)
    }
}

fn to_arg_pair_kind(t: EbpfArgumentType) -> ArgPairKind {
    use crate::ir::syntax::ArgPairKind::*;
    match t {
        EbpfArgumentType::PtrToReadableMem
        | EbpfArgumentType::PtrToReadableMemOrNull
        | EbpfArgumentType::PtrToReadonlyMem
        | EbpfArgumentType::PtrToReadonlyMemOrNull => PtrToReadableMem,
        EbpfArgumentType::PtrToWritableMem | EbpfArgumentType::PtrToWritableMemOrNull => {
            PtrToWritableMem
        }
        _ => PtrToReadableMem, // fallback
    }
}

/// Convert a helper function id + platform into a `Call` instruction.
///
/// Mirrors C++ `make_call(int imm, const ebpf_platform_t& platform)`.
pub fn make_call(imm: i32, platform: &dyn EbpfPlatform) -> Call {
    make_call_result(imm, platform).unwrap_or_else(|msg| panic!("{msg}"))
}

/// Fallible counterpart to `make_call`.
///
/// This keeps C++ parity where unsupported helpers trigger an exception while
/// still allowing Rust callers to propagate a structured error instead of
/// aborting.
pub fn make_call_result(imm: i32, platform: &dyn EbpfPlatform) -> Result<Call, String> {
    let proto = platform.get_helper_prototype(imm);

    let name: Rc<str> = Rc::from(proto.name);

    let mut res = Call {
        func: imm,
        kind: CallKind::Helper,
        name,
        is_supported: true,
        unsupported_reason: Rc::from(""),
        is_map_lookup: proto.return_type == EbpfReturnType::PtrToMapValueOrNull,
        reallocate_packet: proto.reallocate_packet,
        return_ptr_type: None,
        return_nullable: false,
        singles: vec![],
        pairs: vec![],
        stack_frame_prefix: Rc::from(""),
        alloc_size_reg: None,
    };
    let mark_unsupported = |res: &mut Call, why: String| {
        res.is_supported = false;
        res.unsupported_reason = Rc::from(why);
    };

    match proto.return_type {
        EbpfReturnType::Integer
        | EbpfReturnType::PtrToMapValueOrNull
        | EbpfReturnType::IntegerOrNoReturnIfSucceed => {}
        EbpfReturnType::PtrToSockCommonOrNull
        | EbpfReturnType::PtrToSocketOrNull
        | EbpfReturnType::PtrToTcpSocketOrNull => {
            res.return_ptr_type = Some(T_SOCKET);
            res.return_nullable = true;
        }
        EbpfReturnType::PtrToAllocMemOrNull => {
            res.return_ptr_type = Some(T_ALLOC_MEM);
            res.return_nullable = true;
        }
        EbpfReturnType::PtrToBtfIdOrNull | EbpfReturnType::PtrToMemOrBtfIdOrNull => {
            res.return_ptr_type = Some(T_BTF_ID);
            res.return_nullable = true;
        }
        EbpfReturnType::PtrToBtfId | EbpfReturnType::PtrToMemOrBtfId => {
            res.return_ptr_type = Some(T_BTF_ID);
            res.return_nullable = false;
        }
        _ => {
            mark_unsupported(
                &mut res,
                format!(
                    "helper prototype is unavailable on this platform: {}",
                    proto.name
                ),
            );
            return Ok(res);
        }
    }

    // Build argument list: pad with DontCare sentinel on each end (matching C++ array layout)
    let args = [
        EbpfArgumentType::DontCare,
        proto.argument_type[0],
        proto.argument_type[1],
        proto.argument_type[2],
        proto.argument_type[3],
        proto.argument_type[4],
        EbpfArgumentType::DontCare,
    ];

    let mut i = 1usize;
    while i < args.len() - 1 {
        match args[i] {
            EbpfArgumentType::Unsupported => {
                mark_unsupported(
                    &mut res,
                    format!(
                        "helper argument type is unavailable on this platform: {}",
                        proto.name
                    ),
                );
                return Ok(res);
            }
            EbpfArgumentType::DontCare => {
                // No more arguments
                break;
            }
            EbpfArgumentType::Anything
            | EbpfArgumentType::PtrToMap
            | EbpfArgumentType::ConstPtrToMap
            | EbpfArgumentType::PtrToMapOfPrograms
            | EbpfArgumentType::PtrToMapKey
            | EbpfArgumentType::PtrToMapValue
            | EbpfArgumentType::PtrToUninitMapValue
            | EbpfArgumentType::PtrToStack
            | EbpfArgumentType::PtrToCtx
            | EbpfArgumentType::PtrToFunc => {
                res.singles.push(ArgSingle {
                    kind: to_arg_single_kind(args[i]),
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToStackOrNull | EbpfArgumentType::PtrToCtxOrNull => {
                res.singles.push(ArgSingle {
                    kind: to_arg_single_kind(args[i]),
                    or_null: true,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToBtfIdSockCommon | EbpfArgumentType::PtrToSockCommon => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToSocket,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToBtfId | EbpfArgumentType::PtrToPercpuBtfId => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToBtfId,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToAllocMem => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToAllocMem,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToSpinLock => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToSpinLock,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToTimer => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToTimer,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::ConstAllocSizeOrZero => {
                res.alloc_size_reg = Some(Reg { v: i as u8 });
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::ConstSizeOrZero,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToLong => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToWritableLong,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToInt => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToWritableInt,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
            }
            EbpfArgumentType::PtrToConstStr => {
                mark_unsupported(
                    &mut res,
                    format!(
                        "helper argument type is unavailable on this platform: {}",
                        proto.name
                    ),
                );
                return Ok(res);
            }
            EbpfArgumentType::ConstSize | EbpfArgumentType::ConstSizeOrZero => {
                // These should not appear without a preceding PTR_TO_*_MEM
                mark_unsupported(
                    &mut res,
                    format!(
                        "mismatched EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE: {}",
                        proto.name
                    ),
                );
                return Ok(res);
            }
            EbpfArgumentType::PtrToReadableMemOrNull
            | EbpfArgumentType::PtrToReadableMem
            | EbpfArgumentType::PtrToReadonlyMemOrNull
            | EbpfArgumentType::PtrToReadonlyMem
            | EbpfArgumentType::PtrToWritableMemOrNull
            | EbpfArgumentType::PtrToWritableMem => {
                // Must be followed by ConstSize or ConstSizeOrZero
                if i + 1 >= args.len() - 1 {
                    mark_unsupported(
                        &mut res,
                        format!(
                            "mismatched EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE: {}",
                            proto.name
                        ),
                    );
                    return Ok(res);
                }
                if args[i + 1] != EbpfArgumentType::ConstSize
                    && args[i + 1] != EbpfArgumentType::ConstSizeOrZero
                {
                    mark_unsupported(
                        &mut res,
                        format!(
                            "Pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: {}",
                            proto.name
                        ),
                    );
                    return Ok(res);
                }
                let can_be_zero = args[i + 1] == EbpfArgumentType::ConstSizeOrZero;
                let or_null = args[i] == EbpfArgumentType::PtrToReadableMemOrNull
                    || args[i] == EbpfArgumentType::PtrToReadonlyMemOrNull
                    || args[i] == EbpfArgumentType::PtrToWritableMemOrNull;
                res.pairs.push(ArgPair {
                    kind: to_arg_pair_kind(args[i]),
                    or_null,
                    mem: Reg { v: i as u8 },
                    size: Reg { v: (i + 1) as u8 },
                    can_be_zero,
                });
                i += 1; // skip the size argument
            }
        }
        i += 1;
    }

    Ok(res)
}

#[cfg(test)]
mod unmarshal_tests;
