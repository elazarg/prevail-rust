// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! eBPF ISA constants, types, and helpers.
//! Mirrors `src/spec/vm_isa.hpp`.

// ── Class field ──────────────────────────────────────────────────────
pub const INST_CLS_MASK: u8 = 0x07;
pub const INST_CLS_LD: u8 = 0x00;
pub const INST_CLS_LDX: u8 = 0x01;
pub const INST_CLS_ST: u8 = 0x02;
pub const INST_CLS_STX: u8 = 0x03;
pub const INST_CLS_ALU: u8 = 0x04;
pub const INST_CLS_JMP: u8 = 0x05;
pub const INST_CLS_JMP32: u8 = 0x06;
pub const INST_CLS_ALU64: u8 = 0x07;

/// Instruction class extracted from bits 0-2 of an opcode.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InstructionClass {
    LD = 0x00,
    LDX = 0x01,
    ST = 0x02,
    STX = 0x03,
    ALU = 0x04,
    JMP = 0x05,
    JMP32 = 0x06,
    ALU64 = 0x07,
}

impl InstructionClass {
    /// Extract the instruction class from bits 0-2 of an opcode.
    /// Returns `None` only if the implementation is out of sync with the 3-bit
    /// field (currently all 8 values are covered, so this always returns `Some`).
    #[inline]
    pub fn from_opcode(opcode: u8) -> Option<InstructionClass> {
        match opcode & INST_CLS_MASK {
            0x00 => Some(InstructionClass::LD),
            0x01 => Some(InstructionClass::LDX),
            0x02 => Some(InstructionClass::ST),
            0x03 => Some(InstructionClass::STX),
            0x04 => Some(InstructionClass::ALU),
            0x05 => Some(InstructionClass::JMP),
            0x06 => Some(InstructionClass::JMP32),
            0x07 => Some(InstructionClass::ALU64),
            _ => None,
        }
    }
}

// ── Source field ─────────────────────────────────────────────────────
pub const INST_SRC_IMM: u8 = 0x00;
pub const INST_SRC_REG: u8 = 0x08;

// ── Endianness ───────────────────────────────────────────────────────
pub const INST_END_LE: u8 = 0x00;
pub const INST_END_BE: u8 = 0x08;

// ── Size field ───────────────────────────────────────────────────────
pub const INST_SIZE_W: u8 = 0x00;
pub const INST_SIZE_H: u8 = 0x08;
pub const INST_SIZE_B: u8 = 0x10;
pub const INST_SIZE_DW: u8 = 0x18;
pub const INST_SIZE_MASK: u8 = 0x18;

// ── Mode field ───────────────────────────────────────────────────────
pub const INST_MODE_MASK: u8 = 0xe0;
pub const INST_MODE_IMM: u8 = 0x00;
pub const INST_MODE_ABS: u8 = 0x20;
pub const INST_MODE_IND: u8 = 0x40;
pub const INST_MODE_MEM: u8 = 0x60;
pub const INST_MODE_MEMSX: u8 = 0x80;
pub const INST_MODE_UNUSED1: u8 = 0xa0;
pub const INST_MODE_ATOMIC: u8 = 0xc0;
pub const INST_MODE_UNUSED2: u8 = 0xe0;

// ── Compound opcodes ─────────────────────────────────────────────────
pub const INST_OP_LDDW_IMM: u8 = INST_CLS_LD | INST_SRC_IMM | INST_SIZE_DW;

pub const INST_FETCH: u8 = 0x1;

pub const INST_JA: u8 = 0x0;
pub const INST_CALL: u8 = 0x8;
pub const INST_EXIT: u8 = 0x9;

pub const INST_OP_JA32: u8 = (INST_JA << 4) | INST_CLS_JMP32;
pub const INST_OP_JA16: u8 = (INST_JA << 4) | INST_CLS_JMP;
pub const INST_OP_CALL: u8 = (INST_CALL << 4) | INST_SRC_IMM | INST_CLS_JMP;
pub const INST_OP_CALLX: u8 = (INST_CALL << 4) | INST_SRC_REG | INST_CLS_JMP;
pub const INST_OP_EXIT: u8 = (INST_EXIT << 4) | INST_CLS_JMP;

pub const INST_CALL_STATIC_HELPER: u8 = 0x0;
pub const INST_CALL_LOCAL: u8 = 0x1;
pub const INST_CALL_BTF_HELPER: u8 = 0x2;

// ── Jump operation field (bits 4-7 of opcode for JMP/JMP32 class) ───

/// The jump operation nibble, extracted from `(opcode >> 4) & 0xF`.
///
/// Values 0x0, 0x8, 0x9 are special (JA, CALL, EXIT) and are handled
/// separately in the unmarshal dispatch before reaching conditional
/// jump logic. Values 0xE and 0xF are reserved/invalid.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JmpOp {
    JA = 0x0,
    JEQ = 0x1,
    JGT = 0x2,
    JGE = 0x3,
    JSET = 0x4,
    JNE = 0x5,
    JSGT = 0x6,
    JSGE = 0x7,
    CALL = 0x8,
    EXIT = 0x9,
    JLT = 0xa,
    JLE = 0xb,
    JSLT = 0xc,
    JSLE = 0xd,
}

impl JmpOp {
    /// Extract the jump operation from bits 4-7 of an opcode.
    /// Returns `None` for reserved values 0xE and 0xF.
    #[inline]
    pub fn from_opcode(opcode: u8) -> Option<JmpOp> {
        match (opcode >> 4) & 0xF {
            0x0 => Some(JmpOp::JA),
            0x1 => Some(JmpOp::JEQ),
            0x2 => Some(JmpOp::JGT),
            0x3 => Some(JmpOp::JGE),
            0x4 => Some(JmpOp::JSET),
            0x5 => Some(JmpOp::JNE),
            0x6 => Some(JmpOp::JSGT),
            0x7 => Some(JmpOp::JSGE),
            0x8 => Some(JmpOp::CALL),
            0x9 => Some(JmpOp::EXIT),
            0xa => Some(JmpOp::JLT),
            0xb => Some(JmpOp::JLE),
            0xc => Some(JmpOp::JSLT),
            0xd => Some(JmpOp::JSLE),
            _ => None,
        }
    }
}

// ── ALU operation field ──────────────────────────────────────────────
pub const INST_ALU_OP_ADD: u8 = 0x00;
pub const INST_ALU_OP_SUB: u8 = 0x10;
pub const INST_ALU_OP_MUL: u8 = 0x20;
pub const INST_ALU_OP_DIV: u8 = 0x30;
pub const INST_ALU_OP_OR: u8 = 0x40;
pub const INST_ALU_OP_AND: u8 = 0x50;
pub const INST_ALU_OP_LSH: u8 = 0x60;
pub const INST_ALU_OP_RSH: u8 = 0x70;
pub const INST_ALU_OP_NEG: u8 = 0x80;
pub const INST_ALU_OP_MOD: u8 = 0x90;
pub const INST_ALU_OP_XOR: u8 = 0xa0;
pub const INST_ALU_OP_MOV: u8 = 0xb0;
pub const INST_ALU_OP_ARSH: u8 = 0xc0;
pub const INST_ALU_OP_END: u8 = 0xd0;
pub const INST_ALU_OP_MASK: u8 = 0xf0;

/// The ALU operation nibble, extracted from `(opcode >> 4) & 0xF`
/// (equivalently, `opcode & INST_ALU_OP_MASK`).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AluOp {
    ADD = 0x0,
    SUB = 0x1,
    MUL = 0x2,
    DIV = 0x3,
    OR = 0x4,
    AND = 0x5,
    LSH = 0x6,
    RSH = 0x7,
    NEG = 0x8,
    MOD = 0x9,
    XOR = 0xa,
    MOV = 0xb,
    ARSH = 0xc,
    END = 0xd,
}

impl AluOp {
    /// Extract the ALU operation from the opcode.
    /// Returns `None` for reserved values 0xE and 0xF.
    #[inline]
    pub fn from_opcode(opcode: u8) -> Option<AluOp> {
        match opcode & INST_ALU_OP_MASK {
            INST_ALU_OP_ADD => Some(AluOp::ADD),
            INST_ALU_OP_SUB => Some(AluOp::SUB),
            INST_ALU_OP_MUL => Some(AluOp::MUL),
            INST_ALU_OP_DIV => Some(AluOp::DIV),
            INST_ALU_OP_OR => Some(AluOp::OR),
            INST_ALU_OP_AND => Some(AluOp::AND),
            INST_ALU_OP_LSH => Some(AluOp::LSH),
            INST_ALU_OP_RSH => Some(AluOp::RSH),
            INST_ALU_OP_NEG => Some(AluOp::NEG),
            INST_ALU_OP_MOD => Some(AluOp::MOD),
            INST_ALU_OP_XOR => Some(AluOp::XOR),
            INST_ALU_OP_MOV => Some(AluOp::MOV),
            INST_ALU_OP_ARSH => Some(AluOp::ARSH),
            INST_ALU_OP_END => Some(AluOp::END),
            _ => None,
        }
    }
}

// ── LD mode (src field of LDDW) ─────────────────────────────────────
pub const INST_LD_MODE_IMM: u8 = 0x0;
pub const INST_LD_MODE_MAP_FD: u8 = 0x1;
pub const INST_LD_MODE_MAP_VALUE: u8 = 0x2;

// ── Register aliases ─────────────────────────────────────────────────
use crate::ir::syntax::Reg;

pub const R0_RETURN_VALUE: Reg = Reg { v: 0 };
pub const R1_ARG: Reg = Reg { v: 1 };
pub const R2_ARG: Reg = Reg { v: 2 };
pub const R3_ARG: Reg = Reg { v: 3 };
pub const R4_ARG: Reg = Reg { v: 4 };
pub const R5_ARG: Reg = Reg { v: 5 };
pub const R6: Reg = Reg { v: 6 };
pub const R7: Reg = Reg { v: 7 };
pub const R8: Reg = Reg { v: 8 };
pub const R9: Reg = Reg { v: 9 };
pub const R10_STACK_POINTER: Reg = Reg { v: 10 };
pub const R11_ATOMIC_SCRATCH: Reg = Reg { v: 11 };

// ── EbpfInst ─────────────────────────────────────────────────────────
/// Mirrors the C++ `EbpfInst` struct (8 bytes, packed).
///
/// C++ uses bitfields `dst:4` and `src:4`.  We store them together in
/// `dst_src` and provide accessor methods.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EbpfInst {
    pub opcode: u8,
    /// Packed `dst:4 | src:4` (low nibble = dst, high nibble = src).
    pub dst_src: u8,
    pub offset: i16,
    pub imm: i32,
}

impl EbpfInst {
    #[inline]
    pub fn dst(&self) -> Reg {
        Reg {
            v: self.dst_src & 0x0f,
        }
    }

    #[inline]
    pub fn src(&self) -> Reg {
        Reg {
            v: (self.dst_src >> 4) & 0x0f,
        }
    }

    /// Raw dst nibble as u8 (for non-register uses like LD mode).
    #[inline]
    pub fn dst_raw(&self) -> u8 {
        self.dst_src & 0x0f
    }

    /// Raw src nibble as u8 (for non-register uses like LD mode).
    #[inline]
    pub fn src_raw(&self) -> u8 {
        (self.dst_src >> 4) & 0x0f
    }

    #[inline]
    pub fn set_src(&mut self, src: u8) {
        self.dst_src = (self.dst_src & 0x0f) | ((src & 0x0f) << 4);
    }

    #[inline]
    pub fn set_dst(&mut self, dst: u8) {
        self.dst_src = (self.dst_src & 0xf0) | (dst & 0x0f);
    }

    #[inline]
    pub fn new(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
        Self {
            opcode,
            dst_src: (dst & 0x0f) | ((src & 0x0f) << 4),
            offset,
            imm,
        }
    }
}

// ── merge / split ────────────────────────────────────────────────────

/// Combine two 32-bit halves into a single 64-bit value.
/// `merge(imm, next_imm) == (next_imm << 32) | (uint32_t)imm`
pub fn merge(imm: i32, next_imm: i32) -> u64 {
    ((next_imm as u64) << 32) | (imm as u32 as u64)
}

/// Result struct for `split`.
pub struct SplitResult {
    pub lo: i32,
    pub hi: i32,
}

/// Split a 64-bit value into two 32-bit halves.
pub fn split(v: u64) -> SplitResult {
    SplitResult {
        lo: v as u32 as i32,
        hi: (v >> 32) as u32 as i32,
    }
}

// ── AccessSize ───────────────────────────────────────────────────────

/// Memory access width: 1, 2, 4, or 8 bytes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessSize {
    Byte = 1,
    Half = 2,
    Word = 4,
    DWord = 8,
}

impl AccessSize {
    /// Extract `AccessSize` from the size bits of an opcode.
    pub fn from_opcode(opcode: u8) -> Self {
        match opcode & INST_SIZE_MASK {
            INST_SIZE_B => AccessSize::Byte,
            INST_SIZE_H => AccessSize::Half,
            INST_SIZE_W => AccessSize::Word,
            INST_SIZE_DW => AccessSize::DWord,
            _ => unreachable!("unexpected size bits in opcode {opcode:#04x}"),
        }
    }

    /// Encode this size as the ISA size field bits.
    pub fn to_opcode(self) -> u8 {
        match self {
            AccessSize::Byte => INST_SIZE_B,
            AccessSize::Half => INST_SIZE_H,
            AccessSize::Word => INST_SIZE_W,
            AccessSize::DWord => INST_SIZE_DW,
        }
    }

    /// Width in bytes as `i32`.
    pub fn bytes(self) -> i32 {
        self as u8 as i32
    }
}

impl std::fmt::Display for AccessSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "u{}", self.bytes() * 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_size_from_opcode_all_sizes() {
        assert_eq!(AccessSize::from_opcode(INST_SIZE_B), AccessSize::Byte);
        assert_eq!(AccessSize::from_opcode(INST_SIZE_H), AccessSize::Half);
        assert_eq!(AccessSize::from_opcode(INST_SIZE_W), AccessSize::Word);
        assert_eq!(AccessSize::from_opcode(INST_SIZE_DW), AccessSize::DWord);
    }

    #[test]
    fn access_size_from_opcode_ignores_non_size_bits() {
        assert_eq!(AccessSize::from_opcode(0x61), AccessSize::Word); // MEM | LDX | SIZE_W
        assert_eq!(AccessSize::from_opcode(0x69), AccessSize::Half); // MEM | LDX | SIZE_H
        assert_eq!(AccessSize::from_opcode(0x71), AccessSize::Byte); // MEM | LDX | SIZE_B
        assert_eq!(AccessSize::from_opcode(0x79), AccessSize::DWord); // MEM | LDX | SIZE_DW
    }

    #[test]
    fn access_size_to_opcode_all() {
        assert_eq!(AccessSize::Byte.to_opcode(), INST_SIZE_B);
        assert_eq!(AccessSize::Half.to_opcode(), INST_SIZE_H);
        assert_eq!(AccessSize::Word.to_opcode(), INST_SIZE_W);
        assert_eq!(AccessSize::DWord.to_opcode(), INST_SIZE_DW);
    }

    #[test]
    fn access_size_roundtrip() {
        for &size_field in &[INST_SIZE_B, INST_SIZE_H, INST_SIZE_W, INST_SIZE_DW] {
            let size = AccessSize::from_opcode(size_field);
            assert_eq!(size.to_opcode(), size_field);
        }
    }

    #[test]
    fn access_size_bytes() {
        assert_eq!(AccessSize::Byte.bytes(), 1);
        assert_eq!(AccessSize::Half.bytes(), 2);
        assert_eq!(AccessSize::Word.bytes(), 4);
        assert_eq!(AccessSize::DWord.bytes(), 8);
    }

    #[test]
    fn access_size_display() {
        assert_eq!(format!("{}", AccessSize::Byte), "u8");
        assert_eq!(format!("{}", AccessSize::Half), "u16");
        assert_eq!(format!("{}", AccessSize::Word), "u32");
        assert_eq!(format!("{}", AccessSize::DWord), "u64");
    }

    #[test]
    fn merge_basic() {
        assert_eq!(merge(1, 2), (2u64 << 32) | 1);
        assert_eq!(merge(0, 0), 0);
        assert_eq!(merge(-1, 0), 0x0000_0000_FFFF_FFFF);
        assert_eq!(merge(0, -1), 0xFFFF_FFFF_0000_0000);
    }

    #[test]
    fn split_basic() {
        let r = split(0x0000_0002_0000_0001);
        assert_eq!(r.lo, 1);
        assert_eq!(r.hi, 2);
    }

    #[test]
    fn merge_split_roundtrip() {
        for &(lo, hi) in &[(0i32, 0i32), (1, 2), (-1, -1), (i32::MIN, i32::MAX)] {
            let merged = merge(lo, hi);
            let r = split(merged);
            assert_eq!(r.lo, lo);
            assert_eq!(r.hi, hi);
        }
    }

    #[test]
    fn ebpf_inst_accessors() {
        let inst = EbpfInst::new(0x61, 3, 10, 8, 0);
        assert_eq!(inst.dst(), Reg { v: 3 });
        assert_eq!(inst.src(), Reg { v: 10 });
        assert_eq!(inst.offset, 8);
    }

    #[test]
    fn ebpf_inst_size() {
        assert_eq!(std::mem::size_of::<EbpfInst>(), 8);
    }

    #[test]
    fn instruction_class_from_opcode_all_classes() {
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_LD),
            Some(InstructionClass::LD)
        );
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_LDX),
            Some(InstructionClass::LDX)
        );
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_ST),
            Some(InstructionClass::ST)
        );
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_STX),
            Some(InstructionClass::STX)
        );
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_ALU),
            Some(InstructionClass::ALU)
        );
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_JMP),
            Some(InstructionClass::JMP)
        );
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_JMP32),
            Some(InstructionClass::JMP32)
        );
        assert_eq!(
            InstructionClass::from_opcode(INST_CLS_ALU64),
            Some(InstructionClass::ALU64)
        );
    }

    #[test]
    fn instruction_class_from_opcode_ignores_non_class_bits() {
        // LDX | MEM | SIZE_W = 0x61 -> class LDX (0x01)
        assert_eq!(
            InstructionClass::from_opcode(0x61),
            Some(InstructionClass::LDX)
        );
        // ALU64 | SRC_IMM | ALU_OP_ADD = 0x07 -> class ALU64 (0x07)
        assert_eq!(
            InstructionClass::from_opcode(0x07),
            Some(InstructionClass::ALU64)
        );
        // JMP | op nibble = 0x15 -> class JMP (0x05)
        assert_eq!(
            InstructionClass::from_opcode(0x15),
            Some(InstructionClass::JMP)
        );
    }

    #[test]
    fn instruction_class_variant_matches_constant() {
        assert_eq!(InstructionClass::LD as u8, INST_CLS_LD);
        assert_eq!(InstructionClass::LDX as u8, INST_CLS_LDX);
        assert_eq!(InstructionClass::ST as u8, INST_CLS_ST);
        assert_eq!(InstructionClass::STX as u8, INST_CLS_STX);
        assert_eq!(InstructionClass::ALU as u8, INST_CLS_ALU);
        assert_eq!(InstructionClass::JMP as u8, INST_CLS_JMP);
        assert_eq!(InstructionClass::JMP32 as u8, INST_CLS_JMP32);
        assert_eq!(InstructionClass::ALU64 as u8, INST_CLS_ALU64);
    }

    #[test]
    fn jmp_op_from_opcode_all_valid() {
        // JEQ | JMP | SRC_IMM = 0x15
        assert_eq!(JmpOp::from_opcode(0x15), Some(JmpOp::JEQ));
        // JGT | JMP | SRC_REG = 0x2d
        assert_eq!(JmpOp::from_opcode(0x2d), Some(JmpOp::JGT));
        // CALL = 0x85
        assert_eq!(JmpOp::from_opcode(INST_OP_CALL), Some(JmpOp::CALL));
        // EXIT = 0x95
        assert_eq!(JmpOp::from_opcode(INST_OP_EXIT), Some(JmpOp::EXIT));
        // JA (JMP class) = 0x05
        assert_eq!(JmpOp::from_opcode(INST_OP_JA16), Some(JmpOp::JA));
    }

    #[test]
    fn jmp_op_from_opcode_reserved_returns_none() {
        // 0xE nibble: opcode = 0xe5 (JMP class)
        assert_eq!(JmpOp::from_opcode(0xe5), None);
        // 0xF nibble: opcode = 0xf5 (JMP class)
        assert_eq!(JmpOp::from_opcode(0xf5), None);
    }

    #[test]
    fn jmp_op_variant_matches_constant() {
        assert_eq!(JmpOp::JA as u8, INST_JA);
        assert_eq!(JmpOp::CALL as u8, INST_CALL);
        assert_eq!(JmpOp::EXIT as u8, INST_EXIT);
    }

    #[test]
    fn alu_op_from_opcode_all_valid() {
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_ADD | INST_CLS_ALU64),
            Some(AluOp::ADD)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_SUB | INST_CLS_ALU),
            Some(AluOp::SUB)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_MUL | INST_CLS_ALU64),
            Some(AluOp::MUL)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_DIV | INST_CLS_ALU),
            Some(AluOp::DIV)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_OR | INST_CLS_ALU64),
            Some(AluOp::OR)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_AND | INST_CLS_ALU),
            Some(AluOp::AND)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_LSH | INST_CLS_ALU64),
            Some(AluOp::LSH)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_RSH | INST_CLS_ALU),
            Some(AluOp::RSH)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_NEG | INST_CLS_ALU64),
            Some(AluOp::NEG)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_MOD | INST_CLS_ALU),
            Some(AluOp::MOD)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_XOR | INST_CLS_ALU64),
            Some(AluOp::XOR)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_MOV | INST_CLS_ALU),
            Some(AluOp::MOV)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_ARSH | INST_CLS_ALU64),
            Some(AluOp::ARSH)
        );
        assert_eq!(
            AluOp::from_opcode(INST_ALU_OP_END | INST_CLS_ALU),
            Some(AluOp::END)
        );
    }

    #[test]
    fn alu_op_from_opcode_reserved_returns_none() {
        // 0xE0 and 0xF0 are reserved ALU op nibbles
        assert_eq!(AluOp::from_opcode(0xe4), None); // ALU class
        assert_eq!(AluOp::from_opcode(0xf7), None); // ALU64 class
    }

    #[test]
    fn alu_op_variant_matches_constant() {
        assert_eq!((AluOp::ADD as u8) << 4, INST_ALU_OP_ADD);
        assert_eq!((AluOp::SUB as u8) << 4, INST_ALU_OP_SUB);
        assert_eq!((AluOp::MUL as u8) << 4, INST_ALU_OP_MUL);
        assert_eq!((AluOp::DIV as u8) << 4, INST_ALU_OP_DIV);
        assert_eq!((AluOp::OR as u8) << 4, INST_ALU_OP_OR);
        assert_eq!((AluOp::AND as u8) << 4, INST_ALU_OP_AND);
        assert_eq!((AluOp::LSH as u8) << 4, INST_ALU_OP_LSH);
        assert_eq!((AluOp::RSH as u8) << 4, INST_ALU_OP_RSH);
        assert_eq!((AluOp::NEG as u8) << 4, INST_ALU_OP_NEG);
        assert_eq!((AluOp::MOD as u8) << 4, INST_ALU_OP_MOD);
        assert_eq!((AluOp::XOR as u8) << 4, INST_ALU_OP_XOR);
        assert_eq!((AluOp::MOV as u8) << 4, INST_ALU_OP_MOV);
        assert_eq!((AluOp::ARSH as u8) << 4, INST_ALU_OP_ARSH);
        assert_eq!((AluOp::END as u8) << 4, INST_ALU_OP_END);
    }
}
