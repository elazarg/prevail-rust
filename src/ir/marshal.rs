// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Marshal encoding helpers ported from `src/ir/marshal.cpp`.
// Inverse of unmarshal — retained for spec completeness.
#![allow(dead_code)]

use crate::ir::syntax::{BinOp, ConditionOp, UnOp};

/// Encode a `Condition::Op` (passed as u8 discriminant) to the opcode nibble.
pub fn marshal_condition_op(op: u8) -> u8 {
    // SAFETY: We validate the discriminant before using it.
    match op {
        v if v == ConditionOp::EQ as u8 => 0x1,
        v if v == ConditionOp::GT as u8 => 0x2,
        v if v == ConditionOp::GE as u8 => 0x3,
        v if v == ConditionOp::SET as u8 => 0x4,
        v if v == ConditionOp::NSET as u8 => {
            unreachable!("marshal_condition_op: NSET is not a valid eBPF condition");
        }
        v if v == ConditionOp::NE as u8 => 0x5,
        v if v == ConditionOp::SGT as u8 => 0x6,
        v if v == ConditionOp::SGE as u8 => 0x7,
        v if v == ConditionOp::LT as u8 => 0xa,
        v if v == ConditionOp::LE as u8 => 0xb,
        v if v == ConditionOp::SLT as u8 => 0xc,
        v if v == ConditionOp::SLE as u8 => 0xd,
        _ => unreachable!("marshal_condition_op: unexpected op {op}"),
    }
}

/// Encode a `Bin::Op` (passed as u8 discriminant) to the ALU opcode nibble.
pub fn marshal_bin_op(op: u8) -> u8 {
    match op {
        v if v == BinOp::ADD as u8 => 0x0,
        v if v == BinOp::SUB as u8 => 0x1,
        v if v == BinOp::MUL as u8 => 0x2,
        v if v == BinOp::SDIV as u8 || v == BinOp::UDIV as u8 => 0x3,
        v if v == BinOp::OR as u8 => 0x4,
        v if v == BinOp::AND as u8 => 0x5,
        v if v == BinOp::LSH as u8 => 0x6,
        v if v == BinOp::RSH as u8 => 0x7,
        v if v == BinOp::SMOD as u8 || v == BinOp::UMOD as u8 => 0x9,
        v if v == BinOp::XOR as u8 => 0xa,
        v if v == BinOp::MOV as u8
            || v == BinOp::MOVSX8 as u8
            || v == BinOp::MOVSX16 as u8
            || v == BinOp::MOVSX32 as u8 =>
        {
            0xb
        }
        v if v == BinOp::ARSH as u8 => 0xc,
        _ => unreachable!("marshal_bin_op: unexpected op {op}"),
    }
}

/// Return the offset field for a `Bin::Op` (passed as u8 discriminant).
pub fn marshal_bin_op_offset(op: u8) -> i16 {
    match op {
        v if v == BinOp::SDIV as u8 || v == BinOp::SMOD as u8 => 1,
        v if v == BinOp::MOVSX8 as u8 => 8,
        v if v == BinOp::MOVSX16 as u8 => 16,
        v if v == BinOp::MOVSX32 as u8 => 32,
        _ => 0,
    }
}

/// Return the immediate value encoding for endian `Un::Op` (passed as u8 discriminant).
pub fn marshal_imm_endian(op: u8) -> u8 {
    match op {
        v if v == UnOp::NEG as u8 => {
            unreachable!("marshal_imm_endian: NEG has no endian immediate");
        }
        v if v == UnOp::BE16 as u8 || v == UnOp::LE16 as u8 || v == UnOp::SWAP16 as u8 => 16,
        v if v == UnOp::BE32 as u8 || v == UnOp::LE32 as u8 || v == UnOp::SWAP32 as u8 => 32,
        v if v == UnOp::BE64 as u8 || v == UnOp::LE64 as u8 || v == UnOp::SWAP64 as u8 => 64,
        _ => unreachable!("marshal_imm_endian: unexpected op {op}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_op_encoding() {
        assert_eq!(marshal_condition_op(ConditionOp::EQ as u8), 0x1);
        assert_eq!(marshal_condition_op(ConditionOp::GT as u8), 0x2);
        assert_eq!(marshal_condition_op(ConditionOp::GE as u8), 0x3);
        assert_eq!(marshal_condition_op(ConditionOp::SET as u8), 0x4);
        assert_eq!(marshal_condition_op(ConditionOp::NE as u8), 0x5);
        assert_eq!(marshal_condition_op(ConditionOp::SGT as u8), 0x6);
        assert_eq!(marshal_condition_op(ConditionOp::SGE as u8), 0x7);
        assert_eq!(marshal_condition_op(ConditionOp::LT as u8), 0xa);
        assert_eq!(marshal_condition_op(ConditionOp::LE as u8), 0xb);
        assert_eq!(marshal_condition_op(ConditionOp::SLT as u8), 0xc);
        assert_eq!(marshal_condition_op(ConditionOp::SLE as u8), 0xd);
    }

    #[test]
    fn bin_op_encoding() {
        assert_eq!(marshal_bin_op(BinOp::ADD as u8), 0x0);
        assert_eq!(marshal_bin_op(BinOp::SUB as u8), 0x1);
        assert_eq!(marshal_bin_op(BinOp::MUL as u8), 0x2);
        assert_eq!(marshal_bin_op(BinOp::UDIV as u8), 0x3);
        assert_eq!(marshal_bin_op(BinOp::SDIV as u8), 0x3);
        assert_eq!(marshal_bin_op(BinOp::OR as u8), 0x4);
        assert_eq!(marshal_bin_op(BinOp::AND as u8), 0x5);
        assert_eq!(marshal_bin_op(BinOp::LSH as u8), 0x6);
        assert_eq!(marshal_bin_op(BinOp::RSH as u8), 0x7);
        assert_eq!(marshal_bin_op(BinOp::UMOD as u8), 0x9);
        assert_eq!(marshal_bin_op(BinOp::SMOD as u8), 0x9);
        assert_eq!(marshal_bin_op(BinOp::XOR as u8), 0xa);
        assert_eq!(marshal_bin_op(BinOp::MOV as u8), 0xb);
        assert_eq!(marshal_bin_op(BinOp::MOVSX8 as u8), 0xb);
        assert_eq!(marshal_bin_op(BinOp::MOVSX16 as u8), 0xb);
        assert_eq!(marshal_bin_op(BinOp::MOVSX32 as u8), 0xb);
        assert_eq!(marshal_bin_op(BinOp::ARSH as u8), 0xc);
    }

    #[test]
    fn bin_op_offset_encoding() {
        assert_eq!(marshal_bin_op_offset(BinOp::ADD as u8), 0);
        assert_eq!(marshal_bin_op_offset(BinOp::MOV as u8), 0);
        assert_eq!(marshal_bin_op_offset(BinOp::SDIV as u8), 1);
        assert_eq!(marshal_bin_op_offset(BinOp::SMOD as u8), 1);
        assert_eq!(marshal_bin_op_offset(BinOp::MOVSX8 as u8), 8);
        assert_eq!(marshal_bin_op_offset(BinOp::MOVSX16 as u8), 16);
        assert_eq!(marshal_bin_op_offset(BinOp::MOVSX32 as u8), 32);
    }

    #[test]
    fn imm_endian_encoding() {
        assert_eq!(marshal_imm_endian(UnOp::BE16 as u8), 16);
        assert_eq!(marshal_imm_endian(UnOp::LE16 as u8), 16);
        assert_eq!(marshal_imm_endian(UnOp::SWAP16 as u8), 16);
        assert_eq!(marshal_imm_endian(UnOp::BE32 as u8), 32);
        assert_eq!(marshal_imm_endian(UnOp::LE32 as u8), 32);
        assert_eq!(marshal_imm_endian(UnOp::SWAP32 as u8), 32);
        assert_eq!(marshal_imm_endian(UnOp::BE64 as u8), 64);
        assert_eq!(marshal_imm_endian(UnOp::LE64 as u8), 64);
        assert_eq!(marshal_imm_endian(UnOp::SWAP64 as u8), 64);
    }
}
