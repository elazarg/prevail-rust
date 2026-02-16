// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! BPF mnemonic assembler for conformance tests.
//!
//! Ported from `tests/upstream/external/bpf_conformance/src/bpf_assembler.cc`.
//! Converts BPF assembly in mnemonic syntax (`mov32 %r0, 0`, `add %r0, %r1`,
//! labels like `L1:`) into a sequence of `EbpfInst` structs.
//!
//! Two-pass: first pass assembles instructions and collects labels,
//! second pass fixes up jump offsets.

use std::collections::HashMap;

use crate::spec::vm_isa::*;

// ============================================================================
// Encoding result
// ============================================================================

enum EncodeResult {
    Single(EbpfInst),
    Double([EbpfInst; 2]),
}

// ============================================================================
// Assembler
// ============================================================================

struct BpfAssembler {
    labels: HashMap<String, usize>,
    jump_instructions: Vec<Option<String>>,
}

impl BpfAssembler {
    fn new() -> Self {
        BpfAssembler {
            labels: HashMap::new(),
            jump_instructions: Vec::new(),
        }
    }

    // ── Decode helpers ──────────────────────────────────────────────────

    fn decode_register(name: &str) -> Result<u8, String> {
        match name {
            "%r0" => Ok(0),
            "%r1" => Ok(1),
            "%r2" => Ok(2),
            "%r3" => Ok(3),
            "%r4" => Ok(4),
            "%r5" => Ok(5),
            "%r6" => Ok(6),
            "%r7" => Ok(7),
            "%r8" => Ok(8),
            "%r9" => Ok(9),
            "%r10" => Ok(10),
            // Fake registers for negative tests.
            "%r11" => Ok(11),
            "%r12" => Ok(12),
            "%r13" => Ok(13),
            "%r14" => Ok(14),
            "%r15" => Ok(15),
            _ => Err(format!("Invalid register: {name}")),
        }
    }

    fn decode_imm64(s: &str) -> Result<u64, String> {
        if s.contains("0x") || s.contains("0X") {
            let hex = s.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(hex, 16).map_err(|e| format!("Bad hex imm64 '{s}': {e}"))
        } else if s.starts_with('-') {
            let val: i64 = s.parse().map_err(|e| format!("Bad imm64 '{s}': {e}"))?;
            Ok(val as u64)
        } else {
            s.parse::<u64>()
                .map_err(|e| format!("Bad imm64 '{s}': {e}"))
        }
    }

    fn decode_imm32(s: &str) -> Result<u32, String> {
        if s.contains("0x") || s.contains("0X") {
            let hex = s.trim_start_matches("0x").trim_start_matches("0X");
            let value =
                u64::from_str_radix(hex, 16).map_err(|e| format!("Bad hex imm32 '{s}': {e}"))?;
            if value > u32::MAX as u64 {
                return Err(format!("Immediate out of 32-bit range: {s}"));
            }
            Ok(value as u32)
        } else {
            let value: i64 = s.parse().map_err(|e| format!("Bad imm32 '{s}': {e}"))?;
            if value < i32::MIN as i64 || value > i32::MAX as i64 {
                return Err(format!("Immediate out of 32-bit range: {s}"));
            }
            Ok(value as i32 as u32)
        }
    }

    fn decode_offset(s: &str) -> Result<i16, String> {
        if s.contains("0x") || s.contains("0X") {
            let hex = s
                .trim_start_matches('+')
                .trim_start_matches('-')
                .trim_start_matches("0x")
                .trim_start_matches("0X");
            let value =
                u64::from_str_radix(hex, 16).map_err(|e| format!("Bad hex offset '{s}': {e}"))?;
            if s.starts_with('-') {
                let neg = -(value as i64);
                if neg < i16::MIN as i64 {
                    return Err(format!("Offset out of 16-bit range: {s}"));
                }
                Ok(neg as i16)
            } else {
                if value > u16::MAX as u64 {
                    return Err(format!("Offset out of 16-bit range: {s}"));
                }
                Ok(value as u16 as i16)
            }
        } else {
            let value: i64 = s.parse().map_err(|e| format!("Bad offset '{s}': {e}"))?;
            if value < i16::MIN as i64 || value > i16::MAX as i64 {
                return Err(format!("Offset out of 16-bit range: {s}"));
            }
            Ok(value as i16)
        }
    }

    fn decode_jump_target(&mut self, s: &str) -> Result<i16, String> {
        if s.starts_with('+') || s.starts_with('-') {
            Self::decode_offset(s)
        } else {
            // It's a label name; record it for fixup.
            *self.jump_instructions.last_mut().unwrap() = Some(s.to_string());
            Ok(0)
        }
    }

    fn decode_register_and_offset(operand: &str) -> Result<(u8, i16), String> {
        let reg_start = operand
            .find('[')
            .ok_or_else(|| format!("Failed to decode register and offset: {operand}"))?;
        let after_reg = &operand[reg_start + 1..];

        // Find the end of the register name: first '+', '-', or ']'
        let reg_end_pos = after_reg
            .find(['+', '-', ']'])
            .ok_or_else(|| format!("Failed to decode register and offset: {operand}"))?;

        let reg_name = &after_reg[..reg_end_pos];
        let reg = Self::decode_register(reg_name)?;

        let remaining = &after_reg[reg_end_pos..];
        if remaining.starts_with(']') {
            Ok((reg, 0))
        } else {
            // remaining starts with '+' or '-', parse offset up to ']'
            let bracket_pos = remaining
                .find(']')
                .ok_or_else(|| format!("Missing closing bracket: {operand}"))?;
            let offset_str = &remaining[..bracket_pos];
            let offset = Self::decode_offset(offset_str)?;
            Ok((reg, offset))
        }
    }

    // ── ALU ops lookup ──────────────────────────────────────────────────

    fn alu_op(name: &str) -> Option<u8> {
        match name {
            "add" => Some(0x0),
            "sub" => Some(0x1),
            "mul" => Some(0x2),
            "div" | "sdiv" => Some(0x3),
            "or" => Some(0x4),
            "and" => Some(0x5),
            "lsh" => Some(0x6),
            "rsh" => Some(0x7),
            "neg" => Some(0x8),
            "mod" | "smod" => Some(0x9),
            "xor" => Some(0xa),
            "mov" | "movsx" => Some(0xb),
            "arsh" => Some(0xc),
            "le" | "be" | "swap" => Some(0xd),
            _ => None,
        }
    }

    fn jmp_op(name: &str) -> Option<u8> {
        match name {
            "jeq" => Some(0x1),
            "jgt" => Some(0x2),
            "jge" => Some(0x3),
            "jset" => Some(0x4),
            "jne" => Some(0x5),
            "jsgt" => Some(0x6),
            "jsge" => Some(0x7),
            "jlt" => Some(0xa),
            "jle" => Some(0xb),
            "jslt" => Some(0xc),
            "jsle" => Some(0xd),
            _ => None,
        }
    }

    // ── Encode functions ────────────────────────────────────────────────

    fn encode_ld(operands: &[&str]) -> Result<EncodeResult, String> {
        let dst = Self::decode_register(operands[0])?;
        let imm = Self::decode_imm64(operands[1])?;
        Ok(EncodeResult::Double([
            EbpfInst::new(INST_OP_LDDW_IMM, dst, 0, 0, imm as u32 as i32),
            EbpfInst::new(0, 0, 0, 0, (imm >> 32) as u32 as i32),
        ]))
    }

    fn encode_ldx(mnemonic: &str, operands: &[&str]) -> Result<EncodeResult, String> {
        let dst = Self::decode_register(operands[0])?;
        let (src, offset) = Self::decode_register_and_offset(operands[1])?;
        let opcode = match mnemonic {
            "ldxb" => INST_CLS_LDX | INST_MODE_MEM | INST_SIZE_B,
            "ldxh" => INST_CLS_LDX | INST_MODE_MEM | INST_SIZE_H,
            "ldxw" => INST_CLS_LDX | INST_MODE_MEM | INST_SIZE_W,
            "ldxdw" => INST_CLS_LDX | INST_MODE_MEM | INST_SIZE_DW,
            "ldxsb" => INST_CLS_LDX | INST_MODE_MEMSX | INST_SIZE_B,
            "ldxsh" => INST_CLS_LDX | INST_MODE_MEMSX | INST_SIZE_H,
            "ldxsw" => INST_CLS_LDX | INST_MODE_MEMSX | INST_SIZE_W,
            _ => return Err(format!("Invalid mnemonic: {mnemonic}")),
        };
        Ok(EncodeResult::Single(EbpfInst::new(
            opcode, dst, src, offset, 0,
        )))
    }

    fn encode_st(mnemonic: &str, operands: &[&str]) -> Result<EncodeResult, String> {
        let (dst, offset) = Self::decode_register_and_offset(operands[0])?;
        let imm = Self::decode_imm32(operands[1])? as i32;
        let opcode = match mnemonic {
            "stb" => INST_CLS_ST | INST_MODE_MEM | INST_SIZE_B,
            "sth" => INST_CLS_ST | INST_MODE_MEM | INST_SIZE_H,
            "stw" => INST_CLS_ST | INST_MODE_MEM | INST_SIZE_W,
            "stdw" => INST_CLS_ST | INST_MODE_MEM | INST_SIZE_DW,
            _ => return Err(format!("Invalid mnemonic: {mnemonic}")),
        };
        Ok(EncodeResult::Single(EbpfInst::new(
            opcode, dst, 0, offset, imm,
        )))
    }

    fn encode_stx(mnemonic: &str, operands: &[&str]) -> Result<EncodeResult, String> {
        let (dst, offset) = Self::decode_register_and_offset(operands[0])?;
        let src = Self::decode_register(operands[1])?;
        let opcode = match mnemonic {
            "stxb" => INST_CLS_STX | INST_MODE_MEM | INST_SIZE_B,
            "stxh" => INST_CLS_STX | INST_MODE_MEM | INST_SIZE_H,
            "stxw" => INST_CLS_STX | INST_MODE_MEM | INST_SIZE_W,
            "stxdw" => INST_CLS_STX | INST_MODE_MEM | INST_SIZE_DW,
            _ => return Err(format!("Invalid mnemonic: {mnemonic}")),
        };
        Ok(EncodeResult::Single(EbpfInst::new(
            opcode, dst, src, offset, 0,
        )))
    }

    fn encode_alu(mnemonic: &str, operands: &[&str]) -> Result<EncodeResult, String> {
        let mut inst = EbpfInst::new(0, 0, 0, 0, 0);

        // be<N>, le<N>, swap<N>, bswap<N> — endianness conversion
        // Note: check "bswap"/"swap" before "be" since "bswap" starts with "b"
        let endian = mnemonic
            .strip_prefix("bswap")
            .or_else(|| mnemonic.strip_prefix("swap"))
            .map(|s| (INST_CLS_ALU64 | INST_SRC_IMM | INST_ALU_OP_END, s))
            .or_else(|| {
                mnemonic
                    .strip_prefix("be")
                    .map(|s| (INST_CLS_ALU | INST_SRC_REG | INST_ALU_OP_END, s))
            })
            .or_else(|| {
                mnemonic
                    .strip_prefix("le")
                    .map(|s| (INST_CLS_ALU | INST_SRC_IMM | INST_ALU_OP_END, s))
            });
        if let Some((opcode, suffix)) = endian {
            inst.opcode = opcode;
            inst.set_dst(Self::decode_register(operands[0])?);
            inst.imm = Self::decode_imm32(suffix)? as i32;
            return Ok(EncodeResult::Single(inst));
        }

        // sdiv / smod use offset=1
        if mnemonic.starts_with("sdiv") || mnemonic.starts_with("smod") {
            inst.offset = 1;
        }

        // Determine ALU class and base operation name
        let alu_op_name;
        if let Some(base) = mnemonic.strip_suffix("32") {
            inst.opcode |= INST_CLS_ALU;
            alu_op_name = base.to_string();
        } else if let Some(base) = mnemonic.strip_suffix("64") {
            inst.opcode |= INST_CLS_ALU64;
            alu_op_name = base.to_string();
        } else {
            inst.opcode |= INST_CLS_ALU64;
            alu_op_name = mnemonic.to_string();
        }

        // Handle movsx variants: movsx8, movsx16, movsx32
        let final_alu_op = if let Some(size_str) = alu_op_name.strip_prefix("movsx") {
            inst.offset = Self::decode_offset(size_str)?;
            "movsx"
        } else {
            &alu_op_name
        };

        let op_code =
            Self::alu_op(final_alu_op).ok_or_else(|| format!("Unknown ALU op: {final_alu_op}"))?;
        inst.opcode |= op_code << 4;

        inst.set_dst(Self::decode_register(operands[0])?);

        if operands.len() == 2 {
            Self::encode_src_operand(&mut inst, operands[1])?;
        }

        Ok(EncodeResult::Single(inst))
    }

    /// Encode a register-or-immediate source operand into `inst`.
    fn encode_src_operand(inst: &mut EbpfInst, operand: &str) -> Result<(), String> {
        if operand.starts_with('%') {
            inst.opcode |= INST_SRC_REG;
            inst.set_src(Self::decode_register(operand)?);
        } else {
            inst.opcode |= INST_SRC_IMM;
            inst.imm = Self::decode_imm32(operand)? as i32;
        }
        Ok(())
    }

    fn encode_jmp(&mut self, mnemonic: &str, operands: &[&str]) -> Result<EncodeResult, String> {
        let mut inst = EbpfInst::new(0, 0, 0, 0, 0);

        if mnemonic == "ja" {
            inst.opcode = INST_CLS_JMP;
            inst.offset = self.decode_jump_target(operands[0])?;
        } else if mnemonic == "ja32" {
            inst.opcode = INST_CLS_JMP32;
            inst.imm = self.decode_jump_target(operands[0])? as i32;
        } else if mnemonic == "exit" {
            inst.opcode = INST_OP_EXIT;
        } else if mnemonic == "call" {
            inst.opcode = INST_OP_CALL;
            let mode = operands[0];
            let target = operands[1];
            if mode == "helper" {
                if target.starts_with('%') {
                    inst.opcode |= INST_SRC_REG;
                    inst.set_dst(Self::decode_register(target)?);
                } else {
                    inst.opcode |= INST_SRC_IMM;
                    inst.imm = Self::decode_imm32(target)? as i32;
                }
                inst.set_src(0);
            } else if mode == "local" {
                inst.imm = self.decode_jump_target(target)? as i32;
                inst.set_src(1);
            } else if mode == "runtime" {
                inst.imm = Self::decode_imm32(target)? as i32;
                inst.set_src(2);
            } else {
                return Err("Invalid call mode".to_string());
            }
        } else {
            // Conditional jump: jXX[32] reg, reg/imm, target
            if let Some(base) = mnemonic.strip_suffix("32") {
                inst.opcode = INST_CLS_JMP32;
                let jmp_code =
                    Self::jmp_op(base).ok_or_else(|| format!("Unknown jmp op: {base}"))?;
                inst.opcode |= jmp_code << 4;
            } else {
                inst.opcode = INST_CLS_JMP;
                let jmp_code =
                    Self::jmp_op(mnemonic).ok_or_else(|| format!("Unknown jmp op: {mnemonic}"))?;
                inst.opcode |= jmp_code << 4;
            }
            inst.set_dst(Self::decode_register(operands[0])?);
            Self::encode_src_operand(&mut inst, operands[1])?;
            inst.offset = self.decode_jump_target(operands[2])?;
        }
        Ok(EncodeResult::Single(inst))
    }

    fn encode_atomic(mnemonic: &str, operands: &[&str]) -> Result<EncodeResult, String> {
        let mut inst = EbpfInst::new(0, 0, 0, 0, 0);

        // Determine 32-bit or 64-bit atomic
        if mnemonic.ends_with("32") {
            inst.opcode = INST_CLS_STX | INST_MODE_ATOMIC | INST_SIZE_W;
        } else {
            inst.opcode = INST_CLS_STX | INST_MODE_ATOMIC | INST_SIZE_DW;
        }

        let fetch = operands[0] == "fetch";

        // operands: [fetch/no_fetch, [dst+off], src]
        let (dst, offset) = Self::decode_register_and_offset(operands[1])?;
        inst.set_dst(dst);
        inst.offset = offset;
        inst.set_src(Self::decode_register(operands[2])?);

        // Strip trailing "32" from mnemonic for the operation lookup
        let base_op = mnemonic.strip_suffix("32").unwrap_or(mnemonic);

        match base_op {
            "add" => {
                inst.imm = INST_ALU_OP_ADD as i32;
                if fetch {
                    inst.imm |= ATOMIC_OP_FETCH as i32;
                }
            }
            "and" => {
                inst.imm = INST_ALU_OP_AND as i32;
                if fetch {
                    inst.imm |= ATOMIC_OP_FETCH as i32;
                }
            }
            "or" => {
                inst.imm = INST_ALU_OP_OR as i32;
                if fetch {
                    inst.imm |= ATOMIC_OP_FETCH as i32;
                }
            }
            "xor" => {
                inst.imm = INST_ALU_OP_XOR as i32;
                if fetch {
                    inst.imm |= ATOMIC_OP_FETCH as i32;
                }
            }
            "xchg" => {
                // xchg always has fetch bit set
                inst.imm = ATOMIC_OP_XCHG as i32;
            }
            "cmpxchg" => {
                // cmpxchg always has fetch bit set
                inst.imm = ATOMIC_OP_CMPXCHG as i32;
            }
            _ => return Err(format!("Unknown atomic op: {base_op}")),
        }

        Ok(EncodeResult::Single(inst))
    }

    // ── Mnemonic dispatch ───────────────────────────────────────────────

    /// Returns (encode_category, expected_operand_count) for a mnemonic.
    fn mnemonic_info(mnemonic: &str) -> Option<(MnemonicKind, usize)> {
        match mnemonic {
            // ALU 2-operand
            "add" | "add32" | "and" | "and32" | "arsh" | "arsh32" | "div" | "div32" | "lsh"
            | "lsh32" | "mod" | "mod32" | "mov" | "mov32" | "mul" | "mul32" | "or" | "or32"
            | "rsh" | "rsh32" | "sdiv" | "sdiv32" | "smod" | "smod32" | "sub" | "sub32" | "xor"
            | "xor32" => Some((MnemonicKind::Alu, 2)),
            // movsx variants
            m if m.starts_with("movsx") => Some((MnemonicKind::Alu, 2)),
            // ALU 1-operand (neg)
            "neg" | "neg32" => Some((MnemonicKind::Alu, 1)),
            // Endian 1-operand
            "be16" | "be32" | "be64" | "le16" | "le32" | "le64" | "swap16" | "swap32"
            | "swap64" | "bswap16" | "bswap32" | "bswap64" => Some((MnemonicKind::Alu, 1)),
            // LDDW
            "lddw" => Some((MnemonicKind::Ld, 2)),
            // LDX
            "ldxb" | "ldxh" | "ldxw" | "ldxdw" | "ldxsb" | "ldxsh" | "ldxsw" => {
                Some((MnemonicKind::Ldx, 2))
            }
            // ST
            "stb" | "sth" | "stw" | "stdw" => Some((MnemonicKind::St, 2)),
            // STX
            "stxb" | "stxh" | "stxw" | "stxdw" => Some((MnemonicKind::Stx, 2)),
            // JMP
            "exit" => Some((MnemonicKind::Jmp, 0)),
            "ja" | "ja32" => Some((MnemonicKind::Jmp, 1)),
            "call" => Some((MnemonicKind::Jmp, 2)),
            // Conditional jumps: 3 operands
            m if Self::is_conditional_jmp(m) => Some((MnemonicKind::Jmp, 3)),
            _ => None,
        }
    }

    fn is_conditional_jmp(m: &str) -> bool {
        let base = m.strip_suffix("32").unwrap_or(m);
        matches!(
            base,
            "jeq"
                | "jgt"
                | "jge"
                | "jset"
                | "jne"
                | "jsgt"
                | "jsge"
                | "jlt"
                | "jle"
                | "jslt"
                | "jsle"
        )
    }

    fn atomic_info(mnemonic: &str) -> Option<usize> {
        match mnemonic {
            "add" | "add32" | "and" | "and32" | "or" | "or32" | "xor" | "xor32" | "xchg"
            | "xchg32" | "cmpxchg" | "cmpxchg32" => Some(3),
            _ => None,
        }
    }

    // ── Main assembly ───────────────────────────────────────────────────

    fn assemble(&mut self, input: &str) -> Result<Vec<EbpfInst>, String> {
        let mut exit_count = 0usize;
        self.jump_instructions.clear();
        self.labels.clear();
        let mut output: Vec<EbpfInst> = Vec::new();

        for line in input.lines() {
            // Strip comments
            let line = if let Some(pos) = line.find('#') {
                &line[..pos]
            } else {
                line
            };

            let mut tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.is_empty() {
                continue;
            }

            // Strip trailing commas from tokens
            let cleaned: Vec<String> = tokens
                .iter()
                .map(|t| t.strip_suffix(',').unwrap_or(t).to_string())
                .collect();
            tokens = cleaned.iter().map(|s| s.as_str()).collect();

            let mnemonic = tokens[0];
            let operands: Vec<&str> = tokens[1..].to_vec();

            // Check for labels
            if let Some(label) = mnemonic.strip_suffix(':') {
                if self.labels.contains_key(label) {
                    return Err(format!(
                        "Duplicate label ({label}) detected at line {} (previous declaration at line {})",
                        output.len(),
                        self.labels[label]
                    ));
                }
                self.labels.insert(label.to_string(), output.len());
                continue;
            }

            // Add default exit label for the first exit statement
            if mnemonic == "exit" && exit_count == 0 {
                self.labels
                    .entry("exit".to_string())
                    .or_insert(output.len());
                exit_count += 1;
            }

            // Assume not a jump instruction
            self.jump_instructions.push(None);

            // Handle `lock` prefix for atomic operations
            if mnemonic == "lock" {
                if operands.len() < 2 {
                    return Err("Invalid number of operands for lock".to_string());
                }

                // Format: lock [fetch] <op> <dst>, <src>
                // Normalize to: <op> <fetch/no_fetch> <dst> <src>
                let mut owned_ops: Vec<String> = operands.iter().map(|s| s.to_string()).collect();
                if owned_ops.len() > 1 && owned_ops[0] != "fetch" {
                    owned_ops.insert(0, "no_fetch".to_string());
                }
                // Swap fetch/no_fetch and op
                owned_ops.swap(0, 1);

                let atomic_mnemonic = owned_ops[0].clone();
                let remaining: Vec<String> = owned_ops[1..].to_vec();
                let remaining_refs: Vec<&str> = remaining.iter().map(|s| s.as_str()).collect();

                let expected_count = Self::atomic_info(&atomic_mnemonic)
                    .ok_or_else(|| format!("Invalid atomic mnemonic: {atomic_mnemonic}"))?;
                if remaining_refs.len() != expected_count {
                    return Err(format!(
                        "Invalid number of operands for atomic mnemonic: {atomic_mnemonic}"
                    ));
                }
                let result = Self::encode_atomic(&atomic_mnemonic, &remaining_refs)?;
                match result {
                    EncodeResult::Single(inst) => output.push(inst),
                    EncodeResult::Double(insts) => {
                        self.jump_instructions.push(None);
                        output.extend_from_slice(&insts);
                    }
                }
                continue;
            }

            // Handle `call` without explicit mode: default to "helper"
            let mut operands = operands;
            let helper_default;
            if mnemonic == "call" && operands.len() == 1 {
                helper_default = vec!["helper", operands[0]];
                operands = helper_default;
            }

            let (kind, expected_count) = Self::mnemonic_info(mnemonic)
                .ok_or_else(|| format!("Invalid mnemonic: {mnemonic}"))?;

            if operands.len() != expected_count {
                return Err(format!(
                    "Invalid number of operands for mnemonic: {mnemonic}"
                ));
            }

            let result = match kind {
                MnemonicKind::Alu => Self::encode_alu(mnemonic, &operands)?,
                MnemonicKind::Ld => Self::encode_ld(&operands)?,
                MnemonicKind::Ldx => Self::encode_ldx(mnemonic, &operands)?,
                MnemonicKind::St => Self::encode_st(mnemonic, &operands)?,
                MnemonicKind::Stx => Self::encode_stx(mnemonic, &operands)?,
                MnemonicKind::Jmp => self.encode_jmp(mnemonic, &operands)?,
            };

            match result {
                EncodeResult::Single(inst) => output.push(inst),
                EncodeResult::Double(insts) => {
                    // lddw takes 2 instruction slots
                    self.jump_instructions.push(None);
                    output.extend_from_slice(&insts);
                }
            }
        }

        // Fixup jump instructions
        for (i, jump) in self.jump_instructions.iter().enumerate() {
            if let Some(label_name) = jump {
                let target = self
                    .labels
                    .get(label_name)
                    .ok_or_else(|| format!("Invalid label: {label_name}"))?;
                let target = *target;
                if output[i].opcode == INST_OP_CALL || output[i].opcode == INST_OP_JA32 {
                    output[i].imm = (target as isize - i as isize - 1) as i32;
                } else {
                    output[i].offset = (target as isize - i as isize - 1) as i16;
                }
            }
        }

        Ok(output)
    }
}

#[derive(Clone, Copy)]
enum MnemonicKind {
    Alu,
    Ld,
    Ldx,
    St,
    Stx,
    Jmp,
}

// ============================================================================
// Atomic operation constants (matching ebpf.h)
// ============================================================================

const ATOMIC_OP_FETCH: u8 = 0x01;
const ATOMIC_OP_XCHG: u8 = 0xe0 | ATOMIC_OP_FETCH;
const ATOMIC_OP_CMPXCHG: u8 = 0xf0 | ATOMIC_OP_FETCH;

// ============================================================================
// Public API
// ============================================================================

/// Assemble BPF mnemonic assembly text into a vector of `EbpfInst`.
///
/// Supports the conformance test `.data` file assembly format:
/// `mov32 %r0, 0`, `add %r0, %r1`, labels like `L1:`, etc.
pub fn bpf_assemble(input: &str) -> Result<Vec<EbpfInst>, String> {
    let mut assembler = BpfAssembler::new();
    assembler.assemble(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::syntax::Reg;

    #[test]
    fn simple_mov_exit() {
        let asm = "mov32 %r0, 0\nexit\n";
        let insts = bpf_assemble(asm).unwrap();
        assert_eq!(insts.len(), 2);
        assert_eq!(
            insts[0].opcode,
            INST_CLS_ALU | INST_SRC_IMM | INST_ALU_OP_MOV
        );
        assert_eq!(insts[0].dst(), Reg { v: 0 });
        assert_eq!(insts[0].imm, 0);
        assert_eq!(insts[1].opcode, INST_OP_EXIT);
    }

    #[test]
    fn add_test() {
        let asm = "\
mov32 %r0, 0
mov32 %r1, 2
add32 %r0, 1
add32 %r0, %r1
add32 %r0, %r0
add32 %r0, -3
exit
";
        let insts = bpf_assemble(asm).unwrap();
        assert_eq!(insts.len(), 7);
        // add32 %r0, 1 → ALU | IMM | ADD
        assert_eq!(
            insts[2].opcode,
            INST_CLS_ALU | INST_SRC_IMM | INST_ALU_OP_ADD
        );
        assert_eq!(insts[2].imm, 1);
        // add32 %r0, %r1 → ALU | REG | ADD
        assert_eq!(
            insts[3].opcode,
            INST_CLS_ALU | INST_SRC_REG | INST_ALU_OP_ADD
        );
        assert_eq!(insts[3].src(), Reg { v: 1 });
    }

    #[test]
    fn lddw_test() {
        let asm = "lddw %r0, 0x123456789abcdef0\nexit\n";
        let insts = bpf_assemble(asm).unwrap();
        assert_eq!(insts.len(), 3); // lddw is 2 slots + exit
        assert_eq!(insts[0].opcode, INST_OP_LDDW_IMM);
        assert_eq!(insts[0].imm, 0x9abcdef0u32 as i32);
        assert_eq!(insts[1].imm, 0x12345678u32 as i32);
    }

    #[test]
    fn label_jump() {
        let asm = "\
mov %r0, 1
ja L1
mov %r0, 2
L1:
exit
";
        let insts = bpf_assemble(asm).unwrap();
        assert_eq!(insts.len(), 4);
        // ja L1 is at index 1, L1 is at index 3
        assert_eq!(insts[1].offset, 1); // 3 - 1 - 1 = 1
    }

    #[test]
    fn lock_add() {
        let asm = "\
mov %r0, 1
stxdw [%r10-8], %r0
lock add [%r10-8], %r0
ldxdw %r0, [%r10-8]
exit
";
        let insts = bpf_assemble(asm).unwrap();
        // lock add → atomic store DW with ADD op
        let atomic = &insts[2];
        assert_eq!(
            atomic.opcode,
            INST_CLS_STX | INST_MODE_ATOMIC | INST_SIZE_DW
        );
        assert_eq!(atomic.imm, INST_ALU_OP_ADD as i32);
    }
}
