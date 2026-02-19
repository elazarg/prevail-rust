// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Pretty-printing for eBPF instructions, assertions, and program structures.
//!
//! Ported from `src/printing.cpp`. Uses `std::fmt::Display` instead of C++ `operator<<`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};

use crate::cfg::label::{Label, Pc};
use crate::crab::type_encoding::TypeGroup;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::{
    AccessType, Addable, ArgPair, ArgPairKind, ArgSingle, ArgSingleKind, Assertion, Assume, Atomic,
    AtomicOp, Bin, BinOp, BoundedLoopCount, BtfLineInfo, Call, CallBtf, CallLocal, Callx,
    Comparable, Condition, ConditionOp, Deref, Exit, FuncConstraint, Imm, IncrementLoopCounter,
    Instruction, InstructionSeq, Jmp, LoadMapAddress, LoadMapFd, LoadPseudo, Mem, Packet, Reg,
    TypeConstraint, Un, UnOp, Undefined, ValidAccess, ValidCallbackTarget, ValidDivisor,
    ValidMapKeyValue, ValidSize, ValidStore, Value, ZeroCtxOffset,
};
use crate::spec::type_descriptors::EbpfMapDescriptor;
use crate::spec::vm_isa::AccessSize;

// ============================================================================
// Basic Display impls
// ============================================================================

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.v)
    }
}

impl fmt::Display for Imm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as signed (same as C++ which casts to int64_t).
        write!(f, "{}", self.v as i64)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Imm(imm) => write!(f, "{imm}"),
            Value::Reg(reg) => write!(f, "{reg}"),
        }
    }
}

impl fmt::Display for BinOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BinOp::MOV => Ok(()),
            BinOp::MOVSX8 => write!(f, "s8"),
            BinOp::MOVSX16 => write!(f, "s16"),
            BinOp::MOVSX32 => write!(f, "s32"),
            BinOp::ADD => write!(f, "+"),
            BinOp::SUB => write!(f, "-"),
            BinOp::MUL => write!(f, "*"),
            BinOp::UDIV => write!(f, "/"),
            BinOp::SDIV => write!(f, "s/"),
            BinOp::UMOD => write!(f, "%"),
            BinOp::SMOD => write!(f, "s%"),
            BinOp::OR => write!(f, "|"),
            BinOp::AND => write!(f, "&"),
            BinOp::LSH => write!(f, "<<"),
            BinOp::RSH => write!(f, ">>"),
            BinOp::ARSH => write!(f, ">>>"),
            BinOp::XOR => write!(f, "^"),
        }
    }
}

impl fmt::Display for ConditionOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConditionOp::EQ => write!(f, "=="),
            ConditionOp::NE => write!(f, "!="),
            ConditionOp::SET => write!(f, "&=="),
            ConditionOp::NSET => write!(f, "&!="),
            ConditionOp::LT => write!(f, "<"),
            ConditionOp::LE => write!(f, "<="),
            ConditionOp::GT => write!(f, ">"),
            ConditionOp::GE => write!(f, ">="),
            ConditionOp::SLT => write!(f, "s<"),
            ConditionOp::SLE => write!(f, "s<="),
            ConditionOp::SGT => write!(f, "s>"),
            ConditionOp::SGE => write!(f, "s>="),
        }
    }
}

impl fmt::Display for AtomicOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtomicOp::ADD => write!(f, "+"),
            AtomicOp::OR => write!(f, "|"),
            AtomicOp::AND => write!(f, "&"),
            AtomicOp::XOR => write!(f, "^"),
            AtomicOp::XCHG => write!(f, "x"),
            AtomicOp::CMPXCHG => write!(f, "cx"),
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Returns the size string like "u8", "u16", etc. for an access size.
fn size_str(width: AccessSize) -> String {
    format!("{width}")
}

/// llvm-objdump uses "w<number>" for 32-bit operations and "r<number>" for 64-bit operations.
fn reg_name(reg: &Reg, is64: bool) -> String {
    if is64 {
        format!("r{}", reg.v)
    } else {
        format!("w{}", reg.v)
    }
}

/// Returns the instruction size in 8-byte units. LDDW is 2; everything else is 1.
pub fn instruction_size(ins: &Instruction) -> Pc {
    match ins {
        Instruction::LoadMapFd(_) | Instruction::LoadMapAddress(_) | Instruction::LoadPseudo(_) => {
            2
        }
        Instruction::Bin(bin) if bin.lddw => 2,
        _ => 1,
    }
}

// ============================================================================
// Condition printing helper
// ============================================================================

/// Format a condition. In C++ this was `CommandPrinterVisitor::print(Condition)`.
fn fmt_condition(cond: &Condition, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let width_prefix = if !cond.is64 { "w" } else { "" };
    write!(
        f,
        "{} {}{} {}",
        cond.left, width_prefix, cond.op, cond.right
    )
}

/// Format a memory dereference. In C++ this was `CommandPrinterVisitor::print(Deref)`.
fn fmt_deref(access: &Deref, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let sign = if access.offset < 0 { " - " } else { " + " };
    let offset = access.offset.unsigned_abs();
    write!(
        f,
        "*({} *)({}{sign}{offset})",
        size_str(access.width),
        access.basereg
    )
}

// ============================================================================
// Display for Condition
// ============================================================================

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_condition(self, f)
    }
}

// ============================================================================
// Display for ArgSingleKind, ArgPairKind, ArgSingle, ArgPair
// ============================================================================

impl fmt::Display for ArgSingleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgSingleKind::Anything => write!(f, "uint64_t"),
            ArgSingleKind::PtrToCtx => write!(f, "ctx"),
            ArgSingleKind::PtrToStack => write!(f, "stack"),
            ArgSingleKind::PtrToFunc => write!(f, "func"),
            ArgSingleKind::MapFd => write!(f, "map_fd"),
            ArgSingleKind::MapFdPrograms => write!(f, "map_fd_programs"),
            ArgSingleKind::PtrToMapKey => write!(f, "map_key"),
            ArgSingleKind::PtrToMapValue => write!(f, "map_value"),
        }
    }
}

impl fmt::Display for ArgPairKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgPairKind::PtrToReadableMem => write!(f, "mem"),
            ArgPairKind::PtrToWritableMem => write!(f, "out"),
        }
    }
}

impl fmt::Display for ArgSingle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if self.or_null {
            write!(f, "?")?;
        }
        write!(f, " {}", self.reg)
    }
}

impl fmt::Display for ArgPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if self.or_null {
            write!(f, "?")?;
        }
        write!(f, " {}[{}", self.mem, self.size)?;
        if self.can_be_zero {
            write!(f, "?")?;
        }
        write!(f, "], uint64_t {}", self.size)
    }
}

// ============================================================================
// Display for instruction types
// ============================================================================

impl fmt::Display for Undefined {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Undefined{{{}}}", self.opcode)
    }
}

impl fmt::Display for LoadMapFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = map_fd {}", self.dst, self.mapfd)
    }
}

impl fmt::Display for LoadMapAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} = map_val({}) + {}",
            self.dst, self.mapfd, self.offset
        )
    }
}

impl fmt::Display for Bin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}= {}",
            reg_name(&self.dst, self.is64),
            self.op,
            self.v
        )?;
        if self.lddw {
            write!(f, " ll")?;
        }
        Ok(())
    }
}

impl fmt::Display for Un {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = ", self.dst)?;
        match self.op {
            UnOp::BE16 => write!(f, "be16 ")?,
            UnOp::BE32 => write!(f, "be32 ")?,
            UnOp::BE64 => write!(f, "be64 ")?,
            UnOp::LE16 => write!(f, "le16 ")?,
            UnOp::LE32 => write!(f, "le32 ")?,
            UnOp::LE64 => write!(f, "le64 ")?,
            UnOp::SWAP16 => write!(f, "swap16 ")?,
            UnOp::SWAP32 => write!(f, "swap32 ")?,
            UnOp::SWAP64 => write!(f, "swap64 ")?,
            UnOp::NEG => write!(f, "-")?,
        }
        write!(f, "{}", self.dst)
    }
}

impl fmt::Display for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r0 = {}:{}(", self.name, self.func)?;
        let mut r: u8 = 1;
        while r <= 5 {
            // Look for a singleton.
            if let Some(single) = self.singles.iter().find(|a| a.reg.v == r) {
                if r > 1 {
                    write!(f, ", ")?;
                }
                write!(f, "{single}")?;
                r += 1;
                continue;
            }

            // Look for the start of a pair.
            if let Some(pair) = self.pairs.iter().find(|a| a.mem.v == r) {
                if r > 1 {
                    write!(f, ", ")?;
                }
                write!(f, "{pair}")?;
                r += 2; // pair consumes two registers
                continue;
            }

            // Not found — no more arguments.
            break;
        }
        write!(f, ")")
    }
}

impl fmt::Display for CallLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "call <{}>", self.target)
    }
}

impl fmt::Display for Callx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "callx {}", self.func)
    }
}

impl fmt::Display for CallBtf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "call_btf {}", self.btf_id)
    }
}

impl fmt::Display for LoadPseudo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::ir::syntax::PseudoAddressKind;
        match self.addr.kind {
            PseudoAddressKind::VariableAddr => {
                write!(f, "{} = variable_addr {}", self.dst, self.addr.imm)
            }
            PseudoAddressKind::CodeAddr => write!(f, "{} = code_addr {}", self.dst, self.addr.imm),
            PseudoAddressKind::MapByIdx => {
                write!(f, "{} = map_by_idx({})", self.dst, self.addr.imm)
            }
            PseudoAddressKind::MapValueByIdx => {
                write!(
                    f,
                    "{} = mva(map_by_idx({})) + {}",
                    self.dst, self.addr.imm, self.addr.next_imm
                )
            }
        }
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "exit")
    }
}

impl fmt::Display for Jmp {
    /// Standalone jump (no offset calculation). To print with an offset, use
    /// [`fmt_jmp_with_offset`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(cond) = &self.cond {
            write!(f, "if ")?;
            fmt_condition(cond, f)?;
            write!(f, " ")?;
        }
        write!(f, "goto label <{}>", self.target)
    }
}

/// Format a jump instruction with a relative offset (used in sequential disassembly).
pub fn fmt_jmp_with_offset(jmp: &Jmp, offset: i32, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let sign = if offset > 0 { "+" } else { "" };
    let target = format!("{sign}{offset} <{}>", jmp.target);

    if let Some(cond) = &jmp.cond {
        write!(f, "if ")?;
        fmt_condition(cond, f)?;
        write!(f, " ")?;
    }
    write!(f, "goto {target}")
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = size_str(self.width);
        write!(f, "r0 = *({s} *)skb[")?;
        if let Some(reg) = &self.regoffset {
            write!(f, "{reg}")?;
        }
        if self.offset != 0 {
            if self.regoffset.is_some() {
                write!(f, " + ")?;
            }
            write!(f, "{}", self.offset)?;
        }
        write!(f, "]")
    }
}

impl fmt::Display for Deref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_deref(self, f)
    }
}

impl fmt::Display for Mem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_load {
            write!(f, "{} = ", self.value)?;
            if self.is_signed {
                let sign = if self.access.offset < 0 { " - " } else { " + " };
                let offset = self.access.offset.unsigned_abs();
                write!(
                    f,
                    "*(s{} *)({}{sign}{offset})",
                    self.access.width, self.access.basereg
                )
            } else {
                fmt_deref(&self.access, f)
            }
        } else {
            fmt_deref(&self.access, f)?;
            write!(f, " = {}", self.value)
        }
    }
}

impl fmt::Display for Atomic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "lock ")?;
        fmt_deref(&self.access, f)?;
        write!(f, " ")?;
        let show_fetch = match self.op {
            AtomicOp::ADD | AtomicOp::OR | AtomicOp::AND | AtomicOp::XOR => true,
            AtomicOp::XCHG | AtomicOp::CMPXCHG => false,
        };
        write!(f, "{}= {}", self.op, self.valreg)?;
        if show_fetch && self.fetch {
            write!(f, " fetch")?;
        }
        Ok(())
    }
}

impl fmt::Display for Assume {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "assume ")?;
        fmt_condition(&self.cond, f)
    }
}

impl fmt::Display for IncrementLoopCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // In C++ this uses variable_registry->loop_counter(). We print a simpler
        // representation that doesn't require a registry.
        write!(f, "loop_counter({})++", self.name)
    }
}

// ============================================================================
// Display for Instruction (sum type dispatch)
// ============================================================================

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Undefined(x) => write!(f, "{x}"),
            Instruction::Bin(x) => write!(f, "{x}"),
            Instruction::Un(x) => write!(f, "{x}"),
            Instruction::LoadMapFd(x) => write!(f, "{x}"),
            Instruction::LoadMapAddress(x) => write!(f, "{x}"),
            Instruction::Call(x) => write!(f, "{x}"),
            Instruction::CallLocal(x) => write!(f, "{x}"),
            Instruction::Callx(x) => write!(f, "{x}"),
            Instruction::CallBtf(x) => write!(f, "{x}"),
            Instruction::Exit(x) => write!(f, "{x}"),
            Instruction::Jmp(x) => write!(f, "{x}"),
            Instruction::Mem(x) => write!(f, "{x}"),
            Instruction::Packet(x) => write!(f, "{x}"),
            Instruction::Atomic(x) => write!(f, "{x}"),
            Instruction::Assume(x) => write!(f, "{x}"),
            Instruction::IncrementLoopCounter(x) => write!(f, "{x}"),
            Instruction::LoadPseudo(x) => write!(f, "{x}"),
        }
    }
}

// ============================================================================
// Display for assertion types
// ============================================================================

impl fmt::Display for ValidStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.type != stack -> r{}.type == {}",
            self.mem,
            self.val.v,
            TypeGroup::Number
        )
    }
}

impl fmt::Display for ValidAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.or_null {
            write!(
                f,
                "(r{}.type == {} and {}.value == 0) or ",
                self.reg.v,
                TypeGroup::Number,
                self.reg
            )?;
        }
        write!(f, "valid_access({}.offset", self.reg)?;
        if self.offset > 0 {
            write!(f, "+{}", self.offset)?;
        } else if self.offset < 0 {
            write!(f, "{}", self.offset)?;
        }

        if self.width == Value::Imm(Imm { v: 0 }) {
            write!(f, ") for comparison/subtraction")
        } else {
            write!(f, ", width={}) for ", self.width)?;
            match self.access_type {
                AccessType::Read => write!(f, "read"),
                _ => write!(f, "write"),
            }
        }
    }
}

impl fmt::Display for BoundedLoopCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pc[{}] < {}", self.name, BoundedLoopCount::LIMIT)
    }
}

impl fmt::Display for ValidSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let op = if self.can_be_zero { " >= " } else { " > " };
        write!(f, "{}.value{op}0", self.reg)
    }
}

impl fmt::Display for ValidMapKeyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = if self.key { "key_size" } else { "value_size" };
        write!(
            f,
            "within({}:{field}({}))",
            self.access_reg, self.map_fd_reg
        )
    }
}

impl fmt::Display for ZeroCtxOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}.ctx_offset == 0", self.reg.v)
    }
}

impl fmt::Display for Comparable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.or_r2_is_number {
            write!(f, "r{}.type == {} or ", self.r2.v, TypeGroup::Number)?;
        }
        write!(
            f,
            "r{}.type == r{}.type in {}",
            self.r1.v,
            self.r2.v,
            TypeGroup::SingletonPtr
        )
    }
}

impl fmt::Display for Addable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "r{}.type in {} -> r{}.type == {}",
            self.ptr.v,
            TypeGroup::Pointer,
            self.num.v,
            TypeGroup::Number
        )
    }
}

impl fmt::Display for ValidDivisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} != 0", self.reg)
    }
}

impl fmt::Display for TypeConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cmp_op = if self.types.is_singleton_type() {
            "=="
        } else {
            "in"
        };
        write!(f, "r{}.type {cmp_op} {}", self.reg.v, self.types)
    }
}

impl fmt::Display for FuncConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}.type is helper", self.reg.v)
    }
}

impl fmt::Display for ValidCallbackTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "valid_callback_target({})", self.reg)
    }
}

// ============================================================================
// Display for Assertion (sum type dispatch)
// ============================================================================

impl fmt::Display for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Assertion::Comparable(x) => write!(f, "{x}"),
            Assertion::Addable(x) => write!(f, "{x}"),
            Assertion::ValidDivisor(x) => write!(f, "{x}"),
            Assertion::ValidAccess(x) => write!(f, "{x}"),
            Assertion::ValidStore(x) => write!(f, "{x}"),
            Assertion::ValidSize(x) => write!(f, "{x}"),
            Assertion::ValidMapKeyValue(x) => write!(f, "{x}"),
            Assertion::ValidCallbackTarget(x) => write!(f, "{x}"),
            Assertion::TypeConstraint(x) => write!(f, "{x}"),
            Assertion::FuncConstraint(x) => write!(f, "{x}"),
            Assertion::ZeroCtxOffset(x) => write!(f, "{x}"),
            Assertion::BoundedLoopCount(x) => write!(f, "{x}"),
        }
    }
}

// ============================================================================
// Display for BtfLineInfo and EbpfMapDescriptor
// ============================================================================

impl fmt::Display for BtfLineInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "; {}:{}", self.file_name, self.line_number)?;
        writeln!(f, "; {}", self.source_line)
    }
}

impl fmt::Display for EbpfMapDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(original_fd = {}, inner_map_fd = {}, type = {}, max_entries = {}, value_size = {}, key_size = {})",
            self.original_fd,
            self.inner_map_fd,
            self.map_type,
            self.max_entries,
            self.value_size,
            self.key_size
        )
    }
}

// ============================================================================
// InstructionSeq printing
// ============================================================================

/// Build a map from label to program counter for all instructions in the sequence.
fn get_labels(insts: &InstructionSeq) -> BTreeMap<Label, Pc> {
    let mut pc: Pc = 0;
    let mut pc_of_label = BTreeMap::new();
    for (label, inst, _) in insts {
        pc_of_label.insert(label.clone(), pc);
        pc += instruction_size(inst);
    }
    pc_of_label
}

/// A wrapper around a Jmp that prints with a relative offset.
struct JmpWithOffset<'a> {
    jmp: &'a Jmp,
    offset: i32,
}

impl fmt::Display for JmpWithOffset<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_jmp_with_offset(self.jmp, self.offset, f)
    }
}

/// Print an instruction sequence to a writer.
///
/// If `label_to_print` is `Some`, only instructions with that label are printed.
/// If `print_line_info` is true, BTF source line annotations are included.
pub fn print_instruction_seq(
    insts: &InstructionSeq,
    out: &mut dyn Write,
    label_to_print: Option<&Label>,
    print_line_info: bool,
) -> io::Result<()> {
    let pc_of_label = get_labels(insts);
    let mut pc: Pc = 0;
    let mut previous_source = String::new();

    for (label, ins, line_info) in insts {
        if label_to_print.is_none_or(|l| l == label) {
            if let Some(li) = line_info
                && print_line_info
                && li.source_line != previous_source
            {
                write!(out, "{li}")?;
                previous_source.clone_from(&li.source_line);
            }
            if label.isjump() {
                writeln!(out)?;
                writeln!(out, "{label}:")?;
            }
            if label_to_print.is_some() {
                write!(out, "{pc}: ")?;
            } else {
                write!(out, "{pc:>8}:\t")?;
            }
            if let Instruction::Jmp(jmp) = ins {
                let target_pc = pc_of_label
                    .get(&jmp.target)
                    .copied()
                    .expect("Cannot find label");
                let offset = target_pc as i32 - pc as i32 - 1;
                write!(out, "{}", JmpWithOffset { jmp, offset })?;
            } else {
                write!(out, "{ins}")?;
            }
            writeln!(out)?;
        }
        pc += instruction_size(ins);
    }
    Ok(())
}

/// Print map descriptors to a writer.
pub fn print_map_descriptors(
    descriptors: &[EbpfMapDescriptor],
    out: &mut dyn Write,
) -> io::Result<()> {
    for (i, desc) in descriptors.iter().enumerate() {
        writeln!(out, "map {i}:{desc}")?;
    }
    Ok(())
}

// ============================================================================
// Program-level printing
// ============================================================================

use std::collections::BTreeSet;
use std::fs::File;

use crate::cfg::graph::{Cfg, collect_basic_blocks};
use crate::crab::ebpf_domain::{EbpfDomain, VerificationError};
use crate::ir::program::Program;
use crate::result::AnalysisResult;
use crate::spec::type_descriptors::ProgramInfo;

/// Print a set of labels joined by commas, preceded by a direction tag.
fn print_labels(out: &mut dyn Write, direction: &str, labels: &BTreeSet<Label>) -> io::Result<()> {
    if !labels.is_empty() {
        write!(out, "  {direction} ")?;
        for (i, label) in labels.iter().enumerate() {
            write!(out, "{label}")?;
            if i + 1 < labels.len() {
                write!(out, ",")?;
            } else {
                write!(out, ";")?;
            }
        }
    }
    writeln!(out)
}

/// Print the jump predecessors or successors of a label.
fn print_jump(out: &mut dyn Write, cfg: &Cfg, direction: &str, label: &Label) -> io::Result<()> {
    let labels = if direction == "from" {
        cfg.parents_of(label)
    } else {
        cfg.children_of(label)
    };
    print_labels(out, direction, labels)
}

/// Print line info for a label, deduplicating consecutive identical source lines.
fn print_line_info_for_label(
    out: &mut dyn Write,
    info: &ProgramInfo,
    label: &Label,
    previous_source: &mut String,
) -> io::Result<()> {
    if label.from < 0 {
        return Ok(());
    }
    if let Some(li) = info.line_info.get(&(label.from as usize))
        && li.source_line != *previous_source
    {
        writeln!(out)?;
        writeln!(out, "; {}:{}", li.file_name, li.line_number)?;
        writeln!(out, "; {}", li.source_line)?;
        previous_source.clone_from(&li.source_line);
    }
    Ok(())
}

/// Print instructions and assertions for a label.
fn print_instruction_at_label(
    out: &mut dyn Write,
    prog: &Program,
    label: &Label,
) -> io::Result<()> {
    for pre in prog.assertions_at(label) {
        writeln!(out, "  assert {pre};")?;
    }
    writeln!(out, "  {};", prog.instruction_at(label))
}

/// Print the program as assembly-like output grouped by basic blocks.
pub fn print_program(
    prog: &Program,
    info: &ProgramInfo,
    out: &mut dyn Write,
    simplify: bool,
) -> io::Result<()> {
    let mut previous_source = String::new();
    for bb in &collect_basic_blocks(prog.cfg(), simplify) {
        print_jump(out, prog.cfg(), "from", bb.first_label())?;
        writeln!(out, "{}:", bb.first_label())?;
        for label in bb {
            print_line_info_for_label(out, info, label, &mut previous_source)?;
            print_instruction_at_label(out, prog, label)?;
        }
        print_jump(out, prog.cfg(), "goto", bb.last_label())?;
    }
    writeln!(out)
}

/// Print invariants at each basic block with error reporting.
///
/// Stops at the first verification error encountered.
pub fn print_invariants(
    out: &mut dyn Write,
    prog: &Program,
    info: &ProgramInfo,
    simplify: bool,
    result: &AnalysisResult,
    registry: &VariableRegistry,
) -> io::Result<()> {
    let mut previous_source = String::new();
    for bb in &collect_basic_blocks(prog.cfg(), simplify) {
        let first_inv = match result.invariants.get(bb.first_label()) {
            Some(inv) => inv,
            None => continue,
        };
        if first_inv.pre.is_bottom() {
            continue;
        }
        let mut buf = String::new();
        first_inv.pre.write_to(&mut buf, registry).unwrap();
        writeln!(out, "\nPre-invariant : {buf}")?;
        print_jump(out, prog.cfg(), "from", bb.first_label())?;
        writeln!(out, "{}:", bb.first_label())?;

        let mut last_label = bb.first_label().clone();
        for label in bb {
            print_line_info_for_label(out, info, label, &mut previous_source)?;
            print_instruction_at_label(out, prog, label)?;
            last_label = label.clone();

            if let Some(current) = result.invariants.get(&last_label)
                && let Some(ref error) = current.error
            {
                writeln!(out, "\nVerification error:")?;
                if *label != *bb.last_label() {
                    let mut buf = String::new();
                    current.pre.write_to(&mut buf, registry).unwrap();
                    writeln!(out, "After {buf}")?;
                }
                print_error(out, error)?;
                writeln!(out)?;
                return Ok(());
            }
        }
        if let Some(current) = result.invariants.get(&last_label)
            && !current.post.is_bottom()
        {
            print_jump(out, prog.cfg(), "goto", &last_label)?;
            let mut buf = String::new();
            current.post.write_to(&mut buf, registry).unwrap();
            writeln!(out, "\nPost-invariant : {buf}")?;
        }
    }
    writeln!(out)
}

/// Generate a Graphviz DOT representation of the program's CFG.
pub fn print_dot(prog: &Program, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "digraph program {{")?;
    writeln!(out, "    node [shape = rectangle];")?;
    for label in prog.labels() {
        write!(out, "    \"{label}\"[xlabel=\"{label}\",label=\"")?;
        for pre in prog.assertions_at(label) {
            write!(out, "assert {pre}\\l")?;
        }
        write!(out, "{}\\l", prog.instruction_at(label))?;
        writeln!(out, "\"];")?;
        for next in prog.cfg().children_of(label) {
            writeln!(out, "    \"{label}\" -> \"{next}\";")?;
        }
        writeln!(out)?;
    }
    writeln!(out, "}}")
}

/// Write a DOT representation of the program to a file.
pub fn print_dot_to_file(prog: &Program, outfile: &str) -> io::Result<()> {
    let mut out = File::create(outfile)?;
    print_dot(prog, &mut out)
}

/// Print all unreachable code paths found by the analysis.
pub fn print_unreachable(
    out: &mut dyn Write,
    prog: &Program,
    result: &AnalysisResult,
) -> io::Result<()> {
    for (label, notes) in result.find_unreachable(prog.instructions()) {
        for msg in &notes {
            writeln!(out, "{label}: {msg}")?;
        }
    }
    writeln!(out)
}

/// Print a verification error with optional line info.
pub fn print_error(out: &mut dyn Write, error: &VerificationError) -> io::Result<()> {
    writeln!(out, "{error}")?;
    writeln!(out)
}

// ============================================================================
// Failure slice printing
// ============================================================================

use crate::result::{FailureSlice, RelevantState, extract_assertion_registers};

/// Print invariants filtered to only show labels in the given set.
/// Used to print a failure slice in context.
///
/// When `compact` is true, skip invariant output and only show instructions.
/// When `relevance` is provided, only show assertions involving relevant registers.
#[expect(clippy::too_many_arguments)]
pub fn print_invariants_filtered(
    out: &mut dyn Write,
    prog: &Program,
    info: &ProgramInfo,
    simplify: bool,
    result: &AnalysisResult,
    registry: &VariableRegistry,
    filter: &BTreeSet<Label>,
    compact: bool,
    relevance: Option<&BTreeMap<Label, RelevantState>>,
) -> io::Result<()> {
    let basic_blocks = collect_basic_blocks(prog.cfg(), simplify);

    // Build a mapping from each label in a basic block to the block's first label.
    let mut label_to_block_leader: BTreeMap<Label, Label> = BTreeMap::new();
    for bb in &basic_blocks {
        for label in bb {
            label_to_block_leader.insert(label.clone(), bb.first_label().clone());
        }
    }

    // Helper to look up the post-invariant for a predecessor label.
    let get_parent_post_invariant = |parent: &Label| -> Option<&EbpfDomain> {
        let lookup_label = label_to_block_leader.get(parent).unwrap_or(parent);
        result
            .invariants
            .get(lookup_label)
            .filter(|inv| !inv.post.is_bottom())
            .map(|inv| &inv.post)
    };

    let mut previous_source = String::new();

    for bb in &basic_blocks {
        // Check if any label in this basic block is in the filter
        let bb_has_filtered_label = bb.into_iter().any(|label| filter.contains(label));
        if !bb_has_filtered_label {
            continue;
        }

        // Find the first filtered label in this block
        let first_filtered_label = bb
            .into_iter()
            .find(|label| filter.contains(label))
            .unwrap_or(bb.first_label());

        // If the block's entry is unreachable, skip
        if result
            .invariants
            .get(bb.first_label())
            .is_some_and(|inv| inv.pre.is_bottom())
        {
            continue;
        }

        // Print pre-invariant for first filtered label in block (unless compact)
        if !compact {
            let label_relevance = relevance.and_then(|r| r.get(first_filtered_label));
            let inv = &result.invariants[first_filtered_label];
            let mut buf = String::new();
            inv.pre
                .write_to_filtered(&mut buf, registry, label_relevance)
                .unwrap();
            writeln!(out, "\nPre-invariant : {buf}")?;
        }

        // Print jump and block header
        print_jump(out, prog.cfg(), "from", bb.first_label())?;
        writeln!(out, "{}:", bb.first_label())?;

        // Show per-predecessor invariants at join points
        if !compact && let Some(relevance) = relevance {
            let parents = prog.cfg().parents_of(bb.first_label());
            let in_slice_parents: Vec<&Label> =
                parents.iter().filter(|p| filter.contains(p)).collect();
            if in_slice_parents.len() >= 2 {
                // Build union of relevant state
                let mut join_relevance = RelevantState::default();
                if let Some(fl) = relevance.get(first_filtered_label) {
                    join_relevance.registers.extend(&fl.registers);
                    join_relevance.stack_offsets.extend(&fl.stack_offsets);
                }
                for parent in &in_slice_parents {
                    if let Some(pr) = relevance.get(*parent) {
                        join_relevance.registers.extend(&pr.registers);
                        join_relevance.stack_offsets.extend(&pr.stack_offsets);
                    }
                }

                writeln!(out, "  --- join point: per-predecessor state ---")?;
                for parent in &in_slice_parents {
                    if let Some(post) = get_parent_post_invariant(parent) {
                        let mut buf = String::new();
                        post.write_to_filtered(&mut buf, registry, Some(&join_relevance))
                            .unwrap();
                        writeln!(out, "  from {parent}: {buf}")?;
                    }
                }
                writeln!(out, "  --- end join point ---")?;
            }
        }

        if first_filtered_label != bb.first_label() {
            writeln!(out, "  ... skipped ...")?;
        }

        let mut last_label = bb.first_label().clone();
        let mut prev_filtered_label = bb.first_label().clone();
        let mut has_prev_filtered = false;

        for label in bb {
            if !filter.contains(label) {
                continue;
            }

            // Handle gap since previous filtered label
            if has_prev_filtered && prev_filtered_label != *label {
                // Print post-invariant for previous filtered label
                if !compact {
                    let prev_current = &result.invariants[&prev_filtered_label];
                    if !prev_current.post.is_bottom() {
                        let prev_label_relevance =
                            relevance.and_then(|r| r.get(&prev_filtered_label));
                        let mut buf = String::new();
                        prev_current
                            .post
                            .write_to_filtered(&mut buf, registry, prev_label_relevance)
                            .unwrap();
                        print_jump(out, prog.cfg(), "goto", &prev_filtered_label)?;
                        writeln!(out, "\nPost-invariant : {buf}")?;
                    }
                }
                // Check for gap between prev and current
                let has_gap = bb
                    .into_iter()
                    .any(|mid| mid > &prev_filtered_label && mid < label);
                if has_gap {
                    writeln!(out, "  ... skipped ...")?;
                }
                // Print pre-invariant for this label
                if !compact {
                    let label_rel = relevance.and_then(|r| r.get(label));
                    let mut buf = String::new();
                    result.invariants[label]
                        .pre
                        .write_to_filtered(&mut buf, registry, label_rel)
                        .unwrap();
                    writeln!(out, "\nPre-invariant : {buf}")?;
                    print_jump(out, prog.cfg(), "from", label)?;
                }
            }

            print_line_info_for_label(out, info, label, &mut previous_source)?;

            // Print assertions, filtered by relevance
            let label_relevance = relevance.and_then(|r| r.get(label));
            for assertion in prog.assertions_at(label) {
                if let Some(lr) = label_relevance {
                    let assertion_regs = extract_assertion_registers(assertion);
                    if !assertion_regs.is_empty()
                        && !assertion_regs.iter().any(|reg| lr.registers.contains(reg))
                    {
                        continue;
                    }
                }
                writeln!(out, "  assert {assertion};")?;
            }
            writeln!(out, "  {};", prog.instruction_at(label))?;

            last_label = label.clone();
            prev_filtered_label = label.clone();
            has_prev_filtered = true;

            if let Some(current) = result.invariants.get(&last_label)
                && let Some(ref error) = current.error
            {
                writeln!(out, "\nVerification error:")?;
                print_error(out, error)?;
                writeln!(out)?;
            }
        }

        // Print post-invariant (unless compact)
        if !compact
            && let Some(current) = result.invariants.get(&last_label)
            && !current.post.is_bottom()
        {
            let label_relevance = relevance.and_then(|r| r.get(&last_label));
            let mut buf = String::new();
            current
                .post
                .write_to_filtered(&mut buf, registry, label_relevance)
                .unwrap();
            print_jump(out, prog.cfg(), "goto", &last_label)?;
            writeln!(out, "\nPost-invariant : {buf}")?;
        }
    }
    writeln!(out)
}

/// Print all failure slices in a structured diagnostic format.
#[expect(clippy::too_many_arguments)]
pub fn print_failure_slices(
    out: &mut dyn Write,
    prog: &Program,
    info: &ProgramInfo,
    simplify: bool,
    result: &AnalysisResult,
    registry: &VariableRegistry,
    slices: &[FailureSlice],
    compact: bool,
) -> io::Result<()> {
    if slices.is_empty() {
        writeln!(out, "No verification failures found.")?;
        return Ok(());
    }

    for (i, slice) in slices.iter().enumerate() {
        writeln!(out, "=== Failure Slice {} of {} ===\n", i + 1, slices.len())?;

        // Error summary
        writeln!(out, "[ERROR] {}", slice.error)?;
        writeln!(out, "[LOCATION] {}", slice.failing_label)?;

        // Relevant registers at failure point
        if let Some(failing_rel) = slice.relevance.get(&slice.failing_label) {
            write!(out, "[RELEVANT REGISTERS] ")?;
            let mut first = true;
            for reg in &failing_rel.registers {
                if !first {
                    write!(out, ", ")?;
                }
                write!(out, "r{}", reg.v)?;
                first = false;
            }
            for offset in &failing_rel.stack_offsets {
                if !first {
                    write!(out, ", ")?;
                }
                write!(out, "stack[{offset}]")?;
                first = false;
            }
            writeln!(out)?;
        }

        writeln!(
            out,
            "[SLICE SIZE] {} program points\n",
            slice.relevance.len()
        )?;

        // Control flow summary
        {
            write!(out, "[CONTROL FLOW] ")?;
            let labels = slice.impacted_labels();

            // Build join-point map
            let mut join_predecessors: BTreeMap<Label, Vec<Label>> = BTreeMap::new();
            for lbl in &labels {
                let parents = prog.cfg().parents_of(lbl);
                let in_slice_parents: Vec<Label> = parents
                    .iter()
                    .filter(|p| labels.contains(p))
                    .cloned()
                    .collect();
                if in_slice_parents.len() >= 2 {
                    join_predecessors.insert(lbl.clone(), in_slice_parents);
                }
            }

            // Labels consumed by a convergence group
            let mut convergence_members: BTreeSet<Label> = BTreeSet::new();
            for preds in join_predecessors.values() {
                for p in preds {
                    if !join_predecessors.contains_key(p) {
                        convergence_members.insert(p.clone());
                    }
                }
            }

            let annotate_label = |out: &mut dyn Write, lbl: &Label| -> io::Result<()> {
                write!(out, "{lbl}")?;
                let ins = prog.instruction_at(lbl);
                match ins {
                    Instruction::Assume(assume) => {
                        write!(
                            out,
                            " (assume {} {} {})",
                            assume.cond.left, assume.cond.op, assume.cond.right
                        )?;
                    }
                    Instruction::Jmp(jmp) => {
                        if let Some(cond) = &jmp.cond {
                            write!(out, " (if {} {} {})", cond.left, cond.op, cond.right)?;
                        }
                    }
                    _ => {}
                }
                Ok(())
            };

            let mut first_cf = true;
            for lbl in &labels {
                if convergence_members.contains(lbl) {
                    continue;
                }
                if !first_cf {
                    write!(out, ", ")?;
                }
                first_cf = false;

                if let Some(preds) = join_predecessors.get(lbl) {
                    write!(out, "{{")?;
                    for (j, pred) in preds.iter().enumerate() {
                        if j > 0 {
                            write!(out, " | ")?;
                        }
                        annotate_label(out, pred)?;
                    }
                    write!(out, "}} -> ")?;
                }

                annotate_label(out, lbl)?;
            }
            if labels.contains(&slice.failing_label) {
                write!(out, " FAIL")?;
            }
            writeln!(out, "\n")?;
        }

        // Causal trace
        writeln!(out, "[CAUSAL TRACE]")?;
        print_invariants_filtered(
            out,
            prog,
            info,
            simplify,
            result,
            registry,
            &slice.impacted_labels(),
            compact,
            Some(&slice.relevance),
        )?;

        if i + 1 < slices.len() {
            writeln!(out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn test_display_reg() {
        assert_eq!(format!("{}", Reg { v: 0 }), "r0");
        assert_eq!(format!("{}", Reg { v: 10 }), "r10");
    }

    #[test]
    fn test_display_imm_positive() {
        assert_eq!(format!("{}", Imm { v: 42 }), "42");
    }

    #[test]
    fn test_display_imm_negative() {
        // u64 representation of -1i64
        assert_eq!(format!("{}", Imm { v: u64::MAX }), "-1");
    }

    #[test]
    fn test_display_value() {
        assert_eq!(format!("{}", Value::Imm(Imm { v: 10 })), "10");
        assert_eq!(format!("{}", Value::Reg(Reg { v: 3 })), "r3");
    }

    #[test]
    fn test_display_binop() {
        assert_eq!(format!("{}", BinOp::ADD), "+");
        assert_eq!(format!("{}", BinOp::SUB), "-");
        assert_eq!(format!("{}", BinOp::MOV), "");
        assert_eq!(format!("{}", BinOp::ARSH), ">>>");
        assert_eq!(format!("{}", BinOp::SDIV), "s/");
    }

    #[test]
    fn test_display_conditionop() {
        assert_eq!(format!("{}", ConditionOp::EQ), "==");
        assert_eq!(format!("{}", ConditionOp::NE), "!=");
        assert_eq!(format!("{}", ConditionOp::SLT), "s<");
        assert_eq!(format!("{}", ConditionOp::SET), "&==");
    }

    #[test]
    fn test_display_condition() {
        let cond = Condition {
            op: ConditionOp::EQ,
            left: Reg { v: 1 },
            right: Value::Imm(Imm { v: 0 }),
            is64: true,
        };
        assert_eq!(format!("{cond}"), "r1 == 0");
    }

    #[test]
    fn test_display_condition_32bit() {
        let cond = Condition {
            op: ConditionOp::LT,
            left: Reg { v: 2 },
            right: Value::Reg(Reg { v: 3 }),
            is64: false,
        };
        assert_eq!(format!("{cond}"), "r2 w< r3");
    }

    #[test]
    fn test_display_bin() {
        let bin = Bin {
            op: BinOp::ADD,
            dst: Reg { v: 1 },
            v: Value::Imm(Imm { v: 5 }),
            is64: true,
            lddw: false,
        };
        assert_eq!(format!("{bin}"), "r1 += 5");
    }

    #[test]
    fn test_display_bin_32bit() {
        let bin = Bin {
            op: BinOp::SUB,
            dst: Reg { v: 2 },
            v: Value::Reg(Reg { v: 3 }),
            is64: false,
            lddw: false,
        };
        assert_eq!(format!("{bin}"), "w2 -= r3");
    }

    #[test]
    fn test_display_bin_mov() {
        let bin = Bin {
            op: BinOp::MOV,
            dst: Reg { v: 0 },
            v: Value::Imm(Imm { v: 1 }),
            is64: true,
            lddw: false,
        };
        assert_eq!(format!("{bin}"), "r0 = 1");
    }

    #[test]
    fn test_display_bin_lddw() {
        let bin = Bin {
            op: BinOp::MOV,
            dst: Reg { v: 1 },
            v: Value::Imm(Imm { v: 0x1234 }),
            is64: true,
            lddw: true,
        };
        assert_eq!(format!("{bin}"), "r1 = 4660 ll");
    }

    #[test]
    fn test_display_un_neg() {
        let un = Un {
            op: UnOp::NEG,
            dst: Reg { v: 1 },
            is64: true,
        };
        assert_eq!(format!("{un}"), "r1 = -r1");
    }

    #[test]
    fn test_display_un_be16() {
        let un = Un {
            op: UnOp::BE16,
            dst: Reg { v: 2 },
            is64: true,
        };
        assert_eq!(format!("{un}"), "r2 = be16 r2");
    }

    #[test]
    fn test_display_exit() {
        let exit = Exit {
            stack_frame_prefix: Rc::from(""),
        };
        assert_eq!(format!("{exit}"), "exit");
    }

    #[test]
    fn test_display_jmp_unconditional() {
        let jmp = Jmp {
            cond: None,
            target: Label::new(10),
        };
        assert_eq!(format!("{jmp}"), "goto label <10>");
    }

    #[test]
    fn test_display_jmp_conditional() {
        let jmp = Jmp {
            cond: Some(Condition {
                op: ConditionOp::EQ,
                left: Reg { v: 1 },
                right: Value::Imm(Imm { v: 0 }),
                is64: true,
            }),
            target: Label::new(10),
        };
        assert_eq!(format!("{jmp}"), "if r1 == 0 goto label <10>");
    }

    #[test]
    fn test_display_mem_load() {
        let mem = Mem {
            access: Deref {
                width: AccessSize::Word,
                basereg: Reg { v: 10 },
                offset: -4,
            },
            value: Value::Reg(Reg { v: 1 }),
            is_load: true,
            is_signed: false,
        };
        assert_eq!(format!("{mem}"), "r1 = *(u32 *)(r10 - 4)");
    }

    #[test]
    fn test_display_mem_store() {
        let mem = Mem {
            access: Deref {
                width: AccessSize::DWord,
                basereg: Reg { v: 10 },
                offset: -8,
            },
            value: Value::Imm(Imm { v: 0 }),
            is_load: false,
            is_signed: false,
        };
        assert_eq!(format!("{mem}"), "*(u64 *)(r10 - 8) = 0");
    }

    #[test]
    fn test_display_atomic_add() {
        let atomic = Atomic {
            op: AtomicOp::ADD,
            fetch: false,
            access: Deref {
                width: AccessSize::DWord,
                basereg: Reg { v: 10 },
                offset: -8,
            },
            valreg: Reg { v: 1 },
        };
        assert_eq!(format!("{atomic}"), "lock *(u64 *)(r10 - 8) += r1");
    }

    #[test]
    fn test_display_atomic_add_fetch() {
        let atomic = Atomic {
            op: AtomicOp::ADD,
            fetch: true,
            access: Deref {
                width: AccessSize::DWord,
                basereg: Reg { v: 10 },
                offset: -8,
            },
            valreg: Reg { v: 1 },
        };
        assert_eq!(format!("{atomic}"), "lock *(u64 *)(r10 - 8) += r1 fetch");
    }

    #[test]
    fn test_display_atomic_xchg() {
        let atomic = Atomic {
            op: AtomicOp::XCHG,
            fetch: true, // fetch is always true for XCHG but not printed
            access: Deref {
                width: AccessSize::DWord,
                basereg: Reg { v: 10 },
                offset: 0,
            },
            valreg: Reg { v: 1 },
        };
        assert_eq!(format!("{atomic}"), "lock *(u64 *)(r10 + 0) x= r1");
    }

    #[test]
    fn test_display_assume() {
        let assume = Assume {
            cond: Condition {
                op: ConditionOp::GE,
                left: Reg { v: 1 },
                right: Value::Imm(Imm { v: 0 }),
                is64: true,
            },
            is_implicit: false,
        };
        assert_eq!(format!("{assume}"), "assume r1 >= 0");
    }

    #[test]
    fn test_display_packet() {
        let pkt = Packet {
            width: AccessSize::Word,
            offset: 14,
            regoffset: None,
        };
        assert_eq!(format!("{pkt}"), "r0 = *(u32 *)skb[14]");
    }

    #[test]
    fn test_display_packet_with_reg() {
        let pkt = Packet {
            width: AccessSize::Half,
            offset: 0,
            regoffset: Some(Reg { v: 1 }),
        };
        assert_eq!(format!("{pkt}"), "r0 = *(u16 *)skb[r1]");
    }

    #[test]
    fn test_display_packet_with_reg_and_offset() {
        let pkt = Packet {
            width: AccessSize::Byte,
            offset: 14,
            regoffset: Some(Reg { v: 1 }),
        };
        assert_eq!(format!("{pkt}"), "r0 = *(u8 *)skb[r1 + 14]");
    }

    #[test]
    fn test_display_load_map_fd() {
        let lmf = LoadMapFd {
            dst: Reg { v: 1 },
            mapfd: 3,
        };
        assert_eq!(format!("{lmf}"), "r1 = map_fd 3");
    }

    #[test]
    fn test_display_load_map_address() {
        let lma = LoadMapAddress {
            dst: Reg { v: 1 },
            mapfd: 3,
            offset: 16,
        };
        assert_eq!(format!("{lma}"), "r1 = map_val(3) + 16");
    }

    #[test]
    fn test_display_undefined() {
        let undef = Undefined { opcode: 0xff };
        assert_eq!(format!("{undef}"), "Undefined{255}");
    }

    #[test]
    fn test_display_callx() {
        let callx = Callx { func: Reg { v: 3 } };
        assert_eq!(format!("{callx}"), "callx r3");
    }

    #[test]
    fn test_display_call_local() {
        let cl = CallLocal {
            target: Label::new(42),
            stack_frame_prefix: Rc::from(""),
        };
        assert_eq!(format!("{cl}"), "call <42>");
    }

    #[test]
    fn test_display_increment_loop_counter() {
        let ilc = IncrementLoopCounter {
            name: Label::new_with_to(3, 7),
        };
        assert_eq!(format!("{ilc}"), "loop_counter(3:7)++");
    }

    #[test]
    fn test_display_instruction_dispatch() {
        let ins = Instruction::Exit(Exit {
            stack_frame_prefix: Rc::from(""),
        });
        assert_eq!(format!("{ins}"), "exit");
    }

    // -- Assertion Display tests --

    #[test]
    fn test_display_valid_divisor() {
        let vd = ValidDivisor {
            reg: Reg { v: 3 },
            is_signed: false,
        };
        assert_eq!(format!("{vd}"), "r3 != 0");
    }

    #[test]
    fn test_display_valid_size() {
        let vs = ValidSize {
            reg: Reg { v: 2 },
            can_be_zero: false,
        };
        assert_eq!(format!("{vs}"), "r2.value > 0");

        let vs2 = ValidSize {
            reg: Reg { v: 2 },
            can_be_zero: true,
        };
        assert_eq!(format!("{vs2}"), "r2.value >= 0");
    }

    #[test]
    fn test_display_type_constraint_singleton() {
        let tc = TypeConstraint {
            reg: Reg { v: 1 },
            types: TypeGroup::Number,
        };
        assert_eq!(format!("{tc}"), "r1.type == number");
    }

    #[test]
    fn test_display_type_constraint_group() {
        let tc = TypeConstraint {
            reg: Reg { v: 1 },
            types: TypeGroup::Pointer,
        };
        assert_eq!(format!("{tc}"), "r1.type in {ctx, stack, packet, shared}");
    }

    #[test]
    fn test_display_func_constraint() {
        let fc = FuncConstraint { reg: Reg { v: 1 } };
        assert_eq!(format!("{fc}"), "r1.type is helper");
    }

    #[test]
    fn test_display_valid_callback_target() {
        let vct = ValidCallbackTarget { reg: Reg { v: 2 } };
        assert_eq!(format!("{vct}"), "valid_callback_target(r2)");
    }

    #[test]
    fn test_display_zero_ctx_offset() {
        let zco = ZeroCtxOffset {
            reg: Reg { v: 1 },
            or_null: false,
        };
        assert_eq!(format!("{zco}"), "r1.ctx_offset == 0");
    }

    #[test]
    fn test_display_bounded_loop_count() {
        let blc = BoundedLoopCount {
            name: Label::new_with_to(3, 7),
        };
        assert_eq!(format!("{blc}"), "pc[3:7] < 100000");
    }

    #[test]
    fn test_display_valid_map_key_value() {
        let vmkv = ValidMapKeyValue {
            access_reg: Reg { v: 1 },
            map_fd_reg: Reg { v: 2 },
            key: true,
        };
        assert_eq!(format!("{vmkv}"), "within(r1:key_size(r2))");

        let vmkv2 = ValidMapKeyValue {
            access_reg: Reg { v: 1 },
            map_fd_reg: Reg { v: 2 },
            key: false,
        };
        assert_eq!(format!("{vmkv2}"), "within(r1:value_size(r2))");
    }

    #[test]
    fn test_display_valid_access_basic() {
        let va = ValidAccess {
            call_stack_depth: 1,
            reg: Reg { v: 1 },
            offset: 0,
            width: Value::Imm(Imm { v: 4 }),
            or_null: false,
            access_type: AccessType::Read,
        };
        assert_eq!(format!("{va}"), "valid_access(r1.offset, width=4) for read");
    }

    #[test]
    fn test_display_valid_access_with_positive_offset() {
        let va = ValidAccess {
            call_stack_depth: 1,
            reg: Reg { v: 1 },
            offset: 8,
            width: Value::Imm(Imm { v: 4 }),
            or_null: false,
            access_type: AccessType::Write,
        };
        assert_eq!(
            format!("{va}"),
            "valid_access(r1.offset+8, width=4) for write"
        );
    }

    #[test]
    fn test_display_valid_access_comparison() {
        let va = ValidAccess {
            call_stack_depth: 1,
            reg: Reg { v: 1 },
            offset: 0,
            width: Value::Imm(Imm { v: 0 }),
            or_null: false,
            access_type: AccessType::Read,
        };
        assert_eq!(
            format!("{va}"),
            "valid_access(r1.offset) for comparison/subtraction"
        );
    }

    #[test]
    fn test_display_comparable() {
        let c = Comparable {
            r1: Reg { v: 1 },
            r2: Reg { v: 2 },
            or_r2_is_number: false,
        };
        assert_eq!(format!("{c}"), "r1.type == r2.type in {ctx, stack, packet}");
    }

    #[test]
    fn test_display_comparable_or_number() {
        let c = Comparable {
            r1: Reg { v: 1 },
            r2: Reg { v: 2 },
            or_r2_is_number: true,
        };
        assert_eq!(
            format!("{c}"),
            "r2.type == number or r1.type == r2.type in {ctx, stack, packet}"
        );
    }

    #[test]
    fn test_display_addable() {
        let a = Addable {
            ptr: Reg { v: 1 },
            num: Reg { v: 2 },
        };
        assert_eq!(
            format!("{a}"),
            "r1.type in {ctx, stack, packet, shared} -> r2.type == number"
        );
    }

    #[test]
    fn test_display_valid_store() {
        let vs = ValidStore {
            mem: Reg { v: 10 },
            val: Reg { v: 1 },
        };
        assert_eq!(format!("{vs}"), "r10.type != stack -> r1.type == number");
    }

    #[test]
    fn test_display_assertion_dispatch() {
        let a = Assertion::ValidDivisor(ValidDivisor {
            reg: Reg { v: 3 },
            is_signed: false,
        });
        assert_eq!(format!("{a}"), "r3 != 0");
    }

    #[test]
    fn test_display_btf_line_info() {
        let li = BtfLineInfo {
            file_name: "test.c".to_string(),
            source_line: "int x = 0;".to_string(),
            line_number: 42,
            column_number: 1,
        };
        assert_eq!(format!("{li}"), "; test.c:42\n; int x = 0;\n");
    }

    #[test]
    fn test_display_map_descriptor() {
        let desc = EbpfMapDescriptor {
            original_fd: 3,
            map_type: 1,
            key_size: 4,
            value_size: 8,
            max_entries: 1024,
            inner_map_fd: -1,
        };
        assert_eq!(
            format!("{desc}"),
            "(original_fd = 3, inner_map_fd = -1, type = 1, max_entries = 1024, value_size = 8, key_size = 4)"
        );
    }

    #[test]
    fn test_instruction_size_normal() {
        let ins = Instruction::Exit(Exit {
            stack_frame_prefix: Rc::from(""),
        });
        assert_eq!(instruction_size(&ins), 1);
    }

    #[test]
    fn test_instruction_size_lddw() {
        let ins = Instruction::LoadMapFd(LoadMapFd {
            dst: Reg { v: 1 },
            mapfd: 0,
        });
        assert_eq!(instruction_size(&ins), 2);

        let ins2 = Instruction::LoadMapAddress(LoadMapAddress {
            dst: Reg { v: 1 },
            mapfd: 0,
            offset: 0,
        });
        assert_eq!(instruction_size(&ins2), 2);

        let ins3 = Instruction::Bin(Bin {
            op: BinOp::MOV,
            dst: Reg { v: 1 },
            v: Value::Imm(Imm { v: 0 }),
            is64: true,
            lddw: true,
        });
        assert_eq!(instruction_size(&ins3), 2);
    }

    #[test]
    fn test_display_call() {
        let call = Call {
            func: 1,
            kind: crate::ir::syntax::CallKind::Helper,
            name: Rc::from("bpf_map_lookup_elem"),
            is_supported: true,
            unsupported_reason: Rc::from(""),
            is_map_lookup: true,
            reallocate_packet: false,
            singles: vec![ArgSingle {
                kind: ArgSingleKind::MapFd,
                or_null: false,
                reg: Reg { v: 1 },
            }],
            pairs: vec![ArgPair {
                kind: ArgPairKind::PtrToReadableMem,
                or_null: false,
                mem: Reg { v: 2 },
                size: Reg { v: 3 },
                can_be_zero: false,
            }],
            stack_frame_prefix: Rc::from(""),
        };
        assert_eq!(
            format!("{call}"),
            "r0 = bpf_map_lookup_elem:1(map_fd r1, mem r2[r3], uint64_t r3)"
        );
    }

    #[test]
    fn test_reg_name() {
        assert_eq!(reg_name(&Reg { v: 1 }, true), "r1");
        assert_eq!(reg_name(&Reg { v: 1 }, false), "w1");
    }

    #[test]
    fn test_size_str() {
        assert_eq!(size_str(AccessSize::Byte), "u8");
        assert_eq!(size_str(AccessSize::Half), "u16");
        assert_eq!(size_str(AccessSize::Word), "u32");
        assert_eq!(size_str(AccessSize::DWord), "u64");
    }

    #[test]
    fn test_display_arg_single_kinds() {
        assert_eq!(format!("{}", ArgSingleKind::Anything), "uint64_t");
        assert_eq!(format!("{}", ArgSingleKind::PtrToCtx), "ctx");
        assert_eq!(format!("{}", ArgSingleKind::PtrToStack), "stack");
        assert_eq!(format!("{}", ArgSingleKind::PtrToFunc), "func");
        assert_eq!(format!("{}", ArgSingleKind::MapFd), "map_fd");
        assert_eq!(
            format!("{}", ArgSingleKind::MapFdPrograms),
            "map_fd_programs"
        );
        assert_eq!(format!("{}", ArgSingleKind::PtrToMapKey), "map_key");
        assert_eq!(format!("{}", ArgSingleKind::PtrToMapValue), "map_value");
    }

    #[test]
    fn test_display_arg_pair_kinds() {
        assert_eq!(format!("{}", ArgPairKind::PtrToReadableMem), "mem");
        assert_eq!(format!("{}", ArgPairKind::PtrToWritableMem), "out");
    }

    #[test]
    fn test_display_arg_single_or_null() {
        let arg = ArgSingle {
            kind: ArgSingleKind::PtrToCtx,
            or_null: true,
            reg: Reg { v: 1 },
        };
        assert_eq!(format!("{arg}"), "ctx? r1");
    }

    #[test]
    fn test_display_arg_pair() {
        let arg = ArgPair {
            kind: ArgPairKind::PtrToWritableMem,
            or_null: false,
            mem: Reg { v: 1 },
            size: Reg { v: 2 },
            can_be_zero: true,
        };
        assert_eq!(format!("{arg}"), "out r1[r2?], uint64_t r2");
    }

    #[test]
    fn test_print_instruction_seq() {
        let insts: InstructionSeq = vec![
            (
                Label::new(0),
                Instruction::Bin(Bin {
                    op: BinOp::MOV,
                    dst: Reg { v: 0 },
                    v: Value::Imm(Imm { v: 0 }),
                    is64: true,
                    lddw: false,
                }),
                None,
            ),
            (
                Label::new(1),
                Instruction::Exit(Exit {
                    stack_frame_prefix: Rc::from(""),
                }),
                None,
            ),
        ];
        let mut buf = Vec::new();
        print_instruction_seq(&insts, &mut buf, None, false).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("r0 = 0"));
        assert!(output.contains("exit"));
    }

    #[test]
    fn test_valid_access_or_null() {
        let va = ValidAccess {
            call_stack_depth: 1,
            reg: Reg { v: 1 },
            offset: 0,
            width: Value::Imm(Imm { v: 4 }),
            or_null: true,
            access_type: AccessType::Read,
        };
        assert_eq!(
            format!("{va}"),
            "(r1.type == number and r1.value == 0) or valid_access(r1.offset, width=4) for read"
        );
    }
}
