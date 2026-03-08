// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! IR syntax types, mirroring `src/ir/syntax.hpp`.
//! These are Rust-native enums with discriminant values matching the C++ enum class order.

/// Binary ALU operations.
/// Discriminant values match C++ `Bin::Op` enum class order.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    MOV = 0,
    ADD = 1,
    SUB = 2,
    MUL = 3,
    UDIV = 4,
    UMOD = 5,
    OR = 6,
    AND = 7,
    LSH = 8,
    RSH = 9,
    ARSH = 10,
    XOR = 11,
    SDIV = 12,
    SMOD = 13,
    MOVSX8 = 14,
    MOVSX16 = 15,
    MOVSX32 = 16,
}

/// Unary operations.
/// Discriminant values match C++ `Un::Op` enum class order.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnOp {
    BE16 = 0,
    BE32 = 1,
    BE64 = 2,
    LE16 = 3,
    LE32 = 4,
    LE64 = 5,
    SWAP16 = 6,
    SWAP32 = 7,
    SWAP64 = 8,
    NEG = 9,
}

/// Comparison condition operators.
/// Discriminant values match C++ `Condition::Op` enum class order.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionOp {
    EQ = 0,
    NE = 1,
    SET = 2,
    NSET = 3, // Does not exist in eBPF
    LT = 4,
    LE = 5,
    GT = 6,
    GE = 7,
    SLT = 8,
    SLE = 9,
    SGT = 10,
    SGE = 11,
}

/// Atomic memory operations.
/// Values match C++ `Atomic::Op` enum.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtomicOp {
    ADD = 0x00,
    OR = 0x40,
    AND = 0x50,
    XOR = 0xa0,
    XCHG = 0xe0,    // Only valid with fetch=true.
    CMPXCHG = 0xf0, // Only valid with fetch=true.
}

// ============================================================================
// Full instruction types (ported from ir/syntax.hpp)
// ============================================================================

use std::rc::Rc;

use crate::cfg::label::Label;
use crate::crab::type_encoding::{TypeEncoding, TypeGroup};
use crate::spec::vm_isa::AccessSize;

/// Immediate argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Imm {
    pub v: u64,
}

/// Register argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reg {
    pub v: u8,
}

/// Either an immediate or a register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Imm(Imm),
    Reg(Reg),
}

/// Binary operation instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bin {
    pub op: BinOp,
    pub dst: Reg,
    pub v: Value,
    pub is64: bool,
    pub lddw: bool,
}

/// Unary operation instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Un {
    pub op: UnOp,
    pub dst: Reg,
    pub is64: bool,
}

/// Load a map file descriptor into a register (encoded like LDDW).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadMapFd {
    pub dst: Reg,
    pub mapfd: i32,
}

/// Load the address of a map value into a register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadMapAddress {
    pub dst: Reg,
    pub mapfd: i32,
    pub offset: i32,
}

/// Addressing payload for LDDW pseudo forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PseudoAddress {
    pub kind: PseudoAddressKind,
    pub imm: i32,
    pub next_imm: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PseudoAddressKind {
    VariableAddr,  // src=3
    CodeAddr,      // src=4
    MapByIdx,      // src=5
    MapValueByIdx, // src=6
}

/// Load one of the currently-unsupported LDDW pseudo forms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadPseudo {
    pub dst: Reg,
    pub addr: PseudoAddress,
}

/// A condition comparing a register with a value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    pub op: ConditionOp,
    pub left: Reg,
    pub right: Value,
    pub is64: bool,
}

/// Conditional or unconditional jump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jmp {
    pub cond: Option<Condition>,
    pub target: Label,
}

/// Single argument to a helper call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgSingle {
    pub kind: ArgSingleKind,
    pub or_null: bool,
    pub reg: Reg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgSingleKind {
    MapFd,
    MapFdPrograms,
    PtrToMapKey,
    PtrToMapValue,
    PtrToCtx,
    PtrToStack,
    PtrToFunc,
    Anything,
    PtrToSocket,
    PtrToBtfId,
    PtrToAllocMem,
    PtrToSpinLock,
    PtrToTimer,
    ConstSizeOrZero,
    PtrToWritableLong,
    PtrToWritableInt,
}

/// Pair of arguments (pointer + size) to a helper call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgPair {
    pub kind: ArgPairKind,
    pub or_null: bool,
    pub mem: Reg,
    pub size: Reg,
    pub can_be_zero: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgPairKind {
    PtrToReadableMem,
    PtrToWritableMem,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    Helper,
    Kfunc,
}

/// Helper function call.
#[derive(Clone, Debug)]
pub struct Call {
    pub func: i32,
    pub kind: CallKind,
    pub name: Rc<str>,
    pub is_supported: bool,
    pub unsupported_reason: Rc<str>,
    pub is_map_lookup: bool,
    pub reallocate_packet: bool,
    pub return_ptr_type: Option<TypeEncoding>,
    pub return_nullable: bool,
    pub singles: Vec<ArgSingle>,
    pub pairs: Vec<ArgPair>,
    pub stack_frame_prefix: Rc<str>,
    /// Register holding allocation size (for T_ALLOC_MEM returns).
    pub alloc_size_reg: Option<Reg>,
}

impl PartialEq for Call {
    fn eq(&self, other: &Self) -> bool {
        self.func == other.func && self.kind == other.kind
    }
}

impl Eq for Call {}

/// Call a local function (macro) within the same program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallLocal {
    pub target: Label,
    pub stack_frame_prefix: Rc<str>,
}

/// Exit from a function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    pub stack_frame_prefix: Rc<str>,
}

/// Experimental callx instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Callx {
    pub func: Reg,
}

/// Call helper by BTF id (CALL src=2).
/// The module field (i16, matching BPF instruction offset width) identifies
/// which kernel module provides the kfunc; 0 means vmlinux (the default).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallBtf {
    pub btf_id: i32,
    pub module: i16,
}

/// Memory dereference descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deref {
    pub width: AccessSize,
    pub basereg: Reg,
    pub offset: i32,
}

/// Load/store instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mem {
    pub access: Deref,
    pub value: Value,
    pub is_load: bool,
    pub is_signed: bool,
}

/// Deprecated checked packet access instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub width: AccessSize,
    pub offset: i32,
    pub regoffset: Option<Reg>,
}

/// Atomic memory operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Atomic {
    pub op: AtomicOp,
    pub fetch: bool,
    pub access: Deref,
    pub valreg: Reg,
}

/// Placeholder for undefined/invalid instructions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Undefined {
    pub opcode: i32,
}

/// Assumption instruction (replaces conditional jumps in nondeterministic CFG form).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assume {
    pub cond: Condition,
    pub is_implicit: bool,
}

/// Increment loop counter for bounded loop verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncrementLoopCounter {
    pub name: Label,
}

/// Sum type of all eBPF instructions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    Undefined(Undefined),
    Bin(Bin),
    Un(Un),
    LoadMapFd(LoadMapFd),
    LoadMapAddress(LoadMapAddress),
    LoadPseudo(LoadPseudo),
    Call(Call),
    CallLocal(CallLocal),
    Callx(Callx),
    CallBtf(CallBtf),
    Exit(Exit),
    Jmp(Jmp),
    Mem(Mem),
    Packet(Packet),
    Atomic(Atomic),
    Assume(Assume),
    IncrementLoopCounter(IncrementLoopCounter),
}

/// A labeled instruction with optional BTF line info.
pub type LabeledInstruction = (Label, Instruction, Option<BtfLineInfo>);

/// Sequence of labeled instructions.
pub type InstructionSeq = Vec<LabeledInstruction>;

/// BTF line info for debugging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtfLineInfo {
    pub file_name: String,
    pub source_line: String,
    pub line_number: u32,
    pub column_number: u32,
}

// ============================================================================
// Assertion types (safety checks emitted by the verifier)
// ============================================================================

/// Check that something is a valid size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidSize {
    pub reg: Reg,
    pub can_be_zero: bool,
}

/// Check that two registers can be compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comparable {
    pub r1: Reg,
    pub r2: Reg,
    pub or_r2_is_number: bool,
}

/// Check that a pointer and number can be added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Addable {
    pub ptr: Reg,
    pub num: Reg,
}

/// Check that a register contains a non-zero number (for division).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidDivisor {
    pub reg: Reg,
    pub is_signed: bool,
}

/// How memory is being accessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessType {
    Compare,
    Read,
    Write,
}

/// Check that a memory access is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidAccess {
    pub call_stack_depth: i32,
    pub reg: Reg,
    pub offset: i32,
    pub width: Value,
    pub or_null: bool,
    pub access_type: AccessType,
}

/// Check that a map key/value is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidMapKeyValue {
    pub access_reg: Reg,
    pub map_fd_reg: Reg,
    pub key: bool,
}

/// Check that a store to memory is valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidStore {
    pub mem: Reg,
    pub val: Reg,
}

/// Check that a register has a specific type group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeConstraint {
    pub reg: Reg,
    pub types: TypeGroup,
}

/// Check that a callback target register holds a valid top-level code label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidCallbackTarget {
    pub reg: Reg,
}

/// Check that a register holds a function pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncConstraint {
    pub reg: Reg,
}

/// Check that context offset is zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZeroCtxOffset {
    pub reg: Reg,
    pub or_null: bool,
}

/// Check that a loop counter is within bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedLoopCount {
    pub name: Label,
}

impl BoundedLoopCount {
    pub const LIMIT: i32 = 100000;
}

/// Sum type of all assertion checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assertion {
    Comparable(Comparable),
    Addable(Addable),
    ValidDivisor(ValidDivisor),
    ValidAccess(ValidAccess),
    ValidStore(ValidStore),
    ValidSize(ValidSize),
    ValidMapKeyValue(ValidMapKeyValue),
    ValidCallbackTarget(ValidCallbackTarget),
    TypeConstraint(TypeConstraint),
    FuncConstraint(FuncConstraint),
    ZeroCtxOffset(ZeroCtxOffset),
    BoundedLoopCount(BoundedLoopCount),
}
