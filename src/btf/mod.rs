// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! BTF (BPF Type Format) parsing and type information.
//!
//! Ports the read-only subset of `external/libbtf/`.

use zerocopy::FromBytes;

pub mod map;
pub mod parse;
pub mod type_data;

/// Read a test ELF file, returning `None` (with a skip message) if not found.
#[cfg(test)]
pub(crate) fn read_test_elf(path: &str) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(d) => Some(d),
        Err(_) => {
            eprintln!("Skipping test: {path} not found");
            None
        }
    }
}

/// Load a `.BTF` section from an ELF file, returning `None` if the file or section is missing.
#[cfg(test)]
pub(crate) fn load_btf_section_from_elf(path: &str) -> Option<Vec<u8>> {
    let data = read_test_elf(path)?;
    use object::Object;
    use object::ObjectSection;
    let elf = object::File::parse(&*data).unwrap();
    let btf_section = match elf.section_by_name(".BTF") {
        Some(s) => s,
        None => {
            eprintln!("Skipping test: no .BTF section in {path}");
            return None;
        }
    };
    Some(btf_section.data().unwrap().to_vec())
}

use crate::elf_loader::UnmarshalError;

/// BTF type identifier (0 = void).
pub type BtfTypeId = u32;

// ── Constants ────────────────────────────────────────────────────────

pub const BTF_HEADER_MAGIC: u16 = 0xEB9F;
pub const BTF_HEADER_MAGIC_BIG_ENDIAN: u16 = 0x9FEB;
pub const BTF_HEADER_VERSION: u8 = 1;

// BTF_INT encoding bits
pub const BTF_INT_SIGNED: u32 = 1 << 0;
pub const BTF_INT_CHAR: u32 = 1 << 1;
pub const BTF_INT_BOOL: u32 = 1 << 2;

// ── Raw on-disk structs ──────────────────────────────────────────────

/// BTF header (`.BTF` section).
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub type_off: u32,
    pub type_len: u32,
    pub str_off: u32,
    pub str_len: u32,
}

/// BTF.ext header (`.BTF.ext` section).
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfExtHeader {
    pub magic: u16,
    pub version: u8,
    pub flags: u8,
    pub hdr_len: u32,
    pub func_info_off: u32,
    pub func_info_len: u32,
    pub line_info_off: u32,
    pub line_info_len: u32,
}

/// Raw BTF type record (on-disk).
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawType {
    pub name_off: u32,
    pub info: u32,
    /// Union of `size` and `type` — context determines which.
    pub size_or_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawArray {
    pub element_type: u32,
    pub index_type: u32,
    pub nelems: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawParam {
    pub name_off: u32,
    pub type_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawVar {
    pub linkage: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawVarSecInfo {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawDeclTag {
    pub component_idx: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawMember {
    pub name_off: u32,
    pub type_id: u32,
    pub offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawEnum {
    pub name_off: u32,
    pub val: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfRawEnum64 {
    pub name_off: u32,
    pub val_lo32: u32,
    pub val_hi32: u32,
}

/// BTF.ext info section header (variable-length, followed by records).
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BtfExtInfoSec {
    pub sec_name_off: u32,
    pub num_info: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BpfLineInfo {
    pub insn_off: u32,
    pub file_name_off: u32,
    pub line_off: u32,
    pub line_col: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes)]
pub struct BpfFuncInfo {
    pub insn_off: u32,
    pub type_id: u32,
}

// ── Info extraction helpers ──────────────────────────────────────────

#[inline]
pub fn btf_type_info_vlen(info: u32) -> u32 {
    info & 0xffff
}

#[inline]
pub fn btf_type_info_kind(info: u32) -> u32 {
    (info >> 24) & 0x1f
}

#[inline]
pub fn btf_type_info_kind_flag(info: u32) -> bool {
    (info >> 31) & 1 != 0
}

#[inline]
pub fn btf_int_encoding(val: u32) -> u32 {
    (val & 0x0f00_0000) >> 24
}

#[inline]
pub fn btf_int_offset(val: u32) -> u16 {
    ((val & 0x00ff_0000) >> 16) as u16
}

#[inline]
pub fn btf_int_bits(val: u32) -> u8 {
    (val & 0x0000_00ff) as u8
}

#[inline]
pub fn bpf_line_info_line_num(line_col: u32) -> u32 {
    line_col >> 10
}

#[inline]
pub fn bpf_line_info_line_col(line_col: u32) -> u32 {
    line_col & 0x3ff
}

// ── BTF kind index (discriminant) ────────────────────────────────────

/// BTF type kind indices matching the on-disk encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BtfKindIndex {
    Void = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Function = 12,
    FunctionPrototype = 13,
    Var = 14,
    DataSection = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl BtfKindIndex {
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Void),
            1 => Some(Self::Int),
            2 => Some(Self::Ptr),
            3 => Some(Self::Array),
            4 => Some(Self::Struct),
            5 => Some(Self::Union),
            6 => Some(Self::Enum),
            7 => Some(Self::Fwd),
            8 => Some(Self::Typedef),
            9 => Some(Self::Volatile),
            10 => Some(Self::Const),
            11 => Some(Self::Restrict),
            12 => Some(Self::Function),
            13 => Some(Self::FunctionPrototype),
            14 => Some(Self::Var),
            15 => Some(Self::DataSection),
            16 => Some(Self::Float),
            17 => Some(Self::DeclTag),
            18 => Some(Self::TypeTag),
            19 => Some(Self::Enum64),
            _ => None,
        }
    }
}

// ── Linkage ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BtfLinkage {
    Static = 0,
    Global = 1,
    Extern = 2,
}

impl BtfLinkage {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Static,
            1 => Self::Global,
            _ => Self::Extern,
        }
    }
}

// ── High-level BTF kind types ────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BtfStructMember {
    pub name: Option<String>,
    pub type_id: BtfTypeId,
    pub offset_from_start_in_bits: u32,
}

#[derive(Clone, Debug)]
pub struct BtfEnumMember {
    pub name: String,
    pub value: u32,
}

#[derive(Clone, Debug)]
pub struct BtfEnum64Member {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug)]
pub struct BtfFunctionParameter {
    pub name: String,
    pub type_id: BtfTypeId,
}

#[derive(Clone, Debug)]
pub struct BtfDataMember {
    pub type_id: BtfTypeId,
    pub offset: u32,
    pub size: u32,
}

/// Discriminated union of all 20 BTF type kinds.
#[derive(Clone, Debug)]
pub enum BtfKind {
    Void,
    Int {
        name: String,
        size_in_bytes: u32,
        offset_from_start_in_bits: u16,
        field_width_in_bits: u8,
        is_signed: bool,
        is_char: bool,
        is_bool: bool,
    },
    Ptr {
        type_id: BtfTypeId,
    },
    Array {
        element_type: BtfTypeId,
        index_type: BtfTypeId,
        count_of_elements: u32,
    },
    Struct {
        name: Option<String>,
        members: Vec<BtfStructMember>,
        size_in_bytes: u32,
    },
    Union {
        name: Option<String>,
        members: Vec<BtfStructMember>,
        size_in_bytes: u32,
    },
    Enum {
        name: Option<String>,
        is_signed: bool,
        members: Vec<BtfEnumMember>,
        size_in_bytes: u32,
    },
    Fwd {
        name: String,
        is_struct: bool,
    },
    Typedef {
        name: String,
        type_id: BtfTypeId,
    },
    Volatile {
        type_id: BtfTypeId,
    },
    Const {
        type_id: BtfTypeId,
    },
    Restrict {
        type_id: BtfTypeId,
    },
    Function {
        name: String,
        linkage: BtfLinkage,
        type_id: BtfTypeId,
    },
    FunctionPrototype {
        parameters: Vec<BtfFunctionParameter>,
        return_type: BtfTypeId,
    },
    Var {
        name: String,
        type_id: BtfTypeId,
        linkage: BtfLinkage,
    },
    DataSection {
        name: String,
        members: Vec<BtfDataMember>,
        size: u32,
    },
    Float {
        name: String,
        size_in_bytes: u32,
    },
    DeclTag {
        name: String,
        type_id: BtfTypeId,
        component_index: u32,
    },
    TypeTag {
        name: String,
        type_id: BtfTypeId,
    },
    Enum64 {
        name: Option<String>,
        is_signed: bool,
        members: Vec<BtfEnum64Member>,
        size_in_bytes: u32,
    },
}

impl BtfKind {
    /// Return the kind index discriminant.
    pub fn kind_index(&self) -> BtfKindIndex {
        match self {
            BtfKind::Void => BtfKindIndex::Void,
            BtfKind::Int { .. } => BtfKindIndex::Int,
            BtfKind::Ptr { .. } => BtfKindIndex::Ptr,
            BtfKind::Array { .. } => BtfKindIndex::Array,
            BtfKind::Struct { .. } => BtfKindIndex::Struct,
            BtfKind::Union { .. } => BtfKindIndex::Union,
            BtfKind::Enum { .. } => BtfKindIndex::Enum,
            BtfKind::Fwd { .. } => BtfKindIndex::Fwd,
            BtfKind::Typedef { .. } => BtfKindIndex::Typedef,
            BtfKind::Volatile { .. } => BtfKindIndex::Volatile,
            BtfKind::Const { .. } => BtfKindIndex::Const,
            BtfKind::Restrict { .. } => BtfKindIndex::Restrict,
            BtfKind::Function { .. } => BtfKindIndex::Function,
            BtfKind::FunctionPrototype { .. } => BtfKindIndex::FunctionPrototype,
            BtfKind::Var { .. } => BtfKindIndex::Var,
            BtfKind::DataSection { .. } => BtfKindIndex::DataSection,
            BtfKind::Float { .. } => BtfKindIndex::Float,
            BtfKind::DeclTag { .. } => BtfKindIndex::DeclTag,
            BtfKind::TypeTag { .. } => BtfKindIndex::TypeTag,
            BtfKind::Enum64 { .. } => BtfKindIndex::Enum64,
        }
    }

    /// Return the referenced type id if this kind has one (ptr, typedef, volatile, const, restrict).
    pub fn referenced_type_id(&self) -> Option<BtfTypeId> {
        match self {
            BtfKind::Ptr { type_id }
            | BtfKind::Typedef { type_id, .. }
            | BtfKind::Volatile { type_id }
            | BtfKind::Const { type_id }
            | BtfKind::Restrict { type_id }
            | BtfKind::Function { type_id, .. }
            | BtfKind::Var { type_id, .. }
            | BtfKind::DeclTag { type_id, .. }
            | BtfKind::TypeTag { type_id, .. } => Some(*type_id),
            _ => None,
        }
    }
}

// ── BTF map definition ───────────────────────────────────────────────

/// A BTF-defined map extracted from the `.maps` DATASEC.
#[derive(Clone, Debug, Default)]
pub struct BtfMapDefinition {
    pub name: String,
    pub type_id: BtfTypeId,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub inner_map_type_id: BtfTypeId,
}
