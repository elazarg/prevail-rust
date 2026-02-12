// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! eBPF-specific data kind encoding.
//!
//! Ported from `src/crab/type_encoding.hpp` and helpers in `src/crab/type_domain.cpp`.

use std::fmt;

/// The different kinds of per-register data tracked by the abstract domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum DataKind {
    Types = 0,
    Svalues,
    Uvalues,
    CtxOffsets,
    MapFds,
    MapFdPrograms,
    PacketOffsets,
    SharedOffsets,
    StackOffsets,
    SharedRegionSizes,
    StackNumericSizes,
}

#[allow(dead_code)]
pub const KIND_MIN: DataKind = DataKind::Types;
pub const KIND_VALUE_MIN: DataKind = DataKind::Svalues;
pub const KIND_MAX: DataKind = DataKind::StackNumericSizes;

const ALL_KINDS: [DataKind; 11] = [
    DataKind::Types,
    DataKind::Svalues,
    DataKind::Uvalues,
    DataKind::CtxOffsets,
    DataKind::MapFds,
    DataKind::MapFdPrograms,
    DataKind::PacketOffsets,
    DataKind::SharedOffsets,
    DataKind::StackOffsets,
    DataKind::SharedRegionSizes,
    DataKind::StackNumericSizes,
];

/// Returns the string name used in variable names for the given kind.
pub fn name_of(kind: DataKind) -> &'static str {
    match kind {
        DataKind::Types => "type",
        DataKind::Svalues => "svalue",
        DataKind::Uvalues => "uvalue",
        DataKind::CtxOffsets => "ctx_offset",
        DataKind::MapFds => "map_fd",
        DataKind::MapFdPrograms => "map_fd_programs",
        DataKind::PacketOffsets => "packet_offset",
        DataKind::SharedOffsets => "shared_offset",
        DataKind::StackOffsets => "stack_offset",
        DataKind::SharedRegionSizes => "shared_region_size",
        DataKind::StackNumericSizes => "stack_numeric_size",
    }
}

/// Reverse lookup: string name → `DataKind`. Returns `None` for unknown strings.
pub fn regkind(s: &str) -> Option<DataKind> {
    match s {
        "type" => Some(DataKind::Types),
        "svalue" => Some(DataKind::Svalues),
        "uvalue" => Some(DataKind::Uvalues),
        "ctx_offset" => Some(DataKind::CtxOffsets),
        "map_fd" => Some(DataKind::MapFds),
        "map_fd_programs" => Some(DataKind::MapFdPrograms),
        "packet_offset" => Some(DataKind::PacketOffsets),
        "shared_offset" => Some(DataKind::SharedOffsets),
        "stack_offset" => Some(DataKind::StackOffsets),
        "shared_region_size" => Some(DataKind::SharedRegionSizes),
        "stack_numeric_size" => Some(DataKind::StackNumericSizes),
        _ => None,
    }
}

/// Iterate over `DataKind` values in the range `[lb, ub]` (inclusive).
///
/// Panics if `lb > ub` or either is out of the valid range.
pub fn iterate_kinds(lb: DataKind, ub: DataKind) -> Vec<DataKind> {
    let lb_idx = lb as usize;
    let ub_idx = ub as usize;
    assert!(lb_idx <= ub_idx, "lower bound is greater than upper bound");
    assert!(ub_idx < ALL_KINDS.len(), "upper bound out of range");
    ALL_KINDS[lb_idx..=ub_idx].to_vec()
}

// ============================================================================
// Type encoding constants
// ============================================================================

/// eBPF type encoding values.
/// The exact numbers are taken advantage of in EbpfDomain.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(clippy::enum_variant_names)] // T_ prefix matches upstream C++ naming.
pub enum TypeEncoding {
    TUninit = -7,
    TMapPrograms = -6,
    TMap = -5,
    TNum = -4,
    TCtx = -3,
    TPacket = -2,
    TStack = -1,
    TShared = 0,
}

pub const T_UNINIT: TypeEncoding = TypeEncoding::TUninit;
pub const T_MAP_PROGRAMS: TypeEncoding = TypeEncoding::TMapPrograms;
pub const T_MAP: TypeEncoding = TypeEncoding::TMap;
pub const T_NUM: TypeEncoding = TypeEncoding::TNum;
pub const T_CTX: TypeEncoding = TypeEncoding::TCtx;
pub const T_PACKET: TypeEncoding = TypeEncoding::TPacket;
pub const T_STACK: TypeEncoding = TypeEncoding::TStack;
pub const T_SHARED: TypeEncoding = TypeEncoding::TShared;

#[allow(dead_code)]
pub const T_MIN: TypeEncoding = T_UNINIT;
pub const T_MIN_VALID: TypeEncoding = T_MAP_PROGRAMS;
pub const T_MAX: TypeEncoding = T_SHARED;

const ALL_TYPE_ENCODINGS: [TypeEncoding; 8] = [
    TypeEncoding::TUninit,
    TypeEncoding::TMapPrograms,
    TypeEncoding::TMap,
    TypeEncoding::TNum,
    TypeEncoding::TCtx,
    TypeEncoding::TPacket,
    TypeEncoding::TStack,
    TypeEncoding::TShared,
];

/// Iterate over TypeEncoding values in the range [lb, ub] (inclusive).
pub fn iterate_types(lb: TypeEncoding, ub: TypeEncoding) -> Vec<TypeEncoding> {
    ALL_TYPE_ENCODINGS
        .iter()
        .copied()
        .filter(|&t| t >= lb && t <= ub)
        .collect()
}

impl fmt::Display for TypeEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeEncoding::TUninit => write!(f, "uninit"),
            TypeEncoding::TMapPrograms => write!(f, "map_fd_programs"),
            TypeEncoding::TMap => write!(f, "map_fd"),
            TypeEncoding::TNum => write!(f, "number"),
            TypeEncoding::TCtx => write!(f, "ctx"),
            TypeEncoding::TPacket => write!(f, "packet"),
            TypeEncoding::TStack => write!(f, "stack"),
            TypeEncoding::TShared => write!(f, "shared"),
        }
    }
}

/// Parse a type encoding from a string.
pub fn string_to_type_encoding(s: &str) -> Option<TypeEncoding> {
    match s {
        "uninit" => Some(TypeEncoding::TUninit),
        "map_fd_programs" => Some(TypeEncoding::TMapPrograms),
        "map_fd" => Some(TypeEncoding::TMap),
        "number" => Some(TypeEncoding::TNum),
        "ctx" => Some(TypeEncoding::TCtx),
        "packet" => Some(TypeEncoding::TPacket),
        "stack" => Some(TypeEncoding::TStack),
        "shared" => Some(TypeEncoding::TShared),
        _ => None,
    }
}

/// Convert an integer to a TypeEncoding, if valid.
pub fn int_to_type_encoding(v: i32) -> Option<TypeEncoding> {
    match v {
        -7 => Some(TypeEncoding::TUninit),
        -6 => Some(TypeEncoding::TMapPrograms),
        -5 => Some(TypeEncoding::TMap),
        -4 => Some(TypeEncoding::TNum),
        -3 => Some(TypeEncoding::TCtx),
        -2 => Some(TypeEncoding::TPacket),
        -1 => Some(TypeEncoding::TStack),
        0 => Some(TypeEncoding::TShared),
        _ => None,
    }
}

/// Format a set of type encodings as a readable string like "{number, ctx, packet}".
pub fn typeset_to_string(items: &[TypeEncoding]) -> String {
    let parts: Vec<String> = items.iter().map(|t| format!("{t}")).collect();
    format!("{{{}}}", parts.join(", "))
}

// ============================================================================
// TypeGroup
// ============================================================================

/// Groups of eBPF types used in assertion checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypeGroup {
    Number,
    MapFd,
    Ctx,
    CtxOrNum,
    Packet,
    Stack,
    StackOrNum,
    Shared,
    MapFdPrograms,
    Mem,
    MemOrNum,
    Pointer,
    PtrOrNum,
    StackOrPacket,
    SingletonPtr,
}

impl TypeGroup {
    /// Whether this type group represents a single concrete type.
    pub fn is_singleton_type(self) -> bool {
        matches!(
            self,
            TypeGroup::Number
                | TypeGroup::MapFd
                | TypeGroup::Ctx
                | TypeGroup::Packet
                | TypeGroup::Stack
                | TypeGroup::Shared
                | TypeGroup::MapFdPrograms
        )
    }
}

impl fmt::Display for TypeGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TypeEncoding::*;
        match self {
            TypeGroup::Number => write!(f, "number"),
            TypeGroup::MapFd => write!(f, "map_fd"),
            TypeGroup::Ctx => write!(f, "ctx"),
            TypeGroup::Packet => write!(f, "packet"),
            TypeGroup::Stack => write!(f, "stack"),
            TypeGroup::Shared => write!(f, "shared"),
            TypeGroup::MapFdPrograms => write!(f, "map_fd_programs"),
            // Compound groups expand to type sets
            TypeGroup::CtxOrNum => write!(f, "{}", typeset_to_string(&[TNum, TCtx])),
            TypeGroup::StackOrNum => write!(f, "{}", typeset_to_string(&[TNum, TStack])),
            TypeGroup::Mem => write!(f, "{}", typeset_to_string(&[TStack, TPacket, TShared])),
            TypeGroup::MemOrNum => write!(
                f,
                "{}",
                typeset_to_string(&[TNum, TStack, TPacket, TShared])
            ),
            TypeGroup::Pointer => write!(
                f,
                "{}",
                typeset_to_string(&[TCtx, TStack, TPacket, TShared])
            ),
            TypeGroup::PtrOrNum => write!(
                f,
                "{}",
                typeset_to_string(&[TNum, TCtx, TStack, TPacket, TShared])
            ),
            TypeGroup::StackOrPacket => write!(f, "{}", typeset_to_string(&[TStack, TPacket])),
            TypeGroup::SingletonPtr => write!(f, "{}", typeset_to_string(&[TCtx, TStack, TPacket])),
        }
    }
}

impl fmt::Display for DataKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(name_of(*self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_of_all_kinds() {
        assert_eq!(name_of(DataKind::Types), "type");
        assert_eq!(name_of(DataKind::Svalues), "svalue");
        assert_eq!(name_of(DataKind::Uvalues), "uvalue");
        assert_eq!(name_of(DataKind::CtxOffsets), "ctx_offset");
        assert_eq!(name_of(DataKind::MapFds), "map_fd");
        assert_eq!(name_of(DataKind::MapFdPrograms), "map_fd_programs");
        assert_eq!(name_of(DataKind::PacketOffsets), "packet_offset");
        assert_eq!(name_of(DataKind::SharedOffsets), "shared_offset");
        assert_eq!(name_of(DataKind::StackOffsets), "stack_offset");
        assert_eq!(name_of(DataKind::SharedRegionSizes), "shared_region_size");
        assert_eq!(name_of(DataKind::StackNumericSizes), "stack_numeric_size");
    }

    #[test]
    fn test_regkind_roundtrip() {
        for &kind in &ALL_KINDS {
            let name = name_of(kind);
            assert_eq!(regkind(name), Some(kind), "roundtrip failed for {kind:?}");
        }
    }

    #[test]
    fn test_regkind_unknown() {
        assert_eq!(regkind("nonexistent"), None);
        assert_eq!(regkind(""), None);
    }

    #[test]
    fn test_iterate_kinds_full_range() {
        let all = iterate_kinds(KIND_MIN, KIND_MAX);
        assert_eq!(all.len(), 11);
        assert_eq!(all[0], DataKind::Types);
        assert_eq!(all[10], DataKind::StackNumericSizes);
    }

    #[test]
    fn test_iterate_kinds_value_range() {
        let values = iterate_kinds(KIND_VALUE_MIN, KIND_MAX);
        assert_eq!(values.len(), 10);
        assert_eq!(values[0], DataKind::Svalues);
    }

    #[test]
    fn test_iterate_kinds_single() {
        let single = iterate_kinds(DataKind::MapFds, DataKind::MapFds);
        assert_eq!(single, vec![DataKind::MapFds]);
    }

    #[test]
    #[should_panic(expected = "lower bound is greater than upper bound")]
    fn test_iterate_kinds_invalid_range() {
        iterate_kinds(DataKind::Uvalues, DataKind::Svalues);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", DataKind::Types), "type");
        assert_eq!(format!("{}", DataKind::PacketOffsets), "packet_offset");
    }
}
