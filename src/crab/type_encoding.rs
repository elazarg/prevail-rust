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
    SocketOffsets,
    BtfIdOffsets,
    AllocMemOffsets,
    AllocMemSizes,
}

#[allow(dead_code)]
pub const KIND_MIN: DataKind = DataKind::Types;
pub const KIND_VALUE_MIN: DataKind = DataKind::Svalues;
pub const KIND_MAX: DataKind = DataKind::AllocMemSizes;

const ALL_KINDS: [DataKind; 15] = [
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
    DataKind::SocketOffsets,
    DataKind::BtfIdOffsets,
    DataKind::AllocMemOffsets,
    DataKind::AllocMemSizes,
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
        DataKind::SocketOffsets => "socket_offset",
        DataKind::BtfIdOffsets => "btf_id_offset",
        DataKind::AllocMemOffsets => "alloc_mem_offset",
        DataKind::AllocMemSizes => "alloc_mem_size",
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
        "socket_offset" => Some(DataKind::SocketOffsets),
        "btf_id_offset" => Some(DataKind::BtfIdOffsets),
        "alloc_mem_offset" => Some(DataKind::AllocMemOffsets),
        "alloc_mem_size" => Some(DataKind::AllocMemSizes),
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
///
/// Values are 0..11, one per bit position in [`TypeSet`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[expect(clippy::enum_variant_names)] // T_ prefix matches upstream C++ naming.
pub enum TypeEncoding {
    TUninit = 0,
    TMapPrograms = 1,
    TMap = 2,
    TNum = 3,
    TCtx = 4,
    TPacket = 5,
    TStack = 6,
    TShared = 7,
    TSocket = 8,
    TBtfId = 9,
    TAllocMem = 10,
    TFunc = 11,
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
pub const T_SOCKET: TypeEncoding = TypeEncoding::TSocket;
#[allow(dead_code)]
pub const T_BTF_ID: TypeEncoding = TypeEncoding::TBtfId;
#[allow(dead_code)]
pub const T_ALLOC_MEM: TypeEncoding = TypeEncoding::TAllocMem;
#[allow(dead_code)]
pub const T_FUNC: TypeEncoding = TypeEncoding::TFunc;

/// Number of `TypeEncoding` variants.
pub const NUM_TYPE_ENCODINGS: usize = 12;

#[cfg(test)]
const ALL_TYPE_ENCODINGS: [TypeEncoding; NUM_TYPE_ENCODINGS] = [
    TypeEncoding::TUninit,
    TypeEncoding::TMapPrograms,
    TypeEncoding::TMap,
    TypeEncoding::TNum,
    TypeEncoding::TCtx,
    TypeEncoding::TPacket,
    TypeEncoding::TStack,
    TypeEncoding::TShared,
    TypeEncoding::TSocket,
    TypeEncoding::TBtfId,
    TypeEncoding::TAllocMem,
    TypeEncoding::TFunc,
];

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
            TypeEncoding::TSocket => write!(f, "socket"),
            TypeEncoding::TBtfId => write!(f, "btf_id"),
            TypeEncoding::TAllocMem => write!(f, "alloc_mem"),
            TypeEncoding::TFunc => write!(f, "func"),
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
        "socket" => Some(TypeEncoding::TSocket),
        "btf_id" => Some(TypeEncoding::TBtfId),
        "alloc_mem" => Some(TypeEncoding::TAllocMem),
        "func" => Some(TypeEncoding::TFunc),
        _ => None,
    }
}

/// Convert an integer to a TypeEncoding, if valid.
pub fn int_to_type_encoding(v: i32) -> Option<TypeEncoding> {
    match v {
        0 => Some(TypeEncoding::TUninit),
        1 => Some(TypeEncoding::TMapPrograms),
        2 => Some(TypeEncoding::TMap),
        3 => Some(TypeEncoding::TNum),
        4 => Some(TypeEncoding::TCtx),
        5 => Some(TypeEncoding::TPacket),
        6 => Some(TypeEncoding::TStack),
        7 => Some(TypeEncoding::TShared),
        8 => Some(TypeEncoding::TSocket),
        9 => Some(TypeEncoding::TBtfId),
        10 => Some(TypeEncoding::TAllocMem),
        11 => Some(TypeEncoding::TFunc),
        _ => None,
    }
}

/// Format a set of type encodings as a readable string like "{number, ctx, packet}".
pub fn typeset_to_string(items: &[TypeEncoding]) -> String {
    let parts: Vec<String> = items.iter().map(|t| format!("{t}")).collect();
    format!("{{{}}}", parts.join(", "))
}

// ============================================================================
// TypeSet — u16 bitset over TypeEncoding values
// ============================================================================

/// A compact bitset over the 12 `TypeEncoding` values, stored as a `u16`.
///
/// Each bit position corresponds to a `TypeEncoding` variant (mapped via
/// `type_to_bit`). This provides a non-convex representation of type sets,
/// unlike the zone domain's interval-based encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TypeSet(u16);

/// Map a `TypeEncoding` to its bit position (0..7).
pub(crate) const fn type_to_bit(te: TypeEncoding) -> u8 {
    te as u8
}

impl TypeSet {
    /// The empty set (no types).
    pub const EMPTY: TypeSet = TypeSet(0);

    /// The full set (all known types).
    pub const ALL: TypeSet = TypeSet((1u16 << NUM_TYPE_ENCODINGS) - 1);

    /// Create a singleton set containing exactly one type.
    pub const fn singleton(te: TypeEncoding) -> TypeSet {
        TypeSet(1u16 << type_to_bit(te))
    }

    /// Create a set from a slice of types. Usable in `const` contexts.
    pub const fn of(types: &[TypeEncoding]) -> TypeSet {
        let mut bits = 0u16;
        let mut i = 0;
        while i < types.len() {
            bits |= 1u16 << type_to_bit(types[i]);
            i += 1;
        }
        TypeSet(bits)
    }

    /// Create an empty set.
    pub const fn empty() -> TypeSet {
        TypeSet::EMPTY
    }

    /// Create the full set of all types.
    pub const fn all() -> TypeSet {
        TypeSet::ALL
    }

    /// Whether this set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether this set contains exactly one type.
    pub const fn is_singleton(self) -> bool {
        self.0 != 0 && (self.0 & (self.0 - 1)) == 0
    }

    /// Whether this set contains a given type.
    pub const fn contains(self, te: TypeEncoding) -> bool {
        (self.0 & (1u16 << type_to_bit(te))) != 0
    }

    /// Set union.
    pub const fn union(self, other: TypeSet) -> TypeSet {
        TypeSet(self.0 | other.0)
    }

    /// Set intersection.
    pub const fn intersect(self, other: TypeSet) -> TypeSet {
        TypeSet(self.0 & other.0)
    }

    /// Remove a single type from the set.
    pub const fn remove(self, te: TypeEncoding) -> TypeSet {
        TypeSet(self.0 & !(1u16 << type_to_bit(te)))
    }

    /// Whether `self` is a subset of `other`.
    pub const fn is_subset_of(self, other: TypeSet) -> bool {
        (self.0 & !other.0) == 0
    }

    /// Number of types in the set.
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Get the singleton type, if this set has exactly one element.
    pub fn as_singleton(self) -> Option<TypeEncoding> {
        if self.is_singleton() {
            let bit = self.0.trailing_zeros() as i32;
            int_to_type_encoding(bit)
        } else {
            None
        }
    }

    /// Iterate over all types in this set.
    pub fn iter(self) -> TypeSetIter {
        TypeSetIter(self.0)
    }
}

/// Iterator over the types in a `TypeSet`.
pub struct TypeSetIter(u16);

impl Iterator for TypeSetIter {
    type Item = TypeEncoding;

    fn next(&mut self) -> Option<TypeEncoding> {
        if self.0 == 0 {
            return None;
        }
        let bit = self.0.trailing_zeros() as i32;
        self.0 &= self.0 - 1; // clear lowest set bit
        int_to_type_encoding(bit)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.0.count_ones() as usize;
        (n, Some(n))
    }
}

impl ExactSizeIterator for TypeSetIter {}

impl std::fmt::Display for TypeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let items: Vec<TypeEncoding> = self.iter().collect();
        match items.len() {
            0 => write!(f, "{{}}"),
            1 => write!(f, "{}", items[0]),
            _ => write!(f, "{}", typeset_to_string(&items)),
        }
    }
}

// ============================================================================
// Named TypeSet constants
// ============================================================================

use TypeEncoding::*;

/// `{number}`
pub const TS_NUM: TypeSet = TypeSet::singleton(TNum);
/// `{map_fd}`
pub const TS_MAP: TypeSet = TypeSet::singleton(TMap);
/// `{ctx, packet, stack, shared}`
pub const TS_POINTER: TypeSet = TypeSet::of(&[TCtx, TPacket, TStack, TShared]);
/// `{ctx, packet, stack}` — pointer types with a unique region
pub const TS_SINGLETON_PTR: TypeSet = TypeSet::of(&[TCtx, TPacket, TStack]);
/// `{packet, stack, shared}` — memory-accessible pointer types
#[allow(dead_code)]
pub const TS_MEM: TypeSet = TypeSet::of(&[TPacket, TStack, TShared]);
#[allow(dead_code)]
pub const TS_SOCKET: TypeSet = TypeSet::singleton(TSocket);
#[allow(dead_code)]
pub const TS_BTF_ID: TypeSet = TypeSet::singleton(TBtfId);
#[allow(dead_code)]
pub const TS_ALLOC_MEM: TypeSet = TypeSet::singleton(TAllocMem);

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
    Socket,
    BtfId,
    AllocMem,
    Func,
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
                | TypeGroup::Socket
                | TypeGroup::BtfId
                | TypeGroup::AllocMem
                | TypeGroup::Func
        )
    }

    /// Convert this type group to the corresponding `TypeSet`.
    pub fn to_typeset(self) -> TypeSet {
        use TypeEncoding::*;
        match self {
            TypeGroup::Number => TypeSet::singleton(TNum),
            TypeGroup::MapFd => TypeSet::singleton(TMap),
            TypeGroup::Ctx => TypeSet::singleton(TCtx),
            TypeGroup::Packet => TypeSet::singleton(TPacket),
            TypeGroup::Stack => TypeSet::singleton(TStack),
            TypeGroup::Shared => TypeSet::singleton(TShared),
            TypeGroup::MapFdPrograms => TypeSet::singleton(TMapPrograms),
            TypeGroup::Socket => TypeSet::singleton(TSocket),
            TypeGroup::BtfId => TypeSet::singleton(TBtfId),
            TypeGroup::AllocMem => TypeSet::singleton(TAllocMem),
            TypeGroup::Func => TypeSet::singleton(TFunc),
            TypeGroup::CtxOrNum => TypeSet::of(&[TNum, TCtx]),
            TypeGroup::StackOrNum => TypeSet::of(&[TNum, TStack]),
            TypeGroup::Mem => TS_MEM,
            TypeGroup::MemOrNum => TS_MEM.union(TS_NUM),
            TypeGroup::Pointer => TS_POINTER,
            TypeGroup::PtrOrNum => TS_POINTER.union(TS_NUM),
            TypeGroup::StackOrPacket => TypeSet::of(&[TStack, TPacket]),
            TypeGroup::SingletonPtr => TS_SINGLETON_PTR,
        }
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
            TypeGroup::Socket => write!(f, "socket"),
            TypeGroup::BtfId => write!(f, "btf_id"),
            TypeGroup::AllocMem => write!(f, "alloc_mem"),
            TypeGroup::Func => write!(f, "func"),
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
        assert_eq!(name_of(DataKind::SocketOffsets), "socket_offset");
        assert_eq!(name_of(DataKind::BtfIdOffsets), "btf_id_offset");
        assert_eq!(name_of(DataKind::AllocMemOffsets), "alloc_mem_offset");
        assert_eq!(name_of(DataKind::AllocMemSizes), "alloc_mem_size");
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
        assert_eq!(all.len(), 15);
        assert_eq!(all[0], DataKind::Types);
        assert_eq!(all[14], DataKind::AllocMemSizes);
    }

    #[test]
    fn test_iterate_kinds_value_range() {
        let values = iterate_kinds(KIND_VALUE_MIN, KIND_MAX);
        assert_eq!(values.len(), 14);
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

    // TypeSet tests

    #[test]
    fn test_typeset_empty() {
        let s = TypeSet::empty();
        assert!(s.is_empty());
        assert!(!s.is_singleton());
        assert_eq!(s.len(), 0);
        assert_eq!(s.iter().count(), 0);
        assert_eq!(s.as_singleton(), None);
    }

    #[test]
    fn test_typeset_all() {
        let s = TypeSet::all();
        assert!(!s.is_empty());
        assert!(!s.is_singleton());
        assert_eq!(s.len(), 12);
        assert_eq!(s.iter().count(), 12);
    }

    #[test]
    fn test_typeset_singleton() {
        for &te in &ALL_TYPE_ENCODINGS {
            let s = TypeSet::singleton(te);
            assert!(s.is_singleton());
            assert!(s.contains(te));
            assert_eq!(s.len(), 1);
            assert_eq!(s.as_singleton(), Some(te));
        }
    }

    #[test]
    fn test_typeset_union_intersect() {
        let a = TypeSet::of(&[T_NUM, T_CTX]);
        let b = TypeSet::of(&[T_CTX, T_STACK]);
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);

        let u = a.union(b);
        assert_eq!(u.len(), 3);
        assert!(u.contains(T_NUM));
        assert!(u.contains(T_CTX));
        assert!(u.contains(T_STACK));

        let i = a.intersect(b);
        assert_eq!(i.len(), 1);
        assert!(i.contains(T_CTX));
    }

    #[test]
    fn test_typeset_remove() {
        let s = TypeSet::of(&[T_NUM, T_CTX]);
        let r = s.remove(T_NUM);
        assert_eq!(r.len(), 1);
        assert!(!r.contains(T_NUM));
        assert!(r.contains(T_CTX));
    }

    #[test]
    fn test_typeset_subset() {
        let small = TypeSet::singleton(T_CTX);
        let big = TypeSet::of(&[T_CTX, T_STACK]);
        assert!(small.is_subset_of(big));
        assert!(!big.is_subset_of(small));
        assert!(TypeSet::empty().is_subset_of(small));
        assert!(small.is_subset_of(TypeSet::all()));
    }

    #[test]
    fn test_typeset_iter_order() {
        let s = TypeSet::all();
        let items: Vec<TypeEncoding> = s.iter().collect();
        // Should iterate in TypeEncoding order (TUninit first, TFunc last)
        assert_eq!(items, ALL_TYPE_ENCODINGS.to_vec());
    }

    #[test]
    fn test_typeset_display() {
        assert_eq!(format!("{}", TypeSet::singleton(T_NUM)), "number");
        assert_eq!(
            format!("{}", TypeSet::of(&[T_CTX, T_STACK])),
            "{ctx, stack}"
        );
        assert_eq!(format!("{}", TypeSet::empty()), "{}");
    }

    #[test]
    fn test_typegroup_to_typeset() {
        assert_eq!(TypeGroup::Number.to_typeset(), TypeSet::singleton(T_NUM));
        assert_eq!(
            TypeGroup::Pointer.to_typeset(),
            TypeSet::of(&[T_CTX, T_PACKET, T_STACK, T_SHARED])
        );
        assert_eq!(TypeGroup::Pointer.to_typeset().len(), 4);
        assert_eq!(TypeGroup::PtrOrNum.to_typeset().len(), 5);
        assert_eq!(TypeGroup::Mem.to_typeset().len(), 3);
    }

    #[test]
    fn test_ts_constants_match_typegroups() {
        assert_eq!(TS_NUM, TypeGroup::Number.to_typeset());
        assert_eq!(TS_MAP, TypeGroup::MapFd.to_typeset());
        assert_eq!(TS_POINTER, TypeGroup::Pointer.to_typeset());
        assert_eq!(TS_SINGLETON_PTR, TypeGroup::SingletonPtr.to_typeset());
        assert_eq!(TS_MEM, TypeGroup::Mem.to_typeset());
        assert_eq!(TS_SOCKET, TypeGroup::Socket.to_typeset());
        assert_eq!(TS_BTF_ID, TypeGroup::BtfId.to_typeset());
        assert_eq!(TS_ALLOC_MEM, TypeGroup::AllocMem.to_typeset());
    }
}
