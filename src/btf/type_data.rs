// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! BTF type table with query methods.
//!
//! Ports the read-only subset of `external/libbtf/libbtf/btf_type_data.cpp`.

use std::collections::{BTreeMap, HashSet};

use super::parse;
use super::{BtfKind, BtfKindIndex, BtfTypeId, UnmarshalError};

/// Type table constructed from parsed `.BTF` data.
pub struct BtfTypeData {
    id_to_kind: BTreeMap<BtfTypeId, BtfKind>,
    name_to_id: BTreeMap<String, BtfTypeId>,
}

impl BtfTypeData {
    /// Construct from raw `.BTF` section bytes.
    pub fn new(btf_data: &[u8]) -> Result<Self, UnmarshalError> {
        let types = parse::parse_types(btf_data)?;
        let mut id_to_kind = BTreeMap::new();
        let mut name_to_id = BTreeMap::new();

        for (id, name, kind) in types {
            id_to_kind.insert(id, kind);
            if let Some(n) = name
                && !n.is_empty()
            {
                name_to_id.insert(n, id);
            }
        }

        Ok(Self {
            id_to_kind,
            name_to_id,
        })
    }

    /// Look up a type ID by name. Returns 0 if not found (matching C++ behavior).
    pub fn get_id(&self, name: &str) -> BtfTypeId {
        self.name_to_id.get(name).copied().unwrap_or(0)
    }

    /// Get the kind for a given type ID.
    pub fn get_kind(&self, id: BtfTypeId) -> Result<&BtfKind, UnmarshalError> {
        self.id_to_kind
            .get(&id)
            .ok_or_else(|| UnmarshalError(format!("BTF type id not found: {id}")))
    }

    /// Get the kind index (discriminant) for a given type ID.
    pub fn get_kind_index(&self, id: BtfTypeId) -> Result<BtfKindIndex, UnmarshalError> {
        Ok(self.get_kind(id)?.kind_index())
    }

    /// Dereference a pointer type, returning the pointee type ID.
    pub fn dereference_pointer(&self, id: BtfTypeId) -> Result<BtfTypeId, UnmarshalError> {
        match self.get_kind(id)? {
            BtfKind::Ptr { type_id } => Ok(*type_id),
            _ => Err(UnmarshalError(format!(
                "Expected BTF_KIND_PTR for type id {id}"
            ))),
        }
    }

    /// Get the struct kind for a given type ID.
    pub fn get_struct(&self, id: BtfTypeId) -> Result<&BtfKind, UnmarshalError> {
        let kind = self.get_kind(id)?;
        match kind {
            BtfKind::Struct { .. } => Ok(kind),
            _ => Err(UnmarshalError(format!(
                "Expected BTF_KIND_STRUCT for type id {id}"
            ))),
        }
    }

    /// Get the array kind for a given type ID.
    pub fn get_array(&self, id: BtfTypeId) -> Result<&BtfKind, UnmarshalError> {
        let kind = self.get_kind(id)?;
        match kind {
            BtfKind::Array { .. } => Ok(kind),
            _ => Err(UnmarshalError(format!(
                "Expected BTF_KIND_ARRAY for type id {id}"
            ))),
        }
    }

    /// Get the var kind for a given type ID.
    pub fn get_var(&self, id: BtfTypeId) -> Result<(&str, BtfTypeId), UnmarshalError> {
        match self.get_kind(id)? {
            BtfKind::Var { name, type_id, .. } => Ok((name, *type_id)),
            _ => Err(UnmarshalError(format!(
                "Expected BTF_KIND_VAR for type id {id}"
            ))),
        }
    }

    /// Get the data section kind for a given type ID.
    pub fn get_data_section(&self, id: BtfTypeId) -> Result<&BtfKind, UnmarshalError> {
        let kind = self.get_kind(id)?;
        match kind {
            BtfKind::DataSection { .. } => Ok(kind),
            _ => Err(UnmarshalError(format!(
                "Expected BTF_KIND_DATA_SECTION for type id {id}"
            ))),
        }
    }

    /// Return the name of a type by ID, or an empty string if the type has no
    /// name. Matches `btf_type_data::get_type_name` in C++.
    pub fn get_type_name(&self, id: BtfTypeId) -> String {
        let Ok(kind) = self.get_kind(id) else {
            return String::new();
        };
        match kind {
            BtfKind::Int { name, .. }
            | BtfKind::Fwd { name, .. }
            | BtfKind::Typedef { name, .. }
            | BtfKind::Function { name, .. }
            | BtfKind::Var { name, .. }
            | BtfKind::DataSection { name, .. }
            | BtfKind::Float { name, .. }
            | BtfKind::DeclTag { name, .. }
            | BtfKind::TypeTag { name, .. } => name.clone(),
            BtfKind::Struct { name, .. }
            | BtfKind::Union { name, .. }
            | BtfKind::Enum { name, .. }
            | BtfKind::Enum64 { name, .. } => name.clone().unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// Compute the byte size of a type, with cycle detection.
    pub fn get_size(&self, id: BtfTypeId) -> Result<u32, UnmarshalError> {
        let mut visited = HashSet::new();
        self.get_size_inner(id, &mut visited)
    }

    fn get_size_inner(
        &self,
        id: BtfTypeId,
        visited: &mut HashSet<BtfTypeId>,
    ) -> Result<u32, UnmarshalError> {
        if !visited.insert(id) {
            // Cycle detected — return 0 to break recursion (matching C++)
            return Ok(0);
        }
        let kind = self.get_kind(id)?;
        let result = match kind {
            BtfKind::Ptr { .. } => size_of::<*const ()>() as u32,
            BtfKind::Int { size_in_bytes, .. } => *size_in_bytes,
            BtfKind::Struct { size_in_bytes, .. } => *size_in_bytes,
            BtfKind::Union { size_in_bytes, .. } => *size_in_bytes,
            BtfKind::Enum { size_in_bytes, .. } => *size_in_bytes,
            BtfKind::Enum64 { size_in_bytes, .. } => *size_in_bytes,
            BtfKind::Float { size_in_bytes, .. } => *size_in_bytes,
            BtfKind::Array {
                element_type,
                count_of_elements,
                ..
            } => {
                let elem_size = self.get_size_inner(*element_type, visited)?;
                count_of_elements.checked_mul(elem_size).unwrap_or(0)
            }
            BtfKind::Typedef { type_id, .. }
            | BtfKind::Volatile { type_id }
            | BtfKind::Const { type_id }
            | BtfKind::Restrict { type_id }
            | BtfKind::Var { type_id, .. }
            | BtfKind::DeclTag { type_id, .. }
            | BtfKind::TypeTag { type_id, .. } => self.get_size_inner(*type_id, visited)?,
            BtfKind::Void
            | BtfKind::Fwd { .. }
            | BtfKind::Function { .. }
            | BtfKind::FunctionPrototype { .. }
            | BtfKind::DataSection { .. } => 0,
        };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_data_from_elf() {
        let Some(btf_data) =
            super::super::load_btf_section_from_elf("tests/upstream/ebpf-samples/build/byteswap.o")
        else {
            return;
        };

        let td = BtfTypeData::new(&btf_data).unwrap();

        // void is always present
        let void_kind = td.get_kind(0).unwrap();
        assert!(matches!(void_kind, BtfKind::Void));

        // "int" should be present in most BPF programs
        let int_id = td.get_id("int");
        if int_id != 0 {
            let int_kind = td.get_kind(int_id).unwrap();
            assert!(matches!(int_kind, BtfKind::Int { .. }));
            let size = td.get_size(int_id).unwrap();
            assert_eq!(size, 4);
        }
    }
}
