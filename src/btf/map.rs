// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! BTF map section parsing.
//!
//! Ports `external/libbtf/libbtf/btf_map.cpp` (read-only subset).

use std::collections::BTreeSet;

use super::type_data::BtfTypeData;
use super::{BtfKind, BtfKindIndex, BtfMapDefinition, BtfTypeId, UnmarshalError};

/// Decode the `__uint(name, val)` BPF macro encoding.
///
/// The macro expands to `int (*name)[val]`, so the BTF type is a pointer to
/// an array whose element count encodes the value.
fn value_from_btf_uint(btf_data: &BtfTypeData, type_id: BtfTypeId) -> Result<u32, UnmarshalError> {
    // Top level should be a pointer. Dereference it.
    let array_id = btf_data.dereference_pointer(type_id)?;
    // Value is encoded in the count of elements.
    match btf_data.get_array(array_id)? {
        BtfKind::Array {
            count_of_elements, ..
        } => Ok(*count_of_elements),
        _ => unreachable!(),
    }
}

/// Strip typedef/const/volatile/restrict wrappers to find the underlying type.
fn unwrap_type(
    btf_data: &BtfTypeData,
    mut type_id: BtfTypeId,
) -> Result<BtfTypeId, UnmarshalError> {
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(type_id) {
            // Cycle detected — return current type_id
            return Ok(type_id);
        }
        match btf_data.get_kind_index(type_id)? {
            BtfKindIndex::Typedef => {
                if let BtfKind::Typedef { type_id: inner, .. } = btf_data.get_kind(type_id)? {
                    type_id = *inner;
                }
            }
            BtfKindIndex::Const => {
                if let BtfKind::Const { type_id: inner } = btf_data.get_kind(type_id)? {
                    type_id = *inner;
                }
            }
            BtfKindIndex::Volatile => {
                if let BtfKind::Volatile { type_id: inner } = btf_data.get_kind(type_id)? {
                    type_id = *inner;
                }
            }
            BtfKindIndex::Restrict => {
                if let BtfKind::Restrict { type_id: inner } = btf_data.get_kind(type_id)? {
                    type_id = *inner;
                }
            }
            _ => return Ok(type_id),
        }
    }
}

/// Check if a type is a BPF map definition struct (has "type" and "max_entries" fields).
fn is_map_type(btf_data: &BtfTypeData, type_id: BtfTypeId) -> Result<bool, UnmarshalError> {
    if btf_data.get_kind_index(type_id)? != BtfKindIndex::Struct {
        return Ok(false);
    }
    let BtfKind::Struct { members, .. } = btf_data.get_kind(type_id)? else {
        return Ok(false);
    };
    let mut has_type = false;
    let mut has_max_entries = false;
    for m in members {
        match m.name.as_deref() {
            Some("type") => has_type = true,
            Some("max_entries") => has_max_entries = true,
            _ => {}
        }
    }
    Ok(has_type && has_max_entries)
}

/// Extract a map definition from a struct type.
fn get_map_definition_from_btf(
    btf_data: &BtfTypeData,
    name: &str,
    map_type_id: BtfTypeId,
) -> Result<BtfMapDefinition, UnmarshalError> {
    let map_type_id = unwrap_type(btf_data, map_type_id)?;

    let BtfKind::Struct { members, .. } = btf_data.get_struct(map_type_id)? else {
        unreachable!()
    };

    let mut type_field: BtfTypeId = 0;
    let mut max_entries_field: BtfTypeId = 0;
    let mut key_field: BtfTypeId = 0;
    let mut key_size_field: BtfTypeId = 0;
    let mut value_field: BtfTypeId = 0;
    let mut value_size_field: BtfTypeId = 0;
    let mut values_field: BtfTypeId = 0;

    for m in members {
        match m.name.as_deref() {
            Some("type") => type_field = m.type_id,
            Some("max_entries") => max_entries_field = m.type_id,
            Some("key") => key_field = btf_data.dereference_pointer(m.type_id)?,
            Some("value") => value_field = btf_data.dereference_pointer(m.type_id)?,
            Some("key_size") => key_size_field = m.type_id,
            Some("value_size") => value_size_field = m.type_id,
            Some("values") => values_field = m.type_id,
            _ => {}
        }
    }

    if type_field == 0 {
        return Err(UnmarshalError("invalid map type".into()));
    }

    let mut def = BtfMapDefinition {
        name: name.to_string(),
        type_id: map_type_id,
        map_type: value_from_btf_uint(btf_data, type_field)?,
        ..Default::default()
    };

    if max_entries_field != 0 {
        def.max_entries = value_from_btf_uint(btf_data, max_entries_field)?;
    }

    if key_field != 0 {
        let key_size = btf_data.get_size(key_field)?;
        if key_size == 0 {
            let mut type_name = btf_data.get_type_name(key_field);
            if type_name.is_empty() {
                type_name = format!("type_id={key_field}");
            }
            return Err(UnmarshalError(format!(
                "map '{name}': cannot determine key size for type '{type_name}'"
            )));
        }
        def.key_size = key_size;
    } else if key_size_field != 0 {
        def.key_size = value_from_btf_uint(btf_data, key_size_field)?;
    }

    if value_field != 0 {
        let value_size = btf_data.get_size(value_field)?;
        if value_size == 0 {
            let mut type_name = btf_data.get_type_name(value_field);
            if type_name.is_empty() {
                type_name = format!("type_id={value_field}");
            }
            return Err(UnmarshalError(format!(
                "map '{name}': cannot determine value size for type '{type_name}'"
            )));
        }
        def.value_size = value_size;
    } else if value_size_field != 0 {
        def.value_size = value_from_btf_uint(btf_data, value_size_field)?;
    }

    if values_field != 0
        && let BtfKind::Array { element_type, .. } = btf_data.get_array(values_field)?
    {
        // Values is an array of pointers to BTF map definitions or function prototypes.
        let ptr_type_id = btf_data.dereference_pointer(*element_type)?;
        let inner_map_type_id = unwrap_type(btf_data, ptr_type_id)?;

        if is_map_type(btf_data, inner_map_type_id)? {
            def.inner_map_type_id = inner_map_type_id;
            def.value_size = 4; // size of a map id (uint32_t)
        } else if btf_data.get_kind_index(inner_map_type_id)? == BtfKindIndex::FunctionPrototype {
            def.value_size = 4; // size of a program id (uint32_t)
        } else {
            return Err(UnmarshalError("invalid type for values".into()));
        }
    }

    Ok(def)
}

/// Parse BTF map definitions from the `.maps` DATASEC and global variable sections.
pub fn parse_btf_map_section(
    btf_data: &BtfTypeData,
) -> Result<Vec<BtfMapDefinition>, UnmarshalError> {
    // Use Vec to allow duplicate type_ids from shared typedefs.
    // C++ uses std::multimap which keeps all entries; BTreeMap would silently
    // overwrite duplicates (e.g. outer_map_1 and outer_map_2 sharing outer_map_t).
    let mut map_definitions: Vec<BtfMapDefinition> = Vec::new();

    // Parse .maps DATASEC if present
    let maps_id = btf_data.get_id(".maps");
    if maps_id != 0 {
        let mut inner_map_type_ids = BTreeSet::new();

        let maps_section = btf_data.get_data_section(maps_id)?;
        let BtfKind::DataSection { members, .. } = maps_section else {
            unreachable!()
        };

        let handle_map_type_id =
            |btf_data: &BtfTypeData,
             name: &str,
             map_type_id: BtfTypeId,
             defs: &mut Vec<BtfMapDefinition>,
             inner_ids: &mut BTreeSet<BtfTypeId>| {
                let def = get_map_definition_from_btf(btf_data, name, map_type_id)?;
                if def.inner_map_type_id != 0 {
                    inner_ids.insert(def.inner_map_type_id);
                }
                defs.push(def);
                Ok::<(), UnmarshalError>(())
            };

        // Add all maps in the .maps data section
        for var in members {
            let (var_name, var_type_id) = btf_data.get_var(var.type_id)?;
            handle_map_type_id(
                btf_data,
                var_name,
                var_type_id,
                &mut map_definitions,
                &mut inner_map_type_ids,
            )?;
        }

        // Recursively add inner maps (up to 2 levels, matching Linux BPF verifier limit)
        for _level in 0..2 {
            let ids_to_process: Vec<_> = inner_map_type_ids
                .iter()
                .filter(|id| {
                    // Skip if already present in map_definitions (matching C++ multimap::find check)
                    !map_definitions.iter().any(|d| d.type_id == **id)
                })
                .copied()
                .collect();
            for map_type_id in ids_to_process {
                handle_map_type_id(
                    btf_data,
                    "",
                    map_type_id,
                    &mut map_definitions,
                    &mut inner_map_type_ids,
                )?;
            }
        }
    }

    // Add array maps for global data sections (.bss, .data, .rodata)
    for section_name in &[".bss", ".data", ".rodata"] {
        let id = btf_data.get_id(section_name);
        if id == 0 {
            continue;
        }
        if let BtfKind::DataSection { name, members, .. } = btf_data.get_data_section(id)? {
            if members.is_empty() {
                continue;
            }
            let last = members.last().unwrap();
            let def = BtfMapDefinition {
                name: name.clone(),
                type_id: id,
                key_size: 4, // sizeof(uint32_t)
                value_size: last.offset + last.size,
                max_entries: 1,
                ..Default::default()
            };
            map_definitions.push(def);
        }
    }

    // Sort by type_id to match C++ std::multimap ordering.
    map_definitions.sort_by_key(|d| d.type_id);

    Ok(map_definitions)
}
