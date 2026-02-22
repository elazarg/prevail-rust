// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Variable name registry (interning factory).
//!
//! Ported from `src/crab/var_registry.hpp` and `src/crab/var_registry.cpp`.

use std::collections::HashMap;

use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::crab::type_encoding::{DataKind, name_of};

const STACK_FRAME_DELIMITER: char = '/';

/// Per-variable metadata, stored at registration time to avoid string classification.
#[derive(Clone, Copy, Debug, Default)]
struct VarMetadata {
    /// The data kind (e.g. Svalues, Types), if this variable has one.
    kind: Option<DataKind>,
    /// Whether this is a stack cell variable (e.g. `s[10].svalue`).
    is_stack_cell: bool,
    /// Whether this is a loop counter variable (e.g. `pc[42]`).
    is_loop_counter: bool,
    /// Whether only the lower bound of this variable is semantically meaningful.
    is_min_only: bool,
}

/// A factory that maps string names to [`Variable`] IDs.
///
/// Construction pre-fills 184 default register-derived names. Additional names are
/// interned on demand via the various `make`/`reg`/`cell_var`/… methods.
///
/// Unlike the C++ version this is **not** a thread-local singleton. Consumers pass
/// `&mut VariableRegistry` explicitly.
pub struct VariableRegistry {
    names: Vec<String>,
    metadata: Vec<VarMetadata>,
    index: HashMap<String, u64>,
}

/// The per-register data kinds used in the default variable list, in order.
const DEFAULT_REG_KINDS: [DataKind; 15] = [
    DataKind::Svalues,
    DataKind::Uvalues,
    DataKind::CtxOffsets,
    DataKind::MapFds,
    DataKind::MapFdPrograms,
    DataKind::PacketOffsets,
    DataKind::SharedOffsets,
    DataKind::StackOffsets,
    DataKind::Types,
    DataKind::SharedRegionSizes,
    DataKind::StackNumericSizes,
    DataKind::SocketOffsets,
    DataKind::BtfIdOffsets,
    DataKind::AllocMemOffsets,
    DataKind::AllocMemSizes,
];

fn default_variables() -> (Vec<String>, Vec<VarMetadata>) {
    // 12 registers (r0-r10 + r11 atomic scratch) × 15 kinds + 4 specials = 184
    let mut names = Vec::with_capacity(184);
    let mut metadata = Vec::with_capacity(184);
    for i in 0..=11 {
        for &kind in &DEFAULT_REG_KINDS {
            names.push(format!("r{i}.{}", name_of(kind)));
            metadata.push(VarMetadata {
                kind: Some(kind),
                is_stack_cell: false,
                is_loop_counter: false,
                is_min_only: matches!(
                    kind,
                    DataKind::StackNumericSizes | DataKind::SharedRegionSizes
                ),
            });
        }
    }
    for special in ["data_size", "meta_size", "meta_offset"] {
        names.push(special.to_string());
        metadata.push(VarMetadata::default());
    }
    names.push("packet_size".to_string());
    metadata.push(VarMetadata {
        is_min_only: true,
        ..VarMetadata::default()
    });
    debug_assert_eq!(names.len(), 184);
    debug_assert_eq!(metadata.len(), 184);
    (names, metadata)
}

impl VariableRegistry {
    pub fn new() -> Self {
        let (names, metadata) = default_variables();
        let index: HashMap<String, u64> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.clone(), i as u64))
            .collect();
        VariableRegistry {
            names,
            metadata,
            index,
        }
    }

    /// Intern a name with metadata: find existing or append new.
    fn register(&mut self, name: &str, meta: VarMetadata) -> Variable {
        if let Some(&id) = self.index.get(name) {
            Variable::new(id)
        } else {
            let id = self.names.len() as u64;
            self.index.insert(name.to_string(), id);
            self.names.push(name.to_string());
            self.metadata.push(meta);
            Variable::new(id)
        }
    }

    /// Intern a name without specific metadata. Used for special/unknown variables.
    fn make(&mut self, name: &str) -> Variable {
        self.register(name, VarMetadata::default())
    }

    /// Look up the name of a variable by its ID.
    pub fn name(&self, v: Variable) -> &str {
        &self.names[v.id() as usize]
    }

    /// Immutable lookup: returns the variable for a name that was previously registered.
    /// Panics if the name is not found.
    pub fn get(&self, name: &str) -> Variable {
        Variable::new(
            *self
                .index
                .get(name)
                .unwrap_or_else(|| panic!("Variable '{name}' not registered")),
        )
    }

    /// Immutable lookup for `r{i}.{kind_name}`. Panics if not pre-registered.
    pub fn reg_ref(&self, kind: DataKind, i: i32) -> Variable {
        let name = format!("r{i}.{}", name_of(kind));
        self.get(&name)
    }

    fn meta_for_kind(kind: DataKind, is_stack_cell: bool) -> VarMetadata {
        VarMetadata {
            kind: Some(kind),
            is_stack_cell,
            is_loop_counter: false,
            is_min_only: matches!(
                kind,
                DataKind::StackNumericSizes | DataKind::SharedRegionSizes
            ),
        }
    }

    /// Get/create the variable `r{i}.{kind_name}`.
    pub fn reg(&mut self, kind: DataKind, i: i32) -> Variable {
        let name = format!("r{i}.{}", name_of(kind));
        self.register(&name, Self::meta_for_kind(kind, false))
    }

    /// Get/create the variable `r{i}.type`.
    pub fn type_reg(&mut self, i: i32) -> Variable {
        self.reg(DataKind::Types, i)
    }

    /// Get/create the variable `{prefix}/r{i}.{kind_name}`.
    pub fn stack_frame_var(&mut self, kind: DataKind, i: i32, prefix: &str) -> Variable {
        let name = format!("{prefix}{STACK_FRAME_DELIMITER}r{i}.{}", name_of(kind));
        self.register(&name, Self::meta_for_kind(kind, false))
    }

    /// Get/create a stack cell variable like `s[{offset}...{offset+size-1}].{kind}`
    /// (or `s[{offset}].{kind}` when `size` is 1).
    pub fn cell_var(&mut self, array: DataKind, offset: &Number, size: &Number) -> Variable {
        let o = offset.cast_to_unsigned_width(64);
        let name = if *size != Number::from(1) {
            let end = o + size - Number::from(1);
            format!("s[{o}...{end}].{}", name_of(array))
        } else {
            format!("s[{o}].{}", name_of(array))
        };
        self.register(&name, Self::meta_for_kind(array, true))
    }

    /// Get/create a stack cell variable by integer offset and size.
    pub fn cell_var_int(&mut self, kind: DataKind, offset: u64, size: u32) -> Variable {
        let o = Number::from(offset as i64);
        let s = Number::from(size as i64);
        self.cell_var(kind, &o, &s)
    }

    /// Get/create the variable `r{i}.map_fd_programs`.
    pub fn map_fd_programs_reg(&mut self, i: i32) -> Variable {
        self.reg(DataKind::MapFdPrograms, i)
    }

    /// Given a type variable, derive the variable of a different `kind` by replacing
    /// the suffix after the last dot.
    ///
    /// Panics if the variable's name does not contain a dot.
    pub fn kind_var(&mut self, kind: DataKind, type_variable: Variable) -> Variable {
        let is_stack = self.metadata[type_variable.id() as usize].is_stack_cell;
        let var_name = self.name(type_variable).to_string();
        let dot_pos = var_name
            .rfind('.')
            .unwrap_or_else(|| panic!("Variable name '{var_name}' does not contain a dot"));
        let name = format!("{}.{}", &var_name[..dot_pos], name_of(kind));
        self.register(&name, Self::meta_for_kind(kind, is_stack))
    }

    pub fn meta_offset(&mut self) -> Variable {
        self.make("meta_offset")
    }

    pub fn packet_size(&mut self) -> Variable {
        self.register(
            "packet_size",
            VarMetadata {
                is_min_only: true,
                ..VarMetadata::default()
            },
        )
    }

    /// Create a loop iteration counter variable for the given label.
    pub fn loop_counter(&mut self, label: &str) -> Variable {
        let name = format!("pc[{label}]");
        self.register(
            &name,
            VarMetadata {
                is_loop_counter: true,
                ..VarMetadata::default()
            },
        )
    }

    /// Whether the variable represents a `.type` field.
    pub fn is_type(&self, v: Variable) -> bool {
        self.metadata[v.id() as usize].kind == Some(DataKind::Types)
    }

    /// Whether the variable represents a `.uvalue` field.
    pub fn is_unsigned(&self, v: Variable) -> bool {
        self.metadata[v.id() as usize].kind == Some(DataKind::Uvalues)
    }

    /// Whether the variable is a stack cell (name starts with `'s'`).
    pub fn is_in_stack(&self, v: Variable) -> bool {
        self.metadata[v.id() as usize].is_stack_cell
    }

    /// Whether only the lower bound of this variable is semantically meaningful.
    pub fn is_min_only(&self, v: Variable) -> bool {
        self.metadata[v.id() as usize].is_min_only
    }

    /// Return all registered type variables.
    pub fn get_type_variables(&self) -> Vec<Variable> {
        self.metadata
            .iter()
            .enumerate()
            .filter(|(_, m)| m.kind == Some(DataKind::Types))
            .map(|(i, _)| Variable::new(i as u64))
            .collect()
    }

    /// Return all registered loop counter variables.
    pub fn get_loop_counters(&self) -> Vec<Variable> {
        self.metadata
            .iter()
            .enumerate()
            .filter(|(_, m)| m.is_loop_counter)
            .map(|(i, _)| Variable::new(i as u64))
            .collect()
    }

    /// Compare two variables by name, for printing purposes.
    pub fn printing_order(&self, a: Variable, b: Variable) -> std::cmp::Ordering {
        self.name(a).cmp(self.name(b))
    }
}

impl Default for VariableRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crab::type_encoding::DataKind;

    #[test]
    fn test_default_construction_size() {
        let reg = VariableRegistry::new();
        assert_eq!(reg.names.len(), 184);
        assert_eq!(reg.metadata.len(), 184);
    }

    #[test]
    fn test_default_first_and_last() {
        let reg = VariableRegistry::new();
        assert_eq!(reg.names[0], "r0.svalue");
        assert_eq!(reg.names[183], "packet_size");
    }

    #[test]
    fn test_default_r0_kinds() {
        let reg = VariableRegistry::new();
        let r0_names: Vec<&str> = reg.names[0..15].iter().map(|s| s.as_str()).collect();
        assert_eq!(
            r0_names,
            vec![
                "r0.svalue",
                "r0.uvalue",
                "r0.ctx_offset",
                "r0.map_fd",
                "r0.map_fd_programs",
                "r0.packet_offset",
                "r0.shared_offset",
                "r0.stack_offset",
                "r0.type",
                "r0.shared_region_size",
                "r0.stack_numeric_size",
                "r0.socket_offset",
                "r0.btf_id_offset",
                "r0.alloc_mem_offset",
                "r0.alloc_mem_size",
            ]
        );
    }

    #[test]
    fn test_default_trailer_names() {
        let reg = VariableRegistry::new();
        assert_eq!(reg.names[180], "data_size");
        assert_eq!(reg.names[181], "meta_size");
        assert_eq!(reg.names[182], "meta_offset");
        assert_eq!(reg.names[183], "packet_size");
    }

    #[test]
    fn test_reg_produces_correct_name() {
        let mut reg = VariableRegistry::new();
        let v = reg.reg(DataKind::Svalues, 3);
        assert_eq!(reg.name(v), "r3.svalue");
    }

    #[test]
    fn test_type_reg_produces_correct_name() {
        let mut reg = VariableRegistry::new();
        let v = reg.type_reg(5);
        assert_eq!(reg.name(v), "r5.type");
    }

    #[test]
    fn test_stack_frame_var() {
        let mut reg = VariableRegistry::new();
        let v = reg.stack_frame_var(DataKind::Svalues, 1, "caller");
        assert_eq!(reg.name(v), "caller/r1.svalue");
    }

    #[test]
    fn test_cell_var_size_one() {
        let mut reg = VariableRegistry::new();
        let v = reg.cell_var(DataKind::Svalues, &Number::from(10), &Number::from(1));
        assert_eq!(reg.name(v), "s[10].svalue");
    }

    #[test]
    fn test_cell_var_size_multi() {
        let mut reg = VariableRegistry::new();
        let v = reg.cell_var(DataKind::Uvalues, &Number::from(4), &Number::from(8));
        assert_eq!(reg.name(v), "s[4...11].uvalue");
    }

    #[test]
    fn test_kind_var() {
        let mut reg = VariableRegistry::new();
        let type_var = reg.type_reg(2);
        assert_eq!(reg.name(type_var), "r2.type");
        let svalue_var = reg.kind_var(DataKind::Svalues, type_var);
        assert_eq!(reg.name(svalue_var), "r2.svalue");
    }

    #[test]
    #[should_panic(expected = "does not contain a dot")]
    fn test_kind_var_no_dot_panics() {
        let mut reg = VariableRegistry::new();
        let v = reg.make("nodot");
        reg.kind_var(DataKind::Types, v);
    }

    #[test]
    fn test_make_deduplicates() {
        let mut reg = VariableRegistry::new();
        let a = reg.make("r0.svalue");
        let b = reg.make("r0.svalue");
        assert_eq!(a, b);
        assert_eq!(reg.names.len(), 184); // no new entries
    }

    #[test]
    fn test_make_new_name() {
        let mut reg = VariableRegistry::new();
        let v = reg.make("custom_var");
        assert_eq!(v.id(), 184);
        assert_eq!(reg.name(v), "custom_var");
    }

    #[test]
    fn test_meta_offset() {
        let mut reg = VariableRegistry::new();
        let v = reg.meta_offset();
        assert_eq!(reg.name(v), "meta_offset");
        // Should reuse the pre-existing entry.
        assert_eq!(v.id(), 182);
    }

    #[test]
    fn test_packet_size() {
        let mut reg = VariableRegistry::new();
        let v = reg.packet_size();
        assert_eq!(reg.name(v), "packet_size");
        assert_eq!(v.id(), 183);
    }

    #[test]
    fn test_loop_counter() {
        let mut reg = VariableRegistry::new();
        let v = reg.loop_counter("42");
        assert_eq!(reg.name(v), "pc[42]");
    }

    #[test]
    fn test_is_type() {
        let mut reg = VariableRegistry::new();
        let type_var = reg.type_reg(0);
        let sval_var = reg.reg(DataKind::Svalues, 0);
        assert!(reg.is_type(type_var));
        assert!(!reg.is_type(sval_var));
    }

    #[test]
    fn test_is_unsigned() {
        let mut reg = VariableRegistry::new();
        let uval = reg.reg(DataKind::Uvalues, 3);
        let sval = reg.reg(DataKind::Svalues, 3);
        assert!(reg.is_unsigned(uval));
        assert!(!reg.is_unsigned(sval));
    }

    #[test]
    fn test_is_in_stack() {
        let mut reg = VariableRegistry::new();
        let stack_var = reg.cell_var(DataKind::Svalues, &Number::from(0), &Number::from(1));
        let reg_var = reg.reg(DataKind::Svalues, 0);
        assert!(reg.is_in_stack(stack_var));
        assert!(!reg.is_in_stack(reg_var));
    }

    #[test]
    fn test_is_min_only() {
        let mut reg = VariableRegistry::new();
        let stack_num = reg.reg(DataKind::StackNumericSizes, 0);
        let shared_reg = reg.reg(DataKind::SharedRegionSizes, 0);
        let alloc_mem = reg.reg(DataKind::AllocMemSizes, 0);
        let pkt = reg.packet_size();
        let sval = reg.reg(DataKind::Svalues, 0);

        assert!(reg.is_min_only(stack_num));
        assert!(reg.is_min_only(shared_reg));
        assert!(!reg.is_min_only(alloc_mem));
        assert!(reg.is_min_only(pkt));
        assert!(!reg.is_min_only(sval));
    }

    #[test]
    fn test_get_type_variables() {
        let reg = VariableRegistry::new();
        let type_vars = reg.get_type_variables();
        // r0..r11 → 12 type variables (includes r11 atomic scratch)
        assert_eq!(type_vars.len(), 12);
        for (i, v) in type_vars.iter().enumerate() {
            assert_eq!(reg.name(*v), format!("r{i}.type"));
        }
    }

    #[test]
    fn test_get_loop_counters() {
        let mut reg = VariableRegistry::new();
        assert!(reg.get_loop_counters().is_empty());

        reg.loop_counter("1");
        reg.loop_counter("2");
        let counters = reg.get_loop_counters();
        assert_eq!(counters.len(), 2);
        assert_eq!(reg.name(counters[0]), "pc[1]");
        assert_eq!(reg.name(counters[1]), "pc[2]");
    }

    #[test]
    fn test_printing_order() {
        let mut reg = VariableRegistry::new();
        let a = reg.reg(DataKind::Svalues, 0);
        let b = reg.reg(DataKind::Uvalues, 0);
        // "r0.svalue" < "r0.uvalue"
        assert_eq!(reg.printing_order(a, b), std::cmp::Ordering::Less);
        assert_eq!(reg.printing_order(b, a), std::cmp::Ordering::Greater);
        assert_eq!(reg.printing_order(a, a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn test_metadata_for_default_register() {
        let reg = VariableRegistry::new();
        // r0.svalue → kind=Svalues, not stack, not min_only
        assert_eq!(reg.metadata[0].kind, Some(DataKind::Svalues));
        assert!(!reg.metadata[0].is_stack_cell);
        assert!(!reg.metadata[0].is_min_only);
        // r0.type → kind=Types (index 8 with 15 kinds per register)
        assert_eq!(reg.metadata[8].kind, Some(DataKind::Types));
        // r0.stack_numeric_size → min_only (index 10)
        assert!(reg.metadata[10].is_min_only);
        // r0.alloc_mem_size → NOT min_only (index 14)
        assert!(!reg.metadata[14].is_min_only);
        // packet_size → min_only, no kind (index 183)
        assert!(reg.metadata[183].is_min_only);
        assert_eq!(reg.metadata[183].kind, None);
    }

    #[test]
    fn test_metadata_for_stack_cell() {
        let mut reg = VariableRegistry::new();
        let v = reg.cell_var(DataKind::Svalues, &Number::from(10), &Number::from(1));
        let meta = reg.metadata[v.id() as usize];
        assert!(meta.is_stack_cell);
        assert_eq!(meta.kind, Some(DataKind::Svalues));
        assert!(!meta.is_min_only);
    }

    #[test]
    fn test_metadata_for_loop_counter() {
        let mut reg = VariableRegistry::new();
        let v = reg.loop_counter("42");
        let meta = reg.metadata[v.id() as usize];
        assert!(meta.is_loop_counter);
        assert_eq!(meta.kind, None);
    }
}
