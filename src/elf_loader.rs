// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! ELF file parser for BPF programs.
//!
//! Ports `src/elf_loader.cpp`.  Uses the `object` crate for zero-copy ELF
//! parsing instead of ELFIO.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::mem;

use object::elf;
use object::read::elf::{
    ElfFile, FileHeader, Rel as RelTrait, Rela as RelaTrait, SectionHeader, Sym as SymTrait,
};
use object::{LittleEndian, Object, ObjectSection};

use crate::btf::type_data::BtfTypeData;
use crate::platform::EbpfPlatform;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::type_descriptors::{BtfLineInfo, EbpfMapDescriptor, ProgramInfo, RawProgram};
use crate::spec::vm_isa::{
    EbpfInst, INST_CALL_LOCAL, INST_CLS_LD, INST_CLS_MASK, INST_LD_MODE_MAP_FD,
    INST_LD_MODE_MAP_VALUE, INST_OP_CALL,
};

// ── Convenience aliases ─────────────────────────────────────────────

type Elf64 = elf::FileHeader64<LittleEndian>;
type SymbolTable<'data> = object::read::elf::SymbolTable<'data, Elf64>;

const ENDIAN: LittleEndian = LittleEndian;

// ── Error type ──────────────────────────────────────────────────────

/// Error returned when ELF unmarshalling fails.
#[derive(Debug)]
pub struct UnmarshalError(pub String);

impl fmt::Display for UnmarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UnmarshalError {}

// ── Helpers ─────────────────────────────────────────────────────────

const DEFAULT_MAP_FD: i32 = -1;

fn is_map_section(name: &str) -> bool {
    name == "maps" || (name.len() > 5 && name.starts_with("maps/"))
}

fn is_global_section(name: &str) -> bool {
    name == ".data"
        || name == ".rodata"
        || name == ".bss"
        || name.starts_with(".data.")
        || name.starts_with(".rodata.")
        || name.starts_with(".bss.")
}

/// Cast a byte slice to a vector of `EbpfInst`, reading fields in little-endian.
fn bytes_to_instructions(data: &[u8]) -> Result<Vec<EbpfInst>, UnmarshalError> {
    let inst_size = mem::size_of::<EbpfInst>();
    if !data.len().is_multiple_of(inst_size) {
        return Err(UnmarshalError(
            "Section size is not a multiple of instruction size".into(),
        ));
    }
    let count = data.len() / inst_size;
    let mut instructions = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * inst_size;
        instructions.push(EbpfInst {
            opcode: data[off],
            dst_src: data[off + 1],
            offset: i16::from_le_bytes([data[off + 2], data[off + 3]]),
            imm: i32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]),
        });
    }
    Ok(instructions)
}

// ── Map resolution strategy ─────────────────────────────────────────

type MapOffsets = BTreeMap<String, usize>;

enum MapResolution {
    /// Legacy mode — retained for future legacy-record-size path.
    #[expect(dead_code)]
    Legacy(usize),
    /// Name-based lookup from map/section name to descriptor index.
    Named(MapOffsets),
}

// ── Global data extracted from ELF ──────────────────────────────────

struct ElfGlobalData {
    map_section_indices: BTreeSet<usize>,
    map_descriptors: Vec<EbpfMapDescriptor>,
    map_resolution: MapResolution,
    variable_section_indices: BTreeSet<usize>,
}

impl Default for ElfGlobalData {
    fn default() -> Self {
        Self {
            map_section_indices: BTreeSet::new(),
            map_descriptors: Vec::new(),
            map_resolution: MapResolution::Named(BTreeMap::new()),
            variable_section_indices: BTreeSet::new(),
        }
    }
}

// ── Symbol details ──────────────────────────────────────────────────

struct SymbolDetails {
    name: String,
    value: u64,
    sym_type: u8,
    section_index: usize,
}

fn get_symbol_details(
    symbols: &SymbolTable<'_>,
    index: usize,
) -> Result<SymbolDetails, UnmarshalError> {
    let sym = symbols
        .symbol(object::SymbolIndex(index))
        .map_err(|e| UnmarshalError(format!("Invalid symbol index {index}: {e}")))?;
    let name_bytes = symbols
        .strings()
        .get(sym.st_name(ENDIAN))
        .map_err(|_| UnmarshalError(format!("Invalid symbol name at index {index}")))?;
    let name = std::str::from_utf8(name_bytes)
        .map_err(|e| UnmarshalError(format!("Non-UTF8 symbol name at index {index}: {e}")))?
        .to_string();
    Ok(SymbolDetails {
        name,
        value: sym.st_value(ENDIAN),
        sym_type: sym.st_type(),
        section_index: sym.st_shndx(ENDIAN) as usize,
    })
}

// ── Function relocation record ──────────────────────────────────────

struct FunctionRelocation {
    prog_index: usize,
    source_offset: usize,
    relocation_entry_index: usize,
    target_function_name: String,
}

// ── LDDW validation ────────────────────────────────────────────────

const BPF_LDDW: u8 = 0x18;
const BPF_LDDW_HI: u8 = 0x00;

fn validate_lddw_pair(
    instructions: &[EbpfInst],
    location: usize,
    context: &str,
) -> Result<(), UnmarshalError> {
    if instructions.len() <= location + 1 {
        return Err(UnmarshalError(format!(
            "Invalid relocation: {context} reference at instruction boundary"
        )));
    }
    if instructions[location].opcode != BPF_LDDW {
        return Err(UnmarshalError(format!(
            "Invalid relocation: expected LDDW first slot (opcode 0x18) for {context}, \
             found opcode {:#04x}",
            instructions[location].opcode
        )));
    }
    if instructions[location + 1].opcode != BPF_LDDW_HI {
        return Err(UnmarshalError(format!(
            "Invalid relocation: expected LDDW second slot (opcode 0x00) for {context}, \
             found opcode {:#04x}",
            instructions[location + 1].opcode
        )));
    }
    Ok(())
}

// ── Global data extraction ──────────────────────────────────────────

/// Collect global variable sections (.data, .rodata, .bss).
fn collect_global_sections(elf: &ElfFile<'_, Elf64>) -> Vec<(usize, String, u64)> {
    let mut result = Vec::new();
    for section in elf.sections() {
        let name = match section.name() {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };
        if !is_global_section(&name) {
            continue;
        }
        let sh = section.elf_section_header();
        let sh_type = sh.sh_type(ENDIAN);
        let size = section.size();
        if sh_type == elf::SHT_NOBITS || (sh_type == elf::SHT_PROGBITS && size != 0) {
            result.push((section.index().0, name, size));
        }
    }
    result
}

fn add_global_variable_maps(
    elf: &ElfFile<'_, Elf64>,
    global: &mut ElfGlobalData,
    map_offsets: &mut MapOffsets,
) {
    for (sec_idx, sec_name, sec_size) in collect_global_sections(elf) {
        map_offsets.insert(sec_name, global.map_descriptors.len());
        global.map_descriptors.push(EbpfMapDescriptor {
            original_fd: (global.map_descriptors.len() + 1) as i32,
            map_type: 0,
            key_size: 4,
            value_size: sec_size as u32,
            max_entries: 1,
            inner_map_fd: DEFAULT_MAP_FD,
        });
        global.variable_section_indices.insert(sec_idx);
    }
}

fn create_global_variable_maps(elf: &ElfFile<'_, Elf64>) -> ElfGlobalData {
    let mut global = ElfGlobalData::default();
    let mut offsets = MapOffsets::new();
    add_global_variable_maps(elf, &mut global, &mut offsets);
    global.map_resolution = MapResolution::Named(offsets);
    global
}

/// Parse legacy map sections ("maps", "maps/*").
fn parse_map_sections(
    elf: &ElfFile<'_, Elf64>,
    symbols: &SymbolTable<'_>,
    sym_count: usize,
    platform: &mut dyn EbpfPlatform,
    options: &EbpfVerifierOptions,
) -> Result<ElfGlobalData, UnmarshalError> {
    let mut global = ElfGlobalData::default();
    let mut section_record_sizes: BTreeMap<usize, usize> = BTreeMap::new();
    let mut section_base_index: BTreeMap<usize, usize> = BTreeMap::new();

    for section in elf.sections() {
        let sec_name = match section.name() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !is_map_section(sec_name) {
            continue;
        }
        let sec_idx = section.index().0;

        // Count map symbols in this section.
        let mut map_count = 0usize;
        for i in 0..sym_count {
            if let Ok(sd) = get_symbol_details(symbols, i)
                && sd.section_index == sec_idx
                && !sd.name.is_empty()
            {
                map_count += 1;
            }
        }

        global.map_section_indices.insert(sec_idx);

        if map_count == 0 {
            continue;
        }

        let sec_data = section
            .data()
            .map_err(|e| UnmarshalError(format!("Cannot read maps section '{sec_name}': {e}")))?;
        let sec_size = sec_data.len();
        let record_size = sec_size / map_count;

        if record_size == 0 || sec_size % record_size != 0 {
            return Err(UnmarshalError(format!(
                "Malformed legacy maps section: {sec_name}"
            )));
        }

        let base_index = global.map_descriptors.len();
        section_record_sizes.insert(sec_idx, record_size);
        section_base_index.insert(sec_idx, base_index);

        platform.parse_maps_section(
            &mut global.map_descriptors,
            sec_data,
            record_size,
            map_count,
            options,
        );
    }

    platform.resolve_inner_map_references(&mut global.map_descriptors)?;

    // Build name-to-index mapping.
    let mut map_offsets = MapOffsets::new();
    for i in 0..sym_count {
        let sd = match get_symbol_details(symbols, i) {
            Ok(sd) => sd,
            Err(_) => continue,
        };
        if !global.map_section_indices.contains(&sd.section_index) || sd.name.is_empty() {
            continue;
        }
        let record_size = match section_record_sizes.get(&sd.section_index) {
            Some(&rs) => rs,
            None => continue,
        };
        let base_index = match section_base_index.get(&sd.section_index) {
            Some(&bi) => bi,
            None => continue,
        };

        let sym_value = sd.value as usize;
        let sec_size = elf
            .sections()
            .find(|s| s.index().0 == sd.section_index)
            .map(|s| s.size() as usize)
            .unwrap_or(0);

        if record_size > 0 && (!sym_value.is_multiple_of(record_size) || sym_value >= sec_size) {
            return Err(UnmarshalError(format!(
                "Legacy map symbol '{}' has invalid offset: not aligned to \
                 {record_size}-byte boundary or out of section bounds",
                sd.name
            )));
        }

        let local_index = sym_value / record_size;
        let descriptor_index = base_index + local_index;

        if descriptor_index >= global.map_descriptors.len() {
            return Err(UnmarshalError(format!(
                "Legacy map symbol index out of range for: {}",
                sd.name
            )));
        }

        map_offsets.insert(sd.name, descriptor_index);
    }

    add_global_variable_maps(elf, &mut global, &mut map_offsets);
    global.map_resolution = MapResolution::Named(map_offsets);
    Ok(global)
}

/// Remap BTF type IDs to pseudo file descriptors (1, 2, 3…).
fn map_typeid_to_fd(map_descriptors: &[EbpfMapDescriptor]) -> BTreeMap<i32, i32> {
    let mut type_id_to_fd = BTreeMap::new();
    let mut pseudo_fd = 1i32;
    for desc in map_descriptors {
        type_id_to_fd.entry(desc.original_fd).or_insert_with(|| {
            let fd = pseudo_fd;
            pseudo_fd += 1;
            fd
        });
    }
    type_id_to_fd
}

/// Parse BTF-defined maps from the `.BTF` section.
fn parse_btf_section(elf: &ElfFile<'_, Elf64>) -> Result<ElfGlobalData, UnmarshalError> {
    let btf_section = match elf.section_by_name(".BTF") {
        Some(s) => s,
        None => return Ok(ElfGlobalData::default()),
    };
    let btf_bytes = btf_section
        .data()
        .map_err(|e| UnmarshalError(format!("Cannot read .BTF section: {e}")))?;

    let btf_data = BtfTypeData::new(btf_bytes)?;

    let mut global = ElfGlobalData::default();
    let mut map_offsets = MapOffsets::new();

    // Parse BTF-defined maps from the .maps DATASEC
    for map_def in crate::btf::map::parse_btf_map_section(&btf_data)? {
        map_offsets.insert(map_def.name.clone(), global.map_descriptors.len());
        global.map_descriptors.push(EbpfMapDescriptor {
            original_fd: map_def.type_id as i32, // temporary: stores BTF type ID
            map_type: map_def.map_type,
            key_size: map_def.key_size,
            value_size: map_def.value_size,
            max_entries: map_def.max_entries,
            inner_map_fd: if map_def.inner_map_type_id == 0 {
                DEFAULT_MAP_FD
            } else {
                map_def.inner_map_type_id as i32
            },
        });
    }

    // Remap BTF type IDs to pseudo file descriptors
    let type_id_to_fd = map_typeid_to_fd(&global.map_descriptors);
    for desc in &mut global.map_descriptors {
        if let Some(&fd) = type_id_to_fd.get(&desc.original_fd) {
            desc.original_fd = fd;
        } else {
            return Err(UnmarshalError(format!(
                "Unknown map type ID in BTF: {}",
                desc.original_fd
            )));
        }
        if desc.inner_map_fd != DEFAULT_MAP_FD {
            if let Some(&fd) = type_id_to_fd.get(&desc.inner_map_fd) {
                desc.inner_map_fd = fd;
            } else {
                return Err(UnmarshalError(format!(
                    "Unknown inner map type ID in BTF: {}",
                    desc.inner_map_fd
                )));
            }
        }
    }

    // Record the .maps ELF section index if present (used for relocation classification)
    for section in elf.sections() {
        if section.name().is_ok_and(|n| n == ".maps") {
            global.map_section_indices.insert(section.index().0);
        }
    }

    // Add global variable maps
    add_global_variable_maps(elf, &mut global, &mut map_offsets);

    global.map_resolution = MapResolution::Named(map_offsets);
    Ok(global)
}

fn extract_global_data(
    elf: &ElfFile<'_, Elf64>,
    symbols: &SymbolTable<'_>,
    sym_count: usize,
    platform: &mut dyn EbpfPlatform,
    options: &EbpfVerifierOptions,
) -> Result<ElfGlobalData, UnmarshalError> {
    let has_legacy_maps = elf.sections().any(|s| s.name().is_ok_and(is_map_section));

    if has_legacy_maps {
        return parse_map_sections(elf, symbols, sym_count, platform, options);
    }

    // Only use BTF for maps if there's no legacy maps section
    let has_btf = elf.section_by_name(".BTF").is_some();
    if has_btf {
        return parse_btf_section(elf);
    }

    // No maps or BTF, but might still have global variables
    Ok(create_global_variable_maps(elf))
}

// ── Program name and size from symbols ──────────────────────────────

fn get_program_name_and_size(
    sec_idx: usize,
    sec_name: &str,
    sec_size: u64,
    start: u64,
    symbols: &SymbolTable<'_>,
    sym_count: usize,
) -> (String, u64) {
    let mut program_name = sec_name.to_string();
    let mut size = sec_size - start;

    for i in 0..sym_count {
        let sd = match get_symbol_details(symbols, i) {
            Ok(sd) => sd,
            Err(_) => continue,
        };
        if sd.section_index != sec_idx || sd.name.is_empty() {
            continue;
        }
        if sd.sym_type != elf::STT_FUNC {
            continue;
        }
        let relocation_offset = sd.value;
        if relocation_offset == start {
            program_name = sd.name;
        } else if relocation_offset > start && relocation_offset < start + size {
            size = relocation_offset - start;
        }
    }
    (program_name, size)
}

// ── ProgramReader ───────────────────────────────────────────────────

struct ProgramReader<'a> {
    path: &'a str,
    options: &'a EbpfVerifierOptions,
    platform: &'a dyn EbpfPlatform,
    desired_section: &'a str,

    elf: &'a ElfFile<'a, Elf64>,
    data: &'a [u8],
    symbols: &'a SymbolTable<'a>,
    sym_count: usize,
    global: &'a ElfGlobalData,

    raw_programs: Vec<RawProgram>,
    function_relocations: Vec<FunctionRelocation>,
    unresolved_symbol_errors: Vec<String>,
}

#[expect(clippy::too_many_arguments)]
impl<'a> ProgramReader<'a> {
    fn new(
        path: &'a str,
        options: &'a EbpfVerifierOptions,
        platform: &'a dyn EbpfPlatform,
        desired_section: &'a str,
        elf: &'a ElfFile<'a, Elf64>,
        data: &'a [u8],
        symbols: &'a SymbolTable<'a>,
        sym_count: usize,
        global: &'a ElfGlobalData,
    ) -> Self {
        Self {
            path,
            options,
            platform,
            desired_section,
            elf,
            data,
            symbols,
            sym_count,
            global,
            raw_programs: Vec::new(),
            function_relocations: Vec::new(),
            unresolved_symbol_errors: Vec::new(),
        }
    }

    // ── Map relocation helpers ──────────────────────────────────────

    fn relocate_map(&self, name: &str, sym_index: usize) -> Result<i32, UnmarshalError> {
        let val = match &self.global.map_resolution {
            MapResolution::Legacy(record_size) => {
                let sd = get_symbol_details(self.symbols, sym_index)?;
                let symbol_value = sd.value as usize;
                if *record_size > 0 && !symbol_value.is_multiple_of(*record_size) {
                    return Err(UnmarshalError(format!(
                        "Map symbol offset {symbol_value} is not aligned to record size \
                         {record_size}"
                    )));
                }
                symbol_value / record_size
            }
            MapResolution::Named(offsets) => *offsets
                .get(name)
                .ok_or_else(|| UnmarshalError(format!("Map descriptor not found: {name}")))?,
        };
        if val >= self.global.map_descriptors.len() {
            return Err(UnmarshalError(format!(
                "Bad reloc value ({val}). Make sure to compile with -O2."
            )));
        }
        Ok(self.global.map_descriptors[val].original_fd)
    }

    fn relocate_global_variable(&self, section_name: &str) -> Result<i32, UnmarshalError> {
        let offsets = match &self.global.map_resolution {
            MapResolution::Named(o) => o,
            _ => return Err(UnmarshalError("Invalid map offsets".into())),
        };
        let val = *offsets
            .get(section_name)
            .ok_or_else(|| UnmarshalError(format!("Map descriptor not found: {section_name}")))?;
        if val >= self.global.map_descriptors.len() {
            return Err(UnmarshalError(format!(
                "Bad reloc value ({val}). Make sure to compile with -O2."
            )));
        }
        Ok(self.global.map_descriptors[val].original_fd)
    }

    fn compute_lddw_reloc_offset_imm(
        &self,
        addend: i64,
        sym_index: usize,
        lo_inst_imm: i32,
    ) -> Result<i32, UnmarshalError> {
        let sd = get_symbol_details(self.symbols, sym_index)?;
        if sd.sym_type == elf::STT_SECTION {
            if addend != 0 {
                Ok(addend as i32)
            } else {
                Ok(lo_inst_imm)
            }
        } else {
            Ok((sd.value as i64 + addend) as i32)
        }
    }

    fn section_name_by_index(&self, sec_idx: usize) -> Result<String, UnmarshalError> {
        // The `object` crate's sections() iterator skips index 0 (the ELF
        // null section).  Return an empty name for it, matching ELFIO.
        if sec_idx == 0 {
            return Ok(String::new());
        }
        for section in self.elf.sections() {
            if section.index().0 == sec_idx {
                return section
                    .name()
                    .map(|n| n.to_string())
                    .map_err(|e| UnmarshalError(format!("Cannot read section name: {e}")));
            }
        }
        Err(UnmarshalError(format!("Section index {sec_idx} not found")))
    }

    // ── Single relocation ───────────────────────────────────────────

    fn try_reloc(
        &mut self,
        symbol_name: &str,
        symbol_section_index: usize,
        instructions: &mut [EbpfInst],
        location: usize,
        sym_index: usize,
        addend: i64,
    ) -> Result<bool, UnmarshalError> {
        // Handle empty symbol names for global variable sections.
        if symbol_name.is_empty() {
            if self
                .global
                .variable_section_indices
                .contains(&symbol_section_index)
            {
                if !matches!(self.global.map_resolution, MapResolution::Named(_)) {
                    return Ok(false);
                }
                validate_lddw_pair(instructions, location, "global variable")?;
                let lo_imm = instructions[location].imm;
                instructions[location + 1].imm =
                    self.compute_lddw_reloc_offset_imm(addend, sym_index, lo_imm)?;
                instructions[location].set_src(INST_LD_MODE_MAP_VALUE);

                let sec_name = self.section_name_by_index(symbol_section_index)?;
                instructions[location].imm = self.relocate_global_variable(&sec_name)?;
                return Ok(true);
            }
            return Ok(true);
        }

        let inst = &instructions[location];

        // Handle local function calls.
        if inst.opcode == INST_OP_CALL && inst.src_raw() == INST_CALL_LOCAL {
            let prog_index = self.raw_programs.len();
            self.function_relocations.push(FunctionRelocation {
                prog_index,
                source_offset: location,
                relocation_entry_index: sym_index,
                target_function_name: symbol_name.to_string(),
            });
            return Ok(true);
        }

        // Only LD-class instructions can be map/global loads.
        if (inst.opcode & INST_CLS_MASK) != INST_CLS_LD {
            return Ok(false);
        }

        // Map relocations.
        if self
            .global
            .map_section_indices
            .contains(&symbol_section_index)
        {
            let fd = self.relocate_map(symbol_name, sym_index)?;
            instructions[location].set_src(INST_LD_MODE_MAP_FD);
            instructions[location].imm = fd;
            return Ok(true);
        }

        // Named global variables.
        if self
            .global
            .variable_section_indices
            .contains(&symbol_section_index)
        {
            let context = format!("global variable '{symbol_name}'");
            validate_lddw_pair(instructions, location, &context)?;
            let lo_imm = instructions[location].imm;
            instructions[location + 1].imm =
                self.compute_lddw_reloc_offset_imm(addend, sym_index, lo_imm)?;
            instructions[location].set_src(INST_LD_MODE_MAP_VALUE);

            let sec_name = self.section_name_by_index(symbol_section_index)?;
            instructions[location].imm = self.relocate_global_variable(&sec_name)?;
            return Ok(true);
        }

        // Legacy fallback: zero out __config_* symbols.
        if symbol_name.starts_with("__config_") {
            instructions[location].imm = 0;
            return Ok(true);
        }

        Ok(false)
    }

    // ── Process all relocations for a program ───────────────────────

    fn process_relocations(
        &mut self,
        instructions: &mut [EbpfInst],
        section_name: &str,
        program_offset: u64,
        program_size: u64,
        reloc_section_header: &elf::SectionHeader64<LittleEndian>,
    ) -> Result<(), UnmarshalError> {
        let inst_size = mem::size_of::<EbpfInst>() as u64;
        let sh_type = reloc_section_header.sh_type(ENDIAN);

        if sh_type == elf::SHT_RELA {
            if let Some((entries, _link)) = reloc_section_header
                .rela(ENDIAN, self.data)
                .map_err(|e| UnmarshalError(format!("Cannot read RELA section: {e}")))?
            {
                for rela in entries {
                    let offset = rela.r_offset(ENDIAN);
                    let sym_idx = rela.symbol(ENDIAN, false).map(|s| s.0).unwrap_or(0);
                    let addend: i64 = rela.r_addend(ENDIAN);
                    self.process_single_relocation(
                        instructions,
                        section_name,
                        program_offset,
                        program_size,
                        offset,
                        sym_idx,
                        addend,
                        inst_size,
                    )?;
                }
            }
        } else if sh_type == elf::SHT_REL
            && let Some((entries, _link)) = reloc_section_header
                .rel(ENDIAN, self.data)
                .map_err(|e| UnmarshalError(format!("Cannot read REL section: {e}")))?
        {
            for rel in entries {
                let offset = rel.r_offset(ENDIAN);
                let sym_idx = rel.symbol(ENDIAN).map(|s| s.0).unwrap_or(0);
                self.process_single_relocation(
                    instructions,
                    section_name,
                    program_offset,
                    program_size,
                    offset,
                    sym_idx,
                    0,
                    inst_size,
                )?;
            }
        }
        Ok(())
    }

    fn process_single_relocation(
        &mut self,
        instructions: &mut [EbpfInst],
        section_name: &str,
        program_offset: u64,
        program_size: u64,
        offset: u64,
        sym_idx: usize,
        addend: i64,
        inst_size: u64,
    ) -> Result<(), UnmarshalError> {
        if offset < program_offset || offset >= program_offset + program_size {
            return Ok(());
        }
        let o = offset - program_offset;
        if !o.is_multiple_of(inst_size) {
            return Err(UnmarshalError("Unaligned relocation offset".into()));
        }
        let loc = (o / inst_size) as usize;
        if loc >= instructions.len() {
            return Err(UnmarshalError("Invalid relocation".into()));
        }

        let sd = get_symbol_details(self.symbols, sym_idx)?;
        if !self.try_reloc(
            &sd.name,
            sd.section_index,
            instructions,
            loc,
            sym_idx,
            addend,
        )? {
            self.unresolved_symbol_errors.push(format!(
                "Unresolved external symbol {} in section {} at location {}",
                sd.name, section_name, loc,
            ));
        }
        Ok(())
    }

    // ── Find relocation section for a given code section ────────────

    fn find_relocation_section_header(
        &self,
        name: &str,
    ) -> Option<&'a elf::SectionHeader64<LittleEndian>> {
        if name == ".BTF" {
            return None;
        }
        let rel_name = format!(".rel{name}");
        let rela_name = format!(".rela{name}");
        for section in self.elf.sections() {
            let sec_name = match section.name() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if (sec_name == rel_name || sec_name == rela_name)
                && section.data().map(|d| !d.is_empty()).unwrap_or(false)
            {
                return Some(section.elf_section_header());
            }
        }
        None
    }

    // ── CO-RE relocations ──────────────────────────────────────────

    fn process_core_relocations(
        &mut self,
        btf_data: &BtfTypeData,
        btf_section_data: &[u8],
    ) -> Result<(), UnmarshalError> {
        // Find .rel.BTF or .rela.BTF section
        let relo_sec = self.elf.sections().find(|s| {
            let name = s.name().unwrap_or("");
            name == ".rel.BTF" || name == ".rela.BTF"
        });
        let relo_sec = match relo_sec {
            Some(s) => s,
            None => return Ok(()),
        };

        // Find .BTF.ext section
        let btf_ext_sec = self.elf.section_by_name(".BTF.ext").ok_or_else(|| {
            UnmarshalError(".BTF.ext section missing for CO-RE relocations".into())
        })?;
        let btf_ext_data = btf_ext_sec
            .data()
            .map_err(|e| UnmarshalError(format!("Cannot read .BTF.ext section: {e}")))?;

        // R_BPF_64_NODYLD32 from the kernel UAPI
        const R_BPF_64_NODYLD32: u32 = 19;

        let sh = relo_sec.elf_section_header();
        let sh_type = sh.sh_type(ENDIAN);

        if sh_type == elf::SHT_RELA {
            if let Some((entries, _link)) = sh
                .rela(ENDIAN, self.data)
                .map_err(|e| UnmarshalError(format!("Cannot read .rela.BTF section: {e}")))?
            {
                for rela in entries {
                    let relo_type = (rela.r_info(ENDIAN, false) & 0xffff_ffff) as u32;
                    if relo_type != R_BPF_64_NODYLD32 {
                        continue;
                    }
                    let sym_idx = rela.symbol(ENDIAN, false).map(|s| s.0).unwrap_or(0);
                    self.apply_core_relo_from_ext(
                        btf_data,
                        btf_section_data,
                        btf_ext_data,
                        sym_idx,
                    )?;
                }
            }
        } else if sh_type == elf::SHT_REL
            && let Some((entries, _link)) = sh
                .rel(ENDIAN, self.data)
                .map_err(|e| UnmarshalError(format!("Cannot read .rel.BTF section: {e}")))?
        {
            for rel in entries {
                let relo_type = (rel.r_info(ENDIAN) & 0xffff_ffff) as u32;
                if relo_type != R_BPF_64_NODYLD32 {
                    continue;
                }
                let sym_idx = rel.symbol(ENDIAN).map(|s| s.0).unwrap_or(0);
                self.apply_core_relo_from_ext(btf_data, btf_section_data, btf_ext_data, sym_idx)?;
            }
        }

        Ok(())
    }

    fn apply_core_relo_from_ext(
        &mut self,
        btf_data: &BtfTypeData,
        btf_section_data: &[u8],
        btf_ext_data: &[u8],
        sym_idx: usize,
    ) -> Result<(), UnmarshalError> {
        let sd = get_symbol_details(self.symbols, sym_idx)?;

        // Read the bpf_core_relo struct from BTF.ext at the symbol value offset
        let relo_offset = sd.value as usize;
        if relo_offset + 16 > btf_ext_data.len() {
            return Err(UnmarshalError(
                "CO-RE relocation offset out of BTF.ext bounds".into(),
            ));
        }

        // Read 4 u32 fields: insn_off, type_id, access_str_off, kind
        let insn_off = u32::from_le_bytes([
            btf_ext_data[relo_offset],
            btf_ext_data[relo_offset + 1],
            btf_ext_data[relo_offset + 2],
            btf_ext_data[relo_offset + 3],
        ]);
        let type_id = u32::from_le_bytes([
            btf_ext_data[relo_offset + 4],
            btf_ext_data[relo_offset + 5],
            btf_ext_data[relo_offset + 6],
            btf_ext_data[relo_offset + 7],
        ]);
        let access_str_off = u32::from_le_bytes([
            btf_ext_data[relo_offset + 8],
            btf_ext_data[relo_offset + 9],
            btf_ext_data[relo_offset + 10],
            btf_ext_data[relo_offset + 11],
        ]);
        let kind_raw = u32::from_le_bytes([
            btf_ext_data[relo_offset + 12],
            btf_ext_data[relo_offset + 13],
            btf_ext_data[relo_offset + 14],
            btf_ext_data[relo_offset + 15],
        ]);

        // Find the matching program
        let inst_size = mem::size_of::<EbpfInst>();
        let mut applied = false;
        for prog in &mut self.raw_programs {
            let prog_start = prog.insn_off;
            let prog_end = prog.insn_off + (prog.prog.len() as u32) * (inst_size as u32);
            if insn_off >= prog_start && insn_off < prog_end {
                let inst_idx = ((insn_off - prog.insn_off) as usize) / inst_size;
                if inst_idx >= prog.prog.len() {
                    return Err(UnmarshalError(
                        "CO-RE relocation offset out of bounds".into(),
                    ));
                }
                apply_core_relocation(
                    &mut prog.prog[inst_idx],
                    btf_data,
                    btf_section_data,
                    type_id,
                    access_str_off,
                    kind_raw,
                )?;
                applied = true;
                break;
            }
        }

        if !applied {
            return Err(UnmarshalError(format!(
                "Failed to find program for CO-RE relocation at instruction offset {insn_off}"
            )));
        }
        Ok(())
    }

    // ── Subprogram linking ──────────────────────────────────────────

    fn append_subprograms(&mut self) -> Result<(), UnmarshalError> {
        let prog_count = self.raw_programs.len();
        let mut resolved: BTreeSet<usize> = BTreeSet::new();
        let mut visiting: BTreeSet<usize> = BTreeSet::new();

        let mut prog_lookup: BTreeMap<(String, String), usize> = BTreeMap::new();
        for (idx, prog) in self.raw_programs.iter().enumerate() {
            prog_lookup.insert((prog.section_name.clone(), prog.function_name.clone()), idx);
        }

        for prog_idx in 0..prog_count {
            self.resolve_subprograms_for(prog_idx, &prog_lookup, &mut resolved, &mut visiting)?;
        }
        Ok(())
    }

    fn resolve_subprograms_for(
        &mut self,
        prog_idx: usize,
        prog_lookup: &BTreeMap<(String, String), usize>,
        resolved: &mut BTreeSet<usize>,
        visiting: &mut BTreeSet<usize>,
    ) -> Result<(), UnmarshalError> {
        if resolved.contains(&prog_idx) {
            return Ok(());
        }
        if visiting.contains(&prog_idx) {
            return Err(UnmarshalError(
                "Mutual recursion in subprogram calls".into(),
            ));
        }
        visiting.insert(prog_idx);

        let prog_name = self.raw_programs[prog_idx].function_name.clone();

        // Collect relocations for this program.
        let relocs_for_prog: Vec<(usize, usize, String)> = self
            .function_relocations
            .iter()
            .filter(|r| {
                r.prog_index < self.raw_programs.len()
                    && self.raw_programs[r.prog_index].function_name == prog_name
            })
            .map(|r| {
                (
                    r.source_offset,
                    r.relocation_entry_index,
                    r.target_function_name.clone(),
                )
            })
            .collect();

        let mut subprogram_offsets: BTreeMap<String, usize> = BTreeMap::new();

        for (source_offset, reloc_entry_index, target_name) in &relocs_for_prog {
            if !subprogram_offsets.contains_key(target_name) {
                let current_len = self.raw_programs[prog_idx].prog.len();
                subprogram_offsets.insert(target_name.clone(), current_len);

                let sd = get_symbol_details(self.symbols, *reloc_entry_index)?;
                let sub_sec_name = self.section_name_by_index(sd.section_index)?;
                let sub_key = (sub_sec_name, sd.name.clone());
                let sub_idx = prog_lookup.get(&sub_key).copied();

                if let Some(sub_idx) = sub_idx {
                    if sub_idx == prog_idx {
                        return Err(UnmarshalError("Recursive subprogram call".into()));
                    }
                    self.resolve_subprograms_for(sub_idx, prog_lookup, resolved, visiting)?;

                    let sub_instructions = self.raw_programs[sub_idx].prog.clone();
                    let base = *subprogram_offsets.get(target_name).unwrap();

                    if self.options.verbosity_opts.print_line_info {
                        let sub_line_info: BTreeMap<usize, _> = self.raw_programs[sub_idx]
                            .info
                            .line_info
                            .iter()
                            .map(|(&k, v)| (base + k, v.clone()))
                            .collect();
                        self.raw_programs[prog_idx]
                            .info
                            .line_info
                            .extend(sub_line_info);
                    }

                    self.raw_programs[prog_idx]
                        .prog
                        .extend_from_slice(&sub_instructions);
                } else {
                    let err_msg = format!("Subprogram not found: {}", sd.name);
                    if self.raw_programs[prog_idx].section_name == self.desired_section {
                        return Err(UnmarshalError(err_msg));
                    }
                }
            }

            let target_offset = *subprogram_offsets.get(target_name).unwrap() as i64;
            let src_offset = *source_offset as i64;
            self.raw_programs[prog_idx].prog[*source_offset].imm =
                (target_offset - src_offset - 1) as i32;
        }

        visiting.remove(&prog_idx);
        resolved.insert(prog_idx);
        Ok(())
    }

    // ── Main read loop ──────────────────────────────────────────────

    fn read_programs(&mut self) -> Result<(), UnmarshalError> {
        for section in self.elf.sections() {
            let sh = section.elf_section_header();
            let flags = sh.sh_flags(ENDIAN);
            if flags & u64::from(elf::SHF_EXECINSTR) == 0 {
                continue;
            }
            let sec_size = section.size();
            if sec_size == 0 {
                continue;
            }
            let sec_data = match section.data() {
                Ok(d) if !d.is_empty() => d,
                _ => continue,
            };
            let sec_name = section.name().unwrap_or("");
            let sec_idx = section.index().0;

            let prog_type = self.platform.get_program_type(sec_name, self.path);
            let reloc_sh = self.find_relocation_section_header(sec_name);

            let mut offset: u64 = 0;
            while offset < sec_size {
                let (name, size) = get_program_name_and_size(
                    sec_idx,
                    sec_name,
                    sec_size,
                    offset,
                    self.symbols,
                    self.sym_count,
                );

                let end = offset + size;
                if end > sec_size {
                    return Err(UnmarshalError(format!(
                        "Program '{name}' extends past section boundary"
                    )));
                }
                let mut instructions =
                    bytes_to_instructions(&sec_data[offset as usize..end as usize])?;

                if let Some(reloc_sh) = reloc_sh {
                    self.process_relocations(&mut instructions, sec_name, offset, size, reloc_sh)?;
                }

                self.raw_programs.push(RawProgram {
                    filename: self.path.to_string(),
                    section_name: sec_name.to_string(),
                    insn_off: offset as u32,
                    function_name: name,
                    prog: instructions,
                    info: ProgramInfo {
                        map_descriptors: self.global.map_descriptors.clone(),
                        program_type: prog_type.clone(),
                        supported_conformance_groups: self.platform.supported_conformance_groups(),
                        ..Default::default()
                    },
                });

                offset += size;
            }
        }

        // Process CO-RE relocations if .BTF section exists
        if let Some(btf_section) = self.elf.section_by_name(".BTF")
            && let Ok(btf_bytes) = btf_section.data()
            && let Ok(btf_data) = BtfTypeData::new(btf_bytes)
        {
            self.process_core_relocations(&btf_data, btf_bytes)?;
        }

        if !self.unresolved_symbol_errors.is_empty() {
            for err in &self.unresolved_symbol_errors {
                eprintln!("{err}");
            }
            return Err(UnmarshalError("Unresolved symbols found.".into()));
        }

        // Update line info if requested
        if self.options.verbosity_opts.print_line_info
            && let Some(btf_section) = self.elf.section_by_name(".BTF")
            && let Some(btf_ext_section) = self.elf.section_by_name(".BTF.ext")
            && let (Ok(btf_bytes), Ok(btf_ext_bytes)) = (btf_section.data(), btf_ext_section.data())
        {
            update_line_info(&mut self.raw_programs, btf_bytes, btf_ext_bytes)?;
        }

        self.append_subprograms()?;

        if !self.desired_section.is_empty() {
            self.raw_programs
                .retain(|p| p.section_name == self.desired_section);
        }

        if self.raw_programs.is_empty() {
            return Err(UnmarshalError(if self.desired_section.is_empty() {
                "No executable sections".into()
            } else {
                "Section not found".into()
            }));
        }

        Ok(())
    }
}

// ── CO-RE relocation application ─────────────────────────────────────

/// CO-RE relocation kinds (from linux/bpf.h).
#[expect(dead_code)]
mod core_relo_kind {
    pub const FIELD_BYTE_OFFSET: u32 = 0;
    pub const FIELD_BYTE_SIZE: u32 = 1;
    pub const FIELD_EXISTS: u32 = 2;
    pub const FIELD_SIGNED: u32 = 3;
    pub const FIELD_LSHIFT_U64: u32 = 4;
    pub const FIELD_RSHIFT_U64: u32 = 5;
    pub const TYPE_ID_LOCAL: u32 = 6;
    pub const TYPE_ID_TARGET: u32 = 7;
    pub const TYPE_EXISTS: u32 = 8;
    pub const TYPE_SIZE: u32 = 9;
    pub const ENUMVAL_EXISTS: u32 = 10;
    pub const ENUMVAL_VALUE: u32 = 11;
    pub const TYPE_MATCHES: u32 = 12;
}

/// Parse a CO-RE access string (e.g., "0:1:2") into a vector of indices.
fn parse_core_access_string(s: &str) -> Result<Vec<u32>, UnmarshalError> {
    let mut indices = Vec::new();
    for item in s.split(':') {
        if !item.is_empty() {
            let idx: u32 = item
                .parse()
                .map_err(|_| UnmarshalError(format!("Invalid CO-RE access string: {s}")))?;
            indices.push(idx);
        }
    }
    Ok(indices)
}

/// Unwrap typedef/const/volatile/restrict to reach the underlying type.
fn unwrap_btf_type(btf_data: &BtfTypeData, mut type_id: u32) -> Result<u32, UnmarshalError> {
    for _ in 0..256 {
        let kind_index = btf_data.get_kind_index(type_id)?;
        match kind_index {
            crate::btf::BtfKindIndex::Typedef => {
                if let crate::btf::BtfKind::Typedef { type_id: inner, .. } =
                    btf_data.get_kind(type_id)?
                {
                    type_id = *inner;
                }
            }
            crate::btf::BtfKindIndex::Const => {
                if let crate::btf::BtfKind::Const { type_id: inner } = btf_data.get_kind(type_id)? {
                    type_id = *inner;
                }
            }
            crate::btf::BtfKindIndex::Volatile => {
                if let crate::btf::BtfKind::Volatile { type_id: inner } =
                    btf_data.get_kind(type_id)?
                {
                    type_id = *inner;
                }
            }
            crate::btf::BtfKindIndex::Restrict => {
                if let crate::btf::BtfKind::Restrict { type_id: inner } =
                    btf_data.get_kind(type_id)?
                {
                    type_id = *inner;
                }
            }
            _ => return Ok(type_id),
        }
    }
    Err(UnmarshalError(
        "CO-RE type resolution exceeded depth limit (possible corrupt BTF)".into(),
    ))
}

/// Apply a single CO-RE relocation to an instruction.
fn apply_core_relocation(
    inst: &mut EbpfInst,
    btf_data: &BtfTypeData,
    btf_section_data: &[u8],
    type_id: u32,
    access_str_off: u32,
    kind_raw: u32,
) -> Result<(), UnmarshalError> {
    match kind_raw {
        core_relo_kind::FIELD_BYTE_OFFSET => {
            let access_string =
                crate::btf::parse::read_btf_string(btf_section_data, access_str_off)?;
            let indices = parse_core_access_string(&access_string)?;
            let mut current_type_id = type_id;
            let mut final_offset_bits: u32 = 0;

            for &index in &indices {
                current_type_id = unwrap_btf_type(btf_data, current_type_id)?;
                let kind_index = btf_data.get_kind_index(current_type_id)?;

                match kind_index {
                    crate::btf::BtfKindIndex::Struct => {
                        if let crate::btf::BtfKind::Struct { members, .. } =
                            btf_data.get_kind(current_type_id)?
                        {
                            if (index as usize) >= members.len() {
                                return Err(UnmarshalError(
                                    "CO-RE: member index out of bounds".into(),
                                ));
                            }
                            final_offset_bits += members[index as usize].offset_from_start_in_bits;
                            current_type_id = members[index as usize].type_id;
                        }
                    }
                    crate::btf::BtfKindIndex::Array => {
                        if let crate::btf::BtfKind::Array { element_type, .. } =
                            btf_data.get_kind(current_type_id)?
                        {
                            let elem_size = btf_data.get_size(*element_type)?;
                            final_offset_bits += index * elem_size * 8;
                            current_type_id = *element_type;
                        }
                    }
                    _ => {
                        return Err(UnmarshalError(
                            "CO-RE: indexing into non-aggregate type".into(),
                        ));
                    }
                }
            }
            inst.imm = (final_offset_bits / 8) as i32;
        }
        core_relo_kind::TYPE_ID_LOCAL | core_relo_kind::TYPE_ID_TARGET => {
            inst.imm = type_id as i32;
        }
        core_relo_kind::TYPE_SIZE => {
            inst.imm = btf_data.get_size(type_id)? as i32;
        }
        _ => {
            return Err(UnmarshalError(format!(
                "Unsupported CO-RE relocation kind: {kind_raw}"
            )));
        }
    }
    Ok(())
}

// ── Line info update ─────────────────────────────────────────────────

/// Update line info for all programs from BTF/BTF.ext data.
fn update_line_info(
    raw_programs: &mut [RawProgram],
    btf_data: &[u8],
    btf_ext_data: &[u8],
) -> Result<(), UnmarshalError> {
    let records = crate::btf::parse::parse_line_information(btf_data, btf_ext_data)?;
    let inst_size = mem::size_of::<EbpfInst>();

    for record in &records {
        for prog in raw_programs.iter_mut() {
            let prog_end = prog.insn_off + (prog.prog.len() as u32) * (inst_size as u32);
            if prog.section_name == record.section
                && record.instruction_offset >= prog.insn_off
                && record.instruction_offset < prog_end
            {
                let inst_index = ((record.instruction_offset - prog.insn_off) as usize) / inst_size;
                if inst_index < prog.prog.len() {
                    prog.info.line_info.insert(
                        inst_index,
                        BtfLineInfo {
                            file_name: record.file_name.clone(),
                            source_line: record.source.clone(),
                            line_number: record.line_number,
                            column_number: record.column_number,
                        },
                    );
                }
            }
        }
    }

    // Fill forward: for each instruction without line info, copy from the last known entry
    for prog in raw_programs.iter_mut() {
        let mut last: Option<BtfLineInfo> = None;
        for i in 0..prog.prog.len() {
            if let Some(info) = prog.info.line_info.get(&i) {
                if info.line_number != 0 {
                    last = Some(info.clone());
                }
            } else if let Some(ref last_info) = last {
                prog.info.line_info.insert(i, last_info.clone());
            }
        }
    }

    Ok(())
}

// ── Public API ──────────────────────────────────────────────────────

/// Parse an ELF file from bytes and return the BPF programs it contains.
pub fn read_elf(
    data: &[u8],
    path: &str,
    desired_section: &str,
    desired_program: &str,
    options: &EbpfVerifierOptions,
    platform: &mut dyn EbpfPlatform,
) -> Result<Vec<RawProgram>, UnmarshalError> {
    let elf: ElfFile<'_, Elf64> = ElfFile::parse(data)
        .map_err(|e| UnmarshalError(format!("Can't process ELF file {path}: {e}")))?;

    // Get the raw section table and symbol table.
    let header = elf.elf_header();
    let sections = header
        .sections(ENDIAN, data)
        .map_err(|e| UnmarshalError(format!("Cannot read sections: {e}")))?;
    let symbols = sections
        .symbols(ENDIAN, data, elf::SHT_SYMTAB)
        .map_err(|e| UnmarshalError(format!("No symbol section found in ELF file {path}: {e}")))?;
    let sym_count = symbols.len();

    let global = extract_global_data(&elf, &symbols, sym_count, platform, options)?;

    let mut reader = ProgramReader::new(
        path,
        options,
        platform,
        desired_section,
        &elf,
        data,
        &symbols,
        sym_count,
        &global,
    );
    reader.read_programs()?;

    // Filter by desired program name.
    if !desired_program.is_empty()
        && let Some(pos) = reader
            .raw_programs
            .iter()
            .position(|p| p.function_name == desired_program)
    {
        return Ok(vec![reader.raw_programs.swap_remove(pos)]);
    }

    Ok(reader.raw_programs)
}

/// Parse an ELF file from disk.
pub fn read_elf_file(
    path: &str,
    desired_section: &str,
    desired_program: &str,
    options: &EbpfVerifierOptions,
    platform: &mut dyn EbpfPlatform,
) -> Result<Vec<RawProgram>, UnmarshalError> {
    let data = std::fs::read(path).map_err(|e| UnmarshalError(format!("{e} opening {path}")))?;
    read_elf(
        &data,
        path,
        desired_section,
        desired_program,
        options,
        platform,
    )
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::syntax::Reg;
    use crate::spec::type_descriptors::{EbpfMapType, EbpfMapValueType, EbpfProgramType};

    #[test]
    fn is_map_section_basic() {
        assert!(is_map_section("maps"));
        assert!(is_map_section("maps/my_map"));
        assert!(!is_map_section("map"));
        assert!(!is_map_section(".maps"));
        assert!(!is_map_section(""));
    }

    #[test]
    fn is_global_section_basic() {
        assert!(is_global_section(".data"));
        assert!(is_global_section(".rodata"));
        assert!(is_global_section(".bss"));
        assert!(is_global_section(".data.my_var"));
        assert!(is_global_section(".rodata.config"));
        assert!(is_global_section(".bss.zeros"));
        assert!(!is_global_section(".text"));
        assert!(!is_global_section(""));
    }

    #[test]
    fn bytes_to_instructions_basic() {
        // Exit instruction: opcode=0x95
        let bytes = [0x95u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let insts = bytes_to_instructions(&bytes).unwrap();
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].opcode, 0x95);
        assert_eq!(insts[0].dst(), Reg { v: 0 });
        assert_eq!(insts[0].src(), Reg { v: 0 });
        assert_eq!(insts[0].offset, 0);
        assert_eq!(insts[0].imm, 0);
    }

    #[test]
    fn bytes_to_instructions_rejects_unaligned() {
        let bytes = [0u8; 7];
        assert!(bytes_to_instructions(&bytes).is_err());
    }

    #[test]
    fn validate_lddw_pair_ok() {
        let insts = vec![
            EbpfInst::new(BPF_LDDW, 0, 0, 0, 42),
            EbpfInst::new(BPF_LDDW_HI, 0, 0, 0, 0),
        ];
        assert!(validate_lddw_pair(&insts, 0, "test").is_ok());
    }

    #[test]
    fn validate_lddw_pair_boundary() {
        let insts = vec![EbpfInst::new(BPF_LDDW, 0, 0, 0, 42)];
        assert!(validate_lddw_pair(&insts, 0, "test").is_err());
    }

    #[test]
    fn validate_lddw_pair_wrong_opcode() {
        let insts = vec![
            EbpfInst::new(0x04, 0, 0, 0, 42),
            EbpfInst::new(BPF_LDDW_HI, 0, 0, 0, 0),
        ];
        assert!(validate_lddw_pair(&insts, 0, "test").is_err());
    }

    /// A minimal test platform that accepts all sections and provides no maps.
    struct TestPlatform;

    impl EbpfPlatform for TestPlatform {
        fn get_program_type(&self, _section: &str, _path: &str) -> EbpfProgramType {
            EbpfProgramType::default()
        }
        fn get_helper_prototype(&self, _n: i32) -> &crate::linux::spec_prototypes::HelperPrototype {
            unimplemented!("test platform does not support helpers")
        }
        fn is_helper_usable(&self, _n: i32) -> bool {
            false
        }
        fn map_record_size(&self) -> usize {
            0
        }
        fn parse_maps_section(
            &mut self,
            _descriptors: &mut Vec<EbpfMapDescriptor>,
            _data: &[u8],
            _record_size: usize,
            _count: usize,
            _options: &EbpfVerifierOptions,
        ) {
        }
        fn resolve_inner_map_references(
            &self,
            _descriptors: &mut Vec<EbpfMapDescriptor>,
        ) -> Result<(), UnmarshalError> {
            Ok(())
        }
        fn get_map_descriptor(&self, _map_fd: i32) -> Option<&EbpfMapDescriptor> {
            None
        }
        fn get_map_type(&self, _platform_specific_type: u32) -> EbpfMapType {
            EbpfMapType {
                platform_specific_type: 0,
                name: String::new(),
                is_array: false,
                value_type: EbpfMapValueType::Any,
            }
        }
        fn supported_conformance_groups(&self) -> u32 {
            0
        }
    }

    fn default_options() -> EbpfVerifierOptions {
        EbpfVerifierOptions {
            cfg_opts: crate::spec::config::PrepareCfgOptions {
                check_for_termination: false,
                must_have_exit: true,
            },
            mock_map_fds: true,
            strict: false,
            allow_division_by_zero: true,
            setup_constraints: true,
            big_endian: false,
            verbosity_opts: crate::spec::config::VerbosityOptions {
                simplify: true,
                print_invariants: false,
                print_failures: false,
                print_line_info: false,
                dump_btf_types_json: false,
            },
        }
    }

    #[test]
    fn read_elf_rejects_garbage() {
        let mut platform = TestPlatform;
        let options = default_options();
        let result = read_elf(b"not an elf", "test.o", "", "", &options, &mut platform);
        assert!(result.is_err());
    }

    #[test]
    fn load_simple_elf_from_samples() {
        let path = "tests/upstream/ebpf-samples/build/byteswap.o";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Skipping test: {path} not found");
                return;
            }
        };
        let mut platform = TestPlatform;
        let options = default_options();
        let programs = read_elf(&data, path, "", "", &options, &mut platform).unwrap();
        assert!(!programs.is_empty(), "Expected at least one program");
        for prog in &programs {
            assert!(!prog.prog.is_empty(), "Program should have instructions");
            assert!(
                !prog.function_name.is_empty(),
                "Program should have a function name"
            );
        }
    }

    #[test]
    fn load_elf_with_section_filter() {
        let path = "tests/upstream/ebpf-samples/build/byteswap.o";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Skipping test: {path} not found");
                return;
            }
        };
        let mut platform = TestPlatform;
        let options = default_options();

        let all_programs = read_elf(&data, path, "", "", &options, &mut platform).unwrap();
        assert!(!all_programs.is_empty());

        let sec_name = &all_programs[0].section_name;
        let filtered = read_elf(&data, path, sec_name, "", &options, &mut platform).unwrap();
        for prog in &filtered {
            assert_eq!(&prog.section_name, sec_name);
        }
    }

    #[test]
    fn load_elf_nonexistent_section_fails() {
        let path = "tests/upstream/ebpf-samples/build/byteswap.o";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Skipping test: {path} not found");
                return;
            }
        };
        let mut platform = TestPlatform;
        let options = default_options();
        let result = read_elf(
            &data,
            path,
            "nonexistent_section",
            "",
            &options,
            &mut platform,
        );
        assert!(result.is_err());
    }

    #[test]
    fn read_elf_file_nonexistent_path() {
        let mut platform = TestPlatform;
        let options = default_options();
        let result = read_elf_file("/nonexistent/path.o", "", "", &options, &mut platform);
        assert!(result.is_err());
    }

    #[test]
    fn ebpf_inst_set_src() {
        let mut inst = EbpfInst::new(0x18, 1, 0, 0, 0);
        assert_eq!(inst.src(), Reg { v: 0 });
        inst.set_src(2);
        assert_eq!(inst.src(), Reg { v: 2 });
        assert_eq!(inst.dst(), Reg { v: 1 });
    }

    #[test]
    fn ebpf_inst_set_dst() {
        let mut inst = EbpfInst::new(0x18, 1, 5, 0, 0);
        assert_eq!(inst.dst(), Reg { v: 1 });
        inst.set_dst(3);
        assert_eq!(inst.dst(), Reg { v: 3 });
        assert_eq!(inst.src(), Reg { v: 5 });
    }

    #[test]
    fn load_btf_maps_elf() {
        // twomaps_btf.o uses BTF-defined maps (has .maps section with BTF metadata)
        let path = "tests/upstream/ebpf-samples/build/twomaps_btf.o";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Skipping test: {path} not found");
                return;
            }
        };
        let mut platform = TestPlatform;
        let options = default_options();
        let programs = read_elf(&data, path, "", "", &options, &mut platform).unwrap();
        assert!(!programs.is_empty(), "Expected at least one program");

        // twomaps_btf.o should have two BTF-defined maps
        let map_count = programs[0].info.map_descriptors.len();
        assert!(
            map_count >= 2,
            "Expected at least 2 map descriptors from BTF, got {map_count}"
        );

        // Verify map descriptors have valid FDs (not zero)
        for desc in &programs[0].info.map_descriptors {
            assert!(
                desc.original_fd > 0,
                "Map FD should be positive, got {}",
                desc.original_fd
            );
        }
    }

    #[test]
    fn load_elf_with_line_info() {
        let path = "tests/upstream/ebpf-samples/build/byteswap.o";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Skipping test: {path} not found");
                return;
            }
        };
        let mut platform = TestPlatform;
        let mut options = default_options();
        options.verbosity_opts.print_line_info = true;

        let programs = read_elf(&data, path, "", "", &options, &mut platform).unwrap();
        assert!(!programs.is_empty());

        // At least one program should have line info populated
        let has_line_info = programs.iter().any(|p| !p.info.line_info.is_empty());
        assert!(
            has_line_info,
            "Expected line info to be populated when print_line_info is true"
        );

        // Line info should have valid file names
        for prog in &programs {
            for info in prog.info.line_info.values() {
                assert!(
                    !info.file_name.is_empty(),
                    "Line info should have a file name"
                );
            }
        }
    }

    #[test]
    fn load_elf_without_line_info() {
        let path = "tests/upstream/ebpf-samples/build/byteswap.o";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Skipping test: {path} not found");
                return;
            }
        };
        let mut platform = TestPlatform;
        let options = default_options(); // print_line_info = false

        let programs = read_elf(&data, path, "", "", &options, &mut platform).unwrap();
        assert!(!programs.is_empty());

        // Line info should NOT be populated when print_line_info is false
        for prog in &programs {
            assert!(
                prog.info.line_info.is_empty(),
                "Line info should be empty when print_line_info is false"
            );
        }
    }

    #[test]
    fn load_map_in_map_btf() {
        let path = "tests/upstream/ebpf-samples/build/map_in_map.o";
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Skipping test: {path} not found");
                return;
            }
        };
        let mut platform = TestPlatform;
        let options = default_options();
        let programs = read_elf(&data, path, "", "", &options, &mut platform).unwrap();
        assert!(!programs.is_empty(), "Expected at least one program");

        // map_in_map.o should have map descriptors with inner maps
        let has_inner_map = programs[0]
            .info
            .map_descriptors
            .iter()
            .any(|d| d.inner_map_fd != DEFAULT_MAP_FD);
        assert!(
            has_inner_map,
            "Expected at least one map with inner_map_fd set"
        );
    }
}
