// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! ELF file parser for BPF programs.
//!
//! Ports `src/elf_loader.cpp`.  Uses the `object` crate for zero-copy ELF
//! parsing instead of ELFIO.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

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
    EbpfInst, INST_ALU_OP_MOV, INST_CALL_BTF_HELPER, INST_CALL_LOCAL, INST_CALL_STATIC_HELPER,
    INST_CLS_ALU, INST_CLS_ALU64, INST_CLS_LD, INST_CLS_LDX, INST_CLS_MASK, INST_LD_MODE_MAP_FD,
    INST_LD_MODE_MAP_VALUE, INST_MODE_MEM, INST_MODE_MEMSX, INST_OP_CALL, INST_OP_LDDW_IMM,
    INST_SIZE_B, INST_SIZE_DW, INST_SIZE_H, INST_SIZE_MASK, INST_SIZE_W, INST_SRC_IMM,
    INST_SRC_REG,
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
    name == "maps" || name == ".maps" || name.starts_with("maps/") || name.starts_with(".maps/")
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
    let inst_size = size_of::<EbpfInst>();
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
    /// Upstream parity: matches the legacy branch in the C++ parser.
    #[allow(dead_code)]
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
    size: u64,
    sym_type: u8,
    bind: u8,
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
        size: sym.st_size(ENDIAN),
        sym_type: sym.st_type(),
        bind: sym.st_bind(),
        section_index: sym.st_shndx(ENDIAN) as usize,
    })
}

// ── Function relocation record ──────────────────────────────────────

/// Upstream parity: fields are populated for diagnostics; not all are read today.
#[allow(dead_code)]
struct FunctionRelocation {
    prog_index: usize,
    source_offset: usize,
    relocation_entry_index: usize,
    target_section_index: usize,
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

// ── Extern symbol resolution ────────────────────────────────────────

/// Resolve well-known Linux extern symbols to their compile-time values.
fn resolve_known_linux_extern_symbol(symbol_name: &str) -> Option<u64> {
    match symbol_name {
        "LINUX_KERNEL_VERSION" => Some((6 << 16) | (6 << 8)), // 6.6.0
        "LINUX_HAS_SYSCALL_WRAPPER" => Some(1),
        "LINUX_HAS_BPF_COOKIE" => Some(1),
        "CONFIG_HZ" => Some(250),
        "CONFIG_BPF_SYSCALL" => Some(1),
        "CONFIG_DEFAULT_HOSTNAME" => Some(b'l' as u64), // first byte of "localhost"
        _ => {
            if symbol_name.starts_with("__config_") {
                Some(0)
            } else {
                None
            }
        }
    }
}

/// Make a MOV reg,reg no-op instruction (neutralizes a LDDW slot).
fn make_mov_reg_nop(reg: u8) -> EbpfInst {
    EbpfInst {
        opcode: INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_REG,
        dst_src: reg | (reg << 4),
        offset: 0,
        imm: 0,
    }
}

/// Extract the memory access width (in bytes) from an LDX/ST/STX opcode.
fn opcode_to_width(opcode: u8) -> u8 {
    match opcode & INST_SIZE_MASK {
        INST_SIZE_B => 1,
        INST_SIZE_H => 2,
        INST_SIZE_W => 4,
        INST_SIZE_DW => 8,
        _ => 0,
    }
}

/// Rewrite a LDDW + LDX sequence that loads a known extern constant.
///
/// Detects the pattern: LDDW (2-slot) followed by LDX that dereferences
/// the loaded address at offset 0.  Replaces the LDX with MOV-immediate
/// of the resolved value and neutralizes the LDDW pair with no-op MOVs.
fn rewrite_extern_constant_load(
    instructions: &mut [EbpfInst],
    location: usize,
    value: u64,
) -> bool {
    if instructions.len() <= location + 2 {
        return false;
    }

    // Verify LDDW pair
    if instructions[location].opcode != INST_OP_LDDW_IMM {
        return false;
    }
    if instructions[location + 1].opcode != 0x00 {
        return false;
    }

    let load_inst = &instructions[location + 2];
    if (load_inst.opcode & INST_CLS_MASK) != INST_CLS_LDX {
        return false;
    }
    let mode = load_inst.opcode & 0xe0; // INST_MODE_MASK
    if mode != INST_MODE_MEM && mode != INST_MODE_MEMSX {
        return false;
    }
    let lddw_dst = instructions[location].dst_raw();
    if load_inst.src_raw() != lddw_dst || load_inst.offset != 0 {
        return false;
    }

    let width = opcode_to_width(load_inst.opcode);
    let mut narrowed_value = value;
    match width {
        1 => narrowed_value &= 0xff,
        2 => narrowed_value &= 0xffff,
        4 => narrowed_value &= 0xffff_ffff,
        8 => {}
        _ => return false,
    }
    if mode == INST_MODE_MEMSX && width < 8 {
        let shift = 64 - u32::from(width) * 8;
        narrowed_value = ((narrowed_value << shift) as i64 >> shift) as u64;
    }

    // BPF MOV imm has a 32-bit immediate field that is sign-extended to 64 bits
    // by the runtime. Bail out if the value cannot survive the int32 → int64
    // sign-extension round-trip; the caller will fall back to the original
    // LDDW+LDX instruction sequence.
    let truncated = narrowed_value as i32;
    if truncated as i64 as u64 != narrowed_value {
        return false;
    }

    // Use mov-imm to materialize the resolved constant in the destination register of
    // the load, and neutralize the preceding LDDW pair.
    let mov_opcode = if width == 8 || mode == INST_MODE_MEMSX {
        INST_CLS_ALU64 | INST_ALU_OP_MOV | INST_SRC_IMM
    } else {
        INST_CLS_ALU | INST_ALU_OP_MOV | INST_SRC_IMM
    };
    let load_dst = instructions[location + 2].dst_raw();
    instructions[location + 2].opcode = mov_opcode;
    instructions[location + 2].dst_src = load_dst; // src = 0
    instructions[location + 2].offset = 0;
    instructions[location + 2].imm = truncated;

    let lo_dst = instructions[location].dst_raw();
    let hi_dst = instructions[location + 1].dst_raw();
    instructions[location] = make_mov_reg_nop(lo_dst);
    instructions[location + 1] = make_mov_reg_nop(hi_dst);
    true
}

/// Rewrite an unknown extern symbol's LDDW to load zero.
fn rewrite_extern_address_load_to_zero(instructions: &mut [EbpfInst], location: usize) -> bool {
    if location + 1 >= instructions.len() {
        return false;
    }
    if instructions[location].opcode != INST_OP_LDDW_IMM {
        return false;
    }
    // Validate the second slot is present and is 0x00 opcode
    if instructions[location + 1].opcode != 0x00 {
        return false;
    }
    instructions[location].imm = 0;
    instructions[location + 1].imm = 0;
    true
}

/// Rewrite a CALL src=INST_CALL_LOCAL instruction to a CALL src=INST_CALL_BTF_HELPER
/// with the resolved ksym BTF id and module offset.
fn rewrite_extern_kfunc_call(inst: &mut EbpfInst, resolved: &crate::platform::KsymBtfId) -> bool {
    if inst.opcode != INST_OP_CALL || inst.src_raw() != INST_CALL_LOCAL || inst.dst_raw() != 0 {
        return false;
    }
    if inst.offset != 0 {
        return false;
    }
    if resolved.btf_id <= 0 || resolved.module < 0 {
        return false;
    }

    inst.set_src(INST_CALL_BTF_HELPER);
    inst.offset = resolved.module;
    inst.imm = resolved.btf_id;
    true
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
        if (sh_type == elf::SHT_NOBITS || sh_type == elf::SHT_PROGBITS) && size != 0 {
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
        map_offsets.insert(sec_name.clone(), global.map_descriptors.len());
        global.map_descriptors.push(EbpfMapDescriptor {
            original_fd: (global.map_descriptors.len() + 1) as i32,
            map_type: 0,
            key_size: 4,
            value_size: sec_size as u32,
            max_entries: 1,
            inner_map_fd: DEFAULT_MAP_FD,
            name: sec_name,
            is_inner_map_template: false,
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

        // Collect map symbols in this section.
        let mut map_symbols: Vec<SymbolDetails> = Vec::new();
        for i in 0..sym_count {
            if let Ok(sd) = get_symbol_details(symbols, i)
                && sd.section_index == sec_idx
                && !sd.name.is_empty()
            {
                map_symbols.push(sd);
            }
        }

        global.map_section_indices.insert(sec_idx);

        if map_symbols.is_empty() {
            continue;
        }

        let sec_data = section
            .data()
            .map_err(|e| UnmarshalError(format!("Cannot read maps section '{sec_name}': {e}")))?;
        let sec_size = sec_data.len();

        // Compute record size from the minimum non-zero symbol size (matching C++).
        let mut record_size: usize = 0;
        for sd in &map_symbols {
            if sd.size > 0 {
                let sz = sd.size as usize;
                record_size = if record_size == 0 {
                    sz
                } else {
                    record_size.min(sz)
                };
            }
        }
        if record_size == 0 {
            record_size = platform.map_record_size();
        }

        if record_size < 4 * 4 || !record_size.is_multiple_of(4) {
            return Err(UnmarshalError(format!(
                "Malformed legacy maps section: {sec_name}"
            )));
        }
        if sec_size < record_size {
            return Err(UnmarshalError(format!(
                "Malformed legacy maps section: {sec_name}"
            )));
        }

        let mut map_count = sec_size / record_size;
        if map_count == 0 {
            return Err(UnmarshalError(format!(
                "Malformed legacy maps section: {sec_name}"
            )));
        }

        // If section size is not evenly divisible, compute count from symbol extents.
        if sec_size % record_size != 0 {
            let mut max_record_end: usize = 0;
            for sd in &map_symbols {
                let sym_off = sd.value as usize;
                if sym_off >= sec_size {
                    return Err(UnmarshalError(format!(
                        "Malformed legacy maps section: {sec_name}"
                    )));
                }
                max_record_end = max_record_end.max(sym_off + record_size);
            }
            if max_record_end > sec_size {
                return Err(UnmarshalError(format!(
                    "Malformed legacy maps section: {sec_name}"
                )));
            }
            // Use floor division to ensure map_count * record_size <= section size.
            // Ceiling division can produce a count whose last record extends past the
            // buffer, causing a heap-buffer-overflow in parse_maps_section.
            map_count = max_record_end / record_size;
        }

        let base_index = global.map_descriptors.len();
        section_record_sizes.insert(sec_idx, record_size);
        section_base_index.insert(sec_idx, base_index);

        // Safety invariant: all records must fit within the section data.
        if map_count * record_size > sec_size {
            return Err(UnmarshalError(format!(
                "Malformed legacy maps section: {sec_name}"
            )));
        }

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

        global.map_descriptors[descriptor_index].name = sd.name.clone();
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
    let btf_maps = crate::btf::map::parse_btf_map_section(&btf_data)
        .map_err(|e| UnmarshalError(format!("Unsupported or invalid BTF map metadata: {e}")))?;
    for map_def in btf_maps {
        let name = map_def.name.clone();
        map_offsets.insert(name.clone(), global.map_descriptors.len());
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
            name,
            is_inner_map_template: false,
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
    // BTF-defined maps take priority when both .BTF and .maps sections exist.
    let has_btf = elf.section_by_name(".BTF").is_some();
    let has_btf_maps = has_btf && elf.section_by_name(".maps").is_some();
    let mut global = if has_btf_maps {
        // Try BTF parsing first; fall back to section-based maps if BTF can't be decoded.
        match parse_btf_section(elf) {
            Ok(global) => global,
            Err(e) => {
                eprintln!("BTF map parsing failed, falling back to section-based maps: {e}");
                parse_map_sections(elf, symbols, sym_count, platform, options)?
            }
        }
    } else if elf.sections().any(|s| s.name().is_ok_and(is_map_section)) {
        // Fall back to legacy "maps" / "maps/*" / ".maps" / ".maps/*" sections.
        parse_map_sections(elf, symbols, sym_count, platform, options)?
    } else if has_btf {
        // BTF without .maps section (e.g. only global variables).
        parse_btf_section(elf)?
    } else {
        // No maps or BTF, but might still have global variables
        create_global_variable_maps(elf)
    };

    // Mark descriptors that serve only as inner map templates. At runtime the
    // actual inner map can be any map with matching structure, not necessarily
    // the template defined in the ELF.
    let template_fds: Vec<i32> = global
        .map_descriptors
        .iter()
        .filter(|d| d.inner_map_fd != DEFAULT_MAP_FD)
        .map(|d| d.inner_map_fd)
        .collect();
    for desc in &mut global.map_descriptors {
        if template_fds.contains(&desc.original_fd) {
            desc.is_inner_map_template = true;
        }
    }

    Ok(global)
}

// ── Symbol helpers ──────────────────────────────────────────────────

/// Find a function symbol at a given byte offset within a section.
fn find_function_symbol_at_offset(
    symbols: &SymbolTable<'_>,
    sym_count: usize,
    section_index: usize,
    byte_offset: u64,
) -> Option<String> {
    for i in 0..sym_count {
        let sd = match get_symbol_details(symbols, i) {
            Ok(sd) => sd,
            Err(_) => continue,
        };
        if sd.section_index != section_index || sd.sym_type != elf::STT_FUNC || sd.name.is_empty() {
            continue;
        }
        if sd.value == byte_offset {
            return Some(sd.name);
        }
    }
    None
}

// ── Reachable CFG span ─────────────────────────────────────────────

/// Compute the span of reachable instructions starting from a program entry point.
///
/// Starting from the first instruction, follows jumps, calls, and fallthrough
/// to determine the actual program span (which may extend beyond what symbol
/// sizes indicate, e.g., for fall-through subprograms).
fn compute_reachable_program_span(
    section_instructions: &[EbpfInst],
    program_offset: u64,
    initial_size: u64,
) -> u64 {
    use crate::spec::vm_isa::{
        INST_CALL, INST_CLS_JMP, INST_CLS_JMP32, INST_EXIT, INST_JA, INST_OP_LDDW_IMM,
    };
    use std::collections::VecDeque;

    if section_instructions.is_empty() {
        return initial_size;
    }

    let inst_size = size_of::<EbpfInst>() as u64;
    let total = section_instructions.len();
    let start = (program_offset / inst_size) as usize;
    let mut initial_end = ((program_offset + initial_size) / inst_size) as usize;
    if start >= total || initial_end <= start {
        return initial_size;
    }
    initial_end = initial_end.min(total);

    let mut seen = vec![false; total];
    let mut work = VecDeque::new();

    let mark = |idx: i64, seen: &mut Vec<bool>, work: &mut VecDeque<usize>| {
        if idx < 0 || idx >= total as i64 {
            return;
        }
        let idx = idx as usize;
        if !seen[idx] {
            seen[idx] = true;
            work.push_back(idx);
        }
    };

    mark(start as i64, &mut seen, &mut work);
    let mut max_reachable = initial_end - 1;

    while let Some(pc) = work.pop_front() {
        if pc > max_reachable {
            max_reachable = pc;
        }

        let inst = &section_instructions[pc];
        let is_lddw = inst.opcode == INST_OP_LDDW_IMM;
        let fallthrough = pc + if is_lddw { 2 } else { 1 };

        // LDDW is a two-slot instruction: keep the high slot in range.
        if is_lddw && pc + 1 < total {
            mark((pc + 1) as i64, &mut seen, &mut work);
            if pc + 1 > max_reachable {
                max_reachable = pc + 1;
            }
        }

        let cls = inst.opcode & INST_CLS_MASK;
        if cls == INST_CLS_JMP || cls == INST_CLS_JMP32 {
            let op = (inst.opcode >> 4) & 0xf;
            if op == INST_EXIT {
                continue;
            }
            if op == INST_CALL {
                if inst.opcode == INST_OP_CALL && inst.src_raw() == INST_CALL_LOCAL {
                    let target = pc as i64 + 1 + i64::from(inst.imm);
                    mark(target, &mut seen, &mut work);
                }
                mark(fallthrough as i64, &mut seen, &mut work);
                continue;
            }

            let target = pc as i64 + 1 + i64::from(inst.offset);
            mark(target, &mut seen, &mut work);
            if op != INST_JA {
                mark(fallthrough as i64, &mut seen, &mut work);
            }
            continue;
        }

        mark(fallthrough as i64, &mut seen, &mut work);
    }

    let span_end = initial_end.max(max_reachable + 1);
    ((span_end - start) as u64) * inst_size
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

struct UnresolvedSymbolError {
    section: String,
    message: String,
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
    unresolved_symbol_errors: Vec<UnresolvedSymbolError>,
    builtin_offsets_for_current_program: BTreeSet<usize>,
    ksym_function_resolution_cache: BTreeMap<String, Option<crate::platform::KsymBtfId>>,
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
            builtin_offsets_for_current_program: BTreeSet::new(),
            ksym_function_resolution_cache: BTreeMap::new(),
        }
    }

    // ── Ksym resolution cache ─────────────────────────────────────

    fn build_ksym_function_resolution_cache(&mut self) -> Result<(), UnmarshalError> {
        use crate::btf::type_data::BtfTypeData;
        use crate::btf::{BtfKind, BtfKindIndex};

        self.ksym_function_resolution_cache.clear();

        // Find the .BTF section.
        let btf_section = self.elf.sections().find(|s| s.name() == Ok(".BTF"));
        let btf_data_bytes = match btf_section.and_then(|s| s.data().ok()) {
            Some(d) if !d.is_empty() => d,
            _ => return Ok(()),
        };

        let btf_data = match BtfTypeData::new(btf_data_bytes) {
            Ok(td) => td,
            Err(e) => return Err(UnmarshalError(e.to_string())),
        };

        let ksyms_id = btf_data.get_id(".ksyms");
        if ksyms_id == 0 {
            return Ok(());
        }

        let members = match btf_data.get_kind(ksyms_id) {
            Ok(BtfKind::DataSection { members, .. }) => members.clone(),
            _ => return Ok(()),
        };

        for member in &members {
            if !matches!(
                btf_data.get_kind_index(member.type_id),
                Ok(BtfKindIndex::Function)
            ) {
                continue;
            }
            let func_name = match btf_data.get_kind(member.type_id) {
                Ok(BtfKind::Function { name, .. }) => name.clone(),
                _ => continue,
            };
            if func_name.is_empty() || self.ksym_function_resolution_cache.contains_key(&func_name)
            {
                continue;
            }

            let resolved = self.platform.resolve_ksym_btf_id(&func_name);
            self.ksym_function_resolution_cache
                .insert(func_name, resolved);
        }
        Ok(())
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
        symbol_type: u8,
        symbol_bind: u8,
        instructions: &mut [EbpfInst],
        location: usize,
        sym_index: usize,
        addend: i64,
    ) -> Result<bool, UnmarshalError> {
        // Resolve known extern symbols (SHN_UNDEF).
        // Known constants (LINUX_KERNEL_VERSION, CONFIG_HZ, etc.) are rewritten
        // from LDDW+LDX to MOV-immediate.  Unknown extern addresses are zeroed.
        if symbol_section_index == elf::SHN_UNDEF as usize {
            if let Some(value) = resolve_known_linux_extern_symbol(symbol_name)
                && rewrite_extern_constant_load(instructions, location, value)
            {
                return Ok(true);
            }
            if rewrite_extern_address_load_to_zero(instructions, location) {
                return Ok(true);
            }
        }

        // Handle local function calls.
        // Builtins such as memset/memcpy may be encoded as local calls
        // against undefined symbols; those are rewritten to static helpers
        // and gated via ProgramInfo::builtin_call_offsets.
        let inst = &instructions[location];
        if inst.opcode == INST_OP_CALL && inst.src_raw() == INST_CALL_LOCAL {
            if symbol_section_index == elf::SHN_UNDEF as usize {
                // Check ksym function resolution cache before builtin fallback.
                if let Some(cached) = self.ksym_function_resolution_cache.get(symbol_name) {
                    if let Some(resolved) = cached {
                        if !rewrite_extern_kfunc_call(&mut instructions[location], resolved) {
                            return Err(UnmarshalError(format!(
                                "Invalid kfunc call rewrite for symbol {}: \
                                 instruction encoding or resolver output is invalid",
                                symbol_name
                            )));
                        }
                        return Ok(true);
                    }
                    if symbol_bind != elf::STB_WEAK {
                        return Ok(false);
                    }
                }
                if let Some(builtin_id) = self.platform.resolve_builtin_call(symbol_name) {
                    instructions[location].set_src(INST_CALL_STATIC_HELPER);
                    instructions[location].imm = builtin_id;
                    if builtin_id < 0 {
                        self.builtin_offsets_for_current_program.insert(location);
                    }
                    return Ok(true);
                }
                return Ok(false);
            }

            // For section-type symbols with empty names, resolve the actual
            // function name from the symbol table at the target offset.
            let mut target_function_name = symbol_name.to_string();
            if target_function_name.is_empty() && symbol_type == elf::STT_SECTION {
                let target_byte_offset = if addend != 0 {
                    addend
                } else {
                    (i64::from(instructions[location].imm) + 1) * size_of::<EbpfInst>() as i64
                };
                if target_byte_offset < 0
                    || !(target_byte_offset as u64).is_multiple_of(size_of::<EbpfInst>() as u64)
                {
                    return Err(UnmarshalError(
                        "Invalid section-local call target offset".into(),
                    ));
                }
                if let Some(name) = find_function_symbol_at_offset(
                    self.symbols,
                    self.sym_count,
                    symbol_section_index,
                    target_byte_offset as u64,
                ) {
                    target_function_name = name;
                }
            }

            if !target_function_name.is_empty()
                && !self.has_function_relocation(self.raw_programs.len(), location)
            {
                let prog_index = self.raw_programs.len();
                self.function_relocations.push(FunctionRelocation {
                    prog_index,
                    source_offset: location,
                    relocation_entry_index: sym_index,
                    target_section_index: symbol_section_index,
                    target_function_name,
                });
            }
            return Ok(true);
        }

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
        let inst_size = size_of::<EbpfInst>() as u64;
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
            sd.sym_type,
            sd.bind,
            instructions,
            loc,
            sym_idx,
            addend,
        )? {
            self.unresolved_symbol_errors.push(UnresolvedSymbolError {
                section: section_name.to_string(),
                message: format!(
                    "Unresolved external symbol {} in section {} at location {}",
                    if sd.name.is_empty() {
                        "<anonymous>"
                    } else {
                        &sd.name
                    },
                    section_name,
                    loc,
                ),
            });
        }
        Ok(())
    }

    // ── Function relocation helpers ────────────────────────────────

    /// Check whether a function relocation has already been recorded for a
    /// given (prog_index, source_offset) pair.
    fn has_function_relocation(&self, prog_index: usize, source_offset: usize) -> bool {
        self.function_relocations
            .iter()
            .any(|r| r.prog_index == prog_index && r.source_offset == source_offset)
    }

    /// Scan a program for CALL instructions with local source that were not
    /// already resolved by relocations, and record synthetic function
    /// relocations for them.
    fn enqueue_synthetic_local_calls(
        &mut self,
        instructions: &[EbpfInst],
        section_index: usize,
        section_size: u64,
        program_offset: u64,
    ) -> Result<(), UnmarshalError> {
        use crate::spec::vm_isa::INST_CALL_LOCAL;

        let inst_size = size_of::<EbpfInst>() as i64;
        let section_insn_count = section_size as i64 / inst_size;
        let program_start = program_offset as i64 / inst_size;
        let program_end = program_start + instructions.len() as i64;
        let prog_index = self.raw_programs.len();

        for (loc, inst) in instructions.iter().enumerate() {
            if !(inst.opcode == INST_OP_CALL && inst.src_raw() == INST_CALL_LOCAL) {
                continue;
            }
            if self.has_function_relocation(prog_index, loc) {
                continue;
            }

            let target = program_start + loc as i64 + 1 + i64::from(inst.imm);
            // Skip targets within the current program (already local).
            if target >= program_start && target < program_end {
                continue;
            }
            if target < 0 || target >= section_insn_count {
                return Err(UnmarshalError(
                    "Local call target out of section bounds".into(),
                ));
            }

            let target_offset = (target * inst_size) as u64;
            let target_name = find_function_symbol_at_offset(
                self.symbols,
                self.sym_count,
                section_index,
                target_offset,
            )
            .ok_or_else(|| {
                UnmarshalError(format!(
                    "Subprogram not found at section offset {target_offset}"
                ))
            })?;

            self.function_relocations.push(FunctionRelocation {
                prog_index,
                source_offset: loc,
                relocation_entry_index: 0,
                target_section_index: section_index,
                target_function_name: target_name,
            });
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

    /// Process CO-RE relocations from the `.BTF.ext` core_relo subsection.
    ///
    /// Mirrors C++ `ProgramReader::process_core_relocations`.  Directly parses
    /// the core_relo subsection rather than going through ELF relocation entries.
    fn process_core_relocations(
        &mut self,
        btf_data: &BtfTypeData,
        btf_section_data: &[u8],
    ) -> Result<(), UnmarshalError> {
        let btf_ext_sec = match self.elf.section_by_name(".BTF.ext") {
            Some(s) => s,
            None => return Ok(()),
        };
        let ext = btf_ext_sec
            .data()
            .map_err(|e| UnmarshalError(format!("Cannot read .BTF.ext section: {e}")))?;
        if ext.len() < 8 {
            return Ok(());
        }

        // BTF.ext header: magic(2), version(1), flags(1), hdr_len(4),
        //   func_info_off(4), func_info_len(4), line_info_off(4), line_info_len(4),
        //   core_relo_off(4), core_relo_len(4)
        let magic = u16::from_le_bytes([ext[0], ext[1]]);
        let version = ext[2];
        if magic != 0xEB9F || version != 1 {
            return Err(UnmarshalError("Invalid .BTF.ext header".into()));
        }
        let hdr_len = u32::from_le_bytes([ext[4], ext[5], ext[6], ext[7]]) as usize;
        if hdr_len < 32 || hdr_len > ext.len() {
            return Ok(()); // Header too short for core_relo fields — no CO-RE data.
        }

        let core_relo_off = u32::from_le_bytes([ext[24], ext[25], ext[26], ext[27]]) as usize;
        let core_relo_len = u32::from_le_bytes([ext[28], ext[29], ext[30], ext[31]]) as usize;

        let core_start = hdr_len + core_relo_off;
        let core_end = core_start + core_relo_len;
        if core_start >= core_end || core_end > ext.len() {
            return Ok(());
        }

        // First u32 is the record size.
        if core_end - core_start < 4 {
            return Err(UnmarshalError(
                "BTF.ext core_relo subsection truncated".into(),
            ));
        }
        let rec_size = u32::from_le_bytes([
            ext[core_start],
            ext[core_start + 1],
            ext[core_start + 2],
            ext[core_start + 3],
        ]) as usize;
        if rec_size < 16 {
            return Err(UnmarshalError(
                "Invalid CO-RE relocation record size".into(),
            ));
        }

        // Build section-name → programs map for matching.
        let mut progs_by_section: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (idx, prog) in self.raw_programs.iter().enumerate() {
            progs_by_section
                .entry(prog.section_name.clone())
                .or_default()
                .push(idx);
        }

        let inst_size = size_of::<EbpfInst>();
        let mut offset = core_start + 4;
        while offset < core_end {
            // Per-section header: sec_name_off(4), num_info(4).
            if offset + 8 > core_end {
                break;
            }
            let sec_name_off = u32::from_le_bytes([
                ext[offset],
                ext[offset + 1],
                ext[offset + 2],
                ext[offset + 3],
            ]);
            let num_info = u32::from_le_bytes([
                ext[offset + 4],
                ext[offset + 5],
                ext[offset + 6],
                ext[offset + 7],
            ]) as usize;
            offset += 8;

            let records_size = num_info * rec_size;
            if offset + records_size > core_end {
                return Err(UnmarshalError("CO-RE section records out of bounds".into()));
            }

            let section_name = crate::btf::parse::read_btf_string(btf_section_data, sec_name_off)?;

            let prog_indices = match progs_by_section.get(&section_name) {
                Some(v) => v.clone(),
                None => {
                    offset += records_size;
                    continue;
                }
            };

            for i in 0..num_info {
                let rpos = offset + i * rec_size;
                let insn_off =
                    u32::from_le_bytes([ext[rpos], ext[rpos + 1], ext[rpos + 2], ext[rpos + 3]]);
                let type_id = u32::from_le_bytes([
                    ext[rpos + 4],
                    ext[rpos + 5],
                    ext[rpos + 6],
                    ext[rpos + 7],
                ]);
                let access_str_off = u32::from_le_bytes([
                    ext[rpos + 8],
                    ext[rpos + 9],
                    ext[rpos + 10],
                    ext[rpos + 11],
                ]);
                let kind_raw = u32::from_le_bytes([
                    ext[rpos + 12],
                    ext[rpos + 13],
                    ext[rpos + 14],
                    ext[rpos + 15],
                ]);

                // Find the program that contains this instruction.
                let mut applied = false;
                for &pidx in &prog_indices {
                    let prog = &self.raw_programs[pidx];
                    let prog_start = prog.insn_off;
                    let prog_end = prog_start + (prog.prog.len() as u32) * (inst_size as u32);
                    if insn_off >= prog_start && insn_off < prog_end {
                        let inst_idx = ((insn_off - prog_start) as usize) / inst_size;
                        apply_core_relocation(
                            &mut self.raw_programs[pidx].prog[inst_idx],
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
                // Silently skip relocations for programs not in our set
                // (e.g. filtered by desired_section).
                let _ = applied;
            }

            offset += records_size;
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
            match self.resolve_subprograms_for(prog_idx, &prog_lookup, &mut resolved, &mut visiting)
            {
                Ok(()) => {}
                Err(_)
                    if !self.desired_section.is_empty()
                        && self.raw_programs[prog_idx].section_name != self.desired_section =>
                {
                    // Silently ignore subprogram errors for non-desired sections
                }
                Err(e) => return Err(e),
            }
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
                    r.target_section_index,
                    r.target_function_name.clone(),
                )
            })
            .collect();

        let mut subprogram_offsets: BTreeMap<String, usize> = BTreeMap::new();

        for (source_offset, target_section_index, target_name) in &relocs_for_prog {
            if !subprogram_offsets.contains_key(target_name) {
                let current_len = self.raw_programs[prog_idx].prog.len();
                subprogram_offsets.insert(target_name.clone(), current_len);

                let sub_sec_name = self.section_name_by_index(*target_section_index)?;
                let sub_key = (sub_sec_name, target_name.clone());
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
                    let sub_builtin_offsets =
                        self.raw_programs[sub_idx].info.builtin_call_offsets.clone();
                    self.raw_programs[prog_idx]
                        .info
                        .builtin_call_offsets
                        .extend(sub_builtin_offsets.into_iter().map(|off| base + off));

                    self.raw_programs[prog_idx]
                        .prog
                        .extend_from_slice(&sub_instructions);
                } else {
                    let err_msg = format!("Subprogram not found: {}", target_name);
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
        self.build_ksym_function_resolution_cache()?;
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
            // Parse all section instructions for reachable-span computation.
            let section_instructions = bytes_to_instructions(sec_data)?;

            let mut offset: u64 = 0;
            while offset < sec_size {
                self.builtin_offsets_for_current_program.clear();
                let (name, initial_size) = get_program_name_and_size(
                    sec_idx,
                    sec_name,
                    sec_size,
                    offset,
                    self.symbols,
                    self.sym_count,
                );

                // Expand the program span to cover all reachable instructions.
                let extracted_size =
                    compute_reachable_program_span(&section_instructions, offset, initial_size);

                let end = offset + extracted_size;
                if end > sec_size {
                    return Err(UnmarshalError(format!(
                        "Program '{name}' extends past section boundary"
                    )));
                }
                let mut instructions =
                    bytes_to_instructions(&sec_data[offset as usize..end as usize])?;

                if let Some(reloc_sh) = reloc_sh {
                    self.process_relocations(
                        &mut instructions,
                        sec_name,
                        offset,
                        extracted_size,
                        reloc_sh,
                    )?;
                }

                // Discover local calls not covered by explicit relocation entries.
                self.enqueue_synthetic_local_calls(&instructions, sec_idx, sec_size, offset)?;

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
                        builtin_call_offsets: std::mem::take(
                            &mut self.builtin_offsets_for_current_program,
                        ),
                        ..Default::default()
                    },
                });

                // Advance by the symbol-derived size, not the reachable span.
                // The reachable span may extend beyond the symbol boundary
                // (e.g. for local calls to adjacent functions), but the next
                // program starts at the next symbol boundary.
                offset += initial_size;
            }
        }

        // Process CO-RE relocations if .BTF section exists
        if let Some(btf_section) = self.elf.section_by_name(".BTF")
            && let Ok(btf_bytes) = btf_section.data()
        {
            let btf_data = BtfTypeData::new(btf_bytes).map_err(|e| {
                UnmarshalError(format!(
                    "Unsupported or invalid CO-RE/BTF relocation data: {e}"
                ))
            })?;
            self.process_core_relocations(&btf_data, btf_bytes)?;
        }

        let has_relevant = self
            .unresolved_symbol_errors
            .iter()
            .any(|e| self.desired_section.is_empty() || e.section == self.desired_section);
        if has_relevant {
            for e in &self.unresolved_symbol_errors {
                if self.desired_section.is_empty() || e.section == self.desired_section {
                    eprintln!("{}", e.message);
                }
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

/// Unwrap typedef/const/volatile/restrict/type_tag to reach the underlying type.
fn unwrap_btf_type(btf_data: &BtfTypeData, mut type_id: u32) -> Result<u32, UnmarshalError> {
    use crate::btf::{BtfKind, BtfKindIndex};
    for _ in 0..256 {
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
            BtfKindIndex::TypeTag => {
                if let BtfKind::TypeTag { type_id: inner, .. } = btf_data.get_kind(type_id)? {
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

// ── BTF member offset encoding helpers ──────────────────────────────

/// Extract the bit offset from a raw BTF member offset encoding.
/// The lower 24 bits encode the bit offset.
fn btf_member_bit_offset(raw: u32) -> u32 {
    raw & 0x00ff_ffff
}

/// Extract the bitfield size from a raw BTF member offset encoding.
/// Bits 24-31 encode the bitfield size (0 = not a bitfield).
fn btf_member_bitfield_size(raw: u32) -> u32 {
    (raw >> 24) & 0xff
}

// ── CO-RE field resolution ──────────────────────────────────────────

/// Result of resolving a CO-RE field access path.
struct CoreFieldResolution {
    type_id: u32,
    offset_bits: u64,
    /// Raw BTF member offset encoding of the last struct/union member accessed.
    member_offset_encoding: Option<u32>,
}

/// Walk a CO-RE access string to resolve a field within a BTF type.
fn resolve_core_field(
    btf_data: &BtfTypeData,
    type_id: u32,
    access_string: &str,
) -> Result<CoreFieldResolution, UnmarshalError> {
    use crate::btf::{BtfKind, BtfKindIndex};
    let mut indices = parse_core_access_string(access_string)?;
    // Clang/libbpf encode root type with a leading "0" accessor.
    if !indices.is_empty() && indices[0] == 0 {
        indices.remove(0);
    }
    let mut result = CoreFieldResolution {
        type_id,
        offset_bits: 0,
        member_offset_encoding: None,
    };

    for &index in &indices {
        result.type_id = unwrap_btf_type(btf_data, result.type_id)?;
        match btf_data.get_kind_index(result.type_id)? {
            BtfKindIndex::Struct | BtfKindIndex::Union => {
                let members = match btf_data.get_kind(result.type_id)? {
                    BtfKind::Struct { members, .. } | BtfKind::Union { members, .. } => members,
                    _ => unreachable!(),
                };
                if (index as usize) >= members.len() {
                    return Err(UnmarshalError(format!(
                        "CO-RE: member index {index} out of bounds (size {}) for access path {access_string}",
                        members.len()
                    )));
                }
                let member = &members[index as usize];
                result.offset_bits +=
                    u64::from(btf_member_bit_offset(member.offset_from_start_in_bits));
                result.member_offset_encoding = Some(member.offset_from_start_in_bits);
                result.type_id = member.type_id;
            }
            BtfKindIndex::Array => {
                if let BtfKind::Array {
                    element_type,
                    count_of_elements,
                    ..
                } = btf_data.get_kind(result.type_id)?
                {
                    if index >= *count_of_elements {
                        return Err(UnmarshalError(format!(
                            "CO-RE: array index {index} out of bounds (size {count_of_elements}) for access path {access_string}"
                        )));
                    }
                    let elem_size = btf_data.get_size(*element_type)?;
                    result.offset_bits += u64::from(index) * u64::from(elem_size) * 8;
                    result.member_offset_encoding = None;
                    result.type_id = *element_type;
                }
            }
            _ => {
                return Err(UnmarshalError(
                    "CO-RE: indexing into non-aggregate type".into(),
                ));
            }
        }
    }

    result.type_id = unwrap_btf_type(btf_data, result.type_id)?;
    Ok(result)
}

/// Compute the effective bit width of a resolved CO-RE field.
fn core_field_bit_width(
    btf_data: &BtfTypeData,
    field: &CoreFieldResolution,
) -> Result<u32, UnmarshalError> {
    use crate::btf::{BtfKind, BtfKindIndex};
    // Check for explicit bitfield size in the member encoding.
    if let Some(encoding) = field.member_offset_encoding {
        let bf_size = btf_member_bitfield_size(encoding);
        if bf_size != 0 {
            return Ok(bf_size);
        }
    }
    if btf_data.get_kind_index(field.type_id)? == BtfKindIndex::Int
        && let BtfKind::Int {
            field_width_in_bits,
            size_in_bytes,
            ..
        } = btf_data.get_kind(field.type_id)?
    {
        return Ok(if *field_width_in_bits != 0 {
            u32::from(*field_width_in_bits)
        } else {
            *size_in_bytes * 8
        });
    }
    Ok(btf_data.get_size(field.type_id)? * 8)
}

/// Check whether a CO-RE field byte offset relocation should patch
/// the instruction's `offset` field (for LDX/ST/STX with MEM/MEMSX/ATOMIC mode).
fn core_field_offset_uses_offset_field(inst: &EbpfInst) -> bool {
    use crate::spec::vm_isa::{INST_CLS_ST, INST_CLS_STX, INST_MODE_ATOMIC};
    let cls = inst.opcode & INST_CLS_MASK;
    if cls != INST_CLS_LDX && cls != INST_CLS_ST && cls != INST_CLS_STX {
        return false;
    }
    let mode = inst.opcode & 0xe0; // INST_MODE_MASK
    mode == INST_MODE_MEM || mode == INST_MODE_MEMSX || mode == INST_MODE_ATOMIC
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
    use crate::btf::{BtfKind, BtfKindIndex};

    // Resolve field lazily — only computed for FIELD_* kinds.
    let resolve_field = || -> Result<CoreFieldResolution, UnmarshalError> {
        let access_string = crate::btf::parse::read_btf_string(btf_section_data, access_str_off)?;
        resolve_core_field(btf_data, type_id, &access_string)
    };

    match kind_raw {
        core_relo_kind::FIELD_BYTE_OFFSET => {
            let field = resolve_field()?;
            let byte_offset = (field.offset_bits / 8) as i64;
            if core_field_offset_uses_offset_field(inst) {
                if byte_offset < i64::from(i16::MIN) || byte_offset > i64::from(i16::MAX) {
                    return Err(UnmarshalError(
                        "CO-RE field offset does not fit instruction offset field".into(),
                    ));
                }
                inst.offset = byte_offset as i16;
            } else {
                inst.imm = byte_offset as i32;
            }
        }
        core_relo_kind::FIELD_BYTE_SIZE => {
            let field = resolve_field()?;
            inst.imm = btf_data.get_size(field.type_id)? as i32;
        }
        core_relo_kind::FIELD_EXISTS => {
            inst.imm = 1;
        }
        core_relo_kind::FIELD_SIGNED => {
            let field = resolve_field()?;
            inst.imm = match btf_data.get_kind_index(field.type_id)? {
                BtfKindIndex::Int => {
                    if let BtfKind::Int { is_signed, .. } = btf_data.get_kind(field.type_id)? {
                        i32::from(*is_signed)
                    } else {
                        0
                    }
                }
                BtfKindIndex::Enum => {
                    if let BtfKind::Enum { is_signed, .. } = btf_data.get_kind(field.type_id)? {
                        i32::from(*is_signed)
                    } else {
                        0
                    }
                }
                BtfKindIndex::Enum64 => {
                    if let BtfKind::Enum64 { is_signed, .. } = btf_data.get_kind(field.type_id)? {
                        i32::from(*is_signed)
                    } else {
                        0
                    }
                }
                _ => 0,
            };
        }
        core_relo_kind::FIELD_LSHIFT_U64 => {
            let field = resolve_field()?;
            let bit_width = core_field_bit_width(btf_data, &field)?;
            let bit_offset_in_byte = (field.offset_bits % 8) as u32;
            if bit_width == 0 || bit_width > 64 || bit_offset_in_byte + bit_width > 64 {
                return Err(UnmarshalError(
                    "CO-RE field bit width exceeds 64 bits".into(),
                ));
            }
            inst.imm = (64 - (bit_offset_in_byte + bit_width)) as i32;
        }
        core_relo_kind::FIELD_RSHIFT_U64 => {
            let field = resolve_field()?;
            let bit_width = core_field_bit_width(btf_data, &field)?;
            if bit_width == 0 || bit_width > 64 {
                return Err(UnmarshalError(
                    "CO-RE field bit width exceeds 64 bits".into(),
                ));
            }
            inst.imm = (64 - bit_width) as i32;
        }
        core_relo_kind::TYPE_ID_LOCAL | core_relo_kind::TYPE_ID_TARGET => {
            inst.imm = unwrap_btf_type(btf_data, type_id)? as i32;
        }
        core_relo_kind::TYPE_EXISTS | core_relo_kind::TYPE_MATCHES => {
            // Static verifier without target-kernel BTF: existence/match folds to true.
            inst.imm = 1;
        }
        core_relo_kind::TYPE_SIZE => {
            inst.imm = btf_data.get_size(unwrap_btf_type(btf_data, type_id)?)? as i32;
        }
        core_relo_kind::ENUMVAL_EXISTS | core_relo_kind::ENUMVAL_VALUE => {
            let as_str = crate::btf::parse::read_btf_string(btf_section_data, access_str_off)?;
            let indices = parse_core_access_string(&as_str)?;
            if indices.is_empty() {
                return Err(UnmarshalError(
                    "CO-RE enum relocation missing enum value index".into(),
                ));
            }
            let enum_member_index = *indices.last().unwrap();
            let enum_type_id = unwrap_btf_type(btf_data, type_id)?;

            match btf_data.get_kind_index(enum_type_id)? {
                BtfKindIndex::Enum => {
                    if let BtfKind::Enum { members, .. } = btf_data.get_kind(enum_type_id)? {
                        if (enum_member_index as usize) >= members.len() {
                            return Err(UnmarshalError(
                                "CO-RE enum member index out of bounds".into(),
                            ));
                        }
                        inst.imm = if kind_raw == core_relo_kind::ENUMVAL_EXISTS {
                            1
                        } else {
                            members[enum_member_index as usize].value as i32
                        };
                    }
                }
                BtfKindIndex::Enum64 => {
                    if let BtfKind::Enum64 { members, .. } = btf_data.get_kind(enum_type_id)? {
                        if (enum_member_index as usize) >= members.len() {
                            return Err(UnmarshalError(
                                "CO-RE enum64 member index out of bounds".into(),
                            ));
                        }
                        inst.imm = if kind_raw == core_relo_kind::ENUMVAL_EXISTS {
                            1
                        } else {
                            members[enum_member_index as usize].value as i32
                        };
                    }
                }
                _ => {
                    return Err(UnmarshalError(
                        "CO-RE enum relocation target is not enum/enum64".into(),
                    ));
                }
            }
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
    let inst_size = size_of::<EbpfInst>();

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

// ── ElfObject helpers ───────────────────────────────────────────────

/// Filter programs by desired function name (empty = keep all).
/// Returns an error if the name is specified but not found or ambiguous.
fn filter_by_program(
    programs: &[RawProgram],
    desired_program: &str,
) -> Result<Vec<RawProgram>, UnmarshalError> {
    if desired_program.is_empty() {
        return Ok(programs.to_vec());
    }
    let selected: Vec<RawProgram> = programs
        .iter()
        .filter(|p| p.function_name == desired_program)
        .cloned()
        .collect();
    if selected.is_empty() {
        return Err(UnmarshalError(format!(
            "Program not found: {desired_program}"
        )));
    }
    Ok(selected)
}

// ── ElfObject ───────────────────────────────────────────────────────

/// Information about a program discovered in an ELF file.
///
/// Mirrors C++ `ElfProgramInfo` from `elf_loader.hpp`.
pub struct ElfProgramInfo {
    pub section_name: String,
    pub function_name: String,
    pub section_offset: u32,
    pub invalid: bool,
    pub invalid_reason: String,
}

/// Cached result of loading a single ELF section.
///
/// Mirrors C++ `SectionCacheEntry`.
struct SectionCacheEntry {
    valid: bool,
    error: String,
    programs: Vec<RawProgram>,
}

/// ELF object that supports listing programs even when some sections fail to load.
///
/// Mirrors C++ `ElfObject` from `elf_loader.hpp`.  Separates program discovery
/// (enumerating section/function names from the symbol table) from full loading
/// (BTF, relocations, subprogram linking), so that `list_programs` can report
/// per-section errors without aborting.
pub struct ElfObject {
    data: Vec<u8>,
    path: String,
    options: EbpfVerifierOptions,

    catalog_loaded: bool,
    programs: Vec<ElfProgramInfo>,
    section_order: Vec<String>,
    section_program_indices: BTreeMap<String, Vec<usize>>,
    section_cache: BTreeMap<String, SectionCacheEntry>,
}

impl ElfObject {
    /// Create a new `ElfObject` by reading the file into memory.
    pub fn new(path: &str, options: EbpfVerifierOptions) -> Result<Self, UnmarshalError> {
        let data =
            std::fs::read(path).map_err(|e| UnmarshalError(format!("{e} opening {path}")))?;
        Ok(Self {
            data,
            path: path.to_string(),
            options,
            catalog_loaded: false,
            programs: Vec::new(),
            section_order: Vec::new(),
            section_program_indices: BTreeMap::new(),
            section_cache: BTreeMap::new(),
        })
    }

    /// Discover all programs from the ELF symbol table without full loading.
    ///
    /// Catalogs `(section_name, function_name, section_offset)` from executable
    /// sections.  Does not process BTF or relocations.
    fn discover_programs(&mut self) -> Result<(), UnmarshalError> {
        if self.catalog_loaded {
            return Ok(());
        }

        let data: &[u8] = &self.data;
        let elf: ElfFile<'_, Elf64> = ElfFile::parse(data)
            .map_err(|e| UnmarshalError(format!("Can't process ELF file {}: {e}", self.path)))?;
        let header = elf.elf_header();
        let sections = header
            .sections(ENDIAN, data)
            .map_err(|e| UnmarshalError(format!("Cannot read sections: {e}")))?;
        let symbols = sections
            .symbols(ENDIAN, data, elf::SHT_SYMTAB)
            .map_err(|e| {
                UnmarshalError(format!(
                    "No symbol section found in ELF file {}: {e}",
                    self.path
                ))
            })?;
        let sym_count = symbols.len();

        for section in elf.sections() {
            let sh = section.elf_section_header();
            let flags = sh.sh_flags(ENDIAN);
            if flags & u64::from(elf::SHF_EXECINSTR) == 0 {
                continue;
            }
            let sec_size = section.size();
            if sec_size == 0 {
                continue;
            }
            if section.data().map(|d| d.is_empty()).unwrap_or(true) {
                continue;
            }
            let sec_name = section.name().unwrap_or("").to_string();
            let sec_idx = section.index().0;

            if !self.section_order.contains(&sec_name) {
                self.section_order.push(sec_name.clone());
            }

            let mut offset: u64 = 0;
            while offset < sec_size {
                let (name, initial_size) = get_program_name_and_size(
                    sec_idx, &sec_name, sec_size, offset, &symbols, sym_count,
                );
                let prog_idx = self.programs.len();
                self.programs.push(ElfProgramInfo {
                    section_name: sec_name.clone(),
                    function_name: name,
                    section_offset: offset as u32,
                    invalid: false,
                    invalid_reason: String::new(),
                });
                self.section_program_indices
                    .entry(sec_name.clone())
                    .or_default()
                    .push(prog_idx);
                offset += initial_size;
            }
        }

        self.catalog_loaded = true;
        Ok(())
    }

    /// Mark all programs in a section as valid or invalid.
    fn mark_section_validity(&mut self, section_name: &str, valid: bool, reason: &str) {
        if let Some(indices) = self.section_program_indices.get(section_name) {
            for &idx in indices {
                self.programs[idx].invalid = !valid;
                if !valid {
                    self.programs[idx].invalid_reason = reason.to_string();
                }
            }
        }
    }

    /// Load a single section, caching the result and marking programs invalid on error.
    fn load_section(&mut self, section_name: &str, platform: &mut dyn EbpfPlatform) {
        if self.section_cache.contains_key(section_name) {
            return;
        }
        let entry = match read_elf(
            &self.data,
            &self.path,
            section_name,
            "",
            &self.options,
            platform,
        ) {
            Ok(programs) => {
                self.mark_section_validity(section_name, true, "");
                SectionCacheEntry {
                    valid: true,
                    error: String::new(),
                    programs,
                }
            }
            Err(e) => {
                let error = e.to_string();
                self.mark_section_validity(section_name, false, &error);
                SectionCacheEntry {
                    valid: false,
                    error,
                    programs: Vec::new(),
                }
            }
        };
        self.section_cache.insert(section_name.to_string(), entry);
    }

    /// List all programs in the ELF file, loading each section to check validity.
    ///
    /// Mirrors C++ `ElfObject::list_programs()`.
    pub fn list_programs(&mut self, platform: &mut dyn EbpfPlatform) -> &[ElfProgramInfo] {
        if self.discover_programs().is_err() {
            return &[];
        }
        let sections: Vec<String> = self.section_order.clone();
        for sec in &sections {
            self.load_section(sec, platform);
        }
        &self.programs
    }

    /// Load and return programs matching the given section and program name.
    ///
    /// Mirrors C++ `ElfObject::get_programs()`.  When `desired_section` is
    /// non-empty, loads only that section.  When empty, loads all sections
    /// individually (catching per-section errors) and collects valid programs.
    pub fn get_programs(
        &mut self,
        desired_section: &str,
        desired_program: &str,
        platform: &mut dyn EbpfPlatform,
    ) -> Result<Vec<RawProgram>, UnmarshalError> {
        self.discover_programs()?;

        if !desired_section.is_empty() {
            self.load_section(desired_section, platform);
            let entry = self
                .section_cache
                .get(desired_section)
                .ok_or_else(|| UnmarshalError("Section not found".into()))?;
            if !entry.valid {
                return Err(UnmarshalError(entry.error.clone()));
            }
            let programs = filter_by_program(&entry.programs, desired_program)?;
            return Ok(programs);
        }

        // No specific section requested — load all sections, collect valid programs.
        let sections: Vec<String> = self.section_order.clone();
        for sec in &sections {
            self.load_section(sec, platform);
        }
        let mut all_programs = Vec::new();
        for sec in &sections {
            if let Some(entry) = self.section_cache.get(sec)
                && entry.valid
            {
                all_programs.extend(entry.programs.iter().cloned());
            }
        }
        if all_programs.is_empty() {
            return Err(UnmarshalError("No executable sections".into()));
        }
        let programs = filter_by_program(&all_programs, desired_program)?;
        Ok(programs)
    }
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
        assert!(is_map_section(".maps"));
        assert!(is_map_section(".maps/inner"));
        assert!(!is_map_section("map"));
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
            verbosity_opts: crate::spec::config::VerbosityOptions {
                simplify: true,
                ..crate::spec::config::VerbosityOptions::default()
            },
            ..Default::default()
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
