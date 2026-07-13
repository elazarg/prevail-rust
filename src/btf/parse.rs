// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Raw BTF/BTF.ext binary parsing.
//!
//! Ports `external/libbtf/libbtf/btf_parse.cpp`.

use std::collections::BTreeMap;
use std::mem;

use super::*;

// ── Byte-swap helpers ────────────────────────────────────────────────

fn bswap_32(val: u32) -> u32 {
    val.swap_bytes()
}

fn swap_header(h: &mut BtfHeader) {
    // magic, version, flags are used as-is for detection
    h.hdr_len = bswap_32(h.hdr_len);
    h.type_off = bswap_32(h.type_off);
    h.type_len = bswap_32(h.type_len);
    h.str_off = bswap_32(h.str_off);
    h.str_len = bswap_32(h.str_len);
}

fn swap_ext_header(h: &mut BtfExtHeader) {
    h.hdr_len = bswap_32(h.hdr_len);
    h.func_info_off = bswap_32(h.func_info_off);
    h.func_info_len = bswap_32(h.func_info_len);
    h.line_info_off = bswap_32(h.line_info_off);
    h.line_info_len = bswap_32(h.line_info_len);
}

fn swap_raw_type(t: &mut BtfRawType) {
    t.name_off = bswap_32(t.name_off);
    t.info = bswap_32(t.info);
    t.size_or_type = bswap_32(t.size_or_type);
}

fn swap_raw_array(a: &mut BtfRawArray) {
    a.element_type = bswap_32(a.element_type);
    a.index_type = bswap_32(a.index_type);
    a.nelems = bswap_32(a.nelems);
}

fn swap_raw_member(m: &mut BtfRawMember) {
    m.name_off = bswap_32(m.name_off);
    m.type_id = bswap_32(m.type_id);
    m.offset = bswap_32(m.offset);
}

fn swap_raw_param(p: &mut BtfRawParam) {
    p.name_off = bswap_32(p.name_off);
    p.type_id = bswap_32(p.type_id);
}

fn swap_raw_var(v: &mut BtfRawVar) {
    v.linkage = bswap_32(v.linkage);
}

fn swap_raw_var_secinfo(s: &mut BtfRawVarSecInfo) {
    s.type_id = bswap_32(s.type_id);
    s.offset = bswap_32(s.offset);
    s.size = bswap_32(s.size);
}

fn swap_raw_enum(e: &mut BtfRawEnum) {
    e.name_off = bswap_32(e.name_off);
    e.val = bswap_32(e.val);
}

fn swap_raw_enum64(e: &mut BtfRawEnum64) {
    e.name_off = bswap_32(e.name_off);
    e.val_lo32 = bswap_32(e.val_lo32);
    e.val_hi32 = bswap_32(e.val_hi32);
}

fn swap_raw_decl_tag(t: &mut BtfRawDeclTag) {
    t.component_idx = bswap_32(t.component_idx);
}

fn swap_ext_info_sec(s: &mut BtfExtInfoSec) {
    s.sec_name_off = bswap_32(s.sec_name_off);
    s.num_info = bswap_32(s.num_info);
}

fn swap_line_info(i: &mut BpfLineInfo) {
    i.insn_off = bswap_32(i.insn_off);
    i.file_name_off = bswap_32(i.file_name_off);
    i.line_off = bswap_32(i.line_off);
    i.line_col = bswap_32(i.line_col);
}

// ── Generic read helper ──────────────────────────────────────────────

/// Read a `T` from `data` at `offset`, advancing `offset` past it.
/// Optionally byte-swap the result.
fn read_struct<T: zerocopy::FromBytes + Copy>(
    data: &[u8],
    offset: &mut usize,
    min: usize,
    max: usize,
) -> Result<T, UnmarshalError> {
    let size = mem::size_of::<T>();
    if *offset < min || *offset + size > max {
        return Err(UnmarshalError(
            "Invalid .BTF section - offset out of range".into(),
        ));
    }
    let val = T::read_from_bytes(&data[*offset..*offset + size])
        .map_err(|_| UnmarshalError("Invalid .BTF section - read error".into()))?;
    *offset += size;
    Ok(val)
}

/// Read a null-terminated string from `data` at `offset`, within `[min, max)`.
fn read_string(
    data: &[u8],
    offset: &mut usize,
    min: usize,
    max: usize,
) -> Result<String, UnmarshalError> {
    if *offset < min || *offset >= max {
        return Err(UnmarshalError(
            "Invalid .BTF section - string offset out of range".into(),
        ));
    }
    let start = *offset;
    // find null terminator
    let mut end = start;
    while end < max && data[end] != 0 {
        end += 1;
    }
    if end >= max {
        return Err(UnmarshalError(
            "Invalid .BTF section - unterminated string".into(),
        ));
    }
    let s = std::str::from_utf8(&data[start..end])
        .map_err(|e| UnmarshalError(format!("Invalid .BTF section - non-UTF8 string: {e}")))?
        .to_string();
    *offset = end + 1; // skip null byte
    Ok(s)
}

// ── String table ─────────────────────────────────────────────────────

/// Parse the BTF header and string table, returning (string_table, swap_endian).
pub fn parse_string_table(data: &[u8]) -> Result<(BTreeMap<usize, String>, bool), UnmarshalError> {
    let hdr_size = mem::size_of::<BtfHeader>();
    if data.len() < hdr_size {
        return Err(UnmarshalError(
            "Invalid .BTF section - too small for header".into(),
        ));
    }

    let mut offset = 0usize;
    let mut header = read_struct::<BtfHeader>(data, &mut offset, 0, data.len())?;

    let swap_endian = match header.magic {
        BTF_HEADER_MAGIC => false,
        BTF_HEADER_MAGIC_BIG_ENDIAN => {
            swap_header(&mut header);
            true
        }
        _ => return Err(UnmarshalError("Invalid .BTF section - wrong magic".into())),
    };

    if header.version != BTF_HEADER_VERSION {
        return Err(UnmarshalError(
            "Invalid .BTF section - wrong version".into(),
        ));
    }
    if (header.hdr_len as usize) < hdr_size {
        return Err(UnmarshalError("Invalid .BTF section - wrong size".into()));
    }
    if header.hdr_len as usize > data.len() {
        return Err(UnmarshalError(
            "Invalid .BTF section - invalid header length".into(),
        ));
    }

    let str_start = header.hdr_len as usize + header.str_off as usize;
    let str_end = str_start + header.str_len as usize;
    if str_end > data.len() {
        return Err(UnmarshalError(
            "Invalid .BTF section - string table out of range".into(),
        ));
    }

    let mut table = BTreeMap::new();
    let mut pos = str_start;
    while pos < str_end {
        let string_offset = pos - str_start;
        let s = read_string(data, &mut pos, str_start, str_end)?;
        table.insert(string_offset, s);
    }

    Ok((table, swap_endian))
}

fn find_string(
    string_table: &BTreeMap<usize, String>,
    offset: usize,
) -> Result<String, UnmarshalError> {
    string_table
        .get(&offset)
        .cloned()
        .ok_or_else(|| UnmarshalError("Invalid .BTF section - invalid string offset".into()))
}

/// Parse struct/union member records from a BTF type.
fn parse_members(
    raw: &BtfRawType,
    data: &[u8],
    pos: &mut usize,
    type_start: usize,
    type_end: usize,
    swap_endian: bool,
    string_table: &BTreeMap<usize, String>,
) -> Result<Vec<BtfStructMember>, UnmarshalError> {
    let member_count = btf_type_info_vlen(raw.info);
    let mut members = Vec::with_capacity(member_count as usize);
    for _ in 0..member_count {
        let mut m = read_struct::<BtfRawMember>(data, pos, type_start, type_end)?;
        if swap_endian {
            swap_raw_member(&mut m);
        }
        let mname = if m.name_off != 0 {
            Some(find_string(string_table, m.name_off as usize)?)
        } else {
            None
        };
        members.push(BtfStructMember {
            name: mname,
            type_id: m.type_id,
            offset_from_start_in_bits: m.offset,
        });
    }
    Ok(members)
}

// ── Type parsing ─────────────────────────────────────────────────────

/// Parse all BTF type records from a `.BTF` section.
/// Returns (type_id, optional_name, BtfKind) tuples.
pub fn parse_types(
    data: &[u8],
) -> Result<Vec<(BtfTypeId, Option<String>, BtfKind)>, UnmarshalError> {
    let (string_table, swap_endian) = parse_string_table(data)?;

    let mut offset = 0usize;
    let mut header = read_struct::<BtfHeader>(data, &mut offset, 0, data.len())?;
    if swap_endian {
        swap_header(&mut header);
    }

    let type_start = header.hdr_len as usize + header.type_off as usize;
    let type_end = type_start + header.type_len as usize;
    if type_end > data.len() {
        return Err(UnmarshalError(
            "Invalid .BTF section - type section out of range".into(),
        ));
    }

    let mut results = Vec::new();
    // ID 0 is always void
    results.push((0u32, Some("void".to_string()), BtfKind::Void));

    let mut id: BtfTypeId = 0;
    let mut pos = type_start;

    while pos < type_end {
        let mut raw = read_struct::<BtfRawType>(data, &mut pos, type_start, type_end)?;
        if swap_endian {
            swap_raw_type(&mut raw);
        }

        let name = if raw.name_off != 0 {
            Some(find_string(&string_table, raw.name_off as usize)?)
        } else {
            let kind_raw = btf_type_info_kind(raw.info);
            // Types that require a name
            match kind_raw {
                1 | 7 | 8 | 12 | 14 | 15 | 16 | 17 | 18 => {
                    return Err(UnmarshalError("Invalid .BTF section - missing name".into()));
                }
                _ => None,
            }
        };

        let kind_raw = btf_type_info_kind(raw.info);
        let kind_idx = BtfKindIndex::from_raw(kind_raw).ok_or_else(|| {
            UnmarshalError(format!(
                "Invalid .BTF section - invalid BTF_KIND - {kind_raw}"
            ))
        })?;

        let kind = match kind_idx {
            BtfKindIndex::Void => {
                return Err(UnmarshalError(format!(
                    "Invalid .BTF section - invalid BTF_KIND - {kind_raw}"
                )));
            }

            BtfKindIndex::Int => {
                let mut int_data = read_struct::<u32>(data, &mut pos, type_start, type_end)?;
                if swap_endian {
                    int_data = bswap_32(int_data);
                }
                let encoding = btf_int_encoding(int_data);
                BtfKind::Int {
                    name: name.clone().unwrap(),
                    size_in_bytes: raw.size_or_type,
                    offset_from_start_in_bits: btf_int_offset(int_data),
                    field_width_in_bits: btf_int_bits(int_data),
                    is_signed: (encoding & BTF_INT_SIGNED) != 0,
                    is_char: (encoding & BTF_INT_CHAR) != 0,
                    is_bool: (encoding & BTF_INT_BOOL) != 0,
                }
            }

            BtfKindIndex::Ptr => BtfKind::Ptr {
                type_id: raw.size_or_type,
            },

            BtfKindIndex::Array => {
                let mut arr = read_struct::<BtfRawArray>(data, &mut pos, type_start, type_end)?;
                if swap_endian {
                    swap_raw_array(&mut arr);
                }
                BtfKind::Array {
                    element_type: arr.element_type,
                    index_type: arr.index_type,
                    count_of_elements: arr.nelems,
                }
            }

            BtfKindIndex::Struct => {
                let members = parse_members(
                    &raw,
                    data,
                    &mut pos,
                    type_start,
                    type_end,
                    swap_endian,
                    &string_table,
                )?;
                BtfKind::Struct {
                    name: name.clone(),
                    members,
                    size_in_bytes: raw.size_or_type,
                }
            }

            BtfKindIndex::Union => {
                let members = parse_members(
                    &raw,
                    data,
                    &mut pos,
                    type_start,
                    type_end,
                    swap_endian,
                    &string_table,
                )?;
                BtfKind::Union {
                    name: name.clone(),
                    members,
                    size_in_bytes: raw.size_or_type,
                }
            }

            BtfKindIndex::Enum => {
                let enum_count = btf_type_info_vlen(raw.info);
                let mut members = Vec::with_capacity(enum_count as usize);
                for _ in 0..enum_count {
                    let mut e = read_struct::<BtfRawEnum>(data, &mut pos, type_start, type_end)?;
                    if swap_endian {
                        swap_raw_enum(&mut e);
                    }
                    if e.name_off == 0 {
                        return Err(UnmarshalError(
                            "Invalid .BTF section - invalid BTF_KIND_ENUM member name".into(),
                        ));
                    }
                    members.push(BtfEnumMember {
                        name: find_string(&string_table, e.name_off as usize)?,
                        value: e.val,
                    });
                }
                BtfKind::Enum {
                    name: name.clone(),
                    is_signed: btf_type_info_kind_flag(raw.info),
                    members,
                    size_in_bytes: raw.size_or_type,
                }
            }

            BtfKindIndex::Fwd => BtfKind::Fwd {
                name: name.clone().unwrap(),
                is_struct: btf_type_info_kind_flag(raw.info),
            },

            BtfKindIndex::Typedef => BtfKind::Typedef {
                name: name.clone().unwrap(),
                type_id: raw.size_or_type,
            },

            BtfKindIndex::Volatile => BtfKind::Volatile {
                type_id: raw.size_or_type,
            },

            BtfKindIndex::Const => BtfKind::Const {
                type_id: raw.size_or_type,
            },

            BtfKindIndex::Restrict => BtfKind::Restrict {
                type_id: raw.size_or_type,
            },

            BtfKindIndex::Function => BtfKind::Function {
                name: name.clone().unwrap(),
                type_id: raw.size_or_type,
                linkage: BtfLinkage::from_raw(btf_type_info_vlen(raw.info)),
            },

            BtfKindIndex::FunctionPrototype => {
                let param_count = btf_type_info_vlen(raw.info);
                let mut parameters = Vec::with_capacity(param_count as usize);
                for _ in 0..param_count {
                    let mut p = read_struct::<BtfRawParam>(data, &mut pos, type_start, type_end)?;
                    if swap_endian {
                        swap_raw_param(&mut p);
                    }
                    let pname = if p.name_off != 0 {
                        find_string(&string_table, p.name_off as usize)?
                    } else {
                        String::new()
                    };
                    parameters.push(BtfFunctionParameter {
                        name: pname,
                        type_id: p.type_id,
                    });
                }
                BtfKind::FunctionPrototype {
                    parameters,
                    return_type: raw.size_or_type,
                }
            }

            BtfKindIndex::Var => {
                let mut v = read_struct::<BtfRawVar>(data, &mut pos, type_start, type_end)?;
                if swap_endian {
                    swap_raw_var(&mut v);
                }
                BtfKind::Var {
                    name: name.clone().unwrap(),
                    type_id: raw.size_or_type,
                    linkage: BtfLinkage::from_raw(v.linkage),
                }
            }

            BtfKindIndex::DataSection => {
                let section_count = btf_type_info_vlen(raw.info);
                let mut members = Vec::with_capacity(section_count as usize);
                for _ in 0..section_count {
                    let mut s =
                        read_struct::<BtfRawVarSecInfo>(data, &mut pos, type_start, type_end)?;
                    if swap_endian {
                        swap_raw_var_secinfo(&mut s);
                    }
                    members.push(BtfDataMember {
                        type_id: s.type_id,
                        offset: s.offset,
                        size: s.size,
                    });
                }
                BtfKind::DataSection {
                    name: name.clone().unwrap(),
                    members,
                    size: raw.size_or_type,
                }
            }

            BtfKindIndex::Float => BtfKind::Float {
                name: name.clone().unwrap(),
                size_in_bytes: raw.size_or_type,
            },

            BtfKindIndex::DeclTag => {
                let mut tag = read_struct::<BtfRawDeclTag>(data, &mut pos, type_start, type_end)?;
                if swap_endian {
                    swap_raw_decl_tag(&mut tag);
                }
                BtfKind::DeclTag {
                    name: name.clone().unwrap(),
                    type_id: raw.size_or_type,
                    component_index: tag.component_idx,
                }
            }

            BtfKindIndex::TypeTag => BtfKind::TypeTag {
                name: name.clone().unwrap(),
                type_id: raw.size_or_type,
            },

            BtfKindIndex::Enum64 => {
                let enum_count = btf_type_info_vlen(raw.info);
                let mut members = Vec::with_capacity(enum_count as usize);
                for _ in 0..enum_count {
                    let mut e = read_struct::<BtfRawEnum64>(data, &mut pos, type_start, type_end)?;
                    if swap_endian {
                        swap_raw_enum64(&mut e);
                    }
                    let mname = find_string(&string_table, e.name_off as usize)?;
                    members.push(BtfEnum64Member {
                        name: mname,
                        value: (e.val_hi32 as u64) << 32 | e.val_lo32 as u64,
                    });
                }
                BtfKind::Enum64 {
                    name: name.clone(),
                    is_signed: btf_type_info_kind_flag(raw.info),
                    members,
                    size_in_bytes: raw.size_or_type,
                }
            }
        };

        id += 1;
        results.push((id, name, kind));
    }

    Ok(results)
}

// ── Line info parsing ────────────────────────────────────────────────

/// Line information record produced by parsing `.BTF.ext`.
pub struct LineInfoRecord {
    pub section: String,
    pub instruction_offset: u32,
    pub file_name: String,
    pub source: String,
    pub line_number: u32,
    pub column_number: u32,
}

/// Parse `.BTF` and `.BTF.ext` sections to extract line information.
pub fn parse_line_information(
    btf_data: &[u8],
    btf_ext_data: &[u8],
) -> Result<Vec<LineInfoRecord>, UnmarshalError> {
    let (string_table, _swap_endian) = parse_string_table(btf_data)?;

    // Parse BTF.ext header
    let ext_hdr_size = mem::size_of::<BtfExtHeader>();
    if btf_ext_data.len() < ext_hdr_size {
        return Err(UnmarshalError(
            "Invalid .BTF.ext section - too small for header".into(),
        ));
    }

    let mut offset = 0usize;
    let mut ext_header =
        read_struct::<BtfExtHeader>(btf_ext_data, &mut offset, 0, btf_ext_data.len())?;

    let swap_endian_ext = match ext_header.magic {
        BTF_HEADER_MAGIC => false,
        BTF_HEADER_MAGIC_BIG_ENDIAN => {
            swap_ext_header(&mut ext_header);
            true
        }
        _ => {
            return Err(UnmarshalError(
                "Invalid .BTF.ext section - wrong magic".into(),
            ));
        }
    };

    if (ext_header.hdr_len as usize) < ext_hdr_size {
        return Err(UnmarshalError(
            "Invalid .BTF.ext section - wrong size".into(),
        ));
    }
    if ext_header.version != BTF_HEADER_VERSION {
        return Err(UnmarshalError(
            "Invalid .BTF.ext section - wrong version".into(),
        ));
    }
    if ext_header.hdr_len as usize > btf_ext_data.len() {
        return Err(UnmarshalError(
            "Invalid .BTF.ext section - invalid header length".into(),
        ));
    }

    let line_info_start = ext_header.hdr_len as usize + ext_header.line_info_off as usize;
    let line_info_end = line_info_start + ext_header.line_info_len as usize;
    if line_info_end > btf_ext_data.len() {
        return Err(UnmarshalError(
            "Invalid .BTF.ext section - line info out of range".into(),
        ));
    }

    let mut pos = line_info_start;

    // First u32 is the record size
    let mut record_size =
        read_struct::<u32>(btf_ext_data, &mut pos, line_info_start, line_info_end)?;
    if swap_endian_ext {
        record_size = bswap_32(record_size);
    }
    if (record_size as usize) < mem::size_of::<BpfLineInfo>() {
        return Err(UnmarshalError(
            "Invalid .BTF.ext section - invalid line info record size".into(),
        ));
    }

    let mut records = Vec::new();

    while pos < line_info_end {
        let mut sec_info =
            read_struct::<BtfExtInfoSec>(btf_ext_data, &mut pos, line_info_start, line_info_end)?;
        if swap_endian_ext {
            swap_ext_info_sec(&mut sec_info);
        }
        let section_name = find_string(&string_table, sec_info.sec_name_off as usize)?;

        for _ in 0..sec_info.num_info {
            let mut li =
                read_struct::<BpfLineInfo>(btf_ext_data, &mut pos, line_info_start, line_info_end)?;
            if swap_endian_ext {
                swap_line_info(&mut li);
            }
            // Skip extra bytes if record_size > sizeof(BpfLineInfo)
            let extra = record_size as usize - mem::size_of::<BpfLineInfo>();
            if extra > 0 {
                if pos + extra > line_info_end {
                    return Err(UnmarshalError(
                        "Invalid .BTF.ext section - record extends past line info".into(),
                    ));
                }
                pos += extra;
            }

            let file_name = find_string(&string_table, li.file_name_off as usize)?;
            let source = find_string(&string_table, li.line_off as usize)?;
            records.push(LineInfoRecord {
                section: section_name.clone(),
                instruction_offset: li.insn_off,
                file_name,
                source,
                line_number: bpf_line_info_line_num(li.line_col),
                column_number: bpf_line_info_line_col(li.line_col),
            });
        }
    }

    Ok(records)
}

// ── Read a null-terminated string from raw BTF data at a given offset ──

/// Read a null-terminated string from raw `.BTF` bytes at a given
/// offset within the string table. Used for CO-RE access strings.
pub fn read_btf_string(btf_data: &[u8], string_offset: u32) -> Result<String, UnmarshalError> {
    let hdr_size = mem::size_of::<BtfHeader>();
    if btf_data.len() < hdr_size {
        return Err(UnmarshalError(
            "Invalid .BTF section - too small for header".into(),
        ));
    }

    let mut offset = 0usize;
    let mut header = read_struct::<BtfHeader>(btf_data, &mut offset, 0, btf_data.len())?;
    if header.magic == BTF_HEADER_MAGIC_BIG_ENDIAN {
        swap_header(&mut header);
    }

    let str_start = header.hdr_len as usize + header.str_off as usize;
    let str_end = str_start + header.str_len as usize;
    if str_end > btf_data.len() {
        return Err(UnmarshalError(
            "Invalid .BTF section - string table out of range".into(),
        ));
    }
    let target = str_start + string_offset as usize;

    if target >= str_end {
        return Err(UnmarshalError(
            "Invalid .BTF section - access string offset out of range".into(),
        ));
    }

    let mut end = target;
    while end < str_end && btf_data[end] != 0 {
        end += 1;
    }

    std::str::from_utf8(&btf_data[target..end])
        .map(|s| s.to_string())
        .map_err(|e| {
            UnmarshalError(format!(
                "Invalid .BTF section - non-UTF8 access string: {e}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const BTF_TEST_ELF: &str = "tests/upstream/ebpf-samples/build/byteswap.o";

    #[test]
    fn parse_btf_from_elf_file() {
        let Some(btf_data) = super::super::load_btf_section_from_elf(BTF_TEST_ELF) else {
            return;
        };

        // Parse string table
        let (string_table, swap_endian) = parse_string_table(&btf_data).unwrap();
        assert!(!string_table.is_empty(), "String table should not be empty");
        assert!(!swap_endian, "x86 ELF should be little-endian");

        // Parse types
        let types = parse_types(&btf_data).unwrap();
        assert!(types.len() > 1, "Should have at least void + other types");
        // First entry is always void
        assert_eq!(types[0].0, 0);
        assert!(matches!(types[0].2, BtfKind::Void));
    }

    #[test]
    fn parse_line_info_from_elf_file() {
        let Some(data) = super::super::read_test_elf(BTF_TEST_ELF) else {
            return;
        };
        use object::Object;
        use object::ObjectSection;
        let elf = object::File::parse(&*data).unwrap();
        let Some(btf_section) = elf.section_by_name(".BTF") else {
            eprintln!("Skipping test: no .BTF section in {BTF_TEST_ELF}");
            return;
        };
        let btf_ext_section = match elf.section_by_name(".BTF.ext") {
            Some(s) => s,
            None => {
                eprintln!("Skipping test: no .BTF.ext section in {BTF_TEST_ELF}");
                return;
            }
        };

        let btf_data = btf_section.data().unwrap();
        let btf_ext_data = btf_ext_section.data().unwrap();

        let records = parse_line_information(btf_data, btf_ext_data).unwrap();
        assert!(
            !records.is_empty(),
            "Should have line info records for byteswap.o"
        );

        // All records should have non-empty section and file names
        for r in &records {
            assert!(!r.section.is_empty());
            assert!(!r.file_name.is_empty());
        }
    }

    /// A header whose declared string-table range extends past the actual
    /// section data must be rejected, not indexed out of bounds.
    #[test]
    fn read_btf_string_rejects_out_of_range_string_table() {
        let hdr_size = mem::size_of::<BtfHeader>();
        let mut btf_data = vec![0u8; hdr_size];
        // magic (u16 LE)
        btf_data[0..2].copy_from_slice(&BTF_HEADER_MAGIC.to_le_bytes());
        btf_data[2] = BTF_HEADER_VERSION; // version
        btf_data[3] = 0; // flags
        btf_data[4..8].copy_from_slice(&(hdr_size as u32).to_le_bytes()); // hdr_len
        btf_data[8..12].copy_from_slice(&0u32.to_le_bytes()); // type_off
        btf_data[12..16].copy_from_slice(&0u32.to_le_bytes()); // type_len
        btf_data[16..20].copy_from_slice(&0u32.to_le_bytes()); // str_off
        // str_len claims a string table far larger than btf_data actually is.
        btf_data[20..24].copy_from_slice(&1_000_000u32.to_le_bytes());

        let result = read_btf_string(&btf_data, 0);
        assert!(result.is_err(), "expected an error, got {result:?}");
    }
}
