// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Structured ELF fuzzing. `fuzz_elf_parse` feeds raw bytes to the loader, but
// random bytes almost never form a valid ELF container, so the deeper loader
// logic (section classification, symbol tables, the program/license/maps
// sections, function-symbol handling) is rarely exercised. This target builds a
// *structurally valid* eBPF object file with the `object` write API from
// arbitrary fuzzer-chosen section names, instruction bytes, symbols, and a maps
// blob, then runs it through the full load → unmarshal pipeline. The loader must
// never panic on a well-formed-but-hostile container.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use object::write::{Object, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

use prevail::elf_loader::read_elf;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;

#[derive(Debug, Arbitrary)]
struct FuzzFunc {
    /// Index of the section this symbol points into (taken modulo section count).
    section_sel: u8,
    /// Byte offset of the function within its section.
    value: u16,
    name_sel: u8,
}

#[derive(Debug, Arbitrary)]
struct FuzzElf {
    /// Per program section: (name selector, raw instruction bytes).
    prog_sections: Vec<(u8, Vec<u8>)>,
    /// Optional `maps` section contents.
    maps: Option<Vec<u8>>,
    /// Optional license string contents.
    license: Option<Vec<u8>>,
    /// FUNC symbols pointing into the program sections.
    funcs: Vec<FuzzFunc>,
}

// A pool of realistic eBPF section-name prefixes so the loader's section
// classification (by name) is actually reached.
const SECTION_NAMES: &[&str] = &[
    "xdp",
    "xdp/1",
    "tc",
    "classifier",
    "socket",
    "cgroup/skb",
    "kprobe/x",
    "tracepoint/y",
    "sk_skb",
    "lwt_in",
    "perf_event",
    "raw_tp/z",
    ".text",
];
const SYM_NAMES: &[&str] = &["main", "func", "helper", "cb", "prog", "subprog"];

fuzz_target!(|input: FuzzElf| {
    if input.prog_sections.is_empty() || input.prog_sections.len() > 8 {
        return;
    }
    let total: usize = input.prog_sections.iter().map(|(_, b)| b.len()).sum();
    if total > 64 * 1024 {
        return;
    }

    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

    // Program (executable) sections holding arbitrary instruction bytes.
    let mut section_ids = Vec::new();
    for (i, (name_sel, bytes)) in input.prog_sections.iter().enumerate() {
        let base = SECTION_NAMES[*name_sel as usize % SECTION_NAMES.len()];
        // Disambiguate names so multiple sections don't collide.
        let name = format!("{base}.{i}");
        let id = obj.add_section(Vec::new(), name.into_bytes(), SectionKind::Text);
        // Pad to an 8-byte (instruction) multiple; the loader expects this.
        let mut data = bytes.clone();
        while data.len() % 8 != 0 {
            data.push(0);
        }
        obj.append_section_data(id, &data, 8);
        section_ids.push(id);
    }

    if let Some(maps) = &input.maps
        && maps.len() <= 4096
    {
        let id = obj.add_section(Vec::new(), b"maps".to_vec(), SectionKind::Data);
        obj.append_section_data(id, maps, 8);
    }

    if let Some(license) = &input.license
        && license.len() <= 256
    {
        let id = obj.add_section(Vec::new(), b"license".to_vec(), SectionKind::Data);
        obj.append_section_data(id, license, 1);
    }

    // FUNC symbols pointing into program sections.
    for f in input.funcs.iter().take(32) {
        let sec = section_ids[f.section_sel as usize % section_ids.len()];
        let name = SYM_NAMES[f.name_sel as usize % SYM_NAMES.len()];
        obj.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: f.value as u64,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(sec),
            flags: SymbolFlags::None,
        });
    }

    let Ok(data) = obj.write() else {
        return;
    };

    let mut platform = LinuxPlatform::new();
    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        ..EbpfVerifierOptions::default()
    };
    // `read_elf` is the load entry point.
    let _ = read_elf(&data, "fuzz.o", "", "", &opts, &mut platform);
});
