// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;

use anyhow::Result;
use object::{Object, ObjectSection, read::File as ObjectFile};

use crate::util::paths;

pub fn run(root: &Path) -> Result<()> {
    // 1. fuzz_assembler: extract "-- asm" sections from conformance test data files.
    let asm_dir = root.join("fuzz/corpus/fuzz_assembler");
    recreate_dir(&asm_dir)?;
    let mut asm_count = 0u32;

    let data_dir = root.join("tests/upstream/external/bpf_conformance/tests");
    if data_dir.is_dir() {
        for entry in fs::read_dir(&data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "data") {
                let name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let content = fs::read_to_string(&path)?;
                let asm = extract_asm_section(&content);
                if !asm.is_empty() {
                    fs::write(asm_dir.join(format!("{name}.txt")), &asm)?;
                    asm_count += 1;
                }
            }
        }
    }
    println!(
        "fuzz_assembler: {asm_count} seed files in {}",
        asm_dir.display()
    );

    // 2. fuzz_elf_parse & fuzz_end_to_end: copy .o files from ebpf-samples.
    let elf_dir = root.join("fuzz/corpus/fuzz_elf_parse");
    let e2e_dir = root.join("fuzz/corpus/fuzz_end_to_end");
    recreate_dir(&elf_dir)?;
    recreate_dir(&e2e_dir)?;

    let samples_dir = root.join("tests/upstream/ebpf-samples");
    let o_files = paths::find_o_files(&samples_dir)?;
    for f in &o_files {
        let base = corpus_seed_name(root, f);
        fs::copy(f, elf_dir.join(&base))?;
        fs::copy(f, e2e_dir.join(&base))?;
    }
    println!(
        "fuzz_elf_parse: {} seed files in {}",
        count_files(&elf_dir),
        elf_dir.display()
    );
    println!(
        "fuzz_end_to_end: {} seed files in {}",
        count_files(&e2e_dir),
        e2e_dir.display()
    );

    // 3. fuzz_btf_parse: extract .BTF sections from ELF samples that have them.
    let btf_dir = root.join("fuzz/corpus/fuzz_btf_parse");
    recreate_dir(&btf_dir)?;

    for f in &o_files {
        let Ok(data) = fs::read(f) else {
            continue;
        };
        let Ok(obj) = ObjectFile::parse(&*data) else {
            continue;
        };
        let Some(section) = obj.section_by_name(".BTF") else {
            continue;
        };
        let Ok(contents) = section.data() else {
            continue;
        };
        if contents.is_empty() {
            continue;
        }
        let base = corpus_seed_name(root, f);
        let btf_path = btf_dir.join(format!("{base}.btf"));
        fs::write(btf_path, contents)?;
    }
    println!(
        "fuzz_btf_parse: {} seed files in {}",
        count_files(&btf_dir),
        btf_dir.display()
    );

    // 4. fuzz_unmarshal.
    let unmarshal_dir = root.join("fuzz/corpus/fuzz_unmarshal");
    recreate_dir(&unmarshal_dir)?;
    println!("fuzz_unmarshal: using Arbitrary-based structured fuzzing (no seed corpus)");

    println!("Done. Seed corpora generated in fuzz/corpus/");
    Ok(())
}

fn recreate_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir)?;
    }
    fs::create_dir_all(dir)?;
    Ok(())
}

fn corpus_seed_name(root: &Path, path: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(root) {
        return rel.to_string_lossy().replace(['/', '\\'], "_");
    }

    let root_norm = normalize_separators(&root.to_string_lossy());
    let path_norm = normalize_separators(&path.to_string_lossy());
    let root_trimmed = root_norm.trim_end_matches('/');

    let rel_norm = path_norm
        .strip_prefix(root_trimmed)
        .and_then(|s| s.strip_prefix('/').or(Some(s)))
        .unwrap_or(path_norm.as_str());

    rel_norm.replace('/', "_")
}

fn normalize_separators(s: &str) -> String {
    s.replace('\\', "/")
}

/// Extract lines between "-- asm" and the next "-- " marker (or EOF).
fn extract_asm_section(content: &str) -> String {
    let mut found = false;
    let mut result = String::new();
    for line in content.lines() {
        if line == "-- asm" {
            found = true;
            continue;
        }
        if found && line.starts_with("-- ") {
            break;
        }
        if found {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

fn count_files(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|d| d.filter_map(|e| e.ok()).count())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{corpus_seed_name, extract_asm_section};
    use std::path::Path;

    #[test]
    fn extract_asm_stops_at_next_section() {
        let input = "\
-- raw
ignore
-- asm
mov r0, 0
exit
-- result
pass
";
        assert_eq!(extract_asm_section(input), "mov r0, 0\nexit\n");
    }

    #[test]
    fn extract_asm_handles_missing_block() {
        assert_eq!(extract_asm_section("-- raw\nx\n"), "");
    }

    #[test]
    fn corpus_seed_name_is_repo_relative_and_stable() {
        let root = Path::new("/repo");
        let path = Path::new("/repo/tests/upstream/ebpf-samples/cilium/bpf_lxc.o");
        assert_eq!(
            corpus_seed_name(root, path),
            "tests_upstream_ebpf-samples_cilium_bpf_lxc.o"
        );
    }

    #[test]
    fn corpus_seed_name_normalizes_windows_separators() {
        let root = Path::new("C:\\repo");
        let path = Path::new("C:\\repo\\tests\\upstream\\ebpf-samples\\x.o");
        assert_eq!(
            corpus_seed_name(root, path),
            "tests_upstream_ebpf-samples_x.o"
        );
    }
}
