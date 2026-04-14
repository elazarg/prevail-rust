// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Rust entry point for the prevail eBPF verifier CLI.
//! Port of `src/main/check.cpp`.

use std::process::ExitCode;

use clap::Parser;
use clap::builder::PossibleValuesParser;

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader;
use prevail::fwd_analyzer;
use prevail::ir::program::{Program, collect_stats};
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::linux_verifier;
use prevail::memsize;
use prevail::spec::config::{EbpfVerifierOptions, PrepareCfgOptions, VerbosityOptions};
use prevail::spec::type_descriptors::RawProgram;
use prevail::spec::vm_isa::EbpfInst;

use prevail::linux::linux_platform::conformance_groups as conformance;

// ── FNV-1a hash ─────────────────────────────────────────────────────────────

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 1469598103934665603;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    h
}

fn serialize_inst_bytes(insts: &[EbpfInst]) -> Vec<u8> {
    let mut out = Vec::with_capacity(size_of_val(insts));
    for inst in insts {
        out.push(inst.opcode);
        out.push(inst.dst_src);
        out.extend_from_slice(&inst.offset.to_ne_bytes());
        out.extend_from_slice(&inst.imm.to_ne_bytes());
    }
    out
}

/// Format the program label as "section/function" or just "section" if they match.
fn program_label(raw_prog: &RawProgram) -> String {
    if raw_prog.function_name.is_empty() || raw_prog.function_name == raw_prog.section_name {
        raw_prog.section_name.clone()
    } else {
        format!("{}/{}", raw_prog.section_name, raw_prog.function_name)
    }
}

// ── CLI definition ──────────────────────────────────────────────────────────

// Valid conformance group names for CLI validation.
const GROUP_NAMES: [&str; 8] = {
    // Build a fixed array from the shared GROUPS table.
    let groups = conformance::GROUPS;
    [
        groups[0].0,
        groups[1].0,
        groups[2].0,
        groups[3].0,
        groups[4].0,
        groups[5].0,
        groups[6].0,
        groups[7].0,
    ]
};

#[derive(Parser)]
#[command(
    name = "prevail",
    about = "PREVAIL is a new eBPF verifier based on abstract interpretation.",
    disable_help_flag = true
)]
struct Cli {
    /// Elf file to analyze
    path: Option<String>,

    /// Section to analyze (positional)
    #[arg(index = 2)]
    section_pos: Option<String>,

    /// Function to analyze (positional)
    #[arg(index = 3)]
    function_pos: Option<String>,

    /// Print this help message and exit
    #[arg(short = 'h', long = "help")]
    help: bool,

    /// Section to analyze
    #[arg(long)]
    section: Option<String>,

    /// Function to analyze
    #[arg(long = "function")]
    function: Option<String>,

    /// List programs
    #[arg(short = 'l')]
    list: bool,

    /// No stdout output, exit code only
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Print control-flow graph and exit
    #[arg(long = "cfg")]
    print_cfg: bool,

    /// Abstract domain (hidden, kept for xtask backward compatibility)
    #[arg(long, default_value = "zoneCrab", hide = true,
          value_parser = ["stats", "linux", "zoneCrab", "cfg"])]
    domain: String,

    /// Verify termination
    #[arg(long = "termination", overrides_with = "no_verify_termination")]
    termination: bool,

    /// Don't verify termination
    #[arg(long = "no-verify-termination", overrides_with = "termination")]
    no_verify_termination: bool,

    /// Allow division by zero (default: allow)
    #[arg(
        long = "allow-division-by-zero",
        overrides_with = "no_division_by_zero"
    )]
    allow_division_by_zero: bool,

    /// Disallow division by zero
    #[arg(
        long = "no-division-by-zero",
        overrides_with = "allow_division_by_zero"
    )]
    no_division_by_zero: bool,

    /// Apply additional checks that would cause runtime failures
    #[arg(long, short = 's')]
    strict: bool,

    /// Per-subprogram stack frame size in bytes (default: 512)
    #[arg(long = "stack-size", default_value_t = EbpfVerifierOptions::DEFAULT_SUBPROGRAM_STACK_SIZE,
          value_parser = clap::value_parser!(i32).range(1..=EbpfVerifierOptions::MAX_SUBPROGRAM_STACK_SIZE as i64))]
    stack_size: i32,

    /// Maximum number of nested function calls (default: 8)
    #[arg(long = "max-call-stack-frames", default_value_t = EbpfVerifierOptions::DEFAULT_MAX_CALL_STACK_FRAMES,
          value_parser = clap::value_parser!(i32).range(1..=EbpfVerifierOptions::MAX_CALL_STACK_FRAMES_LIMIT as i64))]
    max_call_stack_frames: i32,

    /// Include conformance groups
    #[arg(long = "include_groups", value_delimiter = ',',
          value_parser = PossibleValuesParser::new(GROUP_NAMES))]
    include_groups: Vec<String>,

    /// Exclude conformance groups
    #[arg(long = "exclude_groups", value_delimiter = ',',
          value_parser = PossibleValuesParser::new(GROUP_NAMES))]
    exclude_groups: Vec<String>,

    /// Simplify the display of the CFG (default: enabled)
    #[arg(
        long = "simplify",
        overrides_with = "no_simplify",
        default_value_t = true
    )]
    simplify: bool,

    /// Don't simplify the display of the CFG
    #[arg(long = "no-simplify", overrides_with = "simplify")]
    no_simplify: bool,

    /// Print line information
    #[arg(long = "line-info")]
    line_info: bool,

    /// Print BTF types
    #[arg(long = "print-btf-types")]
    print_btf_types: bool,

    /// Print invariants and first failure
    #[arg(short = 'v')]
    print_invariants: bool,

    /// Print first failure
    #[arg(short = 'f')]
    print_failures: bool,

    /// Print disassembly to FILE
    #[arg(long = "asm")]
    asm_file: Option<String>,

    /// Export control-flow graph to dot FILE
    #[arg(long = "dot")]
    dot_file: Option<String>,

    /// Print failure slices for verification errors
    #[arg(long = "failure-slice")]
    failure_slice: bool,

    /// Maximum backward steps for failure slicing (default: 200)
    #[arg(long = "failure-slice-depth", default_value_t = 200)]
    failure_slice_depth: usize,
}

// ── Custom help text (matches C++ upstream exactly) ─────────────────────────

fn print_help() {
    let argv0 = std::env::args()
        .next()
        .unwrap_or_else(|| "check".to_string());
    println!("PREVAIL is a new eBPF verifier based on abstract interpretation. ");
    println!();
    println!();
    println!("{argv0} [OPTIONS] path [section] [function]");
    println!();
    println!();
    println!("POSITIONALS:");
    println!("  path TEXT:FILE REQUIRED     Elf file to analyze ");
    println!("  section SECTION             Section to analyze ");
    println!("  function FUNCTION           Function to analyze ");
    println!();
    println!("OPTIONS:");
    println!("  -h,     --help              Print this help message and exit ");
    println!("          --section SECTION   Section to analyze ");
    println!("          --function FUNCTION Function to analyze ");
    println!("  -l                          List programs ");
    println!("  -q,     --quiet             No stdout output, exit code only ");
    println!("          --cfg               Print control-flow graph and exit ");
    println!();
    println!("Features:");
    println!("          --termination, --no-verify-termination{{false}} ");
    println!("                              Verify termination. Default: ignore ");
    println!("          --allow-division-by-zero, --no-division-by-zero{{false}} ");
    println!("                              Handling potential division by zero. Default: allow ");
    println!(
        "  -s,     --strict            Apply additional checks that would cause runtime failures "
    );
    println!(
        "          --include_groups GROUPS:{{atomic32,atomic64,base32,base64,callx,divmul32,divmul64,packet}} "
    );
    println!("                              Include conformance groups ");
    println!(
        "          --exclude_groups GROUPS:{{atomic32,atomic64,base32,base64,callx,divmul32,divmul64,packet}} "
    );
    println!("                              Exclude conformance groups ");
    println!();
    println!("Verbosity:");
    println!("          --simplify, --no-simplify{{false}} ");
    println!(
        "                              Simplify the display of the CFG by merging chains of instructions "
    );
    println!(
        "                              into a single basic block. Default: enabled (disabled with "
    );
    println!("                              --failure-slice) ");
    println!("          --line-info         Print line information ");
    println!("          --print-btf-types   Print BTF types ");
    println!("  -v                          Print invariants and first failure ");
    println!("  -f                          Print first failure ");
    println!(
        "          --failure-slice     Print minimal failure slices showing only instructions that "
    );
    println!("                              contributed to errors ");
    println!("          --failure-slice-depth UINT ");
    println!(
        "                              Maximum backward steps for failure slicing (default: 200) "
    );
    println!();
    println!("CFG output:");
    println!("          --asm FILE          Print disassembly to FILE ");
    println!("          --dot FILE          Export control-flow graph to dot FILE ");
}

// ── Main ────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let cli = Cli::parse();

    if cli.help {
        print_help();
        return ExitCode::SUCCESS;
    }

    let Some(path) = cli.path else {
        eprintln!("error: path is required");
        print_help();
        return ExitCode::from(1);
    };

    // Resolve positional vs named section/function (named flag wins if both given).
    let section = cli.section.or(cli.section_pos);
    let function = cli.function.or(cli.function_pos);

    // Build options struct (matches C++ defaults from config.hpp).
    let check_for_termination = cli.termination && !cli.no_verify_termination;
    let allow_division_by_zero = !cli.no_division_by_zero;
    let simplify_explicit = std::env::args().any(|a| a == "--simplify" || a == "--no-simplify");
    let mut simplify = cli.simplify && !cli.no_simplify;
    // When --failure-slice is set and user didn't explicitly pass --simplify,
    // disable simplification so each instruction is shown individually.
    if cli.failure_slice && !simplify_explicit {
        simplify = false;
    }

    let mut opts = EbpfVerifierOptions {
        cfg_opts: PrepareCfgOptions {
            check_for_termination,
            must_have_exit: true,
        },
        mock_map_fds: true,
        strict: cli.strict,
        allow_division_by_zero,
        setup_constraints: true,
        big_endian: false,
        subprogram_stack_size: cli.stack_size,
        max_call_stack_frames: cli.max_call_stack_frames,
        verbosity_opts: VerbosityOptions {
            simplify,
            print_invariants: cli.print_invariants,
            print_failures: cli.print_failures,
            print_line_info: cli.line_info,
            dump_btf_types_json: cli.print_btf_types,
            collect_instruction_deps: cli.failure_slice,
        },
    };

    // Handle @headers special filename.
    if path == "@headers" {
        if cli.domain == "stats" {
            print!("hash,instructions");
            let headers = prevail::ir::program::stats_headers();
            for h in headers {
                print!(",{h}");
            }
        } else {
            print!("{}?,", cli.domain);
            print!("{}_sec,", cli.domain);
            print!("{}_kb", cli.domain);
        }
        println!();
        return ExitCode::SUCCESS;
    }

    #[cfg(not(target_os = "linux"))]
    if cli.domain == "linux" {
        eprintln!("error: linux domain is unsupported on this machine");
        return ExitCode::from(64);
    }

    if cli.domain == "linux" {
        opts.mock_map_fds = false;
    }

    // ── Load ELF using Rust ELF loader ──────────────────────────────────

    let mut rust_platform = LinuxPlatform::new();

    // Apply conformance groups.
    let mut groups = conformance::DEFAULT_GROUPS;
    let include_set: Vec<&str> = if cli.include_groups.is_empty() {
        conformance::all_group_names()
    } else {
        cli.include_groups.iter().map(|s| s.as_str()).collect()
    };
    for name in &include_set {
        if let Some(g) = conformance::group_by_name(name) {
            groups |= g;
        }
    }
    for name in &cli.exclude_groups {
        if let Some(g) = conformance::group_by_name(name) {
            groups &= !g;
        }
    }
    rust_platform.conformance_groups = groups;

    let mut elf = match elf_loader::ElfObject::new(&path, opts) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    let mut load_error: Option<String> = None;
    let raw_progs = if !cli.list {
        match elf.get_programs(
            section.as_deref().unwrap_or(""),
            function.as_deref().unwrap_or(""),
            &mut rust_platform,
        ) {
            Ok(progs) => progs,
            Err(e) => {
                load_error = Some(e.to_string());
                vec![]
            }
        }
    } else {
        vec![]
    };

    // Handle "unsupported function:" errors with C++ parity format.
    if let Some(ref err) = load_error
        && let Some(idx) = err.find("unsupported function: ")
    {
        let what = &err[idx..];
        eprintln!("terminate called after throwing an instance of 'std::runtime_error'");
        eprintln!("  what():  {what}");
        return ExitCode::from(1);
    }

    if cli.list || load_error.is_some() || raw_progs.len() != 1 {
        if let Some(ref err) = load_error {
            eprintln!("error: {err}");
        }
        if !cli.list && load_error.is_none() && raw_progs.len() != 1 {
            println!("please specify a program");
        }
        if !cli.list {
            println!("available programs:");
        }
        for p in elf.list_programs(&mut rust_platform) {
            print!("section={} function={}", p.section_name, p.function_name);
            if p.invalid {
                print!(" [invalid: {}]", p.invalid_reason);
            }
            println!();
        }
        println!();
        return if cli.list {
            ExitCode::SUCCESS
        } else if load_error.is_some() {
            ExitCode::from(1)
        } else {
            ExitCode::from(64)
        };
    }

    // Use the single program.
    let raw_prog = &raw_progs[0];

    // Copy map descriptors and context descriptor to the platform for analysis.
    rust_platform.map_descriptors = raw_prog.info.map_descriptors.clone();
    rust_platform.set_program_type(&raw_prog.info.program_type);

    let info = &raw_prog.info;
    let insts = &raw_prog.prog;

    // ── Linux domain: run kernel verifier ────────────────────────────────

    if cli.domain == "linux" {
        let raw_bytes = serialize_inst_bytes(insts);
        let prog_type = info.program_type.platform_specific_data as u32;
        let (res, seconds) = linux_verifier::bpf_verify_program(
            prog_type,
            &raw_bytes,
            opts.verbosity_opts.print_failures,
        );
        let mem_kb = memsize::resident_set_size_kb();
        println!("{},{seconds},{mem_kb}", if res { 1 } else { 0 });
        return if res {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    // ── Non-linux domains ────────────────────────────────────────────────

    // Unmarshal instructions using the Rust unmarshaller.
    let mut notes = Vec::new();
    let inst_seq = match unmarshal::unmarshal(insts, &mut notes, info, &rust_platform, &opts) {
        Ok(seq) => seq,
        Err(e) => {
            let msg = e.to_string();
            if let Some(idx) = msg.find("unsupported function: ") {
                let what = &msg[idx..];
                eprintln!("terminate called after throwing an instance of 'std::runtime_error'");
                eprintln!("  what():  {what}");
            } else {
                println!("unmarshaling error at {}\n", e);
            }
            return ExitCode::from(1);
        }
    };

    // Optional disassembly output.
    if let Some(ref asm_file) = cli.asm_file {
        let mut out: Box<dyn std::io::Write> = if asm_file == "-" {
            Box::new(std::io::stdout())
        } else {
            match std::fs::File::create(asm_file) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    eprintln!("error: could not create {asm_file}: {e}");
                    return ExitCode::from(1);
                }
            }
        };
        if let Err(e) =
            prevail::printing::print_instruction_seq(&inst_seq, &mut *out, None, cli.line_info)
        {
            eprintln!("error writing asm: {e}");
            return ExitCode::from(1);
        }
    }

    // Build CFG in Rust.
    let program = match Program::from_sequence(&inst_seq, info, &rust_platform, &opts) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(1);
        }
    };

    // Optional DOT output (before --cfg early exit, matching C++ order).
    if let Some(ref dot_file) = cli.dot_file
        && let Err(e) = prevail::printing::print_dot_to_file(&program, dot_file)
    {
        eprintln!("error writing dot: {e}");
        return ExitCode::from(1);
    }

    if cli.print_cfg || cli.domain == "cfg" {
        let _ = prevail::printing::print_program(&program, info, &mut std::io::stdout(), simplify);
        return ExitCode::SUCCESS;
    }

    if cli.domain == "stats" {
        // Hash the raw bytes of the program.
        let raw_bytes = serialize_inst_bytes(insts);
        let hash = fnv1a64(&raw_bytes);
        let inst_count = inst_seq.len();
        print!("{hash:x},{inst_count}");

        let stats = collect_stats(&program);
        let headers = prevail::ir::program::stats_headers();
        for h in headers {
            let val = stats.get(h).unwrap_or(&0);
            print!(",{val}");
        }
        println!();
        return ExitCode::SUCCESS;
    }

    // ── zoneCrab domain: run the Rust forward analyzer ──────────────────

    let ctx = DomainContext {
        program_info: info,
        options: &opts,
        platform: &rust_platform,
    };

    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);

    if !cli.quiet {
        if opts.verbosity_opts.print_invariants {
            let _ = prevail::printing::print_invariants(
                &mut std::io::stdout(),
                &program,
                info,
                simplify,
                &result,
                &registry,
            );
        }
        if opts.verbosity_opts.print_failures
            && let Some(ref error) = result.find_first_error()
        {
            let _ = prevail::printing::print_error(&mut std::io::stdout(), error);
        }
        if cli.failure_slice && result.failed {
            let slice_params = prevail::result::SliceParams {
                max_steps: cli.failure_slice_depth,
                max_slices: 1,
            };
            let slices = result.compute_failure_slices(&program, &ctx, &mut registry, slice_params);
            let _ = prevail::printing::print_failure_slices(
                &mut std::io::stdout(),
                &program,
                info,
                simplify,
                &result,
                &registry,
                &slices,
                false,
            );
        } else if cli.failure_slice && !result.failed {
            println!("Program passed verification; no failure slices to display.");
        }
    }

    let pass = !result.failed;
    let label = program_label(raw_prog);

    if !cli.quiet {
        if pass {
            print!("PASS: {label}");
            if check_for_termination {
                print!(
                    " (terminates within {} loop iterations)",
                    result.max_loop_count
                );
            }
            println!();
        } else {
            println!("FAIL: {label}");
            // Print the first error if not already printed by -v or -f.
            if !opts.verbosity_opts.print_invariants
                && !opts.verbosity_opts.print_failures
                && !cli.failure_slice
            {
                if let Some(ref error) = result.find_first_error() {
                    let _ = prevail::printing::print_error(&mut std::io::stdout(), error);
                }
                println!(
                    "Hint: run with --failure-slice for a causal trace, or -v for full invariants."
                );
            }
        }
    }

    if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
