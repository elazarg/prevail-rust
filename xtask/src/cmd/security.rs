// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! White-hat security harness: differential mutation fuzzing of the eBPF verifier.
//!
//! The strongest soundness oracle available to this project is *differential
//! testing against the upstream C++ verifier* (there is no concrete eBPF
//! interpreter to use as ground truth). This command mutates real, loadable
//! eBPF object files inside their instruction sections — keeping the ELF
//! structure valid so both verifiers fully analyze the program — and runs the
//! Rust and C++ verifiers on each mutant. Verdict divergences are bucketed by
//! severity:
//!
//! - **soundness**   — Rust *accepts* a program the C++ verifier *rejects*.
//!   This is the crown-jewel bug class: the Rust port may have missed a safety
//!   violation. (Confirm against `cpp` semantics; C++ is the reference.)
//! - **precision**   — Rust *rejects* a program C++ *accepts*. Usually a
//!   precision regression in the Rust port, but can also expose a C++ bug.
//! - **termination** — Rust times out while C++ finishes. Candidate violation
//!   of the polynomial-runtime guarantee (analysis blow-up / DoS).
//! - **crash-rust**  — Rust panics or segfaults (the binary is built with
//!   `panic = "abort"`, so a panic surfaces as SIGABRT). Memory-safety / DoS.
//! - **crash-cpp**   — C++ crashes. A genuine upstream bug worth reporting.
//! - **loader**      — the two disagree on *load* acceptance (exit 64 vs not).
//!
//! Mutants that reproduce a finding are written to `security/findings/<class>/`
//! together with a `.txt` report capturing both verifiers' verbose output, so
//! each finding is a self-contained, re-runnable reproducer.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use object::{Object, ObjectSection, SectionFlags};

use crate::cmd::parity_common;
use crate::util::{paths, process};

/// `SHF_EXECINSTR` — marks a section as containing executable instructions.
/// eBPF program sections (xdp/tc/socket/etc.) carry this flag.
const SHF_EXECINSTR: u64 = 0x4;
/// eBPF instructions are 8 bytes wide; program sections are instruction-aligned.
const INSN_SIZE: u64 = 8;

#[derive(Clone, Copy)]
pub struct DiffFuzzArgs {
    /// Maximum number of mutants to evaluate (0 = unbounded, bounded by `time`).
    pub iters: u64,
    /// Wall-clock budget in seconds (0 = unbounded, bounded by `iters`).
    pub time_secs: u64,
    /// Per-verifier timeout in seconds.
    pub timeout_secs: u64,
    /// PRNG seed for reproducible campaigns.
    pub seed: u64,
    /// Maximum reproducers saved per finding class (counting continues regardless).
    pub max_per_class: usize,
}

impl Default for DiffFuzzArgs {
    fn default() -> Self {
        Self {
            iters: 2000,
            time_secs: 0,
            timeout_secs: 10,
            seed: 0x9E3779B97F4A7C15,
            max_per_class: 25,
        }
    }
}

// ── Tiny deterministic PRNG (xorshift64*) ───────────────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero state, which is a fixed point of xorshift.
        Rng(seed ^ 0xD1B54A32D192ED03 | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
    fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        &slice[self.below(slice.len() as u64) as usize]
    }
}

// ── Verifier outcome ────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Pass,
    Reject,
    LoadError,
    Timeout,
    Crash(i32),
    Other(i32),
}

impl Outcome {
    fn from_code(code: Option<i32>) -> Outcome {
        match code {
            Some(0) => Outcome::Pass,
            Some(1) => Outcome::Reject,
            Some(64) => Outcome::LoadError,
            // GNU `timeout` returns 124 (TERM) or 137 (KILL after grace).
            Some(124) | Some(137) => Outcome::Timeout,
            // 128+signal: SIGABRT(134, panic=abort), SIGSEGV(139), SIGBUS(135)...
            Some(c) if c >= 128 => Outcome::Crash(c),
            Some(c) => Outcome::Other(c),
            // Killed by an uncaught signal without going through `timeout`.
            None => Outcome::Crash(-1),
        }
    }
    fn label(self) -> String {
        match self {
            Outcome::Pass => "pass".into(),
            Outcome::Reject => "reject".into(),
            Outcome::LoadError => "load-error".into(),
            Outcome::Timeout => "timeout".into(),
            Outcome::Crash(c) => format!("crash({c})"),
            Outcome::Other(c) => format!("exit({c})"),
        }
    }
}

/// Severity bucket for a (rust, cpp) outcome pair, or `None` when they agree
/// (or disagree only in an uninteresting way).
fn classify(rust: Outcome, cpp: Outcome) -> Option<&'static str> {
    use Outcome::*;
    match (rust, cpp) {
        // Rust crashed — always a finding regardless of what C++ did.
        (Crash(_), _) => Some("crash-rust"),
        // C++ crashed but Rust survived — upstream bug.
        (_, Crash(_)) => Some("crash-cpp"),
        // Rust took too long while C++ converged — complexity/DoS candidate.
        (Timeout, Pass) | (Timeout, Reject) | (Timeout, LoadError) => Some("termination"),
        // C++ slow, Rust fast: still a divergence but not our soundness concern.
        (Pass, Timeout) | (Reject, Timeout) | (LoadError, Timeout) => Some("termination"),
        // A load error and a verify rejection both mean "program not accepted";
        // the exit-code difference alone is not a divergence.
        (LoadError, Reject) | (Reject, LoadError) => None,
        // Crown jewel: Rust accepts what C++ rejects (either stage).
        (Pass, Reject) | (Pass, LoadError) => Some("soundness"),
        // Rust over-rejects (or C++ is unsound) — precision divergence.
        (Reject, Pass) | (LoadError, Pass) => Some("precision"),
        // `Other` exit codes that differ — bucket as loader/oddity.
        (a, b) if a != b => Some("loader"),
        // Agreement (pass/pass, reject/reject, both timeout, both load-error…).
        _ => None,
    }
}

// ── Section discovery ───────────────────────────────────────────────────────

/// File-offset ranges of executable (instruction) sections, instruction-aligned.
fn exec_ranges(data: &[u8]) -> Vec<(usize, usize)> {
    let Ok(obj) = object::read::File::parse(data) else {
        return Vec::new();
    };
    let mut ranges = Vec::new();
    for section in obj.sections() {
        let is_exec = match section.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags & SHF_EXECINSTR != 0,
            _ => false,
        };
        if !is_exec {
            continue;
        }
        if let Some((off, size)) = section.file_range() {
            // Need at least one full instruction and an in-bounds range.
            if size >= INSN_SIZE && (off + size) as usize <= data.len() {
                ranges.push((off as usize, size as usize));
            }
        }
    }
    ranges
}

// ── Mutation ────────────────────────────────────────────────────────────────

/// A representative spread of eBPF opcodes to bias opcode-swap mutations toward
/// plausible (but possibly unsafe) instructions rather than uniform noise.
const OPCODE_PALETTE: &[u8] = &[
    0x07, 0x0f, 0x17, 0x1f, 0x04, 0x0c, 0x14, 0x1c, // ALU add/sub imm/reg, 32/64
    0x27, 0x2f, 0x37, 0x3f, 0x47, 0x4f, 0x57, 0x5f, // mul/div/or/and
    0x67, 0x6f, 0x77, 0x7f, 0x97, 0x9f, 0xa7, 0xaf, // lsh/rsh/mod/xor
    0xb7, 0xbf, 0xc7, 0xcf, // mov, arsh
    0x61, 0x69, 0x71, 0x79, 0x62, 0x6a, 0x72, 0x7a, // ldx/stx/st mem
    0x63, 0x6b, 0x73, 0x7b, 0x18, // mem + lddw
    0x05, 0x15, 0x1d, 0x55, 0x5d, 0x25, 0x35, // jmp/jeq/jne/jgt
    0xa5, 0xb5, 0xc5, 0xd5, 0x85, 0x95, // ju/jslt/jsge/call/exit
];

/// Apply 1–4 mutations to `buf`, all confined to executable section ranges.
/// Returns a human-readable description of what was changed.
fn mutate(buf: &mut [u8], ranges: &[(usize, usize)], rng: &mut Rng) -> String {
    let mut desc = Vec::new();
    let n = 1 + rng.below(4);
    for _ in 0..n {
        let &(off, size) = rng.pick(ranges);
        match rng.below(4) {
            0 => {
                // Bit flip.
                let pos = off + rng.below(size as u64) as usize;
                let bit = 1u8 << rng.below(8);
                buf[pos] ^= bit;
                desc.push(format!("bitflip@{pos:#x}^{bit:#04x}"));
            }
            1 => {
                // Random byte.
                let pos = off + rng.below(size as u64) as usize;
                let val = rng.next_u64() as u8;
                buf[pos] = val;
                desc.push(format!("byte@{pos:#x}={val:#04x}"));
            }
            2 => {
                // Swap an instruction's opcode for one from the palette.
                let insns = size / INSN_SIZE as usize;
                let pos = off + rng.below(insns as u64) as usize * INSN_SIZE as usize;
                let op = *rng.pick(OPCODE_PALETTE);
                buf[pos] = op;
                desc.push(format!("opcode@{pos:#x}={op:#04x}"));
            }
            _ => {
                // Overwrite a whole instruction with random bytes.
                let insns = size / INSN_SIZE as usize;
                let pos = off + rng.below(insns as u64) as usize * INSN_SIZE as usize;
                let mut bytes = [0u8; INSN_SIZE as usize];
                for b in bytes.iter_mut() {
                    *b = rng.next_u64() as u8;
                }
                buf[pos..pos + INSN_SIZE as usize].copy_from_slice(&bytes);
                desc.push(format!("insn@{pos:#x}=rand"));
            }
        }
    }
    desc.join(" ")
}

// ── Running a verifier ──────────────────────────────────────────────────────

/// Run `bin` on `file` under a wall-clock `timeout`, returning the outcome.
/// When `verbose`, captures stdout/stderr for the finding report.
fn run_verifier(
    bin: &Path,
    file: &Path,
    timeout_secs: u64,
    verbose: bool,
) -> Result<(Outcome, String)> {
    let mut cmd = Command::new("timeout");
    cmd.arg("--kill-after=5")
        .arg(timeout_secs.to_string())
        .arg(bin);
    if verbose {
        cmd.arg("-v");
    } else {
        cmd.arg("-q");
    }
    cmd.arg(file);
    let out = cmd.output().with_context(|| {
        format!(
            "failed to spawn {} (is `timeout` installed?)",
            bin.display()
        )
    })?;
    let outcome = Outcome::from_code(out.status.code());
    let text = if verbose {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    } else {
        String::new()
    };
    Ok((outcome, text))
}

/// A seed object: its path, raw bytes, and the file ranges of its executable
/// (instruction) sections that mutation is confined to.
type Seed = (PathBuf, Vec<u8>, Vec<(usize, usize)>);

// ── Main entry ──────────────────────────────────────────────────────────────

pub fn run_diff_fuzz(root: &Path, args: DiffFuzzArgs) -> Result<()> {
    if !process::has_command("timeout") {
        bail!("the GNU `timeout` command is required but was not found on PATH");
    }

    let env =
        parity_common::prepare(root).context("failed to locate Rust and C++ verifier binaries")?;
    println!("rust binary: {}", env.rust_bin.display());
    println!(
        "cpp  binary: {} (upstream {})",
        env.cpp_bin.display(),
        env.upstream_hash
    );

    // Load seed corpus: every loadable .o with at least one executable section.
    let samples = paths::samples_dir(root);
    let all_o = paths::find_o_files(&samples)?;
    let mut seeds: Vec<Seed> = Vec::new();
    for path in all_o {
        let Ok(data) = fs::read(&path) else { continue };
        let ranges = exec_ranges(&data);
        if !ranges.is_empty() {
            seeds.push((path, data, ranges));
        }
    }
    if seeds.is_empty() {
        bail!(
            "no usable seed .o files under {} (run `git submodule update --init --recursive`)",
            samples.display()
        );
    }
    println!(
        "seeds: {} object files with executable sections",
        seeds.len()
    );
    println!(
        "budget: iters={} time={}s timeout={}s seed={:#x}",
        args.iters, args.time_secs, args.timeout_secs, args.seed
    );

    let out_root = root.join("security/findings");
    let tmp_dir = paths::target_dir(root).join("xtask/security");
    fs::create_dir_all(&tmp_dir)?;
    // Namespace by seed so concurrent shards never clobber each other's mutant
    // file or finding reproducers.
    let run_tag = format!("s{:x}", args.seed);
    let mutant_path = tmp_dir.join(format!("mutant_{run_tag}.o"));

    let mut rng = Rng::new(args.seed);
    let start = Instant::now();
    let mut evaluated = 0u64;
    let mut found: std::collections::BTreeMap<String, usize> = Default::default();
    let mut saved: std::collections::BTreeMap<String, usize> = Default::default();

    loop {
        if args.iters != 0 && evaluated >= args.iters {
            break;
        }
        if args.time_secs != 0 && start.elapsed().as_secs() >= args.time_secs {
            break;
        }

        // Pick a seed and mutate a copy of it.
        let (seed_path, seed_data, ranges) = rng.pick(&seeds).clone();
        let mut buf = seed_data.clone();
        let desc = mutate(&mut buf, &ranges, &mut rng);
        fs::write(&mutant_path, &buf)?;

        let (rust_out, _) = run_verifier(&env.rust_bin, &mutant_path, args.timeout_secs, false)?;
        let (cpp_out, _) = run_verifier(&env.cpp_bin, &mutant_path, args.timeout_secs, false)?;
        evaluated += 1;

        if let Some(class) = classify(rust_out, cpp_out) {
            // Refine: a soundness/precision verdict where the *reference* rejects
            // the mutant at DECODE time (illegal opcode) is an unmarshal
            // divergence — the two verifiers analyzed different programs — not a
            // verifier-logic soundness hole. Reclassify so true soundness
            // candidates aren't buried (this extra verbose run is cheap because
            // soundness/precision hits are rare).
            let class = if matches!(class, "soundness" | "precision") {
                let (_, cpp_v) = run_verifier(&env.cpp_bin, &mutant_path, args.timeout_secs, true)?;
                if cpp_v.contains("unmarshaling error") || cpp_v.contains("bad instruction") {
                    "unmarshal"
                } else {
                    class
                }
            } else {
                class
            };
            *found.entry(class.to_string()).or_default() += 1;
            let save_count = saved.entry(class.to_string()).or_default();
            if *save_count < args.max_per_class {
                *save_count += 1;
                let id = *save_count;
                save_finding(
                    &out_root,
                    class,
                    &run_tag,
                    id,
                    &seed_path,
                    &desc,
                    rust_out,
                    cpp_out,
                    &buf,
                    &env,
                    args.timeout_secs,
                )?;
                let stem = seed_path.file_name().unwrap_or_default().to_string_lossy();
                println!(
                    "[{class}] #{id}  rust={} cpp={}  seed={stem}  ({desc})",
                    rust_out.label(),
                    cpp_out.label()
                );
            }
        }

        if evaluated.is_multiple_of(200) {
            println!(
                "  …{evaluated} mutants, {:.0}s elapsed, findings: {}",
                start.elapsed().as_secs_f64(),
                summary(&found)
            );
        }
    }

    println!("\n=== diff-fuzz complete ===");
    println!(
        "evaluated: {evaluated} mutants in {:.0}s",
        start.elapsed().as_secs_f64()
    );
    if found.is_empty() {
        println!("findings: none — no verdict divergence detected");
    } else {
        println!("findings (total occurrences): {}", summary(&found));
        println!("reproducers saved under {}", out_root.display());
    }
    Ok(())
}

fn summary(map: &std::collections::BTreeMap<String, usize>) -> String {
    if map.is_empty() {
        return "none".into();
    }
    map.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[allow(clippy::too_many_arguments)]
fn save_finding(
    out_root: &Path,
    class: &str,
    run_tag: &str,
    id: usize,
    seed_path: &Path,
    desc: &str,
    rust_out: Outcome,
    cpp_out: Outcome,
    mutant: &[u8],
    env: &parity_common::ParityEnv,
    timeout_secs: u64,
) -> Result<()> {
    let dir = out_root.join(class);
    fs::create_dir_all(&dir)?;
    let stem = seed_path.file_stem().unwrap_or_default().to_string_lossy();
    let base = format!("{run_tag}_{id:04}_{stem}");
    let o_path = dir.join(format!("{base}.o"));
    fs::write(&o_path, mutant)?;

    // Re-run both verbosely on the saved reproducer to capture diagnostics.
    let (_, rust_text) = run_verifier(&env.rust_bin, &o_path, timeout_secs, true)?;
    let (_, cpp_text) = run_verifier(&env.cpp_bin, &o_path, timeout_secs, true)?;

    let report = format!(
        "# Differential finding: {class}\n\n\
         - seed:    {}\n\
         - mutation: {desc}\n\
         - rust verdict: {}\n\
         - cpp  verdict: {}\n\
         - reproducer:  {}\n\n\
         Reproduce:\n\
         \x20 target/release/prevail -v {0}\n\
         \x20 tests/upstream/bin/prevail -v {0}\n\n\
         (the path above is the seed; substitute the .o reproducer next to this file)\n\n\
         ## Rust output\n```\n{rust_text}\n```\n\n\
         ## C++ output\n```\n{cpp_text}\n```\n",
        o_path.display(),
        rust_out.label(),
        cpp_out.label(),
        o_path.display(),
    );
    fs::write(dir.join(format!("{base}.txt")), report)?;
    Ok(())
}
