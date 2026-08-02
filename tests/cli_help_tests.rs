// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! The CLI help text is byte-for-byte identical to the upstream C++ verifier's,
//! including the trailing space CLI11 leaves on an option spec whose description
//! wraps to the next line. Only the usage line differs, since it echoes argv[0].

/// Stands in for the trailing space CLI11 leaves on an option spec whose
/// description wraps, so the golden text carries no literal trailing whitespace.
const TRAILING_SPACE: char = '\u{2423}';

/// Expected `--help` output, with the argv[0] usage line replaced by a marker
/// and each trailing space written as [`TRAILING_SPACE`].
const EXPECTED_HELP: &str = r##"PREVAIL is a new eBPF verifier based on abstract interpretation.


{argv0} [OPTIONS] path [section] [function]


POSITIONALS:
  path TEXT:FILE REQUIRED     Elf file to analyze
  section SECTION             Section to analyze
  function FUNCTION           Function to analyze

OPTIONS:
  -h,     --help              Print this help message and exit
          --version           Display program version information and exit
          --section SECTION   Section to analyze
          --function FUNCTION Function to analyze
  -l                          List programs
  -q,     --quiet             No stdout output, exit code only
          --cfg               Print control-flow graph and exit

Features:
          --termination, --no-verify-termination{false}␣
                              Verify termination. Default: ignore
          --allow-division-by-zero, --no-division-by-zero{false}␣
                              Handling potential division by zero. Default: allow
  -s,     --strict            Apply additional checks that would cause runtime failures
          --stack-size INT:INT in [1 - 1048576]␣
                              Per-subprogram stack frame size in bytes (default: 512)
          --max-call-stack-frames INT:INT in [1 - 128]␣
                              Maximum number of nested function calls (default: 8)
          --max-packet-size INT:INT in [1 - 1073741824]␣
                              Maximum packet size in bytes (default: 65535)
          --include_groups GROUPS:{atomic32,atomic64,base32,base64,callx,divmul32,divmul64,packet}␣
                              Include conformance groups
          --exclude_groups GROUPS:{atomic32,atomic64,base32,base64,callx,divmul32,divmul64,packet}␣
                              Exclude conformance groups

Verbosity:
          --simplify, --no-simplify{false}␣
                              Simplify the display of the CFG by merging chains of instructions
                              into a single basic block. Default: enabled (disabled with
                              --failure-slice)
          --line-info         Print line information
          --print-btf-types   Print BTF types
  -v                          Print invariants and first failure
  -f                          Print first failure
          --failure-slice     Print minimal failure slices showing only instructions that
                              contributed to errors
          --failure-slice-depth UINT␣
                              Maximum backward steps for failure slicing (default: 200)

CFG output:
          --asm FILE          Print disassembly to FILE
          --dot FILE          Export control-flow graph to dot FILE
"##;

/// The line of the usage block that echoes argv[0], which varies by invocation.
const ARGV0_LINE: usize = 3;

#[test]
fn help_text_matches_upstream_byte_for_byte() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_prevail"))
        .arg("--help")
        .output()
        .expect("failed to run the prevail binary");
    assert!(output.status.success(), "--help must exit successfully");
    let actual = String::from_utf8(output.stdout).expect("non-UTF-8 help output");

    let mut actual_lines: Vec<&str> = actual.split('\n').collect();
    let expected = EXPECTED_HELP.replace(TRAILING_SPACE, " ");
    let expected_lines: Vec<&str> = expected.split('\n').collect();

    assert!(
        actual_lines[ARGV0_LINE].ends_with(" [OPTIONS] path [section] [function]"),
        "usage line has an unexpected shape: {:?}",
        actual_lines[ARGV0_LINE]
    );
    actual_lines[ARGV0_LINE] = expected_lines[ARGV0_LINE];

    assert_eq!(
        actual_lines, expected_lines,
        "CLI help text diverged from the upstream C++ output"
    );
}
