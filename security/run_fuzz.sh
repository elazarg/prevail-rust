#!/usr/bin/env bash
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
#
# Run every libfuzzer target for a time budget and collect any crashes into
# security/findings/crash-rust/. Robustness oracle: the verifier must never
# panic, abort, or segfault on any input (the binary is built panic=abort).
#
# Usage:
#   security/run_fuzz.sh [SECONDS_PER_TARGET] [target ...]
#
#   security/run_fuzz.sh                 # 120s each, all targets
#   security/run_fuzz.sh 600             # 600s each, all targets
#   security/run_fuzz.sh 300 fuzz_program fuzz_elf_build
set -u

SECS="${1:-120}"
shift || true

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT/fuzz" || exit 1

ALL_TARGETS=(fuzz_elf_parse fuzz_elf_build fuzz_btf_parse fuzz_unmarshal fuzz_assembler fuzz_program fuzz_end_to_end)
if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
else
  TARGETS=("${ALL_TARGETS[@]}")
fi

FINDINGS="$ROOT/security/findings/crash-rust"
mkdir -p "$FINDINGS"

echo "== libfuzzer campaign: ${SECS}s per target =="
echo "targets: ${TARGETS[*]}"
echo

crashes=0
errors=0
marker="$(mktemp)"
trap 'rm -f "$marker"' EXIT
for t in "${TARGETS[@]}"; do
  echo "--- $t ---"
  touch "$marker"
  # Seed corpus from previous runs is reused automatically (corpus/<t>/).
  cargo +nightly fuzz run "$t" -- -max_total_time="$SECS" -print_final_stats=1 2>&1 \
    | grep -E "panicked|Done [0-9]|stat::average_exec|stat::number_of_exec|SUMMARY|ERROR:|^error" \
    | sed 's/^/  /'
  status=${PIPESTATUS[0]}

  # cargo-fuzz writes reproducers to fuzz/artifacts/<t>/ (crash-*, oom-*, timeout-*).
  # Collect only the ones this run wrote; earlier runs' artifacts stay put.
  new_artifacts=0
  art_dir="$ROOT/fuzz/artifacts/$t"
  if [ -d "$art_dir" ]; then
    while IFS= read -r art; do
      dest="$FINDINGS/fuzz_${t}_$(basename "$art")"
      cp "$art" "$dest"
      echo "  CRASH -> $dest"
      new_artifacts=$((new_artifacts + 1))
    done < <(find "$art_dir" -maxdepth 1 -type f -newer "$marker" \
               \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' \))
  fi
  crashes=$((crashes + new_artifacts))
  if [ "$status" -ne 0 ] && [ "$new_artifacts" -eq 0 ]; then
    echo "  ERROR: cargo fuzz exited $status without writing a reproducer (build failure?)"
    errors=$((errors + 1))
  fi
  echo
done

echo "== done: $crashes crash artifact(s) collected under $FINDINGS =="
echo "Reproduce a crash with:"
echo "  cd fuzz && cargo +nightly fuzz run <target> <artifact-file>"
[ "$errors" -gt 0 ] && echo "== $errors target(s) failed to run =="
[ "$crashes" -eq 0 ] && [ "$errors" -eq 0 ]
