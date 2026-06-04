#!/usr/bin/env bash
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
#
# Replay saved crash reproducers and assert the verifier no longer aborts.
# These cover security findings whose triggers are hard to express as unit
# tests (the inputs are fuzzer-minimized). Run from the repo root.
#
#   security/regressions/check.sh
#
# Exit non-zero if any reproducer crashes (SIGABRT/SIGSEGV → exit >= 128).
set -u
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT" || exit 1

fail=0

# ── ELF reproducers: run the release verifier; a crash is exit >= 128. ──
PREVAIL="${PREVAIL:-target/release/prevail}"
if [ ! -x "$PREVAIL" ]; then
  # Honor CARGO_TARGET_DIR layouts.
  alt="$(find "${CARGO_TARGET_DIR:-target}" -path '*release/prevail' -type f 2>/dev/null | head -1)"
  [ -n "$alt" ] && PREVAIL="$alt"
fi
echo "verifier: $PREVAIL"
for f in security/regressions/elf/*.o; do
  [ -e "$f" ] || continue
  "$PREVAIL" -q "$f" >/dev/null 2>&1
  code=$?
  if [ "$code" -ge 128 ]; then
    echo "FAIL (crash, exit $code): $f"
    fail=1
  else
    echo "ok (exit $code): $f"
  fi
done

# ── fuzz_program reproducers: replay through the libfuzzer harness. ──
# A non-crashing input makes the harness exit 0; a crash exits non-zero and
# prints "panicked". Requires the nightly fuzz build.
if command -v cargo >/dev/null 2>&1 && [ -d fuzz ]; then
  for target in fuzz_program fuzz_end_to_end fuzz_assembler; do
    dir="security/regressions/$target"
    [ -d "$dir" ] || continue
    FZ="$(find "${CARGO_TARGET_DIR:-fuzz/target}" -name "$target" -path '*release*' -type f 2>/dev/null | head -1)"
    if [ ! -x "$FZ" ]; then
      echo "building $target (one-off)…"
      ( cd fuzz && cargo +nightly fuzz build "$target" >/dev/null 2>&1 )
      FZ="$(find "${CARGO_TARGET_DIR:-fuzz/target}" -name "$target" -path '*release*' -type f 2>/dev/null | head -1)"
    fi
    if [ ! -x "$FZ" ]; then
      echo "skip $target reproducers (could not build harness)"
      continue
    fi
    for f in "$dir"/*; do
      [ -e "$f" ] || continue
      out="$("$FZ" "$f" 2>&1)"
      if echo "$out" | grep -q "panicked"; then
        echo "FAIL (panic): $f -> $(echo "$out" | grep -m1 'panicked at' | sed 's/.*panicked at //')"
        fail=1
      else
        echo "ok (no panic): $f"
      fi
    done
  done
fi

if [ "$fail" -eq 0 ]; then
  echo "all regression reproducers pass (no crashes)"
fi
exit "$fail"
