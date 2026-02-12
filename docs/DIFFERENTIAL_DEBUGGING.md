# Differential Debugging Methodology

This document defines a scientific workflow for Rust-vs-C++ differential debugging.
The goal is not to "find a plausible fix", but to establish and verify causal claims.

## Core Principles

1. Reproducibility over intuition.
- Every claim must be backed by a command, test, trace, or log artifact.

2. Falsification over confirmation.
- Design experiments that can disprove your current hypothesis.
- Do not keep a hypothesis alive without new supporting evidence.

3. Earliest divergence wins.
- Always chase the first semantic mismatch, not the largest visible mismatch.

4. One variable at a time.
- Change one thing per experiment.
- Avoid multi-factor edits that make causality ambiguous.

5. C++ is the behavioral oracle for parity.
- If unsure what behavior should be, measure upstream.
- Do not "improve" Rust away from C++ semantics in parity work.

## Required Work Log Discipline

Maintain a continuous investigation log (for example, `docs/upstream-parity-bug-hunt-log.md`).
Each attempt must include:

- Timestamp.
- Hypothesis (single sentence, falsifiable).
- Prediction (what should change if hypothesis is true).
- Experiment (exact command(s)/test(s)).
- Observation (verbatim key outputs).
- Conclusion: `supported`, `refuted`, or `inconclusive`.
- Next action.

Rules:

- Never delete prior entries.
- Never rewrite past conclusions. Add a correction entry instead.
- Mark stale hypotheses explicitly as stale or refuted.

Suggested entry template:

```text
[timestamp]
Hypothesis:
Prediction:
Experiment:
Observation:
Conclusion: supported | refuted | inconclusive
Next action:
```

## Standard Differential Loop

1. Select one failing sample/case.
- Prefer the smallest failing case.
- If no small case exists, construct one by reduction.

2. Freeze the case.
- Record exact sample path, section/case name, and expected observable(s).

3. Reproduce both sides.
- Run C++ and Rust with equivalent inputs and verbosity.
- Archive raw outputs before interpretation.

4. Locate first divergence.
- Compare state transitions, not just final output.
- Step through transfer points until the first semantic mismatch appears.

5. State a falsifiable hypothesis.
- "Mismatch appears because X in module Y under condition Z."

6. Run a paired experiment.
- Rust-side focused test or trace.
- C++-side equivalent test or trace for the same property.

7. Decide based on evidence.
- If refuted: record and discard hypothesis.
- If supported: implement smallest parity-preserving fix.

8. Add guardrails.
- Add regression tests for the real failure.
- Add "refuted-hypothesis guards" when a tempting false explanation was disproven.

9. Re-validate in layers.
- Focused test(s) -> local suite -> parity subset -> full parity/conformance.

## Hypothesis Quality Checklist

A usable hypothesis must include:

- Trigger condition: specific state/pattern where mismatch starts.
- Mechanism: concrete function/path expected to cause mismatch.
- Observable prediction: exact string/constraint/value expected to change.
- Refutation condition: what result would prove it wrong.

Bad hypothesis:
- "SplitDBM seems wrong."

Good hypothesis:
- "When joining from bottom in `TypeToNumDomain::join_assign`, early return skips selective join, so relation R remains <=255 instead of <=254 at label L."

## Empirical Testing Patterns

### 1) Differential case runner

Use:

```bash
cargo xtask diff yaml-case <yaml-path> '<test-case substring>' [yaml_suite_test_name]
```

This runs C++, C++-actual, and Rust on the same selected case and stores logs in `/tmp/prevail-diff`.

### 2) Rust test narrowing

Use:

- High-level failing parity test (integration/sample level).
- Medium-level module test (domain/API level).
- Low-level unit test (single function/operation level).

Only tighten scope after a broader failing test is in place.

### 3) Paired Rust/C++ property tests

For non-obvious semantics, add equivalent tests in both implementations.
Keep only tests that verify true upstream behavior or a real Rust divergence.

### 4) Targeted traces

Enable the smallest trace surface needed:

- `TRACE_UNSIGNED=1`
- `TRACE_ZONE_CONSTRAINTS=1`
- `TRACE_DIFF=1` (to enable trace bundle for differential scripts)

Guidelines:

- Trace before and after the suspected transfer function.
- Include identifiers (label/block/op) so traces can be aligned across implementations.
- Remove temporary trace noise once the hypothesis is decided.

## Anti-Self-Deception Rules

1. Separate observation from interpretation.
- First quote what happened.
- Then explain what you think it means.

2. Require bidirectional checks.
- For parity claims, verify in both Rust and C++ when feasible.

3. Guard against "accidental pass".
- A passing test without proving the intended property is insufficient.

4. Do not infer from output formatting alone.
- Confirm semantic entailment where output text might be lossy.

5. Avoid hidden assumption drift.
- If assumptions change (upstream hash, build mode, fixtures), rerun baseline.

## Cycle-Breaking Protocol

If two consecutive hypotheses are refuted or inconclusive:

1. Stop coding and summarize current evidence.
2. List explicit assumptions currently in play.
3. Pick one assumption and design a direct test against it.
4. Reduce scope to an earlier divergence point if available.

If no new evidence is produced for one full cycle:

- Do not continue patching.
- Add instrumentation or a new discriminating test first.

## Stop Criteria for a "real fix"

A fix is accepted only when all are true:

1. A pre-fix failing test exists and fails for the right reason.
2. The test passes after the fix.
3. The fix is consistent with upstream behavior.
4. Conformance/non-targeted suites do not regress.
5. The investigation log records hypothesis -> experiment -> proof chain.

## Minimal Command Reference

Single case differential:

```bash
cargo xtask diff yaml-case tests/upstream/test-data/unsigned.yaml 'assume -1 > INT_MAX nop' yaml_unsigned
cargo xtask diff unsigned-case 'assume [-1, 1] > [1, 2] narrows'
```

Rust filtered YAML run with full mismatch dump:

```bash
YAML_CASE='assume -1 > INT_MAX nop' YAML_PRINT_ACTUAL=1 cargo test --test yaml_tests yaml_unsigned -- --nocapture
```

Full parity baseline:

```bash
cargo xtask parity compare
```
