# Documentation Policy

This repository keeps **Rust-port-specific** documentation in `docs/`.
General Prevail architecture and abstract-interpretation/domain design docs are
maintained upstream and should be read from `tests/upstream/docs/`.

Do not copy upstream architecture docs into this repository. Link to upstream
files instead, so updates happen in one canonical place.

## Local docs (this repo)

- [upstream-sync.md](upstream-sync.md): How to sync Rust behavior with upstream C++.
- [DIFFERENTIAL_DEBUGGING.md](DIFFERENTIAL_DEBUGGING.md): Parity bug-hunting workflow.

## Upstream docs (canonical)

- `tests/upstream/docs/README.md`
- `tests/upstream/docs/architecture.md`
- `tests/upstream/docs/abstract-interpretation.md`
- `tests/upstream/docs/abstract-domains.md`
- `tests/upstream/docs/instruction-semantics.md`
- `tests/upstream/docs/cfg.md`
- `tests/upstream/docs/memory-model.md`
- `tests/upstream/docs/type-system.md`
- `tests/upstream/docs/testing.md`
- `tests/upstream/docs/glossary.md`
