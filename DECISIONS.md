# DECISIONS.md — Architecture Decision Records (ADRs)

This document records architectural, licensing, and governance decisions for RER (RER Engineering Relay).

---

## ADR-0001: Adoption and Owner Confirmation of Apache-2.0 License

- **Status**: Accepted (Confirmed by Owner)
- **Date**: 2026-10-09
- **Deciders**: Ronald Edward Reeves Jr (Project Owner)

### Context
SPEC §3 recommends the Apache License, Version 2.0 for RER, allowing commercial and non-commercial use, modification, and redistribution while preserving attribution. SPEC §3 explicitly required that the owner confirm the license choice before the `LICENSE` and `NOTICE` files were finalized, and that this confirmation be recorded.

### Decision
The owner, Ronald Edward Reeves Jr, confirmed the selection of the Apache License 2.0 as the project's permanent open-source license:
1. The copyright notice "Copyright 2026 Ronald Edward Reeves Jr" was populated in `LICENSE` via pull request #2 (commit `ea37aec`).
2. The `NOTICE` file required under Apache-2.0 section 4(d) was added via pull request #24 (commit `a518001`).
3. All source code, crate metadata, and future contributions are governed by Apache-2.0.

### Consequences
- Downstream users and contributors have explicit Apache-2.0 rights and obligations.
- `LICENSE` and `NOTICE` are finalized and protected from automated agent modification.

---

## ADR-0002: Virtual Cargo Workspace Layout

- **Status**: Accepted
- **Date**: 2026-10-09
- **Deciders**: Ronald Edward Reeves Jr, Implementation Agent

### Context
SPEC §1 and §18 require a maintainable, modular Rust architecture that builds on hosted Linux runners without local compilation prerequisites. Future milestones require distinct capabilities (core relay, configuration, testing harness, protocol modules).

### Decision
Adopt a Cargo virtual workspace at the repository root:
1. Root `Cargo.toml` defines `[workspace]` and coordinates member crates located in `crates/*`.
2. Shared metadata (`edition = "2021"`, `rust-version = "1.80"`, `license = "Apache-2.0"`, authors, repository) is centralized under `[workspace.package]`.
3. The primary crate `crates/rer` houses the main executable CLI and library interfaces.
4. Toolchain requirements are pinned via `rust-toolchain.toml` to stable Rust with `clippy` and `rustfmt`.

### Consequences
- Modular crates can be added in subsequent milestones without altering root build ergonomics.
- Unified `Cargo.lock` ensures deterministic builds across CI runners (`--locked`).

---

## ADR-0003: CI Workflow Boundaries and Agent Constraints

- **Status**: Accepted
- **Date**: 2026-10-09
- **Deciders**: Ronald Edward Reeves Jr, Implementation Agent

### Context
SPEC §1, §18, and §19 require reproducible GitHub Actions CI on public hosted Linux runners within standard free-tier quotas. Autonomous implementation agents need clear boundaries to prevent security and pipeline misconfigurations.

### Decision
1. CI workflows located in `.github/workflows/` are managed exclusively by the owner through reviewed pull requests (established in pull request #25, commit `b7e9a62`).
2. Implementation agents are strictly prohibited from creating or editing files in `.github/`, `LICENSE`, and `NOTICE`.
3. The fast-profile CI workflow executes `cargo fmt --check`, `cargo check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` on push and PR.
4. Caches are keyed on `rust-toolchain*` and `Cargo.lock`.

### Consequences
- Pipeline stability and security are maintained under owner control.
- Changes cannot silently bypass quality gates.
