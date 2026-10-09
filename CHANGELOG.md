# CHANGELOG.md — Changelog

All notable changes to RER (RER Engineering Relay) are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Milestone RER-F-001 (Foundation)
- **Cargo Workspace**: Initialized virtual Cargo workspace with shared package metadata (`edition = "2021"`, `rust-version = "1.80"`, `license = "Apache-2.0"`) and member crate `crates/rer`.
- **Toolchain Specification**: Added `rust-toolchain.toml` targeting the stable channel with `clippy` and `rustfmt` components.
- **Continuous Integration**: Integrated fast-profile CI workflow (`.github/workflows/ci.yml`) enforcing `cargo fmt --check`, `cargo check`, `cargo clippy -D warnings`, and `cargo test` across all targets and features.
- **CI Caching**: Implemented GitHub Actions caching keyed on `rust-toolchain*` and `Cargo.lock`.
- **Licensing Confirmation**: Recorded owner confirmation of Apache License 2.0 in `DECISIONS.md` (ADR-0001) following initial `LICENSE` and `NOTICE` commits.
- **Durable Documentation**: Added complete foundational project documentation describing implemented behavior:
  - `README.md`: Project summary, status, documentation index, and build instructions.
  - `AGENTS.md`: Operational boundaries and constraints for autonomous implementation agents.
  - `ARCHITECTURE.md`: Implemented workspace architecture and planned roadmap subsystems.
  - `DECISIONS.md`: Architecture Decision Records (ADRs) for licensing, workspace layout, and CI controls.
  - `KNOWN_ISSUES.md`: Current baseline limitations and pending roadmap items.
  - `PLATFORM_SUPPORT.md`: Verified Linux x86-64 target and roadmap platform tiers.
  - `CONTRIBUTING.md`: Contribution guidelines, code standards, and PR workflows.
  - `SECURITY.md`: Security policies, vulnerability disclosure, and operational safety tenets.
  - `CHANGELOG.md`: Project history and milestone release notes.
