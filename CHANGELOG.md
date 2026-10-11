# CHANGELOG.md — Changelog

All notable changes to RER (RER Engineering Relay) are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Milestone RER-F-004 (Initial Traffic Generator and Simulation Harness)
- **Deterministic Traffic Generator**: Implemented synthetic traffic generator emitting packets with unique IDs (RFC 4122 v4 UUIDs), strictly increasing sequence numbers, and configurable payload size, rate, burst, duration, and PRNG seed (`crates/rer/src/sim/generator.rs`).
- **Reproducible Packet Streams**: Guaranteed that identical seeds reproduce identical packet streams and payload hashes.
- **Verification Test Receiver**: Implemented receiver verifying expected packet counts, individual payload SHA-256 digests, and stream hashes, reporting detected packet loss, duplication, and reordering as JSON (`crates/rer/src/sim/receiver.rs`).
- **Unprivileged Simulation Harness**: Built fast, unprivileged loopback simulation harness running in ordinary CI without requiring elevated privileges, container privileges, or kernel network emulation (`crates/rer/src/sim/harness.rs`, `crates/rer/src/sim/channel.rs`).
- **Simulation CLI**: Added `rer test` CLI subcommand supporting full simulation harness runs (`rer test harness`), standalone generation (`rer test generate`), and standalone receiving (`rer test receive`) with machine-readable JSON reports.
- **Integration Test Suite**: Added comprehensive test suite verifying generator parameters, seed determinism, receiver verification, impairment detection, and loopback relay harness execution (`crates/rer/tests/traffic_generator_tests.rs`).

### Added - Milestone RER-F-003 (Basic UDP Relay)
- **UDP Datagram Forwarding Engine**: Implemented configurable UDP-to-UDP forwarding preserving datagram boundaries and payload bytes across loopback and multi-hop interfaces (`crates/rer/src/relay.rs`).
- **Bounded Buffer Queues and Drop Policies**: Implemented thread-safe bounded FIFO queues enforcing explicit drop policies (`drop_oldest`, `drop_newest`, `reject`) under overload. Every packet drop and oversized datagram rejection is counted and logged with diagnostics, ensuring zero silent packet loss (SPEC §5, §17).
- **Resilient Destination Error Handling**: Socket errors and unreachable destinations are counted and reported per-stream without halting or panicking relay execution. Fan-out streams continue delivering to healthy destinations.
- **Graceful Lifecycle Management**: Implemented `rer run` CLI subcommand enforcing configuration validation before launch, registering POSIX `SIGINT` and `SIGTERM` signal handlers, draining queued packets on termination, and reporting final stream metrics.
- **Integration Test Suite**: Added comprehensive integration tests covering loopback datagram preservation, bounded queue drop behavior, destination fault tolerance, validation refusal, and signal-driven graceful shutdown (`crates/rer/tests/udp_relay_tests.rs`).

### Added - Milestone RER-F-002 (Configuration Model and Validation)
- **YAML Configuration Format**: Defined and documented strict YAML configuration models for RER instances, forwarding streams, network endpoints, logical interfaces, management planes, and bounded queues (`docs/CONFIGURATION.md`).
- **Configuration Validation CLI**: Implemented `rer validate` supporting human-readable error reports and machine-readable JSON output (`--json` / `--format json`). Reports exact path and failure reason for each invalid field and exits non-zero on error.
- **Strict Error Detection**: Implemented rejection of unknown fields (`deny_unknown_fields` with path attribution), conflicting settings (e.g. dual destination specifications or identical tx/rx streams), and duplicate instance or stream identities.
- **Safe Effective-Configuration Inspection**: Implemented `SecretString` type and redaction mechanisms ensuring secrets (such as management authentication tokens) are never leaked in `rer validate --effective` or `rer inspect` output.
- **Configuration Schema**: Maintained JSON schema specification (`schema/rer-config.schema.json`) and automated CI regression test verifying every example configuration against the schema.
- **Example Configurations**: Added functional example configurations covering minimal UDP forwarding, paired directional streams, multi-instance topologies, fan-out, and authenticated management (`examples/`).

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
