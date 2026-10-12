# CHANGELOG.md — Changelog

All notable changes to RER (RER Engineering Relay) are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added - Milestone RER-F-018 (Legacy OS Compatibility Experiments and Documented Results)
- **Legacy OS Compatibility Evaluation**: Codified experimental test script (`packaging/legacy-compat-test.sh`) to evaluate packaged artifacts (.deb, .rpm, .tar.gz) across clean Debian 10 Buster, Ubuntu 20.04 LTS, and RHEL 7 / CentOS 7 container environments where images and engines are available, with automated limitation detection and static ELF ABI inspection fallback.
- **Experimental Findings & Limitations in PLATFORM_SUPPORT.md**: Documented comprehensive evaluation results, glibc symbol resolution constraints (GLIBC_2.32/GLIBC_2.34 dependencies), systemd hardening version boundaries (systemd 241/245 vs 219), package format compatibility, and operating system EOL lifecycle status in `PLATFORM_SUPPORT.md`.
- **Truth in Documentation Enforcement**: Formally reinforced SPEC §4 requirement that a successful compile alone is never claimed as support, designating legacy Linux systems as unsupported for standard dynamic packages while verifying static musl standalone binary functionality where feasible.
- **Automated Integration Tests**: Added integration test suite (`crates/rer/tests/legacy_compat_tests.rs`) validating script execution, glibc dependency analysis, systemd compatibility constraints, and documentation integrity.

### Added - Milestone RER-F-014 (Helm Chart and Kubernetes Deployment Tests)
- **Helm Chart Packaging**: Created complete Helm chart (`deploy/helm/rer`) matching application version (`0.1.0`), providing Deployment, Service, ServiceAccount, ConfigMap, PodDisruptionBudget, ServiceMonitor, and PVC templates conforming to SPEC §16.D.
- **Values Schema Validation**: Implemented JSON Schema Draft 7 specification (`deploy/helm/rer/values.schema.json`) validating chart values, types, required properties, and port definitions across default values, simple deployment (`values-simple.yaml`), and multi-instance topology (`values-multi-instance.yaml`).
- **Non-Root Hardening & Security Context**: Configured Restricted Pod Security Standard contexts with unprivileged UID/GID `65532:65532`, `readOnlyRootFilesystem: true`, privilege escalation disabled, dropped `ALL` capabilities, and dedicated `emptyDir` mount for `/tmp` health sockets.
- **Application Health Probes & Resource Limits**: Added liveness, readiness, and startup exec probes querying `/usr/local/bin/rer health` without excessive traffic, paired with default CPU and memory requests and limits.
- **Replica Scaling Semantics Documentation**: Explicitly documented that scaling replicas does not preserve UDP/TCP routing semantics automatically across chart documentation, values files, and release notes, providing multi-instance configuration examples with explicit port ownership.
- **Smoke Deployment Script & Integration Tests**: Created `deploy/helm/smoke-test.sh` for linting, schema checking, and live cluster deployment smoke tests on free CI Kubernetes (kind), with cleanly documented limitations when container clusters are unavailable, alongside comprehensive Rust integration tests (`crates/rer/tests/helm_tests.rs`).

### Added - Milestone RER-F-006 (Logical Interfaces, Paired Directional Streams, Multiple Streams, and Fan-Out)
- **Logical Interfaces**: Expressed logical interfaces with one or two directional streams (`tx_stream`, `rx_stream`) in YAML configuration and exposed their topology via CLI output (`crates/rer/src/config.rs`, `crates/rer/src/cli.rs`).
- **Directional Independence**: Guaranteed that transmit (TX) and receive (RX) directions operate with independent counters (`StreamStats`), socket endpoints, transport protocols, bounded queues, error tracking, and routing policies (`crates/rer/src/relay.rs`).
- **Stream and Interface CLI Inspection**: Implemented `rer streams` command supporting human-readable text output and machine-readable JSON reports (`rer streams --json`), detailing stream endpoints, directional pairings, and configuration context.
- **Pairing as Configuration Context**: Explicitly documented that directional pairing represents administrative and operator configuration context, not in-band packet correlation (SPEC §6).
- **Fan-Out Resilience**: Verified that multi-destination streams isolate destination failures, allowing healthy destinations to continue receiving traffic uninterrupted while errors on unavailable destinations are accounted for independently.
- **Multiple Simultaneous Interfaces**: Enabled and verified running multiple simultaneous logical interfaces (paired and single-direction) concurrently on a single relay instance under test (`crates/rer/tests/logical_interface_tests.rs`).
- **Example Configurations**: Added `examples/multi_interface.yaml` and documented configuration context semantics in `examples/paired_streams.yaml`.

### Added - Milestone RER-F-013 (Docker Image and Docker Compose Deployment)
- **Multi-Architecture Distroless Container Image**: Created multi-arch (`amd64` and `arm64`) Dockerfile based on minimal distroless base (`gcr.io/distroless/cc-debian12:nonroot`). Runs as unprivileged non-root user (UID:GID `65532:65532`) with zero added capabilities, and ships no shell or package manager in the runtime image (`deploy/docker/Dockerfile`, `Dockerfile`).
- **Real Application Health Check**: Implemented `rer health` command querying a local Unix domain socket health server exposed by running relay instances. Exercises real application health, checking thread liveness, stream status, and packet counters without generating excessive mission network traffic (`crates/rer/src/health.rs`).
- **CLI Status Inspection**: Implemented `rer status` CLI subcommand reporting live relay health, uptime, and per-stream traffic counters as human-readable text or structured JSON.
- **Docker Compose Deployments**: Created complete single-instance (`deploy/compose/docker-compose.single.yml`) and multi-instance relay-chain (`deploy/compose/docker-compose.relay-chain.yml`) Compose deployments with versioned image references, non-root security settings, dropped capabilities, read-only root filesystems, resource limits, and health checks.
- **SBOM and Vulnerability Scan Artifacts**: Generated full SPDX 2.3 JSON specification SBOM (`deploy/docker/rer.spdx.json`) and container image vulnerability scan report (`deploy/docker/vulnerability-scan.json`) with zero vulnerabilities using free tooling, along with automation script (`deploy/docker/generate-sbom-and-scan.sh`).
- **Comprehensive Integration Tests**: Added integration test suite verifying Dockerfile specifications, image version metadata matching binary version, Compose configuration validation, real healthcheck behavior, graceful SIGTERM shutdown, and end-to-end traffic smoke tests through single and multi-hop relay chains (`crates/rer/tests/docker_compose_tests.rs`).
### Added - Milestone RER-F-015 (.deb, .rpm and Standalone Binary Packaging)
- **Multi-Architecture Standalone Artifacts**: Added standalone tarball packaging for Linux x86-64 and ARM64 (AArch64) containing binaries, systemd units, example configurations, and documentation with SHA-256 checksums (`SHA256SUMS`) and version metadata (`metadata.json`).
- **Debian (.deb) and RPM (.rpm) Packaging**: Created automated packaging definitions and scripts for Debian/Ubuntu (`.deb`) and RHEL/Fedora/compatible distributions (`.rpm`), installing `/usr/bin/rer`, example configuration under `/etc/rer/rer.yaml`, systemd unit `/usr/lib/systemd/system/rer.service`, documentation under `/usr/share/doc/rer/`, and state directory `/var/lib/rer/`.
- **Safe Service Management Defaults**: Ensured systemd unit is installed with safe defaults and is neither enabled nor started automatically upon installation.
- **Configuration Preservation**: Registered `/etc/rer/rer.yaml` in Debian `conffiles` and RPM `%config(noreplace)`, ensuring operator configuration edits are preserved across package upgrades.
- **Data Loss Prevention on Uninstall**: Implemented maintainer scripts (`postrm`, `%postun`) ensuring uninstallation does not silently destroy operator configuration or state data, leaving `/etc/rer` and `/var/lib/rer` intact upon package removal unless explicitly purged.
- **Smoke Testing and Test Suite**: Added `packaging/smoke-test.sh` for container smoke testing of clean install, upgrade, and uninstall without data loss, alongside automated integration tests (`crates/rer/tests/packaging_tests.rs`).

### Added - Milestone RER-F-004 (Initial Traffic Generator and Simulation Harness)
### Added - Milestone RER-F-005 (TCP Relay, Four Transport Conversions, Framing, Reconnection, and Backpressure)
- **Four Transport Conversion Combinations**: Implemented forwarding across all four transport combinations: UDP-to-UDP, UDP-to-TCP, TCP-to-UDP, and TCP-to-TCP (`crates/rer/src/relay.rs`).
- **Explicit Framing Protocol**: Added explicit length-prefixed framing between TCP byte streams and discrete datagrams using a 4-byte big-endian unsigned 32-bit length header, preserving datagram boundaries and payload bytes with defragmentation support (`crates/rer/src/framing.rs`).
- **Resilient Connection Lifecycle & Reconnection**: Implemented TCP connection lifecycle handling with exponential backoff and timeouts against destination outages at startup and during active forwarding. Single TCP destinations buffer packets in bounded queues during outages and deliver upon reconnection.
- **Slow Reader Backpressure & Bounded Memory**: Enforced bounded memory limits with `max_queue_size` and `max_packet_size`. Slow TCP readers stalling writes trigger bounded queue saturation, drop policy enforcement, and accounting in `backpressure_events` and `drops_queue_full`.
- **Harness-Driven Integration Tests**: Extended `SimulationHarness` to drive all four transport conversions end-to-end unprivileged in CI, and added comprehensive integration tests verifying framing, reconnection lifecycle, and slow-reader backpressure (`crates/rer/tests/tcp_relay_tests.rs`).
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
