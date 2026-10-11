# ARCHITECTURE.md — RER Architecture and Design

This document details the architecture of RER (RER Engineering Relay), distinguishing implemented foundation components from planned roadmap features.

## 1. System Overview

RER is designed to connect, observe, test, and diagnose telemetry and command traffic across heterogeneous Linux networks, containers, and multi-hop relay topologies. Rather than acting solely as a passive forwarder, RER provides deep diagnostic visibility into packet paths, sequence continuity, transport boundaries, and relay decisions.

## 2. Implemented Architecture (Milestones RER-F-001 & RER-F-002)

At the current stage, the implemented architecture consists of the workspace scaffold, CI quality gates, and the configuration and validation subsystem:

```
rer/
├── Cargo.toml             # Virtual workspace configuration and shared package metadata
├── Cargo.lock             # Deterministic dependency lockfile
├── rust-toolchain.toml    # Toolchain specification (channel: stable, clippy, rustfmt)
├── crates/
│   └── rer/               # Core executable and library entry point
│       ├── Cargo.toml     # Member manifest inheriting workspace metadata
│       ├── src/
│       │   ├── lib.rs     # Library interface (exposes version, config, CLI, and secret models)
│       │   ├── main.rs    # Executable entry point
│       │   ├── cli.rs     # CLI command parsing and handlers (validate, inspect, version)
│       │   ├── config.rs  # Strict YAML models, semantic validation, and schema generation
│       │   └── secret.rs  # SecretString wrapper protecting sensitive parameters
│       └── tests/
│           ├── cli_tests.rs          # CLI blackbox tests (rer validate, inspect, version)
│           └── config_validation.rs  # Schema, example validation, and rejection tests
├── docs/
│   ├── SPEC.md            # Master project specification
│   └── CONFIGURATION.md   # YAML configuration format reference
├── examples/              # Functional example YAML configurations
│   ├── minimal.yaml
│   ├── paired_streams.yaml
│   ├── multi_instance.yaml
│   ├── fan_out.yaml
│   └── management_auth.yaml
└── schema/
    └── rer-config.schema.json # JSON Schema for RER configuration
```

### 2.1 Workspace Structure

- **Virtual Workspace**: Root `Cargo.toml` coordinates member crates under `crates/*` using Cargo resolver 2. Shared metadata (edition 2021, rust-version 1.80, Apache-2.0 license, authors, repository) is centralized in `[workspace.package]`.
- **`crates/rer`**: The primary package providing the CLI binary and library interfaces.

### 2.2 Configuration and Validation Subsystem (`RER-F-002`)

- **Strict YAML Model**: Validates instance definitions, stream topologies, network endpoints (UDP and TCP), logical interface pairings, management interfaces, and queue/buffer bounds.
- **Path-Attributed Error Diagnostics**: Reports exact structural paths (e.g. `instances[0].streams[1].source.address`) and explanations for all syntax and semantic errors. Rejects unknown fields, duplicate identities, and conflicting configurations.
- **Secret Redaction**: Protects sensitive operational data via `SecretString`, guaranteeing that `rer validate --effective` and `rer inspect` redact secret tokens to `[REDACTED]`.
- **Machine-Readable Automation**: Emits structured JSON validation reports (`--json` / `--format json`).
- **Schema Enforcement**: Maintains `schema/rer-config.schema.json` and automatically validates all project examples against the schema in CI tests.

### 2.3 CI and Quality Pipeline

- **Hosted Execution**: Builds entirely on standard GitHub Actions Linux runners without requiring local compilation or paid infrastructure.
- **Enforced Quality Gates**:
  - `cargo fmt --all --check`
  - `cargo check --all-targets --all-features --locked`
  - `cargo clippy --all-targets --all-features --locked -- -D warnings`
  - `cargo test --all-features --locked`
- **Cache Strategy**: Caching covers Cargo registry indexes, git database, and build target outputs, keyed on `cargo-${{ runner.os }}-${{ hashFiles('rust-toolchain*', 'Cargo.lock') }}`.

## 3. Planned Architecture (Roadmap Overview)

Future milestones (as detailed in [`docs/SPEC.md`](docs/SPEC.md) and [`ROADMAP.md`](ROADMAP.md)) will introduce the following subsystems:

1. **Core Relay and Transport Engine (`RER-F-003`, `RER-F-005`)**:
   Asynchronous I/O handling UDP datagram boundaries, TCP stream lifecycle/reconnection, backpressure, bounded buffer queues, and conversion combinations (UDP↔UDP, UDP↔TCP, TCP↔UDP, TCP↔TCP).
2. **Logical Interfaces and Directional Streams (`RER-F-006`)**:
   Paired directional streams modeling command TX/response RX and uplink/downlink relationships with independent counters, backpressure, and routing policies.
3. **Management API and Diagnostics (`RER-F-007`, `RER-F-008`, `RER-F-009`)**:
   Non-shell local HTTP/JSON management endpoints, structured diagnostic event feeds, sequence tracking, and payload inspection.
4. **Simulation and Verification Harness (`RER-F-004`, `RER-F-010`, `RER-F-011`)**:
   Traffic generation, deterministic multi-relay topology emulation, and capture replay verification.
5. **Observability and Packaging (`RER-F-012`–`RER-F-015`)**:
   Prometheus/OpenMetrics exporter, non-root Docker images, Helm charts, and standalone `.deb`/`.rpm` packaging.
