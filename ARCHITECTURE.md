# ARCHITECTURE.md — RER Architecture and Design

This document details the architecture of RER (RER Engineering Relay), distinguishing implemented foundation components from planned roadmap features.

## 1. System Overview

RER is designed to connect, observe, test, and diagnose telemetry and command traffic across heterogeneous Linux networks, containers, and multi-hop relay topologies. Rather than acting solely as a passive forwarder, RER provides deep diagnostic visibility into packet paths, sequence continuity, transport boundaries, and relay decisions.

## 2. Implemented Architecture (Milestone RER-F-001)

At the current foundation stage, the implemented architecture consists of the core workspace scaffold, build configuration, and CI quality gates:

```
rer/
├── Cargo.toml             # Virtual workspace configuration and shared package metadata
├── Cargo.lock             # Deterministic dependency lockfile
├── rust-toolchain.toml    # Toolchain specification (channel: stable, clippy, rustfmt)
├── crates/
│   └── rer/               # Core executable and library entry point
│       ├── Cargo.toml     # Member manifest inheriting workspace metadata
│       └── src/
│           ├── lib.rs     # Library interface (exposes version and package info)
│           └── main.rs    # Executable entry point
└── docs/
    └── SPEC.md            # Master project specification
```

### 2.1 Workspace Structure

- **Virtual Workspace**: Root `Cargo.toml` coordinates member crates under `crates/*` using Cargo resolver 2. Shared metadata (edition 2021, rust-version 1.80, Apache-2.0 license, authors, repository) is centralized in `[workspace.package]`.
- **`crates/rer`**: The main package providing the executable CLI and library primitives. Currently implements minimal version reporting and test scaffolding.

### 2.2 CI and Quality Pipeline

- **Hosted Execution**: Builds entirely on standard GitHub Actions Linux runners without requiring local compilation or paid infrastructure.
- **Enforced Quality Gates**:
  - `cargo fmt --all --check`
  - `cargo check --all-targets --all-features --locked`
  - `cargo clippy --all-targets --all-features --locked -- -D warnings`
  - `cargo test --all-features --locked`
- **Cache Strategy**: Caching covers Cargo registry indexes, git database, and build target outputs, keyed on `cargo-${{ runner.os }}-${{ hashFiles('rust-toolchain*', 'Cargo.lock') }}`.

## 3. Planned Architecture (Roadmap Overview)

Future milestones (as detailed in [`docs/SPEC.md`](docs/SPEC.md) and [`ROADMAP.md`](ROADMAP.md)) will introduce the following subsystems:

1. **Configuration and Schema Model (`RER-F-002`)**:
   Strict YAML validation, schema verification, path-attributed error reporting, and safe effective-configuration rendering (masking sensitive fields).
2. **Core Relay and Transport Engine (`RER-F-003`, `RER-F-005`)**:
   Asynchronous I/O handling UDP datagram boundaries, TCP stream lifecycle/reconnection, backpressure, bounded buffer queues, and conversion combinations (UDP↔UDP, UDP↔TCP, TCP↔UDP, TCP↔TCP).
3. **Logical Interfaces and Directional Streams (`RER-F-006`)**:
   Paired directional streams modeling command TX/response RX and uplink/downlink relationships with independent counters, backpressure, and routing policies.
4. **Management API and Diagnostics (`RER-F-007`, `RER-F-008`, `RER-F-009`)**:
   Non-shell local HTTP/JSON management endpoints, structured diagnostic event feeds, sequence tracking, and payload inspection.
5. **Simulation and Verification Harness (`RER-F-004`, `RER-F-010`, `RER-F-011`)**:
   Traffic generation, deterministic multi-relay topology emulation, and capture replay verification.
6. **Observability and Packaging (`RER-F-012`–`RER-F-015`)**:
   Prometheus/OpenMetrics exporter, non-root Docker images, Helm charts, and standalone `.deb`/`.rpm` packaging.
