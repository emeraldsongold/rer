# ARCHITECTURE.md — RER Architecture and Design

This document details the architecture of RER (RER Engineering Relay), distinguishing implemented foundation components from planned roadmap features.

## 1. System Overview

RER is designed to connect, observe, test, and diagnose telemetry and command traffic across heterogeneous Linux networks, containers, and multi-hop relay topologies. Rather than acting solely as a passive forwarder, RER provides deep diagnostic visibility into packet paths, sequence continuity, transport boundaries, and relay decisions.

## 2. Implemented Architecture (Milestones RER-F-001, RER-F-002, RER-F-003)

At the current stage, the implemented architecture consists of the workspace scaffold, CI quality gates, configuration/validation, and the basic UDP relay subsystem:

```
rer/
├── Cargo.toml             # Virtual workspace configuration and shared package metadata
├── Cargo.lock             # Deterministic dependency lockfile
├── rust-toolchain.toml    # Toolchain specification (channel: stable, clippy, rustfmt)
├── crates/
│   └── rer/               # Core executable and library entry point
│       ├── Cargo.toml     # Member manifest inheriting workspace metadata
│       ├── src/
│       │   ├── lib.rs     # Library interface (exposes version, config, relay, and secret models)
│       │   ├── main.rs    # Executable entry point
│       │   ├── cli.rs     # CLI command parsing and handlers (run, validate, inspect, version)
│       │   ├── config.rs  # Strict YAML models, semantic validation, and schema generation
│       │   ├── relay.rs   # UDP relay engine, bounded queues, drop policies, and counters
│       │   ├── secret.rs  # SecretString wrapper protecting sensitive parameters
│       │   └── signals.rs # POSIX SIGINT and SIGTERM graceful shutdown handlers
│       └── tests/
│           ├── cli_tests.rs          # CLI blackbox tests (rer validate, inspect, version)
│           ├── config_validation.rs  # Schema, example validation, and rejection tests
│           └── udp_relay_tests.rs    # Loopback UDP forwarding, queues, error resilience, and signals
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

### 2.3 UDP Relay Engine Subsystem (`RER-F-003`)

- **Datagram Preservation**: Preserves UDP datagram boundaries and payload bytes without framing corruption, verified via loopback tests.
- **Bounded Queues & Drop Policies**: Protects memory with thread-safe bounded FIFO queues (`BoundedQueue`). Enforces explicit drop policies (`drop_oldest`, `drop_newest`, `reject`) and bounds max packet size. Drops are strictly accounted for and logged—never silent.
- **Destination Resilience & Fan-out**: Forwards to single destinations or fan-out lists. Unreachable destinations or socket errors are logged and increment per-stream error counters without halting or panicking the relay.
- **Graceful Lifecycle Management**: `rer run` requires valid configuration before launch, installs signal handlers for `SIGINT` and `SIGTERM`, drains active queues on shutdown, and reports stream statistics upon exit with status 0.

### 2.4 TCP Relay & Framing Engine Subsystem (`RER-F-005`)

- **Four Transport Conversion Combinations**: Full configurable forwarding across UDP-to-UDP, UDP-to-TCP, TCP-to-UDP, and TCP-to-TCP stream topologies.
- **Explicit Framing Protocol**: Converts between continuous TCP byte streams and discrete datagrams using an explicit length-prefixed framing format:
  - Header: 4-byte big-endian unsigned 32-bit integer (`uint32`) indicating payload byte length `N`.
  - Body: Exactly `N` payload bytes.
  - Oversized frames exceeding `max_packet_size` are dropped before queuing and accounted under `drops_oversized`.
  - Transparent stream defragmentation handles chunked TCP reads.
- **TCP Connection Lifecycle & Resilience**:
  - Connect and reconnect with exponential backoff against destination outages at startup and during active streaming.
  - Sockets configure explicit connect timeouts, write timeouts, and read timeouts.
  - Unreachable destinations or connection drops increment `destination_errors` and `socket_errors` without panicking or halting the relay.
  - In single TCP destination streams, datagrams arriving during destination outages are buffered in bounded memory and delivered upon reconnection.
- **Slow Reader Backpressure**:
  - Memory usage is strictly bounded by `max_queue_size` and `max_packet_size`.
  - When slow TCP readers cause socket write stalls or write timeouts, backpressure events are tracked in `backpressure_events`.
  - Queue saturation drops are strictly accounted for under `drops_queue_full` and `dropped_packets` according to the configured drop policy.

### 2.5 Simulation & Verification Harness (`RER-F-004`)

- Deterministic traffic generator (`TrafficGenerator`) and test receiver (`TrafficReceiver`) verifying expected counts and SHA-256 payload hashes.
- Unprivileged simulation harness (`SimulationHarness`) testing all four transport combinations, impairments, and queue policies in CI.

### 2.6 CI and Quality Pipeline

- **Hosted Execution**: Builds entirely on standard GitHub Actions Linux runners without requiring local compilation or paid infrastructure.
- **Enforced Quality Gates**:
  - `cargo fmt --all --check`
  - `cargo check --all-targets --all-features --locked`
  - `cargo clippy --all-targets --all-features --locked -- -D warnings`
  - `cargo test --all-features --locked`
- **Cache Strategy**: Caching covers Cargo registry indexes, git database, and build target outputs, keyed on `cargo-${{ runner.os }}-${{ hashFiles('rust-toolchain*', 'Cargo.lock') }}`.

## 3. Planned Architecture (Roadmap Overview)

Future milestones (as detailed in [`docs/SPEC.md`](docs/SPEC.md) and [`ROADMAP.md`](ROADMAP.md)) will introduce the following subsystems:

1. **Logical Interfaces and Directional Streams (`RER-F-006`)**:
   Paired directional streams modeling command TX/response RX and uplink/downlink relationships with independent counters, backpressure, and routing policies.
2. **Management API and Diagnostics (`RER-F-007`, `RER-F-008`, `RER-F-009`)**:
   Non-shell local HTTP/JSON management endpoints, structured diagnostic event feeds, sequence tracking, and payload inspection.
3. **Multi-Hop Topology Emulation (`RER-F-010`, `RER-F-011`)**:
   Deterministic multi-relay topology emulation and capture replay verification.
4. **Observability and Packaging (`RER-F-012`–`RER-F-015`)**:
   Prometheus/OpenMetrics exporter, non-root Docker images, Helm charts, and standalone `.deb`/`.rpm` packaging.
