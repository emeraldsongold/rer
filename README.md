# RER — RER Engineering Relay

RER (RER Engineering Relay) is an open-source, Rust-based network relay, telemetry/command routing, and distributed network diagnostics tool. It is designed to help engineers connect, observe, test, and diagnose telemetry and command traffic across Linux hosts, containers, and multi-hop network topologies.

## Current Status

RER is in its initial foundation phase (**Milestone RER-F-001**). The Cargo workspace, build tooling, repository policies, continuous integration gates, and durable project documentation are established.

Network forwarding capabilities (UDP/TCP relays, paired streams, packet inspection, management API, and simulation harness) are defined in [`docs/SPEC.md`](docs/SPEC.md) and tracked in [`ROADMAP.md`](ROADMAP.md). They are scheduled for implementation in upcoming milestones.

## Documentation Index

- [`ARCHITECTURE.md`](ARCHITECTURE.md): Architectural design, crate layout, and runtime principles.
- [`AGENTS.md`](AGENTS.md): Operational boundaries and guidelines for implementation agents.
- [`DECISIONS.md`](DECISIONS.md): Architectural Decision Records (ADRs), including license confirmation.
- [`KNOWN_ISSUES.md`](KNOWN_ISSUES.md): Current limitations, unimplemented features, and tracking notes.
- [`PLATFORM_SUPPORT.md`](PLATFORM_SUPPORT.md): Target platforms, supported architectures, and compatibility tiers.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): Contribution guidelines, code standards, and verification workflow.
- [`SECURITY.md`](SECURITY.md): Security policy, vulnerability reporting, and design boundaries.
- [`CHANGELOG.md`](CHANGELOG.md): History of changes and milestone completions.
- [`ROADMAP.md`](ROADMAP.md): Sequenced implementation milestones derived from [`FEATURES.yaml`](FEATURES.yaml).
- [`docs/SPEC.md`](docs/SPEC.md): Master technical specification.

## Building and Testing

RER requires a stable Rust toolchain (managed via [`rust-toolchain.toml`](rust-toolchain.toml)).

```bash
# Check formatting
cargo fmt --all --check

# Check compilation across all targets and features
cargo check --all-targets --all-features --locked

# Run linter
cargo clippy --all-targets --all-features --locked -- -D warnings

# Run tests
cargo test --all-features --locked

# Build workspace
cargo build --locked
```

No local compilation is required for issue tracking or reviews; all builds and checks run on GitHub Actions hosted Linux runners.

## License

This project is licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details.
