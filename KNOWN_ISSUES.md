# KNOWN_ISSUES.md — Known Issues and Current Limitations

This document tracks known limitations, pending features, and current operational constraints for RER (RER Engineering Relay).

## 1. Project Phase: Core Relay and Deployment Packaging (Milestones RER-F-004 & RER-F-015)

RER has completed Milestone RER-F-001 (repository foundation and CI), Milestone RER-F-002 (configuration model, validation CLI, and schema), Milestone RER-F-003 (basic UDP relay engine, bounded queues, drop policies, graceful shutdown, and tests), Milestone RER-F-004 (deterministic traffic generator, verification test receiver, loss/duplication/reorder reporting as JSON, and unprivileged simulation harness), and Milestone RER-F-015 (.deb, .rpm, and standalone binary packaging with systemd service units, safe defaults, and configuration preservation). TCP stream forwarding and management telemetry features are planned in subsequent milestones per [`ROADMAP.md`](ROADMAP.md).

## 2. Unimplemented Features (By Design for Current Milestone)

- **TCP Forwarding & Protocol Conversion (`RER-F-005`)**:
  TCP stream forwarding, reconnection logic, TCP/UDP framing conversions, and slow-reader backpressure are scheduled in milestone RER-F-005. The UDP relay engine (`RER-F-003`) is functional (`rer run`).
- **Distributed Multi-Hop Simulation & Correlation (`RER-F-010`)**:
  End-to-end multi-hop topology testing and distributed evidence correlation across multiple relay instances are scheduled in milestone RER-F-010. The initial traffic generator and single-relay simulation harness (`RER-F-004`) are functional (`rer test`).
- **Management API & Telemetry (`RER-F-007`, `RER-F-012`)**:
  Local management HTTP/JSON endpoints, runtime counters, health checks, and Prometheus metrics endpoints are not yet implemented.
- **Diagnostic Logging & Inspection (`RER-F-008`, `RER-F-009`)**:
  Structured packet diagnostics, sequence gap detection, and hex preview facilities are not yet implemented.
- **Container and Orchestration Artifacts (`RER-F-013`, `RER-F-014`, `RER-F-016`)**:
  Container images (`deploy/docker`), Helm charts (`deploy/helm`), and Docker Compose setups (`deploy/compose`) are scheduled in milestones RER-F-013, RER-F-014, and RER-F-016. OS packages (`.deb`, `.rpm`) and standalone binaries are complete (`packaging/`).

## 3. Tooling and CI Tracking

- **Configuration Schema CI Step**:
  JSON schema validation for all example configurations is enforced via automated integration tests (`crates/rer/tests/config_validation.rs`). Direct workflow integration in `.github/workflows/` remains pending owner integration due to agent boundaries.
- **Packaging and Multi-Architecture CI Workflows**:
  Package assembly and specification validation are enforced via automated integration tests (`crates/rer/tests/packaging_tests.rs`) and `packaging/package.sh`. Multi-architecture CI release jobs and automated container smoke test runs (`packaging/smoke-test.sh`) in `.github/workflows/` remain pending owner workflow integration due to agent path boundaries.
