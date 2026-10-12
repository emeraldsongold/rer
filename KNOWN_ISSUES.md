# KNOWN_ISSUES.md — Known Issues and Current Limitations

This document tracks known limitations, pending features, and current operational constraints for RER (RER Engineering Relay).

## 1. Project Phase: Core Relay (Milestone RER-F-005)

RER has completed Milestone RER-F-001 (repository foundation and CI), Milestone RER-F-002 (configuration model, validation CLI, and schema), Milestone RER-F-003 (basic UDP relay engine, bounded queues, drop policies, graceful shutdown, and tests), Milestone RER-F-004 (deterministic traffic generator, verification test receiver, loss/duplication/reorder reporting as JSON, and unprivileged simulation harness), and Milestone RER-F-005 (TCP stream forwarding, four UDP/TCP transport combinations, explicit framing, reconnect with backoff, destination outage resilience, and slow-reader backpressure).

## 2. Unimplemented Features (By Design for Current Milestone)
- **Distributed Multi-Hop Simulation & Correlation (`RER-F-010`)**:
  End-to-end multi-hop topology testing and distributed evidence correlation across multiple relay instances are scheduled in milestone RER-F-010. The initial traffic generator and single-relay simulation harness (`RER-F-004`) are functional (`rer test`).
- **Management API & Telemetry (`RER-F-007`, `RER-F-012`)**:
  Local management HTTP/JSON endpoints, runtime counters, health checks, and Prometheus metrics endpoints are not yet implemented.
- **Diagnostic Logging & Inspection (`RER-F-008`, `RER-F-009`)**:
  Structured packet diagnostics, sequence gap detection, and hex preview facilities are not yet implemented.
- **Packaging and Deployment Artifacts (`RER-F-014`–`RER-F-015`)**:
  Helm charts (`deploy/helm`, milestone RER-F-014) and OS packages (`.deb`, `.rpm`, milestone RER-F-015) are scheduled in subsequent milestones. Container images (`deploy/docker`) and Docker Compose deployments (`deploy/compose`) are implemented in Milestone RER-F-013.

## 3. Tooling and CI Tracking

- **Configuration Schema CI Step**:
  JSON schema validation for all example configurations is enforced via automated integration tests (`crates/rer/tests/config_validation.rs`). Direct workflow integration in `.github/workflows/` remains pending owner integration due to agent boundaries.
- **Docker Multi-Arch & SBOM CI Step**:
  Docker multi-arch image builds, healthchecks, Compose configurations, and security scanning tooling are verified via automated integration tests (`crates/rer/tests/docker_compose_tests.rs`). Direct workflow integration in `.github/workflows/` remains pending owner integration due to agent boundaries.
