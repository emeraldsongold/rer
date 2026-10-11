# KNOWN_ISSUES.md — Known Issues and Current Limitations

This document tracks known limitations, pending features, and current operational constraints for RER (RER Engineering Relay).

## 1. Project Phase: Foundation (Milestone RER-F-002)

RER has completed Milestone RER-F-001 (repository foundation and CI) and Milestone RER-F-002 (configuration model, validation CLI, and schema). Network socket forwarding, traffic generation, and telemetry features are planned in subsequent milestones per [`ROADMAP.md`](ROADMAP.md).

## 2. Unimplemented Features (By Design for Current Milestone)

- **UDP and TCP Forwarding (`RER-F-003`, `RER-F-005`)**:
  Network socket handling, datagram forwarding, TCP stream proxying, backpressure handling, and conversion modes are not yet implemented. Executable currently supports configuration validation (`rer validate`) and effective inspection (`rer inspect`).
- **Traffic Generator & Simulation Harness (`RER-F-004`, `RER-F-010`)**:
  Synthetic network simulation harness and end-to-end multi-hop topology testing are not yet implemented.
- **Management API & Telemetry (`RER-F-007`, `RER-F-012`)**:
  Local management HTTP/JSON endpoints, runtime counters, health checks, and Prometheus metrics endpoints are not yet implemented.
- **Diagnostic Logging & Inspection (`RER-F-008`, `RER-F-009`)**:
  Structured packet diagnostics, sequence gap detection, and hex preview facilities are not yet implemented.
- **Packaging and Deployment Artifacts (`RER-F-013`–`RER-F-015`)**:
  Container images (`deploy/docker`), Helm charts (`deploy/helm`), Docker Compose setups (`deploy/compose`), and OS packages (`.deb`, `.rpm`) are not yet created.

## 3. Tooling and CI Tracking

- **Configuration Schema CI Step**:
  JSON schema validation for all example configurations is enforced via automated integration tests (`crates/rer/tests/config_validation.rs`). Direct workflow integration in `.github/workflows/` remains pending owner integration due to agent boundaries.
