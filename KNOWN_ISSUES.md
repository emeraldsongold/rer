# KNOWN_ISSUES.md — Known Issues and Current Limitations

This document tracks known limitations, pending features, and current operational constraints for RER (RER Engineering Relay).

## 1. Project Phase: Foundation (Milestone RER-F-001)

RER is currently at Milestone RER-F-001. The workspace scaffolding, build pipeline, repository governance, and CI quality gates are operational. Networking, configuration, and diagnostics features are planned in subsequent milestones per [`ROADMAP.md`](ROADMAP.md).

## 2. Unimplemented Features (By Design for Current Milestone)

- **Configuration Validation (`RER-F-002`)**:
  `rer validate` and YAML configuration file loading are not yet implemented. Executable currently reports package version only.
- **UDP and TCP Forwarding (`RER-F-003`, `RER-F-005`)**:
  Network socket handling, datagram forwarding, TCP stream proxying, backpressure handling, and conversion modes are not yet implemented.
- **Traffic Generator & Simulation Harness (`RER-F-004`, `RER-F-010`)**:
  Synthetic network simulation harness and end-to-end multi-hop topology testing are not yet implemented.
- **Management API & Telemetry (`RER-F-007`, `RER-F-012`)**:
  Local management HTTP/JSON endpoints, runtime counters, health checks, and Prometheus metrics endpoints are not yet implemented.
- **Diagnostic Logging & Inspection (`RER-F-008`, `RER-F-009`)**:
  Structured packet diagnostics, sequence gap detection, and hex preview facilities are not yet implemented.
- **Packaging and Deployment Artifacts (`RER-F-013`–`RER-F-015`)**:
  Container images (`deploy/docker`), Helm charts (`deploy/helm`), Docker Compose setups (`deploy/compose`), and OS packages (`.deb`, `.rpm`) are not yet created.

## 3. Tooling and CI Tracking

- **Dependency Advisory and License Checks**:
  Automated CI steps for dependency vulnerability scanning and license compliance (such as `cargo-deny` or `cargo-audit`) are not yet active in `.github/workflows/ci.yml`. Because agents cannot edit `.github/` files directly (ADR-0003), this workflow step is pending owner integration.
