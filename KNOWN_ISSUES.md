# KNOWN_ISSUES.md — Known Issues and Current Limitations

This document tracks known limitations, pending features, and current operational constraints for RER (RER Engineering Relay).

## 1. Project Phase: Diagnostics & Deployment (Milestones RER-F-007, RER-F-018)

RER has completed Milestone RER-F-001 (repository foundation and CI), Milestone RER-F-002 (configuration model, validation CLI, and schema), Milestone RER-F-003 (basic UDP relay engine, bounded queues, drop policies, graceful shutdown, and tests), Milestone RER-F-004 (deterministic traffic generator, verification test receiver, loss/duplication/reorder reporting as JSON, and unprivileged simulation harness), Milestone RER-F-005 (TCP stream forwarding, four UDP/TCP transport combinations, explicit framing, reconnect with backoff, destination outage resilience, and slow-reader backpressure), Milestone RER-F-006 (logical interfaces with one or two directional streams in YAML and CLI `rer streams` output, independent directional counters, endpoints, errors and routing, tested fan-out resilience with destination error isolation, pairing documented as configuration context, and multiple simultaneous interfaces running in a single instance), Milestone RER-F-007 (versioned JSON management API approved by owner, local Unix domain socket default, authenticated/encrypted remote management, data plane fault isolation from management failures, `rer status`, `rer streams` and `rer metrics` reporting health, version, stream state and counters with JSON output, separation of read-only operations from behavior-changing ones, and prohibition of arbitrary shell commands or code execution), Milestone RER-F-013 (Docker image and Docker Compose deployment), Milestone RER-F-014 (Helm chart and Kubernetes deployment tests), Milestone RER-F-015 (.deb, .rpm and standalone binary packaging), and Milestone RER-F-018 (legacy OS compatibility experiments and documented results in PLATFORM_SUPPORT.md).

## 2. Unimplemented Features (By Design for Current Milestone)
- **Distributed Multi-Hop Simulation & Correlation (`RER-F-010`)**:
  End-to-end multi-hop topology testing and distributed evidence correlation across multiple relay instances are scheduled in milestone RER-F-010. The initial traffic generator and single-relay simulation harness (`RER-F-004`) are functional (`rer test`).
- **Diagnostic Logging & Inspection (`RER-F-008`, `RER-F-009`)**:
  All three operational diagnostic modes—production, debug, and test mode—are implemented (RER-F-026, RER-F-027, RER-F-028):
  - **Production mode**: Quiet by default; no per-packet forwarding log output; maintains a bounded recent-event buffer; records significant failures, queue drops, and health transitions.
  - **Debug mode**: Emits detailed per-packet lifecycle events (received, accepted, routed-or-queued, send-attempted, and send-succeeded) with stream IDs, timestamps, endpoints, and packet lengths.
  - **Test mode**: Executes a bounded diagnostic run with documented maximums (up to 86,400 seconds duration and up to 1,000,000 events); stamps every event with the configured correlation ID; ends upon reaching expiry or event limits, records the termination reason, and automatically returns the instance to its prior diagnostic level.
  - **Management API diagnostics query**: Read-only `events` / `recent_events` operation exposes bounded recent diagnostic events (newest last), dropped-event count, current mode, and expiry.
  Runtime mode modification is out of scope (mode and bounds are established via configuration). Sequence gap detection and hex preview facilities remain scheduled in roadmap milestone RER-F-009.

## 3. Tooling and CI Tracking

- **Configuration Schema CI Step**:
  JSON schema validation for all example configurations is enforced via automated integration tests (`crates/rer/tests/config_validation.rs`). Direct workflow integration in `.github/workflows/` remains pending owner integration due to agent boundaries.
- **Docker Multi-Arch & SBOM CI Step**:
  Docker multi-arch image builds, healthchecks, Compose configurations, and security scanning tooling are verified via automated integration tests (`crates/rer/tests/docker_compose_tests.rs`). Direct workflow integration in `.github/workflows/` remains pending owner integration due to agent boundaries.
- **Packaging and Multi-Architecture CI Workflows**:
  Package assembly and specification validation are enforced via automated integration tests (`crates/rer/tests/packaging_tests.rs`) and `packaging/package.sh`. Multi-architecture CI release jobs and automated container smoke test runs (`packaging/smoke-test.sh`) in `.github/workflows/` remain pending owner workflow integration due to agent path boundaries.
- **Helm Chart and Kubernetes Deployment Tests (`RER-F-014`)**:
  Helm chart packaging (`deploy/helm/rer`), values schema validation, security context hardening, and template rendering are verified via automated integration tests (`crates/rer/tests/helm_tests.rs`) and `deploy/helm/smoke-test.sh`. Cluster deployment smoke tests require a running Kubernetes cluster (such as kind on GitHub-hosted runners); in environments without container/kernel cluster capabilities, deployment smoke tests fall back to chart linting, schema validation, and template verification as documented.
- **Legacy OS Compatibility Evaluation (`RER-F-018`)**:
  Evaluation of packaged artifacts across legacy OS baselines (Debian 10 Buster, Ubuntu 20.04 LTS, and RHEL 7 / CentOS 7) is codified via `packaging/legacy-compat-test.sh` and integration tests (`crates/rer/tests/legacy_compat_tests.rs`). Because container runtime availability varies across execution environments, tests automatically detect container daemon capabilities and verify static ELF ABI constraints, documenting glibc incompatibility on legacy systems and confirming that compilation alone is never claimed as support.

