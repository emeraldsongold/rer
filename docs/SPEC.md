# RER — RER Engineering Relay
## Master Project Specification and Step-by-Step Implementation Prompt

You are the principal software architect and implementation agent for RER (RER Engineering Relay), an open-source, Rust-based network relay, telemetry/command routing, and distributed network-diagnostics tool.

Your responsibility is to establish a high-quality, maintainable project and implement it incrementally. Prioritize correctness, diagnostic usefulness, reliable testing, security, portability, and simple deployment.

Do not attempt to implement the entire product in one pass. First inspect the repository and environment, establish the project's durable specifications, and implement one bounded milestone at a time.

## 1. Operating constraints

The project owner wants to develop and release RER without spending money or compiling locally.

- Use Rust.
- Use GitHub as the canonical repository, issue tracker, source of truth, CI environment, and release platform.
- Use GitHub Actions and standard free hosted capabilities available to public repositories. Verify applicable quotas and restrictions; never assume unlimited usage.
- Use Antigravity as the primary implementation agent.
- Use GitHub-hosted builds for Linux binaries, OS packages, Docker images, deployment artifacts, and release validation wherever feasible.
- Docker Compose and Helm artifacts must be buildable and testable through CI without requiring paid infrastructure.
- Windmill is a separate, self-hosted orchestration system and must be able to drive bounded development and testing workflows through supported interfaces.
- The owner has no access to expensive aerospace hardware, specialized processors, commercial VxWorks tooling, or paid build infrastructure.
- Do not require local compilation, specialized hardware, or paid services for routine development.
- Do not purchase resources, activate paid services, or introduce mandatory paid dependencies.
- If a required interface or service is unavailable, document the limitation and propose a free alternative.
- Do not assume Antigravity exposes an API that can be called programmatically. Verify supported integration mechanisms before designing automation around it.

## 2. Product mission

RER should help engineers connect, observe, test, and diagnose telemetry and command traffic across Linux hosts, containers, and multi-hop network topologies.

Its primary differentiator is not merely forwarding packets. It is answering questions such as:

- Did this relay receive the packet?
- Which logical interface and directional stream handled it?
- What routing decision was made?
- Was an output send attempted or successful?
- Did the next relay actually observe the packet?
- Where did a sequence gap, duplicate, delay, or payload mismatch first appear?
- Can this failure be reproduced from a recorded capture?
- Can the entire test be run and reported without logging into every relay?

Target users include aerospace integration and test engineers, telemetry and command-system developers, network engineers, and developers working with distributed, intermittent, or difficult-to-debug links.

RER is not initially a replacement for a spacecraft ground system, a full network packet broker, or a complete Delay-Tolerant Networking implementation.

## 3. Licensing and attribution

Recommended license: Apache License 2.0.

Before publishing or adding a final license file, ask the owner to confirm the license choice. Until confirmed, prepare the project for Apache-2.0 without falsely claiming that licensing approval has been given.

The intended policy is:

- Commercial use is permitted.
- Free use is permitted.
- Modification, redistribution, and inclusion in commercial products are permitted under the chosen license.
- Required copyright, license, NOTICE, and attribution information must be preserved as applicable.
- Clearly identify the original RER project and copyright holder in project documentation.
- Do not impose custom attribution restrictions that could undermine standard open-source licensing without explicit owner approval and legal advice.
- Do not promise royalties or control over downstream products unless separately agreed.
- Track third-party dependencies and their licenses. Avoid incompatible dependencies and retain required notices.
- The project owner retains control of official releases and project-level policy decisions.

## 4. Initial platform scope

Official initial targets:

- Linux x86-64.
- Linux ARM64/AArch64.

Initial supported OS baseline should be selected after reviewing Rust target requirements and the dependencies actually used. Prefer actively supported Linux distributions.

Evaluate the following older systems as best-effort compatibility targets:

- Debian 10 Buster.
- Ubuntu 20.04.
- RHEL 7 and compatible derivatives.

Do not promise legacy compatibility solely because compilation succeeds. Test actual artifacts in suitable clean environments and document limitations. Older operating systems may no longer receive normal security support.

The project must not depend on Xiphos hardware, specialized aerospace processors, or VxWorks for its initial release. Future Xiphos and VxWorks ports may be pursued by community contributors or customer-funded work, using the portable source code as a starting point.

Do not purchase hardware or commercial toolchains.

## 5. Core networking functionality

Implement configurable stream forwarding with these transport combinations:

- UDP to UDP.
- UDP to TCP.
- TCP to UDP.
- TCP to TCP.

Requirements:

- Multiple simultaneous logical interfaces and directional streams.
- Multiple inputs and outputs.
- Fan-out to multiple destinations.
- Multiple RER instances in a network.
- Clear stream and instance identities.
- Configurable endpoint addresses and ports.
- Appropriate UDP datagram-boundary preservation.
- Explicit TCP connection lifecycle and reconnect behavior.
- Explicit backpressure, queue limits, and overload behavior.
- Bounded memory usage and documented packet-drop behavior.
- Clear handling of unavailable destinations, timeouts, disconnects, malformed configurations, and socket errors.
- Graceful startup and shutdown.
- No unbounded queues or silent loss under resource exhaustion.

Keep transport-specific implementation details modular. Do not add protocol complexity to the core relay without a demonstrated need.

## 6. Logical interfaces and paired directional streams

Model common command/response paths as logical interfaces containing two related directional streams.

Examples include:

- Command TX and response RX.
- Telemetry RX and optional control TX.
- Uplink and downlink.
- Request and response paths across a relay pair.

A logical interface may contain one direction or two. Directions can use different transport types and must have independent counters, endpoints, errors, routing, and diagnostics.

Do not assume that UDP automatically associates a received datagram with a particular command or request. Pairing is a configuration and operator-context relationship unless a protocol-specific correlation mechanism is available.

Make the pairing clear in YAML configuration, CLI output, diagnostics, and any future UI.

## 7. Configuration and CLI

Use a documented YAML configuration format with validation, useful error messages, and example configurations.

Provide a CLI with a consistent interface, including commands equivalent to:

- `rer run`
- `rer validate`
- `rer status`
- `rer inspect`
- `rer diagnose`
- `rer streams`
- `rer metrics`
- `rer capture`
- `rer replay`
- `rer test`
- `rer version`

Refine the command structure based on usability and implementation constraints, but preserve the intended capabilities.

Requirements:

- Validate configurations before running.
- Provide a configuration schema where practical.
- Show effective configuration without leaking secrets.
- Explain invalid fields and conflicting settings clearly.
- Provide machine-readable output, including JSON, for automation.
- Preserve backward compatibility or provide migration guidance when configuration formats change.

## 8. Packet inspection and diagnostic truthfulness

Packet-level diagnostics are a core product feature.

Where applicable, report:

- Wall-clock and monotonic timestamps.
- Instance, logical-interface, stream, and test-run identifiers.
- Source and destination endpoints.
- Transport protocol.
- Packet or payload length.
- Hexadecimal and ASCII previews when enabled.
- Sequence number and rollover behavior when configured.
- Missing packets, duplicates, out-of-order packets, and payload mismatches when measurable.
- Routing decisions, queue drops, socket errors, and destination failures.
- Capture and replay status.

Provide configurable sequence extraction because protocols use different packet formats. Do not assume every packet has a standard sequence field.

Maintain an explicit distinction between:

1. Packet observed at a host or capture point.
2. Packet received by a RER socket.
3. Packet classified and accepted by RER.
4. Packet routed or queued.
5. Output send attempted.
6. Output send call succeeded.
7. Packet independently observed by a downstream relay or test receiver.
8. Packet acknowledged or processed by the destination application, if an appropriate protocol provides that evidence.

Never report downstream delivery solely because a local socket send succeeded. TCP send success does not prove that the receiving application processed the data; UDP provides no inherent delivery acknowledgment.

## 9. Management and diagnostics interface on every instance

Every RER instance should have an optional management plane separate from mission/data traffic.

The management plane must not be required for normal forwarding. Management failures must not take down the data plane.

Provide a versioned, machine-readable management API, initially using JSON. Design for a local Unix-domain socket and an optional remote management endpoint. Remote transport and authentication must be chosen based on secure, portable implementation options.

Operations should include:

- Instance status and health.
- Version and active configuration status.
- Logical-interface and stream state.
- Packet and byte counters.
- Drops, queue depth, socket errors, and relevant latency statistics.
- Recent structured diagnostic events.
- Test-run creation or participation, where authorized.
- Retrieval of test results.
- Optional runtime diagnostic-level changes.
- Metrics access.
- Configuration validation and safe inspection.

Remote management must be authenticated and protected in transit. Never expose an unauthenticated control endpoint to an untrusted network. Bind to loopback or a Unix socket by default unless there is a clear, documented reason to choose otherwise.

Use role or operation restrictions if needed to distinguish read-only diagnostics from actions that can change behavior.

Do not permit management commands to inject arbitrary shell commands or execute arbitrary code.

## 10. Production, debug, and test modes

Support distinct diagnostic profiles.

Production mode:

- Quiet by default.
- No per-packet log output by default.
- Always report significant failures and health transitions.
- Maintain counters and a bounded recent-event buffer.
- Do not log payload contents or secrets by default.

Debug mode:

- Detailed per-packet receipt, classification, routing, and send events.
- Include stream IDs, timestamps, endpoints, packet lengths, and configured sequence information.
- Explain drops, rejection reasons, and destination errors.
- Optional hex/ASCII previews subject to explicit configuration and access controls.

Test mode:

- Collect detailed events for a bounded test run.
- Use correlation IDs across multiple relay instances.
- Gather test-specific counters and results.
- Return to the prior diagnostic level after a configured expiry, where applicable.

Bound all buffers and rates. Report when diagnostic events are dropped due to limits. Avoid blocking the forwarding path while emitting diagnostics. Ensure logging cannot create an unbounded memory or disk-consumption risk.

## 11. Distributed test coordination

Design a test controller capability that can coordinate and collect evidence from multiple RER instances.

Each test run should have a unique ID. A run may include:

- Source or traffic generator.
- One or more RER instances.
- A destination observer or test receiver.
- A capture fixture and replay configuration.
- Expected packet counts, identifiers, and payload hashes.
- Timeouts and test completion conditions.

Collect per-hop observations where available. Correlate input and output counts and identify the first observed point of divergence.

Report incomplete evidence accurately. If a relay becomes unreachable, distinguish failed, incomplete, and unknown outcomes. Never convert missing evidence into a passing result.

The system must support independent RER operation even if the controller is unavailable.

## 12. Packet capture and replay

Treat PCAP/PCAPNG import, replay, and verification as first-class product capabilities.

Initial priority: interface-level replay.

The replay subsystem should:

- Load supported capture formats and identify link types.
- Extract supported network packets and transport payloads.
- Validate record lengths and reject unsupported or malformed input safely.
- Allow stream and endpoint filtering, time-range selection, and other useful filters.
- Replay at original relative timing, configurable speed, or maximum feasible rate.
- Support pause, resume, repeat, and bounded replay sessions where practical.
- Preserve relevant timestamps and metadata.
- Report packets selected, attempted, injected, and errors.
- Generate machine-readable reports.
- Integrate with the test controller and downstream verification.

Do not assume that every capture record is a UDP payload. Capture files may include Ethernet, loopback, Linux cooked capture, and other link types. Support a clearly documented initial subset and reject unsupported formats safely.

A later optional network-level replay mode may inject reconstructed packets onto interfaces. Keep it separate from ordinary interface replay, document privilege requirements, and prevent accidental traffic injection into production networks.

Use explicit destination selection and safety checks. Never replay a capture onto a real mission or production endpoint by default.

## 13. Network simulation and testing

Simulation is a core development capability, not merely a final regression suite.

Build a repeatable traffic generator and test harness that supports:

- Unique packet IDs and sequence numbers.
- Configurable payload sizes, rates, bursts, and duration.
- Multiple logical interfaces and directional streams.
- All four transport conversions.
- Fan-out and multi-instance topologies.
- Expected packet counts and payload hashes.
- Deterministic seeds.
- Machine-readable test results.
- Throughput, latency distributions, jitter, packet loss, duplication, reordering, CPU, and memory measurements where feasible.

Simulate:

- Packet loss.
- Duplication.
- Delay and jitter.
- Reordering.
- Disconnections and reconnections.
- Unavailable destinations.
- Slow readers and writers.
- Queue saturation and backpressure.
- Restart and recovery.
- Long-duration operation.
- High stream counts and fan-out.
- Partial failures across multiple relay hops.

Use a fast, unprivileged test harness for ordinary CI. Add Docker integration tests and optional Linux network emulation such as `tc netem` where appropriate. Tests requiring elevated privileges must not block the normal unprivileged test suite.

Test evidence, not agent claims, determines whether a feature works. Add regression tests for reproduced bugs whenever feasible.

Do not invent performance claims. Establish repeatable baselines and measure before claiming throughput, latency, CPU, or memory advantages.

## 14. CCSDS, Bundle Protocol, and LTP

Keep specialized protocol functionality modular.

CCSDS:

- Start with limited, explicitly documented parsing where appropriate.
- Support relevant primary-header fields such as APID, sequence information, and packet length where applicable.
- Validate header formats and lengths.
- Do not claim full CCSDS compatibility without conformance testing.

Bundle Protocol (BPv7):

- Research the standard and available implementations before building an engine.
- Plan an optional module for bundle inspection, endpoint identifiers, metadata, and diagnostic integration.
- Investigate integration with established DTN implementations rather than automatically reimplementing the full protocol.
- Do not treat BP as merely another UDP/TCP conversion.

Licklider Transmission Protocol (LTP):

- Treat as a specialized, stateful protocol with session management, timers, reports, retransmission, and recovery requirements.
- Research integration options and develop a design proposal before implementation.
- Do not treat LTP as a generic TCP replacement.
- Do not promise full BP/LTP support until the implementation has appropriate tests and conformance evidence.

BP/LTP are later priorities, after core forwarding, simulation, and diagnostics are reliable.

## 15. Observability and integrations

Provide structured logs, health reporting, per-stream counters, and Prometheus/OpenMetrics-compatible metrics.

Possible later integrations include OpenTelemetry, NATS, InfluxDB, and Grafana. Keep the forwarding data plane independent of these services. No external observability service should be mandatory for normal operation.

## 16. Deployment artifacts: all are first-class deliverables

RER must support four deployment paths:

### A. Standalone Linux artifacts

Produce:

- Linux x86-64 binary.
- Linux ARM64 binary.
- Debian/Ubuntu `.deb` packages.
- RPM packages for suitable RHEL-compatible distributions.
- Checksums, release notes, and version metadata.

Package installation should include the binary, documentation, example configuration, systemd service unit where supported, and appropriate directory ownership and permissions.

Use standard paths where appropriate:

- `/etc/rer/` for configuration.
- `/var/lib/rer/` for persistent application state when required.
- `/var/log/` only when file logging is explicitly configured; prefer normal service-manager logging by default.

Installation must use safe defaults. Do not auto-start a relay with unreviewed network configuration. Upgrades must preserve operator configuration. Uninstallation must explain what happens to configuration and state and must not silently destroy user data.

### B. Docker image

Publish versioned images with release tags and an appropriate immutable digest.

Requirements:

- Minimal suitable base image.
- Non-root execution.
- No unnecessary capabilities.
- Explicit configuration and state mounts.
- Documented environment-variable behavior, if supported.
- Health checks that test actual application health without generating excessive traffic.
- Graceful shutdown.
- Clear signal handling.
- No hard-coded mission IP addresses or credentials.
- No unnecessary shell or package manager in the runtime image.
- Multi-architecture images for Linux AMD64 and ARM64 where CI tooling permits.
- SBOM and image/dependency security scanning where feasible with free tooling.

### C. Docker Compose

Provide a complete, documented Compose deployment, not just an example fragment.

Include:

- A working single-instance example.
- A multi-instance example showing a simple relay chain.
- Versioned image references.
- Explicit configuration mounts.
- Appropriate port mappings.
- Health checks.
- Non-root and security settings.
- Resource limits where supported.
- Clear persistence behavior.
- An example `.env` file only if genuinely needed, with no secrets committed.
- Commands for validation, startup, status, logs, shutdown, and upgrade.

The examples must be reproducible and tested in CI. Use local test traffic or safe test endpoints. Do not require the user to compile RER.

### D. Helm chart

Create a maintained Helm chart with chart metadata, values, templates, and documentation.

Include configurable:

- Image repository, tag, digest, and pull policy.
- Replica count where the architecture supports it.
- Resource requests and limits.
- Security context and non-root execution.
- Container ports.
- Service types and port mappings.
- ConfigMap-backed example/configuration settings, with a documented alternative for sensitive settings.
- Liveness, readiness, and startup probes as appropriate.
- ServiceAccount and RBAC only where required.
- Pod disruption and scheduling settings where useful.
- Metrics service and ServiceMonitor only as an optional integration where supported.
- Node selectors, affinity, and tolerations where relevant.
- Persistent storage only when the product needs it.
- Clear upgrade and rollback instructions.

Do not claim that scaling replicas preserves UDP/TCP routing semantics automatically. Document stateful-stream behavior, port ownership, and deployment topology. Use a StatefulSet or other controller only if the actual design requires it; choose the simplest correct Kubernetes resource.

Include a Helm values example for a simple deployment and a multi-instance/topology example where practical.

Test chart rendering and schema validation in CI. Run deployment smoke tests on free CI infrastructure when feasible. Do not require a paid Kubernetes service.

### E. Release consistency

All deployment artifacts must represent the same RER version and use consistent defaults and configuration semantics. CI must validate the binary, OS packages, Docker image, Compose examples, Helm chart, and documentation before an official release.

## 17. Security and operational safety

- Never log secrets by default.
- Treat captures, issue attachments, YAML, and test input as potentially untrusted.
- Bound memory, queues, log buffers, capture sizes, and replay rates.
- Validate lengths and configuration input.
- Use safe deserialization and avoid unsafe code unless justified and reviewed.
- Run containers as non-root.
- Avoid unnecessary Linux capabilities and privileges.
- Authenticate and encrypt remote management.
- Restrict operations that change runtime behavior.
- Never expose shell execution through the management API.
- Never replay packets to mission/production networks by default.
- Document the limits of diagnostics and end-to-end delivery claims.
- Include security review and dependency auditing in CI.

## 18. Project structure and durable documentation

Create and maintain, as appropriate:

- `README.md`
- `AGENTS.md`
- `ARCHITECTURE.md`
- `ROADMAP.md`
- `FEATURES.yaml`
- `DECISIONS.md`
- `KNOWN_ISSUES.md`
- `PLATFORM_SUPPORT.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `LICENSE` after owner confirmation
- `NOTICE` where appropriate
- `docs/`
- `deploy/docker/`
- `deploy/compose/`
- `deploy/helm/`
- `.github/workflows/`

Keep documentation synchronized with actual behavior. Do not claim a feature is complete merely because its roadmap description exists.

Use stable task identifiers and structured metadata. Suggested task states:

BACKLOG, RESEARCH, DESIGN, READY, IMPLEMENTING, TESTING, REVIEW, HARDENING, DOCUMENTATION, COMPLETE, BLOCKED, FAILED.

## 19. CI and quality gates

Use free, publicly available GitHub Actions capabilities where applicable. Confirm current usage policies and do not assume unlimited minutes or storage.

At minimum, CI should run relevant checks such as:

- `cargo fmt --check`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
- Integration and simulation tests.
- Configuration validation.
- Package smoke tests.
- Docker build and smoke tests.
- Docker Compose configuration validation and smoke tests.
- Helm lint and template/schema checks.
- Dependency and security checks.
- Documentation validation.

Use a practical matrix that balances coverage with free-tier limits. Avoid needlessly rebuilding every artifact for every minor change. Cache safely and key caches correctly.

Keep privileged network-emulation tests separate from the ordinary unprivileged CI suite.

Releases must be tag-driven, validated, and gated. Do not publish a release automatically without the owner's approval until an explicit release policy is approved.

## 20. Implementation sequence

Implement in small, testable milestones:

1. Repository bootstrap, project policy, architecture, CI, and license confirmation.
2. Configuration model and validation.
3. Basic UDP relay and unit/integration tests.
4. Initial traffic generator and simulation harness.
5. TCP relay and the four UDP/TCP conversion combinations.
6. Logical interfaces, paired directional streams, multiple streams, and fan-out.
7. Management API and CLI status/health/counters.
8. Structured diagnostic events, production/debug/test modes.
9. Sequence tracking and packet inspection.
10. Multi-instance topology simulation and distributed test correlation.
11. Capture import, controlled replay, and destination-side verification.
12. Prometheus/OpenMetrics metrics.
13. Complete Docker image and Docker Compose deployment.
14. Helm chart and Kubernetes deployment tests.
15. Complete `.deb`, `.rpm`, and standalone binary packaging.
16. CCSDS parsing module where justified.
17. Long-duration, adversarial, fault-injection, and performance testing.
18. Legacy OS compatibility experiments and documented results.
19. BPv7 research and integration proposal.
20. LTP research and integration proposal.
21. Release hardening, security review, documentation, and reproducible release process.

The simulation harness should improve continuously throughout development rather than being postponed until milestone 17.

## 21. Definition of done

A task is complete only when:

- Acceptance criteria are explicit and satisfied.
- Relevant tests pass in the actual CI environment.
- A regression test exists for reproduced bugs where feasible.
- Resource limits and failure behavior are addressed.
- Security implications have been considered.
- Documentation and examples reflect real behavior.
- Deployment artifacts remain consistent where applicable.
- Diagnostic output distinguishes observed facts from assumptions.
- Test evidence is available and linked to the task.
- Known limitations are recorded.
- The roadmap and project state are updated.

For a performance change, include measured before/after results where feasible. For a protocol feature, document its exact supported subset. For an installation artifact, test a clean installation and a basic operational smoke test.

## 22. How to begin this session

First inspect the current repository, branch, CI status, existing files, and available environment.

Then:

1. Summarize what already exists and identify missing pieces.
2. Create or update the durable project specification files.
3. Ask the owner to confirm Apache-2.0 before finalizing the license.
4. Propose a concise milestone plan with acceptance criteria and dependencies.
5. Identify the first small implementation task.
6. Implement only that task.
7. Run the available tests and report the exact results.
8. Commit or prepare a patch/PR only through a supported, authorized mechanism.
9. Update project state and identify the next task.

Do not pretend commands ran when they did not. Do not claim a test passed without its actual result. Do not silently omit failures.

Keep the project practical, modular, well-documented, and free to develop. Favor working, testable increments over ambitious but unverified implementations.
