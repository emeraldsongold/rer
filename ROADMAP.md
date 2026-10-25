<!-- Generated from FEATURES.yaml by rer-wm-pipeline (scripts/render_roadmap.py).
     Do not edit by hand: change FEATURES.yaml and re-render. -->

# RER Roadmap

Status, dependencies and autonomy controls for each roadmap item. Acceptance
criteria live in `FEATURES.yaml`; `§` references point into `docs/SPEC.md`.

## Milestones

| # | ID | Title | Status | Type | Risk | Autonomy | Depends on | Spec |
|---|----|-------|--------|------|------|----------|------------|------|
| 1 | RER-F-001 | Repository bootstrap, project policy, architecture, CI and license confirmation | BACKLOG | infra | low | ready-auto | — | §1, §3, §18, §19, §22 |
| 2 | RER-F-002 | Configuration model and validation | BACKLOG | feature | medium | ready-auto | RER-F-001 | §7, §17 |
| 3 | RER-F-003 | Basic UDP relay with unit and integration tests | BACKLOG | feature | medium | ready-auto | RER-F-002 | §5, §17 |
| 4 | RER-F-004 | Initial traffic generator and simulation harness | BACKLOG | test | medium | ready-auto | RER-F-003 | §13 |
| 5 | RER-F-005 | TCP relay and the four UDP/TCP conversion combinations | BACKLOG | feature | medium | ready-auto | RER-F-003, RER-F-004 | §5, §13 |
| 6 | RER-F-006 | Logical interfaces, paired directional streams, multiple streams and fan-out | BACKLOG | feature | medium | ready-auto | RER-F-005 | §5, §6 |
| 7 | RER-F-007 | Management API and CLI status, health and counters | BACKLOG | feature | high | needs-design-approval | RER-F-002, RER-F-003 | §7, §9, §17 |
| 8 | RER-F-008 | Structured diagnostic events and production, debug and test modes | BACKLOG | feature | medium | deferred | RER-F-007 | §8, §10 |
| 9 | RER-F-009 | Sequence tracking and packet inspection | BACKLOG | feature | medium | ready-auto | RER-F-027 | §8 |
| 10 | RER-F-010 | Multi-instance topology simulation and distributed test correlation | BACKLOG | test | medium | ready-auto | RER-F-004, RER-F-006, RER-F-007, RER-F-028 | §11, §13 |
| 11 | RER-F-011 | Capture import, controlled replay and destination-side verification | BACKLOG | feature | high | needs-design-approval | RER-F-004, RER-F-028 | §12, §17 |
| 12 | RER-F-012 | Prometheus/OpenMetrics metrics | BACKLOG | feature | medium | ready-auto | RER-F-007 | §15 |
| 13 | RER-F-013 | Docker image and Docker Compose deployment | BACKLOG | packaging | medium | ready-auto | RER-F-003 | §16, §17 |
| 14 | RER-F-014 | Helm chart and Kubernetes deployment tests | BACKLOG | packaging | medium | ready-auto | RER-F-013 | §16 |
| 15 | RER-F-015 | .deb, .rpm and standalone binary packaging | BACKLOG | packaging | medium | ready-auto | RER-F-003 | §4, §16 |
| 16 | RER-F-016 | CCSDS parsing module where justified | BACKLOG | feature | medium | investigate-only | RER-F-009 | §14 |
| 17 | RER-F-017 | Long-duration, adversarial, fault-injection and performance testing | BACKLOG | performance | medium | ready-auto | RER-F-010 | §13, §17, §21 |
| 18 | RER-F-018 | Legacy OS compatibility experiments and documented results | BACKLOG | test | low | ready-auto | RER-F-015 | §4 |
| 19 | RER-F-019 | BPv7 research and integration proposal | BACKLOG | research | medium | investigate-only | RER-F-006, RER-F-028, RER-F-010 | §14 |
| 20 | RER-F-020 | LTP research and integration proposal | BACKLOG | research | medium | investigate-only | RER-F-006, RER-F-028, RER-F-010 | §14 |
| 21 | RER-F-021 | Release hardening, security review, documentation and reproducible release process | BACKLOG | release | high | no-auto | RER-F-012, RER-F-013, RER-F-014, RER-F-015, RER-F-016, RER-F-017, RER-F-018, RER-F-023, RER-F-024 | §16, §17, §19, §21 |
| 22 | RER-F-022 | Strict validation of IP addresses, hostnames and ports in endpoint configuration | BACKLOG | feature | low | ready-auto | RER-F-002 | §5, §7, §17 |
| 23 | RER-F-023 | IPv6 support for relay endpoints | BACKLOG | feature | medium | ready-auto | RER-F-005, RER-F-022 | §5, §13, §17 |
| 24 | RER-F-024 | Scoped IPv6 addresses with zone identifiers | BACKLOG | feature | medium | ready-auto | RER-F-023 | §5, §17 |
| 25 | RER-F-025 | Traffic receiver counts unique packets, so duplicated packets no longer hide the last originals | BACKLOG | test | low | ready-auto | RER-F-004 | §13 |
| 26 | RER-F-026 | Diagnostic event model with a bounded, non-blocking event buffer | BACKLOG | feature | medium | ready-auto | RER-F-007 | §8, §10 |
| 27 | RER-F-027 | Production and debug modes emit diagnostic events from the forwarding path | BACKLOG | feature | medium | ready-auto | RER-F-026 | §8, §10 |
| 28 | RER-F-028 | Test mode with correlation IDs, and recent events through the management API | BACKLOG | feature | medium | ready-auto | RER-F-027 | §9, §10 |
| 29 | RER-F-029 | Document CLI commands and options in configuration guide | BACKLOG | docs | low | needs-impl-approval | RER-F-009 | §7 |
| 30 | RER-F-030 | Implement rer diagnose CLI command for management diagnostic events | BACKLOG | feature | low | needs-impl-approval | RER-F-028 | §7, §8, §9, §10, §20 |
| 31 | RER-F-031 | In-tree CCSDS primary header parser and per-APID sequence tracker | BACKLOG | feature | low | needs-impl-approval | RER-F-016 | §14, §5, §8 |
| 32 | RER-F-032 | CCSDS stream configuration and relay forwarding integration | BACKLOG | feature | medium | needs-impl-approval | RER-F-031 | §14, §5, §8 |
| 33 | RER-F-033 | CCSDS length-based framing for TCP streams | BACKLOG | feature | medium | needs-impl-approval | RER-F-032 | §14, §5, §8 |
| 34 | RER-F-034 | Separate CLI command documentation into dedicated USAGE guide | BACKLOG | docs | low | needs-impl-approval | RER-F-029 | §7 |
| 35 | RER-F-035 | Create INSTALL guide for package and container deployments | BACKLOG | docs | low | needs-impl-approval | RER-F-014, RER-F-015 | §16 |
| 36 | RER-F-036 | In-tree CBOR parser for BPv7 primary blocks | BACKLOG | feature | low | needs-impl-approval | RER-F-019 | §14, §8 |
| 37 | RER-F-037 | BPv7 inspection configuration and BundleInspection diagnostic event | BACKLOG | feature | low | needs-impl-approval | RER-F-036 | §14, §8 |
| 38 | RER-F-038 | Passive BPv7 stream inspection and transparent relay forwarding | BACKLOG | feature | medium | needs-impl-approval | RER-F-037 | §14, §8 |
| 39 | RER-F-039 | In-tree SDNV and LTP segment header parser | BACKLOG | feature | low | needs-impl-approval | RER-F-020 | §14, §8, §13 |
| 40 | RER-F-040 | LTP inspection configuration and LtpInspection diagnostic event | BACKLOG | feature | low | needs-impl-approval | RER-F-039 | §14, §8, §13 |
| 41 | RER-F-041 | Passive LTP stream inspection and transparent relay forwarding | BACKLOG | feature | medium | needs-impl-approval | RER-F-040 | §14, §8, §13 |
| 42 | RER-F-042 | Deterministic contact schedule outage simulation for channel harness | BACKLOG | feature | medium | needs-impl-approval | RER-F-041 | §14, §8, §13 |
| 43 | RER-F-043 | Deterministic queue saturation fault injection scenario | BACKLOG | test | low | needs-impl-approval | RER-F-017 | §13, §17 |
| 44 | RER-F-044 | SRT research and integration proposal | BACKLOG | research | medium | needs-impl-approval | RER-F-020 | §14 |
| 45 | RER-F-045 | MAVLink research and integration proposal | BACKLOG | research | medium | needs-impl-approval | RER-F-006, RER-F-028, RER-F-010 | §14, §8 |
| 46 | RER-F-046 | In-tree SRT packet header parser | BACKLOG | feature | low | needs-impl-approval | RER-F-044 | §8, §13, §14 |
| 47 | RER-F-047 | SRT inspection configuration and SrtInspection diagnostic event | BACKLOG | feature | low | needs-impl-approval | RER-F-046 | §8, §13, §14 |
| 48 | RER-F-048 | Passive SRT stream inspection and transparent relay forwarding | BACKLOG | feature | medium | needs-impl-approval | RER-F-047 | §8, §13, §14 |
| 49 | RER-F-049 | Channel impairment testing harness for SRT traffic | BACKLOG | feature | medium | needs-impl-approval | RER-F-048 | §8, §13, §14 |
| 50 | RER-F-050 | In-tree MAVLink packet header parser | BACKLOG | feature | low | needs-impl-approval | RER-F-045 | §8, §14 |
| 51 | RER-F-051 | Per-source MAVLink sequence tracking and diagnostic integration | BACKLOG | feature | medium | needs-impl-approval | RER-F-050 | §8, §14 |
| 52 | RER-F-052 | Native MAVLink TCP framing support | BACKLOG | feature | medium | needs-impl-approval | RER-F-051 | §8, §14 |
| 53 | RER-F-053 | MAVLink relay integration and performance benchmarks | BACKLOG | feature | medium | needs-impl-approval | RER-F-052 | §8, §14 |
| 54 | RER-F-054 | MQTT research and integration proposal | BACKLOG | research | medium | needs-impl-approval | RER-F-045 | §14, §8 |
| 55 | RER-F-055 | KISS and AX.25 research and integration proposal | BACKLOG | research | medium | needs-impl-approval | RER-F-045 | §14, §8 |

## Cross-cutting tracks

| ID | Title | Applies to |
|----|-------|------------|
| RER-T-001 | Simulation harness grows with every networking feature | Every networking task from RER-F-003 onward adds harness scenarios and regression tests. |
| RER-T-002 | Documentation and project state stay in sync with behavior | Every task updates docs, FEATURES.yaml status and KNOWN_ISSUES.md with linked evidence. |

## Dependency order

One valid implementation order that respects every dependency:

RER-F-001 → RER-F-002 → RER-F-003 → RER-F-004 → RER-F-005 → RER-F-006 → RER-F-007 → RER-F-008 → RER-F-012 → RER-F-013 → RER-F-014 → RER-F-015 → RER-F-018 → RER-F-022 → RER-F-023 → RER-F-024 → RER-F-025 → RER-F-026 → RER-F-027 → RER-F-009 → RER-F-016 → RER-F-028 → RER-F-010 → RER-F-011 → RER-F-017 → RER-F-019 → RER-F-020 → RER-F-021 → RER-F-029 → RER-F-030 → RER-F-031 → RER-F-032 → RER-F-033 → RER-F-034 → RER-F-035 → RER-F-036 → RER-F-037 → RER-F-038 → RER-F-039 → RER-F-040 → RER-F-041 → RER-F-042 → RER-F-043 → RER-F-044 → RER-F-045 → RER-F-046 → RER-F-047 → RER-F-048 → RER-F-049 → RER-F-050 → RER-F-051 → RER-F-052 → RER-F-053 → RER-F-054 → RER-F-055

## Owner approval gates

- **RER-F-001**: license
- **RER-F-007**: design
- **RER-F-011**: design
- **RER-F-021**: release
