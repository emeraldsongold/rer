# PLATFORM_SUPPORT.md — Supported Platforms and Environments

This document details the platform support matrix for RER (RER Engineering Relay), grounded in current build verification and the target requirements from SPEC §4.

## 1. Verified and Implemented Platform (Tier 1)

At the current foundation milestone (RER-F-001), the following platform is verified in continuous integration:

| Architecture | OS / Environment | Target Triple | Status | CI Verification |
|---|---|---|---|---|
| x86_64 | Linux (Ubuntu hosted runner) | `x86_64-unknown-linux-gnu` | Supported | GitHub Actions `ubuntu-latest` |

All compilation, linter (`clippy`), formatting (`rustfmt`), and unit tests run cleanly on `x86_64-unknown-linux-gnu` under the stable Rust toolchain.

## 2. Target Platforms and Packaged Formats (Milestone RER-F-015)

The official targets for releases (SPEC §4, §16) are:

- **Linux x86-64 (`x86_64-unknown-linux-gnu`)**: Tier 1 release and CI target.
- **Linux AArch64 / ARM64 (`aarch64-unknown-linux-gnu`)**: Tier 1 cross-compilation and package deployment target.

### Distribution Packages and Artifacts

| Format | Architecture | Target Distributions | Artifact Pattern | Systemd Unit | Config Path |
|---|---|---|---|---|---|
| `.deb` | `amd64` (x86_64) | Ubuntu 22.04+, Debian 11/12 | `rer_<version>_amd64.deb` | `/usr/lib/systemd/system/rer.service` | `/etc/rer/rer.yaml` |
| `.deb` | `arm64` (AArch64) | Ubuntu 22.04+, Debian 11/12 | `rer_<version>_arm64.deb` | `/usr/lib/systemd/system/rer.service` | `/etc/rer/rer.yaml` |
| `.rpm` | `x86_64` | RHEL 8/9, AlmaLinux, Rocky, Fedora | `rer-<version>-1.x86_64.rpm` | `/usr/lib/systemd/system/rer.service` | `/etc/rer/rer.yaml` |
| `.rpm` | `aarch64` | RHEL 8/9, AlmaLinux, Rocky, Fedora | `rer-<version>-1.aarch64.rpm` | `/usr/lib/systemd/system/rer.service` | `/etc/rer/rer.yaml` |
| `.tar.gz` | `x86_64`, `aarch64` | Portable Linux | `rer-<version>-linux-<arch>.tar.gz` | Included in archive | Included in archive |

Packages enforce safe defaults: service units are not automatically started or enabled upon installation, upgrades preserve operator configuration under `/etc/rer/`, and package removal retains state and configuration to prevent silent data loss.

## 3. Best-Effort Compatibility Targets (Milestone RER-F-018)

As outlined in SPEC §4, the following legacy environments are designated as best-effort evaluation targets:
- Debian 10 (Buster)
- Ubuntu 20.04 LTS
- RHEL 7 / CentOS 7 and compatible derivatives

*Note per SPEC §4*: Legacy compatibility will not be claimed merely because compilation succeeds; actual binary artifacts will be tested in clean containerized environments during Milestone RER-F-018.

## 4. IPv6 Support and Tested Verification Matrix (Milestone RER-F-023)

RER provides native IPv6 support across UDP and TCP relay endpoints and remote management listeners.

### Tested Capabilities in Continuous Integration
On Tier 1 platform (`x86_64-unknown-linux-gnu` on Ubuntu hosted runner):
- **Endpoint Transports**: Bracketed IPv6 literals (`[::1]:port` and `[::]:port`) for UDP and TCP in all four transport conversions (UDP-to-UDP, UDP-to-TCP, TCP-to-UDP, and TCP-to-TCP).
- **Bidirectional Forwarding**: IPv4-to-IPv6 and IPv6-to-IPv4 forwarding preserving datagram boundaries and payload bytes.
- **Mixed-Family Fan-Out**: Concurrent egress fan-out to mixed combinations of IPv4 and IPv6 UDP/TCP destinations.
- **Listener Isolation (`IPV6_V6ONLY`)**: Explicit configuration of the `IPV6_V6ONLY` socket option using the `socket2` crate on all IPv6 listeners, ensuring `[::]` accepts IPv6 only and `0.0.0.0` accepts IPv4 only.
- **Address Family Selection Rule**: Deterministic selection when a hostname resolves to multiple address families, selecting the first IPv4 address if present, and falling back to IPv6.
- **Destination Error Accounting**: Destination resolution errors or unreachable endpoints are accounted under `destination_errors` without halting forwarding to other healthy destinations.
- **Bracketed Formatting**: Diagnostic output and management APIs present IPv6 endpoints in bracketed form (`[::1]:port`).

### Platform Limitations and Untested Capabilities
- **Environments Without IPv6 Loopback**: In container sandboxes where `::1` cannot be bound (such as restricted container execution environments without IPv6 loopback), IPv6 loopback integration tests skip with a visible diagnostic message (`SKIPPED: IPv6 loopback ([::1]) is unavailable...`) and never pass silently.
- **Scoped Link-Local Addresses**: Scoped IPv6 addresses with zone identifiers (`[fe80::1%eth0]`) belong to roadmap milestone RER-F-024 and are not claimed at milestone RER-F-023. Nothing beyond the above tested baseline is claimed.

## 5. Explicitly Out of Scope for Initial Baseline

The following environments and platforms are intentionally out of scope for initial development:
- Specialized aerospace embedded processors (e.g., Xiphos hardware)
- Proprietary real-time operating systems (e.g., VxWorks)
- Any target requiring paid commercial toolchains or specialized hardware

