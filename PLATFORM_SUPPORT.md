# PLATFORM_SUPPORT.md — Supported Platforms and Environments

This document details the platform support matrix for RER (RER Engineering Relay), grounded in current build verification and the target requirements from SPEC §4.

## 1. Verified and Implemented Platform (Tier 1)

At the current foundation milestone (RER-F-001), the following platform is verified in continuous integration:

| Architecture | OS / Environment | Target Triple | Status | CI Verification |
|---|---|---|---|---|
| x86_64 | Linux (Ubuntu hosted runner) | `x86_64-unknown-linux-gnu` | Supported | GitHub Actions `ubuntu-latest` |

All compilation, linter (`clippy`), formatting (`rustfmt`), and unit tests run cleanly on `x86_64-unknown-linux-gnu` under the stable Rust toolchain.

## 2. Planned Target Platforms (Release Roadmap)

The official targets planned for initial releases (SPEC §4) are:

- **Linux x86-64 (`x86_64-unknown-linux-gnu`)**: Tier 1 release and CI target.
- **Linux AArch64 / ARM64 (`aarch64-unknown-linux-gnu`)**: Tier 1 cross-compilation and container deployment target.

### Supported Distribution Baseline
The target baseline focuses on actively supported Linux distributions with standard `glibc` environments:
- Ubuntu 22.04 LTS and newer
- Debian 11 (Bullseye) and Debian 12 (Bookworm)
- AlmaLinux / Rocky Linux / RHEL 8+

## 3. Best-Effort Compatibility Targets (Milestone RER-F-018)

As outlined in SPEC §4, the following legacy environments are designated as best-effort evaluation targets:
- Debian 10 (Buster)
- Ubuntu 20.04 LTS
- RHEL 7 / CentOS 7 and compatible derivatives

*Note per SPEC §4*: Legacy compatibility will not be claimed merely because compilation succeeds; actual binary artifacts will be tested in clean containerized environments during Milestone RER-F-018.

## 4. Explicitly Out of Scope for Initial Baseline

The following environments and platforms are intentionally out of scope for initial development:
- Specialized aerospace embedded processors (e.g., Xiphos hardware)
- Proprietary real-time operating systems (e.g., VxWorks)
- Any target requiring paid commercial toolchains or specialized hardware
