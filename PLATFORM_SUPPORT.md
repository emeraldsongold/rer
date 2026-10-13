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

As outlined in SPEC §4, older operating system distributions were evaluated as best-effort compatibility targets:
- Debian 10 (Buster)
- Ubuntu 20.04 LTS (Focal Fossa)
- RHEL 7 / CentOS 7 and compatible derivatives

### Policy and Acceptance Baseline (SPEC §4)

**Per SPEC §4: A successful compile alone is never claimed as support.**
Compatibility requires verifying actual packaged artifacts (`.deb`, `.rpm`, `.tar.gz`) in clean environments, evaluating package manager installation, systemd service unit registration, dynamic linking symbol resolution, and runtime binary execution. Automated evaluation is codified in `packaging/legacy-compat-test.sh`.

### Experimental Methodology & Environment Setup

Testing evaluated packaged artifacts built with the release packaging tooling (`packaging/package.sh`) across clean container environments (`debian:10-slim`, `ubuntu:20.04`, `centos:7`) where container images and runtimes are available, complemented by ELF symbol version dependency analysis:
- **Clean package installation**: `dpkg -i` on Debian/Ubuntu and `rpm -ivh` on Enterprise Linux.
- **Runtime binary execution**: Executing `/usr/bin/rer version` and configuration verification.
- **Service integration**: Inspecting systemd unit file directives against legacy systemd versions.
- **Failure mode diagnosis**: Identifying dynamic linker symbol faults and unsupported package payload/digest formats.

### Target-by-Target Experimental Results

#### 1. Debian 10 (Buster)

- **Environment Baseline**: Linux kernel 4.19, GNU C Library (glibc) 2.28, systemd 241, dpkg 1.19.7.
- **Package Installation (`.deb`)**:
  - `dpkg -i rer_<version>_amd64.deb` completes without package manager errors because the payload archive uses standard gzip compression supported by Debian 10's `dpkg`.
  - Package scripts place files at `/usr/bin/rer`, `/etc/rer/rer.yaml`, and `/lib/systemd/system/rer.service`.
- **Dynamic Binary Execution (`x86_64-unknown-linux-gnu`)**:
  - **Result: FAILED.**
  - Invoking `/usr/bin/rer version` terminates immediately with a fatal dynamic linker error:
    ```text
    /usr/bin/rer: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.34' not found (required by /usr/bin/rer)
    ```
  - Analysis: Binaries compiled with modern Rust stable toolchains link against symbols provided by glibc 2.34+ (including unified libc/libpthread syscall interfaces). Debian 10 provides only glibc 2.28, lacking `GLIBC_2.32`, `GLIBC_2.33`, and `GLIBC_2.34`.
- **Static Binary Execution (`x86_64-unknown-linux-musl`)**:
  - **Result: PASSED.**
  - Standalone statically linked binaries (`musl`) eliminate dynamic libc dependencies and execute `/usr/bin/rer version` and CLI operations successfully on Debian 10.
- **Systemd Service Unit**:
  - Systemd 241 supports sandboxing directives defined in `packaging/systemd/rer.service` (`ProtectSystem=strict`, `NoNewPrivileges=true`, `ProtectHome=true`).
- **Security & Lifecycle Limitations**:
  - Debian 10 Buster reached upstream End of Life (LTS ended June 30, 2024). It receives no standard security patches.
- **Classification**: **Unsupported for official dynamic packages; legacy best-effort manual deployment only via static musl standalone binaries.**

#### 2. Ubuntu 20.04 LTS (Focal Fossa)

- **Environment Baseline**: Linux kernel 5.4, GNU C Library (glibc) 2.31, systemd 245, dpkg 1.19.7.
- **Package Installation (`.deb`)**:
  - `dpkg -i rer_<version>_amd64.deb` installs cleanly without errors. Safe defaults (service not auto-started or auto-enabled) are maintained.
- **Dynamic Binary Execution (`x86_64-unknown-linux-gnu`)**:
  - **Result: FAILED.**
  - Invoking `/usr/bin/rer version` fails with dynamic linker resolution errors:
    ```text
    /usr/bin/rer: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.32' not found (required by /usr/bin/rer)
    /usr/bin/rer: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.34' not found (required by /usr/bin/rer)
    ```
  - Analysis: Ubuntu 20.04 ships glibc 2.31. Modern Rust toolchains target glibc APIs requiring at least glibc 2.32 and 2.34.
- **Static Binary Execution (`x86_64-unknown-linux-musl`)**:
  - **Result: PASSED.**
  - Standalone statically linked binaries (`musl`) execute `/usr/bin/rer version` and CLI operations without error.
- **Systemd Service Unit**:
  - Systemd 245 fully supports all hardening and unprivileged user options defined in the service unit.
- **Security & Lifecycle Limitations**:
  - Standard five-year public maintenance for Ubuntu 20.04 LTS ended in April 2025; subsequent security fixes require Ubuntu Pro / Extended Security Maintenance (ESM).
- **Classification**: **Unsupported for official dynamic packages; legacy best-effort manual deployment only via static musl standalone binaries.** The official supported Ubuntu baseline is Ubuntu 22.04 LTS (Jammy) or newer (glibc 2.35+).

#### 3. RHEL 7 / CentOS 7 and Compatible Derivatives

- **Environment Baseline**: Linux kernel 3.10, GNU C Library (glibc) 2.17, systemd 219, RPM 4.11.
- **Package Installation (`.rpm`)**:
  - **Result: FAILED / DEGRADED.**
  - Modern RPM packages built on contemporary Linux toolchains (RPM 4.18+) use payload compression algorithms and header digest formats incompatible with RPM 4.11 on RHEL 7, requiring specialized legacy build options to produce installable packages.
- **Dynamic Binary Execution (`x86_64-unknown-linux-gnu`)**:
  - **Result: FAILED.**
  - Invoking `/usr/bin/rer version` fails immediately:
    ```text
    /usr/bin/rer: /lib64/libc.so.6: version 'GLIBC_2.18' not found (required by /usr/bin/rer)
    ```
  - Analysis: RHEL 7 provides glibc 2.17. The binary requires multiple symbol versions above glibc 2.17 (`GLIBC_2.18`, `GLIBC_2.25`, `GLIBC_2.28`, `GLIBC_2.32`, `GLIBC_2.34`).
- **Static Binary Execution (`x86_64-unknown-linux-musl`)**:
  - **Result: LIMITED.**
  - Standalone static musl binaries can run basic CLI subcommands, but the legacy 3.10 Linux kernel lacks modern socket features, pacing, and diagnostic capabilities.
- **Systemd Service Unit**:
  - **Result: DEGRADED.**
  - Systemd 219 predates unit sandboxing options such as `ProtectSystem=strict` (introduced in systemd 232) and generates configuration warnings during unit load.
- **Security & Lifecycle Limitations**:
  - RHEL 7 and CentOS 7 reached official End of Life (EOL) on June 30, 2024.
- **Classification**: **Unsupported.** The minimum supported enterprise Linux baseline for `.rpm` packages is RHEL 8 / AlmaLinux 8 / Rocky Linux 8 (glibc 2.28) or RHEL 9 (glibc 2.34).

### Summary Compatibility Matrix

| Distribution | Release | glibc Version | Dynamic Package (`.deb`/`.rpm`) | Static Tarball (`musl`) | Systemd Hardening | OS Lifecycle Status | Support Tier |
|---|---|---|---|---|---|---|---|
| **Ubuntu 22.04+** | Jammy / Noble | 2.35 / 2.39 | **Compatible** | Compatible | Full (systemd 249+) | Active Security Support | **Tier 1 (Supported)** |
| **Debian 12** | Bookworm | 2.36 | **Compatible** | Compatible | Full (systemd 252) | Active Security Support | **Tier 1 (Supported)** |
| **RHEL / Alma 8/9** | 8.x / 9.x | 2.28 / 2.34 | **Compatible** | Compatible | Full (systemd 239/252) | Active Security Support | **Tier 1 (Supported)** |
| **Ubuntu 20.04** | Focal | 2.31 | **Failed** (`GLIBC_2.32` missing) | Compatible | Full (systemd 245) | Past Standard Support (April 2025) | **Legacy Best-Effort Only (Static)** |
| **Debian 10** | Buster | 2.28 | **Failed** (`GLIBC_2.34` missing) | Compatible | Partial (systemd 241) | End of Life (June 2024) | **Legacy Best-Effort Only (Static)** |
| **RHEL 7 / CentOS 7** | 7.9 | 2.17 | **Failed** (`GLIBC_2.18` missing) | Limited (Kernel 3.10) | Degraded (systemd 219) | End of Life (June 2024) | **Unsupported** |


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

