# SECURITY.md — Security Policy and Operational Safety

This document defines the security policy and operational safety requirements for RER (RER Engineering Relay).

## 1. Reporting a Vulnerability

If you discover a security vulnerability in RER, please report it privately rather than opening a public issue.

- **Primary Contact**: Project maintainer Ronald Edward Reeves Jr at `gold.emerald@proton.me`
- **GitHub Security**: Use GitHub Private Vulnerability Reporting on the [rer repository](https://github.com/emeraldsongold/rer/security/advisories).

Please include:
- A description of the vulnerability and its potential impact.
- Step-by-step instructions or proof-of-concept code to reproduce the issue.
- Any suggested mitigations or patches.

Reports will be acknowledged promptly, investigated, and coordinated through a responsible disclosure timeline.

## 2. Core Security Principles (SPEC §17)

All implementations and contributions in RER must adhere to the following principles:

1. **Safe by Default**:
   - Prefer safe Rust. Unsafe code is prohibited unless strictly necessary, documented, and reviewed.
   - Avoid unbounded memory allocations, queues, log buffers, or packet capture buffers.
2. **Untrusted Inputs**:
   - Treat network packets, configuration files (YAML), packet captures (PCAP), and API inputs as untrusted data.
   - Enforce strict size and length limits before deserialization or parsing.
3. **Confidentiality & Secret Handling**:
   - Never log secrets, passwords, or authentication tokens by default.
   - Mask sensitive values in effective-configuration views and error outputs.
4. **Principle of Least Privilege**:
   - Container images and system services must run as non-root users.
   - Do not require elevated Linux capabilities (`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`) unless running explicitly designated low-level network emulation scenarios.
5. **No Shell Execution**:
   - Never expose shell command execution through the management API, CLI, or diagnostic endpoints.
6. **Production Safety**:
   - Replay mechanisms must never replay packets to mission or production destinations without explicit operator intent.
   - Diagnostic claims must reflect observed reality and not fabricate success.
