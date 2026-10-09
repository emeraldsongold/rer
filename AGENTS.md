# AGENTS.md — Implementation Agent Guidelines and Constraints

This document governs autonomous and semi-autonomous implementation agents contributing to RER (RER Engineering Relay).

## 1. Operating Principles

1. **Incremental Milestones**: Agents must work on one bounded task at a time as specified in [`FEATURES.yaml`](FEATURES.yaml) and [`ROADMAP.md`](ROADMAP.md). Do not attempt multiple roadmap milestones in a single change.
2. **Test Evidence Over Claims**: As specified in SPEC §18 and §21, test evidence determines whether a task is complete. Agents must never claim a test passed or a feature functions without actual tool execution and verifiable output.
3. **Truthfulness in Documentation**: Documentation must reflect only implemented behavior. A feature described in [`docs/SPEC.md`](docs/SPEC.md) or [`ROADMAP.md`](ROADMAP.md) must not be documented as functional until it is implemented and verified.
4. **Zero-Cost Constraint**: The project relies exclusively on free, publicly available tooling and GitHub-hosted runners (SPEC §1). Never introduce paid service dependencies, proprietary toolchains, or mandatory paid infrastructure.
5. **No Local Compilation Requirement**: All builds and quality gates must run cleanly on GitHub Actions hosted Linux runners without requiring specialized local build setups.

## 2. Boundaries and Restrictions

- **Protected Paths**: Agents must never create or modify files under `.github/`, or the root `LICENSE` and `NOTICE` files. CI workflow changes and licensing files are subject to owner-reviewed pull requests only.
- **No Secrets or Credentials**: Never commit secrets, tokens, private keys, or personal identifiable information.
- **Autonomy Gates**: Respect the `autonomy` field in [`FEATURES.yaml`](FEATURES.yaml):
  - `ready-auto`: Agent may implement autonomously when prerequisites are met.
  - `needs-design-approval`: Requires owner approval on architectural design before implementation.
  - `needs-impl-approval`: Requires explicit owner approval before implementation proceeds.
  - `investigate-only`: Agent may only analyze and report findings.
  - `no-auto`: Reserved for owner-driven manual processes.
- **Cargo.lock Consistency**: Always maintain and include `Cargo.lock` in pull requests when workspace dependencies or packages change. CI builds with `--locked`.

## 3. Quality Standards

Before finishing any implementation increment, agents must run and verify:
- `cargo fmt --all --check`
- `cargo check --all-targets --all-features --locked`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --all-features --locked`

Any unmet acceptance criteria or blocked dependencies must be explicitly stated.
