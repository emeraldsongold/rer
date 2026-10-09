# CONTRIBUTING.md — Contributing to RER

Thank you for your interest in contributing to RER (RER Engineering Relay).

## 1. Operating Principles

- **Small, Testable Increments**: Implement changes in small, bounded increments matching milestone criteria in [`ROADMAP.md`](ROADMAP.md) and [`FEATURES.yaml`](FEATURES.yaml).
- **Test Evidence Required**: Every functional change must include verifiable automated tests (unit, integration, or simulation). Claims without test execution evidence are insufficient.
- **Zero Local Compilation Prerequisite**: Contributors do not need specialized local compilation environments. All CI builds and checks run on public GitHub Actions hosted Linux runners.
- **Strictly Open Source and Free Tooling**: Never introduce dependencies or workflows requiring paid services, proprietary software, or non-free licenses.

## 2. Licensing of Contributions

RER is licensed under the Apache License, Version 2.0. By submitting a pull request, you agree that your contributions will be licensed under the Apache-2.0 terms without additional conditions or restrictions.

Third-party dependencies must have permissive open-source licenses compatible with Apache-2.0 (e.g., Apache-2.0, MIT, BSD-2/3-Clause). Copyleft licenses (GPL, AGPL) are not permitted.

## 3. Development Workflow and Quality Gates

All pull requests must pass the CI quality gates defined in `.github/workflows/ci.yml`:

```bash
# 1. Format verification
cargo fmt --all --check

# 2. Strict type check across all targets and features
cargo check --all-targets --all-features --locked

# 3. Linting with zero warnings allowed
cargo clippy --all-targets --all-features --locked -- -D warnings

# 4. Unit and integration tests
cargo test --all-features --locked
```

## 4. Protected Files and Policies

- **`.github/` workflows, `LICENSE`, and `NOTICE`**: These files are protected and must not be altered by automated implementation agents. Changes to CI workflows and licensing notices require explicit owner review.
- **`Cargo.lock`**: Whenever dependencies or workspace crates are modified, always include the updated `Cargo.lock` in the pull request. CI builds with `--locked`.
- **Secrets and Privacy**: Never commit secrets, tokens, credentials, or personal private information.
- **Documentation Sync**: Any PR that modifies behavior must update the relevant documentation (`README.md`, `ARCHITECTURE.md`, `KNOWN_ISSUES.md`, `CHANGELOG.md`) reflecting only verified, implemented functionality.
