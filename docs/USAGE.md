# RER CLI Usage Guide

This document describes the command-line interface (CLI) commands, flags, options, and operational workflows for RER (RER Engineering Relay).

## Running the Relay (`rer run`)

The relay starts only from a configuration that passes full structural and semantic validation (SPEC §7):

```bash
# Run the relay with a validated configuration
rer run config.yaml
rer run --config config.yaml

# Run with custom health socket and metrics endpoint
rer run --config config.yaml --health-socket /var/run/rer/health.sock --metrics-endpoint 127.0.0.1:9100

# Override management and health socket paths using environment variables
export RER_MGMT_SOCKET=/var/run/rer/mgmt.sock
export RER_HEALTH_SOCKET=/var/run/rer/health.sock
rer run config.yaml
```

Options:
- `FILE`: Path to YAML configuration file (positional argument).
- `--config <FILE>` (`-c`): Path to YAML configuration file (alternative flag).
- `--health-socket <PATH>`: Path to Unix domain socket for health and status checks (default: `/tmp/relay_health.sock`).
- `--metrics-endpoint <ADDR>`: Optional metrics endpoint address (e.g. `127.0.0.1:9100`) to expose Prometheus / OpenMetrics scraping over HTTP.

Environment variables:
- `RER_MGMT_SOCKET`: Overrides the management and health socket path for the relay instance and CLI management queries.
- `RER_HEALTH_SOCKET`: Overrides the health socket path for health checks and management server binding (used as fallback when `RER_MGMT_SOCKET` is not set).

During execution, `rer run` captures `SIGINT` (Ctrl-C) and `SIGTERM` signals, performs a graceful shutdown draining queued packets, and prints stream statistics before exiting with status 0.

## Configuration Validation (`rer validate`)

Validate configurations without starting the relay:

```bash
# Validate human-readable text output (exits 0 on success, non-zero on error)
rer validate config.yaml
rer validate --config config.yaml

# Output machine-readable JSON for automation
rer validate --json config.yaml
rer validate --format json config.yaml

# Inspect effective configuration (resolves defaults and redacts secrets)
rer validate --effective config.yaml
```

Options:
- `FILE`: Path to YAML configuration file (positional argument).
- `--config <FILE>` (`-c`): Path to YAML configuration file (alternative flag).
- `--format <FORMAT>` (`-f`): Output format: `text` (default) or `json`.
- `--json`: Machine-readable JSON output (convenience alias for `--format json`).
- `--effective`: Output effective configuration with sensitive fields and secrets redacted (`[REDACTED]`).

## Configuration and Sequence Tracking Inspection (`rer inspect`)

Inspect effective configuration files or live stream sequence tracking states:

```bash
# Effective configuration output (resolves defaults and redacts secrets)
rer inspect config.yaml
rer inspect --config config.yaml --effective
rer inspect --config config.yaml --format yaml

# Sequence tracking inspection reports from static configuration
rer inspect --config config.yaml --format text
rer inspect --config config.yaml --format json
rer inspect --config config.yaml --json

# Sequence tracking inspection reports from a running instance
rer inspect --socket /tmp/relay_health.sock
rer inspect --endpoint 127.0.0.1:9090 --auth-token "token" --timeout 2.0 --json
```

Options:
- `FILE`: Path to YAML configuration file (positional argument).
- `--config <FILE>` (`-c`): Path to YAML configuration file (alternative flag).
- `--format <FORMAT>` (`-f`): Output format: `yaml`, `text`, or `json`.
- `--json`: Machine-readable JSON output (convenience alias for `--format json`).
- `--effective`: Output effective configuration with secrets redacted.
- `--socket <PATH>`: Path to Unix domain socket for querying running instance (defaults to `/tmp/relay_health.sock` or `RER_MGMT_SOCKET`).
- `--endpoint <ENDPOINT>`: Remote management endpoint for querying running instance (e.g. `127.0.0.1:9090`).
- `--auth-token <TOKEN>`: Authentication token for querying management endpoint.
- `--timeout <SECONDS>`: Timeout in seconds to wait for response from running instance (default: `2.0`).

Output modes:
- **Effective configuration output**: When inspecting a configuration file with `--effective`, `--format yaml`, or by default without format/json flags, `rer inspect` validates the configuration, resolves default parameters, redacts secrets (such as `auth_token`), and prints the effective YAML configuration.
- **Sequence tracking inspection reports**: When inspecting a configuration file with `--format text`, `--format json`, or `--json` (without `--effective`), or when querying a running instance via `--socket` or `--endpoint`, `rer inspect` produces sequence tracking inspection reports. These reports provide per-stream tracking status (enabled/disabled), sequence extraction settings (offset, width, byte order), rollover threshold, packets evaluated, last and highest sequence numbers observed, gap, duplicate, out-of-order, and rollover counts, and payload preview configurations (hex and ASCII previews, max preview bytes).

## Instance Health Check (`rer health`)

Check the operational health of a running relay daemon instance:

```bash
# Check health using default health socket (/tmp/relay_health.sock)
rer health

# Check health specifying socket path and timeout
rer health --socket /tmp/relay_health.sock --timeout 2.0

# Output health status report as JSON
rer health --socket /tmp/relay_health.sock --timeout 2.0 --json
```

Options:
- `--socket <PATH>`: Path to Unix domain socket for health probe (default: `/tmp/relay_health.sock`). Overridden by `RER_HEALTH_SOCKET` if set.
- `--timeout <SECONDS>` (`-t`): Timeout in seconds to wait for health response (default: `2.0`).
- `--json`: Output report as JSON.

Exit code behavior:
- Returns **exit code 0 on healthy status** (`status: "healthy"`).
- Returns **non-zero exit code on unhealthy status or connection failure** (such as socket connection failure, daemon not running, query timeout, or unhealthy status).

## Instance Status (`rer status`)

Query instance status, version, uptime, health state, and stream counters from a running instance:

```bash
# Human-readable status output
rer status --socket /tmp/relay_health.sock

# Machine-readable JSON output for automation
rer status --socket /tmp/relay_health.sock --json

# Query remote management endpoint with authentication token
rer status --endpoint 127.0.0.1:9090 --auth-token "token" --timeout 2.0 --json
```

Options:
- `--socket <PATH>`: Path to Unix domain socket for status probe (default: `/tmp/relay_health.sock`).
- `--endpoint <ENDPOINT>`: Remote management endpoint for status probe (e.g. `127.0.0.1:9090`).
- `--auth-token <TOKEN>`: Authentication token for management probe.
- `--timeout <SECONDS>` (`-t`): Timeout in seconds to wait for status response (default: `2.0`).
- `--json`: Output report as JSON.

## Stream and Logical Interface Inspection (`rer streams`)

Inspect configured streams, directional logical interfaces, and fan-out topologies statically from configuration files or dynamically from running instances:

```bash
# Human-readable static configuration inspection
rer streams config.yaml
rer streams --config config.yaml

# Machine-readable JSON output for automation
rer streams --json config.yaml
rer streams --config config.yaml --format json

# Query active streams and runtime counters from a running instance
rer streams --socket /tmp/relay_health.sock
rer streams --socket /tmp/relay_health.sock --json
```

The output highlights directional pairings, stream endpoints, transports, and configuration context notes (SPEC §6).

## Metrics and Counters (`rer metrics`)

Inspect point-in-time packet, byte, drop, queue depth, error, and uptime counters:

```bash
# Tabular counters summary
rer metrics --socket /tmp/relay_health.sock

# JSON metrics output
rer metrics --socket /tmp/relay_health.sock --json

# OpenMetrics / Prometheus exposition format
rer metrics --socket /tmp/relay_health.sock --format prometheus
```

Options:
- `--socket <PATH>`: Path to Unix domain socket for metrics probe (default: `/tmp/relay_health.sock`).
- `--endpoint <ENDPOINT>`: Remote management endpoint for metrics probe.
- `--auth-token <TOKEN>`: Authentication token for management probe.
- `--timeout <SECONDS>` (`-t`): Timeout in seconds to wait for metrics response (default: `2.0`).
- `--format <FORMAT>` (`-f`): Output format: `text` (default), `json`, or `prometheus`.
- `--json`: Machine-readable JSON output (convenience alias for `--format json`).

## Network Simulation and Verification Testing (`rer test`)

RER includes unprivileged network simulation, traffic generation, and verification test tooling:

```bash
# Run simulation harness with default parameters (100 packets, 256 bytes)
rer test

# Run simulation harness explicitly with custom packet parameters and impairments
rer test harness --count 500 --size 512 --rate 1000 --burst 5 --duration 10.0 --seed 12345 --loss-rate 0.05 --duplicate-rate 0.01 --reorder-rate 0.02 --json

# Run standalone traffic generator against a target UDP address
rer test generate --target 127.0.0.1:5000 --count 1000 --size 256 --rate 500 --burst 2 --seed 42

# Run standalone traffic receiver bound to a local UDP port
rer test receive --bind 127.0.0.1:5000 --count 1000 --timeout 5.0
```

Subcommands and options:

- **`rer test` / `rer test harness`**: Runs an end-to-end unprivileged simulation harness connecting an in-memory traffic generator, simulated network impairment channel, and verification receiver:
  - `--count <COUNT>` (`-c`): Number of packets to generate and verify (default: `100`).
  - `--size <BYTES>` (`-s`): Payload size in bytes (default: `256`).
  - `--rate <PPS>` (`-r`): Packet rate in packets per second (0 for unthrottled, default: `0`).
  - `--burst <SIZE>` (`-b`): Burst size in packets (default: `1`).
  - `--duration <SECONDS>` (`-d`): Optional test duration limit in seconds.
  - `--seed <SEED>`: PRNG seed for deterministic packet generation and impairments (default: `42`).
  - `--loss-rate <RATE>`: Simulated packet loss rate between 0.0 and 1.0 (default: `0.0`).
  - `--duplicate-rate <RATE>`: Simulated packet duplication rate between 0.0 and 1.0 (default: `0.0`).
  - `--reorder-rate <RATE>`: Simulated packet reordering rate between 0.0 and 1.0 (default: `0.0`).
  - `--json`: Output report as JSON (default: `true`).

- **`rer test generate`**: Runs the standalone deterministic traffic generator transmitting UDP datagrams to a target endpoint:
  - `--target <ADDR>` (`-t`): Target UDP address in `host:port` format (required, e.g. `127.0.0.1:5000`).
  - `--count <COUNT>` (`-c`): Number of packets to generate (default: `100`).
  - `--size <BYTES>` (`-s`): Payload size in bytes (default: `256`).
  - `--rate <PPS>` (`-r`): Transmission rate in packets per second (0 for unthrottled, default: `0`).
  - `--burst <SIZE>` (`-b`): Burst size in packets (default: `1`).
  - `--seed <SEED>`: PRNG seed for reproducible test patterns (default: `42`).

- **`rer test receive`**: Runs the standalone verification receiver listening for UDP test traffic:
  - `--bind <ADDR>` (`-b`): Bind UDP address in `host:port` format (default: `127.0.0.1:5000`).
  - `--count <COUNT>` (`-c`): Expected packet count to receive before completing.
  - `--timeout <SECONDS>` (`-t`): Timeout in seconds to wait for packets (default: `2.0`).

## Version Information and Roadmap Commands (`rer version`, `rer diagnose`, `rer capture`, `rer replay`)

```bash
# Print binary version information
rer version

# Planned roadmap commands (exit status 1)
rer diagnose
rer capture
rer replay
```

RER provides version inspection and reserves command slots for roadmap capabilities: `rer version` prints binary version information and exits with status 0 while `rer diagnose`, `rer capture` and `rer replay` exit with status 1 as planned roadmap features.

- **`rer version`**:
  `rer version` prints binary version information (e.g. `rer 0.1.0`) and exits with status 0.
- **`rer diagnose`**:
  Planned roadmap feature for network diagnostics and troubleshooting (scheduled in milestone RER-F-008). Exits with status 1 as planned roadmap features.
- **`rer capture`**:
  Planned roadmap feature for network traffic capture (scheduled in milestone RER-F-011). Exits with status 1 as planned roadmap features.
- **`rer replay`**:
  Planned roadmap feature for traffic replay (scheduled in milestone RER-F-011). Exits with status 1 as planned roadmap features.
