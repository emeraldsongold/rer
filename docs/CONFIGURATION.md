# RER Configuration Guide

This document describes the YAML configuration format, schema structure, field definitions, and validation rules for RER (RER Engineering Relay).

## 1. Overview

RER uses YAML for instance and network relay definitions. Every configuration is strictly validated before execution, rejecting unknown fields, duplicate identities, and conflicting parameters.

A formal JSON schema representing this structure is maintained at [`schema/rer-config.schema.json`](../schema/rer-config.schema.json).

## 2. Top-Level Structure

A configuration file specifies a format `version` and one or more relay `instances`:

```yaml
version: "1"
instances:
  - id: "relay-node-1"
    name: "Primary Gateway"
    mode: "production"
    management:
      enabled: true
      endpoint: "127.0.0.1:9090"
    streams:
      - id: "telem-in"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
          mode: "listen"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
          mode: "connect"
```

### Top-Level Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `version` | string | Yes | Configuration version string (e.g. `"1"` or `"1.0"`). |
| `instances` | array | Yes* | List of RER relay instance objects. |
| `instance` | object | No* | Alternative single-instance definition (conflicts with `instances`). |

*Note: Exactly one of `instances` or `instance` must be specified. Defining both results in a conflicting settings error.*

## 3. Instance Configuration (`InstanceConfig`)

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | string | (required) | Unique identifier for this instance across the configuration. |
| `name` | string | `null` | Optional human-readable name or description. |
| `mode` | string | `"production"` | Operational profile: `"production"`, `"debug"`, or `"test"`. |
| `management` | object | `null` | Optional management plane settings. |
| `streams` | array | `[]` | Forwarding streams configured on this instance. |
| `logical_interfaces` | array | `[]` | Directional stream pairs (command/telemetry). |
| `buffer` | object | `null` | Instance-level buffer queue bounding. |

## 4. Management Plane (`ManagementConfig`)

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enables management API listeners. |
| `endpoint` | string | (required) | Network address or Unix domain socket path. |
| `auth_token` | string | `null` | Optional authentication token. Never displayed in effective configuration output. |
| `tls` | object | `null` | Optional TLS certificate and key paths (`cert_file`, `key_file`). |

## 5. Forwarding Streams (`StreamConfig`)

Each stream specifies forwarding from a `source` to one or more destinations:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique stream identity within the instance. |
| `description` | string | No | Optional description of data flow. |
| `source` | object | Yes | Ingress endpoint (`EndpointConfig`). |
| `destination` | object | No* | Single egress endpoint. Conflicts with `destinations`. |
| `destinations` | array | No* | List of egress endpoints for fan-out. Conflicts with `destination`. |
| `buffer` | object | No | Stream-level buffer limits (`max_queue_size`, `max_packet_size`, `drop_policy`). |

*Note: Either `destination` or `destinations` must be specified, but not both.*

### Endpoint Configuration (`EndpointConfig`)

| Field | Type | Default | Description |
|---|---|---|---|
| `transport` | string | (required) | Transport protocol: `"udp"` or `"tcp"`. |
| `address` | string | (required) | Network address in `host:port` format (e.g. `127.0.0.1:5000`). Port must be between 1 and 65535. |
| `mode` | string | `"listen"` for source, `"connect"` for dest | Connection mode: `"listen"` or `"connect"`. |

### Transport Conversion and TCP Framing Protocol

RER supports all four transport conversion combinations across ingress and egress:
- **UDP to UDP**: Preserves discrete UDP datagram boundaries.
- **UDP to TCP**: Ingress UDP datagrams are framed into TCP byte streams using a 4-byte big-endian length prefix.
- **TCP to UDP**: Ingress framed TCP messages are decoded using their 4-byte length header and transmitted as individual UDP datagrams.
- **TCP to TCP**: End-to-end framed stream forwarding.

#### TCP Wire Framing Format

```text
+---------------------------+------------------------------------+
| Length Prefix (4 bytes)   | Payload Bytes (N bytes)            |
| uint32 big-endian (N)     | [u8; N]                            |
+---------------------------+------------------------------------+
```

Frames with length exceeding `max_packet_size` are dropped at ingress and tracked under `drops_oversized`. Destination outages trigger automatic reconnection with exponential backoff. Slow TCP readers that stall transmission cause bounded queue saturation and explicit drop policy enforcement without unbounded memory growth.

## 6. Logical Interfaces (`LogicalInterfaceConfig`)

Logical interfaces associate related directional streams, such as command TX and telemetry RX paths (SPEC §6):

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique identifier for the logical interface. |
| `name` | string | No | Optional human-readable interface name. |
| `tx_stream` | string | No* | Stream ID for the transmit/uplink direction. |
| `rx_stream` | string | No* | Stream ID for the receive/downlink direction. |

*Note: At least one of `tx_stream` or `rx_stream` must be specified, and they cannot reference the same stream ID.*

## 7. Buffer and Queue Limits (`BufferConfig`)

Enforces memory and queue bounds (SPEC §17):

| Field | Type | Default | Description |
|---|---|---|---|
| `max_queue_size` | integer | `1024` | Maximum queue size in packets (must be > 0). |
| `max_packet_size` | integer | `65535` | Maximum packet size in bytes (must be > 0). |
| `drop_policy` | string | `"drop_oldest"` | Overflow drop behavior: `"drop_oldest"`, `"drop_newest"`, or `"reject"`. |

### Overload Drop Policy and Queue Bounding

All relay queues are strictly bounded. Unbounded queues and silent data loss are prohibited by architectural invariant (SPEC §5, §17).

- **Queue Bounding**: Buffers are bounded by `max_queue_size` (packets) and `max_packet_size` (bytes). When configured at both instance and stream levels, the stream-level setting takes precedence. If omitted, defaults of 1024 packets and 65535 bytes apply.
- **Overload Policies**:
  - `drop_oldest` (default): Evicts and drops the oldest queued packet to accommodate newly arriving packets. Suitable for real-time telemetry where the freshest reading is most valuable.
  - `drop_newest`: Drops the newly arrived packet when the queue is full, preserving earlier received packets.
  - `reject`: Rejects and drops incoming packets immediately upon queue exhaustion.
- **Oversized Datagrams**: Datagrams exceeding `max_packet_size` are dropped at ingress before entering the queue and tracked under `drops_oversized`.
- **Accounting and Visibility (Never Silent)**: Every dropped packet increments `dropped_packets` and specific reason counters (`drops_queue_full`, `drops_oversized`) and is logged to diagnostics with the stream ID and queue capacity. Packet loss is never silent.

## 8. Relay Execution and Validation CLI Usage

### Running the Relay (`rer run`)

The relay starts only from a configuration that passes full structural and semantic validation (SPEC §7):

```bash
# Run the relay with a validated configuration
rer run config.yaml
rer run --config config.yaml
```

During execution, `rer run` captures `SIGINT` (Ctrl-C) and `SIGTERM` signals, performs a graceful shutdown draining queued packets, and prints stream statistics before exiting with status 0.

### Configuration Validation (`rer validate`)

Validate configurations without starting the relay:

```bash
# Validate human-readable text output (exits 0 on success, non-zero on error)
rer validate config.yaml

# Output machine-readable JSON for automation
rer validate --json config.yaml

# Inspect effective configuration (resolves defaults and redacts secrets)
rer validate --effective config.yaml
rer inspect config.yaml
```

### Safety and Secret Handling

Sensitive fields (such as `auth_token`) are typed as `SecretString` and are masked as `[REDACTED]` when printing effective configuration via `rer validate --effective` or `rer inspect`.
