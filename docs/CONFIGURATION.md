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

| Field | Type | Description |
|---|---|---|
| `max_queue_size` | integer | Maximum queue size in packets (must be > 0). |
| `max_packet_size` | integer | Maximum packet size in bytes (must be > 0). |
| `drop_policy` | string | Overflow drop behavior: `"drop_oldest"`, `"drop_newest"`, or `"reject"`. |

## 8. Validation and CLI Usage

Validate configurations using the `rer validate` CLI command:

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
