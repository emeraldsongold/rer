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
| `test_mode` | object | `null` | Optional test mode configuration block (see Test Mode Configuration below). |
| `correlation_id` | string | `null` | Run correlation ID (also configurable inside `test_mode`). Required when `mode` is `"test"`. |
| `expiry_seconds` | integer | `3600` (in test mode) | Maximum test run duration in seconds (1 to 86,400). |
| `max_events` | integer | `10000` (in test mode) | Maximum diagnostic events to emit before ending run (1 to 1,000,000). |
| `prior_mode` | string | `"production"` | Diagnostic mode to revert to after test run ends (`"production"` or `"debug"`). |
| `management` | object | `null` | Optional management plane settings. |
| `streams` | array | `[]` | Forwarding streams configured on this instance. |
| `logical_interfaces` | array | `[]` | Directional stream pairs (command/telemetry). |
| `buffer` | object | `null` | Instance-level buffer queue bounding. |

### Operational Diagnostic Modes

RER supports three distinct operational diagnostic modes:

1. **Production Mode (`"production"`)**:
   - Quiet by default; no per-packet forwarding log output.
   - Retains a bounded ring buffer of recent diagnostic events for significant failures, queue drops, and health state transitions.
   - Default mode for production forwarding instances.

2. **Debug Mode (`"debug"`)**:
   - Emits detailed per-packet lifecycle events across forwarding stages: received, accepted, routed/queued, send-attempted, and send-succeeded.
   - Includes stream IDs, nanosecond-precision timestamps, endpoints, packet lengths, and sequence information.
   - Explains drops, rejection reasons, and destination errors.

3. **Test Mode (`"test"`)**:
   - Collects detailed diagnostic events for a bounded test run.
   - Every event recorded during the run carries the run's configured `correlation_id` across relay instances.
   - Strictly bounded in both duration (`expiry_seconds`, maximum 86,400 seconds / 24 hours) and event count (`max_events`, maximum 1,000,000 events).
   - When a bound is reached or duration expires, the run ends, emits an end-of-run event explaining why (`"duration_expired"` or `"event_limit_reached"`), and the instance automatically returns to its configured `prior_mode` (default `"production"`).
   - Changing modes dynamically at runtime is out of scope; test mode parameters are established via configuration.

#### Test Mode Configuration (`TestModeConfig`)

| Field | Type | Default | Bounds / Description |
|---|---|---|---|
| `correlation_id` | string | (required) | Non-empty correlation identifier stamped on all events in the test run. |
| `expiry_seconds` | integer | `3600` | Run duration timeout in seconds (min: 1, max: 86,400 / 24 hours). |
| `max_events` | integer | `10000` | Maximum diagnostic events to record (min: 1, max: 1,000,000). |
| `prior_mode` | string | `"production"` | Diagnostic level to restore upon completion: `"production"` or `"debug"`. |

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
| `sequence` | object | No | Optional generic sequence extraction and tracking (`SequenceConfig`). Off by default. |
| `inspection` | object | No | Optional packet inspection and preview configuration (`InspectionConfig`). Off by default. |
| `ccsds` | object | No | Optional CCSDS Space Packet parsing, validation, and per-APID sequence tracking (`CcsdsConfig`). Off by default. |
| `framing` | string | No | Optional stream-level framing mode override for TCP endpoints (`"length_prefix"` or `"ccsds"`). Defaults to `"length_prefix"`. |

*Note: Either `destination` or `destinations` must be specified, but not both.*

### CCSDS Space Packet Configuration (`CcsdsConfig`)

Configures parsing, validation, and sequence tracking for CCSDS Space Packets (CCSDS 133.0-B-2, SPEC §14).

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | boolean | `true` | Enables CCSDS primary header parsing and validation. |
| `validate_version` | boolean | `true` | Enforces packet version number == 0 (Space Packets). |
| `validate_length` | boolean | `true` | Validates that datagram length is at least packet data length + 7. |
| `track_sequences` | boolean | `true` | Tracks sequence continuity independently per APID modulo 16,384. |
| `filter_apids` | array | `null` | Optional allowlist of APIDs (0–2047) to accept/track. |
| `ignore_idle_apid` | boolean | `true` | Excludes idle packets (APID 2047 / 0x7FF) from sequence tracking and gap alerts. |
| `passthrough_on_error` | boolean | `false` | When `true`, datagrams failing CCSDS validation are forwarded unchanged while emitting a diagnostic failure event and recording the error. When `false` (default), invalid datagrams are dropped with a `DiagnosticStage::Dropped` event. |
| `framing` | string | `null` | Optional framing mode override (`"length_prefix"` or `"ccsds"`). |

*Note: A configuration specifying both active CCSDS sequence tracking (`ccsds.track_sequences: true`) and generic sequence tracking (`sequence.enabled: true`) on the same stream is rejected by `rer validate` with a conflicting sequence tracking error.*

### Endpoint Configuration (`EndpointConfig`)

| Field | Type | Default | Description |
|---|---|---|---|
| `transport` | string | (required) | Transport protocol: `"udp"` or `"tcp"`. |
| `address` | string | (required) | Network address in `host:port` format (e.g. `127.0.0.1:5000` or `[::1]:5000`). Port must be between 1 and 65535. |
| `mode` | string | `"listen"` for source, `"connect"` for dest | Connection mode: `"listen"` or `"connect"`. |
| `framing` | string | `"length_prefix"` | Optional framing mode for TCP endpoints: `"length_prefix"` (default 4-byte prefix) or `"ccsds"` (CCSDS Space Packet length-based framing, C + 7 bytes). |

#### Address Formats and IPv6 Support

Endpoints accept IPv4 literals (`127.0.0.1:5000`), bracketed IPv6 literals (`[::1]:5000`, `[::]:5000`), and syntactically valid hostnames (`localhost:5000`). Unbracketed IPv6 literals (`::1:5000`) are rejected during validation.

IPv6 endpoints are fully supported for both UDP and TCP across all four transport conversion combinations (UDP to UDP, UDP to TCP, TCP to UDP, and TCP to TCP), as well as multi-destination fan-out. IPv4-only configurations behave exactly as before.

#### Hostname Address Family Selection Rule

When an endpoint address specifies a hostname (such as `localhost:5000`) that resolves to addresses in both IPv4 and IPv6 families:
- **Selection Rule**: RER deterministically selects the first IPv4 address returned by the system resolver to preserve backward compatibility with existing IPv4 network deployments and configurations.
- **Fallback**: If the hostname resolves exclusively to IPv6 addresses, RER selects the first resolved IPv6 address.
- **Explicit Literals**: Explicit bracketed IPv6 literals (`[::1]:5000`) always use IPv6, and IPv4 literals (`127.0.0.1:5000`) always use IPv4 without ambiguity.

#### IPv6 Listener Isolation (`IPV6_V6ONLY`)

All IPv6 listeners (both TCP listening endpoints and UDP receiver sockets) explicitly set the `IPV6_V6ONLY` socket option using the `socket2` crate:
- `[::]` accepts IPv6 connections and datagrams only; IPv4 traffic is refused.
- `0.0.0.0` accepts IPv4 traffic only.
- Dual-stack operation requires configuring two explicit endpoints (one IPv4, one IPv6). Implicit dual-stack wildcard sockets are prohibited by architectural invariant.

#### Destination Error Handling and Multi-Destination Fan-Out

In multi-destination streams (`destinations`), an unresolvable hostname or unreachable destination (such as an unreachable IPv6 host or closed TCP port) is recorded under `destination_errors` and `socket_errors` and logged to diagnostics. It does not stop, interrupt, or degrade forwarding to other reachable destinations.

#### Tested Scope of IPv6 Support

Tested IPv6 support in continuous integration covers bracketed IPv6 literals (`[::1]` and `[::]`) and scoped IPv6 addresses with zone identifiers (`[fe80::1%eth0]:5000` and `[fe80::1%2]:5000`) for UDP and TCP, all four transport conversions, cross-family forwarding (IPv4 to IPv6 and IPv6 to IPv4), multi-destination fan-out, and explicit `IPV6_V6ONLY` listener isolation.

### Transport Conversion and TCP Framing Protocol

RER supports all four transport conversion combinations across ingress and egress:
- **UDP to UDP**: Preserves discrete UDP datagram boundaries.
- **UDP to TCP**: Ingress UDP datagrams are framed into TCP byte streams using a 4-byte big-endian length prefix.
- **TCP to UDP**: Ingress framed TCP messages are decoded using their 4-byte length header and transmitted as individual UDP datagrams.
- **TCP to TCP**: End-to-end framed stream forwarding.

#### TCP Wire Framing Format

##### 1. Default Length-Prefix Framing (`framing: "length_prefix"`)

```text
+---------------------------+------------------------------------+
| Length Prefix (4 bytes)   | Payload Bytes (N bytes)            |
| uint32 big-endian (N)     | [u8; N]                            |
+---------------------------+------------------------------------+
```

##### 2. CCSDS Length-Based Framing (`framing: "ccsds"`)

For TCP streams carrying CCSDS Space Packets (SPEC §14, §5), setting `framing: "ccsds"` on the endpoint or stream enables native length-based framing without RER's 4-byte length prefix:

```text
+-----------------------------------+------------------------------------+
| CCSDS Primary Header (6 octets)   | Packet Data Field (C + 1 octets)   |
| bytes 4..5: big-endian uint16 (C) | user payload / secondary header    |
+-----------------------------------+------------------------------------+
<----------------- Total Packet Length = C + 7 octets ------------------>
```

- **Packet Boundary Detection**: Ingress parses packet boundaries directly from the 6-byte CCSDS primary header's Packet Data Length field $C$, yielding total packet size $C + 7$ octets.
- **Defragmentation**: Reassembles Space Packets arriving across fragmented reads delivering one byte at a time into complete individual Space Packets matching sent payloads.
- **Concatenation Separation**: When multiple concatenated Space Packets arrive in a single read buffer, RER separates and yields each packet individually at its declared $C + 7$ byte boundary.
- **Bounded Buffering**: A declared packet length exceeding the configured `max_packet_size` causes the connection to reject the frame and increment `drops_oversized` and `dropped_packets` counters without crashing the relay.

Frames with length exceeding `max_packet_size` are dropped at ingress and tracked under `drops_oversized`. Destination outages trigger automatic reconnection with exponential backoff. Slow TCP readers that stall transmission cause bounded queue saturation and explicit drop policy enforcement without unbounded memory growth.

## 6. Logical Interfaces (`LogicalInterfaceConfig`)

Logical interfaces associate related directional streams, such as command TX and telemetry RX paths (SPEC §6):

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique identifier for the logical interface. |
| `name` | string | No | Optional human-readable interface name. |
| `tx_stream` | string | No* | Stream ID for the transmit/uplink direction. |
| `rx_stream` | string | No* | Stream ID for the receive/downlink direction. |

*Note: A logical interface may contain one direction (`tx_stream` only or `rx_stream` only) or two (`tx_stream` and `rx_stream`). They cannot reference the same stream ID.*

### Pairing as Configuration Context (Not Packet Correlation)

Directional pairing represents an administrative and operator-context relationship, **not** in-band packet correlation (SPEC §6).

- **No Implicit Association**: RER does not assume that received datagrams on an RX stream correlate with a particular command, request, or packet previously sent on a TX stream. In UDP and generic transport forwarding, pairing provides operational context for monitoring and managing related communication paths together.
- **Directional Independence**: Each direction maintains completely independent:
  - **Endpoints and Transports**: TX and RX can use different transports (e.g. TX over TCP, RX over UDP), addresses, and connection modes (`listen` vs. `connect`).
  - **Counters**: Separate `received_packets`, `forwarded_packets`, `dropped_packets`, and byte counters.
  - **Error Accounting**: Destination unreachable errors or socket faults in one direction do not impact or increment error counters in the other direction.
  - **Routing and Queue Bounds**: Each direction has its own bounded queue, capacity, and overload drop policy.
- **Multiple Simultaneous Interfaces**: A single relay instance can host multiple concurrent logical interfaces (paired and single-direction), processing bidirectional traffic simultaneously without cross-talk.
- **Fan-Out Support**: Any stream within an interface or standalone can configure multiple destinations (`destinations`), forwarding datagrams to all endpoints concurrently while isolating destination errors so that a failure at one destination does not halt delivery to the others.

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

## 8. Metrics Endpoint Configuration (`metrics`)

RER supports an optional OpenMetrics / Prometheus HTTP endpoint for metrics scraping.
The metrics endpoint is optional, bound to loopback (`127.0.0.1:9100`) by default, and never required for forwarding.

```yaml
instances:
  - id: "telemetry-relay-1"
    metrics:
      enabled: true
      endpoint: "127.0.0.1:9100"
      path: "/metrics"
```

Configuration fields:
- `enabled`: Whether the metrics HTTP/TCP endpoint is enabled (`true` or `false`).
- `endpoint`: Bind address in `host:port` format. Defaults to `127.0.0.1:9100` (loopback).
- `path`: HTTP request path for scraping. Defaults to `/metrics`.

### OpenMetrics Specification, Metric Names, and Labels

Metrics are exposed in standard OpenMetrics text format (RFC 9457), grouped by metric family, ending with the mandatory `# EOF` terminator.

#### Aggregate and Instance Metrics

| Metric Name | Type | Description | Labels |
|---|---|---|---|
| `rer_uptime_seconds` | gauge | Daemon uptime in seconds | none |
| `rer_healthy` | gauge | Relay health status (1 = healthy, 0 = degraded/unhealthy) | none |
| `rer_received_packets_total` | counter | Total packets received across all streams | none |
| `rer_received_bytes_total` | counter | Total bytes received across all streams | none |
| `rer_forwarded_packets_total` | counter | Total packets forwarded across all streams | none |
| `rer_forwarded_bytes_total` | counter | Total bytes forwarded across all streams | none |
| `rer_dropped_packets_total` | counter | Total packets dropped across all streams | none |
| `rer_socket_errors_total` | counter | Total socket errors encountered across all streams | none |
| `rer_destination_errors_total` | counter | Total destination errors encountered across all streams | none |
| `rer_backpressure_events_total` | counter | Total backpressure events recorded across all streams | none |

#### Per-Stream Metrics

Per-stream metrics carry the `stream` label containing the stream's unique configured identifier:

| Metric Name | Type | Description | Labels |
|---|---|---|---|
| `rer_stream_received_packets_total` | counter | Total packets received on the stream | `stream="<id>"` |
| `rer_stream_received_bytes_total` | counter | Total bytes received on the stream | `stream="<id>"` |
| `rer_stream_forwarded_packets_total` | counter | Total packets forwarded on the stream | `stream="<id>"` |
| `rer_stream_forwarded_bytes_total` | counter | Total bytes forwarded on the stream | `stream="<id>"` |
| `rer_stream_dropped_packets_total` | counter | Total packets dropped on the stream | `stream="<id>"` |
| `rer_stream_drops_queue_full_total` | counter | Total packets dropped due to queue buffer exhaustion | `stream="<id>"` |
| `rer_stream_drops_oversized_total` | counter | Total packets dropped exceeding maximum packet size | `stream="<id>"` |
| `rer_stream_queue_depth` | gauge | Current number of datagrams queued in stream buffer | `stream="<id>"` |
| `rer_stream_destination_errors_total` | counter | Total destination resolution and transmission errors | `stream="<id>"` |
| `rer_stream_socket_errors_total` | counter | Total socket errors encountered for the stream | `stream="<id>"` |
| `rer_stream_backpressure_events_total` | counter | Total backpressure events recorded for the stream | `stream="<id>"` |
| `rer_stream_healthy` | gauge | Whether the stream runner is currently healthy (1) or degraded (0) | `stream="<id>"` |

## 9. Diagnostic Events Management Operation (`events` / `recent_events`)

The management plane provides a read-only diagnostics query operation (`events` or `recent_events`) over the management JSON socket/endpoint to inspect recent diagnostic events:

- **Request**:
  ```json
  {"action": "events", "limit": 100}
  ```
  The `limit` parameter is optional (defaults to 100, clamped to a maximum of 1,000 events).
- **Response**:
  Returns a `DiagnosticEventsReport` containing:
  - `events`: Array of recent structured diagnostic events ordered chronologically (bounded, newest last).
  - `dropped_count` / `dropped_events`: Cumulative count of diagnostic events dropped due to buffer capacity bounds.
  - `mode`: Current operational diagnostic mode (`"production"`, `"debug"`, or `"test"`).
  - `expiry`: Unix timestamp in seconds when test mode expires (or `null`).
  - `expiry_seconds`: Configured test duration in seconds (or `null`).
  - `correlation_id`: Active test run correlation ID (or `null`).
  - `end_reason`: If a test run has terminated, records why (`"duration_expired"`, `"event_limit_reached"`).
- **Access Control**: Classified as `OperationType::ReadOnly`. Unauthenticated or unauthorized callers are refused with an error response.

## 10. Safety and Secret Handling

Sensitive fields (such as `auth_token`) are typed as `SecretString` and are masked as `[REDACTED]` when printing effective configuration via `rer validate --effective` or `rer inspect`. Remote management across network interfaces requires authentication and TLS encryption (SPEC §9, §17).
