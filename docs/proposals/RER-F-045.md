# Research Proposal: MAVLink Protocol Inspection and Framing (RER-F-045)

## Summary

This proposal provides the technical justification, architectural survey, and implementation design for introducing passive MAVLink (Micro Air Vehicle Link) stream inspection, packet framing, and sequence continuity tracking into RER (RER Engineering Relay), fulfilling the research prerequisite for Task RER-F-045 under SPEC §14 and §8.

MAVLink is a lightweight, binary message marshaling protocol widely adopted across unmanned aerial vehicles (UAVs), ground control stations (GCS), autopilots (such as PX4 and ArduPilot), and robotic testbeds. Field telemetry, telecommand links, and hardware-in-the-loop (HIL) simulators transmit MAVLink streams encapsulated in UDP datagrams or continuous TCP byte streams.

Currently, RER provides generic byte-offset sequence tracking and 4-byte length-prefixed TCP framing. However, MAVLink streams exhibit domain-specific networking characteristics that the generic engine cannot handle correctly:
1. MAVLink multiplexes telemetry and commands from multiple systems (`sysid`) and independent subcomponents (`compid`) onto a single transport channel, where each `(sysid, compid)` endpoint pair maintains an independent 8-bit sequence counter. Evaluating a multiplexed MAVLink stream with RER's single-counter sequence tracker produces false packet loss and duplicate alerts.
2. MAVLink operates across two active framing versions: MAVLink 1 (6-byte header, 1-byte message ID) and MAVLink 2 (10-byte header, 3-byte message ID, incompatibility flags, and optional 13-byte cryptographic signature).
3. Over TCP links, standard MAVLink tools expect raw self-delimited MAVLink frames beginning with start-of-text magic bytes (`0xFE` or `0xFD`), rather than RER's default 4-byte big-endian length prefix.

This proposal defines a scoped, zero-dependency in-tree packet header parser and framing module for MAVLink v1 and v2. It establishes per-endpoint sequence tracking, diagnostic event enrichment, length boundary validation, and TCP stream framing. It details safe error handling to discard or pass malformed frames without relay stalls, establishes the smallest first implementation step, and explicitly defines operational boundaries to preserve RER's role as a transparent engineering relay rather than an autopilot controller.

## Findings

### MAVLink Protocol Architecture and Versions

The MAVLink protocol standard and specifications are maintained by the Dronecode Foundation and published in the [MAVLink Protocol Guide](https://mavlink.io/en/) and [MAVLink Serialization Specification](https://mavlink.io/en/guide/serialization.html). An architectural overview is provided in [MAVLink Overview](https://mavlink.io/en/about/overview.html). Version transition rules and packet formats are detailed in [MAVLink Version Differences](https://mavlink.io/en/guide/mavlink_version.html) and [MAVLink Message Signing](https://mavlink.io/en/guide/message_signing.html).

MAVLink messages are marshaled as self-describing, binary-packed frames designed for low-bandwidth point-to-point and point-to-multipoint communication. Two primary wire format versions exist in operational deployment:

#### 1. MAVLink 1 Packet Format

MAVLink 1 is the legacy wire protocol, formalized in the [MAVLink Serialization Specification](https://mavlink.io/en/guide/serialization.html). The binary frame structure consists of:
- **Magic / STX (1 octet, byte 0)**: Protocol start marker. Must be `0xFE`. Receivers identify message beginnings by seeking this marker.
- **Payload Length `len` (1 octet, byte 1)**: Length of the payload field in octets, ranging from 0 to 255.
- **Packet Sequence Number `seq` (1 octet, byte 2)**: 8-bit continuous counter (0 to 255, wrapping modulo 256) used for packet loss detection. Incremented by the sender for each packet transmitted.
- **System ID `sysid` (1 octet, byte 3)**: Identifier of the sending system or vehicle (valid range 1 to 255; 0 is an invalid source address).
- **Component ID `compid` (1 octet, byte 4)**: Identifier of the sending subsystem component within the vehicle (e.g. autopilot, gimbal, camera, onboard computer; valid range 1 to 255).
- **Message ID `msgid` (1 octet, byte 5)**: 8-bit identifier defining the payload message schema (range 0 to 255).
- **Payload Data (variable length, bytes 6 to $5 + \text{len}$)**: Message data fields, serialized according to message definition rules.
- **Checksum / CRC (2 octets, bytes $6 + \text{len}$ to $7 + \text{len}$)**: 16-bit CRC-16/MCRF4XX checksum serialized in little-endian order (low byte first).

The total framing overhead for MAVLink 1 is 8 octets (6 header octets + 2 checksum octets). The minimum packet length is 8 octets (0-length payload), and the maximum packet length is 263 octets ($6 + 255 + 2$).

#### 2. MAVLink 2 Packet Format

MAVLink 2 was introduced to expand message identifier capacity, support message extensions, allow trailing-zero payload truncation, and introduce packet signing. As specified in the [MAVLink Serialization Specification](https://mavlink.io/en/guide/serialization.html):
- **Magic / STX (1 octet, byte 0)**: Protocol start marker. Must be `0xFD`.
- **Payload Length `len` (1 octet, byte 1)**: Length of the following payload section in octets (0 to 255). In MAVLink 2, senders truncate zero-valued trailing bytes to conserve bandwidth.
- **Incompatibility Flags `incompat_flags` (1 octet, byte 2)**: Bitfield flags that must be understood by the receiver to decode or forward the packet. If a receiver encounters an unknown flag bit, it must reject the packet. Flag `0x01` (`MAVLINK_IFLAG_SIGNED`) indicates that a 13-octet cryptographic signature block is appended to the packet.
- **Compatibility Flags `compat_flags` (1 octet, byte 3)**: Bitfield flags indicating optional features (such as priority handling). Receivers may safely process or forward packets even if specific compatibility flag bits are unrecognized.
- **Packet Sequence Number `seq` (1 octet, byte 4)**: 8-bit continuous counter (0 to 255, modulo 256) incremented per transmitted packet.
- **System ID `sysid` (1 octet, byte 5)**: Identifier of the sending vehicle or node (1 to 255).
- **Component ID `compid` (1 octet, byte 6)**: Identifier of the sending component (1 to 255).
- **Message ID `msgid` (3 octets, bytes 7 to 9)**: 24-bit unsigned integer serialized in little-endian byte order (`low | (mid << 8) | (high << 16)`), allowing up to 16,777,216 distinct message schemas.
- **Payload Data (variable length, bytes 10 to $9 + \text{len}$)**: Message payload octets (0 to 255).
- **Checksum / CRC (2 octets, bytes $10 + \text{len}$ to $11 + \text{len}$)**: 16-bit CRC-16/MCRF4XX checksum in little-endian byte order.
- **Optional Signature (13 octets, bytes $12 + \text{len}$ to $24 + \text{len}$)**: Appended only when `incompat_flags & 0x01` is true. As specified in [MAVLink Message Signing](https://mavlink.io/en/guide/message_signing.html), the signature block comprises:
  - `link_id` (1 octet): Communication channel index (0 to 255).
  - `timestamp` (6 octets, 48-bit little-endian integer): Timestamp in microseconds since 2015-01-01 00:00:00 UTC.
  - `signature` (6 octets, 48 bits): Truncated HMAC-SHA256 signature calculated over the entire packet and secret key.

The total framing overhead for MAVLink 2 without signing is 12 octets (10 header octets + 2 checksum octets). With signing enabled, the framing overhead is 25 octets (10 header + 2 checksum + 13 signature octets). The minimum packet length is 12 octets (unsigned with 0 payload), and the maximum packet length is 280 octets ($10 + 255 + 2 + 13$).

### CRC Validation and the CRC_EXTRA Mechanism

The MAVLink integrity check is detailed in the [MAVLink Serialization Specification](https://mavlink.io/en/guide/serialization.html).

1. **Algorithm**: The checksum algorithm is CRC-16/MCRF4XX (ITU X.25 variant), utilizing polynomial `0x1021` ($x^{16} + x^{12} + x^5 + 1$), initial value `0xFFFF`, reflected input and output, and final XOR `0x0000`.
2. **Checksum Scope**: The CRC accumulator processes all octets in the packet starting immediately after the STX magic byte (byte 1) through the final byte of the payload section ($5 + \text{len}$ in v1, $9 + \text{len}$ in v2). The STX byte itself is excluded from the CRC calculation.
3. **`CRC_EXTRA` Seed**: To ensure that the sender and receiver share an identical schema definition for a given message type, an 8-bit `CRC_EXTRA` byte is calculated at code-generation time from the message's XML definition (accumulating the message name, field types, field names, and array sizes in wire order). Before finalizing the 16-bit checksum, the sender accumulates this `CRC_EXTRA` byte into the CRC state.
4. **Implications for Passive Relays**: A passive relay or network harness that forwards arbitrary MAVLink streams cannot calculate or verify the CRC without knowing the specific message definition's `CRC_EXTRA` value. If a stream carries custom or vendor-specific dialects (e.g. custom telemetry messages), a generic relay lacking the dialect XML definitions cannot compute the expected CRC.
   Consequently, passive relay inspection should prioritize header framing boundaries, payload length validation, and sequence tracking. CRC verification should be configurable: disabled by default for generic forwarding, with opt-in verification supported for standard common dialects or via user-configured message-ID-to-CRC lookup tables.

### Deficiencies of Current RER Architecture for MAVLink

Evaluating the existing RER codebase reveals specific structural mismatches when handling MAVLink traffic:

1. **Multiplexed Multi-Endpoint Sequence Disruption**:
   In `crates/rer/src/diagnostics.rs`, RER provides `SequenceTracker`, configured via `crates/rer/src/config.rs::SequenceConfig`. `SequenceTracker` assumes a single monotonic counter per stream.
   In real MAVLink networks, a single UDP port or TCP socket carries multiplexed packets from multiple systems (`sysid`) and components (`compid`)—such as an autopilot (`sysid: 1, compid: 1`), a companion computer (`sysid: 1, compid: 191`), and an optical camera (`sysid: 1, compid: 100`). Each `(sysid, compid)` endpoint increments its own sequence counter (0 to 255).
   When routed through RER's current `SequenceTracker`, interleaving packets from distinct components causes catastrophic false sequence gaps, out-of-order alarms, and duplicate detections, corrupting diagnostic truthfulness (SPEC §8).
2. **Lack of Native MAVLink Stream Framing for TCP**:
   `crates/rer/src/framing.rs` provides `read_frame()` using a 4-octet big-endian length prefix, and `read_ccsds_frame()` using CCSDS primary header lengths.
   Robotic tools (such as QGroundControl, ArduPilot SITL, and MAVProxy) connect over raw TCP sockets where back-to-back packets are framed solely by MAVLink STX markers and internal length fields. RER cannot currently ingest or egress native MAVLink TCP streams without an external proxy or translator.
3. **Inability to Inspect MAVLink Metadata**:
   `crates/rer/src/diagnostics.rs::DiagnosticEvent` currently captures CCSDS (`apid`, `ccsds_sequence`, `ccsds_flags`), BPv7 (`bundle_destination`, `bundle_source`, `dtn_timestamp`), and LTP (`session_originator`, `session_number`), but lacks fields for MAVLink system ID, component ID, sequence count, and 24-bit message ID. Operators monitoring robotic relays cannot view MAVLink packet metrics in diagnostic events or metrics outputs.

### Survey of Existing Open-Source Implementations and Licensing

A survey of open-source MAVLink implementations was conducted to identify reference architectures, framing techniques, and licensing terms:

1. **`mavlink` (C/C++ Reference Implementation and Code Generator)**:
   - Repository: [mavlink/mavlink](https://github.com/mavlink/mavlink)
   - Scope: Reference repository providing XML dialect definitions (`common.xml`, `minimal.xml`, `ardupilotmega.xml`) and the Python code generator (`mavgen`).
   - License: LGPL-3.0 with an MIT exception for generated code, as verified in the project's [COPYING](https://raw.githubusercontent.com/mavlink/mavlink/master/COPYING) file.
   - Relevance to RER: The generator's LGPL-3.0 license is not suitable for direct inclusion in RER's Apache-2.0 codebase. However, generated data tables or cleanroom in-tree parsing implementations are fully compliant with permissive terms.

2. **`rust-mavlink` (Rust Implementation)**:
   - Repository: [mavlink/rust-mavlink](https://github.com/mavlink/rust-mavlink)
   - Scope: Pure Rust implementation providing serialization, deserialization, asynchronous/synchronous connections, and dialect code generation (`mavlink-bindgen`).
   - License: Dual-licensed under the MIT License and Apache License, Version 2.0, as verified in [LICENSE-MIT](https://raw.githubusercontent.com/mavlink/rust-mavlink/master/LICENSE-MIT) and [LICENSE-APACHE](https://raw.githubusercontent.com/mavlink/rust-mavlink/master/LICENSE-APACHE).
   - Relevance to RER: Permissive Apache-2.0 / MIT licensing is fully compatible with RER. However, `rust-mavlink` is a comprehensive SDK with generated dialect structures and external crate dependencies (`crc-any`, `memchr`, `embedded-io`). Pulling in the full crate would violate RER's minimalist zero-cost architecture and increase dependency supply-chain surface.

3. **`mavlink-router` (High-Performance C++ Router)**:
   - Repository: [mavlink-router/mavlink-router](https://github.com/mavlink-router/mavlink-router)
   - Scope: Originally developed by Intel, `mavlink-router` routes MAVLink packets between serial ports, UDP endpoints, and TCP clients without deserializing full message payloads. It inspects only headers to route based on target system/component IDs.
   - License: Apache License, Version 2.0, as verified in [LICENSE](https://raw.githubusercontent.com/mavlink-router/mavlink-router/master/LICENSE).
   - Relevance to RER: Demonstrates that efficient packet routing and framing can be performed solely using header inspection without full dialect decoding, exactly aligning with RER's relay scope.

4. **`MAVSDK` (C++ Client Library and API Server)**:
   - Repository: [mavlink/MAVSDK](https://github.com/mavlink/MAVSDK)
   - Scope: High-level autonomous vehicle control library providing gRPC APIs for mission planning, telemetry subscription, and vehicle control.
   - License: BSD 3-Clause License, as verified in [LICENSE.md](https://raw.githubusercontent.com/mavlink/MAVSDK/main/LICENSE.md).
   - Relevance to RER: Highlights the distinction between high-level autopilot control suites (MAVSDK) and passive transparent network relays (RER). RER explicitly disclaims high-level vehicle control.

5. **`pymavlink` (Python Implementation)**:
   - Repository: [ArduPilot/pymavlink](https://github.com/ArduPilot/pymavlink)
   - Scope: Reference Python implementation used across ArduPilot and MAVProxy for vehicle communication, dialect compilation, and log analysis.
   - License: LGPL-3.0 with MIT exception for generated code, as verified in [COPYING](https://raw.githubusercontent.com/ArduPilot/pymavlink/master/COPYING).
   - Relevance to RER: Useful for cross-verification of framing and CRC calculations in test harnesses.

6. **`mavp2p` (Go Router and Proxy)**:
   - Repository: [bluenviron/mavp2p](https://github.com/bluenviron/mavp2p)
   - Scope: Lightweight router and proxy written in Go, supporting packet fan-out and TCP/UDP/serial bridging.
   - License: MIT License, as verified in [LICENSE](https://raw.githubusercontent.com/bluenviron/mavp2p/main/LICENSE).
   - Relevance to RER: Validates the demand for standalone framing bridges that forward MAVLink packets without modifying telemetry contents.

### Evaluation of In-Tree Implementation

Parsing MAVLink packet headers requires reading at most 10 octets for unsigned packets or 23 octets for signed packets, using safe bit-shifts and standard integer conversion primitives (`u16::from_le_bytes`, `u32::from_le_bytes`). Implementing an in-tree parser requires zero external dependencies, maintains complete compliance with RER's Apache-2.0 license, avoids Cargo dependency bloat, and provides deterministic microsecond execution without runtime allocations.

### Sources checked

- [https://mavlink.io/en/](https://mavlink.io/en/) — HTTP 200
- [https://mavlink.io/en/about/overview.html](https://mavlink.io/en/about/overview.html) — HTTP 200
- [https://mavlink.io/en/guide/serialization.html](https://mavlink.io/en/guide/serialization.html) — HTTP 200
- [https://mavlink.io/en/guide/mavlink_version.html](https://mavlink.io/en/guide/mavlink_version.html) — HTTP 200
- [https://mavlink.io/en/guide/message_signing.html](https://mavlink.io/en/guide/message_signing.html) — HTTP 200
- [https://github.com/mavlink/mavlink](https://github.com/mavlink/mavlink) — HTTP 200
- [https://raw.githubusercontent.com/mavlink/mavlink/master/COPYING](https://raw.githubusercontent.com/mavlink/mavlink/master/COPYING) — HTTP 200
- [https://github.com/mavlink/rust-mavlink](https://github.com/mavlink/rust-mavlink) — HTTP 200
- [https://raw.githubusercontent.com/mavlink/rust-mavlink/master/LICENSE-MIT](https://raw.githubusercontent.com/mavlink/rust-mavlink/master/LICENSE-MIT) — HTTP 200
- [https://raw.githubusercontent.com/mavlink/rust-mavlink/master/LICENSE-APACHE](https://raw.githubusercontent.com/mavlink/rust-mavlink/master/LICENSE-APACHE) — HTTP 200
- [https://github.com/mavlink-router/mavlink-router](https://github.com/mavlink-router/mavlink-router) — HTTP 200
- [https://raw.githubusercontent.com/mavlink-router/mavlink-router/master/LICENSE](https://raw.githubusercontent.com/mavlink-router/mavlink-router/master/LICENSE) — HTTP 200
- [https://github.com/mavlink/MAVSDK](https://github.com/mavlink/MAVSDK) — HTTP 200
- [https://raw.githubusercontent.com/mavlink/MAVSDK/main/LICENSE.md](https://raw.githubusercontent.com/mavlink/MAVSDK/main/LICENSE.md) — HTTP 200
- [https://github.com/ArduPilot/pymavlink](https://github.com/ArduPilot/pymavlink) — HTTP 200
- [https://raw.githubusercontent.com/ArduPilot/pymavlink/master/COPYING](https://raw.githubusercontent.com/ArduPilot/pymavlink/master/COPYING) — HTTP 200
- [https://github.com/bluenviron/mavp2p](https://github.com/bluenviron/mavp2p) — HTTP 200
- [https://raw.githubusercontent.com/bluenviron/mavp2p/main/LICENSE](https://raw.githubusercontent.com/bluenviron/mavp2p/main/LICENSE) — HTTP 200

## Proposal

### Scope and Supported Subset

In accordance with SPEC §14 and §8, RER will implement a modular, self-contained MAVLink header parsing, framing, and sequence tracking capability supporting both MAVLink 1 and MAVLink 2:

1. **Header Identification and Version Detection**:
   - Detects MAVLink 1 start marker `0xFE` (STX) and MAVLink 2 start marker `0xFD` (STX).
   - Rejects or re-synchronizes on unrecognized start markers.
2. **Field Extraction**:
   - Extracts payload length `len` (0 to 255).
   - Extracts packet sequence number `seq` (0 to 255).
   - Extracts system ID `sysid` (1 to 255) and component ID `compid` (1 to 255).
   - Extracts message ID `msgid`: 8-bit in v1 (`0..=255`), 24-bit in v2 (`0..=16,777,215`).
   - In MAVLink 2: extracts `incompat_flags` and `compat_flags`.
3. **Packet Length and Boundary Accounting**:
   - Computes expected total frame size:
     - MAVLink 1: $L = \text{len} + 8$ octets.
     - MAVLink 2 (unsigned, `(incompat_flags & 0x01) == 0`): $L = \text{len} + 12$ octets.
     - MAVLink 2 (signed, `(incompat_flags & 0x01) != 0`): $L = \text{len} + 25$ octets.
   - Validates that received datagrams or buffer lengths match or safely encompass $L$.
4. **Per-Endpoint Sequence Continuity Tracking**:
   - Tracks sequence numbers independently per `(sysid, compid)` endpoint key.
   - Detects sequence gaps (missing packets), duplicate packets, and out-of-order packets wrapping modulo 256.
   - Provides opt-in filtering for specific system IDs and component IDs.
5. **TCP Stream Framing**:
   - Implements native MAVLink TCP framing in `crates/rer/src/framing.rs` (`FramingMode::Mavlink`), enabling ingestion and emission of raw back-to-back MAVLink packets without 4-byte length prefixes.
6. **Diagnostic Reporting**:
   - Enriches `DiagnosticEvent` with MAVLink metadata (`mavlink_system_id`, `mavlink_component_id`, `mavlink_sequence`, `mavlink_message_id`, `mavlink_version`).
   - Emits structured drop and failure events when malformed packets or sequence anomalies occur.

### Proposed Codebase Integration

The proposed integration grounds all modifications directly in existing RER modules:

#### 1. Configuration (`crates/rer/src/config.rs`)

Define a new `MavlinkConfig` structure and integrate it into `StreamConfig` and `FramingMode`:

```rust
/// Configuration for MAVLink packet inspection, validation, and sequence tracking (SPEC §14, §8).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MavlinkConfig {
    /// Enable MAVLink packet inspection and validation. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Enforce valid MAVLink magic start byte (0xFE for v1, 0xFD for v2). Defaults to true.
    #[serde(default = "default_true")]
    pub validate_magic: bool,

    /// Track sequence continuity independently per (sysid, compid) endpoint. Defaults to true.
    #[serde(default = "default_true")]
    pub track_sequences: bool,

    /// Optional allowlist of System IDs (sysid) to accept and track. If None, all are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_systems: Option<Vec<u8>>,

    /// Optional allowlist of Component IDs (compid) to accept and track. If None, all are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_components: Option<Vec<u8>>,

    /// When true, packets failing MAVLink validation are forwarded unchanged. Defaults to false.
    #[serde(default)]
    pub passthrough_on_error: bool,

    /// Optional framing mode override ("length_prefix", "ccsds", or "mavlink").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}
```

In `crates/rer/src/config.rs`:
- Extend `FramingMode` with `Mavlink`:
  ```rust
  pub enum FramingMode {
      LengthPrefix,
      Ccsds,
      Mavlink,
  }
  ```
- Add `#[serde(default, skip_serializing_if = "Option::is_none")] pub mavlink: Option<MavlinkConfig>` to `StreamConfig`.
- In `StreamConfig::source_framing()` and `destination_framing()`, check `mavlink.as_ref().and_then(|m| m.framing)` alongside `ccsds`.
- In `Config::validate()`, verify that if `stream.mavlink` is enabled with `track_sequences: true`, `stream.sequence` is not concurrently active on the same stream to prevent conflicting sequence tracking logic.

#### 2. TCP Stream Framing (`crates/rer/src/framing.rs`)

Introduce native MAVLink TCP framing routines:
- `pub fn read_mavlink_frame<R: Read>(reader: &mut R, max_frame_size: usize, shutdown: &AtomicBool) -> io::Result<Option<Vec<u8>>>`:
  1. Read bytes until finding STX magic byte `0xFD` or `0xFE`.
  2. If `0xFE` (MAVLink 1): read next 5 header octets, extract payload length `len`, calculate total length $L = \text{len} + 8$, and read the remaining $\text{len} + 2$ octets.
  3. If `0xFD` (MAVLink 2): read next 9 header octets, extract `len` and `incompat_flags`. If `(incompat_flags & 0x01) != 0`, total length $L = \text{len} + 25$; otherwise $L = \text{len} + 12$. Read the remaining payload, checksum, and signature octets.
  4. Enforce `max_frame_size` bounds before allocating or reading the full packet.
- `pub fn write_mavlink_frame<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<()>`:
  Directly write the raw packet octets to the TCP stream without a length prefix.
- Update `read_frame_with_mode` and `write_frame_with_mode` to dispatch `FramingMode::Mavlink`.

#### 3. Diagnostics and Multi-Endpoint Sequence Tracking (`crates/rer/src/diagnostics.rs`)

1. **Header Representation and Parser**:
   Define `MavlinkHeader` and `MavlinkParseError`:
   - `version: MavlinkVersion` (`V1` or `V2`)
   - `payload_length: u8`
   - `incompat_flags: u8` (0 for v1)
   - `compat_flags: u8` (0 for v1)
   - `sequence: u8`
   - `system_id: u8`
   - `component_id: u8`
   - `message_id: u32`
   - `is_signed: bool`
   - `total_packet_length: usize`
   Provide pure parser: `pub fn parse_mavlink_header(buf: &[u8]) -> Result<MavlinkHeader, MavlinkParseError>`.
2. **Multi-Endpoint Sequence Tracking**:
   Introduce `MavlinkSequenceTracker`:
   - Maintains `HashMap<(u8, u8), SequenceTracker>` keyed by `(system_id, component_id)`.
   - Each tracker instance operates with `width: 1`, `rollover_threshold: 256`, and modulo 256 arithmetic.
   - Reports per-endpoint sequence continuity, gaps, duplicate packets, and out-of-order deliveries.
3. **Diagnostic Event Enrichment**:
   Extend `DiagnosticEvent` with MAVLink fields:
   - `mavlink_system_id: Option<u8>`
   - `mavlink_component_id: Option<u8>`
   - `mavlink_sequence: Option<u8>`
   - `mavlink_message_id: Option<u32>`
   - `mavlink_version: Option<u8>`
   Add builder methods `with_mavlink_system_id()`, `with_mavlink_component_id()`, `with_mavlink_sequence()`, and `with_mavlink_message_id()`.

#### 4. Relay Forwarding Loop (`crates/rer/src/relay.rs`)

In `StreamRunner::run_stream()`:
- Add `MavlinkIngressContext` and `process_mavlink_ingress()`, patterned after `process_ccsds_ingress()`.
- On datagram or frame receipt:
  1. If `stream.mavlink` is configured and enabled, inspect incoming bytes via `parse_mavlink_header()`.
  2. If header is truncated or malformed:
     - Increment `stats.validation_errors`.
     - If `passthrough_on_error` is false, increment `stats.dropped_packets` and `stats.drops_validation`, emit a `DiagnosticStage::Dropped` event with failure reason, and drop the packet.
  3. If valid:
     - Check system and component ID filter allowlists if configured.
     - If `track_sequences` is active, record header in `MavlinkSequenceTracker`. Emit sequence anomaly events (`DiagnosticStage::Failure` or `DiagnosticStage::HealthTransition`) if gaps or duplicates occur.
     - Enrich forwarding `DiagnosticEvent` with extracted MAVLink metadata.
     - Forward datagram to egress destination connections.
- Expose `MavlinkSequenceTracker` snapshots in `RelayHealthHandle` for health checks and Prometheus metrics.

### Smallest First Step

The smallest initial implementation step that can be independently built, tested, and validated in CI without altering production packet forwarding or breaking backward compatibility is:

1. Implement pure parser logic in a new module `crates/rer/src/mavlink.rs`:
   - Define `MavlinkVersion`, `MavlinkHeader`, and `MavlinkParseError`.
   - Implement `parse_mavlink_header(data: &[u8]) -> Result<MavlinkHeader, MavlinkParseError>`.
2. Add comprehensive unit tests in `crates/rer/src/mavlink.rs` covering:
   - MAVLink 1 valid header: `0xFE`, length, sequence, system ID, component ID, 8-bit message ID.
   - MAVLink 2 valid unsigned header: `0xFD`, length, flags, sequence, system ID, component ID, 24-bit message ID.
   - MAVLink 2 valid signed header: verifying that `incompat_flags & 0x01` correctly computes `total_packet_length == len + 25`.
   - Rejection of invalid magic markers (`0x00`, `0xFF`, `0x42`).
   - Detection of truncated buffers shorter than minimal header lengths (6 octets for v1, 10 octets for v2).
   - Detection of buffers shorter than declared total packet length ($L > \text{data.len()}$).
   - Endianness validation for 24-bit message ID decoding.
3. This step introduces 100% test-covered parsing logic and types with zero external dependencies and zero risk to existing relay operations.

## Not claimed

This proposal and any subsequent implementation of Task RER-F-045 explicitly do NOT claim or establish:
1. **Full MAVLink Protocol Compliance**: RER does not claim full MAVLink protocol compliance. RER does not implement complete message payload decoding across the hundreds of dialect-specific XML message definitions, nor does it generate dialect structures.
2. **Autonomous Vehicle Control**: No autonomous vehicle control, autopilot control commands, waypoint manipulation, mission guidance, navigation, fly-by-wire steering, or failsafe trigger execution is claimed or supported. RER is strictly a transparent communications relay and test harness.
3. **Stateful Autopilot Session Management**: No stateful autopilot session management is claimed. RER does not maintain MAVLink mission transfer transactions, parameter protocol handshakes, FTP transfer sessions, or heartbeat timeout failover state machines.
4. **End-to-End Cryptographic Authentication**: While MAVLink 2 signature presence flags are inspected for frame length calculation, RER does not claim cryptographic verification or generation of HMAC-SHA256 signatures, key management, or replay attack rejection.
5. **Universal Dialect Deserialization**: No parsing or inspection of internal payload fields for vendor-specific dialects (e.g. ArduPilot, PX4, ASLUAV) is claimed beyond header extraction.
6. **Hard Real-Time Latency Guarantees**: No deterministic microsecond latency or hard real-time flight control loop timing guarantees are established prior to empirical benchmarking on target hardware.

## Open questions

The following architectural decisions require review and resolution by the repository owner:

1. **CRC Validation and Dialect Knowledge**:
   Should RER remain strictly a passive framing parser that skips `CRC_EXTRA` validation, or should it optionally embed an in-tree table of `CRC_EXTRA` seeds for standard messages (`minimal.xml` and `common.xml`), or provide a configuration option allowing users to supply an external mapping of `message_id -> crc_extra`?
2. **TCP Stream Resynchronization Policy**:
   When reading a MAVLink stream over TCP (`FramingMode::Mavlink`), if an unexpected byte is received where an STX marker (`0xFD` or `0xFE`) was expected, should the framing reader scan forward byte-by-byte through the stream to recover synchronization, or should it immediately treat the stream as corrupt and close the connection with an `io::ErrorKind::InvalidData` error?
3. **Configuration Placement**:
   Should MAVLink configuration reside directly on `StreamConfig` (`stream.mavlink`, mirroring `stream.ccsds`), or should it be nested inside `stream.inspection.mavlink`?
4. **Signature Verification Capability**:
   If signed MAVLink 2 packets are transmitted through RER, should a future roadmap task introduce secret key configuration in `MavlinkConfig` to cryptographically verify HMAC-SHA256 signatures and emit diagnostic failure events on signature mismatch, or should signature handling permanently remain limited to header length accounting?
