# Research Proposal: QUIC Transport Protocol Inspection and Telemetry Integration (RER-F-069)

## Summary

This proposal provides the architectural survey, licensing analysis, and integration design for introducing passive packet inspection, Connection ID extraction, and diagnostic telemetry for the QUIC transport protocol into RER (RER Engineering Relay), fulfilling the research prerequisite for Task RER-F-069 under SPEC §8 and §14.

QUIC is a modern, multiplexed, encrypted transport protocol standardized by the IETF in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) and [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html). Operating entirely over UDP, QUIC establishes authenticated and encrypted transport connections with low latency (0-RTT and 1-RTT connection establishment), eliminates transport-level head-of-line blocking, and provides connection survivability across client IP address and port rebindings via explicit Connection Identifiers (CIDs). It forms the foundational transport layer for HTTP/3 and is increasingly deployed in distributed telemetry, aerospace communications, and edge relay infrastructure.

Currently, RER forwards UDP datagrams and TCP streams across configurable endpoints. For stream and packet telemetry, RER provides protocol-specific parsing, framing, and diagnostic enrichment in `crates/rer/src/framing.rs`, `crates/rer/src/diagnostics.rs`, and `crates/rer/src/relay.rs` for CCSDS Space Packets, MAVLink, MQTT, KISS/AX.25, Bundle Protocol (BPv7), Licklider Transmission Protocol (LTP), and Secure Reliable Transport (SRT). However, RER cannot inspect or report QUIC packet traffic due to key structural limitations:
1. RER treats all UDP streams as opaque byte payloads, reporting only raw datagram lengths without inspecting QUIC packet headers, packet types, protocol versions, or Connection Identifiers.
2. RER's stream configuration (`crates/rer/src/config.rs`) lacks options for QUIC header inspection, Connection ID filtering, or short-header Connection ID length hints.
3. RER's diagnostic engine (`crates/rer/src/diagnostics.rs`) and relay forwarding loops (`crates/rer/src/relay.rs`) have no fields or hooks for reporting QUIC packet forms (Long vs Short), packet types (Initial, 0-RTT, Handshake, Retry, Version Negotiation), Source and Destination Connection IDs, Spin Bit latency indicators, or Key Phase status.

This proposal specifies a modular, zero-dependency in-tree QUIC inspection subsystem for RER. It defines configuration extensions in `crates/rer/src/config.rs`, diagnostic telemetry structures in `crates/rer/src/diagnostics.rs`, and UDP ingress hooks in `crates/rer/src/relay.rs`. It identifies the smallest first implementation step for in-tree QUIC packet header parsing and Connection ID extraction, and explicitly establishes operational boundaries preserving RER's core function as a transparent engineering relay rather than a terminating QUIC endpoint.

## Findings

### Survey of QUIC Transport Protocol Specifications

The IETF standardized the core QUIC transport protocols in May 2021 as a suite of standards:
- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9002: Congestion Control and Loss Recovery](https://www.rfc-editor.org/rfc/rfc9002.html)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)

QUIC operates exclusively over UDP. All QUIC packets begin with a single-octet header flags field, whose most significant bit (bit 7, mask `0x80`) indicates the Header Form: Long Header (`1`) or Short Header (`0`). Conforming RFC 9000 packets must have the Fixed Bit (bit 6, mask `0x40`) set to `1` to prevent confusion with other UDP-based protocols.

#### Long Header Packet Format

Long headers are used during connection establishment, version negotiation, and early data exchange before 1-RTT cryptographic keys are established. Because long headers carry explicit Connection ID lengths and version metadata in unencrypted fields, passive network middleboxes and diagnostic observers can inspect connection establishment without possessing cryptographic keys.

The general structure of an RFC 9000 Long Header packet is:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|1|T T|X X X X|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              Destination Connection ID (0..160)             ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0..160)               ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type-Specific Fields and Encrypted Payload                  ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Header Form Bit (Bit 7)**: Set to `1` for all Long Header packets.
2. **Fixed Bit (Bit 6)**: Fixed at `1` for RFC 9000 packets. Packets where bit 6 is `0` do not conform to RFC 9000 and should be flagged or dropped by compliant parsers.
3. **Long Packet Type (Bits 5..4)**:
   - `0x0` (`00b`): Initial packet (starts the handshake; carries CRYPTO frames).
   - `0x1` (`01b`): 0-RTT packet (carries early application data before handshake completes).
   - `0x2` (`10b`): Handshake packet (completes cryptographic key exchange).
   - `0x3` (`11b`): Retry packet (stateless token challenge from server).
4. **Type-Specific Bits (Bits 3..0)**:
   - For Initial, 0-RTT, and Handshake packets: bits 3..2 are Reserved Bits (must be `00b` in cleartext; protected by header protection), and bits 1..0 indicate the Packet Number Length (`00b` = 1 byte, `01b` = 2 bytes, `10b` = 3 bytes, `11b` = 4 bytes).
   - For Retry packets: bits 3..0 contain unused bits not protected by header protection.
5. **Version Field (Octets 1..4)**: 32-bit big-endian unsigned integer.
   - For QUIC Version 1, the value is `0x00000001`.
   - If the Version field is `0x00000000`, the packet is a **Version Negotiation** packet emitted by a server rejecting an unsupported client version. In Version Negotiation packets, the remaining bytes consist of a list of supported 32-bit version integers.
6. **Destination Connection ID Length (DCIL, Octet 5)**: 8-bit unsigned integer specifying the length in octets of the Destination Connection ID. In QUIC Version 1, this must be between 0 and 20 octets inclusive (values greater than 20 indicate an invalid packet in QUIC v1).
7. **Destination Connection ID (DCID)**: Variable-length byte sequence of `DCIL` octets.
8. **Source Connection ID Length (SCIL)**: 8-bit unsigned integer specifying the length of the Source Connection ID (0 to 20 octets inclusive).
9. **Source Connection ID (SCID)**: Variable-length byte sequence of `SCIL` octets.
10. **Type-Specific Fields**:
    - **Initial Packet**: Contains a variable-length integer **Token Length**, followed by the **Token** bytes, followed by a variable-length integer **Length** (specifying the length of the Packet Number and Payload), followed by the encrypted Packet Number (1..4 octets) and encrypted payload.
    - **Retry Packet**: Contains a **Retry Token** followed by a fixed 16-octet **Retry Integrity Tag** computed over the pseudo-packet using AEAD AES-128-GCM.
    - **Handshake and 0-RTT Packets**: Contain a variable-length integer **Length**, followed by the encrypted Packet Number (1..4 octets) and encrypted payload.

#### Short Header Packet Format (1-RTT)

Once the cryptographic handshake completes, communication transitions entirely to Short Header packets (also known as 1-RTT packets). Short headers minimize packet overhead by stripping connection establishment metadata:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|0|1|S|R R|K|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Destination Connection ID (0..160)           ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Packet Number (8..32)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Protected Payload (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Header Form Bit (Bit 7)**: Set to `0` for Short Header packets.
2. **Fixed Bit (Bit 6)**: Fixed at `1` for RFC 9000 packets.
3. **Spin Bit (Bit 5)**: Latency spin bit (RFC 9000 §17.4). Endpoints flip this bit once per round trip time (RTT). Passive diagnostic observers (such as RER) can monitor state transitions of the spin bit to measure endpoint RTT without decrypting payload traffic.
4. **Reserved Bits (Bits 4..3)**: Must be `00b` prior to header protection.
5. **Key Phase Bit (Bit 2)**: Toggled between `0` and `1` to signal 1-RTT cryptographic key rotation without interrupting transport streams.
6. **Packet Number Length (Bits 1..0)**: 2-bit field indicating the length of the packet number field (`00b` = 1 byte, `01b` = 2 bytes, `10b` = 3 bytes, `11b` = 4 bytes). Protected by header protection.
7. **Destination Connection ID**: Carries the Destination Connection ID. **Critical Design Consideration**: Unlike Long Headers, Short Headers *do not contain a DCID length indicator (DCIL)*. The receiving endpoint knows its expected DCID length from local connection state negotiated during the handshake. For an intermediate observer or relay, parsing Short Header DCIDs requires either stateful observation of the preceding Long Header handshake or an explicit configuration specifying expected DCID length.
8. **Packet Number**: 1 to 4 octets, obfuscated by header protection.
9. **Protected Payload**: AEAD-encrypted user stream frames (STREAM, ACK, PING, etc.).

#### Connection ID Semantics

Connection Identifiers are a defining architectural feature of QUIC (RFC 9000 §5):
- **Decoupling from IP 4-Tuple**: Traditional TCP and UDP connections are identified by the 4-tuple (source IP, source port, destination IP, destination port). If a client changes network interfaces (e.g., transitions from Wi-Fi to cellular) or traverses a NAT whose port mapping changes, TCP connections fail immediately. In QUIC, connections are identified by Connection IDs, allowing active streams to survive client IP address and port rebindings (Path Migration).
- **Asymmetric Allocation**: Each endpoint generates the Connection IDs that its peer must use when transmitting packets to it. The Destination CID in a packet matches an ID chosen by the receiving endpoint.
- **Length Bounds**: CIDs can be between 0 and 20 octets in QUIC Version 1. Zero-length CIDs are permitted when endpoint routing is disambiguated solely by IP address and UDP port.
- **Dynamic Rotation and Privacy**: To prevent passive on-path observers from correlating client mobility across disparate networks, endpoints periodically rotate CIDs using encrypted `NEW_CONNECTION_ID` and `RETIRE_CONNECTION_ID` frames.

#### TLS 1.3 Handshake Encapsulation

QUIC integrates TLS 1.3 as specified in [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) and [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html):
- **Absence of TLS Record Layer**: QUIC does not encapsulate messages within the standard TLS record layer. Instead, standard TLS 1.3 handshake messages (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished) are framed inside QUIC `CRYPTO` frames.
- **Cryptographic Epochs**: Packet encryption progresses through four distinct epochs:
  1. *Initial*: Keyed using HKDF-Extract and HKDF-Expand with an initial secret derived from the client's Destination Connection ID and a publicly known salt (`0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a` for QUIC v1).
  2. *0-RTT*: Keyed using pre-shared resumption keys for early application data.
  3. *Handshake*: Keyed using Diffie-Hellman keys derived from the ClientHello/ServerHello exchange.
  4. *1-RTT (Application)*: Keyed using the final shared master secret for ongoing application communication.
- **Header Protection**: In addition to AEAD payload encryption, QUIC applies header protection to obfuscate the low bits of the header flags byte and the Packet Number field. A sample of the ciphertext (typically 16 bytes taken from the payload) is processed through an AES-ECB or ChaCha20 cipher to generate a 5-byte mask applied via XOR to the packet header. Consequently, passive observers without cryptographic keys cannot inspect packet numbers or short-header flag bits, but can observe the cleartext long-header flags, version, and Connection IDs.

### Review of Existing Open-Source Implementations and Licensing

A review of prominent open-source QUIC protocol implementations was conducted to evaluate reference architectures, code patterns, and license terms for compatibility with RER's Apache-2.0 license:

1. **`quinn` (Rust)**:
   - Repository: [quinn-rs/quinn](https://github.com/quinn-rs/quinn)
   - Scope: The de facto pure-Rust implementation of the IETF QUIC transport protocol, split into `quinn-proto` (deterministic, stateful protocol core with no I/O) and `quinn` (asynchronous runtime integration via Tokio).
   - License: Dual Apache-2.0 / MIT, as verified in [LICENSE-APACHE](https://github.com/quinn-rs/quinn/blob/main/LICENSE-APACHE) and [LICENSE-MIT](https://github.com/quinn-rs/quinn/blob/main/LICENSE-MIT).
   - Compatibility Evaluation: The dual Apache-2.0 / MIT license is fully compatible with RER's Apache-2.0 license. However, importing `quinn-proto` or `quinn` as a dependency would pull in dozens of transitive dependencies (including `rustls`, `ring`, `bytes`, and async utilities), conflicting with RER's zero-dependency synchronous architecture and fast CI gate requirements.

2. **`s2n-quic` (Rust)**:
   - Repository: [aws/s2n-quic](https://github.com/aws/s2n-quic)
   - Scope: AWS's formal-methods-driven, high-performance Rust implementation of the QUIC protocol.
   - License: Apache License, Version 2.0, as verified in the project's [LICENSE](https://github.com/aws/s2n-quic/blob/main/LICENSE) file.
   - Compatibility Evaluation: Apache-2.0 is fully compatible with RER. However, `s2n-quic` is architected for large-scale AWS production infrastructure, requiring specialized cryptographic backends (`s2n-tls` or `aws-lc-rs`), complex build scripts, and async Tokio runtimes. It cannot be integrated into RER without violating the zero-cost build and pure standard-library constraints.

3. **`quiche` (Rust / C)**:
   - Repository: [cloudflare/quiche](https://github.com/cloudflare/quiche)
   - Scope: Cloudflare's implementation of the QUIC transport protocol and HTTP/3, with C and Rust APIs.
   - License: BSD 2-Clause License, as verified in the project's [COPYING](https://github.com/cloudflare/quiche/blob/master/COPYING) file.
   - Compatibility Evaluation: The BSD 2-Clause license is permissive and compatible with Apache-2.0. However, `quiche` links against BoringSSL by default, requiring a C/C++ compiler, CMake, and Perl during compilation. This violates AGENTS.md §1 ("Zero-Cost Constraint") and SPEC §1 ("zero external build toolchain requirements").

4. **`msquic` (C)**:
   - Repository: [microsoft/msquic](https://github.com/microsoft/msquic)
   - Scope: Microsoft's cross-platform, kernel- and user-mode C implementation of QUIC powering Windows and .NET.
   - License: MIT License, as verified in the project's [LICENSE](https://github.com/microsoft/msquic/blob/main/LICENSE) file.
   - Compatibility Evaluation: MIT is permissive and compatible with Apache-2.0. However, `msquic` is written in C, requiring complex platform-specific build configurations, OpenSSL/Schannel linking, and C FFI bindings. It is unsuitable for RER's pure-Rust codebase.

5. **`neqo` (Rust)**:
   - Repository: [mozilla/neqo](https://github.com/mozilla/neqo)
   - Scope: Mozilla's pure-Rust implementation of QUIC and HTTP/3 for Firefox.
   - License: Dual Apache-2.0 / MIT, as verified in [LICENSE-APACHE](https://github.com/mozilla/neqo/blob/main/LICENSE-APACHE) and [LICENSE-MIT](https://github.com/mozilla/neqo/blob/main/LICENSE-MIT).
   - Compatibility Evaluation: Fully compatible license terms. However, `neqo` depends tightly on Mozilla's NSS (Network Security Services) C cryptographic library, requiring complex local system dependencies and build environments.

### Justification for an In-Tree Implementation

All surveyed external QUIC libraries are complete, stateful transport engines that implement full cryptographic termination (TLS 1.3, AEAD, key derivation), stateful congestion control (RFC 9002), and stream multiplexing.

For RER, an external QUIC library is both unnecessary and counterproductive:
1. **Relay Philosophy**: RER is an engineering relay and diagnostic observer (SPEC §5, §8, §14), not a terminating web server or client. RER forwards UDP datagrams transparently while extracting diagnostic metadata.
2. **Zero Dependencies**: Extracting QUIC packet forms, version numbers, packet types, and Connection IDs requires only simple bitmasking, byte slicing, and variable-length integer parsing. An in-tree parser requires zero external crates and adds negligible build time.
3. **Truthfulness and Memory Bounds**: An in-tree parser operates synchronously over existing datagram buffers with zero heap allocation, adhering strictly to RER's bounded-memory and diagnostic truthfulness requirements.

### Sources checked

- [https://www.rfc-editor.org/rfc/rfc9000.html](https://www.rfc-editor.org/rfc/rfc9000.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc9001.html](https://www.rfc-editor.org/rfc/rfc9001.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc9002.html](https://www.rfc-editor.org/rfc/rfc9002.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc8446.html](https://www.rfc-editor.org/rfc/rfc8446.html) — HTTP 200
- [https://github.com/quinn-rs/quinn](https://github.com/quinn-rs/quinn) — HTTP 200
- [https://github.com/quinn-rs/quinn/blob/main/LICENSE-APACHE](https://github.com/quinn-rs/quinn/blob/main/LICENSE-APACHE) — HTTP 200
- [https://github.com/quinn-rs/quinn/blob/main/LICENSE-MIT](https://github.com/quinn-rs/quinn/blob/main/LICENSE-MIT) — HTTP 200
- [https://github.com/aws/s2n-quic](https://github.com/aws/s2n-quic) — HTTP 200
- [https://github.com/aws/s2n-quic/blob/main/LICENSE](https://github.com/aws/s2n-quic/blob/main/LICENSE) — HTTP 200
- [https://github.com/cloudflare/quiche](https://github.com/cloudflare/quiche) — HTTP 200
- [https://github.com/cloudflare/quiche/blob/master/COPYING](https://github.com/cloudflare/quiche/blob/master/COPYING) — HTTP 200
- [https://github.com/microsoft/msquic](https://github.com/microsoft/msquic) — HTTP 200
- [https://github.com/microsoft/msquic/blob/main/LICENSE](https://github.com/microsoft/msquic/blob/main/LICENSE) — HTTP 200
- [https://github.com/mozilla/neqo](https://github.com/mozilla/neqo) — HTTP 200
- [https://github.com/mozilla/neqo/blob/main/LICENSE-APACHE](https://github.com/mozilla/neqo/blob/main/LICENSE-APACHE) — HTTP 200
- [https://github.com/mozilla/neqo/blob/main/LICENSE-MIT](https://github.com/mozilla/neqo/blob/main/LICENSE-MIT) — HTTP 200

## Proposal

### Scope and Supported Capabilities

Under SPEC §8 and §14, RER will introduce a modular, zero-dependency QUIC packet inspection and diagnostic telemetry capability for UDP streams:

1. **QUIC Packet Header Inspection**:
   - Inspect raw UDP datagrams arriving on configured UDP forwarding streams.
   - Discriminate between Long Header packets and Short Header packets using bit 7.
   - Enforce Fixed Bit verification (bit 6 must be `1` for RFC 9000 packets).
   - For Long Headers:
     - Detect Version Negotiation packets (Version `0x00000000`) and extract supported version lists.
     - Extract 32-bit Version identifier (e.g. `0x00000001` for QUIC v1).
     - Decode Long Packet Type: Initial (`0x0`), 0-RTT (`0x1`), Handshake (`0x2`), Retry (`0x3`).
     - Extract Destination Connection ID (DCID) and Source Connection ID (SCID) using cleartext DCIL and SCIL bytes.
     - For Initial packets: decode variable-length Token Length and extract Token bytes.
   - For Short Headers (1-RTT):
     - Extract Spin Bit (bit 5) for passive latency and RTT tracking.
     - Extract Key Phase bit (bit 2) for key rotation monitoring.
     - If configured with an expected DCID length, extract the Short Header DCID.
2. **Ingress Filtering and Policy Routing**:
   - Filter packets by Destination Connection ID or Source Connection ID allowlists (hexadecimal strings).
   - Filter packets by QUIC version allowlists (e.g. permit only `0x00000001`).
   - Filter packets by QUIC packet type allowlists.
   - Configurable `passthrough_on_error` policy: when parsing fails or packets are non-conforming, optionally forward unmodified with diagnostic warnings or drop.
3. **Diagnostic Truthfulness and Telemetry Enrichment (SPEC §8)**:
   - Enrich `DiagnosticEvent` with structured QUIC metadata: packet form, packet type, version, DCID, SCID, spin bit, key phase, and parse status.
   - Accurately maintain processing stages (`DiagnosticStage::Received`, `DiagnosticStage::Accepted`, `DiagnosticStage::Routed`, `DiagnosticStage::Sent`, `DiagnosticStage::Dropped`).

### Proposed Codebase Integration

The proposed integration grounds all modifications directly in existing RER modules:

#### 1. Stream Configuration (`crates/rer/src/config.rs`)

Define `QuicConfig` and add an optional `quic: Option<QuicConfig>` field to `StreamConfig`:

```rust
/// Configuration for QUIC packet inspection and filtering (SPEC §8, §14).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuicConfig {
    /// Enable QUIC packet inspection. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional fixed length in bytes of Destination Connection IDs in Short Header (1-RTT) packets.
    /// Because Short Headers do not self-describe DCID length, this hint enables DCID extraction
    /// from 1-RTT packets when known (e.g. 8 or 16 bytes). Values must be in range 0..=20.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_short_dcid_len: Option<usize>,

    /// Optional allowlist of Connection IDs (as hexadecimal strings) to forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_connection_ids: Option<Vec<String>>,

    /// Optional allowlist of 32-bit QUIC versions to forward (e.g. [1]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_versions: Option<Vec<u32>>,

    /// Optional allowlist of packet types ("initial", "0rtt", "handshake", "retry", "version_negotiation", "short").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_packet_types: Option<Vec<String>>,

    /// Forward datagrams unmodified when QUIC parsing encounters malformed headers. Defaults to false.
    #[serde(default)]
    pub passthrough_on_error: bool,
}
```

Modifications to `crates/rer/src/config.rs`:
- Add `pub quic: Option<QuicConfig>` to `StreamConfig` (line 320, alongside `ccsds`, `mavlink`, `mqtt`, `kiss`).
- In `Config::validate()`:
  - Verify that `fixed_short_dcid_len`, if set, is $\le 20$.
  - Validate that `filter_connection_ids` contains valid hexadecimal strings of length at most 40 characters (20 bytes).
  - Verify that `stream.quic` is only configured when the stream transport is UDP (`source.transport == TransportType::Udp`).

#### 2. Diagnostics Engine (`crates/rer/src/diagnostics.rs`)

Introduce QUIC metadata types, parser evaluations, and `DiagnosticEvent` extensions:

```rust
/// QUIC header form (RFC 9000 §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuicHeaderForm {
    Long,
    Short,
}

/// QUIC packet type (RFC 9000 §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    Short,
}

/// Diagnostic evaluation status for QUIC packet parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuicParseStatus {
    Valid,
    TruncatedHeader,
    InvalidFixedBit,
    InvalidCidLength,
    InvalidVarint,
}

/// Structured QUIC metadata extracted from packet header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuicMetadata {
    pub header_form: QuicHeaderForm,
    pub packet_type: QuicPacketType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spin_bit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_phase: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_len: Option<usize>,
}
```

Extend `DiagnosticEvent` in `crates/rer/src/diagnostics.rs`:
- Add fields:
  ```rust
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub quic_packet_type: Option<QuicPacketType>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub quic_version: Option<u32>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub quic_dcid: Option<String>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub quic_scid: Option<String>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub quic_spin_bit: Option<bool>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub quic_parse_status: Option<QuicParseStatus>,

  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub quic_metadata: Option<QuicMetadata>,
  ```
- Implement builder helper `DiagnosticEvent::with_quic_metadata(mut self, metadata: QuicMetadata) -> Self`.

#### 3. Relay Forwarding Loop (`crates/rer/src/relay.rs`)

Introduce `QuicIngressContext` and `process_quic_ingress()`, analogous to existing functions `process_srt_ingress()` and `process_bpv7_ingress()`:

```rust
struct QuicIngressContext<'a> {
    quic_cfg: Option<&'a QuicConfig>,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

fn process_quic_ingress(payload: &[u8], ctx: &QuicIngressContext<'_>) -> ExtractedQuic {
    let Some(quic_cfg) = ctx.quic_cfg else {
        return ExtractedQuic::default();
    };
    if !quic_cfg.enabled {
        return ExtractedQuic::default();
    }

    match parse_quic_header(payload, quic_cfg.fixed_short_dcid_len) {
        Ok(metadata) => {
            // Apply CID filter, Version filter, Packet Type filter
            // Return ExtractedQuic and enriched DiagnosticEvent
            ...
        }
        Err(err) => {
            // Handle drop or passthrough depending on quic_cfg.passthrough_on_error
            ...
        }
    }
}
```

In `StreamRunner::run_udp_stream()`:
- Call `process_quic_ingress` on incoming datagram payloads.
- If filtering rejects the packet, record the drop in `stats.drops_filtering` and buffer a `DiagnosticStage::Dropped` event.
- If accepted, attach QUIC metadata to the forwarding diagnostic telemetry.

### Smallest First Step

The smallest initial implementation step that can be independently implemented, verified, and merged with complete test evidence is:

1. **In-Tree QUIC Header Parsing Primitives**:
   Implement a standalone, zero-dependency module `crates/rer/src/quic.rs` (or functions in `crates/rer/src/framing.rs`) providing:
   ```rust
   pub fn parse_quic_varint(input: &[u8]) -> Result<(u64, usize), QuicParseError>;
   pub fn parse_quic_header(input: &[u8], fixed_short_dcid_len: Option<usize>) -> Result<QuicMetadata, QuicParseError>;
   pub fn extract_connection_ids(input: &[u8], fixed_short_dcid_len: Option<usize>) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), QuicParseError>;
   ```
2. **Comprehensive Unit Tests**:
   - Long Header Initial packet parsing: verify correct decoding of Version (`0x00000001`), DCIL, DCID, SCIL, SCID, and Token Length varint.
   - Long Header Handshake, 0-RTT, and Retry packet parsing.
   - Version Negotiation packet parsing: verify Version `0x00000000` handling and extraction of offered version arrays.
   - Short Header (1-RTT) parsing: verify Fixed Bit validation, Spin Bit extraction, Key Phase bit extraction, and DCID extraction when `fixed_short_dcid_len` is provided.
   - Boundary and Error rejection tests:
     - Datagrams shorter than 1 byte (empty).
     - Long Header datagrams shorter than 5 bytes (truncated version).
     - Packets with non-conforming Fixed Bit (`first_byte & 0x40 == 0`).
     - Long Headers with DCIL $> 20$ or SCIL $> 20$ under QUIC Version 1.
     - Varint decoding with insufficient trailing bytes.
3. **Execution Evidence**:
   - Ensure `cargo test --all-features --locked` passes cleanly with zero warnings under `cargo clippy`.
   - Adds zero third-party crate dependencies to `Cargo.toml`.

## Not claimed

This proposal and any subsequent implementation of Task RER-F-069 explicitly do NOT claim or establish:
1. **Full QUIC Endpoint Termination**: RER does not terminate QUIC connections as a transport endpoint. It does not maintain client or server connection state machines, does not process or transmit connection control frames (such as `CONNECTION_CLOSE`, `NEW_CONNECTION_ID`, `RETIRE_CONNECTION_ID`, `PATH_CHALLENGE`, or `PATH_RESPONSE`), and does not implement stream multiplexing or flow control (`STREAM_DATA_BLOCKED`, `DATA_BLOCKED`).
2. **TLS Decryption and Cryptographic Termination**: RER does not implement TLS 1.3 cryptographic termination, Diffie-Hellman key exchange, AEAD cipher suites, or payload decryption. RER does not remove header protection from 1-RTT packets or decrypt STREAM frame payloads. User data carried over QUIC remains end-to-end encrypted ciphertext.
3. **Stateful Congestion Control**: RER does not implement stateful transport congestion control algorithms specified in RFC 9002 (such as NewReno, CUBIC, or BBR). It does not maintain congestion windows (`cwnd`), pacing timers, loss recovery state, or smoothed round-trip time (SRTT) filters. RER acts strictly as an unbuffered or bounded-queue packet forwarding relay.
4. **Reliable Stream Reassembly**: RER does not reassemble out-of-order stream offsets across multiple UDP datagrams or track cumulative transport acknowledgments.
5. **Path MTU Discovery (PMTUD)**: RER does not generate or respond to Datagram Packetization Layer PMTU Discovery probes (RFC 8899).
6. **Hard Real-Time Latency Guarantees**: RER does not guarantee deterministic sub-millisecond packet scheduling over non-deterministic operating systems or packet-switched IP networks.

## Open questions

The following architectural questions require owner decision:

1. **Short Header DCID Length Resolution Strategy**:
   Short Header (1-RTT) packets do not encode the length of the Destination Connection ID in their headers. Should RER rely exclusively on an explicit configuration parameter (`fixed_short_dcid_len`), or should RER optionally maintain a short-lived cache of observed DCID lengths snooped from preceding Long Header handshake packets between matching IP/port pairs?
2. **Initial Packet SNI Inspection via Public Salt**:
   Because QUIC Version 1 Initial packets are encrypted using keys derived from a publicly known salt published in RFC 9001 §5.2, middleboxes can technically decrypt Initial packets to inspect the TLS 1.3 ClientHello `server_name` (SNI) extension without possessing server private keys. Should RER strictly avoid all decryption, or would an optional, opt-in `inspect_initial_sni: bool` capability be desirable for diagnostic routing?
3. **Connection ID String Representation**:
   Should Connection IDs in configuration files and diagnostic JSON telemetry be formatted as hexadecimal strings (e.g. `"0x4a7b9c..."` or `"4a7b9c..."`), hyphenated byte hex, or Base64-encoded strings?
4. **Handling Coalesced QUIC Packets**:
   RFC 9000 §12.2 allows multiple QUIC packets (such as an Initial packet and a Handshake packet) to be coalesced into a single UDP datagram. Should RER's initial implementation inspect only the first QUIC packet in each datagram, or parse the variable-length integer `Length` field of Long Headers to iterate through and inspect all coalesced packets within the datagram?
5. **Configuration Hierarchy**:
   Should QUIC inspection settings reside as a top-level field on `StreamConfig` (`stream.quic`, mirroring `stream.srt`, `stream.bpv7`, and `stream.ltp`), or should it be nested under a protocol inspection block?
