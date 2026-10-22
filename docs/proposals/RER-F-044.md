# RER-F-044: SRT Research and Integration Proposal

## Summary

This proposal investigates the Secure Reliable Transport (SRT) protocol specified in [draft-sharabayko-srt-01](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-01), [draft-sharabayko-srt-00](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00), and [The SRT Protocol](https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html). It surveys SRT's 16-byte packet framing (data and control variants), caller-listener and rendezvous handshake sequences, and timer-based retransmission mechanisms, including Timestamp-Based Packet Delivery (TSBPD), periodic and event-driven retransmission (ARQ / NAKs), round-trip time estimation (ACK/ACKACK), and Too-Late Packet Drop (TLPKTDROP). It reviews existing open-source implementations and evaluates their license terms against RER's Apache-2.0 codebase.

In conformance with SPEC §14 guidelines on modular protocol functionality, this proposal outlines a non-intrusive integration strategy for RER:
1. **Passive Ingress SRT Header Inspection and Diagnostics**: An opt-in, zero-allocation inspector for UDP streams that parses fixed 16-byte SRT headers and handshake extension records (such as Stream ID / access control), emitting structured telemetry into RER's non-blocking diagnostic buffer (`crates/rer/src/diagnostics.rs`) while forwarding datagrams unmodified in `crates/rer/src/relay.rs`.
2. **Channel Impairment Harness for SRT Validation**: Utilizing RER's software simulation framework (`crates/rer/src/sim/channel.rs`) to inject deterministic loss, reordering, and jitter between external SRT endpoints (such as `srt-live-transmit`), verifying their recovery and pacing state machines without kernel root privileges.

The proposal explicitly establishes that no full SRT protocol compliance or encryption engine is claimed. The smallest first step consists of an in-tree, zero-dependency SRT header parser wired into `InspectionConfig` in `crates/rer/src/config.rs` and verified against reference test vectors.

## Findings

### SRT Protocol Architecture and Standards

The Secure Reliable Transport (SRT) protocol is an application-level transport protocol developed initially by Haivision and published through the SRT Alliance and the IETF as an open specification for low-latency, reliable media streaming over unpredictable IP networks:
- [draft-sharabayko-srt-01](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-01): *The SRT Protocol* (M. Sharabayko, M. Sharabayko, September 2021). The primary reference specification detailing packet layouts, handshakes, retransmission algorithms, congestion control, and encryption mechanisms.
- [draft-sharabayko-srt-00](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00): *The SRT Protocol* (M. Sharabayko, M. Sharabayko, March 2021). The initial IETF Internet-Draft iteration establishing core wire structures.
- [The SRT Protocol](https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html): Official draft publication maintained by the SRT Alliance and Haivision open-source team.

SRT builds on foundations from the UDP-based Data Transfer (UDT) protocol, redesigning the transport and control loop specifically for live stream contribution:
1. **Unidirectional and Bidirectional UDP Transport**: SRT operates over UDP. While live media data flows predominantly in one direction, SRT maintains a bidirectional control stream on the same UDP socket pair to exchange acknowledgments, retransmission requests, and handshake state.
2. **Socket Multiplexing**: SRT assigns 32-bit Destination Socket IDs, allowing multiple logical connections to share a single UDP port on a listener.
3. **Low-Latency Error Recovery**: Combines immediate and periodic Automatic Repeat reQuest (ARQ) with Timestamp-Based Packet Delivery (TSBPD) to recover lost datagrams within a strictly bounded latency budget.

#### 1. Packet Structure

All SRT packets share a common 16-byte big-endian header placed immediately inside the UDP payload, differentiated by the very first bit (Packet Type Flag `F`):
- Bit 0 (`F`): `0` indicates a Data Packet; `1` indicates a Control Packet.

##### Data Packet Format

When `F = 0`, the 16-byte header represents an SRT Data Packet:
- **Bit 0 (`F`)**: `0` (Data flag).
- **Bits 1..31**: Packet Sequence Number (31-bit modulo $2^{31}$ integer incremented for each consecutive data packet).
- **Bits 32..33 (`PP`)**: Packet Position Flag:
  - `10` (binary): First packet of a multi-packet message.
  - `00` (binary): Middle packet of a multi-packet message.
  - `01` (binary): Last packet of a multi-packet message.
  - `11` (binary): Standalone (entire message contained within a single packet).
- **Bit 34 (`O`)**: In-order Delivery Flag (`1` requires sequential delivery to the application; `0` allows out-of-order delivery).
- **Bits 35..36 (`KK`)**: Key-based Encryption Flag:
  - `00` (binary): Unencrypted packet.
  - `01` (binary): Encrypted with even key.
  - `10` (binary): Encrypted with odd key.
- **Bit 37 (`R`)**: Retransmitted Packet Flag (`0` for initial transmission; `1` for retransmitted packets).
- **Bits 38..63**: Message Number (26-bit sequential identifier grouping consecutive packet fragments).
- **Bits 64..95**: Timestamp (32-bit integer expressing the packet send or origin time in microseconds relative to connection start).
- **Bits 96..127**: Destination Socket ID (32-bit identifier routing the packet to the recipient's internal socket).
- **Byte 16 onwards**: Data Payload (variable length, up to UDP path MTU).

##### Control Packet Format

When `F = 1`, the 16-byte header represents an SRT Control Packet:
- **Bit 0 (`F`)**: `1` (Control flag).
- **Bits 1..15**: Control Type (15-bit integer identifying the control command):
  - `0x0000`: Handshake (`TYPE_HANDSHAKE`).
  - `0x0001`: Keepalive (`TYPE_KEEPALIVE`).
  - `0x0002`: ACK (`TYPE_ACK`, Acknowledgment).
  - `0x0003`: NAK (`TYPE_NAK`, Negative Acknowledgment / Loss Report).
  - `0x0004`: Congestion Warning (`TYPE_CONGESTION`).
  - `0x0005`: Shutdown (`TYPE_SHUTDOWN`).
  - `0x0006`: ACKACK (`TYPE_ACKACK`, Acknowledgment of Acknowledgment).
  - `0x0007`: DropReq (`TYPE_DROPREQ`, Message Drop Request).
  - `0x0008`: PeerError (`TYPE_PEERERROR`).
  - `0x7FFF`: User Defined (`TYPE_USER`).
- **Bits 16..31**: Subtype / Extension / Reserved.
- **Bits 32..63**: Type-specific Information (32-bit field whose semantics depend on Control Type; e.g., ACK sequence number for ACK packets, message number for DropReq).
- **Bits 64..95**: Timestamp (32-bit integer in microseconds relative to connection start).
- **Bits 96..127**: Destination Socket ID (32-bit identifier).
- **Byte 16 onwards**: Control Type Specific Payload.

##### Control Payload Formats

- **Handshake Payload**:
  - `HS Version` (32 bits): Protocol version (`4` for legacy UDT handshake; `5` for SRT handshake extensions).
  - `Encryption Field` (16 bits): Encryption flags and ciphersuite.
  - `Extension Field` (16 bits): Flags indicating supported handshake extensions.
  - `Initial Packet Sequence Number` (32 bits): Starting sequence number for subsequent data packets.
  - `MTU Size` (32 bits): Maximum Transmission Unit in bytes (typically 1500).
  - `Maximum Flow Window Size` (32 bits): Receiver buffer limit in packets.
  - `Handshake Type` (32 bits):
    - `0x00000000`: `DONE` (legacy handshake complete).
    - `0x00000001`: `AGREEMENT` (rendezvous agreement).
    - `0x00000002`: `CONCLUSION` (final handshake exchange).
    - `0x00000003`: `INDUCTION` (initial cookie exchange).
    - `0xFFFFFFFF`: `WAVEAHAND` (rendezvous greeting).
  - `SRT Socket ID` (32 bits): Source SRT socket identifier.
  - `SYN Cookie` (32 bits): Anti-spoofing challenge cookie generated by the listener.
  - `Peer IP Address` (128 bits): Public IP address of the peer as observed by the sender.
  - Optional Handshake Extension Records (Header: 16-bit Extension Type, 16-bit Length in 32-bit words; Payload):
    - `SRT_CMD_HSREQ` / `SRT_CMD_HSRSP` (`0x0001`): SRT Version (32 bits), SRT Flags (32 bits), Receiver TSBPD Delay (16 bits), Sender TSBPD Delay (16 bits).
    - `SRT_CMD_KMREQ` / `SRT_CMD_KMRSP` (`0x0002`): Key Material for AES encryption key exchange.
    - `SRT_CMD_SID` (`0x0003`): Stream ID / access control string (UTF-8, up to 512 bytes).
- **ACK Payload (Full ACK)**:
  - `Last Acknowledged Sequence Number` (32 bits): Sequence number up to which all prior packets have been received.
  - `RTT` (32 bits): Estimated round-trip time in microseconds.
  - `RTT Variance` (32 bits): Variance in RTT in microseconds.
  - `Available Buffer Size` (32 bits): Free space in receiver buffer in packets.
  - `Packet Receiving Rate` (32 bits): Packets received per second.
  - `Estimated Link Capacity` (32 bits): Estimated capacity in packets per second.
  - `Receiving Rate` (32 bits): In bytes per second.
  - `Link Capacity` (32 bits): In bytes per second.
- **ACKACK Payload**:
  - The ACKACK packet has no extra payload; the Type-specific Information field in the 16-byte header carries the ACK Sequence Number being acknowledged.
- **NAK (Loss Report) Payload**:
  - Encodes a list of missing packet sequence numbers as an array of 32-bit words:
    - Single loss entry: Bit 0 is `0`, bits 1..31 contain the single lost sequence number.
    - Range loss entry: Represented as two consecutive 32-bit words. The first word has Bit 0 set to `1` with bits 1..31 denoting the start sequence number; the second word has Bit 0 set to `0` with bits 1..31 denoting the end sequence number (inclusive).

#### 2. Handshake Sequence

SRT supports two primary connection initiation workflows: Caller-Listener and Rendezvous.

##### Caller-Listener Handshake

The standard client-server establishment sequence consists of two round trips (four messages):
1. **Induction Phase**:
   - **Caller -> Listener (`INDUCTION`)**: The caller sends a Handshake packet with `Handshake Type = INDUCTION`, `SRT Socket ID = caller_socket`, `SYN Cookie = 0`, and `Destination Socket ID = 0`.
   - **Listener -> Caller (`INDUCTION`)**: The listener calculates a cryptographic `SYN Cookie` (derived from caller source IP, port, timestamp, and local secret). The listener responds with `Handshake Type = INDUCTION`, `SYN Cookie = calculated_cookie`, and `SRT Socket ID = listener_socket`. No connection state is retained on the listener, preventing SYN-flood resource exhaustion.
2. **Conclusion Phase**:
   - **Caller -> Listener (`CONCLUSION`)**: The caller returns `Handshake Type = CONCLUSION`, the echoed `SYN Cookie`, and attaches Handshake Extension blocks (`SRT_CMD_HSREQ` containing proposed TSBPD latency, SRT version, and flags; and optionally `SRT_CMD_SID` with stream routing identifiers).
   - **Listener -> Caller (`CONCLUSION`)**: The listener verifies the cookie, creates a dedicated socket context, negotiates parameters (setting agreed TSBPD delay to $\max(\text{caller\_delay}, \text{listener\_delay})$), and responds with `Handshake Type = CONCLUSION` and `SRT_CMD_HSRSP`. The connection is established, and data transmission begins.

##### Rendezvous Handshake

Designed for peer-to-peer connectivity across stateful firewalls and NAT gateways where neither endpoint can bind a dedicated public listener:
1. Both peers simultaneously transmit Handshake packets with `Handshake Type = WAVEAHAND` to open outbound NAT bindings.
2. Upon receiving a peer's `WAVEAHAND`, each peer computes a cookie and transmits an `AGREEMENT` or `CONCLUSION` Handshake packet.
3. The peer with the greater socket ID or tie-breaker role confirms the negotiated parameters, synchronizing starting sequence numbers.

#### 3. Timer-Based Retransmission Mechanisms

SRT achieves reliable transmission without head-of-line stalls through tightly synchronized timers and selective retransmission:

1. **Timestamp-Based Packet Delivery (TSBPD)**:
   - Live media packets must be presented to decoders with uniform inter-packet timing. SRT tags every data packet with a 32-bit microsecond timestamp $T_{\text{orig}}$ recorded at transmission.
   - During the conclusion handshake, peers negotiate a fixed buffer latency $T_{\text{latency}}$ (recommended at 3–4 times RTT).
   - The receiver delays forwarding or playout of packet $i$ until delivery time:
     $$T_{\text{deliver}}(i) = T_{\text{orig}}(i) + T_{\text{latency}} + \Delta_{\text{drift}}$$
     where $\Delta_{\text{drift}}$ is the clock drift offset computed by SRT's drift management filter.
   - This fixed latency window provides a deterministic interval during which lost packets can be detected, requested, and retransmitted before their scheduled playout.

2. **Periodic and Event-Driven Retransmission (ARQ / NAKs)**:
   - **Immediate NAK**: When the receiver detects a sequence number discontinuity (e.g., packet 102 arrives directly after 99), it immediately formats and transmits a NAK packet containing the missing sequence span [100, 101]. This avoids waiting for a timer tick when network loss occurs.
   - **Periodic NAK Reports**: The receiver maintains a periodic NAK timer (typically running every 20 ms or scaled to RTT). When the timer expires, any sequence numbers in the receiver's loss list that remain unrecovered are re-emitted in a periodic NAK packet to survive dropped NAKs or retransmitted datagram losses.
   - **Sender Retransmission**: Upon receiving a NAK, the sender retrieves the requested packets from its transmission buffer, sets the Retransmitted Packet Flag (`R = 1`), and retransmits them with priority over fresh data.

3. **Round-Trip Time Estimation (ACK and ACKACK)**:
   - The receiver transmits a full ACK packet periodically (every 10 ms). The ACK contains the highest contiguous sequence number received, current RTT, and link capacity.
   - The sender immediately echoes the ACK sequence number back in a 16-byte `ACKACK` packet.
   - The receiver measures elapsed time between ACK transmission and ACKACK receipt:
     $$\text{RTT}_{\text{sample}} = T_{\text{recv\_ackack}} - T_{\text{send\_ack}}$$
     Updating an exponentially weighted moving average (EWMA) of RTT and RTT variance used to govern retransmission timers and congestion control.

4. **Too-Late Packet Drop (TLPKTDROP)**:
   - If severe network degradation causes a lost packet to remain unrecovered when its scheduled delivery timestamp $T_{\text{deliver}}$ expires, SRT drops the packet from the reassembly buffer rather than stalling stream playback.
   - The receiver advances its delivery sequence number, allowing downstream decoders to process subsequent frames.
   - The sender similarly drops packets from its send buffer if their delivery deadline has elapsed, and emits a `DropReq` (Message Drop Request) control packet so the receiver ceases waiting for those sequence numbers.

### Review of Existing Open-Source SRT Implementations and Licensing

To evaluate software licensing compatibility with RER's Apache-2.0 license, active open-source SRT implementations and tools were reviewed:

1. **Haivision/srt (Reference C/C++ Implementation)**
   - Repository: [Haivision/srt](https://github.com/Haivision/srt)
   - Overview: The official reference implementation developed by Haivision and the SRT Alliance. Provides `libsrt`, sample utilities (`srt-live-transmit`, `srt-file-transmit`), and testing tools. Implements caller, listener, and rendezvous connection modes, multiplexing, AES encryption, LiveCC/FileCC congestion control, and connection bonding.
   - License: Mozilla Public License Version 2.0 (MPL-2.0), verified in the project's [LICENSE](https://raw.githubusercontent.com/Haivision/srt/master/LICENSE).
   - Compatibility Evaluation: MPL-2.0 is a file-level copyleft license. Source code licensed under MPL-2.0 cannot be copied, modified, or merged directly into RER's Apache-2.0 source files. However, running compiled binaries (such as `srt-live-transmit`) as external black-box processes in integration tests or dynamically linking against `libsrt` in separate compilation units does not taint RER's Apache-2.0 license.

2. **russelltg/srt-rs (Rust Implementation)**
   - Repository: [russelltg/srt-rs](https://github.com/russelltg/srt-rs)
   - Overview: A pure Rust implementation of the SRT protocol built on Tokio. Features async packet parsing, connection handshaking, loss reporting, and multiplexing without C dependencies.
   - License: Apache License, Version 2.0 (Apache-2.0), verified in the project's [LICENSE](https://raw.githubusercontent.com/russelltg/srt-rs/master/LICENSE).
   - Compatibility Evaluation: Permissive Apache-2.0 license matches RER. Clean Rust implementation of SRT packet serialization, deserialization, and state machine transitions.

3. **shiguredo/srt-rs (Rust Implementation)**
   - Repository: [shiguredo/srt-rs](https://github.com/shiguredo/srt-rs)
   - Overview: A Rust SRT library developed by Shiguredo Inc., focusing on packet codecs and connection handling for media streaming pipelines.
   - License: Apache License, Version 2.0 (Apache-2.0), verified in the project's [LICENSE](https://raw.githubusercontent.com/shiguredo/srt-rs/master/LICENSE).
   - Compatibility Evaluation: Permissive Apache-2.0 license matches RER.

4. **OpenIRL/srt-live-server (C++ Live Streaming Server)**
   - Repository: [OpenIRL/srt-live-server](https://github.com/OpenIRL/srt-live-server)
   - Overview: An open-source, high-performance SRT live streaming proxy and forwarder based on `libsrt`. Useful for routing MPEG-TS streams over SRT.
   - License: MIT License, verified in the project's [LICENSE](https://raw.githubusercontent.com/OpenIRL/srt-live-server/master/LICENSE).
   - Compatibility Evaluation: Permissive MIT license is compatible with Apache-2.0. Can serve as an external test peer or reference architecture.

5. **Wireshark (SRT Protocol Dissector)**
   - Repository: [wireshark/wireshark](https://github.com/wireshark/wireshark)
   - Overview: Packet analysis suite containing `packet-srt.c`, dissecting SRT data and control packets, handshake extensions, and loss reports.
   - License: GNU General Public License Version 2 (GPL-2.0), verified in the project's [COPYING](https://raw.githubusercontent.com/wireshark/wireshark/master/COPYING).
   - Compatibility Evaluation: GPL-2.0 is copyleft and incompatible with Apache-2.0. No source code from Wireshark may be incorporated into RER. However, PCAP traces generated by Wireshark can serve as independent test vector references.

### Sources checked

- `https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-00`: HTTP 200
- `https://datatracker.ietf.org/doc/html/draft-sharabayko-srt-01`: HTTP 200
- `https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html`: HTTP 200
- `https://github.com/Haivision/srt`: HTTP 200
- `https://raw.githubusercontent.com/Haivision/srt/master/LICENSE`: HTTP 200
- `https://github.com/russelltg/srt-rs`: HTTP 200
- `https://raw.githubusercontent.com/russelltg/srt-rs/master/LICENSE`: HTTP 200
- `https://github.com/shiguredo/srt-rs`: HTTP 200
- `https://raw.githubusercontent.com/shiguredo/srt-rs/master/LICENSE`: HTTP 200
- `https://github.com/OpenIRL/srt-live-server`: HTTP 200
- `https://raw.githubusercontent.com/OpenIRL/srt-live-server/master/LICENSE`: HTTP 200
- `https://github.com/wireshark/wireshark`: HTTP 200
- `https://raw.githubusercontent.com/wireshark/wireshark/master/COPYING`: HTTP 200

## Proposal

### Architectural Approach

In strict alignment with SPEC §14, specialized protocol functionality in RER must remain modular, maintainable, and aligned with RER's core mission: deterministic, unprivileged packet forwarding, fan-out, channel impairment simulation, and non-blocking diagnostics.

Building a complete SRT endpoint inside RER—requiring complex retransmission buffers, TSBPD delay timers, rate pacing algorithms, and AES encryption engines—would duplicate mature external stacks like `libsrt` and bloat RER's low-overhead core.

Instead, RER should adopt a clean, two-pillar modular architecture:
1. **Passive Ingress SRT Packet Inspection and Telemetry**:
   - Ingress UDP packets on configured streams are inspected for SRT header framing.
   - An in-tree, zero-allocation parser examines the first 16 bytes. If `F = 0`, it extracts data packet sequence numbers, message numbers, retransmission flags (`R`), encryption flags (`KK`), timestamps, and destination socket IDs. If `F = 1`, it extracts control types (Handshake, ACK, NAK, ACKACK, DropReq, etc.) and decodes handshake parameters (version, handshake type, source socket ID, and stream ID).
   - Extracted telemetry is pushed into RER's bounded diagnostic event buffer (`crates/rer/src/diagnostics.rs`) without taking locks or blocking the forwarding loop.
   - The datagram is forwarded unmodified to all configured egress destinations.
2. **Channel Simulation Harness for SRT Testing**:
   - Leverage RER's existing simulation framework (`crates/rer/src/sim/channel.rs`) to inject controlled packet loss, jitter, latency, and reordering.
   - This allows RER to act as an impairment proxy between external SRT endpoints (such as `srt-live-transmit`), exercising their ARQ retransmission, TSBPD playout buffering, and TLPKTDROP thresholds in automated CI integration tests without requiring kernel root privileges or `tc-netem`.

### Repository Touchpoints

The proposed integration touches existing, verified RER modules and data structures:

1. **`crates/rer/src/config.rs`**:
   - Extend `InspectionConfig` (which currently manages `hex_preview`, `ascii_preview`, `bpv7`, and `ltp`) with an opt-in `srt` sub-table:
     ```rust
     #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
     #[serde(deny_unknown_fields)]
     pub struct InspectionConfig {
         #[serde(default, alias = "hex")]
         pub hex_preview: bool,
         #[serde(default, alias = "ascii")]
         pub ascii_preview: bool,
         #[serde(default = "default_max_preview_bytes")]
         pub max_preview_bytes: usize,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub bpv7: Option<Bpv7InspectionConfig>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub ltp: Option<LtpInspectionConfig>,
         /// Optional SRT passive inspection configuration (SPEC §14, §8). Defaults to None.
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub srt: Option<SrtInspectionConfig>,
     }
     ```
   - Define `SrtInspectionConfig`:
     ```rust
     #[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
     #[serde(deny_unknown_fields)]
     pub struct SrtInspectionConfig {
         /// Whether SRT inspection is enabled. Defaults to true when srt section is present.
         #[serde(default = "default_true")]
         pub enabled: bool,
         /// Maximum number of bytes to inspect for SRT headers and extensions. Defaults to 512.
         #[serde(default = "default_srt_max_inspect_bytes", alias = "max_inspect")]
         pub max_inspect_bytes: usize,
         /// Whether to extract Stream ID (SID) strings from handshake extension records. Defaults to true.
         #[serde(default = "default_true")]
         pub extract_stream_id: bool,
     }
     ```

2. **`crates/rer/src/diagnostics.rs`**:
   - Add a new variant to `DiagnosticStage`:
     ```rust
     pub enum DiagnosticStage {
         // ... existing stages ...
         /// Secure Reliable Transport (SRT) passive inspection event (SPEC §14, §8).
         #[serde(rename = "srt_inspection")]
         SrtInspection,
     }
     ```
   - Define structured SRT metadata types:
     ```rust
     #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
     #[serde(rename_all = "snake_case")]
     pub enum SrtPacketKind {
         Data,
         Control,
     }

     #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
     #[serde(rename_all = "snake_case")]
     pub enum SrtControlType {
         Handshake,
         Keepalive,
         Ack,
         Nak,
         CongestionWarning,
         Shutdown,
         AckAck,
         DropReq,
         PeerError,
         UserDefined,
         Unknown(u16),
     }

     #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
     pub struct SrtMetadata {
         pub packet_kind: SrtPacketKind,
         pub destination_socket_id: u32,
         pub timestamp_us: u32,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub sequence_number: Option<u32>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub message_number: Option<u32>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub retransmitted: Option<bool>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub encryption_flag: Option<u8>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub control_type: Option<SrtControlType>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub handshake_type: Option<u32>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub srt_socket_id: Option<u32>,
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub stream_id: Option<String>,
     }
     ```
   - Define `SrtInspection` event struct and helper methods on `DiagnosticEvent` (`with_srt_inspection`) and `DiagnosticBuffer` (`emit_srt_inspection`), ensuring that telemetry recording adheres to the bounded non-blocking ring buffer guarantee without allocation overhead on the data path.

3. **`crates/rer/src/relay.rs`**:
   - Mirror the pattern implemented for BPv7 (`process_bpv7_ingress`):
     - Define `SrtIngressContext` holding references to stream configuration, stream ID, and the diagnostic buffer.
     - Implement `process_srt_ingress(payload: &[u8], ctx: &SrtIngressContext<'_>)`:
       - If payload length < 16 bytes, skip inspection.
       - Parse the 16-byte fixed header; decode data fields or control fields.
       - If a Handshake packet contains extension records and `extract_stream_id` is enabled, parse extension blocks up to `max_inspect_bytes` to read the Stream ID string.
       - Emit an `SrtInspection` diagnostic event into the bounded ring buffer.
     - In UDP stream processing loops within `relay_stream`, invoke `process_srt_ingress` when `stream.inspection.srt` is configured.
     - Ensure the forwarded datagram payload remains completely unmodified on egress.

### Smallest First Step (Phase 1)

The smallest viable, owner-judged implementation increment consists of:
1. Create a zero-dependency internal module `crates/rer/src/srt.rs` (or `crates/rer/src/inspection/srt.rs`) providing a zero-allocation parser for the 16-byte fixed SRT header and handshake induction/conclusion structures.
2. Wire `SrtInspectionConfig` into `InspectionConfig` in `crates/rer/src/config.rs`.
3. Add `DiagnosticStage::SrtInspection` and `SrtMetadata` to `crates/rer/src/diagnostics.rs`.
4. Connect the parser to UDP ingress processing in `crates/rer/src/relay.rs`.
5. Implement unit tests in `crates/rer` with reference byte arrays (valid data packet, retransmitted data packet, Handshake Induction packet, ACK packet, and NAK loss report), asserting that malformed, undersized, or truncated datagrams fail safely without panics or relay interruption.

## Not claimed

This research proposal explicitly establishes that:
1. **No full SRT protocol compliance is claimed**: RER does not implement an SRT socket engine, server, client, or protocol compliance test suite conforming to draft-sharabayko-srt.
2. **No encryption engine is claimed**: RER does not implement AES-128 or AES-256 CTR decryption, Key Material (KM) message processing, key wrap algorithms, or passphrase-based key derivation. Encrypted data payloads remain encrypted ciphertext.
3. **No stateful connection or session endpoint is claimed**: RER does not maintain caller, listener, or rendezvous state machines, generate SYN cookies, or manage connection lifecycles.
4. **No retransmission or ARQ engine is claimed**: RER does not maintain packet loss lists, schedule periodic NAK reports, transmit ACKs or ACKACKs, or buffer packets for retransmission.
5. **No TSBPD timing engine or playout buffering is claimed**: RER forwards datagrams immediately and deterministically with minimal relay latency. RER does not reconstruct transmitter cadence, compute clock drift offsets, or buffer packets according to TSBPD latency timestamps.
6. **No rate pacing or congestion control is claimed**: RER does not implement LiveCC or FileCC rate estimation or packet pacing algorithms.
7. **No performance or throughput guarantees are claimed**: No SRT transmission throughput, processing bandwidth, or loss-recovery latency benchmarks are established.

## Open questions

The following architectural and design decisions are reserved for repository owner review and direction:

1. **Stream ID Extraction Scope and Memory Allocation**: Stream ID (SID) strings in SRT Handshake extensions can span up to 512 bytes. Should RER bound stream ID extraction to a fixed-size stack buffer (e.g., 64 bytes) to avoid heap allocation in the packet processing path, or permit dynamic string allocation up to the configured `max_inspect_bytes`?
2. **Configuration Mode vs Heuristic Sniffing**: Standard SRT deployments typically bind port 10000 or arbitrary ephemeral ports. Should SRT inspection require explicit stream configuration (`stream.inspection.srt`), or should RER support optional heuristic detection (e.g. testing bit 0, valid control types, and valid handshake version) on unconfigured UDP streams?
3. **Encrypted Stream Handling and Diagnostics**: When an encrypted SRT data packet is observed (`KK = 01` or `KK = 10`), the 16-byte header remains unencrypted while the payload is encrypted. Should RER's diagnostic event explicitly record an `is_encrypted: true` flag and skip payload inspection, or should inspection behavior remain identical regardless of encryption status?
4. **Channel Impairment WAN Presets**: Should RER introduce predefined CLI impairment profiles (e.g., `--srt-wan-profile` injecting 2% packet loss and 80 ms RTT) in `crates/rer/src/sim/channel.rs` to streamline testing external SRT endpoints under realistic public internet conditions?
5. **Module Organization**: Should the SRT parser be placed at the crate root (`crates/rer/src/srt.rs`), mirroring `bpv7.rs` and `ltp.rs`, or organized under an `inspection` submodule alongside existing protocol parsers?

