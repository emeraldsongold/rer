# Research Proposal: KISS Framing Protocol and AX.25 Packet Inspection (RER-F-055)

## Summary

This proposal provides the architectural survey, licensing analysis, and implementation design for introducing passive KISS (Keep It Simple, Stupid) stream framing and AX.25 (Amateur X.25) packet inspection into RER (RER Engineering Relay), fulfilling the research prerequisite for Task RER-F-055 under SPEC §14 and §8.

KISS and AX.25 represent foundational communications protocols across amateur packet radio, aerospace testbeds, small satellite missions (CubeSats), high-altitude balloon telemetry, and automated ground station networks. AX.25 provides link-layer packet framing and station addressing using callsigns, while the KISS protocol provides an asynchronous framing layer designed to transport raw link-layer frames across serial connections and TCP/IP networks without requiring full Terminal Node Controller (TNC) firmware stacks. Field ground stations, automated telemetry collectors, and software TNCs (such as Dire Wolf) frequently expose KISS-over-TCP network ports to stream AX.25 telemetry datagrams and APRS (Automatic Packet Reporting System) packets to client applications.

Currently, RER provides generic length-prefixed framing (4-byte big-endian prefix) and CCSDS Space Packet primary-header framing in `crates/rer/src/framing.rs`. However, RER cannot ingest, frame, or inspect KISS and AX.25 streams due to several domain-specific protocol differences:
1. KISS streams rely on special delimiter bytes (`FEND`, `0xC0`) and escape sequences (`FESC`, `0xDB`) rather than length prefixes. RER currently lacks a byte-delimited framing engine capable of framing continuous TCP streams demarcated by FEND delimiters.
2. AX.25 structures station callsigns using bit-shifted 7-octet address fields, variable-length digipeater routing lists, and distinct Control and Protocol Identifier (PID) bytes. RER's current diagnostic engine (`crates/rer/src/diagnostics.rs`) cannot parse or report callsign addresses, frame types (such as Unnumbered Information / UI frames), or network payload types.
3. RER diagnostic events (`DiagnosticEvent`) lack domain-specific fields for KISS port numbers, command types, station callsigns, SSIDs, and frame classifications, limiting observability in aerospace and packet radio test environments.

This proposal specifies a scoped, zero-dependency in-tree KISS framing engine and AX.25 packet header parser for RER. It outlines native TCP stream framing (`FramingMode::Kiss`), robust escape sequence processing, callsign address extraction, PID classification, callsign filtering, and diagnostic event enrichment. It details safe error handling to pass through or drop malformed frames without stalling the relay, identifies the smallest first implementation step for in-tree KISS framing, and explicitly states the operational boundaries that preserve RER's role as a transparent engineering proxy rather than a physical modem or connected-mode link-layer controller.

## Findings

### Survey of the KISS Framing Protocol

The KISS TNC protocol was developed by Mike Chepponis (K3MC) and Phil Karn (KA9Q) and published in [The KISS TNC: A simple Host-to-TNC communications protocol](https://www.ax25.net/kiss.aspx). An analysis of the protocol within packet radio modem architectures is provided in [DCC 2014 Bell 202 and AX.25 Analysis](https://files.tapr.org/meetings/DCC_2014/DCC2014-Amateur-Bell-202-Modem-W6KWF-and-Bridget-Benson.pdf).

The KISS protocol was designed to decouple higher-level protocol software (such as AX.25 and TCP/IP) from the TNC modem hardware. In traditional smart TNCs, the full AX.25 link-layer state machine resided in TNC firmware, limiting flexibility and protocol evolution. KISS reduced the TNC to a synchronous HDLC modem interface that transmits and receives raw frames over an asynchronous host link.

#### Frame Delimitation and Special Bytes

The KISS protocol uses byte-level delimitation derived from SLIP (Serial Line Internet Protocol), defining four special octets:

| Name | Hex Value | Decimal | Description |
| :--- | :--- | :--- | :--- |
| `FEND` (Frame End) | `0xC0` | 192 | Frame delimiter marking frame boundaries |
| `FESC` (Frame Escape) | `0xDB` | 219 | Escape prefix indicating that a following byte is escaped |
| `TFEND` (Transposed Frame End) | `0xDC` | 220 | Escaped representation of the `0xC0` byte |
| `TFESC` (Transposed Frame Escape) | `0xDD` | 221 | Escaped representation of the `0xDB` byte |

The framing mechanism operates as follows:
- **Frame Boundaries**: Every KISS frame is preceded and followed by at least one `FEND` (`0xC0`) byte.
- **Flushing and Noise Rejection**: A leading `FEND` serves to flush any noise or accumulated line garbage into a separate malformed fragment that upper layers discard, preventing line noise from corrupting the beginning of a valid packet. Consecutive `FEND` bytes (such as back-to-back flags) are discarded and never interpreted as empty data frames.
- **Byte Escaping Rules**:
  - If the byte `0xC0` (`FEND`) occurs within the packet payload, it is escaped on transmission as the two-octet sequence `[0xDB, 0xDC]` (`FESC` followed by `TFEND`).
  - If the byte `0xDB` (`FESC`) occurs within the packet payload, it is escaped on transmission as the two-octet sequence `[0xDB, 0xDD]` (`FESC` followed by `TFESC`).
  - On reception, encountering `FESC` (`0xDB`) causes the receiver to inspect the immediate next byte:
    - If `TFEND` (`0xDC`), it emits a literal `0xC0` into the decoded frame buffer.
    - If `TFESC` (`0xDD`), it emits a literal `0xDB` into the decoded frame buffer.
    - If any other byte follows `FESC` (including another `FESC`), an escape violation has occurred, indicating framing corruption or an aborted transmission. The receiver aborts accumulation and discards the frame until the next `FEND`.

#### Command Byte Format

The first octet of an unescaped KISS frame payload (immediately following the opening `FEND`) is the Command / Type byte:
- **Port Nibble (Bits 7..4)**: The high-order four bits select the TNC radio channel or port index (0 to 15) for multi-port TNC hardware.
- **Command Nibble (Bits 3..0)**: The low-order four bits define the command function:
  - `0x00` (**Data Frame**): The remaining octets of the frame contain the encapsulated packet data (e.g., an AX.25 packet minus HDLC framing and CRC).
  - `0x01` (**TXDELAY**): The following octet configures transmitter keyup delay in units of 10 ms (e.g., default value 50 equals 500 ms).
  - `0x02` (**P-persistence**): The following octet configures the channel access persistence parameter $p$, scaled to $0..255$ via $P = p \times 256 - 1$ (default $P = 63$, representing $p = 0.25$).
  - `0x03` (**SlotTime**): The following octet configures the CSMA contention slot interval in units of 10 ms (default 10 equals 100 ms).
  - `0x04` (**TXtail**): The following octet configures the hold time after frame check sequence transmission in units of 10 ms (obsolete, retained for legacy compatibility).
  - `0x05` (**FullDuplex**): The following octet configures duplex mode (0 for half duplex, non-zero for full duplex).
  - `0x06` (**SetHardware**): Specific hardware configuration parameters for custom TNC implementations.
  - `0x0F` / `0xFF` (**Return / Exit KISS**): Directs the TNC to exit KISS mode and return control to the resident command prompt or higher-level firmware.

For frames sent from the TNC to the host, only type 0 (Data Frame) is defined. Host implementations must ignore unsupported command types without crashing or terminating the session.

#### KISS over TCP Networking

In networked ground stations and virtual amateur radio rigs, KISS frames are routed over TCP sockets (commonly referred to as "KISS TCP" or "KISS-over-TCP"), standardized in software modems like Dire Wolf (default TCP port 8001). Over a TCP connection, the byte stream consists of back-to-back KISS-framed packets delimited by `FEND` bytes without any secondary length prefix. A TCP framing implementation must handle packet reassembly across arbitrary TCP segment boundaries, escape decoding, and leading `FEND` synchronization.

### Survey of the AX.25 Link Access Protocol Specification

The AX.25 Link Access Protocol is defined by [TAPR (Tucson Amateur Packet Radio)](https://tapr.org/) in the standard document [AX.25 Link Access Protocol for Amateur Packet Radio Version 2.2](https://www.ax25.net/AX25.2.2-Jul%2098-2.pdf).

AX.25 operates as a data link layer protocol derived from ITU-T X.25 LAPB (Link Access Procedure Balanced), modified for amateur radio multi-access channels, amateur station callsigns, and repeater (digipeater) forwarding.

#### Layer Separation and KISS Encapsulation

On physical RF media (e.g. Bell 202 AFSK at 1200 baud or G3RUH FSK at 9600 baud), AX.25 frames are transmitted as synchronous HDLC frames flanked by opening and closing flags (`0x7E`), zero-bit stuffing (inserting a 0 bit after every five consecutive 1 bits), and a 16-bit Frame Check Sequence (FCS) calculated using the CRC-16-CCITT polynomial ($x^{16} + x^{12} + x^5 + 1$).

When an AX.25 frame is transported across a KISS link, the TNC handles HDLC flag delimitation, zero-bit insertion/deletion, and FCS verification. The KISS Data Frame (`command == 0x00`) contains only the link-layer AX.25 packet: Address Field, Control Field, Protocol Identifier (PID) Field (when present), and Information Field. The HDLC flags and FCS bytes are stripped by the TNC upon reception from RF, and regenerated by the TNC upon transmission to RF.

#### Callsign Address Field Encoding

The AX.25 Address Field contains the station addresses of the destination, source, and optional digipeaters. Every address field has a fixed length of 7 octets:

```text
+-----------------------+-----------------------+-----+-----------------------+
| Destination (7 bytes) | Source (7 bytes)      | ... | Digipeater N (7 bytes)|
+-----------------------+-----------------------+-----+-----------------------+
```

1. **Callsign Octets (Bytes 0..5)**:
   - Contains uppercase alphanumeric ASCII characters (e.g., `W`, `1`, `A`, `W`).
   - If the callsign is shorter than 6 characters, it is right-padded with ASCII space characters (`0x20`).
   - Each character is shifted left by 1 bit (`char << 1`), leaving the least significant bit (LSB) free for HDLC signaling. For example, an ASCII space (`0x20`) is encoded as `0x40`.
2. **SSID Octet (Byte 6)**:
   - Formatted as an 8-bit bitfield:
     ```text
     Bit 7: C / H bit
     Bits 6..5: Reserved bits (fixed at 11)
     Bits 4..1: Secondary Station Identifier (SSID, range 0..15) shifted left by 1
     Bit 0: HDLC Address Extension bit (0 = more addresses follow, 1 = last address)
     ```
   - **Command/Response (C) Bit**: In destination and source addresses (AX.25 v2.0/v2.2), bit 7 denotes whether the packet is a command or a response:
     - For commands: Destination C-bit = 1, Source C-bit = 0.
     - For responses: Destination C-bit = 0, Source C-bit = 1.
   - **Has-Been-Repeated (H) Bit**: In digipeater addresses, bit 7 indicates whether the digipeater has repeated the frame (0 = not yet repeated, 1 = has been repeated).
   - **Extension Bit (Bit 0)**: In all address octets except the final one, bit 0 is cleared (`0`). In the final octet of the entire address field (either the source SSID byte, or the last digipeater SSID byte if repeaters are present), bit 0 is set to `1`.
3. **Address Length Constraints**:
   - The address field must contain at least 14 octets (Destination and Source).
   - AX.25 allows up to 8 digipeater addresses, resulting in a maximum address field length of 70 octets ($2 \times 7 + 8 \times 7$).

#### Control Field Structure

The Control Field follows immediately after the final address octet. In standard modulo-8 operation, it consists of 1 octet:

1. **Information (I) Frames (`bit 0 == 0`)**:
   - Used for sequenced data transfer in connected mode.
   - Bit layout: `N(R) [bits 7..5] | P [bit 4] | N(S) [bits 3..1] | 0 [bit 0]`.
   - $N(S)$ is the transmitter's send sequence count ($0..7$).
   - $N(R)$ is the transmitter's receive sequence count / acknowledgment ($0..7$).
   - $P$ is the Poll bit.
2. **Supervisory (S) Frames (`bits 1..0 == 01`)**:
   - Used for link supervision (flow control and acknowledgments). No Information or PID field is present.
   - Bit layout: `N(R) [bits 7..5] | P/F [bit 4] | S [bits 3..2] | 01 [bits 1..0]`.
   - Types: Receive Ready (RR, `S = 00`), Receive Not Ready (RNR, `S = 01`), Reject (REJ, `S = 10`), Selective Reject (SREJ, `S = 11`).
3. **Unnumbered (U) Frames (`bits 1..0 == 11`)**:
   - Used for link connection management and unacknowledged datagram transfer.
   - Types:
     - **UI (Unnumbered Information)**: Control byte `0x03` ($P=0$) or `0x13` ($P=1$). Carries connectionless broadcast payloads without sequence counters. This is the primary frame type used by APRS, telemetry beacons, and CubeSat downlinks.
     - **SABM (Set Asynchronous Balanced Mode)**: `0x2F` / `0x3F`. Initiates connected mode.
     - **SABME (Set Asynchronous Balanced Mode Extended)**: `0x6F` / `0x7F` (modulo-128 extended mode).
     - **DISC (Disconnect)**: `0x43` / `0x53`. Terminates a connection.
     - **DM (Disconnected Mode)**: `0x0F` / `0x1F`. Reports disconnected status.
     - **UA (Unnumbered Acknowledge)**: `0x63` / `0x73`. Acknowledges connection management commands.
     - **FRMR (Frame Reject)**: `0x87` / `0x97`. Reports invalid frame reception.
     - **XID (Exchange Identification)**: `0xAF` / `0xBF`. Negotiates link parameters.
     - **TEST**: `0xE3` / `0xF3`. Ping / link verification frame.

#### Protocol Identifier (PID) Types

The Protocol Identifier (PID) field is present only in Information (I) and Unnumbered Information (UI) frames, appearing immediately after the Control field. It identifies the layer-3 protocol carried within the Information payload:

| PID Value | Description | Common Usage |
| :--- | :--- | :--- |
| `0xF0` | No layer 3 protocol implemented | APRS, plain text beacons, satellite telemetry |
| `0xCC` | Internet Protocol (IPv4) | Amateur TCP/IP packet networks (AMPRNet / 44-net) |
| `0xCD` | Address Resolution Protocol (ARP) | IP address resolution over packet radio |
| `0xCE` | FlexNet | FlexNet packet routing protocol |
| `0xCF` | NET/ROM | NET/ROM network layer protocol |
| `0x01` | ISO 8208 / CCITT X.25 PLP | Packet Layer Protocol |
| `0x06` | Compressed TCP/IP packet | Van Jacobson header compression |
| `0x07` | Uncompressed TCP/IP packet | Van Jacobson header compression |
| `0x08` | Segmentation fragment | Fragmented packet payloads |
| `0xC3` | TEXNET | TEXNET datagram protocol |
| `0xC4` | Link Quality Protocol | Automated link quality monitoring |
| `0xFF` | Escape character | Extended PID follows in next octet |

For passive relays handling APRS and telemetry, PID `0xF0` is the most prevalent.

### Review of Existing Open-Source Implementations and Licensing

A comprehensive review of open-source KISS and AX.25 implementations was conducted to assess reference framing patterns and evaluate license terms for compatibility with RER's Apache-2.0 license:

1. **`Dire Wolf` (C Software Soundcard TNC)**:
   - Repository: [wb2osz/direwolf](https://github.com/wb2osz/direwolf)
   - Scope: Reference software "soundcard" modem and TNC implementing AX.25, APRS encoding/decoding, and KISS-over-TCP server (port 8001).
   - License: GNU General Public License v2.0 (GPL-2.0), as verified in the project's [LICENSE](https://github.com/wb2osz/direwolf/blob/master/LICENSE) file.
   - Compatibility Evaluation: GPL-2.0 is a strong copyleft license that is incompatible with RER's Apache-2.0 license. No source code from Dire Wolf may be incorporated, vendored, or compiled into RER. However, Dire Wolf serves as an ideal external integration target for black-box loopback testing over TCP.

2. **`ax25-rs` (Rust Implementation)**:
   - Repository: [thombles/ax25-rs](https://github.com/thombles/ax25-rs)
   - Scope: Pure Rust crate for AX.25 v2.0 frame encoding and decoding, coupled with an `ax25_tnc` crate for KISS TNC communication.
   - License: Apache License, Version 2.0, as verified in the project's [LICENSE](https://github.com/thombles/ax25-rs/blob/master/LICENSE) file.
   - Compatibility Evaluation: Apache-2.0 is fully license-compatible with RER. However, `ax25-rs` depends on external helper crates (`bitfield`, `log`) and couples frame parsing to generic I/O traits that do not integrate cleanly with RER's zero-dependency synchronous stream runner, interruptible shutdown model, or diagnostic stage transitions. Reimplementing clean in-tree parsing avoids dependency bloat while adhering to RER's zero-cost architectural guidelines.

3. **`kiss3` (Python KISS Module)**:
   - Repository: [python-aprs/kiss3](https://github.com/python-aprs/kiss3)
   - Scope: Lightweight Python implementation of the KISS framing protocol for serial and TCP TNC interfaces.
   - License: Apache License, Version 2.0, as verified in the project's [LICENSE](https://github.com/python-aprs/kiss3/blob/master/LICENSE) file.
   - Compatibility Evaluation: Apache-2.0 is fully compatible. The library provides an authoritative reference for FEND/FESC unescaping and multi-port command handling.

4. **`wl2k-go` (Go Winlink / AX.25 Toolkit)**:
   - Repository: [la5nta/wl2k-go](https://github.com/la5nta/wl2k-go)
   - Scope: Go package implementing AX.25 packet assembly, KISS serial and TCP drivers, and Winlink client protocols.
   - License: MIT License, as verified in the project's [LICENSE](https://github.com/la5nta/wl2k-go/blob/master/LICENSE) file.
   - Compatibility Evaluation: The MIT License is fully compatible with Apache-2.0. The implementation confirms that separating the asynchronous KISS byte unescaping layer from the link-layer AX.25 frame header parser provides the cleanest modular architecture.

### Deficiencies of Current RER Architecture for KISS and AX.25

Inspecting RER's current codebase indicates specific gaps that prevent processing KISS and AX.25 streams:
1. **TCP Framing (`crates/rer/src/framing.rs`)**: Currently, RER supports only two framing modes: `FramingMode::LengthPrefix` (4-byte length prefix) and `FramingMode::Ccsds` (reading 6 header bytes to compute Space Packet length). It cannot ingest or egress continuous TCP streams delimited by `0xC0` FEND bytes with internal byte unescaping.
2. **Stream Configuration (`crates/rer/src/config.rs`)**: `FramingMode` has no `Kiss` variant, and `StreamConfig` has no `KissConfig` block to specify KISS port filtering, callsign allowlisting, or AX.25 inspection toggles.
3. **Diagnostic Metadata (`crates/rer/src/diagnostics.rs`)**: `DiagnosticEvent` provides fields for CCSDS (`apid`, `ccsds_sequence`), BPv7 (`bundle_destination`, `bundle_source`), and LTP (`session_originator`), but lacks fields for KISS port, command, AX.25 source callsign, destination callsign, SSIDs, frame type, and PID.
4. **Relay Ingress Loop (`crates/rer/src/relay.rs`)**: In `StreamRunner::run_stream()`, RER dispatches CCSDS and BPv7 ingress parsing, but has no hook to inspect incoming KISS datagrams or TCP frames, parse AX.25 headers, or apply callsign filters.

### Justification for an In-Tree Implementation

Implementing KISS framing and AX.25 header inspection directly within RER requires no external dependencies. The core logic consists of straightforward byte scanning, byte-stuffing unescaping, and 7-bit character shifting for callsign decoding. Implementing this in-tree provides:
- Complete compliance with RER's Apache-2.0 licensing.
- Zero added crate dependencies, preserving reproducible, fast builds under `--locked`.
- Deterministic, zero-allocation microsecond execution in the forwarding path.
- Seamless integration with RER's atomic shutdown signaling and diagnostic event bus.

### Sources checked

- [https://www.ax25.net/kiss.aspx](https://www.ax25.net/kiss.aspx) — HTTP 200
- [https://www.ax25.net/AX25.2.2-Jul%2098-2.pdf](https://www.ax25.net/AX25.2.2-Jul%2098-2.pdf) — HTTP 200
- [https://tapr.org/](https://tapr.org/) — HTTP 200
- [https://files.tapr.org/meetings/DCC_2014/DCC2014-Amateur-Bell-202-Modem-W6KWF-and-Bridget-Benson.pdf](https://files.tapr.org/meetings/DCC_2014/DCC2014-Amateur-Bell-202-Modem-W6KWF-and-Bridget-Benson.pdf) — HTTP 200
- [https://github.com/wb2osz/direwolf](https://github.com/wb2osz/direwolf) — HTTP 200
- [https://github.com/wb2osz/direwolf/blob/master/LICENSE](https://github.com/wb2osz/direwolf/blob/master/LICENSE) — HTTP 200
- [https://github.com/thombles/ax25-rs](https://github.com/thombles/ax25-rs) — HTTP 200
- [https://github.com/thombles/ax25-rs/blob/master/LICENSE](https://github.com/thombles/ax25-rs/blob/master/LICENSE) — HTTP 200
- [https://github.com/python-aprs/kiss3](https://github.com/python-aprs/kiss3) — HTTP 200
- [https://github.com/python-aprs/kiss3/blob/master/LICENSE](https://github.com/python-aprs/kiss3/blob/master/LICENSE) — HTTP 200
- [https://github.com/la5nta/wl2k-go](https://github.com/la5nta/wl2k-go) — HTTP 200
- [https://github.com/la5nta/wl2k-go/blob/master/LICENSE](https://github.com/la5nta/wl2k-go/blob/master/LICENSE) — HTTP 200

## Proposal

### Scope and Supported Subset

Under SPEC §14 and §8, RER will introduce modular KISS stream framing and passive AX.25 packet header inspection:

1. **KISS Stream Framing**:
   - Delimit incoming and outgoing TCP byte streams using `FEND` (`0xC0`).
   - Decode escape sequences: `[0xDB, 0xDC]` -> `0xC0`, `[0xDB, 0xDD]` -> `0xDB`.
   - Reject or abort on invalid escape sequences (e.g. `0xDB` followed by an invalid octet).
   - Extract the KISS command byte: port index (`bits 7..4`) and command type (`bits 3..0`).
   - Discard consecutive leading `FEND` bytes without generating zero-length frames.
2. **AX.25 Packet Header Inspection**:
   - Inspect Data frames (`command == 0x00`).
   - Parse destination callsign, destination SSID, and Command/Response bit.
   - Parse source callsign, source SSID, and Command/Response bit.
   - Parse optional digipeater callsigns, SSIDs, and Has-Been-Repeated (H) flags (up to 8 digipeaters).
   - Decode control fields: identify Unnumbered Information (UI), Information (I), and Supervisory (S) frames.
   - Decode Protocol Identifier (PID) in I and UI frames (`0xF0`, `0xCC`, `0xCD`, `0xCF`, etc.).
3. **Filtering and Ingress Validation**:
   - Support optional allowlists for source callsign and destination callsign.
   - Support optional KISS port filtering (e.g. accept only port 0).
   - Configurable error policy via `passthrough_on_error`: forward malformed frames unmodified, or drop them with validation failure diagnostic events.
4. **Diagnostic Event Integration**:
   - Enrich `DiagnosticEvent` with KISS port, command, AX.25 source, destination, frame type, and PID.
   - Record sequence continuity when I-frames are observed with valid send sequence numbers.

### Proposed Codebase Integration

The proposed design grounds all modifications in existing RER modules:

#### 1. Configuration (`crates/rer/src/config.rs`)

Introduce `KissConfig` and extend `FramingMode` and `StreamConfig`:

```rust
/// Configuration for KISS framing and AX.25 packet inspection (SPEC §14, §8).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KissConfig {
    /// Enable KISS packet inspection and framing. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional KISS port filter (0..=15). If set, frames destined for other ports are dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_filter: Option<u8>,

    /// Inspect encapsulated AX.25 packet headers in Data frames. Defaults to true.
    #[serde(default = "default_true")]
    pub inspect_ax25: bool,

    /// Optional allowlist of source callsigns to forward (e.g., ["N0CALL", "W1AW-1"]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_source_callsigns: Option<Vec<String>>,

    /// Optional allowlist of destination callsigns to forward (e.g., ["APRS", "CQ"]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_destination_callsigns: Option<Vec<String>>,

    /// Forward frames unmodified when AX.25 parsing encounters errors. Defaults to false.
    #[serde(default)]
    pub passthrough_on_error: bool,

    /// Framing mode override for TCP endpoints ("length_prefix", "ccsds", or "kiss").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}

impl Default for KissConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port_filter: None,
            inspect_ax25: true,
            filter_source_callsigns: None,
            filter_destination_callsigns: None,
            passthrough_on_error: false,
            framing: None,
        }
    }
}
```

Modifications to `crates/rer/src/config.rs`:
- Extend `FramingMode` with `Kiss`:
  ```rust
  pub enum FramingMode {
      LengthPrefix,
      Ccsds,
      Kiss,
  }
  ```
- Add `#[serde(default, skip_serializing_if = "Option::is_none")] pub kiss: Option<KissConfig>` to `StreamConfig`.
- In `StreamConfig::source_framing()` and `destination_framing()`, check `kiss.as_ref().and_then(|k| k.framing)` alongside `ccsds`.
- In `Config::validate()`, verify that `port_filter`, if set, does not exceed 15, and callsign filter strings match valid AX.25 callsign format (1 to 6 alphanumeric characters with optional `-SSID` suffix $0..15$).

#### 2. TCP Stream Framing (`crates/rer/src/framing.rs`)

Add dedicated KISS framing functions to handle continuous stream input and output:

- `pub fn read_kiss_frame<R: Read>(reader: &mut R, max_frame_size: usize, shutdown: &AtomicBool) -> io::Result<Option<Vec<u8>>>`:
  1. Scan incoming bytes, discarding consecutive `0xC0` (`FEND`) bytes until an opening non-`FEND` byte is encountered.
  2. Accumulate payload bytes into a frame buffer up to `max_frame_size`.
  3. When `0xDB` (`FESC`) is received, read the next byte:
     - If `0xDC` (`TFEND`), append `0xC0`.
     - If `0xDD` (`TFESC`), append `0xDB`.
     - Otherwise, return `io::Error::new(io::ErrorKind::InvalidData, "invalid KISS escape sequence")`.
  4. Stop accumulating upon receiving `0xC0` (`FEND`) and return the unescaped frame buffer.
  5. Check `shutdown.load(Ordering::Relaxed)` between reads to ensure prompt cancellation.
- `pub fn write_kiss_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()>`:
  1. Write opening delimiter `0xC0` (`FEND`).
  2. For each byte in `frame`:
     - If `0xC0`, write `[0xDB, 0xDC]`.
     - If `0xDB`, write `[0xDB, 0xDD]`.
     - Otherwise, write the literal byte.
  3. Write closing delimiter `0xC0` (`FEND`).
- Dispatch `FramingMode::Kiss` in `read_frame_with_mode()` and `write_frame_with_mode()`.

#### 3. Diagnostics and AX.25 Header Parser (`crates/rer/src/diagnostics.rs`)

1. **Pure AX.25 Header Representation and Parser**:
   ```rust
   #[derive(Debug, Clone, PartialEq, Eq)]
   pub struct Ax25Address {
       pub callsign: String,
       pub ssid: u8,
       pub is_command_or_response: Option<bool>,
       pub has_been_repeated: Option<bool>,
   }

   #[derive(Debug, Clone, Copy, PartialEq, Eq)]
   pub enum Ax25FrameType {
       Information,
       Supervisory,
       UnnumberedInformation,
       Sabm,
       Sabme,
       Disconnect,
       DisconnectedMode,
       UnnumberedAcknowledge,
       FrameReject,
       OtherUnnumbered,
   }

   #[derive(Debug, Clone, PartialEq, Eq)]
   pub struct Ax25Header {
       pub destination: Ax25Address,
       pub source: Ax25Address,
       pub digipeaters: Vec<Ax25Address>,
       pub frame_type: Ax25FrameType,
       pub poll_final: bool,
       pub pid: Option<u8>,
       pub send_sequence: Option<u8>,
       pub receive_sequence: Option<u8>,
       pub header_length: usize,
   }
   ```
   Pure parser function: `pub fn parse_ax25_header(payload: &[u8]) -> Result<Ax25Header, Ax25ParseError>`.
   - Validates minimal payload length ($\ge 15$ octets: 7 bytes destination, 7 bytes source, 1 byte control).
   - Unshifts ASCII characters (`byte >> 1`) and extracts SSIDs.
   - Scans digipeater addresses until bit 0 of the SSID byte is 1 (up to 8 digipeaters).
   - Decodes control byte to classify frame type. If I or UI frame, extracts PID byte.

2. **Diagnostic Event Enrichment**:
   Extend `DiagnosticEvent` with KISS and AX.25 fields:
   - `kiss_port: Option<u8>`
   - `kiss_command: Option<u8>`
   - `ax25_source: Option<String>`
   - `ax25_destination: Option<String>`
   - `ax25_frame_type: Option<String>`
   - `ax25_pid: Option<u8>`
   Add corresponding builder methods: `with_kiss_port()`, `with_kiss_command()`, `with_ax25_metadata()`.

#### 4. Forwarding Loop and Validation (`crates/rer/src/relay.rs`)

In `StreamRunner::run_stream()`:
- Introduce `KissIngressContext` and `process_kiss_ingress()`, structured identically to `process_ccsds_ingress()`.
- On packet ingestion:
  1. If `stream.kiss` is enabled:
     - Verify frame has at least 1 byte (the KISS command byte).
     - Extract port (`byte >> 4`) and command (`byte & 0x0F`).
     - Check `port_filter`; if mismatched, drop packet and increment `stats.drops_filtering`.
     - If command is `0x00` (Data) and `inspect_ax25` is true:
       - Invoke `parse_ax25_header(&payload[1..])`.
       - If parsing fails and `passthrough_on_error` is false, increment `stats.drops_validation`, emit a `DiagnosticStage::Dropped` event with the parse error reason, and drop the frame.
       - If parsing succeeds, check `filter_source_callsigns` and `filter_destination_callsigns`. If filtered, drop packet and increment `stats.drops_filtering`.
       - Enrich forwarding `DiagnosticEvent` with KISS and AX.25 metadata.
  2. Forward packet to egress destinations.

### Smallest First Step

The smallest initial implementation step that can be independently developed, reviewed, and merged with complete test evidence is:

1. Implement pure KISS frame encoding and decoding functions in `crates/rer/src/framing.rs` (or a dedicated module `crates/rer/src/kiss.rs`):
   ```rust
   pub fn encode_kiss_frame(port: u8, command: u8, payload: &[u8]) -> Vec<u8>;
   pub fn decode_kiss_frame(raw: &[u8]) -> Result<(u8, u8, Vec<u8>), KissDecodeError>;
   ```
2. Include comprehensive unit tests verifying:
   - Proper framing with leading and trailing `0xC0` (`FEND`) bytes.
   - Escaping of embedded `0xC0` (`-> [0xDB, 0xDC]`) and `0xDB` (`-> [0xDB, 0xDD]`).
   - Symmetrical unescaping during decoding.
   - Proper packing and extraction of port nibble (`port << 4`) and command nibble (`command & 0x0F`).
   - Clean handling of consecutive leading/trailing `FEND` bytes without generating ghost frames.
   - Detection and error return for malformed escape sequences (e.g., `0xDB` followed by an invalid byte or unexpected end-of-buffer).
3. This step delivers tested byte manipulation primitives with zero external dependencies and zero risk to existing relay operations.

## Not claimed

This proposal and any subsequent implementation of Task RER-F-055 explicitly do NOT claim or establish:
1. **Full AX.25 Connected-Mode State Machines**: RER does not implement stateful AX.25 connected-mode link management. RER does not maintain LAPB connection state machines, handle SABM/SABME session establishment, manage DISC/DM disconnect handshakes, process sliding-window acknowledgment buffers, or operate protocol retransmission timers ($T_1$, $T_2$, $T_3$, $T_{100}$). RER acts strictly as a passive proxy and diagnostic observer.
2. **TNC Modem Hardware Control**: RER does not claim TNC modem hardware control or physical serial port management. It does not configure hardware UARTs, manipulate RS-232 control signals (RTS, CTS, DTR), program modem EEPROM registers, or manage physical PTT (Push-To-Talk) keying lines.
3. **Physical-Layer Modulation and Demodulation**: RER does not claim physical-layer audio modulation, demodulation, or digital signal processing (DSP). It does not implement Bell 202 AFSK audio tone synthesis/demodulation at 1200 baud, G3RUH 9600 baud FSK, FX.25 Reed-Solomon forward error correction, or software-defined radio (SDR) interfaces.
4. **Application-Layer APRS Payload Parsing**: While RER extracts AX.25 address fields and identifies UI frames with PID `0xF0`, RER does not decode internal APRS message payloads, decompress Mic-E coordinate vectors, parse weather station telemetry, or validate APRS checksums.
5. **Dynamic RF Digipeater Routing**: RER does not perform dynamic packet-radio mesh routing, digipeater path recalculation, or duplicate suppression across multi-hop RF paths.
6. **Hard Real-Time Latency Guarantees**: RER does not establish deterministic real-time microsecond delivery guarantees over non-deterministic operating systems or packet-switched IP networks.

## Open questions

The following architectural and operational decisions require owner determination:

1. **Non-Data KISS Command Handling**:
   When client applications transmit non-data KISS command frames (e.g. `0x01` TXDELAY, `0x02` P-persistence, `0x03` SlotTime, or `0x06` SetHardware), should RER forward these command frames downstream across TCP/UDP links, drop them to protect remote TNC endpoints from unauthorized reconfiguration, or convert them into diagnostic health events?
2. **Extended Modulo-128 Control Field Support**:
   AX.25 v2.2 introduces 2-octet modulo-128 control fields (SABME). Should RER's initial AX.25 header parser support only standard 1-octet modulo-8 control fields (which encompass the vast majority of UI, telemetry, and APRS traffic), or should it support 2-octet extended control fields from the outset?
3. **Frame Check Sequence (FCS) Verification**:
   Standard KISS host-to-TNC transport strips the 16-bit HDLC CRC-16 FCS upon receipt from RF. However, certain software bridges (such as SMACK or raw HDLC taps) append or retain the 16-bit FCS. Should RER assume standard KISS frames without FCS, or provide a configurable `validate_fcs` option?
4. **Digipeater Path Traversal Depth**:
   AX.25 supports up to 8 digipeater address fields (up to 56 additional octets). Should RER decode and surface all 8 digipeater callsigns in `DiagnosticEvent`, or should diagnostic reporting be limited to the original source and final destination to conserve event serialization bandwidth?
5. **Configuration Hierarchy**:
   Should KISS/AX.25 configuration reside directly under `stream.kiss` at the top level of `StreamConfig` (matching `stream.ccsds`), or should it be grouped under `stream.inspection.kiss`?
