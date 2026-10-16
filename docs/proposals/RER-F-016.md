# Research Proposal: CCSDS Space Packet Parsing Module (RER-F-016)

## Summary

This proposal provides the architectural justification, technical survey, and implementation design for introducing a scoped CCSDS (Consultative Committee for Space Data Systems) Space Packet parsing module into RER (RER Engineering Relay), fulfilling the design prerequisite for Task RER-F-016 under SPEC §14.

RER currently provides byte-offset-based sequence tracking and length-prefixed framing over UDP and TCP. However, aerospace flight systems, testbeds, and ground segments transmit telemetry and telecommand data structured as Space Packets defined by [CCSDS 133.0-B-2](https://ccsds.org/Pubs/133x0b2e2.pdf). The current generic sequence tracker cannot handle CCSDS streams cleanly because CCSDS packet sequence numbers are 14-bit bitfield values packed alongside sequence flags rather than whole-byte integers, and telemetry streams frequently multiplex multiple Application Process Identifiers (APIDs) onto a single transport stream, where each APID maintains an independent sequence count.

This proposal defines a minimal, robust, zero-dependency in-tree parser strictly targeting the 6-octet CCSDS Space Packet Primary Header (APID, sequence flags, packet sequence count, and packet data length). It details safe validation rules to reject malformed packets without relay disruption, outlines integration with RER diagnostics and stream configuration, defines the exact boundaries of what is supported versus unsupported, and establishes the smallest incremental implementation step.

## Findings

### Standard Architecture: CCSDS Space Packet Protocol

The primary standard governing space packet communications is [CCSDS 133.0-B-2 (Space Packet Protocol, Blue Book, Issue 2, June 2020)](https://ccsds.org/Pubs/133x0b2e2.pdf), published as part of the [CCSDS Recommended Standards](https://ccsds.org/publications/bluebooks/).

Under Section 4.1 of [CCSDS 133.0-B-2](https://ccsds.org/Pubs/133x0b2e2.pdf), a Space Packet consists of two contiguous sections:
1. Packet Primary Header (fixed length of 6 octets / 48 bits)
2. Packet Data Field (variable length up to 65,536 octets)

The 6-octet Packet Primary Header is divided into three 16-bit big-endian words:

1. **Packet Identification (16 bits, bits 0–15)**:
   - *Packet Version Number (bits 0–2)*: 3 bits. Identifies the packet protocol version. For CCSDS Space Packets, this field must be binary `000` (Version 1). Any other value indicates an unrecognized or foreign protocol.
   - *Packet Type (bit 3)*: 1 bit. Differentiates telemetry packets (`0`) from telecommand packets (`1`).
   - *Secondary Header Flag (bit 4)*: 1 bit. Indicates presence (`1`) or absence (`0`) of an optional secondary header in the Packet Data Field.
   - *Application Process Identifier (APID, bits 5–15)*: 11 bits. Identifies the sending or receiving onboard application process (values 0 to 2047 / `0x000` to `0x7FF`). The value 2047 (`0x7FF`, all ones) is reserved across CCSDS missions for idle/fill packets used to maintain channel synchronization.

2. **Packet Sequence Control (16 bits, bits 16–31)**:
   - *Sequence Flags / Grouping Flags (bits 16–17)*: 2 bits. Indicates whether the user data is segmented across packets:
     - `00` (binary): Continuation segment of fragmented data.
     - `01` (binary): First segment of fragmented data.
     - `10` (binary): Last segment of fragmented data.
     - `11` (binary): Unsegmented user data (standalone packet).
   - *Packet Sequence Count (bits 18–31)*: 14 bits. A continuous binary counter (0 to 16,383, modulus 16,384) tracking sequence progression. Per [CCSDS 133.0-B-2](https://ccsds.org/Pubs/133x0b2e2.pdf), this sequence count is maintained independently for each APID.

3. **Packet Data Length (16 bits, bits 32–47)**:
   - A 16-bit unsigned big-endian integer $C$.
   - The value $C$ is defined as $(L_{data} - 1)$, where $L_{data}$ is the total number of octets in the Packet Data Field (including any optional secondary header and user payload).
   - Because $C$ is an offset from 1 octet, $L_{data} = C + 1$, spanning 1 to 65,536 octets.
   - The total Space Packet length $L_{total}$ (including the 6-octet primary header) is $L_{total} = C + 7$ octets, yielding a valid total packet size between 7 and 65,542 octets.

### Justification and Deficiencies of Current RER Architecture

RER currently implements sequence tracking and packet inspection in `crates/rer/src/diagnostics.rs`, configured through `crates/rer/src/config.rs::SequenceConfig`. While effective for generic fixed-offset headers, this existing mechanism suffers from key technical mismatches when handling CCSDS packet streams:

1. **Non-Byte-Aligned Bitfield Packing**:
   `SequenceConfig` only extracts whole-byte sequences (`width: 1, 2, 4, 8`) at byte offsets. In CCSDS, the Packet Sequence Count is a 14-bit field occupying bits 18–31 of the header (bits 2–15 of the sequence control word). If configured to read a 2-byte field at byte offset 2, the tracker includes the 2-bit sequence flags in the highest-order bits. Whenever packets alternate between unsegmented packets (flags `11` = `0xC000`) and segmented packets (flags `01` = `0x4000`), the sequence tracker detects catastrophic false gaps and out-of-order jumps, corrupting continuity metrics.

2. **Lack of Per-APID Multiplexing Support**:
   In space missions, an onboard telemetry bus or ground-link multiplexes packets from dozens of independent instruments, subsystems, and thermal sensors across different APIDs onto a single UDP port or TCP connection. Each APID possesses its own separate sequence counter running from 0 to 16,383. RER's `SequenceTracker` currently maintains only a single sequential counter state per forwarding stream. Passing a multiplexed stream through `SequenceTracker` produces constant false packet loss and duplicate alerts.

3. **Length and Boundary Validation Deficits**:
   RER receives datagrams via UDP or framed streams via TCP (using a 4-byte big-endian length prefix in `crates/rer/src/framing.rs`). For UDP datagrams containing Space Packets, RER currently forwards payloads without validating that the received byte count matches the length declared in the CCSDS primary header. If a truncated packet is received, or if a malformed packet specifies a length exceeding the datagram or buffer, downstream mission systems receive corrupted frames. Validating $L_{total} == \text{received\_len}$ (or $L_{total} \le \text{received\_len}$ in concatenated streams) rejects malformed or corrupted packets at ingress.

### Survey of Existing Rust Implementations and Licensing

Several open-source Rust crates implement CCSDS space packet parsing:

1. **`spacepackets-rs`**:
   - Repository: [spacepackets-rs Repository](https://github.com/us-irs/spacepackets-rs)
   - License: [Apache License 2.0](https://raw.githubusercontent.com/us-irs/spacepackets-rs/main/LICENSE-APACHE)
   - Scope: Developed by the Institute of Space Systems (IRS) at the University of Stuttgart. Implements CCSDS 133.0-B-2 Space Packets, ECSS PUS (Packet Utilization Standard ECSS-E-ST-70-41C), and CFDP. While mature and `no_std` compatible, it contains extensive features, PUS structures, and dependencies that exceed RER's narrow relay scope.

2. **`ccsds-spacepacket`**:
   - Repository: [ccsds-spacepacket Repository](https://github.com/KubOS-Preservation-Group/ccsds-spacepacket)
   - License: [Apache License 2.0](https://raw.githubusercontent.com/KubOS-Preservation-Group/ccsds-spacepacket/master/LICENSE)
   - Scope: Created by KubOS for satellite flight software. Provides parsing for the 6-byte primary header and hooks for secondary headers. However, the repository is unmaintained / preserved and carries external traits.

3. **In-Tree Zero-Dependency Implementation Evaluation**:
   The CCSDS Space Packet primary header is fixed at exactly 6 octets. Parsing and validating these 48 bits in safe Rust requires fewer than 150 lines of code using core standard library primitives (`u16::from_be_bytes`). Adding external dependencies would increase supply chain surface, introduce potential dependency conflicts with RER's strict `Cargo.lock` policy, and violate the minimalist design outlined in SPEC §14. Therefore, an in-tree module is technically superior, fully auditable, and self-contained.

### Sources checked

- [https://ccsds.org/Pubs/133x0b2e2.pdf](https://ccsds.org/Pubs/133x0b2e2.pdf) — HTTP 200
- [https://ccsds.org/publications/bluebooks/](https://ccsds.org/publications/bluebooks/) — HTTP 200
- [https://github.com/us-irs/spacepackets-rs](https://github.com/us-irs/spacepackets-rs) — HTTP 200
- [https://raw.githubusercontent.com/us-irs/spacepackets-rs/main/LICENSE-APACHE](https://raw.githubusercontent.com/us-irs/spacepackets-rs/main/LICENSE-APACHE) — HTTP 200
- [https://github.com/KubOS-Preservation-Group/ccsds-spacepacket](https://github.com/KubOS-Preservation-Group/ccsds-spacepacket) — HTTP 200
- [https://raw.githubusercontent.com/KubOS-Preservation-Group/ccsds-spacepacket/master/LICENSE](https://raw.githubusercontent.com/KubOS-Preservation-Group/ccsds-spacepacket/master/LICENSE) — HTTP 200

## Proposal

### Scope and Supported Subset

In accordance with SPEC §14 ("Start with limited, explicitly documented parsing where appropriate"), RER will implement a modular, self-contained parser supporting strictly the CCSDS Space Packet Primary Header:

1. **Header Size**: Exactly 6 octets.
2. **Packet Version Number**: Validates that bits 0–2 equal `0b000`. Rejects any packet where version $\ne 0$.
3. **Packet Type**: Parses telemetry (`0`) vs telecommand (`1`).
4. **Secondary Header Flag**: Parses presence flag (`0` or `1`).
5. **Application Process Identifier (APID)**: Parses 11-bit value (0–2047). Provides opt-in filtering for specific APIDs and optional exclusion of idle packets (APID 2047).
6. **Sequence Flags**: Extracts 2-bit segmentation grouping (`00`, `01`, `10`, `11`).
7. **Packet Sequence Count**: Extracts 14-bit sequence counter (0–16,383). Implements per-APID continuity tracking with modulus 16,384 ($2^{14}$).
8. **Packet Data Length**: Decodes 16-bit integer $C$ into expected total packet length $L_{total} = C + 7$. Validates that received buffer length matches or safely contains this length, rejecting truncated or oversized packets.

### Proposed Codebase Integration

The proposal grounds all changes in existing RER modules without adding external dependencies:

#### 1. Configuration (`crates/rer/src/config.rs`)
Add a new `CcsdsConfig` struct and integrate it into `StreamConfig`:

```rust
/// Configuration for CCSDS Space Packet inspection and validation (SPEC §14).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CcsdsConfig {
    /// Enable CCSDS primary header parsing and validation. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Enforce Packet Version Number == 0. Defaults to true.
    #[serde(default = "default_true")]
    pub validate_version: bool,

    /// Validate that datagram size matches Packet Data Length + 7. Defaults to true.
    #[serde(default = "default_true")]
    pub validate_length: bool,

    /// Track sequence continuity independently per APID. Defaults to true.
    #[serde(default = "default_true")]
    pub track_sequences: bool,

    /// Optional allowlist of APIDs to accept/track. If None, all APIDs are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_apids: Option<Vec<u16>>,

    /// Exclude idle packets (APID 2047 / 0x7FF) from sequence tracking and gap alerts. Defaults to true.
    #[serde(default = "default_true")]
    pub ignore_idle_apid: bool,
}
```

In `StreamConfig`:
- Add field `#[serde(default, skip_serializing_if = "Option::is_none")] pub ccsds: Option<CcsdsConfig>`.
- In `Config::validate()`, verify that if `stream.ccsds` is enabled with `track_sequences: true`, `stream.sequence` is either not specified or marked `enabled: false` to prevent duplicate/conflicting sequence tracking engines running concurrently on the same stream.

#### 2. Diagnostics and Sequence Tracking (`crates/rer/src/diagnostics.rs`)
1. **Primary Header Representation**:
   Define `CcsdsPrimaryHeader`:
   - `version: u8` (3 bits)
   - `packet_type: u8` (1 bit: 0=TM, 1=TC)
   - `secondary_header_flag: bool` (1 bit)
   - `apid: u16` (11 bits, 0..=2047)
   - `sequence_flags: u8` (2 bits, 0..=3)
   - `sequence_count: u16` (14 bits, 0..=16383)
   - `packet_data_length: u16` (raw 16-bit field)
   - `total_packet_length: usize` (`packet_data_length as usize + 7`)

2. **Parser and Safe Error Rejection**:
   Provide `parse_ccsds_primary_header(payload: &[u8]) -> Result<CcsdsPrimaryHeader, CcsdsParseError>`.
   `CcsdsParseError` safely identifies:
   - `TruncatedHeader`: buffer length $< 6$ bytes.
   - `InvalidVersion(u8)`: packet version number $\ne 0$.
   - `LengthMismatch { declared: usize, actual: usize }`: datagram length is less than declared $C + 7$ octets.
   - `LengthExceedsBuffer { declared: usize, limit: usize }`: declared length exceeds configured maximum packet/buffer size.

3. **Multi-APID Sequence Tracking**:
   Introduce `CcsdsSequenceTracker` (or map inside `SequenceTracker`):
   - Stores `HashMap<u16, SequenceTracker>` where each entry is initialized with `width: 2`, `rollover_threshold: 16384`.
   - Tracks packet count, gap count, duplicate count, and out-of-order count per APID.
   - Ignores APID 2047 if `ignore_idle_apid` is enabled.

4. **Diagnostic Event Enrichment**:
   Extend `DiagnosticEvent` with optional fields:
   - `apid: Option<u16>`
   - `ccsds_sequence: Option<u16>`
   - `ccsds_flags: Option<u8>`
   When a malformed packet is received, emit a `DiagnosticStage::Dropped` or `DiagnosticStage::Failure` event detailing the exact `CcsdsParseError` without panicking.

#### 3. Relay Forwarding Loop (`crates/rer/src/relay.rs`)
In `StreamRunner::run_stream()`:
- When `stream.ccsds` is configured:
  1. Inspect the incoming datagram using `parse_ccsds_primary_header()`.
  2. If parsing fails or length/version validation fails:
     - Increment `stream.stats.packets_dropped` and appropriate failure counter.
     - Emit diagnostic drop event with the failure reason.
     - Safely drop the packet and continue loop execution.
  3. If valid:
     - If `track_sequences` is active, update the APID tracker.
     - Proceed to queue or forward packet to egress destination endpoints.

#### 4. Documentation (`docs/CONFIGURATION.md` and `docs/SPEC.md`)
- Document the `ccsds` stream configuration block in `docs/CONFIGURATION.md`.
- Explicitly document that RER parses only the 6-byte Primary Header and provides per-APID sequence continuity and length verification.
- Add an explicit disclaimer: "RER does not claim full CCSDS compatibility, conformance testing, or support for transfer frames, secondary headers, or higher-level space protocols."

### Smallest First Step

The smallest initial implementation step that can be independently built, tested, and validated in CI without altering existing packet forwarding or breaking backward compatibility is:

1. Create a pure parsing and validation function `crates/rer/src/ccsds.rs` (or submodule in `crates/rer/src/diagnostics.rs`):
   `pub fn parse_ccsds_primary_header(data: &[u8]) -> Result<CcsdsPrimaryHeader, CcsdsParseError>`
2. Implement comprehensive unit tests in `crates/rer/src/ccsds.rs` or `crates/rer/tests/ccsds_tests.rs`:
   - Valid 6-byte header with APID 100, sequence count 42, length 10.
   - Correct extraction of 14-bit sequence counter across varying sequence flags (`00`, `01`, `10`, `11`).
   - Rejection of payloads shorter than 6 octets (`TruncatedHeader`).
   - Rejection of version numbers $\ne 0$ (`InvalidVersion`).
   - Rejection of payloads shorter than $C + 7$ (`LengthMismatch`).
   - APID 2047 idle packet identification.
3. This establishes 100% verified parsing logic and error types without touching production relay traffic loops.

## Not claimed

This proposal and any subsequent implementation of Task RER-F-016 explicitly do NOT claim or establish:
1. **Full CCSDS Compatibility**: No full CCSDS system compatibility is claimed. RER does not implement the complete Space Packet Protocol specification beyond the 6-octet primary header.
2. **Secondary Header Support**: No parsing, interpretation, or semantic validation of secondary headers (such as mission time codes, ECSS PUS service headers, or proprietary mission headers) is supported.
3. **Space Data Link Protocols**: No support is claimed for lower-layer CCSDS link protocols or frame synchronization (e.g., TM Synchronization and Channel Coding CCSDS 131.0-B-4, TM Space Data Link Protocol CCSDS 132.0-B-3, TC Space Data Link Protocol CCSDS 232.0-B-4, or AOS Space Data Link Protocol CCSDS 732.0-B-4).
4. **Higher-Layer Space Protocols**: No support is claimed for CCSDS File Delivery Protocol (CFDP, CCSDS 727.0-B-5), Bundle Protocol (BPv7, RFC 9171 / CCSDS 734.2-B-1), or Licklider Transmission Protocol (LTP, RFC 5326 / CCSDS 734.1-B-1).
5. **Encapsulation Service**: No support is claimed for CCSDS Encapsulation Packets (CCSDS 133.1-B-3).
6. **Performance and Timing Guarantees**: No throughput, zero-copy, or real-time latency claims are made for CCSDS parsing relative to raw packet forwarding prior to empirical benchmarking.
7. **Official Agency Conformance**: No official flight qualification, ECSS compliance, or formal space agency conformance testing (NASA, ESA, JAXA) has been conducted.

## Open questions

The following questions require decisions by the repository owner:

1. **In-Tree Module vs External Dependency**:
   Should RER maintain its own lightweight, zero-dependency 6-byte header parser in-tree (as proposed), or should it depend on an external crate such as `spacepackets` if broader aerospace protocol decoding (such as PUS or time stamps) might be planned for later roadmap phases?
2. **Configuration Layout and Compatibility**:
   Should `ccsds` be a top-level optional subsection under `StreamConfig` (`stream.ccsds`), or should it be modeled as a variant of the existing `sequence` configuration (`sequence.mode: ccsds`)?
3. **Stream-Oriented TCP Framing**:
   Should CCSDS length-based framing ($C + 7$) be implemented as an alternate framing mode in `crates/rer/src/framing.rs` for raw TCP streams, allowing RER to ingest and emit back-to-back CCSDS packets over TCP without RER's custom 4-byte length prefix?
4. **Failure Handling Policy**:
   When a packet fails CCSDS validation (e.g. invalid version or length mismatch), should the default action be strictly to drop the packet, or should RER offer a `passthrough_on_error: bool` option to forward raw bytes while raising a diagnostic event?
