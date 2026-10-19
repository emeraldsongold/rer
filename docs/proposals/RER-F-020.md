# RER-F-020: LTP Research and Integration Proposal

## Summary

This proposal investigates the Licklider Transmission Protocol (LTP) specified in [RFC 5326](https://www.rfc-editor.org/rfc/rfc5326.html) and [CCSDS 734.1-B-1](https://ccsds.org/Pubs/734x1b1.pdf), surveying its session management, timers, reports, and retransmission mechanisms, as well as existing open-source implementations and their licenses.

In strict alignment with SPEC §14, LTP is treated as a specialized, stateful protocol with session management, timers, reports, retransmission, and recovery requirements. LTP is not a generic TCP replacement and cannot be operated as a simple stream or datagram proxy. Furthermore, full BP/LTP support must not be promised until appropriate tests and conformance evidence exist. RER's core mission is deterministic packet forwarding, fan-out, channel simulation, and non-blocking diagnostics. Building a monolithic, stateful LTP engine—complete with persistent block buffers, retransmission queues, and complex countdown timer trees—would compromise RER's low-overhead forwarding model and duplicate mature external implementations such as NASA-JPL ION, NASA HDTN, or Rust licklider.

Instead, this proposal defines a two-pillar integration approach:
1. **Passive Ingress LTP Segment Inspection and Diagnostics**: An opt-in, non-blocking inspector on UDP streams (default port 1113, IANA `ltp-deepspace`) that decodes Self-Delimiting Numeric Values (SDNV) to extract session identifiers, segment types, checkpoint flags, report serial numbers, and client service IDs. Extracted telemetry is emitted into RER's non-blocking diagnostic event buffer (`crates/rer/src/diagnostics.rs`) while forwarding datagrams unmodified.
2. **Deep-Space Channel Simulation Harness**: Utilizing RER's existing simulation framework (`crates/rer/src/sim/channel.rs`) to model long propagation delays and scheduled link outages (contact plans). This enables RER to function as a deterministic, unprivileged impairment bridge between external LTP nodes to test their timer suspension, retransmission, and recovery state machines.

The smallest first step consists of an in-tree, zero-dependency SDNV and LTP segment header parser wired into `InspectionConfig` in `crates/rer/src/config.rs` and tested against RFC 5326 reference test patterns.

## Findings

### LTP Protocol Architecture and Standards

The primary specifications defining the Licklider Transmission Protocol are:
- [RFC 5326](https://www.rfc-editor.org/rfc/rfc5326.html): *Licklider Transmission Protocol - Specification* (M. Ramadas, S. Burleigh, S. Farrell, September 2008). Defines the core segment structures, transmission session lifecycle, reception reporting procedures, and retransmission state transitions.
- [RFC 5325](https://www.rfc-editor.org/rfc/rfc5325.html): *Licklider Transmission Protocol - Motivation* (S. Burleigh, M. Ramadas, S. Farrell, September 2008). Establishes the design rationale for LTP in long-haul interplanetary links characterized by extremely long propagation delays (round-trip times of minutes to hours), frequent planned interruptions, and high bit-error rates where conversational handshakes and TCP-style feedback loops fail.
- [RFC 5327](https://www.rfc-editor.org/rfc/rfc5327.html): *Licklider Transmission Protocol - Security Extensions* (S. Farrell, M. Ramadas, S. Burleigh, September 2008). Specifies optional security extensions including segment authentication, ciphersuites, and cookie exchanges.
- [CCSDS 734.1-B-1](https://ccsds.org/Pubs/734x1b1.pdf): *Licklider Transmission Protocol (LTP) for CCSDS* (Recommended Standard, Blue Book, Issue 1, May 2015). Standardizes LTP for international space agency cross-support, commonly operating beneath the Bundle Protocol ([RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html)) with client service ID 1.

Key structural, stateful, and operational properties established across these standards include:

#### 1. Blocks, Segments, and Red/Green Data Separation
Application service data units presented to LTP are called "blocks". An LTP block is split into two logical portions:
- **Red Part**: Data requiring reliable transmission. Red data segments are subject to reception acknowledgment, checkpointing, and automatic retransmission upon loss. Red data must be retained by the sender in session memory or persistent storage until acknowledged.
- **Green Part**: Data requiring only best-effort transmission. Green data segments are transmitted without checkpointing, are not acknowledged, and are discarded by the sender immediately following transmission.
- Either part may have a length of zero, allowing purely reliable (all-red), purely best-effort (all-green), or hybrid sessions. In space communications, red data typically conveys critical bundle headers and metadata, while green data conveys loss-tolerant science telemetry.

#### 2. Segment Format and SDNV Encoding
LTP segments share a common header format defined in [RFC 5326](https://www.rfc-editor.org/rfc/rfc5326.html) §3.1:
- **Control Byte (1 octet)**: Composed of a 4-bit Version Number (binary `0000` for LTP version 0) and 4-bit Segment Type Flags: CTRL, EXC, Flag 1, and Flag 0.
- **Session ID**: A tuple of `(session_originator_engine_id, session_number)` uniquely identifying the session. Both fields are encoded as Self-Delimiting Numeric Values (SDNV).
- **Extensions**: Optional header and trailer extensions (RFC 5326 §3.1.4).

An SDNV is a variable-length encoding format where bit 7 of each octet is a continuation flag (1 indicates more octets follow; 0 indicates the final octet). Bits 0–6 of each octet represent 7 bits of the big-endian numeric value. SDNVs allow compact representation of integers without fixed 32-bit or 64-bit boundaries.

The combination of the 4 control flags determines the segment type code (RFC 5326 §3.1.2):
- `0x0`: Red data, NOT Checkpoint, NOT EORP (End of Red Part), NOT EOB (End of Block).
- `0x1`: Red data, Checkpoint (CP), NOT EORP, NOT EOB.
- `0x2`: Red data, Checkpoint, EORP, NOT EOB.
- `0x3`: Red data, Checkpoint, EORP, EOB.
- `0x4`: Green data, NOT EOB.
- `0x7`: Green data, EOB.
- `0x8`: Report Segment (RS).
- `0x9`: Report-Acknowledgment Segment (RAx).
- `0xC` (12): Cancel Segment from block sender (CS).
- `0xD` (13): Cancel-Acknowledgment Segment to block sender (CAx).
- `0xE` (14): Cancel Segment from block receiver (CR).
- `0xF` (15): Cancel-Acknowledgment Segment to block receiver (CAx).

Data segments carry a Client Service ID (SDNV, e.g., 1 for Bundle Protocol), a block byte Offset (SDNV), and a data Length (SDNV). If the segment is marked as a Checkpoint, it additionally contains a Checkpoint Serial Number (SDNV) and a Report Serial Number (SDNV).

#### 3. Session Requirements
- **Unidirectional Transfers**: LTP data sessions are strictly unidirectional from a block sender engine to a block receiver engine. Return communication is restricted to acknowledgments (RS, RAx, CAx).
- **Session Identification**: A session is uniquely identified by the Session ID: the sender's Engine ID and a sender-assigned Session Number.
- **Sender Session State**: The sender maintains transmission queues, red-part retention buffers, checkpoint serial numbers, active timers, retransmission counters, and transmission round indices.
- **Receiver Session State**: The receiver tracks received byte spans, maintains block reconstruction buffers, formats report segments with reception claims, and waits for report acknowledgments.
- **Session Termination**: The sender closes a session after receiving an RAx acknowledging the final RS with no outstanding red gaps, or upon cancellation timeout. The receiver closes a session after delivering the reassembled block to the client service and receiving an RAx or timing out.

#### 4. Timer Requirements and Outage Handling
Because round-trip times in deep space range from seconds to hours, timer management in LTP differs fundamentally from TCP:
- **Checkpoint (CP) Timer** (RFC 5326 §6.2): Started when a CP segment is transmitted. It expires when the expected Report Segment (RS) fails to arrive within the computed round-trip time plus processing allowance.
- **Report Segment (RS) Timer** (RFC 5326 §6.3): Started when an RS is transmitted by the receiver. It expires when the expected Report Acknowledgment (RAx) fails to arrive within the expected arrival window.
- **Cancel Timer** (RFC 5326 §6.15): Started when a Cancel Segment is transmitted, governing retry of cancellation notices.
- **Outage Suspension and Resumption** (RFC 5326 §6.5, §6.6): LTP engines must coordinate with contact schedules (e.g., Contact Graph Routing plans). When a planned transmission window closes (e.g., due to planetary rotation or orbital occultation), active timers MUST be suspended. When the contact re-opens, timers are adjusted and resumed. Without outage suspension, link disruptions cause spurious timeouts and massive retransmission storms upon reconnection.

#### 5. Report and Retransmission Requirements
- **Checkpoint Mechanism**: The sender triggers feedback by setting the Checkpoint flag on a red segment. The final segment of the red part (EORP) is always a checkpoint; sender implementations may also emit intermediate checkpoints in large blocks.
- **Report Segments (RS)** (RFC 5326 §3.2.2): When a receiver processes a checkpoint, it issues an RS. The RS contains:
  - Report Serial Number (SDNV).
  - Checkpoint Serial Number (SDNV) to which this RS replies.
  - Lower Bound (SDNV): Byte offset below which all red data has been previously received and acknowledged.
  - Upper Bound (SDNV): Byte offset up to which reception claims in this RS pertain.
  - Reception Claims: An array of `(offset, length)` SDNV pairs denoting contiguous byte ranges successfully received between the lower and upper bounds.
- **Retransmission Processing**: Gaps between the lower bound, reception claims, and the upper bound represent missing red data. The sender slices the missing byte ranges into new red data segments, queues them for transmission, and marks the final retransmitted segment as a new checkpoint with an incremented Checkpoint Serial Number. This process constitutes a retransmission round. Successive rounds occur until all red data is acknowledged or cancellation thresholds are reached.

### Survey of Existing LTP Implementations and Licensing

A survey of active and reference LTP implementations was conducted to examine their design and evaluate license compatibility with RER's Apache-2.0 codebase:

1. **NASA-JPL ION-DTN (Interplanetary Overlay Network)**
   - Repository: [nasa-jpl/ION-DTN](https://github.com/nasa-jpl/ION-DTN)
   - Overview: ION is the reference implementation of DTN protocols developed by the NASA Jet Propulsion Laboratory. It provides a production-grade, flight-qualified LTP engine implemented in C (`ltpdriver`, `udplsi`, `udplso`, `ltpadmin`). ION couples LTP with Contact Graph Routing (CGR) and rate-controlled UDP transmission, supporting contact-plan-based timer suspension.
   - License: Custom BSD-style open-source license by California Institute of Technology, verified in the project's [license.txt](https://raw.githubusercontent.com/nasa-jpl/ION-DTN/master/license.txt).
   - Relevance to RER: Permissive BSD terms allow external interoperation and benchmarking. ION serves as the primary external reference peer for testing RER's relay and channel simulation capabilities.

2. **NASA HDTN (High-rate Delay Tolerant Networking)**
   - Repository: [nasa/HDTN](https://github.com/nasa/HDTN)
   - Overview: Developed by NASA Glenn Research Center, HDTN is an optimized C++ DTN implementation architected for multi-gigabit line rates. It features a multi-threaded pipeline, asynchronous UDP batch sending (`UdpBatchSender`), solid-state drive session buffering for LTP outducts/inducts, and contact plan scheduling.
   - License: Apache License, Version 2.0, verified in the project's [LICENSE.md](https://raw.githubusercontent.com/nasa/HDTN/main/LICENSE.md).
   - Relevance to RER: Permissive Apache-2.0 license matches RER. HDTN demonstrates high-throughput UDP batching techniques and serves as a high-performance external peer.

3. **licklider / licklider-core**
   - Repository: [wowinter13/licklider](https://github.com/wowinter13/licklider)
   - Overview: The first pure Rust implementation of RFC 5326. It is built as a sans-I/O protocol engine (`licklider-core`) without sockets, clocks, threads, or async runtimes, allowing deterministic event-driven testing by stepping a mock clock. It includes SDNV codecs, sender/receiver state machines (RFC 5326 §8), outage timer suspend/resume, and an ION-compatible UDP link service (`licklider-udp` on port 1113).
   - License: Dual-licensed under Apache License, Version 2.0 and MIT License, verified in [LICENSE-APACHE](https://raw.githubusercontent.com/wowinter13/licklider/main/LICENSE-APACHE) and [LICENSE-MIT](https://raw.githubusercontent.com/wowinter13/licklider/main/LICENSE-MIT).
   - Relevance to RER: Native Rust ecosystem project with identical dual licensing. Its sans-I/O architecture is an exceptional technical reference for clean protocol separation, and it can be run in automated CI integration tests.

4. **DTN2 (Reference Implementation)**
   - Repository: [delay-tolerant-networking/DTN2](https://github.com/delay-tolerant-networking/DTN2)
   - Overview: Maintained by the Delay-Tolerant Networking Research Group, DTN2 is an established C++ reference platform supporting BPv6 that incorporates Trinity College Dublin's LTPlib as an optional convergence layer.
   - License: Apache License, Version 2.0, verified in the project's [LICENSE](https://raw.githubusercontent.com/delay-tolerant-networking/DTN2/master/LICENSE).
   - Relevance to RER: Demonstrates legacy integration patterns for LTP convergence layers under Bundle Protocol.

5. **Scapy (LTP contrib module)**
   - Repository: [secdev/scapy](https://github.com/secdev/scapy)
   - Overview: Scapy is an interactive packet manipulation program in Python containing an LTP protocol dissection module contributed by the MITRE Corporation.
   - License: GNU General Public License Version 2 (GPL-2.0), verified in the project's [LICENSE](https://raw.githubusercontent.com/secdev/scapy/master/LICENSE).
   - Relevance to RER: Licensing restriction: GPL-2.0 is a strong copyleft license. No code from Scapy can be incorporated into RER's Apache-2.0 repository. However, Scapy can be executed as an external, black-box test vector generator.

### Sources checked

- `https://www.rfc-editor.org/rfc/rfc5326.html`: HTTP 200
- `https://www.rfc-editor.org/rfc/rfc5325.html`: HTTP 200
- `https://www.rfc-editor.org/rfc/rfc5327.html`: HTTP 200
- `https://ccsds.org/Pubs/734x1b1.pdf`: HTTP 200
- `https://www.rfc-editor.org/rfc/rfc9171.html`: HTTP 200
- `https://github.com/nasa-jpl/ION-DTN`: HTTP 200
- `https://raw.githubusercontent.com/nasa-jpl/ION-DTN/master/license.txt`: HTTP 200
- `https://github.com/nasa/HDTN`: HTTP 200
- `https://raw.githubusercontent.com/nasa/HDTN/main/LICENSE.md`: HTTP 200
- `https://github.com/wowinter13/licklider`: HTTP 200
- `https://raw.githubusercontent.com/wowinter13/licklider/main/LICENSE-APACHE`: HTTP 200
- `https://raw.githubusercontent.com/wowinter13/licklider/main/LICENSE-MIT`: HTTP 200
- `https://github.com/delay-tolerant-networking/DTN2`: HTTP 200
- `https://raw.githubusercontent.com/delay-tolerant-networking/DTN2/master/LICENSE`: HTTP 200
- `https://github.com/secdev/scapy`: HTTP 200
- `https://raw.githubusercontent.com/secdev/scapy/master/LICENSE`: HTTP 200

## Proposal

### Architectural Approach

In strict conformance with SPEC §14:
- "Treat as a specialized, stateful protocol with session management, timers, reports, retransmission, and recovery requirements."
- "Research integration options and develop a design proposal before implementation."
- "Do not treat LTP as a generic TCP replacement."
- "Do not promise full BP/LTP support until the implementation has appropriate tests and conformance evidence."

RER's core design excels at deterministic, low-latency, unprivileged packet forwarding, fan-out, channel impairment injection, and structured event diagnostics. Embedding an end-to-end LTP transport engine into RER—requiring multi-megabyte block buffers, persistent disk storage, session recovery state machines, and fine-grained contact-plan timers—would compromise RER's low-overhead forwarding model and duplicate proven implementations like NASA-JPL ION, NASA HDTN, and licklider.

Consequently, RER should adopt a focused, non-disruptive integration strategy consisting of two functional components:

1. **Passive Ingress LTP Segment Inspection and Telemetry**:
   - Ingress UDP packets on configured streams (or port 1113) are inspected for LTP control headers.
   - When detected, an in-tree, zero-allocation parser extracts the Session Originator Engine ID, Session Number, Segment Type, Checkpoint Flag, EORP Flag, EOB Flag, and relevant serial numbers.
   - Telemetry is recorded into RER's non-blocking diagnostic event buffer (`crates/rer/src/diagnostics.rs`) without delaying packet transmission.
   - The original packet is forwarded byte-identically to downstream destinations.

2. **Deep-Space Channel Impairment Harness for LTP Validation**:
   - Extend RER's software simulation engine (`crates/rer/src/sim/channel.rs`) to model long propagation delays and scheduled contact windows (outages).
   - This empowers RER to act as a realistic, unprivileged deep-space channel between external LTP endpoints (e.g., ION or licklider nodes), testing their ability to suspend timers during occultation, survive packet loss, and retransmit missing spans without requiring kernel root privileges or `netem`.

### Repository Touchpoints

The proposed integration touches specific, existing RER modules, configuration structures, and diagnostic types:

1. **`crates/rer/src/config.rs`**:
   - Extend `InspectionConfig` (which currently configures `hex_preview`, `ascii_preview`, and `max_preview_bytes` for SPEC §8) with an opt-in `ltp` configuration sub-table:
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
         /// Optional LTP segment inspection configuration (SPEC §14).
         #[serde(default, skip_serializing_if = "Option::is_none")]
         pub ltp: Option<LtpInspectionConfig>,
     }
     ```
   - Define `LtpInspectionConfig` with fields:
     - `enabled`: boolean (defaults to true when section is present).
     - `parse_claims`: boolean (whether to parse detailed reception claims in Report Segments; defaults to false to avoid heap allocation).
     - `max_inspect_bytes`: usize (maximum byte limit for header inspection, defaults to 64 bytes).
   - Extend `ImpairmentConfig` in `crates/rer/src/sim/channel.rs` (which currently manages `loss_rate`, `duplicate_rate`, `reorder_rate`, `delay_ms`, and `jitter_ms`) to support scheduled outages for contact plan simulation:
     - `outage_schedule`: optional list of contact windows `(start_ms, duration_ms)` during which the channel drops or buffers datagrams, directly exercising LTP timer suspension (RFC 5326 §6.5).

2. **`crates/rer/src/diagnostics.rs`**:
   - Define a serializable `LtpMetadata` struct capturing:
     - `session_originator`: u64 (engine ID).
     - `session_number`: u64.
     - `segment_type`: u8 (raw type code 0–15).
     - `is_checkpoint`: bool.
     - `is_eorp`: bool.
     - `is_eob`: bool.
     - `checkpoint_serial`: Option<u64>.
     - `report_serial`: Option<u64>.
     - `client_service_id`: Option<u64>.
   - Integrate with `DiagnosticEvent`: record `LtpMetadata` when inspecting datagrams at `DiagnosticStage::Received` or `DiagnosticStage::Accepted`.
   - Adhere strictly to the bounded non-blocking ring buffer guarantee: inspection must never allocate unbounded memory, lock forwarders, or stall packet pipelines.

3. **`crates/rer/src/relay.rs`**:
   - In stream packet processing pipelines (`relay_stream`), invoke the read-only LTP inspector on ingress datagrams when `stream.inspection.ltp` is active.
   - Ensure forwarded payloads remain completely unmodified on egress paths.

4. **`crates/rer/src/sim/channel.rs` & `crates/rer/src/sim/harness.rs`**:
   - Integrate scheduled link outage evaluation into `SimulatedChannel::process_packet` to support contact-plan simulation without root privileges.
   - Utilize existing deterministic PRNG (`SplitMix64`) to preserve fully reproducible test runs.

5. **`crates/rer/Cargo.toml`**:
   - Maintain the zero-cost and minimal dependency constraint (AGENTS.md §1).
   - The Phase 1 LTP parser requires zero third-party dependencies (implementing pure bitfield and SDNV decoding).
   - For end-to-end integration tests, external engines like `licklider-core` or compiled ION containers can be utilized as standalone test peers.

### Smallest First Step (Phase 1)

The smallest viable, owner-judged implementation increment consists of:
1. Implement a self-contained, zero-dependency SDNV and LTP header scanner in a new internal module `crates/rer/src/ltp.rs` (or `crates/rer/src/inspection/ltp.rs`).
2. Validate the 4-bit version (binary `0000`), decode the 4-bit segment type flags, and parse the SDNV Session ID (originator engine ID and session number).
3. Connect the parser to `InspectionConfig` in `crates/rer/src/config.rs` and record `LtpMetadata` into `crates/rer/src/diagnostics.rs`.
4. Implement unit tests with RFC 5326 reference byte sequences (red data, checkpoint, report segment, report ACK, cancel segment), asserting that malformed, truncated, or non-LTP payloads fail safely without panics or relay interruption.

## Not claimed

This research proposal explicitly establishes that:
1. **No LTP support is claimed**: RER does not implement, support, or certify compliance with [RFC 5326](https://www.rfc-editor.org/rfc/rfc5326.html) or [CCSDS 734.1-B-1](https://ccsds.org/Pubs/734x1b1.pdf).
2. **No stateful endpoint or session management is claimed**: RER does not maintain transmission sessions, manage red/green data block assembly, track reception claim lists, or execute block delivery.
3. **No timer management or outage handling is claimed**: RER does not manage LTP countdown timers, compute one-way light times, or execute RFC 5326 §6.5/§6.6 timer suspension procedures in the relay engine.
4. **No retransmission or recovery capability is claimed**: RER does not detect missing spans, issue report segments, or generate retransmitted red data segments.
5. **No security extension support is claimed**: Verification of [RFC 5327](https://www.rfc-editor.org/rfc/rfc5327.html) authentication or cookie extensions is not implemented.
6. **No performance or throughput claims are made**: No LTP throughput, processing latency, or scalability guarantees are established.
7. **Not a generic TCP replacement**: LTP is explicitly not claimed as a general-purpose Internet transport protocol or replacement for TCP.

## Open questions

The following architectural and design decisions are reserved for repository owner review and direction:

1. **Configuration Placement**: Should LTP inspection configuration be nested within `InspectionConfig` (`stream.inspection.ltp`) alongside payload previews, or established as a top-level protocol inspection section under `StreamConfig`?
2. **Parser Scope and Dependencies**: Should RER strictly maintain a zero-dependency, in-tree SDNV and header decoder, or evaluate importing `licklider-core` (dual-licensed Apache-2.0/MIT) if full Report Segment claim parsing is desired in future phases?
3. **Port-Based Automatic Detection**: Standard LTP runs over UDP port 1113 (`ltp-deepspace`). Should RER provide an auto-detection heuristic based on destination port 1113, or require explicit opt-in configuration per stream?
4. **Channel Impairment Contact Schedule Format**: Should scheduled link outage simulation in `crates/rer/src/sim/channel.rs` adopt a simple list of relative millisecond windows `[(start_ms, duration_ms)]`, or conform to the CCSDS Contact Graph Routing (CGR) contact plan syntax used by ION?
5. **Diagnostic Event Granularity**: Should LTP metadata fields be integrated directly into standard packet diagnostic events, or published as a dedicated `LtpInspection` variant in `crates/rer/src/diagnostics.rs`?
