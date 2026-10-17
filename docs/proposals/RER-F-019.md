# RER-F-019: BPv7 Research and Integration Proposal

## Summary

This proposal investigates Bundle Protocol Version 7 (BPv7) standardized under [RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html) and surveys existing open-source Delay-Tolerant Networking (DTN) implementations and their licensing constraints. In alignment with SPEC §14, RER does not attempt to construct a full standalone Bundle Processing Agent (BPA), persistent storage manager, or autonomous bundle routing engine. Instead, RER is an engineering relay and diagnostic harness designed for deterministic packet forwarding, stream fan-out, and channel simulation.

The proposed integration defines a modular, passive, and read-only BPv7 inspection capability for RER streams. This module parses Concise Binary Object Representation ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html)) primary bundle blocks to extract Endpoint Identifiers (EIDs), creation timestamps, lifetimes, and fragmentation metadata without modifying bundle contents, terminating custody, or imposing heavy storage overhead. The extracted metadata is exposed through RER's non-blocking diagnostic event stream. For end-to-end DTN services, RER interfaces with established external DTN implementations rather than reimplementing the protocol stack.

## Findings

### BPv7 Protocol Standard

Bundle Protocol Version 7 is specified by the IETF in [RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html). BPv7 forms the core network layer for Delay/Disruption Tolerant Networking, architected to function over challenged communication channels characterized by high propagation delay, intermittent connectivity, and frequent link disruptions.

Key structural and protocol properties established by [RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html) include:

1. **CBOR Encoding**: Every BPv7 bundle is serialized using Concise Binary Object Representation defined in [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html). A bundle is formatted as an indefinite-length CBOR array containing a mandatory primary bundle block, followed by one or more canonical bundle blocks, and concluding with a single payload block and a CBOR "break" stop code.
2. **Primary Bundle Block**: The primary block is immutable once created. It comprises 8 to 11 CBOR array items depending on CRC inclusion and fragmentation:
   - *Version*: Integer (value 7 for BPv7).
   - *Bundle Processing Control Flags*: Bit field encoding delivery actions (e.g., payload is administrative record, bundle must not be fragmented, acknowledgment requested, status report requested).
   - *CRC Type and Optional Value*: Code 0 (none), 1 (16-bit CRC), or 2 (32-bit CRC).
   - *Destination EID*: Endpoint Identifier for bundle destination.
   - *Source Node ID*: Singleton Endpoint Identifier identifying the originating node.
   - *Report-to EID*: Endpoint Identifier to which status reports are dispatched.
   - *Creation Timestamp*: Two-element array consisting of DTN time (milliseconds since 2000-01-01 00:00:00 UTC epoch) and a sequence number unique to the source node.
   - *Lifetime*: Unsigned integer specifying lifetime duration in milliseconds relative to creation time.
   - *Fragment Offset and Total Application Data Unit Length*: Present only if bundle processing control flags indicate a fragment.
3. **Endpoint Identifiers (EIDs)**: Bundle endpoints are represented as URIs. [RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html) specifies two primary schemes:
   - `dtn:` scheme (e.g., `dtn://node-name/service` or the null endpoint `dtn:none`).
   - `ipn:` scheme (e.g., `ipn:node-nbr.service-nbr`), designed for bandwidth-constrained space communication links.
4. **Canonical and Extension Blocks**: Intermediate blocks provide operational capabilities, such as Previous Node Block, Bundle Age Block, Hop Count Block, and status reporting.
5. **Security**: Security services (integrity and confidentiality) are decoupled into Bundle Protocol Security (BPSec), standardized in [RFC 9172](https://www.rfc-editor.org/rfc/rfc9172.html), introducing Block Integrity Blocks (BIB) and Block Confidentiality Blocks (BCB).
6. **Convergence Layers**: BP relies on Convergence Layer Adapters (CLAs) for transport over underlying networks. The primary TCP convergence layer for BPv7 is TCPCLv4, specified in [RFC 9174](https://www.rfc-editor.org/rfc/rfc9174.html), which provides session negotiation, contact initiation, bundle transfer framing, and keepalives.

### Existing DTN Implementations and Licensing

A survey of active and mature DTN implementations was conducted to assess technical capabilities and license compatibility with RER's Apache-2.0 codebase:

1. **NASA HDTN (High-rate Delay Tolerant Networking)**
   - Repository: [nasa/HDTN](https://github.com/nasa/HDTN)
   - Overview: Implemented in C++, HDTN is developed by NASA Glenn Research Center to achieve high-rate, line-rate BPv7 bundle processing (multi-gigabit per second). It incorporates TCPCLv4, optimized storage rings, and pipeline parallelism compliant with NASA Class B software engineering standards.
   - License: Apache License, Version 2.0, as verified in the project's [LICENSE.md](https://raw.githubusercontent.com/nasa/HDTN/main/LICENSE.md).
   - Relevance to RER: Permissive Apache-2.0 license is fully compatible with RER. HDTN's architecture demonstrates high-throughput pipeline design and separation of convergence layers from routing logic.

2. **NASA-JPL ION-DTN (Interplanetary Overlay Network)**
   - Repository: [nasa-jpl/ION-DTN](https://github.com/nasa-jpl/ION-DTN)
   - Overview: Implemented in C, ION is NASA Jet Propulsion Laboratory's reference implementation for spaceflight systems. ION supports BPv7 ([RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html)), BPv6, Licklider Transmission Protocol (LTP), Contact Graph Routing (CGR), and CFDP, with flight heritage on deep space missions.
   - License: Custom BSD-style open-source license by California Institute of Technology, as verified in the project's [license.txt](https://raw.githubusercontent.com/nasa-jpl/ION-DTN/master/license.txt).
   - Relevance to RER: Permissive BSD terms allow linking or interoperation without copyleft contamination. ION is an ideal external peer node for test harness and relay validation.

3. **NASA bplib (Bundle Protocol Library)**
   - Repository: [nasa/bplib](https://github.com/nasa/bplib)
   - Overview: A lightweight, embedded C library implementing BPv7 ([RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html)) for resource-constrained flight environments, specifically NASA's Core Flight System (cFS) BPNode application.
   - License: Apache License, Version 2.0, as verified in the project's [LICENSE](https://raw.githubusercontent.com/nasa/bplib/main/LICENSE).
   - Relevance to RER: Permissive Apache-2.0 license. Provides a clean reference for minimal embedded CBOR bundle decoding and memory management.

4. **dtn7-rs / dtnd**
   - Repository: [dtn7/dtn7-rs](https://github.com/dtn7/dtn7-rs)
   - Overview: A full-featured DTN daemon written in Rust implementing BPv7 ([RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html)), TCPCLv4 ([RFC 9174](https://www.rfc-editor.org/rfc/rfc9174.html)), HTTP convergence layers, neighborhood discovery, and routing strategies.
   - License: Dual-licensed under Apache License, Version 2.0 or MIT License, as verified in [LICENSE-APACHE](https://raw.githubusercontent.com/dtn7/dtn7-rs/master/LICENSE-APACHE) and [LICENSE-MIT](https://raw.githubusercontent.com/dtn7/dtn7-rs/master/LICENSE-MIT).
   - Relevance to RER: Native Rust ecosystem project with permissive dual licensing. Can be executed as an integration test peer in automated test pipelines without specialized toolchains.

5. **bp7-rs**
   - Repository: [dtn7/bp7-rs](https://github.com/dtn7/bp7-rs)
   - Overview: Standalone Rust library containing the core CBOR serialization and deserialization routines for BPv7 data structures according to [RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html).
   - License: Dual-licensed under Apache License, Version 2.0 or MIT License, as verified in [LICENSE-APACHE](https://raw.githubusercontent.com/dtn7/bp7-rs/master/LICENSE-APACHE) and [LICENSE-MIT](https://raw.githubusercontent.com/dtn7/bp7-rs/master/LICENSE-MIT).
   - Relevance to RER: Directly relevant to RER's Rust ecosystem; permissive license compatible with RER's Apache-2.0 license.

6. **µD3TN (uD3TN)**
   - Repository: [d3tn/ud3tn](https://gitlab.com/d3tn/ud3tn)
   - Overview: Micro Delay-Tolerant Networking implementation written in C by D3TN and German Aerospace Center (DLR), optimized for microcontrollers, nanosatellites, and embedded systems.
   - License: GNU Affero General Public License Version 3 (AGPL-3.0-only), as verified in the project's [LICENSE](https://gitlab.com/d3tn/ud3tn/-/raw/master/LICENSE).
   - Relevance to RER: Licensing restriction: AGPLv3 is a strong network copyleft license. Integrating uD3TN code directly or linking it within RER would impose AGPL obligations, which conflicts with RER's Apache-2.0 licensing and dependency policies. It can only be used as an isolated external network service.

### Sources checked

- `https://www.rfc-editor.org/rfc/rfc9171.html`: HTTP 200
- `https://www.rfc-editor.org/rfc/rfc8949.html`: HTTP 200
- `https://www.rfc-editor.org/rfc/rfc9172.html`: HTTP 200
- `https://www.rfc-editor.org/rfc/rfc9174.html`: HTTP 200
- `https://github.com/nasa/HDTN`: HTTP 200
- `https://raw.githubusercontent.com/nasa/HDTN/main/LICENSE.md`: HTTP 200
- `https://github.com/nasa-jpl/ION-DTN`: HTTP 200
- `https://raw.githubusercontent.com/nasa-jpl/ION-DTN/master/license.txt`: HTTP 200
- `https://github.com/nasa/bplib`: HTTP 200
- `https://raw.githubusercontent.com/nasa/bplib/main/LICENSE`: HTTP 200
- `https://github.com/dtn7/dtn7-rs`: HTTP 200
- `https://raw.githubusercontent.com/dtn7/dtn7-rs/master/LICENSE-APACHE`: HTTP 200
- `https://raw.githubusercontent.com/dtn7/dtn7-rs/master/LICENSE-MIT`: HTTP 200
- `https://github.com/dtn7/bp7-rs`: HTTP 200
- `https://raw.githubusercontent.com/dtn7/bp7-rs/master/LICENSE-APACHE`: HTTP 200
- `https://raw.githubusercontent.com/dtn7/bp7-rs/master/LICENSE-MIT`: HTTP 200
- `https://gitlab.com/d3tn/ud3tn`: HTTP 200
- `https://gitlab.com/d3tn/ud3tn/-/raw/master/LICENSE`: HTTP 200

## Proposal

### Architectural Approach

In compliance with SPEC §14:
- "Plan an optional module for bundle inspection, endpoint identifiers, metadata, and diagnostic integration."
- "Investigate integration with established DTN implementations rather than automatically reimplementing the full protocol."
- "Do not treat BP as merely another UDP/TCP conversion."

RER's primary value is deterministic, low-overhead stream forwarding, fan-out, fault simulation, and rich diagnostics. Building a full BPv7 storage engine, bundle routing table, and custody transfer agent within RER would drastically expand complexity and duplicate mature engines like NASA HDTN, NASA-JPL ION, or dtn7-rs.

Instead, RER should introduce an optional, read-only **Bundle Inspection and Diagnostic Integration Module**. This module acts as a passive observer on forwarding streams:
1. Datagrams or framed streams passing through RER are inspected for BPv7 CBOR primary block signatures.
2. When detected, the inspector parses header metadata (source EID, destination EID, creation timestamp, lifetime, fragmentation flags, block structure).
3. The extracted metadata is recorded into RER's non-blocking diagnostic event buffer.
4. The packet itself is forwarded unmodified to downstream endpoints.

For scenarios requiring full DTN network testing, RER serves as an intermediate network emulator and diagnostic tap between external DTN daemons (e.g., HDTN or ION instances), subjecting bundle traffic to controlled loss, delay, corruption, and jitter using RER's simulation engine (`crates/rer/src/sim/`).

### Repository Touchpoints

The integration is scoped to specific files, modules, and configuration structures within RER:

1. **`crates/rer/src/config.rs`**:
   - Extend `InspectionConfig` (currently providing `hex_preview`, `ascii_preview`, and `max_preview_bytes`) with opt-in bundle inspection fields:
     ```rust
     pub struct InspectionConfig {
         pub hex_preview: bool,
         pub ascii_preview: bool,
         pub max_preview_bytes: usize,
         // Proposed optional extension:
         pub bpv7: Option<Bp7InspectionConfig>,
     }
     ```
   - Alternatively, add an optional `bpv7` block directly to `StreamConfig` to enable protocol inspection per stream without impacting non-BP streams.
   - Configure parameters such as `extract_eids` (boolean), `parse_canonical_blocks` (boolean), and `max_inspect_bytes` (length limit).

2. **`crates/rer/src/diagnostics.rs`**:
   - Define a structured `BundleMetadata` record capturing:
     - `source_eid`: String (e.g. `ipn:10.1` or `dtn://gateway/telemetry`).
     - `destination_eid`: String.
     - `creation_time_dtn`: u64 (milliseconds from DTN epoch).
     - `sequence_number`: u64.
     - `lifetime_ms`: u64.
     - `is_fragment`: bool.
     - `crc_valid`: Option<bool>.
   - Integrate with `DiagnosticStage`: emit a diagnostic event when a bundle is inspected at stage `Received` or `Accepted`.
   - Respect the bounded ring buffer contract: bundle inspection must never block forwarding threads, allocate unbounded memory, or stall relay workers.

3. **`crates/rer/src/relay.rs`**:
   - In stream packet processing pipelines (`relay_stream`), where `SequenceTracker` is evaluated, add a hook to invoke the read-only bundle inspector on ingress packets when `inspection.bpv7` is enabled.
   - Ensure packets remain unaltered on egress paths.

4. **`crates/rer/src/framing.rs`**:
   - Document and maintain separation between RER length-prefixed framing (`encode_frame`, `decode_frame`) and DTN convergence layers (such as RFC 9174 TCPCLv4).
   - In Phase 1, RER forwards framed bundles transparently.

5. **`crates/rer/Cargo.toml`**:
   - Maintain the zero-cost and minimal dependency constraint (AGENTS.md §1).
   - The first step should use a zero-dependency CBOR header scanner or evaluate whether a minimal dependency (e.g. `ciborium` or `bp7`) meets workspace license and security policies.

### Smallest First Step (Phase 1)

The smallest viable, owner-judged implementation step consists of:
1. Implement a lightweight, zero-dependency CBOR primary block reader in a new module `crates/rer/src/bpv7.rs` (or `crates/rer/src/inspection/bpv7.rs`).
2. Implement validation of the BPv7 version tag (integer 7) and extract source and destination EIDs (both `ipn:` and `dtn:` formats).
3. Connect the reader to `InspectionConfig` in `crates/rer/src/config.rs` and emit bundle metadata through `crates/rer/src/diagnostics.rs`.
4. Add unit tests with RFC 9171 reference test vectors verifying that corrupted or non-BP payloads safely fall back without errors or panics.

## Not claimed

This research proposal explicitly establishes that:
1. **No Bundle Protocol support is claimed**: RER does not implement, support, or certify compliance with BPv7 ([RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html)).
2. **No BPA functionality is claimed**: No store-and-forward storage engine, bundle routing table, custody transfer protocol, or bundle reassembly engine is claimed or implemented.
3. **No BPSec support is claimed**: Cryptographic verification of Bundle Protocol Security ([RFC 9172](https://www.rfc-editor.org/rfc/rfc9172.html)) BIB/BCB blocks is not supported.
4. **No performance or line-rate claims are made**: No bundle throughput, parsing latency, or scalability guarantees are established.
5. **No convergence layer compliance is claimed**: RER does not implement or certify RFC 9174 (TCPCLv4) session handshakes or state machines.

## Open questions

The following architectural and design decisions are reserved for the repository owner:

1. **Parser Implementation Strategy**: Should RER implement a self-contained, zero-dependency CBOR scanner strictly parsing the primary block, or import an external crate (such as `bp7` or `ciborium`) into `crates/rer/Cargo.toml`?
2. **Configuration Layout**: Should BPv7 inspection settings be integrated as an optional field within `InspectionConfig` under `stream.inspection`, or as an independent top-level section in `StreamConfig`?
3. **TCPCLv4 Convergence Layer Scope**: Should RER remain strictly a transport-level proxy/relay for TCP and UDP, or should future phases consider implementing a minimal TCPCLv4 session framing adapter?
4. **Diagnostic Event Schema**: Should bundle metadata be published as fields inside general packet diagnostic events or as dedicated `BundleInspection` event types in `crates/rer/src/diagnostics.rs`?
5. **Milestone Progression**: Should the owner approve transitioning RER-F-019's follow-up task in `FEATURES.yaml` from `investigate-only` to `ready-auto` or `needs-design-approval` for Phase 1 implementation?
