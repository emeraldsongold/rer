# Research Proposal: Modbus Application Protocol and DNP3 Integration (RER-F-068)

## Summary

This proposal provides the architectural survey, licensing analysis, and integration design for introducing passive stream inspection, length-based TCP framing, and diagnostic telemetry for Modbus and DNP3 (Distributed Network Protocol) into RER (RER Engineering Relay), fulfilling the research prerequisite for Task RER-F-068 under SPEC §5, §8, and §14.

Modbus and DNP3 represent the standard industrial communication and SCADA (Supervisory Control and Data Acquisition) protocols deployed across critical infrastructure, including electric power transmission and distribution systems, water treatment plants, industrial manufacturing, and aerospace ground telemetry testbeds. Modbus provides a lightweight request/reply messaging protocol operating over TCP/IP (Modbus TCP) via a 7-octet Modbus Application Protocol (MBAP) header. DNP3 (standardized under IEEE Std 1815-2012) provides a tiered, highly reliable communications architecture comprising a 10-octet FT3 data link header delimited by sync octets `0x05 0x64`, CRC-protected 16-octet data blocks, an integrated pseudo-transport layer for application fragmentation, and comprehensive supervisory command functions.

Currently, RER provides generic length-prefixed framing (4-byte big-endian prefix), CCSDS Space Packet primary-header framing, MAVLink v1/v2 framing, MQTT 3.1.1/5.0 packet framing, and KISS byte-delimited framing in `crates/rer/src/framing.rs`. However, RER cannot ingest, frame, or inspect Modbus or DNP3 streams due to key protocol differences:
1. Modbus TCP encapsulates application PDUs within an MBAP header where payload length is indicated by a 2-octet big-endian field located at octets 4–5 rather than a 4-octet prefix at octet 0. RER lacks an MBAP-aware TCP framing engine.
2. DNP3 frames use the FT3 format, beginning with a 2-octet sync pattern (`0x05 0x64`) followed by a 1-octet length field that specifies user data bytes, with 16-bit CRCs inserted after the 10-octet header and after every subsequent 16 octets of user data. RER currently has no sync-hunting, block-CRC-aware framing engine.
3. RER's diagnostic engine (`crates/rer/src/diagnostics.rs`) and relay forwarding loops (`crates/rer/src/relay.rs`) do not parse or report Modbus transaction identifiers, unit identifiers, function codes, exception codes, or DNP3 source/destination station addresses, data link control flags, transport sequence counters, and application function codes.

This proposal specifies a modular, zero-dependency in-tree Modbus and DNP3 inspection and framing subsystem for RER. It defines native TCP framing modes (`FramingMode::ModbusTcp` and `FramingMode::Dnp3`), stream configurations in `crates/rer/src/config.rs`, diagnostic telemetry enrichment in `crates/rer/src/diagnostics.rs`, and stream ingress filtering in `crates/rer/src/relay.rs`. It identifies the smallest first implementation step for in-tree Modbus MBAP header parsing and framing, and explicitly establishes operational boundaries preserving RER's core function as a transparent engineering relay rather than an active PLC emulator or SCADA controller.

## Findings

### Survey of Modbus Application Protocol V1.1b3

The Modbus protocol was originally developed in 1979 by Modicon (now Schneider Electric) and is maintained by the Modbus Organization. The authoritative protocol specification is the [Modbus Application Protocol Specification V1.1b3](https://assets.noviams.com/novi-file-uploads/modbus/pdfs-and-documents/Modbus_Application_Protocol_V1_1b3.pdf).

Modbus operates at Level 7 of the OSI model as an application-layer messaging system. In TCP/IP networks, Modbus messages are exchanged over reserved system port 502 as Modbus TCP Application Data Units (ADUs).

#### Modbus Application Protocol (MBAP) Header

Modbus TCP encapsulates the Modbus Protocol Data Unit (PDU) inside an Application Data Unit (ADU) prefixed by the 7-octet MBAP header:

```text
+------------------------+------------------------+--------------------+-----------------+
| Transaction ID (2B)   | Protocol ID (2B)       | Length (2B)        | Unit ID (1B)    |
| Big-Endian u16         | Fixed 0x0000           | Big-Endian u16     | u8              |
+------------------------+------------------------+--------------------+-----------------+
| <--------------------------- MBAP Header (7 octets) ---------------------------------> |
```

The fields of the MBAP header are defined as follows:
- **Transaction Identifier (Octets 0–1)**: 16-bit big-endian unsigned integer used for transaction pairing between client requests and server responses. This allows multiplexed asynchronous transactions across a single TCP socket.
- **Protocol Identifier (Octets 2–3)**: 16-bit big-endian unsigned integer initialized to `0x0000` for Modbus protocol communications. Values other than `0x0000` indicate reserved or proprietary protocols.
- **Length Field (Octets 4–5)**: 16-bit big-endian unsigned integer specifying the remaining byte count of the message, including the 1-octet Unit Identifier and the entire Modbus PDU (Function Code + Data). Because the maximum Modbus PDU length is 253 octets, the maximum valid value of the Length field is 254 (`1 + 253`), and the minimum valid value is 2 (`1 + 1`, representing a Unit ID and 1-octet Function Code with no data).
- **Unit Identifier (Octet 6)**: 8-bit unsigned integer used for routing to sub-devices on serial bridges, multipoint drops, or virtual PLC controllers. On pure TCP devices, it is typically set to `0x00` or `0xFF`, but gateways map it to the remote RS-485 slave address (1–247).

The maximum total size of a Modbus TCP ADU on the wire is 260 octets (7 octets MBAP header + 253 octets PDU).

#### Modbus Function Codes and Exception Responses

The Modbus PDU consists of a 1-octet Function Code followed by function-specific Data:
- **Function Code (Octet 7)**: 1 octet in the range `1..=127` (`0x01..0x7F`).
  - Standard public function codes defined in V1.1b3 include:
    - `0x01` (1): Read Coils
    - `0x02` (2): Read Discrete Inputs
    - `0x03` (3): Read Holding Registers
    - `0x04` (4): Read Input Registers
    - `0x05` (5): Write Single Coil
    - `0x06` (6): Write Single Register
    - `0x07` (7): Read Exception Status (serial line diagnostics)
    - `0x08` (8): Diagnostics (sub-function code in following 2 octets)
    - `0x0B` (11): Get Comm Event Counter
    - `0x0C` (12): Get Comm Event Log
    - `0x0F` (15): Write Multiple Coils
    - `0x10` (16): Write Multiple Registers
    - `0x11` (17): Report Server ID
    - `0x14` (20): Read File Record
    - `0x15` (21): Write File Record
    - `0x16` (22): Mask Write Register
    - `0x17` (23): Read/Write Multiple Registers
    - `0x18` (24): Read FIFO Queue
    - `0x2B` (43): Encapsulated Interface Transport (e.g. MEI Type `0x0E` for Read Device Identification)
- **Exception Responses**: When a server encounters an error processing a request, it sets the most significant bit of the function code (`function_code | 0x80`, resulting in `0x81..0xFF`) and appends a 1-octet Exception Code:
  - `0x01`: Illegal Function (function not recognized or not implemented)
  - `0x02`: Illegal Data Address (register/coil address not valid on target)
  - `0x03`: Illegal Data Value (quantity or value out of allowable range)
  - `0x04`: Server Device Failure (unrecoverable error occurred while executing action)
  - `0x05`: Acknowledge (request accepted and scheduled, long execution time)
  - `0x06`: Server Device Busy (server engaged in long-running command)
  - `0x08`: Memory Parity Error (extended file or memory error)
  - `0x0A`: Gateway Path Unavailable (specialized gateway misconfiguration)
  - `0x0B`: Gateway Target Device Failed to Respond (subordinate device timeout)

### Survey of DNP3 IEEE 1815 Specification

DNP3 is defined by the IEEE Standards Association in [IEEE Std 1815-2012 (Standard for Electric Power Systems Communications - Distributed Network Protocol)](https://standards.ieee.org/standard/1815-2012.html), succeeding [IEEE Std 1815-2010](https://standards.ieee.org/ieee/1815/4894/). DNP3 is based on the IEC 60870-5 standard and EPA (Enhanced Performance Architecture) 3-layer model with a pseudo-transport function.

DNP3 communicates across TCP and UDP on registered port 20000.

#### Data Link Layer Framing (FT3 Format)

The DNP3 Data Link Layer packages link protocol data units (LPDUs) using the FT3 (Frame Format 3) variable frame structure. Every LPDU begins with a fixed 10-octet header followed by zero or more 16-octet data blocks:

```text
+----------------+----------------+----------------+----------------+----------------+----------------+
| Sync [0] 0x05  | Sync [1] 0x64  | Length (1B)    | Control (1B)   | Dest Addr (2B) | Src Addr (2B)  |
+----------------+----------------+----------------+----------------+----------------+----------------+
| CRC-16 (2B)    | Data Block 1 (up to 16B) + CRC-16 (2B) | Data Block 2 (up to 16B) + CRC-16 (2B)   |
+----------------+----------------------------------------+------------------------------------------+
```

1. **Sync Octets (Octets 0–1)**: Fixed 2-octet sequence `0x05 0x64` (`0x05` at index 0, `0x64` at index 1). Receivers scan stream data looking for this exact synchronization pattern.
2. **Length Field (Octet 2)**: 1-octet value in the range `5..=255`. It specifies the number of user octets following the Length field, excluding all CRC octets. Specifically:
   $$\text{Length} = \text{Control (1)} + \text{Destination (2)} + \text{Source (2)} + \text{User Data Length}$$
   The minimum valid length is 5 (header with 0 user data octets, e.g. for link status checks or acknowledgments). The maximum valid length is 255, permitting up to 250 octets of user data.
3. **Control Octet (Octet 3)**: An 8-bit bitfield controlling link-level communications:
   - **Bit 7 (DIR - Direction)**: `1` indicates transmission from master to outstation; `0` indicates transmission from outstation to master.
   - **Bit 6 (PRM - Primary)**: `1` indicates the frame originates from a primary/initiating station; `0` indicates a frame from a secondary/responding station.
   - **Bit 5 (FCB / RES)**:
     - When `PRM == 1`: Frame Count Bit (FCB), an alternating toggle bit used to detect duplicate or lost frames.
     - When `PRM == 0`: Reserved (fixed at `0`).
   - **Bit 4 (FCV / DFC)**:
     - When `PRM == 1`: Frame Count Valid (FCV), where `1` indicates that the FCB bit is valid and should be evaluated.
     - When `PRM == 0`: Data Flow Control (DFC), where `1` indicates secondary receiver buffer overflow.
   - **Bits 3..0 (Function Code)**: Link-layer control function:
     - Primary functions (`PRM == 1`): `0x00` Reset Link States, `0x01` Reset User Process, `0x02` Test Link States, `0x03` Confirmed User Data, `0x04` Unconfirmed User Data, `0x09` Request Link Status.
     - Secondary functions (`PRM == 0`): `0x00` ACK, `0x01` NACK, `0x0B` (11) Link Status, `0x0E` (14) Not Supported.
4. **Destination Address (Octets 4–5)**: 16-bit little-endian unsigned integer identifying target station (`0x0000..0xFFF0` individual unicast, `0xFFFC..0xFFFF` broadcast addresses).
5. **Source Address (Octets 6–7)**: 16-bit little-endian unsigned integer identifying originating station.
6. **Data Link Header CRC (Octets 8–9)**: 16-bit CRC covering the first 8 octets (Sync, Length, Control, Dest, Src). The generator polynomial is $x^{16} + x^{13} + x^{12} + x^{11} + x^{10} + x^8 + x^6 + x^5 + x^2 + 1$ (`0xA653` bit-reflected), initialized to `0x0000`, with the final result inverted (`CRC ^ 0xFFFF`).
7. **Data Blocks and Data CRCs**:
   User data is partitioned into blocks of at most 16 octets. Each block is immediately followed by a 2-octet CRC calculated with the same polynomial over that block's data octets. For 250 octets of user data, there are 15 full 16-octet blocks and 1 partial 10-octet block, yielding 16 blocks and 32 CRC octets.
   $$\text{Max LPDU Wire Size} = 10 \text{ (header)} + 250 \text{ (user data)} + 32 \text{ (CRCs)} = 292 \text{ octets}$$

#### Transport Layer (Pseudo-Transport Function)

DNP3 specifies a pseudo-transport function that prefixes user data with a 1-octet Transport Control header to segment large application PDUs (up to 2048 octets) across multiple LPDUs:

```text
+---------------+---------------+---------------------------------------+
| FIN (Bit 7)   | FIR (Bit 6)   | Sequence Number (Bits 5..0, 0..=63)   |
+---------------+---------------+---------------------------------------+
```

- **Bit 7 (FIN - Final)**: `1` indicates this LPDU carries the final segment of an application fragment; `0` indicates subsequent segments follow.
- **Bit 6 (FIR - First)**: `1` indicates this LPDU carries the initial segment of an application fragment; `0` indicates a continuation segment.
  - When both `FIR == 1` and `FIN == 1`, the entire application fragment fits within a single LPDU (unfragmented).
- **Bits 5..0 (Sequence Number)**: 6-bit modulo-64 sequence counter (`0..=63`). It increments by 1 for each successive segment within an application fragment and rolls over from 63 to 0.

#### Application Layer (APDU) Structure

The application fragment begins with an Application Control octet and a 1-octet Application Function Code:
- **Application Control Octet**:
  - Bit 7: `FIR` (First fragment of application transaction)
  - Bit 6: `FIN` (Final fragment of application transaction)
  - Bit 5: `CON` (Confirmation requested from receiver)
  - Bit 4: `UNS` (Unsolicited response)
  - Bits 3..0: `SEQ` (4-bit application sequence counter, `0..=15`)
- **Application Function Code Octet**:
  - Request functions: `0x01` Read, `0x02` Write, `0x03` Select, `0x04` Operate, `0x05` Direct Operate, `0x06` Direct Operate No Ack, `0x07` Immediate Freeze, `0x0D` Cold Restart, `0x0E` Warm Restart, `0x14` Enable Unsolicited, `0x15` Disable Unsolicited.
  - Response functions: `0x81` Response, `0x82` Unsolicited Response, `0x83` Authenticating Response.
  - Responses include two octets of Internal Indications (IIN1 and IIN2 bitfields indicating device restart, local trouble, buffer overflow, and configuration corrupt).

### Review of Existing Open-Source Implementations and Licensing

A review of open-source Modbus and DNP3 libraries was conducted to evaluate reference implementations and license compatibility with RER's Apache-2.0 license:

1. **`tokio-modbus` (Rust)**:
   - Repository: [slowtec/tokio-modbus](https://github.com/slowtec/tokio-modbus)
   - Scope: Pure Rust asynchronous Modbus library implementing Modbus TCP and RTU client/server stacks using Tokio.
   - License: Dual MIT / Apache-2.0, as verified in [LICENSES/Apache-2.0.txt](https://github.com/slowtec/tokio-modbus/blob/master/LICENSES/Apache-2.0.txt) and [LICENSES/MIT.txt](https://github.com/slowtec/tokio-modbus/blob/master/LICENSES/MIT.txt).
   - Compatibility Evaluation: Dual Apache-2.0 / MIT licensing is fully compatible with RER's Apache-2.0 license. However, `tokio-modbus` depends heavily on Tokio, `tokio-util` codecs, and futures runtimes. RER is architected around a synchronous, bounded-memory, zero-dependency engine with atomic cancellation flags (`read_exact_interruptible`). Pulling in `tokio-modbus` would introduce dozens of transitive crates, violating RER's zero-cost build constraints and CI performance goals.

2. **`opendnp3` (C++)**:
   - Repository: [dnp3/opendnp3](https://github.com/dnp3/opendnp3)
   - Scope: Industry-standard C++11 implementation of the IEEE 1815 DNP3 protocol stack with master, outstation, and channel management.
   - License: Apache License, Version 2.0, as verified in the project's [LICENSE](https://github.com/dnp3/opendnp3/blob/release/LICENSE) file.
   - Compatibility Evaluation: Apache-2.0 is fully compatible. However, `opendnp3` is written in C++ and requires a native CMake/C++ compiler toolchain. Integrating it into RER would require complex FFI bindings and C++ compiler prerequisites on CI runners, contradicting RER's pure-Rust guidelines (AGENTS.md). Furthermore, `opendnp3` implements full stateful outstations and masters, far exceeding RER's need for passive framing and inspection.

3. **`dnp3` by Step Function I/O (Rust)**:
   - Repository: [stepfunc/dnp3](https://github.com/stepfunc/dnp3)
   - Scope: Pure Rust DNP3 (IEEE 1815) implementation with C, C++, .NET, and Java bindings.
   - License: Proprietary / Non-commercial License, as verified in the project's [LICENSE.txt](https://github.com/stepfunc/dnp3/blob/master/LICENSE.txt) file.
   - Compatibility Evaluation: Incompatible with Apache-2.0. The license is non-commercial and strictly prohibits using the code, documentation, or test artifacts to design, specify, test, or implement any other protocol implementation (Section 2.6). No code, algorithms, or test fixtures from `stepfunc/dnp3` may be reviewed or incorporated into RER.

4. **`libmodbus` (C)**:
   - Repository: [stephane/libmodbus](https://github.com/stephane/libmodbus)
   - Scope: Widely deployed C library for Modbus TCP and RTU communication.
   - License: GNU Lesser General Public License v2.1 or later (LGPL-2.1-or-later), as verified in the project's [COPYING.LESSER](https://github.com/stephane/libmodbus/blob/master/COPYING.LESSER) file.
   - Compatibility Evaluation: LGPL-2.1 is a weak copyleft license that imposes static linking restrictions incompatible with RER's standalone Apache-2.0 binary releases without complex object relinking provisions. It also requires a C build toolchain.

5. **`pymodbus` (Python)**:
   - Repository: [pymodbus-dev/pymodbus](https://github.com/pymodbus-dev/pymodbus)
   - Scope: Comprehensive Python Modbus protocol stack providing client, server, and simulator implementations.
   - License: BSD 3-Clause License, as verified in the project's [LICENSE](https://github.com/pymodbus-dev/pymodbus/blob/dev/LICENSE) file.
   - Compatibility Evaluation: BSD-3-Clause is permissive and compatible with Apache-2.0. While Python code cannot be compiled into RER's binary, `pymodbus` provides an excellent reference tool for black-box loopback integration testing in CI environments.

### Deficiencies of Current RER Architecture for Modbus and DNP3

Inspecting RER's existing codebase highlights specific gaps that prevent processing Modbus and DNP3 streams:
1. **TCP Framing (`crates/rer/src/framing.rs`)**:
   - `read_frame_with_mode()` currently dispatches to `LengthPrefix`, `Ccsds`, `Mavlink`, `Mqtt`, and `Kiss`.
   - Modbus TCP requires reading the 7-octet MBAP header, validating Protocol ID `0x0000`, checking that Length is in `2..=254`, and reading the remaining `Length - 1` octets.
   - DNP3 requires scanning continuous byte streams for sync octets `0x05 0x64`, reading the 10-octet header, calculating total LPDU wire size from the Length field (accounting for 16-octet data blocks and 2-octet CRCs), and reading the complete LPDU.
2. **Stream Configuration (`crates/rer/src/config.rs`)**:
   - `FramingMode` lacks `ModbusTcp` and `Dnp3` enum variants.
   - `StreamConfig` lacks `ModbusConfig` and `Dnp3Config` sections for configuring inspection, Unit ID filtering, station address filtering, and validation error passthrough.
3. **Diagnostic Telemetry (`crates/rer/src/diagnostics.rs`)**:
   - `DiagnosticEvent` provides fields for CCSDS, MAVLink, MQTT, and KISS, but has no fields for Modbus (Transaction ID, Unit ID, Function Code, Exception Code) or DNP3 (Source Address, Destination Address, Control Function, Transport Sequence/Flags, Application Function Code).
4. **Relay Ingress Pipelines (`crates/rer/src/relay.rs`)**:
   - `StreamRunner::run_stream()` dispatches CCSDS, MAVLink, MQTT, and KISS ingress processing, but has no hooks for Modbus or DNP3 ingress parsing, allowlist/blocklist filtering, or validation drop accounting.

### Justification for an In-Tree Implementation

Implementing Modbus MBAP and DNP3 framing and header parsing directly in RER requires no external dependencies. The required algorithms consist of:
- Fixed-offset byte reading and big-endian/little-endian integer unpacking.
- Standard 16-bit CRC table calculation for DNP3 FT3 framing ($x^{16} + x^{13} + x^{12} + x^{11} + x^{10} + x^8 + x^6 + x^5 + x^2 + 1$).
- Bounded buffer validation with zero dynamic heap reallocation in the forwarding loop.

An in-tree implementation ensures full compliance with Apache-2.0 licensing, zero added crate dependencies under `--locked`, zero compilation overhead on GitHub Actions runners, and strict adherence to SPEC §5, §8, and §14.

### Sources checked

- [https://assets.noviams.com/novi-file-uploads/modbus/pdfs-and-documents/Modbus_Application_Protocol_V1_1b3.pdf](https://assets.noviams.com/novi-file-uploads/modbus/pdfs-and-documents/Modbus_Application_Protocol_V1_1b3.pdf) — HTTP 200
- [https://standards.ieee.org/standard/1815-2012.html](https://standards.ieee.org/standard/1815-2012.html) — HTTP 200
- [https://standards.ieee.org/ieee/1815/4894/](https://standards.ieee.org/ieee/1815/4894/) — HTTP 200
- [https://github.com/slowtec/tokio-modbus](https://github.com/slowtec/tokio-modbus) — HTTP 200
- [https://github.com/slowtec/tokio-modbus/blob/master/LICENSES/Apache-2.0.txt](https://github.com/slowtec/tokio-modbus/blob/master/LICENSES/Apache-2.0.txt) — HTTP 200
- [https://github.com/slowtec/tokio-modbus/blob/master/LICENSES/MIT.txt](https://github.com/slowtec/tokio-modbus/blob/master/LICENSES/MIT.txt) — HTTP 200
- [https://github.com/dnp3/opendnp3](https://github.com/dnp3/opendnp3) — HTTP 200
- [https://github.com/dnp3/opendnp3/blob/release/LICENSE](https://github.com/dnp3/opendnp3/blob/release/LICENSE) — HTTP 200
- [https://github.com/stephane/libmodbus](https://github.com/stephane/libmodbus) — HTTP 200
- [https://github.com/stephane/libmodbus/blob/master/COPYING.LESSER](https://github.com/stephane/libmodbus/blob/master/COPYING.LESSER) — HTTP 200
- [https://github.com/pymodbus-dev/pymodbus](https://github.com/pymodbus-dev/pymodbus) — HTTP 200
- [https://github.com/pymodbus-dev/pymodbus/blob/dev/LICENSE](https://github.com/pymodbus-dev/pymodbus/blob/dev/LICENSE) — HTTP 200
- [https://github.com/stepfunc/dnp3](https://github.com/stepfunc/dnp3) — HTTP 200
- [https://github.com/stepfunc/dnp3/blob/master/LICENSE.txt](https://github.com/stepfunc/dnp3/blob/master/LICENSE.txt) — HTTP 200

## Proposal

### Scope and Supported Subset

Under SPEC §5, §8, and §14, RER will introduce modular stream inspection, TCP framing, and diagnostic telemetry for Modbus TCP and DNP3:

1. **Modbus TCP Framing and Inspection**:
   - MBAP header framing over TCP: read the 7-octet MBAP header, validate Protocol ID `0x0000`, compute message length from the Length field, enforce maximum ADU limit (260 octets), and read remaining PDU octets.
   - Header inspection: extract Transaction ID, Protocol ID, Length, Unit ID, Function Code, Exception Code (if `function_code >= 0x80`), and base address/register count for common public functions (`0x01..0x04`, `0x05`, `0x06`, `0x0F`, `0x10`).
   - Unit ID and Function Code filtering: optional allowlists for Unit IDs and Function Codes.
   - Validation and passthrough policy: configurable `passthrough_on_error` flag to drop malformed frames or forward them unchanged with diagnostic warnings.
2. **DNP3 Framing and Inspection**:
   - FT3 link-layer framing over TCP: synchronize on `0x05 0x64`, read the 10-octet header, calculate total LPDU size including 16-octet block CRCs, and read the complete LPDU.
   - Optional link-layer CRC verification: validate header and block CRCs using generator polynomial `0xA653`.
   - Header inspection: extract DIR, PRM, FCB, FCV, DFC, link function code, destination address, source address.
   - Transport layer inspection: extract FIN, FIR, and 6-bit transport sequence counter.
   - Application layer inspection: extract application FIR, FIN, CON, UNS, application sequence counter, and application function code.
   - Station address filtering: optional allowlists for destination and source station addresses.
3. **Diagnostic Telemetry Integration**:
   - Enrich `DiagnosticEvent` with domain-specific Modbus and DNP3 metadata fields.
   - Track sequence continuity across DNP3 transport segments and Modbus transaction identifiers.

### Proposed Codebase Integration

The proposed integration grounds all modifications directly in existing RER modules:

#### 1. Configuration (`crates/rer/src/config.rs`)

Define `ModbusConfig` and `Dnp3Config`, and extend `FramingMode` and `StreamConfig`:

```rust
/// Configuration for Modbus TCP stream framing and inspection (SPEC §5, §8, §14).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModbusConfig {
    /// Enable Modbus packet inspection and framing. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional allowlist of Unit IDs (slave addresses) to forward (e.g. [1, 2, 5]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_unit_ids: Option<Vec<u8>>,

    /// Optional allowlist of Function Codes to forward (e.g. [1, 2, 3, 4]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_function_codes: Option<Vec<u8>>,

    /// Forward frames unmodified when Modbus parsing encounters validation errors. Defaults to false.
    #[serde(default)]
    pub passthrough_on_error: bool,

    /// Optional framing mode override ("length_prefix", "ccsds", "mavlink", "mqtt", "kiss", "modbus_tcp", or "dnp3").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}

/// Configuration for DNP3 stream framing and inspection (SPEC §5, §8, §14).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dnp3Config {
    /// Enable DNP3 packet inspection and framing. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Validate 16-bit CRC on header and data blocks. Defaults to true.
    #[serde(default = "default_true")]
    pub validate_crc: bool,

    /// Optional allowlist of destination station addresses to forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_destinations: Option<Vec<u16>>,

    /// Optional allowlist of source station addresses to forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_sources: Option<Vec<u16>>,

    /// Forward frames unmodified when DNP3 validation fails. Defaults to false.
    #[serde(default)]
    pub passthrough_on_error: bool,

    /// Optional framing mode override ("length_prefix", "ccsds", "mavlink", "mqtt", "kiss", "modbus_tcp", or "dnp3").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}
```

Modifications to `crates/rer/src/config.rs`:
- Extend `FramingMode` with variants:
  ```rust
  #[serde(alias = "MODBUS", alias = "modbus", alias = "modbus_tcp")]
  ModbusTcp,
  #[serde(alias = "DNP3", alias = "dnp3")]
  Dnp3,
  ```
- Add `modbus: Option<ModbusConfig>` and `dnp3: Option<Dnp3Config>` to `StreamConfig`.
- In `StreamConfig::source_framing()` and `StreamConfig::destination_framing()`, inspect `modbus.as_ref().and_then(|m| m.framing)` and `dnp3.as_ref().and_then(|d| d.framing)`.
- In `Config::validate()`, verify that `filter_unit_ids` contains values in `0..=255`, and `filter_function_codes` contains values in `1..=127`.

#### 2. TCP Stream Framing (`crates/rer/src/framing.rs`)

Introduce dedicated framing functions for Modbus TCP and DNP3 FT3:

- `pub fn read_modbus_frame<R: Read>(reader: &mut R, max_frame_size: usize, shutdown: &AtomicBool) -> io::Result<Option<Vec<u8>>>`:
  1. Read 7-octet MBAP header using `read_exact_interruptible`.
  2. Verify Protocol ID `octets[2..4] == [0x00, 0x00]`.
  3. Extract Length `u16::from_be_bytes([octets[4], octets[5]])`.
  4. Verify Length is within `2..=254` (minimum 1 octet Unit ID + 1 octet Function Code; maximum 253 octet PDU + 1).
  5. Validate total frame length `7 + (Length - 1) <= max_frame_size`.
  6. Read remaining `Length - 1` octets into payload buffer and return complete ADU.
- `pub fn write_modbus_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()>`:
  1. Verify `frame.len() >= 7` and write buffer directly to writer.
- `pub fn read_dnp3_frame<R: Read>(reader: &mut R, max_frame_size: usize, shutdown: &AtomicBool) -> io::Result<Option<Vec<u8>>>`:
  1. Scan incoming byte stream looking for sync octets `[0x05, 0x64]`.
  2. Read next 8 octets to complete 10-octet FT3 header.
  3. Extract Length octet `L = header[2]`. Validate $5 \le L \le 255$.
  4. Compute user data bytes $U = L - 5$.
  5. Calculate number of data blocks $B = \lceil U / 16 \rceil$ and total CRC bytes $2 \times B$.
  6. Compute total LPDU wire size $W = 10 + U + 2 \times B$. Verify $W \le \min(292, \text{max\_frame\_size})$.
  7. Read remaining $W - 10$ octets into buffer and return complete LPDU.
- `pub fn write_dnp3_frame<W: Write>(writer: &mut W, frame: &[u8]) -> io::Result<()>`:
  1. Write framed LPDU directly to writer.
- Dispatch `FramingMode::ModbusTcp` and `FramingMode::Dnp3` in `read_frame_with_mode()` and `write_frame_with_mode()`.

#### 3. Diagnostics and Inspection Engine (`crates/rer/src/diagnostics.rs`)

Introduce protocol parsers, metadata structures, and diagnostic event fields:

1. **Modbus Metadata and Parser**:
   ```rust
   #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
   pub struct ModbusMetadata {
       pub transaction_id: u16,
       pub protocol_id: u16,
       pub unit_id: u8,
       pub function_code: u8,
       pub is_exception: bool,
       pub exception_code: Option<u8>,
   }

   pub fn parse_modbus_header(payload: &[u8]) -> Result<ModbusMetadata, ModbusParseError>;
   ```
2. **DNP3 Metadata and Parser**:
   ```rust
   #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
   pub struct Dnp3Metadata {
       pub destination: u16,
       pub source: u16,
       pub is_primary: bool,
       pub direction: bool,
       pub control_function: u8,
       pub transport_fir: Option<bool>,
       pub transport_fin: Option<bool>,
       pub transport_sequence: Option<u8>,
       pub application_function: Option<u8>,
       pub crc_valid: bool,
   }

   pub fn parse_dnp3_frame(payload: &[u8], validate_crc: bool) -> Result<Dnp3Metadata, Dnp3ParseError>;
   ```
3. **Diagnostic Event Fields**:
   Extend `DiagnosticEvent` with:
   - `modbus_transaction_id: Option<u16>`
   - `modbus_unit_id: Option<u8>`
   - `modbus_function_code: Option<u8>`
   - `modbus_is_exception: Option<bool>`
   - `modbus_exception_code: Option<u8>`
   - `dnp3_source: Option<u16>`
   - `dnp3_destination: Option<u16>`
   - `dnp3_control_function: Option<u8>`
   - `dnp3_is_primary: Option<bool>`
   - `dnp3_transport_fir: Option<bool>`
   - `dnp3_transport_fin: Option<bool>`
   - `dnp3_transport_sequence: Option<u8>`
   - `dnp3_application_function: Option<u8>`
   - `dnp3_crc_valid: Option<bool>`
   Add corresponding builder methods (`with_modbus_metadata()`, `with_dnp3_metadata()`).

#### 4. Forwarding Loops and Ingress Filtering (`crates/rer/src/relay.rs`)

In `StreamRunner::run_stream()`:
- Introduce `ModbusIngressContext` and `process_modbus_ingress()`:
  - If `stream.modbus` is configured and enabled:
    - Invoke `parse_modbus_header(payload)`.
    - On parse error: if `passthrough_on_error` is false, emit `DiagnosticStage::Dropped` and drop frame; otherwise emit warning and forward.
    - Check `filter_unit_ids`; if not in allowlist, drop frame and increment `stats.drops_filtering`.
    - Check `filter_function_codes`; if not in allowlist, drop frame and increment `stats.drops_filtering`.
    - Enrich egress `DiagnosticEvent` with Modbus metadata.
- Introduce `Dnp3IngressContext` and `process_dnp3_ingress()`:
  - If `stream.dnp3` is configured and enabled:
    - Invoke `parse_dnp3_frame(payload, config.validate_crc)`.
    - On parse or CRC error: if `passthrough_on_error` is false, drop frame and record drop; otherwise forward.
    - Check `filter_destinations` and `filter_sources`; drop if filtered.
    - Track DNP3 transport sequence continuity (`transport_sequence` rollover from 63 to 0).
    - Enrich egress `DiagnosticEvent` with DNP3 metadata.

### Smallest First Step

The smallest initial implementation step that can be independently developed, reviewed, and merged with complete test evidence is:

1. Implement pure Modbus MBAP header validation and parsing functions in `crates/rer/src/framing.rs` (or a dedicated `crates/rer/src/modbus.rs`):
   ```rust
   pub fn parse_mbap_header(raw: &[u8]) -> Result<MbapHeader, ModbusParseError>;
   pub fn read_modbus_frame<R: Read>(reader: &mut R, max_frame_size: usize, shutdown: &AtomicBool) -> io::Result<Option<Vec<u8>>>;
   ```
2. Include comprehensive unit tests verifying:
   - Successful parsing of valid 7-octet MBAP headers.
   - Rejection of frames with Protocol ID $\ne 0x0000$.
   - Rejection of frames with Length $< 2$ or Length $> 254$.
   - Detection of Modbus exception responses (`function_code >= 0x80`) and extraction of exception codes.
   - Stream reassembly across partial TCP reads and graceful shutdown via `AtomicBool`.
3. This step delivers verified framing and parsing primitives with zero external dependencies and zero risk to existing relay operations.

## Not claimed

This proposal and any subsequent implementation of Task RER-F-068 explicitly do NOT claim or establish:
1. **Full Modbus Master or Slave PLC Emulation**: RER does not implement or emulate a programmable logic controller (PLC), remote terminal unit (RTU), or Modbus server memory model. It does not maintain coil state tables, discrete input bitmaps, input register memory, or 16-bit holding register tables. It does not execute PLC scan loops or ladder logic.
2. **DNP3 Outstation State Machines**: RER does not maintain stateful DNP3 outstation or master protocol state machines. It does not implement internal indication (IIN) bit management, event buffer queues (Class 1, Class 2, Class 3 event storage), freeze counter buffers, select-before-operate (SBO) arm/execute timers, or master periodic polling schedules.
3. **SCADA Control Execution**: RER does not interpret, synthesize, validate, or execute supervisory control actions (such as Control Relay Output Blocks [CROB], analog setpoint commands, or trip/close breaker controls). RER acts strictly as a transparent engineering proxy and diagnostic observer.
4. **Modbus Serial (RTU / ASCII) Physical Layer Management**: RER does not manage RS-232, RS-422, or RS-485 serial transceivers, UART hardware clocks, baud rate generation, parity bit calculation, or the strict $3.5\text{-character}$ inter-frame silence interval timing required on physical Modbus RTU buses.
5. **DNP3 Secure Authentication (SAv5)**: RER does not implement cryptographic challenge/response protocols, key wrap algorithms, session key exchanges, or aggressive mode authentication specified in IEEE 1815-2012 Secure Authentication (SAv5).
6. **Hard Real-Time Latency Guarantees**: RER does not guarantee sub-millisecond deterministic latency or synchronous bus timing over non-deterministic operating systems or packet-switched IP networks.

## Open questions

The following architectural decisions require owner determination:

1. **Modbus RTU Encapsulation over TCP/UDP**:
   Certain legacy industrial devices encapsulate raw Modbus RTU frames (Slave Address + Function Code + Data + CRC-16) directly inside TCP or UDP payloads without an MBAP header. Should RER support a configurable `encapsulation: "mbap" | "rtu"` option, or restrict Modbus TCP support exclusively to standard MBAP-encapsulated frames (RFC/Modbus TCP port 502)?
2. **DNP3 Multi-Segment Application Reassembly**:
   DNP3 application fragments can span multiple LPDUs across the pseudo-transport layer (using FIR/FIN flags). Should RER inspect each LPDU independently on ingress (reporting transport sequence and partial fragment status), or should RER optionally buffer segments until `FIN == 1` to perform deep application-layer inspection on the complete reassembled APDU?
3. **DNP3 Resynchronization Policy on Sync Corruption**:
   If a TCP stream contains corrupted data where sync octets `0x05 0x64` or header CRC verification fails, should RER close the TCP socket immediately, or search byte-by-byte through the buffer to resynchronize on the next valid `0x05 0x64` sync sequence?
4. **Address and Station Filtering Syntax**:
   Should Modbus Unit ID and DNP3 Station Address filtering support range syntax (e.g. `1..=10`) and wildcard rules in `crates/rer/src/config.rs` in addition to explicit discrete lists?
5. **Configuration Hierarchy**:
   Should Modbus and DNP3 configurations reside as top-level fields on `StreamConfig` (`stream.modbus` and `stream.dnp3`, mirroring `stream.ccsds`, `stream.mavlink`, `stream.mqtt`, `stream.kiss`), or should they be unified under a composite industrial inspection structure (`stream.industrial.modbus`)?
