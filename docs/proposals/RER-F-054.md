# RER-F-054: MQTT Research and Integration Proposal

## Summary

This proposal provides the architectural survey, licensing evaluation, and technical design for introducing passive MQTT (Message Queuing Telemetry Transport) protocol inspection, stream framing, and diagnostic telemetry into RER (RER Engineering Relay), fulfilling the research prerequisite for Task RER-F-054 under SPEC §14 and §8.

MQTT is an established, lightweight publish/subscribe messaging protocol widely deployed across Internet of Things (IoT) ecosystems, industrial telemetry, edge computing gateways, flight telemetry testbeds, and aerospace ground segment instrumentation. While MQTT applications typically communicate over reliable byte streams (such as TCP) or constrained datagram networks (via MQTT-SN over UDP), RER currently provides generic fixed-length framing, 4-byte big-endian framing, and CCSDS Space Packet framing. However, standard MQTT network flows present protocol-specific framing and parsing characteristics that RER's existing framing engine cannot handle natively:
1. **Self-Delimited Variable-Length Framing**: MQTT uses a fixed 1-octet control header followed by a 1-to-4 octet variable-length integer encoding the remaining packet length. Concatenated MQTT packets on a TCP stream cannot be framed by RER's default 4-byte big-endian prefix framing without re-encapsulation or stream corruption.
2. **Datagram Sensor Networks (MQTT-SN)**: In constrained telemetry environments where TCP is unavailable or undesirable, MQTT for Sensor Networks (MQTT-SN) conveys publish/subscribe telemetry over UDP datagrams using an upfront 1-octet or 3-octet packet length indicator and registered 16-bit Topic IDs.
3. **Diagnostic Truthfulness**: Field telemetry relays require non-intrusive visibility into packet types, QoS delivery levels, packet identifiers, and protocol anomalies without terminating TLS sessions or interfering with application-level broker state.

This proposal surveys MQTT v3.1.1, MQTT v5.0, and MQTT-SN specifications; evaluates open-source implementations and their licenses against RER's Apache-2.0 codebase; outlines modular inspection, stream framing, and diagnostics integration into `crates/rer/src/config.rs`, `crates/rer/src/diagnostics.rs`, and `crates/rer/src/relay.rs`; explicitly disclaims broker functionality, topic subscription filtering, and message persistence; and establishes the smallest first implementation step for an in-tree fixed header parser and length decoder.

## Findings

### MQTT Protocol Specifications and Wire Architecture

The MQTT protocol standard is governed by the OASIS Message Queuing Telemetry Transport Technical Committee and published as international open standards:
- [MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html): OASIS Standard (29 October 2014), edited by Andrew Banks and Rahul Gupta.
- [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html): OASIS Standard (07 March 2019), edited by Andrew Banks, Ed Briggs, Ken Borgendale, and Rahul Gupta.
- [MQTT Specification Resource](https://mqtt.org/mqtt-specification/): Central specification repository maintained by the MQTT community.

Both MQTT v3.1.1 and MQTT v5.0 organize communication around discrete MQTT Control Packets transmitted over an ordered, lossless byte stream (such as TCP/IP). Every MQTT control packet consists of:
1. A **Fixed Header**, present in all control packets (minimum 2 octets, maximum 5 octets).
2. A **Variable Header**, present in certain control packet types.
3. A **Payload**, present in certain control packet types.

#### 1. Packet Fixed Header

As specified in Section 2.2 of [MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) and Section 2.1 of [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html), the first byte of every MQTT control packet contains two 4-bit fields:
- **Bits 7..4 (MQTT Control Packet Type)**: Unsigned 4-bit integer specifying the packet type (values 1 through 15). Value 0 is forbidden and reserved.
- **Bits 3..0 (Flags specific to each Control Packet type)**: Control flags whose valid bit combinations are strictly prescribed by the standard.

The standard MQTT Control Packet types are:
- `1` (`CONNECT`): Client request to connect to Server (direction: Client to Server). Flags must be `0000`.
- `2` (`CONNACK`): Connect acknowledgment (direction: Server to Client). Flags must be `0000`.
- `3` (`PUBLISH`): Publish message (direction: Bidirectional). Flags define message delivery parameters:
  - Bit 3: `DUP` (Duplicate delivery flag for QoS > 0).
  - Bits 2..1: `QoS` (Quality of Service level: `00` = QoS 0 at most once; `01` = QoS 1 at least once; `10` = QoS 2 exactly once; `11` = Reserved/Invalid).
  - Bit 0: `RETAIN` (Retain flag instructing the broker to store the message).
- `4` (`PUBACK`): Publish acknowledgment for QoS 1 (direction: Bidirectional). Flags must be `0000`.
- `5` (`PUBREC`): Publish received for QoS 2 step 1 (direction: Bidirectional). Flags must be `0000`.
- `6` (`PUBREL`): Publish release for QoS 2 step 2 (direction: Bidirectional). Flags must be `0010` (bit 1 is set).
- `7` (`PUBCOMP`): Publish complete for QoS 2 step 3 (direction: Bidirectional). Flags must be `0000`.
- `8` (`SUBSCRIBE`): Subscribe request (direction: Client to Server). Flags must be `0010` (bit 1 is set).
- `9` (`SUBACK`): Subscribe acknowledgment (direction: Server to Client). Flags must be `0000`.
- `10` (`UNSUBSCRIBE`): Unsubscribe request (direction: Client to Server). Flags must be `0010` (bit 1 is set).
- `11` (`UNSUBACK`): Unsubscribe acknowledgment (direction: Server to Client). Flags must be `0000`.
- `12` (`PINGREQ`): PING request (direction: Client to Server). Flags must be `0000`.
- `13` (`PINGRESP`): PING response (direction: Server to Client). Flags must be `0000`.
- `14` (`DISCONNECT`): Disconnect notification (Client to Server in v3.1.1; Bidirectional in v5.0). Flags must be `0000`.
- `15` (`AUTH`): Authentication exchange (direction: Bidirectional, introduced in MQTT v5.0; reserved in v3.1.1). Flags must be `0000`.

Any packet received with flag bits differing from the required values represents a malformed packet and a protocol violation.

#### 2. Variable-Length Remaining Length Encoding

Directly following the first fixed header byte is the **Remaining Length** field, defined in Section 2.2.3 of [MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) and Section 2.1.4 of [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) (designated as a *Variable Byte Integer* in v5.0).

The Remaining Length specifies the total number of bytes remaining in the packet, spanning the variable header and the payload. It is encoded as a variable-length integer using between 1 and 4 octets:
- For each octet, the lower 7 bits (bits 0..6) encode numeric data in base-128 least-significant-digit-first (little-endian) order.
- The most significant bit (bit 7, `0x80`) is the continuation bit: `1` indicates that another octet follows, while `0` indicates that this is the final octet of the Remaining Length field.

Capacity bounds by byte length:
- **1 octet**: Values 0 to 127 (`0x00` to `0x7F`).
- **2 octets**: Values 128 to 16,383 (`0x80 0x01` to `0xFF 0x7F`).
- **3 octets**: Values 16,384 to 2,097,151 (`0x80 0x80 0x01` to `0xFF 0xFF 0x7F`).
- **4 octets**: Values 2,097,152 to 268,435,455 ($2^{28}-1 = 268,435,455$ octets, approximately 256 megabytes) (`0x80 0x80 0x80 0x01` to `0xFF 0xFF 0xFF 0x7F`).

Decoding algorithm (pseudo-code):
```text
multiplier = 1
value = 0
bytes_read = 0
loop:
    encoded_byte = next_byte()
    bytes_read += 1
    value += (encoded_byte & 0x7F) * multiplier
    if (encoded_byte & 0x80) == 0:
        return (value, bytes_read)
    multiplier *= 128
    if bytes_read == 4:
        error("Malformed Variable Byte Integer: exceeds 4 octets")
```

The total frame size on wire is:
$$\text{Total Packet Length} = 1 + \text{Remaining Length Field Size (1 to 4)} + \text{Remaining Length Value}$$

The minimum MQTT packet length is 2 octets (e.g., `PINGREQ` encoded as `0xC0 0x00` or `PINGRESP` encoded as `0xD0 0x00`).

#### 3. Evolution from MQTT v3.1.1 to MQTT v5.0

MQTT v5.0 introduces architectural extensions while preserving the fixed header structure:
- **Packet Type 15 (`AUTH`)**: Added in [MQTT Version 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) for enhanced authentication flows (such as SCRAM or challenge/response handshakes).
- **Properties Mechanism**: v5.0 introduces property blocks in variable headers encoded as a Variable Byte Integer property length followed by standardized key-value property records. Properties support features such as Session Expiry Interval, Topic Aliases, Maximum Packet Size, User Properties (metadata key-value pairs), and Content Type.
- **Reason Codes**: v5.0 replaces basic return codes with 1-octet standardized Reason Codes across all acknowledgment packets (`CONNACK`, `PUBACK`, `PUBREC`, `PUBREL`, `PUBCOMP`, `SUBACK`, `UNSUBACK`, `DISCONNECT`, `AUTH`), enabling explicit error diagnostics.
- **Bidirectional Disconnect**: In v3.1.1, `DISCONNECT` was strictly client-to-server with zero remaining length. In v5.0, servers can send `DISCONNECT` packets to clients with a Reason Code and Property block explaining the disconnection cause.

### MQTT-SN (MQTT for Sensor Networks)

MQTT for Sensor Networks is governed by the OASIS MQTT-SN Subcommittee:
- [MQTT-SN Specification v1.2](https://www.oasis-open.org/committees/download.php/56041/MQTT-SN_spec_v1.2.pdf): Specification authored by Andy Stanford-Clark and Hong Linh Truong (IBM).
- [OASIS MQTT-SN Technical Committee](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=mqtt-sn): Official OASIS standardization committee home.

MQTT-SN adapts the MQTT publish/subscribe paradigm for resource-constrained devices operating over non-TCP networks, including wireless sensor networks (ZigBee, 6LoWPAN, Bluetooth Low Energy) and raw UDP datagram transports.

#### Packet Framing and Header Architecture in MQTT-SN

Unlike core MQTT's variable-byte remaining length placed after the type byte, MQTT-SN places the packet length at the very beginning of the frame:
1. **1-Octet Length Indicator (Packets $\le 255$ octets)**:
   - If Byte 0 is not `0x01`, Byte 0 represents the total packet length in octets (1 to 255), including the length octet itself.
   - Byte 1 represents the `MsgType` (Message Type).
2. **3-Octet Extended Length Indicator (Packets $> 255$ octets up to 65,535 octets)**:
   - If Byte 0 is `0x01`, an extended 3-octet header is used:
     - Byte 0: `0x01` (flag indicator).
     - Bytes 1..2: 16-bit big-endian integer specifying the total packet length (including the 3 length octets).
     - Byte 3: `MsgType` (Message Type).

#### MQTT-SN Message Types

The `MsgType` field defines the control message:
- `0x00` (`ADVERTISE`): Gateway periodic broadcast.
- `0x01` (`SEARCHGW`): Client broadcast searching for gateways.
- `0x02` (`GWINFO`): Gateway information response.
- `0x04` (`CONNECT`): Client connection request.
- `0x05` (`CONNACK`): Connection acknowledgment.
- `0x06` (`WILLTOPICREQ`): Gateway request for client will topic.
- `0x07` (`WILLTOPIC`): Client will topic declaration.
- `0x08` (`WILLMSGREQ`): Gateway request for client will message.
- `0x09` (`WILLMSG`): Client will message declaration.
- `0x0A` (`REGISTER`): Topic name registration (client or gateway).
- `0x0B` (`REGACK`): Registration acknowledgment assigning a 16-bit Topic ID.
- `0x0C` (`PUBLISH`): Publish message using 16-bit Topic ID or short topic name.
- `0x0D` (`PUBACK`): Publish acknowledgment.
- `0x0E` (`PUBCOMP`): QoS 2 publish complete.
- `0x0F` (`PUBREC`): QoS 2 publish received.
- `0x10` (`PUBREL`): QoS 2 publish release.
- `0x12` (`SUBSCRIBE`): Subscription request using Topic ID, short name, or topic name.
- `0x13` (`SUBACK`): Subscription acknowledgment.
- `0x14` (`UNSUBSCRIBE`): Unsubscribe request.
- `0x15` (`UNSUBACK`): Unsubscribe acknowledgment.
- `0x16` (`PINGREQ`): Ping request (also used by sleeping clients to check for buffered messages).
- `0x17` (`PINGRESP`): Ping response.
- `0x18` (`DISCONNECT`): Disconnect notification (can specify sleep duration).
- `0x1A` (`WILLTOPICUPD`): Will topic update.
- `0x1B` (`WILLTOPICRESP`): Will topic update acknowledgment.
- `0x1C` (`WILLMSGUPD`): Will message update.
- `0x1D` (`WILLMSGRESP`): Will message update acknowledgment.

#### Key Architectural Distinctions Between MQTT and MQTT-SN
- **Transport Independence**: MQTT-SN does not require a persistent connection-oriented TCP stream; it is designed for datagram transports (UDP) where datagram boundaries can coincide with message boundaries.
- **Topic Identifiers**: Long UTF-8 topic strings are replaced with 16-bit integer Topic IDs (`topic_id`) negotiated via `REGISTER`/`REGACK`, or 2-character short topic names, significantly reducing over-the-air packet overhead.
- **Gateway Intermediary**: A transparent or aggregating MQTT-SN Gateway translates between MQTT-SN clients and standard MQTT brokers.
- **Client Sleep Support**: Clients can enter an asleep state and disconnect while maintaining their session; gateways buffer downstream messages until the sleeping client queries with a `PINGREQ`.

### Open-Source Implementation Survey and License Review

Existing open-source MQTT implementations were surveyed to evaluate their design patterns and determine whether their license terms permit inclusion or code reuse within RER's Apache-2.0 codebase:

1. **Bytebeam rumqtt (`rumqttc` / `rumqttd`)**:
   - Repository: [bytebeamio/rumqtt](https://github.com/bytebeamio/rumqtt)
   - License: [Apache License 2.0](https://raw.githubusercontent.com/bytebeamio/rumqtt/master/LICENSE)
   - Evaluation: Pure Rust implementation providing an async/sync client (`rumqttc`) and a high-performance embedded broker (`rumqttd`). Licensed under Apache-2.0, which is fully compatible with RER's Apache-2.0 license. However, `rumqtt` brings external dependencies (`tokio`, `bytes`, `flume`) that exceed RER's minimalist, zero-dependency core requirements.
2. **mqttrs**:
   - Repository: [00imvj00/mqttrs](https://github.com/00imvj00/mqttrs)
   - License: [Apache License 2.0](https://raw.githubusercontent.com/00imvj00/mqttrs/master/LICENSE)
   - Evaluation: A lightweight, zero-copy MQTT 3.1.1 codec library for Rust with optional `no_std` support. Licensed under Apache-2.0, which is fully compatible with RER. Its parsing and state machine models offer clear design references for in-tree zero-dependency decoding.
3. **Eclipse Mosquitto**:
   - Repository: [eclipse/mosquitto](https://github.com/eclipse/mosquitto)
   - License: [EPL-2.0 OR BSD-3-Clause (EDL-1.0)](https://raw.githubusercontent.com/eclipse/mosquitto/master/LICENSE.txt)
   - Evaluation: The industry-standard C-based MQTT broker and client library. Mosquitto is dual-licensed under the Eclipse Public License 2.0 (EPL-2.0) and the Eclipse Distribution License 1.0 (EDL-1.0, which is a BSD 3-Clause license). While EPL-2.0 is a weak copyleft license requiring reciprocal source availability for modified files, EDL-1.0 / BSD-3-Clause is permissive and compatible with Apache-2.0.
4. **Eclipse Paho Rust (`paho.mqtt.rust`)**:
   - Repository: [eclipse/paho.mqtt.rust](https://github.com/eclipse/paho.mqtt.rust)
   - License: [EPL-2.0 OR BSD-3-Clause (EDL-1.0)](https://raw.githubusercontent.com/eclipse/paho.mqtt.rust/master/LICENSE)
   - Evaluation: Official Eclipse Foundation Rust wrapper around the C library `paho.mqtt.c`. Dual-licensed under EPL-2.0 / EDL-1.0 (compatible with Apache-2.0 under EDL-1.0). However, it introduces complex C FFI dependencies and dynamic linking requirements that conflict with RER's pure Rust zero-cost CI compilation mandate (AGENTS §1).
5. **EMQX**:
   - Repository: [emqx/emqx](https://github.com/emqx/emqx)
   - License: [Business Source License 1.1 (BSL-1.1)](https://raw.githubusercontent.com/emqx/emqx/master/LICENSE)
   - Evaluation: High-concurrency Erlang/Elixir-based distributed MQTT broker. Formerly Apache-2.0, EMQX transitioned to BSL-1.1. BSL-1.1 is NOT an OSI-approved open-source license and contains production and commercial use restrictions; it is **incompatible** with Apache-2.0. No code or derivative logic from EMQX may be incorporated into RER.
6. **Eclipse Paho MQTT-SN Embedded C**:
   - Repository: [eclipse-paho/paho.mqtt-sn.embedded-c](https://github.com/eclipse-paho/paho.mqtt-sn.embedded-c)
   - License: [EPL-2.0 OR BSD-3-Clause (EDL-1.0)](https://raw.githubusercontent.com/eclipse-paho/paho.mqtt-sn.embedded-c/master/LICENSE)
   - Evaluation: Embedded C client and transparent/aggregating gateway implementation for MQTT-SN. Dual-licensed under EPL-2.0 / EDL-1.0, compatible under EDL-1.0 terms.
7. **mqtt-sn-tools**:
   - Repository: [njh/mqtt-sn-tools](https://github.com/njh/mqtt-sn-tools)
   - License: [MIT License](https://raw.githubusercontent.com/njh/mqtt-sn-tools/master/LICENSE.md)
   - Evaluation: C-based command-line utilities for MQTT-SN publishing and subscribing by Nicholas Humfrey. Licensed under MIT, which is fully compatible with Apache-2.0.
8. **rust-mqtt-sn**:
   - Repository: [rust-iot/rust-mqtt-sn](https://github.com/rust-iot/rust-mqtt-sn)
   - License: [Mozilla Public License 2.0 (MPL-2.0)](https://raw.githubusercontent.com/rust-iot/rust-mqtt-sn/master/LICENSE)
   - Evaluation: Pure Rust partial implementation of MQTT-SN. Licensed under MPL-2.0 (weak file-level copyleft). While MPL-2.0 code can be distributed alongside Apache-2.0 code in larger works, direct copying into Apache-2.0 source files is restricted.

#### Architectural Recommendation

In line with RER's existing CCSDS (`crates/rer/src/ccsds.rs`), MAVLink, and SRT designs, RER must not introduce external crate dependencies for protocol inspection. An in-tree, zero-dependency pure Rust parser for MQTT fixed headers and remaining length decoding guarantees 100% Apache-2.0 licensing purity, eliminates supply-chain exposure, avoids C FFI toolchain complexities, and ensures predictable, allocation-free execution in the relay forwarding path.

### Sources checked

- [https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html) — HTTP 200
- [https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) — HTTP 200
- [https://mqtt.org/mqtt-specification/](https://mqtt.org/mqtt-specification/) — HTTP 200
- [https://www.oasis-open.org/committees/download.php/56041/MQTT-SN_spec_v1.2.pdf](https://www.oasis-open.org/committees/download.php/56041/MQTT-SN_spec_v1.2.pdf) — HTTP 200
- [https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=mqtt-sn](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=mqtt-sn) — HTTP 200
- [https://github.com/bytebeamio/rumqtt](https://github.com/bytebeamio/rumqtt) — HTTP 200
- [https://raw.githubusercontent.com/bytebeamio/rumqtt/master/LICENSE](https://raw.githubusercontent.com/bytebeamio/rumqtt/master/LICENSE) — HTTP 200
- [https://github.com/00imvj00/mqttrs](https://github.com/00imvj00/mqttrs) — HTTP 200
- [https://raw.githubusercontent.com/00imvj00/mqttrs/master/LICENSE](https://raw.githubusercontent.com/00imvj00/mqttrs/master/LICENSE) — HTTP 200
- [https://github.com/eclipse/mosquitto](https://github.com/eclipse/mosquitto) — HTTP 200
- [https://raw.githubusercontent.com/eclipse/mosquitto/master/LICENSE.txt](https://raw.githubusercontent.com/eclipse/mosquitto/master/LICENSE.txt) — HTTP 200
- [https://github.com/eclipse/paho.mqtt.rust](https://github.com/eclipse/paho.mqtt.rust) — HTTP 200
- [https://raw.githubusercontent.com/eclipse/paho.mqtt.rust/master/LICENSE](https://raw.githubusercontent.com/eclipse/paho.mqtt.rust/master/LICENSE) — HTTP 200
- [https://github.com/emqx/emqx](https://github.com/emqx/emqx) — HTTP 200
- [https://raw.githubusercontent.com/emqx/emqx/master/LICENSE](https://raw.githubusercontent.com/emqx/emqx/master/LICENSE) — HTTP 200
- [https://github.com/eclipse-paho/paho.mqtt-sn.embedded-c](https://github.com/eclipse-paho/paho.mqtt-sn.embedded-c) — HTTP 200
- [https://raw.githubusercontent.com/eclipse-paho/paho.mqtt-sn.embedded-c/master/LICENSE](https://raw.githubusercontent.com/eclipse-paho/paho.mqtt-sn.embedded-c/master/LICENSE) — HTTP 200
- [https://github.com/njh/mqtt-sn-tools](https://github.com/njh/mqtt-sn-tools) — HTTP 200
- [https://raw.githubusercontent.com/njh/mqtt-sn-tools/master/LICENSE.md](https://raw.githubusercontent.com/njh/mqtt-sn-tools/master/LICENSE.md) — HTTP 200
- [https://github.com/rust-iot/rust-mqtt-sn](https://github.com/rust-iot/rust-mqtt-sn) — HTTP 200
- [https://raw.githubusercontent.com/rust-iot/rust-mqtt-sn/master/LICENSE](https://raw.githubusercontent.com/rust-iot/rust-mqtt-sn/master/LICENSE) — HTTP 200

## Proposal

### Architecture Overview

To support MQTT and MQTT-SN transparently within RER without turning RER into a stateful broker, we propose a modular architecture structured across three key repository components:
1. **In-Tree Protocol Parser (`crates/rer/src/mqtt.rs`)**: A pure, zero-dependency parser for MQTT v3.1.1, v5.0, and MQTT-SN fixed headers, remaining length decoding, and packet classification.
2. **Stream Framing (`crates/rer/src/framing.rs`)**: An opt-in TCP framing mode (`FramingMode::Mqtt`) that frames continuous TCP byte streams into discrete MQTT control packets using self-delimited Remaining Length boundaries.
3. **Configuration & Diagnostics Integration (`crates/rer/src/config.rs`, `crates/rer/src/diagnostics.rs`, `crates/rer/src/relay.rs`)**: Opt-in inspection configuration, non-blocking diagnostic telemetry event enrichment, and validation error accounting in the relay forwarding loop.

### Integration with Existing Codebase

#### 1. Configuration Schema (`crates/rer/src/config.rs`)

We extend `crates/rer/src/config.rs` with `FramingMode::Mqtt` and a dedicated `MqttConfig` struct:

```rust
/// Framing modes for TCP streams (SPEC §5, §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum FramingMode {
    /// Standard 4-byte big-endian length prefix (default).
    #[default]
    #[serde(alias = "default", alias = "length_prefix", alias = "length_prefixed")]
    LengthPrefix,
    /// CCSDS Space Packet length-based framing.
    #[serde(alias = "CCSDS")]
    Ccsds,
    /// MQTT self-delimited framing using fixed header and variable remaining length.
    #[serde(alias = "MQTT", alias = "mqtt")]
    Mqtt,
}

/// Configuration for MQTT packet parsing, validation, and framing (SPEC §14, §8).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MqttConfig {
    /// Enable MQTT header parsing and validation. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Validate packet type flags strictly against OASIS specifications. Defaults to true.
    #[serde(default = "default_true")]
    pub validate_flags: bool,

    /// Maximum allowed packet length in octets (bounds buffer allocations). Defaults to 65,536.
    #[serde(default = "default_mqtt_max_packet_size")]
    pub max_packet_size: usize,

    /// When true, packets failing validation are forwarded unchanged to destinations. Defaults to false.
    #[serde(default, alias = "passthrough")]
    pub passthrough_on_error: bool,

    /// Optional framing mode override ("length_prefix", "ccsds", or "mqtt").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            validate_flags: true,
            max_packet_size: 65_536,
            passthrough_on_error: false,
            framing: None,
        }
    }
}
```

In `StreamConfig`:
- Add field `pub mqtt: Option<MqttConfig>`.
- Update `source_framing(&self) -> FramingMode` to check `self.mqtt.as_ref().and_then(|m| m.framing)`.
- Update `destination_framing(&self, dest: &EndpointConfig) -> FramingMode` to resolve `self.mqtt.as_ref().and_then(|m| m.framing)`.

#### 2. Stream Framing Engine (`crates/rer/src/framing.rs`)

In `crates/rer/src/framing.rs`, we introduce self-delimiting frame reading and writing for MQTT:

```rust
/// Reads a single self-delimited MQTT frame from `reader`.
///
/// Reads the 1-octet fixed header, decodes the 1-to-4 octet Variable Byte Integer
/// remaining length field, validates that total packet length does not exceed `max_frame_size`,
/// and reads the remaining payload bytes.
pub fn read_mqtt_frame<R: Read>(
    reader: &mut R,
    max_frame_size: usize,
    shutdown: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    // 1. Read first fixed header byte (packet type + flags)
    let mut first_byte = [0u8; 1];
    let ok = read_exact_interruptible(reader, &mut first_byte, shutdown)?;
    if !ok {
        return Ok(None);
    }

    // 2. Read Variable Byte Integer remaining length (1 to 4 bytes)
    let mut multiplier: usize = 1;
    let mut remaining_length: usize = 0;
    let mut len_bytes = Vec::with_capacity(4);

    loop {
        let mut byte_buf = [0u8; 1];
        let ok = read_exact_interruptible(reader, &mut byte_buf, shutdown)?;
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream closed while reading MQTT remaining length",
            ));
        }
        let b = byte_buf[0];
        len_bytes.push(b);
        remaining_length += ((b & 0x7F) as usize) * multiplier;

        if (b & 0x80) == 0 {
            break;
        }

        multiplier *= 128;
        if len_bytes.len() == 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed MQTT remaining length: exceeds 4 octets",
            ));
        }
    }

    let total_packet_length = 1 + len_bytes.len() + remaining_length;
    if total_packet_length > max_frame_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "MQTT frame total length {} exceeds maximum allowed {}",
                total_packet_length, max_frame_size
            ),
        ));
    }

    // 3. Assemble complete packet
    let mut packet = vec![0u8; total_packet_length];
    packet[0] = first_byte[0];
    packet[1..1 + len_bytes.len()].copy_from_slice(&len_bytes);

    if remaining_length > 0 {
        let payload_dest = &mut packet[1 + len_bytes.len()..];
        let ok = read_exact_interruptible(reader, payload_dest, shutdown)?;
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream closed before full MQTT packet payload was read",
            ));
        }
    }

    Ok(Some(packet))
}

/// Writes an MQTT frame to `writer` without additional framing encapsulation.
pub fn write_mqtt_frame<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet)
}
```

`read_frame_with_mode` and `write_frame_with_mode` dispatch `FramingMode::Mqtt` directly to `read_mqtt_frame` and `write_mqtt_frame`.

#### 3. Diagnostic Event Telemetry (`crates/rer/src/diagnostics.rs`)

In `crates/rer/src/diagnostics.rs`, `DiagnosticEvent` is enriched with opt-in MQTT metadata:
- `pub mqtt_packet_type: Option<u8>`: Raw 4-bit packet type (1..=15).
- `pub mqtt_type_name: Option<&'static str>`: Canonical string representation (e.g., `"CONNECT"`, `"PUBLISH"`, `"PINGREQ"`).
- `pub mqtt_flags: Option<u8>`: 4-bit header flags.
- `pub mqtt_qos: Option<u8>`: QoS level (0, 1, or 2) when packet type is `PUBLISH`.
- `pub mqtt_packet_id: Option<u16>`: Extracted Packet Identifier for QoS > 0 messages.

Builder methods:
- `with_mqtt_packet_type(mut self, packet_type: u8, name: &'static str) -> Self`
- `with_mqtt_qos(mut self, qos: u8) -> Self`
- `with_mqtt_packet_id(mut self, packet_id: u16) -> Self`

In compliance with SPEC §8 truthfulness:
- MQTT classification is reported at `DiagnosticStage::Accepted` or `DiagnosticStage::Observed`.
- Downstream socket transmission is strictly reported as `DiagnosticStage::Forwarded` (local send call succeeded), never fabricated as downstream delivery acknowledgment.

#### 4. Forwarding Pipeline (`crates/rer/src/relay.rs`)

In `crates/rer/src/relay.rs`, ingress packets (datagrams from UDP or frames from TCP) pass through `process_mqtt_ingress()` when `stream.mqtt` is configured:
1. **Header Parsing**: `parse_mqtt_fixed_header()` extracts packet type, flags, remaining length, and total packet size.
2. **Flag Validation**: If `validate_flags` is enabled, flags are checked against OASIS rules (e.g., bit 1 set for `SUBSCRIBE`/`UNSUBSCRIBE`/`PUBREL`, zeros for `CONNECT`/`CONNACK`, valid QoS for `PUBLISH`).
3. **Error Handling**: On parse failure, `stats.validation_errors` is incremented. If `passthrough_on_error` is false, `stats.dropped_packets` and `stats.drops_validation` are incremented, a `DiagnosticStage::Dropped` event is emitted, and the invalid frame is discarded.
4. **Diagnostic Enrichment**: For valid packets, extracted metadata (packet type, QoS, packet ID) enriches the forwarding diagnostic event.
5. **Egress Forwarding**: Valid packets are forwarded to destination endpoints using the destination's configured framing mode.

### Smallest First Step

The smallest initial implementation step that can be independently built, tested, and validated in CI without modifying existing relay forwarding loops or altering default behaviors is:

1. Create a pure in-tree parser module `crates/rer/src/mqtt.rs`:
   - Define `MqttPacketType` enum with discriminant values 1 to 15.
   - Define `MqttFixedHeader` struct:
     ```rust
     pub struct MqttFixedHeader {
         pub packet_type: MqttPacketType,
         pub flags: u8,
         pub remaining_length: usize,
         pub header_len: usize,
         pub total_packet_len: usize,
     }
     ```
   - Implement `decode_variable_byte_integer(buf: &[u8]) -> Result<(usize, usize), MqttParseError>` returning decoded value and bytes consumed (1 to 4).
   - Implement `encode_variable_byte_integer(val: usize, buf: &mut [u8]) -> Result<usize, MqttParseError>`.
   - Implement `parse_mqtt_fixed_header(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError>`.
2. Add comprehensive unit tests in `crates/rer/src/mqtt.rs` covering:
   - Decoding 1-byte, 2-byte, 3-byte, and 4-byte remaining length boundary values (0, 127, 128, 16383, 16384, 2097151, 2097152, 268435455).
   - Rejecting 5-byte variable byte integer overflow.
   - Parsing valid fixed headers for all 15 packet types.
   - Strict flag validation (rejecting non-zero flags on `CONNECT`, non-0010 flags on `SUBSCRIBE`, invalid QoS `3` on `PUBLISH`).
   - Correct length calculation for zero-payload packets (`PINGREQ` `0xC0 0x00` $\to$ total length 2).
   - Buffer underflow detection for truncated inputs.
3. This deliverable introduces zero external dependencies, requires no modifications to network sockets or forwarding threads, and is 100% testable via standard `cargo test`.

## Not claimed

This proposal and any subsequent implementation of Task RER-F-054 explicitly do NOT claim or establish:
1. **Full MQTT Broker Functionality**: RER does not claim MQTT broker or server capabilities. RER does not maintain client connection registries, process `CONNECT` authentication handshakes, maintain client session state, or generate `PINGRESP` keep-alive replies.
2. **Topic Subscription Filtering**: RER does not claim topic subscription management, topic tree filtering, or wildcard (`+`, `#`) routing. Message forwarding is performed strictly based on RER stream and endpoint configurations.
3. **Message Persistence and Queuing**: RER does not claim message persistence, disk storage for QoS 1 or QoS 2 messages, offline client message buffering, or protocol-level retransmission state machines.
4. **Application Payload Parsing**: RER does not decode or validate application payloads (such as JSON, Protobuf, CBOR, or binary formats) contained within `PUBLISH` packets. Payloads are treated as transparent byte buffers.
5. **TLS Termination and Certificate Management**: RER does not terminate TLS connections or manage X.509 certificates for secure MQTT (MQTTS). Transport encryption remains the responsibility of external transport layers or RER's existing socket wrappers.
6. **Hard Real-Time Latency Guarantees**: RER does not guarantee deterministic microsecond latency or hard real-time dispatch for MQTT packet processing.

## Open questions

The following architectural decisions require review and resolution by the repository owner:

1. **MQTT-SN Configuration Integration**:
   Should MQTT-SN support be configured under the same `MqttConfig` struct (via an enum flag such as `protocol_variant: MqttVariant::Standard | MqttVariant::Sn`), or should a distinct `MqttSnConfig` struct be created to keep datagram-oriented sensor network inspection structurally separate from stream-oriented TCP MQTT framing?
2. **TCP Stream Desynchronization Policy**:
   When reading continuous TCP byte streams in `read_mqtt_frame()`, if a byte sequence violates the Variable Byte Integer rules (continuation bit set across > 4 octets) or declares an invalid packet type (type 0), should RER immediately terminate the TCP connection with `io::ErrorKind::InvalidData`, or should it support an optional sliding-window resynchronization mode that seeks the next valid MQTT fixed header byte?
3. **Topic String Extraction for Diagnostics**:
   In `PUBLISH` packets, the variable header contains a UTF-8 topic string. Should RER's diagnostic enrichment optionally extract and report this topic string (truncated to a safe maximum preview length) in `DiagnosticEvent`, or should passive inspection remain strictly confined to fixed header metadata (packet type, flags, QoS, and packet ID) to prevent string allocation overhead on high-throughput relays?
4. **Packet Identifier Tracking for QoS > 0 Streams**:
   For dedicated point-to-point telemetry streams carrying QoS 1 or QoS 2 `PUBLISH` packets, should RER support optional sequence tracking using RER's existing `SequenceTracker` keyed on the 16-bit Packet Identifier, or would out-of-order acknowledgments typical of multiplexed MQTT sessions produce spurious sequence anomaly warnings?
