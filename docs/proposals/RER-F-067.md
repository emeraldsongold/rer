# Research Proposal: Real-Time Transport Protocol (RTP) and Multicast IGMP Integration (RER-F-067)

## Summary

This proposal presents the architectural survey, standards evaluation, open-source licensing analysis, and codebase integration design for introducing passive Real-Time Transport Protocol (RTP) fixed-header stream inspection and native IPv4/IPv6 multicast group socket membership (IGMP/MLD) into RER (RER Engineering Relay). This research establishes the foundational prerequisite for Roadmap Task RER-F-067 under SPEC §5, §8, and §14.

RER is a high-integrity, deterministic engineering relay designed for stream forwarding, protocol conversion, simulation, and packet-level diagnostic observability. While RER currently supports UDP and TCP forwarding along with specialized packet inspection and framing for CCSDS Space Packets, MAVLink, MQTT, and KISS/AX.25, RER cannot ingest or observe RTP streams transported over IP multicast groups due to several protocol and socket-level limitations:
1. **Multicast Socket Group Management**: RER's socket binding logic in `crates/rer/src/relay.rs` currently binds UDP sockets exclusively to local unicast or wildcard addresses (`0.0.0.0:port` or `[::]:port`) without issuing operating system multicast group join requests. It lacks support for joining IPv4 multicast groups via IGMPv1/IGMPv2/IGMPv3 or IPv6 multicast groups via MLDv1/MLDv2, cannot bind to Source-Specific Multicast (SSM) channels, and does not configure multicast Time-To-Live (TTL) or loopback flags for egress fan-out.
2. **Fixed-Header Inspection**: Real-time media feeds, aerospace telemetry, radar streams, and distributed simulation environments (e.g., DIS/HLA) encapsulate real-time payloads inside 12-byte RTP fixed headers as defined in RFC 3550. While RER provides generic sequence tracking in `crates/rer/src/diagnostics.rs` via `SequenceConfig`, it cannot parse the composite bitfields of the 12-byte RTP fixed header, including the 2-bit version, padding bit, extension bit, 4-bit CSRC count, 1-bit marker, 7-bit payload type, 32-bit sampling timestamp, and 32-bit Synchronization Source (SSRC) identifier.
3. **Diagnostic Observability**: Diagnostic events emitted by `DiagnosticEvent` in `crates/rer/src/diagnostics.rs` do not capture RTP-specific stream attributes or multicast subscription context, preventing operators from correlating real-time media streams, detecting clock drift or sampling timestamp jumps, or diagnosing multicast subscription failures.

This proposal specifies an in-tree, zero-dependency RTP fixed-header parser and native multicast socket management design for RER. It outlines configuration extensions in `crates/rer/src/config.rs`, diagnostic enrichments in `crates/rer/src/diagnostics.rs`, and multicast socket lifecycle integration in `crates/rer/src/relay.rs`. It identifies the smallest first implementation step for in-tree RTP fixed-header parsing and sequence tracking, and explicitly defines operational boundaries to preserve RER's architecture as a transparent proxy rather than an RTCP session manager, RTSP streaming engine, media codec transcoder, or multicast routing daemon.

## Findings

### Survey of the Real-Time Transport Protocol (RTP) Specification

The Real-Time Transport Protocol is standardized by the Internet Engineering Task Force (IETF) in [RFC 3550: RTP: A Transport Protocol for Real-Time Applications](https://www.rfc-editor.org/rfc/rfc3550.html), supplemented by profile definitions such as [RFC 3551: RTP Profile for Audio and Video Conferences with Minimal Control](https://www.rfc-editor.org/rfc/rfc3551.html).

RTP provides end-to-end network transport functions suitable for applications transmitting real-time data, such as audio, video, or real-time simulation state over unicast or multicast network services. RTP is almost universally transported over UDP datagrams.

#### The 12-Byte RTP Fixed Header Format

Under Section 5.1 of RFC 3550, every RTP packet begins with a fixed header of at least 12 octets:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier            |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|            contributing source (CSRC) identifiers             |
|                             ....                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The fields of the fixed header are structured as follows:

1. **Version (V, 2 bits, Octet 0, Bits 7..6)**:
   - Identifies the version of RTP. The version defined by RFC 3550 is two (`2`, binary `10`). Packets with version values other than 2 are considered invalid or legacy protocol formats.
2. **Padding (P, 1 bit, Octet 0, Bit 5)**:
   - If the padding bit is set (`1`), the packet contains one or more additional padding octets at the end of the payload that are not part of the payload content.
   - The very last octet of the payload contains an unsigned count of how many padding octets were appended (including itself). Padding is typically utilized by encryption algorithms that require fixed block sizes.
3. **Extension (X, 1 bit, Octet 0, Bit 4)**:
   - If the extension bit is set (`1`), the fixed header is followed by exactly one header extension word formatted according to RFC 3550 Section 5.3.1.
4. **CSRC Count (CC, 4 bits, Octet 0, Bits 3..0)**:
   - Contains the number of Contributing Source (CSRC) identifiers that follow the 12-byte fixed header. The count ranges from `0` to `15` ($0$ to $60$ additional bytes).
5. **Marker (M, 1 bit, Octet 1, Bit 7)**:
   - Defined by a profile (e.g., RFC 3551). It is intended to allow significant events such as frame boundaries in video streams or the beginning of a talkspurt in audio streams to be marked within the packet stream without inspecting payload bytes.
6. **Payload Type (PT, 7 bits, Octet 1, Bits 6..0)**:
   - Identifies the format of the RTP payload and determines its interpretation by the receiving application. A set of default static payload type mappings (such as `0` for PCMU, `8` for PCMA, `26` for JPEG, and `33` for MPEG2-TS) is specified in RFC 3551, while values in the range `96..=127` denote dynamic payload types negotiated out-of-band via SDP or configured statically.
7. **Sequence Number (16 bits, Octets 2..3)**:
   - A 16-bit unsigned integer stored in big-endian (network) byte order.
   - The sequence number increments by one for each RTP data packet sent by an SSRC.
   - It is utilized by the receiver to detect packet loss, identify duplicated packets, and restore packet order.
   - The initial value of the sequence number is randomly chosen by the transmitter to complicate known-plaintext attacks. When the sequence number reaches `65535`, it rolls over to `0`.
8. **Timestamp (32 bits, Octets 4..7)**:
   - A 32-bit unsigned integer stored in big-endian byte order.
   - Reflects the sampling instant of the first octet in the RTP data packet. The sampling instant is derived from a clock that increments monotonically and linearly in time to facilitate synchronization and jitter calculations.
   - The clock frequency depends on the specific payload format (for instance, 8,000 Hz for standard telephony audio, 90,000 Hz for video formats).
   - Like the sequence number, the initial timestamp value is randomly generated. Rollover occurs when the 32-bit integer wraps from $2^{32}-1$ to `0`.
9. **Synchronization Source (SSRC) Identifier (32 bits, Octets 8..11)**:
   - A 32-bit unsigned integer stored in big-endian byte order.
   - Uniquely identifies the synchronization source within an RTP session. All packets from a synchronization source carry the same SSRC, establishing the stream identity independent of underlying network transport addresses or UDP ports.
   - To avoid collisions across distributed transmitters, SSRCs are generated randomly. RFC 3550 Section 8 specifies collision resolution rules when two sources choose the identical SSRC.
10. **Contributing Source (CSRC) Identifiers (0 to 15 entries, Octets 12..)**:
    - An optional array of zero to 15 32-bit SSRC identifiers ($CC \times 4$ octets) identifying the contributing sources for payload data combined by an intermediate RTP mixer.

The total header length before the payload data begins is $12 + (CC \times 4)$ octets, plus the variable extension header length if $X = 1$. A valid RTP packet must be at least 12 octets in length.

### Survey of IP Multicast and IGMP Standards

Multicast transmission allows an IP host to transmit a single packet that is replicated by intermediate network switches and routers to reach multiple subscribing receivers, conserving network bandwidth. Host group memberships on IPv4 local area networks are managed by the Internet Group Management Protocol (IGMP).

The primary standards governing IP multicast host group behavior and IGMP include:
- [RFC 1112: Host Extensions for IP Multicasting (IGMPv1)](https://www.rfc-editor.org/rfc/rfc1112.html): Defined Class D IPv4 multicast addressing (`224.0.0.0` through `239.255.255.255`, or `224.0.0.0/4`) and the initial IGMPv1 host membership query/report protocol.
- [RFC 2236: Internet Group Management Protocol, Version 2 (IGMPv2)](https://www.rfc-editor.org/rfc/rfc2236.html): Introduced explicit Leave Group messages, group-specific queries, and query response timers to reduce leave latency and channel tune times.
- [RFC 3376: Internet Group Management Protocol, Version 3 (IGMPv3)](https://www.rfc-editor.org/rfc/rfc3376.html): Added Source-Specific Multicast (SSM) filtering, enabling hosts to report inclusion or exclusion lists of source IP addresses for a given multicast group.
- [RFC 4607: Source-Specific Multicast for IP](https://www.rfc-editor.org/rfc/rfc4607.html): Standardized the dedicated IPv4 prefix `232.0.0.0/8` for source-specific multicast channels $(S, G)$, eliminating the need for network-wide multicast rendezvous points.
- [RFC 3810: Multicast Listener Discovery Version 2 (MLDv2) for IPv6](https://www.rfc-editor.org/rfc/rfc3810.html): Standardized the IPv6 equivalent of IGMPv3, operating over ICMPv6 to provide source-filtered multicast group reporting for IPv6 multicast addresses (`ff00::/8`).

#### IGMP Protocol Formats and Membership Reports

IGMP messages are encapsulated directly in IPv4 datagrams with IP protocol number 2, using IP Time-To-Live (TTL) set to 1 and carrying the IPv4 Router Alert option.

1. **IGMPv1 Message Format (RFC 1112)**:
   A fixed 8-octet packet format:
   ```text
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Type  |    Unused     |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ```
   - Version: 4 bits (`0x1`).
   - Type: 4 bits (`0x1` for Host Membership Query, `0x2` for Host Membership Report).
   - Unused: 8 bits (set to zero on transmission).
   - Checksum: 16-bit one's complement sum of the 8-octet message.
   - Group Address: The IPv4 multicast group address. In IGMPv1, leaving a group is silent; routers prune forwarding only after query timeouts elapse.

2. **IGMPv2 Message Format (RFC 2236)**:
   A fixed 8-octet packet format retaining wire compatibility with IGMPv1:
   ```text
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      | Max Resp Time |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ```
   - Type (8 bits):
     - `0x11`: Membership Query (General Query if Group Address is `0.0.0.0`; Group-Specific Query otherwise).
     - `0x12`: Version 1 Membership Report (for backwards compatibility).
     - `0x16`: Version 2 Membership Report (sent to the group address being joined).
     - `0x17`: Leave Group (sent to the all-routers group `224.0.0.2` when a host terminates subscription).
   - Max Resp Time (8 bits): Specified in units of 100 milliseconds ($0.1$ seconds) for Query messages; set to `0` for Reports and Leaves.
   - Checksum: 16-bit one's complement checksum.
   - Group Address: 32-bit IPv4 multicast group address.

3. **IGMPv3 Membership Report Format (RFC 3376)**:
   IGMPv3 Membership Reports are assigned Type `0x22` and are transmitted to the reserved link-local multicast address `224.0.0.22`:
   ```text
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Type = 0x22  |    Reserved   |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Reserved            |  Number of Group Records (M)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   .                                                               .
   .                        Group Record [1]                       .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   .                                                               .
   .                        Group Record [M]                       .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ```
   Each Group Record contains:
   ```text
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Multicast Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address [1]                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   .                                                               .
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address [N]                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Auxiliary Data (if len > 0)                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ```
   - Record Types:
     - Current-State Records: `1` (`MODE_IS_INCLUDE`), `2` (`MODE_IS_EXCLUDE`).
     - Filter-Mode-Change Records: `3` (`CHANGE_TO_INCLUDE_MODE`), `4` (`CHANGE_TO_EXCLUDE_MODE`).
     - Source-List-Change Records: `5` (`ALLOW_NEW_SOURCES`), `6` (`BLOCK_OLD_SOURCES`).
   - Number of Sources ($N$): Count of specific unicast IPv4 source addresses listed in the record.

#### Operating System Host Socket API vs. Multicast Routing Daemons

In standard operating systems (Linux, BSD, macOS, Windows), user-space applications participate in IP multicast through operating system socket options on UDP datagram sockets (`SOCK_DGRAM`). Applications do not manually build or emit raw IGMP packets. Instead, when an application invokes socket membership options, the operating system kernel network stack automatically generates the appropriate IGMPv1, IGMPv2, or IGMPv3 membership reports and transmits them across the designated network interface:
- **IPv4 Group Join/Leave**: Configured via `IP_ADD_MEMBERSHIP` and `IP_DROP_MEMBERSHIP` socket options with `struct ip_mreq`. In Rust standard library, this is exposed through `std::net::UdpSocket::join_multicast_v4(&group, &interface)` and `leave_multicast_v4(&group, &interface)`.
- **IPv4 Source-Specific Multicast (SSM)**: Configured via `IP_ADD_SOURCE_MEMBERSHIP` and `IP_DROP_SOURCE_MEMBERSHIP` socket options with `struct ip_mreq_source`. This instructs the kernel to emit IGMPv3 `MODE_IS_INCLUDE` reports listing the permitted source IP address. In Rust, this is exposed via `socket2::Socket::join_multicast_v4_ssm(&group, &interface, &source)` in the `socket2` crate.
- **IPv6 Group Join/Leave**: Configured via `IPV6_ADD_MEMBERSHIP` and `IPV6_DROP_MEMBERSHIP` socket options with `struct ipv6_mreq`. In Rust standard library, this is exposed through `std::net::UdpSocket::join_multicast_v6(&group, interface_index)` and `leave_multicast_v6(&group, interface_index)`.
- **Egress Interface and Hops**:
  - `IP_MULTICAST_IF` / `IPV6_MULTICAST_IF`: Designates the local network interface for outgoing multicast datagrams.
  - `IP_MULTICAST_TTL` / `IPV6_MULTICAST_HOPS`: Controls the time-to-live or hop limit for egress multicast datagrams (default is typically 1, confining packets to the local subnet).
  - `IP_MULTICAST_LOOP` / `IPV6_MULTICAST_LOOP`: Dictates whether transmitted multicast datagrams loop back to local sockets on the sending host.
- **Port Reuse**: On POSIX systems, multiple applications or sockets can listen on the same multicast group port simultaneously by setting `SO_REUSEADDR` and `SO_REUSEPORT` prior to binding.

In contrast, multicast routing daemons (such as PIM-SM or DVMRP daemons) operate at the network routing plane. They require raw network sockets (`SOCK_RAW` with `IPPROTO_IGMP`), administrative privileges (`CAP_NET_ADMIN` on Linux), and kernel routing socket APIs (`MRT_INIT`, `MRT_ADD_MFC`) to populate the kernel's Multicast Forwarding Cache. RER operates as an application-level relay host, not a routing daemon.

### Review of Existing Open-Source Implementations and Licensing Evaluation

Existing open-source RTP and multicast implementations were evaluated to determine architectural fit and license compatibility with RER's Apache License, Version 2.0 (Apache-2.0).

1. **`webrtc-rs/rtp` (Rust)**:
   - Repository: [webrtc-rs/rtp](https://github.com/webrtc-rs/rtp)
   - Licenses: Dual-licensed under [LICENSE-APACHE](https://github.com/webrtc-rs/rtp/blob/main/LICENSE-APACHE) (Apache-2.0) and [LICENSE-MIT](https://github.com/webrtc-rs/rtp/blob/main/LICENSE-MIT) (MIT).
   - Compatibility: **Fully compatible** with Apache-2.0.
   - Analysis: Provides robust serialization and deserialization of RTP packets, header extensions, and CSRC lists in Rust. However, importing `webrtc-rs/rtp` introduces external transitive dependencies (`bytes`, `util-rs`, etc.) into RER's workspace. Because RER only requires passive inspection of the 12-byte fixed header, an in-tree parser is vastly simpler and eliminates dependency footprint.
2. **`pion/rtp` (Go)**:
   - Repository: [pion/rtp](https://github.com/pion/rtp)
   - License: [LICENSE](https://github.com/pion/rtp/blob/master/LICENSE) (MIT).
   - Compatibility: **Compatible** with Apache-2.0.
   - Analysis: The foundational Go implementation for the Pion WebRTC stack. Features clean zero-copy slice parsing for RTP packets. Serves as a reference design for in-tree parsing and sequence rollover tracking.
3. **`socket2` (Rust)**:
   - Repository: [rust-lang/socket2](https://github.com/rust-lang/socket2)
   - Licenses: Dual-licensed under [LICENSE-APACHE](https://github.com/rust-lang/socket2/blob/master/LICENSE-APACHE) (Apache-2.0) and [LICENSE-MIT](https://github.com/rust-lang/socket2/blob/master/LICENSE-MIT) (MIT).
   - Compatibility: **Fully compatible** with Apache-2.0.
   - Analysis: `socket2` is already a direct dependency in RER's `crates/rer/Cargo.toml`. It provides cross-platform low-level socket creation, `SO_REUSEADDR`, and socket options including `join_multicast_v4_ssm`, `set_multicast_if_v4`, `set_multicast_ttl_v4`, and `set_multicast_loop_v4`. Utilizing `socket2` requires adding zero new external dependencies.
4. **`FFmpeg` (C)**:
   - Repository: [FFmpeg/FFmpeg](https://github.com/FFmpeg/FFmpeg)
   - License: [COPYING.LGPLv2.1](https://github.com/FFmpeg/FFmpeg/blob/master/COPYING.LGPLv2.1) (GNU Lesser General Public License v2.1 or later).
   - Compatibility: **Incompatible** with pure Apache-2.0 distribution as in-tree code.
   - Analysis: FFmpeg includes comprehensive RTP, RTCP, RTSP, and SDP processing modules. However, its LGPL-2.1 license imposes copyleft obligations and reverse-engineering requirements that conflict with RER's clean Apache-2.0 codebase. Furthermore, FFmpeg's heavyweight multimedia decoding architecture is unnecessary for a transport-level proxy.
5. **`GStreamer` (C)**:
   - Repository: [GStreamer/gstreamer](https://github.com/GStreamer/gstreamer)
   - License: [LICENSE](https://github.com/GStreamer/gstreamer/blob/main/LICENSE) (GNU Lesser General Public License v2.1 or later).
   - Compatibility: **Incompatible** with pure Apache-2.0 distribution as in-tree code.
   - Analysis: GStreamer provides the standard `rtpbin` pipeline element for RTP stream management, jitter buffering, and RTCP synchronization. Due to its LGPL-2.1 copyleft licensing and complex C runtime architecture, it cannot be incorporated into RER.
6. **`smcroute` (C)**:
   - Repository: [troglobit/smcroute](https://github.com/troglobit/smcroute)
   - License: [COPYING](https://github.com/troglobit/smcroute/blob/master/COPYING) (GNU General Public License v2.0 or later).
   - Compatibility: **Incompatible** with Apache-2.0.
   - Analysis: A static multicast routing daemon that manages Linux/BSD kernel multicast routes (`MRT_ADD_MFC`). The strict copyleft GPL-2.0 license prevents code incorporation, and its routing daemon scope is outside RER's host-level proxy model.
7. **`pimd` (C)**:
   - Repository: [troglobit/pimd](https://github.com/troglobit/pimd)
   - License: [LICENSE](https://github.com/troglobit/pimd/blob/master/LICENSE) (3-clause BSD License).
   - Compatibility: **Compatible** with Apache-2.0.
   - Analysis: Standalone PIM-SM routing daemon. While permissively licensed, it implements inter-router multicast routing protocol state machines rather than host-level socket joining.
8. **`mrouted` (C)**:
   - Repository: [troglobit/mrouted](https://github.com/troglobit/mrouted)
   - License: [LICENSE](https://github.com/troglobit/mrouted/blob/master/LICENSE) (Stanford Permissive License).
   - Compatibility: **Compatible** with Apache-2.0.
   - Analysis: Standalone DVMRP routing daemon for older multicast topologies. Like `pimd`, it operates as a routing plane daemon rather than an application-layer proxy.
9. **`wireshark` (C/C++)**:
   - Repository: [wireshark/wireshark](https://github.com/wireshark/wireshark)
   - License: [COPYING](https://github.com/wireshark/wireshark/blob/master/COPYING) (GNU General Public License v2.0).
   - Compatibility: **Incompatible** with Apache-2.0.
   - Analysis: Contains packet dissectors for RTP (`packet-rtp.c`) and IGMP (`packet-igmp.c`). Serves as a useful behavioral reference for test vectors, but GPL-2.0 prohibits copying code into RER.

#### Summary of Implementation Decision

Implementing RTP fixed-header parsing and multicast socket configuration in-tree within RER using the existing `std::net::UdpSocket` and `socket2` crates achieves:
- **100% License Integrity**: Full compliance with RER's Apache-2.0 license.
- **Zero Added Dependencies**: No new crate dependencies added to `Cargo.lock`.
- **Zero-Allocation Forwarding**: Microsecond-latency parsing of the 12-byte header with no heap allocations on the packet fast-path.
- **Strict Isolation**: Full isolation between RER's transport forwarding core and higher-level media abstractions.

### Sources checked

- [https://www.rfc-editor.org/rfc/rfc3550.html](https://www.rfc-editor.org/rfc/rfc3550.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc3551.html](https://www.rfc-editor.org/rfc/rfc3551.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc1112.html](https://www.rfc-editor.org/rfc/rfc1112.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc2236.html](https://www.rfc-editor.org/rfc/rfc2236.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc3376.html](https://www.rfc-editor.org/rfc/rfc3376.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc4607.html](https://www.rfc-editor.org/rfc/rfc4607.html) — HTTP 200
- [https://www.rfc-editor.org/rfc/rfc3810.html](https://www.rfc-editor.org/rfc/rfc3810.html) — HTTP 200
- [https://github.com/webrtc-rs/rtp](https://github.com/webrtc-rs/rtp) — HTTP 200
- [https://github.com/webrtc-rs/rtp/blob/main/LICENSE-APACHE](https://github.com/webrtc-rs/rtp/blob/main/LICENSE-APACHE) — HTTP 200
- [https://github.com/webrtc-rs/rtp/blob/main/LICENSE-MIT](https://github.com/webrtc-rs/rtp/blob/main/LICENSE-MIT) — HTTP 200
- [https://github.com/pion/rtp](https://github.com/pion/rtp) — HTTP 200
- [https://github.com/pion/rtp/blob/master/LICENSE](https://github.com/pion/rtp/blob/master/LICENSE) — HTTP 200
- [https://github.com/rust-lang/socket2](https://github.com/rust-lang/socket2) — HTTP 200
- [https://github.com/rust-lang/socket2/blob/master/LICENSE-APACHE](https://github.com/rust-lang/socket2/blob/master/LICENSE-APACHE) — HTTP 200
- [https://github.com/rust-lang/socket2/blob/master/LICENSE-MIT](https://github.com/rust-lang/socket2/blob/master/LICENSE-MIT) — HTTP 200
- [https://github.com/FFmpeg/FFmpeg](https://github.com/FFmpeg/FFmpeg) — HTTP 200
- [https://github.com/FFmpeg/FFmpeg/blob/master/COPYING.LGPLv2.1](https://github.com/FFmpeg/FFmpeg/blob/master/COPYING.LGPLv2.1) — HTTP 200
- [https://github.com/GStreamer/gstreamer](https://github.com/GStreamer/gstreamer) — HTTP 200
- [https://github.com/GStreamer/gstreamer/blob/main/LICENSE](https://github.com/GStreamer/gstreamer/blob/main/LICENSE) — HTTP 200
- [https://github.com/troglobit/smcroute](https://github.com/troglobit/smcroute) — HTTP 200
- [https://github.com/troglobit/smcroute/blob/master/COPYING](https://github.com/troglobit/smcroute/blob/master/COPYING) — HTTP 200
- [https://github.com/troglobit/pimd](https://github.com/troglobit/pimd) — HTTP 200
- [https://github.com/troglobit/pimd/blob/master/LICENSE](https://github.com/troglobit/pimd/blob/master/LICENSE) — HTTP 200
- [https://github.com/troglobit/mrouted](https://github.com/troglobit/mrouted) — HTTP 200
- [https://github.com/troglobit/mrouted/blob/master/LICENSE](https://github.com/troglobit/mrouted/blob/master/LICENSE) — HTTP 200
- [https://github.com/wireshark/wireshark](https://github.com/wireshark/wireshark) — HTTP 200
- [https://github.com/wireshark/wireshark/blob/master/COPYING](https://github.com/wireshark/wireshark/blob/master/COPYING) — HTTP 200

## Proposal

### Scope and Architectural Design

Under SPEC §5, §8, and §14, RER will introduce modular RTP stream inspection and multicast socket management across three existing modules: `crates/rer/src/config.rs`, `crates/rer/src/diagnostics.rs`, and `crates/rer/src/relay.rs`.

1. **Multicast Socket Group Membership (`crates/rer/src/relay.rs` & `crates/rer/src/config.rs`)**:
   - Ingress UDP sockets bound to an IPv4 multicast address (`224.0.0.0/4`) or IPv6 multicast address (`ff00::/8`) will automatically join the requested multicast group via the OS network stack.
   - Support optional `multicast` configuration on `EndpointConfig`, permitting explicit specification of:
     - `interface`: Outgoing or incoming network interface IP (e.g. `192.168.1.50`) or interface index.
     - `source`: Source IP address for Source-Specific Multicast (SSM / IGMPv3).
     - `ttl`: Multicast Time-To-Live / Hop Limit for egress datagrams ($1..=255$).
     - `loopback`: Boolean controlling multicast local loopback (default `false`).
   - Sockets joining multicast groups will configure `SO_REUSEADDR` and `SO_REUSEPORT` prior to binding, allowing multiple streams or external applications to share the multicast port.
2. **RTP Stream Inspection (`crates/rer/src/diagnostics.rs`)**:
   - Provide a pure in-tree RTP fixed-header parser function:
     `pub fn parse_rtp_header(buf: &[u8]) -> Result<RtpHeader, RtpParseError>`.
   - Validate that the payload has at least 12 octets and version equals 2.
   - Extract:
     - Version ($V=2$)
     - Padding flag ($P$) and Extension flag ($X$)
     - CSRC count ($CC$) and CSRC identifiers (if $CC > 0$)
     - Marker bit ($M$)
     - Payload Type ($PT$, $0..=127$)
     - Sequence Number (16-bit big-endian)
     - Timestamp (32-bit big-endian)
     - SSRC Identifier (32-bit big-endian)
   - Support optional payload type filtering (`filter_payload_types`) and SSRC filtering (`filter_ssrc`).
   - Support sequence tracking and 16-bit rollover detection ($65535 \to 0$) using RER's sequence tracking infrastructure.
3. **Diagnostic Event Enrichment (`crates/rer/src/diagnostics.rs`)**:
   - Extend `DiagnosticEvent` with RTP fields:
     - `rtp_payload_type: Option<u8>`
     - `rtp_sequence_number: Option<u16>`
     - `rtp_timestamp: Option<u32>`
     - `rtp_ssrc: Option<u32>`
     - `rtp_marker: Option<bool>`
     - `rtp_csrc_count: Option<u8>`
     - `rtp_inspection: Option<RtpInspection>`
     - `multicast_group: Option<String>`
     - `multicast_interface: Option<String>`
   - Provide builder methods: `with_rtp_metadata()` and `with_multicast_info()`.
   - Emit diagnostic events when multicast groups are joined or left, and when packets are dropped due to RTP validation or filtering failures.
4. **Error Handling and Passthrough (`crates/rer/src/relay.rs`)**:
   - Provide a configurable error handling policy via `passthrough_on_error`:
     - If `false` (default): Datagrams that fail RTP header validation (e.g. truncated length $< 12$ bytes or version $\ne 2$) are dropped, `drops_validation` is incremented, and a `DiagnosticStage::Dropped` event is emitted.
     - If `true`: Malformed datagrams are forwarded unmodified to downstream destinations, accompanied by a validation failure diagnostic event.

### Proposed Codebase Integration

#### 1. Configuration (`crates/rer/src/config.rs`)

Introduce `RtpConfig` and `MulticastConfig`, and extend `StreamConfig` and `EndpointConfig`:

```rust
/// Configuration for RTP stream inspection and sequence tracking (SPEC §14, §8).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RtpConfig {
    /// Enable RTP packet inspection. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional payload type filter (0..=127). If specified, packets with other payload types are dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_type: Option<u8>,

    /// Optional allowlist of payload types to forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_payload_types: Option<Vec<u8>>,

    /// Optional allowlist of synchronization source (SSRC) identifiers to forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_ssrc: Option<Vec<u32>>,

    /// Enable 16-bit sequence tracking and rollover detection. Defaults to true.
    #[serde(default = "default_true")]
    pub track_sequence: bool,

    /// Forward packets unmodified when RTP parsing fails. Defaults to false (drop on error).
    #[serde(default)]
    pub passthrough_on_error: bool,
}

impl Default for RtpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            payload_type: None,
            filter_payload_types: None,
            filter_ssrc: None,
            track_sequence: true,
            passthrough_on_error: false,
        }
    }
}

/// Multicast socket configuration options (SPEC §5).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct MulticastConfig {
    /// Local network interface IP address for multicast membership or transmission (e.g. "192.168.1.10" or "0.0.0.0").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,

    /// Source IP address for Source-Specific Multicast (SSM / IGMPv3, RFC 4607).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Multicast Time-to-Live (IPv4) or Hop Limit (IPv6) for egress datagrams (1..=255). Defaults to 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,

    /// Enable loopback of transmitted multicast datagrams to local host sockets. Defaults to false.
    #[serde(default)]
    pub loopback: bool,
}
```

Modifications to `crates/rer/src/config.rs`:
- Add `#[serde(default, skip_serializing_if = "Option::is_none")] pub multicast: Option<MulticastConfig>` to `EndpointConfig`.
- Add `#[serde(default, skip_serializing_if = "Option::is_none")] pub rtp: Option<RtpConfig>` to `StreamConfig`.
- In `Config::validate()`:
  - Verify that `multicast` options are only specified when `transport == TransportType::Udp` (reject multicast on TCP).
  - Verify that if `EndpointConfig.address` contains a multicast IP address, `transport` is UDP.
  - Verify that `payload_type` values in `RtpConfig` do not exceed 127.
  - Verify that `ttl`, if specified, is within $1..=255$.
  - Verify that `interface` and `source` strings parse as valid IP addresses.

#### 2. Diagnostics and RTP Header Parser (`crates/rer/src/diagnostics.rs`)

1. **Pure RTP Header Representation and Parser**:
   ```rust
   /// Parsed 12-byte RTP fixed header (RFC 3550 §5.1).
   #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
   pub struct RtpHeader {
       /// RTP version (must be 2).
       pub version: u8,
       /// Padding flag.
       pub padding: bool,
       /// Header extension flag.
       pub extension: bool,
       /// Contributing source count (0..=15).
       pub csrc_count: u8,
       /// Profile-specific marker bit.
       pub marker: bool,
       /// Payload type (0..=127).
       pub payload_type: u8,
       /// 16-bit sequence number.
       pub sequence_number: u16,
       /// 32-bit sampling timestamp.
       pub timestamp: u32,
       /// 32-bit synchronization source (SSRC) identifier.
       pub ssrc: u32,
       /// Optional contributing source (CSRC) identifiers.
       pub csrc_list: Vec<u32>,
       /// Total header byte length including CSRC list.
       pub header_length: usize,
   }

   #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
   pub struct RtpInspection {
       pub header: RtpHeader,
       pub payload_bytes: usize,
   }

   #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
   pub enum RtpParseError {
       #[error("datagram truncated: expected at least 12 bytes, found {0}")]
       TruncatedHeader(usize),
       #[error("unsupported RTP version {0}, expected 2")]
       UnsupportedVersion(u8),
       #[error("truncated CSRC list: expected {expected} bytes for {count} CSRCs, found {found}")]
       TruncatedCsrcList { count: u8, expected: usize, found: usize },
   }
   ```
   Pure parser function:
   ```rust
   pub fn parse_rtp_header(bytes: &[u8]) -> Result<RtpHeader, RtpParseError> {
       if bytes.len() < 12 {
           return Err(RtpParseError::TruncatedHeader(bytes.len()));
       }
       let b0 = bytes[0];
       let version = (b0 >> 6) & 0x03;
       if version != 2 {
           return Err(RtpParseError::UnsupportedVersion(version));
       }
       let padding = (b0 & 0x20) != 0;
       let extension = (b0 & 0x10) != 0;
       let csrc_count = b0 & 0x0F;

       let b1 = bytes[1];
       let marker = (b1 & 0x80) != 0;
       let payload_type = b1 & 0x7F;

       let sequence_number = u16::from_be_bytes([bytes[2], bytes[3]]);
       let timestamp = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
       let ssrc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

       let csrc_bytes_len = (csrc_count as usize) * 4;
       let min_len = 12 + csrc_bytes_len;
       if bytes.len() < min_len {
           return Err(RtpParseError::TruncatedCsrcList {
               count: csrc_count,
               expected: min_len,
               found: bytes.len(),
           });
       }

       let mut csrc_list = Vec::with_capacity(csrc_count as usize);
       for i in 0..(csrc_count as usize) {
           let offset = 12 + i * 4;
           let csrc = u32::from_be_bytes([
               bytes[offset],
               bytes[offset + 1],
               bytes[offset + 2],
               bytes[offset + 3],
           ]);
           csrc_list.push(csrc);
       }

       Ok(RtpHeader {
           version,
           padding,
           extension,
           csrc_count,
           marker,
           payload_type,
           sequence_number,
           timestamp,
           ssrc,
           csrc_list,
           header_length: min_len,
       })
   }
   ```

2. **Diagnostic Event Extension**:
   Add fields to `DiagnosticEvent`:
   - `pub rtp_payload_type: Option<u8>`
   - `pub rtp_sequence_number: Option<u16>`
   - `pub rtp_timestamp: Option<u32>`
   - `pub rtp_ssrc: Option<u32>`
   - `pub rtp_marker: Option<bool>`
   - `pub rtp_csrc_count: Option<u8>`
   - `pub rtp_inspection: Option<RtpInspection>`
   - `pub multicast_group: Option<String>`
   - `pub multicast_interface: Option<String>`
   Add builder methods `with_rtp_metadata()` and `with_multicast_info()`.

#### 3. Relay Socket Binding and Forwarding (`crates/rer/src/relay.rs`)

1. **Multicast Socket Binding in `bind_udp_socket`**:
   Extend `bind_udp_socket` or provide `bind_multicast_udp_socket`:
   - Detect if the target `SocketAddr` has a multicast IP address (`addr.ip().is_multicast()`).
   - For an ingress multicast socket:
     - On Linux/macOS/Windows, set `SO_REUSEADDR` (and `SO_REUSEPORT` where supported) via `socket2::Socket::set_reuse_address(true)` and `set_reuse_port(true)`.
     - In IPv4, bind the socket to `0.0.0.0:port` (or the multicast address directly where supported by the OS).
     - In IPv6, bind the socket to `[::]:port`.
     - Read `multicast` options:
       - Determine interface IP (default `Ipv4Addr::UNSPECIFIED` / `0.0.0.0`).
       - If `source` is provided (SSM): call `socket.join_multicast_v4_ssm(&group_ip, &interface_ip, &source_ip)`.
       - Otherwise (ASM): call `socket.join_multicast_v4(&group_ip, &interface_ip)` for IPv4 or `socket.join_multicast_v6(&group_ip, interface_index)` for IPv6.
       - If `loopback` is set: call `socket.set_multicast_loop_v4(true)` or `socket.set_multicast_loop_v6(true)`.
2. **Multicast Egress Forwarding**:
   - In `StreamRunner::run_stream()` egress forwarder thread:
     - When sending to an endpoint whose address is multicast:
       - If `multicast.ttl` is configured: call `socket.set_multicast_ttl_v4(ttl)`.
       - If `multicast.interface` is configured: call `socket.set_multicast_if_v4(&interface_ip)`.
3. **Ingress RTP Inspection Helper**:
   Introduce `process_rtp_ingress()` structured identically to `process_ccsds_ingress` and `process_kiss_ingress`:
   - Inspect payload with `parse_rtp_header(&payload)`:
     - If parsing fails and `passthrough_on_error == false`:
       - Increment `stats.drops_validation`.
       - Emit a `DiagnosticStage::Dropped` event with parse error reason.
       - Discard packet.
     - If parsing fails and `passthrough_on_error == true`:
       - Emit validation warning diagnostic event and continue forwarding.
     - If parsing succeeds:
       - Check `payload_type` filter: if configured and mismatched, increment `stats.drops_filtering` and discard.
       - Check `filter_ssrc`: if configured and mismatched, increment `stats.drops_filtering` and discard.
       - If `track_sequence` is enabled: record sequence number in `SequenceTracker` to detect missing packets, duplicates, out-of-order packets, and 16-bit rollover ($65535 \to 0$).
       - Enrich forwarding `DiagnosticEvent` with RTP metadata.

### Smallest First Step

The smallest initial implementation step that can be independently developed, reviewed, and merged with complete test evidence is:

1. Implement the pure RTP fixed-header parser function and data structures in a dedicated in-tree module `crates/rer/src/rtp.rs` (or `crates/rer/src/diagnostics.rs`):
   ```rust
   pub fn parse_rtp_header(buf: &[u8]) -> Result<RtpHeader, RtpParseError>;
   ```
2. Include comprehensive unit tests verifying:
   - Successful parsing of standard 12-byte RTP headers with version 2, default flags, arbitrary sequence numbers, timestamps, and SSRCs.
   - Rejection of truncated buffers smaller than 12 bytes with `RtpParseError::TruncatedHeader`.
   - Rejection of unsupported versions ($V \ne 2$) with `RtpParseError::UnsupportedVersion`.
   - Correct parsing of CSRC count and extraction of multiple 32-bit CSRC identifiers.
   - Rejection of buffers truncated within the CSRC list with `RtpParseError::TruncatedCsrcList`.
   - Verification of big-endian byte ordering for sequence number, timestamp, and SSRC.
   - Detection of marker bit ($M$), padding flag ($P$), and extension flag ($X$).
   - Sequence number tracking and rollover verification from `65535` to `0`.
3. This deliverable requires zero external dependencies, adds zero compilation overhead to existing CI, does not touch the socket forwarding loop, and establishes the pure foundation for subsequent multicast socket and relay integration.

## Not claimed

This proposal and any subsequent implementation of Task RER-F-067 explicitly do NOT claim or establish:
1. **Full RTCP (RTP Control Protocol) Session Control**: RER does not implement stateful RTCP control mechanisms (RFC 3550 §6). RER does not generate, parse, or respond to RTCP Sender Reports (SR), Receiver Reports (RR), Source Description (SDES) items (such as CNAME, NAME, EMAIL), Goodbye (BYE) packets, Application-defined (APP) packets, or Extended Feedback (RFC 4585). RER does not compute network round-trip time, calculate interarrival jitter statistics, or throttle transmission based on receiver feedback.
2. **RTSP (Real Time Streaming Protocol) Session Management**: RER does not implement RTSP 1.0 (RFC 2326) or RTSP 2.0 (RFC 7826) client or server signaling. RER does not parse or execute RTSP control methods (`DESCRIBE`, `SETUP`, `PLAY`, `PAUSE`, `TEARDOWN`), does not maintain RTSP session state machines, and does not parse Session Description Protocol (SDP, RFC 4566) descriptors.
3. **Media Decoding, Transcoding, or Rendering**: RER does not decode, transcode, depacketize, or render audio or video media streams (e.g., H.264, H.265, VP8/VP9, AV1, Opus, AAC, PCMU, or PCMA). RER inspects only the 12-byte fixed transport header and forwards payload bytes strictly unmodified.
4. **Multicast Routing Daemon Functionality**: RER is not an IP multicast router. It does not implement multicast routing protocols such as Protocol Independent Multicast (PIM-SM, PIM-DM, PIM-SSM), Distance Vector Multicast Routing Protocol (DVMRP), or Multicast OSPF (MOSPF). It does not implement IGMP querier election, IGMP proxying between router interfaces, or kernel Multicast Forwarding Cache manipulation (`MRT_INIT`, `MRT_ADD_MFC`). RER acts strictly as an application-level host group member using standard OS socket options.
5. **In-Band Cryptographic Decryption (SRTP)**: RER does not perform Secure Real-time Transport Protocol (SRTP, RFC 3711) decryption or manage DTLS-SRTP key exchanges. (While SRTP encrypts the RTP payload, the 12-byte fixed header remains unencrypted and inspectable by RER).
6. **Hard Real-Time Latency and Jitter Guarantees**: RER does not claim deterministic microsecond real-time scheduling guarantees or hardware-accelerated kernel-bypass packet forwarding over non-deterministic operating systems.

## Open questions

The following architectural and operational decisions require owner determination:

1. **Multicast Endpoint Configuration Schema**:
   Should multicast options be configured via an explicit `multicast` block under `EndpointConfig` (e.g., `EndpointConfig.multicast`), or should RER automatically detect multicast addresses from `EndpointConfig.address` whenever an IP in `224.0.0.0/4` or `ff00::/8` is specified, utilizing sensible defaults (interface `0.0.0.0`, TTL 1, loopback false) unless overridden?
2. **RTCP Co-Relay and Port Pairing**:
   In standard RTP deployments (RFC 3550), RTP data packets use an even UDP port $N$ and corresponding RTCP control packets use the adjacent odd UDP port $N+1$. Should RER provide an opt-in configuration shorthand (e.g., `rtcp_pair: true`) that automatically binds and forwards the paired control port, or should operators configure two independent streams in `rer.yaml`?
3. **Default Malformed Packet Handling Policy**:
   When an incoming datagram fails RTP header validation (e.g., length $< 12$ bytes or version $\ne 2$), should RER drop the packet by default (matching CCSDS, MAVLink, and MQTT behavior), or should RTP defaults favor passthrough because UDP traffic may occasionally intermingle non-RTP datagrams?
4. **RTP Header Extension (RFC 8285) Parsing Depth**:
   RFC 3550 §5.3.1 defines a generic header extension mechanism, and RFC 8285 standardizes one-byte and two-byte header extensions commonly used for audio levels, timestamps, and camera orientation. Should RER's initial RTP parser support RFC 8285 extension header parsing, or should extension payloads be ignored to keep initial complexity minimal?
5. **IGMP Version Preference for Multicast Sockets**:
   While Linux and BSD kernels automatically negotiate IGMP version based on network queries, should RER support explicit socket configuration forcing IGMPv2 compatibility mode over IGMPv3 on networks with legacy multicast switches?
