//! Integration tests for MAVLink relay forwarding, sequence tracking, and validation (SPEC §8, §14, Task RER-F-053).

use std::net::UdpSocket;
use std::time::Duration;

use rer::config::{Config, StreamConfig};
use rer::diagnostics::{DiagnosticEvent, DiagnosticStage};
use rer::mavlink::{
    encode_mavlink1_header, encode_mavlink2_header, MAVLINK_IFLAG_SIGNED, MAVLINK_SIGNATURE_LEN,
    MAVLINK_STX_V1, MAVLINK_STX_V2,
};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn build_mavlink1_packet(seq: u8, sysid: u8, compid: u8, msgid: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u8;
    let header = encode_mavlink1_header(payload_len, seq, sysid, compid, msgid);
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(payload);
    // Two dummy CRC checksum bytes
    bytes.push(0x34);
    bytes.push(0x12);
    bytes
}

fn build_mavlink2_packet(
    seq: u8,
    sysid: u8,
    compid: u8,
    msgid: u32,
    signed: bool,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = payload.len() as u8;
    let incompat = if signed { MAVLINK_IFLAG_SIGNED } else { 0 };
    let header = encode_mavlink2_header(payload_len, incompat, 0, seq, sysid, compid, msgid);
    let mut bytes = header.to_vec();
    bytes.extend_from_slice(payload);
    // Two dummy CRC checksum bytes
    bytes.push(0x78);
    bytes.push(0x56);
    if signed {
        // 13-byte signature block
        bytes.extend_from_slice(&[0xAA; MAVLINK_SIGNATURE_LEN]);
    }
    bytes
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2:
// Forwarding multiplexed MAVLink streams from two distinct system and component
// identifier pairs preserves independent sequence continuity counters without
// emitting false sequence gap events.
// ---------------------------------------------------------------------------

#[test]
fn test_multiplexed_mavlink_streams_preserve_independent_sequence_counters_no_false_gaps() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mavlink-multiplexed"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mavlink:
          enabled: true
          track_sequences: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // Source 1: (sysid 1, compid 1) sequences 0, 1, 2, 3, 4
    // Source 2: (sysid 2, compid 2) sequences 100, 101, 102, 103, 104
    // Interleaved transmission order: A0, B100, A1, B101, A2, B102, A3, B103, A4, B104
    let interleaved_packets: Vec<Vec<u8>> = vec![
        build_mavlink1_packet(0, 1, 1, 10, b"src1-seq0"),
        build_mavlink2_packet(100, 2, 2, 300, false, b"src2-seq100"),
        build_mavlink1_packet(1, 1, 1, 10, b"src1-seq1"),
        build_mavlink2_packet(101, 2, 2, 300, false, b"src2-seq101"),
        build_mavlink1_packet(2, 1, 1, 10, b"src1-seq2"),
        build_mavlink2_packet(102, 2, 2, 300, false, b"src2-seq102"),
        build_mavlink1_packet(3, 1, 1, 10, b"src1-seq3"),
        build_mavlink2_packet(103, 2, 2, 300, false, b"src2-seq103"),
        build_mavlink1_packet(4, 1, 1, 10, b"src1-seq4"),
        build_mavlink2_packet(104, 2, 2, 300, false, b"src2-seq104"),
    ];

    for (idx, pkt) in interleaved_packets.iter().enumerate() {
        sender.send_to(pkt, &target).expect("send");
        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("receive packet");
        assert_eq!(
            &buf[..n],
            pkt.as_slice(),
            "packet {idx} must be forwarded byte-for-byte unmodified"
        );
    }

    let stats = relay.stream_stats("s-mavlink-multiplexed").expect("stats");
    assert_eq!(stats.received_packets, 10);
    assert_eq!(stats.forwarded_packets, 10);
    assert_eq!(stats.dropped_packets, 0);

    // Verify independent sequence tracker state for both sources
    let tracker_arc = relay
        .mavlink_tracker("s-mavlink-multiplexed")
        .expect("mavlink tracker must be configured");
    let tracker = tracker_arc.lock().unwrap();

    assert_eq!(
        tracker.packets_evaluated(1, 1),
        5,
        "Source (1, 1) should have evaluated exactly 5 packets"
    );
    assert_eq!(
        tracker.packets_evaluated(2, 2),
        5,
        "Source (2, 2) should have evaluated exactly 5 packets"
    );
    assert_eq!(
        tracker.last_sequence(1, 1),
        Some(4),
        "Source (1, 1) last sequence should be 4"
    );
    assert_eq!(
        tracker.last_sequence(2, 2),
        Some(104),
        "Source (2, 2) last sequence should be 104"
    );
    assert_eq!(
        tracker.gap_count(1, 1),
        0,
        "Source (1, 1) must have 0 sequence gaps"
    );
    assert_eq!(
        tracker.gap_count(2, 2),
        0,
        "Source (2, 2) must have 0 sequence gaps"
    );
    assert_eq!(
        tracker.total_gap_count(),
        0,
        "Total sequence gap count across all sources must be 0"
    );

    // Verify diagnostic buffer: NO sequence gap events emitted
    let snap = relay.event_buffer().snapshot();
    let gap_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| {
            e.reason
                .as_ref()
                .is_some_and(|r| r.contains("sequence gap"))
        })
        .collect();

    assert!(
        gap_events.is_empty(),
        "multiplexed streams must NOT emit false sequence gap events: found {:?}",
        gap_events
    );

    drop(tracker);

    // Now introduce a genuine sequence gap on Source 1 only: jump from 4 to 8 (missing 5, 6, 7)
    let p_gap1 = build_mavlink1_packet(8, 1, 1, 10, b"src1-seq8-gap");
    sender.send_to(&p_gap1, &target).expect("send");
    let mut buf = vec![0u8; 1024];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], p_gap1.as_slice());

    // And Source 2 sends next in-order packet (105)
    let p_in_order2 = build_mavlink2_packet(105, 2, 2, 300, false, b"src2-seq105");
    sender.send_to(&p_in_order2, &target).expect("send");
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], p_in_order2.as_slice());

    let tracker = tracker_arc.lock().unwrap();
    assert_eq!(
        tracker.gap_count(1, 1),
        3,
        "Source 1 must record 3 missing packets"
    );
    assert_eq!(
        tracker.gap_count(2, 2),
        0,
        "Source 2 must still have 0 gaps"
    );

    // Verify diagnostic event emitted for genuine gap on Source 1
    let snap2 = relay.event_buffer().snapshot();
    let genuine_gap = snap2.events.iter().find(|e| {
        e.reason
            .as_ref()
            .is_some_and(|r| r.contains("MAVLink sequence gap") && r.contains("sysid 1"))
    });
    assert!(
        genuine_gap.is_some(),
        "must emit diagnostic event for genuine sequence gap on Source 1"
    );

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 1:
// Forwarding a UDP datagram on a stream with MAVLink inspection enabled forwards
// the exact datagram payload bytes unmodified while recording sequence metadata
// in diagnostic events.
// ---------------------------------------------------------------------------

#[test]
fn test_forward_udp_mavlink_inspection_exact_bytes_and_metadata_events() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mavlink-inspect"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mavlink:
          enabled: true
          track_sequences: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // Test 1: MAVLink 1 packet
    let v1_pkt = build_mavlink1_packet(15, 10, 20, 42, b"mavlink-v1-payload");
    sender.send_to(&v1_pkt, &target).expect("send");

    let mut buf = vec![0u8; 1024];
    let (n1, _) = dest_sock.recv_from(&mut buf).expect("recv v1");
    assert_eq!(
        &buf[..n1],
        v1_pkt.as_slice(),
        "MAVLink 1 payload must be forwarded exact and unmodified"
    );

    // Test 2: MAVLink 2 signed packet
    let v2_signed_pkt = build_mavlink2_packet(16, 10, 20, 1000, true, b"mavlink-v2-signed-data");
    sender.send_to(&v2_signed_pkt, &target).expect("send");

    let (n2, _) = dest_sock.recv_from(&mut buf).expect("recv v2 signed");
    assert_eq!(
        &buf[..n2],
        v2_signed_pkt.as_slice(),
        "MAVLink 2 signed payload must be forwarded exact and unmodified"
    );

    let stats = relay.stream_stats("s-mavlink-inspect").expect("stats");
    assert_eq!(stats.received_packets, 2);
    assert_eq!(stats.forwarded_packets, 2);
    assert_eq!(stats.dropped_packets, 0);

    // Check inspection diagnostic events
    let snap = relay.event_buffer().snapshot();
    let insp_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::MavlinkInspection)
        .collect();

    assert_eq!(insp_events.len(), 2);

    // First event (MAVLink 1)
    let ev1 = insp_events[0];
    assert_eq!(ev1.mavlink_system_id, Some(10));
    assert_eq!(ev1.mavlink_component_id, Some(20));
    assert_eq!(ev1.mavlink_sequence, Some(15));
    assert_eq!(ev1.sequence_number, Some(15));
    assert_eq!(ev1.mavlink_message_id, Some(42));
    assert_eq!(ev1.mavlink_version, Some(1));
    assert!(ev1.mavlink_metadata.is_some());

    // Second event (MAVLink 2 signed)
    let ev2 = insp_events[1];
    assert_eq!(ev2.mavlink_system_id, Some(10));
    assert_eq!(ev2.mavlink_component_id, Some(20));
    assert_eq!(ev2.mavlink_sequence, Some(16));
    assert_eq!(ev2.sequence_number, Some(16));
    assert_eq!(ev2.mavlink_message_id, Some(1000));
    assert_eq!(ev2.mavlink_version, Some(2));
    assert!(ev2.mavlink_metadata.is_some());
    let m2 = ev2.mavlink_metadata.as_ref().unwrap();
    assert_eq!(m2.is_signed, Some(true));

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3:
// Receiving a malformed or truncated MAVLink packet on an inspected stream drops
// the packet by default, increments dropped packet counters, and emits a dropped
// diagnostic event.
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_or_truncated_mavlink_packet_dropped_by_default() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mavlink-drop-test"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mavlink:
          enabled: true
          passthrough_on_error: false
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // 1. Invalid magic byte (neither 0xFE nor 0xFD)
    let invalid_magic = vec![0x55, 0x05, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00];
    sender.send_to(&invalid_magic, &target).expect("send");

    // 2. Truncated header (< 6 bytes for v1)
    let truncated_hdr = vec![MAVLINK_STX_V1, 0x05, 0x01];
    sender.send_to(&truncated_hdr, &target).expect("send");

    // 3. Truncated total packet length (payload length says 20, but only 10 bytes provided)
    let truncated_pkt = vec![MAVLINK_STX_V1, 20, 1, 1, 1, 1, 0xAA, 0xBB, 0xCC, 0xDD];
    sender.send_to(&truncated_pkt, &target).expect("send");

    // 4. Valid packet (must be forwarded successfully)
    let valid_pkt = build_mavlink1_packet(1, 1, 1, 1, b"valid-packet");
    sender.send_to(&valid_pkt, &target).expect("send");

    // Destination should only receive the 1 valid packet
    let mut buf = vec![0u8; 1024];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv valid packet");
    assert_eq!(&buf[..n], valid_pkt.as_slice());

    // No further packets should be received
    let res = dest_sock.recv_from(&mut buf);
    assert!(res.is_err(), "malformed packets must have been dropped");

    let stats = relay.stream_stats("s-mavlink-drop-test").expect("stats");
    assert_eq!(stats.received_packets, 4);
    assert_eq!(stats.forwarded_packets, 1);
    assert_eq!(stats.dropped_packets, 3);
    assert_eq!(stats.drops_validation, 3);

    // Verify DiagnosticStage::Dropped events
    let snap = relay.event_buffer().snapshot();
    let dropped_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Dropped)
        .collect();

    assert_eq!(dropped_events.len(), 3);
    for ev in &dropped_events {
        assert!(ev.reason.is_some(), "dropped event must include reason");
    }

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4:
// Receiving a malformed MAVLink packet on an inspected stream configured with option
// passthrough_on_error forwards the payload unmodified to destination endpoints while
// recording a validation failure event.
// ---------------------------------------------------------------------------

#[test]
fn test_malformed_mavlink_packet_with_passthrough_on_error_forwards_and_records_failure() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mavlink-passthrough"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mavlink:
          enabled: true
          passthrough_on_error: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // Invalid magic byte packet
    let invalid_pkt = b"totally-invalid-mavlink-bytes".to_vec();
    sender.send_to(&invalid_pkt, &target).expect("send");

    // Truncated packet
    let truncated_pkt = vec![MAVLINK_STX_V2, 50, 0, 0, 1, 1, 1, 1, 0, 0];
    sender.send_to(&truncated_pkt, &target).expect("send");

    let mut buf = vec![0u8; 1024];
    let (n1, _) = dest_sock.recv_from(&mut buf).expect("recv packet 1");
    assert_eq!(
        &buf[..n1],
        invalid_pkt.as_slice(),
        "invalid packet must be forwarded unmodified"
    );

    let (n2, _) = dest_sock.recv_from(&mut buf).expect("recv packet 2");
    assert_eq!(
        &buf[..n2],
        truncated_pkt.as_slice(),
        "truncated packet must be forwarded unmodified"
    );

    let stats = relay.stream_stats("s-mavlink-passthrough").expect("stats");
    assert_eq!(stats.received_packets, 2);
    assert_eq!(stats.forwarded_packets, 2);
    assert_eq!(
        stats.dropped_packets, 0,
        "no packets dropped under passthrough"
    );
    assert_eq!(stats.validation_errors, 2, "2 validation errors recorded");

    // Verify diagnostic failure events
    let snap = relay.event_buffer().snapshot();
    let failure_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Failure)
        .collect();

    assert_eq!(
        failure_events.len(),
        2,
        "must emit 2 failure events for validation failures"
    );
    assert!(failure_events[0]
        .reason
        .as_ref()
        .unwrap()
        .contains("validation failed"));
    assert!(failure_events[1]
        .reason
        .as_ref()
        .unwrap()
        .contains("validation failed"));

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 5:
// Forwarding traffic on a stream without MAVLink inspection configured delivers
// datagrams byte-identically without invoking MAVLink parsing overhead.
// ---------------------------------------------------------------------------

#[test]
fn test_unconfigured_stream_byte_identical_delivery_no_mavlink_overhead() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-unconfigured-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let stream_cfg: &StreamConfig = &config.instances[0].streams[0];
    assert!(stream_cfg.mavlink.is_none());

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    let test_payloads: Vec<Vec<u8>> = vec![
        b"raw-uninspected-bytes-1".to_vec(),
        vec![0x00, 0x01, 0x02, 0x03, 0xFF],
        b"another-unparsed-datagram".to_vec(),
    ];

    for p in &test_payloads {
        sender.send_to(p, &target).expect("send");
        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            p.as_slice(),
            "payload must match byte-identically"
        );
    }

    assert!(
        relay.mavlink_tracker("s-unconfigured-stream").is_none(),
        "unconfigured stream must not instantiate mavlink tracker"
    );

    let stats = relay.stream_stats("s-unconfigured-stream").expect("stats");
    assert_eq!(stats.received_packets, 3);
    assert_eq!(stats.forwarded_packets, 3);
    assert_eq!(stats.dropped_packets, 0);

    // Verify diagnostic buffer contains NO MAVLink inspection events
    let snap = relay.event_buffer().snapshot();
    let mavlink_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::MavlinkInspection)
        .collect();
    assert!(mavlink_events.is_empty());

    relay.stop();
}
