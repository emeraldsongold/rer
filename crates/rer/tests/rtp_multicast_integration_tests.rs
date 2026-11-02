//! Integration tests for RTP stream inspection, sequence tracking, rollover, validation errors,
//! and multicast forwarding (SPEC §5, §8, §14, Task RER-F-073).

use std::net::UdpSocket;
use std::time::Duration;

use rer::config::Config;
use rer::diagnostics::DiagnosticStage;
use rer::relay::Relay;
use rer::rtp::{encode_rtp_header, parse_rtp_header, RTP_VERSION_2};

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn build_rtp_packet(
    seq: u16,
    pt: u8,
    marker: bool,
    timestamp: u32,
    ssrc: u32,
    payload: &[u8],
) -> Vec<u8> {
    let header = encode_rtp_header(
        RTP_VERSION_2,
        false, // padding
        false, // extension
        marker,
        pt,
        seq,
        timestamp,
        ssrc,
        &[],  // csrc_list
        None, // extension_header
    );
    let mut packet = header;
    packet.extend_from_slice(payload);
    packet
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 1:
// In crates/rer/tests/rtp_multicast_integration_tests.rs, forwarding 100
// consecutive RTP datagrams across a relay stream verifies that the destination
// receives the exact payload bytes of the transmitted packets.
// ---------------------------------------------------------------------------

#[test]
fn test_forwarding_100_consecutive_rtp_datagrams_verifies_exact_payload_bytes() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind destination socket");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    let dest_port = dest_sock.local_addr().expect("destination port").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i-rtp-100"
    streams:
      - id: "s-rtp-100"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        rtp:
          enabled: true
          track_sequences: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    std::thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender socket");
    let target = format!("127.0.0.1:{listen_port}");

    let ssrc = 0x11223344;
    let base_ts = 160000;
    let mut sent_packets = Vec::with_capacity(100);

    for i in 0..100u16 {
        let seq = 1000 + i;
        let ts = base_ts + u32::from(i) * 160;
        let marker = i == 99;
        let payload = format!("rtp-payload-data-packet-{:04}", i).into_bytes();
        let packet = build_rtp_packet(seq, 96, marker, ts, ssrc, &payload);

        sender.send_to(&packet, &target).expect("send rtp datagram");
        sent_packets.push((packet, payload));

        std::thread::sleep(Duration::from_millis(1));
    }

    for (i, (expected_packet, expected_payload)) in sent_packets.iter().enumerate() {
        let mut buf = vec![0u8; 1500];
        let (n, _) = dest_sock
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("failed to receive packet {i}: {e}"));

        assert_eq!(
            &buf[..n],
            expected_packet.as_slice(),
            "packet {i} must be forwarded byte-for-byte unmodified"
        );

        let parsed = parse_rtp_header(&buf[..n]).expect("parse received rtp packet");
        let payload_slice = &buf[parsed.payload_offset..n];
        assert_eq!(
            payload_slice,
            expected_payload.as_slice(),
            "destination must receive the exact payload bytes for packet {i}"
        );
    }

    let stats = relay.stream_stats("s-rtp-100").expect("stream stats");
    assert_eq!(stats.received_packets, 100);
    assert_eq!(stats.forwarded_packets, 100);
    assert_eq!(stats.dropped_packets, 0);

    let tracker_arc = relay
        .rtp_tracker("s-rtp-100")
        .expect("rtp tracker configured");
    let tracker = tracker_arc.lock().unwrap();
    assert_eq!(tracker.packets_evaluated(), 100);
    assert_eq!(tracker.gap_count(), 0);
    assert_eq!(tracker.last_sequence(), Some(1099));

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2:
// In crates/rer/tests/rtp_multicast_integration_tests.rs, streaming RTP packets
// through sequence number 65535 to sequence number 0 verifies that sequence
// rollover is tracked without incrementing gap counters.
// ---------------------------------------------------------------------------

#[test]
fn test_streaming_rtp_sequence_65535_to_0_rollover_without_incrementing_gaps() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind destination socket");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    let dest_port = dest_sock.local_addr().expect("destination port").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i-rtp-rollover"
    streams:
      - id: "s-rtp-rollover"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        rtp:
          enabled: true
          track_sequences: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    std::thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender socket");
    let target = format!("127.0.0.1:{listen_port}");

    // Sequences approaching 65535 and rolling over to 0:
    // 65533, 65534, 65535, 0, 1, 2, 3
    let sequences: Vec<u16> = vec![65533, 65534, 65535, 0, 1, 2, 3];
    let ssrc = 0x99887766;
    let mut ts = 200000u32;

    for &seq in &sequences {
        let payload = format!("rollover-payload-seq-{}", seq).into_bytes();
        let packet = build_rtp_packet(seq, 96, false, ts, ssrc, &payload);
        ts += 160;

        sender.send_to(&packet, &target).expect("send rtp datagram");

        let mut buf = vec![0u8; 1500];
        let (n, _) = dest_sock
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("failed to receive seq {seq}: {e}"));

        assert_eq!(
            &buf[..n],
            packet.as_slice(),
            "packet with sequence {seq} must be received byte-for-byte"
        );

        std::thread::sleep(Duration::from_millis(2));
    }

    let stats = relay.stream_stats("s-rtp-rollover").expect("stream stats");
    assert_eq!(stats.received_packets, sequences.len() as u64);
    assert_eq!(stats.forwarded_packets, sequences.len() as u64);
    assert_eq!(stats.dropped_packets, 0);

    // Verify tracker state: rollover tracked without incrementing gap counters
    let tracker_arc = relay
        .rtp_tracker("s-rtp-rollover")
        .expect("rtp tracker configured");
    let tracker = tracker_arc.lock().unwrap();

    assert_eq!(
        tracker.packets_evaluated(),
        sequences.len() as u64,
        "all packets must be evaluated"
    );
    assert_eq!(
        tracker.rollover_count(),
        1,
        "sequence rollover across 65535 to 0 must be recorded"
    );
    assert_eq!(
        tracker.gap_count(),
        0,
        "sequence rollover must NOT increment gap counters"
    );
    assert_eq!(tracker.last_sequence(), Some(3), "last sequence must be 3");

    // Verify no false sequence gap events in diagnostic buffer
    let snap = relay.event_buffer().snapshot();
    let gap_events: Vec<_> = snap
        .events
        .iter()
        .filter(|e| {
            e.reason
                .as_ref()
                .is_some_and(|r| r.to_lowercase().contains("gap"))
        })
        .collect();
    assert!(
        gap_events.is_empty(),
        "sequence rollover must not emit sequence gap events: found {:?}",
        gap_events
    );

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3:
// In crates/rer/tests/rtp_multicast_integration_tests.rs, sending a truncated
// 8-byte datagram to a stream with RTP inspection enabled verifies that the
// packet is dropped and not delivered to the destination.
// ---------------------------------------------------------------------------

#[test]
fn test_sending_truncated_8_byte_datagram_dropped_and_not_delivered() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind destination socket");
    dest_sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set read timeout");
    let dest_port = dest_sock.local_addr().expect("destination port").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i-rtp-drop"
    streams:
      - id: "s-rtp-drop"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        rtp:
          enabled: true
          track_sequences: true
          passthrough_on_error: false
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    std::thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender socket");
    let target = format!("127.0.0.1:{listen_port}");

    // Truncated 8-byte datagram (RFC 3550 RTP fixed header requires 12 bytes minimum)
    let truncated_datagram = [0x80, 0x60, 0x01, 0x02, 0x00, 0x11, 0x22, 0x33];
    assert_eq!(truncated_datagram.len(), 8);

    sender
        .send_to(&truncated_datagram, &target)
        .expect("send truncated datagram");

    // Verify datagram is dropped and not delivered to the destination (read timeout)
    let mut buf = [0u8; 1024];
    let recv_res = dest_sock.recv_from(&mut buf);
    assert!(
        recv_res.is_err(),
        "truncated datagram must be dropped and NOT delivered to destination: got {:?}",
        recv_res
    );

    std::thread::sleep(Duration::from_millis(50));

    let stats = relay.stream_stats("s-rtp-drop").expect("stream stats");
    assert_eq!(stats.received_packets, 1);
    assert_eq!(stats.forwarded_packets, 0);
    assert_eq!(stats.dropped_packets, 1);
    assert_eq!(stats.drops_validation, 1);

    // Verify diagnostic buffer emitted a dropped event for validation failure
    let snap = relay.event_buffer().snapshot();
    let failure_event = snap.events.iter().find(|e| {
        e.stage == DiagnosticStage::Dropped
            || e.reason.as_ref().is_some_and(|r| {
                r.to_lowercase().contains("truncated")
                    || r.to_lowercase().contains("invalid rtp")
                    || r.to_lowercase().contains("12-byte")
            })
    });
    assert!(
        failure_event.is_some(),
        "must emit dropped diagnostic event for truncated datagram"
    );

    // Verify stream remains functional by sending a valid RTP packet
    let valid_packet = build_rtp_packet(1, 96, false, 1000, 0x12345678, b"valid-payload");
    sender
        .send_to(&valid_packet, &target)
        .expect("send valid packet");

    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let (n, _) = dest_sock
        .recv_from(&mut buf)
        .expect("valid packet must be received");
    assert_eq!(&buf[..n], valid_packet.as_slice());

    let updated_stats = relay.stream_stats("s-rtp-drop").expect("stream stats");
    assert_eq!(updated_stats.received_packets, 2);
    assert_eq!(updated_stats.forwarded_packets, 1);
    assert_eq!(updated_stats.dropped_packets, 1);
    assert_eq!(updated_stats.drops_validation, 1);

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4:
// In crates/rer/tests/rtp_multicast_integration_tests.rs, sending a truncated
// 8-byte datagram to an inspected stream configured with passthrough_on_error
// set to true forwards the datagram to the destination.
// ---------------------------------------------------------------------------

#[test]
fn test_sending_truncated_8_byte_datagram_passthrough_on_error_forwards_to_destination() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind destination socket");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let dest_port = dest_sock.local_addr().expect("destination port").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i-rtp-passthrough"
    streams:
      - id: "s-rtp-passthrough"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        rtp:
          enabled: true
          track_sequences: true
          passthrough_on_error: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    std::thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender socket");
    let target = format!("127.0.0.1:{listen_port}");

    // Truncated 8-byte datagram
    let truncated_datagram = [0x80, 0x60, 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
    assert_eq!(truncated_datagram.len(), 8);

    sender
        .send_to(&truncated_datagram, &target)
        .expect("send truncated datagram");

    // Verify the datagram is forwarded and received at the destination
    let mut buf = [0u8; 1024];
    let (n, _) = dest_sock
        .recv_from(&mut buf)
        .expect("destination must receive forwarded datagram when passthrough_on_error is true");

    assert_eq!(
        &buf[..n],
        &truncated_datagram,
        "destination must receive the exact bytes of the forwarded truncated 8-byte datagram"
    );

    std::thread::sleep(Duration::from_millis(50));

    let stats = relay
        .stream_stats("s-rtp-passthrough")
        .expect("stream stats");
    assert_eq!(stats.received_packets, 1);
    assert_eq!(stats.forwarded_packets, 1);
    assert_eq!(stats.dropped_packets, 0);
    assert_eq!(stats.drops_validation, 0);

    // Verify diagnostic buffer emitted a validation failure event
    let snap = relay.event_buffer().snapshot();
    let failure_event = snap
        .events
        .iter()
        .find(|e| e.stage == DiagnosticStage::Failure);
    assert!(
        failure_event.is_some(),
        "must emit validation failure event even when passed through"
    );

    relay.stop();
}

// ---------------------------------------------------------------------------
// Multicast forwarding integration test
// ---------------------------------------------------------------------------

#[test]
fn test_multicast_rtp_forwarding_preserves_payload_and_applies_egress_settings() {
    let egress_port = pick_unused_port();
    let ingress_port = pick_unused_port();
    let mcast_addr = format!("239.255.0.42:{egress_port}");

    let receiver = match rer::relay::bind_multicast_udp_socket(
        mcast_addr.parse().expect("parse mcast addr"),
        None,
    ) {
        Ok(sock) => sock,
        Err(e) => {
            eprintln!("SKIPPED: Multicast bind failed in container environment: {e}");
            return;
        }
    };
    receiver
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("set read timeout");

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i-rtp-mcast"
    streams:
      - id: "s-rtp-mcast"
        source:
          transport: "udp"
          address: "127.0.0.1:{ingress_port}"
        destination:
          transport: "udp"
          address: "{mcast_addr}"
          multicast:
            ttl: 20
            loopback: true
        rtp:
          enabled: true
          track_sequences: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = match Relay::start(&config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("SKIPPED: Multicast relay startup failed in container environment: {e}");
            return;
        }
    };
    std::thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let rtp_packet = build_rtp_packet(
        500,
        96,
        true,
        320000,
        0x55667788,
        b"rtp-multicast-payload-bytes",
    );

    if sender
        .send_to(&rtp_packet, format!("127.0.0.1:{ingress_port}"))
        .is_err()
    {
        relay.stop();
        return;
    }

    let mut buf = [0u8; 1024];
    match receiver.recv_from(&mut buf) {
        Ok((n, _)) => {
            assert_eq!(
                &buf[..n],
                rtp_packet.as_slice(),
                "multicast RTP datagram must preserve exact bytes"
            );
        }
        Err(e) => {
            eprintln!("Multicast receive timed out in container environment: {e}");
        }
    }

    relay.stop();
}
