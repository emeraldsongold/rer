//! Integration tests for CCSDS stream configuration and relay forwarding (SPEC §14, §5, §8, Task RER-F-032).

use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

use rer::ccsds::{CcsdsPrimaryHeader, CCSDS_PRIMARY_HEADER_LEN};
use rer::config::{Config, StreamConfig};
use rer::diagnostics::{DiagnosticEvent, DiagnosticStage};
use rer::relay::Relay;

fn rer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rer")
}

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn build_space_packet(
    version: u8,
    packet_type: u8,
    sec_header: bool,
    apid: u16,
    seq_flags: u8,
    seq_count: u16,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = payload.len().max(1);
    let data_len_field = (payload_len - 1) as u16;
    let header = CcsdsPrimaryHeader {
        version,
        packet_type,
        secondary_header_flag: sec_header,
        apid,
        sequence_flags: seq_flags,
        sequence_count: seq_count,
        packet_data_length: data_len_field,
        total_packet_length: payload_len + CCSDS_PRIMARY_HEADER_LEN,
    };
    let mut bytes = header.to_bytes().to_vec();
    bytes.extend_from_slice(payload);
    if payload.is_empty() {
        bytes.push(0x00);
    }
    bytes
}

// ---------------------------------------------------------------------------
// Criterion 1: StreamConfig accepts optional ccsds, configs without ccsds behave identically
// ---------------------------------------------------------------------------

#[test]
fn test_criterion1_stream_config_accepts_ccsds_and_unconfigured_forwards_identically() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    // Stream without CCSDS subsection
    let yaml_no_ccsds = format!(
        r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-plain"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config_no_ccsds = Config::from_yaml_str(&yaml_no_ccsds).expect("valid config");
    assert!(config_no_ccsds.validate().is_empty());
    let stream_cfg: &StreamConfig = &config_no_ccsds.instances[0].streams[0];
    assert!(stream_cfg.ccsds.is_none());

    let relay = Relay::start(&config_no_ccsds).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    let raw_payloads: Vec<Vec<u8>> = vec![
        b"raw-unframed-datagram-1".to_vec(),
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        vec![1, 2, 3, 4, 5],
    ];

    for p in &raw_payloads {
        sender
            .send_to(p, format!("127.0.0.1:{listen_port}"))
            .expect("send");
        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            p.as_slice(),
            "raw payload must match identically"
        );
    }

    let stats = relay.stream_stats("s-plain").expect("stats");
    assert_eq!(stats.received_packets, 3);
    assert_eq!(stats.forwarded_packets, 3);
    assert_eq!(stats.dropped_packets, 0);

    relay.stop();

    // Stream with CCSDS subsection deserialization
    let yaml_with_ccsds = format!(
        r#"
version: "1"
instances:
  - id: "i2"
    streams:
      - id: "s-ccsds"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        ccsds:
          enabled: true
          validate_version: true
          validate_length: true
          track_sequences: true
          ignore_idle_apid: true
          passthrough_on_error: false
"#
    );
    let config_with_ccsds = Config::from_yaml_str(&yaml_with_ccsds).expect("valid ccsds config");
    assert!(config_with_ccsds.validate().is_empty());
    let stream_cfg_ccsds = &config_with_ccsds.instances[0].streams[0];
    assert!(stream_cfg_ccsds.ccsds.is_some());
    let ccsds_val = stream_cfg_ccsds.ccsds.as_ref().unwrap();
    assert!(ccsds_val.enabled);
    assert!(ccsds_val.validate_version);
    assert!(ccsds_val.validate_length);
    assert!(ccsds_val.track_sequences);
    assert!(ccsds_val.ignore_idle_apid);
    assert!(!ccsds_val.passthrough_on_error);
}

// ---------------------------------------------------------------------------
// Criterion 2: rer validate rejects conflicting sequence tracking
// ---------------------------------------------------------------------------

#[test]
fn test_criterion2_validate_rejects_conflicting_sequence_tracking() {
    let yaml_conflict = r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-conflict"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:6000"
        sequence:
          enabled: true
          offset: 0
          width: 4
        ccsds:
          enabled: true
          track_sequences: true
"#;

    let config = Config::from_yaml_str(yaml_conflict).expect("parse config");
    let errors = config.validate();
    assert!(
        !errors.is_empty(),
        "conflicting sequence tracking must produce validation errors"
    );
    let conflict_err = errors
        .iter()
        .find(|e| e.reason.contains("conflicting sequence tracking"));
    assert!(
        conflict_err.is_some(),
        "expected error reason containing 'conflicting sequence tracking', got: {:?}",
        errors
    );

    // Test through CLI 'rer validate'
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!(
        "test_conflict_{}.yaml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&temp_file, yaml_conflict).expect("write temp config");

    let output = Command::new(rer_bin())
        .arg("validate")
        .arg(&temp_file)
        .output()
        .expect("execute rer validate");

    let _ = std::fs::remove_file(&temp_file);

    assert!(
        !output.status.success(),
        "rer validate must fail for conflicting sequence tracking"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conflicting sequence tracking"),
        "stderr must identify conflicting sequence tracking, got:\n{}",
        stderr
    );

    // Verify when generic sequence tracking is disabled, validation succeeds
    let yaml_allowed = r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-allowed"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:6000"
        sequence:
          enabled: false
        ccsds:
          enabled: true
          track_sequences: true
"#;
    let config_allowed = Config::from_yaml_str(yaml_allowed).expect("parse allowed config");
    assert!(
        config_allowed.validate().is_empty(),
        "when generic sequence tracking is disabled, ccsds sequence tracking should validate cleanly"
    );
}

// ---------------------------------------------------------------------------
// Criterion 3: Incoming datagrams with invalid version or truncated length dropped by default
// ---------------------------------------------------------------------------

#[test]
fn test_criterion3_invalid_version_and_truncated_length_dropped_by_default() {
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
      - id: "s-ccsds-drop"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        ccsds:
          enabled: true
          validate_version: true
          validate_length: true
          passthrough_on_error: false
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // 1. Packet with invalid version (version = 2 != 0)
    let invalid_version_pkt = build_space_packet(2, 0, false, 100, 3, 10, b"data-v2");
    sender.send_to(&invalid_version_pkt, &target).expect("send");

    // 2. Truncated header (< 6 bytes)
    let truncated_hdr_pkt = vec![0x00, 0x64, 0xC0];
    sender.send_to(&truncated_hdr_pkt, &target).expect("send");

    // 3. Length mismatch (declared length 20 -> 27 total bytes, but buffer has only 12 bytes)
    let mut truncated_len_pkt = build_space_packet(0, 0, false, 100, 3, 11, &[0xAA; 20]);
    truncated_len_pkt.truncate(12);
    sender.send_to(&truncated_len_pkt, &target).expect("send");

    // 4. Valid packet (must be forwarded successfully)
    let valid_pkt = build_space_packet(0, 0, false, 100, 3, 12, b"valid-payload");
    sender.send_to(&valid_pkt, &target).expect("send");

    // Destination should only receive the 1 valid packet
    let mut buf = vec![0u8; 1024];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("receive valid packet");
    assert_eq!(&buf[..n], valid_pkt.as_slice());

    // Expect no more packets received
    let res = dest_sock.recv_from(&mut buf);
    assert!(res.is_err(), "invalid packets must not be forwarded");

    // Check stats: 3 dropped packets, 1 forwarded packet
    let stats = relay.stream_stats("s-ccsds-drop").expect("stats");
    assert_eq!(stats.received_packets, 4);
    assert_eq!(stats.forwarded_packets, 1);
    assert_eq!(stats.dropped_packets, 3);

    // Verify diagnostic buffer emitted DiagnosticStage::Dropped events
    let snap = relay.event_buffer().snapshot();
    let dropped_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Dropped)
        .collect();

    assert_eq!(
        dropped_events.len(),
        3,
        "expected 3 dropped events, got {:?}",
        dropped_events
    );

    for ev in &dropped_events {
        assert!(ev.reason.is_some(), "dropped event must have reason");
    }

    relay.stop();
}

// ---------------------------------------------------------------------------
// Criterion 4: passthrough_on_error forwards unchanged with diagnostic failure event
// ---------------------------------------------------------------------------

#[test]
fn test_criterion4_passthrough_on_error_forwards_unchanged_and_emits_failure_event() {
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
      - id: "s-passthrough"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        ccsds:
          enabled: true
          passthrough_on_error: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // Invalid version packet
    let invalid_version_pkt = build_space_packet(3, 0, false, 50, 3, 1, b"err-version");
    sender.send_to(&invalid_version_pkt, &target).expect("send");

    // Truncated length packet
    let mut truncated_pkt = build_space_packet(0, 0, false, 50, 3, 2, &[0xBB; 30]);
    truncated_pkt.truncate(10);
    sender.send_to(&truncated_pkt, &target).expect("send");

    // Both packets must arrive unchanged at destination
    let mut buf = vec![0u8; 1024];
    let (n1, _) = dest_sock.recv_from(&mut buf).expect("recv packet 1");
    assert_eq!(
        &buf[..n1],
        invalid_version_pkt.as_slice(),
        "invalid version packet forwarded unchanged"
    );

    let (n2, _) = dest_sock.recv_from(&mut buf).expect("recv packet 2");
    assert_eq!(
        &buf[..n2],
        truncated_pkt.as_slice(),
        "truncated length packet forwarded unchanged"
    );

    let stats = relay.stream_stats("s-passthrough").expect("stats");
    assert_eq!(stats.received_packets, 2);
    assert_eq!(stats.forwarded_packets, 2);
    assert_eq!(stats.dropped_packets, 0, "no packets should be dropped");
    assert_eq!(stats.validation_errors, 2, "2 validation errors recorded");

    // Verify diagnostic failure events emitted
    let snap = relay.event_buffer().snapshot();
    let failure_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Failure)
        .collect();

    assert_eq!(
        failure_events.len(),
        2,
        "must emit 2 diagnostic failure events for passthrough errors"
    );
    assert!(failure_events[0]
        .reason
        .as_ref()
        .unwrap()
        .contains("version"));
    assert!(
        failure_events[1]
            .reason
            .as_ref()
            .unwrap()
            .contains("length")
            || failure_events[1]
                .reason
                .as_ref()
                .unwrap()
                .contains("shorter")
    );

    relay.stop();
}

// ---------------------------------------------------------------------------
// Criterion 5: Sequence gaps, duplicates, out-of-order emit diagnostic events and forward
// ---------------------------------------------------------------------------

#[test]
fn test_criterion5_sequence_gaps_duplicates_and_out_of_order_packets() {
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
      - id: "s-ccsds-seq"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        ccsds:
          enabled: true
          track_sequences: true
          ignore_idle_apid: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    let apid1 = 100u16;
    let apid2 = 200u16;

    // 1. Initial packet for APID 100 (seq = 0)
    let p1 = build_space_packet(0, 0, false, apid1, 3, 0, b"p1");
    // 2. Sequence Gap for APID 100: jump from 0 to 4 (missing 1, 2, 3)
    let p2 = build_space_packet(0, 0, false, apid1, 3, 4, b"p2");
    // 3. Duplicate packet for APID 100: seq = 4 again
    let p3 = build_space_packet(0, 0, false, apid1, 3, 4, b"p3");
    // 4. Out-of-order packet for APID 100: seq = 2 arrives after 4
    let p4 = build_space_packet(0, 0, false, apid1, 3, 2, b"p4");
    // 5. APID 200 initial packet (seq = 10)
    let p5 = build_space_packet(0, 0, false, apid2, 3, 10, b"p5");
    // 6. APID 200 in-order packet (seq = 11)
    let p6 = build_space_packet(0, 0, false, apid2, 3, 11, b"p6");

    let packets = vec![&p1, &p2, &p3, &p4, &p5, &p6];

    for pkt in &packets {
        sender.send_to(pkt, &target).expect("send");
        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("receive packet");
        assert_eq!(
            &buf[..n],
            pkt.as_slice(),
            "all packets must be forwarded without drops"
        );
    }

    let stats = relay.stream_stats("s-ccsds-seq").expect("stats");
    assert_eq!(stats.received_packets, 6);
    assert_eq!(stats.forwarded_packets, 6);
    assert_eq!(
        stats.dropped_packets, 0,
        "no packets dropped on sequence anomalies"
    );

    // Inspect diagnostic events
    let snap = relay.event_buffer().snapshot();
    let diag_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Failure)
        .collect();

    // Verify sequence gap event
    let gap_event = diag_events.iter().find(|e| {
        e.reason
            .as_ref()
            .is_some_and(|r| r.contains("sequence gap"))
    });
    assert!(
        gap_event.is_some(),
        "must emit diagnostic event for sequence gap"
    );
    let gap_ev = gap_event.unwrap();
    assert_eq!(gap_ev.apid, Some(apid1));

    // Verify duplicate event
    let dup_event = diag_events
        .iter()
        .find(|e| e.reason.as_ref().is_some_and(|r| r.contains("duplicate")));
    assert!(
        dup_event.is_some(),
        "must emit diagnostic event for duplicate packet"
    );
    let dup_ev = dup_event.unwrap();
    assert_eq!(dup_ev.apid, Some(apid1));

    // Verify out-of-order event
    let ooo_event = diag_events.iter().find(|e| {
        e.reason
            .as_ref()
            .is_some_and(|r| r.contains("out-of-order"))
    });
    assert!(
        ooo_event.is_some(),
        "must emit diagnostic event for out-of-order packet"
    );
    let ooo_ev = ooo_event.unwrap();
    assert_eq!(ooo_ev.apid, Some(apid1));

    // Verify tracker state per APID
    let tracker_arc = relay.ccsds_tracker("s-ccsds-seq").expect("ccsds tracker");
    let tracker = tracker_arc.lock().unwrap();
    assert_eq!(tracker.gap_count(apid1), 3);
    assert_eq!(tracker.duplicate_count(apid1), 1);
    assert_eq!(tracker.out_of_order_count(apid1), 1);
    assert_eq!(tracker.gap_count(apid2), 0);
    assert_eq!(tracker.duplicate_count(apid2), 0);
    assert_eq!(tracker.out_of_order_count(apid2), 0);

    relay.stop();
}
