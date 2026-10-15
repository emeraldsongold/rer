//! Integration tests for RER diagnostic event model and bounded non-blocking buffer (SPEC §8, §10).

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use rer::config::{OperationalMode, TransportType};
use rer::diagnostics::{DiagnosticBuffer, DiagnosticEvent, DiagnosticStage, ManualClock};

#[test]
fn test_stage_names_and_snake_case_pinned() {
    let cases = [
        (DiagnosticStage::Received, "\"received\""),
        (DiagnosticStage::Accepted, "\"accepted\""),
        (DiagnosticStage::RoutedOrQueued, "\"routed_or_queued\""),
        (DiagnosticStage::SendAttempted, "\"send_attempted\""),
        (DiagnosticStage::SendSucceeded, "\"send_succeeded\""),
        (DiagnosticStage::Dropped, "\"dropped\""),
        (DiagnosticStage::Failure, "\"failure\""),
        (DiagnosticStage::HealthTransition, "\"health_transition\""),
    ];

    for (stage, expected_json) in cases {
        let serialized = serde_json::to_string(&stage).expect("failed to serialize stage");
        assert_eq!(serialized, expected_json);

        let deserialized: DiagnosticStage =
            serde_json::from_str(expected_json).expect("failed to deserialize stage");
        assert_eq!(deserialized, stage);
    }
}

#[test]
fn test_event_has_no_payload_bytes_field() {
    let event = DiagnosticEvent::new(
        1000,
        2000,
        "stream-test",
        DiagnosticStage::Accepted,
        TransportType::Udp,
        1400,
    )
    .with_source("127.0.0.1:4000")
    .with_destination("127.0.0.1:5000")
    .with_correlation_id("corr-xyz")
    .with_reason("ok");

    let val = serde_json::to_value(&event).expect("serialize event");
    let obj = val.as_object().expect("object expected");

    assert_eq!(
        obj.get("payload_length").and_then(|v| v.as_u64()),
        Some(1400)
    );
    assert!(!obj.contains_key("payload"));
    assert!(!obj.contains_key("data"));
    assert!(!obj.contains_key("bytes"));
    assert!(!obj.contains_key("packet"));
    assert!(!obj.contains_key("body"));
}

#[test]
fn test_buffer_full_overwrites_oldest_and_snapshot_arrival_order() {
    let clock = Arc::new(ManualClock::new(100, 200));
    let buffer = DiagnosticBuffer::with_clock(3, clock.clone());

    // Push 3 events
    for i in 1..=3 {
        clock.advance_millis(10);
        let ev = buffer.create_event(
            format!("s-{i}"),
            DiagnosticStage::Received,
            TransportType::Udp,
            50 * i,
        );
        assert!(buffer.emit(ev));
    }

    assert_eq!(buffer.dropped_count(), 0);
    assert_eq!(buffer.len(), 3);

    // Push 4th event -> s-1 is overwritten, dropped_count becomes 1
    clock.advance_millis(10);
    let ev4 = buffer.create_event(
        "s-4",
        DiagnosticStage::SendAttempted,
        TransportType::Tcp,
        200,
    );
    assert!(buffer.emit(ev4));

    assert_eq!(buffer.dropped_count(), 1);
    let snap = buffer.snapshot();
    assert_eq!(snap.dropped_count, 1);
    assert_eq!(snap.events.len(), 3);
    assert_eq!(snap.events[0].stream_id, "s-2");
    assert_eq!(snap.events[1].stream_id, "s-3");
    assert_eq!(snap.events[2].stream_id, "s-4");

    // Push 5th event -> s-2 overwritten, dropped_count becomes 2
    clock.advance_millis(10);
    let ev5 = buffer.create_event(
        "s-5",
        DiagnosticStage::SendSucceeded,
        TransportType::Tcp,
        250,
    );
    assert!(buffer.emit(ev5));

    assert_eq!(buffer.dropped_count(), 2);
    let (events, drops) = buffer.snapshot_events();
    assert_eq!(drops, 2);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].stream_id, "s-3");
    assert_eq!(events[1].stream_id, "s-4");
    assert_eq!(events[2].stream_id, "s-5");
}

#[test]
fn test_emitting_never_blocks_under_contention() {
    let clock = Arc::new(ManualClock::new(0, 0));
    let buffer = DiagnosticBuffer::with_clock(10, clock);

    let (tx_held, rx_held) = mpsc::channel();
    let (tx_continue, rx_continue) = mpsc::channel();

    let buf_bg = buffer.clone();
    let bg_thread = thread::spawn(move || {
        let guard = buf_bg.hold_lock();
        tx_held.send(()).unwrap();
        rx_continue.recv().unwrap();
        drop(guard);
    });

    rx_held.recv().unwrap();

    // Buffer is currently held by background thread
    let ev = DiagnosticEvent::new(
        1,
        2,
        "s",
        DiagnosticStage::Received,
        TransportType::Udp,
        100,
    );
    let accepted = buffer.emit(ev);

    assert!(
        !accepted,
        "emit must return at once with false when buffer is held"
    );
    assert_eq!(buffer.dropped_count(), 1);

    tx_continue.send(()).unwrap();
    bg_thread.join().unwrap();

    assert_eq!(buffer.snapshot().events.len(), 0);
    assert_eq!(buffer.dropped_count(), 1);
}

#[test]
fn test_rate_limiting_across_second_boundary_without_sleeping() {
    let clock = Arc::new(ManualClock::new(0, 0));
    // 3 events per second
    let buffer = DiagnosticBuffer::with_clock_and_rate_limit(10, clock.clone(), 3);

    // Second 0
    let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Udp, 10);
    let ev2 = buffer.create_event("s2", DiagnosticStage::Accepted, TransportType::Udp, 20);
    let ev3 = buffer.create_event(
        "s3",
        DiagnosticStage::RoutedOrQueued,
        TransportType::Udp,
        30,
    );
    let ev4 = buffer.create_event("s4", DiagnosticStage::SendAttempted, TransportType::Udp, 40);

    assert!(buffer.emit(ev1));
    assert!(buffer.emit(ev2));
    assert!(buffer.emit(ev3));
    assert!(
        !buffer.emit(ev4),
        "4th event in second 0 must be rate-limited"
    );
    assert_eq!(buffer.dropped_count(), 1);

    // Advance clock past the 1-second boundary: monotonic = 1_000_000_000 ns
    // No sleeping!
    clock.advance_secs(1);

    let ev5 = buffer.create_event("s5", DiagnosticStage::SendSucceeded, TransportType::Udp, 50);
    let ev6 = buffer.create_event("s6", DiagnosticStage::Received, TransportType::Udp, 60);
    let ev7 = buffer.create_event("s7", DiagnosticStage::Accepted, TransportType::Udp, 70);
    let ev8 = buffer.create_event("s8", DiagnosticStage::SendAttempted, TransportType::Udp, 80);

    assert!(
        buffer.emit(ev5),
        "boundary crossed: 1st event in second 1 accepted"
    );
    assert!(buffer.emit(ev6), "2nd event in second 1 accepted");
    assert!(buffer.emit(ev7), "3rd event in second 1 accepted");
    assert!(!buffer.emit(ev8), "4th event in second 1 rejected");
    assert_eq!(buffer.dropped_count(), 2);

    let snap = buffer.snapshot();
    assert_eq!(snap.events.len(), 6);
    assert_eq!(snap.dropped_count, 2);
}

// ---------------------------------------------------------------------------
// RER-F-027 Integration Tests: Forwarding Path Diagnostic Events
// ---------------------------------------------------------------------------

use rer::config::Config;
use rer::relay::Relay;
use std::net::UdpSocket;
use std::time::Duration;

fn pick_test_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    sock.local_addr().expect("local addr").port()
}

#[test]
fn test_debug_mode_emits_one_event_per_stage_with_metadata() {
    let rx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    rx_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let dest_port = rx_sock.local_addr().expect("port").port();
    let listen_port = pick_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "node-debug"
    mode: "debug"
    streams:
      - id: "s-debug"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    let tx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let payload = vec![0x42u8; 128];
    tx_sock
        .send_to(&payload, format!("127.0.0.1:{listen_port}"))
        .expect("send packet");

    let mut buf = vec![0u8; 256];
    let (n, _) = rx_sock
        .recv_from(&mut buf)
        .expect("receive forwarded packet");
    assert_eq!(n, 128);
    assert_eq!(&buf[..n], &payload[..]);

    // Give forwarder a few milliseconds to settle events
    std::thread::sleep(Duration::from_millis(50));

    let snap = relay.event_buffer().snapshot();
    let stream_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stream_id == "s-debug")
        .collect();

    // Verify all 5 stages emitted exactly once for this packet
    let stages: Vec<DiagnosticStage> = stream_events.iter().map(|e| e.stage).collect();
    assert!(
        stages.contains(&DiagnosticStage::Received),
        "missing received stage"
    );
    assert!(
        stages.contains(&DiagnosticStage::Accepted),
        "missing accepted stage"
    );
    assert!(
        stages.contains(&DiagnosticStage::RoutedOrQueued),
        "missing routed_or_queued stage"
    );
    assert!(
        stages.contains(&DiagnosticStage::SendAttempted),
        "missing send_attempted stage"
    );
    assert!(
        stages.contains(&DiagnosticStage::SendSucceeded),
        "missing send_succeeded stage"
    );

    for ev in &stream_events {
        assert_eq!(ev.stream_id, "s-debug");
        assert_eq!(ev.transport, TransportType::Udp);
        assert_eq!(ev.payload_length, 128);
        assert!(
            ev.source_endpoint.is_some(),
            "source endpoint must be populated"
        );
        assert!(
            ev.destination_endpoint.is_some(),
            "destination endpoint must be populated"
        );
        assert!(ev.monotonic_timestamp > 0);
        assert!(ev.wall_clock_timestamp > 0);
    }

    relay.stop();
}

#[test]
fn test_production_mode_quiet_no_per_packet_events_and_buffer_holds_none() {
    let rx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    rx_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let dest_port = rx_sock.local_addr().expect("port").port();
    let listen_port = pick_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "node-prod"
    mode: "production"
    streams:
      - id: "s-prod"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    assert_eq!(config.all_instances()[0].mode, OperationalMode::Production);
    let relay = Relay::start(&config).expect("start relay");

    let tx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for i in 0..5 {
        let payload = format!("prod-packet-{i}").into_bytes();
        tx_sock
            .send_to(&payload, format!("127.0.0.1:{listen_port}"))
            .expect("send packet");

        let mut buf = vec![0u8; 256];
        let (n, _) = rx_sock.recv_from(&mut buf).expect("receive packet");
        assert_eq!(&buf[..n], &payload[..]);
    }

    std::thread::sleep(Duration::from_millis(50));

    // Assert that in production mode, after traffic has been forwarded,
    // the buffer holds NONE (0 per-packet events, 0 drops, 0 errors).
    assert_eq!(
        relay.event_buffer().len(),
        0,
        "production buffer must hold no per-packet events"
    );
    assert_eq!(
        relay.event_buffer().dropped_count(),
        0,
        "production buffer must have no dropped events"
    );
    assert!(relay.event_buffer().is_empty());

    relay.stop();
}

#[test]
fn test_all_modes_emit_errors_drops_and_health_transitions_with_reason() {
    // 1. Queue drop & oversized drop test in production mode
    let rx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    let dest_port = rx_sock.local_addr().expect("port").port();
    let listen_port = pick_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "node-drops"
    mode: "production"
    streams:
      - id: "s-drops"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_packet_size: 64
          max_queue_size: 2
          drop_policy: "drop_oldest"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    let tx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Oversized packet (> 64 bytes)
    let oversized = vec![0xAAu8; 128];
    tx_sock
        .send_to(&oversized, format!("127.0.0.1:{listen_port}"))
        .expect("send oversized");

    std::thread::sleep(Duration::from_millis(50));

    // Health transition test
    let transitioned = relay.emit_health_transition(
        "s-drops",
        false,
        "heartbeat check failed: destination degraded",
    );
    assert!(transitioned);

    std::thread::sleep(Duration::from_millis(50));

    let snap = relay.event_buffer().snapshot();

    // Check dropped event
    let drop_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Dropped)
        .collect();
    assert!(
        !drop_events.is_empty(),
        "expected queue/oversized drop event"
    );
    assert!(
        drop_events[0].reason.is_some(),
        "drop event must have a reason"
    );
    assert!(
        drop_events[0]
            .reason
            .as_ref()
            .unwrap()
            .contains("oversized"),
        "reason must describe oversized datagram"
    );

    // Check health transition event
    let health_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::HealthTransition)
        .collect();
    assert!(
        !health_events.is_empty(),
        "expected health transition event"
    );
    assert!(
        health_events[0].reason.is_some(),
        "health transition event must have a reason"
    );
    assert!(
        health_events[0]
            .reason
            .as_ref()
            .unwrap()
            .contains("destination degraded"),
        "reason must describe health transition"
    );

    relay.stop();
}

#[test]
fn test_destination_and_socket_errors_emit_events_with_reason() {
    let listen_port = pick_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "node-err"
    mode: "production"
    streams:
      - id: "s-err"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "255.255.255.255:9999"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    let tx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    tx_sock
        .send_to(b"test-err-packet", format!("127.0.0.1:{listen_port}"))
        .expect("send packet");

    std::thread::sleep(Duration::from_millis(100));

    let snap = relay.event_buffer().snapshot();
    let failure_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Failure)
        .collect();

    // 255.255.255.255 without broadcast permission causes UDP destination error
    assert!(
        !failure_events.is_empty(),
        "expected destination failure event"
    );
    for ev in failure_events {
        assert!(ev.reason.is_some(), "failure event must contain reason");
    }

    relay.stop();
}

#[test]
fn test_no_event_or_log_contains_payload_bytes() {
    let rx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    rx_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let dest_port = rx_sock.local_addr().expect("port").port();
    let listen_port = pick_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "node-payload"
    mode: "debug"
    streams:
      - id: "s-payload"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    let distinctive_str = "DISTINCTIVE_SECRET_PAYLOAD_TOKEN_7749204";
    let distinctive_bytes = distinctive_str.as_bytes();

    let tx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    tx_sock
        .send_to(distinctive_bytes, format!("127.0.0.1:{listen_port}"))
        .expect("send distinctive payload");

    let mut buf = vec![0u8; 256];
    let (n, _) = rx_sock.recv_from(&mut buf).expect("receive payload");
    assert_eq!(&buf[..n], distinctive_bytes);

    std::thread::sleep(Duration::from_millis(50));

    // Retrieve snapshot and serialize all events to JSON
    let snap = relay.event_buffer().snapshot();
    assert!(
        !snap.events.is_empty(),
        "events should be emitted in debug mode"
    );

    let serialized = serde_json::to_string(&snap.events).expect("serialize events");

    // The serialized JSON must NEVER contain payload bytes or distinctive strings!
    assert!(
        !serialized.contains(distinctive_str),
        "serialized events must never contain payload content"
    );
    assert!(
        !serialized.contains("DISTINCTIVE_SECRET"),
        "serialized events must never contain distinctive substring"
    );

    // Verify each event contains only the payload length
    for ev in &snap.events {
        assert_eq!(
            ev.payload_length,
            distinctive_bytes.len() as u64,
            "event records metadata length only"
        );
    }

    relay.stop();
}

#[test]
fn test_diagnostics_never_block_forwarding_flood_through_capacity_8_buffer() {
    let rx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    rx_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let dest_port = rx_sock.local_addr().expect("port").port();
    let listen_port = pick_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "node-flood"
    mode: "debug"
    streams:
      - id: "s-flood"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");

    // Buffer capacity explicitly constrained to 8 events
    let small_buffer = DiagnosticBuffer::new(8);
    assert_eq!(small_buffer.capacity(), 8);

    let relay = Relay::start_with_buffer(&config, small_buffer.clone()).expect("start relay");

    let tx_sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let packet_count = 50;

    // Send a flood of packets
    for i in 0..packet_count {
        let payload = format!("flood-pkt-{i}").into_bytes();
        tx_sock
            .send_to(&payload, format!("127.0.0.1:{listen_port}"))
            .expect("send packet");
    }

    // Verify destination delivers every packet without stalling
    let mut received_count = 0;
    let mut buf = vec![0u8; 256];
    for _ in 0..packet_count {
        match rx_sock.recv_from(&mut buf) {
            Ok(_) => received_count += 1,
            Err(_) => break,
        }
    }

    assert_eq!(
        received_count, packet_count,
        "relay must deliver every single packet despite tiny diagnostic buffer"
    );

    std::thread::sleep(Duration::from_millis(50));

    // Verify buffer capacity remained bounded at 8 and dropped events were counted
    assert_eq!(small_buffer.len(), 8);
    assert!(
        small_buffer.dropped_count() > 0,
        "small buffer must report dropped-event count above zero, got {}",
        small_buffer.dropped_count()
    );

    relay.stop();
}

#[test]
fn test_debug_mode_tcp_emits_one_event_per_stage() {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};

    let rx_listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let dest_port = rx_listener.local_addr().expect("port").port();
    let listen_port = pick_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "node-tcp-debug"
    mode: "debug"
    streams:
      - id: "s-tcp-debug"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          mode: "listen"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    // Accept incoming destination connection from relay
    let (mut rx_conn, _) = rx_listener.accept().expect("accept conn from relay");
    rx_conn
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");

    // Client connects to relay source
    let mut tx_stream =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay");

    // Send framed packet
    let payload = b"tcp-debug-test-payload";
    let frame = rer::framing::encode_frame(payload);
    tx_stream.write_all(&frame).expect("send frame");
    tx_stream.flush().expect("flush");

    // Read frame at receiver
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let received = rer::framing::read_frame(&mut rx_conn, 65535, &shutdown)
        .expect("read frame")
        .expect("payload");
    assert_eq!(received, payload);

    std::thread::sleep(Duration::from_millis(50));

    let snap = relay.event_buffer().snapshot();
    let stream_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stream_id == "s-tcp-debug")
        .collect();

    let stages: Vec<DiagnosticStage> = stream_events.iter().map(|e| e.stage).collect();
    assert!(stages.contains(&DiagnosticStage::Received));
    assert!(stages.contains(&DiagnosticStage::Accepted));
    assert!(stages.contains(&DiagnosticStage::RoutedOrQueued));
    assert!(stages.contains(&DiagnosticStage::SendAttempted));
    assert!(stages.contains(&DiagnosticStage::SendSucceeded));

    let packet_events: Vec<&&DiagnosticEvent> = stream_events
        .iter()
        .filter(|e| e.stage != DiagnosticStage::Failure)
        .collect();
    assert_eq!(packet_events.len(), 5);

    for ev in &packet_events {
        assert_eq!(ev.stream_id, "s-tcp-debug");
        assert_eq!(ev.transport, TransportType::Tcp);
        assert_eq!(ev.payload_length, payload.len() as u64);
        assert!(ev.source_endpoint.is_some());
        assert!(ev.destination_endpoint.is_some());
    }

    relay.stop();
}

#[test]
fn test_test_mode_carries_correlation_id_on_every_event() {
    let src_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let src_port = src_sock.local_addr().unwrap().port();
    drop(src_sock);

    let dst_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let dst_port = dst_sock.local_addr().unwrap().port();

    let yaml = format!(
        r#"
version: "1"
instance:
  id: "inst-test-mode"
  mode: "test"
  test_mode:
    correlation_id: "corr-run-xyz-42"
    duration_seconds: 120
    max_events: 1000
    prior_mode: "production"
  streams:
    - id: "s-test-corr"
      source:
        transport: "udp"
        address: "127.0.0.1:{src_port}"
      destination:
        transport: "udp"
        address: "127.0.0.1:{dst_port}"
"#
    );

    let config = rer::config::Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    let buffer = DiagnosticBuffer::new(1024);
    let relay = rer::relay::Relay::start_with_buffer(&config, buffer).expect("start relay");

    assert_eq!(relay.current_mode(), OperationalMode::Test);
    assert_eq!(relay.correlation_id().as_deref(), Some("corr-run-xyz-42"));

    // Send packet from client
    let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("client bind");
    let payload = b"test-correlation-datagram-payload";
    client
        .send_to(payload, format!("127.0.0.1:{src_port}"))
        .expect("send");

    let mut buf = [0u8; 128];
    dst_sock
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("timeout");
    let (n, _) = dst_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], payload);

    std::thread::sleep(std::time::Duration::from_millis(50));

    let snap = relay.event_buffer().snapshot();
    let stream_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stream_id == "s-test-corr")
        .collect();

    assert!(
        !stream_events.is_empty(),
        "Diagnostic events should be emitted in test mode"
    );

    // Verify every single event in the run carries the correlation ID
    for ev in &stream_events {
        assert_eq!(
            ev.correlation_id.as_deref(),
            Some("corr-run-xyz-42"),
            "Every event in test mode run must carry configured correlation ID"
        );
    }

    // Trigger health transition and verify it carries the correlation ID too
    relay.emit_health_transition("s-test-corr", false, "injected test failure");
    let snap2 = relay.event_buffer().snapshot();
    let health_events: Vec<&DiagnosticEvent> = snap2
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::HealthTransition)
        .collect();
    assert!(!health_events.is_empty());
    assert_eq!(
        health_events.last().unwrap().correlation_id.as_deref(),
        Some("corr-run-xyz-42")
    );

    relay.stop();
}

#[test]
fn test_test_mode_reverts_to_prior_level_on_expiry_with_injected_clock_no_sleeping() {
    let src_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let src_port = src_sock.local_addr().unwrap().port();
    drop(src_sock);

    let dst_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let dst_port = dst_sock.local_addr().unwrap().port();

    let yaml = format!(
        r#"
version: "1"
instance:
  id: "inst-test-expire"
  mode: "test"
  test_mode:
    correlation_id: "corr-expire-run"
    duration_seconds: 60
    prior_mode: "production"
  streams:
    - id: "s-expire"
      source:
        transport: "udp"
        address: "127.0.0.1:{src_port}"
      destination:
        transport: "udp"
        address: "127.0.0.1:{dst_port}"
"#
    );

    let config = rer::config::Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    // Injected manual clock starting at t=1,000,000 ns
    let clock = Arc::new(ManualClock::new(1_000_000, 1_000_000));
    let buffer = DiagnosticBuffer::with_clock(1024, clock.clone());
    let relay = rer::relay::Relay::start_with_buffer(&config, buffer).expect("start relay");

    // Initially in test mode
    assert_eq!(relay.current_mode(), OperationalMode::Test);
    assert_eq!(relay.current_expiry(), Some(60));
    assert_eq!(relay.correlation_id().as_deref(), Some("corr-expire-run"));

    let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    dst_sock
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("timeout");

    // Forward packet 1 during active test run
    client
        .send_to(b"packet-1", format!("127.0.0.1:{src_port}"))
        .expect("send");
    let mut buf = [0u8; 128];
    let (n1, _) = dst_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n1], b"packet-1");

    std::thread::sleep(std::time::Duration::from_millis(40));

    let snap1 = relay.event_buffer().snapshot();
    let packet1_events: Vec<&DiagnosticEvent> = snap1
        .events
        .iter()
        .filter(|e| e.stream_id == "s-expire")
        .collect();
    assert!(
        !packet1_events.is_empty(),
        "Events should be recorded during active test run"
    );
    for ev in &packet1_events {
        assert_eq!(ev.correlation_id.as_deref(), Some("corr-expire-run"));
    }

    // Now advance clock past expiry by 61 seconds WITHOUT sleeping
    clock.advance_secs(61);

    // Verify instance returns to prior diagnostic level (production mode)
    assert_eq!(
        relay.current_mode(),
        OperationalMode::Production,
        "Instance must return to prior diagnostic level (production) upon expiry"
    );
    assert_eq!(
        relay.current_expiry(),
        None,
        "Expiry must be None once test run has completed"
    );

    // Forward packet 2 after expiry with a different payload length
    client
        .send_to(b"packet-after-expiry", format!("127.0.0.1:{src_port}"))
        .expect("send");
    let (n2, _) = dst_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n2], b"packet-after-expiry");

    std::thread::sleep(std::time::Duration::from_millis(40));

    // Verify that NO per-packet events were recorded for packet 2 (quiet production mode)
    let snap2 = relay.event_buffer().snapshot();
    let packet2_events: Vec<&DiagnosticEvent> = snap2
        .events
        .iter()
        .filter(|e| {
            e.stream_id == "s-expire" && e.payload_length == b"packet-after-expiry".len() as u64
        })
        .collect();
    assert_eq!(
        packet2_events.len(),
        0,
        "Production mode must not emit per-packet events after test expiry"
    );

    // Verify end event was recorded explaining duration bound reached
    let end_events: Vec<&DiagnosticEvent> = snap2
        .events
        .iter()
        .filter(|e| {
            e.reason
                .as_deref()
                .is_some_and(|r| r.contains("duration bound"))
        })
        .collect();
    assert!(
        !end_events.is_empty(),
        "Relay must record an event when reaching duration bound"
    );

    relay.stop();
}

#[test]
fn test_test_mode_run_bounded_in_events_and_duration_records_why() {
    let src_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let src_port = src_sock.local_addr().unwrap().port();
    drop(src_sock);

    let dst_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let dst_port = dst_sock.local_addr().unwrap().port();

    let yaml = format!(
        r#"
version: "1"
instance:
  id: "inst-event-bound"
  mode: "test"
  test_mode:
    correlation_id: "corr-event-bound"
    max_events: 5
    duration_seconds: 300
    prior_mode: "production"
  streams:
    - id: "s-bounded"
      source:
        transport: "udp"
        address: "127.0.0.1:{src_port}"
      destination:
        transport: "udp"
        address: "127.0.0.1:{dst_port}"
"#
    );

    let config = rer::config::Config::from_yaml_str(&yaml).expect("parse config");
    let clock = Arc::new(ManualClock::new(0, 0));
    let buffer = DiagnosticBuffer::with_clock(1024, clock.clone());
    let relay = rer::relay::Relay::start_with_buffer(&config, buffer).expect("start relay");

    assert_eq!(relay.current_mode(), OperationalMode::Test);

    // Forward packet (1 packet generates 5 lifecycle events: Received, Accepted, Routed, Attempted, Succeeded)
    let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    dst_sock
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("timeout");
    client
        .send_to(b"reach-bound", format!("127.0.0.1:{src_port}"))
        .expect("send");
    let mut buf = [0u8; 128];
    let (n, _) = dst_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"reach-bound");

    std::thread::sleep(std::time::Duration::from_millis(50));

    // After 5 events, event bound of 5 should have been reached and ended the run
    assert_eq!(
        relay.current_mode(),
        OperationalMode::Production,
        "Run must revert to prior mode when reaching event bound"
    );

    let reason = relay.test_end_reason();
    assert!(reason.is_some(), "Run must record reason why it ended");
    assert!(
        reason.unwrap().contains("event bound"),
        "Recorded reason must describe event bound"
    );

    relay.stop();
}
