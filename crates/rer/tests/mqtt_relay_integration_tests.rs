//! Integration tests for MQTT relay forwarding, inspection, and error handling (SPEC §5, §8, §14, Task RER-F-059).

use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use rer::config::Config;
use rer::diagnostics::{DiagnosticEvent, DiagnosticStage};
use rer::framing::read_mqtt_frame;
use rer::mqtt::{
    encode_variable_byte_integer, MQTT_TYPE_CONNECT, MQTT_TYPE_DISCONNECT, MQTT_TYPE_PINGREQ,
    MQTT_TYPE_PUBLISH, MQTT_TYPE_SUBSCRIBE,
};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn build_mqtt_packet(packet_type: u8, flags: u8, payload_data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.push((packet_type << 4) | (flags & 0x0F));
    let mut varint = [0u8; 4];
    let n = encode_variable_byte_integer(payload_data.len(), &mut varint).unwrap();
    pkt.extend_from_slice(&varint[..n]);
    pkt.extend_from_slice(payload_data);
    pkt
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 1:
// In crates/rer/src/relay.rs, forwarding a valid MQTT packet on a stream with
// MQTT inspection enabled transmits the payload unmodified to destination endpoints
// while recording packet type and QoS in diagnostic events.
// ---------------------------------------------------------------------------

#[test]
fn test_mqtt_forwarding_valid_packet_preserves_payload_and_records_type_and_qos() {
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
      - id: "s-mqtt-fwd"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // 1. PUBLISH packet with QoS 1
    let mut pub_payload = Vec::new();
    pub_payload.extend_from_slice(&[0x00, 0x06]); // topic len 6
    pub_payload.extend_from_slice(b"sensor"); // topic
    pub_payload.extend_from_slice(&[0x00, 0x07]); // packet id 7
    pub_payload.extend_from_slice(b"payload-qos1");
    let pkt_qos1 = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0b0010, &pub_payload);

    sender.send_to(&pkt_qos1, &target).expect("send pkt1");

    let mut buf = vec![0u8; 1024];
    let (n1, _) = dest_sock.recv_from(&mut buf).expect("recv pkt1");
    assert_eq!(
        &buf[..n1],
        pkt_qos1.as_slice(),
        "QoS 1 payload must be transmitted unmodified"
    );

    // 2. PUBLISH packet with QoS 0
    let mut pub_payload_qos0 = Vec::new();
    pub_payload_qos0.extend_from_slice(&[0x00, 0x06]);
    pub_payload_qos0.extend_from_slice(b"sensor");
    pub_payload_qos0.extend_from_slice(b"payload-qos0");
    let pkt_qos0 = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0b0000, &pub_payload_qos0);

    sender.send_to(&pkt_qos0, &target).expect("send pkt2");

    let (n2, _) = dest_sock.recv_from(&mut buf).expect("recv pkt2");
    assert_eq!(
        &buf[..n2],
        pkt_qos0.as_slice(),
        "QoS 0 payload must be transmitted unmodified"
    );

    // 3. PINGREQ packet
    let pkt_ping = build_mqtt_packet(MQTT_TYPE_PINGREQ, 0b0000, &[]);
    sender.send_to(&pkt_ping, &target).expect("send pkt3");

    let (n3, _) = dest_sock.recv_from(&mut buf).expect("recv pkt3");
    assert_eq!(
        &buf[..n3],
        pkt_ping.as_slice(),
        "PINGREQ payload must be transmitted unmodified"
    );

    let stats = relay.stream_stats("s-mqtt-fwd").expect("stats");
    assert_eq!(stats.received_packets, 3);
    assert_eq!(stats.forwarded_packets, 3);
    assert_eq!(stats.dropped_packets, 0);

    // Verify diagnostic events
    let snap = relay.event_buffer().snapshot();
    let insp_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::MqttInspection)
        .collect();

    assert_eq!(insp_events.len(), 3);

    // First event (PUBLISH QoS 1)
    let ev1 = insp_events[0];
    assert_eq!(ev1.mqtt_packet_type, Some(3));
    assert_eq!(ev1.mqtt_type_name.as_deref(), Some("PUBLISH"));
    assert_eq!(ev1.mqtt_qos, Some(1));
    assert_eq!(ev1.mqtt_packet_id, Some(7));
    assert!(ev1.mqtt_metadata.is_some());

    // Second event (PUBLISH QoS 0)
    let ev2 = insp_events[1];
    assert_eq!(ev2.mqtt_packet_type, Some(3));
    assert_eq!(ev2.mqtt_type_name.as_deref(), Some("PUBLISH"));
    assert_eq!(ev2.mqtt_qos, Some(0));

    // Third event (PINGREQ)
    let ev3 = insp_events[2];
    assert_eq!(ev3.mqtt_packet_type, Some(12));
    assert_eq!(ev3.mqtt_type_name.as_deref(), Some("PINGREQ"));

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2:
// In crates/rer/src/relay.rs, receiving a malformed MQTT packet with invalid header flags
// on a stream with MQTT inspection enabled drops the packet by default, increments dropped
// packet counters, and emits a dropped diagnostic event.
// ---------------------------------------------------------------------------

#[test]
fn test_mqtt_malformed_header_flags_dropped_by_default() {
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
      - id: "s-mqtt-drop-test"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
          passthrough_on_error: false
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // 1. PINGREQ (type 12) with non-zero flags (flags = 0001, must be 0000)
    let invalid_ping = build_mqtt_packet(MQTT_TYPE_PINGREQ, 0b0001, &[]);
    sender.send_to(&invalid_ping, &target).expect("send");

    // 2. DISCONNECT (type 14) with non-zero flags (flags = 0010, must be 0000)
    let invalid_disc = build_mqtt_packet(MQTT_TYPE_DISCONNECT, 0b0010, &[]);
    sender.send_to(&invalid_disc, &target).expect("send");

    // 3. PUBLISH (type 3) with reserved QoS 3 (flags = 0b0110)
    let invalid_pub_qos3 = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0b0110, b"\x00\x04testpayload");
    sender.send_to(&invalid_pub_qos3, &target).expect("send");

    // 4. SUBSCRIBE (type 8) with invalid flags (flags = 0b0000, must be 0b0010)
    let invalid_sub = build_mqtt_packet(MQTT_TYPE_SUBSCRIBE, 0b0000, b"\x00\x01\x00\x04test\x00");
    sender.send_to(&invalid_sub, &target).expect("send");

    // 5. Valid PINGREQ (must be forwarded)
    let valid_ping = build_mqtt_packet(MQTT_TYPE_PINGREQ, 0b0000, &[]);
    sender.send_to(&valid_ping, &target).expect("send");

    let mut buf = vec![0u8; 1024];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv valid");
    assert_eq!(
        &buf[..n],
        valid_ping.as_slice(),
        "only valid packet should be received"
    );

    // No other packets received
    let res = dest_sock.recv_from(&mut buf);
    assert!(
        res.is_err(),
        "all 4 malformed packets must have been dropped"
    );

    let stats = relay.stream_stats("s-mqtt-drop-test").expect("stats");
    assert_eq!(stats.received_packets, 5);
    assert_eq!(stats.forwarded_packets, 1);
    assert_eq!(stats.dropped_packets, 4);
    assert_eq!(stats.drops_validation, 4);
    assert_eq!(stats.validation_errors, 4);

    let snap = relay.event_buffer().snapshot();
    let drop_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Dropped)
        .collect();

    assert_eq!(drop_events.len(), 4);
    for ev in drop_events {
        assert!(ev.reason.is_some(), "dropped event must include reason");
        assert!(
            ev.reason
                .as_ref()
                .unwrap()
                .contains("invalid MQTT header flags"),
            "drop reason must explain header flags violation"
        );
    }

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3:
// In crates/rer/src/relay.rs, receiving a malformed MQTT packet on an inspected
// stream configured with option passthrough_on_error forwards the payload
// unmodified to destination endpoints while recording a validation failure event.
// ---------------------------------------------------------------------------

#[test]
fn test_mqtt_malformed_passthrough_on_error_forwards_unmodified_and_records_failure() {
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
      - id: "s-mqtt-pt-test"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
          passthrough_on_error: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    // Malformed packet with invalid flags (CONNECT type 1 with non-zero flags 0x05)
    let malformed_connect = build_mqtt_packet(MQTT_TYPE_CONNECT, 0b0101, b"malformed");
    sender.send_to(&malformed_connect, &target).expect("send");

    let mut buf = vec![0u8; 1024];
    let (n, _) = dest_sock
        .recv_from(&mut buf)
        .expect("recv passthrough packet");
    assert_eq!(
        &buf[..n],
        malformed_connect.as_slice(),
        "passthrough_on_error must forward payload byte-identically and unmodified"
    );

    let stats = relay.stream_stats("s-mqtt-pt-test").expect("stats");
    assert_eq!(stats.received_packets, 1);
    assert_eq!(stats.forwarded_packets, 1);
    assert_eq!(stats.dropped_packets, 0);
    assert_eq!(stats.validation_errors, 1);

    let snap = relay.event_buffer().snapshot();
    let failure_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::Failure)
        .collect();

    assert_eq!(failure_events.len(), 1);
    assert!(failure_events[0].reason.is_some());
    assert!(failure_events[0]
        .reason
        .as_ref()
        .unwrap()
        .contains("MQTT validation failed (passthrough)"));

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4:
// In crates/rer/src/relay.rs, forwarding traffic on a stream without MQTT
// inspection enabled delivers packets byte-identically without invoking MQTT
// parsing overhead.
// ---------------------------------------------------------------------------

#[test]
fn test_mqtt_unconfigured_stream_byte_identical_delivery_without_parsing() {
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
      - id: "s-unconfigured-test"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.instances[0].streams[0].mqtt.is_none());

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Send payload that would fail MQTT validation if parsed (forbidden packet type 0)
    let non_mqtt_data = vec![0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE];
    sender
        .send_to(&non_mqtt_data, format!("127.0.0.1:{listen_port}"))
        .expect("send");

    let mut buf = vec![0u8; 1024];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(
        &buf[..n],
        non_mqtt_data.as_slice(),
        "unconfigured stream must deliver packets byte-identically"
    );

    let stats = relay.stream_stats("s-unconfigured-test").expect("stats");
    assert_eq!(stats.received_packets, 1);
    assert_eq!(stats.forwarded_packets, 1);
    assert_eq!(stats.dropped_packets, 0);
    assert_eq!(stats.validation_errors, 0);

    let snap = relay.event_buffer().snapshot();
    let mqtt_events: Vec<&DiagnosticEvent> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::MqttInspection || e.mqtt_packet_type.is_some())
        .collect();

    assert!(
        mqtt_events.is_empty(),
        "unconfigured stream must not emit MQTT diagnostic events or invoke MQTT parsing"
    );

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 5:
// In crates/rer/src/relay.rs, forwarding an inspected MQTT packet records
// successful local transmission with DiagnosticStage::SendSucceeded without
// claiming downstream broker receipt.
// ---------------------------------------------------------------------------

#[test]
fn test_mqtt_local_transmission_records_send_succeeded_not_downstream_broker_receipt() {
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
      - id: "s-mqtt-sendsucceeded"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let target = format!("127.0.0.1:{listen_port}");

    let mut pub_payload = Vec::new();
    pub_payload.extend_from_slice(&[0x00, 0x04]);
    pub_payload.extend_from_slice(b"data");
    pub_payload.extend_from_slice(&[0x00, 0x64]); // packet id 100
    pub_payload.extend_from_slice(b"diagnostic truthfulness");
    let pkt = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0b0010, &pub_payload);

    sender.send_to(&pkt, &target).expect("send");

    let mut buf = vec![0u8; 1024];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], pkt.as_slice());

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut stats = relay.stream_stats("s-mqtt-sendsucceeded").expect("stats");
    while stats.forwarded_packets < 1 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
        stats = relay.stream_stats("s-mqtt-sendsucceeded").expect("stats");
    }
    assert_eq!(stats.forwarded_packets, 1);

    let mut send_succeeded_ev = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let snap = relay.event_buffer().snapshot();
        if let Some(ev) = snap
            .events
            .iter()
            .find(|e| e.stage == DiagnosticStage::SendSucceeded)
            .cloned()
        {
            send_succeeded_ev = Some(ev);
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let send_succeeded_ev = send_succeeded_ev.expect(
        "must record DiagnosticStage::SendSucceeded event on successful local transmission",
    );

    // SPEC §8 diagnostic truthfulness: local transmission must be reported as SendSucceeded,
    // never as proof of downstream broker receipt or application acknowledgment
    assert_eq!(send_succeeded_ev.stage, DiagnosticStage::SendSucceeded);
    assert_eq!(send_succeeded_ev.stage.to_string(), "send_succeeded");
    assert_ne!(send_succeeded_ev.stage.to_string(), "delivered");
    assert_ne!(send_succeeded_ev.stage.to_string(), "broker_receipt");
    assert_ne!(send_succeeded_ev.stage.to_string(), "broker_accepted");

    // Verify MQTT metadata is captured
    assert_eq!(send_succeeded_ev.mqtt_packet_type, Some(3));
    assert_eq!(send_succeeded_ev.mqtt_type_name.as_deref(), Some("PUBLISH"));
    assert_eq!(send_succeeded_ev.mqtt_qos, Some(1));

    relay.stop();
}

// ---------------------------------------------------------------------------
// TCP to TCP MQTT stream forwarding integration test
// ---------------------------------------------------------------------------

#[test]
fn test_tcp_to_tcp_mqtt_stream_forwarding_integration() {
    let dest_listener = TcpListener::bind("127.0.0.1:0").expect("bind dest listener");
    let dest_port = dest_listener.local_addr().expect("dest port").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-tcp-mqtt"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          mode: "listen"
          framing: "mqtt"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
          mode: "connect"
          framing: "mqtt"
        mqtt:
          enabled: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    // Accept destination connection from relay
    let (mut dest_conn, _) = dest_listener.accept().expect("dest accept");
    dest_conn
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");

    // Connect client to relay source
    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("client connect");

    // Send valid MQTT packet over TCP
    let mut pub_payload = Vec::new();
    pub_payload.extend_from_slice(&[0x00, 0x05]);
    pub_payload.extend_from_slice(b"topic");
    pub_payload.extend_from_slice(&[0x00, 0x14]); // packet id 20
    pub_payload.extend_from_slice(b"tcp stream data");
    let pkt = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0b0010, &pub_payload);

    client.write_all(&pkt).expect("client send");
    client.flush().expect("flush");

    // Read frame from dest
    let shutdown = Arc::new(AtomicBool::new(false));
    let frame = read_mqtt_frame(&mut dest_conn, 1024, &shutdown)
        .expect("read mqtt frame")
        .expect("frame must be some");

    assert_eq!(
        frame, pkt,
        "TCP to TCP forwarding must preserve MQTT packet payload"
    );

    let snap = relay.event_buffer().snapshot();
    let insp_ev = snap
        .events
        .iter()
        .find(|e| e.stage == DiagnosticStage::MqttInspection)
        .expect("must emit MqttInspection event on TCP stream");

    assert_eq!(insp_ev.mqtt_packet_type, Some(3));
    assert_eq!(insp_ev.mqtt_qos, Some(1));
    assert_eq!(insp_ev.mqtt_packet_id, Some(20));

    relay.stop();
}
