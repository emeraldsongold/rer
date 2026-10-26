//! Integration tests for opt-in MQTT TCP stream framing support (SPEC §5, §8, §14, Task RER-F-057).

use std::io::{Cursor, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use rer::config::{Config, FramingMode};
use rer::framing::{
    read_frame_with_mode, read_mqtt_frame, write_frame_with_mode, write_mqtt_frame,
};
use rer::mqtt::{
    encode_variable_byte_integer, MQTT_TYPE_CONNECT, MQTT_TYPE_PINGREQ, MQTT_TYPE_PUBLISH,
};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn build_mqtt_packet(packet_type: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(5 + payload.len());
    pkt.push((packet_type << 4) | (flags & 0x0F));
    let mut varint = [0u8; 4];
    let n = encode_variable_byte_integer(payload.len(), &mut varint)
        .expect("encode variable byte integer");
    pkt.extend_from_slice(&varint[..n]);
    pkt.extend_from_slice(payload);
    pkt
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 1:
// In crates/rer/src/framing.rs, reading from a TCP stream delivering an MQTT packet
// fragmented across 1-byte reads reassembles the complete packet matching the transmitted bytes.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion1_tcp_stream_mqtt_framing_reassembles_fragmented_reads() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-mqtt-fragmented"
    streams:
      - id: "s-mqtt-frag"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "mqtt"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    client.set_nodelay(true).unwrap();

    // 1. MQTT PUBLISH packet sent 1 byte at a time
    let pub_pkt = build_mqtt_packet(
        MQTT_TYPE_PUBLISH,
        0,
        b"fragmented mqtt telemetry payload bytes",
    );
    for &b in &pub_pkt {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let mut buf = vec![0u8; 1024];
    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled mqtt publish packet");
    assert_eq!(&buf[..n], pub_pkt.as_slice());

    // 2. 2-byte PINGREQ packet sent 1 byte at a time
    let pingreq_pkt = vec![(MQTT_TYPE_PINGREQ << 4), 0x00];
    for &b in &pingreq_pkt {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled pingreq packet");
    assert_eq!(&buf[..n], pingreq_pkt.as_slice());

    // 3. Multi-byte varint MQTT packet sent 1 byte at a time
    let large_payload = vec![0x7A; 250];
    let large_pkt = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0, &large_payload);
    for &b in &large_pkt {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(1));
    }

    let mut large_buf = vec![0u8; 2048];
    let (n, _) = receiver
        .recv_from(&mut large_buf)
        .expect("receive reassembled multibyte varint packet");
    assert_eq!(&large_buf[..n], large_pkt.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2:
// In crates/rer/src/framing.rs, reading from a TCP stream delivering two
// concatenated MQTT packets in a single read buffer yields the two packets
// individually at their calculated remaining length boundaries.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion2_concatenated_mqtt_packets_in_single_read_buffer() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-mqtt-concat"
    streams:
      - id: "s-mqtt-concat"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "mqtt"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    client.set_nodelay(true).unwrap();

    let p1 = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0, b"first packet payload");
    let p2 = vec![(MQTT_TYPE_PINGREQ << 4), 0x00]; // 2-byte PINGREQ
    let p3 = build_mqtt_packet(MQTT_TYPE_CONNECT, 0, b"third packet payload");

    // Concatenate packets in a single write call
    let mut batch = Vec::new();
    batch.extend_from_slice(&p1);
    batch.extend_from_slice(&p2);
    batch.extend_from_slice(&p3);

    client.write_all(&batch).expect("write concatenated batch");
    client.flush().expect("flush batch");

    let mut buf1 = vec![0u8; 1024];
    let (n1, _) = receiver
        .recv_from(&mut buf1)
        .expect("receive first individual packet");
    assert_eq!(&buf1[..n1], p1.as_slice());

    let mut buf2 = vec![0u8; 1024];
    let (n2, _) = receiver
        .recv_from(&mut buf2)
        .expect("receive second individual packet");
    assert_eq!(&buf2[..n2], p2.as_slice());

    let mut buf3 = vec![0u8; 1024];
    let (n3, _) = receiver
        .recv_from(&mut buf3)
        .expect("receive third individual packet");
    assert_eq!(&buf3[..n3], p3.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3:
// In crates/rer/src/framing.rs, reading an MQTT TCP frame declaring a remaining length
// that exceeds the configured maximum frame size returns an invalid data error
// without allocating the declared frame size.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion3_oversized_mqtt_frame_returns_invalid_data_without_allocating() {
    let shutdown = AtomicBool::new(false);

    // Declared remaining length 200, configured max frame size 100
    let payload = vec![0xCC; 200];
    let pkt = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0, &payload);
    let mut cursor = Cursor::new(pkt);

    let res = read_mqtt_frame(&mut cursor, 100, &shutdown);
    assert!(res.is_err(), "oversized packet must return error");
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds maximum allowed"));
    assert!(err.to_string().contains("remaining length"));

    // Huge remaining length declaration (100 MB) with short buffer
    // Must fail without allocating 100 MB
    let mut huge_header = Vec::new();
    huge_header.push(MQTT_TYPE_PUBLISH << 4);
    let mut varint = [0u8; 4];
    let n = encode_variable_byte_integer(100_000_000, &mut varint).unwrap();
    huge_header.extend_from_slice(&varint[..n]);

    let mut huge_cursor = Cursor::new(huge_header);
    let res_huge = read_mqtt_frame(&mut huge_cursor, 1024, &shutdown);
    assert!(res_huge.is_err());
    let err_huge = res_huge.unwrap_err();
    assert_eq!(err_huge.kind(), std::io::ErrorKind::InvalidData);
    assert!(err_huge.to_string().contains("exceeds maximum allowed"));

    // Also verify via read_frame_with_mode
    let mut cursor_mode = Cursor::new(build_mqtt_packet(MQTT_TYPE_PUBLISH, 0, &[0xDD; 150]));
    let res_mode = read_frame_with_mode(&mut cursor_mode, FramingMode::Mqtt, 80, &shutdown);
    assert!(res_mode.is_err());
    assert_eq!(
        res_mode.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4:
// In crates/rer/src/framing.rs, reading an MQTT frame from a TCP stream with a
// variable byte integer exceeding 4 octets returns an invalid data error and terminates the stream.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion4_mqtt_varint_exceeding_four_octets_returns_invalid_data_and_terminates_stream() {
    let shutdown = AtomicBool::new(false);

    // 5-byte variable byte integer
    let malformed_varint_packet = vec![0x30, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00];
    let mut cursor = Cursor::new(malformed_varint_packet);

    let res = read_mqtt_frame(&mut cursor, 1024, &shutdown);
    assert!(res.is_err(), "varint exceeding 4 octets must return error");
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds 4 octets"));

    // Verify stream termination in Relay
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-mqtt-malformed-varint"
    streams:
      - id: "s-mqtt-malformed"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "mqtt"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    client.set_nodelay(true).unwrap();

    // Send malformed packet with 5-byte varint
    let bad_bytes = vec![0x30, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00];
    client.write_all(&bad_bytes).expect("write bad varint");
    client.flush().expect("flush");

    // The stream must terminate; subsequent writes will either fail or peer has disconnected
    thread::sleep(Duration::from_millis(50));
    // Verify nothing delivered to destination
    let mut buf = [0u8; 128];
    assert!(receiver.recv_from(&mut buf).is_err());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 5:
// In crates/rer/src/framing.rs, writing an MQTT packet using write_frame_with_mode
// transmits raw packet bytes without prepending a 4-byte length prefix.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion5_write_frame_with_mode_transmits_raw_packet_bytes() {
    let publish_pkt = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0, b"mqtt raw telemetry data");
    let mut buf = Vec::new();

    write_frame_with_mode(&mut buf, FramingMode::Mqtt, &publish_pkt)
        .expect("write frame with mode mqtt");

    // Exactly matches raw packet bytes without 4-byte length prefix
    assert_eq!(buf, publish_pkt);
    assert_eq!(buf.len(), publish_pkt.len());
    // Verify first 4 bytes are NOT the length prefix
    assert_ne!(&buf[0..4], &(publish_pkt.len() as u32).to_be_bytes());
    assert_eq!(buf[0], (MQTT_TYPE_PUBLISH << 4));

    // Test PINGREQ packet
    let pingreq_pkt = vec![(MQTT_TYPE_PINGREQ << 4), 0x00];
    let mut buf_ping = Vec::new();
    write_frame_with_mode(&mut buf_ping, FramingMode::Mqtt, &pingreq_pkt)
        .expect("write pingreq frame with mode mqtt");
    assert_eq!(buf_ping, pingreq_pkt);
    assert_eq!(buf_ping.len(), 2);
    assert_ne!(&buf_ping[0..2], &(2u16).to_be_bytes());

    // Test write_mqtt_frame helper directly
    let mut buf_direct = Vec::new();
    write_mqtt_frame(&mut buf_direct, &publish_pkt).expect("write_mqtt_frame");
    assert_eq!(buf_direct, publish_pkt);
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 6:
// In crates/rer/src/config.rs, configuring option framing with value mqtt
// deserializes into FramingMode::Mqtt.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion6_config_framing_option_mqtt_deserializes() {
    // 1. Stream-level option framing with value mqtt
    let yaml_stream = r#"
version: "1"
instances:
  - id: "i-mqtt"
    streams:
      - id: "s-mqtt"
        framing: mqtt
        source:
          transport: "tcp"
          address: "127.0.0.1:5000"
        destination:
          transport: "tcp"
          address: "127.0.0.1:5001"
"#;
    let config = Config::from_yaml_str(yaml_stream).expect("parse stream framing: mqtt");
    let stream = &config.instances[0].streams[0];
    assert_eq!(stream.framing, Some(FramingMode::Mqtt));
    assert_eq!(stream.source_framing(), FramingMode::Mqtt);
    assert_eq!(
        stream.destination_framing(stream.destination.as_ref().unwrap()),
        FramingMode::Mqtt
    );

    // 2. Endpoint-level option framing with value mqtt
    let yaml_endpoint = r#"
version: "1"
instances:
  - id: "i-ep-mqtt"
    streams:
      - id: "s-ep-mqtt"
        source:
          transport: "tcp"
          address: "127.0.0.1:5000"
          framing: mqtt
        destination:
          transport: "tcp"
          address: "127.0.0.1:5001"
          framing: mqtt
"#;
    let config_ep = Config::from_yaml_str(yaml_endpoint).expect("parse endpoint framing: mqtt");
    let ep_stream = &config_ep.instances[0].streams[0];
    assert_eq!(ep_stream.source.framing, Some(FramingMode::Mqtt));
    let dest = ep_stream.destination.as_ref().unwrap();
    assert_eq!(dest.framing, Some(FramingMode::Mqtt));
    assert_eq!(ep_stream.source_framing(), FramingMode::Mqtt);
    assert_eq!(ep_stream.destination_framing(dest), FramingMode::Mqtt);

    // 3. Block-scalar YAML
    let yaml_block = r#"
version: "1"
instances:
  - id: "i-block-mqtt"
    streams:
      - id: "s-block-mqtt"
        framing: "mqtt"
        source:
          transport: "tcp"
          address: "127.0.0.1:5000"
        destination:
          transport: "tcp"
          address: "127.0.0.1:5001"
"#;
    let config_block = Config::from_yaml_str(yaml_block).expect("parse quoted framing: mqtt");
    let block_stream = &config_block.instances[0].streams[0];
    assert_eq!(block_stream.framing, Some(FramingMode::Mqtt));
    assert_eq!(block_stream.source_framing(), FramingMode::Mqtt);

    // 4. JSON deserialization
    let json_val = serde_json::json!("mqtt");
    let deserialized: FramingMode = serde_json::from_value(json_val).expect("json deserialize");
    assert_eq!(deserialized, FramingMode::Mqtt);
    assert_eq!(deserialized.to_string(), "mqtt");
}

// ---------------------------------------------------------------------------
// End-to-end TCP-to-TCP MQTT framing test
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_to_tcp_mqtt_framing_end_to_end() {
    let listen_ingress = pick_unused_port();
    let listen_egress = pick_unused_port();

    // Egress listener (mock backend broker or test receiver)
    let egress_listener =
        std::net::TcpListener::bind(format!("127.0.0.1:{listen_egress}")).expect("bind egress");
    egress_listener
        .set_nonblocking(true)
        .expect("set nonblocking");

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-tcp-to-tcp-mqtt"
    streams:
      - id: "s-mqtt-tcp2tcp"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_ingress}"
          mode: "listen"
          framing: "mqtt"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{listen_egress}"
          mode: "connect"
          framing: "mqtt"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    // Wait for relay to connect to egress
    let mut egress_stream = None;
    for _ in 0..50 {
        match egress_listener.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                egress_stream = Some(s);
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    }
    let mut egress_stream = egress_stream.expect("relay must connect to egress listener");

    // Connect client to ingress
    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_ingress}")).expect("connect to ingress");
    client.set_nodelay(true).unwrap();

    let packet = build_mqtt_packet(MQTT_TYPE_PUBLISH, 0, b"end to end tcp-to-tcp mqtt packet");
    client.write_all(&packet).expect("write packet");
    client.flush().expect("flush");

    // Receive at egress
    let shutdown = AtomicBool::new(false);
    let received = read_mqtt_frame(&mut egress_stream, 1024, &shutdown)
        .expect("read mqtt frame from egress")
        .expect("payload");

    assert_eq!(received, packet);

    relay.stop();
}
