//! Integration tests for native MAVLink TCP framing support (SPEC §14, §5, §8, Task RER-F-052).

use std::io::{Cursor, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use rer::config::{Config, FramingMode};
use rer::framing::{
    read_frame_with_mode, read_mavlink_frame, write_frame_with_mode, write_mavlink_frame,
};
use rer::mavlink::{
    MAVLINK_IFLAG_SIGNED, MAVLINK_STX_V1, MAVLINK_STX_V2, MAVLINK_V2_OVERHEAD_SIGNED,
    MAVLINK_V2_OVERHEAD_UNSIGNED,
};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn build_mavlink1_packet(seq: u8, sysid: u8, compid: u8, msgid: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(6 + payload.len() + 2);
    pkt.push(MAVLINK_STX_V1); // 0xFE
    pkt.push(payload.len() as u8);
    pkt.push(seq);
    pkt.push(sysid);
    pkt.push(compid);
    pkt.push(msgid);
    pkt.extend_from_slice(payload);
    // 2 CRC bytes
    pkt.push(0x55);
    pkt.push(0xAA);
    pkt
}

fn build_mavlink2_packet(
    seq: u8,
    sysid: u8,
    compid: u8,
    msgid: u32,
    is_signed: bool,
    payload: &[u8],
) -> Vec<u8> {
    let incompat = if is_signed { MAVLINK_IFLAG_SIGNED } else { 0 };
    let overhead = if is_signed {
        MAVLINK_V2_OVERHEAD_SIGNED
    } else {
        MAVLINK_V2_OVERHEAD_UNSIGNED
    };
    let mut pkt = Vec::with_capacity(overhead + payload.len());
    pkt.push(MAVLINK_STX_V2); // 0xFD
    pkt.push(payload.len() as u8);
    pkt.push(incompat);
    pkt.push(0x00); // compat_flags
    pkt.push(seq);
    pkt.push(sysid);
    pkt.push(compid);
    pkt.push((msgid & 0xFF) as u8);
    pkt.push(((msgid >> 8) & 0xFF) as u8);
    pkt.push(((msgid >> 16) & 0xFF) as u8);
    pkt.extend_from_slice(payload);
    // 2 CRC bytes
    pkt.push(0x12);
    pkt.push(0x34);
    if is_signed {
        // 13 signature bytes
        pkt.extend_from_slice(&[0x77; 13]);
    }
    pkt
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 1:
// In crates/rer/src/framing.rs, reading from a TCP stream delivering a MAVLink 1
// or MAVLink 2 frame fragmented across multiple 1-byte reads reassembles the
// complete frame matching the original transmitted bytes.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion1_tcp_stream_mavlink_framing_reassembles_fragmented_reads() {
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
  - id: "relay-mavlink-fragmented"
    streams:
      - id: "s-mavlink-frag"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "mavlink"
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

    // 1. MAVLink 1 packet sent 1 byte at a time
    let v1_pkt = build_mavlink1_packet(1, 10, 1, 30, b"mavlink 1 fragmented bytes");
    for &b in &v1_pkt {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let mut buf = vec![0u8; 1024];
    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled mavlink 1 packet");
    assert_eq!(&buf[..n], v1_pkt.as_slice());

    // 2. MAVLink 2 unsigned packet sent 1 byte at a time
    let v2_pkt = build_mavlink2_packet(2, 10, 1, 147, false, b"mavlink 2 unsigned fragmented");
    for &b in &v2_pkt {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled mavlink 2 packet");
    assert_eq!(&buf[..n], v2_pkt.as_slice());

    // 3. MAVLink 2 signed packet sent 1 byte at a time
    let v2_signed = build_mavlink2_packet(3, 10, 1, 200, true, b"mavlink 2 signed with sig block");
    for &b in &v2_signed {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled signed packet");
    assert_eq!(&buf[..n], v2_signed.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2:
// In crates/rer/src/framing.rs, reading from a TCP stream delivering two
// concatenated MAVLink frames in a single read buffer yields the two frames
// individually at their calculated frame length boundaries.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion2_concatenated_mavlink_frames_in_single_read_buffer() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-mavlink-concat"
    streams:
      - id: "s-mavlink-concat"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "mavlink"
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

    let p1 = build_mavlink1_packet(1, 1, 1, 10, b"first frame v1");
    let p2 = build_mavlink2_packet(
        2,
        2,
        2,
        20,
        false,
        b"second frame v2 concatenated in buffer",
    );

    // Concatenate two frames in a single write call
    let mut batch = Vec::new();
    batch.extend_from_slice(&p1);
    batch.extend_from_slice(&p2);

    client.write_all(&batch).expect("write concatenated batch");
    client.flush().expect("flush batch");

    let mut buf1 = vec![0u8; 1024];
    let (n1, _) = receiver
        .recv_from(&mut buf1)
        .expect("receive first individual frame");
    assert_eq!(&buf1[..n1], p1.as_slice());

    let mut buf2 = vec![0u8; 1024];
    let (n2, _) = receiver
        .recv_from(&mut buf2)
        .expect("receive second individual frame");
    assert_eq!(&buf2[..n2], p2.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3:
// In crates/rer/src/framing.rs, reading a MAVLink TCP frame declaring a length
// that exceeds the configured maximum frame size returns an invalid data error
// without panicking.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion3_oversized_mavlink_frame_returns_invalid_data_without_panic() {
    let shutdown = AtomicBool::new(false);

    // MAVLink 1 frame declaring payload length 200 -> total length 208
    let v1_pkt = build_mavlink1_packet(1, 1, 1, 1, &[0xAA; 200]);
    let mut cursor_v1 = Cursor::new(v1_pkt);

    // Configured max frame size is 100
    let res = read_mavlink_frame(&mut cursor_v1, 100, &shutdown);
    assert!(res.is_err(), "oversized frame must return error");
    let err = res.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds maximum allowed"));

    // MAVLink 2 frame declaring payload length 200 -> total length 212
    let v2_pkt = build_mavlink2_packet(1, 1, 1, 1, false, &[0xBB; 200]);
    let mut cursor_v2 = Cursor::new(v2_pkt);

    let res_v2 = read_mavlink_frame(&mut cursor_v2, 100, &shutdown);
    assert!(res_v2.is_err(), "oversized frame must return error");
    let err_v2 = res_v2.unwrap_err();
    assert_eq!(err_v2.kind(), std::io::ErrorKind::InvalidData);
    assert!(err_v2.to_string().contains("exceeds maximum allowed"));

    // Also verify via read_frame_with_mode
    let mut cursor_mode = Cursor::new(build_mavlink1_packet(1, 1, 1, 1, &[0xCC; 150]));
    let res_mode = read_frame_with_mode(&mut cursor_mode, FramingMode::Mavlink, 80, &shutdown);
    assert!(res_mode.is_err());
    assert_eq!(
        res_mode.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4:
// In crates/rer/src/framing.rs, writing a MAVLink frame using write_frame_with_mode
// transmits raw packet bytes without prepending a 4-byte length prefix.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion4_write_frame_with_mode_transmits_raw_packet_bytes() {
    let v1_packet = build_mavlink1_packet(42, 1, 1, 76, b"mavlink raw telemetry");
    let mut buf = Vec::new();

    write_frame_with_mode(&mut buf, FramingMode::Mavlink, &v1_packet)
        .expect("write frame with mode mavlink");

    // Exactly matches raw packet bytes without 4-byte length prefix
    assert_eq!(buf, v1_packet);
    assert_eq!(buf.len(), v1_packet.len());
    // Verify that the first 4 bytes are NOT the length prefix
    assert_ne!(&buf[0..4], &(v1_packet.len() as u32).to_be_bytes());
    assert_eq!(buf[0], MAVLINK_STX_V1);

    // MAVLink 2 signed packet
    let v2_packet = build_mavlink2_packet(99, 5, 2, 300, true, b"mavlink 2 signed raw");
    let mut buf_v2 = Vec::new();

    write_frame_with_mode(&mut buf_v2, FramingMode::Mavlink, &v2_packet)
        .expect("write frame with mode mavlink signed");

    assert_eq!(buf_v2, v2_packet);
    assert_eq!(buf_v2.len(), v2_packet.len());
    assert_ne!(&buf_v2[0..4], &(v2_packet.len() as u32).to_be_bytes());
    assert_eq!(buf_v2[0], MAVLINK_STX_V2);

    // Test write_mavlink_frame helper directly
    let mut buf_direct = Vec::new();
    write_mavlink_frame(&mut buf_direct, &v1_packet).expect("write_mavlink_frame");
    assert_eq!(buf_direct, v1_packet);
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 5:
// In crates/rer/src/config.rs, configuring option framing with value mavlink
// deserializes into FramingMode::Mavlink.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion5_config_framing_option_mavlink_deserializes() {
    // 1. Stream-level option framing with value mavlink
    let yaml_stream = r#"
version: "1"
instances:
  - id: "i-mavlink"
    streams:
      - id: "s-mavlink"
        framing: mavlink
        source:
          transport: "tcp"
          address: "127.0.0.1:5000"
        destination:
          transport: "tcp"
          address: "127.0.0.1:5001"
"#;
    let config = Config::from_yaml_str(yaml_stream).expect("parse stream framing: mavlink");
    let stream = &config.instances[0].streams[0];
    assert_eq!(stream.framing, Some(FramingMode::Mavlink));
    assert_eq!(stream.source_framing(), FramingMode::Mavlink);
    assert_eq!(
        stream.destination_framing(stream.destination.as_ref().unwrap()),
        FramingMode::Mavlink
    );

    // 2. Endpoint-level option framing with value mavlink
    let yaml_endpoint = r#"
version: "1"
instances:
  - id: "i-ep-mavlink"
    streams:
      - id: "s-ep-mavlink"
        source:
          transport: "tcp"
          address: "127.0.0.1:5000"
          framing: mavlink
        destination:
          transport: "tcp"
          address: "127.0.0.1:5001"
          framing: mavlink
"#;
    let config_ep = Config::from_yaml_str(yaml_endpoint).expect("parse endpoint framing: mavlink");
    let ep_stream = &config_ep.instances[0].streams[0];
    assert_eq!(ep_stream.source.framing, Some(FramingMode::Mavlink));
    let dest = ep_stream.destination.as_ref().unwrap();
    assert_eq!(dest.framing, Some(FramingMode::Mavlink));
    assert_eq!(ep_stream.source_framing(), FramingMode::Mavlink);
    assert_eq!(ep_stream.destination_framing(dest), FramingMode::Mavlink);

    // 3. Option mavlink block framing override
    let yaml_mavlink_block = r#"
version: "1"
instances:
  - id: "i-block-mavlink"
    streams:
      - id: "s-block-mavlink"
        mavlink:
          framing: mavlink
        source:
          transport: "tcp"
          address: "127.0.0.1:5000"
        destination:
          transport: "tcp"
          address: "127.0.0.1:5001"
"#;
    let config_block =
        Config::from_yaml_str(yaml_mavlink_block).expect("parse mavlink block framing");
    let block_stream = &config_block.instances[0].streams[0];
    assert_eq!(
        block_stream.mavlink.as_ref().and_then(|m| m.framing),
        Some(FramingMode::Mavlink)
    );
    assert_eq!(block_stream.source_framing(), FramingMode::Mavlink);

    // 4. Case-insensitive and alias deserialization
    let json_val = serde_json::json!("mavlink");
    let deserialized: FramingMode = serde_json::from_value(json_val).expect("json deserialize");
    assert_eq!(deserialized, FramingMode::Mavlink);
    assert_eq!(deserialized.to_string(), "mavlink");
}

// ---------------------------------------------------------------------------
// TCP-to-TCP end-to-end MAVLink framing integration test
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_to_tcp_mavlink_framing_end_to_end() {
    let listen_port = pick_unused_port();
    let dest_port = pick_unused_port();

    let dest_listener = std::net::TcpListener::bind(format!("127.0.0.1:{dest_port}"))
        .expect("bind tcp dest listener");
    dest_listener.set_nonblocking(false).expect("set blocking");

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-tcp-to-tcp-mavlink"
    streams:
      - id: "s-tcp-to-tcp-mavlink"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "mavlink"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
          framing: "mavlink"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(50));

    // Accept destination connection from relay
    let (mut dest_conn, _) = dest_listener.accept().expect("accept from relay");
    dest_conn.set_nodelay(true).unwrap();

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    client.set_nodelay(true).unwrap();

    let pkt1 = build_mavlink1_packet(1, 1, 1, 1, b"mavlink1 tcp-to-tcp");
    let pkt2 = build_mavlink2_packet(2, 2, 2, 2, false, b"mavlink2 tcp-to-tcp");

    client.write_all(&pkt1).expect("write pkt1");
    client.write_all(&pkt2).expect("write pkt2");
    client.flush().expect("flush client");

    let shutdown = AtomicBool::new(false);
    let r1 = read_mavlink_frame(&mut dest_conn, 1024, &shutdown)
        .expect("read frame 1")
        .expect("some frame 1");
    assert_eq!(r1, pkt1);

    let r2 = read_mavlink_frame(&mut dest_conn, 1024, &shutdown)
        .expect("read frame 2")
        .expect("some frame 2");
    assert_eq!(r2, pkt2);

    relay.stop();
}
