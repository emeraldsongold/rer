//! Integration tests for KISS TCP stream framing support (SPEC §5, §8, §14, Task RER-F-060).

use std::io::{Cursor, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use rer::config::{Config, FramingMode};
use rer::framing::{
    encode_kiss_frame, read_frame_with_mode, read_kiss_frame, write_frame_with_mode,
    write_kiss_frame, KISS_FEND, KISS_FESC, KISS_TFEND, KISS_TFESC,
};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 1:
// In crates/rer/src/framing.rs, reading from a TCP stream delivering a KISS frame
// fragmented across multiple 1-byte reads reassembles the complete unescaped frame
// matching the original transmitted payload bytes.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion1_tcp_stream_kiss_framing_reassembles_fragmented_reads() {
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
  - id: "relay-kiss-fragmented"
    streams:
      - id: "s-kiss-frag"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "kiss"
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

    // 1. KISS Data frame delivered 1 byte at a time
    let original_payload = b"\x00CQ CQ DE N0CALL test amateur radio payload".to_vec();
    let wire_frame = encode_kiss_frame(&original_payload);

    for &b in &wire_frame {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let mut buf = vec![0u8; 1024];
    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled kiss data packet");
    assert_eq!(&buf[..n], original_payload.as_slice());

    // 2. KISS frame with escaped characters delivered 1 byte at a time
    let escaped_payload = vec![0x00, 0xC0, 0x11, 0xDB, 0x22, 0xC0, 0xDB];
    let wire_frame2 = encode_kiss_frame(&escaped_payload);

    for &b in &wire_frame2 {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled escaped kiss data packet");
    assert_eq!(&buf[..n], escaped_payload.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2:
// In crates/rer/src/framing.rs, reading from a TCP stream delivering two concatenated
// KISS frames separated by FEND delimiter byte 0xC0 in a single read buffer yields
// the two frames individually.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion2_tcp_stream_concatenated_kiss_frames_separated_by_fend() {
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
  - id: "relay-kiss-concat"
    streams:
      - id: "s-kiss-concat"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "kiss"
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

    let frame1 = vec![0x00, 0x01, 0x02, 0x03];
    let frame2 = vec![0x00, 0x10, 0x20, 0x30, 0x40];

    // Build single buffer with two frames separated by FEND (0xC0)
    let mut single_buffer = Vec::new();
    single_buffer.push(KISS_FEND);
    single_buffer.extend_from_slice(&frame1);
    single_buffer.push(KISS_FEND); // Delimiter ending frame 1 and starting frame 2
    single_buffer.extend_from_slice(&frame2);
    single_buffer.push(KISS_FEND);

    // Write the entire buffer in a single write call
    client
        .write_all(&single_buffer)
        .expect("write concatenated frames");
    client.flush().expect("flush concatenated frames");

    let mut buf = vec![0u8; 1024];
    let (n1, _) = receiver.recv_from(&mut buf).expect("receive first frame");
    assert_eq!(&buf[..n1], frame1.as_slice());

    let (n2, _) = receiver.recv_from(&mut buf).expect("receive second frame");
    assert_eq!(&buf[..n2], frame2.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3:
// In crates/rer/src/framing.rs, reading from a TCP stream delivering an escaped
// sequence of 0xDB followed by 0xDC decodes byte 0xC0, and 0xDB followed by
// 0xDD decodes byte 0xDB.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion3_tcp_stream_kiss_escape_sequences_decode() {
    let shutdown = AtomicBool::new(false);

    // 0xDB followed by 0xDC decodes byte 0xC0
    let stream_dc = vec![KISS_FEND, 0x00, KISS_FESC, KISS_TFEND, 0xFF, KISS_FEND];
    let mut cursor_dc = Cursor::new(stream_dc);
    let decoded_dc = read_kiss_frame(&mut cursor_dc, 1024, &shutdown)
        .expect("read kiss frame")
        .expect("frame");
    assert_eq!(decoded_dc, vec![0x00, 0xC0, 0xFF]);

    // 0xDB followed by 0xDD decodes byte 0xDB
    let stream_dd = vec![KISS_FEND, 0x00, KISS_FESC, KISS_TFESC, 0xEE, KISS_FEND];
    let mut cursor_dd = Cursor::new(stream_dd);
    let decoded_dd = read_kiss_frame(&mut cursor_dd, 1024, &shutdown)
        .expect("read kiss frame")
        .expect("frame");
    assert_eq!(decoded_dd, vec![0x00, 0xDB, 0xEE]);

    // Combined both escape sequences in single frame
    let stream_both = vec![
        KISS_FEND, 0x00, KISS_FESC, KISS_TFEND, 0x01, KISS_FESC, KISS_TFESC, 0x02, KISS_FEND,
    ];
    let mut cursor_both = Cursor::new(stream_both);
    let decoded_both = read_frame_with_mode(&mut cursor_both, FramingMode::Kiss, 1024, &shutdown)
        .expect("read kiss frame with mode")
        .expect("frame");
    assert_eq!(decoded_both, vec![0x00, 0xC0, 0x01, 0xDB, 0x02]);
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4:
// In crates/rer/src/framing.rs, reading a KISS frame containing escape byte 0xDB
// followed by an unexpected byte returns an io::ErrorKind::InvalidData error.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion4_kiss_unexpected_escape_byte_returns_invalid_data() {
    let shutdown = AtomicBool::new(false);

    // 0xDB followed by 0x42
    let stream_bad = vec![KISS_FEND, 0x00, 0xDB, 0x42, KISS_FEND];
    let mut cursor = Cursor::new(stream_bad);
    let err = read_kiss_frame(&mut cursor, 1024, &shutdown).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    // 0xDB followed by 0xC0 (FEND)
    let stream_bad2 = vec![KISS_FEND, 0x00, 0xDB, KISS_FEND];
    let mut cursor2 = Cursor::new(stream_bad2);
    let err2 = read_kiss_frame(&mut cursor2, 1024, &shutdown).unwrap_err();
    assert_eq!(err2.kind(), std::io::ErrorKind::InvalidData);

    // Via read_frame_with_mode
    let stream_bad3 = vec![KISS_FEND, 0x00, 0xDB, 0xAA, KISS_FEND];
    let mut cursor3 = Cursor::new(stream_bad3);
    let err3 = read_frame_with_mode(&mut cursor3, FramingMode::Kiss, 1024, &shutdown).unwrap_err();
    assert_eq!(err3.kind(), std::io::ErrorKind::InvalidData);
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 5:
// In crates/rer/src/framing.rs, reading a KISS frame whose unescaped length exceeds
// the configured max_frame_size returns an io::ErrorKind::InvalidData error.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion5_oversized_kiss_frame_returns_invalid_data() {
    let shutdown = AtomicBool::new(false);

    // Unescaped frame of length 6 with max_frame_size 5
    let oversized = vec![KISS_FEND, 1, 2, 3, 4, 5, 6, KISS_FEND];
    let mut cursor = Cursor::new(oversized);
    let err = read_kiss_frame(&mut cursor, 5, &shutdown).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds maximum allowed"));

    // Frame with escapes that unescapes to length 6 with max_frame_size 5
    let escaped_oversized = vec![KISS_FEND, 1, 2, 3, 4, 5, 0xDB, 0xDC, KISS_FEND];
    let mut cursor2 = Cursor::new(escaped_oversized);
    let err2 = read_frame_with_mode(&mut cursor2, FramingMode::Kiss, 5, &shutdown).unwrap_err();
    assert_eq!(err2.kind(), std::io::ErrorKind::InvalidData);
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 6:
// In crates/rer/src/config.rs, configuring option framing with value kiss
// deserializes into FramingMode::Kiss.
// ---------------------------------------------------------------------------
#[test]
fn test_criterion6_config_framing_option_kiss_deserializes() {
    // 1. Stream-level option framing with value kiss
    let yaml_stream = r#"
version: "1"
instances:
  - id: "i-kiss"
    streams:
      - id: "s-kiss"
        framing: kiss
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
"#;
    let config = Config::from_yaml_str(yaml_stream).expect("parse stream framing: kiss");
    let stream = &config.instances[0].streams[0];
    assert_eq!(stream.framing, Some(FramingMode::Kiss));
    assert_eq!(stream.source_framing(), FramingMode::Kiss);
    assert_eq!(
        stream.destination_framing(stream.destination.as_ref().unwrap()),
        FramingMode::Kiss
    );

    // 2. Endpoint-level option framing with value kiss
    let yaml_endpoint = r#"
version: "1"
instances:
  - id: "i-ep-kiss"
    streams:
      - id: "s-ep-kiss"
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
          framing: kiss
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
          framing: kiss
"#;
    let config_ep = Config::from_yaml_str(yaml_endpoint).expect("parse endpoint framing: kiss");
    let ep_stream = &config_ep.instances[0].streams[0];
    let dest = ep_stream.destination.as_ref().unwrap();
    assert_eq!(ep_stream.source.framing, Some(FramingMode::Kiss));
    assert_eq!(dest.framing, Some(FramingMode::Kiss));
    assert_eq!(ep_stream.source_framing(), FramingMode::Kiss);
    assert_eq!(ep_stream.destination_framing(dest), FramingMode::Kiss);

    // 3. Quoted "kiss" and uppercase "KISS"
    let yaml_quoted = r#"
version: "1"
instances:
  - id: "i-quoted"
    streams:
      - id: "s-quoted"
        framing: "kiss"
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
"#;
    let config_quoted = Config::from_yaml_str(yaml_quoted).expect("parse quoted framing: kiss");
    assert_eq!(
        config_quoted.instances[0].streams[0].framing,
        Some(FramingMode::Kiss)
    );

    // 4. Direct serde deserialization
    let deserialized: FramingMode = serde_json::from_str("\"kiss\"").unwrap();
    assert_eq!(deserialized, FramingMode::Kiss);
    let deserialized_upper: FramingMode = serde_json::from_str("\"KISS\"").unwrap();
    assert_eq!(deserialized_upper, FramingMode::Kiss);
}

// ---------------------------------------------------------------------------
// End-to-end TCP-to-TCP KISS framing test
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_to_tcp_kiss_framing_end_to_end() {
    let egress_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind egress listener");
    let egress_port = egress_listener.local_addr().unwrap().port();
    let ingress_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-tcp-to-tcp-kiss"
    streams:
      - id: "s-t2t-kiss"
        source:
          transport: "tcp"
          address: "127.0.0.1:{ingress_port}"
          framing: "kiss"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{egress_port}"
          mode: "connect"
          framing: "kiss"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    // Accept destination connection from relay
    egress_listener
        .set_nonblocking(false)
        .expect("blocking listener");
    let (mut rx_conn, _) = egress_listener
        .accept()
        .expect("accept connection from relay");
    rx_conn
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // Connect sender client to relay ingress
    let mut tx_client =
        TcpStream::connect(format!("127.0.0.1:{ingress_port}")).expect("connect to relay");
    tx_client.set_nodelay(true).unwrap();

    let original_payload = b"\x00AX25 telemetry data packet".to_vec();
    write_frame_with_mode(&mut tx_client, FramingMode::Kiss, &original_payload)
        .expect("send kiss frame");
    tx_client.flush().expect("flush kiss frame");

    let shutdown = AtomicBool::new(false);
    let received = read_frame_with_mode(&mut rx_conn, FramingMode::Kiss, 65535, &shutdown)
        .expect("read egress kiss frame")
        .expect("received frame");

    assert_eq!(received, original_payload);

    relay.stop();
}

#[test]
fn test_write_kiss_frame_encodes_and_transmits_delimiters_and_escapes() {
    let payload = vec![0x00, KISS_FEND, 0x12, KISS_FESC, 0x34];
    let mut out = Vec::new();
    write_kiss_frame(&mut out, &payload).expect("write_kiss_frame");

    assert_eq!(out[0], KISS_FEND);
    assert_eq!(*out.last().unwrap(), KISS_FEND);

    let shutdown = AtomicBool::new(false);
    let mut cursor = Cursor::new(out);
    let decoded = read_kiss_frame(&mut cursor, 1024, &shutdown)
        .expect("read_kiss_frame")
        .expect("payload");
    assert_eq!(decoded, payload);
}
