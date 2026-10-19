//! Integration tests for CCSDS length-based TCP framing (SPEC §14, §5, §8, Task RER-F-033).

use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use rer::ccsds::{CcsdsPrimaryHeader, CCSDS_PRIMARY_HEADER_LEN};
use rer::config::Config;
use rer::framing::{encode_frame, read_ccsds_frame};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn build_space_packet(apid: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len().max(1);
    let data_len_field = (payload_len - 1) as u16;
    let header = CcsdsPrimaryHeader {
        version: 0,
        packet_type: 0,
        secondary_header_flag: false,
        apid,
        sequence_flags: 3,
        sequence_count: seq,
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
// Acceptance Criterion 1:
// When TCP framing is configured with option framing set to ccsds, TCP ingress
// parses packet boundaries from the 6-byte CCSDS primary header data length field
// plus 7 bytes instead of the default 4-byte length prefix.
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_ingress_ccsds_framing_parses_packet_boundaries() {
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
  - id: "relay-ccsds-tcp-ingress"
    streams:
      - id: "s-ccsds-tcp"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "ccsds"
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

    let test_packets = vec![
        build_space_packet(100, 1, b"hello space telemetry"),
        build_space_packet(100, 2, b"x"),
        build_space_packet(200, 1, &[0x42; 256]),
        build_space_packet(200, 2, &[0x99; 1024]),
    ];

    for pkt in &test_packets {
        // Send raw CCSDS Space Packet directly over TCP (no 4-byte length prefix)
        client.write_all(pkt).expect("write ccsds packet");
        thread::sleep(Duration::from_millis(10));

        let mut buf = vec![0u8; 2048];
        let (n, _) = receiver.recv_from(&mut buf).expect("receive packet");
        assert_eq!(&buf[..n], pkt.as_slice());
    }

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 2:
// A TCP stream configured with CCSDS framing reassembles packets arriving
// across fragmented reads delivering one byte at a time into complete individual
// Space Packets matching the sent payloads.
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_stream_ccsds_framing_reassembles_fragmented_one_byte_reads() {
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
  - id: "relay-ccsds-fragmented"
    streams:
      - id: "s-fragmented"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "ccsds"
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

    let packet = build_space_packet(150, 42, b"defragmentation across one-byte-at-a-time reads");

    // Send packet 1 byte at a time
    for &byte in &packet {
        client.write_all(&[byte]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(3));
    }

    let mut buf = vec![0u8; 1024];
    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled packet");
    assert_eq!(&buf[..n], packet.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 3:
// A TCP stream configured with CCSDS framing receiving three concatenated Space
// Packets in a single read buffer separates and yields the three packets
// individually at their declared packet data length plus 7 byte boundaries.
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_stream_ccsds_framing_three_concatenated_packets_in_single_read_buffer() {
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
  - id: "relay-ccsds-concatenated"
    streams:
      - id: "s-concatenated"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "ccsds"
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

    let p1 = build_space_packet(10, 101, b"packet one payload");
    let p2 = build_space_packet(20, 202, b"longer packet two payload with more data");
    let p3 = build_space_packet(30, 303, b"p3");

    // Concatenate all 3 packets into a single write buffer
    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&p1);
    concatenated.extend_from_slice(&p2);
    concatenated.extend_from_slice(&p3);

    client
        .write_all(&concatenated)
        .expect("write concatenated packets");
    client.flush().expect("flush client");

    // Receive the 3 packets individually from UDP destination
    let mut buf = vec![0u8; 1024];

    let (n1, _) = receiver.recv_from(&mut buf).expect("receive packet 1");
    assert_eq!(&buf[..n1], p1.as_slice());

    let (n2, _) = receiver.recv_from(&mut buf).expect("receive packet 2");
    assert_eq!(&buf[..n2], p2.as_slice());

    let (n3, _) = receiver.recv_from(&mut buf).expect("receive packet 3");
    assert_eq!(&buf[..n3], p3.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 4:
// A TCP frame declaring a packet length exceeding the stream buffer limit causes
// the connection to reject the frame and increment dropped packet counters
// without crashing the relay.
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_frame_exceeding_buffer_limit_rejected_and_counters_incremented() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-ccsds-oversized"
    streams:
      - id: "s-oversized"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "ccsds"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_packet_size: 100
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay");
    client.set_nodelay(true).unwrap();

    // Send valid frame (total packet length 50 <= 100)
    let valid_packet = build_space_packet(50, 1, &[0xAA; 43]); // 6 header + 43 payload + 1 fill = 50 bytes
    client.write_all(&valid_packet).expect("write valid packet");

    let mut buf = vec![0u8; 256];
    let (n, _) = receiver.recv_from(&mut buf).expect("receive valid packet");
    assert_eq!(&buf[..n], valid_packet.as_slice());

    // Send oversized frame (total packet length 207 > 100)
    let oversized_packet = build_space_packet(50, 2, &[0xBB; 200]);
    let _ = client.write_all(&oversized_packet);
    let _ = client.flush();

    thread::sleep(Duration::from_millis(60));
    let stats = relay.stream_stats("s-oversized").expect("stream stats");
    assert_eq!(stats.drops_oversized, 1);
    assert_eq!(stats.dropped_packets, 1);

    // Relay is still running without crashing
    assert!(relay.stream_stats("s-oversized").is_some());

    relay.stop();
}

// ---------------------------------------------------------------------------
// Acceptance Criterion 5:
// TCP endpoints without explicit framing configuration continue to use the default
// 4-byte length prefix, verified by existing TCP loopback integration tests
// passing unmodified.
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_endpoint_default_framing_retains_4_byte_length_prefix() {
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
  - id: "relay-tcp-default"
    streams:
      - id: "s-default"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
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

    let payload = b"default 4-byte length prefix frame payload".to_vec();
    // Send with 4-byte length prefix
    client
        .write_all(&encode_frame(&payload))
        .expect("write framed");

    let mut buf = vec![0u8; 1024];
    let (n, _) = receiver.recv_from(&mut buf).expect("receive packet");
    assert_eq!(&buf[..n], payload.as_slice());

    relay.stop();
}

// ---------------------------------------------------------------------------
// End-to-end TCP-to-TCP with CCSDS framing
// ---------------------------------------------------------------------------
#[test]
fn test_tcp_to_tcp_ccsds_framing_end_to_end() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-t2t-ccsds"
    streams:
      - id: "s-t2t"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "ccsds"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
          framing: "ccsds"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    // Accept relay connection to destination
    let (mut egress_stream, _) = listener.accept().expect("accept connection from relay");
    egress_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Client connects to relay source
    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay");
    client.set_nodelay(true).unwrap();

    let p1 = build_space_packet(77, 10, b"telemetry-block-1");
    let p2 = build_space_packet(77, 11, b"telemetry-block-2");

    client.write_all(&p1).expect("write p1");
    client.write_all(&p2).expect("write p2");

    let shutdown = AtomicBool::new(false);
    let r1 = read_ccsds_frame(&mut egress_stream, 1024, &shutdown)
        .expect("read p1")
        .expect("some p1");
    let r2 = read_ccsds_frame(&mut egress_stream, 1024, &shutdown)
        .expect("read p2")
        .expect("some p2");

    assert_eq!(r1, p1);
    assert_eq!(r2, p2);

    relay.stop();
}
