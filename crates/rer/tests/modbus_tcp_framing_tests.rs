//! Integration tests for in-tree Modbus TCP stream framing (Task RER-F-074).

use std::io::{self, Cursor, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use rer::config::{Config, FramingMode};
use rer::framing::{
    read_frame_with_mode, read_modbus_frame, write_frame_with_mode, write_modbus_frame,
};
use rer::modbus::{
    encode_modbus_exception_response, encode_modbus_frame, parse_mbap_header, parse_modbus_frame,
    MbapHeader, ModbusExceptionCode,
};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

#[test]
fn test_criterion5_modbus_frame_fragmented_1_byte_reads() {
    // Acceptance criterion 5:
    // In crates/rer/src/framing.rs, reading a Modbus frame fragmented across multiple 1-byte reads
    // reassembles the complete frame matching the transmitted payload bytes.
    struct OneByteReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl<'a> Read for OneByteReader<'a> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    // Modbus frame: TxID=1, ProtoID=0, Length=6, UnitID=1, FunctionCode=3, Reg=100, Count=10
    let frame = encode_modbus_frame(1, 1, 3, &[0x00, 0x64, 0x00, 0x0A]);
    assert_eq!(frame.len(), 12);

    let mut reader = OneByteReader {
        data: &frame,
        pos: 0,
    };
    let shutdown = AtomicBool::new(false);
    let reassembled = read_modbus_frame(&mut reader, 1024, &shutdown)
        .expect("read_modbus_frame must succeed")
        .expect("frame must be returned");

    assert_eq!(reassembled, frame);

    // Verify parsed frame matches expected MbapHeader
    let parsed_header: MbapHeader = parse_mbap_header(&reassembled).expect("parse reassembled");
    assert_eq!(parsed_header.transaction_id, 1);
    assert_eq!(parsed_header.function_code, 3);

    // Also verify via read_frame_with_mode
    let mut reader_mode = OneByteReader {
        data: &frame,
        pos: 0,
    };
    let reassembled_mode =
        read_frame_with_mode(&mut reader_mode, FramingMode::ModbusTcp, 1024, &shutdown)
            .expect("read_frame_with_mode must succeed")
            .expect("frame must be returned");

    assert_eq!(reassembled_mode, frame);
}

#[test]
fn test_criterion6_modbus_frame_exceeds_max_frame_size_no_allocation() {
    // Acceptance criterion 6:
    // In crates/rer/src/framing.rs, reading a Modbus frame declaring a length exceeding max_frame_size
    // returns an invalid data error without allocating the declared length.
    let mut frame = Vec::new();
    frame.extend_from_slice(&1u16.to_be_bytes()); // TxID 1
    frame.extend_from_slice(&0u16.to_be_bytes()); // ProtoID 0
    frame.extend_from_slice(&200u16.to_be_bytes()); // Length 200 (within 2..=254, but exceeds max_frame_size 50)
    frame.push(1); // UnitID 1

    let mut cursor = Cursor::new(frame);
    let shutdown = AtomicBool::new(false);
    let err = read_modbus_frame(&mut cursor, 50, &shutdown)
        .expect_err("reading frame exceeding max_frame_size must fail");

    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds maximum allowed 50"));

    // Also verify via read_frame_with_mode
    let mut frame_mode = Vec::new();
    frame_mode.extend_from_slice(&1u16.to_be_bytes());
    frame_mode.extend_from_slice(&0u16.to_be_bytes());
    frame_mode.extend_from_slice(&200u16.to_be_bytes());
    frame_mode.push(1);

    let mut cursor_mode = Cursor::new(frame_mode);
    let err_mode = read_frame_with_mode(&mut cursor_mode, FramingMode::ModbusTcp, 50, &shutdown)
        .expect_err("read_frame_with_mode with oversized frame must fail");

    assert_eq!(err_mode.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn test_modbus_framing_write_and_roundtrip() {
    let frame = encode_modbus_exception_response(42, 1, 3, 2);
    let mut out = Vec::new();
    write_modbus_frame(&mut out, &frame).expect("write_modbus_frame must succeed");
    assert_eq!(out, frame);

    let mut out_mode = Vec::new();
    write_frame_with_mode(&mut out_mode, FramingMode::ModbusTcp, &frame)
        .expect("write_frame_with_mode must succeed");
    assert_eq!(out_mode, frame);

    let parsed = parse_modbus_frame(&out).expect("parse written frame");
    assert_eq!(
        parsed.exception,
        Some(ModbusExceptionCode::IllegalDataAddress)
    );
}

#[test]
fn test_tcp_relay_modbus_framing_fragmented_stream_forwarding() {
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
  - id: "relay-modbus-fragmented"
    streams:
      - id: "s-modbus-frag"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "modbus_tcp"
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

    // 1. Modbus Read Holding Registers request sent 1 byte at a time
    let req_frame = encode_modbus_frame(1, 1, 3, &[0x00, 0x64, 0x00, 0x0A]);
    for &b in &req_frame {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let mut buf = vec![0u8; 1024];
    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled modbus request frame");
    assert_eq!(&buf[..n], req_frame.as_slice());

    // 2. Modbus Exception response sent 1 byte at a time
    let exc_frame = encode_modbus_exception_response(2, 1, 3, 2);
    for &b in &exc_frame {
        client.write_all(&[b]).expect("write byte");
        client.flush().expect("flush byte");
        thread::sleep(Duration::from_millis(2));
    }

    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("receive reassembled modbus exception frame");
    assert_eq!(&buf[..n], exc_frame.as_slice());

    relay.stop();
}
