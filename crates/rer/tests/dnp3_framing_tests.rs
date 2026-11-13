//! Integration tests for DNP3 TCP stream framing and sync detection (Task RER-F-075).

use std::io::{self, Cursor, Read};
use std::sync::atomic::AtomicBool;

use rer::config::FramingMode;
use rer::dnp3::{calculate_crc, encode_dnp3_frame, encode_ft3_header, parse_ft3_header};
use rer::framing::{
    read_dnp3_frame, read_frame_with_mode, write_dnp3_frame, write_frame_with_mode,
    DNP3_MAX_SYNC_SEARCH_BYTES,
};

#[test]
fn test_criterion5_scan_through_leading_noise_bytes_to_sync() {
    // Acceptance criterion 5:
    // In crates/rer/src/framing.rs, reading from a TCP stream containing leading noise bytes
    // before sync octets 0x05 and 0x64 scans through up to a bounded limit to synchronize
    // on the valid FT3 frame.
    let valid_hdr = encode_ft3_header(5, 0xC0, 1, 2);

    // Prepend leading noise bytes, including random data and false sync starts
    let mut stream = vec![0x00, 0xFF, 0xAA, 0x05, 0x05, 0x33, 0x05, 0x12, 0x99];
    stream.extend_from_slice(&valid_hdr);

    let mut cursor = Cursor::new(stream);
    let shutdown = AtomicBool::new(false);
    let frame = read_dnp3_frame(&mut cursor, 1024, &shutdown)
        .expect("read_dnp3_frame must succeed")
        .expect("frame must be returned");

    assert_eq!(frame, valid_hdr);

    // Verify parsed frame matches expected link header fields
    let parsed = parse_ft3_header(&frame).expect("parse frame header");
    assert_eq!(parsed.sync, [0x05, 0x64]);
    assert_eq!(parsed.length, 5);
    assert_eq!(parsed.control, 0xC0);
    assert_eq!(parsed.destination, 1);
    assert_eq!(parsed.source, 2);

    // Verify with read_frame_with_mode using FramingMode::Dnp3
    let mut stream2 = vec![0xDE, 0xAD, 0xBE, 0xEF];
    stream2.extend_from_slice(&valid_hdr);
    let mut cursor2 = Cursor::new(stream2);
    let frame2 = read_frame_with_mode(&mut cursor2, FramingMode::Dnp3, 1024, &shutdown)
        .expect("read_frame_with_mode must succeed")
        .expect("frame must be returned");
    assert_eq!(frame2, valid_hdr);
}

#[test]
fn test_criterion6_reading_frame_exceeding_max_frame_size_returns_error() {
    // Acceptance criterion 6:
    // In crates/rer/src/framing.rs, reading a DNP3 frame declaring a length exceeding
    // max_frame_size returns an invalid data error without allocating the declared frame size.
    let mut frame_data = Vec::new();
    frame_data.push(0x05); // sync 0
    frame_data.push(0x64); // sync 1
    frame_data.push(200); // length 200 (wire length 200 + user data blocks CRCs > 200)
    frame_data.extend_from_slice(&[0xC0, 0x01, 0x00, 0x02, 0x00]); // control, dest 1, src 2
    let crc = calculate_crc(&frame_data[..8]);
    frame_data.extend_from_slice(&crc.to_le_bytes()); // header CRC

    // Total wire length will be > 200, which exceeds max_frame_size of 50
    let mut cursor = Cursor::new(frame_data);
    let shutdown = AtomicBool::new(false);
    let err = read_dnp3_frame(&mut cursor, 50, &shutdown).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("exceeds maximum allowed 50"));

    // Also verify via read_frame_with_mode
    let mut frame_data2 = Vec::new();
    frame_data2.push(0x05);
    frame_data2.push(0x64);
    frame_data2.push(255); // max length 255 (wire length 292)
    frame_data2.extend_from_slice(&[0xC0, 0x01, 0x00, 0x02, 0x00]);
    let crc2 = calculate_crc(&frame_data2[..8]);
    frame_data2.extend_from_slice(&crc2.to_le_bytes());

    let mut cursor2 = Cursor::new(frame_data2);
    let err2 = read_frame_with_mode(&mut cursor2, FramingMode::Dnp3, 100, &shutdown).unwrap_err();
    assert_eq!(err2.kind(), io::ErrorKind::InvalidData);
    assert!(err2.to_string().contains("exceeds maximum allowed 100"));
}

#[test]
fn test_dnp3_framing_1_byte_fragmented_reads() {
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

    let frame = encode_dnp3_frame(0xC0, 1, 2, &[0xC0, 0x01, 0x02]);
    let mut reader = OneByteReader {
        data: &frame,
        pos: 0,
    };
    let shutdown = AtomicBool::new(false);
    let reassembled = read_dnp3_frame(&mut reader, 1024, &shutdown)
        .expect("read_dnp3_frame must succeed")
        .expect("frame must be returned");

    assert_eq!(reassembled, frame);
}

#[test]
fn test_dnp3_write_and_read_roundtrip() {
    let frame = encode_dnp3_frame(0xC0, 5, 10, &[0xC0, 0x11, 0x22, 0x33]);
    let mut written = Vec::new();
    write_dnp3_frame(&mut written, &frame).expect("write_dnp3_frame");
    assert_eq!(written, frame);

    let mut cursor = Cursor::new(written);
    let shutdown = AtomicBool::new(false);
    let read_back = read_dnp3_frame(&mut cursor, 1024, &shutdown)
        .expect("read_dnp3_frame")
        .expect("frame");
    assert_eq!(read_back, frame);

    let mut out_mode = Vec::new();
    write_frame_with_mode(&mut out_mode, FramingMode::Dnp3, &frame).expect("write_frame_with_mode");
    assert_eq!(out_mode, frame);
}

#[test]
fn test_dnp3_noise_scan_limit() {
    let noise = vec![0x11; DNP3_MAX_SYNC_SEARCH_BYTES + 50];
    let mut cursor = Cursor::new(noise);
    let shutdown = AtomicBool::new(false);
    let err = read_dnp3_frame(&mut cursor, 1024, &shutdown).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err
        .to_string()
        .contains("exceeded synchronization scan limit"));
}
