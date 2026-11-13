//! Integration tests for in-tree DNP3 FT3 link header parsing, CRC validation, and transport control (Task RER-F-075).

use rer::dnp3::{
    calculate_crc, compute_crc, dnp3_crc, encode_dnp3_frame, encode_ft3_header, parse_dnp3,
    parse_dnp3_frame, parse_dnp3_header, parse_frame, parse_ft3_header, parse_link_header,
    parse_transport_control, parse_transport_header, parse_user_data_block, Dnp3Frame,
    Dnp3LinkHeader, Dnp3Metadata, Dnp3ParseError, Dnp3TransportHeader, Dnp3UserDataBlock,
    TransportHeader, CRC_POLYNOMIAL, DNP3_BLOCK_SIZE, DNP3_CRC_POLY, DNP3_HEADER_DATA_LEN,
    DNP3_HEADER_LEN, DNP3_MAX_FRAME_LEN, DNP3_MAX_LENGTH, DNP3_MIN_FRAME_LEN, DNP3_MIN_LENGTH,
    DNP3_SYNC, DNP3_SYNC_0, DNP3_SYNC_1,
};

#[test]
fn test_criterion1_parse_10_octet_ft3_header() {
    // Acceptance criterion 1:
    // In crates/rer/src/dnp3.rs, parsing a 10-octet FT3 header with sync octets 0x05 and 0x64,
    // length 5, control 0xC0, destination address 1, and source address 2 validates the
    // header CRC and extracts the link header fields.
    let raw_8 = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
    let crc = calculate_crc(&raw_8);

    let mut raw_10 = [0u8; 10];
    raw_10[..8].copy_from_slice(&raw_8);
    raw_10[8..10].copy_from_slice(&crc.to_le_bytes());

    let header = parse_ft3_header(&raw_10).expect("parsing valid FT3 header must succeed");
    assert_eq!(header.sync, [0x05, 0x64]);
    assert_eq!(header.length, 5);
    assert_eq!(header.control, 0xC0);
    assert_eq!(header.destination, 1);
    assert_eq!(header.source, 2);
    assert_eq!(header.header_crc, crc);
    assert!(header.is_primary);
    assert!(header.direction);
    assert_eq!(header.control_function, 0);

    // Also verify via Dnp3LinkHeader methods and aliases
    assert_eq!(header.destination_address(), 1);
    assert_eq!(header.source_address(), 2);
    assert_eq!(header.dest(), 1);
    assert_eq!(header.src(), 2);
    assert_eq!(header.crc(), crc);
    assert!(header.dir());
    assert!(header.prm());
    assert_eq!(header.user_data_len(), 0);
    assert_eq!(header.num_blocks(), 0);
    assert_eq!(header.wire_length(), 10);

    let h_link = parse_link_header(&raw_10).expect("parse_link_header");
    assert_eq!(h_link, header);

    let h_dnp3 = parse_dnp3_header(&raw_10).expect("parse_dnp3_header");
    assert_eq!(h_dnp3, header);

    let h_struct = Dnp3LinkHeader::parse(&raw_10).expect("Dnp3LinkHeader::parse");
    assert_eq!(h_struct, header);

    let h_slice = Dnp3LinkHeader::from_slice(&raw_10).expect("Dnp3LinkHeader::from_slice");
    assert_eq!(h_slice, header);

    // Because length 5 has 0 user data bytes, the 10-octet header is also a valid frame
    let frame = parse_dnp3_frame(&raw_10, true).expect("parse_dnp3_frame");
    assert_eq!(frame.destination, 1);
    assert_eq!(frame.source, 2);
    assert_eq!(frame.control, 0xC0);
    assert!(frame.is_primary);
    assert!(frame.direction);
    assert_eq!(frame.control_function, 0);
    assert!(frame.header_crc_valid);
    assert!(frame.crc_valid);
}

#[test]
fn test_criterion2_calculate_16bit_crc_over_8octet_header() {
    // Acceptance criterion 2:
    // In crates/rer/src/dnp3.rs, calculating the 16-bit CRC over an 8-octet header using
    // polynomial 0xA653 with inverted output produces the matching expected CRC value.
    let header = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
    let crc = calculate_crc(&header);

    // Reference calculation using the bit-by-bit polynomial shift
    let mut ref_crc = 0x0000u16;
    for &byte in &header {
        ref_crc ^= byte as u16;
        for _ in 0..8 {
            if (ref_crc & 1) != 0 {
                ref_crc = (ref_crc >> 1) ^ 0xA653;
            } else {
                ref_crc >>= 1;
            }
        }
    }
    ref_crc = !ref_crc;

    assert_eq!(crc, ref_crc);
    assert_eq!(crc, 0x196F);
    assert_eq!(dnp3_crc(&header), ref_crc);
    assert_eq!(compute_crc(&header), ref_crc);

    // Verify constants
    assert_eq!(DNP3_CRC_POLY, 0xA653);
    assert_eq!(CRC_POLYNOMIAL, 0xA653);
}

#[test]
fn test_criterion3_invalid_header_crc_returns_error() {
    // Acceptance criterion 3:
    // In crates/rer/src/dnp3.rs, parsing a frame with an invalid header CRC returns an error
    // indicating CRC verification failure.
    let raw_8 = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
    let valid_crc = calculate_crc(&raw_8);

    let mut corrupted = [0u8; 10];
    corrupted[..8].copy_from_slice(&raw_8);
    // Invert the CRC to ensure mismatch
    corrupted[8..10].copy_from_slice(&(valid_crc ^ 0xFFFF).to_le_bytes());

    let err = parse_ft3_header(&corrupted).unwrap_err();
    assert!(err.is_crc_failure());
    assert!(err.is_header_crc_failure());
    assert!(err.to_string().contains("CRC verification failure"));

    match err {
        Dnp3ParseError::HeaderCrcFailure {
            expected,
            calculated,
        } => {
            assert_eq!(expected, valid_crc ^ 0xFFFF);
            assert_eq!(calculated, valid_crc);
        }
        other => panic!("expected HeaderCrcFailure, got {other:?}"),
    }

    let frame_err = parse_dnp3_frame(&corrupted, true).unwrap_err();
    assert!(frame_err.is_crc_failure());
    assert!(frame_err.to_string().contains("CRC verification failure"));
}

#[test]
fn test_criterion4_transport_control_fir_fin_sequence() {
    // Acceptance criterion 4:
    // In crates/rer/src/dnp3.rs, parsing an FT3 user data block containing transport control
    // octet 0xC0 extracts first segment flag FIR, final segment flag FIN, and transport sequence number 0.
    let user_data_block = [0xC0, 0x01, 0x02, 0x03];
    let block = parse_user_data_block(&user_data_block).expect("parse_user_data_block");
    assert!(block.fir);
    assert!(block.fin);
    assert_eq!(block.sequence, 0);
    assert_eq!(block.sequence_number, 0);

    // Direct methods on block
    assert!(block.fir());
    assert!(block.fin());
    assert_eq!(block.sequence(), 0);
    assert_eq!(block.sequence_number(), 0);

    // Test parse_transport_control
    let ctrl = parse_transport_control(0xC0);
    assert!(ctrl.fir);
    assert!(ctrl.fin);
    assert_eq!(ctrl.sequence, 0);
    assert_eq!(ctrl.sequence_number, 0);
    assert!(ctrl.is_first_segment());
    assert!(ctrl.is_final_segment());
    assert!(ctrl.is_unfragmented());

    // Test parse_transport_header
    let th = parse_transport_header(&user_data_block).expect("parse_transport_header");
    assert_eq!(th, ctrl);

    // Test sequence values other than 0 (e.g. sequence 42 with FIR=0, FIN=1)
    let octet = 0x80 | 42; // FIN=1, FIR=0, sequence=42
    let ctrl2 = parse_transport_control(octet);
    assert!(!ctrl2.fir);
    assert!(ctrl2.fin);
    assert_eq!(ctrl2.sequence, 42);
}

#[test]
fn test_encode_and_parse_full_dnp3_frame() {
    // Construct frame with 20 user data bytes (spans 2 blocks: 16 bytes + 4 bytes)
    let user_payload = vec![0xC0; 20];
    let encoded = encode_dnp3_frame(0xC0, 10, 20, &user_payload);

    let parsed = parse_dnp3_frame(&encoded, true).expect("parse encoded full frame");
    assert_eq!(parsed.destination, 10);
    assert_eq!(parsed.source, 20);
    assert_eq!(parsed.length, 25);
    assert!(parsed.crc_valid);
    assert_eq!(parsed.user_data, user_payload);
    assert_eq!(parsed.blocks.len(), 2);
    assert_eq!(parsed.blocks[0].len(), 16);
    assert_eq!(parsed.blocks[1].len(), 4);

    let transport = parsed.transport.expect("transport header");
    assert!(transport.fir);
    assert!(transport.fin);
    assert_eq!(transport.sequence, 0);
}

#[test]
fn test_dnp3_constants_and_aliases() {
    assert_eq!(DNP3_SYNC_0, 0x05);
    assert_eq!(DNP3_SYNC_1, 0x64);
    assert_eq!(DNP3_SYNC, [0x05, 0x64]);
    assert_eq!(DNP3_HEADER_LEN, 10);
    assert_eq!(DNP3_HEADER_DATA_LEN, 8);
    assert_eq!(DNP3_MIN_LENGTH, 5);
    assert_eq!(DNP3_MAX_LENGTH, 255);
    assert_eq!(DNP3_MIN_FRAME_LEN, 10);
    assert_eq!(DNP3_MAX_FRAME_LEN, 292);
    assert_eq!(DNP3_BLOCK_SIZE, 16);

    let hdr = encode_ft3_header(5, 0xC0, 1, 2);
    let frame1: Dnp3Frame = parse_frame(&hdr).expect("parse_frame");
    let frame2: Dnp3Frame = parse_dnp3(&hdr).expect("parse_dnp3");
    assert_eq!(frame1, frame2);

    let meta: Dnp3Metadata = frame1.to_metadata();
    assert_eq!(meta.destination, 1);
    assert_eq!(meta.source, 2);

    let blk: Dnp3UserDataBlock = parse_user_data_block(&[0xC0]).expect("block");
    let th1: Dnp3TransportHeader = blk.transport_header();
    let th2: TransportHeader = blk.transport;
    assert_eq!(th1, th2);
}
