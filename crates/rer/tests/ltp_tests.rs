use rer::ltp::{
    decode_sdnv, encode_sdnv, evaluate_ltp_payload, evaluate_payload, evaluate_segment_header,
    parse_data_segment, parse_ltp_header, parse_ltp_segment, parse_segment, parse_segment_header,
    ExtensionTlv, LtpDataSegment, LtpHeader, LtpParseError, LtpParseStatus, LtpSegment,
    LtpSegmentHeader, ReceptionClaim, SegmentType, LTP_VERSION_0,
};

#[test]
fn test_criterion1_parse_valid_ltp_data_segment_rfc5326() {
    // Reference vector 1: Red data segment (not checkpoint)
    // - Version: 0
    // - Segment type: 0 (Red data, not CP, not EORP, not EOB)
    // - Originator Engine ID: 0xABC (SDNV [0x95, 0x3C] per RFC 5326 §2)
    // - Session Number: 0x1234 (SDNV [0xA4, 0x34] per RFC 5326 §2)
    // - Extension count: 0x00
    // - Client Service ID: 1 (Bundle Protocol) -> SDNV [0x01]
    // - Offset: 1000 -> SDNV [0x87, 0x68]
    // - Length: 12 -> SDNV [0x0C]
    // - Payload: "Hello, Space"
    let mut raw = vec![0x00];
    raw.extend_from_slice(&[0x95, 0x3C]); // Engine ID 0xABC
    raw.extend_from_slice(&[0xA4, 0x34]); // Session number 0x1234
    raw.push(0x00); // 0 extensions
    raw.push(0x01); // Client Service ID 1
    raw.extend_from_slice(&encode_sdnv(1000)); // Offset 1000
    raw.extend_from_slice(&encode_sdnv(12)); // Length 12
    raw.extend_from_slice(b"Hello, Space");

    let header = parse_segment(&raw).expect("valid LTP data segment must parse");
    assert_eq!(header.version, 0);
    assert_eq!(header.version(), 0);
    assert_eq!(header.version, LTP_VERSION_0);
    assert_eq!(header.segment_type, SegmentType::RedData);
    assert_eq!(header.segment_type, 0);
    assert_eq!(header.segment_type_code(), 0);
    assert_eq!(header.session_originator_engine_id, 0xABC);
    assert_eq!(header.session_originator, 0xABC);
    assert_eq!(header.session_originator_engine_id(), 0xABC);
    assert_eq!(header.session_originator(), 0xABC);
    assert_eq!(header.session_number, 0x1234);
    assert_eq!(header.session_number(), 0x1234);
    assert_eq!(header.client_service_id, Some(1));
    assert_eq!(header.client_service_id(), Some(1));
    assert_eq!(header.offset, Some(1000));
    assert_eq!(header.offset(), Some(1000));
    assert_eq!(header.length, Some(12));
    assert_eq!(header.length(), Some(12));
    assert_eq!(header.client_data(), b"Hello, Space");

    // Also verify parse_ltp_segment and parse_segment_header aliases
    let alias_seg: LtpSegment = parse_ltp_segment(&raw).expect("parse_ltp_segment must succeed");
    assert_eq!(alias_seg.version, 0);
    assert_eq!(alias_seg.session_originator, 0xABC);

    let parsed_hdr: LtpHeader =
        parse_segment_header(&raw).expect("parse_segment_header must succeed");
    assert_eq!(parsed_hdr.version, 0);
    assert_eq!(parsed_hdr.session_originator_engine_id, 0xABC);

    let full_hdr: LtpSegmentHeader = parse_ltp_header(&raw).expect("parse_ltp_header must succeed");
    assert_eq!(full_hdr.version, 0);
    assert_eq!(full_hdr.session_originator_engine_id, 0xABC);

    // Verify typed LtpDataSegment
    let data_seg: LtpDataSegment =
        parse_data_segment(&raw).expect("parse_data_segment must succeed");
    assert_eq!(data_seg.version, 0);
    assert_eq!(data_seg.segment_type, SegmentType::RedData);
    assert_eq!(data_seg.session_originator_engine_id, 0xABC);
    assert_eq!(data_seg.session_originator, 0xABC);
    assert_eq!(data_seg.session_number, 0x1234);
    assert_eq!(data_seg.client_service_id, 1);
    assert_eq!(data_seg.offset, 1000);
    assert_eq!(data_seg.length, 12);
    assert_eq!(data_seg.client_data, b"Hello, Space");
}

#[test]
fn test_criterion1_parse_green_data_segment() {
    // Green data segment (Type 4: Green data, not EOB)
    // Originator: 99, Session: 1000, Client ID: 2, Offset: 5000, Length: 8
    let mut raw = vec![0x04];
    raw.extend_from_slice(&encode_sdnv(99));
    raw.extend_from_slice(&encode_sdnv(1000));
    raw.push(0x00); // 0 extensions
    raw.extend_from_slice(&encode_sdnv(2));
    raw.extend_from_slice(&encode_sdnv(5000));
    raw.extend_from_slice(&encode_sdnv(8));
    raw.extend_from_slice(b"telemetry");

    let seg = parse_segment(&raw).expect("green data segment must parse");
    assert_eq!(seg.version, 0);
    assert_eq!(seg.segment_type, SegmentType::GreenData);
    assert_eq!(seg.segment_type, 4);
    assert!(seg.segment_type.is_green());
    assert!(!seg.segment_type.is_red());
    assert!(!seg.is_checkpoint());
    assert_eq!(seg.session_originator_engine_id, 99);
    assert_eq!(seg.session_number, 1000);
    assert_eq!(seg.client_service_id, Some(2));
    assert_eq!(seg.offset, Some(5000));
    assert_eq!(seg.length, Some(8));
}

#[test]
fn test_criterion2_parse_checkpoint_segment_extracts_serials() {
    // LTP Checkpoint segment:
    // Type 1: Red data, Checkpoint, NOT EORP, NOT EOB
    let mut raw_cp1 = vec![0x01];
    raw_cp1.extend_from_slice(&encode_sdnv(500));
    raw_cp1.extend_from_slice(&encode_sdnv(101));
    raw_cp1.push(0x00); // 0 extensions
    raw_cp1.extend_from_slice(&encode_sdnv(1)); // Client service ID 1
    raw_cp1.extend_from_slice(&encode_sdnv(0)); // Offset 0
    raw_cp1.extend_from_slice(&encode_sdnv(16)); // Length 16
    raw_cp1.extend_from_slice(&encode_sdnv(42)); // Checkpoint serial number 42
    raw_cp1.extend_from_slice(&encode_sdnv(7)); // Report serial number 7
    raw_cp1.extend_from_slice(&[0xAA; 16]); // 16 bytes of data

    let seg1 = parse_segment(&raw_cp1).expect("checkpoint segment type 1 must parse");
    assert_eq!(seg1.version, 0);
    assert_eq!(seg1.segment_type, SegmentType::RedDataCheckpoint);
    assert_eq!(seg1.segment_type, 1);
    assert!(seg1.is_checkpoint());
    assert_eq!(seg1.checkpoint_serial_number, Some(42));
    assert_eq!(seg1.checkpoint_serial_number(), Some(42));
    assert_eq!(seg1.checkpoint_serial, Some(42));
    assert_eq!(seg1.checkpoint_serial(), Some(42));
    assert_eq!(seg1.report_serial_number, Some(7));
    assert_eq!(seg1.report_serial_number(), Some(7));
    assert_eq!(seg1.report_serial, Some(7));
    assert_eq!(seg1.report_serial(), Some(7));

    // Type 2: Red data, Checkpoint, EORP, NOT EOB
    let mut raw_cp2 = vec![0x02];
    raw_cp2.extend_from_slice(&encode_sdnv(10));
    raw_cp2.extend_from_slice(&encode_sdnv(20));
    raw_cp2.push(0x00);
    raw_cp2.extend_from_slice(&encode_sdnv(1));
    raw_cp2.extend_from_slice(&encode_sdnv(100));
    raw_cp2.extend_from_slice(&encode_sdnv(4));
    raw_cp2.extend_from_slice(&encode_sdnv(88)); // CP serial 88
    raw_cp2.extend_from_slice(&encode_sdnv(0)); // Report serial 0
    raw_cp2.extend_from_slice(b"eorp");

    let seg2 = parse_segment(&raw_cp2).expect("checkpoint segment type 2 must parse");
    assert!(seg2.is_checkpoint());
    assert!(seg2.is_eorp());
    assert!(!seg2.is_eob());
    assert_eq!(seg2.checkpoint_serial_number, Some(88));
    assert_eq!(seg2.report_serial_number, Some(0));

    // Type 3: Red data, Checkpoint, EORP, EOB
    let mut raw_cp3 = vec![0x03];
    raw_cp3.extend_from_slice(&encode_sdnv(1));
    raw_cp3.extend_from_slice(&encode_sdnv(2));
    raw_cp3.push(0x00);
    raw_cp3.extend_from_slice(&encode_sdnv(1));
    raw_cp3.extend_from_slice(&encode_sdnv(500));
    raw_cp3.extend_from_slice(&encode_sdnv(3));
    raw_cp3.extend_from_slice(&encode_sdnv(999)); // CP serial 999
    raw_cp3.extend_from_slice(&encode_sdnv(15)); // Report serial 15
    raw_cp3.extend_from_slice(b"end");

    let seg3 = parse_segment(&raw_cp3).expect("checkpoint segment type 3 must parse");
    assert!(seg3.is_checkpoint());
    assert!(seg3.is_eorp());
    assert!(seg3.is_eob());
    assert_eq!(seg3.checkpoint_serial_number, Some(999));
    assert_eq!(seg3.report_serial_number, Some(15));
}

#[test]
fn test_criterion3_truncated_sdnv_returns_truncated_error() {
    // 1-byte buffer with continuation bit set
    let single_byte = [0x80];
    let err = decode_sdnv(&single_byte).expect_err("truncated SDNV must error");
    assert!(err.is_truncated());
    assert!(matches!(err, LtpParseError::Truncated { .. }));
    assert!(err.to_string().contains("truncated input"));

    // 2-byte buffer with continuation bit set on both
    let two_bytes = [0x85, 0x90];
    let err2 = decode_sdnv(&two_bytes).expect_err("truncated SDNV must error");
    assert!(err2.is_truncated());
    assert!(matches!(err2, LtpParseError::Truncated { .. }));
    assert!(err2.to_string().contains("truncated input"));

    // 3-byte buffer with continuation bit set on all 3
    let three_bytes = [0x81, 0x82, 0x83];
    let err3 = decode_sdnv(&three_bytes).expect_err("truncated SDNV must error");
    assert!(err3.is_truncated());
    assert!(matches!(err3, LtpParseError::Truncated { .. }));
    assert_eq!(err3.status(), LtpParseStatus::Truncated);
}

#[test]
fn test_criterion4_non_zero_ltp_version_distinguishes_invalid_version() {
    // Version 1 (byte 0x10)
    let v1 = [0x10, 0x01, 0x01, 0x00];
    let err1 = parse_segment_header(&v1).expect_err("version 1 must error");
    assert!(err1.is_invalid_version());
    assert_eq!(err1, LtpParseError::InvalidVersion(1));
    assert!(err1.to_string().contains("invalid LTP version: 1"));

    // Version 2 (byte 0x20)
    let v2 = [0x20, 0x01, 0x01, 0x00];
    let err2 = parse_segment_header(&v2).expect_err("version 2 must error");
    assert!(err2.is_invalid_version());
    assert_eq!(err2, LtpParseError::InvalidVersion(2));

    // Version 15 (byte 0xF0)
    let v15 = [0xF0, 0x01, 0x01, 0x00];
    let err15 = parse_segment(&v15).expect_err("version 15 must error");
    assert!(err15.is_invalid_version());
    assert_eq!(err15, LtpParseError::InvalidVersion(15));
}

#[test]
fn test_criterion5_evaluating_arbitrary_non_ltp_payloads() {
    let arbitrary_inputs: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!",
        b"POST /api/telemetry HTTP/1.1\r\nHost: dtn.example.org\r\n\r\n",
        b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06", // IPv4 packet header
        &[0x88, 0x07, 0x00, 0x00],                   // CBOR array
        &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB],
        &[0x05, 0x01, 0x01, 0x00], // Version 0, undefined type 5
        &[0x06, 0x01, 0x01, 0x00], // Version 0, undefined type 6
        &[0x0A, 0x01, 0x01, 0x00], // Version 0, undefined type 10
        &[0x0B, 0x01, 0x01, 0x00], // Version 0, undefined type 11
    ];

    for input in arbitrary_inputs {
        let status = evaluate_payload(input);
        assert!(
            status.is_not_ltp() || status.is_malformed(),
            "arbitrary non-LTP input must return NotLtp or MalformedLtp, got {status:?}"
        );
        assert!(!status.is_valid());
        assert!(status.is_invalid());

        let alias = evaluate_ltp_payload(input);
        assert_eq!(alias, status);

        let (hdr_status, hdr_opt) = evaluate_segment_header(input);
        assert_eq!(hdr_status, status);
        assert!(hdr_opt.is_none());
    }
}

#[test]
fn test_report_segment_rfc5326() {
    // Report Segment (RS, Type 8)
    // - Originator Engine: 1
    // - Session Number: 200 (encoded as [0x81, 0x48])
    // - Extensions count: 0x00
    // - Report serial number: 5
    // - Checkpoint serial number: 42
    // - Upper bound: 6000 (encoded as [0xAE, 0x70])
    // - Lower bound: 0
    // - Claim count: 1
    // - Claim 0: offset 0, length 6000
    let mut raw = vec![0x08];
    raw.extend_from_slice(&encode_sdnv(1));
    raw.extend_from_slice(&encode_sdnv(200));
    raw.push(0x00);
    raw.extend_from_slice(&encode_sdnv(5)); // Report serial 5
    raw.extend_from_slice(&encode_sdnv(42)); // CP serial 42
    raw.extend_from_slice(&encode_sdnv(6000)); // Upper bound 6000
    raw.extend_from_slice(&encode_sdnv(0)); // Lower bound 0
    raw.extend_from_slice(&encode_sdnv(1)); // 1 claim
    raw.extend_from_slice(&encode_sdnv(0)); // Claim offset 0
    raw.extend_from_slice(&encode_sdnv(6000)); // Claim length 6000

    let seg = parse_segment(&raw).expect("report segment must parse");
    assert_eq!(seg.version, 0);
    assert_eq!(seg.segment_type, SegmentType::Report);
    assert_eq!(seg.segment_type, 8);
    assert!(seg.is_report());
    assert_eq!(seg.report_serial_number, Some(5));
    assert_eq!(seg.checkpoint_serial_number, Some(42));
    assert_eq!(seg.report_upper_bound, Some(6000));
    assert_eq!(seg.report_lower_bound, Some(0));
    assert_eq!(seg.reception_claims.len(), 1);
    let claim: ReceptionClaim = seg.reception_claims[0];
    assert_eq!(claim.offset, 0);
    assert_eq!(claim.length, 6000);
}

#[test]
fn test_report_ack_segment_rfc5326() {
    // Report-Acknowledgment Segment (RAx, Type 9)
    // - Originator Engine: 1
    // - Session Number: 200
    // - Extensions count: 0x00
    // - Report serial number: 5
    let mut raw = vec![0x09];
    raw.extend_from_slice(&encode_sdnv(1));
    raw.extend_from_slice(&encode_sdnv(200));
    raw.push(0x00);
    raw.extend_from_slice(&encode_sdnv(5));

    let seg = parse_segment(&raw).expect("report ack segment must parse");
    assert_eq!(seg.version, 0);
    assert_eq!(seg.segment_type, SegmentType::ReportAck);
    assert_eq!(seg.segment_type, 9);
    assert!(seg.is_report_ack());
    assert_eq!(seg.report_serial_number, Some(5));
}

#[test]
fn test_cancel_segment_rfc5326() {
    // Cancel from sender (CS, Type 12)
    // Reason code: 0x02 (RLEXC - Retransmission limit exceeded)
    let mut raw = vec![0x0C];
    raw.extend_from_slice(&encode_sdnv(1));
    raw.extend_from_slice(&encode_sdnv(55));
    raw.push(0x00);
    raw.push(0x02); // Reason code 2

    let seg = parse_segment(&raw).expect("cancel segment must parse");
    assert_eq!(seg.version, 0);
    assert_eq!(seg.segment_type, SegmentType::CancelFromSender);
    assert_eq!(seg.segment_type, 12);
    assert!(seg.is_cancel());
    assert_eq!(seg.cancel_reason_code, Some(2));
}

#[test]
fn test_header_extensions_rfc5326() {
    // Data segment with 1 header extension:
    // Tag 0x00 (LTP authentication extension per RFC 5327 / RFC 5326 §3.1.4)
    // Ext length: 4, value: [0xDE, 0xAD, 0xBE, 0xEF]
    let mut raw = vec![0x00];
    raw.extend_from_slice(&encode_sdnv(10));
    raw.extend_from_slice(&encode_sdnv(20));
    raw.push(0x10); // 1 header extension, 0 trailer extensions
    raw.push(0x00); // Tag 0x00
    raw.extend_from_slice(&encode_sdnv(4)); // Extension length 4
    raw.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    // Client data fields
    raw.extend_from_slice(&encode_sdnv(1)); // Client service ID 1
    raw.extend_from_slice(&encode_sdnv(0)); // Offset 0
    raw.extend_from_slice(&encode_sdnv(3)); // Length 3
    raw.extend_from_slice(b"abc");

    let seg = parse_segment(&raw).expect("segment with header extension must parse");
    assert_eq!(seg.header_extensions_count, 1);
    assert_eq!(seg.trailer_extensions_count, 0);
    assert_eq!(seg.header_extensions.len(), 1);
    let ext: &ExtensionTlv = &seg.header_extensions[0];
    assert_eq!(ext.tag, 0x00);
    assert_eq!(ext.length, 4);
    assert_eq!(ext.value, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(seg.client_data(), b"abc");
}
