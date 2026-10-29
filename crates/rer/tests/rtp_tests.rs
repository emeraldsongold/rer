use rer::rtp::{
    encode_rtp_header, evaluate_payload, evaluate_rtp_header, evaluate_rtp_payload, parse_header,
    parse_packet, parse_rtp, parse_rtp_header, parse_rtp_packet, RtpHeader, RtpHeaderExtension,
    RtpPacket, RtpParseError, RtpParseStatus, RtpSequenceTracker, RtpSessionSequenceTracker,
    SequenceTrackingEvent, RTP_FIXED_HEADER_LEN, RTP_HEADER_LEN, RTP_MAX_CSRC_COUNT,
    RTP_SEQUENCE_MODULUS, RTP_VERSION_2,
};

#[test]
fn test_type_and_constant_aliases() {
    assert_eq!(RTP_VERSION_2, 2);
    assert_eq!(RTP_FIXED_HEADER_LEN, 12);
    assert_eq!(RTP_HEADER_LEN, 12);
    assert_eq!(RTP_SEQUENCE_MODULUS, 65536);
    assert_eq!(RTP_MAX_CSRC_COUNT, 15);

    let raw = [0x80, 0x60, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let packet: RtpPacket = parse_packet(&raw).expect("parse_packet");
    assert_eq!(packet.header().payload_type, 96);

    let ext = RtpHeaderExtension {
        profile: 1,
        data: vec![0; 4],
    };
    assert_eq!(ext.profile(), 1);
}

#[test]
fn test_criterion1_parse_12_byte_buffer_returns_matching_fields() {
    // 12-byte buffer:
    // Version 2, PT 96, Sequence number 1000, Timestamp 160000, SSRC 0x12345678
    let raw = [
        0x80, // V=2 (0b10), P=0, X=0, CC=0
        0x60, // M=0, PT=96 (0x60)
        0x03, 0xE8, // Sequence number 1000 (0x03E8)
        0x00, 0x02, 0x71, 0x00, // Timestamp 160000 (0x00027100)
        0x12, 0x34, 0x56, 0x78, // SSRC 0x12345678
    ];

    assert_eq!(raw.len(), 12);

    let header: RtpHeader =
        parse_rtp_header(&raw).expect("12-byte buffer must parse to valid RtpHeader");
    assert_eq!(header.version, 2);
    assert_eq!(header.version(), 2);
    assert_eq!(header.payload_type, 96);
    assert_eq!(header.payload_type(), 96);
    assert_eq!(header.sequence_number, 1000);
    assert_eq!(header.sequence_number(), 1000);
    assert_eq!(header.sequence(), 1000);
    assert_eq!(header.timestamp, 160000);
    assert_eq!(header.timestamp(), 160000);
    assert_eq!(header.ssrc, 0x12345678);
    assert_eq!(header.ssrc(), 0x12345678);

    assert!(!header.padding);
    assert!(!header.extension);
    assert_eq!(header.csrc_count, 0);
    assert!(!header.marker);
    assert_eq!(header.csrc_list, Vec::<u32>::new());
    assert_eq!(header.extension_profile, None);
    assert_eq!(header.extension_data, None);
    assert_eq!(header.header_length, 12);
    assert_eq!(header.payload_offset, 12);

    // Verify all parsing aliases
    assert_eq!(parse_header(&raw).unwrap(), header);
    assert_eq!(parse_rtp(&raw).unwrap(), header);
    assert_eq!(RtpHeader::parse(&raw).unwrap(), header);
    assert_eq!(RtpHeader::from_slice(&raw).unwrap(), header);
    assert_eq!(RtpHeader::from_bytes(&raw).unwrap(), header);
    assert_eq!(RtpHeader::try_from(raw.as_slice()).unwrap(), header);

    // Verify round-trip encoding
    assert_eq!(header.to_bytes(), raw);
}

#[test]
fn test_criterion2_shorter_than_12_bytes_returns_truncated_header_error() {
    for len in 0..12 {
        let buf = vec![0x80u8; len];
        let res = parse_rtp_header(&buf);
        assert_eq!(res, Err(RtpParseError::TruncatedHeader));
        let err = res.unwrap_err();
        assert!(err.is_truncated_header());
        assert!(err.is_truncated());
        assert_eq!(err.status(), RtpParseStatus::TruncatedHeader);
        assert!(err.to_string().to_lowercase().contains("truncated"));
    }
}

#[test]
fn test_criterion3_version_0_1_3_returns_unsupported_version_error() {
    let mut buf = [
        0x80, 0x60, 0x03, 0xE8, 0x00, 0x02, 0x71, 0x00, 0x12, 0x34, 0x56, 0x78,
    ];

    for &v in &[0u8, 1u8, 3u8] {
        buf[0] = (buf[0] & 0x3F) | (v << 6);
        let res = parse_rtp_header(&buf);
        assert_eq!(res, Err(RtpParseError::UnsupportedVersion(v)));
        let err = res.unwrap_err();
        assert!(err.is_unsupported_version());
        assert_eq!(err.unsupported_version(), Some(v));
        assert_eq!(err.status(), RtpParseStatus::UnsupportedVersion);
        assert!(err
            .to_string()
            .to_lowercase()
            .contains("unsupported rtp version"));
    }
}

#[test]
fn test_criterion4_csrc_count_2_fewer_than_8_bytes_returns_truncated_csrc_list() {
    // CC = 2 requires 2 * 4 = 8 bytes of CSRC data
    let base = [
        0x82, // V=2, P=0, X=0, CC=2
        0x60, 0x03, 0xE8, 0x00, 0x02, 0x71, 0x00, 0x12, 0x34, 0x56, 0x78,
    ];

    // 0 bytes of CSRC data (total 12 bytes)
    let res0 = parse_rtp_header(&base);
    assert_eq!(res0, Err(RtpParseError::TruncatedCsrcList));
    let err0 = res0.unwrap_err();
    assert!(err0.is_truncated_csrc_list());
    assert!(err0.is_truncated());
    assert_eq!(err0.status(), RtpParseStatus::TruncatedCsrcList);
    assert!(err0
        .to_string()
        .to_lowercase()
        .contains("truncated csrc list"));

    // 1 to 7 bytes of CSRC data (fewer than 8 bytes)
    for csrc_len in 1..8 {
        let mut buf = base.to_vec();
        buf.extend(vec![0xAA; csrc_len]);
        let res = parse_rtp_header(&buf);
        assert_eq!(res, Err(RtpParseError::TruncatedCsrcList));
        assert!(res.unwrap_err().is_truncated_csrc_list());
    }

    // Exactly 8 bytes of CSRC data succeeds
    let mut buf_valid = base.to_vec();
    buf_valid.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let res_valid = parse_rtp_header(&buf_valid);
    assert!(res_valid.is_ok());
    let hdr = res_valid.unwrap();
    assert_eq!(hdr.csrc_count, 2);
    assert_eq!(hdr.csrc_list, vec![0x01020304, 0x05060708]);
    assert_eq!(hdr.header_length, 20);
    assert_eq!(hdr.payload_offset, 20);
}

#[test]
fn test_criterion5_extension_flag_and_4_byte_extension_header_extracts_profile_and_data() {
    // Base 12-byte header with X=1 (0x90 in byte 0)
    let base = [
        0x90, // V=2, P=0, X=1, CC=0
        0x60, 0x03, 0xE8, 0x00, 0x02, 0x71, 0x00, 0x12, 0x34, 0x56, 0x78,
    ];

    // Case A: 4-byte extension header with length=0 words (0 data bytes)
    let mut buf_ext0 = base.to_vec();
    let profile = 0xBEDEu16;
    buf_ext0.extend_from_slice(&profile.to_be_bytes());
    buf_ext0.extend_from_slice(&0u16.to_be_bytes()); // length in words = 0

    let hdr0 = parse_rtp_header(&buf_ext0).expect("valid 4-byte extension header must parse");
    assert!(hdr0.extension);
    assert!(hdr0.extension_flag());
    assert_eq!(hdr0.extension_profile, Some(profile));
    assert_eq!(hdr0.extension_profile(), Some(profile));
    assert_eq!(hdr0.extension_data, Some(vec![]));
    assert_eq!(hdr0.extension_data(), Some([].as_slice()));
    let ext0 = hdr0.header_extension.as_ref().unwrap();
    assert_eq!(ext0.profile, profile);
    assert_eq!(ext0.data, Vec::<u8>::new());

    // Case B: 4-byte extension header with length=2 words (8 data bytes)
    let mut buf_ext2 = base.to_vec();
    let ext_data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    buf_ext2.extend_from_slice(&profile.to_be_bytes());
    buf_ext2.extend_from_slice(&2u16.to_be_bytes()); // length in words = 2
    buf_ext2.extend_from_slice(&ext_data);

    let hdr2 = parse_rtp_header(&buf_ext2).expect("valid extension with data must parse");
    assert!(hdr2.extension);
    assert_eq!(hdr2.extension_profile, Some(profile));
    assert_eq!(hdr2.extension_profile(), Some(profile));
    assert_eq!(hdr2.extension_data, Some(ext_data.clone()));
    assert_eq!(hdr2.extension_data(), Some(ext_data.as_slice()));
    let ext2 = hdr2.header_extension.as_ref().unwrap();
    assert_eq!(ext2.profile, profile);
    assert_eq!(ext2.data, ext_data);
    assert_eq!(ext2.length_words(), 2);
    assert_eq!(hdr2.header_length, 12 + 4 + 8);

    // Case C: Extension bit set but fewer than 4 bytes available for extension header
    for ext_hdr_len in 0..4 {
        let mut buf_trunc = base.to_vec();
        buf_trunc.extend(vec![0xAA; ext_hdr_len]);
        let err = parse_rtp_header(&buf_trunc).unwrap_err();
        assert_eq!(err, RtpParseError::TruncatedExtensionHeader);
        assert!(err.is_truncated_extension());
    }

    // Case D: Extension header declares length 2 (8 bytes) but fewer than 8 bytes present
    for data_len in 0..8 {
        let mut buf_data_trunc = base.to_vec();
        buf_data_trunc.extend_from_slice(&profile.to_be_bytes());
        buf_data_trunc.extend_from_slice(&2u16.to_be_bytes());
        buf_data_trunc.extend(vec![0xFF; data_len]);
        let err = parse_rtp_header(&buf_data_trunc).unwrap_err();
        assert_eq!(err, RtpParseError::TruncatedExtensionData);
        assert!(err.is_truncated_extension());
    }
}

#[test]
fn test_criterion6_sequence_tracker_rollover_65535_to_0_records_rollover_no_packet_loss() {
    let mut tracker = RtpSequenceTracker::new();

    // Start with sequence number 65535
    let ev1 = tracker.record_sequence(65535);
    assert_eq!(ev1, SequenceTrackingEvent::Initial { sequence: 65535 });
    assert_eq!(tracker.last_sequence(), Some(65535));
    assert_eq!(tracker.gap_count(), 0);
    assert_eq!(tracker.packet_loss(), 0);
    assert_eq!(tracker.rollover_count(), 0);

    // Sequence number 0 immediately follows 65535
    let ev2 = tracker.record_sequence(0);
    assert_eq!(
        ev2,
        SequenceTrackingEvent::Rollover {
            sequence: 0,
            missing_count: 0,
        }
    );
    assert_eq!(tracker.last_sequence(), Some(0));
    assert_eq!(tracker.rollover_count(), 1);
    assert_eq!(
        tracker.gap_count(),
        0,
        "sequence rollover must not report packet loss"
    );
    assert_eq!(
        tracker.packet_loss(),
        0,
        "sequence rollover must not report packet loss"
    );

    // Sequence number 1 immediately follows 0
    let ev3 = tracker.record_sequence(1);
    assert_eq!(ev3, SequenceTrackingEvent::InOrder { sequence: 1 });
    assert_eq!(tracker.gap_count(), 0);
    assert_eq!(tracker.rollover_count(), 1);
}

#[test]
fn test_multi_ssrc_session_tracker() {
    let mut session = RtpSessionSequenceTracker::new();
    let ssrc_a = 0xAAAA_1111;
    let ssrc_b = 0xBBBB_2222;

    assert_eq!(
        session.record_sequence(ssrc_a, 65535),
        SequenceTrackingEvent::Initial { sequence: 65535 }
    );
    assert_eq!(
        session.record_sequence(ssrc_b, 100),
        SequenceTrackingEvent::Initial { sequence: 100 }
    );

    // SSRC A rolls over
    assert_eq!(
        session.record_sequence(ssrc_a, 0),
        SequenceTrackingEvent::Rollover {
            sequence: 0,
            missing_count: 0,
        }
    );
    assert_eq!(session.rollover_count(ssrc_a), 1);
    assert_eq!(session.gap_count(ssrc_a), 0);

    // SSRC B is independent and in-order
    assert_eq!(
        session.record_sequence(ssrc_b, 101),
        SequenceTrackingEvent::InOrder { sequence: 101 }
    );
    assert_eq!(session.rollover_count(ssrc_b), 0);
    assert_eq!(session.gap_count(ssrc_b), 0);

    assert_eq!(session.total_rollover_count(), 1);
    assert_eq!(session.total_gap_count(), 0);
    assert_eq!(session.total_packets_evaluated(), 4);
}

#[test]
fn test_packet_payload_and_padding_parsing() {
    let raw = encode_rtp_header(
        RTP_VERSION_2,
        true, // padding = true
        false,
        true, // marker = true
        97,
        500,
        99999,
        0xDEADBEEF,
        &[],
        None,
    );
    let mut packet_bytes = raw;
    let payload = b"hello rtp payload";
    packet_bytes.extend_from_slice(payload);
    // Add 4 bytes of padding; last byte is 4
    packet_bytes.extend_from_slice(&[0, 0, 0, 4]);

    let parsed = parse_rtp_packet(&packet_bytes).expect("packet with padding must parse");
    assert_eq!(parsed.header.payload_type, 97);
    assert!(parsed.header.marker);
    assert!(parsed.header.padding);
    assert_eq!(parsed.payload, payload);
    assert_eq!(parsed.padding, &[0, 0, 0, 4]);

    let (status, hdr) = evaluate_rtp_header(&packet_bytes);
    assert_eq!(status, RtpParseStatus::Valid);
    assert!(hdr.is_some());
    assert_eq!(evaluate_payload(&packet_bytes), RtpParseStatus::Valid);
    assert_eq!(evaluate_rtp_payload(&packet_bytes), RtpParseStatus::Valid);
}
