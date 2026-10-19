//! Integration tests for CCSDS Space Packet primary header parser and per-APID sequence tracker (SPEC §14, §5, §8, Task RER-F-031).

use rer::ccsds::{
    parse_ccsds_primary_header, CcsdsParseError, CcsdsPrimaryHeader, CcsdsSequenceTracker,
    CCSDS_IDLE_APID, CCSDS_PRIMARY_HEADER_LEN, CCSDS_SEQUENCE_MODULUS,
};
use rer::diagnostics::SequenceTrackingEvent;

fn make_packet(
    version: u8,
    packet_type: u8,
    sec_header: bool,
    apid: u16,
    seq_flags: u8,
    seq_count: u16,
    payload_len: usize,
) -> Vec<u8> {
    assert!(payload_len >= 1);
    let data_len_field = (payload_len - 1) as u16;
    let header = CcsdsPrimaryHeader {
        version,
        packet_type,
        secondary_header_flag: sec_header,
        apid,
        sequence_flags: seq_flags,
        sequence_count: seq_count,
        packet_data_length: data_len_field,
        total_packet_length: payload_len + 6,
    };
    let mut bytes = header.to_bytes().to_vec();
    bytes.resize(payload_len + 6, 0x55);
    bytes
}

#[test]
fn test_criterion1_parse_ccsds_primary_header_fields() {
    // 3-bit version = 0
    // 1-bit packet type = 0 (TM)
    // 1-bit secondary header flag = false
    // 11-bit APID = 0x3A5 (933)
    // 2-bit sequence flags = 0b01 (first segment)
    // 14-bit sequence count = 12345
    // packet data length field = 49 (meaning 50 bytes payload)
    // total packet length = 49 + 7 = 56 bytes
    let packet = make_packet(0, 0, false, 933, 1, 12345, 50);
    assert_eq!(packet.len(), 56);

    let parsed = parse_ccsds_primary_header(&packet).expect("valid header must parse");
    assert_eq!(parsed.version, 0);
    assert_eq!(parsed.packet_type, 0);
    assert!(!parsed.secondary_header_flag);
    assert_eq!(parsed.apid, 933);
    assert_eq!(parsed.sequence_flags, 1);
    assert_eq!(parsed.sequence_count, 12345);
    assert_eq!(parsed.packet_data_length, 49);
    assert_eq!(parsed.total_packet_length, 56);

    // Another test with telemetry, secondary header flag true, and telecommand
    let packet_tc = make_packet(0, 1, true, 200, 3, 400, 10);
    let parsed_tc = parse_ccsds_primary_header(&packet_tc).expect("valid tc header");
    assert_eq!(parsed_tc.version, 0);
    assert_eq!(parsed_tc.packet_type, 1);
    assert!(parsed_tc.secondary_header_flag);
    assert_eq!(parsed_tc.apid, 200);
    assert_eq!(parsed_tc.sequence_flags, 3);
    assert_eq!(parsed_tc.sequence_count, 400);
    assert_eq!(parsed_tc.packet_data_length, 9);
    assert_eq!(parsed_tc.total_packet_length, 16);
}

#[test]
fn test_criterion2_buffer_shorter_than_6_bytes_returns_truncated_header() {
    for len in 0..6 {
        let buf = vec![0u8; len];
        assert_eq!(
            parse_ccsds_primary_header(&buf),
            Err(CcsdsParseError::TruncatedHeader),
            "buffer of length {len} must return TruncatedHeader"
        );
    }
}

#[test]
fn test_criterion3_non_zero_version_returns_invalid_version() {
    for version in 1..=7 {
        let mut buf = make_packet(0, 0, false, 10, 3, 0, 5);
        // Overwrite version bits (bits 0..2)
        buf[0] = (buf[0] & 0x1F) | (version << 5);

        assert_eq!(
            parse_ccsds_primary_header(&buf),
            Err(CcsdsParseError::InvalidVersion),
            "version {version} must return InvalidVersion"
        );
    }
}

#[test]
fn test_criterion4_length_less_than_declared_plus_7_returns_length_mismatch() {
    // Declared data length 20 -> total packet length 27 bytes (20 + 7).
    let buf = make_packet(0, 0, false, 10, 3, 0, 21); // data length field = 20, total = 27
    assert_eq!(buf.len(), 27);

    // Truncated buffers: from 6 bytes up to 26 bytes (< 27)
    for len in 6..27 {
        assert_eq!(
            parse_ccsds_primary_header(&buf[..len]),
            Err(CcsdsParseError::LengthMismatch),
            "buffer of length {len} (declared 27) must return LengthMismatch"
        );
    }

    // Exact length (27 bytes) must succeed
    assert!(parse_ccsds_primary_header(&buf[..27]).is_ok());

    // Greater length (e.g. concatenated TCP stream with trailing data) must also succeed
    let mut larger = buf.clone();
    larger.extend_from_slice(&[0xFF; 10]);
    let parsed = parse_ccsds_primary_header(&larger).expect("buffer with extra data succeeds");
    assert_eq!(parsed.total_packet_length, 27);
}

#[test]
fn test_criterion5_independent_per_apid_sequence_tracker_modulo_16384() {
    let mut tracker = CcsdsSequenceTracker::new(false);
    let apid_a: u16 = 100;
    let apid_b: u16 = 200;

    // Sequence progression on APID A:
    // Packet 0: Initial
    assert_eq!(
        tracker.record_sequence(apid_a, 0),
        Some(SequenceTrackingEvent::Initial { sequence: 0 })
    );

    // Sequence progression on APID B:
    // Packet 0: Initial (different start sequence)
    assert_eq!(
        tracker.record_sequence(apid_b, 500),
        Some(SequenceTrackingEvent::Initial { sequence: 500 })
    );

    // APID A receives sequence 1 (in order)
    assert_eq!(
        tracker.record_sequence(apid_a, 1),
        Some(SequenceTrackingEvent::InOrder { sequence: 1 })
    );

    // APID A receives sequence 4 (gap of 2: missing 2, 3)
    assert_eq!(
        tracker.record_sequence(apid_a, 4),
        Some(SequenceTrackingEvent::Gap {
            expected: 2,
            actual: 4,
            missing_count: 2,
        })
    );
    assert_eq!(tracker.gap_count(apid_a), 2);

    // APID A receives sequence 4 again (duplicate)
    assert_eq!(
        tracker.record_sequence(apid_a, 4),
        Some(SequenceTrackingEvent::Duplicate { sequence: 4 })
    );
    assert_eq!(tracker.duplicate_count(apid_a), 1);

    // VERIFY: APID B continuity state is completely unaltered!
    assert_eq!(
        tracker.gap_count(apid_b),
        0,
        "APID B must have 0 gaps despite APID A gaps"
    );
    assert_eq!(
        tracker.duplicate_count(apid_b),
        0,
        "APID B must have 0 duplicates despite APID A duplicates"
    );
    assert_eq!(tracker.last_sequence(apid_b), Some(500));
    assert_eq!(tracker.packets_evaluated(apid_b), 1);

    // APID B advances in-order to 501
    assert_eq!(
        tracker.record_sequence(apid_b, 501),
        Some(SequenceTrackingEvent::InOrder { sequence: 501 })
    );
    assert_eq!(tracker.last_sequence(apid_b), Some(501));
    assert_eq!(tracker.gap_count(apid_b), 0);
    assert_eq!(tracker.duplicate_count(apid_b), 0);

    // Test modulo 16384 rollover independently on a second tracker
    let mut tracker_roll = CcsdsSequenceTracker::new(false);
    assert_eq!(
        tracker_roll.record_sequence(apid_a, 16383),
        Some(SequenceTrackingEvent::Initial { sequence: 16383 })
    );
    assert_eq!(
        tracker_roll.record_sequence(apid_b, 100),
        Some(SequenceTrackingEvent::Initial { sequence: 100 })
    );
    // Rollover on APID A from 16383 to 0
    assert_eq!(
        tracker_roll.record_sequence(apid_a, 0),
        Some(SequenceTrackingEvent::Rollover {
            sequence: 0,
            missing_count: 0,
        })
    );
    assert_eq!(tracker_roll.last_sequence(apid_a), Some(0));
    assert_eq!(tracker_roll.rollover_count(apid_a), 1);
    assert_eq!(tracker_roll.gap_count(apid_a), 0);

    // APID B is unaffected by APID A rollover
    assert_eq!(tracker_roll.last_sequence(apid_b), Some(100));
    assert_eq!(tracker_roll.rollover_count(apid_b), 0);
    assert_eq!(tracker_roll.gap_count(apid_b), 0);
}

#[test]
fn test_criterion6_idle_packet_filtering_ignores_apid_2047() {
    let mut tracker = CcsdsSequenceTracker::new(true); // idle packet filtering enabled

    // Regular traffic on APID 1
    assert_eq!(
        tracker.record_sequence(1, 10),
        Some(SequenceTrackingEvent::Initial { sequence: 10 })
    );

    // Idle packets with APID 2047 arrive with chaotic / non-contiguous sequences
    assert_eq!(tracker.record_sequence(CCSDS_IDLE_APID, 0), None);
    assert_eq!(tracker.record_sequence(CCSDS_IDLE_APID, 100), None);
    assert_eq!(tracker.record_sequence(CCSDS_IDLE_APID, 100), None); // duplicate
    assert_eq!(tracker.record_sequence(CCSDS_IDLE_APID, 5000), None); // large jump

    // Verify APID 2047 records NO sequence continuity gaps, duplicates, or packets
    assert_eq!(tracker.gap_count(CCSDS_IDLE_APID), 0);
    assert_eq!(tracker.duplicate_count(CCSDS_IDLE_APID), 0);
    assert_eq!(tracker.packets_evaluated(CCSDS_IDLE_APID), 0);
    assert_eq!(tracker.last_sequence(CCSDS_IDLE_APID), None);
    assert_eq!(tracker.total_gap_count(), 0);

    // APID 1 receives in-order packet 11
    assert_eq!(
        tracker.record_sequence(1, 11),
        Some(SequenceTrackingEvent::InOrder { sequence: 11 })
    );
    assert_eq!(tracker.gap_count(1), 0);
    assert_eq!(tracker.packets_evaluated(1), 2);
}

#[test]
fn test_ccsds_constants_and_helpers() {
    assert_eq!(CCSDS_PRIMARY_HEADER_LEN, 6);
    assert_eq!(CCSDS_IDLE_APID, 2047);
    assert_eq!(CCSDS_SEQUENCE_MODULUS, 16384);
}
