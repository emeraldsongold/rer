//! Integration tests for in-tree MAVLink packet header parser (SPEC §14, §8, Task RER-F-050).

use std::process::Command;

use rer::mavlink::{
    encode_mavlink1_header, encode_mavlink2_header, evaluate_header, evaluate_mavlink,
    evaluate_mavlink_2_packet, evaluate_mavlink_header, evaluate_mavlink_packet,
    evaluate_mavlink_payload, evaluate_packet, evaluate_payload, parse_header,
    parse_mavlink_header, parse_mavlink_packet, parse_packet, MavlinkHeader, MavlinkParseError,
    MavlinkParseStatus, MavlinkParseWarning, MavlinkVersion, MAVLINK_IFLAG_SIGNED,
    MAVLINK_KNOWN_INCOMPAT_FLAGS, MAVLINK_MAGIC_V1, MAVLINK_MAGIC_V2, MAVLINK_SIGNATURE_LEN,
    MAVLINK_STX_V1, MAVLINK_STX_V2, MAVLINK_V1_FRAMING_OVERHEAD, MAVLINK_V1_HEADER_LEN,
    MAVLINK_V1_MIN_HEADER_LEN, MAVLINK_V1_OVERHEAD, MAVLINK_V1_STX,
    MAVLINK_V2_FRAMING_OVERHEAD_SIGNED, MAVLINK_V2_FRAMING_OVERHEAD_UNSIGNED,
    MAVLINK_V2_HEADER_LEN, MAVLINK_V2_MIN_HEADER_LEN, MAVLINK_V2_OVERHEAD_SIGNED,
    MAVLINK_V2_OVERHEAD_UNSIGNED, MAVLINK_V2_STX,
};

fn make_v1_packet(payload_len: u8, seq: u8, sysid: u8, compid: u8, msgid: u8) -> Vec<u8> {
    let mut buf = encode_mavlink1_header(payload_len, seq, sysid, compid, msgid).to_vec();
    buf.resize(buf.len() + usize::from(payload_len), 0xDD);
    buf.extend_from_slice(&[0x12, 0x34]); // 2 bytes CRC
    buf
}

fn make_v2_packet(
    payload_len: u8,
    incompat_flags: u8,
    compat_flags: u8,
    seq: u8,
    sysid: u8,
    compid: u8,
    msgid: u32,
) -> Vec<u8> {
    let mut buf = encode_mavlink2_header(
        payload_len,
        incompat_flags,
        compat_flags,
        seq,
        sysid,
        compid,
        msgid,
    )
    .to_vec();
    buf.resize(buf.len() + usize::from(payload_len), 0xEE);
    buf.extend_from_slice(&[0x56, 0x78]); // 2 bytes CRC
    if (incompat_flags & MAVLINK_IFLAG_SIGNED) != 0 {
        buf.resize(buf.len() + MAVLINK_SIGNATURE_LEN, 0x99);
    }
    buf
}

#[test]
fn test_criterion1_mavlink1_parsing() {
    // Acceptance criterion 1:
    // In crates/rer/src/mavlink.rs, parsing a buffer beginning with magic byte 0xFE extracts
    // MAVLink 1 sequence number, system ID, component ID, 8-bit message ID, and total packet length
    // calculated as payload length plus 8 bytes.
    let payload_lens: [u8; 4] = [0, 1, 50, 255];
    for len in payload_lens {
        let seq = 42u8;
        let sysid = 1u8;
        let compid = 200u8;
        let msgid = 76u8;

        let packet = make_v1_packet(len, seq, sysid, compid, msgid);
        assert_eq!(packet[0], 0xFE);
        assert_eq!(packet.len(), usize::from(len) + 8);

        let parsed: MavlinkHeader =
            parse_mavlink_header(&packet).expect("valid MAVLink 1 packet must parse");
        assert_eq!(parsed.version, MavlinkVersion::V1);
        assert!(parsed.is_v1());
        assert!(!parsed.is_v2());
        assert_eq!(parsed.sequence, seq);
        assert_eq!(parsed.sequence_number(), seq);
        assert_eq!(parsed.system_id, sysid);
        assert_eq!(parsed.sysid(), sysid);
        assert_eq!(parsed.component_id, compid);
        assert_eq!(parsed.compid(), compid);
        assert_eq!(parsed.message_id, u32::from(msgid));
        assert_eq!(parsed.msgid(), u32::from(msgid));
        assert_eq!(parsed.payload_length, len);
        assert_eq!(parsed.total_packet_length, usize::from(len) + 8);
        assert_eq!(parsed.packet_length(), usize::from(len) + 8);
        assert!(!parsed.is_signed);

        // Alias function checks
        let parsed_alias = parse_header(&packet).expect("parse_header alias");
        assert_eq!(parsed_alias, parsed);
        let parsed_pkt = parse_packet(&packet).expect("parse_packet alias");
        assert_eq!(parsed_pkt, parsed);
        let parsed_mavlink_pkt = parse_mavlink_packet(&packet).expect("parse_mavlink_packet alias");
        assert_eq!(parsed_mavlink_pkt, parsed);
    }
}

#[test]
fn test_criterion2_mavlink2_unsigned_parsing() {
    // Acceptance criterion 2:
    // In crates/rer/src/mavlink.rs, parsing a buffer beginning with magic byte 0xFD without signature flag
    // extracts MAVLink 2 sequence number, system ID, component ID, 24-bit little-endian message ID,
    // and total packet length calculated as payload length plus 12 bytes.
    let payload_lens: [u8; 4] = [0, 1, 100, 255];
    for len in payload_lens {
        let seq = 123u8;
        let sysid = 10u8;
        let compid = 20u8;
        // 24-bit little-endian message ID: 0x123456 (byte 7: 0x56, byte 8: 0x34, byte 9: 0x12)
        let msgid = 0x123456u32;

        let packet = make_v2_packet(len, 0, 0, seq, sysid, compid, msgid);
        assert_eq!(packet[0], 0xFD);
        assert_eq!(packet[2] & 0x01, 0); // No signature flag
        assert_eq!(packet.len(), usize::from(len) + 12);

        // Verify little-endian wire bytes
        assert_eq!(packet[7], 0x56);
        assert_eq!(packet[8], 0x34);
        assert_eq!(packet[9], 0x12);

        let parsed =
            parse_mavlink_header(&packet).expect("valid unsigned MAVLink 2 packet must parse");
        assert_eq!(parsed.version, MavlinkVersion::V2);
        assert!(parsed.is_v2());
        assert!(!parsed.is_v1());
        assert_eq!(parsed.sequence, seq);
        assert_eq!(parsed.sequence_number(), seq);
        assert_eq!(parsed.system_id, sysid);
        assert_eq!(parsed.sysid(), sysid);
        assert_eq!(parsed.component_id, compid);
        assert_eq!(parsed.compid(), compid);
        assert_eq!(parsed.message_id, msgid);
        assert_eq!(parsed.msgid(), msgid);
        assert_eq!(parsed.payload_length, len);
        assert_eq!(parsed.total_packet_length, usize::from(len) + 12);
        assert_eq!(parsed.packet_length(), usize::from(len) + 12);
        assert!(!parsed.is_signed);
        assert!(!parsed.has_warning());
    }
}

#[test]
fn test_criterion3_mavlink2_signed_parsing() {
    // Acceptance criterion 3:
    // In crates/rer/src/mavlink.rs, parsing a buffer beginning with magic byte 0xFD with incompatibility flag bit 0 set
    // calculates total packet length as payload length plus 25 bytes.
    let payload_lens: [u8; 4] = [0, 5, 64, 255];
    for len in payload_lens {
        let seq = 77u8;
        let sysid = 5u8;
        let compid = 15u8;
        let msgid = 300u32;
        let incompat = MAVLINK_IFLAG_SIGNED; // bit 0 set (0x01)

        let packet = make_v2_packet(len, incompat, 0, seq, sysid, compid, msgid);
        assert_eq!(packet[0], 0xFD);
        assert_eq!(packet[2] & 0x01, 1);
        assert_eq!(packet.len(), usize::from(len) + 25);

        let parsed =
            parse_mavlink_header(&packet).expect("valid signed MAVLink 2 packet must parse");
        assert_eq!(parsed.version, MavlinkVersion::V2);
        assert!(parsed.is_signed);
        assert_eq!(parsed.incompat_flags, MAVLINK_IFLAG_SIGNED);
        assert_eq!(parsed.sequence, seq);
        assert_eq!(parsed.system_id, sysid);
        assert_eq!(parsed.component_id, compid);
        assert_eq!(parsed.message_id, msgid);
        assert_eq!(parsed.payload_length, len);
        assert_eq!(parsed.total_packet_length, usize::from(len) + 25);
        assert_eq!(parsed.packet_length(), usize::from(len) + 25);
    }
}

#[test]
fn test_criterion4_invalid_magic_marker_error() {
    // Acceptance criterion 4:
    // In crates/rer/src/mavlink.rs, parsing an input buffer whose first byte is neither 0xFE nor 0xFD
    // returns an error indicating an invalid magic marker.
    let bad_bytes: [u8; 6] = [0x00, 0x42, 0xAA, 0xFC, 0xFF, 0x7E];
    for b in bad_bytes {
        let buf = [b, 10, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = parse_mavlink_header(&buf).expect_err("non-magic byte must error");
        assert_eq!(err, MavlinkParseError::InvalidMagicMarker);
        assert!(err.is_invalid_magic_marker());
        assert!(err.is_invalid_magic());
        assert!(!err.is_truncated());
        assert!(format!("{err}")
            .to_lowercase()
            .contains("invalid magic marker"));

        let (status, hdr) = evaluate_mavlink_header(&buf);
        assert_eq!(status, MavlinkParseStatus::InvalidMagic);
        assert!(status.is_invalid_magic());
        assert!(hdr.is_none());

        let status_payload = evaluate_payload(&buf);
        assert_eq!(status_payload, MavlinkParseStatus::InvalidMagic);
    }
}

#[test]
fn test_criterion5_truncated_packet_error() {
    // Acceptance criterion 5:
    // In crates/rer/src/mavlink.rs, parsing an input buffer shorter than minimal header length
    // or shorter than declared total packet length returns an error indicating a truncated packet.

    // 1. Empty buffer
    let empty: &[u8] = &[];
    let err_empty = parse_mavlink_header(empty).expect_err("empty buffer must error");
    assert_eq!(err_empty, MavlinkParseError::TruncatedPacket);
    assert!(err_empty.is_truncated_packet());
    assert!(err_empty.is_truncated());
    assert!(format!("{err_empty}")
        .to_lowercase()
        .contains("truncated packet"));

    // 2. MAVLink 1: minimal header length is 6 bytes
    let v1_pkt = make_v1_packet(10, 1, 1, 1, 1); // 10 + 8 = 18 bytes
    for len in 1..6 {
        let err = parse_mavlink_header(&v1_pkt[..len]).expect_err("shorter than v1 header");
        assert_eq!(err, MavlinkParseError::TruncatedPacket);
        assert!(err.is_truncated());
    }

    // 3. MAVLink 1: shorter than declared total packet length (6..18)
    for len in 6..18 {
        let err =
            parse_mavlink_header(&v1_pkt[..len]).expect_err("shorter than declared packet length");
        assert_eq!(err, MavlinkParseError::TruncatedPacket);
        assert!(err.is_truncated());
    }
    // Exactly 18 bytes succeeds
    assert!(parse_mavlink_header(&v1_pkt[..18]).is_ok());

    // 4. MAVLink 2: minimal header length is 10 bytes
    let v2_pkt = make_v2_packet(8, 0, 0, 1, 1, 1, 1); // 8 + 12 = 20 bytes
    for len in 1..10 {
        let err = parse_mavlink_header(&v2_pkt[..len]).expect_err("shorter than v2 header");
        assert_eq!(err, MavlinkParseError::TruncatedPacket);
        assert!(err.is_truncated());
    }

    // 5. MAVLink 2: shorter than declared total packet length (10..20)
    for len in 10..20 {
        let err =
            parse_mavlink_header(&v2_pkt[..len]).expect_err("shorter than declared packet length");
        assert_eq!(err, MavlinkParseError::TruncatedPacket);
        assert!(err.is_truncated());
    }
    // Exactly 20 bytes succeeds
    assert!(parse_mavlink_header(&v2_pkt[..20]).is_ok());

    // 6. MAVLink 2 signed: shorter than declared total packet length (10 + 25 = 35)
    let v2_signed = make_v2_packet(10, MAVLINK_IFLAG_SIGNED, 0, 1, 1, 1, 1);
    for len in 10..35 {
        let err = parse_mavlink_header(&v2_signed[..len]).expect_err("shorter than signed length");
        assert_eq!(err, MavlinkParseError::TruncatedPacket);
        assert!(err.is_truncated());
    }
    assert!(parse_mavlink_header(&v2_signed[..35]).is_ok());
}

#[test]
fn test_criterion6_unknown_incompatibility_flag_warning() {
    // Acceptance criterion 6:
    // In crates/rer/src/mavlink.rs, evaluating a MAVLink 2 packet with unknown incompatibility flag bits
    // returns a parse warning while preserving extracted header metadata.

    // Bit 1 (0x02) is unknown
    let unknown_flag = 0x02u8;
    let packet = make_v2_packet(12, unknown_flag, 0, 88, 7, 8, 9999);

    // 1. Parsing directly succeeds and preserves extracted metadata
    let header = parse_mavlink_header(&packet).expect("parsing must succeed");
    assert_eq!(header.sequence, 88);
    assert_eq!(header.system_id, 7);
    assert_eq!(header.component_id, 8);
    assert_eq!(header.message_id, 9999);
    assert_eq!(header.incompat_flags, unknown_flag);
    assert!(header.has_warning());
    assert_eq!(
        header.warning(),
        Some(MavlinkParseWarning::UnknownIncompatibilityFlags(
            unknown_flag
        ))
    );

    // 2. Evaluating returns parse warning while preserving extracted header metadata
    let (status, header_opt) = evaluate_mavlink_header(&packet);
    assert!(status.is_warning());
    assert!(status.has_warning());
    assert_eq!(
        status,
        MavlinkParseStatus::Warning(MavlinkParseWarning::UnknownIncompatibilityFlags(
            unknown_flag
        ))
    );
    assert_eq!(
        status,
        MavlinkParseWarning::UnknownIncompatibilityFlags(unknown_flag)
    );

    let preserved = header_opt.expect("extracted header metadata must be preserved");
    assert_eq!(preserved.version, MavlinkVersion::V2);
    assert_eq!(preserved.sequence, 88);
    assert_eq!(preserved.system_id, 7);
    assert_eq!(preserved.component_id, 8);
    assert_eq!(preserved.message_id, 9999);
    assert_eq!(preserved.payload_length, 12);
    assert_eq!(preserved.total_packet_length, 12 + 12);

    // 3. Aliases evaluation checks
    let (eval_status, eval_hdr) = evaluate_mavlink_packet(&packet);
    assert!(eval_status.is_warning());
    assert_eq!(eval_hdr, Some(preserved));

    let (pkt_status, pkt_hdr) = evaluate_packet(&packet);
    assert!(pkt_status.is_warning());
    assert_eq!(pkt_hdr, Some(preserved));

    let (hdr_status, hdr_hdr) = evaluate_header(&packet);
    assert!(hdr_status.is_warning());
    assert_eq!(hdr_hdr, Some(preserved));

    let (m2_status, m2_hdr) = evaluate_mavlink_2_packet(&packet);
    assert!(m2_status.is_warning());
    assert_eq!(m2_hdr, Some(preserved));

    let (mav_status, mav_hdr) = evaluate_mavlink(&packet);
    assert!(mav_status.is_warning());
    assert_eq!(mav_hdr, Some(preserved));

    let payload_status = evaluate_payload(&packet);
    assert!(payload_status.is_warning());

    let mav_payload_status = evaluate_mavlink_payload(&packet);
    assert!(mav_payload_status.is_warning());
}

#[test]
fn test_constants_and_aliases() {
    assert_eq!(MAVLINK_STX_V1, 0xFE);
    assert_eq!(MAVLINK_V1_STX, 0xFE);
    assert_eq!(MAVLINK_MAGIC_V1, 0xFE);
    assert_eq!(MAVLINK_STX_V2, 0xFD);
    assert_eq!(MAVLINK_V2_STX, 0xFD);
    assert_eq!(MAVLINK_MAGIC_V2, 0xFD);
    assert_eq!(MAVLINK_V1_HEADER_LEN, 6);
    assert_eq!(MAVLINK_V1_MIN_HEADER_LEN, 6);
    assert_eq!(MAVLINK_V2_HEADER_LEN, 10);
    assert_eq!(MAVLINK_V2_MIN_HEADER_LEN, 10);
    assert_eq!(MAVLINK_V1_OVERHEAD, 8);
    assert_eq!(MAVLINK_V1_FRAMING_OVERHEAD, 8);
    assert_eq!(MAVLINK_V2_OVERHEAD_UNSIGNED, 12);
    assert_eq!(MAVLINK_V2_FRAMING_OVERHEAD_UNSIGNED, 12);
    assert_eq!(MAVLINK_V2_OVERHEAD_SIGNED, 25);
    assert_eq!(MAVLINK_V2_FRAMING_OVERHEAD_SIGNED, 25);
    assert_eq!(MAVLINK_SIGNATURE_LEN, 13);
    assert_eq!(MAVLINK_IFLAG_SIGNED, 0x01);
    assert_eq!(MAVLINK_KNOWN_INCOMPAT_FLAGS, 0x01);
}

// ---------------------------------------------------------------------------
// Task RER-F-051 Acceptance Criteria Tests
// ---------------------------------------------------------------------------

#[test]
fn test_f051_criterion1_independent_per_source_sequence_tracking() {
    // Acceptance criterion: In crates/rer/src/mavlink.rs, sequence tracking maintains 8-bit
    // sequence counters modulo 256 independently for two distinct system and component identifier sources,
    // detecting a sequence gap on one source without altering continuity state on the other source.
    use rer::diagnostics::SequenceTrackingEvent;
    use rer::mavlink::MavlinkSequenceTracker;

    let mut tracker = MavlinkSequenceTracker::new();
    let sys_1 = 1u8;
    let comp_1 = 1u8;
    let sys_2 = 2u8;
    let comp_2 = 1u8;

    // Initial packets on distinct sources
    assert_eq!(
        tracker.record_sequence(sys_1, comp_1, 10),
        Some(SequenceTrackingEvent::Initial { sequence: 10 })
    );
    assert_eq!(
        tracker.record_sequence(sys_2, comp_2, 200),
        Some(SequenceTrackingEvent::Initial { sequence: 200 })
    );

    // Source 1 advances in-order
    assert_eq!(
        tracker.record_sequence(sys_1, comp_1, 11),
        Some(SequenceTrackingEvent::InOrder { sequence: 11 })
    );

    // Source 1 experiences a sequence gap: jumps from 11 to 15 (missing 12, 13, 14 -> 3 packets)
    assert_eq!(
        tracker.record_sequence(sys_1, comp_1, 15),
        Some(SequenceTrackingEvent::Gap {
            expected: 12,
            actual: 15,
            missing_count: 3,
        })
    );
    assert_eq!(tracker.gap_count(sys_1, comp_1), 3);
    assert_eq!(tracker.last_sequence(sys_1, comp_1), Some(15));

    // VERIFY: Source 2 continuity state is completely unaltered!
    assert_eq!(
        tracker.gap_count(sys_2, comp_2),
        0,
        "Source 2 must have 0 gaps despite Source 1 sequence gap"
    );
    assert_eq!(
        tracker.duplicate_count(sys_2, comp_2),
        0,
        "Source 2 must have 0 duplicates"
    );
    assert_eq!(tracker.last_sequence(sys_2, comp_2), Some(200));
    assert_eq!(tracker.packets_evaluated(sys_2, comp_2), 1);

    // Source 2 advances in-order to 201 without disruption
    assert_eq!(
        tracker.record_sequence(sys_2, comp_2, 201),
        Some(SequenceTrackingEvent::InOrder { sequence: 201 })
    );
    assert_eq!(tracker.last_sequence(sys_2, comp_2), Some(201));
    assert_eq!(tracker.gap_count(sys_2, comp_2), 0);
}

#[test]
fn test_f051_criterion2_duplicate_sequence_number_tracking() {
    // Acceptance criterion: In crates/rer/src/mavlink.rs, sequence tracking receiving a duplicate
    // sequence number for an existing source increments duplicate counters and identifies duplicate
    // packets without dropping traffic.
    use rer::diagnostics::SequenceTrackingEvent;
    use rer::mavlink::MavlinkSequenceTracker;

    let mut tracker = MavlinkSequenceTracker::new();
    let sys = 1u8;
    let comp = 1u8;

    assert_eq!(
        tracker.record_sequence(sys, comp, 50),
        Some(SequenceTrackingEvent::Initial { sequence: 50 })
    );
    assert_eq!(
        tracker.record_sequence(sys, comp, 51),
        Some(SequenceTrackingEvent::InOrder { sequence: 51 })
    );

    // Receive duplicate sequence 51
    assert!(tracker.is_duplicate(sys, comp, 51));
    assert_eq!(
        tracker.record_sequence(sys, comp, 51),
        Some(SequenceTrackingEvent::Duplicate { sequence: 51 })
    );
    assert_eq!(tracker.duplicate_count(sys, comp), 1);
    assert_eq!(tracker.total_duplicate_count(), 1);
    assert_eq!(tracker.last_sequence(sys, comp), Some(51));

    // Subsequent in-order packet
    assert_eq!(
        tracker.record_sequence(sys, comp, 52),
        Some(SequenceTrackingEvent::InOrder { sequence: 52 })
    );

    // Receive duplicate sequence 51 again (out-of-order duplicate)
    assert!(tracker.is_duplicate(sys, comp, 51));
    assert_eq!(
        tracker.record_sequence(sys, comp, 51),
        Some(SequenceTrackingEvent::Duplicate { sequence: 51 })
    );
    assert_eq!(tracker.duplicate_count(sys, comp), 2);
    assert_eq!(tracker.total_duplicate_count(), 2);
    // last_sequence is preserved at 52
    assert_eq!(tracker.last_sequence(sys, comp), Some(52));
}

#[test]
fn test_f051_criterion3_diagnostic_event_mavlink_serialization() {
    // Acceptance criterion: In crates/rer/src/diagnostics.rs, serializing a DiagnosticEvent
    // containing MAVLink system ID, component ID, sequence number, and 24-bit message ID
    // produces a JSON object containing the structured MAVLink metadata fields.
    use rer::config::TransportType;
    use rer::diagnostics::{DiagnosticEvent, DiagnosticStage};

    let msgid_24bit = 16_777_215u32; // 0xFFFFFF
    let event = DiagnosticEvent::new(
        1000,
        2000,
        "mavlink-test-stream",
        DiagnosticStage::MavlinkInspection,
        TransportType::Udp,
        1400,
    )
    .with_mavlink_system_id(1)
    .with_mavlink_component_id(2)
    .with_mavlink_sequence(42)
    .with_mavlink_message_id(msgid_24bit);

    let json_str = serde_json::to_string(&event).expect("serialize event to JSON");
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("parse JSON");
    let obj = val.as_object().expect("expected JSON object");

    // Top-level structured fields
    assert_eq!(
        obj.get("mavlink_system_id").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        obj.get("mavlink_component_id").and_then(|v| v.as_u64()),
        Some(2)
    );
    assert_eq!(
        obj.get("mavlink_sequence").and_then(|v| v.as_u64()),
        Some(42)
    );
    assert_eq!(
        obj.get("sequence_number").and_then(|v| v.as_u64()),
        Some(42)
    );
    assert_eq!(
        obj.get("mavlink_message_id").and_then(|v| v.as_u64()),
        Some(u64::from(msgid_24bit))
    );

    // Structured MavlinkMetadata object
    let meta = obj
        .get("mavlink_metadata")
        .and_then(|v| v.as_object())
        .expect("expected mavlink_metadata object in JSON");
    assert_eq!(meta.get("system_id").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(meta.get("component_id").and_then(|v| v.as_u64()), Some(2));
    assert_eq!(meta.get("sequence").and_then(|v| v.as_u64()), Some(42));
    assert_eq!(
        meta.get("message_id").and_then(|v| v.as_u64()),
        Some(u64::from(msgid_24bit))
    );

    // Also verify deserialization round-trip
    let deserialized: DiagnosticEvent = serde_json::from_value(val).expect("deserialize");
    assert_eq!(deserialized.mavlink_system_id, Some(1));
    assert_eq!(deserialized.mavlink_component_id, Some(2));
    assert_eq!(deserialized.mavlink_sequence, Some(42));
    assert_eq!(deserialized.mavlink_message_id, Some(msgid_24bit));
}

#[test]
fn test_f051_criterion4_validate_rejects_conflicting_sequence_tracking() {
    // Acceptance criterion: Running rer validate on a configuration where both option mavlink
    // sequence tracking and option sequence tracking are enabled on the same stream returns a
    // validation error reporting conflicting sequence tracking.
    use rer::config::Config;

    let yaml_conflict = r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "stream-conflict"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:6000"
        sequence:
          enabled: true
          offset: 0
          width: 4
        mavlink:
          enabled: true
          track_sequences: true
"#;

    let config = Config::from_yaml_str(yaml_conflict).expect("parse yaml config");
    let errors = config.validate();
    assert!(
        !errors.is_empty(),
        "conflicting sequence tracking must produce validation errors"
    );
    let conflict_err = errors
        .iter()
        .find(|e| e.reason.contains("conflicting sequence tracking"));
    assert!(
        conflict_err.is_some(),
        "expected error reason containing 'conflicting sequence tracking', got: {:?}",
        errors
    );

    // Test through CLI 'rer validate'
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!(
        "test_mavlink_conflict_{}.yaml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&temp_file, yaml_conflict).expect("write temp config");

    let output = Command::new(env!("CARGO_BIN_EXE_rer"))
        .arg("validate")
        .arg(&temp_file)
        .output()
        .expect("execute rer validate");

    let _ = std::fs::remove_file(&temp_file);

    assert!(
        !output.status.success(),
        "rer validate must fail for conflicting sequence tracking"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("conflicting sequence tracking"),
        "stderr must report conflicting sequence tracking, got:\n{}",
        stderr
    );

    // Verify with sequence_tracking alias in yaml
    let yaml_conflict_alias = r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "stream-conflict-alias"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:6000"
        sequence:
          enabled: true
        mavlink:
          enabled: true
          sequence_tracking: true
"#;
    let config_alias = Config::from_yaml_str(yaml_conflict_alias).expect("parse yaml");
    let errors_alias = config_alias.validate();
    assert!(
        errors_alias
            .iter()
            .any(|e| e.reason.contains("conflicting sequence tracking")),
        "sequence_tracking alias must also trigger conflicting sequence tracking error"
    );

    // Verify when generic sequence tracking is disabled, validation succeeds
    let yaml_valid = r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "stream-valid"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:6000"
        sequence:
          enabled: false
        mavlink:
          enabled: true
          track_sequences: true
"#;
    let config_valid = Config::from_yaml_str(yaml_valid).expect("parse valid yaml");
    assert!(
        config_valid.validate().is_empty(),
        "when generic sequence tracking is disabled, mavlink sequence tracking is allowed"
    );
}

#[test]
fn test_f051_criterion5_deserializing_yaml_defaults_mavlink_to_none() {
    // Acceptance criterion: Deserializing a configuration YAML containing a stream without
    // option mavlink defaults to None and preserves existing relay configuration behavior.
    use rer::config::Config;

    let yaml_without_mavlink = r#"
version: "1"
instances:
  - id: "inst-default"
    streams:
      - id: "stream-default"
        source:
          transport: "udp"
          address: "127.0.0.1:7000"
        destination:
          transport: "udp"
          address: "127.0.0.1:8000"
"#;

    let config = Config::from_yaml_str(yaml_without_mavlink).expect("parse yaml without mavlink");
    let stream = &config.instances[0].streams[0];
    assert_eq!(
        stream.mavlink, None,
        "stream without mavlink option must deserialize into None"
    );
    assert!(
        config.validate().is_empty(),
        "standard configuration without mavlink must validate cleanly"
    );
}
