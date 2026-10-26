//! Integration tests for in-tree MQTT fixed header parser and variable-byte integer codec (Task RER-F-056).

use rer::mqtt::{
    decode_variable_byte_integer, decode_variable_length_integer, decode_varint,
    encode_variable_byte_integer, encode_variable_byte_integer_vec, encode_varint,
    evaluate_mqtt_header, parse_fixed_header, parse_header, parse_mqtt_fixed_header,
    parse_mqtt_fixed_header_prefix, parse_mqtt_fixed_header_relaxed, parse_mqtt_header,
    parse_mqtt_packet, parse_packet, validate_flags, MqttFixedHeader, MqttPacketType,
    MqttParseError, MqttParseStatus, MQTT_MAX_FIXED_HEADER_LEN, MQTT_MAX_PACKET_SIZE,
    MQTT_MAX_VARIABLE_BYTE_INTEGER, MQTT_MAX_VARINT_BYTES, MQTT_MIN_FIXED_HEADER_LEN,
    MQTT_TYPE_AUTH, MQTT_TYPE_CONNACK, MQTT_TYPE_CONNECT, MQTT_TYPE_DISCONNECT, MQTT_TYPE_PINGREQ,
    MQTT_TYPE_PINGRESP, MQTT_TYPE_PUBACK, MQTT_TYPE_PUBCOMP, MQTT_TYPE_PUBLISH, MQTT_TYPE_PUBREC,
    MQTT_TYPE_PUBREL, MQTT_TYPE_SUBACK, MQTT_TYPE_SUBSCRIBE, MQTT_TYPE_UNSUBACK,
    MQTT_TYPE_UNSUBSCRIBE,
};

#[test]
fn test_criterion1_decode_variable_byte_integer_128() {
    // Acceptance criterion 1:
    // In crates/rer/src/mqtt.rs, decoding a variable byte integer from byte buffer [0x80, 0x01]
    // returns a decoded value of 128 and 2 bytes consumed.
    let buf = [0x80, 0x01];
    let (val, consumed) =
        decode_variable_byte_integer(&buf).expect("decoding [0x80, 0x01] must succeed");
    assert_eq!(val, 128);
    assert_eq!(consumed, 2);

    // Aliases
    let (v_varint, c_varint) = decode_varint(&buf).expect("decode_varint must succeed");
    assert_eq!(v_varint, 128);
    assert_eq!(c_varint, 2);

    let (v_vli, c_vli) =
        decode_variable_length_integer(&buf).expect("decode_variable_length_integer must succeed");
    assert_eq!(v_vli, 128);
    assert_eq!(c_vli, 2);
}

#[test]
fn test_criterion2_decode_varint_5_bytes_overflow() {
    // Acceptance criterion 2:
    // In crates/rer/src/mqtt.rs, decoding a variable byte integer containing 5 consecutive bytes
    // with the continuation bit set returns an error indicating length overflow beyond 4 octets.
    let buf = [0x80, 0x80, 0x80, 0x80, 0x80];
    let err = decode_variable_byte_integer(&buf).expect_err("5 continuation bytes must overflow");
    assert_eq!(err, MqttParseError::VariableByteIntegerOverflow);
    assert_eq!(err, MqttParseError::LengthOverflow);
    assert!(err.is_length_overflow());
    assert!(err.is_varint_overflow());
    assert!(format!("{err}")
        .to_lowercase()
        .contains("length overflow beyond 4 octets"));

    // Also verify decode_varint and decode_variable_length_integer aliases
    let err_alias = decode_varint(&buf).expect_err("alias must error");
    assert_eq!(err_alias, MqttParseError::LengthOverflow);
}

#[test]
fn test_criterion3_connect_non_zero_flags_rejected() {
    // Acceptance criterion 3:
    // In crates/rer/src/mqtt.rs, parsing a fixed header with packet type 1 for CONNECT and flag bits
    // 0b0001 returns an error rejecting non-zero flags.
    let first_byte = (1 << 4) | 0b0001; // packet type 1, flags 0b0001
    let buf = [first_byte, 0x00];
    let err = parse_mqtt_fixed_header(&buf).expect_err("CONNECT with non-zero flags must error");
    assert_eq!(err, MqttParseError::InvalidFlags);
    assert_eq!(err, MqttParseError::NonZeroFlags);
    assert!(err.is_invalid_flags());
    assert!(err.is_non_zero_flags());
    assert!(format!("{err}")
        .to_lowercase()
        .contains("rejecting non-zero flags"));

    // Also test flag validation directly
    let flag_err = validate_flags(1, 0b0001).expect_err("CONNECT non-zero flags must error");
    assert_eq!(flag_err, MqttParseError::InvalidFlags);
}

#[test]
fn test_criterion4_pingreq_fixed_header() {
    // Acceptance criterion 4:
    // In crates/rer/src/mqtt.rs, parsing a 2-byte PINGREQ packet with first byte 0xC0 and remaining
    // length byte 0x00 returns an MqttFixedHeader with packet type 12, flags 0, remaining length 0,
    // and total packet length 2.
    let buf = [0xC0, 0x00];
    let header: MqttFixedHeader =
        parse_mqtt_fixed_header(&buf).expect("2-byte PINGREQ must parse successfully");
    assert_eq!(header.packet_type, 12);
    assert_eq!(header.packet_type, MqttPacketType::Pingreq);
    assert_eq!(header.packet_type_code(), 12);
    assert_eq!(header.packet_type_name(), "PINGREQ");
    assert_eq!(header.flags, 0);
    assert_eq!(header.remaining_length, 0);
    assert_eq!(header.total_packet_length, 2);
    assert_eq!(header.total_packet_len, 2);
    assert_eq!(header.header_len, 2);
    assert_eq!(header.header_length, 2);
    assert!(header.is_pingreq());

    // Also check function aliases
    let alias_hdr = parse_fixed_header(&buf).expect("parse_fixed_header must succeed");
    assert_eq!(alias_hdr.packet_type, 12);
    assert_eq!(alias_hdr.total_packet_length, 2);

    let alias_hdr2 = parse_header(&buf).expect("parse_header must succeed");
    assert_eq!(alias_hdr2.packet_type, 12);

    let alias_hdr3 = parse_mqtt_header(&buf).expect("parse_mqtt_header must succeed");
    assert_eq!(alias_hdr3.packet_type, 12);

    let alias_pkt = parse_packet(&buf).expect("parse_packet must succeed");
    assert_eq!(alias_pkt.packet_type, 12);
    assert_eq!(alias_pkt.total_packet_length, 2);

    let alias_pkt2 = parse_mqtt_packet(&buf).expect("parse_mqtt_packet must succeed");
    assert_eq!(alias_pkt2.packet_type, 12);
}

#[test]
fn test_criterion5_truncated_packet_data() {
    // Acceptance criterion 5:
    // In crates/rer/src/mqtt.rs, parsing a buffer shorter than the declared variable byte integer
    // or declared remaining length returns an error indicating truncated packet data.

    // A: Shorter than declared variable byte integer
    let buf_truncated_varint = [0xC0, 0x80];
    let err_varint = parse_mqtt_fixed_header(&buf_truncated_varint)
        .expect_err("truncated varint must return error");
    assert_eq!(err_varint, MqttParseError::TruncatedPacket);
    assert_eq!(err_varint, MqttParseError::TruncatedPacketData);
    assert!(err_varint.is_truncated());
    assert!(format!("{err_varint}")
        .to_lowercase()
        .contains("truncated packet data"));

    // B: Shorter than declared remaining length
    // Type = PUBLISH (3), flags = 0, remaining length = 5, but buffer only provides 2 payload bytes
    let mut buf_truncated_payload = vec![0x30, 0x05];
    buf_truncated_payload.extend_from_slice(&[0xAA, 0xBB]); // only 2 bytes, needs 5
    let err_payload = parse_mqtt_fixed_header(&buf_truncated_payload)
        .expect_err("buffer shorter than declared remaining length must error");
    assert_eq!(err_payload, MqttParseError::TruncatedPacket);
    assert!(err_payload.is_truncated());
    assert!(format!("{err_payload}")
        .to_lowercase()
        .contains("truncated packet data"));

    // C: Buffer shorter than 2 bytes
    let buf_1byte = [0xC0];
    let err_1byte = parse_mqtt_fixed_header(&buf_1byte).expect_err("1-byte buffer must error");
    assert_eq!(err_1byte, MqttParseError::TruncatedPacket);
    assert!(err_1byte.is_truncated());

    // D: Completely empty buffer
    let empty: &[u8] = &[];
    let err_empty = parse_mqtt_fixed_header(empty).expect_err("empty buffer must error");
    assert_eq!(err_empty, MqttParseError::TruncatedPacket);
    assert!(err_empty.is_truncated());
}

#[test]
fn test_criterion6_forbidden_packet_type_0() {
    // Acceptance criterion 6:
    // In crates/rer/src/mqtt.rs, parsing a byte buffer whose first byte has 4 high bits equal to 0
    // returns an error indicating forbidden packet type 0.
    let buf_zeros = [0x00, 0x00];
    let err = parse_mqtt_fixed_header(&buf_zeros).expect_err("packet type 0 must error");
    assert_eq!(err, MqttParseError::ForbiddenPacketType0);
    assert_eq!(err, MqttParseError::ForbiddenPacketType);
    assert!(err.is_forbidden_packet_type());
    assert!(err.is_forbidden_packet_type_0());
    assert!(format!("{err}")
        .to_lowercase()
        .contains("forbidden packet type 0"));

    // High 4 bits 0, lower 4 bits non-zero (0x0F)
    let buf_flags = [0x0F, 0x00];
    let err_flags = parse_mqtt_fixed_header(&buf_flags).expect_err("type 0 with flags must error");
    assert_eq!(err_flags, MqttParseError::ForbiddenPacketType0);
    assert!(err_flags.is_forbidden_packet_type());
}

#[test]
fn test_variable_byte_integer_codecs() {
    let test_cases: &[(usize, &[u8])] = &[
        (0, &[0x00]),
        (127, &[0x7F]),
        (128, &[0x80, 0x01]),
        (16383, &[0xFF, 0x7F]),
        (16384, &[0x80, 0x80, 0x01]),
        (2097151, &[0xFF, 0xFF, 0x7F]),
        (2097152, &[0x80, 0x80, 0x80, 0x01]),
        (268435455, &[0xFF, 0xFF, 0xFF, 0x7F]),
    ];

    for &(val, wire) in test_cases {
        let (decoded, consumed) = decode_variable_byte_integer(wire).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, wire.len());

        let mut buf = [0u8; 4];
        let written = encode_variable_byte_integer(val, &mut buf).unwrap();
        assert_eq!(written, wire.len());
        assert_eq!(&buf[..written], wire);

        let written_alias = encode_varint(val, &mut buf).unwrap();
        assert_eq!(written_alias, wire.len());

        let vec_encoded = encode_variable_byte_integer_vec(val).unwrap();
        assert_eq!(vec_encoded, wire);
    }
}

#[test]
fn test_all_standard_mqtt_packet_types() {
    let types = [
        (MQTT_TYPE_CONNECT, 0b0000, "CONNECT"),
        (MQTT_TYPE_CONNACK, 0b0000, "CONNACK"),
        (MQTT_TYPE_PUBLISH, 0b0000, "PUBLISH"),
        (MQTT_TYPE_PUBACK, 0b0000, "PUBACK"),
        (MQTT_TYPE_PUBREC, 0b0000, "PUBREC"),
        (MQTT_TYPE_PUBREL, 0b0010, "PUBREL"),
        (MQTT_TYPE_PUBCOMP, 0b0000, "PUBCOMP"),
        (MQTT_TYPE_SUBSCRIBE, 0b0010, "SUBSCRIBE"),
        (MQTT_TYPE_SUBACK, 0b0000, "SUBACK"),
        (MQTT_TYPE_UNSUBSCRIBE, 0b0010, "UNSUBSCRIBE"),
        (MQTT_TYPE_UNSUBACK, 0b0000, "UNSUBACK"),
        (MQTT_TYPE_PINGREQ, 0b0000, "PINGREQ"),
        (MQTT_TYPE_PINGRESP, 0b0000, "PINGRESP"),
        (MQTT_TYPE_DISCONNECT, 0b0000, "DISCONNECT"),
        (MQTT_TYPE_AUTH, 0b0000, "AUTH"),
    ];

    for &(type_code, flags, name) in &types {
        let first_byte = (type_code << 4) | flags;
        let buf = [first_byte, 0x00];
        let parsed = parse_mqtt_fixed_header(&buf).unwrap();
        assert_eq!(parsed.packet_type, type_code);
        assert_eq!(parsed.packet_type_name(), name);
        assert_eq!(parsed.flags, flags);
        assert_eq!(parsed.remaining_length, 0);
        assert_eq!(parsed.total_packet_length, 2);
    }
}

#[test]
fn test_flag_validation_rules() {
    // SUBSCRIBE requires 0010 (flags = 2)
    let sub_invalid = [8 << 4, 0x00];
    assert_eq!(
        parse_mqtt_fixed_header(&sub_invalid).unwrap_err(),
        MqttParseError::InvalidFlags
    );
    let sub_valid = [(8 << 4) | 0b0010, 0x00];
    assert!(parse_mqtt_fixed_header(&sub_valid).is_ok());

    // Relaxed parser ignores invalid flags
    assert!(parse_mqtt_fixed_header_relaxed(&sub_invalid).is_ok());

    // Prefix parser parses header even when payload is absent
    let pub_prefix = [3 << 4, 0x10]; // remaining len = 16, but only 2 bytes total
    assert!(parse_mqtt_fixed_header_prefix(&pub_prefix).is_ok());
    assert!(parse_mqtt_fixed_header(&pub_prefix).is_err());
}

#[test]
fn test_evaluate_mqtt_header() {
    let pingreq = [0xC0, 0x00];
    let (status, hdr) = evaluate_mqtt_header(&pingreq);
    assert_eq!(status, MqttParseStatus::Valid);
    assert!(status.is_valid());
    let h = hdr.unwrap();
    assert_eq!(h.packet_type, 12);

    let bad_type = [0x00, 0x00];
    let (status_bad, hdr_bad) = evaluate_mqtt_header(&bad_type);
    assert_eq!(status_bad, MqttParseStatus::ForbiddenPacketType);
    assert!(status_bad.is_forbidden_packet_type());
    assert!(hdr_bad.is_none());
}

#[test]
fn test_constants_definitions() {
    assert_eq!(MQTT_MIN_FIXED_HEADER_LEN, 2);
    assert_eq!(MQTT_MAX_FIXED_HEADER_LEN, 5);
    assert_eq!(MQTT_MAX_VARINT_BYTES, 4);
    assert_eq!(MQTT_MAX_VARIABLE_BYTE_INTEGER, 268_435_455);
    assert_eq!(MQTT_MAX_PACKET_SIZE, 268_435_455 + 5);
}
