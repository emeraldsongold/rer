use rer::srt::{
    encode_control_header, encode_data_header, evaluate_header, evaluate_payload,
    evaluate_srt_header, evaluate_srt_payload, parse_control_header, parse_control_packet,
    parse_data_header, parse_data_packet, parse_handshake, parse_handshake_control, parse_header,
    parse_packet, parse_srt_control_packet, parse_srt_data_packet, parse_srt_handshake,
    parse_srt_header, parse_srt_packet, PacketPosition, SrtControlHeader, SrtControlPacket,
    SrtControlType, SrtDataHeader, SrtDataPacket, SrtHandshake, SrtHandshakeControl,
    SrtHandshakePacket, SrtHandshakeType, SrtHeader, SrtPacket, SrtPacketKind, SrtPacketType,
    SrtParseError, SrtParseStatus, SRT_CMD_ACK, SRT_CMD_ACKACK, SRT_CMD_CONGESTION,
    SRT_CMD_DROPREQ, SRT_CMD_HANDSHAKE, SRT_CMD_HSREQ, SRT_CMD_HSRSP, SRT_CMD_KEEPALIVE,
    SRT_CMD_KMREQ, SRT_CMD_KMRSP, SRT_CMD_NAK, SRT_CMD_PEERERROR, SRT_CMD_SHUTDOWN, SRT_CMD_SID,
    SRT_CMD_USER, SRT_HANDSHAKE_MIN_LEN, SRT_HANDSHAKE_PAYLOAD_LEN, SRT_HEADER_LEN,
    SRT_HS_AGREEMENT, SRT_HS_CONCLUSION, SRT_HS_DONE, SRT_HS_INDUCTION, SRT_HS_WAVEAHAND,
    SRT_VERSION_5, UDT_VERSION_4,
};

#[test]
fn test_type_and_function_aliases_compile() {
    let _p: SrtPacketType = SrtPacketKind::Data;
    let _h: SrtHandshakeControl = SrtHandshakePacket {
        version: SRT_VERSION_5,
        protocol_version: SRT_VERSION_5,
        encryption_field: 0,
        extension_field: 0,
        initial_sequence_number: 1,
        initial_packet_sequence_number: 1,
        mtu: 1500,
        mtu_size: 1500,
        max_flow_window_size: 100,
        flow_window_size: 100,
        handshake_type: SRT_HS_DONE,
        handshake_kind: SrtHandshakeType::Done,
        srt_socket_id: 1,
        source_socket_id: 1,
        syn_cookie: 0,
        peer_ip: [0; 16],
        peer_ip_address: [0; 16],
        stream_id: None,
    };
    let _ = (
        SRT_CMD_HSREQ,
        SRT_CMD_HSRSP,
        SRT_CMD_KMREQ,
        SRT_CMD_KMRSP,
        SRT_CMD_SID,
        SRT_HANDSHAKE_PAYLOAD_LEN,
        SRT_HEADER_LEN,
    );
    let raw_data = encode_data_header(0, PacketPosition::Single, false, 0, false, 0, 0, 0);
    assert!(parse_data_packet(&raw_data).is_ok());
    assert!(parse_srt_header(&raw_data).is_ok());
    assert!(parse_srt_packet(&raw_data).is_ok());

    let raw_ctrl = encode_control_header(SRT_CMD_KEEPALIVE, 0, 0, 0, 0);
    assert!(parse_control_packet(&raw_ctrl).is_ok());

    let hs_pkt = _h.to_packet_bytes(0, 0);
    assert!(parse_handshake_control(&hs_pkt).is_ok());
}

#[test]
fn test_criterion1_parse_16_byte_buffer_packet_type_bit_0_extracts_data_fields() {
    // 16-byte buffer with packet type bit 0 (Data packet):
    // Sequence Number = 123456 (0x0001E240)
    // Packet Position = First (10b)
    // In-order = true (1b)
    // Encryption Flag = 1 (even key, 01b)
    // Retransmitted = false (0b)
    // Message Number = 789 (0x00000315)
    // Timestamp = 987654321 us (0x3ADE68B1)
    // Destination Socket ID = 42 (0x0000002A)
    let seq_num = 123456u32;
    let msg_num = 789u32;
    let timestamp = 987654321u32;
    let dest_socket = 42u32;

    let raw = encode_data_header(
        seq_num,
        PacketPosition::First,
        true,
        1,
        false,
        msg_num,
        timestamp,
        dest_socket,
    );

    assert_eq!(raw.len(), 16);
    // Verify packet type bit (MSB of byte 0) is 0
    assert_eq!(raw[0] & 0x80, 0);

    // Parse with parse_header
    let header: SrtHeader = parse_header(&raw).expect("valid 16-byte data header must parse");
    assert!(!header.is_control);
    assert!(header.is_data());
    assert_eq!(header.packet_type, SrtPacketKind::Data);
    assert_eq!(header.sequence_number, Some(seq_num));
    assert_eq!(header.sequence_number(), Some(seq_num));
    assert_eq!(header.message_number, Some(msg_num));
    assert_eq!(header.message_number(), Some(msg_num));
    assert_eq!(header.timestamp, timestamp);
    assert_eq!(header.timestamp(), timestamp);
    assert_eq!(header.destination_socket_id, dest_socket);
    assert_eq!(header.destination_socket_id(), dest_socket);

    // Additional data fields
    assert_eq!(header.packet_position, Some(PacketPosition::First));
    assert_eq!(header.in_order, Some(true));
    assert_eq!(header.encryption_flag, Some(1));
    assert_eq!(header.retransmitted, Some(false));

    // Parse with parse_data_header and parse_data_packet
    let data_hdr: SrtDataHeader = parse_data_header(&raw).expect("parse_data_header must succeed");
    assert_eq!(data_hdr.sequence_number, seq_num);
    assert_eq!(data_hdr.sequence_number(), seq_num);
    assert_eq!(data_hdr.message_number, msg_num);
    assert_eq!(data_hdr.message_number(), msg_num);
    assert_eq!(data_hdr.timestamp, timestamp);
    assert_eq!(data_hdr.timestamp(), timestamp);
    assert_eq!(data_hdr.destination_socket_id, dest_socket);
    assert_eq!(data_hdr.destination_socket_id(), dest_socket);

    let alias_data: SrtDataPacket =
        parse_srt_data_packet(&raw).expect("parse_srt_data_packet must succeed");
    assert_eq!(alias_data.sequence_number, seq_num);
    assert_eq!(alias_data.message_number, msg_num);

    // Parse with parse_packet
    let pkt: SrtPacket = parse_packet(&raw).expect("parse_packet must succeed");
    assert!(pkt.is_data());
    assert_eq!(pkt.sequence_number(), Some(seq_num));
    assert_eq!(pkt.message_number(), Some(msg_num));
    assert_eq!(pkt.timestamp(), Some(timestamp));
    assert_eq!(pkt.destination_socket_id(), Some(dest_socket));

    // Round-trip byte encoding
    assert_eq!(header.to_bytes(), raw);
    assert_eq!(data_hdr.to_bytes(), raw);
}

#[test]
fn test_criterion1_parse_retransmitted_data_packet() {
    let raw = encode_data_header(
        0x7FFF_FFFF, // Max 31-bit sequence number
        PacketPosition::Last,
        false,
        2,           // odd key
        true,        // retransmitted
        0x03FF_FFFF, // Max 26-bit message number
        555555,
        9999,
    );

    let hdr = parse_header(&raw).expect("must parse");
    assert_eq!(hdr.sequence_number, Some(0x7FFF_FFFF));
    assert_eq!(hdr.message_number, Some(0x03FF_FFFF));
    assert_eq!(hdr.retransmitted, Some(true));
    assert_eq!(hdr.encryption_flag, Some(2));
    assert_eq!(hdr.packet_position, Some(PacketPosition::Last));
}

#[test]
fn test_criterion2_parse_16_byte_buffer_packet_type_bit_1_extracts_control_fields() {
    // 16-byte buffer with packet type bit 1 (Control packet):
    // Control Type = Keepalive (0x0001)
    // Subtype = 0x0000
    // Type-specific Information = 0x12345678
    // Timestamp = 456789 us
    // Destination Socket ID = 1001
    let ctype_code = SRT_CMD_KEEPALIVE;
    let type_specific = 0x12345678u32;
    let timestamp = 456789u32;
    let dest_socket = 1001u32;

    let raw = encode_control_header(ctype_code, 0, type_specific, timestamp, dest_socket);

    assert_eq!(raw.len(), 16);
    // Verify packet type bit (MSB of byte 0) is 1
    assert_eq!(raw[0] & 0x80, 0x80);

    // Parse with parse_header
    let header: SrtHeader = parse_header(&raw).expect("valid 16-byte control header must parse");
    assert!(header.is_control);
    assert!(!header.is_data());
    assert_eq!(header.packet_type, SrtPacketKind::Control);
    assert_eq!(header.control_type, Some(SrtControlType::Keepalive));
    assert_eq!(header.control_type(), Some(SrtControlType::Keepalive));
    assert_eq!(header.type_specific_info, Some(type_specific));
    assert_eq!(header.type_specific_info(), Some(type_specific));
    assert_eq!(header.type_specific_information, Some(type_specific));
    assert_eq!(header.type_specific_information(), Some(type_specific));
    assert_eq!(header.timestamp, timestamp);
    assert_eq!(header.timestamp(), timestamp);
    assert_eq!(header.destination_socket_id, dest_socket);
    assert_eq!(header.destination_socket_id(), dest_socket);

    // Parse with parse_control_header and parse_control_packet
    let ctrl_hdr: SrtControlHeader =
        parse_control_header(&raw).expect("parse_control_header must succeed");
    assert_eq!(ctrl_hdr.control_type, SrtControlType::Keepalive);
    assert_eq!(ctrl_hdr.control_type(), SrtControlType::Keepalive);
    assert_eq!(ctrl_hdr.type_specific_info, type_specific);
    assert_eq!(ctrl_hdr.type_specific_info(), type_specific);
    assert_eq!(ctrl_hdr.type_specific_information, type_specific);
    assert_eq!(ctrl_hdr.type_specific_information(), type_specific);
    assert_eq!(ctrl_hdr.timestamp, timestamp);
    assert_eq!(ctrl_hdr.timestamp(), timestamp);
    assert_eq!(ctrl_hdr.destination_socket_id, dest_socket);
    assert_eq!(ctrl_hdr.destination_socket_id(), dest_socket);

    let alias_ctrl: SrtControlPacket =
        parse_srt_control_packet(&raw).expect("parse_srt_control_packet must succeed");
    assert_eq!(alias_ctrl.control_type, SrtControlType::Keepalive);
    assert_eq!(alias_ctrl.type_specific_info, type_specific);

    // Parse with parse_packet
    let pkt: SrtPacket = parse_packet(&raw).expect("parse_packet must succeed");
    assert!(pkt.is_control());
    assert_eq!(pkt.control_type(), Some(SrtControlType::Keepalive));
    assert_eq!(pkt.type_specific_info(), Some(type_specific));
    assert_eq!(pkt.type_specific_information(), Some(type_specific));
    assert_eq!(pkt.timestamp(), Some(timestamp));
    assert_eq!(pkt.destination_socket_id(), Some(dest_socket));

    // Round-trip byte encoding
    assert_eq!(header.to_bytes(), raw);
    assert_eq!(ctrl_hdr.to_bytes(), raw);
}

#[test]
fn test_criterion2_various_control_types() {
    let types = [
        (SRT_CMD_HANDSHAKE, SrtControlType::Handshake),
        (SRT_CMD_KEEPALIVE, SrtControlType::Keepalive),
        (SRT_CMD_ACK, SrtControlType::Ack),
        (SRT_CMD_NAK, SrtControlType::Nak),
        (SRT_CMD_CONGESTION, SrtControlType::CongestionWarning),
        (SRT_CMD_SHUTDOWN, SrtControlType::Shutdown),
        (SRT_CMD_ACKACK, SrtControlType::AckAck),
        (SRT_CMD_DROPREQ, SrtControlType::DropReq),
        (SRT_CMD_PEERERROR, SrtControlType::PeerError),
        (SRT_CMD_USER, SrtControlType::UserDefined),
    ];

    for (code, expected_type) in types {
        let raw = encode_control_header(code, 0, 777, 888, 999);
        let hdr = parse_header(&raw).expect("must parse control header");
        assert_eq!(hdr.control_type, Some(expected_type));
        assert_eq!(hdr.type_specific_info, Some(777));
        assert_eq!(hdr.timestamp, 888);
        assert_eq!(hdr.destination_socket_id, 999);
    }
}

#[test]
fn test_criterion3_buffer_shorter_than_16_bytes_returns_truncated_header_error() {
    for len in 0..16 {
        let buf = vec![0u8; len];

        let err = parse_header(&buf).expect_err(&format!("len {len} must fail"));
        assert_eq!(err, SrtParseError::TruncatedHeader);
        assert!(err.is_truncated());
        assert_eq!(err.status(), SrtParseStatus::Truncated);
        let msg = format!("{err}");
        assert!(msg.to_lowercase().contains("truncated"));

        let data_err = parse_data_header(&buf).expect_err(&format!("data len {len} must fail"));
        assert_eq!(data_err, SrtParseError::TruncatedHeader);
        assert!(data_err.is_truncated());

        let ctrl_err = parse_control_header(&buf).expect_err(&format!("ctrl len {len} must fail"));
        assert_eq!(ctrl_err, SrtParseError::TruncatedHeader);
        assert!(ctrl_err.is_truncated());

        let pkt_err = parse_packet(&buf).expect_err(&format!("packet len {len} must fail"));
        assert_eq!(pkt_err, SrtParseError::TruncatedHeader);
        assert!(pkt_err.is_truncated());

        let hs_err = parse_handshake(&buf).expect_err(&format!("handshake len {len} must fail"));
        assert_eq!(hs_err, SrtParseError::TruncatedHeader);
        assert!(hs_err.is_truncated());

        // evaluate_payload must return SrtParseStatus::Truncated
        let status = evaluate_payload(&buf);
        assert_eq!(status, SrtParseStatus::Truncated);
        assert!(status.is_truncated());
        assert!(!status.is_valid());
    }
}

#[test]
fn test_criterion4_parse_srt_handshake_control_packet() {
    let hs_obj = SrtHandshake {
        version: SRT_VERSION_5,
        protocol_version: SRT_VERSION_5,
        encryption_field: 0,
        extension_field: 0x0005,
        initial_sequence_number: 10001,
        initial_packet_sequence_number: 10001,
        mtu: 1500,
        mtu_size: 1500,
        max_flow_window_size: 8192,
        flow_window_size: 8192,
        handshake_type: SRT_HS_INDUCTION,
        handshake_kind: SrtHandshakeType::Induction,
        srt_socket_id: 0x00112233,
        source_socket_id: 0x00112233,
        syn_cookie: 0xAABBCCDD,
        peer_ip: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        peer_ip_address: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        stream_id: Some("live/stream1".to_string()),
    };

    let packet_bytes = hs_obj.to_packet_bytes(54321, 0);
    assert!(packet_bytes.len() >= SRT_HANDSHAKE_MIN_LEN);

    // 1. Parse directly with parse_handshake
    let parsed_hs: SrtHandshake =
        parse_handshake(&packet_bytes).expect("parse_handshake must succeed");
    assert_eq!(parsed_hs.handshake_type, SRT_HS_INDUCTION);
    assert_eq!(parsed_hs.handshake_type(), SRT_HS_INDUCTION);
    assert_eq!(parsed_hs.handshake_kind, SrtHandshakeType::Induction);
    assert_eq!(parsed_hs.version, SRT_VERSION_5);
    assert_eq!(parsed_hs.version(), SRT_VERSION_5);
    assert_eq!(parsed_hs.protocol_version, SRT_VERSION_5);
    assert_eq!(parsed_hs.protocol_version(), SRT_VERSION_5);
    assert_eq!(parsed_hs.initial_sequence_number, 10001);
    assert_eq!(parsed_hs.initial_sequence_number(), 10001);
    assert_eq!(parsed_hs.srt_socket_id, 0x00112233);
    assert_eq!(parsed_hs.syn_cookie, 0xAABBCCDD);
    assert_eq!(parsed_hs.stream_id(), Some("live/stream1"));

    // 2. Parse with parse_srt_handshake alias
    let alias_hs: SrtHandshakeControl =
        parse_srt_handshake(&packet_bytes).expect("parse_srt_handshake must succeed");
    assert_eq!(alias_hs.handshake_type, SRT_HS_INDUCTION);
    assert_eq!(alias_hs.protocol_version, SRT_VERSION_5);
    assert_eq!(alias_hs.initial_sequence_number, 10001);

    // 3. Parse with parse_header
    let hdr: SrtHeader = parse_header(&packet_bytes).expect("parse_header must succeed");
    assert!(hdr.is_control);
    assert_eq!(hdr.control_type, Some(SrtControlType::Handshake));
    assert_eq!(hdr.handshake_type, Some(SRT_HS_INDUCTION));
    assert_eq!(hdr.handshake_type(), Some(SRT_HS_INDUCTION));
    assert_eq!(hdr.protocol_version, Some(SRT_VERSION_5));
    assert_eq!(hdr.protocol_version(), Some(SRT_VERSION_5));
    assert_eq!(hdr.version, Some(SRT_VERSION_5));
    assert_eq!(hdr.initial_sequence_number, Some(10001));
    assert_eq!(hdr.initial_sequence_number(), Some(10001));
    assert_eq!(hdr.stream_id(), Some("live/stream1"));

    // 4. Parse with parse_packet
    let pkt: SrtPacket = parse_packet(&packet_bytes).expect("parse_packet must succeed");
    assert_eq!(pkt.handshake_type(), Some(SRT_HS_INDUCTION));
    assert_eq!(pkt.protocol_version(), Some(SRT_VERSION_5));
    assert_eq!(pkt.initial_sequence_number(), Some(10001));
}

#[test]
fn test_criterion4_handshake_types_agreement_conclusion_waveahand() {
    let types = [
        (SRT_HS_DONE, SrtHandshakeType::Done),
        (SRT_HS_AGREEMENT, SrtHandshakeType::Agreement),
        (SRT_HS_CONCLUSION, SrtHandshakeType::Conclusion),
        (SRT_HS_INDUCTION, SrtHandshakeType::Induction),
        (SRT_HS_WAVEAHAND, SrtHandshakeType::Waveahand),
    ];

    for (hs_code, expected_kind) in types {
        let hs = SrtHandshake {
            version: UDT_VERSION_4,
            protocol_version: UDT_VERSION_4,
            encryption_field: 0,
            extension_field: 0,
            initial_sequence_number: 5555,
            initial_packet_sequence_number: 5555,
            mtu: 1500,
            mtu_size: 1500,
            max_flow_window_size: 2048,
            flow_window_size: 2048,
            handshake_type: hs_code,
            handshake_kind: expected_kind,
            srt_socket_id: 1234,
            source_socket_id: 1234,
            syn_cookie: 5678,
            peer_ip: [0; 16],
            peer_ip_address: [0; 16],
            stream_id: None,
        };

        let raw = hs.to_packet_bytes(100, 200);
        let parsed = parse_handshake(&raw).expect("handshake must parse");
        assert_eq!(parsed.handshake_type, hs_code);
        assert_eq!(parsed.handshake_kind, expected_kind);
        assert_eq!(parsed.protocol_version, UDT_VERSION_4);
        assert_eq!(parsed.initial_sequence_number, 5555);
    }
}

#[test]
fn test_criterion5_evaluating_arbitrary_non_srt_payload_bytes_returns_status_distinguishing_non_srt(
) {
    let arbitrary_inputs: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!",
        b"POST /api/telemetry HTTP/1.1\r\nHost: srt.example.org\r\n\r\n",
        b"GET /live/stream.m3u8 HTTP/1.1\r\nHost: video.example.org\r\n\r\n",
        b"\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06", // IPv4 packet header (< 16 bytes: truncated)
        &[0x88, 0x07, 0x00, 0x00],                   // CBOR array (< 16 bytes: truncated)
        &[0xFF, 0xFE, 0xFD, 0xFC, 0xFB],
        // Control packet with invalid/unknown control type 0x7FFE (length 16)
        &[
            0xFF, 0xFE, 0x00, 0x00, // Bit 0 = 1, type = 0x7FFE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        // Handshake packet with invalid version 99 (length 64)
        &{
            let mut v = vec![0u8; 64];
            v[0] = 0x80; // Control Handshake (type 0)
            v[16] = 0;
            v[17] = 0;
            v[18] = 0;
            v[19] = 99; // Version 99
            v
        },
        // Handshake packet with invalid handshake_type 0x12345678 (length 64)
        &{
            let mut v = vec![0u8; 64];
            v[0] = 0x80; // Control Handshake (type 0)
            v[16] = 0;
            v[17] = 0;
            v[18] = 0;
            v[19] = 5; // Version 5
            v[36] = 0x12;
            v[37] = 0x34;
            v[38] = 0x56;
            v[39] = 0x78; // Invalid handshake type
            v
        },
        // Data packet with reserved encryption flag KK = 0b11 (length 16)
        &{
            let mut v = vec![0u8; 16];
            v[4] = 0x18; // KK = 3 (0b11 << 3)
            v
        },
    ];

    for input in arbitrary_inputs {
        let status = evaluate_payload(input);
        assert!(
            status.is_not_srt() || status.is_malformed() || status.is_truncated(),
            "arbitrary non-SRT input must return NotSrt, MalformedSrt, or Truncated, got {status:?}"
        );
        assert!(!status.is_valid());
        assert!(status.is_invalid());

        // evaluate_srt_payload alias check
        let alias_status = evaluate_srt_payload(input);
        assert_eq!(alias_status, status);

        // evaluate_srt_header check
        let (eval_status, header_opt) = evaluate_srt_header(input);
        assert_eq!(eval_status, status);
        assert!(header_opt.is_none());

        let (alias_hdr_status, alias_hdr_opt) = evaluate_header(input);
        assert_eq!(alias_hdr_status, status);
        assert!(alias_hdr_opt.is_none());
    }
}

#[test]
fn test_evaluate_valid_packets() {
    // Valid data packet
    let data_pkt = encode_data_header(100, PacketPosition::Single, false, 0, false, 1, 1000, 2000);
    assert_eq!(evaluate_payload(&data_pkt), SrtParseStatus::Valid);

    // Valid keepalive packet
    let keepalive_pkt = encode_control_header(SRT_CMD_KEEPALIVE, 0, 0, 1000, 2000);
    assert_eq!(evaluate_payload(&keepalive_pkt), SrtParseStatus::Valid);

    // Valid handshake packet
    let hs = SrtHandshake {
        version: SRT_VERSION_5,
        protocol_version: SRT_VERSION_5,
        encryption_field: 0,
        extension_field: 0,
        initial_sequence_number: 1,
        initial_packet_sequence_number: 1,
        mtu: 1500,
        mtu_size: 1500,
        max_flow_window_size: 8192,
        flow_window_size: 8192,
        handshake_type: SRT_HS_INDUCTION,
        handshake_kind: SrtHandshakeType::Induction,
        srt_socket_id: 1,
        source_socket_id: 1,
        syn_cookie: 0,
        peer_ip: [0; 16],
        peer_ip_address: [0; 16],
        stream_id: None,
    };
    let hs_pkt = hs.to_packet_bytes(500, 0);
    assert_eq!(evaluate_payload(&hs_pkt), SrtParseStatus::Valid);
}

#[test]
fn test_deserializing_config_yaml_without_srt_defaults_to_none_and_preserves_inspection() {
    let yaml = r#"
version: "1"
instances:
  - id: "node1"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
        inspection:
          hex: true
          max_preview_bytes: 32
"#;
    let config = rer::config::Config::from_yaml_str(yaml).expect("parse valid config");
    let stream = &config.all_instances()[0].streams[0];
    let insp = stream.inspection.as_ref().expect("inspection present");
    assert!(insp.hex_preview);
    assert_eq!(insp.max_preview_bytes, 32);
    assert!(insp.srt.is_none(), "srt must default to None when omitted");
}

#[test]
fn test_rer_validate_srt_max_inspect_bytes_zero_returns_validation_error() {
    let yaml = r#"
version: "1"
instances:
  - id: "node-srt"
    streams:
      - id: "srt-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:10000"
        destination:
          transport: "udp"
          address: "127.0.0.1:10001"
        inspection:
          srt:
            max_inspect_bytes: 0
"#;
    let config = rer::config::Config::from_yaml_str(yaml).expect("parse YAML");
    let errors = config.validate();
    assert!(
        errors.iter().any(|e| {
            e.path.contains("inspection.srt.max_inspect_bytes")
                && e.reason.contains("invalid inspection size limit")
        }),
        "Expected validation error for invalid inspection size limit: {:?}",
        errors
    );

    // Also verify via CLI `rer validate`
    let temp_file = std::env::temp_dir().join(format!("test_srt_zero_{}.yaml", std::process::id()));
    std::fs::write(&temp_file, yaml).expect("write temp config");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rer"))
        .arg("validate")
        .arg(&temp_file)
        .output()
        .expect("run rer validate");
    let _ = std::fs::remove_file(&temp_file);

    assert!(
        !output.status.success(),
        "rer validate must exit non-zero for invalid inspection size limit"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid inspection size limit") || stderr.contains("max_inspect_bytes"),
        "stderr must report invalid inspection size limit: {}",
        stderr
    );
}

#[test]
fn test_srt_inspection_diagnostic_event_serializes_structured_metadata() {
    let event = rer::diagnostics::SrtInspection::new(0x2A, 123_456, SrtPacketKind::Data);

    let json_str = serde_json::to_string(&event).expect("serialize SrtInspection");
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("parse JSON");

    assert_eq!(val["destination_socket_id"], 0x2A);
    assert_eq!(val["timestamp"], 123_456);
    assert_eq!(val["packet_kind"], "data");

    // Check structured SRT metadata representation
    assert!(
        val["srt_metadata"].is_object(),
        "must contain structured SRT metadata"
    );
    assert_eq!(val["srt_metadata"]["destination_socket_id"], 0x2A);
    assert_eq!(val["srt_metadata"]["timestamp_us"], 123_456);
    assert_eq!(val["srt_metadata"]["packet_kind"], "data");

    // Also verify when converted to DiagnosticEvent
    let diag_ev: rer::diagnostics::DiagnosticEvent = event.into();
    let diag_json = serde_json::to_string(&diag_ev).expect("serialize DiagnosticEvent");
    let diag_val: serde_json::Value = serde_json::from_str(&diag_json).expect("parse JSON");
    assert_eq!(diag_val["stage"], "srt_inspection");
    assert_eq!(diag_val["destination_socket_id"], 0x2A);
    assert_eq!(diag_val["srt_timestamp"], 123_456);
    assert_eq!(diag_val["srt_packet_kind"], "data");
    assert!(diag_val["srt_inspection"].is_object());
    assert!(diag_val["srt_metadata"].is_object());
}

#[test]
fn test_srt_inspection_into_full_buffer_drops_without_blocking_or_panicking() {
    let clock = std::sync::Arc::new(rer::diagnostics::ManualClock::new(1000, 2000));
    let buffer = rer::diagnostics::DiagnosticBuffer::with_clock(2, clock);
    assert_eq!(buffer.capacity(), 2);

    // Fill buffer
    let ev1 = buffer.create_event(
        "s1",
        rer::diagnostics::DiagnosticStage::Received,
        rer::config::TransportType::Udp,
        100,
    );
    let ev2 = buffer.create_event(
        "s1",
        rer::diagnostics::DiagnosticStage::Accepted,
        rer::config::TransportType::Udp,
        100,
    );
    assert!(buffer.emit(ev1));
    assert!(buffer.emit(ev2));
    assert_eq!(buffer.len(), 2);
    assert_eq!(buffer.dropped_count(), 0);

    // Emit SrtInspection into the full buffer
    let srt_ev = rer::diagnostics::SrtInspection::new(0x2A, 123_456, SrtPacketKind::Data);

    let emitted = buffer.emit(srt_ev);
    assert!(
        emitted,
        "non-blocking emit into full buffer succeeds by dropping oldest"
    );
    assert_eq!(buffer.len(), 2);
    assert_eq!(
        buffer.dropped_count(),
        1,
        "emitting into full buffer must increment dropped count"
    );

    let snap = buffer.snapshot();
    assert_eq!(snap.dropped_count, 1);
    assert_eq!(
        snap.events[1].stage,
        rer::diagnostics::DiagnosticStage::SrtInspection
    );
    assert_eq!(snap.events[1].destination_socket_id, Some(0x2A));
    assert_eq!(snap.events[1].srt_timestamp, Some(123_456));
    assert_eq!(snap.events[1].srt_packet_kind, Some(SrtPacketKind::Data));
}

fn pick_unused_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    let port = socket.local_addr().expect("local addr").port();
    drop(socket);
    port
}

fn sample_valid_srt_data_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
    let hdr = encode_data_header(
        seq,
        PacketPosition::Single,
        true,
        0,
        false,
        1,
        123_456,
        1001,
    );
    let mut pkt = Vec::with_capacity(SRT_HEADER_LEN + payload.len());
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(payload);
    pkt
}

#[test]
fn test_criterion1_and_2_udp_forwarding_valid_srt_data_packet_sends_exact_bytes_and_records_srt_inspection(
) {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = receiver.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "srt-relay-test"
    streams:
      - id: "s-srt-udp"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        inspection:
          srt:
            enabled: true
"#
    );

    let config = rer::config::Config::from_yaml_str(&yaml).expect("valid config");
    let relay = rer::relay::Relay::start(&config).expect("start relay");
    std::thread::sleep(std::time::Duration::from_millis(40));

    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let srt_packet = sample_valid_srt_data_packet(42, b"hello SRT live video payload 12345");

    sender
        .send_to(&srt_packet, format!("127.0.0.1:{listen_port}"))
        .expect("send srt packet");

    let mut buf = vec![0u8; 4096];
    let (n, _) = receiver.recv_from(&mut buf).expect("receive srt packet");

    // Acceptance criterion 1: sends exact datagram payload bytes unmodified to destination sockets
    assert_eq!(
        &buf[..n],
        &srt_packet[..],
        "forwarded UDP datagram payload bytes must match byte-identically"
    );

    std::thread::sleep(std::time::Duration::from_millis(30));
    let snap = relay.event_buffer().snapshot();
    let srt_events: Vec<_> = snap
        .events
        .iter()
        .filter(|e| e.stage == rer::diagnostics::DiagnosticStage::SrtInspection)
        .collect();

    // Acceptance criterion 2: records an SrtInspection diagnostic event with extracted sequence number
    assert_eq!(
        srt_events.len(),
        1,
        "expected exactly 1 SrtInspection event"
    );
    let ev = srt_events[0];
    assert_eq!(ev.stage, rer::diagnostics::DiagnosticStage::SrtInspection);
    assert_eq!(ev.srt_sequence_number, Some(42));
    assert_eq!(ev.sequence_number, Some(42));
    assert_eq!(ev.destination_socket_id, Some(1001));
    assert_eq!(ev.srt_packet_kind, Some(SrtPacketKind::Data));
    assert_eq!(ev.srt_parse_status, Some(SrtParseStatus::Valid));
    assert_eq!(ev.payload_length, srt_packet.len() as u64);

    let insp = ev
        .srt_inspection
        .as_ref()
        .expect("srt_inspection structured metadata present");
    assert_eq!(insp.sequence_number, Some(42));
    assert_eq!(insp.destination_socket_id, 1001);
    assert_eq!(insp.packet_kind, SrtPacketKind::Data);
    assert_eq!(insp.parse_status, Some(SrtParseStatus::Valid));

    relay.stop();
}

#[test]
fn test_criterion3_udp_forwarding_non_srt_or_truncated_datagrams_forwards_unmodified_and_records_unparsed_event(
) {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = receiver.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "srt-unparsed-test"
    streams:
      - id: "s-unparsed"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        inspection:
          srt:
            enabled: true
"#
    );

    let config = rer::config::Config::from_yaml_str(&yaml).expect("valid config");
    let relay = rer::relay::Relay::start(&config).expect("start relay");
    std::thread::sleep(std::time::Duration::from_millis(40));

    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let mut buf = vec![0u8; 4096];

    // 1. Non-SRT traffic (HTTP GET header)
    let non_srt_data = b"GET /live/stream HTTP/1.1\r\nHost: example.org\r\n\r\n";
    sender
        .send_to(non_srt_data, format!("127.0.0.1:{listen_port}"))
        .expect("send non-srt");

    let (n1, _) = receiver.recv_from(&mut buf).expect("recv non-srt");
    assert_eq!(
        &buf[..n1],
        non_srt_data,
        "non-SRT payload must be forwarded unmodified"
    );

    // 2. Truncated datagram (< 16 bytes)
    let truncated_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    sender
        .send_to(&truncated_data, format!("127.0.0.1:{listen_port}"))
        .expect("send truncated");

    let (n2, _) = receiver.recv_from(&mut buf).expect("recv truncated");
    assert_eq!(
        &buf[..n2],
        &truncated_data[..],
        "truncated payload must be forwarded unmodified"
    );

    // 3. Malformed SRT data packet (reserved encryption flag 0b11)
    let mut malformed_srt = sample_valid_srt_data_packet(10, b"malformed encryption");
    malformed_srt[4] = 0x18; // KK = 0b11
    sender
        .send_to(&malformed_srt, format!("127.0.0.1:{listen_port}"))
        .expect("send malformed srt");

    let (n3, _) = receiver.recv_from(&mut buf).expect("recv malformed srt");
    assert_eq!(
        &buf[..n3],
        &malformed_srt[..],
        "malformed SRT payload must be forwarded unmodified"
    );

    // 4. Valid SRT packet right after unparsed traffic to prove relay operation was NOT interrupted
    let valid_srt = sample_valid_srt_data_packet(999, b"valid SRT packet after unparsed traffic");
    sender
        .send_to(&valid_srt, format!("127.0.0.1:{listen_port}"))
        .expect("send valid srt");

    let (n4, _) = receiver.recv_from(&mut buf).expect("recv valid srt");
    assert_eq!(
        &buf[..n4],
        &valid_srt[..],
        "valid SRT packet must be forwarded unmodified"
    );

    std::thread::sleep(std::time::Duration::from_millis(30));
    let snap = relay.event_buffer().snapshot();
    let srt_events: Vec<_> = snap
        .events
        .iter()
        .filter(|e| e.stage == rer::diagnostics::DiagnosticStage::SrtInspection)
        .collect();

    // Acceptance criterion 3: records diagnostic events indicating unparsed traffic without interrupting relay
    assert_eq!(srt_events.len(), 4, "expected 4 inspection events");

    // Event 0: non-SRT traffic
    assert_eq!(
        srt_events[0].stage,
        rer::diagnostics::DiagnosticStage::SrtInspection
    );
    assert!(
        srt_events[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("unparsed traffic"),
        "event 0 must indicate unparsed traffic"
    );
    assert!(
        srt_events[0]
            .srt_parse_status
            .expect("status present")
            .is_not_srt()
            || srt_events[0].srt_parse_status.unwrap().is_malformed()
    );
    assert_eq!(srt_events[0].srt_sequence_number, None);

    // Event 1: truncated datagram
    assert!(
        srt_events[1]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("unparsed traffic"),
        "event 1 must indicate unparsed traffic"
    );
    assert_eq!(
        srt_events[1].srt_parse_status,
        Some(SrtParseStatus::Truncated)
    );
    assert_eq!(srt_events[1].srt_sequence_number, None);

    // Event 2: malformed SRT packet
    assert!(
        srt_events[2]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("unparsed traffic"),
        "event 2 must indicate unparsed traffic"
    );
    assert_eq!(
        srt_events[2].srt_parse_status,
        Some(SrtParseStatus::MalformedSrt)
    );
    assert_eq!(srt_events[2].srt_sequence_number, None);

    // Event 3: valid SRT packet following unparsed traffic
    assert_eq!(srt_events[3].srt_parse_status, Some(SrtParseStatus::Valid));
    assert_eq!(srt_events[3].srt_sequence_number, Some(999));
    assert_eq!(srt_events[3].sequence_number, Some(999));

    relay.stop();
}

#[test]
fn test_criterion4_udp_stream_without_srt_configured_forwards_without_srt_inspection_events() {
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = receiver.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "no-srt-test"
    streams:
      - id: "s-unconfigured"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = rer::config::Config::from_yaml_str(&yaml).expect("valid config");
    let relay = rer::relay::Relay::start(&config).expect("start relay");
    std::thread::sleep(std::time::Duration::from_millis(40));

    let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let srt_bytes = sample_valid_srt_data_packet(1234, b"srt data on unconfigured stream");

    sender
        .send_to(&srt_bytes, format!("127.0.0.1:{listen_port}"))
        .expect("send valid srt");

    let mut buf = vec![0u8; 4096];
    let (n, _) = receiver.recv_from(&mut buf).expect("receive packet");

    // Acceptance criterion 4: forwards datagrams byte-identically
    assert_eq!(
        &buf[..n],
        &srt_bytes[..],
        "forwarded UDP datagram payload bytes must match byte-identically"
    );

    std::thread::sleep(std::time::Duration::from_millis(30));
    let snap = relay.event_buffer().snapshot();
    let srt_events: Vec<_> = snap
        .events
        .iter()
        .filter(|e| {
            e.stage == rer::diagnostics::DiagnosticStage::SrtInspection
                || e.srt_inspection.is_some()
        })
        .collect();

    // Acceptance criterion 4: without emitting SrtInspection diagnostic events
    assert!(
        srt_events.is_empty(),
        "unconfigured stream must not emit SrtInspection events: {srt_events:?}"
    );

    relay.stop();
}

#[test]
fn test_criterion5_configuration_doc_specifies_srt_passive_metadata_inspection() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let doc_path = std::path::Path::new(manifest_dir)
        .parent()
        .expect("crates")
        .parent()
        .expect("repo root")
        .join("docs")
        .join("CONFIGURATION.md");

    let doc = std::fs::read_to_string(&doc_path).expect("read docs/CONFIGURATION.md");

    // Acceptance criterion 5: documentation for stream option inspection specifies that SRT support
    // performs passive metadata inspection without stream termination, encryption management, or retransmission recovery
    assert!(
        doc.contains("stream.inspection.srt") || doc.contains("inspection.srt"),
        "docs/CONFIGURATION.md must document stream option inspection for SRT"
    );
    assert!(
        doc.contains(
            "passive metadata inspection without stream termination, encryption management, or retransmission recovery"
        ),
        "docs/CONFIGURATION.md must specify passive metadata inspection without stream termination, encryption management, or retransmission recovery"
    );
}

#[test]
fn test_impairment_harness_with_srt_traffic_under_loss_reordering_jitter() {
    use rer::sim::channel::{ImpairmentConfig, SimulatedChannel};
    use rer::sim::packet::Packet;

    let impairment = ImpairmentConfig {
        seed: 42,
        loss_rate: 0.10,
        reorder_rate: 0.20,
        delay_ms: 10,
        jitter_ms: 5,
        ..Default::default()
    };

    let mut channel = SimulatedChannel::new(impairment);

    let count = 50;
    let mut input_packets = Vec::with_capacity(count as usize);
    for i in 0..count {
        let pkt_bytes =
            sample_valid_srt_data_packet(i, &format!("impairment test packet {i}").into_bytes());
        let pkt = Packet::new(format!("srt-{i}"), i as u64, i as u64 * 1000, pkt_bytes);
        input_packets.push(pkt);
    }

    let out_packets = channel.apply(input_packets);
    // Under 10% loss, some packets should be received
    assert!(
        !out_packets.is_empty(),
        "some packets must be received through impaired channel"
    );
    assert!(
        out_packets.len() <= count as usize,
        "cannot receive more than transmitted"
    );
}
