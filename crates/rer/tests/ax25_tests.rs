//! Integration tests for in-tree AX.25 packet header parser (SPEC §14, §5, §8, Task RER-F-061).

use rer::ax25::{
    encode_address, encode_ax25_frame, parse_address, parse_address_field, parse_ax25_address,
    parse_ax25_frame, parse_ax25_header, parse_ax25_packet, parse_frame, parse_header,
    parse_packet, Ax25Address, Ax25AddressField, Ax25Frame, Ax25FrameType, Ax25Header, Ax25Packet,
    Ax25ParseError, FrameType, AX25_ADDR_SUBFIELD_LEN, AX25_CTRL_UI, AX25_CTRL_UI_PF,
    AX25_MAX_DIGIPEATERS, AX25_MIN_FRAME_LEN, AX25_PID_ARP, AX25_PID_ESCAPE, AX25_PID_FLEXNET,
    AX25_PID_ISO_8473, AX25_PID_NETROM, AX25_PID_NO_LAYER_3, AX25_PID_TCP_IP, AX25_PID_TEXNET,
    AX25_STANDARD_ADDR_LEN,
};

#[test]
fn test_criterion1_parse_15_byte_buffer_unshifts_callsigns_and_ssids() {
    // Acceptance criterion 1:
    // In crates/rer/src/ax25.rs, parsing a 15-byte buffer containing standard 7-byte destination
    // and 7-byte source address fields unshifts ASCII callsign characters by 1 bit and extracts
    // destination callsign, source callsign, and SSIDs in range 0 to 15.

    // 1. Manually craft a 15-byte AX.25 frame with unshifted callsigns:
    // Destination: "CQ" (ASCII 0x43, 0x51), padded with spaces (0x20).
    // Shifted left 1 bit:
    // 0x43 << 1 = 0x86
    // 0x51 << 1 = 0xA2
    // 0x20 << 1 = 0x40
    // SSID: 0, reserved bits 11, extension bit 0 -> (0 << 1) | 0x60 | 0 = 0x60
    //
    // Source: "N0CALL" (ASCII 'N', '0', 'C', 'A', 'L', 'L').
    // 'N' (0x4E) << 1 = 0x9C
    // '0' (0x30) << 1 = 0x60
    // 'C' (0x43) << 1 = 0x86
    // 'A' (0x41) << 1 = 0x82
    // 'L' (0x4C) << 1 = 0x98
    // 'L' (0x4C) << 1 = 0x98
    // SSID: 15, reserved bits 11, extension bit 1 -> (15 << 1) | 0x60 | 1 = 0x7F
    //
    // Control: 0x03 (UI)
    let manual_15_bytes: [u8; 15] = [
        0x86, 0xA2, 0x40, 0x40, 0x40, 0x40, 0x60, // Destination: "CQ-0"
        0x9C, 0x60, 0x86, 0x82, 0x98, 0x98, 0x7F, // Source: "N0CALL-15"
        0x03, // Control: 0x03
    ];
    assert_eq!(manual_15_bytes.len(), 15);

    let parsed = parse_ax25_frame(&manual_15_bytes).expect("15-byte frame parses");
    assert_eq!(parsed.destination.callsign, "CQ");
    assert_eq!(parsed.destination_callsign, "CQ");
    assert_eq!(parsed.destination.callsign(), "CQ");
    assert_eq!(parsed.destination.ssid, 0);
    assert_eq!(parsed.destination.ssid(), 0);
    assert_eq!(parsed.destination_ssid, 0);

    assert_eq!(parsed.source.callsign, "N0CALL");
    assert_eq!(parsed.source_callsign, "N0CALL");
    assert_eq!(parsed.source.callsign(), "N0CALL");
    assert_eq!(parsed.source.ssid, 15);
    assert_eq!(parsed.source.ssid(), 15);
    assert_eq!(parsed.source_ssid, 15);

    assert_eq!(parsed.control, 0x03);
    assert_eq!(parsed.frame_type, Ax25FrameType::UnnumberedInformation);
    assert!(parsed.is_unnumbered_information());
    assert!(parsed.is_ui());

    // 2. Iterate through all possible SSID values 0..=15
    for dest_ssid in 0..=15 {
        for src_ssid in 0..=15 {
            let dest = Ax25Address::new("DEST", dest_ssid);
            let src = Ax25Address::new("SRC", src_ssid);
            let bytes = encode_ax25_frame(&dest, &src, &[], 0x03, None, &[])
                .expect("encode 15-byte buffer");
            assert_eq!(bytes.len(), 15);

            let res = parse_ax25_frame(&bytes).expect("parse 15-byte buffer");
            assert_eq!(res.destination.callsign, "DEST");
            assert_eq!(res.destination_ssid, dest_ssid);
            assert_eq!(res.source.callsign, "SRC");
            assert_eq!(res.source_ssid, src_ssid);
        }
    }
}

#[test]
fn test_criterion2_parse_digipeater_addresses_and_repeated_bit() {
    // Acceptance criterion 2:
    // In crates/rer/src/ax25.rs, parsing an address field with digipeater addresses extracts
    // up to 8 repeater callsigns and identifies whether the repeated bit is set.

    let dest = Ax25Address::new("APRS", 0);
    let src = Ax25Address::new("MYCALL", 1);

    // Test with 1, 2, 4, and 8 repeaters
    for count in 1..=8 {
        let mut digis = Vec::with_capacity(count);
        for i in 0..count {
            let call = format!("RELAY{}", i + 1);
            let mut addr = Ax25Address::new(call, (i as u8) % 16);
            addr.repeated = (i % 2) == 0; // Even index: repeated = true, Odd index: repeated = false
            digis.push(addr);
        }

        let raw = encode_ax25_frame(
            &dest,
            &src,
            &digis,
            AX25_CTRL_UI,
            Some(0xF0),
            b"TestPayload",
        )
        .expect("encode frame with digis");

        let expected_addr_len = 14 + count * 7;
        let expected_total_len = expected_addr_len + 1 + 1 + 11;
        assert_eq!(raw.len(), expected_total_len);

        let parsed = parse_ax25_frame(&raw).expect("parse frame with digis");
        assert_eq!(parsed.digipeaters.len(), count);
        assert_eq!(parsed.repeaters.len(), count);

        let rep_calls = parsed.repeater_callsigns();
        assert_eq!(rep_calls.len(), count);

        for (i, rep_call) in rep_calls.iter().enumerate().take(count) {
            let expected_call = format!("RELAY{}", i + 1);
            let expected_repeated = (i % 2) == 0;

            assert_eq!(parsed.digipeaters[i].callsign, expected_call);
            assert_eq!(parsed.repeaters[i].callsign, expected_call);
            assert_eq!(*rep_call, expected_call.as_str());

            assert_eq!(parsed.digipeaters[i].repeated, expected_repeated);
            assert_eq!(parsed.digipeaters[i].is_repeated(), expected_repeated);
            assert_eq!(parsed.digipeaters[i].has_been_repeated(), expected_repeated);
            assert_eq!(parsed.repeaters[i].repeated, expected_repeated);
        }

        // Test address field parser directly
        let addr_field = parse_address_field(&raw).expect("parse address field");
        assert_eq!(addr_field.bytes_consumed, expected_addr_len);
        assert_eq!(addr_field.digipeaters.len(), count);
        assert_eq!(addr_field.repeaters.len(), count);
        assert_eq!(addr_field.repeater_callsigns().len(), count);
    }
}

#[test]
fn test_criterion3_control_byte_0x03_and_0x13_classification_and_pid() {
    // Acceptance criterion 3:
    // In crates/rer/src/ax25.rs, parsing a frame with control byte 0x03 or 0x13 classifies
    // the frame as Unnumbered Information and extracts the following protocol identifier byte.

    let dest = Ax25Address::new("DEST", 0);
    let src = Ax25Address::new("SRC", 0);

    // Test 0x03 with various PID bytes
    let pids = [
        AX25_PID_NO_LAYER_3, // 0xF0
        AX25_PID_TCP_IP,     // 0xCC
        AX25_PID_ARP,        // 0xCD
        AX25_PID_NETROM,     // 0xCF
        AX25_PID_ISO_8473,   // 0x08
        AX25_PID_ESCAPE,     // 0xFF
    ];

    for &pid in &pids {
        // Control byte 0x03 (UI, P/F = 0)
        let frame_0x03 = encode_ax25_frame(
            &dest,
            &src,
            &[],
            0x03,
            Some(pid),
            b"Payload for UI frame with 0x03",
        )
        .expect("encode UI 0x03");
        let parsed_0x03 = parse_ax25_frame(&frame_0x03).expect("parse UI 0x03");
        assert_eq!(parsed_0x03.frame_type, Ax25FrameType::UnnumberedInformation);
        assert!(parsed_0x03.is_unnumbered_information());
        assert!(parsed_0x03.is_ui());
        assert_eq!(parsed_0x03.control, 0x03);
        assert!(!parsed_0x03.poll_final);
        assert_eq!(parsed_0x03.pid, Some(pid));
        assert_eq!(parsed_0x03.protocol_id(), Some(pid));
        assert_eq!(parsed_0x03.protocol_identifier(), Some(pid));
        assert_eq!(parsed_0x03.payload, b"Payload for UI frame with 0x03");

        // Control byte 0x13 (UI, P/F = 1)
        let frame_0x13 = encode_ax25_frame(
            &dest,
            &src,
            &[],
            0x13,
            Some(pid),
            b"Payload for UI frame with 0x13",
        )
        .expect("encode UI 0x13");
        let parsed_0x13 = parse_ax25_frame(&frame_0x13).expect("parse UI 0x13");
        assert_eq!(parsed_0x13.frame_type, Ax25FrameType::UnnumberedInformation);
        assert!(parsed_0x13.is_unnumbered_information());
        assert!(parsed_0x13.is_ui());
        assert_eq!(parsed_0x13.control, 0x13);
        assert!(parsed_0x13.poll_final);
        assert_eq!(parsed_0x13.pid, Some(pid));
        assert_eq!(parsed_0x13.protocol_id(), Some(pid));
        assert_eq!(parsed_0x13.protocol_identifier(), Some(pid));
        assert_eq!(parsed_0x13.payload, b"Payload for UI frame with 0x13");
    }
}

#[test]
fn test_criterion4_input_shorter_than_15_bytes_returns_truncated_error() {
    // Acceptance criterion 4:
    // In crates/rer/src/ax25.rs, parsing an input buffer shorter than 15 bytes returns an
    // error indicating a truncated packet.

    let valid_frame = encode_ax25_frame(
        &Ax25Address::new("CQ", 0),
        &Ax25Address::new("N0CALL", 0),
        &[],
        AX25_CTRL_UI,
        None,
        &[],
    )
    .expect("valid 15-byte frame");
    assert_eq!(valid_frame.len(), 15);

    // Test buffer lengths from 0 to 14
    for len in 0..15 {
        let truncated = &valid_frame[..len];
        let err = parse_ax25_frame(truncated).expect_err("must fail for length < 15");
        assert_eq!(err, Ax25ParseError::TruncatedPacket);
        assert!(err.is_truncated());
        assert!(err.is_truncated_packet());
        assert!(format!("{err}").to_lowercase().contains("truncated packet"));

        // Also test aliases
        assert!(parse_ax25_header(truncated).is_err());
        assert!(parse_ax25_packet(truncated).is_err());
        assert!(parse_frame(truncated).is_err());
        assert!(parse_header(truncated).is_err());
        assert!(parse_packet(truncated).is_err());
        assert!(Ax25Frame::parse(truncated).is_err());
    }

    // Exactly 15 bytes parses successfully
    assert!(parse_ax25_frame(&valid_frame).is_ok());
}

#[test]
fn test_criterion5_non_alphanumeric_callsign_returns_parse_error_without_panic() {
    // Acceptance criterion 5:
    // In crates/rer/src/ax25.rs, parsing an address field containing non-alphanumeric callsign
    // characters returns a parse error without panicking.

    let dest = Ax25Address::new("CQ", 0);
    let src = Ax25Address::new("N0CALL", 0);
    let valid = encode_ax25_frame(&dest, &src, &[], AX25_CTRL_UI, None, &[]).expect("valid frame");

    let bad_chars = [
        b'!', b'@', b'#', b'$', b'%', b'^', b'&', b'*', b'(', b')', b'-', b'_', b'+', b'=', b'{',
        b'}', b'[', b']', b'|', b'\\', b':', b';', b'"', b'\'', b'<', b'>', b',', b'.', b'?', b'/',
        b'`', b'~', 0x00, 0x1F, 0x7F, 0x80, 0xFF,
    ];

    for &bad in &bad_chars {
        // Corrupt destination address byte
        let mut buf_dest = valid.clone();
        buf_dest[0] = bad << 1;
        let err_dest = parse_ax25_frame(&buf_dest).expect_err("non-alphanumeric in destination");
        assert!(err_dest.is_invalid_callsign());

        // Corrupt source address byte
        let mut buf_src = valid.clone();
        buf_src[7] = bad << 1;
        let err_src = parse_ax25_frame(&buf_src).expect_err("non-alphanumeric in source");
        assert!(err_src.is_invalid_callsign());

        // Corrupt single address subfield directly
        let mut single_addr = [0x40; 7];
        single_addr[0] = bad << 1;
        single_addr[6] = 0x61; // SSID 0, last bit 1
        let err_sub = parse_address(&single_addr).expect_err("non-alphanumeric in single address");
        assert!(err_sub.is_invalid_callsign());
    }
}

#[test]
fn test_type_aliases_and_api_surface() {
    // Verify Ax25Header and Ax25Packet aliases and FrameType alias
    let dest = Ax25Address::new("CQ", 0);
    let src = Ax25Address::new("W1AW", 0);
    let bytes = encode_ax25_frame(&dest, &src, &[], 0x03, Some(0xF0), b"test").unwrap();

    let header: Ax25Header = parse_ax25_header(&bytes).unwrap();
    let packet: Ax25Packet = parse_ax25_packet(&bytes).unwrap();
    let frame: Ax25Frame = parse_frame(&bytes).unwrap();

    assert_eq!(header.destination_callsign, "CQ");
    assert_eq!(packet.source_callsign, "W1AW");
    assert_eq!(frame.frame_type, FrameType::UnnumberedInformation);
    assert_eq!(frame.frame_type, Ax25FrameType::UI);
    assert_eq!(frame.frame_type, Ax25FrameType::Ui);

    // Verify constants
    assert_eq!(AX25_MIN_FRAME_LEN, 15);
    assert_eq!(AX25_STANDARD_ADDR_LEN, 14);
    assert_eq!(AX25_ADDR_SUBFIELD_LEN, 7);
    assert_eq!(AX25_MAX_DIGIPEATERS, 8);
    assert_eq!(AX25_CTRL_UI, 0x03);
    assert_eq!(AX25_CTRL_UI_PF, 0x13);
    assert_eq!(AX25_PID_NO_LAYER_3, 0xF0);
    assert_eq!(AX25_PID_ISO_8473, 0x08);
    assert_eq!(AX25_PID_TCP_IP, 0xCC);
    assert_eq!(AX25_PID_ARP, 0xCD);
    assert_eq!(AX25_PID_NETROM, 0xCF);
    assert_eq!(AX25_PID_FLEXNET, 0xCE);
    assert_eq!(AX25_PID_TEXNET, 0xC3);
    assert_eq!(AX25_PID_ESCAPE, 0xFF);

    // Verify encode_address, parse_address, parse_ax25_address, Ax25AddressField
    let enc = encode_address("TEST", 2, false, true).expect("encode single address");
    let parsed_addr1 = parse_address(&enc).expect("parse_address");
    let parsed_addr2 = parse_ax25_address(&enc).expect("parse_ax25_address");
    assert_eq!(parsed_addr1.callsign, "TEST");
    assert_eq!(parsed_addr1.ssid, 2);
    assert_eq!(parsed_addr2, parsed_addr1);

    let addr_field: Ax25AddressField = parse_address_field(&bytes).expect("parse_address_field");
    assert_eq!(addr_field.destination.callsign, "CQ");
    assert_eq!(addr_field.source.callsign, "W1AW");
}
