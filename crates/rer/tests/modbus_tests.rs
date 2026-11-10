//! Integration tests for in-tree Modbus TCP MBAP parser and exception handling (Task RER-F-074).

use rer::modbus::{
    encode_modbus_exception_response, encode_modbus_frame, parse_frame, parse_mbap_header,
    parse_mbap_header_with_fc, parse_modbus, parse_modbus_frame, parse_modbus_header,
    parse_modbus_pdu, parse_modbus_response, parse_pdu, ExceptionCode, MbapHeader, ModbusException,
    ModbusExceptionCode, ModbusFrame, ModbusParseError, ModbusPdu, MBAP_HEADER_LEN,
    MODBUS_FC_READ_HOLDING_REGISTERS, MODBUS_MAX_FRAME_LEN, MODBUS_MAX_LENGTH,
    MODBUS_MIN_FRAME_LEN, MODBUS_MIN_LENGTH, MODBUS_PROTOCOL_ID,
};

#[test]
fn test_criterion1_parse_mbap_header_matching_fields() {
    // Acceptance criterion 1:
    // In crates/rer/src/modbus.rs, parsing a 7-octet MBAP header with transaction ID 1,
    // protocol ID 0, length 6, unit ID 1, and function code 3 returns an MbapHeader with matching fields.
    let mut raw = [0u8; 8];
    raw[0..2].copy_from_slice(&1u16.to_be_bytes()); // transaction ID 1
    raw[2..4].copy_from_slice(&0u16.to_be_bytes()); // protocol ID 0
    raw[4..6].copy_from_slice(&6u16.to_be_bytes()); // length 6
    raw[6] = 1; // unit ID 1
    raw[7] = 3; // function code 3

    let header = parse_mbap_header(&raw).expect("parsing valid MBAP header must succeed");
    assert_eq!(header.transaction_id, 1);
    assert_eq!(header.protocol_id, 0);
    assert_eq!(header.length, 6);
    assert_eq!(header.unit_id, 1);
    assert_eq!(header.function_code, 3);
    assert!(!header.is_exception());
    assert_eq!(header.exception_code, None);
    assert_eq!(header.exception_code(), None);
    assert_eq!(header.exception, None);
    assert_eq!(header.exception(), None);

    // Also verify via MbapHeader::parse and from_slice
    let h_parse = MbapHeader::parse(&raw).expect("MbapHeader::parse must succeed");
    assert_eq!(h_parse, header);

    let h_slice = MbapHeader::from_slice(&raw).expect("MbapHeader::from_slice must succeed");
    assert_eq!(h_slice, header);

    let h_bytes = MbapHeader::from_bytes(&raw).expect("MbapHeader::from_bytes must succeed");
    assert_eq!(h_bytes, header);

    // Also verify parse_modbus_header alias
    let h_modbus = parse_modbus_header(&raw).expect("parse_modbus_header must succeed");
    assert_eq!(h_modbus, header);

    // Also verify parse_mbap_header_with_fc
    let h_fc =
        parse_mbap_header_with_fc(&raw[..7], 3).expect("parse_mbap_header_with_fc must succeed");
    assert_eq!(h_fc, header);

    // Also verify encode_modbus_frame
    let encoded = encode_modbus_frame(1, 1, 3, &[0x00, 0x64, 0x00, 0x0A]);
    let h_enc = parse_mbap_header(&encoded).expect("parse encoded frame");
    assert_eq!(h_enc.transaction_id, 1);
    assert_eq!(h_enc.unit_id, 1);
    assert_eq!(h_enc.function_code, MODBUS_FC_READ_HOLDING_REGISTERS);
}

#[test]
fn test_criterion2_parse_mbap_header_rejects_invalid_protocol_id() {
    // Acceptance criterion 2:
    // In crates/rer/src/modbus.rs, parsing an MBAP header with a protocol ID other than 0
    // returns an error rejecting invalid protocol identifiers.
    for invalid_proto in [1u16, 2, 42, 255, 65535] {
        let mut raw = [0u8; 8];
        raw[0..2].copy_from_slice(&1u16.to_be_bytes());
        raw[2..4].copy_from_slice(&invalid_proto.to_be_bytes());
        raw[4..6].copy_from_slice(&6u16.to_be_bytes());
        raw[6] = 1;
        raw[7] = 3;

        let err = parse_mbap_header(&raw).expect_err("non-zero protocol ID must be rejected");
        assert_eq!(err, ModbusParseError::InvalidProtocolId(invalid_proto));
        assert!(err.is_invalid_protocol_id());
        assert!(err.is_invalid_protocol_identifier());

        let err_msg = format!("{err}").to_lowercase();
        assert!(
            err_msg.contains("invalid protocol identifier")
                || err_msg.contains("invalid protocol id")
        );

        // Also test 7-octet slice
        let err7 =
            parse_mbap_header(&raw[..7]).expect_err("7-octet slice with non-zero proto must error");
        assert_eq!(err7, ModbusParseError::InvalidProtocolId(invalid_proto));
    }
}

#[test]
fn test_criterion3_parse_mbap_header_rejects_out_of_range_length() {
    // Acceptance criterion 3:
    // In crates/rer/src/modbus.rs, parsing an MBAP header declaring a length less than 2
    // or greater than 254 returns an error indicating an out-of-range length field.

    // Length less than 2
    for bad_len in [0u16, 1] {
        let mut raw = [0u8; 8];
        raw[0..2].copy_from_slice(&1u16.to_be_bytes());
        raw[2..4].copy_from_slice(&0u16.to_be_bytes());
        raw[4..6].copy_from_slice(&bad_len.to_be_bytes());
        raw[6] = 1;
        raw[7] = 3;

        let err = parse_mbap_header(&raw).expect_err("length < 2 must be rejected");
        assert_eq!(err, ModbusParseError::LengthOutOfRange(bad_len));
        assert!(err.is_length_out_of_range());
        assert!(err.is_out_of_range_length());
        assert!(err.is_invalid_length());

        let err_msg = format!("{err}").to_lowercase();
        assert!(err_msg.contains("out-of-range length field"));

        // Also test 7-octet slice
        let err7 =
            parse_mbap_header(&raw[..7]).expect_err("7-octet slice with length < 2 must error");
        assert_eq!(err7, ModbusParseError::LengthOutOfRange(bad_len));
    }

    // Length greater than 254
    for bad_len in [255u16, 256, 300, 1000, 65535] {
        let mut raw = [0u8; 8];
        raw[0..2].copy_from_slice(&1u16.to_be_bytes());
        raw[2..4].copy_from_slice(&0u16.to_be_bytes());
        raw[4..6].copy_from_slice(&bad_len.to_be_bytes());
        raw[6] = 1;
        raw[7] = 3;

        let err = parse_mbap_header(&raw).expect_err("length > 254 must be rejected");
        assert_eq!(err, ModbusParseError::LengthOutOfRange(bad_len));
        assert!(err.is_length_out_of_range());
        assert!(err.is_out_of_range_length());
        assert!(err.is_invalid_length());

        let err_msg = format!("{err}").to_lowercase();
        assert!(err_msg.contains("out-of-range length field"));

        // Also test 7-octet slice
        let err7 =
            parse_mbap_header(&raw[..7]).expect_err("7-octet slice with length > 254 must error");
        assert_eq!(err7, ModbusParseError::LengthOutOfRange(bad_len));
    }

    // Boundary valid lengths (2 and 254) must succeed
    let mut raw_min = [0u8; 8];
    raw_min[0..2].copy_from_slice(&1u16.to_be_bytes());
    raw_min[2..4].copy_from_slice(&0u16.to_be_bytes());
    raw_min[4..6].copy_from_slice(&2u16.to_be_bytes());
    raw_min[6] = 1;
    raw_min[7] = 3;
    assert!(parse_mbap_header(&raw_min).is_ok());

    let mut raw_max = [0u8; 8];
    raw_max[0..2].copy_from_slice(&1u16.to_be_bytes());
    raw_max[2..4].copy_from_slice(&0u16.to_be_bytes());
    raw_max[4..6].copy_from_slice(&254u16.to_be_bytes());
    raw_max[6] = 1;
    raw_max[7] = 3;
    assert!(parse_mbap_header(&raw_max).is_ok());
}

#[test]
fn test_criterion4_parse_frame_exception_0x83_and_0x02_illegal_data_address() {
    // Acceptance criterion 4:
    // In crates/rer/src/modbus.rs, parsing a frame with function code 0x83 and exception code 0x02
    // identifies an exception response with illegal data address.
    let frame_bytes = encode_modbus_exception_response(1, 1, 0x03, 0x02);
    assert_eq!(frame_bytes[7], 0x83);
    assert_eq!(frame_bytes[8], 0x02);

    let frame: ModbusFrame =
        parse_modbus_frame(&frame_bytes).expect("parse_modbus_frame must succeed");
    assert!(frame.is_exception());
    assert_eq!(frame.function_code, 0x83);
    assert_eq!(frame.exception_code, Some(0x02));
    assert_eq!(frame.exception_code(), Some(0x02));
    assert_eq!(
        frame.exception,
        Some(ModbusExceptionCode::IllegalDataAddress)
    );
    assert_eq!(
        frame.exception(),
        Some(ModbusExceptionCode::IllegalDataAddress)
    );
    assert!(frame.is_illegal_data_address());
    assert_eq!(
        frame.exception.unwrap().description(),
        "illegal data address"
    );

    // Test parse_frame alias
    let f_alias = parse_frame(&frame_bytes).expect("parse_frame must succeed");
    assert!(f_alias.is_exception());
    assert!(f_alias.is_illegal_data_address());

    // Test parse_modbus alias
    let f_modbus = parse_modbus(&frame_bytes).expect("parse_modbus must succeed");
    assert!(f_modbus.is_exception());
    assert!(f_modbus.is_illegal_data_address());

    // Test parse_modbus_response alias
    let f_resp = parse_modbus_response(&frame_bytes).expect("parse_modbus_response must succeed");
    assert!(f_resp.is_exception());
    assert!(f_resp.is_illegal_data_address());

    // Test parse_mbap_header
    let header = parse_mbap_header(&frame_bytes).expect("parse_mbap_header must succeed");
    assert!(header.is_exception());
    assert_eq!(header.function_code, 0x83);
    assert_eq!(header.exception_code, Some(0x02));
    assert_eq!(
        header.exception,
        Some(ModbusExceptionCode::IllegalDataAddress)
    );
    assert!(header.is_illegal_data_address());

    // Test bare PDU frame
    let bare_pdu = [0x83, 0x02];
    let pdu: ModbusPdu = parse_modbus_pdu(&bare_pdu).expect("parse_modbus_pdu must succeed");
    assert!(pdu.is_exception());
    assert_eq!(pdu.exception_code, Some(0x02));
    assert_eq!(pdu.exception, Some(ModbusExceptionCode::IllegalDataAddress));
    assert!(pdu.is_illegal_data_address());

    let pdu_alias = parse_pdu(&bare_pdu).expect("parse_pdu must succeed");
    assert!(pdu_alias.is_illegal_data_address());

    // Test ModbusExceptionCode enum equality with u8 and aliases
    let exc: ModbusException = ModbusExceptionCode::IllegalDataAddress;
    let exc_code: ExceptionCode = ModbusExceptionCode::IllegalDataAddress;
    assert_eq!(exc, 0x02);
    assert_eq!(0x02, exc_code);
    assert_eq!(
        ModbusExceptionCode::from_u8(0x02),
        Some(ModbusExceptionCode::IllegalDataAddress)
    );
    assert!(ModbusExceptionCode::IllegalDataAddress.is_illegal_data_address());
}

#[test]
fn test_modbus_constants_and_limits() {
    assert_eq!(MBAP_HEADER_LEN, 7);
    assert_eq!(MODBUS_PROTOCOL_ID, 0);
    assert_eq!(MODBUS_MIN_LENGTH, 2);
    assert_eq!(MODBUS_MAX_LENGTH, 254);
    assert_eq!(MODBUS_MIN_FRAME_LEN, 8);
    assert_eq!(MODBUS_MAX_FRAME_LEN, 260);
}
