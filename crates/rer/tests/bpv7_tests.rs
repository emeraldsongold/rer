//! Integration tests for BPv7 CBOR Primary Block parser (SPEC §14, §8, Task RER-F-036).

use rer::bpv7::{
    evaluate_bpv7_payload, evaluate_bundle_header, evaluate_payload, parse_bpv7_primary_block,
    parse_bundle, parse_primary_block, Bpv7ParseError, BundleParseStatus, CrcType,
    CreationTimestamp, EndpointId, PrimaryBlock, BUNDLE_IS_FRAGMENT, BUNDLE_MUST_NOT_BE_FRAGMENTED,
    BUNDLE_PAYLOAD_IS_ADMIN_RECORD,
};

#[test]
fn test_criterion1_parse_valid_cbor_primary_block_matching_rfc9171_reference_vectors() {
    // RFC 9171 reference bundle vector:
    // Indefinite array [0x9f], Primary block [0x88, 7, 0, 0, [2, [2, 1]], [2, [1, 1]], [2, [0, 1]], [0x00ff00bb0e20b4ea, 0], 600000], ...
    let hex_bundle = "9f88070000820282020182028201018202820001821b00ff00bb0e20b4ea001a000927c08507020100410085010100004d48656c6f2c20576f726c642142ff";
    let raw_bundle: Vec<u8> = (0..hex_bundle.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_bundle[i..i + 2], 16).unwrap())
        .collect();

    // Parse from full bundle payload
    let header = parse_primary_block(&raw_bundle).expect("valid RFC 9171 bundle must parse");
    assert_eq!(header.version(), 7);
    assert_eq!(header.destination_eid(), "ipn:2.1");
    assert_eq!(header.source_node_id(), "ipn:1.1");
    assert_eq!(header.creation_timestamp().time(), 0x00ff_00bb_0e20_b4ea);
    assert_eq!(header.creation_timestamp().sequence_number(), 0);
    assert_eq!(header.lifetime(), 600_000);
    assert_eq!(header.lifetime_ms(), 600_000);
    assert!(!header.is_fragment());

    // Also parse using parse_bundle and parse_bpv7_primary_block aliases
    let header_b = parse_bundle(&raw_bundle).expect("parse_bundle alias must succeed");
    assert_eq!(header_b.version, 7);
    assert_eq!(header_b.destination_eid(), "ipn:2.1");

    let header_alias =
        parse_bpv7_primary_block(&raw_bundle).expect("parse_bpv7_primary_block alias must succeed");
    assert_eq!(header_alias.version, 7);

    // Parse standalone primary block slice
    let primary_slice = &raw_bundle[1..36];
    let header_slice =
        parse_primary_block(primary_slice).expect("standalone primary block slice must parse");
    assert_eq!(header_slice.version(), 7);
    assert_eq!(header_slice.destination_eid(), "ipn:2.1");
    assert_eq!(header_slice.source_node_id(), "ipn:1.1");
    assert_eq!(
        header_slice.creation_timestamp().time(),
        0x00ff_00bb_0e20_b4ea
    );
    assert_eq!(header_slice.creation_timestamp().sequence_number(), 0);
    assert_eq!(header_slice.lifetime(), 600_000);
}

#[test]
fn test_criterion2_primary_block_ipn_destination_and_dtn_source_decoded_uri_strings() {
    let primary = PrimaryBlock {
        version: 7,
        bundle_control_flags: BUNDLE_PAYLOAD_IS_ADMIN_RECORD,
        crc_type: CrcType::None,
        destination: EndpointId::ipn(42, 100),
        source: EndpointId::dtn("//mars-rover/telemetry/sensors"),
        report_to: EndpointId::dtn_none(),
        creation_timestamp: CreationTimestamp::new(55_000_000, 3),
        lifetime: 86_400_000,
        fragment_offset: None,
        total_application_data_unit_length: None,
        crc: None,
        crc_valid: None,
    };

    let cbor_bytes = primary.to_cbor();
    let parsed = parse_primary_block(&cbor_bytes).expect("mixed EID primary block must parse");

    assert_eq!(parsed.destination_eid(), "ipn:42.100");
    assert_eq!(
        parsed.source_node_id(),
        "dtn://mars-rover/telemetry/sensors"
    );
    assert_eq!(parsed.report_to_eid(), "dtn:none");

    // Verify Display, Deref, and equality helpers
    assert_eq!(parsed.destination.as_str(), "ipn:42.100");
    assert_eq!(parsed.destination.uri(), "ipn:42.100");
    assert_eq!(parsed.destination.to_string(), "ipn:42.100");
    assert_eq!(parsed.destination, "ipn:42.100");

    assert_eq!(parsed.source.as_str(), "dtn://mars-rover/telemetry/sensors");
    assert_eq!(parsed.source.uri(), "dtn://mars-rover/telemetry/sensors");
    assert_eq!(
        parsed.source.to_string(),
        "dtn://mars-rover/telemetry/sensors"
    );
    assert_eq!(parsed.source, "dtn://mars-rover/telemetry/sensors");
}

#[test]
fn test_criterion3_truncated_input_returns_truncated_error() {
    let primary = PrimaryBlock {
        version: 7,
        bundle_control_flags: 0,
        crc_type: CrcType::None,
        destination: EndpointId::ipn(1, 1),
        source: EndpointId::dtn("//earth-station/control"),
        report_to: EndpointId::dtn_none(),
        creation_timestamp: CreationTimestamp::new(12345, 1),
        lifetime: 3600,
        fragment_offset: None,
        total_application_data_unit_length: None,
        crc: None,
        crc_valid: None,
    };

    let cbor_bytes = primary.to_cbor();

    // Buffer shorter than primary block completion
    for cut in 1..cbor_bytes.len() {
        let truncated = &cbor_bytes[..cut];
        let err = parse_primary_block(truncated).expect_err("truncated buffer must error");
        assert!(
            err.is_truncated(),
            "cut at {cut}/{} must be truncated",
            cbor_bytes.len()
        );
        assert!(matches!(err, Bpv7ParseError::Truncated { .. }));
        assert_eq!(err.status(), BundleParseStatus::Truncated);
        assert!(err.to_string().contains("truncated input"));
    }

    // Declared CBOR item length longer than buffer
    // Major type 3 (text string) length 50, followed by only 4 bytes
    let truncated_item = [
        0x88, 0x07, 0x00, 0x00, 0x82, 0x01, 0x78, 50, b'f', b'o', b'o', b'b',
    ];
    let err_item =
        parse_primary_block(&truncated_item).expect_err("truncated text item must error");
    assert!(err_item.is_truncated());
    assert_eq!(err_item.status(), BundleParseStatus::Truncated);
    assert_eq!(
        evaluate_payload(&truncated_item),
        BundleParseStatus::Truncated
    );
}

#[test]
fn test_criterion4_fragmentation_flags_extracts_offset_and_adu_length() {
    let primary = PrimaryBlock {
        version: 7,
        bundle_control_flags: BUNDLE_IS_FRAGMENT | BUNDLE_MUST_NOT_BE_FRAGMENTED,
        crc_type: CrcType::None,
        destination: EndpointId::ipn(9, 1),
        source: EndpointId::ipn(10, 2),
        report_to: EndpointId::dtn_none(),
        creation_timestamp: CreationTimestamp::new(777_888, 9),
        lifetime: 14_400,
        fragment_offset: Some(8192),
        total_application_data_unit_length: Some(65536),
        crc: None,
        crc_valid: None,
    };

    let cbor_bytes = primary.to_cbor();
    let parsed = parse_primary_block(&cbor_bytes).expect("fragmented primary block must parse");

    assert!(parsed.is_fragment());
    assert_eq!(parsed.fragment_offset, Some(8192));
    assert_eq!(parsed.fragment_offset(), Some(8192));
    assert_eq!(parsed.total_application_data_unit_length, Some(65536));
    assert_eq!(parsed.total_application_data_unit_length(), Some(65536));
    assert_eq!(parsed.total_adu_length(), Some(65536));
    assert_eq!(parsed.total_data_length(), Some(65536));
}

#[test]
fn test_criterion5_evaluating_arbitrary_non_cbor_distinguishes_malformed_cbor_without_panicking() {
    let arbitrary_inputs: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!",
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09",
        &[0x1C, 0x01, 0x02],       // Reserved CBOR additional info 28
        &[0x3C, 0x10, 0x20],       // Reserved CBOR negative int additional info 28
        &[0x7C, 0xAA, 0xBB],       // Reserved CBOR text string additional info 28
        &[0x9C, 0x11, 0x22],       // Reserved CBOR array additional info 28
        &[0xBC, 0x33, 0x44],       // Reserved CBOR map additional info 28
        &[0xDC, 0x55, 0x66],       // Reserved CBOR tag additional info 28
        &[0xFC, 0x77, 0x88],       // Reserved CBOR simple additional info 28
        &[0xFF, 0x00, 0x11],       // Unexpected break code outside indefinite item
        &[0x65, 0xFF, 0xFF, 0xFF], // Invalid UTF-8 bytes in declared text string
    ];

    for input in arbitrary_inputs {
        let status = evaluate_payload(input);
        assert!(
            status.is_malformed() || status.is_not_bpv7(),
            "arbitrary non-CBOR payload must return MalformedCbor or NotBpv7, got {status:?}"
        );
        assert!(!status.is_valid());

        let status_alias = evaluate_bpv7_payload(input);
        assert_eq!(status_alias, status);

        let (eval_status, header_opt) = evaluate_bundle_header(input);
        assert_eq!(eval_status, status);
        assert!(header_opt.is_none());
    }
}

#[test]
fn test_crc_verification_crc16_and_crc32() {
    for crc_type in [CrcType::Crc16, CrcType::Crc32] {
        let primary = PrimaryBlock {
            version: 7,
            bundle_control_flags: 0,
            crc_type,
            destination: EndpointId::ipn(1, 1),
            source: EndpointId::ipn(2, 1),
            report_to: EndpointId::dtn_none(),
            creation_timestamp: CreationTimestamp::new(100, 1),
            lifetime: 3600,
            fragment_offset: None,
            total_application_data_unit_length: None,
            crc: None,
            crc_valid: None,
        };

        let bytes = primary.to_cbor();
        let parsed = parse_primary_block(&bytes).expect("valid CRC block must parse");
        assert!(parsed.has_crc());
        assert_eq!(parsed.is_crc_valid(), Some(true));
        assert!(parsed.check_crc());

        // Corrupt CRC
        let mut corrupted = bytes.clone();
        let last_idx = corrupted.len() - 1;
        corrupted[last_idx] ^= 0xFF;
        let parsed_corrupt =
            parse_primary_block(&corrupted).expect("block with invalid CRC still parses metadata");
        assert_eq!(parsed_corrupt.is_crc_valid(), Some(false));
        assert!(!parsed_corrupt.check_crc());
    }
}
