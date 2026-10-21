use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use rer::bpv7::{
    evaluate_bpv7_payload, evaluate_bundle_header, evaluate_payload, parse_bpv7_primary_block,
    parse_bundle, parse_primary_block, Bpv7ParseError, BundleParseStatus, CrcType,
    CreationTimestamp, EndpointId, PrimaryBlock, BUNDLE_IS_FRAGMENT, BUNDLE_MUST_NOT_BE_FRAGMENTED,
    BUNDLE_PAYLOAD_IS_ADMIN_RECORD,
};
use rer::config::Config;
use rer::diagnostics::DiagnosticStage;
use rer::framing::encode_frame;
use rer::relay::Relay;

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

#[test]
fn test_config_inspection_without_bpv7_defaults_to_none() {
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
    assert!(
        insp.bpv7.is_none(),
        "bpv7 must default to None when omitted"
    );
}

#[test]
fn test_rer_validate_bpv7_max_inspect_bytes_zero_returns_validation_error() {
    let yaml = r#"
version: "1"
instances:
  - id: "node-bpv7"
    streams:
      - id: "bp-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:4556"
        destination:
          transport: "udp"
          address: "127.0.0.1:4557"
        inspection:
          bpv7:
            max_inspect_bytes: 0
"#;
    let config = rer::config::Config::from_yaml_str(yaml).expect("parse YAML");
    let errors = config.validate();
    assert!(
        errors.iter().any(|e| {
            e.path.contains("inspection.bpv7.max_inspect_bytes")
                && e.reason.contains("invalid inspection size limit")
        }),
        "Expected validation error for invalid inspection size limit: {:?}",
        errors
    );

    // Also verify via CLI `rer validate`
    let temp_file =
        std::env::temp_dir().join(format!("test_bpv7_zero_{}.yaml", std::process::id()));
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
fn test_bundle_inspection_diagnostic_event_serializes_structured_metadata() {
    let event = rer::diagnostics::BundleInspection::new(
        "ipn:1.2",
        "dtn://origin/service",
        987_654_321u64,
        86_400_000u64,
        rer::bpv7::BundleParseStatus::Valid,
    );

    let json_str = serde_json::to_string(&event).expect("serialize BundleInspection");
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("parse JSON");

    assert_eq!(val["destination"], "ipn:1.2");
    assert_eq!(val["source"], "dtn://origin/service");
    assert_eq!(val["dtn_timestamp"], 987_654_321);
    assert_eq!(val["lifetime"], 86_400_000);
    assert_eq!(val["parse_status"], "valid");

    // Check structured bundle metadata representation
    assert!(
        val["bundle_metadata"].is_object(),
        "must contain structured bundle metadata"
    );
    assert_eq!(val["bundle_metadata"]["destination"], "ipn:1.2");
    assert_eq!(val["bundle_metadata"]["source"], "dtn://origin/service");
    assert_eq!(val["bundle_metadata"]["dtn_timestamp"], 987_654_321);
    assert_eq!(val["bundle_metadata"]["lifetime"], 86_400_000);
    assert_eq!(val["bundle_metadata"]["parse_status"], "valid");
}

#[test]
fn test_bundle_inspection_into_full_buffer_drops_without_blocking_or_panicking() {
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

    // Emit BundleInspection into the full buffer
    let bundle_ev = rer::diagnostics::BundleInspection::new(
        "ipn:10.1",
        "dtn://node/service",
        5000u64,
        10000u64,
        rer::bpv7::BundleParseStatus::Valid,
    );

    let emitted = buffer.emit(bundle_ev);
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
        rer::diagnostics::DiagnosticStage::BundleInspection
    );
}

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

fn rfc9171_bundle_bytes() -> Vec<u8> {
    let hex_bundle = "9f88070000820282020182028201018202820001821b00ff00bb0e20b4ea001a000927c08507020100410085010100004d48656c6f2c20576f726c642142ff";
    (0..hex_bundle.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_bundle[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn test_udp_forwarding_valid_bpv7_bundle_sends_exact_payload_unmodified() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-udp-bpv7"
    streams:
      - id: "s-bpv7-udp"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        inspection:
          bpv7:
            enabled: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(30));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Test 1: RFC 9171 reference bundle
    let bundle1 = rfc9171_bundle_bytes();
    sender
        .send_to(&bundle1, format!("127.0.0.1:{listen_port}"))
        .expect("send bundle1");

    let mut buf = vec![0u8; 4096];
    let (n1, _) = dest_sock.recv_from(&mut buf).expect("recv bundle1");
    assert_eq!(
        &buf[..n1],
        &bundle1[..],
        "received UDP datagram must match bundle bytes exactly unmodified"
    );

    // Test 2: Custom BPv7 primary block bundle
    let primary = PrimaryBlock {
        version: 7,
        bundle_control_flags: 0,
        crc_type: CrcType::None,
        destination: EndpointId::dtn("node-dest/service"),
        source: EndpointId::ipn(42, 100),
        report_to: EndpointId::dtn_none(),
        creation_timestamp: CreationTimestamp::new(1_000_000, 42),
        lifetime: 3_600_000,
        fragment_offset: None,
        total_application_data_unit_length: None,
        crc: None,
        crc_valid: None,
    };
    let bundle2 = primary.to_cbor();
    sender
        .send_to(&bundle2, format!("127.0.0.1:{listen_port}"))
        .expect("send bundle2");

    let (n2, _) = dest_sock.recv_from(&mut buf).expect("recv bundle2");
    assert_eq!(
        &buf[..n2],
        &bundle2[..],
        "received UDP datagram must match bundle2 bytes exactly unmodified"
    );

    // Verify diagnostic buffer recorded bundle inspection events
    let snap = relay.event_buffer().snapshot();
    let bpv7_events: Vec<_> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::BundleInspection)
        .collect();
    assert_eq!(
        bpv7_events.len(),
        2,
        "expected 2 BundleInspection diagnostic events"
    );

    assert_eq!(
        bpv7_events[0].bundle_destination.as_deref(),
        Some("ipn:2.1")
    );
    assert_eq!(bpv7_events[0].bundle_source.as_deref(), Some("ipn:1.1"));
    assert_eq!(bpv7_events[0].parse_status, Some(BundleParseStatus::Valid));

    assert_eq!(
        bpv7_events[1].bundle_destination.as_deref(),
        Some("dtn://node-dest/service")
    );
    assert_eq!(bpv7_events[1].bundle_source.as_deref(), Some("ipn:42.100"));
    assert_eq!(bpv7_events[1].parse_status, Some(BundleParseStatus::Valid));

    relay.stop();
}

#[test]
fn test_tcp_forwarding_bpv7_bundle_records_bundle_inspection_with_eids_and_forwards_unmodified() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-tcp-bpv7"
    streams:
      - id: "s-bpv7-tcp"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        inspection:
          bpv7:
            enabled: true
            extract_eids: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    client.set_nodelay(true).unwrap();

    let raw_bundle = rfc9171_bundle_bytes();
    let framed = encode_frame(&raw_bundle);
    client
        .write_all(&framed)
        .expect("write framed bundle to tcp");
    client.flush().expect("flush tcp");

    // Check payload received at destination is unmodified
    let mut buf = vec![0u8; 4096];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv from dest");
    assert_eq!(
        &buf[..n],
        &raw_bundle[..],
        "forwarded payload bytes must be unmodified"
    );

    // Check BundleInspection diagnostic event was recorded with extracted EIDs
    thread::sleep(Duration::from_millis(30));
    let snap = relay.event_buffer().snapshot();
    let bi_event = snap
        .events
        .iter()
        .find(|e| e.stage == DiagnosticStage::BundleInspection)
        .expect("must record a BundleInspection diagnostic event");

    assert_eq!(bi_event.bundle_destination.as_deref(), Some("ipn:2.1"));
    assert_eq!(bi_event.bundle_source.as_deref(), Some("ipn:1.1"));
    assert_eq!(bi_event.destination_endpoint.as_deref(), Some("ipn:2.1"));
    assert_eq!(bi_event.source_endpoint.as_deref(), Some("ipn:1.1"));
    assert_eq!(bi_event.dtn_timestamp, Some(0x00ff_00bb_0e20_b4ea));
    assert_eq!(bi_event.bundle_lifetime, Some(600_000));
    assert_eq!(bi_event.parse_status, Some(BundleParseStatus::Valid));

    let bi = bi_event
        .bundle_inspection
        .as_ref()
        .expect("structured bundle inspection present");
    assert_eq!(bi.destination(), "ipn:2.1");
    assert_eq!(bi.source(), "ipn:1.1");
    assert_eq!(bi.parse_status(), BundleParseStatus::Valid);

    relay.stop();
}

#[test]
fn test_relay_stream_malformed_cbor_and_non_bpv7_traffic_forwards_unmodified_without_stalling() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-unparsed-traffic"
    streams:
      - id: "s-unparsed"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        inspection:
          bpv7:
            enabled: true
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    client.set_nodelay(true).unwrap();

    // 1. Malformed CBOR bytes
    let malformed_cbor = vec![0x9f, 0x88, 0xff, 0xff];
    let framed_malformed = encode_frame(&malformed_cbor);
    client
        .write_all(&framed_malformed)
        .expect("write malformed cbor");
    client.flush().expect("flush");

    let mut buf = vec![0u8; 4096];
    let (n1, _) = dest_sock.recv_from(&mut buf).expect("recv malformed cbor");
    assert_eq!(
        &buf[..n1],
        &malformed_cbor[..],
        "malformed payload forwarded unmodified"
    );

    // 2. Valid non-BPv7 CBOR (integer 42: [0x18, 0x2A])
    let valid_cbor_not_bpv7 = vec![0x18, 0x2A];
    let framed_cbor = encode_frame(&valid_cbor_not_bpv7);
    client
        .write_all(&framed_cbor)
        .expect("write valid non-bpv7 cbor");
    client.flush().expect("flush");

    let (n2, _) = dest_sock
        .recv_from(&mut buf)
        .expect("recv valid non-bpv7 cbor");
    assert_eq!(
        &buf[..n2],
        &valid_cbor_not_bpv7[..],
        "non-bpv7 cbor forwarded unmodified"
    );

    // 3. Plain arbitrary non-CBOR text payload
    let plain_text = b"plain-telemetry-non-cbor-data-stream".to_vec();
    let framed_text = encode_frame(&plain_text);
    client.write_all(&framed_text).expect("write plain text");
    client.flush().expect("flush");

    let (n3, _) = dest_sock.recv_from(&mut buf).expect("recv plain text");
    assert_eq!(
        &buf[..n3],
        &plain_text[..],
        "plain text forwarded unmodified"
    );

    // 4. Valid BPv7 bundle right after unparsed traffic to prove thread did not stall
    let valid_bundle = rfc9171_bundle_bytes();
    let framed_bundle = encode_frame(&valid_bundle);
    client
        .write_all(&framed_bundle)
        .expect("write valid bundle");
    client.flush().expect("flush");

    let (n4, _) = dest_sock.recv_from(&mut buf).expect("recv valid bundle");
    assert_eq!(
        &buf[..n4],
        &valid_bundle[..],
        "valid bundle forwarded unmodified without stalling"
    );

    thread::sleep(Duration::from_millis(30));
    let snap = relay.event_buffer().snapshot();
    let inspection_events: Vec<_> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::BundleInspection)
        .collect();

    assert_eq!(inspection_events.len(), 4, "expected 4 inspection events");

    // Malformed CBOR event
    assert_eq!(
        inspection_events[0].parse_status,
        Some(BundleParseStatus::MalformedCbor)
    );
    assert!(inspection_events[0].parse_status.unwrap().is_malformed());

    // Valid non-BPv7 CBOR event
    assert_eq!(
        inspection_events[1].parse_status,
        Some(BundleParseStatus::NotBpv7)
    );
    assert!(inspection_events[1].parse_status.unwrap().is_not_bpv7());

    // Plain text event (unparsed traffic: malformed cbor or not bpv7)
    assert!(inspection_events[2].parse_status.is_some());
    assert!(!inspection_events[2].parse_status.unwrap().is_valid());

    // Valid bundle event
    assert_eq!(
        inspection_events[3].parse_status,
        Some(BundleParseStatus::Valid)
    );
    assert_eq!(
        inspection_events[3].bundle_destination.as_deref(),
        Some("ipn:2.1")
    );

    relay.stop();
}

#[test]
fn test_configuration_doc_specifies_bpv7_passive_inspection_without_storage_routing_bpsec_tcpclv4()
{
    let doc = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/CONFIGURATION.md"
    ))
    .expect("read docs/CONFIGURATION.md");

    assert!(
        doc.contains("passive metadata inspection without bundle storage, routing, BPSec verification, or TCPCLv4 convergence layer framing"),
        "docs/CONFIGURATION.md must specify BPv7 passive inspection non-claims"
    );
    assert!(doc.contains("stream.inspection.bpv7") || doc.contains("inspection.bpv7"));
    assert!(doc.contains("max_inspect_bytes"));
    assert!(doc.contains("extract_eids"));
}

#[test]
fn test_bpv7_inspection_disabled_preserves_behavior_no_bundle_inspection_event() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-disabled-bpv7"
    streams:
      - id: "s-bpv7-disabled"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        inspection:
          bpv7:
            enabled: false
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    let bundle = rfc9171_bundle_bytes();
    client
        .write_all(&encode_frame(&bundle))
        .expect("write frame");
    client.flush().expect("flush");

    let mut buf = vec![0u8; 4096];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], &bundle[..]);

    thread::sleep(Duration::from_millis(30));
    let snap = relay.event_buffer().snapshot();
    let bpv7_events: Vec<_> = snap
        .events
        .iter()
        .filter(|e| e.stage == DiagnosticStage::BundleInspection)
        .collect();
    assert!(
        bpv7_events.is_empty(),
        "disabled BPv7 inspection must not record BundleInspection events"
    );

    relay.stop();
}

#[test]
fn test_bpv7_inspection_extract_eids_false_omits_eids() {
    let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
    dest_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = dest_sock.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-no-eids"
    streams:
      - id: "s-no-eids"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        inspection:
          bpv7:
            enabled: true
            extract_eids: false
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(40));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    let bundle = rfc9171_bundle_bytes();
    client
        .write_all(&encode_frame(&bundle))
        .expect("write frame");
    client.flush().expect("flush");

    let mut buf = vec![0u8; 4096];
    let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], &bundle[..]);

    thread::sleep(Duration::from_millis(30));
    let snap = relay.event_buffer().snapshot();
    let bi_event = snap
        .events
        .iter()
        .find(|e| e.stage == DiagnosticStage::BundleInspection)
        .expect("BundleInspection recorded");
    assert_eq!(bi_event.bundle_destination, None);
    assert_eq!(bi_event.bundle_source, None);
    assert_eq!(bi_event.parse_status, Some(BundleParseStatus::Valid));

    relay.stop();
}
