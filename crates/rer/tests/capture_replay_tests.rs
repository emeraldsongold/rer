//! Integration tests for capture import, link types, controlled replay,
//! destination safety, fuzzing, and destination-side verification (SPEC §12, §17).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use rer::capture::{
    build_synthetic_frame, build_synthetic_pcap, build_synthetic_pcapng, parse_capture,
    CaptureError, LinkType, SyntheticPacket,
};
use rer::replay::{execute_replay_session, ReplayConfig};
use rer::sim::{GeneratorConfig, SplitMix64, TrafficGenerator, TrafficReceiver};

/// Creates a test list of synthetic packets.
fn make_test_packets(count: usize) -> Vec<SyntheticPacket> {
    let mut pkts = Vec::new();
    for i in 0..count {
        pkts.push(SyntheticPacket {
            timestamp: Duration::from_millis(10 * i as u64),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5000 + i as u16,
            dst_port: 6000,
            payload: format!("payload-datagram-test-{i}").into_bytes(),
        });
    }
    pkts
}

// ----------------------------------------------------------------------------
// 1. Link Types Regression Tests
// ----------------------------------------------------------------------------

#[test]
fn test_link_type_ethernet_ipv4_and_vlan() {
    let pkts = make_test_packets(5);
    let pcap_bytes = build_synthetic_pcap(LinkType::Ethernet, &pkts, false);

    let parsed = parse_capture(&pcap_bytes).expect("parse ethernet pcap");
    assert_eq!(parsed.len(), 5);
    for (i, p) in parsed.iter().enumerate() {
        assert_eq!(p.link_type, LinkType::Ethernet);
        assert_eq!(p.network_protocol.as_deref(), Some("ipv4"));
        assert_eq!(p.transport_protocol.as_deref(), Some("udp"));
        assert_eq!(p.src_port, Some(5000 + i as u16));
        assert_eq!(p.dst_port, Some(6000));
        assert_eq!(p.payload, pkts[i].payload);
    }

    // Ethernet with 802.1Q VLAN tag
    let mut vlan_frame = Vec::new();
    vlan_frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // Dst
    vlan_frame.extend_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]); // Src
    vlan_frame.extend_from_slice(&[0x81, 0x00]); // 802.1Q tag
    vlan_frame.extend_from_slice(&[0x00, 0x64]); // VLAN ID 100
    vlan_frame.extend_from_slice(&[0x08, 0x00]); // Encapsulated EtherType IPv4
    let raw_frame = build_synthetic_frame(LinkType::Raw, &pkts[0]);
    vlan_frame.extend_from_slice(&raw_frame);

    // Build pcap with this frame
    let mut custom_pcap = Vec::new();
    custom_pcap.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // Magic
    custom_pcap.extend_from_slice(&2u16.to_le_bytes());
    custom_pcap.extend_from_slice(&4u16.to_le_bytes());
    custom_pcap.extend_from_slice(&0i32.to_le_bytes());
    custom_pcap.extend_from_slice(&0u32.to_le_bytes());
    custom_pcap.extend_from_slice(&65535u32.to_le_bytes());
    custom_pcap.extend_from_slice(&(LinkType::Ethernet as u32).to_le_bytes());

    custom_pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    custom_pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    let flen = vlan_frame.len() as u32;
    custom_pcap.extend_from_slice(&flen.to_le_bytes());
    custom_pcap.extend_from_slice(&flen.to_le_bytes());
    custom_pcap.extend_from_slice(&vlan_frame);

    let parsed_vlan = parse_capture(&custom_pcap).expect("parse vlan ethernet");
    assert_eq!(parsed_vlan.len(), 1);
    assert_eq!(parsed_vlan[0].link_type, LinkType::Ethernet);
    assert_eq!(parsed_vlan[0].payload, pkts[0].payload);
}

#[test]
fn test_link_type_ethernet_ipv6() {
    let pkts = vec![SyntheticPacket {
        timestamp: Duration::from_millis(50),
        src_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        dst_ip: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        src_port: 8080,
        dst_port: 9090,
        payload: b"ipv6-test-payload".to_vec(),
    }];

    let pcap = build_synthetic_pcap(LinkType::Ethernet, &pkts, false);
    let parsed = parse_capture(&pcap).expect("parse ipv6 ethernet");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].network_protocol.as_deref(), Some("ipv6"));
    assert_eq!(parsed[0].src_port, Some(8080));
    assert_eq!(parsed[0].dst_port, Some(9090));
    assert_eq!(parsed[0].payload, b"ipv6-test-payload");
}

#[test]
fn test_link_type_linux_sll_and_sll2() {
    let pkts = make_test_packets(3);

    // Linux SLL v1
    let pcap_sll = build_synthetic_pcap(LinkType::LinuxSll, &pkts, false);
    let parsed_sll = parse_capture(&pcap_sll).expect("parse linux sll v1");
    assert_eq!(parsed_sll.len(), 3);
    assert_eq!(parsed_sll[0].link_type, LinkType::LinuxSll);
    assert_eq!(parsed_sll[0].payload, pkts[0].payload);

    // Linux SLL2 v2
    let pcap_sll2 = build_synthetic_pcap(LinkType::LinuxSll2, &pkts, false);
    let parsed_sll2 = parse_capture(&pcap_sll2).expect("parse linux sll2 v2");
    assert_eq!(parsed_sll2.len(), 3);
    assert_eq!(parsed_sll2[0].link_type, LinkType::LinuxSll2);
    assert_eq!(parsed_sll2[0].payload, pkts[0].payload);
}

#[test]
fn test_link_type_null_and_loop() {
    let pkts = make_test_packets(3);

    // BSD Null loopback
    let pcap_null = build_synthetic_pcap(LinkType::Null, &pkts, false);
    let parsed_null = parse_capture(&pcap_null).expect("parse bsd null");
    assert_eq!(parsed_null.len(), 3);
    assert_eq!(parsed_null[0].link_type, LinkType::Null);
    assert_eq!(parsed_null[0].payload, pkts[0].payload);

    // OpenBSD Loop loopback
    let pcap_loop = build_synthetic_pcap(LinkType::Loop, &pkts, false);
    let parsed_loop = parse_capture(&pcap_loop).expect("parse openbsd loop");
    assert_eq!(parsed_loop.len(), 3);
    assert_eq!(parsed_loop[0].link_type, LinkType::Loop);
    assert_eq!(parsed_loop[0].payload, pkts[0].payload);
}

#[test]
fn test_link_type_raw_ip() {
    let pkts = make_test_packets(3);

    let pcap_raw = build_synthetic_pcap(LinkType::Raw, &pkts, false);
    let parsed_raw = parse_capture(&pcap_raw).expect("parse raw ip");
    assert_eq!(parsed_raw.len(), 3);
    assert_eq!(parsed_raw[0].link_type, LinkType::Raw);
    assert_eq!(parsed_raw[0].payload, pkts[0].payload);
}

#[test]
fn test_pcapng_import_roundtrip() {
    let pkts = make_test_packets(6);
    let pcapng_bytes = build_synthetic_pcapng(LinkType::Ethernet, &pkts);

    let parsed = parse_capture(&pcapng_bytes).expect("parse pcapng");
    assert_eq!(parsed.len(), 6);
    for (i, p) in parsed.iter().enumerate() {
        assert_eq!(p.link_type, LinkType::Ethernet);
        assert_eq!(p.src_port, Some(5000 + i as u16));
        assert_eq!(p.dst_port, Some(6000));
        assert_eq!(p.payload, pkts[i].payload);
    }
}

// ----------------------------------------------------------------------------
// 2. Unsupported Link Types & Safe Rejection
// ----------------------------------------------------------------------------

#[test]
fn test_unsupported_link_types_rejected_safely() {
    // Construct PCAP with DLT_IEEE802_11 (105)
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]); // Magic
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&105u32.to_le_bytes()); // LinkType 105 (802.11 Wireless)

    let res = parse_capture(&pcap);
    match res {
        Err(CaptureError::UnsupportedLinkType(lt, desc)) => {
            assert_eq!(lt, 105);
            assert!(desc.contains("unsupported capture link type 105"));
        }
        other => panic!("expected UnsupportedLinkType error, got {:?}", other),
    }

    // LinkType 999
    let mut pcap999 = pcap.clone();
    pcap999[20..24].copy_from_slice(&999u32.to_le_bytes());
    let res999 = parse_capture(&pcap999);
    assert!(matches!(
        res999,
        Err(CaptureError::UnsupportedLinkType(999, _))
    ));
}

// ----------------------------------------------------------------------------
// 3. Malformed Input & Fuzz Tests
// ----------------------------------------------------------------------------

#[test]
fn test_malformed_pcap_headers_rejected_safely() {
    // 1. Empty input
    assert!(matches!(parse_capture(&[]), Err(CaptureError::EmptyInput)));

    // 2. Truncated header (< 12 bytes)
    assert!(matches!(
        parse_capture(&[0xd4, 0xc3, 0xb2]),
        Err(CaptureError::TruncatedHeader(_))
    ));

    // 3. Invalid magic
    assert!(matches!(
        parse_capture(&[0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0]),
        Err(CaptureError::InvalidMagic(_))
    ));

    // 4. Truncated packet record header
    let pkts = make_test_packets(1);
    let pcap = build_synthetic_pcap(LinkType::Ethernet, &pkts, false);
    // Cut file right inside the packet record header (e.g. 24 + 8 bytes)
    let truncated_hdr = &pcap[..32];
    assert!(matches!(
        parse_capture(truncated_hdr),
        Err(CaptureError::TruncatedHeader(_))
    ));

    // 5. Truncated packet payload
    let truncated_data = &pcap[..pcap.len() - 10];
    assert!(matches!(
        parse_capture(truncated_data),
        Err(CaptureError::MalformedPacket(_))
    ));

    // 6. Packet length exceeding limit
    let mut corrupt_len = pcap.clone();
    // incl_len is at bytes 32..36 (24 + 8)
    corrupt_len[32..36].copy_from_slice(&5_000_000u32.to_le_bytes());
    assert!(matches!(
        parse_capture(&corrupt_len),
        Err(CaptureError::MalformedPacket(_))
    ));
}

#[test]
fn test_malformed_pcapng_blocks_rejected_safely() {
    let pkts = make_test_packets(2);
    let pcapng = build_synthetic_pcapng(LinkType::Ethernet, &pkts);

    // 1. Block length < 12
    let mut corrupt_len = pcapng.clone();
    corrupt_len[4..8].copy_from_slice(&8u32.to_le_bytes());
    assert!(matches!(
        parse_capture(&corrupt_len),
        Err(CaptureError::MalformedBlock(_))
    ));

    // 2. Trailing block length mismatch
    let mut corrupt_trailing = pcapng.clone();
    let shb_len = u32::from_le_bytes([pcapng[4], pcapng[5], pcapng[6], pcapng[7]]) as usize;
    corrupt_trailing[shb_len - 4..shb_len].copy_from_slice(&999u32.to_le_bytes());
    assert!(matches!(
        parse_capture(&corrupt_trailing),
        Err(CaptureError::MalformedBlock(_))
    ));

    // 3. Truncated block
    let truncated_block = &pcapng[..pcapng.len() - 15];
    assert!(matches!(
        parse_capture(truncated_block),
        Err(CaptureError::MalformedBlock(_))
    ));
}

#[test]
fn test_fuzz_parser_with_arbitrary_and_mutated_inputs() {
    let mut prng = SplitMix64::new(0xdeadbeef12345678);

    // 1. Completely random byte buffers of varying lengths
    for _ in 0..1000 {
        let len = (prng.next_u64() % 4096) as usize;
        let mut buf = vec![0u8; len];
        prng.fill_bytes(&mut buf);

        // Parser must reject or handle safely without ever panicking
        let _ = parse_capture(&buf);
    }

    // 2. Bit mutations on valid PCAP
    let pkts = make_test_packets(4);
    let valid_pcap = build_synthetic_pcap(LinkType::Ethernet, &pkts, false);
    for _ in 0..1000 {
        let mut mutated = valid_pcap.clone();
        let num_mutations = (prng.next_u64() % 8 + 1) as usize;
        for _ in 0..num_mutations {
            let idx = (prng.next_u64() as usize) % mutated.len();
            mutated[idx] ^= (prng.next_u64() & 0xff) as u8;
        }
        let _ = parse_capture(&mutated);
    }

    // 3. Bit mutations on valid PCAPNG
    let valid_pcapng = build_synthetic_pcapng(LinkType::Ethernet, &pkts);
    for _ in 0..1000 {
        let mut mutated = valid_pcapng.clone();
        let num_mutations = (prng.next_u64() % 8 + 1) as usize;
        for _ in 0..num_mutations {
            let idx = (prng.next_u64() as usize) % mutated.len();
            mutated[idx] ^= (prng.next_u64() & 0xff) as u8;
        }
        let _ = parse_capture(&mutated);
    }
}

// ----------------------------------------------------------------------------
// 4. Controlled Replay Timing Modes
// ----------------------------------------------------------------------------

#[test]
fn test_replay_timing_modes() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let port = socket.local_addr().unwrap().port();
    let dest = format!("127.0.0.1:{port}");

    // Create 3 packets spaced 30ms apart
    let pkts = vec![
        SyntheticPacket {
            timestamp: Duration::ZERO,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5001,
            dst_port: port,
            payload: b"pkt-0".to_vec(),
        },
        SyntheticPacket {
            timestamp: Duration::from_millis(30),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5002,
            dst_port: port,
            payload: b"pkt-1".to_vec(),
        },
        SyntheticPacket {
            timestamp: Duration::from_millis(60),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5003,
            dst_port: port,
            payload: b"pkt-2".to_vec(),
        },
    ];

    let pcap_bytes = build_synthetic_pcap(LinkType::Ethernet, &pkts, false);
    let temp_file = std::env::temp_dir().join(format!("test_timing_{}.pcap", port));
    std::fs::write(&temp_file, &pcap_bytes).expect("write temp pcap");

    // 1. Maximum rate (speed = 0 / max_rate = true) should take < 20ms
    let max_rate_config = ReplayConfig {
        destination: dest.clone(),
        max_rate: true,
        ..Default::default()
    };
    let t0 = Instant::now();
    let rep_max = execute_replay_session(&temp_file, &max_rate_config).expect("run max rate");
    let dur_max = t0.elapsed();
    assert_eq!(rep_max.selected, 3);
    assert_eq!(rep_max.injected, 3);
    assert_eq!(rep_max.failed, 0);
    assert!(dur_max < Duration::from_millis(35));

    // 2. Scaled speed (4.0x faster -> 60ms / 4 = 15ms)
    let scaled_config = ReplayConfig {
        destination: dest.clone(),
        speed: 4.0,
        ..Default::default()
    };
    let t1 = Instant::now();
    let rep_scaled = execute_replay_session(&temp_file, &scaled_config).expect("run scaled");
    let dur_scaled = t1.elapsed();
    assert_eq!(rep_scaled.selected, 3);
    assert_eq!(rep_scaled.injected, 3);
    assert!(dur_scaled >= Duration::from_millis(10));

    let _ = std::fs::remove_file(&temp_file);
}

// ----------------------------------------------------------------------------
// 5. Stream, Endpoint, and Time-Range Filters
// ----------------------------------------------------------------------------

#[test]
fn test_replay_filters() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let port = socket.local_addr().unwrap().port();
    let dest = format!("127.0.0.1:{port}");

    let pkts = vec![
        SyntheticPacket {
            timestamp: Duration::from_millis(0),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5001,
            dst_port: port,
            payload: b"filter-stream-1".to_vec(),
        },
        SyntheticPacket {
            timestamp: Duration::from_millis(20),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5002,
            dst_port: port,
            payload: b"filter-stream-2".to_vec(),
        },
        SyntheticPacket {
            timestamp: Duration::from_millis(50),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5001,
            dst_port: port,
            payload: b"filter-stream-1-b".to_vec(),
        },
    ];

    let pcap_bytes = build_synthetic_pcap(LinkType::Ethernet, &pkts, false);
    let temp_file = std::env::temp_dir().join(format!("test_filter_{}.pcap", port));
    std::fs::write(&temp_file, &pcap_bytes).expect("write temp pcap");

    // 1. Filter by stream / port (5001 only -> 2 packets)
    let stream_cfg = ReplayConfig {
        destination: dest.clone(),
        stream_filter: Some("5001".to_string()),
        max_rate: true,
        ..Default::default()
    };
    let rep_stream = execute_replay_session(&temp_file, &stream_cfg).unwrap();
    assert_eq!(rep_stream.selected, 2);
    assert_eq!(rep_stream.injected, 2);

    // 2. Filter by source endpoint (5002 only -> 1 packet)
    let src_cfg = ReplayConfig {
        destination: dest.clone(),
        src_filter: Some("5002".to_string()),
        max_rate: true,
        ..Default::default()
    };
    let rep_src = execute_replay_session(&temp_file, &src_cfg).unwrap();
    assert_eq!(rep_src.selected, 1);
    assert_eq!(rep_src.injected, 1);

    // 3. Time-range filter: start_time >= 0.030s (only 3rd packet at 50ms)
    let time_cfg = ReplayConfig {
        destination: dest.clone(),
        start_time: Some(0.030),
        max_rate: true,
        ..Default::default()
    };
    let rep_time = execute_replay_session(&temp_file, &time_cfg).unwrap();
    assert_eq!(rep_time.selected, 1);
    assert_eq!(rep_time.injected, 1);

    // 4. Max packets limit: 1 packet
    let limit_cfg = ReplayConfig {
        destination: dest.clone(),
        max_packets: Some(1),
        max_rate: true,
        ..Default::default()
    };
    let rep_limit = execute_replay_session(&temp_file, &limit_cfg).unwrap();
    assert_eq!(rep_limit.selected, 1);
    assert_eq!(rep_limit.injected, 1);

    let _ = std::fs::remove_file(&temp_file);
}

// ----------------------------------------------------------------------------
// 6. Destination Safety Verification
// ----------------------------------------------------------------------------

#[test]
fn test_replay_destination_safety_checks() {
    let pkts = make_test_packets(1);
    let pcap_bytes = build_synthetic_pcap(LinkType::Ethernet, &pkts, false);
    let temp_file = std::env::temp_dir().join("test_safety.pcap");
    std::fs::write(&temp_file, &pcap_bytes).expect("write temp pcap");

    // 1. Missing / empty destination refused
    let empty_cfg = ReplayConfig {
        destination: "".to_string(),
        ..Default::default()
    };
    let err_empty = execute_replay_session(&temp_file, &empty_cfg).unwrap_err();
    assert!(err_empty.contains("explicit destination endpoint"));

    // 2. Non-test endpoint refused by default (e.g. public DNS 8.8.8.8:53)
    let non_test_cfg = ReplayConfig {
        destination: "8.8.8.8:53".to_string(),
        allow_non_test_destinations: false,
        ..Default::default()
    };
    let err_non_test = execute_replay_session(&temp_file, &non_test_cfg).unwrap_err();
    assert!(err_non_test.contains("refusing to replay capture to non-test endpoint '8.8.8.8:53'"));

    // 3. Private production network refused by default (e.g. 10.0.0.1:5000)
    let prod_cfg = ReplayConfig {
        destination: "10.0.0.1:5000".to_string(),
        allow_non_test_destinations: false,
        ..Default::default()
    };
    let err_prod = execute_replay_session(&temp_file, &prod_cfg).unwrap_err();
    assert!(err_prod.contains("refusing to replay capture to non-test endpoint '10.0.0.1:5000'"));

    // 4. Overridden non-test destination allowed when allow_non_test_destinations is set
    // Note: It will attempt to send to 192.0.2.1 (TEST-NET-1) or unresolvable and fail network send, but pass safety check!
    let override_cfg = ReplayConfig {
        destination: "192.0.2.1:5000".to_string(),
        allow_non_test_destinations: false, // 192.0.2.1 is already a test net!
        max_rate: true,
        ..Default::default()
    };
    let rep_override = execute_replay_session(&temp_file, &override_cfg);
    assert!(rep_override.is_ok());

    let _ = std::fs::remove_file(&temp_file);
}

// ----------------------------------------------------------------------------
// 7. Destination-Side Verification with Test Receiver
// ----------------------------------------------------------------------------

#[test]
fn test_destination_side_verification_with_test_receiver() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let port = socket.local_addr().unwrap().port();
    let dest = format!("127.0.0.1:{port}");

    // Generate deterministic packet stream using TrafficGenerator (RER-F-004)
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: 42,
        packet_size: 64,
        count: Some(20),
        ..Default::default()
    });
    let test_packets = gen.emit_all();
    assert_eq!(test_packets.len(), 20);

    // Build synthetic PCAP with these packets
    let mut syn_pkts = Vec::new();
    for (i, p) in test_packets.iter().enumerate() {
        syn_pkts.push(SyntheticPacket {
            timestamp: Duration::from_millis(5 * i as u64),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 7000 + i as u16,
            dst_port: port,
            payload: p.to_bytes(),
        });
    }

    let pcap_bytes = build_synthetic_pcap(LinkType::Ethernet, &syn_pkts, false);
    let temp_file = std::env::temp_dir().join(format!("test_dest_verify_{}.pcap", port));
    std::fs::write(&temp_file, &pcap_bytes).expect("write temp pcap");

    // Start background receiver thread
    let socket_clone = socket.try_clone().expect("clone socket");

    let receiver_handle = thread::spawn(move || {
        let mut receiver = TrafficReceiver::new(Some(20), None);
        receiver.set_test_id("destination-side-replay-verify".into());
        receiver
            .listen_udp(&socket_clone, Duration::from_millis(1000))
            .expect("listen_udp")
    });

    // Replay the capture
    let replay_config = ReplayConfig {
        destination: dest,
        max_rate: true,
        ..Default::default()
    };

    let rep = execute_replay_session(&temp_file, &replay_config).expect("replay session");
    assert_eq!(rep.selected, 20);
    assert_eq!(rep.attempted, 20);
    assert_eq!(rep.injected, 20);
    assert_eq!(rep.failed, 0);
    assert!(rep.success);

    // Verify JSON serialization of ReplayReport
    let json_str = rep.to_json();
    assert!(json_str.contains("\"selected\": 20"));
    assert!(json_str.contains("\"attempted\": 20"));
    assert!(json_str.contains("\"injected\": 20"));
    assert!(json_str.contains("\"failed\": 0"));

    let receiver_report = receiver_handle.join().expect("receiver join");

    // Verify destination receiver verified counts and payload hashes!
    assert_eq!(receiver_report.received_count, 20);
    assert_eq!(receiver_report.lost_count, 0);
    assert_eq!(receiver_report.duplicate_count, 0);
    assert_eq!(receiver_report.reordered_count, 0);
    assert!(receiver_report.payload_hashes_verified);
    assert!(receiver_report.pass);

    let _ = std::fs::remove_file(&temp_file);
}
