use std::collections::HashSet;
use std::time::Duration;

use rer::config::DropPolicy;
use rer::sim::{
    GeneratorConfig, HarnessConfig, ImpairmentConfig, Packet, ReceiverReport, SimulatedChannel,
    SimulationHarness, TrafficGenerator, TrafficReceiver,
};

// ---------------------------------------------------------------------------
// Criterion 1: Generator emits unique IDs, sequences, configurable params
// ---------------------------------------------------------------------------

#[test]
fn test_generator_unique_ids_sequence_numbers_and_configurable_parameters() {
    let config = GeneratorConfig {
        seed: 42,
        packet_size: 512,
        rate: Some(1000.0),
        burst: Some(5),
        duration: Some(Duration::from_secs(5)),
        count: Some(100),
    };

    let mut generator = TrafficGenerator::new(config);
    let mut ids = HashSet::new();
    let mut seq = 0u64;

    while let Some(pkt) = generator.next_packet() {
        assert_eq!(
            pkt.sequence, seq,
            "sequence numbers must be strictly increasing"
        );
        seq += 1;

        assert!(
            ids.insert(pkt.id.clone()),
            "packet id must be unique within stream: {}",
            pkt.id
        );
        assert_eq!(
            pkt.payload.len(),
            512,
            "payload size must match configured packet_size"
        );
        assert!(pkt.verify_hash(), "packet payload hash must be valid");
    }

    assert_eq!(seq, 100, "count limit must be respected");
    assert_eq!(ids.len(), 100, "all 100 packet IDs must be distinct");
}

#[test]
fn test_generator_duration_limit() {
    let config = GeneratorConfig {
        seed: 123,
        packet_size: 64,
        rate: Some(20.0),
        burst: Some(1),
        duration: Some(Duration::from_millis(50)),
        count: None,
    };

    let mut gen = TrafficGenerator::new(config);
    let start = std::time::Instant::now();
    let pkts = gen.emit_all();
    let elapsed = start.elapsed();

    assert!(elapsed >= Duration::from_millis(40));
    assert!(!pkts.is_empty());
}

// ---------------------------------------------------------------------------
// Criterion 2: Same seed reproduces the same packet stream
// ---------------------------------------------------------------------------

#[test]
fn test_same_seed_reproduces_same_packet_stream() {
    let seed = 0xdead_beef_cafe_babe;
    let config1 = GeneratorConfig {
        seed,
        packet_size: 128,
        rate: None,
        burst: None,
        duration: None,
        count: Some(50),
    };
    let config2 = config1.clone();

    let mut gen1 = TrafficGenerator::new(config1);
    let mut gen2 = TrafficGenerator::new(config2);

    let stream1: Vec<Packet> = gen1.by_ref().collect();
    let stream2: Vec<Packet> = gen2.by_ref().collect();

    assert_eq!(stream1.len(), 50);
    assert_eq!(stream2.len(), 50);

    for (p1, p2) in stream1.iter().zip(stream2.iter()) {
        assert_eq!(
            p1.id, p2.id,
            "packet IDs must match across identical seed runs"
        );
        assert_eq!(p1.sequence, p2.sequence, "sequences must match");
        assert_eq!(
            p1.payload, p2.payload,
            "payload bytes must match identically"
        );
        assert_eq!(
            p1.payload_hash, p2.payload_hash,
            "payload hashes must match identically"
        );
    }

    // Different seed produces different stream
    let config3 = GeneratorConfig {
        seed: 0x1234_5678,
        packet_size: 128,
        rate: None,
        burst: None,
        duration: None,
        count: Some(50),
    };
    let stream3: Vec<Packet> = TrafficGenerator::new(config3).collect();
    assert_ne!(stream1[0].id, stream3[0].id);
    assert_ne!(stream1[0].payload, stream3[0].payload);
}

// ---------------------------------------------------------------------------
// Criterion 3: Receiver verifies expected counts, hashes, reports loss/dup/reorder as JSON
// ---------------------------------------------------------------------------

#[test]
fn test_receiver_verifies_expected_counts_and_payload_hashes() {
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: 777,
        packet_size: 200,
        count: Some(25),
        ..Default::default()
    });

    let expected_stream_hash = gen.expected_stream_hash(25);
    let mut receiver = TrafficReceiver::new(Some(25), Some(expected_stream_hash.clone()));

    let packets = gen.emit_all();
    for pkt in &packets {
        receiver.record_packet(pkt);
    }

    let report = receiver.report();
    assert!(report.pass);
    assert_eq!(report.expected_count, Some(25));
    assert_eq!(report.received_count, 25);
    assert_eq!(report.unique_received_count, 25);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.reordered_count, 0);
    assert_eq!(report.corrupted_count, 0);
    assert!(report.payload_hashes_verified);
    assert_eq!(report.actual_stream_hash, Some(expected_stream_hash));

    // Verify JSON format
    let json_str = report.to_json();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("parse JSON");
    assert_eq!(parsed["pass"], true);
    assert_eq!(parsed["expected_count"], 25);
    assert_eq!(parsed["received_count"], 25);
    assert_eq!(parsed["lost_count"], 0);
    assert_eq!(parsed["duplicate_count"], 0);
    assert_eq!(parsed["reordered_count"], 0);
    assert_eq!(parsed["payload_hashes_verified"], true);
}

#[test]
fn test_receiver_reports_loss_duplication_and_reordering_as_json() {
    let mut receiver = TrafficReceiver::new(Some(6), None);
    receiver.set_test_id("impairment-detection-test".into());

    // Generate 6 packets: 0, 1, 2, 3, 4, 5
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: 42,
        packet_size: 32,
        count: Some(6),
        ..Default::default()
    });
    let pkts = gen.emit_all();

    // Injected arrival order:
    // Packet 0: normal
    // Packet 1: normal
    // Packet 4: arrives before 2 and 3 (reordering!)
    // Packet 2: arrives late
    // (Packet 3: lost, never arrives!)
    // Packet 4: duplicate arrival!
    // Packet 5: normal
    receiver.record_packet(&pkts[0]);
    receiver.record_packet(&pkts[1]);
    receiver.record_packet(&pkts[4]); // highest = 4
    receiver.record_packet(&pkts[2]); // reordered: seq 2 < highest 4
    receiver.record_packet(&pkts[4]); // duplicate: seq 4 seen again
    receiver.record_packet(&pkts[5]);

    let report = receiver.report();
    assert!(!report.pass, "test must fail on impairments");
    assert_eq!(report.expected_count, Some(6));
    assert_eq!(report.received_count, 6);
    assert_eq!(report.unique_received_count, 5); // 0, 1, 2, 4, 5

    // Loss verification
    assert_eq!(report.lost_count, 1);
    assert_eq!(report.lost_sequences, vec![3]);

    // Duplication verification
    assert_eq!(report.duplicate_count, 1);
    assert_eq!(report.duplicate_sequences, vec![4]);

    // Reordering verification
    assert_eq!(report.reordered_count, 1);
    assert_eq!(report.reordered_sequences.len(), 1);
    assert_eq!(report.reordered_sequences[0].sequence, 2);
    assert_eq!(report.reordered_sequences[0].previous_highest_seq, 4);

    // Verify JSON report output contains loss, duplication, and reordering
    let json_str = report.to_json();
    let parsed: ReceiverReport = ReceiverReport::from_json(&json_str).expect("valid JSON report");
    assert_eq!(parsed.test_id, Some("impairment-detection-test".into()));
    assert_eq!(parsed.lost_sequences, vec![3]);
    assert_eq!(parsed.duplicate_sequences, vec![4]);
    assert_eq!(parsed.reordered_sequences.len(), 1);
    assert_eq!(parsed.reordered_sequences[0].sequence, 2);
}

#[test]
fn test_receiver_detects_corrupted_payload_hash() {
    let mut receiver = TrafficReceiver::new(Some(1), None);
    let mut pkt = Packet::new("p0".into(), 0, 0, b"original-payload".to_vec());
    // Corrupt the payload without updating the hash
    pkt.payload[0] ^= 0xff;

    receiver.record_packet(&pkt);
    let report = receiver.report();

    assert!(!report.pass);
    assert_eq!(report.corrupted_count, 1);
    assert!(!report.payload_hashes_verified);
}

// ---------------------------------------------------------------------------
// Criterion 4: Harness runs unprivileged in ordinary CI
// ---------------------------------------------------------------------------

#[test]
fn test_simulation_harness_runs_unprivileged_in_ci() {
    let harness_config = HarnessConfig {
        test_id: Some("ci-unprivileged-standard-test".into()),
        generator: GeneratorConfig {
            seed: 2026,
            packet_size: 256,
            rate: Some(200.0),
            burst: Some(2),
            duration: None,
            count: Some(40),
        },
        impairments: None,
        use_relay: true,
        relay_queue_capacity: None,
        relay_drop_policy: None,
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("harness execution");

    assert!(report.pass, "unprivileged loopback relay harness must pass");
    assert_eq!(report.expected_count, Some(40));
    assert_eq!(report.received_count, 40);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.reordered_count, 0);
    assert!(report.payload_hashes_verified);

    // Validate JSON output
    let json = report.to_json();
    assert!(json.contains("\"pass\": true"));
    assert!(json.contains("\"ci-unprivileged-standard-test\""));
}

#[test]
fn test_simulation_harness_with_deterministic_impairments() {
    let harness_config = HarnessConfig {
        test_id: Some("ci-impairment-test".into()),
        generator: GeneratorConfig {
            seed: 888,
            packet_size: 128,
            rate: None,
            burst: None,
            duration: None,
            count: Some(50),
        },
        impairments: Some(ImpairmentConfig {
            seed: 555,
            loss_rate: 0.1,
            duplicate_rate: 0.1,
            reorder_rate: 0.1,
            delay_ms: 0,
            jitter_ms: 0,
        }),
        use_relay: true,
        relay_queue_capacity: None,
        relay_drop_policy: None,
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("harness run");

    // Impairments should be reflected in the report
    let json = report.to_json();
    let parsed: ReceiverReport = ReceiverReport::from_json(&json).expect("valid JSON");

    assert_eq!(parsed.expected_count, Some(50));
    // Verify that the receiver reported loss/duplication/reordering
    assert!(
        parsed.lost_count > 0 || parsed.duplicate_count > 0 || parsed.reordered_count > 0,
        "impairments must be captured by receiver report"
    );
}

#[test]
fn test_simulation_channel_in_memory_reproducibility() {
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: 1234,
        packet_size: 64,
        count: Some(30),
        ..Default::default()
    });
    let packets = gen.emit_all();

    let imp_cfg = ImpairmentConfig {
        seed: 7777,
        loss_rate: 0.2,
        duplicate_rate: 0.2,
        reorder_rate: 0.2,
        delay_ms: 0,
        jitter_ms: 0,
    };

    let mut ch1 = SimulatedChannel::new(imp_cfg.clone());
    let mut ch2 = SimulatedChannel::new(imp_cfg);

    let out1 = ch1.apply(packets.clone());
    let out2 = ch2.apply(packets);

    assert_eq!(
        out1, out2,
        "same impairment seed must produce identical impaired stream"
    );
}

#[test]
fn test_simulation_harness_with_relay_queue_drop_policy() {
    let harness_config = HarnessConfig {
        test_id: Some("ci-relay-queue-policy-test".into()),
        generator: GeneratorConfig {
            seed: 444,
            packet_size: 64,
            rate: Some(500.0),
            burst: Some(1),
            duration: None,
            count: Some(20),
        },
        impairments: None,
        use_relay: true,
        relay_queue_capacity: Some(50),
        relay_drop_policy: Some(DropPolicy::DropOldest),
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("harness run");
    assert!(report.pass);
    assert_eq!(report.received_count, 20);
}

#[test]
fn test_simulation_harness_duplicate_scenario() {
    let harness_config = HarnessConfig {
        test_id: Some("ci-duplicate-scenario-test".into()),
        generator: GeneratorConfig {
            seed: 2026,
            packet_size: 128,
            rate: None,
            burst: None,
            duration: None,
            count: Some(1000),
        },
        impairments: Some(ImpairmentConfig {
            seed: 1337,
            loss_rate: 0.0,
            duplicate_rate: 0.1,
            reorder_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
        }),
        use_relay: true,
        relay_queue_capacity: None,
        relay_drop_policy: None,
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("harness run");

    assert_eq!(report.expected_count, Some(1000));
    assert_eq!(
        report.lost_count, 0,
        "lost_count must be 0 despite duplicates"
    );
    assert!(
        report.duplicate_count > 0,
        "duplicate_count must be above 0 with 10% duplication"
    );
    assert_eq!(report.unique_received_count, 1000);
}

// ---------------------------------------------------------------------------
// RER-F-009: Sequence tracking and packet inspection tests
// ---------------------------------------------------------------------------

#[test]
fn test_sequence_extraction_configurable_widths_and_endianness() {
    use rer::{ByteOrder, SequenceConfig, SequenceTracker};

    // 1-byte sequence
    let seq_cfg_1 = SequenceConfig {
        enabled: true,
        offset: 0,
        width: 1,
        byte_order: ByteOrder::BigEndian,
        rollover_threshold: Some(256),
        ..Default::default()
    };
    let mut tracker1 = SequenceTracker::new("s1", Some(&seq_cfg_1), None);
    assert_eq!(tracker1.extract_sequence(&[42, 0, 0]), Some(42));
    let _ = tracker1.process_packet(&[42, 0, 0]);
    assert_eq!(tracker1.last_sequence(), Some(42));

    // 2-byte little-endian sequence at offset 2
    let seq_cfg_2 = SequenceConfig {
        enabled: true,
        offset: 2,
        width: 2,
        byte_order: ByteOrder::LittleEndian,
        rollover_threshold: Some(65536),
        ..Default::default()
    };
    let mut tracker2 = SequenceTracker::new("s2", Some(&seq_cfg_2), None);
    let pkt2 = [0xAA, 0xBB, 0x34, 0x12]; // 0x1234 = 4660
    assert_eq!(tracker2.extract_sequence(&pkt2), Some(4660));
    let _ = tracker2.process_packet(&pkt2);
    assert_eq!(tracker2.last_sequence(), Some(4660));

    // 4-byte big-endian sequence at offset 0
    let seq_cfg_4 = SequenceConfig {
        enabled: true,
        offset: 0,
        width: 4,
        byte_order: ByteOrder::BigEndian,
        rollover_threshold: None,
        ..Default::default()
    };
    let mut tracker4 = SequenceTracker::new("s4", Some(&seq_cfg_4), None);
    let pkt4 = [0x00, 0x01, 0x00, 0x00]; // 65536
    assert_eq!(tracker4.extract_sequence(&pkt4), Some(65536));
    let _ = tracker4.process_packet(&pkt4);
    assert_eq!(tracker4.last_sequence(), Some(65536));

    // 8-byte little-endian sequence at offset 1
    let seq_cfg_8 = SequenceConfig {
        enabled: true,
        offset: 1,
        width: 8,
        byte_order: ByteOrder::LittleEndian,
        rollover_threshold: None,
        ..Default::default()
    };
    let mut tracker8 = SequenceTracker::new("s8", Some(&seq_cfg_8), None);
    let mut pkt8 = vec![0xFF];
    pkt8.extend_from_slice(&123456789012345u64.to_le_bytes());
    assert_eq!(tracker8.extract_sequence(&pkt8), Some(123456789012345));
    let _ = tracker8.process_packet(&pkt8);
    assert_eq!(tracker8.last_sequence(), Some(123456789012345));

    // Off by default
    let tracker_def = SequenceTracker::new("s_def", None, None);
    assert!(!tracker_def.is_enabled());
    assert_eq!(tracker_def.extract_sequence(&[1, 2, 3, 4]), None);
}

#[test]
fn test_harness_gaps_duplicates_out_of_order_and_rollover_detected() {
    let mut receiver = TrafficReceiver::new(Some(10), None);
    receiver.set_rollover_threshold(100);

    // Sequence 0
    let p0 = Packet::new("p0".into(), 0, 0, vec![1, 2, 3]);
    receiver.record_packet(&p0);
    // Gap: sequence 1 missing, sequence 2 arrives
    let p2 = Packet::new("p2".into(), 2, 0, vec![4, 5, 6]);
    receiver.record_packet(&p2);
    // Duplicate: sequence 2 arrives again
    receiver.record_packet(&p2);
    // Out of order: sequence 1 arrives later
    let p1 = Packet::new("p1".into(), 1, 0, vec![7, 8, 9]);
    receiver.record_packet(&p1);
    // Sequence 99 arrives
    let p99 = Packet::new("p99".into(), 99, 0, vec![10]);
    receiver.record_packet(&p99);
    // Rollover: sequence 0 arrives after 99 (threshold 100)
    let p0_roll = Packet::new("p0_roll".into(), 0, 0, vec![11]);
    receiver.record_packet(&p0_roll);

    let report = receiver.report();
    assert_eq!(report.duplicate_count, 1, "must detect 1 duplicate");
    assert_eq!(report.reordered_count, 1, "must detect 1 out-of-order");
    assert_eq!(report.rollover_count, 1, "must detect 1 rollover");
    assert_eq!(receiver.rollover_count(), 1);
}

#[test]
fn test_simulation_harness_with_sequence_and_rollover_tracking() {
    use rer::{ByteOrder, SequenceConfig};

    let harness_config = HarnessConfig {
        test_id: Some("harness-sequence-tracking-test".into()),
        generator: GeneratorConfig {
            seed: 777,
            packet_size: 128,
            rate: None,
            burst: None,
            duration: None,
            count: Some(25),
        },
        impairments: None,
        use_relay: true,
        relay_queue_capacity: None,
        relay_drop_policy: None,
        sequence: Some(SequenceConfig {
            enabled: true,
            offset: 0,
            width: 4,
            byte_order: ByteOrder::BigEndian,
            rollover_threshold: Some(1000),
            ..Default::default()
        }),
        rollover_threshold: Some(1000),
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("run harness with sequence config");
    assert!(report.pass);
    assert_eq!(report.received_count, 25);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.gap_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.reordered_count, 0);
    assert_eq!(report.rollover_count, 0);
}

#[test]
fn test_previews_opt_in_and_length_bounded() {
    use rer::{format_ascii_preview, format_hex_preview, Config};

    // Previews opt-in: default minimal config has inspection = None
    let minimal_yaml = r#"
version: "1"
instance:
  id: "test-preview-defaults"
  streams:
    - id: "stream-no-preview"
      source:
        transport: "udp"
        address: "127.0.0.1:8001"
      destination:
        transport: "udp"
        address: "127.0.0.1:8002"
"#;
    let config = Config::from_yaml_str(minimal_yaml).expect("parse minimal");
    let stream = &config.all_instances()[0].streams[0];
    assert!(stream.sequence.is_none(), "sequence is off by default");
    assert!(stream.inspection.is_none(), "inspection is off by default");

    // Length bounded previews
    let sample = b"Hello, World! 0123456789\x00\xFF\x1B[31m";
    let hex_bounded = format_hex_preview(sample, 5);
    assert_eq!(hex_bounded, "48656c6c6f"); // exactly 5 bytes hex

    let ascii_bounded = format_ascii_preview(sample, 5);
    assert_eq!(ascii_bounded, "Hello"); // exactly 5 bytes ascii

    let ascii_printable = format_ascii_preview(sample, sample.len());
    // Non-printable replaced with '.'
    assert!(ascii_printable.starts_with("Hello, World! 0123456789"));
    assert!(ascii_printable.contains("..[31m"));
}
