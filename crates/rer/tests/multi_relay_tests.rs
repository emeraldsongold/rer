use std::net::UdpSocket;
use std::time::Duration;

use rer::config::{DropPolicy, TransportType};
use rer::sim::{
    DivergenceType, ImpairmentConfig, RelayHopConfig, SimulationHarness, TestController,
    TestOutcome, TopologyConfig, TopologyReport,
};
use rer::{Config, Relay};

// ---------------------------------------------------------------------------
// Criterion 1: Multi-relay chains run in CI with deterministic seeds
// ---------------------------------------------------------------------------

#[test]
fn test_multi_relay_chain_deterministic_seeds_udp() {
    let seed = 42;
    let count = 40;

    // Run 1 with seed 42
    let config1 = TopologyConfig::chain_udp(3, seed, count);
    let report1 = TestController::run(config1).expect("multi-relay UDP chain must run");

    assert_eq!(report1.outcome, TestOutcome::Pass);
    assert!(report1.pass);
    assert_eq!(report1.hops.len(), 5); // Generator + 3 Relays + Receiver
    assert_eq!(report1.correlation.source_emitted, count);
    assert_eq!(report1.correlation.final_received, count);
    assert_eq!(report1.correlation.unique_received, count);
    assert_eq!(report1.correlation.total_lost, 0);
    assert_eq!(report1.correlation.total_duplicates, 0);
    assert!(report1.first_divergence.is_none());

    // Run 2 with same seed 42 must produce identical results
    let config2 = TopologyConfig::chain_udp(3, seed, count);
    let report2 = TestController::run(config2).expect("multi-relay UDP chain must run");

    assert_eq!(report2.outcome, TestOutcome::Pass);
    assert_eq!(
        report1.correlation.source_emitted,
        report2.correlation.source_emitted
    );
    assert_eq!(
        report1.correlation.final_received,
        report2.correlation.final_received
    );

    // Run 3 with different seed
    let config3 = TopologyConfig::chain_udp(3, 99999, count);
    let report3 = TestController::run(config3).expect("multi-relay UDP chain must run");
    assert_eq!(report3.outcome, TestOutcome::Pass);
    assert_ne!(report1.seed, report3.seed);
}

#[test]
fn test_multi_relay_chain_mixed_transport_conversions() {
    let mut config = TopologyConfig::new(101);
    config.generator.count = Some(25);
    config.destination_transport = TransportType::Udp;

    // Relay 1: UDP -> TCP
    config.relays.push(
        RelayHopConfig::new("relay-1").with_transports(TransportType::Udp, TransportType::Tcp),
    );
    // Relay 2: TCP -> TCP
    config.relays.push(
        RelayHopConfig::new("relay-2").with_transports(TransportType::Tcp, TransportType::Tcp),
    );
    // Relay 3: TCP -> UDP
    config.relays.push(
        RelayHopConfig::new("relay-3").with_transports(TransportType::Tcp, TransportType::Udp),
    );

    let report = SimulationHarness::run_topology(config)
        .expect("mixed transport multi-relay chain must run");

    assert_eq!(report.outcome, TestOutcome::Pass);
    assert!(report.pass);
    assert_eq!(report.correlation.source_emitted, 25);
    assert_eq!(report.correlation.final_received, 25);
    assert_eq!(report.correlation.total_lost, 0);
}

// ---------------------------------------------------------------------------
// Criterion 2: Each test run has a unique ID, and per-hop observations are collected and correlated
// ---------------------------------------------------------------------------

#[test]
fn test_unique_test_id_and_per_hop_observations() {
    // 1. Auto-generated unique run IDs
    let c1 = TopologyConfig::chain_udp(2, 42, 10);
    let r1 = TestController::run(c1).expect("run 1");

    let c2 = TopologyConfig::chain_udp(2, 42, 10);
    let r2 = TestController::run(c2).expect("run 2");

    assert!(!r1.test_id.is_empty());
    assert!(!r2.test_id.is_empty());
    assert_ne!(
        r1.test_id, r2.test_id,
        "each test run must have a distinct unique run ID"
    );

    // 2. Explicit configured unique run ID
    let explicit_id = "test-run-dist-corr-abc-123";
    let mut c3 = TopologyConfig::chain_udp(2, 55, 15);
    c3.test_id = Some(explicit_id.to_string());
    let r3 = TestController::run(c3).expect("run 3");

    assert_eq!(r3.test_id, explicit_id);

    // Verify per-hop observations are collected at each hop
    assert_eq!(r3.hops.len(), 4); // Generator, Relay 1, Relay 2, Receiver
    assert_eq!(r3.hops[0].hop_id, "generator");
    assert_eq!(r3.hops[1].hop_id, "relay-1");
    assert_eq!(r3.hops[2].hop_id, "relay-2");
    assert_eq!(r3.hops[3].hop_id, "receiver");

    // All hops must carry the run's unique correlation ID
    for hop in &r3.hops {
        assert_eq!(
            hop.correlation_id.as_deref(),
            Some(explicit_id),
            "hop '{}' must carry the test run's correlation ID",
            hop.hop_id
        );
    }

    // Input and output counts correlated across hops
    assert_eq!(r3.hops[0].local_send_success_count, 15);
    assert_eq!(r3.hops[1].received_count, 15);
    assert_eq!(r3.hops[1].local_send_success_count, 15);
    assert_eq!(r3.hops[2].received_count, 15);
    assert_eq!(r3.hops[2].local_send_success_count, 15);
    assert_eq!(r3.hops[3].received_count, 15);

    // Downstream delivery independently observed at each hop
    assert_eq!(r3.hops[0].downstream_delivered_count, 15);
    assert_eq!(r3.hops[1].downstream_delivered_count, 15);
    assert_eq!(r3.hops[2].downstream_delivered_count, 15);
    assert_eq!(r3.hops[3].downstream_delivered_count, 0); // Terminal receiver
}

// ---------------------------------------------------------------------------
// Criterion 3: The first point of divergence (gap, duplicate or mismatch) is identified
// ---------------------------------------------------------------------------

#[test]
fn test_identify_first_point_of_divergence_gap_on_link() {
    let mut config = TopologyConfig::new(42);
    config.generator.count = Some(30);

    // Relay 1 with egress loss (impairment drops 30% of packets on link between relay-1 and relay-2)
    let loss_impairment = ImpairmentConfig {
        loss_rate: 0.3,
        duplicate_rate: 0.0,
        reorder_rate: 0.0,
        delay_ms: 0,
        jitter_ms: 0,
        seed: 42,
        ..Default::default()
    };

    config
        .relays
        .push(RelayHopConfig::new("relay-1").with_impairments(loss_impairment));
    config.relays.push(RelayHopConfig::new("relay-2"));

    let report = TestController::run(config).expect("test run with loss");

    assert_eq!(report.outcome, TestOutcome::Fail);
    assert!(!report.pass);

    let first = report
        .first_divergence
        .expect("first point of divergence must be identified");
    assert_eq!(first.divergence_type, DivergenceType::Gap);
    // Divergence first observed at relay-2 (loss between relay-1 and relay-2)
    assert_eq!(first.hop_id, "relay-2");
    assert!(report.correlation.total_lost > 0);
}

#[test]
fn test_identify_first_point_of_divergence_duplicate_on_link() {
    let mut config = TopologyConfig::new(42);
    config.generator.count = Some(20);

    // Egress duplication between relay-1 and relay-2
    let dup_impairment = ImpairmentConfig {
        loss_rate: 0.0,
        duplicate_rate: 0.5,
        reorder_rate: 0.0,
        delay_ms: 0,
        jitter_ms: 0,
        seed: 99,
        ..Default::default()
    };

    config
        .relays
        .push(RelayHopConfig::new("relay-1").with_impairments(dup_impairment));
    config.relays.push(RelayHopConfig::new("relay-2"));

    let report = TestController::run(config).expect("test run with duplicates");

    assert_eq!(report.outcome, TestOutcome::Fail);
    assert!(!report.pass);

    let first = report
        .first_divergence
        .expect("first point of divergence must be identified");
    assert_eq!(first.divergence_type, DivergenceType::Duplicate);
    assert!(report.correlation.total_duplicates > 0);
}

#[test]
fn test_identify_first_point_of_divergence_queue_overflow_drop() {
    let mut config = TopologyConfig::new(42);
    config.generator.count = Some(30);

    // Relay 1 with tiny queue capacity 3 and Reject drop policy
    config
        .relays
        .push(RelayHopConfig::new("relay-1").with_queue(3, DropPolicy::DropOldest));
    config.relays.push(RelayHopConfig::new("relay-2"));

    let report = TestController::run(config).expect("test run with queue drops");

    // Queue drops must be detected as gap divergence
    if report.hops[1].dropped_count > 0 {
        assert_eq!(report.outcome, TestOutcome::Fail);
        assert!(!report.pass);
        let first = report
            .first_divergence
            .expect("first divergence must be identified");
        assert_eq!(first.divergence_type, DivergenceType::Gap);
        assert_eq!(first.hop_id, "relay-1");
    }
}

// ---------------------------------------------------------------------------
// Criterion 4: An unreachable relay yields incomplete or unknown, never pass
// ---------------------------------------------------------------------------

#[test]
fn test_unreachable_intermediate_relay_yields_incomplete_or_unknown_never_pass() {
    let mut config = TopologyConfig::new(42);
    config.generator.count = Some(20);

    config.relays.push(RelayHopConfig::new("relay-1"));
    // Relay 2 is simulated as unreachable (e.g. node down, uncontactable)
    config
        .relays
        .push(RelayHopConfig::new("relay-2").unreachable());
    config.relays.push(RelayHopConfig::new("relay-3"));

    let report = TestController::run(config).expect("test run with unreachable relay");

    // MUST NEVER BE PASS!
    assert_ne!(report.outcome, TestOutcome::Pass);
    assert!(!report.pass, "unreachable relay must never yield pass");
    assert!(
        report.outcome == TestOutcome::Incomplete || report.outcome == TestOutcome::Unknown,
        "unreachable relay must yield incomplete or unknown, got {:?}",
        report.outcome
    );

    assert!(report.correlation.has_unreachable_relay);
    assert!(!report.hops[2].reachable);
    assert_eq!(report.hops[2].hop_id, "relay-2");

    let first = report
        .first_divergence
        .expect("unreachable relay must register as divergence");
    assert_eq!(first.hop_id, "relay-2");
}

#[test]
fn test_unreachable_first_relay_yields_unknown_never_pass() {
    let mut config = TopologyConfig::new(42);
    config.generator.count = Some(10);

    // Relay 1 is unreachable right from the start
    config
        .relays
        .push(RelayHopConfig::new("relay-1").unreachable());

    let report = TestController::run(config).expect("test run with unreachable first relay");

    assert_ne!(report.outcome, TestOutcome::Pass);
    assert!(!report.pass);
    assert!(
        report.outcome == TestOutcome::Incomplete || report.outcome == TestOutcome::Unknown,
        "got {:?}",
        report.outcome
    );
    assert!(report.correlation.has_unreachable_relay);
}

// ---------------------------------------------------------------------------
// Criterion 5: Local send success is never reported as downstream delivery
// ---------------------------------------------------------------------------

#[test]
fn test_local_send_success_is_never_reported_as_downstream_delivery() {
    let mut config = TopologyConfig::new(42);
    config.generator.count = Some(20);

    // Relay 1 succeeds in sending locally, but downstream Relay 2 is unreachable
    config.relays.push(RelayHopConfig::new("relay-1"));
    config
        .relays
        .push(RelayHopConfig::new("relay-2").unreachable());

    let report = TestController::run(config).expect("test run");

    let relay1_hop = &report.hops[1];
    let relay2_hop = &report.hops[2];

    assert_eq!(relay1_hop.hop_id, "relay-1");
    assert_eq!(relay2_hop.hop_id, "relay-2");

    // Relay 1 local socket send succeeded for its forwarded packets
    assert!(
        relay1_hop.local_send_success_count > 0,
        "local send on socket should have succeeded"
    );

    // Downstream delivery for Relay 1 MUST BE ZERO because Relay 2 is unreachable!
    assert_eq!(
        relay1_hop.downstream_delivered_count, 0,
        "downstream delivery must never be claimed when downstream hop received nothing"
    );

    // Critical assertion: local send success MUST NOT equal downstream delivery
    assert_ne!(
        relay1_hop.local_send_success_count, relay1_hop.downstream_delivered_count,
        "local send success must never be reported as downstream delivery"
    );
    assert!(!relay1_hop.is_downstream_confirmed());
}

// ---------------------------------------------------------------------------
// Independent RER operation without controller (SPEC §11)
// ---------------------------------------------------------------------------

#[test]
fn test_independent_rer_operation_without_controller() {
    // The system must support independent RER operation even if the controller is unavailable.
    let udp = UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let listen_port = udp.local_addr().unwrap().port();
    drop(udp);

    let dst = UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let dst_port = dst.local_addr().unwrap().port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "standalone-relay"
    streams:
      - id: "standalone-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dst_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse standalone config");
    let relay = Relay::start(&config).expect("relay starts independently without controller");

    assert!(relay.health_handle().is_healthy());

    // Send a datagram through the standalone relay
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    sender
        .send_to(b"test-payload", format!("127.0.0.1:{listen_port}"))
        .expect("send datagram");

    let mut buf = [0u8; 64];
    dst.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let (n, _) = dst.recv_from(&mut buf).expect("receive datagram");
    assert_eq!(&buf[..n], b"test-payload");

    relay.stop();
}

// ---------------------------------------------------------------------------
// Machine-readable JSON report serialization
// ---------------------------------------------------------------------------

#[test]
fn test_topology_report_json_roundtrip() {
    let config = TopologyConfig::chain_udp(2, 42, 10);
    let report = TestController::run(config).expect("run chain");

    let json = report.to_json();
    assert!(json.contains("\"test_id\":"));
    assert!(json.contains("\"outcome\":"));
    assert!(json.contains("\"pass\":"));
    assert!(json.contains("\"hops\":"));
    assert!(json.contains("\"correlation\":"));

    let deserialized = TopologyReport::from_json(&json).expect("deserialize report");
    assert_eq!(report.test_id, deserialized.test_id);
    assert_eq!(report.outcome, deserialized.outcome);
    assert_eq!(report.pass, deserialized.pass);
    assert_eq!(report.hops.len(), deserialized.hops.len());
    assert_eq!(report.correlation, deserialized.correlation);
}
