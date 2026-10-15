//! Multi-instance topology simulation and distributed test correlation (SPEC §11, §13).
//!
//! Provides a test controller capability coordinating and collecting evidence from
//! multi-relay chains and topologies in CI with deterministic seeds. Correlates per-hop
//! observations (ingress, routing, local send success, downstream delivery), identifies
//! the first observed point of divergence (gap, duplicate, mismatch), and guarantees that
//! unreachable relays yield incomplete or unknown outcomes (never pass) and local send
//! success is never reported as downstream delivery.

use std::io;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{Config, DropPolicy, SequenceConfig, TransportType};
use crate::diagnostics::DiagnosticStage;
use crate::relay::Relay;

use super::channel::{ImpairmentConfig, SimulatedChannel};
use super::generator::{GeneratorConfig, SplitMix64, TrafficGenerator};
use super::receiver::{ReceiverReport, TrafficReceiver};

/// Overall outcome of a multi-instance topology test run (SPEC §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestOutcome {
    /// All hops reachable, evidence complete, no divergence, all packets delivered intact.
    Pass,
    /// Test failed: a divergence (gap, duplicate, or mismatch) was identified with complete evidence.
    Fail,
    /// Test incomplete: an intermediate or target relay became unreachable or evidence collection was partial.
    Incomplete,
    /// Test outcome unknown: a relay was unreachable or uncontactable from the start, leaving insufficient evidence.
    Unknown,
}

impl TestOutcome {
    /// Returns true if and only if the outcome is `Pass`.
    #[must_use]
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Type of divergence detected across hops or streams (SPEC §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceType {
    /// Expected packet sequence missing / lost.
    Gap,
    /// Packet sequence duplicated.
    Duplicate,
    /// Payload hash, payload data, packet ID, or length mismatch.
    Mismatch,
}

/// Details about the first observed point of divergence in a topology run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergencePoint {
    /// The classification of divergence: gap, duplicate, or mismatch.
    pub divergence_type: DivergenceType,
    /// Hop identifier where the divergence was first detected (e.g. "relay-2", "receiver").
    pub hop_id: String,
    /// Zero-based index of the hop in the topology chain.
    pub hop_index: usize,
    /// Sequence number of the divergent packet, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,
    /// Unique packet ID of the divergent packet, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_id: Option<String>,
    /// Human-readable explanation of the divergence.
    pub description: String,
}

/// Category of participant in a topology chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopType {
    /// Traffic source / generator.
    Source,
    /// Intermediate RER relay instance.
    Relay,
    /// Destination test observer / receiver.
    Receiver,
}

/// Per-hop evidence collected during a coordinated test run (SPEC §11).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HopObservation {
    /// Unique hop identifier (e.g. "generator", "relay-1", "relay-2", "receiver").
    pub hop_id: String,
    /// Zero-based index in the forwarding chain (0 for source, 1..N for relays, N+1 for receiver).
    pub hop_index: usize,
    /// Type of participant (Source, Relay, Receiver).
    pub hop_type: HopType,
    /// Whether this hop was reachable and responsive to observation collection.
    pub reachable: bool,
    /// Optional correlation identifier assigned to this hop during the test run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Total packets observed entering this hop (received or emitted).
    pub received_count: u64,
    /// Packets accepted by this hop.
    pub accepted_count: u64,
    /// Packets routed or queued by this hop.
    pub routed_count: u64,
    /// Number of output send calls attempted.
    pub send_attempted_count: u64,
    /// Number of output send calls that succeeded locally (SPEC §8 Stage 6).
    pub local_send_success_count: u64,
    /// Number of packets independently confirmed delivered to / observed by the downstream hop (SPEC §8 Stage 7).
    ///
    /// CRITICAL (SPEC §8, §11): Local send success is NEVER reported as downstream delivery.
    /// This value is ONLY populated from independent downstream observation, never inferred
    /// from `local_send_success_count`.
    pub downstream_delivered_count: u64,
    /// Packets dropped at this hop (due to queue overflow, policy, rate limits, etc.).
    pub dropped_count: u64,
    /// Errors encountered at this hop (e.g. socket errors, destination outages).
    pub error_count: u64,
    /// Observed sequence numbers in arrival order at this hop.
    pub observed_sequences: Vec<u64>,
    /// Duplicate sequence numbers detected at this hop.
    pub duplicate_sequences: Vec<u64>,
    /// Missing sequence numbers (gaps) detected at this hop.
    pub gap_sequences: Vec<u64>,
    /// Whether all packet payload hashes observed at this hop were verified.
    pub payload_hashes_verified: bool,
}

impl HopObservation {
    /// Creates a new hop observation with default zero counters.
    #[must_use]
    pub fn new(hop_id: impl Into<String>, hop_index: usize, hop_type: HopType) -> Self {
        Self {
            hop_id: hop_id.into(),
            hop_index,
            hop_type,
            reachable: true,
            correlation_id: None,
            received_count: 0,
            accepted_count: 0,
            routed_count: 0,
            send_attempted_count: 0,
            local_send_success_count: 0,
            downstream_delivered_count: 0,
            dropped_count: 0,
            error_count: 0,
            observed_sequences: Vec::new(),
            duplicate_sequences: Vec::new(),
            gap_sequences: Vec::new(),
            payload_hashes_verified: true,
        }
    }

    /// Verifies whether local send success was confirmed by downstream delivery.
    #[must_use]
    pub fn is_downstream_confirmed(&self) -> bool {
        self.downstream_delivered_count > 0
            && self.downstream_delivered_count == self.local_send_success_count
    }
}

/// Aggregate correlation summary across all hops in the topology.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorrelationSummary {
    /// Total packets emitted by the traffic source.
    pub source_emitted: u64,
    /// Total packets received by the final destination observer.
    pub final_received: u64,
    /// Unique sequence numbers received at the final destination.
    pub unique_received: u64,
    /// Total packets lost across the topology.
    pub total_lost: u64,
    /// Total duplicate packets observed at final destination.
    pub total_duplicates: u64,
    /// Total out-of-order packets observed at destination.
    pub total_reordered: u64,
    /// Total number of hops in the topology.
    pub hop_count: usize,
    /// Number of hops confirmed reachable.
    pub reachable_hops: usize,
    /// True if any relay in the chain was unreachable.
    pub has_unreachable_relay: bool,
}

/// Machine-readable report of a multi-instance topology simulation and correlation run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyReport {
    /// Unique test run identifier (SPEC §11).
    pub test_id: String,
    /// Deterministic seed used for traffic generation and simulation.
    pub seed: u64,
    /// Overall test outcome: Pass, Fail, Incomplete, or Unknown (SPEC §11).
    pub outcome: TestOutcome,
    /// Whether the test met all verification criteria without flaws (`outcome == Pass`).
    pub pass: bool,
    /// The first point of divergence (gap, duplicate, or mismatch) identified, if any.
    pub first_divergence: Option<DivergencePoint>,
    /// All points of divergence identified across the topology in chain order.
    pub all_divergences: Vec<DivergencePoint>,
    /// Per-hop observations in topological order (source, relays, receiver).
    pub hops: Vec<HopObservation>,
    /// High-level correlation summary across all hops.
    pub correlation: CorrelationSummary,
    /// Duration of the test run in milliseconds.
    pub duration_ms: u64,
    /// Additional diagnostic notes (e.g. unreachability explanations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl TopologyReport {
    /// Serializes this report to a formatted JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Deserializes a report from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

fn default_transport_udp() -> TransportType {
    TransportType::Udp
}

fn default_seed() -> u64 {
    42
}

fn default_timeout() -> Duration {
    Duration::from_millis(3000)
}

/// Configuration for an individual relay hop within a multi-instance topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHopConfig {
    /// Relay instance identifier (e.g. "relay-1", "relay-west").
    pub id: String,
    /// Ingress transport protocol (UDP or TCP).
    #[serde(default = "default_transport_udp")]
    pub ingress_transport: TransportType,
    /// Egress transport protocol (UDP or TCP).
    #[serde(default = "default_transport_udp")]
    pub egress_transport: TransportType,
    /// Optional queue capacity limit.
    #[serde(default)]
    pub queue_capacity: Option<usize>,
    /// Optional queue overload drop policy.
    #[serde(default)]
    pub drop_policy: Option<DropPolicy>,
    /// Optional sequence extraction configuration (SPEC §8).
    #[serde(default)]
    pub sequence: Option<SequenceConfig>,
    /// Optional network impairments applied immediately after this relay's egress.
    #[serde(default)]
    pub egress_impairments: Option<ImpairmentConfig>,
    /// Simulated unreachability: if true, this relay cannot be contacted / started.
    #[serde(default)]
    pub simulate_unreachable: bool,
}

impl RelayHopConfig {
    /// Creates a new relay hop with default UDP transports.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ingress_transport: TransportType::Udp,
            egress_transport: TransportType::Udp,
            queue_capacity: None,
            drop_policy: None,
            sequence: None,
            egress_impairments: None,
            simulate_unreachable: false,
        }
    }

    /// Sets ingress and egress transport types.
    #[must_use]
    pub fn with_transports(mut self, ingress: TransportType, egress: TransportType) -> Self {
        self.ingress_transport = ingress;
        self.egress_transport = egress;
        self
    }

    /// Sets queue capacity and drop policy.
    #[must_use]
    pub fn with_queue(mut self, capacity: usize, drop_policy: DropPolicy) -> Self {
        self.queue_capacity = Some(capacity);
        self.drop_policy = Some(drop_policy);
        self
    }

    /// Sets network impairments on egress link.
    #[must_use]
    pub fn with_impairments(mut self, impairments: ImpairmentConfig) -> Self {
        self.egress_impairments = Some(impairments);
        self
    }

    /// Marks this relay hop as unreachable.
    #[must_use]
    pub fn unreachable(mut self) -> Self {
        self.simulate_unreachable = true;
        self
    }
}

/// Configuration for a coordinated multi-instance topology simulation (SPEC §11, §13).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyConfig {
    /// Unique test run identifier (auto-generated if None).
    #[serde(default)]
    pub test_id: Option<String>,
    /// Deterministic PRNG seed for reproducible execution.
    #[serde(default = "default_seed")]
    pub seed: u64,
    /// Traffic generator configuration.
    pub generator: GeneratorConfig,
    /// Sequential chain of relay hops.
    pub relays: Vec<RelayHopConfig>,
    /// Final destination observer transport protocol (UDP or TCP).
    #[serde(default = "default_transport_udp")]
    pub destination_transport: TransportType,
    /// Optional sequence rollover threshold.
    #[serde(default)]
    pub rollover_threshold: Option<u64>,
    /// Completion timeout for the test run.
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    /// Optional capture fixture path (SPEC §11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_fixture: Option<String>,
    /// Optional replay configuration (SPEC §11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_config: Option<String>,
}

impl TopologyConfig {
    /// Creates a topology configuration with a given PRNG seed and default generator settings.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            test_id: None,
            seed,
            generator: GeneratorConfig {
                seed,
                packet_size: 256,
                rate: None,
                burst: None,
                duration: None,
                count: Some(50),
            },
            relays: Vec::new(),
            destination_transport: TransportType::Udp,
            rollover_threshold: None,
            timeout: default_timeout(),
            capture_fixture: None,
            replay_config: None,
        }
    }

    /// Helper creating an end-to-end multi-relay UDP chain.
    #[must_use]
    pub fn chain_udp(num_relays: usize, seed: u64, count: u64) -> Self {
        let mut cfg = Self::new(seed);
        cfg.generator.count = Some(count);
        for i in 1..=num_relays {
            cfg.relays.push(RelayHopConfig::new(format!("relay-{}", i)));
        }
        cfg
    }

    /// Helper creating an end-to-end multi-relay TCP chain.
    #[must_use]
    pub fn chain_tcp(num_relays: usize, seed: u64, count: u64) -> Self {
        let mut cfg = Self::new(seed);
        cfg.generator.count = Some(count);
        cfg.destination_transport = TransportType::Tcp;
        for i in 1..=num_relays {
            cfg.relays.push(
                RelayHopConfig::new(format!("relay-{}", i))
                    .with_transports(TransportType::Tcp, TransportType::Tcp),
            );
        }
        cfg
    }
}

/// Correlates per-hop observations across a topology chain and computes the comprehensive report.
///
/// Implements distributed evidence correlation (SPEC §11):
/// - Identifies the first observed point of divergence (gap, duplicate, or mismatch).
/// - Enforces that unreachable relays yield `Incomplete` or `Unknown`, never `Pass`.
/// - Guarantees that local socket send success is NEVER reported as downstream delivery.
#[must_use]
pub fn correlate_topology_hops(
    test_id: &str,
    seed: u64,
    mut hops: Vec<HopObservation>,
    expected_count: Option<u64>,
    receiver_report: Option<&ReceiverReport>,
    duration_ms: u64,
) -> TopologyReport {
    let num_hops = hops.len();

    // 1. Correlate downstream delivery across adjacent hops:
    // CRITICAL: Local send success is NEVER reported as downstream delivery!
    // Downstream delivery is strictly populated from the next hop's independently observed count.
    for i in 0..num_hops {
        if i + 1 < num_hops {
            let next_hop = &hops[i + 1];
            if next_hop.reachable {
                hops[i].downstream_delivered_count = next_hop.received_count;
            } else {
                hops[i].downstream_delivered_count = 0;
            }
        } else {
            // Final destination has no downstream hop
            hops[i].downstream_delivered_count = 0;
        }
    }

    // 2. Identify all points of divergence in topological order
    let mut all_divergences = Vec::new();

    for (i, hop) in hops.iter().enumerate() {
        if !hop.reachable {
            all_divergences.push(DivergencePoint {
                divergence_type: DivergenceType::Gap,
                hop_id: hop.hop_id.clone(),
                hop_index: hop.hop_index,
                sequence_number: None,
                packet_id: None,
                description: format!(
                    "Hop '{}' (index {}) is unreachable",
                    hop.hop_id, hop.hop_index
                ),
            });
            continue;
        }

        // Mismatches (e.g. payload hash verification failure)
        if !hop.payload_hashes_verified {
            all_divergences.push(DivergencePoint {
                divergence_type: DivergenceType::Mismatch,
                hop_id: hop.hop_id.clone(),
                hop_index: hop.hop_index,
                sequence_number: None,
                packet_id: None,
                description: format!("Payload hash verification mismatch at hop '{}'", hop.hop_id),
            });
        }

        // Duplicates
        for &dup_seq in &hop.duplicate_sequences {
            all_divergences.push(DivergencePoint {
                divergence_type: DivergenceType::Duplicate,
                hop_id: hop.hop_id.clone(),
                hop_index: hop.hop_index,
                sequence_number: Some(dup_seq),
                packet_id: None,
                description: format!(
                    "Duplicate sequence {} observed at hop '{}'",
                    dup_seq, hop.hop_id
                ),
            });
        }

        // Gaps
        for &gap_seq in &hop.gap_sequences {
            all_divergences.push(DivergencePoint {
                divergence_type: DivergenceType::Gap,
                hop_id: hop.hop_id.clone(),
                hop_index: hop.hop_index,
                sequence_number: Some(gap_seq),
                packet_id: None,
                description: format!("Sequence {} missing (gap) at hop '{}'", gap_seq, hop.hop_id),
            });
        }

        // Dropped packets
        if hop.dropped_count > 0 && hop.gap_sequences.is_empty() {
            all_divergences.push(DivergencePoint {
                divergence_type: DivergenceType::Gap,
                hop_id: hop.hop_id.clone(),
                hop_index: hop.hop_index,
                sequence_number: None,
                packet_id: None,
                description: format!(
                    "{} packets dropped at hop '{}'",
                    hop.dropped_count, hop.hop_id
                ),
            });
        }

        // Loss on the link between hop i-1 and hop i
        if i > 0 {
            let prev = &hops[i - 1];
            if prev.reachable
                && prev.local_send_success_count > hop.received_count
                && hop.gap_sequences.is_empty()
                && hop.dropped_count == 0
            {
                let diff = prev.local_send_success_count - hop.received_count;
                all_divergences.push(DivergencePoint {
                    divergence_type: DivergenceType::Gap,
                    hop_id: hop.hop_id.clone(),
                    hop_index: hop.hop_index,
                    sequence_number: None,
                    packet_id: None,
                    description: format!(
                        "{} packets lost on link between '{}' and '{}'",
                        diff, prev.hop_id, hop.hop_id
                    ),
                });
            }
        }
    }

    let first_divergence = all_divergences.first().cloned();

    // 3. Compute correlation summary
    let source_emitted = hops
        .first()
        .map(|h| h.local_send_success_count)
        .unwrap_or(0);
    let final_received = hops.last().map(|h| h.received_count).unwrap_or(0);
    let unique_received = receiver_report
        .map(|r| r.unique_received_count)
        .unwrap_or_else(|| {
            hops.last()
                .map(|h| h.observed_sequences.len() as u64)
                .unwrap_or(0)
        });
    let total_lost = source_emitted.saturating_sub(unique_received);
    let total_duplicates = receiver_report
        .map(|r| r.duplicate_count)
        .unwrap_or_else(|| {
            hops.iter()
                .map(|h| h.duplicate_sequences.len() as u64)
                .sum()
        });
    let total_reordered = receiver_report.map(|r| r.reordered_count).unwrap_or(0);
    let reachable_hops = hops.iter().filter(|h| h.reachable).count();
    let has_unreachable_relay = hops.iter().any(|h| !h.reachable);

    let correlation = CorrelationSummary {
        source_emitted,
        final_received,
        unique_received,
        total_lost,
        total_duplicates,
        total_reordered,
        hop_count: num_hops,
        reachable_hops,
        has_unreachable_relay,
    };

    // 4. Determine test outcome:
    // SPEC §11: "If a relay becomes unreachable, distinguish failed, incomplete, and unknown outcomes.
    // Never convert missing evidence into a passing result."
    let outcome = if has_unreachable_relay {
        let any_evidence = hops.iter().any(|h| h.received_count > 0);
        if any_evidence {
            TestOutcome::Incomplete
        } else {
            TestOutcome::Unknown
        }
    } else if first_divergence.is_some()
        || receiver_report.map(|r| !r.pass).unwrap_or(false)
        || expected_count
            .map(|exp| final_received != exp)
            .unwrap_or(false)
    {
        TestOutcome::Fail
    } else {
        TestOutcome::Pass
    };

    let pass = outcome == TestOutcome::Pass;

    let notes = if has_unreachable_relay {
        Some(
            "One or more relays were unreachable; missing evidence yielded incomplete/unknown outcome"
                .to_string(),
        )
    } else {
        None
    };

    TopologyReport {
        test_id: test_id.to_string(),
        seed,
        outcome,
        pass,
        first_divergence,
        all_divergences,
        hops,
        correlation,
        duration_ms,
        notes,
    }
}

/// Test controller coordinating multi-instance RER topologies (SPEC §11, §13).
pub struct TestController;

impl TestController {
    /// Executes a coordinated multi-instance topology simulation on localhost.
    pub fn run(config: TopologyConfig) -> io::Result<TopologyReport> {
        let start_time = Instant::now();
        let seed = config.seed;
        static TEST_RUN_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        let test_id = config.test_id.clone().unwrap_or_else(|| {
            let counter = TEST_RUN_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let mixed_seed = seed.wrapping_add(counter).wrapping_add(nanos);
            let mut prng = SplitMix64::new(mixed_seed);
            format!("test-run-{}", prng.next_uuid_v4())
        });

        let expected_count = config.generator.count;
        let expected_stream_hash = expected_count
            .map(|cnt| TrafficGenerator::new(config.generator.clone()).expected_stream_hash(cnt));

        let num_relays = config.relays.len();

        // 1. Setup destination receiver
        let mut receiver = TrafficReceiver::new(expected_count, expected_stream_hash);
        receiver.set_test_id(test_id.clone());
        if let Some(thresh) = config.rollover_threshold {
            receiver.set_rollover_threshold(thresh);
        }

        let receiver_port: u16;
        let receiver_udp_socket: Option<UdpSocket>;
        let receiver_tcp_listener: Option<TcpListener>;

        match config.destination_transport {
            TransportType::Udp => {
                let socket = UdpSocket::bind("127.0.0.1:0")?;
                receiver_port = socket.local_addr()?.port();
                receiver_udp_socket = Some(socket);
                receiver_tcp_listener = None;
            }
            TransportType::Tcp => {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                receiver_port = listener.local_addr()?.port();
                receiver_tcp_listener = Some(listener);
                receiver_udp_socket = None;
            }
        }

        // 2. Pre-allocate distinct ephemeral listen ports for each relay
        let mut relay_listen_ports = Vec::with_capacity(num_relays);
        for r in &config.relays {
            let port = match r.ingress_transport {
                TransportType::Udp => {
                    let s = UdpSocket::bind("127.0.0.1:0")?;
                    let p = s.local_addr()?.port();
                    drop(s);
                    p
                }
                TransportType::Tcp => {
                    let l = TcpListener::bind("127.0.0.1:0")?;
                    let p = l.local_addr()?.port();
                    drop(l);
                    p
                }
            };
            relay_listen_ports.push(port);
        }

        // 3. Setup optional impairment channels between hops
        let stop_proxies = Arc::new(AtomicBool::new(false));
        let mut proxy_handles = Vec::new();
        let mut relay_egress_targets = Vec::with_capacity(num_relays);

        for (i, r) in config.relays.iter().enumerate() {
            let next_target = if i + 1 < num_relays {
                format!("127.0.0.1:{}", relay_listen_ports[i + 1])
            } else {
                format!("127.0.0.1:{}", receiver_port)
            };

            if let Some(impairments) = r.egress_impairments.clone() {
                let proxy_socket = UdpSocket::bind("127.0.0.1:0")?;
                let proxy_port = proxy_socket.local_addr()?.port();
                let stop_flag = stop_proxies.clone();
                let fwd_target = next_target;

                let handle = thread::spawn(move || {
                    let mut channel = SimulatedChannel::new(impairments);
                    let _ = channel.forward_udp_loop(&proxy_socket, &fwd_target, stop_flag);
                });

                proxy_handles.push(handle);
                relay_egress_targets.push(format!("127.0.0.1:{}", proxy_port));
            } else {
                relay_egress_targets.push(next_target);
            }
        }

        // 4. Start active reachable Relay instances
        let mut relay_instances = Vec::with_capacity(num_relays);
        let mut has_tcp = config.destination_transport == TransportType::Tcp;

        // Start relays in reverse order so downstream listeners are bound before upstream connects
        for idx in (0..num_relays).rev() {
            let r = &config.relays[idx];
            if r.simulate_unreachable {
                continue;
            }

            if r.ingress_transport == TransportType::Tcp || r.egress_transport == TransportType::Tcp
            {
                has_tcp = true;
            }

            let listen_port = relay_listen_ports[idx];
            let egress_target = &relay_egress_targets[idx];
            let src_transport_name = match r.ingress_transport {
                TransportType::Udp => "udp",
                TransportType::Tcp => "tcp",
            };
            let dest_transport_name = match r.egress_transport {
                TransportType::Udp => "udp",
                TransportType::Tcp => "tcp",
            };

            let max_queue_str = r
                .queue_capacity
                .map(|c| format!("          max_queue_size: {}", c))
                .unwrap_or_default();

            let drop_policy_str = r
                .drop_policy
                .map(|p| match p {
                    DropPolicy::DropOldest => "          drop_policy: \"drop_oldest\"",
                    DropPolicy::DropNewest => "          drop_policy: \"drop_newest\"",
                    DropPolicy::Reject => "          drop_policy: \"reject\"",
                })
                .unwrap_or_default();

            let buffer_yaml = if !max_queue_str.is_empty() || !drop_policy_str.is_empty() {
                let mut s = String::from("        buffer:\n");
                if !max_queue_str.is_empty() {
                    s.push_str(&max_queue_str);
                    s.push('\n');
                }
                if !drop_policy_str.is_empty() {
                    s.push_str(drop_policy_str);
                    s.push('\n');
                }
                s
            } else {
                String::new()
            };

            // Configure sequence extraction on relay streams (SPEC §8)
            let sequence_yaml = if let Some(ref seq) = r.sequence {
                let off = seq.offset;
                let w = seq.width;
                let bo = seq.byte_order.to_string();
                let thresh_str = seq
                    .rollover_threshold
                    .map(|t| format!("          rollover_threshold: {}\n", t))
                    .unwrap_or_default();
                format!(
                    "        sequence:\n          enabled: {}\n          offset: {}\n          width: {}\n          byte_order: \"{}\"\n{}",
                    seq.enabled, off, w, bo, thresh_str
                )
            } else {
                // Default sequence tracking for packet stream inspection
                "        sequence:\n          enabled: true\n          offset: 4\n          width: 8\n          byte_order: \"big_endian\"\n".to_string()
            };

            let relay_yaml = format!(
                r#"
version: "1"
instances:
  - id: "{relay_id}"
    mode: "test"
    correlation_id: "{test_id}"
    expiry: 60
    streams:
      - id: "stream-{relay_id}"
        source:
          transport: "{src_transport_name}"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "{dest_transport_name}"
          address: "{egress_target}"
{buffer_yaml}{sequence_yaml}
"#,
                relay_id = r.id,
                test_id = test_id,
                listen_port = listen_port,
                egress_target = egress_target,
                buffer_yaml = buffer_yaml,
                sequence_yaml = sequence_yaml,
            );

            let relay_cfg = Config::from_yaml_str(&relay_yaml)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;

            let relay = Relay::start(&relay_cfg).map_err(|e| {
                io::Error::other(format!("failed to start relay '{}': {}", r.id, e))
            })?;

            relay_instances.push((idx, r.id.clone(), relay));
        }

        // 5. Spawn destination receiver thread
        let receiver_dest_transport = config.destination_transport;
        let timeout = config.timeout;
        let receiver_handle = thread::spawn(move || match receiver_dest_transport {
            TransportType::Udp => {
                let socket = receiver_udp_socket.unwrap();
                receiver.listen_udp(&socket, timeout)
            }
            TransportType::Tcp => {
                let listener = receiver_tcp_listener.unwrap();
                receiver.listen_tcp(&listener, timeout)
            }
        });

        // Small delay if TCP in use so accept loops are ready
        if has_tcp {
            thread::sleep(Duration::from_millis(50));
        }

        // 6. Run traffic generator
        let generator_target = if num_relays > 0 {
            format!("127.0.0.1:{}", relay_listen_ports[0])
        } else {
            format!("127.0.0.1:{}", receiver_port)
        };

        let generator_transport = if num_relays > 0 {
            config.relays[0].ingress_transport
        } else {
            config.destination_transport
        };

        let mut generator = TrafficGenerator::new(config.generator.clone());
        let (gen_stats, gen_error) = match generator_transport {
            TransportType::Udp => match generator.run_udp(&generator_target) {
                Ok(s) => (s, None),
                Err(e) => (
                    super::generator::GeneratorStats {
                        packets_emitted: 0,
                        bytes_emitted: 0,
                        duration_ms: 0,
                        stream_hash: String::new(),
                    },
                    Some(e.to_string()),
                ),
            },
            TransportType::Tcp => match generator.run_tcp(&generator_target) {
                Ok(s) => (s, None),
                Err(e) => (
                    super::generator::GeneratorStats {
                        packets_emitted: 0,
                        bytes_emitted: 0,
                        duration_ms: 0,
                        stream_hash: String::new(),
                    },
                    Some(e.to_string()),
                ),
            },
        };

        // 7. Collect receiver report
        let rec_report = receiver_handle
            .join()
            .map_err(|_| io::Error::other("receiver thread panicked"))??;

        // 8. Collect relay stats and diagnostic events before stopping
        let mut relay_observations = Vec::with_capacity(num_relays);
        for (idx, r) in config.relays.iter().enumerate() {
            if r.simulate_unreachable {
                let mut obs = HopObservation::new(&r.id, idx + 1, HopType::Relay);
                obs.reachable = false;
                obs.payload_hashes_verified = false;
                relay_observations.push(obs);
                continue;
            }

            // Find matching active instance
            let found = relay_instances.iter().find(|(i, _, _)| *i == idx);
            if let Some((_, relay_id, relay)) = found {
                let stream_id = format!("stream-{}", relay_id);
                let health_handle = relay.health_handle();
                let stats = health_handle.stream_stats(&stream_id).unwrap_or_default();
                let snapshot = relay.event_buffer().snapshot();
                let seq_states = health_handle.sequence_states();

                let mut obs = HopObservation::new(relay_id, idx + 1, HopType::Relay);
                obs.reachable = true;
                obs.correlation_id = relay.correlation_id();
                obs.received_count = stats.received_packets;
                obs.local_send_success_count = stats.forwarded_packets;
                obs.dropped_count = stats.dropped_packets;
                obs.error_count = stats.destination_errors + stats.socket_errors;

                // Tally stages from diagnostic events
                for ev in &snapshot.events {
                    if ev.stream_id == stream_id {
                        match ev.stage {
                            DiagnosticStage::Accepted => obs.accepted_count += 1,
                            DiagnosticStage::RoutedOrQueued => obs.routed_count += 1,
                            DiagnosticStage::SendAttempted => obs.send_attempted_count += 1,
                            _ => {}
                        }
                        if let Some(s) = ev.sequence_number {
                            if !obs.observed_sequences.contains(&s) {
                                obs.observed_sequences.push(s);
                            }
                        }
                    }
                }

                // Sequence continuity state from relay tracker
                if let Some(seq_st) = seq_states.iter().find(|s| s.stream_id == stream_id) {
                    if seq_st.gap_count > 0 && obs.gap_sequences.is_empty() {
                        // If tracker detected gaps
                        obs.gap_sequences.push(seq_st.highest_sequence.unwrap_or(0));
                    }
                    if seq_st.duplicate_count > 0 && obs.duplicate_sequences.is_empty() {
                        obs.duplicate_sequences
                            .push(seq_st.last_sequence.unwrap_or(0));
                    }
                }

                relay_observations.push(obs);
            } else {
                let mut obs = HopObservation::new(&r.id, idx + 1, HopType::Relay);
                obs.reachable = false;
                obs.payload_hashes_verified = false;
                relay_observations.push(obs);
            }
        }

        // Cleanup: Stop all relays and proxies
        for (_, _, relay) in relay_instances {
            relay.stop();
        }

        stop_proxies.store(true, Ordering::Relaxed);
        for h in proxy_handles {
            let _ = h.join();
        }

        // 9. Assemble full topology hop sequence
        let mut all_hops = Vec::with_capacity(num_relays + 2);

        // Hop 0: Source (Generator)
        let mut source_hop = HopObservation::new("generator", 0, HopType::Source);
        source_hop.correlation_id = Some(test_id.clone());
        source_hop.local_send_success_count = gen_stats.packets_emitted;
        source_hop.send_attempted_count = gen_stats.packets_emitted;
        source_hop.accepted_count = gen_stats.packets_emitted;
        source_hop.routed_count = gen_stats.packets_emitted;
        source_hop.error_count = if gen_error.is_some() { 1 } else { 0 };
        source_hop.observed_sequences = (0..gen_stats.packets_emitted).collect();
        all_hops.push(source_hop);

        // Hops 1..N: Relays
        all_hops.extend(relay_observations);

        // Hop N+1: Receiver
        let mut rec_hop = HopObservation::new("receiver", num_relays + 1, HopType::Receiver);
        rec_hop.correlation_id = rec_report.test_id.clone();
        rec_hop.received_count = rec_report.received_count;
        rec_hop.accepted_count = rec_report.received_count;
        rec_hop.dropped_count = rec_report.lost_count;
        rec_hop.error_count = rec_report.corrupted_count;
        rec_hop.duplicate_sequences = rec_report.duplicate_sequences.clone();
        rec_hop.gap_sequences = rec_report.lost_sequences.clone();
        rec_hop.payload_hashes_verified = rec_report.payload_hashes_verified;
        all_hops.push(rec_hop);

        // 10. Correlate per-hop observations
        let duration_ms = start_time.elapsed().as_millis() as u64;
        let report = correlate_topology_hops(
            &test_id,
            seed,
            all_hops,
            expected_count,
            Some(&rec_report),
            duration_ms,
        );

        Ok(report)
    }
}

/// Alias for `TestController`.
pub type TopologyHarness = TestController;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlate_topology_clean_chain() {
        let mut h0 = HopObservation::new("generator", 0, HopType::Source);
        h0.local_send_success_count = 10;
        h0.observed_sequences = (0..10).collect();

        let mut h1 = HopObservation::new("relay-1", 1, HopType::Relay);
        h1.received_count = 10;
        h1.local_send_success_count = 10;
        h1.observed_sequences = (0..10).collect();

        let mut h2 = HopObservation::new("receiver", 2, HopType::Receiver);
        h2.received_count = 10;
        h2.observed_sequences = (0..10).collect();

        let hops = vec![h0, h1, h2];
        let report = correlate_topology_hops("run-1", 42, hops, Some(10), None, 50);

        assert_eq!(report.outcome, TestOutcome::Pass);
        assert!(report.pass);
        assert!(report.first_divergence.is_none());
        assert_eq!(report.hops[0].downstream_delivered_count, 10);
        assert_eq!(report.hops[1].downstream_delivered_count, 10);
        assert!(report.hops[0].is_downstream_confirmed());
    }

    #[test]
    fn test_local_send_success_never_reported_as_downstream_delivery_on_drop() {
        let mut h0 = HopObservation::new("generator", 0, HopType::Source);
        h0.local_send_success_count = 100;

        let mut h1 = HopObservation::new("relay-1", 1, HopType::Relay);
        h1.received_count = 100;
        h1.local_send_success_count = 100; // Local send succeeded on socket

        let mut h2 = HopObservation::new("relay-2", 2, HopType::Relay);
        h2.reachable = false; // Downstream relay is dead / unreachable
        h2.received_count = 0;

        let hops = vec![h0, h1, h2];
        let report = correlate_topology_hops("run-2", 42, hops, Some(100), None, 50);

        // Crucial test of requirement: Local send success is never reported as downstream delivery!
        assert_eq!(report.hops[1].local_send_success_count, 100);
        assert_eq!(report.hops[1].downstream_delivered_count, 0);
        assert_ne!(
            report.hops[1].local_send_success_count,
            report.hops[1].downstream_delivered_count
        );
        assert!(!report.hops[1].is_downstream_confirmed());
    }

    #[test]
    fn test_unreachable_relay_yields_incomplete_or_unknown_never_pass() {
        let mut h0 = HopObservation::new("generator", 0, HopType::Source);
        h0.local_send_success_count = 10;

        let mut h1 = HopObservation::new("relay-1", 1, HopType::Relay);
        h1.reachable = false; // Unreachable
        h1.received_count = 0;

        let hops = vec![h0, h1];
        let report = correlate_topology_hops("run-3", 42, hops, Some(10), None, 20);

        assert!(!report.pass);
        assert!(
            report.outcome == TestOutcome::Incomplete || report.outcome == TestOutcome::Unknown
        );
        assert!(report.correlation.has_unreachable_relay);
    }

    #[test]
    fn test_identify_first_point_of_divergence_gap() {
        let mut h0 = HopObservation::new("generator", 0, HopType::Source);
        h0.local_send_success_count = 10;
        h0.observed_sequences = (0..10).collect();

        let mut h1 = HopObservation::new("relay-1", 1, HopType::Relay);
        h1.received_count = 10;
        h1.local_send_success_count = 9;
        h1.dropped_count = 1;
        h1.gap_sequences = vec![5];

        let mut h2 = HopObservation::new("receiver", 2, HopType::Receiver);
        h2.received_count = 9;
        h2.gap_sequences = vec![5];

        let hops = vec![h0, h1, h2];
        let report = correlate_topology_hops("run-4", 42, hops, Some(10), None, 30);

        assert_eq!(report.outcome, TestOutcome::Fail);
        assert!(!report.pass);
        let first = report.first_divergence.expect("must find divergence");
        assert_eq!(first.divergence_type, DivergenceType::Gap);
        assert_eq!(first.hop_id, "relay-1");
        assert_eq!(first.sequence_number, Some(5));
    }

    #[test]
    fn test_identify_first_point_of_divergence_duplicate() {
        let mut h0 = HopObservation::new("generator", 0, HopType::Source);
        h0.local_send_success_count = 5;

        let mut h1 = HopObservation::new("relay-1", 1, HopType::Relay);
        h1.received_count = 5;
        h1.local_send_success_count = 6;
        h1.duplicate_sequences = vec![2];

        let hops = vec![h0, h1];
        let report = correlate_topology_hops("run-5", 42, hops, Some(5), None, 15);

        assert_eq!(report.outcome, TestOutcome::Fail);
        let first = report.first_divergence.expect("must find divergence");
        assert_eq!(first.divergence_type, DivergenceType::Duplicate);
        assert_eq!(first.hop_id, "relay-1");
        assert_eq!(first.sequence_number, Some(2));
    }

    #[test]
    fn test_identify_first_point_of_divergence_mismatch() {
        let mut h0 = HopObservation::new("generator", 0, HopType::Source);
        h0.local_send_success_count = 5;

        let mut h1 = HopObservation::new("relay-1", 1, HopType::Relay);
        h1.received_count = 5;
        h1.local_send_success_count = 5;
        h1.payload_hashes_verified = false;

        let hops = vec![h0, h1];
        let report = correlate_topology_hops("run-6", 42, hops, Some(5), None, 15);

        assert_eq!(report.outcome, TestOutcome::Fail);
        let first = report.first_divergence.expect("must find divergence");
        assert_eq!(first.divergence_type, DivergenceType::Mismatch);
        assert_eq!(first.hop_id, "relay-1");
    }
}
