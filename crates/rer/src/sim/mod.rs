//! Simulation, traffic generation, and verification harness (SPEC §13).
//!
//! Provides deterministic traffic generation with unique packet IDs and sequence numbers,
//! configurable payload size, rate, burst, duration and seed; test receiver verifying expected
//! counts and SHA-256 payload hashes and reporting loss, duplication, and reordering as JSON;
//! and an unprivileged simulation harness suitable for ordinary CI.

pub mod channel;
pub mod generator;
pub mod harness;
pub mod packet;
pub mod receiver;
pub mod sha256;
pub mod topology;

pub use channel::{ImpairmentConfig, SimulatedChannel};
pub use generator::{GeneratorConfig, GeneratorStats, SplitMix64, TrafficGenerator};
pub use harness::{HarnessConfig, SimulationHarness};
pub use packet::{Packet, PacketError};
pub use receiver::{ReceiverReport, ReorderedPacket, TrafficReceiver};
pub use sha256::{sha256_bytes, sha256_hex};
pub use topology::{
    correlate_topology_hops, CorrelationSummary, DivergencePoint, DivergenceType, HopObservation,
    HopType, RelayHopConfig, TestController, TestOutcome, TopologyConfig, TopologyHarness,
    TopologyReport,
};

/// Alias for `TrafficReceiver`.
pub type TestReceiver = TrafficReceiver;
