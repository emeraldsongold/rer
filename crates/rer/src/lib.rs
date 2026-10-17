//! RER — RER Engineering Relay
//!
//! An open-source network relay, telemetry/command routing, and distributed
//! network diagnostics tool.

pub mod capture;
pub mod ccsds;
pub mod cli;
pub mod config;
pub mod diagnostics;
pub mod framing;
pub mod health;
pub mod management;
pub mod relay;
pub mod replay;
pub mod secret;
pub mod signals;
pub mod sim;

pub use capture::{
    build_synthetic_frame, build_synthetic_pcap, build_synthetic_pcapng, compute_ipv4_checksum,
    decode_packet, parse_capture, parse_capture_file, parse_pcap, parse_pcapng, CaptureError,
    CaptureFormat, CaptureSummary, CapturedPacket, LinkType, SyntheticPacket,
};
pub use ccsds::{
    parse_ccsds_primary_header, ApidSequenceTracker, CcsdsParseError, CcsdsPrimaryHeader,
    CcsdsSequenceTracker, CCSDS_IDLE_APID, CCSDS_PRIMARY_HEADER_LEN, CCSDS_SEQUENCE_MODULUS,
};
pub use config::{
    ByteOrder, Config, DropPolicy, InspectionConfig, InstanceConfig, LogicalInterfaceConfig,
    MetricsConfig, OperationalMode, SequenceConfig, StreamConfig, TestModeConfig, ValidationError,
    ValidationReport,
};
pub use diagnostics::{
    format_ascii_preview, format_hex_preview, Clock, DiagnosticBuffer, DiagnosticBufferBuilder,
    DiagnosticEvent, DiagnosticSnapshot, DiagnosticStage, DiagnosticTestState, ManualClock,
    RateLimiter, SequenceState, SequenceTracker, SequenceTrackingEvent, Stage, SystemClock,
};
pub use framing::{encode_frame, read_frame, write_frame};
pub use health::{
    generate_health_report, query_health, HealthReport, HealthServer, StreamHealthReport,
};
pub use management::{
    generate_inspect_report, generate_prometheus_text, query_events, query_inspect, query_metrics,
    query_recent_events, query_status, query_streams, query_version, AggregateCounters,
    DiagnosticEventsReport, InspectReport, ManagementError, ManagementRequest, ManagementResponse,
    ManagementServer, MetricsReport, MetricsServer, OperationType, StatusReport,
    StreamStatusReport, StreamsManagementReport, VersionReport, DEFAULT_MANAGEMENT_SOCKET,
    MGMT_API_VERSION,
};
pub use relay::{
    bind_tcp_listener, bind_udp_socket, format_endpoint, interface_name_to_index,
    parse_scoped_socket_addr, resolve_endpoint, resolve_endpoint_with_context, select_socket_addr,
    BoundedQueue, Datagram, LogicalInterfaceInfo, LogicalInterfaceStats, Relay, RelayHealthHandle,
    ScopedEndpoint, StreamHealthSnapshot, StreamRunner, StreamStats, StreamStatsSnapshot,
};
pub use replay::{
    execute_replay_session, is_test_endpoint, matches_filter, ReplayConfig, ReplayReport,
};

pub use secret::SecretString;
pub use sim::{
    correlate_topology_hops, current_rss_bytes, default_benchmark_suite, BaselineComparison,
    BenchmarkDefinition, BenchmarkResult, BenchmarkRunner, CorrelationSummary, DivergencePoint,
    DivergenceType, EnvironmentInfo, FaultInjectionRunner, FaultScenarioResult, FaultType,
    GeneratorConfig, GeneratorStats, HarnessConfig, HopObservation, HopType, ImpairmentConfig,
    LongDurationConfig, LongDurationReport, LongDurationRunner, MemoryStabilityReport, Packet,
    QueueStabilityReport, ReceiverReport, RelayHopConfig, ReorderedPacket, SimulatedChannel,
    SimulationHarness, StabilitySample, TestController, TestOutcome, TestReceiver, TopologyConfig,
    TopologyHarness, TopologyReport, TrafficGenerator,
};

/// Returns the current version of RER.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert!(!version().is_empty());
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
