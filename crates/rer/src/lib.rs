//! RER — RER Engineering Relay
//!
//! An open-source network relay, telemetry/command routing, and distributed
//! network diagnostics tool.

pub mod cli;
pub mod config;
pub mod diagnostics;
pub mod framing;
pub mod health;
pub mod management;
pub mod relay;
pub mod secret;
pub mod signals;
pub mod sim;

pub use config::{
    ByteOrder, Config, DropPolicy, InspectionConfig, InstanceConfig, LogicalInterfaceConfig,
    MetricsConfig, SequenceConfig, StreamConfig, TestModeConfig, ValidationError, ValidationReport,
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

pub use secret::SecretString;
pub use sim::{
    GeneratorConfig, GeneratorStats, HarnessConfig, ImpairmentConfig, Packet, ReceiverReport,
    ReorderedPacket, SimulatedChannel, SimulationHarness, TestReceiver, TrafficGenerator,
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
