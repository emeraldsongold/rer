//! RER — RER Engineering Relay
//!
//! An open-source network relay, telemetry/command routing, and distributed
//! network diagnostics tool.

pub mod bpv7;
pub mod capture;
pub mod ccsds;
pub mod cli;
pub mod config;
pub mod diagnostics;
pub mod framing;
pub mod health;
pub mod ltp;
pub mod management;
pub mod mavlink;
pub mod mqtt;
pub mod relay;
pub mod replay;
pub mod secret;
pub mod signals;
pub mod sim;
pub mod srt;

pub use bpv7::{
    compute_crc16_x25, compute_crc32c, evaluate_bpv7_payload, evaluate_bundle_header,
    evaluate_payload, parse_bpv7_primary_block, parse_bundle, parse_primary_block, Bpv7ParseError,
    BundleParseStatus, CrcType, CreationTimestamp, EndpointId, EndpointScheme, PrimaryBlock,
    BP_VERSION_7, BUNDLE_IS_FRAGMENT, BUNDLE_MUST_NOT_BE_FRAGMENTED,
    BUNDLE_PAYLOAD_IS_ADMIN_RECORD, BUNDLE_STATUS_REPORT_DELETION, BUNDLE_STATUS_REPORT_DELIVERY,
    BUNDLE_STATUS_REPORT_FORWARDING, BUNDLE_STATUS_REPORT_RECEPTION, BUNDLE_STATUS_TIME_REQUESTED,
};
pub use capture::{
    build_synthetic_frame, build_synthetic_pcap, build_synthetic_pcapng, compute_ipv4_checksum,
    decode_packet, parse_capture, parse_capture_file, parse_pcap, parse_pcapng, CaptureError,
    CaptureFormat, CaptureSummary, CapturedPacket, LinkType, SyntheticPacket,
};
pub use ccsds::{
    parse_and_validate_ccsds_packet, parse_ccsds_primary_header,
    parse_ccsds_primary_header_relaxed, ApidSequenceTracker, CcsdsParseError, CcsdsPrimaryHeader,
    CcsdsSequenceTracker, CCSDS_IDLE_APID, CCSDS_PRIMARY_HEADER_LEN, CCSDS_SEQUENCE_MODULUS,
};
pub use config::{
    Bpv7InspectionConfig, ByteOrder, CcsdsConfig, Config, DropPolicy, FramingMode,
    InspectionConfig, InstanceConfig, LogicalInterfaceConfig, LtpInspectionConfig, MavlinkConfig,
    MetricsConfig, MqttConfig, OperationalMode, SequenceConfig, SrtInspectionConfig, StreamConfig,
    TestModeConfig, ValidationError, ValidationReport,
};
pub use diagnostics::{
    format_ascii_preview, format_hex_preview, record_mqtt_local_transmission, BundleInspection,
    BundleInspectionEvent, BundleMetadata, Clock, DiagnosticBuffer, DiagnosticBufferBuilder,
    DiagnosticEvent, DiagnosticSnapshot, DiagnosticStage, DiagnosticTestState, IntoDtnTimestamp,
    LtpInspection, LtpInspectionEvent, LtpMetadata, ManualClock, MavlinkInspection,
    MavlinkInspectionEvent, MavlinkMetadata, MqttInspection, MqttInspectionEvent, MqttMetadata,
    RateLimiter, SequenceState, SequenceTracker, SequenceTrackingEvent, SrtInspection,
    SrtInspectionEvent, SrtMetadata, Stage, SystemClock,
};
pub use framing::{
    encode_frame, encode_kiss_frame, read_ccsds_frame, read_frame, read_frame_with_mode,
    read_kiss_frame, read_mavlink_frame, read_mqtt_frame, write_ccsds_frame, write_frame,
    write_frame_with_mode, write_kiss_frame, write_mavlink_frame, write_mqtt_frame, KISS_FEND,
    KISS_FESC, KISS_TFEND, KISS_TFESC,
};
pub use health::{
    generate_health_report, query_health, HealthReport, HealthServer, StreamHealthReport,
};
pub use ltp::{
    decode_sdnv, encode_sdnv, evaluate_ltp_payload, evaluate_segment_header, parse_data_segment,
    parse_ltp_header, parse_ltp_segment, parse_segment, parse_segment_header, ExtensionTlv,
    LtpDataSegment, LtpHeader, LtpParseError, LtpParseStatus, LtpSegment, LtpSegmentHeader,
    ReceptionClaim, SegmentType, SessionId, LTP_VERSION_0,
};
pub use management::{
    generate_inspect_report, generate_prometheus_text, query_events, query_inspect, query_metrics,
    query_recent_events, query_status, query_streams, query_version, AggregateCounters,
    DiagnosticEventsReport, InspectReport, ManagementError, ManagementRequest, ManagementResponse,
    ManagementServer, MetricsReport, MetricsServer, OperationType, StatusReport,
    StreamStatusReport, StreamsManagementReport, VersionReport, DEFAULT_MANAGEMENT_SOCKET,
    MGMT_API_VERSION,
};
pub use mavlink::{
    encode_mavlink1_header, encode_mavlink2_header, evaluate_mavlink, evaluate_mavlink_2_packet,
    evaluate_mavlink_header, evaluate_mavlink_packet, evaluate_mavlink_payload,
    parse_mavlink_header, parse_mavlink_packet, EndpointSequenceTracker,
    MavlinkEndpointSequenceTracker, MavlinkHeader, MavlinkParseError, MavlinkParseStatus,
    MavlinkParseWarning, MavlinkSequenceTracker, MavlinkSourceSequenceTracker,
    MavlinkStreamSequenceTracker, MavlinkVersion, SourceSequenceTracker, MAVLINK_IFLAG_SIGNED,
    MAVLINK_KNOWN_INCOMPAT_FLAGS, MAVLINK_MAGIC_V1, MAVLINK_MAGIC_V2, MAVLINK_SEQUENCE_MODULUS,
    MAVLINK_SIGNATURE_LEN, MAVLINK_STX_V1, MAVLINK_STX_V2, MAVLINK_V1_FRAMING_OVERHEAD,
    MAVLINK_V1_HEADER_LEN, MAVLINK_V1_MIN_HEADER_LEN, MAVLINK_V1_OVERHEAD, MAVLINK_V1_STX,
    MAVLINK_V2_FRAMING_OVERHEAD_SIGNED, MAVLINK_V2_FRAMING_OVERHEAD_UNSIGNED,
    MAVLINK_V2_HEADER_LEN, MAVLINK_V2_MIN_HEADER_LEN, MAVLINK_V2_OVERHEAD_SIGNED,
    MAVLINK_V2_OVERHEAD_UNSIGNED, MAVLINK_V2_STX,
};
pub use mqtt::{
    decode_variable_byte_integer, decode_variable_length_integer, decode_varint,
    encode_variable_byte_integer, encode_variable_byte_integer_vec, encode_varint,
    evaluate_mqtt_header, evaluate_payload as evaluate_mqtt_payload, parse_fixed_header,
    parse_mqtt_fixed_header, parse_mqtt_fixed_header_prefix, parse_mqtt_fixed_header_relaxed,
    parse_mqtt_header, parse_mqtt_packet, validate_flags, MqttFixedHeader, MqttPacketType,
    MqttParseError, MqttParseStatus, MQTT_MAX_FIXED_HEADER_LEN, MQTT_MAX_PACKET_SIZE,
    MQTT_MAX_VARIABLE_BYTE_INTEGER, MQTT_MAX_VARINT_BYTES, MQTT_MIN_FIXED_HEADER_LEN,
    MQTT_TYPE_AUTH, MQTT_TYPE_CONNACK, MQTT_TYPE_CONNECT, MQTT_TYPE_DISCONNECT, MQTT_TYPE_PINGREQ,
    MQTT_TYPE_PINGRESP, MQTT_TYPE_PUBACK, MQTT_TYPE_PUBCOMP, MQTT_TYPE_PUBLISH, MQTT_TYPE_PUBREC,
    MQTT_TYPE_PUBREL, MQTT_TYPE_SUBACK, MQTT_TYPE_SUBSCRIBE, MQTT_TYPE_UNSUBACK,
    MQTT_TYPE_UNSUBSCRIBE,
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
    LongDurationConfig, LongDurationReport, LongDurationRunner, MemoryStabilityReport,
    OutageSchedule, OutageWindow, Packet, QueueStabilityReport, ReceiverReport, RelayHopConfig,
    ReorderedPacket, SimulatedChannel, SimulationHarness, StabilitySample, TestController,
    TestOutcome, TestReceiver, TopologyConfig, TopologyHarness, TopologyReport, TrafficGenerator,
};
pub use srt::{
    encode_control_header, encode_data_header, evaluate_header, evaluate_srt_header,
    evaluate_srt_payload, parse_control_header, parse_control_packet, parse_data_header,
    parse_data_packet, parse_handshake, parse_handshake_control, parse_header, parse_packet,
    parse_srt_control_packet, parse_srt_data_packet, parse_srt_handshake, parse_srt_header,
    parse_srt_packet, PacketPosition, SrtControlHeader, SrtControlPacket, SrtControlType,
    SrtDataHeader, SrtDataPacket, SrtHandshake, SrtHandshakeControl, SrtHandshakePacket,
    SrtHandshakeType, SrtHeader, SrtPacket, SrtPacketKind, SrtPacketType, SrtParseError,
    SrtParseStatus, SRT_CMD_ACK, SRT_CMD_ACKACK, SRT_CMD_CONGESTION, SRT_CMD_DROPREQ,
    SRT_CMD_HANDSHAKE, SRT_CMD_HSREQ, SRT_CMD_HSRSP, SRT_CMD_KEEPALIVE, SRT_CMD_KMREQ,
    SRT_CMD_KMRSP, SRT_CMD_NAK, SRT_CMD_PEERERROR, SRT_CMD_SHUTDOWN, SRT_CMD_SID, SRT_CMD_USER,
    SRT_HANDSHAKE_MIN_LEN, SRT_HANDSHAKE_PAYLOAD_LEN, SRT_HEADER_LEN, SRT_HS_AGREEMENT,
    SRT_HS_CONCLUSION, SRT_HS_DONE, SRT_HS_INDUCTION, SRT_HS_WAVEAHAND, SRT_VERSION_5,
    UDT_VERSION_4,
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
