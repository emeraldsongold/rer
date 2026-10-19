use std::collections::HashSet;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// Top-level configuration for RER.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration format version (e.g. "1" or "1.0").
    pub version: String,

    /// Single instance configuration (alternative to `instances`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<InstanceConfig>,

    /// List of RER relay instances.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<InstanceConfig>,
}

/// Configuration for an individual RER relay instance.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    /// Unique identity of the instance.
    pub id: String,

    /// Human-readable name or label for the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Diagnostic and operational profile ("production", "debug", or "test").
    #[serde(default = "default_operational_mode")]
    pub mode: OperationalMode,

    /// Management and diagnostics interface configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<ManagementConfig>,

    /// Prometheus/OpenMetrics metrics endpoint configuration (SPEC §15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<MetricsConfig>,

    /// Forwarding streams configured on this instance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<StreamConfig>,

    /// Logical interfaces pairing directional streams.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logical_interfaces: Vec<LogicalInterfaceConfig>,

    /// Instance-level bounded buffer and queue limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer: Option<BufferConfig>,

    /// Test mode configuration (correlation ID, expiry, bounds, prior mode) (SPEC §10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_mode: Option<TestModeConfig>,

    /// Direct correlation ID on instance (alternative to test_mode.correlation_id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,

    /// Direct expiry in seconds on instance (alternative to test_mode.expiry_seconds).
    #[serde(
        default,
        alias = "expiry",
        alias = "duration_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub expiry_seconds: Option<u64>,

    /// Direct max events on instance (alternative to test_mode.max_events).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u64>,

    /// Direct prior mode on instance (alternative to test_mode.prior_mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_mode: Option<OperationalMode>,
}

/// Prometheus and OpenMetrics metrics endpoint configuration (SPEC §15).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Whether the metrics HTTP/TCP endpoint is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Bind address for the metrics endpoint (e.g. "127.0.0.1:9100").
    /// Bound to loopback by default.
    #[serde(default = "default_metrics_endpoint")]
    pub endpoint: String,

    /// HTTP request path for metrics scraping (e.g. "/metrics"). Defaults to "/metrics".
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_endpoint() -> String {
    "127.0.0.1:9100".to_string()
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

/// Operational diagnostic modes (SPEC §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationalMode {
    Production,
    Debug,
    Test,
}

impl fmt::Display for OperationalMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Production => write!(f, "production"),
            Self::Debug => write!(f, "debug"),
            Self::Test => write!(f, "test"),
        }
    }
}

fn default_operational_mode() -> OperationalMode {
    OperationalMode::Production
}

/// Documented maximum test run duration in seconds (24 hours = 86,400s).
pub const MAX_TEST_DURATION_SECONDS: u64 = 86_400;

/// Default test run duration in seconds if not specified (5 minutes = 300s).
pub const DEFAULT_TEST_DURATION_SECONDS: u64 = 300;

/// Documented maximum events recorded in a test run before reaching bound (1,000,000 events).
pub const MAX_TEST_EVENTS: u64 = 1_000_000;

/// Default maximum events recorded in a test run (10,000 events).
pub const DEFAULT_TEST_MAX_EVENTS: u64 = 10_000;

/// Test mode configuration parameters (SPEC §10).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TestModeConfig {
    /// Correlation identifier spanning multiple relays.
    #[serde(
        default,
        alias = "correlation",
        skip_serializing_if = "Option::is_none"
    )]
    pub correlation_id: Option<String>,

    /// Configured test run expiry / duration in seconds.
    #[serde(
        default,
        alias = "expiry",
        alias = "duration",
        alias = "duration_seconds",
        skip_serializing_if = "Option::is_none"
    )]
    pub expiry_seconds: Option<u64>,

    /// Configured event limit for the test run before reaching bound.
    #[serde(
        default,
        alias = "events_bound",
        alias = "event_limit",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_events: Option<u64>,

    /// Diagnostic profile to revert to upon expiry or reaching bounds (defaults to production).
    #[serde(
        default,
        alias = "revert_to",
        alias = "prior_level",
        skip_serializing_if = "Option::is_none"
    )]
    pub prior_mode: Option<OperationalMode>,
}

impl InstanceConfig {
    /// Resolved correlation identifier for test mode.
    #[must_use]
    pub fn resolved_correlation_id(&self) -> Option<&str> {
        self.test_mode
            .as_ref()
            .and_then(|t| t.correlation_id.as_deref())
            .or(self.correlation_id.as_deref())
    }

    /// Resolved expiry in seconds for test mode.
    #[must_use]
    pub fn resolved_expiry_seconds(&self) -> Option<u64> {
        self.test_mode
            .as_ref()
            .and_then(|t| t.expiry_seconds)
            .or(self.expiry_seconds)
    }

    /// Resolved max events bound for test mode.
    #[must_use]
    pub fn resolved_max_events(&self) -> Option<u64> {
        self.test_mode
            .as_ref()
            .and_then(|t| t.max_events)
            .or(self.max_events)
    }

    /// Resolved prior operational mode to return to upon test expiry.
    #[must_use]
    pub fn resolved_prior_mode(&self) -> OperationalMode {
        self.test_mode
            .as_ref()
            .and_then(|t| t.prior_mode)
            .or(self.prior_mode)
            .unwrap_or(OperationalMode::Production)
    }
}

/// Management plane configuration (SPEC §9).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    /// Whether the management plane is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Bind address or socket path (e.g. "127.0.0.1:9090" or "/run/rer/mgmt.sock").
    pub endpoint: String,

    /// Optional authentication token for remote management.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<SecretString>,

    /// Optional TLS configuration for remote management.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

fn default_true() -> bool {
    true
}

/// TLS configuration for management traffic encryption.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to TLS certificate file.
    pub cert_file: String,

    /// Path to TLS private key file.
    pub key_file: String,
}

/// Configuration for a forwarding stream (SPEC §5).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    /// Unique identity of the stream.
    pub id: String,

    /// Optional description of the stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Stream forwarding source.
    pub source: EndpointConfig,

    /// Stream destination endpoint (conflicts with `destinations`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<EndpointConfig>,

    /// Multiple destination endpoints for fan-out (conflicts with `destination`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destinations: Option<Vec<EndpointConfig>>,

    /// Optional stream-level buffer and queue limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer: Option<BufferConfig>,

    /// Optional sequence extraction and tracking configuration (SPEC §8). Off by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<SequenceConfig>,

    /// Optional packet inspection and preview configuration (SPEC §8). Off by default.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "preview")]
    pub inspection: Option<InspectionConfig>,

    /// Optional CCSDS Space Packet parsing, validation, and sequence tracking configuration (SPEC §14). Off by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccsds: Option<CcsdsConfig>,

    /// Optional framing mode for TCP streams ("length_prefix" or "ccsds"). Defaults to length_prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}

/// Configuration for CCSDS Space Packet parsing, validation, and sequence tracking (SPEC §14).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CcsdsConfig {
    /// Enable CCSDS primary header parsing and validation. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Enforce Packet Version Number == 0. Defaults to true.
    #[serde(default = "default_true", alias = "version")]
    pub validate_version: bool,

    /// Validate that datagram size matches Packet Data Length + 7. Defaults to true.
    #[serde(default = "default_true", alias = "length")]
    pub validate_length: bool,

    /// Track sequence continuity independently per APID. Defaults to true.
    #[serde(
        default = "default_true",
        alias = "sequence_tracking",
        alias = "track_sequence"
    )]
    pub track_sequences: bool,

    /// Optional allowlist of APIDs to accept/track. If None, all APIDs are accepted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "allowed_apids",
        alias = "apids"
    )]
    pub filter_apids: Option<Vec<u16>>,

    /// Exclude idle packets (APID 2047 / 0x7FF) from sequence tracking and gap alerts. Defaults to true.
    #[serde(default = "default_true", alias = "ignore_idle", alias = "filter_idle")]
    pub ignore_idle_apid: bool,

    /// When true, datagrams failing CCSDS validation are forwarded unchanged to destination. Defaults to false.
    #[serde(default, alias = "passthrough")]
    pub passthrough_on_error: bool,

    /// Optional framing mode override ("length_prefix" or "ccsds").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}

impl Default for CcsdsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            validate_version: true,
            validate_length: true,
            track_sequences: true,
            filter_apids: None,
            ignore_idle_apid: true,
            passthrough_on_error: false,
            framing: None,
        }
    }
}

impl StreamConfig {
    /// Returns the effective framing mode for the source endpoint.
    #[must_use]
    pub fn source_framing(&self) -> FramingMode {
        self.source
            .framing
            .or(self.framing)
            .or_else(|| self.ccsds.as_ref().and_then(|c| c.framing))
            .unwrap_or_default()
    }

    /// Returns the effective framing mode for a destination endpoint.
    #[must_use]
    pub fn destination_framing(&self, dest: &EndpointConfig) -> FramingMode {
        dest.framing
            .or(self.framing)
            .or_else(|| self.ccsds.as_ref().and_then(|c| c.framing))
            .unwrap_or_default()
    }
}

/// Supported byte orders for binary sequence extraction (SPEC §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum ByteOrder {
    #[default]
    #[serde(alias = "big", alias = "be", alias = "network")]
    BigEndian,
    #[serde(alias = "little", alias = "le")]
    LittleEndian,
}

impl fmt::Display for ByteOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BigEndian => write!(f, "big_endian"),
            Self::LittleEndian => write!(f, "little_endian"),
        }
    }
}

/// Configuration for packet sequence extraction and continuity tracking (SPEC §8).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SequenceConfig {
    /// Whether sequence tracking is enabled. Defaults to true when this section is present.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Byte offset of the sequence number in packet payload (0-indexed). Defaults to 0.
    #[serde(default)]
    pub offset: usize,

    /// Width of the sequence field in bytes (1, 2, 4, or 8). Defaults to 4.
    #[serde(default = "default_sequence_width")]
    pub width: usize,

    /// Byte order of the sequence number field. Defaults to big-endian (network byte order).
    #[serde(default)]
    pub byte_order: ByteOrder,

    /// Optional sequence rollover / modulus value (e.g. 65536 for 16-bit). Defaults to 2^(8*width).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollover_threshold: Option<u64>,

    /// Opt-in hexadecimal preview of payload bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex_preview: Option<bool>,

    /// Opt-in ASCII preview of payload bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ascii_preview: Option<bool>,

    /// Maximum length in bytes for previews (length-bounded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_preview_bytes: Option<usize>,
}

pub fn default_sequence_width() -> usize {
    4
}

/// Opt-in packet inspection and payload preview configuration (SPEC §8).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InspectionConfig {
    /// Whether hexadecimal payload previews are enabled. Defaults to false (opt-in).
    #[serde(default, alias = "hex")]
    pub hex_preview: bool,

    /// Whether ASCII payload previews are enabled. Defaults to false (opt-in).
    #[serde(default, alias = "ascii")]
    pub ascii_preview: bool,

    /// Maximum length in bytes for previews (length-bounded). Defaults to 64 bytes.
    #[serde(
        default = "default_max_preview_bytes",
        alias = "max_bytes",
        alias = "max_length"
    )]
    pub max_preview_bytes: usize,
}

pub fn default_max_preview_bytes() -> usize {
    64
}

impl Default for SequenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            offset: 0,
            width: 4,
            byte_order: ByteOrder::BigEndian,
            rollover_threshold: None,
            hex_preview: None,
            ascii_preview: None,
            max_preview_bytes: None,
        }
    }
}

impl Default for InspectionConfig {
    fn default() -> Self {
        Self {
            hex_preview: false,
            ascii_preview: false,
            max_preview_bytes: 64,
        }
    }
}

/// Network endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    /// Transport protocol ("udp" or "tcp").
    pub transport: TransportType,

    /// Network endpoint address in "host:port" format (e.g. "127.0.0.1:5000").
    pub address: String,

    /// Connection mode ("listen" or "connect").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ConnectionMode>,

    /// Optional framing mode for TCP endpoints ("length_prefix" or "ccsds"). Defaults to length_prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framing: Option<FramingMode>,
}

/// Framing modes for TCP streams (SPEC §5, §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum FramingMode {
    /// Standard 4-byte big-endian length prefix (default).
    #[default]
    #[serde(alias = "default", alias = "length_prefix", alias = "length_prefixed")]
    LengthPrefix,
    /// CCSDS Space Packet length-based framing (packet data length field + 7 bytes).
    #[serde(alias = "CCSDS")]
    Ccsds,
}

impl fmt::Display for FramingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthPrefix => write!(f, "length_prefix"),
            Self::Ccsds => write!(f, "ccsds"),
        }
    }
}

/// Supported transport protocols (SPEC §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    Udp,
    Tcp,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
        }
    }
}

/// Connection modes for endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    Listen,
    Connect,
}

/// Logical interface pairing directional streams (SPEC §6).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LogicalInterfaceConfig {
    /// Unique identity of the logical interface.
    pub id: String,

    /// Human-readable label or description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Transmit / uplink stream identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_stream: Option<String>,

    /// Receive / downlink stream identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_stream: Option<String>,
}

/// Buffer and queue bounding configuration (SPEC §17).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BufferConfig {
    /// Maximum queue size in packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queue_size: Option<usize>,

    /// Maximum packet size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packet_size: Option<usize>,

    /// Drop policy under queue exhaustion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop_policy: Option<DropPolicy>,
}

/// Drop policies under queue exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DropPolicy {
    DropOldest,
    DropNewest,
    Reject,
}

/// A validation error reporting the exact path and reason for the failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationError {
    /// Path to the invalid field (e.g. "instances[0].streams[1].source.address").
    pub path: String,
    /// Explanation of why the field or configuration is invalid.
    pub reason: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

/// Machine-readable validation report for automation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationReport {
    /// True if configuration is valid; false if any errors exist.
    pub valid: bool,
    /// List of validation errors.
    pub errors: Vec<ValidationError>,
    /// Effective configuration with defaults resolved and secrets redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_config: Option<Config>,
}

impl Config {
    /// Parses and deserializes configuration from a YAML string.
    ///
    /// Unknown fields are rejected and reported with their path and reason.
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, Vec<ValidationError>> {
        let deserializer = serde_yaml::Deserializer::from_str(yaml_str);
        match serde_path_to_error::deserialize::<_, Self>(deserializer) {
            Ok(config) => Ok(config),
            Err(err) => {
                let path = err.path().to_string();
                let path = if path.is_empty() || path == "." {
                    "file".to_string()
                } else {
                    path
                };
                let reason = err.inner().to_string();
                Err(vec![ValidationError { path, reason }])
            }
        }
    }

    /// Resolves and returns all configured instances (supporting both `instances` and `instance`).
    pub fn all_instances(&self) -> Vec<InstanceConfig> {
        if let Some(inst) = &self.instance {
            vec![inst.clone()]
        } else {
            self.instances.clone()
        }
    }

    /// Performs semantic validation across the configuration.
    ///
    /// Validates duplicate instance/stream IDs, conflicting settings,
    /// endpoint addresses, and referenced stream identities.
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if self.version.trim().is_empty() {
            errors.push(ValidationError {
                path: "version".to_string(),
                reason: "version must not be empty".to_string(),
            });
        }

        // Validate instance vs instances
        if self.instance.is_some() && !self.instances.is_empty() {
            errors.push(ValidationError {
                path: "instances".to_string(),
                reason: "conflicting settings: cannot specify both 'instance' and 'instances'"
                    .to_string(),
            });
        } else if self.instance.is_none() && self.instances.is_empty() {
            errors.push(ValidationError {
                path: "instances".to_string(),
                reason: "at least one instance must be configured".to_string(),
            });
            return errors;
        }

        let instances_to_check = if let Some(inst) = &self.instance {
            vec![(None, inst)]
        } else {
            self.instances
                .iter()
                .enumerate()
                .map(|(i, inst)| (Some(i), inst))
                .collect()
        };

        let mut seen_instance_ids = HashSet::new();
        let mut global_stream_ids = HashSet::new();

        for (idx_opt, inst) in instances_to_check {
            let inst_prefix = match idx_opt {
                Some(i) => format!("instances[{}]", i),
                None => "instance".to_string(),
            };

            // Check instance ID
            if inst.id.trim().is_empty() {
                errors.push(ValidationError {
                    path: format!("{}.id", inst_prefix),
                    reason: "instance id must not be empty".to_string(),
                });
            } else if !seen_instance_ids.insert(inst.id.clone()) {
                errors.push(ValidationError {
                    path: format!("{}.id", inst_prefix),
                    reason: format!("duplicate instance identity '{}'", inst.id),
                });
            }

            // Check management
            if let Some(mgmt) = &inst.management {
                let mgmt_prefix = format!("{}.management", inst_prefix);
                if mgmt.enabled && mgmt.endpoint.trim().is_empty() {
                    errors.push(ValidationError {
                        path: format!("{}.endpoint", mgmt_prefix),
                        reason: "management endpoint must not be empty when enabled".to_string(),
                    });
                } else if mgmt.enabled && is_remote_endpoint(&mgmt.endpoint) {
                    validate_endpoint_address(
                        &mgmt.endpoint,
                        &format!("{}.endpoint", mgmt_prefix),
                        &mut errors,
                    );
                }
                if mgmt.enabled && is_untrusted_remote_endpoint(&mgmt.endpoint) {
                    if mgmt
                        .auth_token
                        .as_ref()
                        .map(|t| t.expose_secret().trim().is_empty())
                        .unwrap_or(true)
                    {
                        errors.push(ValidationError {
                            path: format!("{}.auth_token", mgmt_prefix),
                            reason: format!(
                                "remote management endpoint '{}' requires authentication; 'auth_token' must be configured",
                                mgmt.endpoint
                            ),
                        });
                    }
                    if mgmt.tls.is_none() {
                        errors.push(ValidationError {
                            path: format!("{}.tls", mgmt_prefix),
                            reason: format!(
                                "remote management endpoint '{}' requires encryption; 'tls' with cert_file and key_file must be configured",
                                mgmt.endpoint
                            ),
                        });
                    }
                }
                if let Some(tls) = &mgmt.tls {
                    if tls.cert_file.trim().is_empty() {
                        errors.push(ValidationError {
                            path: format!("{}.tls.cert_file", mgmt_prefix),
                            reason: "cert_file must not be empty".to_string(),
                        });
                    }
                    if tls.key_file.trim().is_empty() {
                        errors.push(ValidationError {
                            path: format!("{}.tls.key_file", mgmt_prefix),
                            reason: "key_file must not be empty".to_string(),
                        });
                    }
                }
            }

            // Check metrics configuration
            if let Some(metrics) = &inst.metrics {
                let metrics_prefix = format!("{}.metrics", inst_prefix);
                if metrics.enabled && metrics.endpoint.trim().is_empty() {
                    errors.push(ValidationError {
                        path: format!("{}.endpoint", metrics_prefix),
                        reason: "metrics endpoint must not be empty when enabled".to_string(),
                    });
                }
            }

            // Check instance buffer
            if let Some(buf) = &inst.buffer {
                validate_buffer(buf, &format!("{}.buffer", inst_prefix), &mut errors);
            }

            // Check test mode bounds
            if inst.mode == OperationalMode::Test {
                if let Some(dur) = inst.resolved_expiry_seconds() {
                    if dur > MAX_TEST_DURATION_SECONDS {
                        errors.push(ValidationError {
                            path: format!("{}.test_mode.expiry_seconds", inst_prefix),
                            reason: format!(
                                "configured test mode duration ({}s) exceeds maximum allowed duration ({}s)",
                                dur, MAX_TEST_DURATION_SECONDS
                            ),
                        });
                    }
                    if dur == 0 {
                        errors.push(ValidationError {
                            path: format!("{}.test_mode.expiry_seconds", inst_prefix),
                            reason: "configured test mode duration must be greater than 0"
                                .to_string(),
                        });
                    }
                }
                if let Some(evs) = inst.resolved_max_events() {
                    if evs > MAX_TEST_EVENTS {
                        errors.push(ValidationError {
                            path: format!("{}.test_mode.max_events", inst_prefix),
                            reason: format!(
                                "configured test mode max_events ({}) exceeds maximum allowed ({})",
                                evs, MAX_TEST_EVENTS
                            ),
                        });
                    }
                    if evs == 0 {
                        errors.push(ValidationError {
                            path: format!("{}.test_mode.max_events", inst_prefix),
                            reason: "configured test mode max_events must be greater than 0"
                                .to_string(),
                        });
                    }
                }
            }

            // Check streams
            let mut inst_stream_ids = HashSet::new();
            for (s_idx, stream) in inst.streams.iter().enumerate() {
                let stream_prefix = format!("{}.streams[{}]", inst_prefix, s_idx);

                // Stream ID check
                if stream.id.trim().is_empty() {
                    errors.push(ValidationError {
                        path: format!("{}.id", stream_prefix),
                        reason: "stream id must not be empty".to_string(),
                    });
                } else {
                    if !inst_stream_ids.insert(stream.id.clone()) {
                        errors.push(ValidationError {
                            path: format!("{}.id", stream_prefix),
                            reason: format!("duplicate stream identity '{}'", stream.id),
                        });
                    }
                    if !global_stream_ids.insert(stream.id.clone()) {
                        // Check if duplicate across instances
                        if inst_stream_ids.contains(&stream.id) && inst_stream_ids.len() == 1 {
                            // Only report once per instance
                        }
                    }
                }

                // Stream destination conflicts
                if stream.destination.is_some() && stream.destinations.is_some() {
                    errors.push(ValidationError {
                        path: stream_prefix.clone(),
                        reason: "conflicting settings: cannot specify both 'destination' and 'destinations'".to_string(),
                    });
                } else if stream.destination.is_none() && stream.destinations.is_none() {
                    errors.push(ValidationError {
                        path: stream_prefix.clone(),
                        reason: "missing destination: either 'destination' or 'destinations' must be specified".to_string(),
                    });
                } else if let Some(dests) = &stream.destinations {
                    if dests.is_empty() {
                        errors.push(ValidationError {
                            path: format!("{}.destinations", stream_prefix),
                            reason: "'destinations' list cannot be empty".to_string(),
                        });
                    }
                }

                // Validate source endpoint
                validate_endpoint(
                    &stream.source,
                    &format!("{}.source", stream_prefix),
                    true,
                    &mut errors,
                );

                // Validate destination endpoint(s)
                if let Some(dest) = &stream.destination {
                    validate_endpoint(
                        dest,
                        &format!("{}.destination", stream_prefix),
                        false,
                        &mut errors,
                    );
                }
                if let Some(dests) = &stream.destinations {
                    for (d_idx, dest) in dests.iter().enumerate() {
                        validate_endpoint(
                            dest,
                            &format!("{}.destinations[{}]", stream_prefix, d_idx),
                            false,
                            &mut errors,
                        );
                    }
                }

                // Validate stream buffer
                if let Some(buf) = &stream.buffer {
                    validate_buffer(buf, &format!("{}.buffer", stream_prefix), &mut errors);
                }

                // Validate sequence tracking configuration
                if let Some(ref seq) = stream.sequence {
                    if seq.width != 1 && seq.width != 2 && seq.width != 4 && seq.width != 8 {
                        errors.push(ValidationError {
                            path: format!("{}.sequence.width", stream_prefix),
                            reason: format!(
                                "sequence width {} is invalid; must be 1, 2, 4, or 8 bytes",
                                seq.width
                            ),
                        });
                    }
                    if let Some(thresh) = seq.rollover_threshold {
                        if thresh == 0 {
                            errors.push(ValidationError {
                                path: format!("{}.sequence.rollover_threshold", stream_prefix),
                                reason: "sequence rollover_threshold must be greater than 0"
                                    .to_string(),
                            });
                        }
                    }
                    if let Some(max_bytes) = seq.max_preview_bytes {
                        if max_bytes == 0 {
                            errors.push(ValidationError {
                                path: format!("{}.sequence.max_preview_bytes", stream_prefix),
                                reason: "max_preview_bytes must be greater than 0".to_string(),
                            });
                        }
                    }
                }

                // Validate packet inspection configuration
                if let Some(ref insp) = stream.inspection {
                    if insp.max_preview_bytes == 0 {
                        errors.push(ValidationError {
                            path: format!("{}.inspection.max_preview_bytes", stream_prefix),
                            reason: "max_preview_bytes must be greater than 0".to_string(),
                        });
                    }
                }

                // Validate CCSDS configuration and check conflicting sequence tracking
                if let Some(ref ccsds) = stream.ccsds {
                    let ccsds_seq_enabled = ccsds.enabled && ccsds.track_sequences;
                    let generic_seq_enabled = stream.sequence.as_ref().is_some_and(|s| s.enabled);

                    if ccsds_seq_enabled && generic_seq_enabled {
                        errors.push(ValidationError {
                            path: format!("{}.ccsds.track_sequences", stream_prefix),
                            reason: "conflicting sequence tracking: both CCSDS sequence tracking and generic sequence tracking cannot be enabled simultaneously".to_string(),
                        });
                    }

                    if let Some(ref apids) = ccsds.filter_apids {
                        for apid in apids {
                            if *apid > 2047 {
                                errors.push(ValidationError {
                                    path: format!("{}.ccsds.filter_apids", stream_prefix),
                                    reason: format!(
                                        "invalid APID {}: APID must be between 0 and 2047",
                                        apid
                                    ),
                                });
                            }
                        }
                    }
                }
            }

            // Check logical interfaces
            let mut iface_ids = HashSet::new();
            for (l_idx, iface) in inst.logical_interfaces.iter().enumerate() {
                let iface_prefix = format!("{}.logical_interfaces[{}]", inst_prefix, l_idx);

                if iface.id.trim().is_empty() {
                    errors.push(ValidationError {
                        path: format!("{}.id", iface_prefix),
                        reason: "logical interface id must not be empty".to_string(),
                    });
                } else if !iface_ids.insert(iface.id.clone()) {
                    errors.push(ValidationError {
                        path: format!("{}.id", iface_prefix),
                        reason: format!("duplicate logical interface identity '{}'", iface.id),
                    });
                }

                if iface.tx_stream.is_none() && iface.rx_stream.is_none() {
                    errors.push(ValidationError {
                        path: iface_prefix.clone(),
                        reason: "logical interface must specify at least one directional stream ('tx_stream' or 'rx_stream')".to_string(),
                    });
                }

                if let (Some(tx), Some(rx)) = (&iface.tx_stream, &iface.rx_stream) {
                    if tx == rx {
                        errors.push(ValidationError {
                            path: iface_prefix.clone(),
                            reason: "conflicting settings: 'tx_stream' and 'rx_stream' cannot reference the same stream ID".to_string(),
                        });
                    }
                }

                if let Some(tx) = &iface.tx_stream {
                    if !inst_stream_ids.contains(tx) {
                        errors.push(ValidationError {
                            path: format!("{}.tx_stream", iface_prefix),
                            reason: format!("stream ID '{}' referenced by logical interface not found in instance streams", tx),
                        });
                    }
                }

                if let Some(rx) = &iface.rx_stream {
                    if !inst_stream_ids.contains(rx) {
                        errors.push(ValidationError {
                            path: format!("{}.rx_stream", iface_prefix),
                            reason: format!("stream ID '{}' referenced by logical interface not found in instance streams", rx),
                        });
                    }
                }
            }
        }

        errors
    }

    /// Returns the effective configuration with all defaults resolved and secrets redacted.
    pub fn to_effective(&self) -> Self {
        let instances = self
            .all_instances()
            .into_iter()
            .map(|mut inst| {
                // Apply default mode
                // For endpoints, apply default mode if not present
                for stream in &mut inst.streams {
                    if stream.source.mode.is_none() {
                        stream.source.mode = Some(ConnectionMode::Listen);
                    }
                    if let Some(dest) = &mut stream.destination {
                        if dest.mode.is_none() {
                            dest.mode = Some(ConnectionMode::Connect);
                        }
                    }
                    if let Some(dests) = &mut stream.destinations {
                        for dest in dests.iter_mut() {
                            if dest.mode.is_none() {
                                dest.mode = Some(ConnectionMode::Connect);
                            }
                        }
                    }
                }
                inst
            })
            .collect();

        Self {
            version: self.version.clone(),
            instance: None,
            instances,
        }
    }

    /// Serializes effective configuration as YAML.
    pub fn to_effective_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(&self.to_effective())
    }

    /// Serializes effective configuration as JSON.
    pub fn to_effective_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self.to_effective())
    }
}

fn validate_buffer(buf: &BufferConfig, path: &str, errors: &mut Vec<ValidationError>) {
    if let Some(q) = buf.max_queue_size {
        if q == 0 {
            errors.push(ValidationError {
                path: format!("{}.max_queue_size", path),
                reason: "max_queue_size must be greater than 0".to_string(),
            });
        }
    }
    if let Some(p) = buf.max_packet_size {
        if p == 0 {
            errors.push(ValidationError {
                path: format!("{}.max_packet_size", path),
                reason: "max_packet_size must be greater than 0".to_string(),
            });
        }
    }
}

fn validate_endpoint(
    ep: &EndpointConfig,
    path: &str,
    is_source: bool,
    errors: &mut Vec<ValidationError>,
) {
    validate_endpoint_address(&ep.address, &format!("{}.address", path), errors);

    // Conflicting modes
    if is_source && ep.transport == TransportType::Udp && ep.mode == Some(ConnectionMode::Connect) {
        errors.push(ValidationError {
            path: format!("{}.mode", path),
            reason: "conflicting settings: UDP source cannot be in 'connect' mode".to_string(),
        });
    }
}

/// Validates an endpoint address string offline and deterministically.
///
/// An endpoint address must be `host:port` where `host` is:
/// - an IPv4 literal (e.g. `127.0.0.1`),
/// - a bracketed IPv6 literal (e.g. `[::1]`), optionally with a zone identifier (e.g. `[fe80::1%eth0]`),
/// - or a syntactically valid hostname (e.g. `localhost`, `relay-1.example.com`).
///
/// Ports must be an integer between 1 and 65535.
pub fn validate_endpoint_address(addr_str: &str, path: &str, errors: &mut Vec<ValidationError>) {
    let addr = addr_str.trim();
    if addr.is_empty() {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: "address must not be empty".to_string(),
        });
        return;
    }

    // Unix-domain-socket paths keep their current handling and are not run through host validation.
    if !is_remote_endpoint(addr) {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: "invalid address format: expected 'host:port' (e.g. '127.0.0.1:5000')"
                .to_string(),
        });
        return;
    }

    if addr.starts_with('[') {
        let Some(close_idx) = addr.find(']') else {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: "malformed bracketed IPv6 address: missing closing ']'".to_string(),
            });
            return;
        };

        let raw_host = &addr[1..close_idx];
        let remainder = &addr[close_idx + 1..];

        if remainder.is_empty() {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: "invalid address format: expected 'host:port' (missing port after bracketed IPv6)".to_string(),
            });
            return;
        }

        if !remainder.starts_with(':') {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!(
                    "invalid characters after closing bracket: '{}'; expected ':port'",
                    remainder
                ),
            });
            return;
        }

        let port_str = &remainder[1..];
        validate_port(port_str, path, errors);
        validate_bracketed_ipv6_host(raw_host, path, errors);
    } else {
        let colon_count = addr.matches(':').count();
        if colon_count == 0 {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: "invalid address format: expected 'host:port' (e.g. '127.0.0.1:5000')"
                    .to_string(),
            });
            return;
        }

        if colon_count > 1 {
            // Unbracketed IPv6 literal or multiple colons
            errors.push(ValidationError {
                path: path.to_string(),
                reason: "IPv6 literals must be bracketed in address (e.g. '[::1]:80')".to_string(),
            });
            return;
        }

        // Exactly one colon
        let (host, port_str) = addr.split_once(':').unwrap();
        validate_port(port_str, path, errors);
        validate_unbracketed_host(host, path, errors);
    }
}

fn validate_port(port_str: &str, path: &str, errors: &mut Vec<ValidationError>) {
    if port_str.is_empty() {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: "port must not be empty; must be an integer between 1 and 65535".to_string(),
        });
        return;
    }

    if port_str.starts_with('-') {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!(
                "negative port '{}' is invalid; must be between 1 and 65535",
                port_str
            ),
        });
        return;
    }

    if !port_str.chars().all(|c| c.is_ascii_digit()) {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!(
                "non-numeric port '{}' is invalid; must be an integer between 1 and 65535",
                port_str
            ),
        });
        return;
    }

    match port_str.parse::<u64>() {
        Ok(0) => {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: "port 0 is invalid; must be between 1 and 65535".to_string(),
            });
        }
        Ok(p) if p > 65535 => {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!("port {} is out of valid range 1..=65535", p),
            });
        }
        Ok(_) => {}
        Err(_) => {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!("port '{}' is out of valid range 1..=65535", port_str),
            });
        }
    }
}

fn validate_bracketed_ipv6_host(raw_host: &str, path: &str, errors: &mut Vec<ValidationError>) {
    if raw_host.is_empty() {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: "IPv6 address inside brackets cannot be empty".to_string(),
        });
        return;
    }

    if raw_host.contains('%') {
        let percent_count = raw_host.matches('%').count();
        if percent_count > 1 {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: "IPv6 literal cannot contain multiple zone identifiers ('%')".to_string(),
            });
            return;
        }

        let (ip_part, zone_part) = raw_host.split_once('%').unwrap();
        // Validate zone identifier
        if zone_part.is_empty() {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: "IPv6 zone identifier cannot be empty".to_string(),
            });
            return;
        }
        if zone_part.len() > 15 {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!(
                    "IPv6 zone identifier '{}' exceeds maximum length of 15 bytes",
                    zone_part
                ),
            });
            return;
        }
        if zone_part
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!(
                    "IPv6 zone identifier '{}' contains whitespace or control characters",
                    zone_part
                ),
            });
            return;
        }

        // Validate IP part
        if ip_part.parse::<std::net::Ipv6Addr>().is_err() {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!("invalid IPv6 address '{}'", ip_part),
            });
        }
    } else if raw_host.parse::<std::net::Ipv6Addr>().is_err() {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!("invalid IPv6 address '{}'", raw_host),
        });
    }
}

fn validate_unbracketed_host(host: &str, path: &str, errors: &mut Vec<ValidationError>) {
    if host.is_empty() {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: "address host part must not be empty".to_string(),
        });
        return;
    }

    if host.contains('[') || host.contains(']') {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!("malformed host '{}': unbracketed brackets", host),
        });
        return;
    }

    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!("host '{}' contains spaces or control characters", host),
        });
        return;
    }

    // Check if valid IPv4 literal
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return;
    }

    // Not a valid IPv4 literal; check if it's an invalid IPv4 literal or a hostname
    let labels: Vec<&str> = host.split('.').collect();
    let all_labels_numeric = labels
        .iter()
        .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit()));
    if all_labels_numeric {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!("invalid IPv4 address '{}'", host),
        });
        return;
    }

    // Validate as hostname
    if host.len() > 253 {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!("hostname '{}' exceeds maximum length of 253 bytes", host),
        });
        return;
    }

    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        errors.push(ValidationError {
            path: path.to_string(),
            reason: format!("hostname '{}' contains empty label", host),
        });
        return;
    }

    if let Some(last_label) = labels.last() {
        if last_label.chars().all(|c| c.is_ascii_digit()) {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!("hostname '{}' has an all-numeric top-level domain", host),
            });
            return;
        }
    }

    for label in &labels {
        if label.is_empty() {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!("hostname '{}' contains empty label", host),
            });
            return;
        }
        if label.len() > 63 {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!(
                    "hostname label '{}' exceeds maximum length of 63 bytes",
                    label
                ),
            });
            return;
        }
        if label.starts_with('-') || label.ends_with('-') {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!(
                    "hostname label '{}' cannot start or end with a hyphen",
                    label
                ),
            });
            return;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            errors.push(ValidationError {
                path: path.to_string(),
                reason: format!("hostname label '{}' contains invalid character", label),
            });
            return;
        }
    }
}

/// Returns true if an endpoint string is a network endpoint (TCP/IP).
#[must_use]
pub fn is_remote_endpoint(endpoint: &str) -> bool {
    let ep = endpoint.trim();
    if ep.starts_with('/') || ep.starts_with("./") || ep.ends_with(".sock") || ep.contains(".sock")
    {
        return false;
    }
    true
}

/// Returns true if an endpoint points to an untrusted remote network (i.e. not local Unix domain socket and not loopback).
#[must_use]
pub fn is_untrusted_remote_endpoint(endpoint: &str) -> bool {
    if !is_remote_endpoint(endpoint) {
        return false;
    }
    let host = endpoint
        .trim()
        .trim_start_matches("tcp://")
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host_part = if host.starts_with('[') {
        if let Some(close_idx) = host.find(']') {
            &host[1..close_idx]
        } else {
            host
        }
    } else if let Some(idx) = host.rfind(':') {
        &host[..idx]
    } else {
        host
    };
    let h = host_part.trim_matches('[').trim_matches(']');
    let h_clean = h.split('%').next().unwrap_or(h);
    h_clean != "127.0.0.1" && h_clean != "localhost" && h_clean != "::1"
}

/// Generates the canonical JSON Schema for RER configuration.
pub fn generate_schema() -> schemars::schema::RootSchema {
    let mut schema = schemars::schema_for!(Config);
    if let Some(ref mut meta) = schema.schema.metadata {
        meta.title = Some("RER Configuration Schema".to_string());
        meta.description = Some("Configuration schema for RER (RER Engineering Relay)".to_string());
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_matches_generated() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let schema_path = repo_root.join("schema").join("rer-config.schema.json");
        let generated = serde_json::to_string_pretty(&generate_schema()).unwrap() + "\n";

        if !schema_path.exists() {
            std::fs::create_dir_all(schema_path.parent().unwrap()).unwrap();
            std::fs::write(&schema_path, &generated).unwrap();
        }

        let existing = std::fs::read_to_string(&schema_path).unwrap();
        assert_eq!(
            existing.trim(),
            generated.trim(),
            "schema/rer-config.schema.json is out of date with Config models."
        );
    }
}
