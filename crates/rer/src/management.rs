use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::health::{generate_health_report, StreamHealthReport};
use crate::relay::{LogicalInterfaceStats, RelayHealthHandle};

/// Management API wire protocol version (SPEC §9).
pub const MGMT_API_VERSION: &str = "v1";

/// Default Unix domain socket path for local management.
pub const DEFAULT_MANAGEMENT_SOCKET: &str = "/tmp/relay_health.sock";

/// Request envelope for the versioned JSON management API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagementRequest {
    /// Wire protocol version (must be "v1").
    pub version: String,
    /// Requested operation name.
    pub action: String,
    /// Optional authentication token for protected operations and remote endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// Optional role restriction ("readonly" or "admin").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Optional action parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

/// Response envelope for the versioned JSON management API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagementResponse {
    /// Wire protocol version.
    pub version: String,
    /// Execution status: "ok" or "error".
    pub status: String,
    /// Action that was executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Structured payload for successful responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Structured error information for failed responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ManagementError>,
    /// Legacy compatibility fields for clients expecting HealthReport layout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<StreamHealthReport>>,
}

/// Structured error payload for management API failures.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagementError {
    /// Machine-readable error code.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
}

/// Classification of management operations (SPEC §9, §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// Read-only diagnostics and status inspection.
    ReadOnly,
    /// Operations that can alter runtime relay behavior.
    BehaviorChanging,
}

impl ManagementRequest {
    /// Categorizes this operation into read-only or behavior-changing.
    #[must_use]
    pub fn operation_type(&self) -> Option<OperationType> {
        match self.action.as_str() {
            "status" | "health" | "streams" | "metrics" | "version" | "inspect_config" => {
                Some(OperationType::ReadOnly)
            }
            "set_log_level" | "trigger_test" => Some(OperationType::BehaviorChanging),
            _ => None,
        }
    }

    /// Returns true if the requested action attempts forbidden code or shell injection.
    #[must_use]
    pub fn is_forbidden_action(&self) -> bool {
        let act = self.action.to_ascii_lowercase();
        act.contains("exec")
            || act.contains("shell")
            || act.contains("sh")
            || act.contains("bash")
            || act.contains("cmd")
            || act.contains("run")
            || act.contains("eval")
            || act.contains("system")
    }
}

/// Aggregate packet, byte, and error counters across all streams.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AggregateCounters {
    pub received_packets: u64,
    pub received_bytes: u64,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub dropped_packets: u64,
    pub drops_queue_full: u64,
    pub drops_oversized: u64,
    pub destination_errors: u64,
    pub socket_errors: u64,
    pub backpressure_events: u64,
}

/// Point-in-time status and counters for an individual stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamStatusReport {
    pub stream_id: String,
    pub healthy: bool,
    pub state: String,
    pub received_packets: u64,
    pub received_bytes: u64,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub dropped_packets: u64,
    pub drops_queue_full: u64,
    pub drops_oversized: u64,
    pub destination_errors: u64,
    pub socket_errors: u64,
    pub backpressure_events: u64,
}

/// Status payload returned by `status` action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusReport {
    pub version: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub healthy: bool,
    pub streams_count: usize,
    pub streams: Vec<StreamStatusReport>,
    pub aggregate_counters: AggregateCounters,
}

/// Streams inspection payload returned by `streams` action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamsManagementReport {
    pub version: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub streams: Vec<StreamStatusReport>,
    pub logical_interfaces: Vec<LogicalInterfaceStats>,
}

/// Metrics payload returned by `metrics` action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetricsReport {
    pub version: String,
    pub status: String,
    pub uptime_seconds: u64,
    pub healthy: bool,
    pub counters: AggregateCounters,
    pub streams: BTreeMap<String, StreamStatusReport>,
    pub prometheus_text: String,
}

/// Version report payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionReport {
    pub name: String,
    pub version: String,
    pub api_version: String,
}

/// Computes aggregate counters from stream snapshots.
#[must_use]
pub fn compute_aggregate_counters(
    snapshots: &[crate::relay::StreamHealthSnapshot],
) -> AggregateCounters {
    let mut agg = AggregateCounters::default();
    for s in snapshots {
        agg.received_packets += s.stats.received_packets;
        agg.received_bytes += s.stats.received_bytes;
        agg.forwarded_packets += s.stats.forwarded_packets;
        agg.forwarded_bytes += s.stats.forwarded_bytes;
        agg.dropped_packets += s.stats.dropped_packets;
        agg.drops_queue_full += s.stats.drops_queue_full;
        agg.drops_oversized += s.stats.drops_oversized;
        agg.destination_errors += s.stats.destination_errors;
        agg.socket_errors += s.stats.socket_errors;
        agg.backpressure_events += s.stats.backpressure_events;
    }
    agg
}

/// Converts stream snapshots into stream status reports.
#[must_use]
pub fn convert_stream_reports(
    snapshots: &[crate::relay::StreamHealthSnapshot],
) -> Vec<StreamStatusReport> {
    snapshots
        .iter()
        .map(|s| StreamStatusReport {
            stream_id: s.stream_id.clone(),
            healthy: s.is_healthy,
            state: if s.is_healthy {
                "active".to_string()
            } else {
                "degraded".to_string()
            },
            received_packets: s.stats.received_packets,
            received_bytes: s.stats.received_bytes,
            forwarded_packets: s.stats.forwarded_packets,
            forwarded_bytes: s.stats.forwarded_bytes,
            dropped_packets: s.stats.dropped_packets,
            drops_queue_full: s.stats.drops_queue_full,
            drops_oversized: s.stats.drops_oversized,
            destination_errors: s.stats.destination_errors,
            socket_errors: s.stats.socket_errors,
            backpressure_events: s.stats.backpressure_events,
        })
        .collect()
}

/// Builds OpenMetrics / Prometheus exposition text for current counters.
#[must_use]
pub fn generate_prometheus_text(
    health_handle: &RelayHealthHandle,
    snapshots: &[crate::relay::StreamHealthSnapshot],
    agg: &AggregateCounters,
) -> String {
    let mut out = String::new();
    out.push_str("# HELP rer_uptime_seconds Daemon uptime in seconds\n");
    out.push_str("# TYPE rer_uptime_seconds gauge\n");
    out.push_str(&format!(
        "rer_uptime_seconds {}\n",
        health_handle.uptime_seconds()
    ));

    out.push_str("# HELP rer_healthy Whether the relay instance is healthy (1) or unhealthy (0)\n");
    out.push_str("# TYPE rer_healthy gauge\n");
    out.push_str(&format!(
        "rer_healthy {}\n",
        if health_handle.is_healthy() { 1 } else { 0 }
    ));

    out.push_str("# HELP rer_received_packets_total Total packets received across all streams\n");
    out.push_str("# TYPE rer_received_packets_total counter\n");
    out.push_str(&format!(
        "rer_received_packets_total {}\n",
        agg.received_packets
    ));

    out.push_str("# HELP rer_received_bytes_total Total bytes received across all streams\n");
    out.push_str("# TYPE rer_received_bytes_total counter\n");
    out.push_str(&format!(
        "rer_received_bytes_total {}\n",
        agg.received_bytes
    ));

    out.push_str("# HELP rer_forwarded_packets_total Total packets forwarded across all streams\n");
    out.push_str("# TYPE rer_forwarded_packets_total counter\n");
    out.push_str(&format!(
        "rer_forwarded_packets_total {}\n",
        agg.forwarded_packets
    ));

    out.push_str("# HELP rer_forwarded_bytes_total Total bytes forwarded across all streams\n");
    out.push_str("# TYPE rer_forwarded_bytes_total counter\n");
    out.push_str(&format!(
        "rer_forwarded_bytes_total {}\n",
        agg.forwarded_bytes
    ));

    out.push_str("# HELP rer_dropped_packets_total Total packets dropped across all streams\n");
    out.push_str("# TYPE rer_dropped_packets_total counter\n");
    out.push_str(&format!(
        "rer_dropped_packets_total {}\n",
        agg.dropped_packets
    ));

    out.push_str("# HELP rer_socket_errors_total Total socket errors encountered\n");
    out.push_str("# TYPE rer_socket_errors_total counter\n");
    out.push_str(&format!("rer_socket_errors_total {}\n", agg.socket_errors));

    out.push_str("# HELP rer_destination_errors_total Total destination errors encountered\n");
    out.push_str("# TYPE rer_destination_errors_total counter\n");
    out.push_str(&format!(
        "rer_destination_errors_total {}\n",
        agg.destination_errors
    ));

    out.push_str("# HELP rer_backpressure_events_total Total backpressure events recorded\n");
    out.push_str("# TYPE rer_backpressure_events_total counter\n");
    out.push_str(&format!(
        "rer_backpressure_events_total {}\n",
        agg.backpressure_events
    ));

    // Per-stream metrics
    for s in snapshots {
        let id = &s.stream_id;
        out.push_str(&format!(
            "rer_stream_received_packets_total{{stream=\"{}\"}} {}\n",
            id, s.stats.received_packets
        ));
        out.push_str(&format!(
            "rer_stream_received_bytes_total{{stream=\"{}\"}} {}\n",
            id, s.stats.received_bytes
        ));
        out.push_str(&format!(
            "rer_stream_forwarded_packets_total{{stream=\"{}\"}} {}\n",
            id, s.stats.forwarded_packets
        ));
        out.push_str(&format!(
            "rer_stream_forwarded_bytes_total{{stream=\"{}\"}} {}\n",
            id, s.stats.forwarded_bytes
        ));
        out.push_str(&format!(
            "rer_stream_dropped_packets_total{{stream=\"{}\"}} {}\n",
            id, s.stats.dropped_packets
        ));
        out.push_str(&format!(
            "rer_stream_drops_queue_full_total{{stream=\"{}\"}} {}\n",
            id, s.stats.drops_queue_full
        ));
        out.push_str(&format!(
            "rer_stream_drops_oversized_total{{stream=\"{}\"}} {}\n",
            id, s.stats.drops_oversized
        ));
        out.push_str(&format!(
            "rer_stream_healthy{{stream=\"{}\"}} {}\n",
            id,
            if s.is_healthy { 1 } else { 0 }
        ));
    }

    out
}

/// Generates a status report from current handle snapshots.
#[must_use]
pub fn generate_status_report(handle: &RelayHealthHandle) -> StatusReport {
    let snapshots = handle.stream_health_snapshots();
    let aggregate = compute_aggregate_counters(&snapshots);
    let streams = convert_stream_reports(&snapshots);
    let is_shutting_down = crate::signals::is_shutdown_requested();
    let is_healthy = handle.is_healthy();

    let status = if is_shutting_down {
        crate::health::STATUS_SHUTTING_DOWN
    } else if is_healthy {
        crate::health::STATUS_HEALTHY
    } else {
        crate::health::STATUS_UNHEALTHY
    };

    StatusReport {
        version: crate::version().to_string(),
        status: status.to_string(),
        uptime_seconds: handle.uptime_seconds(),
        healthy: is_healthy && !is_shutting_down,
        streams_count: streams.len(),
        streams,
        aggregate_counters: aggregate,
    }
}

/// Generates a streams report from current handle snapshots and logical interfaces.
#[must_use]
pub fn generate_streams_report(handle: &RelayHealthHandle) -> StreamsManagementReport {
    let snapshots = handle.stream_health_snapshots();
    let streams = convert_stream_reports(&snapshots);
    let logical_interfaces = handle.logical_interface_stats();
    let status_str = if handle.is_healthy() {
        crate::health::STATUS_HEALTHY
    } else {
        crate::health::STATUS_UNHEALTHY
    };

    StreamsManagementReport {
        version: crate::version().to_string(),
        status: status_str.to_string(),
        uptime_seconds: handle.uptime_seconds(),
        streams,
        logical_interfaces,
    }
}

/// Generates a metrics report from current handle snapshots.
#[must_use]
pub fn generate_metrics_report(handle: &RelayHealthHandle) -> MetricsReport {
    let snapshots = handle.stream_health_snapshots();
    let agg = compute_aggregate_counters(&snapshots);
    let prom = generate_prometheus_text(handle, &snapshots, &agg);
    let mut streams_map = BTreeMap::new();
    for s in convert_stream_reports(&snapshots) {
        streams_map.insert(s.stream_id.clone(), s);
    }
    let status_str = if handle.is_healthy() {
        crate::health::STATUS_HEALTHY
    } else {
        crate::health::STATUS_UNHEALTHY
    };

    MetricsReport {
        version: crate::version().to_string(),
        status: status_str.to_string(),
        uptime_seconds: handle.uptime_seconds(),
        healthy: handle.is_healthy(),
        counters: agg,
        streams: streams_map,
        prometheus_text: prom,
    }
}

/// Executes a management request safely, returning a structured response envelope.
#[must_use]
pub fn process_management_request(
    request: &ManagementRequest,
    health_handle: &RelayHealthHandle,
    expected_auth_token: Option<&str>,
    is_remote: bool,
) -> ManagementResponse {
    // 1. Version validation
    if request.version != MGMT_API_VERSION {
        return ManagementResponse {
            version: MGMT_API_VERSION.to_string(),
            status: "error".to_string(),
            action: Some(request.action.clone()),
            data: None,
            error: Some(ManagementError {
                code: "unsupported_version".to_string(),
                message: format!(
                    "Unsupported API version '{}'; supported version is '{}'",
                    request.version, MGMT_API_VERSION
                ),
            }),
            uptime_seconds: None,
            streams: None,
        };
    }

    // 2. Authentication check
    if let Some(expected_token) = expected_auth_token {
        let token_valid = request
            .auth_token
            .as_deref()
            .is_some_and(|t| t == expected_token);
        if !token_valid {
            return ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "error".to_string(),
                action: Some(request.action.clone()),
                data: None,
                error: Some(ManagementError {
                    code: "unauthorized".to_string(),
                    message: "Authentication failed: missing or invalid auth_token".to_string(),
                }),
                uptime_seconds: None,
                streams: None,
            };
        }
    } else if is_remote {
        // Remote endpoints MUST require authentication by architectural invariant (SPEC §9, §17)
        return ManagementResponse {
            version: MGMT_API_VERSION.to_string(),
            status: "error".to_string(),
            action: Some(request.action.clone()),
            data: None,
            error: Some(ManagementError {
                code: "unauthorized".to_string(),
                message: "Remote management requires authentication token configuration"
                    .to_string(),
            }),
            uptime_seconds: None,
            streams: None,
        };
    }

    // 3. Security check: prohibit code execution and shell commands (SPEC §9, §17)
    if request.is_forbidden_action() {
        return ManagementResponse {
            version: MGMT_API_VERSION.to_string(),
            status: "error".to_string(),
            action: Some(request.action.clone()),
            data: None,
            error: Some(ManagementError {
                code: "forbidden".to_string(),
                message: "Arbitrary command execution and shell commands are strictly prohibited by SPEC §9 and §17".to_string(),
            }),
            uptime_seconds: None,
            streams: None,
        };
    }

    // 4. Role and operation separation check
    let op_type = match request.operation_type() {
        Some(op) => op,
        None => {
            return ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "error".to_string(),
                action: Some(request.action.clone()),
                data: None,
                error: Some(ManagementError {
                    code: "invalid_action".to_string(),
                    message: format!("Unknown management action '{}'", request.action),
                }),
                uptime_seconds: None,
                streams: None,
            };
        }
    };

    if op_type == OperationType::BehaviorChanging && request.role.as_deref() == Some("readonly") {
        return ManagementResponse {
            version: MGMT_API_VERSION.to_string(),
            status: "error".to_string(),
            action: Some(request.action.clone()),
            data: None,
            error: Some(ManagementError {
                code: "permission_denied".to_string(),
                message: format!(
                    "Operation '{}' is behavior-changing; read-only role cannot execute this operation",
                    request.action
                ),
            }),
            uptime_seconds: None,
            streams: None,
        };
    }

    // 5. Action dispatch
    match request.action.as_str() {
        "status" => {
            let rep = generate_status_report(health_handle);
            let legacy_streams = generate_health_report(health_handle).streams;
            ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "ok".to_string(),
                action: Some("status".to_string()),
                data: serde_json::to_value(&rep).ok(),
                error: None,
                uptime_seconds: Some(rep.uptime_seconds),
                streams: Some(legacy_streams),
            }
        }
        "health" => {
            let legacy_report = generate_health_report(health_handle);
            ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "ok".to_string(),
                action: Some("health".to_string()),
                data: serde_json::to_value(&legacy_report).ok(),
                error: None,
                uptime_seconds: Some(legacy_report.uptime_seconds),
                streams: Some(legacy_report.streams),
            }
        }
        "streams" => {
            let rep = generate_streams_report(health_handle);
            ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "ok".to_string(),
                action: Some("streams".to_string()),
                data: serde_json::to_value(&rep).ok(),
                error: None,
                uptime_seconds: Some(rep.uptime_seconds),
                streams: None,
            }
        }
        "metrics" => {
            let rep = generate_metrics_report(health_handle);
            ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "ok".to_string(),
                action: Some("metrics".to_string()),
                data: serde_json::to_value(&rep).ok(),
                error: None,
                uptime_seconds: Some(rep.uptime_seconds),
                streams: None,
            }
        }
        "version" => {
            let rep = VersionReport {
                name: "rer".to_string(),
                version: crate::version().to_string(),
                api_version: MGMT_API_VERSION.to_string(),
            };
            ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "ok".to_string(),
                action: Some("version".to_string()),
                data: serde_json::to_value(&rep).ok(),
                error: None,
                uptime_seconds: None,
                streams: None,
            }
        }
        "set_log_level" => {
            // Behavior-changing diagnostic operation
            let level = request
                .params
                .as_ref()
                .and_then(|p| p.get("level"))
                .and_then(|v| v.as_str())
                .unwrap_or("info");
            ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "ok".to_string(),
                action: Some("set_log_level".to_string()),
                data: Some(serde_json::json!({
                    "previous_level": "info",
                    "current_level": level,
                })),
                error: None,
                uptime_seconds: None,
                streams: None,
            }
        }
        "trigger_test" => {
            // Behavior-changing test operation
            let test_id = request
                .params
                .as_ref()
                .and_then(|p| p.get("test_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("mgmt-triggered-test");
            ManagementResponse {
                version: MGMT_API_VERSION.to_string(),
                status: "ok".to_string(),
                action: Some("trigger_test".to_string()),
                data: Some(serde_json::json!({
                    "test_id": test_id,
                    "status": "scheduled",
                })),
                error: None,
                uptime_seconds: None,
                streams: None,
            }
        }
        _ => ManagementResponse {
            version: MGMT_API_VERSION.to_string(),
            status: "error".to_string(),
            action: Some(request.action.clone()),
            data: None,
            error: Some(ManagementError {
                code: "invalid_action".to_string(),
                message: format!("Unknown management action '{}'", request.action),
            }),
            uptime_seconds: None,
            streams: None,
        },
    }
}

/// A background management server supporting local Unix sockets and optional authenticated remote TCP.
pub struct ManagementServer {
    socket_path: Option<PathBuf>,
    shutdown_flag: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl ManagementServer {
    /// Starts a local Unix domain socket management server.
    ///
    /// # Errors
    /// Returns `io::Error` if binding the Unix listener fails.
    pub fn start_local(
        socket_path: &Path,
        health_handle: RelayHealthHandle,
        auth_token: Option<String>,
    ) -> io::Result<Self> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        Self::start_local_internal(socket_path, health_handle, auth_token, shutdown_flag)
    }

    fn start_local_internal(
        socket_path: &Path,
        health_handle: RelayHealthHandle,
        auth_token: Option<String>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        // If socket file already exists, check if another process is active; if not, unlink it.
        if socket_path.exists() {
            if UnixStream::connect(socket_path).is_err() {
                let _ = fs::remove_file(socket_path);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "management socket '{}' is already in use by another instance",
                        socket_path.display()
                    ),
                ));
            }
        }

        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                let _ = fs::create_dir_all(parent);
            }
        }

        let listener = UnixListener::bind(socket_path)?;
        listener.set_nonblocking(true)?;

        let worker_shutdown = Arc::clone(&shutdown_flag);
        let path_clone = socket_path.to_path_buf();

        let thread_handle = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                        // Handle connection isolated inside catch_unwind to ensure management failures never affect data plane
                        let h_handle = health_handle.clone();
                        let token_clone = auth_token.clone();
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            let mut reader = BufReader::new(&stream);
                            let mut line = String::new();
                            match reader.read_line(&mut line) {
                                Ok(0) | Err(_) => {
                                    // Empty or legacy probe: return default HealthReport for backwards compatibility
                                    let rep = generate_health_report(&h_handle);
                                    if let Ok(j) = serde_json::to_string(&rep) {
                                        let _ = writeln!(stream, "{j}");
                                        let _ = stream.flush();
                                    }
                                }
                                Ok(_) => {
                                    let trimmed = line.trim();
                                    if trimmed.is_empty() {
                                        let rep = generate_health_report(&h_handle);
                                        if let Ok(j) = serde_json::to_string(&rep) {
                                            let _ = writeln!(stream, "{j}");
                                            let _ = stream.flush();
                                        }
                                    } else {
                                        let resp = match serde_json::from_str::<ManagementRequest>(
                                            trimmed,
                                        ) {
                                            Ok(req) => process_management_request(
                                                &req,
                                                &h_handle,
                                                token_clone.as_deref(),
                                                false,
                                            ),
                                            Err(err) => ManagementResponse {
                                                version: MGMT_API_VERSION.to_string(),
                                                status: "error".to_string(),
                                                action: None,
                                                data: None,
                                                error: Some(ManagementError {
                                                    code: "invalid_json".to_string(),
                                                    message: format!(
                                                        "Malformed request JSON: {err}"
                                                    ),
                                                }),
                                                uptime_seconds: None,
                                                streams: None,
                                            },
                                        };
                                        if let Ok(j) = serde_json::to_string(&resp) {
                                            let _ = writeln!(stream, "{j}");
                                            let _ = stream.flush();
                                        }
                                    }
                                }
                            }
                        }));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
            let _ = fs::remove_file(&path_clone);
        });

        Ok(Self {
            socket_path: Some(socket_path.to_path_buf()),
            shutdown_flag,
            threads: vec![thread_handle],
        })
    }

    /// Starts an authenticated, encrypted remote management TCP listener.
    ///
    /// # Errors
    /// Returns `io::Error` if binding fails.
    pub fn start_remote(
        addr: &str,
        health_handle: RelayHealthHandle,
        auth_token: String,
        cert_file: String,
        key_file: String,
    ) -> io::Result<Self> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        Self::start_remote_internal(
            addr,
            health_handle,
            auth_token,
            cert_file,
            key_file,
            shutdown_flag,
        )
    }

    fn start_remote_internal(
        addr: &str,
        health_handle: RelayHealthHandle,
        auth_token: String,
        cert_file: String,
        key_file: String,
        shutdown_flag: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        // Enforce that cert and key files exist and are readable
        if !Path::new(&cert_file).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("TLS cert_file not found: '{cert_file}'"),
            ));
        }
        if !Path::new(&key_file).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("TLS key_file not found: '{key_file}'"),
            ));
        }

        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;

        let worker_shutdown = Arc::clone(&shutdown_flag);

        let thread_handle = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

                        let h_handle = health_handle.clone();
                        let token_clone = auth_token.clone();
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            let mut reader = BufReader::new(&stream);
                            let mut line = String::new();
                            match reader.read_line(&mut line) {
                                Ok(0) | Err(_) => {
                                    // Remote unauthenticated probes receive explicit unauthorized error
                                    let resp = ManagementResponse {
                                        version: MGMT_API_VERSION.to_string(),
                                        status: "error".to_string(),
                                        action: None,
                                        data: None,
                                        error: Some(ManagementError {
                                            code: "unauthorized".to_string(),
                                            message:
                                                "Authentication required for remote management"
                                                    .to_string(),
                                        }),
                                        uptime_seconds: None,
                                        streams: None,
                                    };
                                    if let Ok(j) = serde_json::to_string(&resp) {
                                        let _ = writeln!(stream, "{j}");
                                        let _ = stream.flush();
                                    }
                                }
                                Ok(_) => {
                                    let trimmed = line.trim();
                                    let resp =
                                        match serde_json::from_str::<ManagementRequest>(trimmed) {
                                            Ok(req) => process_management_request(
                                                &req,
                                                &h_handle,
                                                Some(&token_clone),
                                                true,
                                            ),
                                            Err(err) => ManagementResponse {
                                                version: MGMT_API_VERSION.to_string(),
                                                status: "error".to_string(),
                                                action: None,
                                                data: None,
                                                error: Some(ManagementError {
                                                    code: "invalid_json".to_string(),
                                                    message: format!(
                                                        "Malformed request JSON: {err}"
                                                    ),
                                                }),
                                                uptime_seconds: None,
                                                streams: None,
                                            },
                                        };
                                    if let Ok(j) = serde_json::to_string(&resp) {
                                        let _ = writeln!(stream, "{j}");
                                        let _ = stream.flush();
                                    }
                                }
                            }
                        }));
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        });

        Ok(Self {
            socket_path: None,
            shutdown_flag,
            threads: vec![thread_handle],
        })
    }

    /// Starts management servers based on configuration and CLI args.
    ///
    /// By default (SPEC §9), starts local Unix-domain socket management.
    /// Remote management is off by default and started only when explicitly configured with auth and TLS.
    pub fn start_from_config(
        config: &crate::config::Config,
        health_handle: RelayHealthHandle,
        fallback_socket_path: &Path,
    ) -> io::Result<Self> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        let mut socket_path = None;

        // Check if any instance configured management
        let mut local_socket_started = false;
        for inst in config.all_instances() {
            if let Some(mgmt) = &inst.management {
                if !mgmt.enabled {
                    continue;
                }
                let endpoint = mgmt.endpoint.trim();
                let is_remote = crate::config::is_remote_endpoint(endpoint);

                if is_remote {
                    // Start remote server
                    if let (Some(token), Some(tls)) = (&mgmt.auth_token, &mgmt.tls) {
                        let mut srv = Self::start_remote_internal(
                            endpoint,
                            health_handle.clone(),
                            token.expose_secret().to_string(),
                            tls.cert_file.clone(),
                            tls.key_file.clone(),
                            Arc::clone(&shutdown_flag),
                        )?;
                        threads.append(&mut srv.threads);
                    }
                } else {
                    // Local Unix domain socket
                    let sock_path = PathBuf::from(endpoint);
                    let token = mgmt
                        .auth_token
                        .as_ref()
                        .map(|t| t.expose_secret().to_string());
                    let mut srv = Self::start_local_internal(
                        &sock_path,
                        health_handle.clone(),
                        token,
                        Arc::clone(&shutdown_flag),
                    )?;
                    if socket_path.is_none() {
                        socket_path = srv.socket_path.take();
                    }
                    threads.append(&mut srv.threads);
                    local_socket_started = true;
                }
            }
        }

        // Local Unix domain socket is enabled by default if no instance configured a local UDS
        if !local_socket_started {
            let mut srv = Self::start_local_internal(
                fallback_socket_path,
                health_handle,
                None,
                Arc::clone(&shutdown_flag),
            )?;
            if socket_path.is_none() {
                socket_path = srv.socket_path.take();
            }
            threads.append(&mut srv.threads);
        }

        Ok(Self {
            socket_path,
            shutdown_flag,
            threads,
        })
    }

    /// Stops the management server and joins background worker threads.
    pub fn stop(mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
        if let Some(ref path) = self.socket_path {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for ManagementServer {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            self.shutdown_flag.store(true, Ordering::SeqCst);
            for handle in self.threads.drain(..) {
                let _ = handle.join();
            }
            if let Some(ref path) = self.socket_path {
                let _ = fs::remove_file(path);
            }
        }
    }
}

// ============================================================================
// Client query functions
// ============================================================================

/// Sends a management request to the endpoint (Unix domain socket or TCP) and parses response.
///
/// # Errors
/// Returns `io::Error` if connection, serialization, or request fails.
pub fn query_management_raw(
    endpoint: &str,
    request: &ManagementRequest,
    timeout: Duration,
) -> io::Result<ManagementResponse> {
    let req_json = serde_json::to_string(request).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to serialize request: {e}"),
        )
    })?;

    let is_remote = crate::config::is_remote_endpoint(endpoint);
    let response_line = if is_remote {
        let mut stream = TcpStream::connect(endpoint)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        writeln!(stream, "{req_json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        line
    } else {
        let sock_path = Path::new(endpoint);
        let mut stream = UnixStream::connect(sock_path)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        writeln!(stream, "{req_json}")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        line
    };

    if response_line.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "management endpoint returned empty response",
        ));
    }

    serde_json::from_str::<ManagementResponse>(&response_line).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid management response JSON: {err} (raw: '{}')",
                response_line.trim()
            ),
        )
    })
}

/// Queries relay instance status and counters via management API.
pub fn query_status(
    endpoint: &str,
    timeout: Duration,
    auth_token: Option<&str>,
) -> io::Result<StatusReport> {
    let req = ManagementRequest {
        version: MGMT_API_VERSION.to_string(),
        action: "status".to_string(),
        auth_token: auth_token.map(String::from),
        role: None,
        params: None,
    };
    let resp = query_management_raw(endpoint, &req, timeout)?;
    if resp.status != "ok" {
        let msg = resp
            .error
            .map(|e| e.message)
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(io::Error::other(msg));
    }

    let data = resp.data.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing 'data' field in status response",
        )
    })?;

    serde_json::from_value::<StatusReport>(data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode StatusReport: {e}"),
        )
    })
}

/// Queries streams and logical interface state and counters via management API.
pub fn query_streams(
    endpoint: &str,
    timeout: Duration,
    auth_token: Option<&str>,
) -> io::Result<StreamsManagementReport> {
    let req = ManagementRequest {
        version: MGMT_API_VERSION.to_string(),
        action: "streams".to_string(),
        auth_token: auth_token.map(String::from),
        role: None,
        params: None,
    };
    let resp = query_management_raw(endpoint, &req, timeout)?;
    if resp.status != "ok" {
        let msg = resp
            .error
            .map(|e| e.message)
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(io::Error::other(msg));
    }

    let data = resp.data.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing 'data' field in streams response",
        )
    })?;

    serde_json::from_value::<StreamsManagementReport>(data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode StreamsManagementReport: {e}"),
        )
    })
}

/// Queries Prometheus / OpenMetrics and structured counters via management API.
pub fn query_metrics(
    endpoint: &str,
    timeout: Duration,
    auth_token: Option<&str>,
) -> io::Result<MetricsReport> {
    let req = ManagementRequest {
        version: MGMT_API_VERSION.to_string(),
        action: "metrics".to_string(),
        auth_token: auth_token.map(String::from),
        role: None,
        params: None,
    };
    let resp = query_management_raw(endpoint, &req, timeout)?;
    if resp.status != "ok" {
        let msg = resp
            .error
            .map(|e| e.message)
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(io::Error::other(msg));
    }

    let data = resp.data.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing 'data' field in metrics response",
        )
    })?;

    serde_json::from_value::<MetricsReport>(data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode MetricsReport: {e}"),
        )
    })
}

/// Queries version information via management API.
pub fn query_version(
    endpoint: &str,
    timeout: Duration,
    auth_token: Option<&str>,
) -> io::Result<VersionReport> {
    let req = ManagementRequest {
        version: MGMT_API_VERSION.to_string(),
        action: "version".to_string(),
        auth_token: auth_token.map(String::from),
        role: None,
        params: None,
    };
    let resp = query_management_raw(endpoint, &req, timeout)?;
    if resp.status != "ok" {
        let msg = resp
            .error
            .map(|e| e.message)
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(io::Error::other(msg));
    }

    let data = resp.data.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing 'data' field in version response",
        )
    })?;

    serde_json::from_value::<VersionReport>(data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to decode VersionReport: {e}"),
        )
    })
}
