use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::management::ManagementServer;
use crate::relay::RelayHealthHandle;

/// Status string values for health reporting.
pub const STATUS_HEALTHY: &str = "healthy";
pub const STATUS_UNHEALTHY: &str = "unhealthy";
pub const STATUS_SHUTTING_DOWN: &str = "shutting_down";

/// Health report returned by the RER health check endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthReport {
    /// Overall health status ("healthy", "unhealthy", or "shutting_down").
    pub status: String,
    /// Application binary version.
    pub version: String,
    /// Daemon uptime in seconds.
    pub uptime_seconds: u64,
    /// Health and statistics for each stream.
    pub streams: Vec<StreamHealthReport>,
}

/// Health and packet counters for an individual stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamHealthReport {
    /// Stream identifier.
    pub stream_id: String,
    /// Whether this stream is actively running and healthy.
    pub healthy: bool,
    /// Total received packets.
    pub received_packets: u64,
    /// Total forwarded packets.
    pub forwarded_packets: u64,
    /// Total dropped packets.
    pub dropped_packets: u64,
    /// Total destination and socket errors.
    pub errors: u64,
    /// Total received bytes.
    #[serde(default)]
    pub received_bytes: u64,
    /// Total forwarded bytes.
    #[serde(default)]
    pub forwarded_bytes: u64,
    /// Drops caused by queue full.
    #[serde(default)]
    pub drops_queue_full: u64,
    /// Drops caused by oversized packets.
    #[serde(default)]
    pub drops_oversized: u64,
    /// Destination errors.
    #[serde(default)]
    pub destination_errors: u64,
    /// Socket errors.
    #[serde(default)]
    pub socket_errors: u64,
    /// Backpressure events.
    #[serde(default)]
    pub backpressure_events: u64,
}

/// A background Unix-domain socket server providing health status and metrics.
pub struct HealthServer {
    server: ManagementServer,
}

impl HealthServer {
    /// Starts the health server listening on the specified Unix domain socket.
    ///
    /// # Errors
    /// Returns an `io::Error` if binding the UnixListener fails.
    pub fn start(socket_path: &Path, health_handle: RelayHealthHandle) -> io::Result<Self> {
        let server = ManagementServer::start_local(socket_path, health_handle, None)?;
        Ok(Self { server })
    }

    /// Stops the health server, waits for the background thread, and unlinks the socket.
    pub fn stop(self) {
        self.server.stop();
    }
}

/// Generates a `HealthReport` from the `RelayHealthHandle`.
#[must_use]
pub fn generate_health_report(handle: &RelayHealthHandle) -> HealthReport {
    let is_healthy = handle.is_healthy();
    let is_shutting_down = crate::signals::is_shutdown_requested();
    let status = if is_shutting_down {
        STATUS_SHUTTING_DOWN
    } else if is_healthy {
        STATUS_HEALTHY
    } else {
        STATUS_UNHEALTHY
    };

    let streams = handle
        .stream_health_snapshots()
        .into_iter()
        .map(|s| StreamHealthReport {
            stream_id: s.stream_id,
            healthy: s.is_healthy,
            received_packets: s.stats.received_packets,
            forwarded_packets: s.stats.forwarded_packets,
            dropped_packets: s.stats.dropped_packets,
            errors: s.stats.destination_errors + s.stats.socket_errors,
            received_bytes: s.stats.received_bytes,
            forwarded_bytes: s.stats.forwarded_bytes,
            drops_queue_full: s.stats.drops_queue_full,
            drops_oversized: s.stats.drops_oversized,
            destination_errors: s.stats.destination_errors,
            socket_errors: s.stats.socket_errors,
            backpressure_events: s.stats.backpressure_events,
        })
        .collect();

    HealthReport {
        status: status.to_string(),
        version: crate::version().to_string(),
        uptime_seconds: handle.uptime_seconds(),
        streams,
    }
}

/// Queries health status from a running RER relay via its Unix domain socket.
///
/// # Errors
/// Returns an `io::Error` if connection fails, times out, or returns invalid data.
pub fn query_health(socket_path: &Path, timeout: Duration) -> io::Result<HealthReport> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let req = serde_json::json!({
        "version": "v1",
        "action": "health"
    });
    let _ = writeln!(stream, "{req}");
    let _ = stream.flush();

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(&response_line) {
        if let Some(data) = envelope.get("data") {
            if let Ok(rep) = serde_json::from_value::<HealthReport>(data.clone()) {
                return Ok(rep);
            }
        }
    }

    serde_json::from_str::<HealthReport>(&response_line).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid health report JSON: {err}"),
        )
    })
}
