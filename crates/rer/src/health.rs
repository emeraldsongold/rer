use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

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
}

/// A background Unix-domain socket server providing health status and metrics.
pub struct HealthServer {
    socket_path: PathBuf,
    shutdown_flag: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<()>>,
}

impl HealthServer {
    /// Starts the health server listening on the specified Unix domain socket.
    ///
    /// Cleans up any stale socket file before binding.
    ///
    /// # Errors
    /// Returns an `io::Error` if binding the UnixListener fails.
    pub fn start(socket_path: &Path, health_handle: RelayHealthHandle) -> io::Result<Self> {
        // If socket file already exists, check if another process is active; if not, remove it.
        if socket_path.exists() {
            if UnixStream::connect(socket_path).is_err() {
                let _ = fs::remove_file(socket_path);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "health socket '{}' is already in use by another instance",
                        socket_path.display()
                    ),
                ));
            }
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                let _ = fs::create_dir_all(parent);
            }
        }

        let listener = UnixListener::bind(socket_path)?;
        listener.set_nonblocking(true)?;

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown_flag);
        let path_clone = socket_path.to_path_buf();

        let thread_handle = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let report = generate_health_report(&health_handle);
                        if let Ok(json) = serde_json::to_string(&report) {
                            let _ = writeln!(stream, "{json}");
                            let _ = stream.flush();
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
            // Clean up socket file on shutdown
            let _ = fs::remove_file(&path_clone);
        });

        Ok(Self {
            socket_path: socket_path.to_path_buf(),
            shutdown_flag,
            thread_handle: Some(thread_handle),
        })
    }

    /// Stops the health server, waits for the background thread, and unlinks the socket.
    pub fn stop(mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&self.socket_path);
    }
}

impl Drop for HealthServer {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&self.socket_path);
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
    let stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(timeout))?;

    let mut reader = BufReader::new(stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    serde_json::from_str::<HealthReport>(&response_line).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid health report JSON: {err}"),
        )
    })
}
