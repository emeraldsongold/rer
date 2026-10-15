//! Long-duration operation, memory tracking, and queue stability testing (SPEC §13, §17).
//!
//! Provides continuous execution monitoring memory RSS, queue depth, and drop counters
//! to verify bounded memory and queue stability during sustained workloads.

use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::relay::Relay;

/// Returns current resident set size (RSS) in bytes for the active process.
pub fn current_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let mut parts = statm.split_whitespace();
            let _size = parts.next();
            if let Some(resident_str) = parts.next() {
                if let Ok(pages) = resident_str.parse::<u64>() {
                    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
                    if page_size > 0 {
                        return pages * (page_size as u64);
                    }
                }
            }
        }
    }

    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0 {
        let usage = unsafe { usage.assume_init() };
        #[cfg(target_os = "macos")]
        {
            return usage.ru_maxrss as u64;
        }
        #[cfg(not(target_os = "macos"))]
        {
            return (usage.ru_maxrss as u64) * 1024;
        }
    }

    0
}

/// Periodic snapshot of memory and queue metrics during a stability run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabilitySample {
    /// Timestamp relative to test start in milliseconds
    pub timestamp_ms: u64,
    /// Resident set size in bytes
    pub rss_bytes: u64,
    /// Current queue depth (pending datagrams)
    pub queue_depth: u64,
    /// Cumulative packets forwarded so far
    pub packets_forwarded: u64,
    /// Cumulative packets dropped due to queue exhaustion
    pub drops_queue_full: u64,
}

/// Summary of memory behavior over the test duration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStabilityReport {
    /// Initial RSS before load in bytes
    pub initial_rss_bytes: u64,
    /// Maximum RSS observed in bytes
    pub peak_rss_bytes: u64,
    /// Final RSS after load in bytes
    pub final_rss_bytes: u64,
    /// Net RSS change (final - initial) in bytes
    pub net_growth_bytes: i64,
    /// True if memory remained bounded without runaway growth
    pub stable: bool,
}

/// Summary of queue behavior over the test duration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStabilityReport {
    /// Configured queue capacity limit
    pub queue_capacity: usize,
    /// Maximum observed queue depth during the run
    pub max_observed_depth: u64,
    /// Final queue depth upon completion
    pub final_queue_depth: u64,
    /// Total drops caused by queue capacity bounds
    pub drops_queue_full: u64,
    /// True if queue depth strictly respected the capacity limit
    pub strictly_bounded: bool,
    /// True if queue drained or remained bounded
    pub stable: bool,
}

/// Complete machine-readable stability report for long-duration execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LongDurationReport {
    /// Test duration in milliseconds
    pub duration_ms: u64,
    /// Total packets generated and sent
    pub total_packets_sent: u64,
    /// Total packets received by destination
    pub total_packets_received: u64,
    /// Overall throughput achieved (packets/sec)
    pub throughput_pps: f64,
    /// Memory stability metrics
    pub memory: MemoryStabilityReport,
    /// Queue stability metrics
    pub queue: QueueStabilityReport,
    /// Periodic metric samples
    pub samples: Vec<StabilitySample>,
    /// Overall pass condition (memory and queue stable)
    pub pass: bool,
}

impl LongDurationReport {
    /// Serializes report as formatted JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Configuration parameters for a long-duration stability run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LongDurationConfig {
    /// Duration to run the test
    pub duration: Duration,
    /// Target packet generation rate in packets per second (0 for unthrottled)
    pub packet_rate: f64,
    /// Payload size for generated packets
    pub packet_size: usize,
    /// Relay buffer queue capacity limit
    pub queue_capacity: usize,
    /// Interval between metric samples
    pub sample_interval: Duration,
    /// Deterministic seed
    pub seed: u64,
}

impl Default for LongDurationConfig {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(3),
            packet_rate: 1000.0,
            packet_size: 256,
            queue_capacity: 128,
            sample_interval: Duration::from_millis(200),
            seed: 1337,
        }
    }
}

/// Executes long-duration stability runs monitoring memory and queues.
pub struct LongDurationRunner;

impl LongDurationRunner {
    /// Executes a stability run under the specified configuration.
    pub fn run(config: LongDurationConfig) -> io::Result<LongDurationReport> {
        let dest_socket = UdpSocket::bind("127.0.0.1:0")?;
        let dest_port = dest_socket.local_addr()?.port();
        dest_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        let relay_socket = UdpSocket::bind("127.0.0.1:0")?;
        let relay_port = relay_socket.local_addr()?.port();
        drop(relay_socket);

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "stability-relay"
    streams:
      - id: "long-duration-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{relay_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_queue_size: {}
          drop_policy: "drop_oldest"
"#,
            config.queue_capacity
        );

        let relay_cfg = Config::from_yaml_str(&yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;
        let relay = Relay::start(&relay_cfg)
            .map_err(|e| io::Error::other(format!("failed to start relay: {}", e)))?;

        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_receiver = stop_signal.clone();
        let received_packets = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let rc_clone = received_packets.clone();

        // Destination receiver thread
        let receiver_handle = thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while !stop_receiver.load(Ordering::Relaxed) {
                if let Ok((_len, _)) = dest_socket.recv_from(&mut buf) {
                    rc_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        let start_time = Instant::now();
        let initial_rss = current_rss_bytes();
        let mut peak_rss = initial_rss;
        let mut samples = Vec::new();

        let sender_socket = UdpSocket::bind("127.0.0.1:0")?;
        let relay_dest = format!("127.0.0.1:{}", relay_port);

        let mut total_sent = 0u64;
        let mut next_sample = Instant::now() + config.sample_interval;
        let payload = vec![0xaa; config.packet_size];

        let delay_between_packets = if config.packet_rate > 0.0 {
            Some(Duration::from_secs_f64(1.0 / config.packet_rate))
        } else {
            None
        };

        while start_time.elapsed() < config.duration {
            let _ = sender_socket.send_to(&payload, &relay_dest);
            total_sent += 1;

            if let Some(delay) = delay_between_packets {
                if delay > Duration::from_micros(100) {
                    thread::sleep(delay);
                }
            }

            if Instant::now() >= next_sample {
                let current_rss = current_rss_bytes();
                if current_rss > peak_rss {
                    peak_rss = current_rss;
                }

                let (q_depth, fwd, drops) = relay
                    .stream_stats("long-duration-stream")
                    .map(|s| (s.queue_depth, s.forwarded_packets, s.drops_queue_full))
                    .unwrap_or((0, 0, 0));

                samples.push(StabilitySample {
                    timestamp_ms: start_time.elapsed().as_millis() as u64,
                    rss_bytes: current_rss,
                    queue_depth: q_depth,
                    packets_forwarded: fwd,
                    drops_queue_full: drops,
                });

                next_sample = Instant::now() + config.sample_interval;
            }
        }

        // Allow trailing datagrams to clear
        thread::sleep(Duration::from_millis(100));
        stop_signal.store(true, Ordering::Relaxed);
        let _ = receiver_handle.join();

        let final_rss = current_rss_bytes();
        if final_rss > peak_rss {
            peak_rss = final_rss;
        }

        let stats = relay.stream_stats("long-duration-stream");
        relay.stop();

        let total_rc = received_packets.load(Ordering::Relaxed);
        let duration_ms = start_time.elapsed().as_millis() as u64;
        let throughput_pps = if duration_ms > 0 {
            (total_rc as f64 * 1000.0) / duration_ms as f64
        } else {
            0.0
        };

        let max_observed_depth = samples.iter().map(|s| s.queue_depth).max().unwrap_or(0);
        let final_queue_depth = stats.map(|s| s.queue_depth).unwrap_or(0);
        let drops_queue_full = stats.map(|s| s.drops_queue_full).unwrap_or(0);

        let net_growth = (final_rss as i64) - (initial_rss as i64);

        // Memory stability: memory growth bounded within 64 MB allowance for buffers/allocators
        let memory_stable = net_growth < (64 * 1024 * 1024);

        // Queue stability: queue depth never exceeds configured queue capacity limit
        let strictly_bounded = max_observed_depth <= config.queue_capacity as u64;
        let queue_stable = strictly_bounded && final_queue_depth <= config.queue_capacity as u64;

        let pass = memory_stable && queue_stable && total_rc > 0;

        Ok(LongDurationReport {
            duration_ms,
            total_packets_sent: total_sent,
            total_packets_received: total_rc,
            throughput_pps,
            memory: MemoryStabilityReport {
                initial_rss_bytes: initial_rss,
                peak_rss_bytes: peak_rss,
                final_rss_bytes: final_rss,
                net_growth_bytes: net_growth,
                stable: memory_stable,
            },
            queue: QueueStabilityReport {
                queue_capacity: config.queue_capacity,
                max_observed_depth,
                final_queue_depth,
                drops_queue_full,
                strictly_bounded,
                stable: queue_stable,
            },
            samples,
            pass,
        })
    }
}
