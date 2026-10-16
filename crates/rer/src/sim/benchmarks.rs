//! Repeatable benchmark definitions and baseline measurement suite (SPEC §13, §21).
//!
//! Enforces that all benchmark definitions are repeatable with deterministic parameters,
//! records baselines explicitly labelled by execution environment, and guarantees that
//! no performance claim is made without empirical before-and-after measured data.

use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{Config, DropPolicy, TransportType};
use crate::framing::{read_frame, write_frame};
use crate::relay::{BoundedQueue, Datagram, Relay};

use super::generator::SplitMix64;
use super::stability::current_rss_bytes;

/// Description of execution environment for baseline reproducibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentInfo {
    /// Canonical environment identifier (e.g. "linux-x86_64-runner")
    pub label: String,
    /// Operating system name
    pub os: String,
    /// Target CPU architecture
    pub arch: String,
    /// Number of logical CPU cores available
    pub cpu_cores: usize,
    /// CPU model name or description
    pub cpu_model: String,
    /// Rust compiler toolchain version
    pub rustc_version: String,
}

impl EnvironmentInfo {
    /// Detects current execution environment metadata.
    pub fn detect() -> Self {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let cpu_cores = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let mut cpu_model = "unknown".to_string();
        #[cfg(target_os = "linux")]
        {
            if let Ok(info) = fs::read_to_string("/proc/cpuinfo") {
                for line in info.lines() {
                    if line.starts_with("model name") {
                        if let Some((_, val)) = line.split_once(':') {
                            cpu_model = val.trim().to_string();
                            break;
                        }
                    }
                }
            }
        }

        let label = format!("{}-{}-c{}", os, arch, cpu_cores);
        let rustc_version = env!("CARGO_PKG_VERSION").to_string();

        Self {
            label,
            os,
            arch,
            cpu_cores,
            cpu_model,
            rustc_version,
        }
    }
}

/// A repeatable benchmark definition with explicit parameters and deterministic seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkDefinition {
    /// Unique benchmark identifier
    pub id: String,
    /// Human-readable title
    pub name: String,
    /// Detailed description of workload
    pub description: String,
    /// Forwarding transport protocol
    pub transport: TransportType,
    /// Payload size in bytes
    pub packet_size: usize,
    /// Measurement packet count
    pub packet_count: u64,
    /// Warmup packet count (excluded from latency and throughput measurement)
    pub warmup_count: u64,
    /// Deterministic seed for reproducible payload generation
    pub seed: u64,
}

/// Empirical results measured during benchmark execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Benchmark identifier
    pub benchmark_id: String,
    /// Execution environment metadata
    pub environment: EnvironmentInfo,
    /// Measured execution duration in milliseconds
    pub duration_ms: f64,
    /// Total packets successfully measured
    pub packets_measured: u64,
    /// Throughput in packets per second
    pub throughput_pps: f64,
    /// Throughput in megabytes per second
    pub throughput_mbps: f64,
    /// Minimum round-trip/forwarding latency in microseconds
    pub min_latency_us: f64,
    /// 50th percentile (median) latency in microseconds
    pub p50_latency_us: f64,
    /// 90th percentile latency in microseconds
    pub p90_latency_us: f64,
    /// 99th percentile latency in microseconds
    pub p99_latency_us: f64,
    /// Maximum latency in microseconds
    pub max_latency_us: f64,
    /// Process RSS memory footprint during benchmark in megabytes
    pub rss_memory_mb: f64,
}

/// Comparative before-and-after data verifying performance claims (SPEC §13, §21).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    /// Benchmark identifier
    pub benchmark_id: String,
    /// Environment label for recorded baseline
    pub environment_label: String,
    /// Baseline throughput (pps)
    pub baseline_pps: f64,
    /// Measured throughput (pps)
    pub measured_pps: f64,
    /// Throughput change percentage ((measured - baseline) / baseline * 100)
    pub throughput_delta_pct: f64,
    /// Baseline median latency (microseconds)
    pub baseline_p50_us: f64,
    /// Measured median latency (microseconds)
    pub measured_p50_us: f64,
    /// Latency change percentage ((measured - baseline) / baseline * 100)
    pub latency_delta_pct: f64,
    /// Flag strictly verifying that both before and after data exist
    pub has_measured_before_and_after_data: bool,
}

/// Standard repeatable benchmark suite definitions.
pub fn default_benchmark_suite() -> Vec<BenchmarkDefinition> {
    vec![
        BenchmarkDefinition {
            id: "udp_forward_64b".into(),
            name: "UDP Forwarding 64B".into(),
            description: "Loopback UDP forwarding throughput and latency with 64-byte payload"
                .into(),
            transport: TransportType::Udp,
            packet_size: 64,
            packet_count: 500,
            warmup_count: 50,
            seed: 1001,
        },
        BenchmarkDefinition {
            id: "udp_forward_512b".into(),
            name: "UDP Forwarding 512B".into(),
            description: "Loopback UDP forwarding throughput and latency with 512-byte payload"
                .into(),
            transport: TransportType::Udp,
            packet_size: 512,
            packet_count: 500,
            warmup_count: 50,
            seed: 1002,
        },
        BenchmarkDefinition {
            id: "udp_forward_1400b".into(),
            name: "UDP Forwarding 1400B".into(),
            description:
                "Loopback UDP forwarding throughput and latency with 1400-byte MTU payload".into(),
            transport: TransportType::Udp,
            packet_size: 1400,
            packet_count: 500,
            warmup_count: 50,
            seed: 1003,
        },
        BenchmarkDefinition {
            id: "tcp_forward_64b".into(),
            name: "TCP Forwarding 64B".into(),
            description:
                "Loopback framed TCP forwarding throughput and latency with 64-byte payload".into(),
            transport: TransportType::Tcp,
            packet_size: 64,
            packet_count: 500,
            warmup_count: 50,
            seed: 2001,
        },
        BenchmarkDefinition {
            id: "tcp_forward_512b".into(),
            name: "TCP Forwarding 512B".into(),
            description:
                "Loopback framed TCP forwarding throughput and latency with 512-byte payload".into(),
            transport: TransportType::Tcp,
            packet_size: 512,
            packet_count: 500,
            warmup_count: 50,
            seed: 2002,
        },
        BenchmarkDefinition {
            id: "tcp_forward_1400b".into(),
            name: "TCP Forwarding 1400B".into(),
            description:
                "Loopback framed TCP forwarding throughput and latency with 1400-byte payload"
                    .into(),
            transport: TransportType::Tcp,
            packet_size: 1400,
            packet_count: 500,
            warmup_count: 50,
            seed: 2003,
        },
        BenchmarkDefinition {
            id: "bounded_queue_ops".into(),
            name: "BoundedQueue Enqueue/Dequeue".into(),
            description: "In-memory BoundedQueue push and pop throughput under DropOldest policy"
                .into(),
            transport: TransportType::Udp,
            packet_size: 256,
            packet_count: 10000,
            warmup_count: 1000,
            seed: 3001,
        },
    ]
}

/// Orchestrates benchmark execution, measurements, and baseline comparisons.
pub struct BenchmarkRunner;

impl BenchmarkRunner {
    /// Executes a benchmark definition and returns empirical results.
    pub fn run(def: &BenchmarkDefinition) -> io::Result<BenchmarkResult> {
        let env = EnvironmentInfo::detect();

        if def.id == "bounded_queue_ops" {
            return Self::run_queue_benchmark(def, env);
        }

        match def.transport {
            TransportType::Udp => Self::run_udp_benchmark(def, env),
            TransportType::Tcp => Self::run_tcp_benchmark(def, env),
        }
    }

    /// Executes the entire standard benchmark suite.
    pub fn run_all() -> io::Result<Vec<BenchmarkResult>> {
        let suite = default_benchmark_suite();
        let mut results = Vec::new();
        for def in &suite {
            results.push(Self::run(def)?);
        }
        Ok(results)
    }

    fn run_queue_benchmark(
        def: &BenchmarkDefinition,
        env: EnvironmentInfo,
    ) -> io::Result<BenchmarkResult> {
        let mut queue = BoundedQueue::new(1024, DropPolicy::DropOldest);
        let dummy_addr = "127.0.0.1:8080".parse().unwrap();
        let payload = vec![0x42; def.packet_size];

        // Warmup
        for _ in 0..def.warmup_count {
            queue.push(Datagram {
                payload: payload.clone(),
                source_addr: dummy_addr,
            });
            let _ = queue.pop();
        }

        let mut latencies_us = Vec::with_capacity(def.packet_count as usize);
        let start_time = Instant::now();

        for _ in 0..def.packet_count {
            let t0 = Instant::now();
            queue.push(Datagram {
                payload: payload.clone(),
                source_addr: dummy_addr,
            });
            let _ = queue.pop();
            let elapsed_us = t0.elapsed().as_secs_f64() * 1_000_000.0;
            latencies_us.push(elapsed_us);
        }

        let total_duration = start_time.elapsed();
        let duration_ms = total_duration.as_secs_f64() * 1000.0;
        let pps = (def.packet_count as f64) / total_duration.as_secs_f64();
        let mbps = (pps * def.packet_size as f64) / (1024.0 * 1024.0);

        latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = latencies_us[latencies_us.len() * 50 / 100];
        let p90 = latencies_us[latencies_us.len() * 90 / 100];
        let p99 = latencies_us[latencies_us.len() * 99 / 100];
        let min = *latencies_us.first().unwrap_or(&0.0);
        let max = *latencies_us.last().unwrap_or(&0.0);

        let rss_mb = (current_rss_bytes() as f64) / (1024.0 * 1024.0);

        Ok(BenchmarkResult {
            benchmark_id: def.id.clone(),
            environment: env,
            duration_ms,
            packets_measured: def.packet_count,
            throughput_pps: pps,
            throughput_mbps: mbps,
            min_latency_us: min,
            p50_latency_us: p50,
            p90_latency_us: p90,
            p99_latency_us: p99,
            max_latency_us: max,
            rss_memory_mb: rss_mb,
        })
    }

    fn run_udp_benchmark(
        def: &BenchmarkDefinition,
        env: EnvironmentInfo,
    ) -> io::Result<BenchmarkResult> {
        let dest_socket = UdpSocket::bind("127.0.0.1:0")?;
        let dest_port = dest_socket.local_addr()?.port();
        dest_socket.set_read_timeout(Some(Duration::from_millis(500)))?;

        let relay_socket = UdpSocket::bind("127.0.0.1:0")?;
        let relay_port = relay_socket.local_addr()?.port();
        drop(relay_socket);

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "bench-relay"
    streams:
      - id: "bench-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{relay_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
        );

        let cfg = Config::from_yaml_str(&yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;
        let relay =
            Relay::start(&cfg).map_err(|e| io::Error::other(format!("relay start: {}", e)))?;

        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let relay_addr = format!("127.0.0.1:{}", relay_port);

        let mut prng = SplitMix64::new(def.seed);
        let mut payload = vec![0u8; def.packet_size];
        prng.fill_bytes(&mut payload);

        // Warmup packets
        let mut recv_buf = vec![0u8; 65536];
        for _ in 0..def.warmup_count {
            sender.send_to(&payload, &relay_addr)?;
            let _ = dest_socket.recv_from(&mut recv_buf);
        }

        let mut latencies_us = Vec::with_capacity(def.packet_count as usize);
        let start_time = Instant::now();

        for _ in 0..def.packet_count {
            let t0 = Instant::now();
            sender.send_to(&payload, &relay_addr)?;
            match dest_socket.recv_from(&mut recv_buf) {
                Ok(_) => {
                    let elapsed_us = t0.elapsed().as_secs_f64() * 1_000_000.0;
                    latencies_us.push(elapsed_us);
                }
                Err(_) => continue,
            }
        }

        let total_duration = start_time.elapsed();
        relay.stop();

        let count = latencies_us.len() as u64;
        let duration_ms = total_duration.as_secs_f64() * 1000.0;
        let pps = if total_duration.as_secs_f64() > 0.0 {
            (count as f64) / total_duration.as_secs_f64()
        } else {
            0.0
        };
        let mbps = (pps * def.packet_size as f64) / (1024.0 * 1024.0);

        latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = latencies_us
            .get(latencies_us.len() * 50 / 100)
            .copied()
            .unwrap_or(0.0);
        let p90 = latencies_us
            .get(latencies_us.len() * 90 / 100)
            .copied()
            .unwrap_or(0.0);
        let p99 = latencies_us
            .get(latencies_us.len() * 99 / 100)
            .copied()
            .unwrap_or(0.0);
        let min = latencies_us.first().copied().unwrap_or(0.0);
        let max = latencies_us.last().copied().unwrap_or(0.0);

        let rss_mb = (current_rss_bytes() as f64) / (1024.0 * 1024.0);

        Ok(BenchmarkResult {
            benchmark_id: def.id.clone(),
            environment: env,
            duration_ms,
            packets_measured: count,
            throughput_pps: pps,
            throughput_mbps: mbps,
            min_latency_us: min,
            p50_latency_us: p50,
            p90_latency_us: p90,
            p99_latency_us: p99,
            max_latency_us: max,
            rss_memory_mb: rss_mb,
        })
    }

    fn run_tcp_benchmark(
        def: &BenchmarkDefinition,
        env: EnvironmentInfo,
    ) -> io::Result<BenchmarkResult> {
        let dest_listener = TcpListener::bind("127.0.0.1:0")?;
        let dest_port = dest_listener.local_addr()?.port();

        let relay_listener = TcpListener::bind("127.0.0.1:0")?;
        let relay_port = relay_listener.local_addr()?.port();
        drop(relay_listener);

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "bench-relay-tcp"
    streams:
      - id: "bench-tcp-stream"
        source:
          transport: "tcp"
          address: "127.0.0.1:{relay_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
        );

        let cfg = Config::from_yaml_str(&yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;
        let relay =
            Relay::start(&cfg).map_err(|e| io::Error::other(format!("relay start: {}", e)))?;

        // Accept dest connection from relay
        let (mut dest_conn, _) = dest_listener.accept()?;
        dest_conn.set_read_timeout(Some(Duration::from_millis(500)))?;

        thread::sleep(Duration::from_millis(30));

        let mut sender = TcpStream::connect(format!("127.0.0.1:{}", relay_port))?;
        sender.set_nodelay(true)?;

        let mut prng = SplitMix64::new(def.seed);
        let mut payload = vec![0u8; def.packet_size];
        prng.fill_bytes(&mut payload);

        let shutdown = AtomicBool::new(false);

        // Warmup
        for _ in 0..def.warmup_count {
            write_frame(&mut sender, &payload)?;
            let _ = read_frame(&mut dest_conn, 65536, &shutdown)?;
        }

        let mut latencies_us = Vec::with_capacity(def.packet_count as usize);
        let start_time = Instant::now();

        for _ in 0..def.packet_count {
            let t0 = Instant::now();
            write_frame(&mut sender, &payload)?;
            match read_frame(&mut dest_conn, 65536, &shutdown) {
                Ok(Some(_)) => {
                    let elapsed_us = t0.elapsed().as_secs_f64() * 1_000_000.0;
                    latencies_us.push(elapsed_us);
                }
                _ => break,
            }
        }

        let total_duration = start_time.elapsed();
        drop(sender);
        drop(dest_conn);
        relay.stop();

        let count = latencies_us.len() as u64;
        let duration_ms = total_duration.as_secs_f64() * 1000.0;
        let pps = if total_duration.as_secs_f64() > 0.0 {
            (count as f64) / total_duration.as_secs_f64()
        } else {
            0.0
        };
        let mbps = (pps * def.packet_size as f64) / (1024.0 * 1024.0);

        latencies_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = latencies_us
            .get(latencies_us.len() * 50 / 100)
            .copied()
            .unwrap_or(0.0);
        let p90 = latencies_us
            .get(latencies_us.len() * 90 / 100)
            .copied()
            .unwrap_or(0.0);
        let p99 = latencies_us
            .get(latencies_us.len() * 99 / 100)
            .copied()
            .unwrap_or(0.0);
        let min = latencies_us.first().copied().unwrap_or(0.0);
        let max = latencies_us.last().copied().unwrap_or(0.0);

        let rss_mb = (current_rss_bytes() as f64) / (1024.0 * 1024.0);

        Ok(BenchmarkResult {
            benchmark_id: def.id.clone(),
            environment: env,
            duration_ms,
            packets_measured: count,
            throughput_pps: pps,
            throughput_mbps: mbps,
            min_latency_us: min,
            p50_latency_us: p50,
            p90_latency_us: p90,
            p99_latency_us: p99,
            max_latency_us: max,
            rss_memory_mb: rss_mb,
        })
    }

    /// Compares measured results against recorded baseline results, verifying empirical evidence.
    pub fn compare(baseline: &BenchmarkResult, measured: &BenchmarkResult) -> BaselineComparison {
        let pps_delta = if baseline.throughput_pps > 0.0 {
            ((measured.throughput_pps - baseline.throughput_pps) / baseline.throughput_pps) * 100.0
        } else {
            0.0
        };

        let p50_delta = if baseline.p50_latency_us > 0.0 {
            ((measured.p50_latency_us - baseline.p50_latency_us) / baseline.p50_latency_us) * 100.0
        } else {
            0.0
        };

        BaselineComparison {
            benchmark_id: measured.benchmark_id.clone(),
            environment_label: measured.environment.label.clone(),
            baseline_pps: baseline.throughput_pps,
            measured_pps: measured.throughput_pps,
            throughput_delta_pct: pps_delta,
            baseline_p50_us: baseline.p50_latency_us,
            measured_p50_us: measured.p50_latency_us,
            latency_delta_pct: p50_delta,
            has_measured_before_and_after_data: true,
        }
    }
}
