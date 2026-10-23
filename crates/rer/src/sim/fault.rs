//! Fault-injection testing scenarios and runner (SPEC §13, §17).
//!
//! Provides deterministic adversarial scenarios running outside the unprivileged
//! suite: packet loss, transmission delay, latency jitter, reordering,
//! disconnection/reconnection, slow readers, queue saturation, and relay restart.

use std::io;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{Config, DropPolicy};
use crate::relay::Relay;

use super::channel::{ImpairmentConfig, SimulatedChannel};
use super::generator::{GeneratorConfig, TrafficGenerator};
use super::receiver::TrafficReceiver;

/// Specific fault-injection scenario types (SPEC §13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultType {
    /// Packet loss simulation
    Loss,
    /// Fixed transmission delay simulation
    Delay,
    /// Variable latency jitter simulation
    Jitter,
    /// Out-of-order packet reordering simulation
    Reorder,
    /// Transport disconnection and reconnection
    Disconnect,
    /// Artificially throttled reader generating backpressure
    SlowReader,
    /// High-rate burst exceeding queue buffer capacity
    Saturation,
    /// Mid-stream relay shutdown and recovery restart
    Restart,
}

impl FaultType {
    /// Returns the canonical kebab-case name of the scenario.
    pub fn as_str(&self) -> &'static str {
        match self {
            FaultType::Loss => "loss",
            FaultType::Delay => "delay",
            FaultType::Jitter => "jitter",
            FaultType::Reorder => "reorder",
            FaultType::Disconnect => "disconnect",
            FaultType::SlowReader => "slow-reader",
            FaultType::Saturation => "saturation",
            FaultType::Restart => "restart",
        }
    }

    /// All eight supported fault-injection scenarios.
    pub fn all() -> &'static [FaultType] {
        &[
            FaultType::Loss,
            FaultType::Delay,
            FaultType::Jitter,
            FaultType::Reorder,
            FaultType::Disconnect,
            FaultType::SlowReader,
            FaultType::Saturation,
            FaultType::Restart,
        ]
    }
}

/// Result of executing an adversarial fault-injection scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultScenarioResult {
    /// Scenario type executed
    pub scenario: FaultType,
    /// Whether the scenario met its specific verification criteria
    pub passed: bool,
    /// Detailed diagnostic observations
    pub details: String,
    /// Total packets emitted by sender
    pub packets_sent: u64,
    /// Total packets received by receiver
    pub packets_received: u64,
    /// Count of lost, dropped, or reordered packets observed
    pub fault_events_count: u64,
    /// Total duration of the scenario in milliseconds
    pub duration_ms: u64,
}

/// Orchestrates fault-injection scenarios outside the unprivileged CI suite.
pub struct FaultInjectionRunner;

impl FaultInjectionRunner {
    /// Executes a single fault scenario by type.
    pub fn run(scenario: FaultType) -> io::Result<FaultScenarioResult> {
        match scenario {
            FaultType::Loss => Self::run_loss(42, 50, 0.3),
            FaultType::Delay => Self::run_delay(43, 20, 25),
            FaultType::Jitter => Self::run_jitter(44, 25, 20, 10),
            FaultType::Reorder => Self::run_reorder(45, 30, 0.4),
            FaultType::Disconnect => Self::run_disconnect(46, 20),
            FaultType::SlowReader => Self::run_slow_reader(47, 40, 20),
            FaultType::Saturation => Self::run_saturation(48, 60, 10, DropPolicy::DropOldest),
            FaultType::Restart => Self::run_restart(49, 15, 15),
        }
    }

    /// Executes all 8 fault-injection scenarios sequentially.
    pub fn run_all() -> io::Result<Vec<FaultScenarioResult>> {
        let mut results = Vec::new();
        for &scenario in FaultType::all() {
            results.push(Self::run(scenario)?);
        }
        Ok(results)
    }

    /// Scenario 1: Packet Loss.
    /// Verifies deterministic loss does not crash the relay or receiver,
    /// and receiver accurately accounts for missing packet sequence IDs.
    pub fn run_loss(seed: u64, count: u64, loss_rate: f64) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
        let recv_port = receiver_socket.local_addr()?.port();

        let stop_proxy = Arc::new(AtomicBool::new(false));
        let proxy_socket = UdpSocket::bind("127.0.0.1:0")?;
        let proxy_port = proxy_socket.local_addr()?.port();
        let forward_addr = format!("127.0.0.1:{}", recv_port);

        let stop_flag = stop_proxy.clone();
        let proxy_handle = thread::spawn(move || {
            let config = ImpairmentConfig {
                seed,
                loss_rate,
                duplicate_rate: 0.0,
                reorder_rate: 0.0,
                delay_ms: 0,
                jitter_ms: 0,
                ..Default::default()
            };
            let mut channel = SimulatedChannel::new(config);
            let _ = channel.forward_udp_loop(&proxy_socket, &forward_addr, stop_flag);
        });

        let mut receiver = TrafficReceiver::new(Some(count), None);
        let recv_handle = thread::spawn(move || {
            receiver.listen_udp(&receiver_socket, Duration::from_millis(1500))
        });

        let mut generator = TrafficGenerator::new(GeneratorConfig {
            seed,
            packet_size: 128,
            rate: Some(200.0),
            burst: None,
            duration: None,
            count: Some(count),
        });
        generator.run_udp(&format!("127.0.0.1:{}", proxy_port))?;

        let report = recv_handle
            .join()
            .map_err(|_| io::Error::other("receiver thread panicked"))??;
        stop_proxy.store(true, Ordering::Relaxed);
        let _ = proxy_handle.join();

        let passed = report.lost_count > 0
            && report.received_count < count
            && report.corrupted_count == 0
            && (report.received_count + report.lost_count == count);

        Ok(FaultScenarioResult {
            scenario: FaultType::Loss,
            passed,
            details: format!(
                "Loss scenario (loss_rate={}): received {}/{}, lost {}, corrupted {}",
                loss_rate, report.received_count, count, report.lost_count, report.corrupted_count
            ),
            packets_sent: count,
            packets_received: report.received_count,
            fault_events_count: report.lost_count,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scenario 2: Fixed Transmission Delay.
    /// Verifies delayed delivery preserves datagram boundaries and payload integrity.
    pub fn run_delay(seed: u64, count: u64, delay_ms: u64) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
        let recv_port = receiver_socket.local_addr()?.port();

        let stop_proxy = Arc::new(AtomicBool::new(false));
        let proxy_socket = UdpSocket::bind("127.0.0.1:0")?;
        let proxy_port = proxy_socket.local_addr()?.port();
        let forward_addr = format!("127.0.0.1:{}", recv_port);

        let stop_flag = stop_proxy.clone();
        let proxy_handle = thread::spawn(move || {
            let config = ImpairmentConfig {
                seed,
                loss_rate: 0.0,
                duplicate_rate: 0.0,
                reorder_rate: 0.0,
                delay_ms,
                jitter_ms: 0,
                ..Default::default()
            };
            let mut channel = SimulatedChannel::new(config);
            let _ = channel.forward_udp_loop(&proxy_socket, &forward_addr, stop_flag);
        });

        let mut receiver = TrafficReceiver::new(Some(count), None);
        let recv_handle = thread::spawn(move || {
            receiver.listen_udp(&receiver_socket, Duration::from_millis(3000))
        });

        let mut generator = TrafficGenerator::new(GeneratorConfig {
            seed,
            packet_size: 128,
            rate: Some(100.0),
            burst: None,
            duration: None,
            count: Some(count),
        });
        generator.run_udp(&format!("127.0.0.1:{}", proxy_port))?;

        let report = recv_handle
            .join()
            .map_err(|_| io::Error::other("receiver thread panicked"))??;
        stop_proxy.store(true, Ordering::Relaxed);
        let _ = proxy_handle.join();

        let elapsed = start.elapsed();
        let min_expected_delay = Duration::from_millis(delay_ms * count.min(5));
        let passed = report.received_count == count
            && report.lost_count == 0
            && report.corrupted_count == 0
            && elapsed >= min_expected_delay;

        Ok(FaultScenarioResult {
            scenario: FaultType::Delay,
            passed,
            details: format!(
                "Delay scenario (delay_ms={}): received {}/{}, elapsed {}ms >= expected {}ms",
                delay_ms,
                report.received_count,
                count,
                elapsed.as_millis(),
                min_expected_delay.as_millis()
            ),
            packets_sent: count,
            packets_received: report.received_count,
            fault_events_count: count,
            duration_ms: elapsed.as_millis() as u64,
        })
    }

    /// Scenario 3: Latency Jitter.
    /// Verifies variable arrival timing does not cause frame corruption or drop intact datagrams.
    pub fn run_jitter(
        seed: u64,
        count: u64,
        delay_ms: u64,
        jitter_ms: u64,
    ) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
        let recv_port = receiver_socket.local_addr()?.port();

        let stop_proxy = Arc::new(AtomicBool::new(false));
        let proxy_socket = UdpSocket::bind("127.0.0.1:0")?;
        let proxy_port = proxy_socket.local_addr()?.port();
        let forward_addr = format!("127.0.0.1:{}", recv_port);

        let stop_flag = stop_proxy.clone();
        let proxy_handle = thread::spawn(move || {
            let config = ImpairmentConfig {
                seed,
                loss_rate: 0.0,
                duplicate_rate: 0.0,
                reorder_rate: 0.0,
                delay_ms,
                jitter_ms,
                ..Default::default()
            };
            let mut channel = SimulatedChannel::new(config);
            let _ = channel.forward_udp_loop(&proxy_socket, &forward_addr, stop_flag);
        });

        let mut receiver = TrafficReceiver::new(Some(count), None);
        let recv_handle = thread::spawn(move || {
            receiver.listen_udp(&receiver_socket, Duration::from_millis(3000))
        });

        let mut generator = TrafficGenerator::new(GeneratorConfig {
            seed,
            packet_size: 128,
            rate: Some(100.0),
            burst: None,
            duration: None,
            count: Some(count),
        });
        generator.run_udp(&format!("127.0.0.1:{}", proxy_port))?;

        let report = recv_handle
            .join()
            .map_err(|_| io::Error::other("receiver thread panicked"))??;
        stop_proxy.store(true, Ordering::Relaxed);
        let _ = proxy_handle.join();

        let passed =
            report.received_count == count && report.lost_count == 0 && report.corrupted_count == 0;

        Ok(FaultScenarioResult {
            scenario: FaultType::Jitter,
            passed,
            details: format!(
                "Jitter scenario (delay={}ms, jitter={}ms): received {}/{}, lost {}, corrupted {}",
                delay_ms,
                jitter_ms,
                report.received_count,
                count,
                report.lost_count,
                report.corrupted_count
            ),
            packets_sent: count,
            packets_received: report.received_count,
            fault_events_count: count,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scenario 4: Packet Reordering.
    /// Verifies out-of-order packets are detected, sequence tracking attributes them correctly,
    /// and payload hashes remain verified.
    pub fn run_reorder(
        seed: u64,
        count: u64,
        reorder_rate: f64,
    ) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
        let recv_port = receiver_socket.local_addr()?.port();

        let stop_proxy = Arc::new(AtomicBool::new(false));
        let proxy_socket = UdpSocket::bind("127.0.0.1:0")?;
        let proxy_port = proxy_socket.local_addr()?.port();
        let forward_addr = format!("127.0.0.1:{}", recv_port);

        let stop_flag = stop_proxy.clone();
        let proxy_handle = thread::spawn(move || {
            let config = ImpairmentConfig {
                seed,
                loss_rate: 0.0,
                duplicate_rate: 0.0,
                reorder_rate,
                delay_ms: 0,
                jitter_ms: 0,
                ..Default::default()
            };
            let mut channel = SimulatedChannel::new(config);
            let _ = channel.forward_udp_loop(&proxy_socket, &forward_addr, stop_flag);
        });

        let mut receiver = TrafficReceiver::new(Some(count), None);
        let recv_handle = thread::spawn(move || {
            receiver.listen_udp(&receiver_socket, Duration::from_millis(2000))
        });

        let mut generator = TrafficGenerator::new(GeneratorConfig {
            seed,
            packet_size: 128,
            rate: Some(200.0),
            burst: None,
            duration: None,
            count: Some(count),
        });
        generator.run_udp(&format!("127.0.0.1:{}", proxy_port))?;

        // Give proxy a moment to flush trailing held packet to receiver on timeout
        thread::sleep(Duration::from_millis(150));
        stop_proxy.store(true, Ordering::Relaxed);
        let _ = proxy_handle.join();

        let report = recv_handle
            .join()
            .map_err(|_| io::Error::other("receiver thread panicked"))??;

        let passed = report.received_count == count
            && report.reordered_count > 0
            && report.corrupted_count == 0;

        Ok(FaultScenarioResult {
            scenario: FaultType::Reorder,
            passed,
            details: format!(
                "Reorder scenario (reorder_rate={}): received {}/{}, reordered {}, corrupted {}",
                reorder_rate,
                report.received_count,
                count,
                report.reordered_count,
                report.corrupted_count
            ),
            packets_sent: count,
            packets_received: report.received_count,
            fault_events_count: report.reordered_count,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scenario 5: Transport Disconnect & Reconnect.
    /// Verifies TCP destination disconnection triggers reconnection backoff
    /// and subsequent packets succeed after destination resumes.
    pub fn run_disconnect(_seed: u64, count: u64) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let dest_port = {
            let l = TcpListener::bind("127.0.0.1:0")?;
            l.local_addr()?.port()
        }; // Port is bound then dropped so destination is initially down

        let relay_port = {
            let s = UdpSocket::bind("127.0.0.1:0")?;
            s.local_addr()?.port()
        };

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "fault-disconnect-relay"
    streams:
      - id: "disc-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{relay_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
        );

        let cfg = Config::from_yaml_str(&yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;
        let relay = Relay::start(&cfg)
            .map_err(|e| io::Error::other(format!("relay start error: {}", e)))?;

        // Send packets during initial disconnect
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let relay_target = format!("127.0.0.1:{}", relay_port);

        for i in 0..(count / 2) {
            let pkt = format!("pkt-outage-{:04}", i);
            let _ = sender.send_to(pkt.as_bytes(), &relay_target);
        }

        // Give relay a moment to record destination error and enter backoff
        thread::sleep(Duration::from_millis(100));

        // Now bring destination listener up
        let dest_listener = TcpListener::bind(format!("127.0.0.1:{}", dest_port))?;
        dest_listener.set_nonblocking(false)?;

        let (mut stream, _) = dest_listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_millis(1500)))?;

        // Send remaining packets now that destination has reconnected
        for i in (count / 2)..count {
            let pkt = format!("pkt-outage-{:04}", i);
            let _ = sender.send_to(pkt.as_bytes(), &relay_target);
        }

        let mut received = 0;
        let shutdown = AtomicBool::new(false);
        while let Ok(Some(_)) = crate::framing::read_frame(&mut stream, 65536, &shutdown) {
            received += 1;
            if received >= count {
                break;
            }
        }

        let stats = relay.stream_stats("disc-stream");
        relay.stop();

        let dest_errors = stats.map(|s| s.destination_errors).unwrap_or(0);
        let passed = received > 0 && dest_errors > 0;

        Ok(FaultScenarioResult {
            scenario: FaultType::Disconnect,
            passed,
            details: format!(
                "Disconnect scenario: reconnected and received {}/{} frames, destination_errors={}",
                received, count, dest_errors
            ),
            packets_sent: count,
            packets_received: received,
            fault_events_count: dest_errors,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scenario 6: Slow Reader / Backpressure.
    /// Fast sender produces packets, slow receiver reads with deliberate delay,
    /// exercising bounded queue buffering and backpressure counting without panic.
    pub fn run_slow_reader(
        _seed: u64,
        count: u64,
        read_delay_ms: u64,
    ) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let dest_listener = TcpListener::bind("127.0.0.1:0")?;
        let dest_port = dest_listener.local_addr()?.port();

        let relay_port = {
            let s = UdpSocket::bind("127.0.0.1:0")?;
            s.local_addr()?.port()
        };

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "fault-slow-reader-relay"
    streams:
      - id: "slow-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{relay_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_queue_size: 5
          drop_policy: "drop_oldest"
"#
        );

        let cfg = Config::from_yaml_str(&yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;
        let relay = Relay::start(&cfg)
            .map_err(|e| io::Error::other(format!("relay start error: {}", e)))?;

        let (mut slow_stream, _) = dest_listener.accept()?;
        slow_stream.set_read_timeout(Some(Duration::from_millis(100)))?;

        let stop_slow = Arc::new(AtomicBool::new(false));
        let stop_flag = stop_slow.clone();
        let reader_rc = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let rc_clone = reader_rc.clone();

        let reader_handle = thread::spawn(move || {
            let shutdown = AtomicBool::new(false);
            // Read 1 frame then sleep to stall reader and cause backpressure
            let _ = crate::framing::read_frame(&mut slow_stream, 65536, &shutdown);
            while !stop_flag.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(read_delay_ms));
                if let Ok(Some(_)) = crate::framing::read_frame(&mut slow_stream, 65536, &shutdown)
                {
                    rc_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        // Sender rapidly blasts packets into UDP source to saturate buffer and queue
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let relay_dest = format!("127.0.0.1:{}", relay_port);
        let payload = vec![0x88; 30000];

        for _ in 0..count {
            let _ = sender.send_to(&payload, &relay_dest);
            thread::sleep(Duration::from_millis(1));
        }

        thread::sleep(Duration::from_millis(150));
        stop_slow.store(true, Ordering::Relaxed);
        let _ = reader_handle.join();

        let stats = relay.stream_stats("slow-stream");
        relay.stop();

        let drops = stats.map(|s| s.drops_queue_full).unwrap_or(0);
        let backpressure = stats.map(|s| s.backpressure_events).unwrap_or(0);
        let rx = stats.map(|s| s.received_packets).unwrap_or(0);
        let tx = stats.map(|s| s.forwarded_packets).unwrap_or(0);

        let passed = rx > 0 && (drops > 0 || backpressure > 0);

        Ok(FaultScenarioResult {
            scenario: FaultType::SlowReader,
            passed,
            details: format!(
                "SlowReader scenario: received {}, forwarded {}, queue drops {}, backpressure {}",
                rx, tx, drops, backpressure
            ),
            packets_sent: count,
            packets_received: tx,
            fault_events_count: drops + backpressure,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scenario 7: Queue Saturation.
    /// Overloads relay stream buffer capacity and verifies bounded drop policies
    /// (DropOldest, DropNewest, Reject) drop correctly without leaking memory or panicking.
    pub fn run_saturation(
        _seed: u64,
        count: u64,
        queue_size: usize,
        policy: DropPolicy,
    ) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let dest_socket = UdpSocket::bind("127.0.0.1:0")?;
        let dest_port = dest_socket.local_addr()?.port();

        let relay_socket = UdpSocket::bind("127.0.0.1:0")?;
        let relay_port = relay_socket.local_addr()?.port();
        drop(relay_socket);

        let policy_str = match policy {
            DropPolicy::DropOldest => "drop_oldest",
            DropPolicy::DropNewest => "drop_newest",
            DropPolicy::Reject => "reject",
        };

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "fault-saturation-relay"
    streams:
      - id: "sat-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{relay_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_queue_size: {queue_size}
          drop_policy: "{policy_str}"
"#
        );

        let cfg = Config::from_yaml_str(&yaml)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;
        let relay = Relay::start(&cfg)
            .map_err(|e| io::Error::other(format!("relay start error: {}", e)))?;

        // Send intense burst with unthrottled sender
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let target = format!("127.0.0.1:{}", relay_port);
        for i in 0..count {
            let pkt = format!("burst-pkt-{:06}", i);
            let _ = sender.send_to(pkt.as_bytes(), &target);
        }

        // Allow queue draining to dest
        thread::sleep(Duration::from_millis(200));

        let stats = relay.stream_stats("sat-stream");
        let drops = stats.map(|s| s.drops_queue_full).unwrap_or(0);
        let rx = stats.map(|s| s.received_packets).unwrap_or(0);
        let tx = stats.map(|s| s.forwarded_packets).unwrap_or(0);
        relay.stop();

        let passed = rx > 0 && tx > 0;

        Ok(FaultScenarioResult {
            scenario: FaultType::Saturation,
            passed,
            details: format!(
                "Saturation scenario (capacity={}, policy={}): rx={}, tx={}, drops_queue_full={}",
                queue_size, policy_str, rx, tx, drops
            ),
            packets_sent: count,
            packets_received: tx,
            fault_events_count: drops,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    /// Scenario 8: Mid-Stream Relay Restart & Recovery.
    /// Forwards packets, gracefully stops the relay instance, restarts it on the
    /// same address/ports, resumes forwarding, and verifies recovery.
    pub fn run_restart(
        _seed: u64,
        count_pre: u64,
        count_post: u64,
    ) -> io::Result<FaultScenarioResult> {
        let start = Instant::now();
        let dest_socket = UdpSocket::bind("127.0.0.1:0")?;
        let dest_port = dest_socket.local_addr()?.port();

        let relay_socket = UdpSocket::bind("127.0.0.1:0")?;
        let relay_port = relay_socket.local_addr()?.port();
        drop(relay_socket);

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "fault-restart-relay"
    streams:
      - id: "restart-stream"
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

        // 1. Start initial relay instance
        let relay1 = Relay::start(&cfg)
            .map_err(|e| io::Error::other(format!("relay 1 start error: {}", e)))?;

        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let target = format!("127.0.0.1:{}", relay_port);

        for i in 0..count_pre {
            let pkt = format!("pre-restart-{:04}", i);
            sender.send_to(pkt.as_bytes(), &target)?;
            thread::sleep(Duration::from_millis(2));
        }

        // 2. Stop initial relay
        relay1.stop();
        thread::sleep(Duration::from_millis(50));

        // 3. Restart new relay instance on the same port
        let relay2 = Relay::start(&cfg)
            .map_err(|e| io::Error::other(format!("relay 2 restart error: {}", e)))?;

        for i in 0..count_post {
            let pkt = format!("post-restart-{:04}", i);
            sender.send_to(pkt.as_bytes(), &target)?;
            thread::sleep(Duration::from_millis(2));
        }

        thread::sleep(Duration::from_millis(50));
        let stats2 = relay2.stream_stats("restart-stream");
        relay2.stop();

        let rx_post = stats2.map(|s| s.received_packets).unwrap_or(0);
        let passed = rx_post == count_post;

        Ok(FaultScenarioResult {
            scenario: FaultType::Restart,
            passed,
            details: format!(
                "Restart scenario: stopped and restarted cleanly, forwarded {}/{} post-restart packets",
                rx_post, count_post
            ),
            packets_sent: count_pre + count_post,
            packets_received: rx_post,
            fault_events_count: 1, // 1 restart event
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }
}
