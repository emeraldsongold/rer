use std::io;
use std::net::{TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{Config, DropPolicy, TransportType};
use crate::relay::Relay;

use super::channel::{ImpairmentConfig, SimulatedChannel};
use super::generator::{GeneratorConfig, TrafficGenerator};
use super::receiver::{ReceiverReport, TrafficReceiver};

/// Configuration for an automated simulation test harness run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    /// Test run identifier
    #[serde(default)]
    pub test_id: Option<String>,
    /// Traffic generator configuration
    pub generator: GeneratorConfig,
    /// Optional network impairments configuration
    #[serde(default)]
    pub impairments: Option<ImpairmentConfig>,
    /// Whether to route traffic through an active RER Relay instance
    #[serde(default = "default_true")]
    pub use_relay: bool,
    /// Relay queue capacity (if using relay)
    #[serde(default)]
    pub relay_queue_capacity: Option<usize>,
    /// Relay overload drop policy (if using relay)
    #[serde(default)]
    pub relay_drop_policy: Option<DropPolicy>,
    /// Forwarding source transport protocol (default: UDP)
    #[serde(default = "default_transport_udp")]
    pub source_transport: TransportType,
    /// Forwarding destination transport protocol (default: UDP)
    #[serde(default = "default_transport_udp")]
    pub destination_transport: TransportType,
    /// Optional sequence extraction configuration for the relay stream (SPEC §8)
    #[serde(default)]
    pub sequence: Option<crate::config::SequenceConfig>,
    /// Optional packet inspection configuration for the relay stream (SPEC §8)
    #[serde(default)]
    pub inspection: Option<crate::config::InspectionConfig>,
    /// Optional sequence rollover threshold
    #[serde(default)]
    pub rollover_threshold: Option<u64>,
}

fn default_transport_udp() -> TransportType {
    TransportType::Udp
}

fn default_true() -> bool {
    true
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            test_id: None,
            generator: GeneratorConfig::default(),
            impairments: None,
            use_relay: true,
            relay_queue_capacity: None,
            relay_drop_policy: None,
            source_transport: TransportType::Udp,
            destination_transport: TransportType::Udp,
            sequence: None,
            inspection: None,
            rollover_threshold: None,
        }
    }
}

/// Unprivileged simulation harness that orchestrates generator, relay,
/// impairments, and receiver in ordinary CI across all four transport combinations.
pub struct SimulationHarness;

impl SimulationHarness {
    /// Executes the simulation harness end-to-end unprivileged on localhost,
    /// returning the receiver's JSON-serializable report.
    pub fn run(config: HarnessConfig) -> io::Result<ReceiverReport> {
        let expected_count = config.generator.count;
        let expected_stream_hash = expected_count
            .map(|cnt| TrafficGenerator::new(config.generator.clone()).expected_stream_hash(cnt));

        let mut receiver = TrafficReceiver::new(expected_count, expected_stream_hash);
        if let Some(ref tid) = config.test_id {
            receiver.set_test_id(tid.clone());
        }
        if let Some(ref seq_cfg) = config.sequence {
            receiver.set_sequence_config(seq_cfg.clone());
        }
        if let Some(thresh) = config.rollover_threshold {
            receiver.set_rollover_threshold(thresh);
        }

        let receiver_port: u16;
        let receiver_udp_socket: Option<UdpSocket>;
        let receiver_tcp_listener: Option<TcpListener>;

        match config.destination_transport {
            TransportType::Udp => {
                let socket = UdpSocket::bind("127.0.0.1:0")?;
                receiver_port = socket.local_addr()?.port();
                receiver_udp_socket = Some(socket);
                receiver_tcp_listener = None;
            }
            TransportType::Tcp => {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                receiver_port = listener.local_addr()?.port();
                receiver_tcp_listener = Some(listener);
                receiver_udp_socket = None;
            }
        }

        let stop_proxy = Arc::new(AtomicBool::new(false));
        let proxy_handle;
        let final_receiver_dest;

        // Setup optional impairment proxy (for UDP)
        if let Some(impairments) = config.impairments.clone() {
            let proxy_socket = UdpSocket::bind("127.0.0.1:0")?;
            let proxy_port = proxy_socket.local_addr()?.port();
            let forward_target = format!("127.0.0.1:{}", receiver_port);
            let stop_flag = stop_proxy.clone();

            proxy_handle = Some(thread::spawn(move || {
                let mut channel = SimulatedChannel::new(impairments);
                let _ = channel.forward_udp_loop(&proxy_socket, &forward_target, stop_flag);
            }));

            final_receiver_dest = format!("127.0.0.1:{}", proxy_port);
        } else {
            proxy_handle = None;
            final_receiver_dest = format!("127.0.0.1:{}", receiver_port);
        }

        let generator_target: String;
        let relay_instance: Option<Relay>;

        if config.use_relay {
            let relay_listen_port = match config.source_transport {
                TransportType::Udp => {
                    let s = UdpSocket::bind("127.0.0.1:0")?;
                    let port = s.local_addr()?.port();
                    drop(s);
                    port
                }
                TransportType::Tcp => {
                    let l = TcpListener::bind("127.0.0.1:0")?;
                    let port = l.local_addr()?.port();
                    drop(l);
                    port
                }
            };

            let src_transport_name = match config.source_transport {
                TransportType::Udp => "udp",
                TransportType::Tcp => "tcp",
            };

            let dest_transport_name = match config.destination_transport {
                TransportType::Udp => "udp",
                TransportType::Tcp => "tcp",
            };

            let max_queue_str = config
                .relay_queue_capacity
                .map(|c| format!("          max_queue_size: {}", c))
                .unwrap_or_default();

            let drop_policy_str = config
                .relay_drop_policy
                .map(|p| match p {
                    DropPolicy::DropOldest => "          drop_policy: \"drop_oldest\"",
                    DropPolicy::DropNewest => "          drop_policy: \"drop_newest\"",
                    DropPolicy::Reject => "          drop_policy: \"reject\"",
                })
                .unwrap_or_default();

            let buffer_yaml = if !max_queue_str.is_empty() || !drop_policy_str.is_empty() {
                let mut s = String::from("        buffer:\n");
                if !max_queue_str.is_empty() {
                    s.push_str(&max_queue_str);
                    s.push('\n');
                }
                if !drop_policy_str.is_empty() {
                    s.push_str(drop_policy_str);
                    s.push('\n');
                }
                s
            } else {
                String::new()
            };

            let sequence_yaml = if let Some(ref seq) = config.sequence {
                let off = seq.offset;
                let w = seq.width;
                let bo = seq.byte_order.to_string();
                let thresh_str = seq
                    .rollover_threshold
                    .map(|t| format!("          rollover_threshold: {}\n", t))
                    .unwrap_or_default();
                format!(
                    "        sequence:\n          enabled: {}\n          offset: {}\n          width: {}\n          byte_order: \"{}\"\n{}",
                    seq.enabled, off, w, bo, thresh_str
                )
            } else {
                String::new()
            };

            let inspection_yaml = if let Some(ref insp) = config.inspection {
                format!(
                    "        inspection:\n          hex_preview: {}\n          ascii_preview: {}\n          max_preview_bytes: {}\n",
                    insp.hex_preview, insp.ascii_preview, insp.max_preview_bytes
                )
            } else {
                String::new()
            };

            let yaml = format!(
                r#"
version: "1"
instances:
  - id: "harness-relay"
    streams:
      - id: "sim-stream"
        source:
          transport: "{src_transport_name}"
          address: "127.0.0.1:{relay_listen_port}"
        destination:
          transport: "{dest_transport_name}"
          address: "{final_receiver_dest}"
{buffer_yaml}{sequence_yaml}{inspection_yaml}
"#
            );

            let relay_cfg = Config::from_yaml_str(&yaml)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;

            relay_instance = Some(
                Relay::start(&relay_cfg)
                    .map_err(|e| io::Error::other(format!("failed to start relay: {}", e)))?,
            );

            generator_target = format!("127.0.0.1:{}", relay_listen_port);
        } else {
            relay_instance = None;
            generator_target = final_receiver_dest;
        }

        // Spawn receiver thread
        let receiver_dest_transport = config.destination_transport;
        let receiver_handle = thread::spawn(move || {
            let timeout = Duration::from_millis(2500);
            match receiver_dest_transport {
                TransportType::Udp => {
                    let socket = receiver_udp_socket.unwrap();
                    receiver.listen_udp(&socket, timeout)
                }
                TransportType::Tcp => {
                    let listener = receiver_tcp_listener.unwrap();
                    receiver.listen_tcp(&listener, timeout)
                }
            }
        });

        // Small delay if TCP source so relay's accept loop is ready
        if config.source_transport == TransportType::Tcp {
            thread::sleep(Duration::from_millis(30));
        }

        // Run traffic generator
        let mut generator = TrafficGenerator::new(config.generator);
        match config.source_transport {
            TransportType::Udp => {
                generator.run_udp(&generator_target)?;
            }
            TransportType::Tcp => {
                generator.run_tcp(&generator_target)?;
            }
        }

        // Collect receiver report
        let report = receiver_handle
            .join()
            .map_err(|_| io::Error::other("receiver thread panicked"))??;

        // Cleanup
        if let Some(relay) = relay_instance {
            relay.stop();
        }

        stop_proxy.store(true, Ordering::Relaxed);
        if let Some(handle) = proxy_handle {
            let _ = handle.join();
        }

        Ok(report)
    }

    /// Executes a coordinated multi-instance topology simulation on localhost.
    pub fn run_topology(
        config: super::topology::TopologyConfig,
    ) -> io::Result<super::topology::TopologyReport> {
        super::topology::TestController::run(config)
    }
}
