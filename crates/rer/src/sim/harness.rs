use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{Config, DropPolicy};
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
        }
    }
}

/// Unprivileged simulation harness that orchestrates generator, relay,
/// impairments, and receiver in ordinary CI.
pub struct SimulationHarness;

impl SimulationHarness {
    /// Executes the simulation harness end-to-end unprivileged on localhost,
    /// returning the receiver's JSON-serializable report.
    pub fn run(config: HarnessConfig) -> io::Result<ReceiverReport> {
        let receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
        let receiver_port = receiver_socket.local_addr()?.port();

        let expected_count = config.generator.count;
        let expected_stream_hash = expected_count
            .map(|cnt| TrafficGenerator::new(config.generator.clone()).expected_stream_hash(cnt));

        let mut receiver = TrafficReceiver::new(expected_count, expected_stream_hash);
        if let Some(ref tid) = config.test_id {
            receiver.set_test_id(tid.clone());
        }

        let stop_proxy = Arc::new(AtomicBool::new(false));
        let proxy_handle;
        let final_receiver_dest;

        // Setup optional impairment proxy
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
            let listen_socket = UdpSocket::bind("127.0.0.1:0")?;
            let relay_listen_port = listen_socket.local_addr()?.port();
            drop(listen_socket); // Free port for relay bind

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

            let yaml = format!(
                r#"
version: "1"
instances:
  - id: "harness-relay"
    streams:
      - id: "sim-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{relay_listen_port}"
        destination:
          transport: "udp"
          address: "{final_receiver_dest}"
{buffer_yaml}
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
        let receiver_handle = thread::spawn(move || {
            let timeout = Duration::from_millis(1500);
            receiver.listen_udp(&receiver_socket, timeout)
        });

        // Run traffic generator
        let mut generator = TrafficGenerator::new(config.generator);
        generator.run_udp(&generator_target)?;

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
}
