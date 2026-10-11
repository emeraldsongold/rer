use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::generator::SplitMix64;
use super::packet::Packet;

/// Configuration for simulated network impairments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpairmentConfig {
    /// PRNG seed for deterministic impairment decisions
    pub seed: u64,
    /// Probability of dropping a packet (0.0 to 1.0)
    #[serde(default)]
    pub loss_rate: f64,
    /// Probability of duplicating a packet (0.0 to 1.0)
    #[serde(default)]
    pub duplicate_rate: f64,
    /// Probability of reordering a packet (0.0 to 1.0)
    #[serde(default)]
    pub reorder_rate: f64,
    /// Fixed transmission delay in milliseconds
    #[serde(default)]
    pub delay_ms: u64,
    /// Random delay jitter in milliseconds (+/- jitter)
    #[serde(default)]
    pub jitter_ms: u64,
}

impl Default for ImpairmentConfig {
    fn default() -> Self {
        Self {
            seed: 1337,
            loss_rate: 0.0,
            duplicate_rate: 0.0,
            reorder_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
        }
    }
}

/// Software-simulated network channel that injects deterministic loss, duplication,
/// reordering, and delay without requiring elevated privileges or kernel netem.
pub struct SimulatedChannel {
    config: ImpairmentConfig,
    prng: SplitMix64,
}

impl SimulatedChannel {
    /// Constructs a new impairment channel with the given configuration.
    pub fn new(config: ImpairmentConfig) -> Self {
        let seed = config.seed;
        Self {
            config,
            prng: SplitMix64::new(seed),
        }
    }

    /// Applies configured impairments to an in-memory packet sequence.
    pub fn apply(&mut self, packets: Vec<Packet>) -> Vec<Packet> {
        let mut output = Vec::new();
        let mut held_packet: Option<Packet> = None;

        for packet in packets {
            // 1. Loss check
            if self.config.loss_rate > 0.0 && self.prng.next_f64() < self.config.loss_rate {
                continue;
            }

            // 2. Reordering check
            if self.config.reorder_rate > 0.0 && self.prng.next_f64() < self.config.reorder_rate {
                if let Some(prev) = held_packet.take() {
                    output.push(prev);
                }
                held_packet = Some(packet.clone());
                continue;
            }

            // If we have a held packet from reordering, emit current packet first then held packet
            if let Some(held) = held_packet.take() {
                output.push(packet.clone());
                output.push(held);
            } else {
                output.push(packet.clone());
            }

            // 3. Duplication check
            if self.config.duplicate_rate > 0.0 && self.prng.next_f64() < self.config.duplicate_rate
            {
                output.push(packet);
            }
        }

        if let Some(held) = held_packet {
            output.push(held);
        }

        output
    }

    /// Runs an unprivileged UDP proxy forwarding from `listen_socket` to `forward_addr`,
    /// applying impairments to each forwarded packet.
    pub fn forward_udp_loop(
        &mut self,
        listen_socket: &UdpSocket,
        forward_addr: &str,
        stop_signal: Arc<AtomicBool>,
    ) -> io::Result<()> {
        listen_socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        let mut buf = vec![0u8; 65536];
        let mut held_buf: Option<Vec<u8>> = None;

        while !stop_signal.load(Ordering::Relaxed) {
            match listen_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let data = &buf[..len];

                    // Loss check
                    if self.config.loss_rate > 0.0 && self.prng.next_f64() < self.config.loss_rate {
                        continue;
                    }

                    // Delay / jitter
                    if self.config.delay_ms > 0 || self.config.jitter_ms > 0 {
                        let mut delay = self.config.delay_ms;
                        if self.config.jitter_ms > 0 {
                            let jitter_fraction = (self.prng.next_f64() * 2.0) - 1.0;
                            let jitter = (self.config.jitter_ms as f64 * jitter_fraction) as i64;
                            delay = (delay as i64 + jitter).max(0) as u64;
                        }
                        if delay > 0 {
                            thread::sleep(Duration::from_millis(delay));
                        }
                    }

                    // Reordering
                    if self.config.reorder_rate > 0.0
                        && self.prng.next_f64() < self.config.reorder_rate
                    {
                        if let Some(prev) = held_buf.take() {
                            let _ = sender.send_to(&prev, forward_addr);
                        }
                        held_buf = Some(data.to_vec());
                        continue;
                    }

                    if let Some(held) = held_buf.take() {
                        let _ = sender.send_to(data, forward_addr);
                        let _ = sender.send_to(&held, forward_addr);
                    } else {
                        let _ = sender.send_to(data, forward_addr);
                    }

                    // Duplication
                    if self.config.duplicate_rate > 0.0
                        && self.prng.next_f64() < self.config.duplicate_rate
                    {
                        let _ = sender.send_to(data, forward_addr);
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        if let Some(held) = held_buf {
            let _ = sender.send_to(&held, forward_addr);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impairment_channel_deterministic_loss() {
        let config = ImpairmentConfig {
            seed: 42,
            loss_rate: 0.5,
            duplicate_rate: 0.0,
            reorder_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
        };
        let mut ch1 = SimulatedChannel::new(config.clone());
        let mut ch2 = SimulatedChannel::new(config);

        let packets: Vec<Packet> = (0..20)
            .map(|i| Packet::new(format!("p{}", i), i, 0, vec![i as u8]))
            .collect();

        let out1 = ch1.apply(packets.clone());
        let out2 = ch2.apply(packets);

        assert_eq!(out1, out2);
        assert!(out1.len() < 20);
    }
}
