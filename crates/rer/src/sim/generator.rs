use std::io;
use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::packet::Packet;
use super::sha256::sha256_hex;

/// Deterministic 64-bit pseudo-random number generator (SplitMix64).
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Initializes the PRNG with a 64-bit seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generates the next pseudo-random 64-bit integer.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    /// Generates a floating point number in `[0.0, 1.0)`.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
    }

    /// Fills the destination slice with deterministic random bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut i = 0;
        while i < dest.len() {
            let val = self.next_u64().to_le_bytes();
            let take = (dest.len() - i).min(8);
            dest[i..i + take].copy_from_slice(&val[..take]);
            i += take;
        }
    }

    /// Generates a deterministic RFC 4122 version 4 UUID string.
    pub fn next_uuid_v4(&mut self) -> String {
        let mut bytes = [0u8; 16];
        self.fill_bytes(&mut bytes);
        // Set version 4 (0100 in bits 4..7 of byte 6)
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        // Set variant 1 (10 in bits 6..7 of byte 8)
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        )
    }
}

fn default_packet_size() -> usize {
    256
}

/// Configuration options for the traffic generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorConfig {
    /// PRNG seed ensuring deterministic, reproducible packet streams
    pub seed: u64,
    /// Configurable payload size in bytes (default: 256)
    #[serde(default = "default_packet_size")]
    pub packet_size: usize,
    /// Configurable rate in packets per second (None or <= 0 for unthrottled)
    #[serde(default)]
    pub rate: Option<f64>,
    /// Configurable burst size (number of packets emitted per burst interval, default: 1)
    #[serde(default)]
    pub burst: Option<usize>,
    /// Configurable duration after which generation halts
    #[serde(default)]
    pub duration: Option<Duration>,
    /// Maximum number of packets to emit
    #[serde(default)]
    pub count: Option<u64>,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            packet_size: default_packet_size(),
            rate: None,
            burst: None,
            duration: None,
            count: None,
        }
    }
}

/// Statistics and summary reported after running the traffic generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratorStats {
    pub packets_emitted: u64,
    pub bytes_emitted: u64,
    pub duration_ms: u64,
    pub stream_hash: String,
}

/// Traffic generator emitting deterministic packets with unique IDs, sequential numbers,
/// and configurable size, rate, burst, duration and seed.
pub struct TrafficGenerator {
    config: GeneratorConfig,
    prng: SplitMix64,
    current_sequence: u64,
    emitted_count: u64,
    start_time: Option<Instant>,
}

impl TrafficGenerator {
    /// Constructs a new traffic generator with the specified configuration.
    pub fn new(config: GeneratorConfig) -> Self {
        let seed = config.seed;
        Self {
            config,
            prng: SplitMix64::new(seed),
            current_sequence: 0,
            emitted_count: 0,
            start_time: None,
        }
    }

    /// Resets the generator back to sequence 0 with its initial seed.
    pub fn reset(&mut self) {
        let seed = self.config.seed;
        self.prng = SplitMix64::new(seed);
        self.current_sequence = 0;
        self.emitted_count = 0;
        self.start_time = None;
    }

    /// Returns a reference to the active configuration.
    pub fn config(&self) -> &GeneratorConfig {
        &self.config
    }

    /// Computes the expected SHA-256 stream hash for `count` packets generated with this config.
    pub fn expected_stream_hash(&self, count: u64) -> String {
        let mut sim = Self::new(self.config.clone());
        let mut all_payloads = Vec::with_capacity((count as usize) * self.config.packet_size);
        for _ in 0..count {
            if let Some(pkt) = sim.next_packet() {
                all_payloads.extend_from_slice(&pkt.payload);
            } else {
                break;
            }
        }
        sha256_hex(&all_payloads)
    }

    /// Produces the next packet in the deterministic stream, or `None` if count/duration is reached.
    pub fn next_packet(&mut self) -> Option<Packet> {
        if let Some(limit) = self.config.count {
            if self.emitted_count >= limit {
                return None;
            }
        }

        if let Some(duration) = self.config.duration {
            let start = *self.start_time.get_or_insert_with(Instant::now);
            if start.elapsed() >= duration {
                return None;
            }
        } else if self.start_time.is_none() {
            self.start_time = Some(Instant::now());
        }

        let seq = self.current_sequence;
        self.current_sequence = self.current_sequence.wrapping_add(1);
        self.emitted_count += 1;

        let id = self.prng.next_uuid_v4();

        let mut payload = vec![0u8; self.config.packet_size];
        self.prng.fill_bytes(&mut payload);

        let timestamp_ns = if let Some(r) = self.config.rate {
            if r > 0.0 {
                ((seq as f64) * (1_000_000_000.0 / r)) as u64
            } else {
                seq * 1_000_000
            }
        } else {
            seq * 1_000_000
        };

        Some(Packet::new(id, seq, timestamp_ns, payload))
    }

    /// Collects and returns all remaining packets up to the configured limit or duration.
    pub fn emit_all(&mut self) -> Vec<Packet> {
        let mut packets = Vec::new();
        while let Some(pkt) = self.next_packet() {
            packets.push(pkt);
        }
        packets
    }

    /// Sends generated packets over UDP to `target_addr`, pacing according to `rate` and `burst`.
    pub fn run_udp(&mut self, target_addr: &str) -> io::Result<GeneratorStats> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(target_addr)?;

        let rate = self.config.rate.unwrap_or(0.0);
        let burst = self.config.burst.unwrap_or(1).max(1);

        let burst_delay = if rate > 0.0 {
            Duration::from_secs_f64(burst as f64 / rate)
        } else {
            Duration::ZERO
        };

        let start = Instant::now();
        self.start_time = Some(start);

        let mut total_bytes = 0u64;
        let mut all_payloads = Vec::new();
        let mut burst_counter = 0;
        let mut next_burst_time = Instant::now();

        while let Some(pkt) = self.next_packet() {
            let bytes = pkt.to_bytes();
            socket.send(&bytes)?;
            total_bytes += bytes.len() as u64;
            all_payloads.extend_from_slice(&pkt.payload);

            burst_counter += 1;
            if burst_counter >= burst {
                burst_counter = 0;
                if rate > 0.0 {
                    next_burst_time += burst_delay;
                    let now = Instant::now();
                    if next_burst_time > now {
                        thread::sleep(next_burst_time - now);
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        let stream_hash = sha256_hex(&all_payloads);

        Ok(GeneratorStats {
            packets_emitted: self.emitted_count,
            bytes_emitted: total_bytes,
            duration_ms: elapsed.as_millis() as u64,
            stream_hash,
        })
    }
}

impl Iterator for TrafficGenerator {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_packet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_seed_reproduces_identical_packet_stream() {
        let config1 = GeneratorConfig {
            seed: 12345,
            packet_size: 128,
            count: Some(50),
            ..Default::default()
        };
        let mut gen1 = TrafficGenerator::new(config1);
        let pkts1: Vec<Packet> = gen1.by_ref().collect();

        let config2 = GeneratorConfig {
            seed: 12345,
            packet_size: 128,
            count: Some(50),
            ..Default::default()
        };
        let mut gen2 = TrafficGenerator::new(config2);
        let pkts2: Vec<Packet> = gen2.by_ref().collect();

        assert_eq!(pkts1.len(), 50);
        assert_eq!(pkts2.len(), 50);
        assert_eq!(pkts1, pkts2);
    }

    #[test]
    fn test_different_seeds_produce_different_streams() {
        let config1 = GeneratorConfig {
            seed: 100,
            packet_size: 64,
            count: Some(10),
            ..Default::default()
        };
        let pkts1: Vec<Packet> = TrafficGenerator::new(config1).collect();

        let config2 = GeneratorConfig {
            seed: 200,
            packet_size: 64,
            count: Some(10),
            ..Default::default()
        };
        let pkts2: Vec<Packet> = TrafficGenerator::new(config2).collect();

        assert_ne!(pkts1[0].id, pkts2[0].id);
        assert_ne!(pkts1[0].payload, pkts2[0].payload);
    }

    #[test]
    fn test_unique_packet_ids_and_sequence_numbers() {
        let config = GeneratorConfig {
            seed: 999,
            packet_size: 32,
            count: Some(200),
            ..Default::default()
        };
        let pkts: Vec<Packet> = TrafficGenerator::new(config).collect();

        let mut ids = std::collections::HashSet::new();
        for (idx, pkt) in pkts.iter().enumerate() {
            assert_eq!(pkt.sequence, idx as u64);
            assert!(ids.insert(&pkt.id), "duplicate id found: {}", pkt.id);
            assert_eq!(pkt.payload.len(), 32);
            assert!(pkt.verify_hash());
        }
    }
}
