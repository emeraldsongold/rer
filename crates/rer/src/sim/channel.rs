use std::io;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::generator::SplitMix64;
use super::packet::Packet;

/// A scheduled contact outage window defined in relative milliseconds from simulation start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "OutageWindowHelper", into = "OutageWindowHelper")]
pub struct OutageWindow {
    /// Start of outage window in milliseconds relative to simulation start.
    pub start_ms: u64,
    /// End of outage window in milliseconds relative to simulation start.
    pub end_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum OutageWindowHelper {
    Tuple(u64, u64),
    Object {
        #[serde(alias = "start")]
        start_ms: u64,
        #[serde(default, alias = "end")]
        end_ms: Option<u64>,
        #[serde(default, alias = "duration")]
        duration_ms: Option<u64>,
    },
}

impl From<OutageWindowHelper> for OutageWindow {
    fn from(helper: OutageWindowHelper) -> Self {
        match helper {
            OutageWindowHelper::Tuple(start, second) => {
                if second < start {
                    Self::with_duration(start, second)
                } else {
                    Self::new(start, second)
                }
            }
            OutageWindowHelper::Object {
                start_ms,
                end_ms,
                duration_ms,
            } => {
                if let Some(end) = end_ms {
                    Self::new(start_ms, end)
                } else if let Some(dur) = duration_ms {
                    Self::with_duration(start_ms, dur)
                } else {
                    Self::new(start_ms, start_ms)
                }
            }
        }
    }
}

impl From<OutageWindow> for OutageWindowHelper {
    fn from(w: OutageWindow) -> Self {
        OutageWindowHelper::Object {
            start_ms: w.start_ms,
            end_ms: Some(w.end_ms),
            duration_ms: Some(w.duration_ms()),
        }
    }
}

impl From<(u64, u64)> for OutageWindow {
    fn from((start, second): (u64, u64)) -> Self {
        if second < start {
            Self::with_duration(start, second)
        } else {
            Self::new(start, second)
        }
    }
}

impl OutageWindow {
    /// Creates a new outage window from `start_ms` to `end_ms`.
    pub fn new(start_ms: u64, end_ms: u64) -> Self {
        Self { start_ms, end_ms }
    }

    /// Creates an outage window starting at `start_ms` with duration `duration_ms`.
    pub fn with_duration(start_ms: u64, duration_ms: u64) -> Self {
        Self {
            start_ms,
            end_ms: start_ms.saturating_add(duration_ms),
        }
    }

    /// Duration of the outage window in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }

    /// Checks if a millisecond timestamp falls within this outage window `[start_ms, end_ms)`.
    pub fn contains(&self, timestamp_ms: u64) -> bool {
        timestamp_ms >= self.start_ms && timestamp_ms < self.end_ms
    }

    /// Checks if a packet's timestamp matches this outage window.
    pub fn matches_packet(&self, packet: &Packet) -> bool {
        if self.contains(packet.timestamp_ns) {
            return true;
        }
        if packet.timestamp_ns >= 1_000_000 && self.contains(packet.timestamp_ns / 1_000_000) {
            return true;
        }
        false
    }
}

/// Contact schedule specifying planned outage windows for deep-space channel simulation.
///
/// Designed to model deterministic contact intervals and occultation outages without
/// root privileges or kernel network emulation (SPEC §14, §13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(from = "OutageScheduleHelper", into = "OutageScheduleHelper")]
pub struct OutageSchedule {
    /// Sequence of scheduled outage windows.
    pub windows: Vec<OutageWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum OutageScheduleHelper {
    List(Vec<OutageWindow>),
    Object {
        #[serde(default)]
        windows: Vec<OutageWindow>,
    },
}

impl From<OutageScheduleHelper> for OutageSchedule {
    fn from(helper: OutageScheduleHelper) -> Self {
        match helper {
            OutageScheduleHelper::List(windows) => Self::new(windows),
            OutageScheduleHelper::Object { windows } => Self::new(windows),
        }
    }
}

impl From<OutageSchedule> for OutageScheduleHelper {
    fn from(s: OutageSchedule) -> Self {
        OutageScheduleHelper::Object { windows: s.windows }
    }
}

impl From<Vec<OutageWindow>> for OutageSchedule {
    fn from(windows: Vec<OutageWindow>) -> Self {
        Self::new(windows)
    }
}

impl From<Vec<(u64, u64)>> for OutageSchedule {
    fn from(tuples: Vec<(u64, u64)>) -> Self {
        Self::from_tuples(&tuples)
    }
}

impl OutageSchedule {
    /// Creates a new outage schedule from the provided windows, sorted by start time.
    pub fn new(mut windows: Vec<OutageWindow>) -> Self {
        windows.sort_by_key(|w| w.start_ms);
        Self { windows }
    }

    /// Creates an outage schedule from a slice of `(start_ms, end_ms)` tuples.
    pub fn from_tuples(tuples: &[(u64, u64)]) -> Self {
        let windows = tuples
            .iter()
            .map(|&(s, e)| OutageWindow::from((s, e)))
            .collect();
        Self::new(windows)
    }

    /// Creates an outage schedule from relative contact windows.
    pub fn import_relative_windows(windows: Vec<OutageWindow>) -> Self {
        Self::new(windows)
    }

    /// Checks if a timestamp in milliseconds falls within any scheduled outage window.
    pub fn is_in_outage(&self, timestamp_ms: u64) -> bool {
        self.windows.iter().any(|w| w.contains(timestamp_ms))
    }

    /// Checks if the channel is in contact (not in an outage window) at `timestamp_ms`.
    pub fn is_in_contact(&self, timestamp_ms: u64) -> bool {
        !self.is_in_outage(timestamp_ms)
    }

    /// Returns the outage window containing `timestamp_ms`, if any.
    pub fn window_at(&self, timestamp_ms: u64) -> Option<&OutageWindow> {
        self.windows.iter().find(|w| w.contains(timestamp_ms))
    }

    /// Checks if a packet's arrival time falls within any scheduled outage window.
    pub fn is_packet_in_outage(&self, packet: &Packet) -> bool {
        self.windows.iter().any(|w| w.matches_packet(packet))
    }

    /// Computes the effective arrival timestamp in milliseconds for a packet.
    pub fn packet_time_ms(&self, packet: &Packet) -> u64 {
        let max_window_end = self.windows.iter().map(|w| w.end_ms).max().unwrap_or(0);
        if max_window_end < 1_000_000 && packet.timestamp_ns >= 1_000_000 {
            packet.timestamp_ns / 1_000_000
        } else {
            packet.timestamp_ns
        }
    }
}

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
    /// Optional contact schedule outage windows (relative milliseconds from start)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outage_schedule: Option<OutageSchedule>,
    /// Whether to buffer packets arriving during outage windows instead of dropping them
    #[serde(default)]
    pub buffer_during_outage: bool,
}

impl ImpairmentConfig {
    /// Configures an outage schedule on this impairment configuration.
    pub fn with_outage_schedule(mut self, schedule: OutageSchedule) -> Self {
        self.outage_schedule = Some(schedule);
        self
    }

    /// Configures whether to buffer packets arriving during outage windows.
    pub fn with_buffer_during_outage(mut self, buffer: bool) -> Self {
        self.buffer_during_outage = buffer;
        self
    }
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
            outage_schedule: None,
            buffer_during_outage: false,
        }
    }
}

/// Software-simulated network channel that injects deterministic loss, duplication,
/// reordering, delay, and contact schedule outages without requiring elevated privileges.
#[derive(Debug, Clone)]
pub struct SimulatedChannel {
    config: ImpairmentConfig,
    prng: SplitMix64,
    outage_buffer: Vec<Packet>,
}

impl SimulatedChannel {
    /// Constructs a new impairment channel with the given configuration.
    pub fn new(config: ImpairmentConfig) -> Self {
        let seed = config.seed;
        Self {
            config,
            prng: SplitMix64::new(seed),
            outage_buffer: Vec::new(),
        }
    }

    /// Returns a reference to the active configuration.
    pub fn config(&self) -> &ImpairmentConfig {
        &self.config
    }

    /// Resets the channel state and PRNG to initial values.
    pub fn reset(&mut self) {
        self.prng = SplitMix64::new(self.config.seed);
        self.outage_buffer.clear();
    }

    /// Returns a slice of packets currently held in the outage buffer.
    pub fn buffered_packets(&self) -> &[Packet] {
        &self.outage_buffer
    }

    /// Number of packets currently held in the outage buffer.
    pub fn buffered_count(&self) -> usize {
        self.outage_buffer.len()
    }

    /// Manually flushes and returns all packets currently held in the outage buffer.
    pub fn release_buffered(&mut self) -> Vec<Packet> {
        let mut output = Vec::new();
        let mut held_packet = None;
        let buffered = std::mem::take(&mut self.outage_buffer);
        for packet in buffered {
            self.apply_impairments_to_packet(packet, &mut held_packet, &mut output);
        }
        if let Some(held) = held_packet {
            output.push(held);
        }
        output
    }

    /// Processes a single packet through channel impairments and outage schedule.
    pub fn process_packet(&mut self, packet: Packet) -> Vec<Packet> {
        self.apply(vec![packet])
    }

    /// Internal helper applying loss, reordering, and duplication to a packet.
    fn apply_impairments_to_packet(
        &mut self,
        packet: Packet,
        held_packet: &mut Option<Packet>,
        output: &mut Vec<Packet>,
    ) {
        // 1. Loss check
        if self.config.loss_rate > 0.0 && self.prng.next_f64() < self.config.loss_rate {
            return;
        }

        // 2. Reordering check
        if self.config.reorder_rate > 0.0 && self.prng.next_f64() < self.config.reorder_rate {
            if let Some(prev) = held_packet.take() {
                output.push(prev);
            }
            *held_packet = Some(packet);
            return;
        }

        // If we have a held packet from reordering, emit current packet first then held packet
        if let Some(held) = held_packet.take() {
            output.push(packet.clone());
            output.push(held);
        } else {
            output.push(packet.clone());
        }

        // 3. Duplication check
        if self.config.duplicate_rate > 0.0 && self.prng.next_f64() < self.config.duplicate_rate {
            output.push(packet);
        }
    }

    /// Applies configured impairments and contact schedule outages to an in-memory packet sequence.
    pub fn apply(&mut self, packets: Vec<Packet>) -> Vec<Packet> {
        let mut output = Vec::new();
        let mut held_packet: Option<Packet> = None;

        for packet in packets {
            // Outage schedule evaluation
            if let Some(ref schedule) = self.config.outage_schedule {
                let pkt_time = schedule.packet_time_ms(&packet);
                let in_outage = schedule.is_in_outage(pkt_time);

                if in_outage {
                    if self.config.buffer_during_outage {
                        // If this packet is in a new outage window, any packets buffered from
                        // an earlier window whose contact window opened in between must be released
                        if let Some(curr_win) = schedule.window_at(pkt_time) {
                            let mut to_release = Vec::new();
                            let mut remaining = Vec::new();
                            for held in self.outage_buffer.drain(..) {
                                let held_time = schedule.packet_time_ms(&held);
                                if held_time < curr_win.start_ms {
                                    to_release.push(held);
                                } else {
                                    remaining.push(held);
                                }
                            }
                            self.outage_buffer = remaining;
                            for p in to_release {
                                self.apply_impairments_to_packet(p, &mut held_packet, &mut output);
                            }
                        }
                        self.outage_buffer.push(packet);
                        continue;
                    } else {
                        // Dropped during outage window
                        continue;
                    }
                } else {
                    // Contact window is open: release all previously buffered packets in order
                    let buffered = std::mem::take(&mut self.outage_buffer);
                    for p in buffered {
                        self.apply_impairments_to_packet(p, &mut held_packet, &mut output);
                    }
                }
            }

            self.apply_impairments_to_packet(packet, &mut held_packet, &mut output);
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
        let mut outage_udp_buf: Vec<Vec<u8>> = Vec::new();
        let start_time = std::time::Instant::now();

        while !stop_signal.load(Ordering::Relaxed) {
            match listen_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let data = &buf[..len];
                    let recv_ms = start_time.elapsed().as_millis() as u64;

                    // Outage schedule check
                    if let Some(ref schedule) = self.config.outage_schedule {
                        if schedule.is_in_outage(recv_ms) {
                            if self.config.buffer_during_outage {
                                outage_udp_buf.push(data.to_vec());
                            }
                            continue;
                        } else if !outage_udp_buf.is_empty() {
                            for held in outage_udp_buf.drain(..) {
                                let _ = sender.send_to(&held, forward_addr);
                            }
                        }
                    }

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
                    if let Some(ref schedule) = self.config.outage_schedule {
                        let now_ms = start_time.elapsed().as_millis() as u64;
                        if !schedule.is_in_outage(now_ms) && !outage_udp_buf.is_empty() {
                            for held in outage_udp_buf.drain(..) {
                                let _ = sender.send_to(&held, forward_addr);
                            }
                        }
                    }

                    if let Some(held) = held_buf.take() {
                        let _ = sender.send_to(&held, forward_addr);
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        for held in outage_udp_buf {
            let _ = sender.send_to(&held, forward_addr);
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
            ..Default::default()
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

    #[test]
    fn test_outage_schedule_drops_packets_without_buffering() {
        // Criterion 1: Configuring ImpairmentConfig with option outage_schedule drops packets
        // whose arrival timestamp falls within a scheduled outage window when buffering is not configured.
        let config = ImpairmentConfig {
            seed: 123,
            loss_rate: 0.0,
            duplicate_rate: 0.0,
            reorder_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
            outage_schedule: Some(OutageSchedule::from_tuples(&[(100, 200)])),
            buffer_during_outage: false,
        };
        let mut channel = SimulatedChannel::new(config);

        let packets = vec![
            Packet::new("p0".into(), 0, 50 * 1_000_000, vec![0]), // 50ms - before outage
            Packet::new("p1".into(), 1, 100 * 1_000_000, vec![1]), // 100ms - start of outage window (dropped)
            Packet::new("p2".into(), 2, 150 * 1_000_000, vec![2]), // 150ms - inside outage window (dropped)
            Packet::new("p3".into(), 3, 199 * 1_000_000, vec![3]), // 199ms - inside outage window (dropped)
            Packet::new("p4".into(), 4, 200 * 1_000_000, vec![4]), // 200ms - contact window open (forwarded)
            Packet::new("p5".into(), 5, 250 * 1_000_000, vec![5]), // 250ms - after outage (forwarded)
        ];

        let output = channel.apply(packets);
        let ids: Vec<&str> = output.iter().map(|p| p.id.as_str()).collect();

        assert_eq!(ids, vec!["p0", "p4", "p5"]);
    }

    #[test]
    fn test_outage_schedule_buffers_and_releases_in_order() {
        // Criterion 2: Configuring ImpairmentConfig with option outage_schedule and option buffer_during_outage
        // holds packets arriving during an outage window and releases them in order when the contact window opens.
        let config = ImpairmentConfig {
            seed: 456,
            loss_rate: 0.0,
            duplicate_rate: 0.0,
            reorder_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
            outage_schedule: Some(OutageSchedule::from_tuples(&[(100, 200)])),
            buffer_during_outage: true,
        };
        let mut channel = SimulatedChannel::new(config);

        let packets = vec![
            Packet::new("p0".into(), 0, 50 * 1_000_000, vec![0]),
            Packet::new("p1".into(), 1, 120 * 1_000_000, vec![1]),
            Packet::new("p2".into(), 2, 150 * 1_000_000, vec![2]),
            Packet::new("p3".into(), 3, 180 * 1_000_000, vec![3]),
            Packet::new("p4".into(), 4, 220 * 1_000_000, vec![4]),
            Packet::new("p5".into(), 5, 300 * 1_000_000, vec![5]),
        ];

        let output = channel.apply(packets);
        let ids: Vec<&str> = output.iter().map(|p| p.id.as_str()).collect();

        // When p4 arrives at 220ms (contact window open), buffered packets p1, p2, p3
        // must be released in order, followed by p4 and p5.
        assert_eq!(ids, vec!["p0", "p1", "p2", "p3", "p4", "p5"]);
    }

    #[test]
    fn test_outage_schedule_buffers_across_multiple_apply_calls() {
        let config = ImpairmentConfig {
            seed: 789,
            loss_rate: 0.0,
            duplicate_rate: 0.0,
            reorder_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
            outage_schedule: Some(OutageSchedule::from_tuples(&[(100, 200)])),
            buffer_during_outage: true,
        };
        let mut channel = SimulatedChannel::new(config);

        // Batch 1: arriving during outage window
        let batch1 = vec![
            Packet::new("p1".into(), 1, 120 * 1_000_000, vec![1]),
            Packet::new("p2".into(), 2, 160 * 1_000_000, vec![2]),
        ];
        let out1 = channel.apply(batch1);
        assert!(out1.is_empty(), "packets during outage must be held");
        assert_eq!(channel.buffered_count(), 2);

        // Batch 2: arrives when contact window opens (250ms)
        let batch2 = vec![Packet::new("p3".into(), 3, 250 * 1_000_000, vec![3])];
        let out2 = channel.apply(batch2);
        let ids: Vec<&str> = out2.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["p1", "p2", "p3"]);
        assert_eq!(channel.buffered_count(), 0);
    }

    #[test]
    fn test_identical_channels_produce_identical_output_sequences() {
        // Criterion 3: Processing packets across two identical SimulatedChannel instances
        // initialized with identical PRNG seed and outage_schedule produces identical packet output sequences.
        let config1 = ImpairmentConfig {
            seed: 9999,
            loss_rate: 0.25,
            duplicate_rate: 0.15,
            reorder_rate: 0.2,
            delay_ms: 0,
            jitter_ms: 0,
            outage_schedule: Some(OutageSchedule::from_tuples(&[(100, 200), (300, 400)])),
            buffer_during_outage: true,
        };
        let config2 = config1.clone();

        let mut ch1 = SimulatedChannel::new(config1);
        let mut ch2 = SimulatedChannel::new(config2);

        let packets: Vec<Packet> = (0..50)
            .map(|i| Packet::new(format!("pkt-{}", i), i, i * 10 * 1_000_000, vec![i as u8]))
            .collect();

        let out1 = ch1.apply(packets.clone());
        let out2 = ch2.apply(packets);

        assert_eq!(out1, out2);
        assert!(!out1.is_empty());
    }

    #[test]
    fn test_without_outage_schedule_preserves_previous_behavior() {
        // Criterion 4: An ImpairmentConfig without option outage_schedule forwards packets
        // according to configured option loss_rate and option delay_ms preserving previous impairment behavior.
        let config = ImpairmentConfig {
            seed: 42,
            loss_rate: 0.0,
            duplicate_rate: 0.0,
            reorder_rate: 0.0,
            delay_ms: 50,
            jitter_ms: 0,
            outage_schedule: None,
            buffer_during_outage: false,
        };
        let mut channel = SimulatedChannel::new(config);

        let packets: Vec<Packet> = (0..10)
            .map(|i| Packet::new(format!("p{}", i), i, i * 1_000_000, vec![i as u8]))
            .collect();

        let output = channel.apply(packets.clone());
        assert_eq!(output, packets);
    }

    #[test]
    fn test_multiple_outage_windows_with_contact_interval() {
        let config = ImpairmentConfig {
            seed: 100,
            loss_rate: 0.0,
            duplicate_rate: 0.0,
            reorder_rate: 0.0,
            delay_ms: 0,
            jitter_ms: 0,
            outage_schedule: Some(OutageSchedule::from_tuples(&[(100, 200), (300, 400)])),
            buffer_during_outage: true,
        };
        let mut channel = SimulatedChannel::new(config);

        let packets = vec![
            Packet::new("p0".into(), 0, 50 * 1_000_000, vec![0]), // contact
            Packet::new("p1".into(), 1, 150 * 1_000_000, vec![1]), // outage 1
            Packet::new("p2".into(), 2, 250 * 1_000_000, vec![2]), // contact (releases p1)
            Packet::new("p3".into(), 3, 350 * 1_000_000, vec![3]), // outage 2
            Packet::new("p4".into(), 4, 450 * 1_000_000, vec![4]), // contact (releases p3)
        ];

        let output = channel.apply(packets);
        let ids: Vec<&str> = output.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, vec!["p0", "p1", "p2", "p3", "p4"]);
    }

    #[test]
    fn test_outage_schedule_serde_deserialization() {
        let json_list = r#"{"seed":42,"outage_schedule":[[100,200],[300,400]]}"#;
        let config: ImpairmentConfig = serde_json::from_str(json_list).unwrap();
        assert!(config.outage_schedule.is_some());
        let sched = config.outage_schedule.unwrap();
        assert_eq!(sched.windows.len(), 2);
        assert_eq!(sched.windows[0].start_ms, 100);
        assert_eq!(sched.windows[0].end_ms, 200);

        let json_objs = r#"{"seed":42,"outage_schedule":[{"start_ms":100,"duration_ms":100}]}"#;
        let config: ImpairmentConfig = serde_json::from_str(json_objs).unwrap();
        let sched = config.outage_schedule.unwrap();
        assert_eq!(sched.windows[0].start_ms, 100);
        assert_eq!(sched.windows[0].end_ms, 200);
    }
}
