use std::collections::HashSet;
use std::io;
use std::net::{TcpListener, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::packet::{Packet, PacketError};
use super::sha256::sha256_hex;

/// Details about a packet that arrived out of sequential order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReorderedPacket {
    /// The sequence number of the out-of-order packet
    pub sequence: u64,
    /// The zero-based arrival index of the packet
    pub received_index: usize,
    /// The highest sequence number seen before this packet arrived
    pub previous_highest_seq: u64,
}

/// JSON-serializable report of verification results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReceiverReport {
    /// Optional identifier for this test run
    pub test_id: Option<String>,
    /// Expected number of packets, if configured
    pub expected_count: Option<u64>,
    /// Total number of packets received
    pub received_count: u64,
    /// Total number of distinct packet sequences received
    pub unique_received_count: u64,
    /// Number of expected packets that were never received
    pub lost_count: u64,
    /// Number of duplicate packets received
    pub duplicate_count: u64,
    /// Number of packets received out of sequential order
    pub reordered_count: u64,
    /// Number of packets whose payload hash did not match their payload
    pub corrupted_count: u64,
    /// Packet loss rate as a fraction between 0.0 and 1.0
    pub loss_rate: f64,
    /// True if all received payloads matched their hashes and stream hash matched
    pub payload_hashes_verified: bool,
    /// Expected SHA-256 digest of concatenated ordered payloads, if known
    pub expected_stream_hash: Option<String>,
    /// Actual SHA-256 digest of concatenated ordered payloads
    pub actual_stream_hash: Option<String>,
    /// List of sequence numbers that were lost
    pub lost_sequences: Vec<u64>,
    /// List of sequence numbers that arrived multiple times
    pub duplicate_sequences: Vec<u64>,
    /// List of packets that arrived out of order
    pub reordered_sequences: Vec<ReorderedPacket>,
    /// Duration of the test in milliseconds
    pub duration_ms: u64,
    /// Whether the test met all verification criteria without flaws
    pub pass: bool,
}

impl ReceiverReport {
    /// Serializes this report to a formatted JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Deserializes a report from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

struct StoredPacket {
    sequence: u64,
    payload: Vec<u8>,
}

/// Test receiver that verifies packet counts, payload hashes, and reports
/// loss, duplication, and reordering as JSON.
pub struct TrafficReceiver {
    test_id: Option<String>,
    expected_count: Option<u64>,
    expected_stream_hash: Option<String>,
    received_packets: Vec<StoredPacket>,
    seen_sequences: HashSet<u64>,
    highest_seq_seen: Option<u64>,
    duplicates: Vec<u64>,
    reordered: Vec<ReorderedPacket>,
    corrupted: Vec<u64>,
    total_received: u64,
    start_time: Option<Instant>,
    end_time: Option<Instant>,
}

impl TrafficReceiver {
    /// Creates a new receiver with optional expected count and expected stream hash.
    pub fn new(expected_count: Option<u64>, expected_stream_hash: Option<String>) -> Self {
        Self {
            test_id: None,
            expected_count,
            expected_stream_hash,
            received_packets: Vec::new(),
            seen_sequences: HashSet::new(),
            highest_seq_seen: None,
            duplicates: Vec::new(),
            reordered: Vec::new(),
            corrupted: Vec::new(),
            total_received: 0,
            start_time: None,
            end_time: None,
        }
    }

    /// Sets an identifier for this test run.
    pub fn set_test_id(&mut self, test_id: String) {
        self.test_id = Some(test_id);
    }

    /// Records an incoming packet and checks its payload hash, sequence ordering, and duplication.
    pub fn record_packet(&mut self, packet: &Packet) {
        if self.start_time.is_none() {
            self.start_time = Some(Instant::now());
        }
        self.end_time = Some(Instant::now());

        let idx = self.total_received as usize;
        self.total_received += 1;

        // Verify individual packet payload hash
        if !packet.verify_hash() {
            self.corrupted.push(packet.sequence);
        }

        // Check for duplication
        if self.seen_sequences.contains(&packet.sequence) {
            self.duplicates.push(packet.sequence);
        } else {
            self.seen_sequences.insert(packet.sequence);
            self.received_packets.push(StoredPacket {
                sequence: packet.sequence,
                payload: packet.payload.clone(),
            });
        }

        // Check for reordering
        if let Some(highest) = self.highest_seq_seen {
            if packet.sequence < highest {
                self.reordered.push(ReorderedPacket {
                    sequence: packet.sequence,
                    received_index: idx,
                    previous_highest_seq: highest,
                });
            } else {
                self.highest_seq_seen = Some(packet.sequence);
            }
        } else {
            self.highest_seq_seen = Some(packet.sequence);
        }
    }

    /// Decodes raw packet bytes and records the packet.
    pub fn record_bytes(&mut self, bytes: &[u8]) -> Result<(), PacketError> {
        let pkt = Packet::from_bytes(bytes)?;
        self.record_packet(&pkt);
        Ok(())
    }

    /// Generates a comprehensive verification report.
    pub fn report(&self) -> ReceiverReport {
        let expected_total = self
            .expected_count
            .or_else(|| self.highest_seq_seen.map(|h| h + 1));

        let mut lost_sequences = Vec::new();
        if let Some(max_expected) = expected_total {
            for seq in 0..max_expected {
                if !self.seen_sequences.contains(&seq) {
                    lost_sequences.push(seq);
                }
            }
        }

        let lost_count = lost_sequences.len() as u64;
        let expected_denom = expected_total.unwrap_or(0);
        let loss_rate = if expected_denom > 0 {
            lost_count as f64 / expected_denom as f64
        } else {
            0.0
        };

        // Compute actual stream hash by ordering unique received packets by sequence
        let mut sorted_packets = self.received_packets.iter().collect::<Vec<&StoredPacket>>();
        sorted_packets.sort_by_key(|p| p.sequence);

        let mut concatenated = Vec::new();
        for p in &sorted_packets {
            concatenated.extend_from_slice(&p.payload);
        }
        let actual_stream_hash = Some(sha256_hex(&concatenated));

        let stream_hash_matches = match (&self.expected_stream_hash, &actual_stream_hash) {
            (Some(exp), Some(act)) => exp == act,
            (None, _) => true,
            _ => false,
        };

        let payload_hashes_verified = self.corrupted.is_empty() && stream_hash_matches;

        let counts_match = match self.expected_count {
            Some(exp) => self.total_received == exp && lost_count == 0,
            None => lost_count == 0,
        };

        let pass = counts_match
            && self.duplicates.is_empty()
            && self.reordered.is_empty()
            && self.corrupted.is_empty()
            && payload_hashes_verified;

        let duration_ms = match (self.start_time, self.end_time) {
            (Some(s), Some(e)) if e >= s => (e - s).as_millis() as u64,
            _ => 0,
        };

        ReceiverReport {
            test_id: self.test_id.clone(),
            expected_count: self.expected_count,
            received_count: self.total_received,
            unique_received_count: self.seen_sequences.len() as u64,
            lost_count,
            duplicate_count: self.duplicates.len() as u64,
            reordered_count: self.reordered.len() as u64,
            corrupted_count: self.corrupted.len() as u64,
            loss_rate,
            payload_hashes_verified,
            expected_stream_hash: self.expected_stream_hash.clone(),
            actual_stream_hash,
            lost_sequences,
            duplicate_sequences: self.duplicates.clone(),
            reordered_sequences: self.reordered.clone(),
            duration_ms,
            pass,
        }
    }

    /// Listens on `socket` for datagrams until `timeout` has elapsed without receiving a packet,
    /// or until the expected number of packets has been received.
    pub fn listen_udp(
        &mut self,
        socket: &UdpSocket,
        timeout: Duration,
    ) -> io::Result<ReceiverReport> {
        socket.set_read_timeout(Some(timeout))?;
        let mut buf = vec![0u8; 65536];

        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, _addr)) => {
                    let _ = self.record_bytes(&buf[..len]);
                    if let Some(exp) = self.expected_count {
                        if self.total_received >= exp {
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(self.report())
    }

    /// Listens on `listener` for incoming TCP connection(s) and reads framed packets until
    /// `timeout` has elapsed without receiving a packet, or until the expected number
    /// of packets has been received.
    pub fn listen_tcp(
        &mut self,
        listener: &TcpListener,
        timeout: Duration,
    ) -> io::Result<ReceiverReport> {
        listener.set_nonblocking(true)?;
        let start_listen = Instant::now();
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let mut active_stream = None;

        // Accept loop: wait for incoming connection within timeout
        while active_stream.is_none() {
            match listener.accept() {
                Ok((s, _)) => {
                    let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
                    let _ = s.set_nodelay(true);
                    active_stream = Some(s);
                    break;
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if start_listen.elapsed() >= timeout {
                        return Ok(self.report());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }

        let mut stream = active_stream.unwrap();
        let mut last_packet_time = Instant::now();

        loop {
            match crate::framing::read_frame(&mut stream, 1024 * 1024, &shutdown) {
                Ok(Some(frame_bytes)) => {
                    let _ = self.record_bytes(&frame_bytes);
                    last_packet_time = Instant::now();
                    if let Some(exp) = self.expected_count {
                        if self.total_received >= exp {
                            break;
                        }
                    }
                }
                Ok(None) => {
                    // Clean EOF from client
                    break;
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    if last_packet_time.elapsed() >= timeout {
                        break;
                    }
                }
                Err(_) => {
                    // Socket disconnect or read error
                    break;
                }
            }
        }

        Ok(self.report())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_receiver_verifies_intact_stream() {
        let mut receiver = TrafficReceiver::new(Some(3), None);
        let p0 = Packet::new("p0".into(), 0, 0, b"data0".to_vec());
        let p1 = Packet::new("p1".into(), 1, 0, b"data1".to_vec());
        let p2 = Packet::new("p2".into(), 2, 0, b"data2".to_vec());

        receiver.record_packet(&p0);
        receiver.record_packet(&p1);
        receiver.record_packet(&p2);

        let report = receiver.report();
        assert!(report.pass);
        assert_eq!(report.received_count, 3);
        assert_eq!(report.lost_count, 0);
        assert_eq!(report.duplicate_count, 0);
        assert_eq!(report.reordered_count, 0);
        assert!(report.payload_hashes_verified);
    }

    #[test]
    fn test_receiver_detects_loss_duplication_and_reordering() {
        let mut receiver = TrafficReceiver::new(Some(4), None);
        // Packets: 0, 2, 1, 2 (loss of 3, duplicate 2, reordering of 1)
        let p0 = Packet::new("p0".into(), 0, 0, b"data0".to_vec());
        let p2 = Packet::new("p2".into(), 2, 0, b"data2".to_vec());
        let p1 = Packet::new("p1".into(), 1, 0, b"data1".to_vec());
        let p2_dup = Packet::new("p2".into(), 2, 0, b"data2".to_vec());

        receiver.record_packet(&p0);
        receiver.record_packet(&p2);
        receiver.record_packet(&p1); // reordered (seq 1 after highest 2)
        receiver.record_packet(&p2_dup); // duplicate

        let report = receiver.report();
        assert!(!report.pass);
        assert_eq!(report.received_count, 4);
        assert_eq!(report.lost_count, 1);
        assert_eq!(report.lost_sequences, vec![3]);
        assert_eq!(report.duplicate_count, 1);
        assert_eq!(report.duplicate_sequences, vec![2]);
        assert_eq!(report.reordered_count, 1);
        assert_eq!(report.reordered_sequences[0].sequence, 1);
    }

    #[test]
    fn test_receiver_report_json_serialization() {
        let mut receiver = TrafficReceiver::new(Some(2), None);
        let p0 = Packet::new("p0".into(), 0, 0, b"a".to_vec());
        receiver.record_packet(&p0);

        let report = receiver.report();
        let json = report.to_json();
        assert!(json.contains("\"expected_count\": 2"));
        assert!(json.contains("\"lost_count\": 1"));

        let deserialized = ReceiverReport::from_json(&json).expect("parse json");
        assert_eq!(report, deserialized);
    }
}
