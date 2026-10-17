//! CCSDS Space Packet Primary Header Parser and Sequence Tracker (SPEC §14, §5, §8).
//!
//! Provides a zero-dependency in-tree parser for the 6-octet CCSDS Space Packet Primary Header
//! and an independent per-APID sequence tracker as defined in CCSDS 133.0-B-2.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14, RER implements limited, explicitly documented parsing of the
//! 6-octet Space Packet primary header and per-APID sequence tracking. RER does not claim full
//! CCSDS compatibility, conformance testing, or support for lower-layer link protocols (e.g. TM/TC/AOS
//! transfer frames), secondary headers, or higher-layer protocols (CFDP, BP, LTP) without appropriate
//! conformance evidence.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::ByteOrder;
use crate::diagnostics::{SequenceState, SequenceTrackingEvent};

/// CCSDS Space Packet Primary Header length in octets (fixed 6 octets / 48 bits).
pub const CCSDS_PRIMARY_HEADER_LEN: usize = 6;

/// Reserved CCSDS idle/fill packet APID (2047 / 0x7FF).
pub const CCSDS_IDLE_APID: u16 = 2047;

/// CCSDS Packet Sequence Count modulus (2^14 = 16384).
pub const CCSDS_SEQUENCE_MODULUS: u64 = 16384;

/// Parsed representation of the 6-octet CCSDS Space Packet Primary Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CcsdsPrimaryHeader {
    /// 3-bit Packet Version Number (bits 0–2 of Packet Identification word; must be 0 for CCSDS Space Packets).
    pub version: u8,
    /// 1-bit Packet Type (bit 3 of Packet Identification word; 0 = Telemetry, 1 = Telecommand).
    pub packet_type: u8,
    /// 1-bit Secondary Header Flag (bit 4 of Packet Identification word; true = secondary header present).
    pub secondary_header_flag: bool,
    /// 11-bit Application Process Identifier (APID, bits 5–15 of Packet Identification word, 0..=2047).
    pub apid: u16,
    /// 2-bit Sequence Flags / Grouping Flags (bits 16–17 of primary header, bits 0–1 of Sequence Control word).
    ///
    /// - `00` (0): Continuation segment of fragmented data.
    /// - `01` (1): First segment of fragmented data.
    /// - `10` (2): Last segment of fragmented data.
    /// - `11` (3): Unsegmented user data.
    pub sequence_flags: u8,
    /// 14-bit Packet Sequence Count (bits 18–31 of primary header, bits 2–15 of Sequence Control word, 0..=16383).
    pub sequence_count: u16,
    /// 16-bit Packet Data Length field C (bits 32–47 of primary header; declared length of data field minus 1).
    pub packet_data_length: u16,
    /// Total packet length in octets, calculated as `packet_data_length + 7` octets.
    pub total_packet_length: usize,
}

impl CcsdsPrimaryHeader {
    /// Returns true if this packet carries the reserved idle APID (2047).
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.apid == CCSDS_IDLE_APID
    }

    /// Returns true if this packet is a telemetry (TM) packet (type == 0).
    #[must_use]
    pub fn is_telemetry(&self) -> bool {
        self.packet_type == 0
    }

    /// Returns true if this packet is a telecommand (TC) packet (type == 1).
    #[must_use]
    pub fn is_telecommand(&self) -> bool {
        self.packet_type == 1
    }

    /// Returns true if this packet represents unsegmented user data (sequence flags == 3).
    #[must_use]
    pub fn is_unsegmented(&self) -> bool {
        self.sequence_flags == 3
    }

    /// Returns true if the secondary header flag is set.
    #[must_use]
    pub fn has_secondary_header(&self) -> bool {
        self.secondary_header_flag
    }

    /// Returns the declared raw 16-bit packet data length.
    #[must_use]
    pub fn data_length(&self) -> u16 {
        self.packet_data_length
    }

    /// Returns the calculated total packet length in octets (packet data length + 7).
    #[must_use]
    pub fn packet_length(&self) -> usize {
        self.total_packet_length
    }

    /// Encodes the 6-octet CCSDS primary header into big-endian byte representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CCSDS_PRIMARY_HEADER_LEN] {
        let mut bytes = [0u8; CCSDS_PRIMARY_HEADER_LEN];

        let word1: u16 = ((u16::from(self.version) & 0x07) << 13)
            | ((u16::from(self.packet_type) & 0x01) << 12)
            | (if self.secondary_header_flag {
                1u16
            } else {
                0u16
            } << 11)
            | (self.apid & 0x07FF);
        bytes[0..2].copy_from_slice(&word1.to_be_bytes());

        let word2: u16 =
            ((u16::from(self.sequence_flags) & 0x03) << 14) | (self.sequence_count & 0x3FFF);
        bytes[2..4].copy_from_slice(&word2.to_be_bytes());

        bytes[4..6].copy_from_slice(&self.packet_data_length.to_be_bytes());
        bytes
    }
}

/// Errors encountered when parsing a CCSDS Space Packet Primary Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CcsdsParseError {
    /// Buffer is shorter than the mandatory 6-octet primary header.
    TruncatedHeader,
    /// 3-bit Packet Version Number is non-zero (unsupported or invalid protocol version).
    InvalidVersion,
    /// Buffer length is less than the declared total packet length (packet data length + 7 bytes).
    LengthMismatch,
}

impl fmt::Display for CcsdsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => {
                write!(
                    f,
                    "CCSDS packet truncated: buffer shorter than 6-byte primary header"
                )
            }
            Self::InvalidVersion => {
                write!(
                    f,
                    "invalid CCSDS packet version: expected 0 for Space Packets"
                )
            }
            Self::LengthMismatch => write!(
                f,
                "CCSDS packet length mismatch: buffer length is less than declared packet data length plus 7 bytes"
            ),
        }
    }
}

impl std::error::Error for CcsdsParseError {}

/// Parses a CCSDS Space Packet Primary Header from a byte slice.
///
/// # Acceptance Rules
/// - Returns [`CcsdsParseError::TruncatedHeader`] if `data.len() < 6`.
/// - Returns [`CcsdsParseError::InvalidVersion`] if the 3-bit packet version is non-zero.
/// - Returns [`CcsdsParseError::LengthMismatch`] if `data.len() < packet_data_length + 7`.
/// - Calculates `total_packet_length` as `packet_data_length + 7` bytes.
///
/// # Errors
/// Returns [`CcsdsParseError`] if the header is truncated, invalid, or length declared exceeds the buffer.
pub fn parse_ccsds_primary_header(data: &[u8]) -> Result<CcsdsPrimaryHeader, CcsdsParseError> {
    if data.len() < CCSDS_PRIMARY_HEADER_LEN {
        return Err(CcsdsParseError::TruncatedHeader);
    }

    let word1 = u16::from_be_bytes([data[0], data[1]]);
    let version = ((word1 >> 13) & 0x07) as u8;
    if version != 0 {
        return Err(CcsdsParseError::InvalidVersion);
    }

    let packet_type = ((word1 >> 12) & 0x01) as u8;
    let secondary_header_flag = ((word1 >> 11) & 0x01) != 0;
    let apid = word1 & 0x07FF;

    let word2 = u16::from_be_bytes([data[2], data[3]]);
    let sequence_flags = ((word2 >> 14) & 0x03) as u8;
    let sequence_count = word2 & 0x3FFF;

    let packet_data_length = u16::from_be_bytes([data[4], data[5]]);
    let total_packet_length = (packet_data_length as usize) + 7;

    if data.len() < total_packet_length {
        return Err(CcsdsParseError::LengthMismatch);
    }

    Ok(CcsdsPrimaryHeader {
        version,
        packet_type,
        secondary_header_flag,
        apid,
        sequence_flags,
        sequence_count,
        packet_data_length,
        total_packet_length,
    })
}

/// Continuity and sequence tracking state for an individual APID modulo 16384.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApidSequenceTracker {
    /// The 11-bit Application Process Identifier.
    pub apid: u16,
    /// Total number of packets evaluated for this APID.
    pub packets_evaluated: u64,
    /// The last observed sequence number for this APID.
    pub last_sequence: Option<u16>,
    /// The highest sequence number observed for this APID.
    pub highest_sequence: Option<u16>,
    /// Cumulative count of missing packets (sequence gaps) detected.
    pub gap_count: u64,
    /// Cumulative count of duplicate packets detected.
    pub duplicate_count: u64,
    /// Cumulative count of out-of-order packets detected.
    pub out_of_order_count: u64,
    /// Cumulative count of rollover events detected modulo 16384.
    pub rollover_count: u64,
    recent_seen_queue: VecDeque<u16>,
    recent_seen_set: HashSet<u16>,
}

impl ApidSequenceTracker {
    /// Creates a new sequence tracker for the given APID.
    #[must_use]
    pub fn new(apid: u16) -> Self {
        Self {
            apid,
            packets_evaluated: 0,
            last_sequence: None,
            highest_sequence: None,
            gap_count: 0,
            duplicate_count: 0,
            out_of_order_count: 0,
            rollover_count: 0,
            recent_seen_queue: VecDeque::with_capacity(1024),
            recent_seen_set: HashSet::with_capacity(1024),
        }
    }

    /// Evaluates a 14-bit sequence count for this APID modulo 16384.
    pub fn record_sequence(&mut self, seq: u16) -> SequenceTrackingEvent {
        let seq = seq % (CCSDS_SEQUENCE_MODULUS as u16);
        self.packets_evaluated += 1;

        let last = match self.last_sequence {
            None => {
                self.last_sequence = Some(seq);
                self.highest_sequence = Some(seq);
                self.remember_seen(seq);
                return SequenceTrackingEvent::Initial {
                    sequence: u64::from(seq),
                };
            }
            Some(l) => l,
        };

        let modulus = CCSDS_SEQUENCE_MODULUS as u32;
        let half_modulus = modulus / 2;
        let seq_u = u32::from(seq);
        let last_u = u32::from(last);

        if seq == last || self.recent_seen_set.contains(&seq) {
            self.duplicate_count += 1;
            return SequenceTrackingEvent::Duplicate {
                sequence: u64::from(seq),
            };
        }

        self.remember_seen(seq);

        if seq > last {
            let dist_forward = seq_u - last_u;
            if dist_forward < half_modulus {
                self.last_sequence = Some(seq);
                if seq > self.highest_sequence.unwrap_or(0) {
                    self.highest_sequence = Some(seq);
                }
                if dist_forward == 1 {
                    SequenceTrackingEvent::InOrder {
                        sequence: u64::from(seq),
                    }
                } else {
                    let missing = u64::from(dist_forward - 1);
                    self.gap_count += missing;
                    let expected = u64::from((last_u + 1) % modulus);
                    SequenceTrackingEvent::Gap {
                        expected,
                        actual: u64::from(seq),
                        missing_count: missing,
                    }
                }
            } else {
                self.out_of_order_count += 1;
                SequenceTrackingEvent::OutOfOrder {
                    sequence: u64::from(seq),
                    previous_highest: u64::from(self.highest_sequence.unwrap_or(last)),
                }
            }
        } else {
            // seq < last
            let dist_backward = last_u - seq_u;
            let dist_rollover = (seq_u + modulus) - last_u;

            if dist_rollover < half_modulus {
                self.rollover_count += 1;
                self.last_sequence = Some(seq);
                self.highest_sequence = Some(seq);
                if dist_rollover == 1 {
                    SequenceTrackingEvent::Rollover {
                        sequence: u64::from(seq),
                        missing_count: 0,
                    }
                } else {
                    let missing = u64::from(dist_rollover - 1);
                    self.gap_count += missing;
                    SequenceTrackingEvent::Rollover {
                        sequence: u64::from(seq),
                        missing_count: missing,
                    }
                }
            } else {
                let _ = dist_backward;
                self.out_of_order_count += 1;
                SequenceTrackingEvent::OutOfOrder {
                    sequence: u64::from(seq),
                    previous_highest: u64::from(self.highest_sequence.unwrap_or(last)),
                }
            }
        }
    }

    fn remember_seen(&mut self, seq: u16) {
        if self.recent_seen_queue.len() >= 2048 {
            if let Some(old) = self.recent_seen_queue.pop_front() {
                self.recent_seen_set.remove(&old);
            }
        }
        self.recent_seen_queue.push_back(seq);
        self.recent_seen_set.insert(seq);
    }

    /// Returns the number of sequence gaps recorded.
    #[must_use]
    pub fn gap_count(&self) -> u64 {
        self.gap_count
    }

    /// Returns the number of duplicate packets recorded.
    #[must_use]
    pub fn duplicate_count(&self) -> u64 {
        self.duplicate_count
    }

    /// Returns the number of out-of-order packets recorded.
    #[must_use]
    pub fn out_of_order_count(&self) -> u64 {
        self.out_of_order_count
    }

    /// Returns the number of sequence rollovers recorded.
    #[must_use]
    pub fn rollover_count(&self) -> u64 {
        self.rollover_count
    }

    /// Returns the number of packets evaluated.
    #[must_use]
    pub fn packets_evaluated(&self) -> u64 {
        self.packets_evaluated
    }

    /// Returns the last sequence number observed, if any.
    #[must_use]
    pub fn last_sequence(&self) -> Option<u16> {
        self.last_sequence
    }

    /// Returns the highest sequence number observed, if any.
    #[must_use]
    pub fn highest_sequence(&self) -> Option<u16> {
        self.highest_sequence
    }
}

/// Multi-APID CCSDS sequence tracker maintaining independent modulo-16384 counters.
#[derive(Debug, Clone)]
pub struct CcsdsSequenceTracker {
    ignore_idle_apid: bool,
    allowed_apids: Option<HashSet<u16>>,
    trackers: HashMap<u16, ApidSequenceTracker>,
}

impl CcsdsSequenceTracker {
    /// Creates a new CCSDS sequence tracker.
    ///
    /// When `ignore_idle_apid` is true, packets with APID 2047 (`0x7FF`) are ignored
    /// and record no sequence continuity gaps or state.
    #[must_use]
    pub fn new(ignore_idle_apid: bool) -> Self {
        Self {
            ignore_idle_apid,
            allowed_apids: None,
            trackers: HashMap::new(),
        }
    }

    /// Creates a new CCSDS sequence tracker with idle packet filtering.
    #[must_use]
    pub fn with_idle_filtering(ignore_idle_apid: bool) -> Self {
        Self::new(ignore_idle_apid)
    }

    /// Builder method configuring idle packet filtering.
    #[must_use]
    pub fn with_idle_packet_filtering(mut self, ignore_idle_apid: bool) -> Self {
        self.ignore_idle_apid = ignore_idle_apid;
        self
    }

    /// Sets whether idle packets (APID 2047) are filtered/ignored.
    pub fn set_ignore_idle_apid(&mut self, ignore: bool) {
        self.ignore_idle_apid = ignore;
    }

    /// Sets whether idle packet filtering is enabled.
    pub fn set_idle_packet_filtering(&mut self, ignore: bool) {
        self.ignore_idle_apid = ignore;
    }

    /// Returns whether idle packet filtering is active.
    #[must_use]
    pub fn is_idle_filtered(&self) -> bool {
        self.ignore_idle_apid
    }

    /// Configures an optional allowlist of APIDs to track.
    #[must_use]
    pub fn with_allowed_apids(mut self, apids: impl IntoIterator<Item = u16>) -> Self {
        self.allowed_apids = Some(apids.into_iter().collect());
        self
    }

    /// Sets an optional allowlist of APIDs to track.
    pub fn set_allowed_apids(&mut self, apids: Option<Vec<u16>>) {
        self.allowed_apids = apids.map(|list| list.into_iter().collect());
    }

    /// Evaluates sequence progression for the specified APID and sequence count.
    ///
    /// If `ignore_idle_apid` is true and `apid == 2047`, returns `None` and records no state.
    pub fn record_sequence(
        &mut self,
        apid: u16,
        sequence_count: u16,
    ) -> Option<SequenceTrackingEvent> {
        if self.ignore_idle_apid && apid == CCSDS_IDLE_APID {
            return None;
        }
        if let Some(ref allowed) = self.allowed_apids {
            if !allowed.contains(&apid) {
                return None;
            }
        }

        let tracker = self
            .trackers
            .entry(apid)
            .or_insert_with(|| ApidSequenceTracker::new(apid));
        Some(tracker.record_sequence(sequence_count))
    }

    /// Alias for `record_sequence`.
    pub fn track_sequence(
        &mut self,
        apid: u16,
        sequence_count: u16,
    ) -> Option<SequenceTrackingEvent> {
        self.record_sequence(apid, sequence_count)
    }

    /// Alias for `record_sequence`.
    pub fn process_sequence(
        &mut self,
        apid: u16,
        sequence_count: u16,
    ) -> Option<SequenceTrackingEvent> {
        self.record_sequence(apid, sequence_count)
    }

    /// Records sequence progression from a parsed CCSDS primary header.
    pub fn record_header(&mut self, header: &CcsdsPrimaryHeader) -> Option<SequenceTrackingEvent> {
        self.record_sequence(header.apid, header.sequence_count)
    }

    /// Processes a parsed CCSDS primary header.
    pub fn process_header(&mut self, header: &CcsdsPrimaryHeader) -> Option<SequenceTrackingEvent> {
        self.record_sequence(header.apid, header.sequence_count)
    }

    /// Parses and processes a raw CCSDS packet buffer.
    pub fn process_packet(&mut self, packet: &[u8]) -> Option<SequenceTrackingEvent> {
        let header = parse_ccsds_primary_header(packet).ok()?;
        self.process_header(&header)
    }

    /// Parses and processes a raw CCSDS packet buffer, returning any parse error encountered.
    ///
    /// # Errors
    /// Returns [`CcsdsParseError`] if the packet is malformed.
    pub fn process_packet_checked(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<SequenceTrackingEvent>, CcsdsParseError> {
        let header = parse_ccsds_primary_header(packet)?;
        Ok(self.process_header(&header))
    }

    /// Returns the sequence gap count for a specific APID.
    #[must_use]
    pub fn gap_count(&self, apid: u16) -> u64 {
        self.trackers.get(&apid).map_or(0, |t| t.gap_count)
    }

    /// Returns the duplicate count for a specific APID.
    #[must_use]
    pub fn duplicate_count(&self, apid: u16) -> u64 {
        self.trackers.get(&apid).map_or(0, |t| t.duplicate_count)
    }

    /// Returns the out-of-order count for a specific APID.
    #[must_use]
    pub fn out_of_order_count(&self, apid: u16) -> u64 {
        self.trackers.get(&apid).map_or(0, |t| t.out_of_order_count)
    }

    /// Returns the rollover count for a specific APID.
    #[must_use]
    pub fn rollover_count(&self, apid: u16) -> u64 {
        self.trackers.get(&apid).map_or(0, |t| t.rollover_count)
    }

    /// Returns the number of packets evaluated for a specific APID.
    #[must_use]
    pub fn packets_evaluated(&self, apid: u16) -> u64 {
        self.trackers.get(&apid).map_or(0, |t| t.packets_evaluated)
    }

    /// Alias for `packets_evaluated`.
    #[must_use]
    pub fn packet_count(&self, apid: u16) -> u64 {
        self.packets_evaluated(apid)
    }

    /// Returns the last sequence number observed for a specific APID.
    #[must_use]
    pub fn last_sequence(&self, apid: u16) -> Option<u16> {
        self.trackers.get(&apid).and_then(|t| t.last_sequence)
    }

    /// Returns the highest sequence number observed for a specific APID.
    #[must_use]
    pub fn highest_sequence(&self, apid: u16) -> Option<u16> {
        self.trackers.get(&apid).and_then(|t| t.highest_sequence)
    }

    /// Returns a reference to the tracker state for a specific APID, if any.
    #[must_use]
    pub fn get(&self, apid: u16) -> Option<&ApidSequenceTracker> {
        self.trackers.get(&apid)
    }

    /// Returns a reference to the tracker state for a specific APID, if any.
    #[must_use]
    pub fn apid_tracker(&self, apid: u16) -> Option<&ApidSequenceTracker> {
        self.trackers.get(&apid)
    }

    /// Returns the total gap count across all tracked APIDs.
    #[must_use]
    pub fn total_gap_count(&self) -> u64 {
        self.trackers.values().map(|t| t.gap_count).sum()
    }

    /// Returns the total duplicate count across all tracked APIDs.
    #[must_use]
    pub fn total_duplicate_count(&self) -> u64 {
        self.trackers.values().map(|t| t.duplicate_count).sum()
    }

    /// Returns the total out-of-order count across all tracked APIDs.
    #[must_use]
    pub fn total_out_of_order_count(&self) -> u64 {
        self.trackers.values().map(|t| t.out_of_order_count).sum()
    }

    /// Returns the total packets evaluated across all tracked APIDs.
    #[must_use]
    pub fn total_packets_evaluated(&self) -> u64 {
        self.trackers.values().map(|t| t.packets_evaluated).sum()
    }

    /// Returns a sorted list of APIDs currently tracked.
    #[must_use]
    pub fn tracked_apids(&self) -> Vec<u16> {
        let mut apids: Vec<u16> = self.trackers.keys().copied().collect();
        apids.sort_unstable();
        apids
    }

    /// Returns a sorted list of APIDs currently tracked (alias for `tracked_apids`).
    #[must_use]
    pub fn apids(&self) -> Vec<u16> {
        self.tracked_apids()
    }

    /// Resets all per-APID sequence tracking states.
    pub fn reset(&mut self) {
        self.trackers.clear();
    }

    /// Resets sequence tracking state for a specific APID.
    pub fn reset_apid(&mut self, apid: u16) {
        self.trackers.remove(&apid);
    }

    /// Captures a point-in-time snapshot of the sequence state for an APID (SPEC §8).
    #[must_use]
    pub fn apid_state(&self, stream_id: &str, apid: u16) -> Option<SequenceState> {
        let t = self.trackers.get(&apid)?;
        Some(SequenceState {
            stream_id: format!("{stream_id}:apid_{apid}"),
            enabled: true,
            offset: Some(2),
            width: Some(2),
            byte_order: Some(ByteOrder::BigEndian),
            rollover_threshold: Some(CCSDS_SEQUENCE_MODULUS),
            packets_evaluated: t.packets_evaluated,
            last_sequence: t.last_sequence.map(u64::from),
            highest_sequence: t.highest_sequence.map(u64::from),
            gap_count: t.gap_count,
            duplicate_count: t.duplicate_count,
            out_of_order_count: t.out_of_order_count,
            rollover_count: t.rollover_count,
            hex_preview_enabled: false,
            ascii_preview_enabled: false,
            max_preview_bytes: 64,
        })
    }
}

impl Default for CcsdsSequenceTracker {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_packet(
        version: u8,
        packet_type: u8,
        sec_header: bool,
        apid: u16,
        seq_flags: u8,
        seq_count: u16,
        payload_len: usize,
    ) -> Vec<u8> {
        assert!(payload_len >= 1, "CCSDS payload data length is at least 1");
        let data_len_field = (payload_len - 1) as u16;

        let header = CcsdsPrimaryHeader {
            version,
            packet_type,
            secondary_header_flag: sec_header,
            apid,
            sequence_flags: seq_flags,
            sequence_count: seq_count,
            packet_data_length: data_len_field,
            total_packet_length: payload_len + 6,
        };

        let mut buf = Vec::with_capacity(payload_len + 6);
        buf.extend_from_slice(&header.to_bytes());
        buf.resize(payload_len + 6, 0xAA);
        buf
    }

    #[test]
    fn test_parse_valid_ccsds_primary_header() {
        // APID 100, TC packet (type 1), secondary header present, unsegmented (flags 3), seq 42, payload len 10
        let buf = build_test_packet(0, 1, true, 100, 3, 42, 10);
        assert_eq!(buf.len(), 16);

        let parsed = parse_ccsds_primary_header(&buf).expect("failed to parse valid header");
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.packet_type, 1);
        assert!(parsed.secondary_header_flag);
        assert_eq!(parsed.apid, 100);
        assert_eq!(parsed.sequence_flags, 3);
        assert_eq!(parsed.sequence_count, 42);
        assert_eq!(parsed.packet_data_length, 9);
        assert_eq!(parsed.total_packet_length, 16); // 9 + 7 = 16
        assert!(parsed.is_telecommand());
        assert!(!parsed.is_telemetry());
        assert!(parsed.is_unsegmented());
        assert!(!parsed.is_idle());
    }

    #[test]
    fn test_parse_truncated_header() {
        // Less than 6 octets
        for len in 0..6 {
            let buf = vec![0u8; len];
            let res = parse_ccsds_primary_header(&buf);
            assert_eq!(res, Err(CcsdsParseError::TruncatedHeader));
        }
    }

    #[test]
    fn test_parse_invalid_version() {
        // Non-zero 3-bit version (e.g. version 1)
        let mut buf = build_test_packet(0, 0, false, 42, 3, 0, 10);
        // Change version bits (bits 0..2 of first byte) to 1 (0b0010_0000 = 0x20)
        buf[0] = (buf[0] & 0x1F) | (1 << 5);

        let res = parse_ccsds_primary_header(&buf);
        assert_eq!(res, Err(CcsdsParseError::InvalidVersion));

        // Test all other non-zero versions (2 through 7)
        for v in 2..=7 {
            buf[0] = (buf[0] & 0x1F) | (v << 5);
            assert_eq!(
                parse_ccsds_primary_header(&buf),
                Err(CcsdsParseError::InvalidVersion)
            );
        }
    }

    #[test]
    fn test_parse_length_mismatch() {
        // Declared data length 9 -> total packet length 16 bytes.
        // Buffer has only 15 bytes -> LengthMismatch.
        let buf = build_test_packet(0, 0, false, 50, 3, 1, 10);
        assert_eq!(buf.len(), 16);

        // Truncate payload by 1 byte
        let truncated = &buf[..15];
        let res = parse_ccsds_primary_header(truncated);
        assert_eq!(res, Err(CcsdsParseError::LengthMismatch));

        // Exactly 6 bytes with declared length > 0
        let header_only = &buf[..6];
        let res2 = parse_ccsds_primary_header(header_only);
        assert_eq!(res2, Err(CcsdsParseError::LengthMismatch));
    }

    #[test]
    fn test_parse_buffer_exceeding_total_packet_length() {
        // In TCP or concatenated streams, buffer may contain multiple packets
        let buf = build_test_packet(0, 0, false, 50, 3, 1, 10);
        let mut extended = buf.clone();
        extended.extend_from_slice(&[1, 2, 3, 4, 5]);

        let parsed = parse_ccsds_primary_header(&extended).expect("should parse first packet");
        assert_eq!(parsed.total_packet_length, 16);
    }

    #[test]
    fn test_independent_apid_sequence_tracking() {
        let mut tracker = CcsdsSequenceTracker::new(false);

        // APID 10 initial packet
        assert_eq!(
            tracker.record_sequence(10, 0),
            Some(SequenceTrackingEvent::Initial { sequence: 0 })
        );
        // APID 20 initial packet
        assert_eq!(
            tracker.record_sequence(20, 100),
            Some(SequenceTrackingEvent::Initial { sequence: 100 })
        );

        // APID 10 receives seq 1 (in-order)
        assert_eq!(
            tracker.record_sequence(10, 1),
            Some(SequenceTrackingEvent::InOrder { sequence: 1 })
        );

        // APID 10 receives seq 4 (missing 2 and 3: gap of 2)
        assert_eq!(
            tracker.record_sequence(10, 4),
            Some(SequenceTrackingEvent::Gap {
                expected: 2,
                actual: 4,
                missing_count: 2,
            })
        );
        assert_eq!(tracker.gap_count(10), 2);

        // APID 10 receives seq 4 again (duplicate)
        assert_eq!(
            tracker.record_sequence(10, 4),
            Some(SequenceTrackingEvent::Duplicate { sequence: 4 })
        );
        assert_eq!(tracker.duplicate_count(10), 1);

        // Verify APID 20 state is completely unaltered!
        assert_eq!(tracker.gap_count(20), 0);
        assert_eq!(tracker.duplicate_count(20), 0);
        assert_eq!(tracker.last_sequence(20), Some(100));
        assert_eq!(tracker.packets_evaluated(20), 1);

        // Now APID 20 receives seq 101 (in-order)
        assert_eq!(
            tracker.record_sequence(20, 101),
            Some(SequenceTrackingEvent::InOrder { sequence: 101 })
        );
        assert_eq!(tracker.gap_count(20), 0);
        assert_eq!(tracker.duplicate_count(20), 0);
        assert_eq!(tracker.last_sequence(20), Some(101));
    }

    #[test]
    fn test_modulo_16384_rollover() {
        let mut tracker = CcsdsSequenceTracker::new(false);

        // Sequence near modulus boundary
        tracker.record_sequence(1, 16383);
        assert_eq!(tracker.last_sequence(1), Some(16383));

        // Rollover to 0 (in-order)
        let ev = tracker.record_sequence(1, 0);
        assert_eq!(
            ev,
            Some(SequenceTrackingEvent::Rollover {
                sequence: 0,
                missing_count: 0
            })
        );
        assert_eq!(tracker.gap_count(1), 0);
        assert_eq!(tracker.rollover_count(1), 1);
        assert_eq!(tracker.last_sequence(1), Some(0));

        // Test rollover with gap on fresh tracker
        let mut tracker2 = CcsdsSequenceTracker::new(false);
        tracker2.record_sequence(1, 16380);

        // Rollover with gap: from 16380 to 2 (missing 16381, 16382, 16383, 0, 1: 5 missing)
        let ev_gap = tracker2.record_sequence(1, 2);
        assert_eq!(
            ev_gap,
            Some(SequenceTrackingEvent::Rollover {
                sequence: 2,
                missing_count: 5
            })
        );
        assert_eq!(tracker2.gap_count(1), 5);
        assert_eq!(tracker2.rollover_count(1), 1);
        assert_eq!(tracker2.last_sequence(1), Some(2));
    }

    #[test]
    fn test_idle_packet_filtering_ignores_apid_2047() {
        let mut tracker = CcsdsSequenceTracker::new(true);

        // Normal APID 50
        assert_eq!(
            tracker.record_sequence(50, 0),
            Some(SequenceTrackingEvent::Initial { sequence: 0 })
        );

        // Idle packets on APID 2047
        assert_eq!(tracker.record_sequence(2047, 0), None);
        assert_eq!(tracker.record_sequence(2047, 50), None);
        assert_eq!(tracker.record_sequence(2047, 50), None);
        assert_eq!(tracker.record_sequence(2047, 100), None);

        // APID 2047 records no sequence continuity gaps or packets
        assert_eq!(tracker.gap_count(2047), 0);
        assert_eq!(tracker.duplicate_count(2047), 0);
        assert_eq!(tracker.packets_evaluated(2047), 0);
        assert_eq!(tracker.last_sequence(2047), None);
        assert_eq!(tracker.total_gap_count(), 0);

        // APID 50 receives in-order seq 1
        assert_eq!(
            tracker.record_sequence(50, 1),
            Some(SequenceTrackingEvent::InOrder { sequence: 1 })
        );
        assert_eq!(tracker.gap_count(50), 0);
    }

    #[test]
    fn test_idle_packet_not_ignored_when_filter_disabled() {
        let mut tracker = CcsdsSequenceTracker::new(false);

        // Idle packets are tracked normally when filtering is disabled
        assert_eq!(
            tracker.record_sequence(2047, 0),
            Some(SequenceTrackingEvent::Initial { sequence: 0 })
        );
        assert_eq!(
            tracker.record_sequence(2047, 5),
            Some(SequenceTrackingEvent::Gap {
                expected: 1,
                actual: 5,
                missing_count: 4,
            })
        );
        assert_eq!(tracker.gap_count(2047), 4);
        assert_eq!(tracker.packets_evaluated(2047), 2);
    }
}
