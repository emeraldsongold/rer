//! In-tree MAVLink packet header parser (SPEC §14, §8, Task RER-F-050).
//!
//! Provides a zero-dependency in-tree packet header parser for MAVLink 1 and MAVLink 2
//! as defined in the MAVLink Serialization Specification and SPEC §14.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14, RER implements passive metadata inspection of MAVLink
//! packet headers. RER does not implement complete message payload decoding across dialect-specific
//! XML message definitions, autonomous vehicle control, autopilot session management, or
//! end-to-end cryptographic signature generation. Forwarded datagrams are transmitted byte-unmodified.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::ByteOrder;
use crate::diagnostics::{SequenceState, SequenceTrackingEvent};

/// Minimal header length for MAVLink 1 packets in octets (STX, len, seq, sysid, compid, msgid).
pub const MAVLINK_V1_HEADER_LEN: usize = 6;
pub const MAVLINK_V1_MIN_HEADER_LEN: usize = 6;

/// Minimal header length for MAVLink 2 packets in octets (STX, len, incompat, compat, seq, sysid, compid, msgid[3]).
pub const MAVLINK_V2_HEADER_LEN: usize = 10;
pub const MAVLINK_V2_MIN_HEADER_LEN: usize = 10;

/// MAVLink 1 total framing overhead (6 header + 2 checksum octets).
pub const MAVLINK_V1_OVERHEAD: usize = 8;
pub const MAVLINK_V1_FRAMING_OVERHEAD: usize = 8;

/// MAVLink 2 total framing overhead for unsigned packets (10 header + 2 checksum octets).
pub const MAVLINK_V2_OVERHEAD_UNSIGNED: usize = 12;
pub const MAVLINK_V2_FRAMING_OVERHEAD_UNSIGNED: usize = 12;

/// MAVLink 2 total framing overhead for signed packets (10 header + 2 checksum + 13 signature octets).
pub const MAVLINK_V2_OVERHEAD_SIGNED: usize = 25;
pub const MAVLINK_V2_FRAMING_OVERHEAD_SIGNED: usize = 25;

/// MAVLink 2 signature block length in octets.
pub const MAVLINK_SIGNATURE_LEN: usize = 13;

/// MAVLink 1 protocol magic start byte.
pub const MAVLINK_STX_V1: u8 = 0xFE;
pub const MAVLINK_V1_STX: u8 = 0xFE;
pub const MAVLINK_MAGIC_V1: u8 = 0xFE;

/// MAVLink 2 protocol magic start byte.
pub const MAVLINK_STX_V2: u8 = 0xFD;
pub const MAVLINK_V2_STX: u8 = 0xFD;
pub const MAVLINK_MAGIC_V2: u8 = 0xFD;

/// Incompatibility flag bit 0: signed packet indicator.
pub const MAVLINK_IFLAG_SIGNED: u8 = 0x01;

/// Known MAVLink 2 incompatibility flag mask.
pub const MAVLINK_KNOWN_INCOMPAT_FLAGS: u8 = MAVLINK_IFLAG_SIGNED;

/// Protocol version identifier for MAVLink packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MavlinkVersion {
    /// MAVLink 1 packet (magic 0xFE, 6-byte header, 8-bit message ID).
    V1,
    /// MAVLink 2 packet (magic 0xFD, 10-byte header, 24-bit message ID).
    V2,
}

impl MavlinkVersion {
    /// Returns true if this version is MAVLink 1.
    #[must_use]
    pub const fn is_v1(&self) -> bool {
        matches!(self, Self::V1)
    }

    /// Returns true if this version is MAVLink 2.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        matches!(self, Self::V2)
    }
}

impl fmt::Display for MavlinkVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
        }
    }
}

/// Errors encountered when parsing a MAVLink packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MavlinkParseError {
    /// Input buffer does not begin with magic byte 0xFE or 0xFD.
    InvalidMagicMarker,
    /// Input buffer is shorter than minimal header length or declared total packet length.
    TruncatedPacket,
}

impl MavlinkParseError {
    pub const INVALID_MAGIC: Self = Self::InvalidMagicMarker;
    pub const TRUNCATED: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const InvalidMagic: Self = Self::InvalidMagicMarker;
    #[allow(non_upper_case_globals)]
    pub const Truncated: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const TruncatedHeader: Self = Self::TruncatedPacket;

    /// Returns true if the error indicates an invalid magic marker.
    #[must_use]
    pub const fn is_invalid_magic_marker(&self) -> bool {
        matches!(self, Self::InvalidMagicMarker)
    }

    /// Alias for [`is_invalid_magic_marker`].
    #[must_use]
    pub const fn is_invalid_magic(&self) -> bool {
        matches!(self, Self::InvalidMagicMarker)
    }

    /// Returns true if the error indicates a truncated packet or header.
    #[must_use]
    pub const fn is_truncated_packet(&self) -> bool {
        matches!(self, Self::TruncatedPacket)
    }

    /// Alias for [`is_truncated_packet`].
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::TruncatedPacket)
    }
}

impl fmt::Display for MavlinkParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagicMarker => {
                write!(
                    f,
                    "invalid magic marker: expected 0xFE (MAVLink 1) or 0xFD (MAVLink 2)"
                )
            }
            Self::TruncatedPacket => {
                write!(
                    f,
                    "truncated packet: buffer shorter than header length or declared total length"
                )
            }
        }
    }
}

impl std::error::Error for MavlinkParseError {}

/// Parse warning encountered when evaluating a MAVLink packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MavlinkParseWarning {
    /// Packet carries unknown incompatibility flag bits.
    UnknownIncompatibilityFlags(u8),
    /// Packet carries unknown incompatibility flag bits (alias).
    UnknownIncompatibilityFlagBits(u8),
}

impl MavlinkParseWarning {
    /// Returns the unknown incompatibility flag bitfield.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        match self {
            Self::UnknownIncompatibilityFlags(f) | Self::UnknownIncompatibilityFlagBits(f) => *f,
        }
    }

    /// Returns true if this warning is for unknown incompatibility flags.
    #[must_use]
    pub const fn is_unknown_incompatibility_flags(&self) -> bool {
        true
    }

    /// Alias for [`is_unknown_incompatibility_flags`].
    #[must_use]
    pub const fn is_unknown_incompat_flags(&self) -> bool {
        true
    }
}

impl fmt::Display for MavlinkParseWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownIncompatibilityFlags(flags)
            | Self::UnknownIncompatibilityFlagBits(flags) => {
                write!(f, "unknown incompatibility flags: 0x{:02X}", flags)
            }
        }
    }
}

impl std::error::Error for MavlinkParseWarning {}

/// Evaluation parse status distinguishing valid packets, parse warnings, and errors without panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MavlinkParseStatus {
    /// Packet is valid with no parse warnings.
    Valid,
    /// Packet parsed successfully but carries a warning (e.g. unknown incompatibility flags).
    Warning(MavlinkParseWarning),
    /// Buffer does not begin with a valid MAVLink magic start byte (0xFE or 0xFD).
    InvalidMagic,
    /// Buffer is shorter than minimal header length or declared total packet length.
    Truncated,
}

impl MavlinkParseStatus {
    /// Returns true if the status is [`Self::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns true if the status is [`Self::Warning`].
    #[must_use]
    pub const fn is_warning(&self) -> bool {
        matches!(self, Self::Warning(_))
    }

    /// Alias for [`is_warning`].
    #[must_use]
    pub const fn has_warning(&self) -> bool {
        matches!(self, Self::Warning(_))
    }

    /// Returns the inner warning if the status is [`Self::Warning`].
    #[must_use]
    pub const fn warning(&self) -> Option<MavlinkParseWarning> {
        match self {
            Self::Warning(w) => Some(*w),
            _ => None,
        }
    }

    /// Returns true if the status is [`Self::InvalidMagic`].
    #[must_use]
    pub const fn is_invalid_magic(&self) -> bool {
        matches!(self, Self::InvalidMagic)
    }

    /// Returns true if the status is [`Self::Truncated`].
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated)
    }

    /// Returns true if the status is not valid and not a warning.
    #[must_use]
    pub const fn is_invalid(&self) -> bool {
        !self.is_valid() && !self.is_warning()
    }
}

impl PartialEq<MavlinkParseWarning> for MavlinkParseStatus {
    fn eq(&self, other: &MavlinkParseWarning) -> bool {
        match self {
            Self::Warning(w) => w == other,
            _ => false,
        }
    }
}

impl PartialEq<MavlinkParseStatus> for MavlinkParseWarning {
    fn eq(&self, other: &MavlinkParseStatus) -> bool {
        other == self
    }
}

impl From<MavlinkParseWarning> for MavlinkParseStatus {
    fn from(warning: MavlinkParseWarning) -> Self {
        Self::Warning(warning)
    }
}

impl fmt::Display for MavlinkParseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Warning(w) => write!(f, "warning: {w}"),
            Self::InvalidMagic => write!(f, "invalid_magic"),
            Self::Truncated => write!(f, "truncated"),
        }
    }
}

/// Parsed representation of a MAVLink 1 or MAVLink 2 packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MavlinkHeader {
    /// Protocol version (V1 or V2).
    pub version: MavlinkVersion,
    /// Length of payload in octets (0 to 255).
    pub payload_length: u8,
    /// Incompatibility flags bitfield (0 for MAVLink 1).
    pub incompat_flags: u8,
    /// Compatibility flags bitfield (0 for MAVLink 1).
    pub compat_flags: u8,
    /// Packet sequence number (0 to 255, wrapping modulo 256).
    pub sequence: u8,
    /// Sending vehicle/node system ID (1 to 255).
    pub system_id: u8,
    /// Sending subsystem component ID (1 to 255).
    pub component_id: u8,
    /// Message schema identifier (8-bit for v1, 24-bit for v2).
    pub message_id: u32,
    /// True if the packet includes a 13-octet signature block.
    pub is_signed: bool,
    /// Calculated total packet length in octets including header, payload, checksum, and signature.
    pub total_packet_length: usize,
}

impl MavlinkHeader {
    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> MavlinkVersion {
        self.version
    }

    /// Returns true if this packet is MAVLink 1.
    #[must_use]
    pub const fn is_v1(&self) -> bool {
        self.version.is_v1()
    }

    /// Returns true if this packet is MAVLink 2.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        self.version.is_v2()
    }

    /// Returns the payload length in octets.
    #[must_use]
    pub const fn payload_length(&self) -> u8 {
        self.payload_length
    }

    /// Alias for [`payload_length`].
    #[must_use]
    pub const fn len(&self) -> u8 {
        self.payload_length
    }

    /// Returns true if the payload length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.payload_length == 0
    }

    /// Returns the incompatibility flags bitfield.
    #[must_use]
    pub const fn incompat_flags(&self) -> u8 {
        self.incompat_flags
    }

    /// Returns the compatibility flags bitfield.
    #[must_use]
    pub const fn compat_flags(&self) -> u8 {
        self.compat_flags
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u8 {
        self.sequence
    }

    /// Alias for [`sequence`].
    #[must_use]
    pub const fn sequence_number(&self) -> u8 {
        self.sequence
    }

    /// Alias for [`sequence`].
    #[must_use]
    pub const fn seq(&self) -> u8 {
        self.sequence
    }

    /// Returns the system ID.
    #[must_use]
    pub const fn system_id(&self) -> u8 {
        self.system_id
    }

    /// Alias for [`system_id`].
    #[must_use]
    pub const fn sysid(&self) -> u8 {
        self.system_id
    }

    /// Returns the component ID.
    #[must_use]
    pub const fn component_id(&self) -> u8 {
        self.component_id
    }

    /// Alias for [`component_id`].
    #[must_use]
    pub const fn compid(&self) -> u8 {
        self.component_id
    }

    /// Returns the message ID.
    #[must_use]
    pub const fn message_id(&self) -> u32 {
        self.message_id
    }

    /// Alias for [`message_id`].
    #[must_use]
    pub const fn msgid(&self) -> u32 {
        self.message_id
    }

    /// Returns true if the packet carries a signature block.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.is_signed
    }

    /// Returns the calculated total packet length in octets.
    #[must_use]
    pub const fn total_packet_length(&self) -> usize {
        self.total_packet_length
    }

    /// Alias for [`total_packet_length`].
    #[must_use]
    pub const fn packet_length(&self) -> usize {
        self.total_packet_length
    }

    /// Checks for parse warnings, returning [`MavlinkParseWarning`] if unknown incompatibility flag bits are set.
    #[must_use]
    pub const fn warning(&self) -> Option<MavlinkParseWarning> {
        if self.version.is_v2() && (self.incompat_flags & !MAVLINK_IFLAG_SIGNED) != 0 {
            Some(MavlinkParseWarning::UnknownIncompatibilityFlags(
                self.incompat_flags & !MAVLINK_IFLAG_SIGNED,
            ))
        } else {
            None
        }
    }

    /// Returns true if this packet has any parse warning.
    #[must_use]
    pub const fn has_warning(&self) -> bool {
        self.warning().is_some()
    }

    /// Serializes the header into raw octets.
    #[must_use]
    pub fn to_header_bytes(&self) -> Vec<u8> {
        match self.version {
            MavlinkVersion::V1 => encode_mavlink1_header(
                self.payload_length,
                self.sequence,
                self.system_id,
                self.component_id,
                (self.message_id & 0xFF) as u8,
            )
            .to_vec(),
            MavlinkVersion::V2 => encode_mavlink2_header(
                self.payload_length,
                self.incompat_flags,
                self.compat_flags,
                self.sequence,
                self.system_id,
                self.component_id,
                self.message_id,
            )
            .to_vec(),
        }
    }

    /// Alias for [`to_header_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_header_bytes()
    }
}

impl fmt::Display for MavlinkHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MAVLink {:?} [seq={}, sys={}, comp={}, msg={}, len={}, total={}]",
            self.version,
            self.sequence,
            self.system_id,
            self.component_id,
            self.message_id,
            self.payload_length,
            self.total_packet_length
        )
    }
}

/// Encodes a 6-byte MAVLink 1 header into a byte array.
#[must_use]
pub fn encode_mavlink1_header(
    payload_len: u8,
    sequence: u8,
    system_id: u8,
    component_id: u8,
    message_id: u8,
) -> [u8; MAVLINK_V1_HEADER_LEN] {
    [
        MAVLINK_STX_V1,
        payload_len,
        sequence,
        system_id,
        component_id,
        message_id,
    ]
}

/// Encodes a 10-byte MAVLink 2 header into a byte array.
#[must_use]
pub fn encode_mavlink2_header(
    payload_len: u8,
    incompat_flags: u8,
    compat_flags: u8,
    sequence: u8,
    system_id: u8,
    component_id: u8,
    message_id: u32,
) -> [u8; MAVLINK_V2_HEADER_LEN] {
    [
        MAVLINK_STX_V2,
        payload_len,
        incompat_flags,
        compat_flags,
        sequence,
        system_id,
        component_id,
        (message_id & 0xFF) as u8,
        ((message_id >> 8) & 0xFF) as u8,
        ((message_id >> 16) & 0xFF) as u8,
    ]
}

/// Parses a MAVLink 1 or MAVLink 2 packet header from an input buffer.
///
/// # Errors
///
/// Returns [`MavlinkParseError::InvalidMagicMarker`] if the first byte is neither `0xFE` nor `0xFD`.
/// Returns [`MavlinkParseError::TruncatedPacket`] if the buffer is shorter than the minimal header
/// length (6 bytes for v1, 10 bytes for v2) or shorter than the declared total packet length.
pub fn parse_mavlink_header(data: &[u8]) -> Result<MavlinkHeader, MavlinkParseError> {
    if data.is_empty() {
        return Err(MavlinkParseError::TruncatedPacket);
    }

    let magic = data[0];
    match magic {
        MAVLINK_STX_V1 => {
            if data.len() < MAVLINK_V1_HEADER_LEN {
                return Err(MavlinkParseError::TruncatedPacket);
            }
            let payload_length = data[1];
            let sequence = data[2];
            let system_id = data[3];
            let component_id = data[4];
            let message_id = u32::from(data[5]);
            let total_packet_length = usize::from(payload_length) + MAVLINK_V1_OVERHEAD;

            if data.len() < total_packet_length {
                return Err(MavlinkParseError::TruncatedPacket);
            }

            Ok(MavlinkHeader {
                version: MavlinkVersion::V1,
                payload_length,
                incompat_flags: 0,
                compat_flags: 0,
                sequence,
                system_id,
                component_id,
                message_id,
                is_signed: false,
                total_packet_length,
            })
        }
        MAVLINK_STX_V2 => {
            if data.len() < MAVLINK_V2_HEADER_LEN {
                return Err(MavlinkParseError::TruncatedPacket);
            }
            let payload_length = data[1];
            let incompat_flags = data[2];
            let compat_flags = data[3];
            let sequence = data[4];
            let system_id = data[5];
            let component_id = data[6];
            let message_id =
                u32::from(data[7]) | (u32::from(data[8]) << 8) | (u32::from(data[9]) << 16);
            let is_signed = (incompat_flags & MAVLINK_IFLAG_SIGNED) != 0;
            let overhead = if is_signed {
                MAVLINK_V2_OVERHEAD_SIGNED
            } else {
                MAVLINK_V2_OVERHEAD_UNSIGNED
            };
            let total_packet_length = usize::from(payload_length) + overhead;

            if data.len() < total_packet_length {
                return Err(MavlinkParseError::TruncatedPacket);
            }

            Ok(MavlinkHeader {
                version: MavlinkVersion::V2,
                payload_length,
                incompat_flags,
                compat_flags,
                sequence,
                system_id,
                component_id,
                message_id,
                is_signed,
                total_packet_length,
            })
        }
        _ => Err(MavlinkParseError::InvalidMagicMarker),
    }
}

/// Evaluates raw payload bytes, returning both [`MavlinkParseStatus`] and optional [`MavlinkHeader`].
///
/// If the packet is a MAVLink 2 packet with unknown incompatibility flag bits, returns
/// [`MavlinkParseStatus::Warning`] while preserving the extracted [`MavlinkHeader`].
#[must_use]
pub fn evaluate_mavlink_header(data: &[u8]) -> (MavlinkParseStatus, Option<MavlinkHeader>) {
    if data.is_empty() {
        return (MavlinkParseStatus::Truncated, None);
    }

    let magic = data[0];
    if magic != MAVLINK_STX_V1 && magic != MAVLINK_STX_V2 {
        return (MavlinkParseStatus::InvalidMagic, None);
    }

    match parse_mavlink_header(data) {
        Ok(header) => {
            if let Some(warning) = header.warning() {
                (MavlinkParseStatus::Warning(warning), Some(header))
            } else {
                (MavlinkParseStatus::Valid, Some(header))
            }
        }
        Err(err) => match err {
            MavlinkParseError::TruncatedPacket => (MavlinkParseStatus::Truncated, None),
            MavlinkParseError::InvalidMagicMarker => (MavlinkParseStatus::InvalidMagic, None),
        },
    }
}

/// Evaluates raw payload bytes and returns a [`MavlinkParseStatus`].
#[must_use]
pub fn evaluate_payload(data: &[u8]) -> MavlinkParseStatus {
    evaluate_mavlink_header(data).0
}

/// Alias for [`evaluate_payload`].
#[must_use]
pub fn evaluate_mavlink_payload(data: &[u8]) -> MavlinkParseStatus {
    evaluate_payload(data)
}

pub use evaluate_mavlink_header as evaluate_header;
pub use evaluate_mavlink_header as evaluate_mavlink_packet;
pub use evaluate_mavlink_header as evaluate_packet;
pub use evaluate_mavlink_header as evaluate_mavlink;
pub use evaluate_mavlink_header as evaluate_mavlink_2_packet;

pub use parse_mavlink_header as parse_header;
pub use parse_mavlink_header as parse_mavlink_packet;
pub use parse_mavlink_header as parse_packet;

/// Modulus value for 8-bit MAVLink sequence counters (256).
pub const MAVLINK_SEQUENCE_MODULUS: u64 = 256;

/// Single-source MAVLink sequence continuity tracker maintaining an 8-bit counter modulo 256 (SPEC §14, §8).
#[derive(Debug, Clone)]
pub struct MavlinkSourceSequenceTracker {
    /// System ID of the tracked source (1 to 255).
    pub system_id: u8,
    /// Component ID of the tracked source (1 to 255).
    pub component_id: u8,
    /// Number of packets evaluated for this source.
    pub packets_evaluated: u64,
    /// Last sequence number observed, if any.
    pub last_sequence: Option<u8>,
    /// Highest sequence number observed, if any.
    pub highest_sequence: Option<u8>,
    /// Cumulative count of missing packets (sequence gaps) detected.
    pub gap_count: u64,
    /// Cumulative count of duplicate packets detected.
    pub duplicate_count: u64,
    /// Cumulative count of out-of-order packets detected.
    pub out_of_order_count: u64,
    /// Cumulative count of rollover events detected modulo 256.
    pub rollover_count: u64,
    recent_seen_queue: VecDeque<u8>,
    recent_seen_set: HashSet<u8>,
}

impl MavlinkSourceSequenceTracker {
    /// Creates a new sequence tracker for a given system and component identifier.
    #[must_use]
    pub fn new(system_id: u8, component_id: u8) -> Self {
        Self {
            system_id,
            component_id,
            packets_evaluated: 0,
            last_sequence: None,
            highest_sequence: None,
            gap_count: 0,
            duplicate_count: 0,
            out_of_order_count: 0,
            rollover_count: 0,
            recent_seen_queue: VecDeque::with_capacity(64),
            recent_seen_set: HashSet::with_capacity(64),
        }
    }

    /// Evaluates an 8-bit sequence number modulo 256 and updates continuity state.
    pub fn record_sequence(&mut self, seq: u8) -> SequenceTrackingEvent {
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

        let modulus: u32 = 256;
        let half_modulus: u32 = 128;
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

    fn remember_seen(&mut self, seq: u8) {
        if self.recent_seen_queue.len() >= 64 {
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
    pub fn last_sequence(&self) -> Option<u8> {
        self.last_sequence
    }

    /// Returns the highest sequence number observed, if any.
    #[must_use]
    pub fn highest_sequence(&self) -> Option<u8> {
        self.highest_sequence
    }

    /// Returns true if the sequence number is identified as a duplicate.
    #[must_use]
    pub fn is_duplicate(&self, seq: u8) -> bool {
        self.last_sequence == Some(seq) || self.recent_seen_set.contains(&seq)
    }
}

/// Multi-source MAVLink sequence tracker maintaining independent modulo-256 counters per (system_id, component_id) (SPEC §14, §8).
#[derive(Debug, Clone, Default)]
pub struct MavlinkSequenceTracker {
    allowed_sources: Option<HashSet<(u8, u8)>>,
    filter_systems: Option<HashSet<u8>>,
    filter_components: Option<HashSet<u8>>,
    trackers: HashMap<(u8, u8), MavlinkSourceSequenceTracker>,
    validation_errors: u64,
}

impl MavlinkSequenceTracker {
    /// Creates a new MAVLink sequence tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a MAVLink sequence tracker with optional system and component ID allowlists.
    #[must_use]
    pub fn with_filters(
        filter_systems: Option<Vec<u8>>,
        filter_components: Option<Vec<u8>>,
    ) -> Self {
        Self {
            allowed_sources: None,
            filter_systems: filter_systems.map(|v| v.into_iter().collect()),
            filter_components: filter_components.map(|v| v.into_iter().collect()),
            trackers: HashMap::new(),
            validation_errors: 0,
        }
    }

    /// Returns true if the source `(system_id, component_id)` passes configured filters.
    #[must_use]
    pub fn is_source_allowed(&self, system_id: u8, component_id: u8) -> bool {
        if let Some(ref allowed) = self.allowed_sources {
            if !allowed.contains(&(system_id, component_id)) {
                return false;
            }
        }
        if let Some(ref systems) = self.filter_systems {
            if !systems.contains(&system_id) {
                return false;
            }
        }
        if let Some(ref comps) = self.filter_components {
            if !comps.contains(&component_id) {
                return false;
            }
        }
        true
    }

    /// Records and evaluates a sequence number for a specific system and component source.
    pub fn record_sequence(
        &mut self,
        system_id: u8,
        component_id: u8,
        seq: u8,
    ) -> Option<SequenceTrackingEvent> {
        if !self.is_source_allowed(system_id, component_id) {
            return None;
        }
        let tracker = self
            .trackers
            .entry((system_id, component_id))
            .or_insert_with(|| MavlinkSourceSequenceTracker::new(system_id, component_id));
        Some(tracker.record_sequence(seq))
    }

    /// Records and evaluates a sequence number for a source given as a tuple `(system_id, component_id)`.
    pub fn record_source_sequence(
        &mut self,
        source: (u8, u8),
        seq: u8,
    ) -> Option<SequenceTrackingEvent> {
        self.record_sequence(source.0, source.1, seq)
    }

    /// Evaluates sequence continuity from an extracted [`MavlinkHeader`].
    pub fn record_header(&mut self, header: &MavlinkHeader) -> Option<SequenceTrackingEvent> {
        self.record_sequence(header.system_id, header.component_id, header.sequence)
    }

    /// Alias for [`record_header`].
    pub fn process_header(&mut self, header: &MavlinkHeader) -> Option<SequenceTrackingEvent> {
        self.record_header(header)
    }

    /// Parses a raw packet buffer and evaluates sequence continuity if valid.
    ///
    /// # Errors
    /// Returns [`MavlinkParseError`] if the packet is malformed or truncated.
    pub fn process_packet(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<SequenceTrackingEvent>, MavlinkParseError> {
        let header = parse_mavlink_header(packet)?;
        Ok(self.record_header(&header))
    }

    /// Returns the last sequence number observed for a specific source, if any.
    #[must_use]
    pub fn last_sequence(&self, system_id: u8, component_id: u8) -> Option<u8> {
        self.trackers
            .get(&(system_id, component_id))
            .and_then(|t| t.last_sequence)
    }

    /// Returns the highest sequence number observed for a specific source, if any.
    #[must_use]
    pub fn highest_sequence(&self, system_id: u8, component_id: u8) -> Option<u8> {
        self.trackers
            .get(&(system_id, component_id))
            .and_then(|t| t.highest_sequence)
    }

    /// Returns the sequence gap count for a specific source.
    #[must_use]
    pub fn gap_count(&self, system_id: u8, component_id: u8) -> u64 {
        self.trackers
            .get(&(system_id, component_id))
            .map_or(0, |t| t.gap_count)
    }

    /// Returns the duplicate packet count for a specific source.
    #[must_use]
    pub fn duplicate_count(&self, system_id: u8, component_id: u8) -> u64 {
        self.trackers
            .get(&(system_id, component_id))
            .map_or(0, |t| t.duplicate_count)
    }

    /// Returns the out-of-order packet count for a specific source.
    #[must_use]
    pub fn out_of_order_count(&self, system_id: u8, component_id: u8) -> u64 {
        self.trackers
            .get(&(system_id, component_id))
            .map_or(0, |t| t.out_of_order_count)
    }

    /// Returns the sequence rollover count for a specific source.
    #[must_use]
    pub fn rollover_count(&self, system_id: u8, component_id: u8) -> u64 {
        self.trackers
            .get(&(system_id, component_id))
            .map_or(0, |t| t.rollover_count)
    }

    /// Returns the total packets evaluated for a specific source.
    #[must_use]
    pub fn packets_evaluated(&self, system_id: u8, component_id: u8) -> u64 {
        self.trackers
            .get(&(system_id, component_id))
            .map_or(0, |t| t.packets_evaluated)
    }

    /// Returns true if the sequence number is identified as a duplicate for the given source.
    #[must_use]
    pub fn is_duplicate(&self, system_id: u8, component_id: u8, seq: u8) -> bool {
        self.trackers
            .get(&(system_id, component_id))
            .is_some_and(|t| t.is_duplicate(seq))
    }

    /// Returns cumulative gap count across all sources.
    #[must_use]
    pub fn total_gap_count(&self) -> u64 {
        self.trackers.values().map(|t| t.gap_count).sum()
    }

    /// Returns cumulative duplicate count across all sources.
    #[must_use]
    pub fn total_duplicate_count(&self) -> u64 {
        self.trackers.values().map(|t| t.duplicate_count).sum()
    }

    /// Returns total packets evaluated across all sources.
    #[must_use]
    pub fn total_packets_evaluated(&self) -> u64 {
        self.trackers.values().map(|t| t.packets_evaluated).sum()
    }

    /// Returns a reference to the tracker for a specific source if initialized.
    #[must_use]
    pub fn source_tracker(
        &self,
        system_id: u8,
        component_id: u8,
    ) -> Option<&MavlinkSourceSequenceTracker> {
        self.trackers.get(&(system_id, component_id))
    }

    /// Alias for [`source_tracker`].
    #[must_use]
    pub fn get(&self, system_id: u8, component_id: u8) -> Option<&MavlinkSourceSequenceTracker> {
        self.source_tracker(system_id, component_id)
    }

    /// Records a packet validation error.
    pub fn record_validation_error(&mut self) {
        self.validation_errors += 1;
    }

    /// Returns total validation errors recorded.
    #[must_use]
    pub fn validation_error_count(&self) -> u64 {
        self.validation_errors
    }

    /// Resets all sequence tracking state across all sources.
    pub fn reset(&mut self) {
        self.trackers.clear();
        self.validation_errors = 0;
    }

    /// Resets sequence tracking state for a specific source.
    pub fn reset_source(&mut self, system_id: u8, component_id: u8) {
        self.trackers.remove(&(system_id, component_id));
    }

    /// Captures a point-in-time snapshot of the sequence state for a source (SPEC §8).
    #[must_use]
    pub fn source_state(
        &self,
        stream_id: &str,
        system_id: u8,
        component_id: u8,
    ) -> Option<SequenceState> {
        let t = self.trackers.get(&(system_id, component_id))?;
        Some(SequenceState {
            stream_id: format!("{stream_id}:mavlink_{system_id}_{component_id}"),
            enabled: true,
            offset: Some(2),
            width: Some(1),
            byte_order: Some(ByteOrder::LittleEndian),
            rollover_threshold: Some(MAVLINK_SEQUENCE_MODULUS),
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

pub type MavlinkEndpointSequenceTracker = MavlinkSourceSequenceTracker;
pub type EndpointSequenceTracker = MavlinkSourceSequenceTracker;
pub type SourceSequenceTracker = MavlinkSourceSequenceTracker;
pub type MavlinkStreamSequenceTracker = MavlinkSequenceTracker;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v1_packet(payload_len: u8, seq: u8, sysid: u8, compid: u8, msgid: u8) -> Vec<u8> {
        let mut buf = encode_mavlink1_header(payload_len, seq, sysid, compid, msgid).to_vec();
        buf.resize(buf.len() + usize::from(payload_len), 0xAA);
        buf.extend_from_slice(&[0x11, 0x22]); // 2 bytes CRC
        buf
    }

    fn make_v2_packet(
        payload_len: u8,
        incompat_flags: u8,
        compat_flags: u8,
        seq: u8,
        sysid: u8,
        compid: u8,
        msgid: u32,
    ) -> Vec<u8> {
        let mut buf = encode_mavlink2_header(
            payload_len,
            incompat_flags,
            compat_flags,
            seq,
            sysid,
            compid,
            msgid,
        )
        .to_vec();
        buf.resize(buf.len() + usize::from(payload_len), 0xBB);
        buf.extend_from_slice(&[0x33, 0x44]); // 2 bytes CRC
        if (incompat_flags & MAVLINK_IFLAG_SIGNED) != 0 {
            buf.resize(buf.len() + MAVLINK_SIGNATURE_LEN, 0x55);
        }
        buf
    }

    #[test]
    fn test_criterion1_mavlink1_header_extraction() {
        // MAVLink 1 packet with magic 0xFE
        let packet = make_v1_packet(10, 42, 1, 2, 77);
        assert_eq!(packet.len(), 10 + 8);
        assert_eq!(packet[0], 0xFE);

        let header = parse_mavlink_header(&packet).expect("valid MAVLink 1 must parse");
        assert_eq!(header.version, MavlinkVersion::V1);
        assert!(header.is_v1());
        assert!(!header.is_v2());
        assert_eq!(header.sequence, 42);
        assert_eq!(header.sequence_number(), 42);
        assert_eq!(header.seq(), 42);
        assert_eq!(header.system_id, 1);
        assert_eq!(header.sysid(), 1);
        assert_eq!(header.component_id, 2);
        assert_eq!(header.compid(), 2);
        assert_eq!(header.message_id, 77);
        assert_eq!(header.msgid(), 77);
        assert_eq!(header.payload_length, 10);
        assert_eq!(header.total_packet_length, 18);
        assert_eq!(header.packet_length(), 18);
        assert!(!header.is_signed);
        assert_eq!(header.incompat_flags, 0);
        assert_eq!(header.compat_flags, 0);
        assert!(!header.has_warning());
    }

    #[test]
    fn test_criterion2_mavlink2_unsigned_extraction() {
        // MAVLink 2 packet without signature flag
        // 24-bit little-endian message ID: 0x010203 -> bytes [0x03, 0x02, 0x01]
        let msgid = 0x010203u32;
        let packet = make_v2_packet(15, 0, 0, 100, 3, 4, msgid);
        assert_eq!(packet.len(), 15 + 12);
        assert_eq!(packet[0], 0xFD);

        let header = parse_mavlink_header(&packet).expect("valid MAVLink 2 must parse");
        assert_eq!(header.version, MavlinkVersion::V2);
        assert!(header.is_v2());
        assert!(!header.is_v1());
        assert_eq!(header.sequence, 100);
        assert_eq!(header.sequence_number(), 100);
        assert_eq!(header.system_id, 3);
        assert_eq!(header.sysid(), 3);
        assert_eq!(header.component_id, 4);
        assert_eq!(header.compid(), 4);
        assert_eq!(header.message_id, msgid);
        assert_eq!(header.msgid(), msgid);
        assert_eq!(header.payload_length, 15);
        assert_eq!(header.total_packet_length, 27);
        assert_eq!(header.packet_length(), 27);
        assert!(!header.is_signed);
        assert!(!header.has_warning());
    }

    #[test]
    fn test_criterion3_mavlink2_signed_length() {
        // MAVLink 2 packet with incompatibility flag bit 0 set (signed)
        let payload_len = 20u8;
        let packet = make_v2_packet(payload_len, MAVLINK_IFLAG_SIGNED, 0, 50, 10, 20, 300);
        assert_eq!(packet.len(), 20 + 25);
        assert_eq!(packet[0], 0xFD);
        assert_eq!(packet[2] & 0x01, 1);

        let header = parse_mavlink_header(&packet).expect("valid signed MAVLink 2 must parse");
        assert_eq!(header.version, MavlinkVersion::V2);
        assert!(header.is_signed);
        assert_eq!(header.payload_length, 20);
        assert_eq!(header.total_packet_length, 20 + 25);
        assert_eq!(header.packet_length(), 45);
        assert!(!header.has_warning());
    }

    #[test]
    fn test_criterion4_invalid_magic_marker() {
        let invalid_magics = [0x00, 0x01, 0x42, 0x80, 0xFC, 0xFF];
        for magic in invalid_magics {
            let buf = [magic, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            let err = parse_mavlink_header(&buf).expect_err("non-magic byte must fail");
            assert_eq!(err, MavlinkParseError::InvalidMagicMarker);
            assert!(err.is_invalid_magic_marker());
            assert!(err.is_invalid_magic());
            assert!(!err.is_truncated());

            let (status, hdr) = evaluate_mavlink_header(&buf);
            assert_eq!(status, MavlinkParseStatus::InvalidMagic);
            assert!(status.is_invalid_magic());
            assert!(hdr.is_none());
        }
    }

    #[test]
    fn test_criterion5_truncated_packets() {
        // 1. Empty buffer
        let empty: &[u8] = &[];
        let err = parse_mavlink_header(empty).expect_err("empty buffer must fail");
        assert_eq!(err, MavlinkParseError::TruncatedPacket);
        assert!(err.is_truncated_packet());
        assert!(err.is_truncated());

        // 2. MAVLink 1 shorter than minimal header length (6 octets)
        let v1_full = make_v1_packet(5, 1, 1, 1, 1); // total = 5 + 8 = 13 bytes
        for len in 1..6 {
            let err = parse_mavlink_header(&v1_full[..len]).expect_err("shorter than v1 header");
            assert_eq!(err, MavlinkParseError::TruncatedPacket);
            assert!(err.is_truncated());
        }

        // 3. MAVLink 1 shorter than declared total length (6..13)
        for len in 6..13 {
            let err = parse_mavlink_header(&v1_full[..len]).expect_err("shorter than declared len");
            assert_eq!(err, MavlinkParseError::TruncatedPacket);
            assert!(err.is_truncated());
        }

        // Exact length must succeed
        assert!(parse_mavlink_header(&v1_full[..13]).is_ok());

        // 4. MAVLink 2 shorter than minimal header length (10 octets)
        let v2_unsigned = make_v2_packet(10, 0, 0, 1, 1, 1, 1); // total = 10 + 12 = 22 bytes
        for len in 1..10 {
            let err =
                parse_mavlink_header(&v2_unsigned[..len]).expect_err("shorter than v2 header");
            assert_eq!(err, MavlinkParseError::TruncatedPacket);
            assert!(err.is_truncated());
        }

        // 5. MAVLink 2 shorter than declared total length (10..22)
        for len in 10..22 {
            let err =
                parse_mavlink_header(&v2_unsigned[..len]).expect_err("shorter than declared len");
            assert_eq!(err, MavlinkParseError::TruncatedPacket);
            assert!(err.is_truncated());
        }

        // Exact length must succeed
        assert!(parse_mavlink_header(&v2_unsigned[..22]).is_ok());

        // 6. MAVLink 2 signed shorter than declared total length (10 + 25 = 35)
        let v2_signed = make_v2_packet(10, MAVLINK_IFLAG_SIGNED, 0, 1, 1, 1, 1); // 10 + 25 = 35 bytes
        for len in 10..35 {
            let err = parse_mavlink_header(&v2_signed[..len])
                .expect_err("signed shorter than declared len");
            assert_eq!(err, MavlinkParseError::TruncatedPacket);
            assert!(err.is_truncated());
        }
        assert!(parse_mavlink_header(&v2_signed[..35]).is_ok());
    }

    #[test]
    fn test_criterion6_unknown_incompatibility_flags_returns_warning() {
        // Unknown incompat flag bit 1 (0x02) set, bit 2 (0x04) set, etc.
        let unknown_flags = 0x02u8;
        let packet = make_v2_packet(8, unknown_flags, 0, 99, 12, 34, 5678);

        // Header parsing still succeeds and preserves extracted metadata
        let header =
            parse_mavlink_header(&packet).expect("parsing must succeed despite unknown flag");
        assert_eq!(header.sequence, 99);
        assert_eq!(header.system_id, 12);
        assert_eq!(header.component_id, 34);
        assert_eq!(header.message_id, 5678);
        assert_eq!(header.incompat_flags, 0x02);
        assert!(header.has_warning());
        assert_eq!(
            header.warning(),
            Some(MavlinkParseWarning::UnknownIncompatibilityFlags(0x02))
        );

        // evaluate_mavlink_header returns Warning while preserving extracted header
        let (status, header_opt) = evaluate_mavlink_header(&packet);
        assert!(status.is_warning());
        assert_eq!(
            status,
            MavlinkParseStatus::Warning(MavlinkParseWarning::UnknownIncompatibilityFlags(0x02))
        );
        let preserved = header_opt.expect("extracted header metadata must be preserved");
        assert_eq!(preserved.sequence, 99);
        assert_eq!(preserved.system_id, 12);
        assert_eq!(preserved.component_id, 34);
        assert_eq!(preserved.message_id, 5678);
        assert_eq!(preserved.total_packet_length, 8 + 12);

        // Also test combined signed + unknown incompat flag (0x01 | 0x04 = 0x05)
        let signed_unknown_packet = make_v2_packet(10, 0x05, 0, 7, 1, 1, 100);
        let (signed_status, signed_header_opt) = evaluate_mavlink_header(&signed_unknown_packet);
        assert!(signed_status.is_warning());
        assert_eq!(
            signed_status,
            MavlinkParseStatus::Warning(MavlinkParseWarning::UnknownIncompatibilityFlags(0x04))
        );
        let signed_hdr = signed_header_opt.expect("signed header must be preserved");
        assert!(signed_hdr.is_signed);
        assert_eq!(signed_hdr.total_packet_length, 10 + 25);
    }

    #[test]
    fn test_criterion1_independent_per_source_sequence_tracking() {
        // Acceptance criterion: In crates/rer/src/mavlink.rs, sequence tracking maintains 8-bit
        // sequence counters modulo 256 independently for two distinct system and component identifier sources,
        // detecting a sequence gap on one source without altering continuity state on the other source.
        let mut tracker = MavlinkSequenceTracker::new();
        let sys_a = 1;
        let comp_a = 1;
        let sys_b = 2;
        let comp_b = 1;

        // Source A initial packet
        assert_eq!(
            tracker.record_sequence(sys_a, comp_a, 0),
            Some(SequenceTrackingEvent::Initial { sequence: 0 })
        );

        // Source B initial packet (different start sequence)
        assert_eq!(
            tracker.record_sequence(sys_b, comp_b, 100),
            Some(SequenceTrackingEvent::Initial { sequence: 100 })
        );

        // Source A in-order packet
        assert_eq!(
            tracker.record_sequence(sys_a, comp_a, 1),
            Some(SequenceTrackingEvent::InOrder { sequence: 1 })
        );

        // Source A receives sequence 4 (gap of 2: missing 2, 3)
        assert_eq!(
            tracker.record_sequence(sys_a, comp_a, 4),
            Some(SequenceTrackingEvent::Gap {
                expected: 2,
                actual: 4,
                missing_count: 2,
            })
        );
        assert_eq!(tracker.gap_count(sys_a, comp_a), 2);
        assert_eq!(tracker.last_sequence(sys_a, comp_a), Some(4));

        // VERIFY: Source B continuity state is completely unaltered!
        assert_eq!(tracker.gap_count(sys_b, comp_b), 0);
        assert_eq!(tracker.duplicate_count(sys_b, comp_b), 0);
        assert_eq!(tracker.last_sequence(sys_b, comp_b), Some(100));
        assert_eq!(tracker.packets_evaluated(sys_b, comp_b), 1);

        // Source B advances in-order to 101
        assert_eq!(
            tracker.record_sequence(sys_b, comp_b, 101),
            Some(SequenceTrackingEvent::InOrder { sequence: 101 })
        );
        assert_eq!(tracker.last_sequence(sys_b, comp_b), Some(101));
        assert_eq!(tracker.gap_count(sys_b, comp_b), 0);
    }

    #[test]
    fn test_criterion2_duplicate_sequence_tracking() {
        // Acceptance criterion: In crates/rer/src/mavlink.rs, sequence tracking receiving a duplicate
        // sequence number for an existing source increments duplicate counters and identifies duplicate
        // packets without dropping traffic.
        let mut tracker = MavlinkSequenceTracker::new();
        let sys = 1;
        let comp = 1;

        assert_eq!(
            tracker.record_sequence(sys, comp, 10),
            Some(SequenceTrackingEvent::Initial { sequence: 10 })
        );
        assert_eq!(
            tracker.record_sequence(sys, comp, 11),
            Some(SequenceTrackingEvent::InOrder { sequence: 11 })
        );

        // Immediate duplicate: sequence 11 again
        assert!(tracker.is_duplicate(sys, comp, 11));
        assert_eq!(
            tracker.record_sequence(sys, comp, 11),
            Some(SequenceTrackingEvent::Duplicate { sequence: 11 })
        );
        assert_eq!(tracker.duplicate_count(sys, comp), 1);
        assert_eq!(tracker.total_duplicate_count(), 1);
        // last_sequence is still 11
        assert_eq!(tracker.last_sequence(sys, comp), Some(11));

        // Advance to 12
        assert_eq!(
            tracker.record_sequence(sys, comp, 12),
            Some(SequenceTrackingEvent::InOrder { sequence: 12 })
        );

        // Previous sequence 11 arrives again (recent window duplicate)
        assert!(tracker.is_duplicate(sys, comp, 11));
        assert_eq!(
            tracker.record_sequence(sys, comp, 11),
            Some(SequenceTrackingEvent::Duplicate { sequence: 11 })
        );
        assert_eq!(tracker.duplicate_count(sys, comp), 2);
        assert_eq!(tracker.total_duplicate_count(), 2);
        // last_sequence is preserved at 12
        assert_eq!(tracker.last_sequence(sys, comp), Some(12));
    }

    #[test]
    fn test_mavlink_sequence_rollover_modulo_256() {
        let mut tracker = MavlinkSequenceTracker::new();
        let sys = 1;
        let comp = 1;

        // Sequence near 255 boundary
        assert_eq!(
            tracker.record_sequence(sys, comp, 255),
            Some(SequenceTrackingEvent::Initial { sequence: 255 })
        );

        // Rollover to 0
        assert_eq!(
            tracker.record_sequence(sys, comp, 0),
            Some(SequenceTrackingEvent::Rollover {
                sequence: 0,
                missing_count: 0,
            })
        );
        assert_eq!(tracker.last_sequence(sys, comp), Some(0));
        assert_eq!(tracker.rollover_count(sys, comp), 1);

        // Rollover with gap: from 254 to 2 (missing 255, 0, 1 -> 3 packets)
        let mut tracker2 = MavlinkSequenceTracker::new();
        assert_eq!(
            tracker2.record_sequence(sys, comp, 254),
            Some(SequenceTrackingEvent::Initial { sequence: 254 })
        );
        assert_eq!(
            tracker2.record_sequence(sys, comp, 2),
            Some(SequenceTrackingEvent::Rollover {
                sequence: 2,
                missing_count: 3,
            })
        );
        assert_eq!(tracker2.gap_count(sys, comp), 3);
        assert_eq!(tracker2.last_sequence(sys, comp), Some(2));
    }
}
