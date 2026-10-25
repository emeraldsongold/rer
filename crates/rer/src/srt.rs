//! In-tree Secure Reliable Transport (SRT) packet header parser (SPEC §14, §8).
//!
//! Provides a zero-dependency in-tree SRT packet header parser and payload evaluator as defined
//! in draft-sharabayko-srt-01 and SPEC §14.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14, RER implements passive metadata inspection of SRT packet headers.
//! RER does NOT implement a stateful SRT protocol engine, caller/listener handshake negotiation,
//! retransmission queues, TSBPD playout buffering, rate pacing, or AES encryption engines.
//! Forwarded datagrams are transmitted byte-unmodified.

use std::fmt;

use serde::{Deserialize, Serialize};

/// SRT fixed header length in bytes (16 octets / 128 bits).
pub const SRT_HEADER_LEN: usize = 16;

/// Minimum SRT Handshake control packet length in bytes (16 header + 48 base handshake payload).
pub const SRT_HANDSHAKE_MIN_LEN: usize = 64;

/// Base SRT Handshake payload length in bytes (48 octets).
pub const SRT_HANDSHAKE_PAYLOAD_LEN: usize = 48;

/// Standard legacy UDT protocol version (4).
pub const UDT_VERSION_4: u32 = 4;

/// Standard SRT protocol version (5).
pub const SRT_VERSION_5: u32 = 5;

// SRT Control packet types (draft-sharabayko-srt §3.2)
pub const SRT_CMD_HANDSHAKE: u16 = 0x0000;
pub const SRT_CMD_KEEPALIVE: u16 = 0x0001;
pub const SRT_CMD_ACK: u16 = 0x0002;
pub const SRT_CMD_NAK: u16 = 0x0003;
pub const SRT_CMD_CONGESTION: u16 = 0x0004;
pub const SRT_CMD_SHUTDOWN: u16 = 0x0005;
pub const SRT_CMD_ACKACK: u16 = 0x0006;
pub const SRT_CMD_DROPREQ: u16 = 0x0007;
pub const SRT_CMD_PEERERROR: u16 = 0x0008;
pub const SRT_CMD_USER: u16 = 0x7FFF;

// SRT Handshake types (draft-sharabayko-srt §3.2.1.1)
pub const SRT_HS_DONE: u32 = 0x0000_0000;
pub const SRT_HS_AGREEMENT: u32 = 0x0000_0001;
pub const SRT_HS_CONCLUSION: u32 = 0x0000_0002;
pub const SRT_HS_INDUCTION: u32 = 0x0000_0003;
pub const SRT_HS_WAVEAHAND: u32 = 0xFFFF_FFFF;

// SRT Handshake extension types (draft-sharabayko-srt §3.2.1.2)
pub const SRT_CMD_HSREQ: u16 = 0x0001;
pub const SRT_CMD_HSRSP: u16 = 0x0001;
pub const SRT_CMD_KMREQ: u16 = 0x0002;
pub const SRT_CMD_KMRSP: u16 = 0x0002;
pub const SRT_CMD_SID: u16 = 0x0003;

/// Packet Position Flag (PP) in SRT Data Packets (draft-sharabayko-srt §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketPosition {
    /// Middle packet of a multi-packet message (00b).
    Middle = 0b00,
    /// Last packet of a multi-packet message (01b).
    Last = 0b01,
    /// First packet of a multi-packet message (10b).
    First = 0b10,
    /// Standalone packet containing entire message (11b).
    Single = 0b11,
}

impl PacketPosition {
    pub const MIDDLE: Self = Self::Middle;
    pub const LAST: Self = Self::Last;
    pub const FIRST: Self = Self::First;
    pub const SINGLE: Self = Self::Single;
    pub const STANDALONE: Self = Self::Single;
    #[allow(non_upper_case_globals)]
    pub const Standalone: Self = Self::Single;

    /// Parses a 2-bit packet position code.
    #[must_use]
    pub const fn from_u8(code: u8) -> Self {
        match code & 0x03 {
            0b00 => Self::Middle,
            0b01 => Self::Last,
            0b10 => Self::First,
            _ => Self::Single,
        }
    }

    /// Returns the raw 2-bit code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        *self as u8
    }

    /// Returns true if this packet is standalone (contains whole message).
    #[must_use]
    pub const fn is_standalone(&self) -> bool {
        matches!(self, Self::Single)
    }

    /// Returns true if this is the first packet of a message.
    #[must_use]
    pub const fn is_first(&self) -> bool {
        matches!(self, Self::First)
    }

    /// Returns true if this is the last packet of a message.
    #[must_use]
    pub const fn is_last(&self) -> bool {
        matches!(self, Self::Last)
    }

    /// Returns true if this is a middle packet of a message.
    #[must_use]
    pub const fn is_middle(&self) -> bool {
        matches!(self, Self::Middle)
    }
}

/// SRT Packet Kind (Data or Control), defined by bit 0 of the 16-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SrtPacketKind {
    /// Data Packet (bit 0 = 0).
    Data = 0,
    /// Control Packet (bit 0 = 1).
    Control = 1,
}

pub type SrtPacketType = SrtPacketKind;

impl SrtPacketKind {
    /// Returns true if this is a data packet.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(self, Self::Data)
    }

    /// Returns true if this is a control packet.
    #[must_use]
    pub const fn is_control(&self) -> bool {
        matches!(self, Self::Control)
    }
}

/// SRT Control Packet Type (bits 1..15 of a Control Packet header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SrtControlType {
    Handshake,
    Keepalive,
    Ack,
    Nak,
    CongestionWarning,
    Shutdown,
    AckAck,
    DropReq,
    PeerError,
    UserDefined,
    Unknown(u16),
}

impl SrtControlType {
    pub const HANDSHAKE: Self = Self::Handshake;
    pub const KEEPALIVE: Self = Self::Keepalive;
    pub const ACK: Self = Self::Ack;
    pub const NAK: Self = Self::Nak;
    pub const CONGESTION: Self = Self::CongestionWarning;
    pub const CONGESTION_WARNING: Self = Self::CongestionWarning;
    pub const SHUTDOWN: Self = Self::Shutdown;
    pub const ACKACK: Self = Self::AckAck;
    pub const ACK_ACK: Self = Self::AckAck;
    pub const DROPREQ: Self = Self::DropReq;
    pub const DROP_REQ: Self = Self::DropReq;
    pub const PEERERROR: Self = Self::PeerError;
    pub const PEER_ERROR: Self = Self::PeerError;
    pub const USER: Self = Self::UserDefined;
    pub const USER_DEFINED: Self = Self::UserDefined;

    /// Parses a 15-bit control type code.
    #[must_use]
    pub const fn from_u16(code: u16) -> Self {
        match code {
            SRT_CMD_HANDSHAKE => Self::Handshake,
            SRT_CMD_KEEPALIVE => Self::Keepalive,
            SRT_CMD_ACK => Self::Ack,
            SRT_CMD_NAK => Self::Nak,
            SRT_CMD_CONGESTION => Self::CongestionWarning,
            SRT_CMD_SHUTDOWN => Self::Shutdown,
            SRT_CMD_ACKACK => Self::AckAck,
            SRT_CMD_DROPREQ => Self::DropReq,
            SRT_CMD_PEERERROR => Self::PeerError,
            SRT_CMD_USER => Self::UserDefined,
            other => Self::Unknown(other),
        }
    }

    /// Returns the 15-bit control type code.
    #[must_use]
    pub const fn code(&self) -> u16 {
        match self {
            Self::Handshake => SRT_CMD_HANDSHAKE,
            Self::Keepalive => SRT_CMD_KEEPALIVE,
            Self::Ack => SRT_CMD_ACK,
            Self::Nak => SRT_CMD_NAK,
            Self::CongestionWarning => SRT_CMD_CONGESTION,
            Self::Shutdown => SRT_CMD_SHUTDOWN,
            Self::AckAck => SRT_CMD_ACKACK,
            Self::DropReq => SRT_CMD_DROPREQ,
            Self::PeerError => SRT_CMD_PEERERROR,
            Self::UserDefined => SRT_CMD_USER,
            Self::Unknown(c) => *c,
        }
    }

    /// Returns true if this control type is recognized by standard SRT.
    #[must_use]
    pub const fn is_standard(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl From<u16> for SrtControlType {
    fn from(val: u16) -> Self {
        Self::from_u16(val)
    }
}

impl From<SrtControlType> for u16 {
    fn from(val: SrtControlType) -> Self {
        val.code()
    }
}

impl PartialEq<u16> for SrtControlType {
    fn eq(&self, other: &u16) -> bool {
        self.code() == *other
    }
}

impl PartialEq<SrtControlType> for u16 {
    fn eq(&self, other: &SrtControlType) -> bool {
        *self == other.code()
    }
}

/// SRT Handshake Type (draft-sharabayko-srt §3.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SrtHandshakeType {
    Done,
    Agreement,
    Conclusion,
    Induction,
    Waveahand,
    Unknown(u32),
}

impl SrtHandshakeType {
    pub const DONE: Self = Self::Done;
    pub const AGREEMENT: Self = Self::Agreement;
    pub const CONCLUSION: Self = Self::Conclusion;
    pub const INDUCTION: Self = Self::Induction;
    pub const WAVEAHAND: Self = Self::Waveahand;

    /// Parses a 32-bit handshake type integer.
    #[must_use]
    pub const fn from_u32(code: u32) -> Self {
        match code {
            SRT_HS_DONE => Self::Done,
            SRT_HS_AGREEMENT => Self::Agreement,
            SRT_HS_CONCLUSION => Self::Conclusion,
            SRT_HS_INDUCTION => Self::Induction,
            SRT_HS_WAVEAHAND => Self::Waveahand,
            other => Self::Unknown(other),
        }
    }

    /// Returns the 32-bit handshake type integer.
    #[must_use]
    pub const fn code(&self) -> u32 {
        match self {
            Self::Done => SRT_HS_DONE,
            Self::Agreement => SRT_HS_AGREEMENT,
            Self::Conclusion => SRT_HS_CONCLUSION,
            Self::Induction => SRT_HS_INDUCTION,
            Self::Waveahand => SRT_HS_WAVEAHAND,
            Self::Unknown(c) => *c,
        }
    }
}

impl From<u32> for SrtHandshakeType {
    fn from(val: u32) -> Self {
        Self::from_u32(val)
    }
}

impl From<SrtHandshakeType> for u32 {
    fn from(val: SrtHandshakeType) -> Self {
        val.code()
    }
}

impl PartialEq<u32> for SrtHandshakeType {
    fn eq(&self, other: &u32) -> bool {
        self.code() == *other
    }
}

impl PartialEq<SrtHandshakeType> for u32 {
    fn eq(&self, other: &SrtHandshakeType) -> bool {
        *self == other.code()
    }
}

/// Evaluation parse status distinguishing non-SRT traffic from valid SRT packets without panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SrtParseStatus {
    /// Payload is a valid SRT packet.
    Valid,
    /// Payload is arbitrary non-SRT data.
    NotSrt,
    /// Payload appears to be SRT but has malformed fields or structure.
    MalformedSrt,
    /// Input buffer is truncated before completing the 16-byte header or required structure.
    Truncated,
}

impl SrtParseStatus {
    pub const MALFORMED: Self = Self::MalformedSrt;
    #[allow(non_upper_case_globals)]
    pub const Malformed: Self = Self::MalformedSrt;
    #[allow(non_upper_case_globals)]
    pub const NotSrt: Self = Self::NotSrt;
    #[allow(non_upper_case_globals)]
    pub const Valid: Self = Self::Valid;
    #[allow(non_upper_case_globals)]
    pub const Truncated: Self = Self::Truncated;

    /// Returns true if the status is [`Self::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns true if the payload is not SRT traffic.
    #[must_use]
    pub const fn is_not_srt(&self) -> bool {
        matches!(self, Self::NotSrt)
    }

    /// Returns true if the payload is malformed SRT traffic.
    #[must_use]
    pub const fn is_malformed(&self) -> bool {
        matches!(self, Self::MalformedSrt)
    }

    /// Returns true if the input was truncated.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated)
    }

    /// Returns true if the status is not valid (either NotSrt, MalformedSrt, or Truncated).
    #[must_use]
    pub const fn is_invalid(&self) -> bool {
        !self.is_valid()
    }
}

impl fmt::Display for SrtParseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::NotSrt => write!(f, "not_srt"),
            Self::MalformedSrt => write!(f, "malformed_srt"),
            Self::Truncated => write!(f, "truncated"),
        }
    }
}

/// Errors encountered when parsing an SRT packet header or handshake record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SrtParseError {
    /// Buffer is shorter than the 16-byte fixed SRT header.
    TruncatedHeader,
    /// Buffer is truncated where a larger structure was expected.
    Truncated { expected: usize, actual: usize },
    /// Packet type or structure is invalid.
    InvalidPacket,
    /// Unknown or unsupported control type.
    InvalidControlType(u16),
    /// Invalid or malformed handshake payload.
    InvalidHandshake,
    /// Input does not match SRT protocol signatures.
    NotSrt,
}

impl SrtParseError {
    /// Returns true if the error indicates truncated input.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::TruncatedHeader | Self::Truncated { .. })
    }

    /// Maps this parse error to an [`SrtParseStatus`].
    #[must_use]
    pub const fn status(&self) -> SrtParseStatus {
        match self {
            Self::TruncatedHeader | Self::Truncated { .. } => SrtParseStatus::Truncated,
            Self::NotSrt => SrtParseStatus::NotSrt,
            Self::InvalidPacket | Self::InvalidControlType(_) | Self::InvalidHandshake => {
                SrtParseStatus::MalformedSrt
            }
        }
    }
}

impl fmt::Display for SrtParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => {
                write!(
                    f,
                    "SRT header truncated: buffer shorter than 16-byte header"
                )
            }
            Self::Truncated { expected, actual } => {
                write!(
                    f,
                    "SRT payload truncated: expected at least {expected} bytes, got {actual}"
                )
            }
            Self::InvalidPacket => write!(f, "invalid SRT packet format or structure"),
            Self::InvalidControlType(c) => {
                write!(f, "unknown or invalid SRT control type {c:#06x}")
            }
            Self::InvalidHandshake => write!(f, "invalid or malformed SRT handshake payload"),
            Self::NotSrt => write!(f, "input does not conform to SRT protocol structure"),
        }
    }
}

impl std::error::Error for SrtParseError {}

/// Parsed representation of an SRT Data Packet Header (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrtDataHeader {
    /// 31-bit packet sequence number (modulo 2^31).
    pub sequence_number: u32,
    /// 2-bit packet position flag (PP).
    pub packet_position: PacketPosition,
    /// 1-bit in-order delivery flag (O).
    pub in_order: bool,
    /// 2-bit key-based encryption flag (KK).
    pub encryption_flag: u8,
    /// 1-bit retransmitted packet flag (R).
    pub retransmitted: bool,
    /// 26-bit message number.
    pub message_number: u32,
    /// 32-bit timestamp in microseconds.
    pub timestamp: u32,
    /// Alias for [`Self::timestamp`].
    pub timestamp_us: u32,
    /// 32-bit Destination Socket ID.
    pub destination_socket_id: u32,
    /// Offset where payload data begins (16).
    pub payload_offset: usize,
    /// Length of payload in bytes.
    pub payload_length: usize,
}

pub type SrtDataPacket = SrtDataHeader;

impl SrtDataHeader {
    #[must_use]
    pub const fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    #[must_use]
    pub const fn message_number(&self) -> u32 {
        self.message_number
    }

    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    #[must_use]
    pub const fn destination_socket_id(&self) -> u32 {
        self.destination_socket_id
    }

    #[must_use]
    pub const fn packet_position(&self) -> PacketPosition {
        self.packet_position
    }

    #[must_use]
    pub const fn in_order(&self) -> bool {
        self.in_order
    }

    #[must_use]
    pub const fn encryption_flag(&self) -> u8 {
        self.encryption_flag
    }

    #[must_use]
    pub const fn is_retransmitted(&self) -> bool {
        self.retransmitted
    }

    /// Encodes this data header into 16 big-endian bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SRT_HEADER_LEN] {
        encode_data_header(
            self.sequence_number,
            self.packet_position,
            self.in_order,
            self.encryption_flag,
            self.retransmitted,
            self.message_number,
            self.timestamp,
            self.destination_socket_id,
        )
    }
}

/// Parsed representation of an SRT Control Packet Header (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrtControlHeader {
    /// 15-bit control type.
    pub control_type: SrtControlType,
    /// 16-bit subtype / extension / reserved field.
    pub subtype: u16,
    /// 32-bit type-specific information.
    pub type_specific_info: u32,
    /// Alias for [`Self::type_specific_info`].
    pub type_specific_information: u32,
    /// 32-bit timestamp in microseconds.
    pub timestamp: u32,
    /// Alias for [`Self::timestamp`].
    pub timestamp_us: u32,
    /// 32-bit Destination Socket ID.
    pub destination_socket_id: u32,
    /// Offset where payload data begins (16).
    pub payload_offset: usize,
    /// Length of payload in bytes.
    pub payload_length: usize,
}

pub type SrtControlPacket = SrtControlHeader;

impl SrtControlHeader {
    #[must_use]
    pub const fn control_type(&self) -> SrtControlType {
        self.control_type
    }

    #[must_use]
    pub const fn subtype(&self) -> u16 {
        self.subtype
    }

    #[must_use]
    pub const fn type_specific_info(&self) -> u32 {
        self.type_specific_info
    }

    #[must_use]
    pub const fn type_specific_information(&self) -> u32 {
        self.type_specific_information
    }

    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    #[must_use]
    pub const fn destination_socket_id(&self) -> u32 {
        self.destination_socket_id
    }

    /// Encodes this control header into 16 big-endian bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SRT_HEADER_LEN] {
        encode_control_header(
            self.control_type.code(),
            self.subtype,
            self.type_specific_info,
            self.timestamp,
            self.destination_socket_id,
        )
    }
}

/// Parsed representation of an SRT Handshake control packet payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrtHandshake {
    /// 32-bit protocol version (4 for UDT legacy, 5 for SRT).
    pub version: u32,
    /// Alias for [`Self::version`].
    pub protocol_version: u32,
    /// 16-bit encryption field.
    pub encryption_field: u16,
    /// 16-bit extension field flags.
    pub extension_field: u16,
    /// 32-bit starting sequence number for data packets.
    pub initial_sequence_number: u32,
    /// Alias for [`Self::initial_sequence_number`].
    pub initial_packet_sequence_number: u32,
    /// 32-bit maximum transmission unit in bytes.
    pub mtu: u32,
    /// Alias for [`Self::mtu`].
    pub mtu_size: u32,
    /// 32-bit maximum flow window size in packets.
    pub max_flow_window_size: u32,
    /// Alias for [`Self::max_flow_window_size`].
    pub flow_window_size: u32,
    /// 32-bit handshake type integer.
    pub handshake_type: u32,
    /// Typed handshake kind.
    pub handshake_kind: SrtHandshakeType,
    /// 32-bit sender SRT Socket ID.
    pub srt_socket_id: u32,
    /// Alias for [`Self::srt_socket_id`].
    pub source_socket_id: u32,
    /// 32-bit anti-spoofing challenge cookie.
    pub syn_cookie: u32,
    /// 128-bit peer public IP address.
    pub peer_ip: [u8; 16],
    /// Alias for [`Self::peer_ip`].
    pub peer_ip_address: [u8; 16],
    /// Optional Stream ID extracted from Handshake Extension records (SRT_CMD_SID).
    pub stream_id: Option<String>,
}

pub type SrtHandshakePacket = SrtHandshake;
pub type SrtHandshakeControl = SrtHandshake;

impl SrtHandshake {
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    #[must_use]
    pub const fn initial_sequence_number(&self) -> u32 {
        self.initial_sequence_number
    }

    #[must_use]
    pub const fn handshake_type(&self) -> u32 {
        self.handshake_type
    }

    #[must_use]
    pub const fn handshake_kind(&self) -> SrtHandshakeType {
        self.handshake_kind
    }

    #[must_use]
    pub const fn srt_socket_id(&self) -> u32 {
        self.srt_socket_id
    }

    #[must_use]
    pub const fn syn_cookie(&self) -> u32 {
        self.syn_cookie
    }

    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    /// Encodes this handshake payload into bytes.
    #[must_use]
    pub fn to_payload_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SRT_HANDSHAKE_PAYLOAD_LEN);
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&self.encryption_field.to_be_bytes());
        buf.extend_from_slice(&self.extension_field.to_be_bytes());
        buf.extend_from_slice(&self.initial_sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.mtu.to_be_bytes());
        buf.extend_from_slice(&self.max_flow_window_size.to_be_bytes());
        buf.extend_from_slice(&self.handshake_type.to_be_bytes());
        buf.extend_from_slice(&self.srt_socket_id.to_be_bytes());
        buf.extend_from_slice(&self.syn_cookie.to_be_bytes());
        buf.extend_from_slice(&self.peer_ip);

        // Optional Stream ID extension record
        if let Some(ref sid) = self.stream_id {
            let sid_bytes = sid.as_bytes();
            let pad_len = (4 - (sid_bytes.len() % 4)) % 4;
            let total_len = sid_bytes.len() + pad_len;
            let words = (total_len / 4) as u16;
            buf.extend_from_slice(&SRT_CMD_SID.to_be_bytes());
            buf.extend_from_slice(&words.to_be_bytes());
            buf.extend_from_slice(sid_bytes);
            buf.extend(std::iter::repeat(0u8).take(pad_len));
        }

        buf
    }

    /// Encodes this handshake into a complete 64+ byte control packet.
    #[must_use]
    pub fn to_packet_bytes(&self, timestamp: u32, destination_socket_id: u32) -> Vec<u8> {
        let mut pkt = Vec::new();
        let hdr = encode_control_header(SRT_CMD_HANDSHAKE, 0, 0, timestamp, destination_socket_id);
        pkt.extend_from_slice(&hdr);
        pkt.extend_from_slice(&self.to_payload_bytes());
        pkt
    }
}

/// Unified parsed representation of an SRT 16-byte fixed header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrtHeader {
    /// True if bit 0 is 1 (Control packet); false if bit 0 is 0 (Data packet).
    pub is_control: bool,
    /// Packet kind: Data or Control.
    pub packet_type: SrtPacketKind,
    /// Alias for [`Self::packet_type`].
    pub packet_kind: SrtPacketKind,
    /// 32-bit timestamp in microseconds.
    pub timestamp: u32,
    /// Alias for [`Self::timestamp`].
    pub timestamp_us: u32,
    /// 32-bit Destination Socket ID.
    pub destination_socket_id: u32,

    // Data-specific fields
    pub sequence_number: Option<u32>,
    pub message_number: Option<u32>,
    pub packet_position: Option<PacketPosition>,
    pub in_order: Option<bool>,
    pub encryption_flag: Option<u8>,
    pub retransmitted: Option<bool>,

    // Control-specific fields
    pub control_type: Option<SrtControlType>,
    pub subtype: Option<u16>,
    pub type_specific_info: Option<u32>,
    pub type_specific_information: Option<u32>,

    // Handshake-specific fields (when parsed from a complete handshake packet)
    pub handshake: Option<SrtHandshake>,
    pub handshake_type: Option<u32>,
    pub protocol_version: Option<u32>,
    pub version: Option<u32>,
    pub initial_sequence_number: Option<u32>,
    pub initial_packet_sequence_number: Option<u32>,
    pub srt_socket_id: Option<u32>,
    pub syn_cookie: Option<u32>,
    pub stream_id: Option<String>,
}

impl SrtHeader {
    #[must_use]
    pub const fn is_data(&self) -> bool {
        !self.is_control
    }

    #[must_use]
    pub const fn is_control(&self) -> bool {
        self.is_control
    }

    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    #[must_use]
    pub const fn destination_socket_id(&self) -> u32 {
        self.destination_socket_id
    }

    #[must_use]
    pub const fn sequence_number(&self) -> Option<u32> {
        self.sequence_number
    }

    #[must_use]
    pub const fn message_number(&self) -> Option<u32> {
        self.message_number
    }

    #[must_use]
    pub const fn control_type(&self) -> Option<SrtControlType> {
        self.control_type
    }

    #[must_use]
    pub const fn type_specific_info(&self) -> Option<u32> {
        self.type_specific_info
    }

    #[must_use]
    pub const fn type_specific_information(&self) -> Option<u32> {
        self.type_specific_information
    }

    #[must_use]
    pub const fn handshake_type(&self) -> Option<u32> {
        self.handshake_type
    }

    #[must_use]
    pub const fn protocol_version(&self) -> Option<u32> {
        self.protocol_version
    }

    #[must_use]
    pub const fn initial_sequence_number(&self) -> Option<u32> {
        self.initial_sequence_number
    }

    #[must_use]
    pub const fn srt_socket_id(&self) -> Option<u32> {
        self.srt_socket_id
    }

    #[must_use]
    pub const fn syn_cookie(&self) -> Option<u32> {
        self.syn_cookie
    }

    #[must_use]
    pub fn stream_id(&self) -> Option<&str> {
        self.stream_id.as_deref()
    }

    /// Converts this header to a 16-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SRT_HEADER_LEN] {
        if self.is_control {
            let ctype = self.control_type.map_or(0, |c| c.code());
            encode_control_header(
                ctype,
                self.subtype.unwrap_or(0),
                self.type_specific_info.unwrap_or(0),
                self.timestamp,
                self.destination_socket_id,
            )
        } else {
            encode_data_header(
                self.sequence_number.unwrap_or(0),
                self.packet_position.unwrap_or(PacketPosition::Single),
                self.in_order.unwrap_or(false),
                self.encryption_flag.unwrap_or(0),
                self.retransmitted.unwrap_or(false),
                self.message_number.unwrap_or(0),
                self.timestamp,
                self.destination_socket_id,
            )
        }
    }
}

/// Enum representing parsed SRT packet types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SrtPacket {
    Data(SrtDataHeader),
    Control(SrtControlHeader),
    Handshake(SrtHandshake),
}

impl SrtPacket {
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(self, Self::Data(_))
    }

    #[must_use]
    pub const fn is_control(&self) -> bool {
        matches!(self, Self::Control(_) | Self::Handshake(_))
    }

    #[must_use]
    pub const fn timestamp(&self) -> Option<u32> {
        match self {
            Self::Data(d) => Some(d.timestamp),
            Self::Control(c) => Some(c.timestamp),
            Self::Handshake(_) => None,
        }
    }

    #[must_use]
    pub const fn destination_socket_id(&self) -> Option<u32> {
        match self {
            Self::Data(d) => Some(d.destination_socket_id),
            Self::Control(c) => Some(c.destination_socket_id),
            Self::Handshake(_) => None,
        }
    }

    #[must_use]
    pub const fn sequence_number(&self) -> Option<u32> {
        match self {
            Self::Data(d) => Some(d.sequence_number),
            Self::Control(_) | Self::Handshake(_) => None,
        }
    }

    #[must_use]
    pub const fn message_number(&self) -> Option<u32> {
        match self {
            Self::Data(d) => Some(d.message_number),
            Self::Control(_) | Self::Handshake(_) => None,
        }
    }

    #[must_use]
    pub const fn control_type(&self) -> Option<SrtControlType> {
        match self {
            Self::Control(c) => Some(c.control_type),
            Self::Handshake(_) => Some(SrtControlType::Handshake),
            Self::Data(_) => None,
        }
    }

    #[must_use]
    pub const fn type_specific_info(&self) -> Option<u32> {
        match self {
            Self::Control(c) => Some(c.type_specific_info),
            Self::Data(_) | Self::Handshake(_) => None,
        }
    }

    #[must_use]
    pub const fn type_specific_information(&self) -> Option<u32> {
        self.type_specific_info()
    }

    #[must_use]
    pub const fn handshake_type(&self) -> Option<u32> {
        match self {
            Self::Handshake(h) => Some(h.handshake_type),
            Self::Data(_) | Self::Control(_) => None,
        }
    }

    #[must_use]
    pub const fn protocol_version(&self) -> Option<u32> {
        match self {
            Self::Handshake(h) => Some(h.version),
            Self::Data(_) | Self::Control(_) => None,
        }
    }

    #[must_use]
    pub const fn initial_sequence_number(&self) -> Option<u32> {
        match self {
            Self::Handshake(h) => Some(h.initial_sequence_number),
            Self::Data(_) | Self::Control(_) => None,
        }
    }
}

/// Encodes an SRT Data packet header (16 bytes).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode_data_header(
    sequence_number: u32,
    packet_position: PacketPosition,
    in_order: bool,
    encryption_flag: u8,
    retransmitted: bool,
    message_number: u32,
    timestamp: u32,
    destination_socket_id: u32,
) -> [u8; SRT_HEADER_LEN] {
    let mut bytes = [0u8; SRT_HEADER_LEN];

    // Word 0: Bit 0 = 0 (Data), Bits 1..31 = Sequence Number
    let word0 = sequence_number & 0x7FFF_FFFF;
    bytes[0..4].copy_from_slice(&word0.to_be_bytes());

    // Word 1: PP (2 bits), O (1 bit), KK (2 bits), R (1 bit), Message Number (26 bits)
    let pp = (packet_position.code() as u32 & 0x03) << 30;
    let o = if in_order { 1u32 } else { 0u32 } << 29;
    let kk = (encryption_flag as u32 & 0x03) << 27;
    let r = if retransmitted { 1u32 } else { 0u32 } << 26;
    let msg = message_number & 0x03FF_FFFF;
    let word1 = pp | o | kk | r | msg;
    bytes[4..8].copy_from_slice(&word1.to_be_bytes());

    // Word 2: Timestamp (32 bits)
    bytes[8..12].copy_from_slice(&timestamp.to_be_bytes());

    // Word 3: Destination Socket ID (32 bits)
    bytes[12..16].copy_from_slice(&destination_socket_id.to_be_bytes());

    bytes
}

/// Encodes an SRT Control packet header (16 bytes).
#[must_use]
pub fn encode_control_header(
    control_type: u16,
    subtype: u16,
    type_specific_info: u32,
    timestamp: u32,
    destination_socket_id: u32,
) -> [u8; SRT_HEADER_LEN] {
    let mut bytes = [0u8; SRT_HEADER_LEN];

    // Word 0: Bit 0 = 1 (Control), Bits 1..15 = Control Type, Bits 16..31 = Subtype
    let word0 = 0x8000_0000 | ((control_type as u32 & 0x7FFF) << 16) | (subtype as u32 & 0xFFFF);
    bytes[0..4].copy_from_slice(&word0.to_be_bytes());

    // Word 1: Type-specific Information (32 bits)
    bytes[4..8].copy_from_slice(&type_specific_info.to_be_bytes());

    // Word 2: Timestamp (32 bits)
    bytes[8..12].copy_from_slice(&timestamp.to_be_bytes());

    // Word 3: Destination Socket ID (32 bits)
    bytes[12..16].copy_from_slice(&destination_socket_id.to_be_bytes());

    bytes
}

/// Parses a 16-byte buffer into a data packet header [`SrtDataHeader`].
///
/// # Errors
/// Returns [`SrtParseError::TruncatedHeader`] if buffer is shorter than 16 bytes.
/// Returns [`SrtParseError::InvalidPacket`] if bit 0 is not 0 (i.e. is a control packet).
pub fn parse_data_header(data: &[u8]) -> Result<SrtDataHeader, SrtParseError> {
    if data.len() < SRT_HEADER_LEN {
        return Err(SrtParseError::TruncatedHeader);
    }

    let word0 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if (word0 & 0x8000_0000) != 0 {
        return Err(SrtParseError::InvalidPacket);
    }

    let sequence_number = word0 & 0x7FFF_FFFF;

    let word1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let packet_position = PacketPosition::from_u8(((word1 >> 30) & 0x03) as u8);
    let in_order = ((word1 >> 29) & 0x01) != 0;
    let encryption_flag = ((word1 >> 27) & 0x03) as u8;
    let retransmitted = ((word1 >> 26) & 0x01) != 0;
    let message_number = word1 & 0x03FF_FFFF;

    let timestamp = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let destination_socket_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    Ok(SrtDataHeader {
        sequence_number,
        packet_position,
        in_order,
        encryption_flag,
        retransmitted,
        message_number,
        timestamp,
        timestamp_us: timestamp,
        destination_socket_id,
        payload_offset: SRT_HEADER_LEN,
        payload_length: data.len() - SRT_HEADER_LEN,
    })
}

pub use parse_data_header as parse_data_packet;
pub use parse_data_header as parse_srt_data_packet;

/// Parses a 16-byte buffer into a control packet header [`SrtControlHeader`].
///
/// # Errors
/// Returns [`SrtParseError::TruncatedHeader`] if buffer is shorter than 16 bytes.
/// Returns [`SrtParseError::InvalidPacket`] if bit 0 is not 1 (i.e. is a data packet).
pub fn parse_control_header(data: &[u8]) -> Result<SrtControlHeader, SrtParseError> {
    if data.len() < SRT_HEADER_LEN {
        return Err(SrtParseError::TruncatedHeader);
    }

    let word0 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if (word0 & 0x8000_0000) == 0 {
        return Err(SrtParseError::InvalidPacket);
    }

    let control_type_code = ((word0 >> 16) & 0x7FFF) as u16;
    let control_type = SrtControlType::from_u16(control_type_code);
    let subtype = (word0 & 0xFFFF) as u16;

    let type_specific_info = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let timestamp = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let destination_socket_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    Ok(SrtControlHeader {
        control_type,
        subtype,
        type_specific_info,
        type_specific_information: type_specific_info,
        timestamp,
        timestamp_us: timestamp,
        destination_socket_id,
        payload_offset: SRT_HEADER_LEN,
        payload_length: data.len() - SRT_HEADER_LEN,
    })
}

pub use parse_control_header as parse_control_packet;
pub use parse_control_header as parse_srt_control_packet;

/// Parses an SRT Handshake control packet or raw handshake payload.
///
/// Extracts handshake type, protocol version, initial sequence number, and other metadata.
///
/// # Errors
/// Returns [`SrtParseError::TruncatedHeader`] if the input buffer is shorter than 16 bytes.
/// Returns [`SrtParseError::Truncated`] if the input buffer is shorter than required handshake length.
/// Returns [`SrtParseError::InvalidHandshake`] if fields or control types are malformed.
pub fn parse_handshake(data: &[u8]) -> Result<SrtHandshake, SrtParseError> {
    if data.len() < SRT_HEADER_LEN {
        return Err(SrtParseError::TruncatedHeader);
    }

    // Determine whether data contains a 16-byte control header or starts directly with handshake payload.
    let payload_bytes = if data.len() >= SRT_HANDSHAKE_MIN_LEN && (data[0] & 0x80) != 0 {
        // Control packet header present: verify it is a Handshake control packet (type 0x0000)
        let ctype = (((data[0] as u16) & 0x7F) << 8) | (data[1] as u16);
        if ctype != SRT_CMD_HANDSHAKE {
            return Err(SrtParseError::InvalidHandshake);
        }
        &data[SRT_HEADER_LEN..]
    } else if data.len() >= SRT_HANDSHAKE_PAYLOAD_LEN {
        // Raw 48+ byte handshake payload
        data
    } else {
        return Err(SrtParseError::Truncated {
            expected: SRT_HANDSHAKE_MIN_LEN,
            actual: data.len(),
        });
    };

    if payload_bytes.len() < SRT_HANDSHAKE_PAYLOAD_LEN {
        return Err(SrtParseError::Truncated {
            expected: SRT_HANDSHAKE_PAYLOAD_LEN,
            actual: payload_bytes.len(),
        });
    }

    let version = u32::from_be_bytes([
        payload_bytes[0],
        payload_bytes[1],
        payload_bytes[2],
        payload_bytes[3],
    ]);
    let encryption_field = u16::from_be_bytes([payload_bytes[4], payload_bytes[5]]);
    let extension_field = u16::from_be_bytes([payload_bytes[6], payload_bytes[7]]);
    let initial_sequence_number = u32::from_be_bytes([
        payload_bytes[8],
        payload_bytes[9],
        payload_bytes[10],
        payload_bytes[11],
    ]);
    let mtu = u32::from_be_bytes([
        payload_bytes[12],
        payload_bytes[13],
        payload_bytes[14],
        payload_bytes[15],
    ]);
    let max_flow_window_size = u32::from_be_bytes([
        payload_bytes[16],
        payload_bytes[17],
        payload_bytes[18],
        payload_bytes[19],
    ]);
    let handshake_type = u32::from_be_bytes([
        payload_bytes[20],
        payload_bytes[21],
        payload_bytes[22],
        payload_bytes[23],
    ]);
    let srt_socket_id = u32::from_be_bytes([
        payload_bytes[24],
        payload_bytes[25],
        payload_bytes[26],
        payload_bytes[27],
    ]);
    let syn_cookie = u32::from_be_bytes([
        payload_bytes[28],
        payload_bytes[29],
        payload_bytes[30],
        payload_bytes[31],
    ]);

    let mut peer_ip = [0u8; 16];
    peer_ip.copy_from_slice(&payload_bytes[32..48]);

    // Parse optional handshake extension blocks (e.g. SRT_CMD_SID)
    let mut stream_id = None;
    let mut cursor = SRT_HANDSHAKE_PAYLOAD_LEN;
    while cursor + 4 <= payload_bytes.len() {
        let ext_type = u16::from_be_bytes([payload_bytes[cursor], payload_bytes[cursor + 1]]);
        let ext_words =
            u16::from_be_bytes([payload_bytes[cursor + 2], payload_bytes[cursor + 3]]) as usize;
        let ext_len_bytes = ext_words * 4;
        cursor += 4;

        if cursor + ext_len_bytes > payload_bytes.len() {
            break;
        }

        if ext_type == SRT_CMD_SID {
            let sid_raw = &payload_bytes[cursor..cursor + ext_len_bytes];
            let sid_str = String::from_utf8_lossy(sid_raw)
                .trim_end_matches('\0')
                .to_string();
            stream_id = Some(sid_str);
        }

        cursor += ext_len_bytes;
    }

    Ok(SrtHandshake {
        version,
        protocol_version: version,
        encryption_field,
        extension_field,
        initial_sequence_number,
        initial_packet_sequence_number: initial_sequence_number,
        mtu,
        mtu_size: mtu,
        max_flow_window_size,
        flow_window_size: max_flow_window_size,
        handshake_type,
        handshake_kind: SrtHandshakeType::from_u32(handshake_type),
        srt_socket_id,
        source_socket_id: srt_socket_id,
        syn_cookie,
        peer_ip,
        peer_ip_address: peer_ip,
        stream_id,
    })
}

pub use parse_handshake as parse_srt_handshake;
pub use parse_handshake as parse_handshake_control;

/// Parses any valid 16-byte SRT packet header into [`SrtHeader`].
///
/// If the packet is a Handshake packet and carries a complete handshake payload (>= 64 bytes),
/// the handshake fields are also extracted.
///
/// # Acceptance Rules
/// - Buffer shorter than 16 bytes returns [`SrtParseError::TruncatedHeader`].
/// - Packet type bit 0 extracts data packet sequence number, message number, timestamp, and socket ID.
/// - Packet type bit 1 extracts control type, type-specific information, timestamp, and socket ID.
pub fn parse_header(data: &[u8]) -> Result<SrtHeader, SrtParseError> {
    if data.len() < SRT_HEADER_LEN {
        return Err(SrtParseError::TruncatedHeader);
    }

    let is_control = (data[0] & 0x80) != 0;
    let timestamp = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let destination_socket_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

    if !is_control {
        // Data Packet
        let word0 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let sequence_number = word0 & 0x7FFF_FFFF;

        let word1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let packet_position = PacketPosition::from_u8(((word1 >> 30) & 0x03) as u8);
        let in_order = ((word1 >> 29) & 0x01) != 0;
        let encryption_flag = ((word1 >> 27) & 0x03) as u8;
        let retransmitted = ((word1 >> 26) & 0x01) != 0;
        let message_number = word1 & 0x03FF_FFFF;

        Ok(SrtHeader {
            is_control: false,
            packet_type: SrtPacketKind::Data,
            packet_kind: SrtPacketKind::Data,
            timestamp,
            timestamp_us: timestamp,
            destination_socket_id,
            sequence_number: Some(sequence_number),
            message_number: Some(message_number),
            packet_position: Some(packet_position),
            in_order: Some(in_order),
            encryption_flag: Some(encryption_flag),
            retransmitted: Some(retransmitted),
            control_type: None,
            subtype: None,
            type_specific_info: None,
            type_specific_information: None,
            handshake: None,
            handshake_type: None,
            protocol_version: None,
            version: None,
            initial_sequence_number: None,
            initial_packet_sequence_number: None,
            srt_socket_id: None,
            syn_cookie: None,
            stream_id: None,
        })
    } else {
        // Control Packet
        let word0 = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let control_type_code = ((word0 >> 16) & 0x7FFF) as u16;
        let control_type = SrtControlType::from_u16(control_type_code);
        let subtype = (word0 & 0xFFFF) as u16;

        let type_specific_info = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let mut handshake = None;
        let mut handshake_type = None;
        let mut protocol_version = None;
        let mut initial_sequence_number = None;
        let mut srt_socket_id = None;
        let mut syn_cookie = None;
        let mut stream_id = None;

        if control_type == SrtControlType::Handshake && data.len() >= SRT_HANDSHAKE_MIN_LEN {
            if let Ok(hs) = parse_handshake(data) {
                handshake_type = Some(hs.handshake_type);
                protocol_version = Some(hs.version);
                initial_sequence_number = Some(hs.initial_sequence_number);
                srt_socket_id = Some(hs.srt_socket_id);
                syn_cookie = Some(hs.syn_cookie);
                stream_id = hs.stream_id.clone();
                handshake = Some(hs);
            }
        }

        Ok(SrtHeader {
            is_control: true,
            packet_type: SrtPacketKind::Control,
            packet_kind: SrtPacketKind::Control,
            timestamp,
            timestamp_us: timestamp,
            destination_socket_id,
            sequence_number: None,
            message_number: None,
            packet_position: None,
            in_order: None,
            encryption_flag: None,
            retransmitted: None,
            control_type: Some(control_type),
            subtype: Some(subtype),
            type_specific_info: Some(type_specific_info),
            type_specific_information: Some(type_specific_info),
            handshake,
            handshake_type,
            protocol_version,
            version: protocol_version,
            initial_sequence_number,
            initial_packet_sequence_number: initial_sequence_number,
            srt_socket_id,
            syn_cookie,
            stream_id,
        })
    }
}

pub use parse_header as parse_srt_header;

/// Parses a packet buffer into an [`SrtPacket`] enum.
///
/// # Errors
/// Returns [`SrtParseError::TruncatedHeader`] if buffer is shorter than 16 bytes.
/// Returns [`SrtParseError::InvalidPacket`] if packet structure is invalid.
pub fn parse_packet(data: &[u8]) -> Result<SrtPacket, SrtParseError> {
    if data.len() < SRT_HEADER_LEN {
        return Err(SrtParseError::TruncatedHeader);
    }

    let is_control = (data[0] & 0x80) != 0;
    if !is_control {
        parse_data_header(data).map(SrtPacket::Data)
    } else {
        let control_type_code = (((data[0] as u16) & 0x7F) << 8) | (data[1] as u16);
        if control_type_code == SRT_CMD_HANDSHAKE && data.len() >= SRT_HANDSHAKE_MIN_LEN {
            parse_handshake(data).map(SrtPacket::Handshake)
        } else {
            parse_control_header(data).map(SrtPacket::Control)
        }
    }
}

pub use parse_packet as parse_srt_packet;

/// Helper detecting common non-SRT payload patterns (e.g. HTTP, ASCII commands, CBOR, IPv4).
fn is_obviously_non_srt(data: &[u8]) -> bool {
    // Check known non-SRT protocol prefixes
    if data.starts_with(b"HTTP/")
        || data.starts_with(b"GET ")
        || data.starts_with(b"POST ")
        || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ")
        || data.starts_with(b"HEAD ")
        || data.starts_with(b"OPTIONS ")
        || data.starts_with(b"CONNECT ")
        || data.starts_with(b"TRACE ")
        || data.starts_with(b"PATCH ")
        || data.starts_with(b"SSH-")
        || data.starts_with(b"{\"")
        || data.starts_with(b"<?xml")
    {
        return true;
    }

    // Check if the entire 16-byte header is printable ASCII text with spaces / newlines
    if data.len() >= SRT_HEADER_LEN
        && data[..SRT_HEADER_LEN]
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\r' || b == b'\n' || b == b'\t')
    {
        // Real SRT binary headers contain binary timestamps and socket IDs, which rarely consist solely
        // of printable ASCII text and whitespace.
        return true;
    }

    false
}

/// Evaluates raw payload bytes, returning an [`SrtParseStatus`] distinguishing valid SRT from non-SRT traffic without panicking.
#[must_use]
pub fn evaluate_payload(data: &[u8]) -> SrtParseStatus {
    if data.is_empty() || data.len() < SRT_HEADER_LEN {
        return SrtParseStatus::Truncated;
    }

    if is_obviously_non_srt(data) {
        return SrtParseStatus::NotSrt;
    }

    let is_control = (data[0] & 0x80) != 0;
    if is_control {
        let control_type_raw = (((data[0] as u16) & 0x7F) << 8) | (data[1] as u16);
        let control_type = SrtControlType::from_u16(control_type_raw);
        if !control_type.is_standard() {
            return SrtParseStatus::NotSrt;
        }

        if control_type == SrtControlType::Handshake {
            if data.len() < SRT_HANDSHAKE_MIN_LEN {
                return SrtParseStatus::Truncated;
            }
            let version = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
            if version != UDT_VERSION_4 && version != SRT_VERSION_5 {
                return SrtParseStatus::NotSrt;
            }
            let hs_type = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);
            let valid_hs = matches!(
                hs_type,
                SRT_HS_DONE
                    | SRT_HS_AGREEMENT
                    | SRT_HS_CONCLUSION
                    | SRT_HS_INDUCTION
                    | SRT_HS_WAVEAHAND
            );
            if !valid_hs {
                return SrtParseStatus::MalformedSrt;
            }
        }
    } else {
        // Data packet checks
        let word1 = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let kk = (word1 >> 27) & 0x03;
        if kk == 0b11 {
            // Reserved encryption flag in SRT specification
            return SrtParseStatus::MalformedSrt;
        }
    }

    SrtParseStatus::Valid
}

/// Alias for [`evaluate_payload`].
#[must_use]
pub fn evaluate_srt_payload(data: &[u8]) -> SrtParseStatus {
    evaluate_payload(data)
}

/// Evaluates raw payload bytes, returning both [`SrtParseStatus`] and optional [`SrtHeader`].
#[must_use]
pub fn evaluate_srt_header(data: &[u8]) -> (SrtParseStatus, Option<SrtHeader>) {
    let status = evaluate_payload(data);
    if status.is_valid() {
        match parse_header(data) {
            Ok(hdr) => (status, Some(hdr)),
            Err(e) => (e.status(), None),
        }
    } else {
        (status, None)
    }
}

pub use evaluate_srt_header as evaluate_header;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_position_round_trip() {
        for (code, expected) in [
            (0b00, PacketPosition::Middle),
            (0b01, PacketPosition::Last),
            (0b10, PacketPosition::First),
            (0b11, PacketPosition::Single),
        ] {
            let pos = PacketPosition::from_u8(code);
            assert_eq!(pos, expected);
            assert_eq!(pos.code(), code);
        }
    }

    #[test]
    fn test_control_type_mapping() {
        assert_eq!(SrtControlType::from_u16(0x0000), SrtControlType::Handshake);
        assert_eq!(SrtControlType::from_u16(0x0001), SrtControlType::Keepalive);
        assert_eq!(SrtControlType::from_u16(0x0002), SrtControlType::Ack);
        assert_eq!(SrtControlType::from_u16(0x0003), SrtControlType::Nak);
        assert_eq!(
            SrtControlType::from_u16(0x0004),
            SrtControlType::CongestionWarning
        );
        assert_eq!(SrtControlType::from_u16(0x0005), SrtControlType::Shutdown);
        assert_eq!(SrtControlType::from_u16(0x0006), SrtControlType::AckAck);
        assert_eq!(SrtControlType::from_u16(0x0007), SrtControlType::DropReq);
        assert_eq!(SrtControlType::from_u16(0x0008), SrtControlType::PeerError);
        assert_eq!(
            SrtControlType::from_u16(0x7FFF),
            SrtControlType::UserDefined
        );
        assert_eq!(
            SrtControlType::from_u16(0x1234),
            SrtControlType::Unknown(0x1234)
        );
    }
}
