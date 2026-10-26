//! In-tree MQTT fixed header parser and variable-byte integer codec (SPEC §5, §8, §14, Task RER-F-056).
//!
//! Provides a zero-dependency in-tree MQTT fixed header parser and variable-byte integer
//! codec supporting MQTT 3.1.1 and MQTT 5.0 specifications (OASIS standard).
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14 and §8, RER implements passive metadata inspection of MQTT
//! fixed packet headers. RER does not implement an MQTT broker, topic tree filtering, client
//! session state, message persistence, QoS 1/2 retransmission queues, TLS termination,
//! or application-payload decoding. Forwarded packets are transmitted byte-unmodified.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

/// Minimum MQTT fixed header length in octets (1 byte packet type/flags + 1 byte remaining length).
pub const MQTT_MIN_FIXED_HEADER_LEN: usize = 2;

/// Maximum MQTT fixed header length in octets (1 byte packet type/flags + 4 bytes remaining length).
pub const MQTT_MAX_FIXED_HEADER_LEN: usize = 5;

/// Maximum number of octets in an MQTT Variable Byte Integer field (4 octets).
pub const MQTT_MAX_VARINT_BYTES: usize = 4;

/// Maximum variable-byte integer value (268,435,455 / 0x0FFF_FFFF) per OASIS MQTT spec.
pub const MQTT_MAX_VARIABLE_BYTE_INTEGER: usize = 268_435_455;

/// Maximum total MQTT packet size supported by the protocol (header + remaining length).
pub const MQTT_MAX_PACKET_SIZE: usize = MQTT_MAX_VARIABLE_BYTE_INTEGER + MQTT_MAX_FIXED_HEADER_LEN;

// Raw 4-bit MQTT Control Packet types (OASIS MQTT 3.1.1 §2.2.1 and MQTT 5.0 §2.1.2)
pub const MQTT_TYPE_CONNECT: u8 = 1;
pub const MQTT_TYPE_CONNACK: u8 = 2;
pub const MQTT_TYPE_PUBLISH: u8 = 3;
pub const MQTT_TYPE_PUBACK: u8 = 4;
pub const MQTT_TYPE_PUBREC: u8 = 5;
pub const MQTT_TYPE_PUBREL: u8 = 6;
pub const MQTT_TYPE_PUBCOMP: u8 = 7;
pub const MQTT_TYPE_SUBSCRIBE: u8 = 8;
pub const MQTT_TYPE_SUBACK: u8 = 9;
pub const MQTT_TYPE_UNSUBSCRIBE: u8 = 10;
pub const MQTT_TYPE_UNSUBACK: u8 = 11;
pub const MQTT_TYPE_PINGREQ: u8 = 12;
pub const MQTT_TYPE_PINGRESP: u8 = 13;
pub const MQTT_TYPE_DISCONNECT: u8 = 14;
pub const MQTT_TYPE_AUTH: u8 = 15;

/// MQTT Control Packet type representation as defined in OASIS MQTT specifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum MqttPacketType {
    /// Client request to connect to Server (1).
    Connect = 1,
    /// Connect acknowledgment (2).
    Connack = 2,
    /// Publish message (3).
    Publish = 3,
    /// Publish acknowledgment for QoS 1 (4).
    Puback = 4,
    /// Publish received for QoS 2 delivery part 1 (5).
    Pubrec = 5,
    /// Publish release for QoS 2 delivery part 2 (6).
    Pubrel = 6,
    /// Publish complete for QoS 2 delivery part 3 (7).
    Pubcomp = 7,
    /// Client subscribe request (8).
    Subscribe = 8,
    /// Subscribe acknowledgment (9).
    Suback = 9,
    /// Unsubscribe request (10).
    Unsubscribe = 10,
    /// Unsubscribe acknowledgment (11).
    Unsuback = 11,
    /// PING request (12).
    Pingreq = 12,
    /// PING response (13).
    Pingresp = 13,
    /// Notification that client or server is disconnecting (14).
    Disconnect = 14,
    /// Authentication exchange (15, MQTT 5.0).
    Auth = 15,
}

impl MqttPacketType {
    pub const CONNECT: Self = Self::Connect;
    pub const CONNACK: Self = Self::Connack;
    pub const PUBLISH: Self = Self::Publish;
    pub const PUBACK: Self = Self::Puback;
    pub const PUBREC: Self = Self::Pubrec;
    pub const PUBREL: Self = Self::Pubrel;
    pub const PUBCOMP: Self = Self::Pubcomp;
    pub const SUBSCRIBE: Self = Self::Subscribe;
    pub const SUBACK: Self = Self::Suback;
    pub const UNSUBSCRIBE: Self = Self::Unsubscribe;
    pub const UNSUBACK: Self = Self::Unsuback;
    pub const PINGREQ: Self = Self::Pingreq;
    pub const PINGRESP: Self = Self::Pingresp;
    pub const DISCONNECT: Self = Self::Disconnect;
    pub const AUTH: Self = Self::Auth;

    #[allow(non_upper_case_globals)]
    pub const PingReq: Self = Self::Pingreq;
    #[allow(non_upper_case_globals)]
    pub const PingResp: Self = Self::Pingresp;

    /// Returns the raw 4-bit packet type code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        *self as u8
    }

    /// Alias for [`code`].
    #[must_use]
    pub const fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Returns the canonical uppercase name of this packet type.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Connect => "CONNECT",
            Self::Connack => "CONNACK",
            Self::Publish => "PUBLISH",
            Self::Puback => "PUBACK",
            Self::Pubrec => "PUBREC",
            Self::Pubrel => "PUBREL",
            Self::Pubcomp => "PUBCOMP",
            Self::Subscribe => "SUBSCRIBE",
            Self::Suback => "SUBACK",
            Self::Unsubscribe => "UNSUBSCRIBE",
            Self::Unsuback => "UNSUBACK",
            Self::Pingreq => "PINGREQ",
            Self::Pingresp => "PINGRESP",
            Self::Disconnect => "DISCONNECT",
            Self::Auth => "AUTH",
        }
    }

    /// Alias for [`name`].
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.name()
    }

    /// Parses a 4-bit packet type code into an [`MqttPacketType`].
    ///
    /// # Errors
    /// Returns [`MqttParseError::ForbiddenPacketType0`] if the packet type code is 0.
    pub fn from_u8(code: u8) -> Result<Self, MqttParseError> {
        match code {
            0 => Err(MqttParseError::ForbiddenPacketType0),
            1 => Ok(Self::Connect),
            2 => Ok(Self::Connack),
            3 => Ok(Self::Publish),
            4 => Ok(Self::Puback),
            5 => Ok(Self::Pubrec),
            6 => Ok(Self::Pubrel),
            7 => Ok(Self::Pubcomp),
            8 => Ok(Self::Subscribe),
            9 => Ok(Self::Suback),
            10 => Ok(Self::Unsubscribe),
            11 => Ok(Self::Unsuback),
            12 => Ok(Self::Pingreq),
            13 => Ok(Self::Pingresp),
            14 => Ok(Self::Disconnect),
            15 => Ok(Self::Auth),
            _ => Err(MqttParseError::ForbiddenPacketType0),
        }
    }
}

impl PartialEq<u8> for MqttPacketType {
    fn eq(&self, other: &u8) -> bool {
        (*self as u8) == *other
    }
}

impl PartialEq<MqttPacketType> for u8 {
    fn eq(&self, other: &MqttPacketType) -> bool {
        *self == (*other as u8)
    }
}

impl From<MqttPacketType> for u8 {
    fn from(pt: MqttPacketType) -> Self {
        pt as u8
    }
}

impl TryFrom<u8> for MqttPacketType {
    type Error = MqttParseError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Self::from_u8(code)
    }
}

impl Deref for MqttPacketType {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Connect => &1,
            Self::Connack => &2,
            Self::Publish => &3,
            Self::Puback => &4,
            Self::Pubrec => &5,
            Self::Pubrel => &6,
            Self::Pubcomp => &7,
            Self::Subscribe => &8,
            Self::Suback => &9,
            Self::Unsubscribe => &10,
            Self::Unsuback => &11,
            Self::Pingreq => &12,
            Self::Pingresp => &13,
            Self::Disconnect => &14,
            Self::Auth => &15,
        }
    }
}

impl fmt::Display for MqttPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Errors encountered while parsing MQTT packet headers or decoding variable byte integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MqttParseError {
    /// Packet data is shorter than declared or variable byte integer is truncated.
    TruncatedPacket,
    /// Packet type 0 is forbidden according to OASIS MQTT specifications.
    ForbiddenPacketType0,
    /// Variable byte integer exceeds 4 octets.
    VariableByteIntegerOverflow,
    /// Header flag bits are invalid or non-zero for the packet type.
    InvalidFlags,
}

impl MqttParseError {
    pub const TRUNCATED_PACKET: Self = Self::TruncatedPacket;
    pub const FORBIDDEN_PACKET_TYPE_0: Self = Self::ForbiddenPacketType0;
    pub const VARIABLE_BYTE_INTEGER_OVERFLOW: Self = Self::VariableByteIntegerOverflow;
    pub const LENGTH_OVERFLOW: Self = Self::VariableByteIntegerOverflow;
    pub const INVALID_FLAGS: Self = Self::InvalidFlags;
    pub const NON_ZERO_FLAGS: Self = Self::InvalidFlags;

    #[allow(non_upper_case_globals)]
    pub const Truncated: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const TruncatedHeader: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const TruncatedPacketData: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const ForbiddenPacketType: Self = Self::ForbiddenPacketType0;
    #[allow(non_upper_case_globals)]
    pub const LengthOverflow: Self = Self::VariableByteIntegerOverflow;
    #[allow(non_upper_case_globals)]
    pub const VarintOverflow: Self = Self::VariableByteIntegerOverflow;
    #[allow(non_upper_case_globals)]
    pub const NonZeroFlags: Self = Self::InvalidFlags;

    /// Returns true if this error indicates truncated packet data.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::TruncatedPacket)
    }

    /// Alias for [`is_truncated`].
    #[must_use]
    pub const fn is_truncated_packet(&self) -> bool {
        matches!(self, Self::TruncatedPacket)
    }

    /// Returns true if this error indicates length overflow beyond 4 octets.
    #[must_use]
    pub const fn is_length_overflow(&self) -> bool {
        matches!(self, Self::VariableByteIntegerOverflow)
    }

    /// Alias for [`is_length_overflow`].
    #[must_use]
    pub const fn is_varint_overflow(&self) -> bool {
        matches!(self, Self::VariableByteIntegerOverflow)
    }

    /// Returns true if this error indicates forbidden packet type 0.
    #[must_use]
    pub const fn is_forbidden_packet_type(&self) -> bool {
        matches!(self, Self::ForbiddenPacketType0)
    }

    /// Alias for [`is_forbidden_packet_type`].
    #[must_use]
    pub const fn is_forbidden_packet_type_0(&self) -> bool {
        matches!(self, Self::ForbiddenPacketType0)
    }

    /// Returns true if this error indicates invalid or non-zero flags.
    #[must_use]
    pub const fn is_invalid_flags(&self) -> bool {
        matches!(self, Self::InvalidFlags)
    }

    /// Alias for [`is_invalid_flags`].
    #[must_use]
    pub const fn is_non_zero_flags(&self) -> bool {
        matches!(self, Self::InvalidFlags)
    }
}

impl fmt::Display for MqttParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedPacket => {
                write!(
                    f,
                    "truncated packet data: buffer shorter than declared variable byte integer or declared remaining length"
                )
            }
            Self::ForbiddenPacketType0 => {
                write!(
                    f,
                    "forbidden packet type 0: packet type 0 is reserved and forbidden"
                )
            }
            Self::VariableByteIntegerOverflow => {
                write!(f, "variable byte integer length overflow beyond 4 octets")
            }
            Self::InvalidFlags => {
                write!(
                    f,
                    "invalid packet flags: rejecting non-zero flags or invalid flag combination"
                )
            }
        }
    }
}

impl std::error::Error for MqttParseError {}

/// High-level parse status for MQTT packet inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MqttParseStatus {
    /// Packet fixed header parsed successfully and complete packet is present.
    Valid,
    /// Packet data is truncated.
    Truncated,
    /// Packet type 0 was encountered (forbidden).
    ForbiddenPacketType,
    /// Variable byte integer exceeded 4 octets.
    VariableByteIntegerOverflow,
    /// Flags are invalid for packet type.
    InvalidFlags,
}

impl MqttParseStatus {
    /// Returns true if the status is [`Self::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns true if the status is [`Self::Truncated`].
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated)
    }

    /// Returns true if the status is [`Self::ForbiddenPacketType`].
    #[must_use]
    pub const fn is_forbidden_packet_type(&self) -> bool {
        matches!(self, Self::ForbiddenPacketType)
    }

    /// Returns true if the status is [`Self::VariableByteIntegerOverflow`].
    #[must_use]
    pub const fn is_length_overflow(&self) -> bool {
        matches!(self, Self::VariableByteIntegerOverflow)
    }

    /// Returns true if the status is [`Self::InvalidFlags`].
    #[must_use]
    pub const fn is_invalid_flags(&self) -> bool {
        matches!(self, Self::InvalidFlags)
    }
}

impl From<MqttParseError> for MqttParseStatus {
    fn from(err: MqttParseError) -> Self {
        match err {
            MqttParseError::TruncatedPacket => Self::Truncated,
            MqttParseError::ForbiddenPacketType0 => Self::ForbiddenPacketType,
            MqttParseError::VariableByteIntegerOverflow => Self::VariableByteIntegerOverflow,
            MqttParseError::InvalidFlags => Self::InvalidFlags,
        }
    }
}

/// Parsed representation of an MQTT Control Packet Fixed Header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MqttFixedHeader {
    /// MQTT Control Packet type.
    pub packet_type: MqttPacketType,
    /// 4-bit header flags from the first octet.
    pub flags: u8,
    /// Declared remaining length in octets.
    pub remaining_length: usize,
    /// Length of the fixed header in octets (1 byte type/flags + 1-4 bytes remaining length).
    pub header_len: usize,
    /// Alias for [`header_len`].
    pub header_length: usize,
    /// Total packet length in octets (header length + remaining length).
    pub total_packet_len: usize,
    /// Alias for [`total_packet_len`].
    pub total_packet_length: usize,
}

impl MqttFixedHeader {
    /// Returns the raw 4-bit packet type code.
    #[must_use]
    pub const fn packet_type_code(&self) -> u8 {
        self.packet_type.code()
    }

    /// Returns the canonical uppercase name of this packet type.
    #[must_use]
    pub const fn packet_type_name(&self) -> &'static str {
        self.packet_type.name()
    }

    /// Extracted QoS level if this is a PUBLISH packet (bits 2..1 of flags).
    #[must_use]
    pub const fn qos(&self) -> Option<u8> {
        if matches!(self.packet_type, MqttPacketType::Publish) {
            Some((self.flags >> 1) & 0x03)
        } else {
            None
        }
    }

    /// Duplicate delivery flag if this is a PUBLISH packet (bit 3 of flags).
    #[must_use]
    pub const fn dup(&self) -> Option<bool> {
        if matches!(self.packet_type, MqttPacketType::Publish) {
            Some((self.flags & 0x08) != 0)
        } else {
            None
        }
    }

    /// Retain flag if this is a PUBLISH packet (bit 0 of flags).
    #[must_use]
    pub const fn retain(&self) -> Option<bool> {
        if matches!(self.packet_type, MqttPacketType::Publish) {
            Some((self.flags & 0x01) != 0)
        } else {
            None
        }
    }

    /// Returns true if this packet is a CONNECT control packet.
    #[must_use]
    pub const fn is_connect(&self) -> bool {
        matches!(self.packet_type, MqttPacketType::Connect)
    }

    /// Returns true if this packet is a PUBLISH control packet.
    #[must_use]
    pub const fn is_publish(&self) -> bool {
        matches!(self.packet_type, MqttPacketType::Publish)
    }

    /// Returns true if this packet is a PINGREQ control packet.
    #[must_use]
    pub const fn is_pingreq(&self) -> bool {
        matches!(self.packet_type, MqttPacketType::Pingreq)
    }

    /// Returns true if this packet is a PINGRESP control packet.
    #[must_use]
    pub const fn is_pingresp(&self) -> bool {
        matches!(self.packet_type, MqttPacketType::Pingresp)
    }

    /// Returns true if this packet is a DISCONNECT control packet.
    #[must_use]
    pub const fn is_disconnect(&self) -> bool {
        matches!(self.packet_type, MqttPacketType::Disconnect)
    }
}

/// Decodes an MQTT Variable Byte Integer from `buf`.
///
/// Returns `Ok((value, bytes_consumed))` on success.
///
/// # Errors
/// - Returns [`MqttParseError::TruncatedPacket`] if `buf` ends before the continuation bit (MSB) clears.
/// - Returns [`MqttParseError::VariableByteIntegerOverflow`] if the integer exceeds 4 octets.
pub fn decode_variable_byte_integer(buf: &[u8]) -> Result<(usize, usize), MqttParseError> {
    if buf.is_empty() {
        return Err(MqttParseError::TruncatedPacket);
    }

    let mut multiplier: usize = 1;
    let mut value: usize = 0;
    let mut bytes_read: usize = 0;

    for &b in buf {
        bytes_read += 1;
        if bytes_read > MQTT_MAX_VARINT_BYTES {
            return Err(MqttParseError::VariableByteIntegerOverflow);
        }

        value += ((b & 0x7F) as usize) * multiplier;

        if (b & 0x80) == 0 {
            return Ok((value, bytes_read));
        }

        multiplier *= 128;
    }

    // Buffer ended while continuation bit was set
    if bytes_read >= MQTT_MAX_VARINT_BYTES {
        return Err(MqttParseError::VariableByteIntegerOverflow);
    }

    Err(MqttParseError::TruncatedPacket)
}

/// Alias for [`decode_variable_byte_integer`].
pub fn decode_varint(buf: &[u8]) -> Result<(usize, usize), MqttParseError> {
    decode_variable_byte_integer(buf)
}

/// Alias for [`decode_variable_byte_integer`].
pub fn decode_variable_length_integer(buf: &[u8]) -> Result<(usize, usize), MqttParseError> {
    decode_variable_byte_integer(buf)
}

/// Encodes an unsigned integer into an MQTT Variable Byte Integer in `buf`.
///
/// Returns the number of octets written (1 to 4).
///
/// # Errors
/// - Returns [`MqttParseError::VariableByteIntegerOverflow`] if `val` exceeds 268,435,455.
/// - Returns [`MqttParseError::TruncatedPacket`] if `buf` is too small to receive the encoded bytes.
pub fn encode_variable_byte_integer(val: usize, buf: &mut [u8]) -> Result<usize, MqttParseError> {
    if val > MQTT_MAX_VARIABLE_BYTE_INTEGER {
        return Err(MqttParseError::VariableByteIntegerOverflow);
    }

    let mut x = val;
    let mut bytes_written = 0;

    loop {
        let mut encoded_byte = (x % 128) as u8;
        x /= 128;
        if x > 0 {
            encoded_byte |= 0x80;
        }

        if bytes_written >= buf.len() {
            return Err(MqttParseError::TruncatedPacket);
        }

        buf[bytes_written] = encoded_byte;
        bytes_written += 1;

        if x == 0 {
            break;
        }
    }

    Ok(bytes_written)
}

/// Alias for [`encode_variable_byte_integer`].
pub fn encode_varint(val: usize, buf: &mut [u8]) -> Result<usize, MqttParseError> {
    encode_variable_byte_integer(val, buf)
}

/// Encodes an unsigned integer into an MQTT Variable Byte Integer returning a `Vec<u8>`.
///
/// # Errors
/// Returns [`MqttParseError::VariableByteIntegerOverflow`] if `val` exceeds 268,435,455.
pub fn encode_variable_byte_integer_vec(val: usize) -> Result<Vec<u8>, MqttParseError> {
    let mut buf = [0u8; MQTT_MAX_VARINT_BYTES];
    let len = encode_variable_byte_integer(val, &mut buf)?;
    Ok(buf[..len].to_vec())
}

/// Validates MQTT fixed header flag bits for a given packet type code according to OASIS MQTT specifications.
///
/// # Errors
/// Returns [`MqttParseError::InvalidFlags`] if flags do not match mandatory values.
pub fn validate_flags(packet_type: u8, flags: u8) -> Result<(), MqttParseError> {
    match packet_type {
        1 | 2 | 4 | 5 | 7 | 9 | 11 | 12 | 13 | 14 | 15 => {
            // CONNECT, CONNACK, PUBACK, PUBREC, PUBCOMP, SUBACK, UNSUBACK,
            // PINGREQ, PINGRESP, DISCONNECT, AUTH: flags must be 0000
            if flags != 0 {
                return Err(MqttParseError::InvalidFlags);
            }
        }
        3 => {
            // PUBLISH: QoS bits (bits 2..=1) must not be 3 (0b11)
            let qos = (flags >> 1) & 0x03;
            if qos == 3 {
                return Err(MqttParseError::InvalidFlags);
            }
        }
        6 | 8 | 10 => {
            // PUBREL, SUBSCRIBE, UNSUBSCRIBE: flags must be 0010 (2)
            if flags != 0b0010 {
                return Err(MqttParseError::InvalidFlags);
            }
        }
        _ => return Err(MqttParseError::ForbiddenPacketType0),
    }
    Ok(())
}

/// Parses an MQTT Control Packet fixed header from `buf` with strict validation.
///
/// # Errors
/// - Returns [`MqttParseError::TruncatedPacket`] if `buf` is shorter than the fixed header
///   or shorter than the declared total packet length.
/// - Returns [`MqttParseError::ForbiddenPacketType0`] if the 4 high bits of the first byte are 0.
/// - Returns [`MqttParseError::InvalidFlags`] if the header flag bits violate specification rules.
/// - Returns [`MqttParseError::VariableByteIntegerOverflow`] if the remaining length field exceeds 4 octets.
pub fn parse_mqtt_fixed_header(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header_internal(buf, true, true)
}

/// Parses an MQTT Control Packet fixed header without enforcing flag validation rules.
pub fn parse_mqtt_fixed_header_relaxed(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header_internal(buf, false, true)
}

/// Parses an MQTT Control Packet fixed header without requiring the buffer to contain the entire payload.
pub fn parse_mqtt_fixed_header_prefix(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header_internal(buf, true, false)
}

fn parse_mqtt_fixed_header_internal(
    buf: &[u8],
    strict_flags: bool,
    check_payload_len: bool,
) -> Result<MqttFixedHeader, MqttParseError> {
    if buf.is_empty() {
        return Err(MqttParseError::TruncatedPacket);
    }

    let first_byte = buf[0];
    let packet_type_raw = first_byte >> 4;
    let flags = first_byte & 0x0F;

    if packet_type_raw == 0 {
        return Err(MqttParseError::ForbiddenPacketType0);
    }

    let packet_type = MqttPacketType::from_u8(packet_type_raw)?;

    if strict_flags {
        validate_flags(packet_type_raw, flags)?;
    }

    if buf.len() < 2 {
        return Err(MqttParseError::TruncatedPacket);
    }

    let (remaining_length, varint_len) = decode_variable_byte_integer(&buf[1..])?;
    let header_length = 1 + varint_len;
    let total_packet_length = header_length
        .checked_add(remaining_length)
        .ok_or(MqttParseError::VariableByteIntegerOverflow)?;

    if check_payload_len && buf.len() < total_packet_length {
        return Err(MqttParseError::TruncatedPacket);
    }

    Ok(MqttFixedHeader {
        packet_type,
        flags,
        remaining_length,
        header_len: header_length,
        header_length,
        total_packet_len: total_packet_length,
        total_packet_length,
    })
}

/// Alias for [`parse_mqtt_fixed_header`].
pub fn parse_fixed_header(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header(buf)
}

/// Alias for [`parse_mqtt_fixed_header`].
pub fn parse_mqtt_header(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header(buf)
}

/// Alias for [`parse_mqtt_fixed_header`].
pub fn parse_header(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header(buf)
}

/// Alias for [`parse_mqtt_fixed_header`].
pub fn parse_packet(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header(buf)
}

/// Alias for [`parse_mqtt_fixed_header`].
pub fn parse_mqtt_packet(buf: &[u8]) -> Result<MqttFixedHeader, MqttParseError> {
    parse_mqtt_fixed_header(buf)
}

/// Evaluates an MQTT packet buffer, returning a parse status and optional header.
pub fn evaluate_mqtt_header(buf: &[u8]) -> (MqttParseStatus, Option<MqttFixedHeader>) {
    match parse_mqtt_fixed_header(buf) {
        Ok(header) => (MqttParseStatus::Valid, Some(header)),
        Err(err) => (MqttParseStatus::from(err), None),
    }
}

/// Alias for [`evaluate_mqtt_header`].
pub fn evaluate_header(buf: &[u8]) -> (MqttParseStatus, Option<MqttFixedHeader>) {
    evaluate_mqtt_header(buf)
}

/// Evaluates an MQTT packet payload buffer, returning the parse status.
pub fn evaluate_payload(buf: &[u8]) -> MqttParseStatus {
    evaluate_mqtt_header(buf).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criterion1_decode_variable_byte_integer_128() {
        // Acceptance criterion 1:
        // In crates/rer/src/mqtt.rs, decoding a variable byte integer from byte buffer [0x80, 0x01]
        // returns a decoded value of 128 and 2 bytes consumed.
        let buf = [0x80, 0x01];
        let (val, consumed) =
            decode_variable_byte_integer(&buf).expect("decoding 128 must succeed");
        assert_eq!(val, 128);
        assert_eq!(consumed, 2);

        // Also test alias
        let (val_alias, consumed_alias) =
            decode_varint(&buf).expect("decode_varint alias must succeed");
        assert_eq!(val_alias, 128);
        assert_eq!(consumed_alias, 2);
    }

    #[test]
    fn test_criterion2_decode_varint_5_bytes_overflow() {
        // Acceptance criterion 2:
        // In crates/rer/src/mqtt.rs, decoding a variable byte integer containing 5 consecutive bytes
        // with the continuation bit set returns an error indicating length overflow beyond 4 octets.
        let buf = [0x80, 0x80, 0x80, 0x80, 0x80];
        let err = decode_variable_byte_integer(&buf).expect_err("5 continuation bytes must error");
        assert_eq!(err, MqttParseError::VariableByteIntegerOverflow);
        assert_eq!(err, MqttParseError::LengthOverflow);
        assert!(err.is_length_overflow());
        assert!(format!("{err}")
            .to_lowercase()
            .contains("length overflow beyond 4 octets"));

        // 4 continuation bytes without terminal byte is also length overflow
        let buf4 = [0x80, 0x80, 0x80, 0x80];
        let err4 =
            decode_variable_byte_integer(&buf4).expect_err("4 continuation bytes must error");
        assert_eq!(err4, MqttParseError::VariableByteIntegerOverflow);
        assert!(err4.is_length_overflow());
    }

    #[test]
    fn test_criterion3_connect_non_zero_flags_rejected() {
        // Acceptance criterion 3:
        // In crates/rer/src/mqtt.rs, parsing a fixed header with packet type 1 for CONNECT and flag bits
        // 0b0001 returns an error rejecting non-zero flags.
        let first_byte = (1 << 4) | 0b0001; // packet type 1 (CONNECT), flags 0b0001
        let buf = [first_byte, 0x00];
        let err = parse_mqtt_fixed_header(&buf).expect_err("CONNECT with flags 0b0001 must error");
        assert_eq!(err, MqttParseError::InvalidFlags);
        assert_eq!(err, MqttParseError::NonZeroFlags);
        assert!(err.is_invalid_flags());
        assert!(err.is_non_zero_flags());
        assert!(format!("{err}")
            .to_lowercase()
            .contains("rejecting non-zero flags"));
    }

    #[test]
    fn test_criterion4_pingreq_fixed_header() {
        // Acceptance criterion 4:
        // In crates/rer/src/mqtt.rs, parsing a 2-byte PINGREQ packet with first byte 0xC0 and remaining
        // length byte 0x00 returns an MqttFixedHeader with packet type 12, flags 0, remaining length 0,
        // and total packet length 2.
        let buf = [0xC0, 0x00];
        let header = parse_mqtt_fixed_header(&buf).expect("valid PINGREQ must parse");
        assert_eq!(header.packet_type, 12);
        assert_eq!(header.packet_type, MqttPacketType::Pingreq);
        assert_eq!(header.packet_type_code(), 12);
        assert_eq!(header.packet_type_name(), "PINGREQ");
        assert_eq!(header.flags, 0);
        assert_eq!(header.remaining_length, 0);
        assert_eq!(header.total_packet_length, 2);
        assert_eq!(header.total_packet_len, 2);
        assert_eq!(header.header_len, 2);
        assert_eq!(header.header_length, 2);
        assert!(header.is_pingreq());
    }

    #[test]
    fn test_criterion5_truncated_packet_data() {
        // Acceptance criterion 5:
        // In crates/rer/src/mqtt.rs, parsing a buffer shorter than the declared variable byte integer
        // or declared remaining length returns an error indicating truncated packet data.

        // 1. Shorter than declared variable byte integer (continuation bit set, but buffer ends)
        let buf_truncated_varint = [0xC0, 0x80];
        let err1 = parse_mqtt_fixed_header(&buf_truncated_varint)
            .expect_err("truncated varint must return error");
        assert_eq!(err1, MqttParseError::TruncatedPacket);
        assert!(err1.is_truncated());
        assert!(format!("{err1}")
            .to_lowercase()
            .contains("truncated packet data"));

        // 2. Shorter than declared remaining length (declared length = 10, but only 2 payload bytes provided)
        let mut buf_truncated_remaining = vec![0x30, 0x0A]; // PUBLISH QoS 0, remaining len 10
        buf_truncated_remaining.extend_from_slice(&[0x01, 0x02]); // only 2 bytes instead of 10
        let err2 = parse_mqtt_fixed_header(&buf_truncated_remaining)
            .expect_err("shorter than remaining length must return error");
        assert_eq!(err2, MqttParseError::TruncatedPacket);
        assert!(err2.is_truncated());
        assert!(format!("{err2}")
            .to_lowercase()
            .contains("truncated packet data"));

        // 3. Completely empty buffer
        let empty: &[u8] = &[];
        let err3 = parse_mqtt_fixed_header(empty).expect_err("empty buffer must error");
        assert_eq!(err3, MqttParseError::TruncatedPacket);
        assert!(err3.is_truncated());
    }

    #[test]
    fn test_criterion6_forbidden_packet_type_0() {
        // Acceptance criterion 6:
        // In crates/rer/src/mqtt.rs, parsing a byte buffer whose first byte has 4 high bits equal to 0
        // returns an error indicating forbidden packet type 0.
        let buf = [0x00, 0x00];
        let err = parse_mqtt_fixed_header(&buf).expect_err("packet type 0 must return error");
        assert_eq!(err, MqttParseError::ForbiddenPacketType0);
        assert!(err.is_forbidden_packet_type());
        assert!(format!("{err}")
            .to_lowercase()
            .contains("forbidden packet type 0"));

        let buf_flags = [0x05, 0x00]; // 4 high bits still 0, low bits 5
        let err2 = parse_mqtt_fixed_header(&buf_flags).expect_err("high bits 0 must return error");
        assert_eq!(err2, MqttParseError::ForbiddenPacketType0);
        assert!(err2.is_forbidden_packet_type());
    }

    #[test]
    fn test_variable_byte_integer_boundary_values() {
        // Boundary values per MQTT specifications:
        // 0: [0x00] (1 byte)
        // 127: [0x7F] (1 byte)
        // 128: [0x80, 0x01] (2 bytes)
        // 16383: [0xFF, 0x7F] (2 bytes)
        // 16384: [0x80, 0x80, 0x01] (3 bytes)
        // 2097151: [0xFF, 0xFF, 0x7F] (3 bytes)
        // 2097152: [0x80, 0x80, 0x80, 0x01] (4 bytes)
        // 268435455: [0xFF, 0xFF, 0xFF, 0x7F] (4 bytes)
        let test_cases: &[(usize, &[u8])] = &[
            (0, &[0x00]),
            (127, &[0x7F]),
            (128, &[0x80, 0x01]),
            (16383, &[0xFF, 0x7F]),
            (16384, &[0x80, 0x80, 0x01]),
            (2097151, &[0xFF, 0xFF, 0x7F]),
            (2097152, &[0x80, 0x80, 0x80, 0x01]),
            (268435455, &[0xFF, 0xFF, 0xFF, 0x7F]),
        ];

        for &(expected_val, wire_bytes) in test_cases {
            let (decoded_val, consumed) = decode_variable_byte_integer(wire_bytes)
                .unwrap_or_else(|e| panic!("failed to decode {expected_val}: {e}"));
            assert_eq!(decoded_val, expected_val);
            assert_eq!(consumed, wire_bytes.len());

            // Test round-trip encode
            let mut out = [0u8; 4];
            let written = encode_variable_byte_integer(expected_val, &mut out).unwrap();
            assert_eq!(written, wire_bytes.len());
            assert_eq!(&out[..written], wire_bytes);

            let vec_out = encode_variable_byte_integer_vec(expected_val).unwrap();
            assert_eq!(vec_out, wire_bytes);
        }

        // Exceeding maximum value returns overflow
        let mut out = [0u8; 4];
        assert_eq!(
            encode_variable_byte_integer(268435456, &mut out).unwrap_err(),
            MqttParseError::VariableByteIntegerOverflow
        );
    }

    #[test]
    fn test_all_15_packet_types_parsed() {
        for type_code in 1..=15 {
            let flags = match type_code {
                6 | 8 | 10 => 0b0010, // PUBREL, SUBSCRIBE, UNSUBSCRIBE require 0010
                _ => 0b0000,
            };
            let first_byte = (type_code << 4) | flags;
            let buf = [first_byte, 0x00];
            let header = parse_mqtt_fixed_header(&buf)
                .unwrap_or_else(|e| panic!("type {type_code} failed to parse: {e}"));
            assert_eq!(header.packet_type, type_code);
            assert_eq!(header.flags, flags);
            assert_eq!(header.remaining_length, 0);
            assert_eq!(header.total_packet_length, 2);
        }
    }

    #[test]
    fn test_publish_flags_and_metadata() {
        // PUBLISH with QoS 1 (flags: bit 1 = 1, bit 2 = 0) and DUP bit set (bit 3 = 1) -> 0b1010 = 0x0A
        let first_byte = (3 << 4) | 0b1010;
        let buf = [first_byte, 0x02, 0x11, 0x22];
        let header = parse_mqtt_fixed_header(&buf).expect("PUBLISH QoS 1 must parse");
        assert_eq!(header.packet_type, MqttPacketType::Publish);
        assert_eq!(header.qos(), Some(1));
        assert_eq!(header.dup(), Some(true));
        assert_eq!(header.retain(), Some(false));
        assert_eq!(header.total_packet_length, 4);

        // PUBLISH with invalid QoS 3 (0b11 in bits 2..1) must fail validation
        let invalid_first_byte = (3 << 4) | 0b0110;
        let err =
            parse_mqtt_fixed_header(&[invalid_first_byte, 0x00]).expect_err("QoS 3 must fail");
        assert_eq!(err, MqttParseError::InvalidFlags);
    }

    #[test]
    fn test_evaluation_helpers() {
        let pingreq = [0xC0, 0x00];
        let (status, hdr) = evaluate_mqtt_header(&pingreq);
        assert_eq!(status, MqttParseStatus::Valid);
        assert!(hdr.is_some());
        assert_eq!(evaluate_payload(&pingreq), MqttParseStatus::Valid);

        let bad = [0x00, 0x00];
        let (bad_status, bad_hdr) = evaluate_header(&bad);
        assert_eq!(bad_status, MqttParseStatus::ForbiddenPacketType);
        assert!(bad_hdr.is_none());
    }
}
