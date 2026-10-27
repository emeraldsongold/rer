//! In-tree AX.25 packet header parser (SPEC §14, §5, §8, Task RER-F-061).
//!
//! Provides a zero-dependency in-tree parser for AX.25 packet headers (AX.25 Protocol
//! Specification v2.0 / v2.2) commonly used in amateur radio, APRS, ground stations,
//! and small-satellite telemetry.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14, RER implements passive metadata inspection of AX.25
//! packet headers. RER does not implement connected-mode state machines, flow control,
//! radio/TNC control commands, or application-level APRS decoding. Forwarded datagrams
//! are transmitted byte-unmodified.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Minimum AX.25 frame length in octets (7 destination + 7 source + 1 control = 15).
pub const AX25_MIN_FRAME_LEN: usize = 15;

/// Length of standard AX.25 destination plus source address fields without digipeaters (14 octets).
pub const AX25_STANDARD_ADDR_LEN: usize = 14;

/// Length of a single AX.25 address subfield (callsign + SSID) in octets (7 octets).
pub const AX25_ADDR_SUBFIELD_LEN: usize = 7;

/// Maximum number of digipeater (repeater) addresses permitted by AX.25 v2.0 (8).
pub const AX25_MAX_DIGIPEATERS: usize = 8;

/// Unnumbered Information (UI) frame control byte with Poll/Final = 0.
pub const AX25_CTRL_UI: u8 = 0x03;

/// Unnumbered Information (UI) frame control byte with Poll/Final = 1.
pub const AX25_CTRL_UI_PF: u8 = 0x13;

/// Protocol Identifier (PID) indicating no layer 3 protocol implemented (standard APRS / text).
pub const AX25_PID_NO_LAYER_3: u8 = 0xF0;

/// Protocol Identifier (PID) indicating ISO 8473.
pub const AX25_PID_ISO_8473: u8 = 0x08;

/// Protocol Identifier (PID) indicating ARPA Internet Protocol (IPv4).
pub const AX25_PID_TCP_IP: u8 = 0xCC;

/// Protocol Identifier (PID) indicating ARPA Address Resolution Protocol (ARP).
pub const AX25_PID_ARP: u8 = 0xCD;

/// Protocol Identifier (PID) indicating NET/ROM.
pub const AX25_PID_NETROM: u8 = 0xCF;

/// Protocol Identifier (PID) indicating FLEXNET.
pub const AX25_PID_FLEXNET: u8 = 0xCE;

/// Protocol Identifier (PID) indicating TEXNET.
pub const AX25_PID_TEXNET: u8 = 0xC3;

/// Protocol Identifier (PID) escape character for extended PID.
pub const AX25_PID_ESCAPE: u8 = 0xFF;

/// Error encountered while parsing an AX.25 packet or address header.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ax25ParseError {
    /// Buffer is shorter than required minimum 15 octets or declared field boundaries.
    TruncatedPacket,
    /// Callsign contains non-alphanumeric characters.
    NonAlphanumericCallsign(String),
    /// Invalid callsign formatting or empty callsign.
    InvalidCallsign(String),
    /// Invalid address field structure or terminator bit configuration.
    InvalidAddress(String),
    /// Number of digipeater addresses exceeds the maximum allowed (8).
    TooManyDigipeaters,
    /// Frame control or structure is invalid.
    InvalidFrame(String),
}

impl Ax25ParseError {
    pub const TRUNCATED: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const Truncated: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const TruncatedPacket: Self = Self::TruncatedPacket;
    #[allow(non_upper_case_globals)]
    pub const TruncatedHeader: Self = Self::TruncatedPacket;

    /// Returns true if the error indicates a truncated packet.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::TruncatedPacket)
    }

    /// Returns true if the error indicates a truncated packet.
    #[must_use]
    pub const fn is_truncated_packet(&self) -> bool {
        matches!(self, Self::TruncatedPacket)
    }

    /// Returns true if the error indicates a non-alphanumeric callsign character.
    #[must_use]
    pub fn is_non_alphanumeric_callsign(&self) -> bool {
        matches!(self, Self::NonAlphanumericCallsign(_))
    }

    /// Returns true if the error indicates an invalid or malformed callsign.
    #[must_use]
    pub fn is_invalid_callsign(&self) -> bool {
        matches!(
            self,
            Self::NonAlphanumericCallsign(_) | Self::InvalidCallsign(_)
        )
    }
}

impl fmt::Display for Ax25ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedPacket => {
                write!(
                    f,
                    "truncated packet: AX.25 buffer shorter than minimum 15 octets or declared fields"
                )
            }
            Self::NonAlphanumericCallsign(msg) => {
                write!(f, "non-alphanumeric callsign character: {msg}")
            }
            Self::InvalidCallsign(msg) => {
                write!(f, "invalid AX.25 callsign: {msg}")
            }
            Self::InvalidAddress(msg) => {
                write!(f, "invalid AX.25 address field: {msg}")
            }
            Self::TooManyDigipeaters => {
                write!(
                    f,
                    "too many digipeaters: AX.25 permits a maximum of 8 repeaters"
                )
            }
            Self::InvalidFrame(msg) => {
                write!(f, "invalid AX.25 frame: {msg}")
            }
        }
    }
}

impl std::error::Error for Ax25ParseError {}

/// Classification of AX.25 frame type based on control field octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ax25FrameType {
    /// Unnumbered Information (UI) frame (control 0x03 or 0x13).
    UnnumberedInformation,
    /// Information (I) frame.
    Information,
    /// Supervisory (S) frame (e.g. RR, RNR, REJ, SREJ).
    Supervisory,
    /// Unnumbered (U) frame other than UI (e.g. SABM, DISC, DM, UA).
    Unnumbered,
    /// Unknown or unclassified frame type.
    Unknown,
}

impl Ax25FrameType {
    pub const UI: Self = Self::UnnumberedInformation;
    #[allow(non_upper_case_globals)]
    pub const Ui: Self = Self::UnnumberedInformation;
    pub const I: Self = Self::Information;
    pub const S: Self = Self::Supervisory;
    pub const U: Self = Self::Unnumbered;

    /// Returns true if this is an Unnumbered Information (UI) frame.
    #[must_use]
    pub const fn is_unnumbered_information(&self) -> bool {
        matches!(self, Self::UnnumberedInformation)
    }

    /// Returns true if this is an Unnumbered Information (UI) frame (alias).
    #[must_use]
    pub const fn is_ui(&self) -> bool {
        matches!(self, Self::UnnumberedInformation)
    }
}

pub type FrameType = Ax25FrameType;

/// Parsed AX.25 address subfield (destination, source, or digipeater).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ax25Address {
    /// Station callsign (ASCII alphanumeric, trimmed of trailing padding spaces).
    pub callsign: String,
    /// Secondary Station Identifier (0–15).
    pub ssid: u8,
    /// Has-been-repeated flag (H-bit, bit 7 of SSID octet in repeater addresses).
    pub repeated: bool,
    /// Command/Response bit (C-bit, bit 7 of SSID octet in destination/source addresses).
    pub c_bit: bool,
    /// Extension bit flag (bit 0 == 1 indicates last address subfield in address field).
    pub is_last: bool,
}

impl Ax25Address {
    /// Creates a new `Ax25Address` with default flags.
    #[must_use]
    pub fn new(callsign: impl Into<String>, ssid: u8) -> Self {
        Self {
            callsign: callsign.into(),
            ssid,
            repeated: false,
            c_bit: false,
            is_last: false,
        }
    }

    /// Station callsign string reference.
    #[must_use]
    pub fn callsign(&self) -> &str {
        &self.callsign
    }

    /// Station SSID (0–15).
    #[must_use]
    pub const fn ssid(&self) -> u8 {
        self.ssid
    }

    /// True if the repeated (H) bit is set.
    #[must_use]
    pub const fn is_repeated(&self) -> bool {
        self.repeated
    }

    /// True if the repeated (H) bit is set (alias).
    #[must_use]
    pub const fn repeated(&self) -> bool {
        self.repeated
    }

    /// True if the frame has been repeated by this repeater station.
    #[must_use]
    pub const fn has_been_repeated(&self) -> bool {
        self.repeated
    }

    /// Formats the address in standard amateur radio callsign-SSID notation (e.g. "N0CALL-1" or "N0CALL").
    #[must_use]
    pub fn formatted(&self) -> String {
        if self.ssid == 0 {
            self.callsign.clone()
        } else {
            format!("{}-{}", self.callsign, self.ssid)
        }
    }

    /// Parses a 7-octet AX.25 address subfield.
    pub fn parse(raw: &[u8]) -> Result<Self, Ax25ParseError> {
        if raw.len() < AX25_ADDR_SUBFIELD_LEN {
            return Err(Ax25ParseError::TruncatedPacket);
        }
        let (addr, _) = parse_address_subfield(&raw[..AX25_ADDR_SUBFIELD_LEN])?;
        Ok(addr)
    }

    /// Encodes this address into standard 7-octet wire format.
    pub fn to_bytes(&self) -> Result<[u8; 7], Ax25ParseError> {
        encode_address(&self.callsign, self.ssid, self.repeated, self.is_last)
    }
}

impl fmt::Display for Ax25Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ssid == 0 {
            write!(f, "{}", self.callsign)?;
        } else {
            write!(f, "{}-{}", self.callsign, self.ssid)?;
        }
        if self.repeated {
            write!(f, "*")?;
        }
        Ok(())
    }
}

/// Parsed address field containing destination, source, and optional digipeater addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ax25AddressField {
    /// Destination station address.
    pub destination: Ax25Address,
    /// Source station address.
    pub source: Ax25Address,
    /// Digipeater path addresses (0 to 8).
    pub digipeaters: Vec<Ax25Address>,
    /// Repeater path addresses (alias for `digipeaters`).
    pub repeaters: Vec<Ax25Address>,
    /// Number of bytes consumed by the address field (14 + 7 * N).
    pub bytes_consumed: usize,
}

impl Ax25AddressField {
    /// Returns repeater callsigns as a vector of string slices.
    #[must_use]
    pub fn repeater_callsigns(&self) -> Vec<&str> {
        self.digipeaters
            .iter()
            .map(|d| d.callsign.as_str())
            .collect()
    }

    /// Returns repeater callsigns as a vector of cloned strings.
    #[must_use]
    pub fn repeater_callsign_strings(&self) -> Vec<String> {
        self.digipeaters
            .iter()
            .map(|d| d.callsign.clone())
            .collect()
    }

    /// Returns digipeater callsigns as a vector of string slices (alias).
    #[must_use]
    pub fn digipeater_callsigns(&self) -> Vec<&str> {
        self.repeater_callsigns()
    }
}

/// Parsed AX.25 frame header and content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ax25Frame {
    /// Destination station address.
    pub destination: Ax25Address,
    /// Source station address.
    pub source: Ax25Address,
    /// Digipeater (repeater) path addresses (0 to 8).
    pub digipeaters: Vec<Ax25Address>,
    /// Repeater path addresses (alias for `digipeaters`).
    pub repeaters: Vec<Ax25Address>,
    /// Destination callsign string (convenience field).
    pub destination_callsign: String,
    /// Source callsign string (convenience field).
    pub source_callsign: String,
    /// Destination SSID (0–15).
    pub destination_ssid: u8,
    /// Source SSID (0–15).
    pub source_ssid: u8,
    /// Raw control field byte.
    pub control: u8,
    /// Poll/Final bit extracted from control field.
    pub poll_final: bool,
    /// Classified frame type.
    pub frame_type: Ax25FrameType,
    /// Protocol Identifier (PID) byte if present (e.g. for UI and I frames).
    pub pid: Option<u8>,
    /// Frame payload data following header (and PID if present).
    pub payload: Vec<u8>,
    /// Frame payload data (alias for `payload`).
    pub info: Vec<u8>,
    /// Total parsed header length in octets (address field + control + PID if present).
    pub header_len: usize,
}

impl Ax25Frame {
    /// Destination callsign string reference.
    #[must_use]
    pub fn destination_callsign(&self) -> &str {
        &self.destination_callsign
    }

    /// Source callsign string reference.
    #[must_use]
    pub fn source_callsign(&self) -> &str {
        &self.source_callsign
    }

    /// Destination SSID (0–15).
    #[must_use]
    pub const fn destination_ssid(&self) -> u8 {
        self.destination_ssid
    }

    /// Source SSID (0–15).
    #[must_use]
    pub const fn source_ssid(&self) -> u8 {
        self.source_ssid
    }

    /// Returns repeater callsigns as a vector of string slices.
    #[must_use]
    pub fn repeater_callsigns(&self) -> Vec<&str> {
        self.digipeaters
            .iter()
            .map(|d| d.callsign.as_str())
            .collect()
    }

    /// Returns repeater callsigns as a vector of cloned strings.
    #[must_use]
    pub fn repeater_callsign_strings(&self) -> Vec<String> {
        self.digipeaters
            .iter()
            .map(|d| d.callsign.clone())
            .collect()
    }

    /// Returns digipeater callsigns as a vector of string slices (alias).
    #[must_use]
    pub fn digipeater_callsigns(&self) -> Vec<&str> {
        self.repeater_callsigns()
    }

    /// Returns true if this is an Unnumbered Information (UI) frame.
    #[must_use]
    pub const fn is_unnumbered_information(&self) -> bool {
        matches!(self.frame_type, Ax25FrameType::UnnumberedInformation)
    }

    /// Returns true if this is an Unnumbered Information (UI) frame (alias).
    #[must_use]
    pub const fn is_ui(&self) -> bool {
        matches!(self.frame_type, Ax25FrameType::UnnumberedInformation)
    }

    /// Returns frame payload slice.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Returns frame info / payload slice (alias).
    #[must_use]
    pub fn info(&self) -> &[u8] {
        &self.info
    }

    /// Returns protocol identifier byte if present.
    #[must_use]
    pub const fn protocol_id(&self) -> Option<u8> {
        self.pid
    }

    /// Returns protocol identifier byte if present (alias).
    #[must_use]
    pub const fn protocol_identifier(&self) -> Option<u8> {
        self.pid
    }

    /// Parses an AX.25 frame from a byte slice.
    pub fn parse(input: &[u8]) -> Result<Self, Ax25ParseError> {
        parse_ax25_frame(input)
    }

    /// Parses an AX.25 frame header from a byte slice.
    pub fn parse_header(input: &[u8]) -> Result<Self, Ax25ParseError> {
        parse_ax25_frame(input)
    }

    /// Parses an AX.25 packet from a byte slice.
    pub fn parse_packet(input: &[u8]) -> Result<Self, Ax25ParseError> {
        parse_ax25_frame(input)
    }
}

/// Type alias for [`Ax25Frame`].
pub type Ax25Header = Ax25Frame;

/// Type alias for [`Ax25Frame`].
pub type Ax25Packet = Ax25Frame;

/// Parses a single 7-octet AX.25 address subfield.
///
/// Returns `(Ax25Address, is_last_address)` where `is_last_address` indicates
/// whether bit 0 of the SSID octet was set (signaling the end of the address field).
fn parse_address_subfield(raw: &[u8]) -> Result<(Ax25Address, bool), Ax25ParseError> {
    if raw.len() < AX25_ADDR_SUBFIELD_LEN {
        return Err(Ax25ParseError::TruncatedPacket);
    }

    let mut callsign = String::with_capacity(6);
    let mut seen_space = false;

    for &b in &raw[0..6] {
        let ch = (b >> 1) as char;
        if ch == ' ' {
            seen_space = true;
        } else {
            if seen_space {
                return Err(Ax25ParseError::InvalidCallsign(
                    "non-trailing space in callsign".to_string(),
                ));
            }
            if !ch.is_ascii_alphanumeric() {
                return Err(Ax25ParseError::NonAlphanumericCallsign(format!(
                    "invalid non-alphanumeric character '{ch}' (ASCII 0x{:02X}) in callsign",
                    ch as u8
                )));
            }
            callsign.push(ch);
        }
    }

    if callsign.is_empty() {
        return Err(Ax25ParseError::InvalidCallsign(
            "callsign is empty (all spaces)".to_string(),
        ));
    }

    let ssid_byte = raw[6];
    let ssid = (ssid_byte >> 1) & 0x0F;
    let is_last = (ssid_byte & 0x01) == 0x01;
    let repeated = (ssid_byte & 0x80) != 0;
    let c_bit = (ssid_byte & 0x80) != 0;

    let addr = Ax25Address {
        callsign,
        ssid,
        repeated,
        c_bit,
        is_last,
    };

    Ok((addr, is_last))
}

/// Parses a 7-octet AX.25 address subfield.
pub fn parse_address(input: &[u8]) -> Result<Ax25Address, Ax25ParseError> {
    if input.len() < AX25_ADDR_SUBFIELD_LEN {
        return Err(Ax25ParseError::TruncatedPacket);
    }
    let (addr, _) = parse_address_subfield(&input[..AX25_ADDR_SUBFIELD_LEN])?;
    Ok(addr)
}

/// Parses a 7-octet AX.25 address subfield (alias).
pub fn parse_ax25_address(input: &[u8]) -> Result<Ax25Address, Ax25ParseError> {
    parse_address(input)
}

/// Parses an AX.25 address field (destination, source, and optional digipeaters) from a byte slice.
pub fn parse_address_field(input: &[u8]) -> Result<Ax25AddressField, Ax25ParseError> {
    if input.len() < AX25_STANDARD_ADDR_LEN {
        return Err(Ax25ParseError::TruncatedPacket);
    }

    let (destination, dest_last) = parse_address_subfield(&input[0..7])?;
    if dest_last {
        return Err(Ax25ParseError::InvalidAddress(
            "destination address extension bit is set (missing source address)".to_string(),
        ));
    }

    let (source, mut last_seen) = parse_address_subfield(&input[7..14])?;
    let mut digipeaters = Vec::new();
    let mut offset = 14;

    while !last_seen {
        if input.len() < offset + AX25_ADDR_SUBFIELD_LEN {
            return Err(Ax25ParseError::TruncatedPacket);
        }
        if digipeaters.len() >= AX25_MAX_DIGIPEATERS {
            return Err(Ax25ParseError::TooManyDigipeaters);
        }
        let (digi, is_last) =
            parse_address_subfield(&input[offset..offset + AX25_ADDR_SUBFIELD_LEN])?;
        digipeaters.push(digi);
        last_seen = is_last;
        offset += AX25_ADDR_SUBFIELD_LEN;
    }

    let repeaters = digipeaters.clone();
    Ok(Ax25AddressField {
        destination,
        source,
        digipeaters,
        repeaters,
        bytes_consumed: offset,
    })
}

/// Parses an AX.25 frame header and content from a byte slice.
///
/// # Requirements (SPEC §5, §8, §14)
///
/// - Input buffer must be at least 15 octets (7 destination + 7 source + 1 control).
/// - Unshifts ASCII callsign characters by 1 bit (`byte >> 1`).
/// - Extracts destination callsign, source callsign, and SSIDs in range 0 to 15.
/// - Extracts up to 8 repeater callsigns and identifies whether the repeated bit is set.
/// - Frames with control byte 0x03 or 0x13 are classified as Unnumbered Information (UI),
///   and the following protocol identifier (PID) byte is extracted if present.
/// - Buffers shorter than 15 octets return [`Ax25ParseError::TruncatedPacket`].
/// - Address fields containing non-alphanumeric characters return a parse error without panicking.
pub fn parse_ax25_frame(input: &[u8]) -> Result<Ax25Frame, Ax25ParseError> {
    if input.len() < AX25_MIN_FRAME_LEN {
        return Err(Ax25ParseError::TruncatedPacket);
    }

    let addr_field = parse_address_field(input)?;
    let offset = addr_field.bytes_consumed;

    if input.len() < offset + 1 {
        return Err(Ax25ParseError::TruncatedPacket);
    }

    let control = input[offset];
    let poll_final = (control & 0x10) != 0;

    let (frame_type, pid, payload_offset) = if control == AX25_CTRL_UI || control == AX25_CTRL_UI_PF
    {
        let ft = Ax25FrameType::UnnumberedInformation;
        if input.len() > offset + 1 {
            let pid_byte = input[offset + 1];
            (ft, Some(pid_byte), offset + 2)
        } else {
            (ft, None, offset + 1)
        }
    } else if (control & 0x01) == 0 {
        let ft = Ax25FrameType::Information;
        if input.len() > offset + 1 {
            let pid_byte = input[offset + 1];
            (ft, Some(pid_byte), offset + 2)
        } else {
            (ft, None, offset + 1)
        }
    } else if (control & 0x03) == 0x01 {
        (Ax25FrameType::Supervisory, None, offset + 1)
    } else if (control & 0x03) == 0x03 {
        (Ax25FrameType::Unnumbered, None, offset + 1)
    } else {
        (Ax25FrameType::Unknown, None, offset + 1)
    };

    let payload = if input.len() >= payload_offset {
        input[payload_offset..].to_vec()
    } else {
        Vec::new()
    };
    let info = payload.clone();

    let dest_call = addr_field.destination.callsign.clone();
    let src_call = addr_field.source.callsign.clone();
    let dest_ssid = addr_field.destination.ssid;
    let src_ssid = addr_field.source.ssid;

    Ok(Ax25Frame {
        destination: addr_field.destination,
        source: addr_field.source,
        digipeaters: addr_field.digipeaters,
        repeaters: addr_field.repeaters,
        destination_callsign: dest_call,
        source_callsign: src_call,
        destination_ssid: dest_ssid,
        source_ssid: src_ssid,
        control,
        poll_final,
        frame_type,
        pid,
        payload,
        info,
        header_len: payload_offset,
    })
}

/// Parses an AX.25 frame header from a byte slice (alias for [`parse_ax25_frame`]).
pub fn parse_ax25_header(input: &[u8]) -> Result<Ax25Frame, Ax25ParseError> {
    parse_ax25_frame(input)
}

/// Parses an AX.25 packet from a byte slice (alias for [`parse_ax25_frame`]).
pub fn parse_ax25_packet(input: &[u8]) -> Result<Ax25Frame, Ax25ParseError> {
    parse_ax25_frame(input)
}

/// Parses an AX.25 frame from a byte slice (short alias).
pub fn parse_frame(input: &[u8]) -> Result<Ax25Frame, Ax25ParseError> {
    parse_ax25_frame(input)
}

/// Parses an AX.25 frame header from a byte slice (short alias).
pub fn parse_header(input: &[u8]) -> Result<Ax25Frame, Ax25ParseError> {
    parse_ax25_frame(input)
}

/// Parses an AX.25 packet from a byte slice (short alias).
pub fn parse_packet(input: &[u8]) -> Result<Ax25Frame, Ax25ParseError> {
    parse_ax25_frame(input)
}

/// Encodes an address into standard 7-octet AX.25 wire format.
///
/// Shifts ASCII callsign characters left by 1 bit, pads with spaces (shifted to 0x40),
/// and encodes SSID, repeated (H) bit, and extension (last address) bit into the 7th octet.
pub fn encode_address(
    callsign: &str,
    ssid: u8,
    repeated: bool,
    is_last: bool,
) -> Result<[u8; 7], Ax25ParseError> {
    let callsign = callsign.trim();
    if callsign.is_empty() || callsign.len() > 6 {
        return Err(Ax25ParseError::InvalidCallsign(
            "callsign must be 1 to 6 ASCII alphanumeric characters".to_string(),
        ));
    }
    for ch in callsign.chars() {
        if !ch.is_ascii_alphanumeric() {
            return Err(Ax25ParseError::NonAlphanumericCallsign(format!(
                "character '{ch}' is not ASCII alphanumeric"
            )));
        }
    }
    if ssid > 15 {
        return Err(Ax25ParseError::InvalidAddress(format!(
            "SSID {ssid} exceeds maximum 15"
        )));
    }

    let mut buf = [0x40; 7]; // 0x40 is ' ' << 1
    for (i, b) in callsign.bytes().enumerate() {
        buf[i] = b << 1;
    }
    let h_bit = if repeated { 0x80 } else { 0x00 };
    let e_bit = if is_last { 0x01 } else { 0x00 };
    // Standard AX.25 reserved bits 6 and 5 are 11 (0x60)
    buf[6] = h_bit | 0x60 | ((ssid & 0x0F) << 1) | e_bit;
    Ok(buf)
}

/// Encodes an AX.25 frame into raw wire bytes.
pub fn encode_ax25_frame(
    destination: &Ax25Address,
    source: &Ax25Address,
    digipeaters: &[Ax25Address],
    control: u8,
    pid: Option<u8>,
    payload: &[u8],
) -> Result<Vec<u8>, Ax25ParseError> {
    if digipeaters.len() > AX25_MAX_DIGIPEATERS {
        return Err(Ax25ParseError::TooManyDigipeaters);
    }
    let mut buf = Vec::new();
    let dest_bytes = encode_address(
        &destination.callsign,
        destination.ssid,
        destination.repeated,
        false,
    )?;
    buf.extend_from_slice(&dest_bytes);

    let src_last = digipeaters.is_empty();
    let src_bytes = encode_address(&source.callsign, source.ssid, source.repeated, src_last)?;
    buf.extend_from_slice(&src_bytes);

    for (i, digi) in digipeaters.iter().enumerate() {
        let is_last = i == digipeaters.len() - 1;
        let digi_bytes = encode_address(&digi.callsign, digi.ssid, digi.repeated, is_last)?;
        buf.extend_from_slice(&digi_bytes);
    }

    buf.push(control);
    if let Some(pid_byte) = pid {
        buf.push(pid_byte);
    }
    buf.extend_from_slice(payload);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criterion1_parse_15_byte_buffer_standard_addresses() {
        // Acceptance criterion:
        // In crates/rer/src/ax25.rs, parsing a 15-byte buffer containing standard 7-byte destination
        // and 7-byte source address fields unshifts ASCII callsign characters by 1 bit and extracts
        // destination callsign, source callsign, and SSIDs in range 0 to 15.

        // Test with SSID 0 and SSID 15
        let dest = Ax25Address::new("CQ", 0);
        let src = Ax25Address::new("N0CALL", 15);
        let frame_bytes = encode_ax25_frame(&dest, &src, &[], AX25_CTRL_UI, None, &[])
            .expect("encode valid 15-byte frame");
        assert_eq!(frame_bytes.len(), 15);

        let parsed = parse_ax25_frame(&frame_bytes).expect("parse valid 15-byte frame");
        assert_eq!(parsed.destination.callsign, "CQ");
        assert_eq!(parsed.destination_callsign, "CQ");
        assert_eq!(parsed.destination.ssid, 0);
        assert_eq!(parsed.destination_ssid, 0);

        assert_eq!(parsed.source.callsign, "N0CALL");
        assert_eq!(parsed.source_callsign, "N0CALL");
        assert_eq!(parsed.source.ssid, 15);
        assert_eq!(parsed.source_ssid, 15);
        assert_eq!(parsed.control, AX25_CTRL_UI);
        assert_eq!(parsed.frame_type, Ax25FrameType::UnnumberedInformation);
        assert!(parsed.digipeaters.is_empty());
        assert!(parsed.repeaters.is_empty());

        // Test with different SSID values in range 0..15
        for ssid in 0..=15 {
            let dest_test = Ax25Address::new("W1AW", ssid);
            let src_test = Ax25Address::new("KB1ABC", 15 - ssid);
            let bytes = encode_ax25_frame(&dest_test, &src_test, &[], 0x00, None, &[])
                .expect("encode frame");
            assert_eq!(bytes.len(), 15);
            let p = parse_ax25_frame(&bytes).expect("parse frame");
            assert_eq!(p.destination_callsign, "W1AW");
            assert_eq!(p.destination_ssid, ssid);
            assert_eq!(p.source_callsign, "KB1ABC");
            assert_eq!(p.source_ssid, 15 - ssid);
        }
    }

    #[test]
    fn test_criterion2_parse_digipeater_addresses_and_repeated_bit() {
        // Acceptance criterion:
        // In crates/rer/src/ax25.rs, parsing an address field with digipeater addresses extracts
        // up to 8 repeater callsigns and identifies whether the repeated bit is set.

        let dest = Ax25Address::new("APRS", 0);
        let src = Ax25Address::new("W3XYZ", 9);

        // Build 8 digipeaters alternating repeated flag
        let mut digipeaters = Vec::new();
        for i in 1..=8 {
            let mut digi = Ax25Address::new(format!("DIGI{i}"), i as u8);
            digi.repeated = (i % 2) != 0; // Odd: true, Even: false
            digipeaters.push(digi);
        }

        let frame_bytes =
            encode_ax25_frame(&dest, &src, &digipeaters, AX25_CTRL_UI, Some(0xF0), b"Test")
                .expect("encode 8-digi frame");

        // 7 dest + 7 src + 8 * 7 digis + 1 control + 1 PID + 4 payload = 14 + 56 + 6 = 76 bytes
        assert_eq!(frame_bytes.len(), 76);

        let parsed = parse_ax25_frame(&frame_bytes).expect("parse 8-digi frame");
        assert_eq!(parsed.digipeaters.len(), 8);
        assert_eq!(parsed.repeaters.len(), 8);

        for (i, digi) in parsed.digipeaters.iter().enumerate() {
            let expected_idx = i + 1;
            assert_eq!(digi.callsign, format!("DIGI{expected_idx}"));
            assert_eq!(digi.ssid, expected_idx as u8);
            let expected_repeated = (expected_idx % 2) != 0;
            assert_eq!(digi.repeated, expected_repeated);
            assert_eq!(digi.is_repeated(), expected_repeated);
            assert_eq!(digi.has_been_repeated(), expected_repeated);
        }

        let repeater_calls = parsed.repeater_callsigns();
        assert_eq!(
            repeater_calls,
            vec!["DIGI1", "DIGI2", "DIGI3", "DIGI4", "DIGI5", "DIGI6", "DIGI7", "DIGI8"]
        );

        // Test with address field parser directly
        let addr_field =
            parse_address_field(&frame_bytes).expect("parse address field with 8 digis");
        assert_eq!(addr_field.digipeaters.len(), 8);
        assert_eq!(addr_field.repeaters.len(), 8);
        assert_eq!(addr_field.bytes_consumed, 70);

        // Test that 9 digipeaters is rejected
        let mut nine_digis = digipeaters.clone();
        nine_digis.push(Ax25Address::new("EXTRA", 0));
        let bad_encode = encode_ax25_frame(&dest, &src, &nine_digis, AX25_CTRL_UI, Some(0xF0), b"");
        assert_eq!(bad_encode.unwrap_err(), Ax25ParseError::TooManyDigipeaters);
    }

    #[test]
    fn test_criterion3_control_byte_0x03_and_0x13_ui_and_pid() {
        // Acceptance criterion:
        // In crates/rer/src/ax25.rs, parsing a frame with control byte 0x03 or 0x13 classifies
        // the frame as Unnumbered Information and extracts the following protocol identifier byte.

        let dest = Ax25Address::new("CQ", 0);
        let src = Ax25Address::new("N0CALL", 0);

        // Control byte 0x03 (UI, P/F = 0) with PID 0xF0 (No layer 3)
        let frame_0x03 =
            encode_ax25_frame(&dest, &src, &[], 0x03, Some(0xF0), b">Hello APRS world!")
                .expect("encode UI frame 0x03");
        let parsed_0x03 = parse_ax25_frame(&frame_0x03).expect("parse UI frame 0x03");
        assert_eq!(parsed_0x03.frame_type, Ax25FrameType::UnnumberedInformation);
        assert!(parsed_0x03.is_unnumbered_information());
        assert!(parsed_0x03.is_ui());
        assert_eq!(parsed_0x03.control, 0x03);
        assert!(!parsed_0x03.poll_final);
        assert_eq!(parsed_0x03.pid, Some(0xF0));
        assert_eq!(parsed_0x03.protocol_id(), Some(0xF0));
        assert_eq!(parsed_0x03.payload, b">Hello APRS world!");

        // Control byte 0x13 (UI, P/F = 1) with PID 0xCC (IPv4)
        let frame_0x13 =
            encode_ax25_frame(&dest, &src, &[], 0x13, Some(0xCC), b"\x45\x00\x00\x28...")
                .expect("encode UI frame 0x13");
        let parsed_0x13 = parse_ax25_frame(&frame_0x13).expect("parse UI frame 0x13");
        assert_eq!(parsed_0x13.frame_type, Ax25FrameType::UnnumberedInformation);
        assert!(parsed_0x13.is_unnumbered_information());
        assert!(parsed_0x13.is_ui());
        assert_eq!(parsed_0x13.control, 0x13);
        assert!(parsed_0x13.poll_final);
        assert_eq!(parsed_0x13.pid, Some(0xCC));
        assert_eq!(parsed_0x13.protocol_id(), Some(0xCC));
    }

    #[test]
    fn test_criterion4_input_shorter_than_15_bytes_returns_truncated() {
        // Acceptance criterion:
        // In crates/rer/src/ax25.rs, parsing an input buffer shorter than 15 bytes returns an
        // error indicating a truncated packet.

        let dest = Ax25Address::new("CQ", 0);
        let src = Ax25Address::new("N0CALL", 0);
        let full_15_bytes =
            encode_ax25_frame(&dest, &src, &[], AX25_CTRL_UI, None, &[]).expect("encode 15 bytes");
        assert_eq!(full_15_bytes.len(), 15);

        // Test every slice length from 0 to 14
        for len in 0..15 {
            let slice = &full_15_bytes[..len];
            let err = parse_ax25_frame(slice).expect_err("buffer shorter than 15 must error");
            assert_eq!(err, Ax25ParseError::TruncatedPacket);
            assert!(err.is_truncated());
            assert!(err.is_truncated_packet());
            assert!(format!("{err}").to_lowercase().contains("truncated packet"));
        }

        // Exactly 15 bytes succeeds
        assert!(parse_ax25_frame(&full_15_bytes).is_ok());
    }

    #[test]
    fn test_criterion5_non_alphanumeric_callsign_returns_error_without_panic() {
        // Acceptance criterion:
        // In crates/rer/src/ax25.rs, parsing an address field containing non-alphanumeric callsign
        // characters returns a parse error without panicking.

        let dest = Ax25Address::new("CQ", 0);
        let src = Ax25Address::new("N0CALL", 0);
        let mut base_bytes =
            encode_ax25_frame(&dest, &src, &[], AX25_CTRL_UI, None, &[]).expect("encode base");

        // Corrupt destination byte 0 with '$' (ASCII 0x24 << 1 = 0x48)
        base_bytes[0] = b'$' << 1;
        let err1 = parse_ax25_frame(&base_bytes).expect_err("non-alphanumeric character '$'");
        assert!(err1.is_invalid_callsign());
        assert!(err1.is_non_alphanumeric_callsign());

        // Corrupt destination byte 1 with '-' (ASCII 0x2D << 1 = 0x5A)
        base_bytes[0] = b'C' << 1;
        base_bytes[1] = b'-' << 1;
        let err2 = parse_ax25_frame(&base_bytes).expect_err("non-alphanumeric character '-'");
        assert!(err2.is_invalid_callsign());

        // Corrupt source byte 7 with '@' (ASCII 0x40 << 1 = 0x80)
        base_bytes[1] = b'Q' << 1;
        base_bytes[7] = b'@' << 1;
        let err3 = parse_ax25_frame(&base_bytes).expect_err("non-alphanumeric character '@'");
        assert!(err3.is_invalid_callsign());

        // Corrupt with control char \x00
        base_bytes[7] = 0x00;
        let err4 = parse_ax25_frame(&base_bytes).expect_err("null byte character");
        assert!(err4.is_invalid_callsign());

        // Corrupt digipeater callsign with '!'
        let digi = Ax25Address::new("WIDE1", 1);
        let mut digi_bytes = encode_ax25_frame(&dest, &src, &[digi], AX25_CTRL_UI, None, &[])
            .expect("encode digi frame");
        // Digipeater callsign starts at offset 14
        digi_bytes[14] = b'!' << 1;
        let err5 =
            parse_ax25_frame(&digi_bytes).expect_err("non-alphanumeric character in digipeater");
        assert!(err5.is_invalid_callsign());

        // Test parse_address_field and parse_address directly with non-alphanumeric character
        let bad_addr = [b'#' << 1, b'A' << 1, 0x40, 0x40, 0x40, 0x40, 0x60];
        let err_addr = parse_address(&bad_addr).expect_err("non-alphanumeric single address");
        assert!(err_addr.is_invalid_callsign());
    }
}
