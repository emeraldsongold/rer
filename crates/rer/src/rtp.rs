//! In-tree Real-time Transport Protocol (RTP) packet header parser and sequence tracker (SPEC §5, §8, §14).
//!
//! Provides a zero-dependency in-tree RTP packet header parser, validator, and stateful sequence tracker
//! as specified in RFC 3550 and SPEC §8, §14.
//!
//! # Passive Inspection Architecture
//!
//! In accordance with SPEC §8 and §14, RER performs transparent, passive metadata inspection of RTP
//! packet headers. RER does NOT implement a stateful media session daemon, RTCP feedback engine,
//! RTSP control session manager, or audio/video codec pipeline. Forwarded datagrams are preserved
//! byte-for-byte.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::diagnostics::SequenceTrackingEvent;

/// Standard RTP protocol version (RFC 3550 §5.1).
pub const RTP_VERSION_2: u8 = 2;

/// Standard fixed RTP header length in bytes (12 octets / 96 bits).
pub const RTP_FIXED_HEADER_LEN: usize = 12;

/// Alias for [`RTP_FIXED_HEADER_LEN`].
pub const RTP_HEADER_LEN: usize = RTP_FIXED_HEADER_LEN;

/// RTP sequence number space modulus (2^16 = 65536).
pub const RTP_SEQUENCE_MODULUS: u64 = 65536;

/// Maximum number of Contributing Source (CSRC) identifiers (4 bits in CC field: 0..=15).
pub const RTP_MAX_CSRC_COUNT: usize = 15;

/// Errors encountered when parsing an RTP packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RtpParseError {
    /// Buffer is shorter than the mandatory 12-octet fixed header.
    TruncatedHeader,
    /// Protocol version is unsupported (expected version 2; got 0, 1, or 3).
    UnsupportedVersion(u8),
    /// Declared CSRC count specifies more bytes than available in buffer.
    TruncatedCsrcList,
    /// Extension header flag is set but buffer is shorter than the 4-byte extension header.
    TruncatedExtensionHeader,
    /// Extension length field specifies more extension data bytes than available in buffer.
    TruncatedExtensionData,
    /// Declared padding length exceeds available packet payload bytes.
    TruncatedPadding,
}

impl RtpParseError {
    pub const TRUNCATED_HEADER: Self = Self::TruncatedHeader;
    pub const TRUNCATED_CSRC_LIST: Self = Self::TruncatedCsrcList;
    #[allow(non_upper_case_globals)]
    pub const Truncated: Self = Self::TruncatedHeader;
    #[allow(non_upper_case_globals)]
    pub const TruncatedCsrc: Self = Self::TruncatedCsrcList;

    /// Returns true if the error indicates a truncated fixed header.
    #[must_use]
    pub const fn is_truncated_header(&self) -> bool {
        matches!(self, Self::TruncatedHeader)
    }

    /// Returns true if the error distinguishes an unsupported RTP version.
    #[must_use]
    pub const fn is_unsupported_version(&self) -> bool {
        matches!(self, Self::UnsupportedVersion(_))
    }

    /// Returns the unsupported version number if applicable.
    #[must_use]
    pub const fn unsupported_version(&self) -> Option<u8> {
        match self {
            Self::UnsupportedVersion(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns true if the error indicates a truncated CSRC list.
    #[must_use]
    pub const fn is_truncated_csrc_list(&self) -> bool {
        matches!(self, Self::TruncatedCsrcList)
    }

    /// Returns true if the error indicates a truncated extension header or data.
    #[must_use]
    pub const fn is_truncated_extension(&self) -> bool {
        matches!(
            self,
            Self::TruncatedExtensionHeader | Self::TruncatedExtensionData
        )
    }

    /// Returns true if the error indicates any form of buffer truncation.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(
            self,
            Self::TruncatedHeader
                | Self::TruncatedCsrcList
                | Self::TruncatedExtensionHeader
                | Self::TruncatedExtensionData
                | Self::TruncatedPadding
        )
    }

    /// Maps this parse error to an [`RtpParseStatus`].
    #[must_use]
    pub const fn status(&self) -> RtpParseStatus {
        match self {
            Self::TruncatedHeader => RtpParseStatus::TruncatedHeader,
            Self::UnsupportedVersion(_) => RtpParseStatus::UnsupportedVersion,
            Self::TruncatedCsrcList => RtpParseStatus::TruncatedCsrcList,
            Self::TruncatedExtensionHeader => RtpParseStatus::TruncatedExtensionHeader,
            Self::TruncatedExtensionData => RtpParseStatus::TruncatedExtensionData,
            Self::TruncatedPadding => RtpParseStatus::TruncatedPadding,
        }
    }
}

impl fmt::Display for RtpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => {
                write!(
                    f,
                    "RTP packet truncated: buffer shorter than 12-byte header"
                )
            }
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported RTP version: {v} (expected version 2)")
            }
            Self::TruncatedCsrcList => {
                write!(
                    f,
                    "truncated CSRC list: buffer shorter than declared CSRC identifiers"
                )
            }
            Self::TruncatedExtensionHeader => {
                write!(
                    f,
                    "truncated extension header: buffer shorter than 4-byte extension header"
                )
            }
            Self::TruncatedExtensionData => {
                write!(
                    f,
                    "truncated extension data: buffer shorter than declared extension length"
                )
            }
            Self::TruncatedPadding => {
                write!(
                    f,
                    "truncated padding: buffer shorter than declared padding length"
                )
            }
        }
    }
}

impl std::error::Error for RtpParseError {}

/// Parse status distinguishing valid RTP traffic from malformed or non-RTP payloads without panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RtpParseStatus {
    /// Packet is valid RTP version 2.
    Valid,
    /// Buffer is shorter than the 12-byte fixed header.
    TruncatedHeader,
    /// Version field is not 2.
    UnsupportedVersion,
    /// Declared CSRC count exceeds available buffer.
    TruncatedCsrcList,
    /// Extension header is shorter than 4 octets.
    TruncatedExtensionHeader,
    /// Extension data is shorter than declared word count.
    TruncatedExtensionData,
    /// Padding length byte exceeds available payload.
    TruncatedPadding,
    /// General malformed packet structure.
    Malformed,
}

impl RtpParseStatus {
    /// Returns true if the status is [`Self::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns true if the status indicates truncation.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(
            self,
            Self::TruncatedHeader
                | Self::TruncatedCsrcList
                | Self::TruncatedExtensionHeader
                | Self::TruncatedExtensionData
                | Self::TruncatedPadding
        )
    }
}

impl fmt::Display for RtpParseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::TruncatedHeader => write!(f, "truncated_header"),
            Self::UnsupportedVersion => write!(f, "unsupported_version"),
            Self::TruncatedCsrcList => write!(f, "truncated_csrc_list"),
            Self::TruncatedExtensionHeader => write!(f, "truncated_extension_header"),
            Self::TruncatedExtensionData => write!(f, "truncated_extension_data"),
            Self::TruncatedPadding => write!(f, "truncated_padding"),
            Self::Malformed => write!(f, "malformed"),
        }
    }
}

/// RTP header extension structure (RFC 3550 §5.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RtpHeaderExtension {
    /// 16-bit profile-specific identifier.
    pub profile: u16,
    /// Raw extension data bytes (excluding 4-byte extension header).
    pub data: Vec<u8>,
}

impl RtpHeaderExtension {
    /// Returns the 16-bit profile identifier.
    #[must_use]
    pub const fn profile(&self) -> u16 {
        self.profile
    }

    /// Alias for [`Self::profile`].
    #[must_use]
    pub const fn profile_id(&self) -> u16 {
        self.profile
    }

    /// Returns a slice of the raw extension data bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length of the extension in 32-bit words (as encoded in the 16-bit length field).
    #[must_use]
    pub fn length_words(&self) -> u16 {
        (self.data.len() / 4) as u16
    }
}

/// Parsed representation of an RTP packet header (RFC 3550 §5.1, §5.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtpHeader {
    /// 2-bit protocol version number (must be 2).
    pub version: u8,
    /// 1-bit padding flag (true if packet contains trailing padding octets).
    pub padding: bool,
    /// 1-bit extension flag (true if fixed header is followed by a header extension).
    pub extension: bool,
    /// 4-bit CSRC count (0..=15 contributing source identifiers).
    pub csrc_count: u8,
    /// 1-bit marker bit (profile-dependent significance, e.g. frame boundary).
    pub marker: bool,
    /// 7-bit payload type identifier (0..=127).
    pub payload_type: u8,
    /// 16-bit packet sequence number (increments by 1 for each RTP data packet sent).
    pub sequence_number: u16,
    /// 32-bit sampling timestamp (monotonic sampling clock).
    pub timestamp: u32,
    /// 32-bit synchronization source (SSRC) identifier.
    pub ssrc: u32,
    /// Contributing source (CSRC) identifier list (0 to 15 items).
    pub csrc_list: Vec<u32>,
    /// 16-bit extension profile identifier, if an extension header is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_profile: Option<u16>,
    /// Header extension data bytes, if an extension header is present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_data: Option<Vec<u8>>,
    /// Structured header extension if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_extension: Option<RtpHeaderExtension>,
    /// Total header length in octets including fixed header, CSRC list, and extension header.
    pub header_length: usize,
    /// Byte offset in datagram where packet payload begins (identical to `header_length`).
    pub payload_offset: usize,
}

impl Default for RtpHeader {
    fn default() -> Self {
        Self {
            version: RTP_VERSION_2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 0,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
            csrc_list: Vec::new(),
            extension_profile: None,
            extension_data: None,
            header_extension: None,
            header_length: RTP_FIXED_HEADER_LEN,
            payload_offset: RTP_FIXED_HEADER_LEN,
        }
    }
}

impl RtpHeader {
    /// Parses an RTP header from a byte slice.
    ///
    /// # Errors
    /// Returns [`RtpParseError`] if the header is truncated, has an unsupported version,
    /// or declares an invalid extension or CSRC list.
    pub fn parse(data: &[u8]) -> Result<Self, RtpParseError> {
        parse_rtp_header(data)
    }

    /// Alias for [`Self::parse`].
    pub fn from_slice(data: &[u8]) -> Result<Self, RtpParseError> {
        parse_rtp_header(data)
    }

    /// Alias for [`Self::parse`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, RtpParseError> {
        parse_rtp_header(data)
    }

    /// Returns the RTP version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns true if the padding bit is set.
    #[must_use]
    pub const fn padding(&self) -> bool {
        self.padding
    }

    /// Alias for [`Self::padding`].
    #[must_use]
    pub const fn has_padding(&self) -> bool {
        self.padding
    }

    /// Returns true if the extension bit is set.
    #[must_use]
    pub const fn extension(&self) -> bool {
        self.extension
    }

    /// Alias for [`Self::extension`].
    #[must_use]
    pub const fn extension_flag(&self) -> bool {
        self.extension
    }

    /// Alias for [`Self::extension`].
    #[must_use]
    pub const fn has_extension(&self) -> bool {
        self.extension
    }

    /// Returns the CSRC count.
    #[must_use]
    pub const fn csrc_count(&self) -> u8 {
        self.csrc_count
    }

    /// Returns the marker bit.
    #[must_use]
    pub const fn marker(&self) -> bool {
        self.marker
    }

    /// Returns the 7-bit payload type.
    #[must_use]
    pub const fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Returns the 16-bit sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Alias for [`Self::sequence_number`].
    #[must_use]
    pub const fn sequence(&self) -> u16 {
        self.sequence_number
    }

    /// Returns the 32-bit sampling timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns the 32-bit synchronization source (SSRC) identifier.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Returns a slice of the CSRC identifiers.
    #[must_use]
    pub fn csrc_list(&self) -> &[u32] {
        &self.csrc_list
    }

    /// Returns the extension profile identifier, if present.
    #[must_use]
    pub const fn extension_profile(&self) -> Option<u16> {
        self.extension_profile
    }

    /// Returns a slice of the extension data bytes, if present.
    #[must_use]
    pub fn extension_data(&self) -> Option<&[u8]> {
        self.extension_data.as_deref()
    }

    /// Returns the structured header extension, if present.
    #[must_use]
    pub fn header_extension(&self) -> Option<&RtpHeaderExtension> {
        self.header_extension.as_ref()
    }

    /// Returns the total header length in octets.
    #[must_use]
    pub const fn header_length(&self) -> usize {
        self.header_length
    }

    /// Returns the byte offset in datagram where packet payload begins.
    #[must_use]
    pub const fn payload_offset(&self) -> usize {
        self.payload_offset
    }

    /// Encodes this RTP header into bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.header_length);

        let byte0 = (self.version << 6)
            | (u8::from(self.padding) << 5)
            | (u8::from(self.extension) << 4)
            | (self.csrc_count & 0x0F);
        let byte1 = (u8::from(self.marker) << 7) | (self.payload_type & 0x7F);

        bytes.push(byte0);
        bytes.push(byte1);
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes.extend_from_slice(&self.ssrc.to_be_bytes());

        for &csrc in &self.csrc_list {
            bytes.extend_from_slice(&csrc.to_be_bytes());
        }

        if self.extension {
            if let Some(ext) = &self.header_extension {
                bytes.extend_from_slice(&ext.profile.to_be_bytes());
                let length_words = (ext.data.len() / 4) as u16;
                bytes.extend_from_slice(&length_words.to_be_bytes());
                bytes.extend_from_slice(&ext.data);
            } else if let Some(prof) = self.extension_profile {
                bytes.extend_from_slice(&prof.to_be_bytes());
                let data = self.extension_data.as_deref().unwrap_or(&[]);
                let length_words = (data.len() / 4) as u16;
                bytes.extend_from_slice(&length_words.to_be_bytes());
                bytes.extend_from_slice(data);
            }
        }

        bytes
    }
}

impl TryFrom<&[u8]> for RtpHeader {
    type Error = RtpParseError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        parse_rtp_header(data)
    }
}

/// Parsed view of an RTP packet containing parsed header and borrowed payload slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    /// Parsed RTP header.
    pub header: RtpHeader,
    /// Borrowed slice of payload data bytes.
    pub payload: &'a [u8],
    /// Borrowed slice of trailing padding octets, if any.
    pub padding: &'a [u8],
}

impl<'a> RtpPacket<'a> {
    /// Parses an RTP packet from a byte slice.
    ///
    /// # Errors
    /// Returns [`RtpParseError`] if header or payload structure is truncated or malformed.
    pub fn parse(data: &'a [u8]) -> Result<Self, RtpParseError> {
        parse_rtp_packet(data)
    }

    /// Returns a reference to the parsed header.
    #[must_use]
    pub const fn header(&self) -> &RtpHeader {
        &self.header
    }

    /// Returns a slice of the payload data bytes.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Returns a slice of trailing padding bytes, if any.
    #[must_use]
    pub const fn padding(&self) -> &'a [u8] {
        self.padding
    }
}

/// Parses an RTP packet header from a byte buffer.
///
/// # Acceptance Rules
/// - Returns [`RtpParseError::TruncatedHeader`] if `data.len() < 12`.
/// - Returns [`RtpParseError::UnsupportedVersion`] if version is 0, 1, or 3 (must be 2).
/// - Returns [`RtpParseError::TruncatedCsrcList`] if CSRC count declares more bytes than available.
/// - Returns [`RtpParseError::TruncatedExtensionHeader`] if extension bit is set and buffer < offset + 4.
/// - Returns [`RtpParseError::TruncatedExtensionData`] if extension data length exceeds buffer.
///
/// # Errors
/// Returns [`RtpParseError`] if the buffer is truncated or malformed.
pub fn parse_rtp_header(data: &[u8]) -> Result<RtpHeader, RtpParseError> {
    if data.len() < RTP_FIXED_HEADER_LEN {
        return Err(RtpParseError::TruncatedHeader);
    }

    let byte0 = data[0];
    let version = (byte0 >> 6) & 0x03;
    if version != RTP_VERSION_2 {
        return Err(RtpParseError::UnsupportedVersion(version));
    }

    let padding = (byte0 & 0x20) != 0;
    let extension = (byte0 & 0x10) != 0;
    let csrc_count = byte0 & 0x0F;

    let byte1 = data[1];
    let marker = (byte1 & 0x80) != 0;
    let payload_type = byte1 & 0x7F;

    let sequence_number = u16::from_be_bytes([data[2], data[3]]);
    let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let mut offset = RTP_FIXED_HEADER_LEN;

    // CSRC list validation and extraction
    let csrc_bytes_len = (csrc_count as usize) * 4;
    if data.len() < offset + csrc_bytes_len {
        return Err(RtpParseError::TruncatedCsrcList);
    }

    let mut csrc_list = Vec::with_capacity(csrc_count as usize);
    for _ in 0..csrc_count {
        let csrc = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        csrc_list.push(csrc);
        offset += 4;
    }

    // Header extension validation and extraction (RFC 3550 §5.3.1)
    let mut extension_profile = None;
    let mut extension_data = None;
    let mut header_extension = None;

    if extension {
        if data.len() < offset + 4 {
            return Err(RtpParseError::TruncatedExtensionHeader);
        }

        let prof = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let length_words = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let ext_data_len = length_words * 4;
        offset += 4;

        if data.len() < offset + ext_data_len {
            return Err(RtpParseError::TruncatedExtensionData);
        }

        let ext_bytes = data[offset..offset + ext_data_len].to_vec();
        offset += ext_data_len;

        extension_profile = Some(prof);
        extension_data = Some(ext_bytes.clone());
        header_extension = Some(RtpHeaderExtension {
            profile: prof,
            data: ext_bytes,
        });
    }

    let header_length = offset;
    let payload_offset = offset;

    Ok(RtpHeader {
        version,
        padding,
        extension,
        csrc_count,
        marker,
        payload_type,
        sequence_number,
        timestamp,
        ssrc,
        csrc_list,
        extension_profile,
        extension_data,
        header_extension,
        header_length,
        payload_offset,
    })
}

/// Alias for [`parse_rtp_header`].
pub fn parse_header(data: &[u8]) -> Result<RtpHeader, RtpParseError> {
    parse_rtp_header(data)
}

/// Alias for [`parse_rtp_header`].
pub fn parse_rtp(data: &[u8]) -> Result<RtpHeader, RtpParseError> {
    parse_rtp_header(data)
}

/// Parses a full RTP packet (header and payload).
///
/// # Errors
/// Returns [`RtpParseError`] if header is malformed or declared padding exceeds payload bounds.
pub fn parse_rtp_packet<'a>(data: &'a [u8]) -> Result<RtpPacket<'a>, RtpParseError> {
    let header = parse_rtp_header(data)?;
    let mut payload_end = data.len();
    let mut padding_slice = &data[payload_end..];

    if header.padding {
        if data.len() <= header.payload_offset {
            return Err(RtpParseError::TruncatedPadding);
        }
        let pad_len = data[data.len() - 1] as usize;
        if pad_len == 0 || pad_len > (data.len() - header.payload_offset) {
            return Err(RtpParseError::TruncatedPadding);
        }
        payload_end = data.len() - pad_len;
        padding_slice = &data[payload_end..];
    }

    let payload = &data[header.payload_offset..payload_end];

    Ok(RtpPacket {
        header,
        payload,
        padding: padding_slice,
    })
}

/// Alias for [`parse_rtp_packet`].
pub fn parse_packet<'a>(data: &'a [u8]) -> Result<RtpPacket<'a>, RtpParseError> {
    parse_rtp_packet(data)
}

/// Evaluates payload bytes, returning both [`RtpParseStatus`] and optional [`RtpHeader`].
pub fn evaluate_rtp_header(data: &[u8]) -> (RtpParseStatus, Option<RtpHeader>) {
    match parse_rtp_header(data) {
        Ok(hdr) => (RtpParseStatus::Valid, Some(hdr)),
        Err(err) => (err.status(), None),
    }
}

/// Evaluates raw payload bytes, returning [`RtpParseStatus`] without panicking.
pub fn evaluate_payload(data: &[u8]) -> RtpParseStatus {
    match parse_rtp_header(data) {
        Ok(_) => RtpParseStatus::Valid,
        Err(err) => err.status(),
    }
}

/// Alias for [`evaluate_payload`].
pub fn evaluate_rtp_payload(data: &[u8]) -> RtpParseStatus {
    evaluate_payload(data)
}

/// Encodes an RTP header into a newly allocated byte vector.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn encode_rtp_header(
    version: u8,
    padding: bool,
    extension: bool,
    marker: bool,
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    csrc_list: &[u32],
    extension_header: Option<(u16, &[u8])>,
) -> Vec<u8> {
    let csrc_count = (csrc_list.len() & 0x0F) as u8;
    let ext_len = extension_header.map_or(0, |(_, d)| 4 + d.len());
    let mut bytes = Vec::with_capacity(12 + csrc_list.len() * 4 + ext_len);

    let byte0 = (version << 6)
        | (u8::from(padding) << 5)
        | (u8::from(extension) << 4)
        | (csrc_count & 0x0F);
    let byte1 = (u8::from(marker) << 7) | (payload_type & 0x7F);

    bytes.push(byte0);
    bytes.push(byte1);
    bytes.extend_from_slice(&sequence_number.to_be_bytes());
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&ssrc.to_be_bytes());

    for &csrc in csrc_list {
        bytes.extend_from_slice(&csrc.to_be_bytes());
    }

    if let Some((profile, ext_data)) = extension_header {
        bytes.extend_from_slice(&profile.to_be_bytes());
        let length_words = (ext_data.len() / 4) as u16;
        bytes.extend_from_slice(&length_words.to_be_bytes());
        bytes.extend_from_slice(ext_data);
    }

    bytes
}

/// Stateful continuity and sequence tracker for an individual RTP stream (SSRC) modulo 65536.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpSequenceTracker {
    /// Optional SSRC identifier associated with this tracker.
    pub ssrc: Option<u32>,
    /// Total number of packets evaluated.
    pub packets_evaluated: u64,
    /// Last observed sequence number.
    pub last_sequence: Option<u16>,
    /// Highest sequence number observed.
    pub highest_sequence: Option<u16>,
    /// Cumulative count of missing packets (sequence gaps) detected.
    pub gap_count: u64,
    /// Cumulative count of duplicate packets detected.
    pub duplicate_count: u64,
    /// Cumulative count of out-of-order packets detected.
    pub out_of_order_count: u64,
    /// Cumulative count of rollover events detected modulo 65536.
    pub rollover_count: u64,
    recent_seen_queue: VecDeque<u16>,
    recent_seen_set: HashSet<u16>,
}

impl Default for RtpSequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpSequenceTracker {
    /// Creates a new sequence tracker for RTP sequence evaluation modulo 65536.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ssrc: None,
            packets_evaluated: 0,
            last_sequence: None,
            highest_sequence: None,
            gap_count: 0,
            duplicate_count: 0,
            out_of_order_count: 0,
            rollover_count: 0,
            recent_seen_queue: VecDeque::with_capacity(2048),
            recent_seen_set: HashSet::with_capacity(2048),
        }
    }

    /// Creates a new sequence tracker configured for a specific SSRC.
    #[must_use]
    pub fn with_ssrc(ssrc: u32) -> Self {
        let mut tracker = Self::new();
        tracker.ssrc = Some(ssrc);
        tracker
    }

    /// Evaluates a 16-bit RTP sequence number modulo 65536 and updates continuity state.
    ///
    /// # Rollover Behavior
    /// When sequence number `0` is received immediately following `65535`, a rollover event
    /// is recorded without incrementing the gap count (no packet loss reported).
    pub fn record_sequence(&mut self, seq: u16) -> SequenceTrackingEvent {
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

        let modulus: u32 = RTP_SEQUENCE_MODULUS as u32; // 65536
        let half_modulus: u32 = modulus / 2; // 32768
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

    /// Alias for [`Self::record_sequence`].
    pub fn process_sequence(&mut self, seq: u16) -> SequenceTrackingEvent {
        self.record_sequence(seq)
    }

    /// Evaluates sequence continuity from an extracted [`RtpHeader`].
    pub fn record_header(&mut self, header: &RtpHeader) -> SequenceTrackingEvent {
        if self.ssrc.is_none() {
            self.ssrc = Some(header.ssrc);
        }
        self.record_sequence(header.sequence_number)
    }

    /// Alias for [`Self::record_header`].
    pub fn process_header(&mut self, header: &RtpHeader) -> SequenceTrackingEvent {
        self.record_header(header)
    }

    /// Evaluates sequence continuity from a parsed [`RtpPacket`].
    pub fn record_packet(&mut self, packet: &RtpPacket<'_>) -> SequenceTrackingEvent {
        self.record_header(&packet.header)
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

    /// Returns true if the sequence number was already seen in the recent duplicate window.
    #[must_use]
    pub fn is_duplicate(&self, seq: u16) -> bool {
        self.last_sequence == Some(seq) || self.recent_seen_set.contains(&seq)
    }

    /// Returns the number of sequence gaps (missing packets) detected.
    #[must_use]
    pub const fn gap_count(&self) -> u64 {
        self.gap_count
    }

    /// Alias for [`Self::gap_count`].
    #[must_use]
    pub const fn packet_loss(&self) -> u64 {
        self.gap_count
    }

    /// Alias for [`Self::gap_count`].
    #[must_use]
    pub const fn lost_count(&self) -> u64 {
        self.gap_count
    }

    /// Returns the number of duplicate packets detected.
    #[must_use]
    pub const fn duplicate_count(&self) -> u64 {
        self.duplicate_count
    }

    /// Returns the number of out-of-order packets detected.
    #[must_use]
    pub const fn out_of_order_count(&self) -> u64 {
        self.out_of_order_count
    }

    /// Returns the number of rollover events detected modulo 65536.
    #[must_use]
    pub const fn rollover_count(&self) -> u64 {
        self.rollover_count
    }

    /// Returns the total number of packets evaluated.
    #[must_use]
    pub const fn packets_evaluated(&self) -> u64 {
        self.packets_evaluated
    }

    /// Returns the last sequence number processed, if any.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<u16> {
        self.last_sequence
    }

    /// Returns the highest sequence number processed, if any.
    #[must_use]
    pub const fn highest_sequence(&self) -> Option<u16> {
        self.highest_sequence
    }

    /// Returns the SSRC associated with this tracker, if any.
    #[must_use]
    pub const fn ssrc(&self) -> Option<u32> {
        self.ssrc
    }

    /// Resets all sequence tracking state and counters.
    pub fn reset(&mut self) {
        self.packets_evaluated = 0;
        self.last_sequence = None;
        self.highest_sequence = None;
        self.gap_count = 0;
        self.duplicate_count = 0;
        self.out_of_order_count = 0;
        self.rollover_count = 0;
        self.recent_seen_queue.clear();
        self.recent_seen_set.clear();
    }
}

/// Multi-stream sequence tracker managing independent [`RtpSequenceTracker`] instances keyed by SSRC.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RtpSessionSequenceTracker {
    trackers: HashMap<u32, RtpSequenceTracker>,
}

impl RtpSessionSequenceTracker {
    /// Creates a new multi-SSRC session tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trackers: HashMap::new(),
        }
    }

    /// Records a sequence number for a specific SSRC.
    pub fn record_sequence(&mut self, ssrc: u32, seq: u16) -> SequenceTrackingEvent {
        let tracker = self
            .trackers
            .entry(ssrc)
            .or_insert_with(|| RtpSequenceTracker::with_ssrc(ssrc));
        tracker.record_sequence(seq)
    }

    /// Records sequence continuity from a parsed [`RtpHeader`].
    pub fn record_header(&mut self, header: &RtpHeader) -> SequenceTrackingEvent {
        self.record_sequence(header.ssrc, header.sequence_number)
    }

    /// Returns a reference to the tracker for a specific SSRC, if present.
    #[must_use]
    pub fn get(&self, ssrc: u32) -> Option<&RtpSequenceTracker> {
        self.trackers.get(&ssrc)
    }

    /// Returns a mutable reference to the tracker for a specific SSRC, if present.
    pub fn get_mut(&mut self, ssrc: u32) -> Option<&mut RtpSequenceTracker> {
        self.trackers.get_mut(&ssrc)
    }

    /// Alias for [`Self::get`].
    #[must_use]
    pub fn ssrc_tracker(&self, ssrc: u32) -> Option<&RtpSequenceTracker> {
        self.get(ssrc)
    }

    /// Returns the last sequence number observed for a specific SSRC.
    #[must_use]
    pub fn last_sequence(&self, ssrc: u32) -> Option<u16> {
        self.get(ssrc).and_then(|t| t.last_sequence())
    }

    /// Returns the missing packet gap count for a specific SSRC.
    #[must_use]
    pub fn gap_count(&self, ssrc: u32) -> u64 {
        self.get(ssrc).map_or(0, |t| t.gap_count())
    }

    /// Returns the duplicate count for a specific SSRC.
    #[must_use]
    pub fn duplicate_count(&self, ssrc: u32) -> u64 {
        self.get(ssrc).map_or(0, |t| t.duplicate_count())
    }

    /// Returns the out-of-order count for a specific SSRC.
    #[must_use]
    pub fn out_of_order_count(&self, ssrc: u32) -> u64 {
        self.get(ssrc).map_or(0, |t| t.out_of_order_count())
    }

    /// Returns the rollover count for a specific SSRC.
    #[must_use]
    pub fn rollover_count(&self, ssrc: u32) -> u64 {
        self.get(ssrc).map_or(0, |t| t.rollover_count())
    }

    /// Returns the total packets evaluated across all SSRCs.
    #[must_use]
    pub fn total_packets_evaluated(&self) -> u64 {
        self.trackers.values().map(|t| t.packets_evaluated()).sum()
    }

    /// Returns the total gaps across all SSRCs.
    #[must_use]
    pub fn total_gap_count(&self) -> u64 {
        self.trackers.values().map(|t| t.gap_count()).sum()
    }

    /// Returns the total duplicates across all SSRCs.
    #[must_use]
    pub fn total_duplicate_count(&self) -> u64 {
        self.trackers.values().map(|t| t.duplicate_count()).sum()
    }

    /// Returns the total out-of-order packets across all SSRCs.
    #[must_use]
    pub fn total_out_of_order_count(&self) -> u64 {
        self.trackers.values().map(|t| t.out_of_order_count()).sum()
    }

    /// Returns the total rollover events across all SSRCs.
    #[must_use]
    pub fn total_rollover_count(&self) -> u64 {
        self.trackers.values().map(|t| t.rollover_count()).sum()
    }

    /// Clears all SSRC trackers.
    pub fn reset(&mut self) {
        self.trackers.clear();
    }
}

// Type aliases for naming compatibility
pub type RtpSourceSequenceTracker = RtpSequenceTracker;
pub type RtpSsrcSequenceTracker = RtpSequenceTracker;
pub type RtpEndpointSequenceTracker = RtpSequenceTracker;
pub type RtpStreamSequenceTracker = RtpSessionSequenceTracker;
pub type RtpMultiSequenceTracker = RtpSessionSequenceTracker;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criterion1_parse_12_byte_buffer_extracts_matching_fields() {
        // Acceptance criterion:
        // In crates/rer/src/rtp.rs, parsing a 12-byte buffer with version 2, payload type 96,
        // sequence number 1000, timestamp 160000, and SSRC 0x12345678 returns an RtpHeader
        // with matching field values.
        let raw = [
            0x80, // V=2, P=0, X=0, CC=0
            96,   // M=0, PT=96
            0x03, 0xE8, // Sequence number 1000
            0x00, 0x02, 0x71, 0x00, // Timestamp 160000
            0x12, 0x34, 0x56, 0x78, // SSRC 0x12345678
        ];

        assert_eq!(raw.len(), 12);

        let header = parse_rtp_header(&raw).expect("12-byte buffer must parse successfully");
        assert_eq!(header.version, 2);
        assert_eq!(header.version(), 2);
        assert_eq!(header.payload_type, 96);
        assert_eq!(header.payload_type(), 96);
        assert_eq!(header.sequence_number, 1000);
        assert_eq!(header.sequence_number(), 1000);
        assert_eq!(header.timestamp, 160_000);
        assert_eq!(header.timestamp(), 160_000);
        assert_eq!(header.ssrc, 0x12345678);
        assert_eq!(header.ssrc(), 0x12345678);

        assert!(!header.padding);
        assert!(!header.extension);
        assert_eq!(header.csrc_count, 0);
        assert!(!header.marker);
        assert_eq!(header.header_length, 12);
        assert_eq!(header.payload_offset, 12);

        // Also test with parse_header and RtpHeader::parse
        let h2 = parse_header(&raw).expect("parse_header must succeed");
        assert_eq!(h2, header);
        let h3 = RtpHeader::parse(&raw).expect("RtpHeader::parse must succeed");
        assert_eq!(h3, header);
    }

    #[test]
    fn test_criterion2_shorter_than_12_bytes_returns_truncated_header() {
        // Acceptance criterion:
        // In crates/rer/src/rtp.rs, parsing a buffer shorter than 12 bytes returns an error
        // indicating a truncated header.
        for len in 0..12 {
            let buf = vec![0u8; len];
            let res = parse_rtp_header(&buf);
            assert_eq!(res, Err(RtpParseError::TruncatedHeader));
            let err = res.unwrap_err();
            assert!(err.is_truncated_header());
            assert!(err.is_truncated());
            assert!(err.to_string().contains("truncated"));
        }
    }

    #[test]
    fn test_criterion3_unsupported_versions_0_1_3_return_unsupported_version_error() {
        // Acceptance criterion:
        // In crates/rer/src/rtp.rs, parsing a buffer with version field set to 0, 1, or 3
        // returns an error indicating an unsupported version.
        let mut buf = [
            0x80, 96, 0x03, 0xE8, 0x00, 0x02, 0x71, 0x00, 0x12, 0x34, 0x56, 0x78,
        ];

        for &unsupported_v in &[0u8, 1u8, 3u8] {
            // Overwrite version bits (bits 7..6)
            buf[0] = (buf[0] & 0x3F) | (unsupported_v << 6);
            let res = parse_rtp_header(&buf);
            assert_eq!(res, Err(RtpParseError::UnsupportedVersion(unsupported_v)));
            let err = res.unwrap_err();
            assert!(err.is_unsupported_version());
            assert_eq!(err.unsupported_version(), Some(unsupported_v));
            assert!(err.to_string().contains("unsupported RTP version"));
        }
    }

    #[test]
    fn test_criterion4_csrc_count_2_fewer_than_8_bytes_returns_truncated_csrc_list() {
        // Acceptance criterion:
        // In crates/rer/src/rtp.rs, parsing a buffer declaring a CSRC count of 2 but
        // containing fewer than 8 bytes of CSRC data returns an error indicating a truncated CSRC list.
        let mut buf = vec![
            0x82, // V=2, CC=2 (needs 2 * 4 = 8 bytes of CSRC data)
            96, 0x03, 0xE8, 0x00, 0x02, 0x71, 0x00, 0x12, 0x34, 0x56, 0x78,
        ];
        // Currently buf.len() == 12, CSRC data present is 0 bytes (fewer than 8)
        let res = parse_rtp_header(&buf);
        assert_eq!(res, Err(RtpParseError::TruncatedCsrcList));
        let err = res.unwrap_err();
        assert!(err.is_truncated_csrc_list());
        assert!(err.to_string().contains("truncated CSRC list"));

        // Add 4 bytes of CSRC data (still fewer than 8 bytes)
        buf.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(buf.len(), 16);
        let res2 = parse_rtp_header(&buf);
        assert_eq!(res2, Err(RtpParseError::TruncatedCsrcList));

        // Add remaining 4 bytes of CSRC data (now exactly 8 bytes)
        buf.extend_from_slice(&[0x55, 0x66, 0x77, 0x88]);
        assert_eq!(buf.len(), 20);
        let res3 = parse_rtp_header(&buf);
        assert!(res3.is_ok());
        let hdr = res3.unwrap();
        assert_eq!(hdr.csrc_count, 2);
        assert_eq!(hdr.csrc_list, vec![0x11223344, 0x55667788]);
    }

    #[test]
    fn test_criterion5_extension_flag_extracts_profile_and_data() {
        // Acceptance criterion:
        // In crates/rer/src/rtp.rs, parsing a buffer with extension flag set and a valid 4-byte
        // extension header extracts the extension profile identifier and extension data bytes.
        let mut buf = vec![
            0x90, // V=2, X=1 (extension flag set), CC=0
            96, 0x03, 0xE8, 0x00, 0x02, 0x71, 0x00, 0x12, 0x34, 0x56, 0x78,
        ];
        // 4-byte extension header: profile = 0xBEDE, length = 1 word (4 octets)
        let profile = 0xBEDEu16;
        let ext_data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        buf.extend_from_slice(&profile.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // length in 32-bit words
        buf.extend_from_slice(&ext_data);

        let header = parse_rtp_header(&buf).expect("must parse with extension");
        assert!(header.extension);
        assert!(header.extension_flag());
        assert_eq!(header.extension_profile, Some(profile));
        assert_eq!(header.extension_profile(), Some(profile));
        assert_eq!(header.extension_data, Some(ext_data.clone()));
        assert_eq!(header.extension_data(), Some(ext_data.as_slice()));

        let ext = header.header_extension.as_ref().expect("header extension");
        assert_eq!(ext.profile, profile);
        assert_eq!(ext.data, ext_data);

        // Also test with length = 0 (empty extension data, exactly 4-byte extension header)
        let mut buf_empty_ext = vec![
            0x90, 96, 0x03, 0xE8, 0x00, 0x02, 0x71, 0x00, 0x12, 0x34, 0x56, 0x78,
        ];
        let profile_empty = 0x1234u16;
        buf_empty_ext.extend_from_slice(&profile_empty.to_be_bytes());
        buf_empty_ext.extend_from_slice(&0u16.to_be_bytes()); // length = 0 words
        let header2 = parse_rtp_header(&buf_empty_ext).expect("4-byte ext header length 0");
        assert_eq!(header2.extension_profile, Some(profile_empty));
        assert_eq!(header2.extension_data, Some(vec![]));
    }

    #[test]
    fn test_criterion6_sequence_tracker_rollover_from_65535_to_0_no_packet_loss() {
        // Acceptance criterion:
        // In crates/rer/src/rtp.rs, sequence tracking receiving sequence number 0 immediately
        // following sequence number 65535 records a sequence rollover event without reporting packet loss.
        let mut tracker = RtpSequenceTracker::new();

        // Initial packet at 65535
        let ev1 = tracker.record_sequence(65535);
        assert_eq!(ev1, SequenceTrackingEvent::Initial { sequence: 65535 });
        assert_eq!(tracker.last_sequence(), Some(65535));
        assert_eq!(tracker.gap_count(), 0);
        assert_eq!(tracker.packet_loss(), 0);
        assert_eq!(tracker.rollover_count(), 0);

        // Sequence number 0 immediately follows 65535
        let ev2 = tracker.record_sequence(0);
        assert_eq!(
            ev2,
            SequenceTrackingEvent::Rollover {
                sequence: 0,
                missing_count: 0,
            }
        );
        assert_eq!(tracker.last_sequence(), Some(0));
        assert_eq!(tracker.rollover_count(), 1);
        assert_eq!(
            tracker.gap_count(),
            0,
            "must not report packet loss on rollover"
        );
        assert_eq!(
            tracker.packet_loss(),
            0,
            "must not report packet loss on rollover"
        );

        // Advance in-order to 1
        let ev3 = tracker.record_sequence(1);
        assert_eq!(ev3, SequenceTrackingEvent::InOrder { sequence: 1 });
        assert_eq!(tracker.gap_count(), 0);
        assert_eq!(tracker.rollover_count(), 1);
    }

    #[test]
    fn test_sequence_tracker_gaps_duplicates_and_out_of_order() {
        let mut tracker = RtpSequenceTracker::new();
        assert_eq!(
            tracker.record_sequence(100),
            SequenceTrackingEvent::Initial { sequence: 100 }
        );
        assert_eq!(
            tracker.record_sequence(101),
            SequenceTrackingEvent::InOrder { sequence: 101 }
        );

        // Duplicate
        assert_eq!(
            tracker.record_sequence(101),
            SequenceTrackingEvent::Duplicate { sequence: 101 }
        );
        assert_eq!(tracker.duplicate_count(), 1);

        // Gap: skip 102, 103, arrive 104
        assert_eq!(
            tracker.record_sequence(104),
            SequenceTrackingEvent::Gap {
                expected: 102,
                actual: 104,
                missing_count: 2,
            }
        );
        assert_eq!(tracker.gap_count(), 2);

        // Out of order: 102 arrives late
        assert_eq!(
            tracker.record_sequence(102),
            SequenceTrackingEvent::OutOfOrder {
                sequence: 102,
                previous_highest: 104,
            }
        );
        assert_eq!(tracker.out_of_order_count(), 1);

        // Rollover with gap: from 65534 to 2 (missing 65535, 0, 1 -> 3 packets)
        let mut tracker2 = RtpSequenceTracker::new();
        assert_eq!(
            tracker2.record_sequence(65534),
            SequenceTrackingEvent::Initial { sequence: 65534 }
        );
        assert_eq!(
            tracker2.record_sequence(2),
            SequenceTrackingEvent::Rollover {
                sequence: 2,
                missing_count: 3,
            }
        );
        assert_eq!(tracker2.rollover_count(), 1);
        assert_eq!(tracker2.gap_count(), 3);
    }
}
