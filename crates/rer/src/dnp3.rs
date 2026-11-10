//! In-tree DNP3 FT3 stream framing and CRC validation (SPEC §5, §8, §14, Task RER-F-075).
//!
//! Provides a zero-dependency in-tree parser and framing implementation for DNP3
//! (Distributed Network Protocol / IEEE Std 1815-2012) Link Protocol Data Units (LPDUs)
//! in FT3 format, transport pseudo-layer headers, and 16-bit CRC validation.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14 and §8, RER implements passive stream inspection and TCP framing
//! for DNP3. RER does not implement an outstation state machine, master polling schedule,
//! event queues (Class 1/2/3), internal indication (IIN) management, or active SCADA control
//! execution. Forwarded frames are transmitted byte-unmodified.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

pub use crate::framing::{read_dnp3_frame, write_dnp3_frame};

/// First synchronization octet of an FT3 frame (0x05).
pub const DNP3_SYNC_0: u8 = 0x05;

/// Second synchronization octet of an FT3 frame (0x64).
pub const DNP3_SYNC_1: u8 = 0x64;

/// Complete 2-octet sync sequence [0x05, 0x64].
pub const DNP3_SYNC: [u8; 2] = [0x05, 0x64];

/// Fixed length of the FT3 data link header in octets (including 2-octet header CRC).
pub const DNP3_HEADER_LEN: usize = 10;

/// Number of octets covered by the FT3 header CRC (Sync + Length + Control + Dest + Src).
pub const DNP3_HEADER_DATA_LEN: usize = 8;

/// Minimum valid value for the FT3 Length field (5 octets: 1 Control + 2 Dest + 2 Src, 0 user data).
pub const DNP3_MIN_LENGTH: u8 = 5;

/// Maximum valid value for the FT3 Length field (255 octets: 5 link header + 250 user data).
pub const DNP3_MAX_LENGTH: u8 = 255;

/// Minimum total FT3 LPDU length (10-octet header with 0 user data).
pub const DNP3_MIN_FRAME_LEN: usize = 10;

/// Maximum total FT3 LPDU length (10-octet header + 250 user data + 32 CRCs = 292 octets).
pub const DNP3_MAX_FRAME_LEN: usize = 292;

/// Maximum user data payload per CRC-protected block (16 octets).
pub const DNP3_BLOCK_SIZE: usize = 16;

/// 16-bit CRC generator polynomial for DNP3 (0xA653, bit-reflected from 0x3D65).
pub const DNP3_CRC_POLY: u16 = 0xA653;

/// Alias for [`DNP3_CRC_POLY`].
pub const CRC_POLYNOMIAL: u16 = 0xA653;

// Primary link-layer control function codes (PRM = 1)
pub const DNP3_FC_RESET_LINK_STATES: u8 = 0x00;
pub const DNP3_FC_RESET_USER_PROCESS: u8 = 0x01;
pub const DNP3_FC_TEST_LINK_STATES: u8 = 0x02;
pub const DNP3_FC_CONFIRMED_USER_DATA: u8 = 0x03;
pub const DNP3_FC_UNCONFIRMED_USER_DATA: u8 = 0x04;
pub const DNP3_FC_REQUEST_LINK_STATUS: u8 = 0x09;

// Secondary link-layer control function codes (PRM = 0)
pub const DNP3_FC_ACK: u8 = 0x00;
pub const DNP3_FC_NACK: u8 = 0x01;
pub const DNP3_FC_LINK_STATUS: u8 = 0x0B;
pub const DNP3_FC_NOT_SUPPORTED: u8 = 0x0E;

/// Compile-time lookup table generator for DNP3 16-bit CRC with polynomial 0xA653.
const fn make_crc_table() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u16;
        let mut j = 0;
        while j < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ DNP3_CRC_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Precomputed 256-entry lookup table for DNP3 CRC-16.
pub const CRC_TABLE: [u16; 256] = make_crc_table();

/// Calculates the 16-bit CRC over `data` using polynomial 0xA653 with inverted output.
///
/// In standard DNP3 (IEEE Std 1815-2012):
/// - Polynomial: x^16 + x^13 + x^12 + x^11 + x^10 + x^8 + x^6 + x^5 + x^2 + 1 (0xA653 bit-reflected)
/// - Initial value: 0x0000
/// - Final XOR: 0xFFFF (bitwise inversion of output)
#[must_use]
pub fn calculate_crc(data: &[u8]) -> u16 {
    let mut crc = 0x0000u16;
    for &byte in data {
        let idx = ((crc ^ (byte as u16)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[idx];
    }
    !crc
}

/// Alias for [`calculate_crc`].
#[must_use]
pub fn dnp3_crc(data: &[u8]) -> u16 {
    calculate_crc(data)
}

/// Alias for [`calculate_crc`].
#[must_use]
pub fn compute_crc(data: &[u8]) -> u16 {
    calculate_crc(data)
}

/// Alias for [`calculate_crc`].
#[must_use]
pub fn crc16(data: &[u8]) -> u16 {
    calculate_crc(data)
}

/// Errors encountered when parsing a DNP3 FT3 header, user data block, or frame.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Dnp3ParseError {
    /// Buffer is shorter than the mandatory 10-octet FT3 header.
    TruncatedHeader,
    /// Buffer is shorter than the declared total LPDU wire length.
    TruncatedPayload,
    /// Frame does not begin with sync octets 0x05 0x64.
    InvalidSync([u8; 2]),
    /// Declared length field is out of allowable range (5..=255).
    LengthOutOfRange(u8),
    /// Declared length exceeds maximum allowed frame size.
    LengthExceedsMaximum(usize),
    /// Header CRC verification failed.
    HeaderCrcFailure { expected: u16, calculated: u16 },
    /// Data block CRC verification failed.
    BlockCrcFailure {
        block_index: usize,
        expected: u16,
        calculated: u16,
    },
    /// User data block is empty when attempting to extract transport control.
    EmptyUserData,
    /// Transport control octet is invalid.
    InvalidTransportControl,
}

impl Dnp3ParseError {
    /// Returns true if this error represents a CRC verification failure.
    #[must_use]
    pub const fn is_crc_failure(&self) -> bool {
        matches!(
            self,
            Self::HeaderCrcFailure { .. } | Self::BlockCrcFailure { .. }
        )
    }

    /// Alias for [`is_crc_failure`].
    #[must_use]
    pub const fn is_crc_verification_failure(&self) -> bool {
        self.is_crc_failure()
    }

    /// Alias for [`is_crc_failure`].
    #[must_use]
    pub const fn is_crc_error(&self) -> bool {
        self.is_crc_failure()
    }

    /// Returns true if this error is specifically a header CRC failure.
    #[must_use]
    pub const fn is_header_crc_failure(&self) -> bool {
        matches!(self, Self::HeaderCrcFailure { .. })
    }

    /// Returns true if the buffer was truncated.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::TruncatedHeader | Self::TruncatedPayload)
    }
}

impl fmt::Display for Dnp3ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => {
                write!(f, "truncated FT3 header (fewer than 10 octets)")
            }
            Self::TruncatedPayload => {
                write!(f, "truncated LPDU frame payload")
            }
            Self::InvalidSync(s) => {
                write!(
                    f,
                    "invalid DNP3 sync octets: [0x{:02X}, 0x{:02X}] (expected [0x05, 0x64])",
                    s[0], s[1]
                )
            }
            Self::LengthOutOfRange(len) => {
                write!(
                    f,
                    "out-of-range DNP3 length field: {len} (expected 5..=255)"
                )
            }
            Self::LengthExceedsMaximum(len) => {
                write!(f, "DNP3 frame length {len} exceeds maximum allowed size")
            }
            Self::HeaderCrcFailure {
                expected,
                calculated,
            } => {
                write!(
                    f,
                    "DNP3 header CRC verification failure: calculated 0x{calculated:04X}, expected 0x{expected:04X}"
                )
            }
            Self::BlockCrcFailure {
                block_index,
                expected,
                calculated,
            } => {
                write!(
                    f,
                    "DNP3 data block {block_index} CRC verification failure: calculated 0x{calculated:04X}, expected 0x{expected:04X}"
                )
            }
            Self::EmptyUserData => write!(f, "empty user data block"),
            Self::InvalidTransportControl => write!(f, "invalid transport control"),
        }
    }
}

impl std::error::Error for Dnp3ParseError {}

/// Parsed DNP3 FT3 link layer header (10 octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dnp3LinkHeader {
    /// 2-octet synchronization pattern (0x05 0x64).
    pub sync: [u8; 2],
    /// Length field (5..=255).
    pub length: u8,
    /// Raw link control octet.
    pub control: u8,
    /// Destination station address (16-bit unsigned little-endian integer).
    pub destination: u16,
    /// Source station address (16-bit unsigned little-endian integer).
    pub source: u16,
    /// 16-bit header CRC (little-endian).
    pub header_crc: u16,
    /// Direction bit (DIR, bit 7 of control): true = master-to-outstation.
    pub direction: bool,
    /// Primary bit (PRM, bit 6 of control): true = initiating/primary station.
    pub is_primary: bool,
    /// Frame Count Bit (FCB, bit 5 of control, valid when PRM = 1).
    pub fcb: bool,
    /// Frame Count Valid (FCV, bit 4 of control when PRM = 1).
    pub fcv: bool,
    /// Data Flow Control (DFC, bit 4 of control when PRM = 0).
    pub dfc: bool,
    /// Control function code (bits 3..0 of control).
    pub control_function: u8,
}

impl Dnp3LinkHeader {
    /// Parses and validates a 10-octet FT3 header from raw bytes.
    pub fn parse(raw: &[u8]) -> Result<Self, Dnp3ParseError> {
        parse_ft3_header(raw)
    }

    /// Alias for [`parse`].
    pub fn from_slice(raw: &[u8]) -> Result<Self, Dnp3ParseError> {
        parse_ft3_header(raw)
    }

    /// Alias for [`parse`].
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Dnp3ParseError> {
        parse_ft3_header(raw)
    }

    #[must_use]
    pub const fn sync(&self) -> [u8; 2] {
        self.sync
    }

    #[must_use]
    pub const fn length(&self) -> u8 {
        self.length
    }

    #[must_use]
    pub const fn control(&self) -> u8 {
        self.control
    }

    #[must_use]
    pub const fn destination(&self) -> u16 {
        self.destination
    }

    #[must_use]
    pub const fn destination_address(&self) -> u16 {
        self.destination
    }

    #[must_use]
    pub const fn dest(&self) -> u16 {
        self.destination
    }

    #[must_use]
    pub const fn source(&self) -> u16 {
        self.source
    }

    #[must_use]
    pub const fn source_address(&self) -> u16 {
        self.source
    }

    #[must_use]
    pub const fn src(&self) -> u16 {
        self.source
    }

    #[must_use]
    pub const fn header_crc(&self) -> u16 {
        self.header_crc
    }

    #[must_use]
    pub const fn crc(&self) -> u16 {
        self.header_crc
    }

    #[must_use]
    pub const fn direction(&self) -> bool {
        self.direction
    }

    #[must_use]
    pub const fn dir(&self) -> bool {
        self.direction
    }

    #[must_use]
    pub const fn is_primary(&self) -> bool {
        self.is_primary
    }

    #[must_use]
    pub const fn prm(&self) -> bool {
        self.is_primary
    }

    #[must_use]
    pub const fn fcb(&self) -> bool {
        self.fcb
    }

    #[must_use]
    pub const fn fcv(&self) -> bool {
        self.fcv
    }

    #[must_use]
    pub const fn dfc(&self) -> bool {
        self.dfc
    }

    #[must_use]
    pub const fn control_function(&self) -> u8 {
        self.control_function
    }

    #[must_use]
    pub const fn function_code(&self) -> u8 {
        self.control_function
    }

    /// Returns the number of user data octets declared by this header (Length - 5).
    #[must_use]
    pub const fn user_data_len(&self) -> usize {
        (self.length as usize).saturating_sub(DNP3_MIN_LENGTH as usize)
    }

    /// Returns the number of CRC-protected data blocks required for the user data.
    #[must_use]
    pub const fn num_blocks(&self) -> usize {
        let u = self.user_data_len();
        if u == 0 {
            0
        } else {
            u.div_ceil(DNP3_BLOCK_SIZE)
        }
    }

    /// Returns the expected total wire length of the LPDU (10 + user_data + 2 * blocks).
    #[must_use]
    pub const fn wire_length(&self) -> usize {
        DNP3_HEADER_LEN + self.user_data_len() + 2 * self.num_blocks()
    }
}

impl fmt::Display for Dnp3LinkHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FT3Header(len={}, ctrl=0x{:02X}, dst={}, src={}, crc=0x{:04X})",
            self.length, self.control, self.destination, self.source, self.header_crc
        )
    }
}

/// Parsed DNP3 Transport Control header (SPEC §14, IEEE Std 1815-2012).
///
/// Encoded in a single octet:
/// - Bit 7: FIN (Final segment of an application fragment)
/// - Bit 6: FIR (First segment of an application fragment)
/// - Bits 5..0: Sequence number (0..=63 modulo-64 counter)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dnp3TransportHeader {
    /// Raw transport control octet.
    pub control: u8,
    /// First segment flag (FIR, bit 6).
    pub fir: bool,
    /// Final segment flag (FIN, bit 7).
    pub fin: bool,
    /// 6-bit modulo-64 transport sequence number (bits 5..0, 0..=63).
    pub sequence: u8,
    /// Alias for `sequence`.
    pub sequence_number: u8,
}

pub type TransportHeader = Dnp3TransportHeader;

impl Dnp3TransportHeader {
    /// Parses a transport header directly from a single transport control octet.
    #[must_use]
    pub const fn from_octet(control: u8) -> Self {
        let fin = (control & 0x80) != 0;
        let fir = (control & 0x40) != 0;
        let sequence = control & 0x3F;
        Self {
            control,
            fir,
            fin,
            sequence,
            sequence_number: sequence,
        }
    }

    /// Parses transport header from a user data slice or block.
    pub fn parse(data: &[u8]) -> Result<Self, Dnp3ParseError> {
        if data.is_empty() {
            return Err(Dnp3ParseError::EmptyUserData);
        }
        Ok(Self::from_octet(data[0]))
    }

    /// Alias for [`parse`].
    pub fn from_slice(data: &[u8]) -> Result<Self, Dnp3ParseError> {
        Self::parse(data)
    }

    #[must_use]
    pub const fn fir(&self) -> bool {
        self.fir
    }

    #[must_use]
    pub const fn fin(&self) -> bool {
        self.fin
    }

    #[must_use]
    pub const fn sequence(&self) -> u8 {
        self.sequence
    }

    #[must_use]
    pub const fn sequence_number(&self) -> u8 {
        self.sequence_number
    }

    #[must_use]
    pub const fn seq(&self) -> u8 {
        self.sequence
    }

    #[must_use]
    pub const fn control(&self) -> u8 {
        self.control
    }

    #[must_use]
    pub const fn is_first_segment(&self) -> bool {
        self.fir
    }

    #[must_use]
    pub const fn is_final_segment(&self) -> bool {
        self.fin
    }

    #[must_use]
    pub const fn is_unfragmented(&self) -> bool {
        self.fir && self.fin
    }
}

impl fmt::Display for Dnp3TransportHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransportControl(fir={}, fin={}, seq={})",
            self.fir, self.fin, self.sequence
        )
    }
}

/// Parsed DNP3 user data block, containing the transport header and payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3UserDataBlock {
    /// Parsed transport control header.
    pub transport: Dnp3TransportHeader,
    /// First segment flag (FIR, bit 6).
    pub fir: bool,
    /// Final segment flag (FIN, bit 7).
    pub fin: bool,
    /// 6-bit modulo-64 transport sequence number.
    pub sequence: u8,
    /// Alias for `sequence`.
    pub sequence_number: u8,
    /// Block user data payload bytes.
    pub data: Vec<u8>,
    /// Optional block CRC if present.
    pub crc: Option<u16>,
    /// True if block CRC was valid (or no CRC was checked).
    pub crc_valid: bool,
}

impl Deref for Dnp3UserDataBlock {
    type Target = Dnp3TransportHeader;

    fn deref(&self) -> &Self::Target {
        &self.transport
    }
}

impl Dnp3UserDataBlock {
    #[must_use]
    pub const fn fir(&self) -> bool {
        self.fir
    }

    #[must_use]
    pub const fn fin(&self) -> bool {
        self.fin
    }

    #[must_use]
    pub const fn sequence(&self) -> u8 {
        self.sequence
    }

    #[must_use]
    pub const fn sequence_number(&self) -> u8 {
        self.sequence_number
    }

    #[must_use]
    pub const fn transport_header(&self) -> Dnp3TransportHeader {
        self.transport
    }
}

/// High-level DNP3 diagnostic metadata structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3Metadata {
    pub destination: u16,
    pub source: u16,
    pub is_primary: bool,
    pub direction: bool,
    pub control_function: u8,
    pub transport_fir: Option<bool>,
    pub transport_fin: Option<bool>,
    pub transport_sequence: Option<u8>,
    pub application_function: Option<u8>,
    pub crc_valid: bool,
}

/// Parsed DNP3 Link Protocol Data Unit (LPDU) frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dnp3Frame {
    /// Parsed FT3 link layer header.
    pub header: Dnp3LinkHeader,
    /// High-level diagnostic metadata.
    pub metadata: Dnp3Metadata,
    /// Destination station address (from header).
    pub destination: u16,
    /// Source station address (from header).
    pub source: u16,
    /// Control octet (from header).
    pub control: u8,
    /// Link control function code (from header).
    pub control_function: u8,
    /// True if primary station initiated (from header).
    pub is_primary: bool,
    /// Direction bit (from header).
    pub direction: bool,
    /// Declared length (from header).
    pub length: u8,
    /// Header CRC (from header).
    pub header_crc: u16,
    /// True if header CRC passed verification.
    pub header_crc_valid: bool,
    /// Parsed transport control header if user data is present.
    pub transport: Option<Dnp3TransportHeader>,
    /// Transport FIR flag.
    pub transport_fir: Option<bool>,
    /// Transport FIN flag.
    pub transport_fin: Option<bool>,
    /// Transport sequence number (0..=63).
    pub transport_sequence: Option<u8>,
    /// Application function code if present.
    pub application_function: Option<u8>,
    /// De-framed user data payload (concatenated without block CRCs).
    pub user_data: Vec<u8>,
    /// Individual user data blocks.
    pub blocks: Vec<Vec<u8>>,
    /// True if all checked CRCs (header and data blocks) were valid.
    pub crc_valid: bool,
    /// Complete raw frame bytes on wire.
    pub raw: Vec<u8>,
}

impl Deref for Dnp3Frame {
    type Target = Dnp3LinkHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl Dnp3Frame {
    /// Parses a complete DNP3 LPDU frame from raw bytes with CRC validation enabled.
    pub fn parse(payload: &[u8]) -> Result<Self, Dnp3ParseError> {
        parse_dnp3_frame(payload, true)
    }

    /// Alias for [`parse`].
    pub fn from_slice(payload: &[u8]) -> Result<Self, Dnp3ParseError> {
        parse_dnp3_frame(payload, true)
    }

    /// Parses a complete DNP3 LPDU frame with configurable CRC validation.
    pub fn parse_with_crc_validation(
        payload: &[u8],
        validate_crc: bool,
    ) -> Result<Self, Dnp3ParseError> {
        parse_dnp3_frame(payload, validate_crc)
    }

    #[must_use]
    pub fn metadata(&self) -> &Dnp3Metadata {
        &self.metadata
    }

    #[must_use]
    pub fn to_metadata(&self) -> Dnp3Metadata {
        self.metadata.clone()
    }
}

impl From<Dnp3Frame> for Dnp3Metadata {
    fn from(frame: Dnp3Frame) -> Self {
        frame.metadata
    }
}

impl From<Dnp3Frame> for Dnp3LinkHeader {
    fn from(frame: Dnp3Frame) -> Self {
        frame.header
    }
}

/// Parses and validates a 10-octet FT3 header from raw bytes.
///
/// Validates:
/// - Buffer length is at least 10 octets.
/// - Synchronization octets are `[0x05, 0x64]`.
/// - Length field is at least 5 (`DNP3_MIN_LENGTH`).
/// - 16-bit CRC over first 8 octets matches the header CRC field.
pub fn parse_ft3_header(raw: &[u8]) -> Result<Dnp3LinkHeader, Dnp3ParseError> {
    if raw.len() < DNP3_HEADER_LEN {
        return Err(Dnp3ParseError::TruncatedHeader);
    }
    if raw[0] != DNP3_SYNC_0 || raw[1] != DNP3_SYNC_1 {
        return Err(Dnp3ParseError::InvalidSync([raw[0], raw[1]]));
    }
    let length = raw[2];
    if length < DNP3_MIN_LENGTH {
        return Err(Dnp3ParseError::LengthOutOfRange(length));
    }

    let expected_crc = u16::from_le_bytes([raw[8], raw[9]]);
    let calculated_crc = calculate_crc(&raw[0..DNP3_HEADER_DATA_LEN]);
    if expected_crc != calculated_crc {
        return Err(Dnp3ParseError::HeaderCrcFailure {
            expected: expected_crc,
            calculated: calculated_crc,
        });
    }

    let control = raw[3];
    let destination = u16::from_le_bytes([raw[4], raw[5]]);
    let source = u16::from_le_bytes([raw[6], raw[7]]);
    let direction = (control & 0x80) != 0;
    let is_primary = (control & 0x40) != 0;
    let fcb = (control & 0x20) != 0;
    let fcv = is_primary && ((control & 0x10) != 0);
    let dfc = !is_primary && ((control & 0x10) != 0);
    let control_function = control & 0x0F;

    Ok(Dnp3LinkHeader {
        sync: [raw[0], raw[1]],
        length,
        control,
        destination,
        source,
        header_crc: expected_crc,
        direction,
        is_primary,
        fcb,
        fcv,
        dfc,
        control_function,
    })
}

/// Alias for [`parse_ft3_header`].
pub fn parse_link_header(raw: &[u8]) -> Result<Dnp3LinkHeader, Dnp3ParseError> {
    parse_ft3_header(raw)
}

/// Alias for [`parse_ft3_header`].
pub fn parse_dnp3_header(raw: &[u8]) -> Result<Dnp3LinkHeader, Dnp3ParseError> {
    parse_ft3_header(raw)
}

/// Alias for [`parse_ft3_header`].
pub fn parse_header(raw: &[u8]) -> Result<Dnp3LinkHeader, Dnp3ParseError> {
    parse_ft3_header(raw)
}

/// Parses an FT3 user data block containing a transport control octet.
///
/// Extracts FIR (first segment flag), FIN (final segment flag), and 6-bit transport sequence number.
pub fn parse_user_data_block(block: &[u8]) -> Result<Dnp3UserDataBlock, Dnp3ParseError> {
    if block.is_empty() {
        return Err(Dnp3ParseError::EmptyUserData);
    }
    let transport = Dnp3TransportHeader::from_octet(block[0]);
    let (data, crc, crc_valid) = if block.len() > 2 && block.len() <= 18 {
        let data_part = &block[..block.len() - 2];
        let expected_crc = u16::from_le_bytes([block[block.len() - 2], block[block.len() - 1]]);
        let calculated = calculate_crc(data_part);
        (
            data_part.to_vec(),
            Some(expected_crc),
            expected_crc == calculated,
        )
    } else {
        (block.to_vec(), None, true)
    };

    Ok(Dnp3UserDataBlock {
        transport,
        fir: transport.fir,
        fin: transport.fin,
        sequence: transport.sequence,
        sequence_number: transport.sequence,
        data,
        crc,
        crc_valid,
    })
}

/// Parses a DNP3 transport control octet from user data bytes.
pub fn parse_transport_header(block: &[u8]) -> Result<Dnp3TransportHeader, Dnp3ParseError> {
    Dnp3TransportHeader::parse(block)
}

/// Parses a DNP3 transport control octet.
#[must_use]
pub const fn parse_transport_control(octet: u8) -> Dnp3TransportHeader {
    Dnp3TransportHeader::from_octet(octet)
}

/// Parses a complete DNP3 LPDU frame from `raw` bytes, optionally validating CRCs.
pub fn parse_dnp3_frame(raw: &[u8], validate_crc: bool) -> Result<Dnp3Frame, Dnp3ParseError> {
    if raw.len() < DNP3_HEADER_LEN {
        return Err(Dnp3ParseError::TruncatedHeader);
    }
    if raw[0] != DNP3_SYNC_0 || raw[1] != DNP3_SYNC_1 {
        return Err(Dnp3ParseError::InvalidSync([raw[0], raw[1]]));
    }
    let length = raw[2];
    if length < DNP3_MIN_LENGTH {
        return Err(Dnp3ParseError::LengthOutOfRange(length));
    }

    let user_data_len = (length - DNP3_MIN_LENGTH) as usize;
    let num_blocks = if user_data_len == 0 {
        0
    } else {
        user_data_len.div_ceil(DNP3_BLOCK_SIZE)
    };
    let total_wire_length = DNP3_HEADER_LEN + user_data_len + 2 * num_blocks;

    if raw.len() < total_wire_length {
        return Err(Dnp3ParseError::TruncatedPayload);
    }

    let header_expected_crc = u16::from_le_bytes([raw[8], raw[9]]);
    let header_calculated_crc = calculate_crc(&raw[0..DNP3_HEADER_DATA_LEN]);
    let header_crc_valid = header_expected_crc == header_calculated_crc;

    if validate_crc && !header_crc_valid {
        return Err(Dnp3ParseError::HeaderCrcFailure {
            expected: header_expected_crc,
            calculated: header_calculated_crc,
        });
    }

    let control = raw[3];
    let destination = u16::from_le_bytes([raw[4], raw[5]]);
    let source = u16::from_le_bytes([raw[6], raw[7]]);
    let direction = (control & 0x80) != 0;
    let is_primary = (control & 0x40) != 0;
    let fcb = (control & 0x20) != 0;
    let fcv = is_primary && ((control & 0x10) != 0);
    let dfc = !is_primary && ((control & 0x10) != 0);
    let control_function = control & 0x0F;

    let header = Dnp3LinkHeader {
        sync: [raw[0], raw[1]],
        length,
        control,
        destination,
        source,
        header_crc: header_expected_crc,
        direction,
        is_primary,
        fcb,
        fcv,
        dfc,
        control_function,
    };

    let mut user_data = Vec::with_capacity(user_data_len);
    let mut blocks = Vec::with_capacity(num_blocks);
    let mut offset = DNP3_HEADER_LEN;
    let mut remaining_user = user_data_len;
    let mut all_crc_valid = header_crc_valid;

    for block_idx in 0..num_blocks {
        let block_data_len = remaining_user.min(DNP3_BLOCK_SIZE);
        let block_data = &raw[offset..offset + block_data_len];
        offset += block_data_len;

        let block_expected_crc = u16::from_le_bytes([raw[offset], raw[offset + 1]]);
        offset += 2;

        let block_calculated_crc = calculate_crc(block_data);
        let block_crc_valid = block_expected_crc == block_calculated_crc;

        if validate_crc && !block_crc_valid {
            return Err(Dnp3ParseError::BlockCrcFailure {
                block_index: block_idx,
                expected: block_expected_crc,
                calculated: block_calculated_crc,
            });
        }

        if !block_crc_valid {
            all_crc_valid = false;
        }

        user_data.extend_from_slice(block_data);
        blocks.push(block_data.to_vec());
        remaining_user -= block_data_len;
    }

    let (transport, transport_fir, transport_fin, transport_sequence) = if !user_data.is_empty() {
        let th = Dnp3TransportHeader::from_octet(user_data[0]);
        (Some(th), Some(th.fir), Some(th.fin), Some(th.sequence))
    } else {
        (None, None, None, None)
    };

    let application_function = if user_data.len() >= 3 && transport_fir == Some(true) {
        Some(user_data[2])
    } else {
        None
    };

    let metadata = Dnp3Metadata {
        destination,
        source,
        is_primary,
        direction,
        control_function,
        transport_fir,
        transport_fin,
        transport_sequence,
        application_function,
        crc_valid: all_crc_valid,
    };

    Ok(Dnp3Frame {
        header,
        metadata,
        destination,
        source,
        control,
        control_function,
        is_primary,
        direction,
        length,
        header_crc: header_expected_crc,
        header_crc_valid,
        transport,
        transport_fir,
        transport_fin,
        transport_sequence,
        application_function,
        user_data,
        blocks,
        crc_valid: all_crc_valid,
        raw: raw[..total_wire_length].to_vec(),
    })
}

/// Parses a complete DNP3 LPDU frame from `raw` bytes (alias for [`parse_dnp3_frame`] with CRC validation).
pub fn parse_frame(raw: &[u8]) -> Result<Dnp3Frame, Dnp3ParseError> {
    parse_dnp3_frame(raw, true)
}

/// Alias for [`parse_frame`].
pub fn parse_dnp3(raw: &[u8]) -> Result<Dnp3Frame, Dnp3ParseError> {
    parse_dnp3_frame(raw, true)
}

/// Encodes a 10-octet FT3 header with computed CRC.
#[must_use]
pub fn encode_ft3_header(length: u8, control: u8, destination: u16, source: u16) -> [u8; 10] {
    let mut hdr = [0u8; 10];
    hdr[0] = DNP3_SYNC_0;
    hdr[1] = DNP3_SYNC_1;
    hdr[2] = length;
    hdr[3] = control;
    hdr[4..6].copy_from_slice(&destination.to_le_bytes());
    hdr[6..8].copy_from_slice(&source.to_le_bytes());
    let crc = calculate_crc(&hdr[0..DNP3_HEADER_DATA_LEN]);
    hdr[8..10].copy_from_slice(&crc.to_le_bytes());
    hdr
}

/// Encodes a complete DNP3 LPDU frame from link header fields and user data.
///
/// Automatically segments `user_data` into <=16-octet blocks, computes and appends
/// 16-bit CRCs for each block, and sets the Length field in the header.
#[must_use]
pub fn encode_dnp3_frame(control: u8, destination: u16, source: u16, user_data: &[u8]) -> Vec<u8> {
    assert!(
        user_data.len() <= 250,
        "DNP3 user data cannot exceed 250 octets"
    );
    let length = (DNP3_MIN_LENGTH as usize + user_data.len()) as u8;
    let hdr = encode_ft3_header(length, control, destination, source);
    let num_blocks = if user_data.is_empty() {
        0
    } else {
        user_data.len().div_ceil(DNP3_BLOCK_SIZE)
    };
    let mut frame = Vec::with_capacity(DNP3_HEADER_LEN + user_data.len() + 2 * num_blocks);
    frame.extend_from_slice(&hdr);

    for chunk in user_data.chunks(DNP3_BLOCK_SIZE) {
        frame.extend_from_slice(chunk);
        let block_crc = calculate_crc(chunk);
        frame.extend_from_slice(&block_crc.to_le_bytes());
    }

    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criterion1_parse_10_octet_ft3_header() {
        // Acceptance criterion 1:
        // In crates/rer/src/dnp3.rs, parsing a 10-octet FT3 header with sync octets 0x05 and 0x64,
        // length 5, control 0xC0, destination address 1, and source address 2 validates the
        // header CRC and extracts the link header fields.
        let raw_8 = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
        let crc = calculate_crc(&raw_8);

        let mut raw_10 = [0u8; 10];
        raw_10[..8].copy_from_slice(&raw_8);
        raw_10[8..10].copy_from_slice(&crc.to_le_bytes());

        let header = parse_ft3_header(&raw_10).expect("parsing valid FT3 header must succeed");
        assert_eq!(header.sync, [0x05, 0x64]);
        assert_eq!(header.length, 5);
        assert_eq!(header.control, 0xC0);
        assert_eq!(header.destination, 1);
        assert_eq!(header.source, 2);
        assert_eq!(header.header_crc, crc);
        assert!(header.is_primary);
        assert!(header.direction);
        assert_eq!(header.control_function, 0);

        // Also test through Dnp3LinkHeader::parse
        let h2 = Dnp3LinkHeader::parse(&raw_10).expect("parse via struct method");
        assert_eq!(h2, header);
    }

    #[test]
    fn test_criterion2_crc_calculation() {
        // Acceptance criterion 2:
        // In crates/rer/src/dnp3.rs, calculating the 16-bit CRC over an 8-octet header using
        // polynomial 0xA653 with inverted output produces the matching expected CRC value.
        let header = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
        let calculated = calculate_crc(&header);

        // Verify with bitwise algorithm independently
        let mut expected = 0x0000u16;
        for &byte in &header {
            expected ^= byte as u16;
            for _ in 0..8 {
                if (expected & 1) != 0 {
                    expected = (expected >> 1) ^ 0xA653;
                } else {
                    expected >>= 1;
                }
            }
        }
        expected = !expected;

        assert_eq!(calculated, expected);
        assert_eq!(dnp3_crc(&header), expected);
        assert_eq!(compute_crc(&header), expected);
    }

    #[test]
    fn test_criterion3_invalid_header_crc_returns_error() {
        // Acceptance criterion 3:
        // In crates/rer/src/dnp3.rs, parsing a frame with an invalid header CRC returns an error
        // indicating CRC verification failure.
        let raw_8 = [0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x02, 0x00];
        let valid_crc = calculate_crc(&raw_8);

        let mut invalid_frame = [0u8; 10];
        invalid_frame[..8].copy_from_slice(&raw_8);
        invalid_frame[8..10].copy_from_slice(&(valid_crc ^ 0xFFFF).to_le_bytes());

        let err = parse_ft3_header(&invalid_frame).unwrap_err();
        assert!(err.is_crc_failure());
        assert!(err.to_string().contains("CRC verification failure"));

        let frame_err = parse_dnp3_frame(&invalid_frame, true).unwrap_err();
        assert!(frame_err.is_crc_failure());
        assert!(frame_err.to_string().contains("CRC verification failure"));
    }

    #[test]
    fn test_criterion4_transport_control_parsing() {
        // Acceptance criterion 4:
        // In crates/rer/src/dnp3.rs, parsing an FT3 user data block containing transport control
        // octet 0xC0 extracts first segment flag FIR, final segment flag FIN, and transport sequence number 0.
        let user_data_block = [0xC0, 0x01, 0x02];
        let parsed = parse_user_data_block(&user_data_block).expect("parse user data block");
        assert!(parsed.fir);
        assert!(parsed.fin);
        assert_eq!(parsed.sequence, 0);
        assert_eq!(parsed.sequence_number, 0);

        // Also test directly via parse_transport_control
        let transport = parse_transport_control(0xC0);
        assert!(transport.fir);
        assert!(transport.fin);
        assert_eq!(transport.sequence, 0);
        assert_eq!(transport.sequence_number, 0);

        // Also test through parse_transport_header
        let th = parse_transport_header(&user_data_block).expect("parse transport header");
        assert!(th.fir);
        assert!(th.fin);
        assert_eq!(th.sequence, 0);
        assert_eq!(th.sequence_number, 0);
    }
}
