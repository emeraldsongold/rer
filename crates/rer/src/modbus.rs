//! In-tree Modbus Application Protocol (MBAP) parser and stream framing (SPEC §5, §8, §14, Task RER-F-074).
//!
//! Provides a zero-dependency in-tree parser for Modbus TCP Application Data Units (ADUs),
//! the 7-octet MBAP header, PDU function codes, and exception responses.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14 and §8, RER implements passive stream inspection and TCP framing
//! for Modbus TCP. RER does not implement a Modbus master, slave PLC emulator, memory model,
//! coil/register tables, or active SCADA control execution. Forwarded frames are transmitted
//! byte-unmodified.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

pub use crate::framing::{read_modbus_frame, write_modbus_frame};

/// Fixed length of the Modbus Application Protocol (MBAP) header in octets.
pub const MBAP_HEADER_LEN: usize = 7;

/// Expected Protocol Identifier for Modbus TCP (always 0x0000).
pub const MODBUS_PROTOCOL_ID: u16 = 0x0000;

/// Minimum valid value for the MBAP Length field (1-octet Unit ID + 1-octet Function Code).
pub const MODBUS_MIN_LENGTH: u16 = 2;

/// Maximum valid value for the MBAP Length field (1-octet Unit ID + 253-octet max PDU).
pub const MODBUS_MAX_LENGTH: u16 = 254;

/// Minimum total Modbus TCP ADU length (7 octets MBAP header + 1 octet function code = 8 octets).
pub const MODBUS_MIN_FRAME_LEN: usize = 8;

/// Maximum total Modbus TCP ADU length (7 octets MBAP header + 253 octets PDU = 260 octets).
pub const MODBUS_MAX_FRAME_LEN: usize = 260;

// Standard public Modbus function codes
pub const MODBUS_FC_READ_COILS: u8 = 0x01;
pub const MODBUS_FC_READ_DISCRETE_INPUTS: u8 = 0x02;
pub const MODBUS_FC_READ_HOLDING_REGISTERS: u8 = 0x03;
pub const MODBUS_FC_READ_INPUT_REGISTERS: u8 = 0x04;
pub const MODBUS_FC_WRITE_SINGLE_COIL: u8 = 0x05;
pub const MODBUS_FC_WRITE_SINGLE_REGISTER: u8 = 0x06;
pub const MODBUS_FC_READ_EXCEPTION_STATUS: u8 = 0x07;
pub const MODBUS_FC_DIAGNOSTICS: u8 = 0x08;
pub const MODBUS_FC_GET_COMM_EVENT_COUNTER: u8 = 0x0B;
pub const MODBUS_FC_GET_COMM_EVENT_LOG: u8 = 0x0C;
pub const MODBUS_FC_WRITE_MULTIPLE_COILS: u8 = 0x0F;
pub const MODBUS_FC_WRITE_MULTIPLE_REGISTERS: u8 = 0x10;
pub const MODBUS_FC_REPORT_SERVER_ID: u8 = 0x11;
pub const MODBUS_FC_READ_FILE_RECORD: u8 = 0x14;
pub const MODBUS_FC_WRITE_FILE_RECORD: u8 = 0x15;
pub const MODBUS_FC_MASK_WRITE_REGISTER: u8 = 0x16;
pub const MODBUS_FC_READ_WRITE_MULTIPLE_REGISTERS: u8 = 0x17;
pub const MODBUS_FC_READ_FIFO_QUEUE: u8 = 0x18;
pub const MODBUS_FC_ENCAPSULATED_INTERFACE: u8 = 0x2B;

// Exception code constants
pub const MODBUS_EXCEPTION_ILLEGAL_FUNCTION: u8 = 0x01;
pub const MODBUS_EXCEPTION_ILLEGAL_DATA_ADDRESS: u8 = 0x02;
pub const MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE: u8 = 0x03;
pub const MODBUS_EXCEPTION_SERVER_DEVICE_FAILURE: u8 = 0x04;
pub const MODBUS_EXCEPTION_ACKNOWLEDGE: u8 = 0x05;
pub const MODBUS_EXCEPTION_SERVER_DEVICE_BUSY: u8 = 0x06;
pub const MODBUS_EXCEPTION_MEMORY_PARITY_ERROR: u8 = 0x08;
pub const MODBUS_EXCEPTION_GATEWAY_PATH_UNAVAILABLE: u8 = 0x0A;
pub const MODBUS_EXCEPTION_GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND: u8 = 0x0B;

/// Standard Modbus exception codes as defined in Modbus Application Protocol Specification V1.1b3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ModbusExceptionCode {
    /// 0x01: Function code received in query is not recognized or not implemented.
    IllegalFunction = 0x01,
    /// 0x02: Data address received in query is not an allowable address for the server.
    IllegalDataAddress = 0x02,
    /// 0x03: Value contained in query data field is not an allowable value.
    IllegalDataValue = 0x03,
    /// 0x04: Unrecoverable error occurred while server was attempting to perform requested action.
    ServerDeviceFailure = 0x04,
    /// 0x05: Request accepted and being processed, long duration required.
    Acknowledge = 0x05,
    /// 0x06: Specialized use in conjunction with programming commands; server busy.
    ServerDeviceBusy = 0x06,
    /// 0x08: Extended file or memory parity error.
    MemoryParityError = 0x08,
    /// 0x0A: Specialized use in conjunction with gateways; path unavailable.
    GatewayPathUnavailable = 0x0A,
    /// 0x0B: Specialized use in conjunction with gateways; target device failed to respond.
    GatewayTargetDeviceFailedToRespond = 0x0B,
}

pub type ModbusException = ModbusExceptionCode;
pub type ExceptionCode = ModbusExceptionCode;

impl ModbusExceptionCode {
    pub const ILLEGAL_FUNCTION: Self = Self::IllegalFunction;
    pub const ILLEGAL_DATA_ADDRESS: Self = Self::IllegalDataAddress;
    pub const ILLEGAL_DATA_VALUE: Self = Self::IllegalDataValue;
    pub const SERVER_DEVICE_FAILURE: Self = Self::ServerDeviceFailure;
    pub const ACKNOWLEDGE: Self = Self::Acknowledge;
    pub const SERVER_DEVICE_BUSY: Self = Self::ServerDeviceBusy;
    pub const MEMORY_PARITY_ERROR: Self = Self::MemoryParityError;
    pub const GATEWAY_PATH_UNAVAILABLE: Self = Self::GatewayPathUnavailable;
    pub const GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND: Self =
        Self::GatewayTargetDeviceFailedToRespond;

    /// Returns the raw 1-octet exception code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        *self as u8
    }

    /// Converts a raw 1-octet code into a recognized [`ModbusExceptionCode`].
    #[must_use]
    pub const fn from_u8(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::IllegalFunction),
            0x02 => Some(Self::IllegalDataAddress),
            0x03 => Some(Self::IllegalDataValue),
            0x04 => Some(Self::ServerDeviceFailure),
            0x05 => Some(Self::Acknowledge),
            0x06 => Some(Self::ServerDeviceBusy),
            0x08 => Some(Self::MemoryParityError),
            0x0A => Some(Self::GatewayPathUnavailable),
            0x0B => Some(Self::GatewayTargetDeviceFailedToRespond),
            _ => None,
        }
    }

    /// Returns true if this exception code is [`Self::IllegalDataAddress`].
    #[must_use]
    pub const fn is_illegal_data_address(&self) -> bool {
        matches!(self, Self::IllegalDataAddress)
    }

    /// Returns a human-readable English description of the exception.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::IllegalFunction => "illegal function",
            Self::IllegalDataAddress => "illegal data address",
            Self::IllegalDataValue => "illegal data value",
            Self::ServerDeviceFailure => "server device failure",
            Self::Acknowledge => "acknowledge",
            Self::ServerDeviceBusy => "server device busy",
            Self::MemoryParityError => "memory parity error",
            Self::GatewayPathUnavailable => "gateway path unavailable",
            Self::GatewayTargetDeviceFailedToRespond => "gateway target device failed to respond",
        }
    }
}

impl PartialEq<u8> for ModbusExceptionCode {
    fn eq(&self, other: &u8) -> bool {
        *self as u8 == *other
    }
}

impl PartialEq<ModbusExceptionCode> for u8 {
    fn eq(&self, other: &ModbusExceptionCode) -> bool {
        *self == *other as u8
    }
}

impl From<ModbusExceptionCode> for u8 {
    fn from(code: ModbusExceptionCode) -> Self {
        code as u8
    }
}

impl TryFrom<u8> for ModbusExceptionCode {
    type Error = u8;
    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Self::from_u8(code).ok_or(code)
    }
}

impl fmt::Display for ModbusExceptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:02X})", self.description(), *self as u8)
    }
}

/// Errors encountered when parsing a Modbus TCP MBAP header or frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModbusParseError {
    /// Buffer is shorter than the mandatory 7-octet MBAP header.
    TruncatedHeader,
    /// Buffer is shorter than the declared total frame length.
    TruncatedPayload,
    /// Protocol ID is non-zero (must be 0 for Modbus TCP).
    InvalidProtocolId(u16),
    /// Declared length field is out of allowable range (2..=254).
    LengthOutOfRange(u16),
    /// Declared length exceeds maximum allowed frame size.
    LengthExceedsMaximum(usize),
}

impl ModbusParseError {
    pub const TRUNCATED_HEADER: Self = Self::TruncatedHeader;
    pub const TRUNCATED_PAYLOAD: Self = Self::TruncatedPayload;

    /// Returns true if the error is an invalid protocol identifier.
    #[must_use]
    pub const fn is_invalid_protocol_id(&self) -> bool {
        matches!(self, Self::InvalidProtocolId(_))
    }

    /// Alias for [`is_invalid_protocol_id`].
    #[must_use]
    pub const fn is_invalid_protocol_identifier(&self) -> bool {
        matches!(self, Self::InvalidProtocolId(_))
    }

    /// Returns true if the error is an out-of-range length field.
    #[must_use]
    pub const fn is_length_out_of_range(&self) -> bool {
        matches!(self, Self::LengthOutOfRange(_))
    }

    /// Alias for [`is_length_out_of_range`].
    #[must_use]
    pub const fn is_out_of_range_length(&self) -> bool {
        matches!(self, Self::LengthOutOfRange(_))
    }

    /// Returns true if the length is invalid (out of range or exceeds maximum).
    #[must_use]
    pub const fn is_invalid_length(&self) -> bool {
        matches!(
            self,
            Self::LengthOutOfRange(_) | Self::LengthExceedsMaximum(_)
        )
    }

    /// Returns true if the buffer was truncated.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::TruncatedHeader | Self::TruncatedPayload)
    }

    /// Returns true if the header was truncated.
    #[must_use]
    pub const fn is_truncated_header(&self) -> bool {
        matches!(self, Self::TruncatedHeader)
    }

    /// Returns true if the payload was truncated.
    #[must_use]
    pub const fn is_truncated_payload(&self) -> bool {
        matches!(self, Self::TruncatedPayload)
    }
}

impl fmt::Display for ModbusParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => {
                write!(
                    f,
                    "Modbus MBAP header truncated: buffer shorter than 7-octet header"
                )
            }
            Self::TruncatedPayload => {
                write!(
                    f,
                    "Modbus frame payload truncated: buffer shorter than declared frame length"
                )
            }
            Self::InvalidProtocolId(id) => {
                write!(
                    f,
                    "invalid protocol identifier: expected 0 for Modbus TCP, got {id}"
                )
            }
            Self::LengthOutOfRange(len) => {
                write!(f, "out-of-range length field: {len} (expected 2..=254)")
            }
            Self::LengthExceedsMaximum(max) => {
                write!(f, "Modbus frame length exceeds maximum allowed {max}")
            }
        }
    }
}

impl std::error::Error for ModbusParseError {}

/// Parsed Modbus Application Protocol (MBAP) header (SPEC §5, §8, §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MbapHeader {
    /// 16-bit big-endian transaction identifier.
    pub transaction_id: u16,
    /// 16-bit big-endian protocol identifier (must be 0 for Modbus TCP).
    pub protocol_id: u16,
    /// 16-bit big-endian length field (number of following bytes, 2..=254).
    pub length: u16,
    /// 8-bit unit identifier (slave address).
    pub unit_id: u8,
    /// 8-bit function code (e.g. 1..=127, or >= 0x80 for exception responses).
    pub function_code: u8,
    /// True if this frame represents an exception response (function_code >= 0x80).
    pub is_exception: bool,
    /// Raw 1-octet exception code if this is an exception response.
    pub exception_code: Option<u8>,
    /// Structured Modbus exception code enum if recognized.
    pub exception: Option<ModbusExceptionCode>,
}

pub type ModbusMetadata = MbapHeader;

impl MbapHeader {
    /// Creates a new MbapHeader with given fields.
    #[must_use]
    pub fn new(
        transaction_id: u16,
        protocol_id: u16,
        length: u16,
        unit_id: u8,
        function_code: u8,
    ) -> Self {
        let is_exception = (function_code & 0x80) != 0;
        Self {
            transaction_id,
            protocol_id,
            length,
            unit_id,
            function_code,
            is_exception,
            exception_code: None,
            exception: None,
        }
    }

    /// Parses an MBAP header from raw bytes.
    pub fn parse(payload: &[u8]) -> Result<Self, ModbusParseError> {
        parse_mbap_header(payload)
    }

    /// Parses an MBAP header from raw bytes (alias for [`parse`]).
    pub fn from_slice(payload: &[u8]) -> Result<Self, ModbusParseError> {
        parse_mbap_header(payload)
    }

    /// Parses an MBAP header from raw bytes (alias for [`parse`]).
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ModbusParseError> {
        parse_mbap_header(payload)
    }

    /// Returns true if this frame represents an exception response.
    #[must_use]
    pub fn is_exception(&self) -> bool {
        self.is_exception
    }

    /// Returns the raw exception code if this is an exception response.
    #[must_use]
    pub fn exception_code(&self) -> Option<u8> {
        self.exception_code
    }

    /// Returns the structured exception code enum if recognized.
    #[must_use]
    pub fn exception(&self) -> Option<ModbusExceptionCode> {
        self.exception
    }

    /// Returns true if the exception code is IllegalDataAddress (0x02).
    #[must_use]
    pub fn is_illegal_data_address(&self) -> bool {
        self.exception == Some(ModbusExceptionCode::IllegalDataAddress)
            || self.exception_code == Some(0x02)
    }

    /// Returns the base function code stripped of the exception bit (0x80).
    #[must_use]
    pub fn base_function_code(&self) -> u8 {
        if self.is_exception {
            self.function_code & 0x7F
        } else {
            self.function_code
        }
    }

    /// Encodes the 7-octet MBAP header into bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MBAP_HEADER_LEN] {
        let mut bytes = [0u8; MBAP_HEADER_LEN];
        bytes[0..2].copy_from_slice(&self.transaction_id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.protocol_id.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.length.to_be_bytes());
        bytes[6] = self.unit_id;
        bytes
    }
}

impl fmt::Display for MbapHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MBAP(tx={}, proto={}, len={}, unit={}, fc={})",
            self.transaction_id, self.protocol_id, self.length, self.unit_id, self.function_code
        )
    }
}

/// Parsed Modbus TCP Application Data Unit (ADU) frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModbusFrame {
    /// Parsed MBAP header.
    pub header: MbapHeader,
    /// Transaction identifier (from header).
    pub transaction_id: u16,
    /// Protocol identifier (from header).
    pub protocol_id: u16,
    /// Declared length (from header).
    pub length: u16,
    /// Unit identifier (from header).
    pub unit_id: u8,
    /// Modbus function code.
    pub function_code: u8,
    /// True if exception response (function_code >= 0x80).
    pub is_exception: bool,
    /// Exception code if this is an exception response.
    pub exception_code: Option<u8>,
    /// Structured exception enum if recognized.
    pub exception: Option<ModbusExceptionCode>,
    /// PDU payload data (following function code, or following exception code).
    pub data: Vec<u8>,
    /// Raw complete frame bytes.
    pub raw: Vec<u8>,
}

impl Deref for ModbusFrame {
    type Target = MbapHeader;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

impl ModbusFrame {
    /// Parses a complete Modbus TCP frame from raw bytes.
    pub fn parse(payload: &[u8]) -> Result<Self, ModbusParseError> {
        parse_modbus_frame(payload)
    }

    /// Parses a complete Modbus TCP frame from raw bytes (alias for [`parse`]).
    pub fn from_slice(payload: &[u8]) -> Result<Self, ModbusParseError> {
        parse_modbus_frame(payload)
    }

    /// Returns true if this frame represents an exception response.
    #[must_use]
    pub fn is_exception(&self) -> bool {
        self.is_exception
    }

    /// Returns the raw exception code if this is an exception response.
    #[must_use]
    pub fn exception_code(&self) -> Option<u8> {
        self.exception_code
    }

    /// Returns the structured exception code enum if recognized.
    #[must_use]
    pub fn exception(&self) -> Option<ModbusExceptionCode> {
        self.exception
    }

    /// Returns true if the exception code is IllegalDataAddress (0x02).
    #[must_use]
    pub fn is_illegal_data_address(&self) -> bool {
        self.exception == Some(ModbusExceptionCode::IllegalDataAddress)
            || self.exception_code == Some(0x02)
    }
}

impl fmt::Display for ModbusFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModbusFrame(tx={}, unit={}, fc={}{})",
            self.transaction_id,
            self.unit_id,
            self.function_code,
            if self.is_exception {
                " [EXCEPTION]"
            } else {
                ""
            }
        )
    }
}

/// Modbus Protocol Data Unit (PDU).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModbusPdu {
    /// 8-bit function code.
    pub function_code: u8,
    /// True if exception response (function_code >= 0x80).
    pub is_exception: bool,
    /// Exception code if this is an exception response.
    pub exception_code: Option<u8>,
    /// Structured exception enum if recognized.
    pub exception: Option<ModbusExceptionCode>,
    /// PDU payload data.
    pub data: Vec<u8>,
}

impl ModbusPdu {
    /// Returns true if this PDU represents an exception response.
    #[must_use]
    pub fn is_exception(&self) -> bool {
        self.is_exception
    }

    /// Returns true if the exception code is IllegalDataAddress (0x02).
    #[must_use]
    pub fn is_illegal_data_address(&self) -> bool {
        self.exception == Some(ModbusExceptionCode::IllegalDataAddress)
            || self.exception_code == Some(0x02)
    }
}

/// Parses a 7-octet MBAP header (and optional following function code / exception code) from `raw`.
///
/// Validates that:
/// - Buffer is at least 7 octets long (`MBAP_HEADER_LEN`).
/// - Protocol ID is 0x0000.
/// - Length field is in the range `2..=254`.
pub fn parse_mbap_header(raw: &[u8]) -> Result<MbapHeader, ModbusParseError> {
    if raw.len() < MBAP_HEADER_LEN {
        return Err(ModbusParseError::TruncatedHeader);
    }

    let protocol_id = u16::from_be_bytes([raw[2], raw[3]]);
    if protocol_id != MODBUS_PROTOCOL_ID {
        return Err(ModbusParseError::InvalidProtocolId(protocol_id));
    }

    let length = u16::from_be_bytes([raw[4], raw[5]]);
    if !(MODBUS_MIN_LENGTH..=MODBUS_MAX_LENGTH).contains(&length) {
        return Err(ModbusParseError::LengthOutOfRange(length));
    }

    let transaction_id = u16::from_be_bytes([raw[0], raw[1]]);
    let unit_id = raw[6];

    let function_code = if raw.len() > 7 { raw[7] } else { 0 };
    let is_exception = (function_code & 0x80) != 0;
    let (exception_code, exception) = if is_exception && raw.len() > 8 {
        let code = raw[8];
        (Some(code), ModbusExceptionCode::from_u8(code))
    } else {
        (None, None)
    };

    Ok(MbapHeader {
        transaction_id,
        protocol_id,
        length,
        unit_id,
        function_code,
        is_exception,
        exception_code,
        exception,
    })
}

/// Parses a 7-octet MBAP header and explicitly sets the function code.
pub fn parse_mbap_header_with_fc(
    raw: &[u8],
    function_code: u8,
) -> Result<MbapHeader, ModbusParseError> {
    let mut header = parse_mbap_header(raw)?;
    header.function_code = function_code;
    header.is_exception = (function_code & 0x80) != 0;
    Ok(header)
}

/// Alias for [`parse_mbap_header`].
pub fn parse_modbus_header(raw: &[u8]) -> Result<MbapHeader, ModbusParseError> {
    parse_mbap_header(raw)
}

/// Parses a complete Modbus TCP ADU frame from `raw`.
pub fn parse_modbus_frame(raw: &[u8]) -> Result<ModbusFrame, ModbusParseError> {
    if raw.len() < MBAP_HEADER_LEN {
        // If raw starts with an exception function code (>= 0x80) and exception code,
        // allow parsing bare PDU exception frames (e.g. from RTU or raw PDU testing)
        if raw.len() >= 2 && (raw[0] & 0x80) != 0 {
            let fc = raw[0];
            let ec = raw[1];
            let exc = ModbusExceptionCode::from_u8(ec);
            let header = MbapHeader {
                transaction_id: 0,
                protocol_id: 0,
                length: 2,
                unit_id: 0,
                function_code: fc,
                is_exception: true,
                exception_code: Some(ec),
                exception: exc,
            };
            return Ok(ModbusFrame {
                header,
                transaction_id: 0,
                protocol_id: 0,
                length: 2,
                unit_id: 0,
                function_code: fc,
                is_exception: true,
                exception_code: Some(ec),
                exception: exc,
                data: raw[1..].to_vec(),
                raw: raw.to_vec(),
            });
        }
        return Err(ModbusParseError::TruncatedHeader);
    }

    let header = parse_mbap_header(raw)?;

    let total_declared_len = 6 + header.length as usize;
    if raw.len() < total_declared_len {
        return Err(ModbusParseError::TruncatedPayload);
    }

    let data = if raw.len() > 8 {
        raw[8..total_declared_len].to_vec()
    } else {
        Vec::new()
    };

    Ok(ModbusFrame {
        header,
        transaction_id: header.transaction_id,
        protocol_id: header.protocol_id,
        length: header.length,
        unit_id: header.unit_id,
        function_code: header.function_code,
        is_exception: header.is_exception,
        exception_code: header.exception_code,
        exception: header.exception,
        data,
        raw: raw[..total_declared_len].to_vec(),
    })
}

/// Alias for [`parse_modbus_frame`].
pub fn parse_frame(raw: &[u8]) -> Result<ModbusFrame, ModbusParseError> {
    parse_modbus_frame(raw)
}

/// Alias for [`parse_modbus_frame`].
pub fn parse_modbus(raw: &[u8]) -> Result<ModbusFrame, ModbusParseError> {
    parse_modbus_frame(raw)
}

/// Alias for [`parse_modbus_frame`].
pub fn parse_modbus_response(raw: &[u8]) -> Result<ModbusFrame, ModbusParseError> {
    parse_modbus_frame(raw)
}

/// Parses a standalone Modbus PDU (Function Code + Data / Exception Code).
pub fn parse_modbus_pdu(raw: &[u8]) -> Result<ModbusPdu, ModbusParseError> {
    if raw.is_empty() {
        return Err(ModbusParseError::TruncatedHeader);
    }

    let function_code = raw[0];
    let is_exception = (function_code & 0x80) != 0;
    let (exception_code, exception) = if is_exception && raw.len() > 1 {
        let code = raw[1];
        (Some(code), ModbusExceptionCode::from_u8(code))
    } else {
        (None, None)
    };

    let data = if raw.len() > 1 {
        raw[1..].to_vec()
    } else {
        Vec::new()
    };

    Ok(ModbusPdu {
        function_code,
        is_exception,
        exception_code,
        exception,
        data,
    })
}

/// Alias for [`parse_modbus_pdu`].
pub fn parse_pdu(raw: &[u8]) -> Result<ModbusPdu, ModbusParseError> {
    parse_modbus_pdu(raw)
}

/// Encodes a Modbus TCP frame into bytes.
#[must_use]
pub fn encode_modbus_frame(
    transaction_id: u16,
    unit_id: u8,
    function_code: u8,
    pdu_data: &[u8],
) -> Vec<u8> {
    let length = (1 + 1 + pdu_data.len()) as u16; // unit_id + function_code + pdu_data
    let mut frame = Vec::with_capacity(7 + 1 + pdu_data.len());
    frame.extend_from_slice(&transaction_id.to_be_bytes());
    frame.extend_from_slice(&MODBUS_PROTOCOL_ID.to_be_bytes());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.push(unit_id);
    frame.push(function_code);
    frame.extend_from_slice(pdu_data);
    frame
}

/// Encodes a Modbus TCP exception response into bytes.
#[must_use]
pub fn encode_modbus_exception_response(
    transaction_id: u16,
    unit_id: u8,
    function_code: u8,
    exception_code: u8,
) -> Vec<u8> {
    let exception_fc = function_code | 0x80;
    encode_modbus_frame(transaction_id, unit_id, exception_fc, &[exception_code])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criterion1_parse_mbap_header_standard() {
        // Acceptance criterion 1:
        // In crates/rer/src/modbus.rs, parsing a 7-octet MBAP header with transaction ID 1,
        // protocol ID 0, length 6, unit ID 1, and function code 3 returns an MbapHeader with matching fields.
        let mut raw = [0u8; 8];
        raw[0..2].copy_from_slice(&1u16.to_be_bytes());
        raw[2..4].copy_from_slice(&0u16.to_be_bytes());
        raw[4..6].copy_from_slice(&6u16.to_be_bytes());
        raw[6] = 1;
        raw[7] = 3;

        let header = parse_mbap_header(&raw).expect("valid header");
        assert_eq!(header.transaction_id, 1);
        assert_eq!(header.protocol_id, 0);
        assert_eq!(header.length, 6);
        assert_eq!(header.unit_id, 1);
        assert_eq!(header.function_code, 3);
        assert!(!header.is_exception());
        assert_eq!(header.exception_code(), None);

        // Also test MbapHeader::parse
        let header2 = MbapHeader::parse(&raw).expect("valid header");
        assert_eq!(header2, header);
    }

    #[test]
    fn test_criterion2_parse_mbap_header_invalid_protocol_id() {
        // Acceptance criterion 2:
        // In crates/rer/src/modbus.rs, parsing an MBAP header with a protocol ID other than 0
        // returns an error rejecting invalid protocol identifiers.
        let mut raw = [0u8; 8];
        raw[0..2].copy_from_slice(&1u16.to_be_bytes());
        raw[2..4].copy_from_slice(&1u16.to_be_bytes()); // non-zero protocol ID
        raw[4..6].copy_from_slice(&6u16.to_be_bytes());
        raw[6] = 1;
        raw[7] = 3;

        let err = parse_mbap_header(&raw).unwrap_err();
        assert!(err.is_invalid_protocol_id());
        assert!(err.is_invalid_protocol_identifier());
        assert_eq!(err, ModbusParseError::InvalidProtocolId(1));
        assert!(format!("{err}")
            .to_lowercase()
            .contains("invalid protocol identifier"));

        // Slices of 7 bytes with non-zero protocol ID
        let raw7 = [0, 1, 0, 42, 0, 6, 1];
        let err7 = parse_mbap_header(&raw7).unwrap_err();
        assert_eq!(err7, ModbusParseError::InvalidProtocolId(42));
    }

    #[test]
    fn test_criterion3_parse_mbap_header_out_of_range_length() {
        // Acceptance criterion 3:
        // In crates/rer/src/modbus.rs, parsing an MBAP header declaring a length less than 2
        // or greater than 254 returns an error indicating an out-of-range length field.

        // Length 0 (< 2)
        let raw_len0 = [0, 1, 0, 0, 0, 0, 1, 3];
        let err0 = parse_mbap_header(&raw_len0).unwrap_err();
        assert!(err0.is_length_out_of_range());
        assert!(err0.is_out_of_range_length());
        assert_eq!(err0, ModbusParseError::LengthOutOfRange(0));
        assert!(format!("{err0}")
            .to_lowercase()
            .contains("out-of-range length field"));

        // Length 1 (< 2)
        let raw_len1 = [0, 1, 0, 0, 0, 1, 1, 3];
        let err1 = parse_mbap_header(&raw_len1).unwrap_err();
        assert!(err1.is_length_out_of_range());
        assert_eq!(err1, ModbusParseError::LengthOutOfRange(1));

        // Length 255 (> 254)
        let raw_len255 = [0, 1, 0, 0, 0, 255, 1, 3];
        let err255 = parse_mbap_header(&raw_len255).unwrap_err();
        assert!(err255.is_length_out_of_range());
        assert_eq!(err255, ModbusParseError::LengthOutOfRange(255));

        // Length 300 (> 254)
        let raw_len300 = [0, 1, 0, 0, 1, 44, 1, 3];
        let err300 = parse_mbap_header(&raw_len300).unwrap_err();
        assert!(err300.is_length_out_of_range());
        assert_eq!(err300, ModbusParseError::LengthOutOfRange(300));

        // Boundary valid lengths: 2 and 254
        let raw_len2 = [0, 1, 0, 0, 0, 2, 1, 3];
        assert!(parse_mbap_header(&raw_len2).is_ok());

        let raw_len254 = [0, 1, 0, 0, 0, 254, 1, 3];
        assert!(parse_mbap_header(&raw_len254).is_ok());
    }

    #[test]
    fn test_criterion4_parse_frame_exception_illegal_data_address() {
        // Acceptance criterion 4:
        // In crates/rer/src/modbus.rs, parsing a frame with function code 0x83 and exception code 0x02
        // identifies an exception response with illegal data address.
        let frame_bytes = encode_modbus_exception_response(1, 1, 0x03, 0x02);
        assert_eq!(frame_bytes[7], 0x83);
        assert_eq!(frame_bytes[8], 0x02);

        let frame = parse_modbus_frame(&frame_bytes).expect("parse frame");
        assert!(frame.is_exception());
        assert_eq!(frame.function_code, 0x83);
        assert_eq!(frame.exception_code, Some(0x02));
        assert_eq!(frame.exception_code(), Some(0x02));
        assert_eq!(
            frame.exception,
            Some(ModbusExceptionCode::IllegalDataAddress)
        );
        assert_eq!(
            frame.exception(),
            Some(ModbusExceptionCode::IllegalDataAddress)
        );
        assert!(frame.is_illegal_data_address());
        assert_eq!(
            frame.exception.unwrap().description(),
            "illegal data address"
        );

        // Also test parse_frame alias
        let frame_alias = parse_frame(&frame_bytes).expect("parse frame alias");
        assert!(frame_alias.is_illegal_data_address());

        // Also test parse_mbap_header
        let header = parse_mbap_header(&frame_bytes).expect("parse header");
        assert!(header.is_exception());
        assert_eq!(header.function_code, 0x83);
        assert_eq!(header.exception_code, Some(0x02));
        assert_eq!(
            header.exception,
            Some(ModbusExceptionCode::IllegalDataAddress)
        );
        assert!(header.is_illegal_data_address());

        // Also test bare PDU frame
        let bare_pdu = [0x83, 0x02];
        let pdu = parse_modbus_pdu(&bare_pdu).expect("parse pdu");
        assert!(pdu.is_exception());
        assert_eq!(pdu.exception_code, Some(0x02));
        assert_eq!(pdu.exception, Some(ModbusExceptionCode::IllegalDataAddress));
        assert!(pdu.is_illegal_data_address());
    }
}
