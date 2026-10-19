//! Bundle Protocol Version 7 (BPv7) CBOR Primary Block Parser (SPEC §14, §8, RFC 9171).
//!
//! Provides a zero-dependency in-tree CBOR scanner and parser for BPv7 primary bundle blocks
//! as defined in RFC 9171.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14, RER provides passive metadata inspection of BPv7 bundle headers.
//! RER does NOT implement a Bundle Processing Agent (BPA), bundle storage engine, routing tables,
//! Bundle Protocol Security (BPSec, RFC 9172), or TCPCLv4 convergence layer framing (RFC 9174).
//! Forwarded bundles are transmitted unmodified.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Bundle processing control flag: bundle is a fragment.
pub const BUNDLE_IS_FRAGMENT: u64 = 0x0000_0001;
/// Bundle processing control flag: payload is an administrative record.
pub const BUNDLE_PAYLOAD_IS_ADMIN_RECORD: u64 = 0x0000_0002;
/// Bundle processing control flag: bundle must not be fragmented.
pub const BUNDLE_MUST_NOT_BE_FRAGMENTED: u64 = 0x0000_0004;
/// Bundle processing control flag: status time requested in all reports.
pub const BUNDLE_STATUS_TIME_REQUESTED: u64 = 0x0000_0040;
/// Bundle processing control flag: request reporting of bundle reception.
pub const BUNDLE_STATUS_REPORT_RECEPTION: u64 = 0x0000_4000;
/// Bundle processing control flag: request reporting of bundle forwarding.
pub const BUNDLE_STATUS_REPORT_FORWARDING: u64 = 0x0000_8000;
/// Bundle processing control flag: request reporting of bundle delivery.
pub const BUNDLE_STATUS_REPORT_DELIVERY: u64 = 0x0001_0000;
/// Bundle processing control flag: request reporting of bundle deletion.
pub const BUNDLE_STATUS_REPORT_DELETION: u64 = 0x0002_0000;

/// Expected Bundle Protocol version for BPv7.
pub const BP_VERSION_7: u64 = 7;

/// CRC type code specified in RFC 9171 §4.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum CrcType {
    /// No CRC is present (code 0).
    #[default]
    None = 0,
    /// 16-bit CRC (CRC-16/X-25, code 1).
    Crc16 = 1,
    /// 32-bit CRC (CRC-32C Castagnoli, code 2).
    Crc32 = 2,
}

impl CrcType {
    /// Parses a CRC type code from an unsigned integer.
    ///
    /// # Errors
    /// Returns [`Bpv7ParseError::InvalidBlock`] if the CRC code is unknown.
    pub fn from_u64(val: u64) -> Result<Self, Bpv7ParseError> {
        match val {
            0 => Ok(Self::None),
            1 => Ok(Self::Crc16),
            2 => Ok(Self::Crc32),
            other => Err(Bpv7ParseError::InvalidBlock(format!(
                "unsupported CRC type: {other}"
            ))),
        }
    }

    /// Returns the expected byte length of the CRC field value.
    #[must_use]
    pub const fn expected_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Crc16 => 2,
            Self::Crc32 => 4,
        }
    }

    /// Returns the raw integer code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        *self as u8
    }
}

/// Endpoint Identifier scheme identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EndpointScheme {
    /// DTN URI scheme (`dtn:`, code 1).
    Dtn,
    /// IPN URI scheme (`ipn:`, code 2).
    Ipn,
    /// Other scheme code.
    Other(u64),
}

impl EndpointScheme {
    /// Returns the RFC 9171 scheme code.
    #[must_use]
    pub const fn code(&self) -> u64 {
        match self {
            Self::Dtn => 1,
            Self::Ipn => 2,
            Self::Other(c) => *c,
        }
    }
}

/// A decoded BPv7 Endpoint Identifier (EID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EndpointId {
    uri: String,
    scheme: EndpointScheme,
}

impl EndpointId {
    /// Creates the null endpoint identifier (`dtn:none`).
    #[must_use]
    pub fn dtn_none() -> Self {
        Self {
            uri: "dtn:none".to_string(),
            scheme: EndpointScheme::Dtn,
        }
    }

    /// Creates a `dtn:` scheme endpoint identifier with the given SSP.
    #[must_use]
    pub fn dtn(ssp: &str) -> Self {
        let trimmed = ssp.trim();
        let uri = if trimmed == "none" || trimmed.is_empty() {
            "dtn:none".to_string()
        } else if let Some(stripped) = trimmed.strip_prefix("dtn:") {
            if stripped == "none" {
                "dtn:none".to_string()
            } else if stripped.starts_with("//") {
                format!("dtn:{stripped}")
            } else {
                format!("dtn://{stripped}")
            }
        } else if trimmed.starts_with("//") {
            format!("dtn:{trimmed}")
        } else {
            format!("dtn://{trimmed}")
        };
        Self {
            uri,
            scheme: EndpointScheme::Dtn,
        }
    }

    /// Creates an `ipn:` scheme endpoint identifier from node and service numbers.
    #[must_use]
    pub fn ipn(node: u64, service: u64) -> Self {
        Self {
            uri: format!("ipn:{node}.{service}"),
            scheme: EndpointScheme::Ipn,
        }
    }

    /// Returns the string representation of this EID.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Returns the URI string slice.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Returns the endpoint scheme.
    #[must_use]
    pub const fn scheme(&self) -> EndpointScheme {
        self.scheme
    }

    /// Returns true if this is the null endpoint (`dtn:none`).
    #[must_use]
    pub fn is_dtn_none(&self) -> bool {
        self.uri == "dtn:none"
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uri)
    }
}

impl std::ops::Deref for EndpointId {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.uri
    }
}

impl AsRef<str> for EndpointId {
    fn as_ref(&self) -> &str {
        &self.uri
    }
}

impl std::borrow::Borrow<str> for EndpointId {
    fn borrow(&self) -> &str {
        &self.uri
    }
}

impl PartialEq<str> for EndpointId {
    fn eq(&self, other: &str) -> bool {
        self.uri == other
    }
}

impl PartialEq<&str> for EndpointId {
    fn eq(&self, other: &&str) -> bool {
        self.uri == *other
    }
}

impl PartialEq<String> for EndpointId {
    fn eq(&self, other: &String) -> bool {
        self.uri == *other
    }
}

impl FromStr for EndpointId {
    type Err = Bpv7ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed == "dtn:none" {
            Ok(Self::dtn_none())
        } else if let Some(stripped) = trimmed.strip_prefix("dtn:") {
            Ok(Self::dtn(stripped))
        } else if let Some(stripped) = trimmed.strip_prefix("ipn:") {
            let parts: Vec<&str> = stripped.split('.').collect();
            if parts.len() == 2 {
                if let (Ok(node), Ok(service)) = (parts[0].parse::<u64>(), parts[1].parse::<u64>())
                {
                    return Ok(Self::ipn(node, service));
                }
            }
            Err(Bpv7ParseError::InvalidBlock(format!(
                "invalid ipn URI: {s}"
            )))
        } else {
            Ok(Self {
                uri: trimmed.to_string(),
                scheme: EndpointScheme::Other(0),
            })
        }
    }
}

/// BPv7 Bundle Creation Timestamp as defined in RFC 9171 §4.2.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct CreationTimestamp {
    /// Milliseconds since DTN epoch (2000-01-01 00:00:00 UTC).
    pub time: u64,
    /// Sequence count unique to the source node at this millisecond.
    pub sequence_number: u64,
}

impl CreationTimestamp {
    /// Creates a new creation timestamp.
    #[must_use]
    pub const fn new(time: u64, sequence_number: u64) -> Self {
        Self {
            time,
            sequence_number,
        }
    }

    /// Returns the DTN time in milliseconds since 2000-01-01 00:00:00 UTC.
    #[must_use]
    pub const fn time(&self) -> u64 {
        self.time
    }

    /// Returns the sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u64 {
        self.sequence_number
    }
}

impl fmt::Display for CreationTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.time, self.sequence_number)
    }
}

/// Parsed representation of a BPv7 Primary Bundle Block (RFC 9171 §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryBlock {
    /// Bundle protocol version (7 for BPv7).
    pub version: u64,
    /// Bundle processing control flags bit field.
    pub bundle_control_flags: u64,
    /// Declared CRC type.
    pub crc_type: CrcType,
    /// Destination endpoint identifier.
    pub destination: EndpointId,
    /// Source node identifier.
    pub source: EndpointId,
    /// Report-to endpoint identifier.
    pub report_to: EndpointId,
    /// Creation timestamp (DTN time and sequence count).
    pub creation_timestamp: CreationTimestamp,
    /// Bundle lifetime in milliseconds relative to creation time.
    pub lifetime: u64,
    /// Fragment offset (in bytes) if bundle is a fragment.
    pub fragment_offset: Option<u64>,
    /// Total Application Data Unit (ADU) length if bundle is a fragment.
    pub total_application_data_unit_length: Option<u64>,
    /// Raw CRC byte value if present.
    pub crc: Option<Vec<u8>>,
    /// Verification result of the CRC if CRC was present and computed.
    pub crc_valid: Option<bool>,
}

impl PrimaryBlock {
    /// Parses a primary bundle block from raw CBOR bytes.
    ///
    /// # Errors
    /// Returns [`Bpv7ParseError`] if the buffer is truncated, malformed, or not a BPv7 header.
    pub fn parse(data: &[u8]) -> Result<Self, Bpv7ParseError> {
        parse_primary_block(data)
    }

    /// Evaluates raw payload bytes and returns the parse status.
    #[must_use]
    pub fn evaluate(data: &[u8]) -> BundleParseStatus {
        evaluate_payload(data)
    }

    /// Returns the bundle protocol version.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the raw bundle control flags.
    #[must_use]
    pub const fn bundle_control_flags(&self) -> u64 {
        self.bundle_control_flags
    }

    /// Returns the bundle processing control flags.
    #[must_use]
    pub const fn bundle_processing_control_flags(&self) -> u64 {
        self.bundle_control_flags
    }

    /// Returns a reference to the destination endpoint identifier.
    #[must_use]
    pub const fn destination(&self) -> &EndpointId {
        &self.destination
    }

    /// Returns the decoded destination EID URI string.
    #[must_use]
    pub fn destination_eid(&self) -> &str {
        self.destination.as_str()
    }

    /// Returns a reference to the source node identifier.
    #[must_use]
    pub const fn source(&self) -> &EndpointId {
        &self.source
    }

    /// Returns a reference to the source node identifier.
    #[must_use]
    pub const fn source_node(&self) -> &EndpointId {
        &self.source
    }

    /// Returns the decoded source node ID URI string.
    #[must_use]
    pub fn source_node_id(&self) -> &str {
        self.source.as_str()
    }

    /// Returns a reference to the report-to endpoint identifier.
    #[must_use]
    pub const fn report_to(&self) -> &EndpointId {
        &self.report_to
    }

    /// Returns the decoded report-to EID URI string.
    #[must_use]
    pub fn report_to_eid(&self) -> &str {
        self.report_to.as_str()
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn creation_timestamp(&self) -> CreationTimestamp {
        self.creation_timestamp
    }

    /// Returns the creation timestamp DTN time (milliseconds).
    #[must_use]
    pub const fn creation_time(&self) -> u64 {
        self.creation_timestamp.time
    }

    /// Returns the creation sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u64 {
        self.creation_timestamp.sequence_number
    }

    /// Returns the bundle lifetime in milliseconds.
    #[must_use]
    pub const fn lifetime(&self) -> u64 {
        self.lifetime
    }

    /// Returns the bundle lifetime in milliseconds.
    #[must_use]
    pub const fn lifetime_ms(&self) -> u64 {
        self.lifetime
    }

    /// Returns the fragment offset in bytes, if fragmented.
    #[must_use]
    pub const fn fragment_offset(&self) -> Option<u64> {
        self.fragment_offset
    }

    /// Returns the total Application Data Unit length in bytes, if fragmented.
    #[must_use]
    pub const fn total_application_data_unit_length(&self) -> Option<u64> {
        self.total_application_data_unit_length
    }

    /// Returns the total Application Data Unit length in bytes, if fragmented.
    #[must_use]
    pub const fn total_adu_length(&self) -> Option<u64> {
        self.total_application_data_unit_length
    }

    /// Returns the total Application Data Unit length in bytes, if fragmented.
    #[must_use]
    pub const fn total_data_length(&self) -> Option<u64> {
        self.total_application_data_unit_length
    }

    /// Returns true if the bundle processing control flags indicate a fragment.
    #[must_use]
    pub const fn is_fragment(&self) -> bool {
        (self.bundle_control_flags & BUNDLE_IS_FRAGMENT) != 0
    }

    /// Returns true if a CRC is declared on this primary block.
    #[must_use]
    pub const fn has_crc(&self) -> bool {
        !matches!(self.crc_type, CrcType::None)
    }

    /// Returns whether the CRC is valid, if one was present.
    #[must_use]
    pub const fn is_crc_valid(&self) -> Option<bool> {
        self.crc_valid
    }

    /// Returns true if no CRC is present or if the present CRC verified successfully.
    #[must_use]
    pub fn check_crc(&self) -> bool {
        self.crc_valid.unwrap_or(true)
    }

    /// Serializes this PrimaryBlock into valid CBOR bytes.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let has_frag = self.is_fragment();
        let has_crc = self.has_crc();
        let count = match (has_frag, has_crc) {
            (false, false) => 8,
            (false, true) => 9,
            (true, false) => 10,
            (true, true) => 11,
        };

        let mut buf = Vec::new();
        encode_cbor_array_header(count, &mut buf);
        encode_cbor_uint(self.version, &mut buf);
        encode_cbor_uint(self.bundle_control_flags, &mut buf);
        encode_cbor_uint(u64::from(self.crc_type.code()), &mut buf);
        encode_cbor_eid(&self.destination, &mut buf);
        encode_cbor_eid(&self.source, &mut buf);
        encode_cbor_eid(&self.report_to, &mut buf);

        encode_cbor_array_header(2, &mut buf);
        encode_cbor_uint(self.creation_timestamp.time, &mut buf);
        encode_cbor_uint(self.creation_timestamp.sequence_number, &mut buf);

        encode_cbor_uint(self.lifetime, &mut buf);

        if has_frag {
            encode_cbor_uint(self.fragment_offset.unwrap_or(0), &mut buf);
            encode_cbor_uint(
                self.total_application_data_unit_length.unwrap_or(0),
                &mut buf,
            );
        }

        if has_crc {
            let crc_len = self.crc_type.expected_len();
            encode_cbor_byte_string_header(crc_len, &mut buf);
            let crc_val_offset = buf.len();
            buf.resize(crc_val_offset + crc_len, 0);

            match self.crc_type {
                CrcType::None => {}
                CrcType::Crc16 => {
                    let calculated = compute_crc16_x25(&buf);
                    buf[crc_val_offset..crc_val_offset + 2]
                        .copy_from_slice(&calculated.to_be_bytes());
                }
                CrcType::Crc32 => {
                    let calculated = compute_crc32c(&buf);
                    buf[crc_val_offset..crc_val_offset + 4]
                        .copy_from_slice(&calculated.to_be_bytes());
                }
            }
        }

        buf
    }
}

/// Evaluation status indicating the outcome of parsing a payload for BPv7 bundle headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleParseStatus {
    /// Payload is a valid BPv7 bundle or primary block.
    Valid,
    /// Payload is valid non-BPv7 data or valid CBOR that does not form a BPv7 bundle.
    NotBpv7,
    /// Payload is malformed CBOR or contains invalid byte sequences.
    MalformedCbor,
    /// Input is truncated before the declared lengths or primary block completed.
    Truncated,
}

impl fmt::Display for BundleParseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::NotBpv7 => write!(f, "not_bpv7"),
            Self::MalformedCbor => write!(f, "malformed_cbor"),
            Self::Truncated => write!(f, "truncated"),
        }
    }
}

impl BundleParseStatus {
    /// Returns true if the status is [`Self::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns true if the status is [`Self::MalformedCbor`].
    #[must_use]
    pub const fn is_malformed(&self) -> bool {
        matches!(self, Self::MalformedCbor)
    }

    /// Returns true if the status is [`Self::NotBpv7`].
    #[must_use]
    pub const fn is_not_bpv7(&self) -> bool {
        matches!(self, Self::NotBpv7)
    }

    /// Returns true if the status is [`Self::Truncated`].
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated)
    }
}

/// Errors returned when parsing BPv7 bundles and primary blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Bpv7ParseError {
    /// Buffer is shorter than declared CBOR length or ends before header completion.
    Truncated {
        /// Number of bytes expected.
        expected: usize,
        /// Number of bytes actually available.
        actual: usize,
    },
    /// Malformed CBOR byte stream or invalid CBOR syntax.
    MalformedCbor(String),
    /// Data is not a BPv7 bundle header (e.g. wrong version or wrong structure).
    NotBpv7(String),
    /// Invalid primary block structure or fields.
    InvalidBlock(String),
    /// CRC verification mismatch.
    CrcMismatch {
        /// CRC value expected from calculation.
        expected: u32,
        /// CRC value actually read from packet.
        actual: u32,
    },
}

impl fmt::Display for Bpv7ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { expected, actual } => {
                write!(
                    f,
                    "truncated input: expected at least {expected} bytes, got {actual}"
                )
            }
            Self::MalformedCbor(msg) => write!(f, "malformed CBOR: {msg}"),
            Self::NotBpv7(msg) => write!(f, "not a BPv7 bundle: {msg}"),
            Self::InvalidBlock(msg) => write!(f, "invalid primary block: {msg}"),
            Self::CrcMismatch { expected, actual } => {
                write!(f, "CRC mismatch: expected {expected:#x}, got {actual:#x}")
            }
        }
    }
}

impl std::error::Error for Bpv7ParseError {}

impl Bpv7ParseError {
    /// Returns true if the error represents truncated input.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }

    /// Maps this parse error into a corresponding [`BundleParseStatus`].
    #[must_use]
    pub fn status(&self) -> BundleParseStatus {
        match self {
            Self::Truncated { .. } => BundleParseStatus::Truncated,
            Self::MalformedCbor(_) => BundleParseStatus::MalformedCbor,
            Self::NotBpv7(_) => BundleParseStatus::NotBpv7,
            Self::InvalidBlock(_) => BundleParseStatus::NotBpv7,
            Self::CrcMismatch { .. } => BundleParseStatus::MalformedCbor,
        }
    }
}

/// Parses a BPv7 Primary Block from a CBOR byte slice.
///
/// Can parse standalone primary blocks or bundles whose first item is the primary block.
///
/// # Errors
/// Returns [`Bpv7ParseError`] if the buffer is truncated, malformed, or not a BPv7 block.
pub fn parse_primary_block(data: &[u8]) -> Result<PrimaryBlock, Bpv7ParseError> {
    if data.is_empty() {
        return Err(Bpv7ParseError::Truncated {
            expected: 1,
            actual: 0,
        });
    }

    let mut cursor = CborCursor::new(data);
    let first_byte = cursor.peek_byte()?;
    let major = first_byte >> 5;

    if major != 4 {
        // Not a CBOR array. Distinguish well-formed non-array CBOR from arbitrary non-CBOR.
        if is_well_formed_cbor(data) {
            return Err(Bpv7ParseError::NotBpv7(
                "expected CBOR array for BPv7 bundle or primary block".to_string(),
            ));
        }
        return Err(Bpv7ParseError::MalformedCbor(
            "payload is not well-formed CBOR".to_string(),
        ));
    }

    let outer_array_len = cursor.read_array_header()?;
    let inner_byte = cursor.peek_byte()?;
    let inner_major = inner_byte >> 5;

    let (declared_block_items, block_start_offset) = if inner_major == 4 {
        // Outer array is a bundle; inner array is the primary block.
        let block_start = cursor.offset;
        let inner_len = cursor.read_array_header()?;
        (inner_len, block_start)
    } else {
        // Outer array is the primary block itself.
        (outer_array_len, 0)
    };

    // Element 0: Version
    let version = cursor.read_uint()?;
    if version != BP_VERSION_7 {
        return Err(Bpv7ParseError::NotBpv7(format!(
            "unsupported BP version: expected {BP_VERSION_7}, got {version}"
        )));
    }

    // Element 1: Bundle Processing Control Flags
    let bundle_control_flags = cursor.read_uint()?;
    let is_frag = (bundle_control_flags & BUNDLE_IS_FRAGMENT) != 0;

    // Element 2: CRC Type
    let crc_type_val = cursor.read_uint()?;
    let crc_type = CrcType::from_u64(crc_type_val)?;
    let has_crc = !matches!(crc_type, CrcType::None);

    let expected_items = match (is_frag, has_crc) {
        (false, false) => 8,
        (false, true) => 9,
        (true, false) => 10,
        (true, true) => 11,
    };

    if let Some(items) = declared_block_items {
        if items < 8 {
            return Err(Bpv7ParseError::NotBpv7(format!(
                "primary block array length {items} is less than required 8 items"
            )));
        }
        if items != expected_items {
            return Err(Bpv7ParseError::InvalidBlock(format!(
                "primary block array declared {items} items, but expected {expected_items} items"
            )));
        }
    }

    // Element 3: Destination EID
    let destination = read_eid(&mut cursor)?;

    // Element 4: Source Node ID
    let source = read_eid(&mut cursor)?;

    // Element 5: Report-to EID
    let report_to = read_eid(&mut cursor)?;

    // Element 6: Creation Timestamp [time, seq]
    let timestamp_items = cursor.read_array_header()?;
    if let Some(cnt) = timestamp_items {
        if cnt != 2 {
            return Err(Bpv7ParseError::InvalidBlock(format!(
                "creation timestamp array must have 2 elements, got {cnt}"
            )));
        }
    }
    let creation_time = cursor.read_uint()?;
    let sequence_number = cursor.read_uint()?;
    if timestamp_items.is_none() {
        cursor.read_break()?;
    }
    let creation_timestamp = CreationTimestamp::new(creation_time, sequence_number);

    // Element 7: Lifetime
    let lifetime = cursor.read_uint()?;

    // Optional Elements 8 & 9: Fragment Offset & Total ADU Length
    let (fragment_offset, total_application_data_unit_length) = if is_frag {
        let offset = cursor.read_uint()?;
        let total_adu = cursor.read_uint()?;
        (Some(offset), Some(total_adu))
    } else {
        (None, None)
    };

    // Optional Element (8, 9, 10, or 11): CRC Field
    let (crc, crc_valid) = if has_crc {
        let crc_bytes = cursor.read_byte_string()?;
        let expected_len = crc_type.expected_len();
        if crc_bytes.len() != expected_len {
            return Err(Bpv7ParseError::MalformedCbor(format!(
                "CRC field length mismatch: expected {expected_len} bytes, got {}",
                crc_bytes.len()
            )));
        }

        let block_end_offset = cursor.offset;
        let block_slice = &data[block_start_offset..block_end_offset];
        let valid = verify_primary_block_crc(block_slice, crc_type, crc_bytes);

        (Some(crc_bytes.to_vec()), Some(valid))
    } else {
        (None, None)
    };

    if declared_block_items.is_none() {
        cursor.read_break()?;
    }

    Ok(PrimaryBlock {
        version,
        bundle_control_flags,
        crc_type,
        destination,
        source,
        report_to,
        creation_timestamp,
        lifetime,
        fragment_offset,
        total_application_data_unit_length,
        crc,
        crc_valid,
    })
}

/// Alias for [`parse_primary_block`].
pub fn parse_bpv7_primary_block(data: &[u8]) -> Result<PrimaryBlock, Bpv7ParseError> {
    parse_primary_block(data)
}

/// Alias for [`parse_primary_block`].
pub fn parse_bundle(data: &[u8]) -> Result<PrimaryBlock, Bpv7ParseError> {
    parse_primary_block(data)
}

/// Evaluates raw payload bytes and returns the classified [`BundleParseStatus`].
#[must_use]
pub fn evaluate_payload(data: &[u8]) -> BundleParseStatus {
    if data.is_empty() {
        return BundleParseStatus::Truncated;
    }

    match parse_primary_block(data) {
        Ok(_) => BundleParseStatus::Valid,
        Err(err) => err.status(),
    }
}

/// Alias for [`evaluate_payload`].
#[must_use]
pub fn evaluate_bpv7_payload(data: &[u8]) -> BundleParseStatus {
    evaluate_payload(data)
}

/// Evaluates raw payload bytes, returning both the [`BundleParseStatus`] and optional [`PrimaryBlock`].
#[must_use]
pub fn evaluate_bundle_header(data: &[u8]) -> (BundleParseStatus, Option<PrimaryBlock>) {
    match parse_primary_block(data) {
        Ok(block) => (BundleParseStatus::Valid, Some(block)),
        Err(err) => (err.status(), None),
    }
}

fn read_eid(cursor: &mut CborCursor<'_>) -> Result<EndpointId, Bpv7ParseError> {
    let array_len = cursor.read_array_header()?;
    if let Some(cnt) = array_len {
        if cnt != 2 {
            return Err(Bpv7ParseError::InvalidBlock(format!(
                "endpoint ID array must have 2 elements, got {cnt}"
            )));
        }
    }

    let scheme_code = cursor.read_uint()?;

    let eid = match scheme_code {
        1 => {
            // dtn: scheme
            let peek = cursor.peek_byte()?;
            let major = peek >> 5;
            match major {
                0 => {
                    let code = cursor.read_uint()?;
                    if code == 0 {
                        EndpointId::dtn_none()
                    } else {
                        return Err(Bpv7ParseError::InvalidBlock(format!(
                            "invalid integer SSP for dtn scheme: {code}"
                        )));
                    }
                }
                3 => {
                    let ssp = cursor.read_text_string()?;
                    EndpointId::dtn(ssp)
                }
                _ => {
                    return Err(Bpv7ParseError::MalformedCbor(
                        "expected uint 0 or text string SSP for dtn EID".to_string(),
                    ));
                }
            }
        }
        2 => {
            // ipn: scheme
            let ssp_len = cursor.read_array_header()?;
            if let Some(cnt) = ssp_len {
                if cnt != 2 {
                    return Err(Bpv7ParseError::InvalidBlock(format!(
                        "ipn EID SSP array must have 2 elements, got {cnt}"
                    )));
                }
            }
            let node = cursor.read_uint()?;
            let service = cursor.read_uint()?;
            if ssp_len.is_none() {
                cursor.read_break()?;
            }
            EndpointId::ipn(node, service)
        }
        other => {
            let peek = cursor.peek_byte()?;
            let major = peek >> 5;
            if major == 3 {
                let ssp = cursor.read_text_string()?;
                EndpointId {
                    uri: format!("scheme-{other}:{ssp}"),
                    scheme: EndpointScheme::Other(other),
                }
            } else {
                cursor.skip_item(0)?;
                EndpointId {
                    uri: format!("scheme-{other}:unknown"),
                    scheme: EndpointScheme::Other(other),
                }
            }
        }
    };

    if array_len.is_none() {
        cursor.read_break()?;
    }

    Ok(eid)
}

fn verify_primary_block_crc(block_bytes: &[u8], crc_type: CrcType, declared_crc: &[u8]) -> bool {
    let crc_len = crc_type.expected_len();
    if block_bytes.len() < crc_len {
        return false;
    }

    let mut buf = block_bytes.to_vec();
    let zero_offset = buf.len() - crc_len;
    buf[zero_offset..].fill(0);

    match crc_type {
        CrcType::None => true,
        CrcType::Crc16 => {
            let calc = compute_crc16_x25(&buf);
            calc.to_be_bytes() == declared_crc
        }
        CrcType::Crc32 => {
            let calc = compute_crc32c(&buf);
            calc.to_be_bytes() == declared_crc
        }
    }
}

/// Computes standard CRC-16/X-25 checksum over bytes.
#[must_use]
pub fn compute_crc16_x25(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &b in data {
        crc ^= u16::from(b);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x8408;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF
}

/// Computes standard CRC-32C (Castagnoli, RFC 9171) checksum over bytes.
#[must_use]
pub fn compute_crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

struct CborCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn peek_byte(&self) -> Result<u8, Bpv7ParseError> {
        if self.offset >= self.data.len() {
            Err(Bpv7ParseError::Truncated {
                expected: 1,
                actual: 0,
            })
        } else {
            Ok(self.data[self.offset])
        }
    }

    fn read_byte(&mut self) -> Result<u8, Bpv7ParseError> {
        let b = self.peek_byte()?;
        self.offset += 1;
        Ok(b)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8], Bpv7ParseError> {
        let rem = self.remaining();
        if rem < n {
            Err(Bpv7ParseError::Truncated {
                expected: n,
                actual: rem,
            })
        } else {
            let start = self.offset;
            self.offset += n;
            Ok(&self.data[start..start + n])
        }
    }

    fn read_break(&mut self) -> Result<(), Bpv7ParseError> {
        let b = self.read_byte()?;
        if b == 0xFF {
            Ok(())
        } else {
            Err(Bpv7ParseError::MalformedCbor(format!(
                "expected CBOR break (0xFF), got {b:#x}"
            )))
        }
    }

    fn read_header(&mut self) -> Result<(u8, Option<u64>), Bpv7ParseError> {
        let b = self.read_byte()?;
        let major = b >> 5;
        let info = b & 0x1F;

        if (28..=30).contains(&info) {
            return Err(Bpv7ParseError::MalformedCbor(format!(
                "reserved CBOR additional information {info}"
            )));
        }

        if info < 24 {
            Ok((major, Some(u64::from(info))))
        } else if info == 24 {
            let val = self.read_byte()?;
            Ok((major, Some(u64::from(val))))
        } else if info == 25 {
            let slice = self.read_exact(2)?;
            let val = u16::from_be_bytes([slice[0], slice[1]]);
            Ok((major, Some(u64::from(val))))
        } else if info == 26 {
            let slice = self.read_exact(4)?;
            let val = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
            Ok((major, Some(u64::from(val))))
        } else if info == 27 {
            let slice = self.read_exact(8)?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(slice);
            let val = u64::from_be_bytes(arr);
            Ok((major, Some(val)))
        } else if info == 31 {
            Ok((major, None))
        } else {
            Err(Bpv7ParseError::MalformedCbor(format!(
                "unexpected additional information {info}"
            )))
        }
    }

    fn read_uint(&mut self) -> Result<u64, Bpv7ParseError> {
        let (major, val) = self.read_header()?;
        if major != 0 {
            return Err(Bpv7ParseError::MalformedCbor(format!(
                "expected unsigned integer (major type 0), got major type {major}"
            )));
        }
        val.ok_or_else(|| {
            Bpv7ParseError::MalformedCbor("indefinite length unsigned integer not allowed".into())
        })
    }

    fn read_text_string(&mut self) -> Result<&'a str, Bpv7ParseError> {
        let (major, val) = self.read_header()?;
        if major != 3 {
            return Err(Bpv7ParseError::MalformedCbor(format!(
                "expected text string (major type 3), got major type {major}"
            )));
        }
        let len = val.ok_or_else(|| {
            Bpv7ParseError::MalformedCbor("indefinite length text strings not supported".into())
        })?;
        let len_usize = usize::try_from(len).map_err(|_| {
            Bpv7ParseError::MalformedCbor("text string length exceeds platform usize".into())
        })?;
        let bytes = self.read_exact(len_usize)?;
        std::str::from_utf8(bytes).map_err(|e| {
            Bpv7ParseError::MalformedCbor(format!("invalid UTF-8 in text string: {e}"))
        })
    }

    fn read_byte_string(&mut self) -> Result<&'a [u8], Bpv7ParseError> {
        let (major, val) = self.read_header()?;
        if major != 2 {
            return Err(Bpv7ParseError::MalformedCbor(format!(
                "expected byte string (major type 2), got major type {major}"
            )));
        }
        let len = val.ok_or_else(|| {
            Bpv7ParseError::MalformedCbor("indefinite length byte strings not supported".into())
        })?;
        let len_usize = usize::try_from(len).map_err(|_| {
            Bpv7ParseError::MalformedCbor("byte string length exceeds platform usize".into())
        })?;
        self.read_exact(len_usize)
    }

    fn read_array_header(&mut self) -> Result<Option<usize>, Bpv7ParseError> {
        let (major, val) = self.read_header()?;
        if major != 4 {
            return Err(Bpv7ParseError::NotBpv7(format!(
                "expected array (major type 4), got major type {major}"
            )));
        }
        match val {
            Some(v) => {
                let cnt = usize::try_from(v).map_err(|_| {
                    Bpv7ParseError::MalformedCbor("array length exceeds platform usize".into())
                })?;
                Ok(Some(cnt))
            }
            None => Ok(None),
        }
    }

    fn skip_item(&mut self, depth: usize) -> Result<(), Bpv7ParseError> {
        if depth > 32 {
            return Err(Bpv7ParseError::MalformedCbor(
                "nesting depth exceeded limit of 32".into(),
            ));
        }

        let (major, val) = self.read_header()?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                if let Some(len) = val {
                    let len_usize = usize::try_from(len).map_err(|_| {
                        Bpv7ParseError::MalformedCbor("string length exceeds platform usize".into())
                    })?;
                    self.read_exact(len_usize)?;
                } else {
                    loop {
                        if self.peek_byte()? == 0xFF {
                            self.read_byte()?;
                            break;
                        }
                        self.skip_item(depth + 1)?;
                    }
                }
                Ok(())
            }
            4 => {
                if let Some(cnt) = val {
                    let cnt_usize = usize::try_from(cnt).map_err(|_| {
                        Bpv7ParseError::MalformedCbor("array count exceeds platform usize".into())
                    })?;
                    for _ in 0..cnt_usize {
                        self.skip_item(depth + 1)?;
                    }
                } else {
                    loop {
                        if self.peek_byte()? == 0xFF {
                            self.read_byte()?;
                            break;
                        }
                        self.skip_item(depth + 1)?;
                    }
                }
                Ok(())
            }
            5 => {
                if let Some(cnt) = val {
                    let cnt_usize = usize::try_from(cnt).map_err(|_| {
                        Bpv7ParseError::MalformedCbor("map count exceeds platform usize".into())
                    })?;
                    for _ in 0..cnt_usize * 2 {
                        self.skip_item(depth + 1)?;
                    }
                } else {
                    loop {
                        if self.peek_byte()? == 0xFF {
                            self.read_byte()?;
                            break;
                        }
                        self.skip_item(depth + 1)?;
                    }
                }
                Ok(())
            }
            6 => self.skip_item(depth + 1),
            _ => Err(Bpv7ParseError::MalformedCbor(format!(
                "unsupported major type {major}"
            ))),
        }
    }
}

fn is_well_formed_cbor(data: &[u8]) -> bool {
    let mut cursor = CborCursor::new(data);
    if cursor.skip_item(0).is_err() {
        return false;
    }
    // Return true if first item successfully validated as CBOR
    true
}

fn encode_cbor_uint(val: u64, buf: &mut Vec<u8>) {
    if val < 24 {
        buf.push(val as u8);
    } else if val <= 0xFF {
        buf.push(24);
        buf.push(val as u8);
    } else if val <= 0xFFFF {
        buf.push(25);
        buf.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= 0xFFFF_FFFF {
        buf.push(26);
        buf.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        buf.push(27);
        buf.extend_from_slice(&val.to_be_bytes());
    }
}

fn encode_cbor_array_header(count: usize, buf: &mut Vec<u8>) {
    if count < 24 {
        buf.push(0x80 | (count as u8));
    } else if count <= 0xFF {
        buf.push(0x80 | 24);
        buf.push(count as u8);
    } else if count <= 0xFFFF {
        buf.push(0x80 | 25);
        buf.extend_from_slice(&(count as u16).to_be_bytes());
    } else if count <= 0xFFFF_FFFF {
        buf.push(0x80 | 26);
        buf.extend_from_slice(&(count as u32).to_be_bytes());
    } else {
        buf.push(0x80 | 27);
        buf.extend_from_slice(&(count as u64).to_be_bytes());
    }
}

fn encode_cbor_text_string(text: &str, buf: &mut Vec<u8>) {
    let bytes = text.as_bytes();
    let len = bytes.len();
    if len < 24 {
        buf.push(0x60 | (len as u8));
    } else if len <= 0xFF {
        buf.push(0x60 | 24);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0x60 | 25);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= 0xFFFF_FFFF {
        buf.push(0x60 | 26);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        buf.push(0x60 | 27);
        buf.extend_from_slice(&(len as u64).to_be_bytes());
    }
    buf.extend_from_slice(bytes);
}

fn encode_cbor_byte_string_header(len: usize, buf: &mut Vec<u8>) {
    if len < 24 {
        buf.push(0x40 | (len as u8));
    } else if len <= 0xFF {
        buf.push(0x40 | 24);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0x40 | 25);
        buf.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        buf.push(0x40 | 26);
        buf.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn encode_cbor_eid(eid: &EndpointId, buf: &mut Vec<u8>) {
    encode_cbor_array_header(2, buf);
    match eid.scheme {
        EndpointScheme::Dtn => {
            encode_cbor_uint(1, buf);
            if eid.is_dtn_none() {
                encode_cbor_uint(0, buf);
            } else {
                let ssp = eid.uri.strip_prefix("dtn:").unwrap_or(eid.as_str());
                encode_cbor_text_string(ssp, buf);
            }
        }
        EndpointScheme::Ipn => {
            encode_cbor_uint(2, buf);
            encode_cbor_array_header(2, buf);
            let ssp = eid.uri.strip_prefix("ipn:").unwrap_or(eid.as_str());
            let parts: Vec<&str> = ssp.split('.').collect();
            let node = parts
                .first()
                .and_then(|p| p.parse::<u64>().ok())
                .unwrap_or(0);
            let service = parts
                .get(1)
                .and_then(|p| p.parse::<u64>().ok())
                .unwrap_or(0);
            encode_cbor_uint(node, buf);
            encode_cbor_uint(service, buf);
        }
        EndpointScheme::Other(code) => {
            encode_cbor_uint(code, buf);
            encode_cbor_text_string(&eid.uri, buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc9171_reference_vector_extraction() {
        // RFC 9171 reference bundle vector from bp7-rs:
        // [indefinite array, primary block: [7, 0, 0, [2, [2, 1]], [2, [1, 1]], [2, [0, 1]], [0x00ff00bb0e20b4ea, 0], 600000], ...]
        let hex_bundle = "9f88070000820282020182028201018202820001821b00ff00bb0e20b4ea001a000927c08507020100410085010100004d48656c6f2c20576f726c642142ff";
        let raw_bundle: Vec<u8> = (0..hex_bundle.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_bundle[i..i + 2], 16).unwrap())
            .collect();

        let header = parse_primary_block(&raw_bundle).expect("must parse valid RFC 9171 bundle");
        assert_eq!(header.version, 7);
        assert_eq!(header.destination_eid(), "ipn:2.1");
        assert_eq!(header.source_node_id(), "ipn:1.1");
        assert_eq!(header.report_to_eid(), "ipn:0.1");
        assert_eq!(header.creation_timestamp.time, 0x00ff_00bb_0e20_b4ea);
        assert_eq!(header.creation_timestamp.sequence_number, 0);
        assert_eq!(header.lifetime, 600_000);
        assert!(!header.is_fragment());
        assert_eq!(header.fragment_offset, None);
        assert_eq!(header.total_application_data_unit_length, None);

        // Also test parsing just the primary block slice (without the outer 0x9f bundle array)
        let primary_slice = &raw_bundle[1..36];
        let header2 =
            parse_primary_block(primary_slice).expect("must parse primary block directly");
        assert_eq!(header2.version, 7);
        assert_eq!(header2.destination_eid(), "ipn:2.1");
        assert_eq!(header2.source_node_id(), "ipn:1.1");
        assert_eq!(header2.lifetime, 600_000);
    }

    #[test]
    fn test_ipn_destination_and_dtn_source_uri_strings() {
        let primary = PrimaryBlock {
            version: 7,
            bundle_control_flags: 0,
            crc_type: CrcType::None,
            destination: EndpointId::ipn(42, 1),
            source: EndpointId::dtn("//mars-rover/telemetry"),
            report_to: EndpointId::dtn_none(),
            creation_timestamp: CreationTimestamp::new(1_000_000, 5),
            lifetime: 3600,
            fragment_offset: None,
            total_application_data_unit_length: None,
            crc: None,
            crc_valid: None,
        };

        let cbor_bytes = primary.to_cbor();
        let parsed = parse_primary_block(&cbor_bytes).expect("must parse mixed EID primary block");

        assert_eq!(parsed.destination_eid(), "ipn:42.1");
        assert_eq!(parsed.source_node_id(), "dtn://mars-rover/telemetry");
        assert_eq!(parsed.report_to_eid(), "dtn:none");
        assert_eq!(parsed.destination.to_string(), "ipn:42.1");
        assert_eq!(parsed.source.to_string(), "dtn://mars-rover/telemetry");
    }

    #[test]
    fn test_truncated_input_returns_truncated_error() {
        let primary = PrimaryBlock {
            version: 7,
            bundle_control_flags: 0,
            crc_type: CrcType::None,
            destination: EndpointId::ipn(1, 2),
            source: EndpointId::dtn("//gateway/status"),
            report_to: EndpointId::dtn_none(),
            creation_timestamp: CreationTimestamp::new(500, 1),
            lifetime: 10_000,
            fragment_offset: None,
            total_application_data_unit_length: None,
            crc: None,
            crc_valid: None,
        };

        let full_bytes = primary.to_cbor();

        // 1. Empty buffer
        let err_empty = parse_primary_block(&[]).unwrap_err();
        assert!(err_empty.is_truncated());
        assert!(err_empty.to_string().contains("truncated input"));

        // 2. Truncated mid-primary-block
        for cut in 1..full_bytes.len() {
            let truncated = &full_bytes[..cut];
            let err = parse_primary_block(truncated).unwrap_err();
            assert!(
                err.is_truncated(),
                "cut at {cut}/{} failed to return Truncated: {err:?}",
                full_bytes.len()
            );
            assert_eq!(err.status(), BundleParseStatus::Truncated);
        }

        // 3. CBOR item declares length longer than buffer
        // 0x64 is text string length 4, but only 2 bytes follow
        let bad_item = vec![0x88, 0x07, 0x00, 0x00, 0x82, 0x01, 0x64, b'a', b'b'];
        let err_item = parse_primary_block(&bad_item).unwrap_err();
        assert!(err_item.is_truncated());
    }

    #[test]
    fn test_rfc9171_fragmentation_flags_extracts_offset_and_adu_length() {
        let primary = PrimaryBlock {
            version: 7,
            bundle_control_flags: BUNDLE_IS_FRAGMENT | BUNDLE_MUST_NOT_BE_FRAGMENTED,
            crc_type: CrcType::None,
            destination: EndpointId::ipn(100, 1),
            source: EndpointId::ipn(200, 2),
            report_to: EndpointId::dtn_none(),
            creation_timestamp: CreationTimestamp::new(99_999, 12),
            lifetime: 7200,
            fragment_offset: Some(4096),
            total_application_data_unit_length: Some(16384),
            crc: None,
            crc_valid: None,
        };

        let cbor_bytes = primary.to_cbor();
        let parsed = parse_primary_block(&cbor_bytes).expect("must parse fragmented primary block");

        assert!(parsed.is_fragment());
        assert_eq!(parsed.fragment_offset(), Some(4096));
        assert_eq!(parsed.total_application_data_unit_length(), Some(16384));
        assert_eq!(parsed.total_adu_length(), Some(16384));
        assert_eq!(parsed.total_data_length(), Some(16384));
    }

    #[test]
    fn test_evaluating_arbitrary_non_cbor_returns_malformed_without_panicking() {
        let test_payloads: Vec<&[u8]> = vec![
            b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
            &[0x1C, 0x00, 0x01, 0x02], // Reserved info 28
            &[0x1D, 0xFF],             // Reserved info 29
            &[0x1E, 0xAA, 0xBB],       // Reserved info 30
            &[0xFF, 0x00, 0x00],       // Unexpected break code
            &[0xDE, 0xAD, 0xBE, 0xEF], // Non-CBOR noise
            &[0x65, 0xFF, 0xFE, 0xFD], // Invalid UTF-8 in text string
        ];

        for payload in test_payloads {
            let status = evaluate_payload(payload);
            assert!(
                status.is_malformed() || status.is_not_bpv7(),
                "payload {payload:?} must distinguish malformed CBOR / non-BPv7, got {status:?}"
            );
            assert!(!status.is_valid());

            let (s, opt) = evaluate_bundle_header(payload);
            assert_eq!(s, status);
            assert!(opt.is_none());
        }
    }

    #[test]
    fn test_valid_non_bpv7_cbor_distinguished_from_malformed_and_valid() {
        // Valid CBOR integer 42
        let int_cbor = [0x18, 0x2A];
        assert_eq!(evaluate_payload(&int_cbor), BundleParseStatus::NotBpv7);

        // Valid CBOR array of 3 integers: [1, 2, 3]
        let array_cbor = [0x83, 0x01, 0x02, 0x03];
        assert_eq!(evaluate_payload(&array_cbor), BundleParseStatus::NotBpv7);

        // Valid CBOR array with version 6 (BPv6)
        let bpv6 = [
            0x88, 0x06, 0x00, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82, 0x01, 0x00, 0x82,
            0x00, 0x00, 0x18, 0x64,
        ];
        assert_eq!(evaluate_payload(&bpv6), BundleParseStatus::NotBpv7);
    }

    #[test]
    fn test_crc16_and_crc32_roundtrip_verification() {
        for crc_type in [CrcType::None, CrcType::Crc16, CrcType::Crc32] {
            let primary = PrimaryBlock {
                version: 7,
                bundle_control_flags: 0,
                crc_type,
                destination: EndpointId::dtn("//station/command"),
                source: EndpointId::ipn(999, 1),
                report_to: EndpointId::dtn_none(),
                creation_timestamp: CreationTimestamp::new(123_456, 1),
                lifetime: 86400,
                fragment_offset: None,
                total_application_data_unit_length: None,
                crc: None,
                crc_valid: None,
            };

            let bytes = primary.to_cbor();
            let parsed = parse_primary_block(&bytes).expect("must parse with CRC");
            assert_eq!(parsed.crc_type, crc_type);
            if crc_type != CrcType::None {
                assert!(parsed.has_crc());
                assert_eq!(parsed.is_crc_valid(), Some(true));
                assert!(parsed.check_crc());
            } else {
                assert!(!parsed.has_crc());
                assert_eq!(parsed.is_crc_valid(), None);
                assert!(parsed.check_crc());
            }

            // Corrupt CRC bytes and verify detection
            if crc_type != CrcType::None {
                let mut corrupted = bytes.clone();
                let last = corrupted.len() - 1;
                corrupted[last] ^= 0xFF;
                let parsed_corrupt =
                    parse_primary_block(&corrupted).expect("parse primary block with bad CRC");
                assert_eq!(parsed_corrupt.is_crc_valid(), Some(false));
                assert!(!parsed_corrupt.check_crc());
            }
        }
    }
}
