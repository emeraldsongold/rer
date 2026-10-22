//! In-tree SDNV and Licklider Transmission Protocol (LTP) segment header parser (SPEC §14, §8, RFC 5326).
//!
//! Provides a zero-dependency in-tree Self-Delimiting Numeric Value (SDNV) codec and LTP segment
//! header parser as defined in RFC 5326 and CCSDS 734.1-B-1.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §14, RER implements passive metadata inspection of LTP segment headers.
//! RER does NOT implement a stateful LTP protocol engine, block reassembly, retransmission queues,
//! countdown timer management, contact schedule execution, or LTP security extensions (RFC 5327).
//! Forwarded segments are transmitted byte-unmodified.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Standard LTP protocol version (0 for RFC 5326).
pub const LTP_VERSION_0: u8 = 0;

/// LTP Segment Type representation as defined in RFC 5326 §3.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SegmentType {
    /// Red data, NOT Checkpoint, NOT EORP, NOT EOB (code 0).
    RedData = 0,
    /// Red data, Checkpoint, NOT EORP, NOT EOB (code 1).
    RedDataCheckpoint = 1,
    /// Red data, Checkpoint, EORP, NOT EOB (code 2).
    RedDataCheckpointEorp = 2,
    /// Red data, Checkpoint, EORP, EOB (code 3).
    RedDataCheckpointEorpEob = 3,
    /// Green data, NOT EOB (code 4).
    GreenData = 4,
    /// Green data, undefined (code 5).
    GreenDataUndefined5 = 5,
    /// Green data, undefined (code 6).
    GreenDataUndefined6 = 6,
    /// Green data, EOB (code 7).
    GreenDataEob = 7,
    /// Report segment (code 8).
    Report = 8,
    /// Report-acknowledgment segment (code 9).
    ReportAck = 9,
    /// Control segment, undefined (code 10).
    ControlUndefined10 = 10,
    /// Control segment, undefined (code 11).
    ControlUndefined11 = 11,
    /// Cancel segment from block sender (code 12).
    CancelFromSender = 12,
    /// Cancel-acknowledgment segment to block sender (code 13).
    CancelAckToSender = 13,
    /// Cancel segment from block receiver (code 14).
    CancelFromReceiver = 14,
    /// Cancel-acknowledgment segment to block receiver (code 15).
    CancelAckToReceiver = 15,
}

impl SegmentType {
    /// Alias for [`Self::RedData`].
    pub const RED_DATA: Self = Self::RedData;
    /// Alias for [`Self::RedDataCheckpoint`].
    pub const CHECKPOINT: Self = Self::RedDataCheckpoint;
    /// Alias for [`Self::Report`].
    pub const REPORT: Self = Self::Report;
    /// Alias for [`Self::ReportAck`].
    pub const REPORT_ACK: Self = Self::ReportAck;
    /// Alias for [`Self::CancelFromSender`].
    pub const CANCEL_FROM_SENDER: Self = Self::CancelFromSender;
    /// Alias for [`Self::CancelAckToSender`].
    pub const CANCEL_ACK_TO_SENDER: Self = Self::CancelAckToSender;
    /// Alias for [`Self::CancelFromReceiver`].
    pub const CANCEL_FROM_RECEIVER: Self = Self::CancelFromReceiver;
    /// Alias for [`Self::CancelAckToReceiver`].
    pub const CANCEL_ACK_TO_RECEIVER: Self = Self::CancelAckToReceiver;

    /// Returns the raw 4-bit segment type code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        *self as u8
    }

    /// Parses a 4-bit segment type code according to RFC 5326 §3.1.2.
    ///
    /// # Errors
    /// Returns [`LtpParseError::InvalidSegmentType`] if the code is undefined (5, 6, 10, 11).
    pub fn from_u8(code: u8) -> Result<Self, LtpParseError> {
        match code {
            0 => Ok(Self::RedData),
            1 => Ok(Self::RedDataCheckpoint),
            2 => Ok(Self::RedDataCheckpointEorp),
            3 => Ok(Self::RedDataCheckpointEorpEob),
            4 => Ok(Self::GreenData),
            7 => Ok(Self::GreenDataEob),
            8 => Ok(Self::Report),
            9 => Ok(Self::ReportAck),
            12 => Ok(Self::CancelFromSender),
            13 => Ok(Self::CancelAckToSender),
            14 => Ok(Self::CancelFromReceiver),
            15 => Ok(Self::CancelAckToReceiver),
            undefined => Err(LtpParseError::InvalidSegmentType(undefined)),
        }
    }

    /// Returns true if this segment is a data segment (types 0, 1, 2, 3, 4, 7).
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(
            self,
            Self::RedData
                | Self::RedDataCheckpoint
                | Self::RedDataCheckpointEorp
                | Self::RedDataCheckpointEorpEob
                | Self::GreenData
                | Self::GreenDataEob
        )
    }

    /// Returns true if this segment is a checkpoint segment (types 1, 2, 3).
    #[must_use]
    pub const fn is_checkpoint(&self) -> bool {
        matches!(
            self,
            Self::RedDataCheckpoint | Self::RedDataCheckpointEorp | Self::RedDataCheckpointEorpEob
        )
    }

    /// Returns true if this segment contains red-part data (types 0, 1, 2, 3).
    #[must_use]
    pub const fn is_red(&self) -> bool {
        matches!(
            self,
            Self::RedData
                | Self::RedDataCheckpoint
                | Self::RedDataCheckpointEorp
                | Self::RedDataCheckpointEorpEob
        )
    }

    /// Returns true if this segment contains green-part data (types 4, 7).
    #[must_use]
    pub const fn is_green(&self) -> bool {
        matches!(self, Self::GreenData | Self::GreenDataEob)
    }

    /// Returns true if this segment marks the End of Red Part (EORP, types 2, 3).
    #[must_use]
    pub const fn is_eorp(&self) -> bool {
        matches!(
            self,
            Self::RedDataCheckpointEorp | Self::RedDataCheckpointEorpEob
        )
    }

    /// Returns true if this segment marks the End of Block (EOB, types 3, 7).
    #[must_use]
    pub const fn is_eob(&self) -> bool {
        matches!(self, Self::RedDataCheckpointEorpEob | Self::GreenDataEob)
    }

    /// Returns true if this segment is a Report Segment (RS, type 8).
    #[must_use]
    pub const fn is_report(&self) -> bool {
        matches!(self, Self::Report)
    }

    /// Returns true if this segment is a Report-Acknowledgment Segment (RAx, type 9).
    #[must_use]
    pub const fn is_report_ack(&self) -> bool {
        matches!(self, Self::ReportAck)
    }

    /// Returns true if this segment is a Cancellation Segment (CS / CR, types 12, 14).
    #[must_use]
    pub const fn is_cancel(&self) -> bool {
        matches!(self, Self::CancelFromSender | Self::CancelFromReceiver)
    }

    /// Returns true if this segment is a Cancellation-Acknowledgment Segment (CAS / CAR, types 13, 15).
    #[must_use]
    pub const fn is_cancel_ack(&self) -> bool {
        matches!(self, Self::CancelAckToSender | Self::CancelAckToReceiver)
    }
}

impl PartialEq<u8> for SegmentType {
    fn eq(&self, other: &u8) -> bool {
        (*self as u8) == *other
    }
}

impl PartialEq<SegmentType> for u8 {
    fn eq(&self, other: &SegmentType) -> bool {
        *self == (*other as u8)
    }
}

impl From<SegmentType> for u8 {
    fn from(st: SegmentType) -> Self {
        st as u8
    }
}

impl TryFrom<u8> for SegmentType {
    type Error = LtpParseError;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        Self::from_u8(code)
    }
}

impl fmt::Display for SegmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RedData => write!(f, "red_data"),
            Self::RedDataCheckpoint => write!(f, "red_data_checkpoint"),
            Self::RedDataCheckpointEorp => write!(f, "red_data_checkpoint_eorp"),
            Self::RedDataCheckpointEorpEob => write!(f, "red_data_checkpoint_eorp_eob"),
            Self::GreenData => write!(f, "green_data"),
            Self::GreenDataUndefined5 => write!(f, "green_data_undefined_5"),
            Self::GreenDataUndefined6 => write!(f, "green_data_undefined_6"),
            Self::GreenDataEob => write!(f, "green_data_eob"),
            Self::Report => write!(f, "report"),
            Self::ReportAck => write!(f, "report_ack"),
            Self::ControlUndefined10 => write!(f, "control_undefined_10"),
            Self::ControlUndefined11 => write!(f, "control_undefined_11"),
            Self::CancelFromSender => write!(f, "cancel_from_sender"),
            Self::CancelAckToSender => write!(f, "cancel_ack_to_sender"),
            Self::CancelFromReceiver => write!(f, "cancel_from_receiver"),
            Self::CancelAckToReceiver => write!(f, "cancel_ack_to_receiver"),
        }
    }
}

/// Header or trailer extension in Type-Length-Value (TLV) format (RFC 5326 §3.1.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionTlv {
    /// 1-octet extension tag.
    pub tag: u8,
    /// Extension length in octets.
    pub length: u64,
    /// Extension value bytes.
    pub value: Vec<u8>,
}

/// Reception claim in a Report Segment (RS) (RFC 5326 §3.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReceptionClaim {
    /// Offset from the lower bound of the RS.
    pub offset: u64,
    /// Number of contiguous successfully received octets.
    pub length: u64,
}

/// Unique session identifier composed of sender engine ID and session number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId {
    /// Sender's Engine ID.
    pub session_originator_engine_id: u64,
    /// Unique session number assigned by sender.
    pub session_number: u64,
}

/// Parsed representation of an LTP Segment Header (RFC 5326 §3.1, §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtpSegmentHeader {
    /// 4-bit LTP version number (must be 0 for RFC 5326).
    pub version: u8,
    /// 4-bit segment type.
    pub segment_type: SegmentType,
    /// Session Originator Engine ID.
    pub session_originator_engine_id: u64,
    /// Alias for [`Self::session_originator_engine_id`].
    pub session_originator: u64,
    /// Unique session number.
    pub session_number: u64,
    /// Number of header extensions (0–15).
    pub header_extensions_count: u8,
    /// Number of trailer extensions (0–15).
    pub trailer_extensions_count: u8,
    /// Parsed header extensions.
    pub header_extensions: Vec<ExtensionTlv>,
    /// Parsed trailer extensions.
    pub trailer_extensions: Vec<ExtensionTlv>,
    /// Client Service ID (present in data segments).
    pub client_service_id: Option<u64>,
    /// Block byte offset (present in data segments).
    pub offset: Option<u64>,
    /// Client service data length in octets (present in data segments).
    pub length: Option<u64>,
    /// Checkpoint serial number (present in checkpoint segments and RS).
    pub checkpoint_serial_number: Option<u64>,
    /// Alias for [`Self::checkpoint_serial_number`].
    pub checkpoint_serial: Option<u64>,
    /// Report serial number (present in checkpoint segments, RS, and RAx).
    pub report_serial_number: Option<u64>,
    /// Alias for [`Self::report_serial_number`].
    pub report_serial: Option<u64>,
    /// Upper bound of block scope (present in RS).
    pub report_upper_bound: Option<u64>,
    /// Lower bound of block scope (present in RS).
    pub report_lower_bound: Option<u64>,
    /// Reception claims (present in RS).
    pub reception_claims: Vec<ReceptionClaim>,
    /// Cancellation reason code (present in CS / CR).
    pub cancel_reason_code: Option<u8>,
    /// Total header length in octets up to the payload / content.
    pub header_length: usize,
    /// Client service data payload bytes, if present.
    pub client_data: Vec<u8>,
}

/// Alias for [`LtpSegmentHeader`].
pub type LtpHeader = LtpSegmentHeader;
/// Alias for [`LtpSegmentHeader`].
pub type LtpSegment = LtpSegmentHeader;

impl LtpSegmentHeader {
    /// Returns the LTP protocol version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the segment type.
    #[must_use]
    pub const fn segment_type(&self) -> SegmentType {
        self.segment_type
    }

    /// Returns the raw segment type code.
    #[must_use]
    pub const fn segment_type_code(&self) -> u8 {
        self.segment_type.code()
    }

    /// Returns the session originator engine ID.
    #[must_use]
    pub const fn session_originator_engine_id(&self) -> u64 {
        self.session_originator_engine_id
    }

    /// Returns the session originator engine ID (alias).
    #[must_use]
    pub const fn session_originator(&self) -> u64 {
        self.session_originator
    }

    /// Returns the session number.
    #[must_use]
    pub const fn session_number(&self) -> u64 {
        self.session_number
    }

    /// Returns the client service ID, if present.
    #[must_use]
    pub const fn client_service_id(&self) -> Option<u64> {
        self.client_service_id
    }

    /// Returns the block offset, if present.
    #[must_use]
    pub const fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Returns the data length, if present.
    #[must_use]
    pub const fn length(&self) -> Option<u64> {
        self.length
    }

    /// Returns the checkpoint serial number, if present.
    #[must_use]
    pub const fn checkpoint_serial_number(&self) -> Option<u64> {
        self.checkpoint_serial_number
    }

    /// Returns the checkpoint serial number (alias), if present.
    #[must_use]
    pub const fn checkpoint_serial(&self) -> Option<u64> {
        self.checkpoint_serial
    }

    /// Returns the report serial number, if present.
    #[must_use]
    pub const fn report_serial_number(&self) -> Option<u64> {
        self.report_serial_number
    }

    /// Returns the report serial number (alias), if present.
    #[must_use]
    pub const fn report_serial(&self) -> Option<u64> {
        self.report_serial
    }

    /// Returns true if this segment is a checkpoint.
    #[must_use]
    pub const fn is_checkpoint(&self) -> bool {
        self.segment_type.is_checkpoint()
    }

    /// Returns true if this segment is a data segment.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        self.segment_type.is_data()
    }

    /// Returns true if this segment is marked End of Red Part.
    #[must_use]
    pub const fn is_eorp(&self) -> bool {
        self.segment_type.is_eorp()
    }

    /// Returns true if this segment is marked End of Block.
    #[must_use]
    pub const fn is_eob(&self) -> bool {
        self.segment_type.is_eob()
    }

    /// Returns true if this segment is a Report Segment.
    #[must_use]
    pub const fn is_report(&self) -> bool {
        self.segment_type.is_report()
    }

    /// Returns true if this segment is a Report Acknowledgment.
    #[must_use]
    pub const fn is_report_ack(&self) -> bool {
        self.segment_type.is_report_ack()
    }

    /// Returns true if this segment is a Cancellation Segment.
    #[must_use]
    pub const fn is_cancel(&self) -> bool {
        self.segment_type.is_cancel()
    }

    /// Returns true if this segment is a Cancellation Acknowledgment.
    #[must_use]
    pub const fn is_cancel_ack(&self) -> bool {
        self.segment_type.is_cancel_ack()
    }

    /// Returns the header length in octets.
    #[must_use]
    pub const fn header_length(&self) -> usize {
        self.header_length
    }

    /// Returns a slice of the client payload bytes.
    #[must_use]
    pub fn client_data(&self) -> &[u8] {
        &self.client_data
    }

    /// Converts this segment to a typed [`LtpDataSegment`] if it carries client data.
    ///
    /// # Errors
    /// Returns [`LtpParseError::Malformed`] if the segment is not a data segment or required
    /// data segment fields are missing.
    pub fn to_data_segment(&self) -> Result<LtpDataSegment, LtpParseError> {
        if !self.segment_type.is_data() {
            return Err(LtpParseError::Malformed(format!(
                "segment type {:?} is not a data segment",
                self.segment_type
            )));
        }

        let client_service_id = self.client_service_id.ok_or_else(|| {
            LtpParseError::Malformed("missing client service ID in data segment".into())
        })?;
        let offset = self
            .offset
            .ok_or_else(|| LtpParseError::Malformed("missing offset in data segment".into()))?;
        let length = self
            .length
            .ok_or_else(|| LtpParseError::Malformed("missing length in data segment".into()))?;

        Ok(LtpDataSegment {
            version: self.version,
            segment_type: self.segment_type,
            session_originator_engine_id: self.session_originator_engine_id,
            session_originator: self.session_originator,
            session_number: self.session_number,
            client_service_id,
            offset,
            length,
            checkpoint_serial_number: self.checkpoint_serial_number,
            checkpoint_serial: self.checkpoint_serial,
            report_serial_number: self.report_serial_number,
            report_serial: self.report_serial,
            client_data: self.client_data.clone(),
        })
    }

    /// Encodes this segment into RFC 5326 wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Control byte: 4 bits version, 4 bits segment type
        let ctrl = ((self.version & 0x0F) << 4) | (self.segment_type.code() & 0x0F);
        buf.push(ctrl);

        // Session ID
        buf.extend_from_slice(&encode_sdnv(self.session_originator_engine_id));
        buf.extend_from_slice(&encode_sdnv(self.session_number));

        // Extensions count: 4 bits header, 4 bits trailer
        let ext_cnt =
            ((self.header_extensions_count & 0x0F) << 4) | (self.trailer_extensions_count & 0x0F);
        buf.push(ext_cnt);

        // Header extensions
        for ext in &self.header_extensions {
            buf.push(ext.tag);
            buf.extend_from_slice(&encode_sdnv(ext.value.len() as u64));
            buf.extend_from_slice(&ext.value);
        }

        // Segment Content
        if self.segment_type.is_data() {
            buf.extend_from_slice(&encode_sdnv(self.client_service_id.unwrap_or(0)));
            buf.extend_from_slice(&encode_sdnv(self.offset.unwrap_or(0)));
            buf.extend_from_slice(&encode_sdnv(
                self.length.unwrap_or(self.client_data.len() as u64),
            ));
            if self.segment_type.is_checkpoint() {
                buf.extend_from_slice(&encode_sdnv(self.checkpoint_serial_number.unwrap_or(0)));
                buf.extend_from_slice(&encode_sdnv(self.report_serial_number.unwrap_or(0)));
            }
            buf.extend_from_slice(&self.client_data);
        } else if self.segment_type.is_report() {
            buf.extend_from_slice(&encode_sdnv(self.report_serial_number.unwrap_or(0)));
            buf.extend_from_slice(&encode_sdnv(self.checkpoint_serial_number.unwrap_or(0)));
            buf.extend_from_slice(&encode_sdnv(self.report_upper_bound.unwrap_or(0)));
            buf.extend_from_slice(&encode_sdnv(self.report_lower_bound.unwrap_or(0)));
            buf.extend_from_slice(&encode_sdnv(self.reception_claims.len() as u64));
            for claim in &self.reception_claims {
                buf.extend_from_slice(&encode_sdnv(claim.offset));
                buf.extend_from_slice(&encode_sdnv(claim.length));
            }
        } else if self.segment_type.is_report_ack() {
            buf.extend_from_slice(&encode_sdnv(self.report_serial_number.unwrap_or(0)));
        } else if self.segment_type.is_cancel() {
            buf.push(self.cancel_reason_code.unwrap_or(0));
        }

        // Trailer extensions
        for ext in &self.trailer_extensions {
            buf.push(ext.tag);
            buf.extend_from_slice(&encode_sdnv(ext.value.len() as u64));
            buf.extend_from_slice(&ext.value);
        }

        buf
    }
}

/// Parsed representation of an LTP Data Segment (RFC 5326 §3.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtpDataSegment {
    /// 4-bit LTP version (0).
    pub version: u8,
    /// 4-bit Segment Type.
    pub segment_type: SegmentType,
    /// Session Originator Engine ID.
    pub session_originator_engine_id: u64,
    /// Alias for [`Self::session_originator_engine_id`].
    pub session_originator: u64,
    /// Unique session number.
    pub session_number: u64,
    /// Upper-level client service ID (e.g. 1 for Bundle Protocol).
    pub client_service_id: u64,
    /// Block offset in octets.
    pub offset: u64,
    /// Ensuing client service data length in octets.
    pub length: u64,
    /// Checkpoint serial number (present if checkpoint segment).
    pub checkpoint_serial_number: Option<u64>,
    /// Alias for [`Self::checkpoint_serial_number`].
    pub checkpoint_serial: Option<u64>,
    /// Report serial number (present if checkpoint segment).
    pub report_serial_number: Option<u64>,
    /// Alias for [`Self::report_serial_number`].
    pub report_serial: Option<u64>,
    /// Client service data payload bytes.
    pub client_data: Vec<u8>,
}

impl LtpDataSegment {
    /// Returns the LTP protocol version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the segment type.
    #[must_use]
    pub const fn segment_type(&self) -> SegmentType {
        self.segment_type
    }

    /// Returns the session originator engine ID.
    #[must_use]
    pub const fn session_originator_engine_id(&self) -> u64 {
        self.session_originator_engine_id
    }

    /// Returns the session originator engine ID (alias).
    #[must_use]
    pub const fn session_originator(&self) -> u64 {
        self.session_originator
    }

    /// Returns the session number.
    #[must_use]
    pub const fn session_number(&self) -> u64 {
        self.session_number
    }

    /// Returns the client service ID.
    #[must_use]
    pub const fn client_service_id(&self) -> u64 {
        self.client_service_id
    }

    /// Returns the block offset.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the data length.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Returns the checkpoint serial number, if present.
    #[must_use]
    pub const fn checkpoint_serial_number(&self) -> Option<u64> {
        self.checkpoint_serial_number
    }

    /// Returns the checkpoint serial number (alias), if present.
    #[must_use]
    pub const fn checkpoint_serial(&self) -> Option<u64> {
        self.checkpoint_serial
    }

    /// Returns the report serial number, if present.
    #[must_use]
    pub const fn report_serial_number(&self) -> Option<u64> {
        self.report_serial_number
    }

    /// Returns the report serial number (alias), if present.
    #[must_use]
    pub const fn report_serial(&self) -> Option<u64> {
        self.report_serial
    }

    /// Returns true if this data segment is a checkpoint.
    #[must_use]
    pub const fn is_checkpoint(&self) -> bool {
        self.segment_type.is_checkpoint()
    }

    /// Encodes this data segment into RFC 5326 wire bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let ctrl = ((self.version & 0x0F) << 4) | (self.segment_type.code() & 0x0F);
        buf.push(ctrl);
        buf.extend_from_slice(&encode_sdnv(self.session_originator_engine_id));
        buf.extend_from_slice(&encode_sdnv(self.session_number));
        buf.push(0x00); // 0 extensions
        buf.extend_from_slice(&encode_sdnv(self.client_service_id));
        buf.extend_from_slice(&encode_sdnv(self.offset));
        buf.extend_from_slice(&encode_sdnv(self.length));
        if self.segment_type.is_checkpoint() {
            buf.extend_from_slice(&encode_sdnv(self.checkpoint_serial_number.unwrap_or(0)));
            buf.extend_from_slice(&encode_sdnv(self.report_serial_number.unwrap_or(0)));
        }
        buf.extend_from_slice(&self.client_data);
        buf
    }
}

/// Evaluation status indicating the outcome of inspecting an LTP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LtpParseStatus {
    /// Payload is a valid LTP segment.
    Valid,
    /// Payload is arbitrary non-LTP data (e.g. non-zero version or unknown structure).
    NotLtp,
    /// Payload appears to be LTP but has malformed structure or fields.
    MalformedLtp,
    /// Input is truncated before the header or segment completed.
    Truncated,
}

impl LtpParseStatus {
    /// Constant alias for [`Self::MalformedLtp`].
    pub const MALFORMED: Self = Self::MalformedLtp;

    /// Constant alias for [`Self::MalformedLtp`].
    #[allow(non_upper_case_globals)]
    pub const Malformed: Self = Self::MalformedLtp;

    /// Returns true if the status is [`Self::Valid`].
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns true if the payload is not LTP traffic.
    #[must_use]
    pub const fn is_not_ltp(&self) -> bool {
        matches!(self, Self::NotLtp)
    }

    /// Returns true if the status is malformed.
    #[must_use]
    pub const fn is_malformed(&self) -> bool {
        matches!(self, Self::MalformedLtp)
    }

    /// Returns true if the status is truncated.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated)
    }

    /// Returns true if the status is invalid (i.e. not [`Self::Valid`]).
    #[must_use]
    pub const fn is_invalid(&self) -> bool {
        !self.is_valid()
    }
}

impl fmt::Display for LtpParseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::NotLtp => write!(f, "not_ltp"),
            Self::MalformedLtp => write!(f, "malformed_ltp"),
            Self::Truncated => write!(f, "truncated"),
        }
    }
}

/// Errors encountered when decoding SDNVs or parsing LTP segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LtpParseError {
    /// Input buffer is truncated before header completion or before SDNV continuation bit clears.
    Truncated {
        /// Number of bytes expected or needed.
        expected: usize,
        /// Number of bytes actually available.
        actual: usize,
    },
    /// Non-zero LTP version encountered (expected 0 for RFC 5326).
    InvalidVersion(u8),
    /// Undefined or unsupported segment type code.
    InvalidSegmentType(u8),
    /// SDNV value exceeds 64-bit integer limits.
    SdnvOverflow,
    /// Data is not an LTP segment.
    NotLtp(String),
    /// Malformed LTP segment structure or encoding.
    Malformed(String),
}

impl LtpParseError {
    /// Returns true if the error indicates truncated input.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        matches!(self, Self::Truncated { .. })
    }

    /// Returns true if the error distinguishes an invalid LTP version.
    #[must_use]
    pub const fn is_invalid_version(&self) -> bool {
        matches!(self, Self::InvalidVersion(_))
    }

    /// Returns true if the error indicates non-LTP traffic.
    #[must_use]
    pub const fn is_not_ltp(&self) -> bool {
        matches!(self, Self::NotLtp(_))
    }

    /// Returns the corresponding [`LtpParseStatus`].
    #[must_use]
    pub fn status(&self) -> LtpParseStatus {
        match self {
            Self::Truncated { .. } => LtpParseStatus::Truncated,
            Self::InvalidVersion(_) | Self::NotLtp(_) => LtpParseStatus::NotLtp,
            Self::InvalidSegmentType(_) | Self::SdnvOverflow | Self::Malformed(_) => {
                LtpParseStatus::MalformedLtp
            }
        }
    }
}

impl fmt::Display for LtpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { expected, actual } => {
                write!(
                    f,
                    "truncated input: expected at least {expected} bytes, but only {actual} bytes available"
                )
            }
            Self::InvalidVersion(v) => {
                write!(f, "invalid LTP version: {v} (expected version 0)")
            }
            Self::InvalidSegmentType(t) => {
                write!(f, "invalid LTP segment type code: {t}")
            }
            Self::SdnvOverflow => {
                write!(f, "SDNV value overflow: exceeds 64-bit capacity")
            }
            Self::NotLtp(msg) => {
                write!(f, "not LTP traffic: {msg}")
            }
            Self::Malformed(msg) => {
                write!(f, "malformed LTP segment: {msg}")
            }
        }
    }
}

impl std::error::Error for LtpParseError {}

/// Decodes a Self-Delimiting Numeric Value (SDNV) from a byte slice (RFC 5326 §2).
///
/// Returns `Ok((value, bytes_consumed))`.
///
/// # Errors
/// - Returns [`LtpParseError::Truncated`] if the input buffer ends before the continuation bit (MSB) clears.
/// - Returns [`LtpParseError::SdnvOverflow`] if the value exceeds 64 bits.
pub fn decode_sdnv(bytes: &[u8]) -> Result<(u64, usize), LtpParseError> {
    if bytes.is_empty() {
        return Err(LtpParseError::Truncated {
            expected: 1,
            actual: 0,
        });
    }

    let mut val: u64 = 0;
    let mut bytes_read = 0;

    for &b in bytes {
        bytes_read += 1;
        // Verify value will not overflow 64-bit integer when shifting left 7 bits
        if val > (u64::MAX >> 7) {
            return Err(LtpParseError::SdnvOverflow);
        }
        val = (val << 7) | u64::from(b & 0x7F);

        if (b & 0x80) == 0 {
            // Continuation bit cleared: complete SDNV
            return Ok((val, bytes_read));
        }

        // Limit SDNV to 10 bytes (10 * 7 = 70 bits)
        if bytes_read >= 10 {
            return Err(LtpParseError::SdnvOverflow);
        }
    }

    // Buffer truncated before continuation bit cleared
    Err(LtpParseError::Truncated {
        expected: bytes_read + 1,
        actual: bytes_read,
    })
}

/// Encodes an unsigned 64-bit integer into SDNV octets (RFC 5326 §2).
#[must_use]
pub fn encode_sdnv(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }

    let mut chunks = Vec::with_capacity(10);
    let mut v = val;
    while v > 0 {
        chunks.push((v & 0x7F) as u8);
        v >>= 7;
    }
    chunks.reverse();

    let len = chunks.len();
    for chunk in chunks.iter_mut().take(len.saturating_sub(1)) {
        *chunk |= 0x80;
    }
    chunks
}

/// Parses an LTP segment from raw bytes, extracting all header fields and payload (RFC 5326).
///
/// # Errors
/// Returns [`LtpParseError`] if the segment is truncated, has an invalid version, undefined type,
/// or malformed fields.
pub fn parse_segment(data: &[u8]) -> Result<LtpSegmentHeader, LtpParseError> {
    parse_segment_internal(data, true)
}

/// Parses an LTP segment header without requiring the full client data payload to be present.
///
/// # Errors
/// Returns [`LtpParseError`] if header fields are truncated or invalid.
pub fn parse_segment_header(data: &[u8]) -> Result<LtpSegmentHeader, LtpParseError> {
    parse_segment_internal(data, false)
}

/// Alias for [`parse_segment`].
pub fn parse_ltp_segment(data: &[u8]) -> Result<LtpSegmentHeader, LtpParseError> {
    parse_segment(data)
}

/// Alias for [`parse_segment_header`].
pub fn parse_ltp_header(data: &[u8]) -> Result<LtpSegmentHeader, LtpParseError> {
    parse_segment_header(data)
}

/// Parses a valid LTP data segment, extracting version 0, segment type, session originator,
/// session number, client service ID, offset, length, and optional checkpoint/report serials.
///
/// # Errors
/// Returns [`LtpParseError`] if the segment is not a data segment or is invalid.
pub fn parse_data_segment(data: &[u8]) -> Result<LtpDataSegment, LtpParseError> {
    let seg = parse_segment(data)?;
    seg.to_data_segment()
}

/// Evaluates raw payload bytes and returns the classified [`LtpParseStatus`].
#[must_use]
pub fn evaluate_payload(data: &[u8]) -> LtpParseStatus {
    if data.is_empty() {
        return LtpParseStatus::Truncated;
    }

    match parse_segment(data) {
        Ok(_) => LtpParseStatus::Valid,
        Err(err) => err.status(),
    }
}

/// Alias for [`evaluate_payload`].
#[must_use]
pub fn evaluate_ltp_payload(data: &[u8]) -> LtpParseStatus {
    evaluate_payload(data)
}

/// Evaluates raw payload bytes, returning both [`LtpParseStatus`] and optional [`LtpSegmentHeader`].
#[must_use]
pub fn evaluate_segment_header(data: &[u8]) -> (LtpParseStatus, Option<LtpSegmentHeader>) {
    match parse_segment_header(data) {
        Ok(header) => (LtpParseStatus::Valid, Some(header)),
        Err(err) => (err.status(), None),
    }
}

fn parse_segment_internal(
    data: &[u8],
    require_full_payload: bool,
) -> Result<LtpSegmentHeader, LtpParseError> {
    if data.is_empty() {
        return Err(LtpParseError::Truncated {
            expected: 1,
            actual: 0,
        });
    }

    let mut cursor = 0;

    // 1. Control byte (RFC 5326 §3.1)
    let ctrl_byte = data[cursor];
    cursor += 1;

    let version = (ctrl_byte >> 4) & 0x0F;
    if version != LTP_VERSION_0 {
        return Err(LtpParseError::InvalidVersion(version));
    }

    let type_code = ctrl_byte & 0x0F;
    let segment_type = SegmentType::from_u8(type_code)?;

    // 2. Session ID (RFC 5326 §3.1)
    if cursor >= data.len() {
        return Err(LtpParseError::Truncated {
            expected: cursor + 1,
            actual: data.len(),
        });
    }

    let (session_originator, sdnv_len) = decode_sdnv(&data[cursor..])?;
    cursor += sdnv_len;

    if cursor >= data.len() {
        return Err(LtpParseError::Truncated {
            expected: cursor + 1,
            actual: data.len(),
        });
    }

    let (session_number, sdnv_len) = decode_sdnv(&data[cursor..])?;
    cursor += sdnv_len;

    // 3. Extensions Count (RFC 5326 §3.1.4)
    if cursor >= data.len() {
        return Err(LtpParseError::Truncated {
            expected: cursor + 1,
            actual: data.len(),
        });
    }

    let ext_byte = data[cursor];
    cursor += 1;
    let header_extensions_count = (ext_byte >> 4) & 0x0F;
    let trailer_extensions_count = ext_byte & 0x0F;

    // 4. Header Extensions
    let mut header_extensions = Vec::with_capacity(header_extensions_count as usize);
    for _ in 0..header_extensions_count {
        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let tag = data[cursor];
        cursor += 1;

        let (ext_len, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;

        let ext_len_usize = ext_len as usize;
        if cursor + ext_len_usize > data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + ext_len_usize,
                actual: data.len(),
            });
        }

        let value = data[cursor..cursor + ext_len_usize].to_vec();
        cursor += ext_len_usize;

        header_extensions.push(ExtensionTlv {
            tag,
            length: ext_len,
            value,
        });
    }

    // 5. Segment Content (RFC 5326 §3.2)
    let mut client_service_id = None;
    let mut offset = None;
    let mut length = None;
    let mut checkpoint_serial_number = None;
    let mut report_serial_number = None;
    let mut report_upper_bound = None;
    let mut report_lower_bound = None;
    let mut reception_claims = Vec::new();
    let mut cancel_reason_code = None;

    if segment_type.is_data() {
        // Data Segment Content (RFC 5326 §3.2.1)
        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (cid, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        client_service_id = Some(cid);

        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (off, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        offset = Some(off);

        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (len, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        length = Some(len);

        if segment_type.is_checkpoint() {
            // Checkpoint segments carry CP serial number and Report serial number
            if cursor >= data.len() {
                return Err(LtpParseError::Truncated {
                    expected: cursor + 1,
                    actual: data.len(),
                });
            }
            let (cp_serial, sdnv_len) = decode_sdnv(&data[cursor..])?;
            cursor += sdnv_len;
            checkpoint_serial_number = Some(cp_serial);

            if cursor >= data.len() {
                return Err(LtpParseError::Truncated {
                    expected: cursor + 1,
                    actual: data.len(),
                });
            }
            let (rpt_serial, sdnv_len) = decode_sdnv(&data[cursor..])?;
            cursor += sdnv_len;
            report_serial_number = Some(rpt_serial);
        }
    } else if segment_type.is_report() {
        // Report Segment Content (RFC 5326 §3.2.2)
        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (rpt_serial, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        report_serial_number = Some(rpt_serial);

        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (cp_serial, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        checkpoint_serial_number = Some(cp_serial);

        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (upper, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        report_upper_bound = Some(upper);

        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (lower, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        report_lower_bound = Some(lower);

        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (claim_cnt, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;

        for _ in 0..claim_cnt {
            if cursor >= data.len() {
                return Err(LtpParseError::Truncated {
                    expected: cursor + 1,
                    actual: data.len(),
                });
            }
            let (claim_off, sdnv_len) = decode_sdnv(&data[cursor..])?;
            cursor += sdnv_len;

            if cursor >= data.len() {
                return Err(LtpParseError::Truncated {
                    expected: cursor + 1,
                    actual: data.len(),
                });
            }
            let (claim_len, sdnv_len) = decode_sdnv(&data[cursor..])?;
            cursor += sdnv_len;

            reception_claims.push(ReceptionClaim {
                offset: claim_off,
                length: claim_len,
            });
        }
    } else if segment_type.is_report_ack() {
        // Report Acknowledgment Segment Content (RFC 5326 §3.2.3)
        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let (rpt_serial, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;
        report_serial_number = Some(rpt_serial);
    } else if segment_type.is_cancel() {
        // Cancel Segment Content (RFC 5326 §3.2.4)
        if cursor >= data.len() {
            return Err(LtpParseError::Truncated {
                expected: cursor + 1,
                actual: data.len(),
            });
        }
        let reason = data[cursor];
        cursor += 1;
        cancel_reason_code = Some(reason);
    }

    let header_length = cursor;
    let mut client_data = Vec::new();

    // If data segment, extract payload
    if segment_type.is_data() {
        if let Some(decl_len) = length {
            let decl_len_usize = decl_len as usize;
            if require_full_payload && cursor + decl_len_usize > data.len() {
                return Err(LtpParseError::Truncated {
                    expected: cursor + decl_len_usize,
                    actual: data.len(),
                });
            }
            let available = (data.len() - cursor).min(decl_len_usize);
            client_data = data[cursor..cursor + available].to_vec();
            cursor += available;
        }
    }

    // 6. Trailer Extensions
    let mut trailer_extensions = Vec::with_capacity(trailer_extensions_count as usize);
    for _ in 0..trailer_extensions_count {
        if cursor >= data.len() {
            if require_full_payload {
                return Err(LtpParseError::Truncated {
                    expected: cursor + 1,
                    actual: data.len(),
                });
            }
            break;
        }
        let tag = data[cursor];
        cursor += 1;

        let (ext_len, sdnv_len) = decode_sdnv(&data[cursor..])?;
        cursor += sdnv_len;

        let ext_len_usize = ext_len as usize;
        if cursor + ext_len_usize > data.len() {
            if require_full_payload {
                return Err(LtpParseError::Truncated {
                    expected: cursor + ext_len_usize,
                    actual: data.len(),
                });
            }
            break;
        }

        let value = data[cursor..cursor + ext_len_usize].to_vec();
        cursor += ext_len_usize;

        trailer_extensions.push(ExtensionTlv {
            tag,
            length: ext_len,
            value,
        });
    }

    Ok(LtpSegmentHeader {
        version,
        segment_type,
        session_originator_engine_id: session_originator,
        session_originator,
        session_number,
        header_extensions_count,
        trailer_extensions_count,
        header_extensions,
        trailer_extensions,
        client_service_id,
        offset,
        length,
        checkpoint_serial_number,
        checkpoint_serial: checkpoint_serial_number,
        report_serial_number,
        report_serial: report_serial_number,
        report_upper_bound,
        report_lower_bound,
        reception_claims,
        cancel_reason_code,
        header_length,
        client_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc5326_sdnv_reference_vectors() {
        // RFC 5326 §2 (20) reference vectors:
        // 0xABC  -> [0x95, 0x3C]
        let (val, len) = decode_sdnv(&[0x95, 0x3C]).expect("0xABC must decode");
        assert_eq!(val, 0xABC);
        assert_eq!(len, 2);
        assert_eq!(encode_sdnv(0xABC), vec![0x95, 0x3C]);

        // 0x1234 -> [0xA4, 0x34]
        let (val, len) = decode_sdnv(&[0xA4, 0x34]).expect("0x1234 must decode");
        assert_eq!(val, 0x1234);
        assert_eq!(len, 2);
        assert_eq!(encode_sdnv(0x1234), vec![0xA4, 0x34]);

        // 0x4234 -> [0x81, 0x84, 0x34]
        let (val, len) = decode_sdnv(&[0x81, 0x84, 0x34]).expect("0x4234 must decode");
        assert_eq!(val, 0x4234);
        assert_eq!(len, 3);
        assert_eq!(encode_sdnv(0x4234), vec![0x81, 0x84, 0x34]);

        // 0x7F   -> [0x7F]
        let (val, len) = decode_sdnv(&[0x7F]).expect("0x7F must decode");
        assert_eq!(val, 0x7F);
        assert_eq!(len, 1);
        assert_eq!(encode_sdnv(0x7F), vec![0x7F]);

        // 0x00   -> [0x00]
        let (val, len) = decode_sdnv(&[0x00]).expect("0x00 must decode");
        assert_eq!(val, 0);
        assert_eq!(len, 1);
        assert_eq!(encode_sdnv(0), vec![0x00]);

        // 0x80   -> [0x81, 0x00]
        let (val, len) = decode_sdnv(&[0x81, 0x00]).expect("0x80 must decode");
        assert_eq!(val, 0x80);
        assert_eq!(len, 2);
        assert_eq!(encode_sdnv(0x80), vec![0x81, 0x00]);
    }

    #[test]
    fn test_criterion1_parse_valid_ltp_data_segment_rfc5326() {
        // Valid LTP data segment:
        // Version 0, Type 0 (RedData)
        // Session Originator: 0xABC (encoded as [0x95, 0x3C])
        // Session Number: 0x1234 (encoded as [0xA4, 0x34])
        // Extensions Count: 0x00
        // Client Service ID: 1 (encoded as [0x01])
        // Offset: 1000 (encoded as [0x87, 0x68])
        // Length: 5 (encoded as [0x05])
        // Payload: "hello"
        let mut raw = vec![0x00];
        raw.extend_from_slice(&[0x95, 0x3C]); // session originator 0xABC
        raw.extend_from_slice(&[0xA4, 0x34]); // session number 0x1234
        raw.push(0x00); // 0 extensions
        raw.push(0x01); // client service id 1
        raw.extend_from_slice(&encode_sdnv(1000)); // offset 1000
        raw.push(0x05); // length 5
        raw.extend_from_slice(b"hello"); // 5 bytes payload

        let seg = parse_segment(&raw).expect("valid LTP data segment must parse");
        assert_eq!(seg.version, 0);
        assert_eq!(seg.version(), 0);
        assert_eq!(seg.segment_type, SegmentType::RedData);
        assert_eq!(seg.segment_type, 0);
        assert_eq!(seg.segment_type_code(), 0);
        assert_eq!(seg.session_originator_engine_id, 0xABC);
        assert_eq!(seg.session_originator, 0xABC);
        assert_eq!(seg.session_originator_engine_id(), 0xABC);
        assert_eq!(seg.session_originator(), 0xABC);
        assert_eq!(seg.session_number, 0x1234);
        assert_eq!(seg.session_number(), 0x1234);
        assert_eq!(seg.client_service_id, Some(1));
        assert_eq!(seg.client_service_id(), Some(1));
        assert_eq!(seg.offset, Some(1000));
        assert_eq!(seg.offset(), Some(1000));
        assert_eq!(seg.length, Some(5));
        assert_eq!(seg.length(), Some(5));
        assert_eq!(seg.client_data(), b"hello");

        // Also test parse_data_segment
        let data_seg = parse_data_segment(&raw).expect("parse_data_segment must succeed");
        assert_eq!(data_seg.version, 0);
        assert_eq!(data_seg.segment_type, SegmentType::RedData);
        assert_eq!(data_seg.session_originator_engine_id, 0xABC);
        assert_eq!(data_seg.session_originator, 0xABC);
        assert_eq!(data_seg.session_number, 0x1234);
        assert_eq!(data_seg.client_service_id, 1);
        assert_eq!(data_seg.offset, 1000);
        assert_eq!(data_seg.length, 5);
        assert_eq!(data_seg.client_data, b"hello");
    }

    #[test]
    fn test_criterion2_parse_checkpoint_segment_extracts_serials() {
        // LTP Checkpoint segment:
        // Version 0, Type 3 (RedDataCheckpointEorpEob)
        // Session Originator: 42
        // Session Number: 100
        // Extensions Count: 0x00
        // Client Service ID: 1
        // Offset: 0
        // Length: 4
        // Checkpoint Serial Number: 1001 (encoded as [0x87, 0x69])
        // Report Serial Number: 0 (encoded as [0x00])
        // Payload: "ping"
        let mut raw = vec![0x03];
        raw.extend_from_slice(&encode_sdnv(42));
        raw.extend_from_slice(&encode_sdnv(100));
        raw.push(0x00); // 0 extensions
        raw.push(0x01); // client service id 1
        raw.push(0x00); // offset 0
        raw.push(0x04); // length 4
        raw.extend_from_slice(&encode_sdnv(1001)); // checkpoint serial 1001
        raw.extend_from_slice(&encode_sdnv(0)); // report serial 0
        raw.extend_from_slice(b"ping");

        let seg = parse_segment(&raw).expect("valid checkpoint segment must parse");
        assert_eq!(seg.version, 0);
        assert_eq!(seg.segment_type, SegmentType::RedDataCheckpointEorpEob);
        assert_eq!(seg.segment_type, 3);
        assert!(seg.is_checkpoint());
        assert!(seg.is_eorp());
        assert!(seg.is_eob());
        assert_eq!(seg.checkpoint_serial_number, Some(1001));
        assert_eq!(seg.checkpoint_serial_number(), Some(1001));
        assert_eq!(seg.checkpoint_serial, Some(1001));
        assert_eq!(seg.checkpoint_serial(), Some(1001));
        assert_eq!(seg.report_serial_number, Some(0));
        assert_eq!(seg.report_serial_number(), Some(0));
        assert_eq!(seg.report_serial, Some(0));
        assert_eq!(seg.report_serial(), Some(0));

        let data_seg = parse_data_segment(&raw).expect("parse_data_segment must succeed");
        assert_eq!(data_seg.checkpoint_serial_number, Some(1001));
        assert_eq!(data_seg.report_serial_number, Some(0));
    }

    #[test]
    fn test_criterion3_truncated_sdnv_returns_truncated_error() {
        // SDNV byte with continuation bit (0x80) set, but buffer ends immediately
        let truncated_1 = [0x81];
        let err_1 = decode_sdnv(&truncated_1).expect_err("truncated SDNV must error");
        assert!(err_1.is_truncated());
        assert!(matches!(err_1, LtpParseError::Truncated { .. }));
        assert!(err_1.to_string().contains("truncated input"));

        // Multi-byte SDNV with continuation bit on all bytes
        let truncated_2 = [0x81, 0x82, 0x90];
        let err_2 = decode_sdnv(&truncated_2).expect_err("truncated multi-byte SDNV must error");
        assert!(err_2.is_truncated());
        assert!(matches!(err_2, LtpParseError::Truncated { .. }));
        assert!(err_2.to_string().contains("truncated input"));

        // Empty buffer
        let err_empty = decode_sdnv(&[]).expect_err("empty buffer must error");
        assert!(err_empty.is_truncated());
    }

    #[test]
    fn test_criterion4_non_zero_version_returns_invalid_version_error() {
        // First byte has non-zero version (e.g. version 1: 0x10)
        let raw = [0x10, 0x01, 0x01, 0x00];
        let err = parse_segment_header(&raw).expect_err("non-zero LTP version must error");
        assert!(err.is_invalid_version());
        assert_eq!(err, LtpParseError::InvalidVersion(1));
        assert!(err.to_string().contains("invalid LTP version: 1"));

        // Version 2 (0x20)
        let raw_v2 = [0x20, 0x01, 0x01, 0x00];
        let err_v2 = parse_segment(&raw_v2).expect_err("version 2 must error");
        assert!(err_v2.is_invalid_version());
        assert_eq!(err_v2, LtpParseError::InvalidVersion(2));
    }

    #[test]
    fn test_criterion5_evaluating_arbitrary_non_ltp_payloads() {
        let test_payloads: &[&[u8]] = &[
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello",
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
            &[0xFF, 0xFF, 0xFF, 0xFF],
            &[0x12, 0x34, 0x56, 0x78],
            &[0x05, 0x01, 0x01, 0x00], // Version 0, undefined type 5
            &[0x0A, 0x01, 0x01, 0x00], // Version 0, undefined type 10
            &[0x0B, 0x01, 0x01, 0x00], // Version 0, undefined type 11
        ];

        for payload in test_payloads {
            let status = evaluate_payload(payload);
            assert!(
                status.is_not_ltp() || status.is_malformed(),
                "arbitrary payload must return NotLtp or Malformed, got {status:?}"
            );
            assert!(!status.is_valid());

            let alias_status = evaluate_ltp_payload(payload);
            assert_eq!(alias_status, status);

            let (header_status, header_opt) = evaluate_segment_header(payload);
            assert_eq!(header_status, status);
            assert!(header_opt.is_none());
        }
    }

    #[test]
    fn test_round_trip_serialization() {
        let original = LtpSegmentHeader {
            version: 0,
            segment_type: SegmentType::RedDataCheckpoint,
            session_originator_engine_id: 12345,
            session_originator: 12345,
            session_number: 67890,
            header_extensions_count: 0,
            trailer_extensions_count: 0,
            header_extensions: Vec::new(),
            trailer_extensions: Vec::new(),
            client_service_id: Some(1),
            offset: Some(512),
            length: Some(11),
            checkpoint_serial_number: Some(99),
            checkpoint_serial: Some(99),
            report_serial_number: Some(0),
            report_serial: Some(0),
            report_upper_bound: None,
            report_lower_bound: None,
            reception_claims: Vec::new(),
            cancel_reason_code: None,
            header_length: 0,
            client_data: b"hello world".to_vec(),
        };

        let bytes = original.to_bytes();
        let parsed = parse_segment(&bytes).expect("round trip must parse");

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.segment_type, original.segment_type);
        assert_eq!(
            parsed.session_originator_engine_id,
            original.session_originator_engine_id
        );
        assert_eq!(parsed.session_number, original.session_number);
        assert_eq!(parsed.client_service_id, original.client_service_id);
        assert_eq!(parsed.offset, original.offset);
        assert_eq!(parsed.length, original.length);
        assert_eq!(
            parsed.checkpoint_serial_number,
            original.checkpoint_serial_number
        );
        assert_eq!(parsed.report_serial_number, original.report_serial_number);
        assert_eq!(parsed.client_data, original.client_data);
    }
}
