//! Diagnostic event model with a bounded, non-blocking event buffer (SPEC §8, §10).
//!
//! Provides structured packet inspection events, lifecycle stages, clock abstraction
//! for deterministic testing, rate limiting, and a non-blocking ring buffer that never
//! stalls packet forwarding threads.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::bpv7::{BundleParseStatus, CreationTimestamp, PrimaryBlock};
use crate::config::{ByteOrder, InspectionConfig, OperationalMode, SequenceConfig, TransportType};
use crate::ltp::{LtpParseStatus, LtpSegmentHeader, SegmentType};
use crate::srt::{
    PacketPosition, SrtControlHeader, SrtControlType, SrtDataHeader, SrtHeader, SrtPacketKind,
    SrtParseStatus,
};

/// Stage in packet lifecycle or diagnostic event category (SPEC §8, stages 2–6, drops, failures, and health).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStage {
    /// Stage 2: Packet received by a RER socket.
    #[serde(rename = "received")]
    Received,
    /// Stage 3: Packet classified and accepted by RER.
    #[serde(rename = "accepted")]
    Accepted,
    /// Stage 4: Packet routed or queued.
    #[serde(rename = "routed_or_queued")]
    RoutedOrQueued,
    /// Stage 5: Output send attempted.
    #[serde(rename = "send_attempted")]
    SendAttempted,
    /// Stage 6: Output send call succeeded.
    #[serde(rename = "send_succeeded")]
    SendSucceeded,
    /// Packet dropped due to full queue, rate limit, buffer contention, or policy.
    #[serde(rename = "dropped")]
    Dropped,
    /// Socket error, destination outage, or processing failure.
    #[serde(rename = "failure")]
    Failure,
    /// Relay or stream health state transition.
    #[serde(rename = "health_transition")]
    HealthTransition,
    /// Bundle Protocol (BPv7) passive inspection event (SPEC §14, §8).
    #[serde(rename = "bundle_inspection")]
    BundleInspection,
    /// Licklider Transmission Protocol (LTP) passive inspection event (SPEC §14, §8).
    #[serde(rename = "ltp_inspection")]
    LtpInspection,
    /// Secure Reliable Transport (SRT) passive inspection event (SPEC §14, §8).
    #[serde(rename = "srt_inspection")]
    SrtInspection,
    /// MAVLink passive inspection event (SPEC §14, §8).
    #[serde(rename = "mavlink_inspection")]
    MavlinkInspection,
}

pub type Stage = DiagnosticStage;

impl fmt::Display for DiagnosticStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Received => write!(f, "received"),
            Self::Accepted => write!(f, "accepted"),
            Self::RoutedOrQueued => write!(f, "routed_or_queued"),
            Self::SendAttempted => write!(f, "send_attempted"),
            Self::SendSucceeded => write!(f, "send_succeeded"),
            Self::Dropped => write!(f, "dropped"),
            Self::Failure => write!(f, "failure"),
            Self::HealthTransition => write!(f, "health_transition"),
            Self::BundleInspection => write!(f, "bundle_inspection"),
            Self::LtpInspection => write!(f, "ltp_inspection"),
            Self::SrtInspection => write!(f, "srt_inspection"),
            Self::MavlinkInspection => write!(f, "mavlink_inspection"),
        }
    }
}

impl FromStr for DiagnosticStage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "received" => Ok(Self::Received),
            "accepted" => Ok(Self::Accepted),
            "routed_or_queued" => Ok(Self::RoutedOrQueued),
            "send_attempted" => Ok(Self::SendAttempted),
            "send_succeeded" => Ok(Self::SendSucceeded),
            "dropped" => Ok(Self::Dropped),
            "failure" => Ok(Self::Failure),
            "health_transition" => Ok(Self::HealthTransition),
            "bundle_inspection" => Ok(Self::BundleInspection),
            "ltp_inspection" => Ok(Self::LtpInspection),
            "srt_inspection" => Ok(Self::SrtInspection),
            "mavlink_inspection" | "mavlink" => Ok(Self::MavlinkInspection),
            other => Err(format!("Unknown diagnostic stage: '{other}'")),
        }
    }
}

/// Trait allowing flexible construction of DTN creation timestamps.
pub trait IntoDtnTimestamp {
    /// Converts into a tuple of `(time_milliseconds, sequence_number)`.
    fn into_dtn_timestamp(self) -> (u64, u64);
}

impl IntoDtnTimestamp for u64 {
    fn into_dtn_timestamp(self) -> (u64, u64) {
        (self, 0)
    }
}

impl IntoDtnTimestamp for CreationTimestamp {
    fn into_dtn_timestamp(self) -> (u64, u64) {
        (self.time, self.sequence_number)
    }
}

impl IntoDtnTimestamp for (u64, u64) {
    fn into_dtn_timestamp(self) -> (u64, u64) {
        self
    }
}

impl IntoDtnTimestamp for &(u64, u64) {
    fn into_dtn_timestamp(self) -> (u64, u64) {
        *self
    }
}

const fn default_bundle_inspection_stage() -> DiagnosticStage {
    DiagnosticStage::BundleInspection
}

/// Structured BPv7 bundle metadata extracted during passive packet inspection (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleMetadata {
    /// Destination endpoint identifier URI.
    pub destination: String,

    /// Source node endpoint identifier URI.
    pub source: String,

    /// Destination endpoint identifier URI (redundant key for explicit access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_eid: Option<String>,

    /// Source endpoint identifier URI (redundant key for explicit access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_eid: Option<String>,

    /// DTN timestamp in milliseconds since DTN epoch (2000-01-01 00:00:00 UTC).
    pub dtn_timestamp: u64,

    /// Structured creation timestamp (time and sequence number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<CreationTimestamp>,

    /// Sequence number unique to source node at timestamp millisecond.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,

    /// Bundle lifetime in milliseconds relative to creation time.
    pub lifetime: u64,

    /// Parse outcome status.
    pub parse_status: BundleParseStatus,

    /// Optional report-to endpoint identifier URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_to: Option<String>,

    /// Whether the bundle is a fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_fragment: Option<bool>,

    /// Fragment offset in bytes if this bundle is a fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment_offset: Option<u64>,

    /// Total application data unit length in bytes if this bundle is a fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_application_data_unit_length: Option<u64>,

    /// CRC verification outcome if CRC was present and computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crc_valid: Option<bool>,
}

/// Diagnostic event representing a BPv7 passive inspection event (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleInspection {
    /// Monotonic timestamp in nanoseconds when this event was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monotonic_timestamp: Option<u64>,

    /// Wall-clock timestamp in nanoseconds since UNIX epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_timestamp: Option<u64>,

    /// Forwarding stream identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Diagnostic stage or event category (defaults to `bundle_inspection`).
    #[serde(default = "default_bundle_inspection_stage")]
    pub stage: DiagnosticStage,

    /// Destination endpoint identifier URI (e.g. `ipn:1.2` or `dtn://node/service`).
    pub destination_eid: String,

    /// Source node endpoint identifier URI.
    pub source_eid: String,

    /// Optional report-to endpoint identifier URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_to_eid: Option<String>,

    /// DTN creation timestamp in milliseconds since 2000-01-01 00:00:00 UTC.
    #[serde(alias = "dtn_time", alias = "creation_time", alias = "timestamp")]
    pub dtn_timestamp: u64,

    /// Sequence number unique to the source node at this millisecond.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "sequence")]
    pub sequence_number: Option<u64>,

    /// Bundle lifetime in milliseconds relative to creation time.
    #[serde(alias = "lifetime_ms")]
    pub lifetime: u64,

    /// Outcome status of parsing the BPv7 bundle headers.
    #[serde(alias = "status")]
    pub parse_status: BundleParseStatus,

    /// Destination endpoint identifier URI (redundant key for `destination` access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,

    /// Source endpoint identifier URI (redundant key for `source` access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Structured creation timestamp (time and sequence number).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_timestamp: Option<CreationTimestamp>,

    /// Whether this bundle is a fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_fragment: Option<bool>,

    /// Fragment offset in bytes if this bundle is a fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment_offset: Option<u64>,

    /// Total application data unit length in bytes if this bundle is a fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_application_data_unit_length: Option<u64>,

    /// Verification status of bundle CRC if CRC was present and computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crc_valid: Option<bool>,

    /// Structured bundle metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_metadata: Option<BundleMetadata>,
}

pub type BundleInspectionEvent = BundleInspection;

impl BundleInspection {
    /// Creates a new `BundleInspection` event.
    #[must_use]
    pub fn new(
        destination: impl Into<String>,
        source: impl Into<String>,
        dtn_timestamp: impl IntoDtnTimestamp,
        lifetime: u64,
        parse_status: BundleParseStatus,
    ) -> Self {
        let dest = destination.into();
        let src = source.into();
        let (ts, seq) = dtn_timestamp.into_dtn_timestamp();
        let ct = CreationTimestamp::new(ts, seq);
        let metadata = BundleMetadata {
            destination: dest.clone(),
            source: src.clone(),
            destination_eid: Some(dest.clone()),
            source_eid: Some(src.clone()),
            dtn_timestamp: ts,
            creation_timestamp: Some(ct),
            sequence_number: Some(seq),
            lifetime,
            parse_status,
            report_to: None,
            is_fragment: None,
            fragment_offset: None,
            total_application_data_unit_length: None,
            crc_valid: None,
        };
        Self {
            monotonic_timestamp: None,
            wall_clock_timestamp: None,
            stream_id: None,
            stage: DiagnosticStage::BundleInspection,
            destination_eid: dest.clone(),
            source_eid: src.clone(),
            report_to_eid: None,
            dtn_timestamp: ts,
            sequence_number: Some(seq),
            lifetime,
            parse_status,
            destination: Some(dest),
            source: Some(src),
            creation_timestamp: Some(ct),
            is_fragment: None,
            fragment_offset: None,
            total_application_data_unit_length: None,
            crc_valid: None,
            bundle_metadata: Some(metadata),
        }
    }

    /// Destination endpoint identifier string.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination_eid
    }

    /// Source endpoint identifier string.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source_eid
    }

    /// Destination endpoint identifier string.
    #[must_use]
    pub fn destination_eid(&self) -> &str {
        &self.destination_eid
    }

    /// Source endpoint identifier string.
    #[must_use]
    pub fn source_eid(&self) -> &str {
        &self.source_eid
    }

    /// DTN timestamp in milliseconds.
    #[must_use]
    pub fn dtn_timestamp(&self) -> u64 {
        self.dtn_timestamp
    }

    /// Lifetime in milliseconds.
    #[must_use]
    pub fn lifetime(&self) -> u64 {
        self.lifetime
    }

    /// Parse status.
    #[must_use]
    pub fn parse_status(&self) -> BundleParseStatus {
        self.parse_status
    }

    /// Creates a `BundleInspection` from a parsed [`PrimaryBlock`] and parse status.
    #[must_use]
    pub fn from_primary_block(primary: &PrimaryBlock, parse_status: BundleParseStatus) -> Self {
        let dest = primary.destination.to_string();
        let src = primary.source.to_string();
        let report = primary.report_to.to_string();
        let ts = primary.creation_timestamp.time;
        let seq = primary.creation_timestamp.sequence_number;
        let is_frag = (primary.bundle_control_flags & crate::bpv7::BUNDLE_IS_FRAGMENT) != 0;
        let mut insp = Self::new(dest, src, (ts, seq), primary.lifetime, parse_status);
        insp.report_to_eid = Some(report.clone());
        insp.is_fragment = Some(is_frag);
        insp.fragment_offset = primary.fragment_offset;
        insp.total_application_data_unit_length = primary.total_application_data_unit_length;
        insp.crc_valid = primary.crc_valid;
        if let Some(ref mut meta) = insp.bundle_metadata {
            meta.report_to = Some(report);
            meta.is_fragment = Some(is_frag);
            meta.fragment_offset = primary.fragment_offset;
            meta.total_application_data_unit_length = primary.total_application_data_unit_length;
            meta.crc_valid = primary.crc_valid;
        }
        insp
    }

    /// Sets the destination endpoint identifier.
    #[must_use]
    pub fn with_destination(mut self, dest: impl Into<String>) -> Self {
        let d = dest.into();
        self.destination_eid = d.clone();
        self.destination = Some(d.clone());
        if let Some(ref mut m) = self.bundle_metadata {
            m.destination_eid = Some(d.clone());
            m.destination = d;
        }
        self
    }

    /// Sets the destination endpoint identifier.
    #[must_use]
    pub fn with_destination_eid(self, dest: impl Into<String>) -> Self {
        self.with_destination(dest)
    }

    /// Sets the source endpoint identifier.
    #[must_use]
    pub fn with_source(mut self, src: impl Into<String>) -> Self {
        let s = src.into();
        self.source_eid = s.clone();
        self.source = Some(s.clone());
        if let Some(ref mut m) = self.bundle_metadata {
            m.source_eid = Some(s.clone());
            m.source = s;
        }
        self
    }

    /// Sets the source endpoint identifier.
    #[must_use]
    pub fn with_source_eid(self, src: impl Into<String>) -> Self {
        self.with_source(src)
    }

    /// Sets the stream identifier.
    #[must_use]
    pub fn with_stream_id(mut self, stream_id: impl Into<String>) -> Self {
        self.stream_id = Some(stream_id.into());
        self
    }

    /// Sets monotonic and wall-clock timestamps.
    #[must_use]
    pub fn with_timestamps(mut self, monotonic: u64, wall_clock: u64) -> Self {
        self.monotonic_timestamp = Some(monotonic);
        self.wall_clock_timestamp = Some(wall_clock);
        self
    }

    /// Sets the DTN timestamp.
    #[must_use]
    pub fn with_dtn_timestamp(mut self, ts: impl IntoDtnTimestamp) -> Self {
        let (t, seq) = ts.into_dtn_timestamp();
        self.dtn_timestamp = t;
        self.sequence_number = Some(seq);
        self.creation_timestamp = Some(CreationTimestamp::new(t, seq));
        if let Some(ref mut m) = self.bundle_metadata {
            m.dtn_timestamp = t;
            m.sequence_number = Some(seq);
            m.creation_timestamp = Some(CreationTimestamp::new(t, seq));
        }
        self
    }

    /// Sets the bundle lifetime.
    #[must_use]
    pub fn with_lifetime(mut self, lifetime: u64) -> Self {
        self.lifetime = lifetime;
        if let Some(ref mut m) = self.bundle_metadata {
            m.lifetime = lifetime;
        }
        self
    }

    /// Sets the parse status.
    #[must_use]
    pub fn with_parse_status(mut self, status: BundleParseStatus) -> Self {
        self.parse_status = status;
        if let Some(ref mut m) = self.bundle_metadata {
            m.parse_status = status;
        }
        self
    }

    /// Sets the report-to endpoint identifier.
    #[must_use]
    pub fn with_report_to(mut self, report_to: impl Into<String>) -> Self {
        let r = report_to.into();
        if let Some(ref mut m) = self.bundle_metadata {
            m.report_to = Some(r.clone());
        }
        self.report_to_eid = Some(r);
        self
    }
}

impl From<BundleInspection> for DiagnosticEvent {
    fn from(bi: BundleInspection) -> Self {
        let mono = bi.monotonic_timestamp.unwrap_or(0);
        let wall = bi.wall_clock_timestamp.unwrap_or(0);
        let stream = bi.stream_id.clone().unwrap_or_else(|| "bpv7".to_string());
        let mut event = DiagnosticEvent::new(
            mono,
            wall,
            stream,
            DiagnosticStage::BundleInspection,
            TransportType::Udp,
            0,
        );
        event.destination_endpoint = Some(bi.destination_eid.clone());
        event.source_endpoint = Some(bi.source_eid.clone());
        event.bundle_destination = Some(bi.destination_eid.clone());
        event.bundle_source = Some(bi.source_eid.clone());
        event.dtn_timestamp = Some(bi.dtn_timestamp);
        event.bundle_lifetime = Some(bi.lifetime);
        event.parse_status = Some(bi.parse_status);
        event.bundle_inspection = Some(bi);
        event
    }
}

const fn default_ltp_inspection_stage() -> DiagnosticStage {
    DiagnosticStage::LtpInspection
}

/// Structured LTP segment metadata extracted during passive packet inspection (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtpMetadata {
    /// Session Originator Engine ID.
    pub session_originator: u64,

    /// Session Originator Engine ID (redundant key for explicit engine ID access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_originator_engine_id: Option<u64>,

    /// Unique session number.
    pub session_number: u64,

    /// LTP Segment Type.
    pub segment_type: SegmentType,

    /// Raw 4-bit segment type code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_type_code: Option<u8>,

    /// Protocol version (0 for RFC 5326).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,

    /// Parse outcome status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_status: Option<LtpParseStatus>,

    /// Client Service ID (present in data segments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_service_id: Option<u64>,

    /// Block byte offset (present in data segments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,

    /// Client service data length in octets (present in data segments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,

    /// Checkpoint serial number (present in checkpoint segments and RS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_serial_number: Option<u64>,

    /// Report serial number (present in checkpoint segments, RS, and RAx).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_serial_number: Option<u64>,
}

/// Diagnostic event representing an LTP passive inspection event (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LtpInspection {
    /// Monotonic timestamp in nanoseconds when this event was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monotonic_timestamp: Option<u64>,

    /// Wall-clock timestamp in nanoseconds since UNIX epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_timestamp: Option<u64>,

    /// Forwarding stream identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Diagnostic stage or event category (defaults to `ltp_inspection`).
    #[serde(default = "default_ltp_inspection_stage")]
    pub stage: DiagnosticStage,

    /// Session Originator Engine ID.
    #[serde(alias = "originator", alias = "engine_id")]
    pub session_originator: u64,

    /// Session Originator Engine ID (alias for engine_id access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_originator_engine_id: Option<u64>,

    /// Unique session number assigned by sender.
    #[serde(alias = "session")]
    pub session_number: u64,

    /// LTP Segment Type.
    pub segment_type: SegmentType,

    /// Parse outcome status of the LTP segment.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "status")]
    pub parse_status: Option<LtpParseStatus>,

    /// Protocol version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,

    /// Client service ID (present in data segments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_service_id: Option<u64>,

    /// Block byte offset (present in data segments).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,

    /// Client service data length in octets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,

    /// Checkpoint serial number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_serial_number: Option<u64>,

    /// Report serial number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_serial_number: Option<u64>,

    /// Structured LTP metadata.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "metadata",
        alias = "ltp"
    )]
    pub ltp_metadata: Option<LtpMetadata>,
}

pub type LtpInspectionEvent = LtpInspection;

impl LtpInspection {
    /// Creates a new `LtpInspection` event.
    #[must_use]
    pub fn new(session_originator: u64, session_number: u64, segment_type: SegmentType) -> Self {
        let metadata = LtpMetadata {
            session_originator,
            session_originator_engine_id: Some(session_originator),
            session_number,
            segment_type,
            segment_type_code: Some(segment_type.code()),
            version: Some(0),
            parse_status: Some(LtpParseStatus::Valid),
            client_service_id: None,
            offset: None,
            length: None,
            checkpoint_serial_number: None,
            report_serial_number: None,
        };
        Self {
            monotonic_timestamp: None,
            wall_clock_timestamp: None,
            stream_id: None,
            stage: DiagnosticStage::LtpInspection,
            session_originator,
            session_originator_engine_id: Some(session_originator),
            session_number,
            segment_type,
            parse_status: Some(LtpParseStatus::Valid),
            version: Some(0),
            client_service_id: None,
            offset: None,
            length: None,
            checkpoint_serial_number: None,
            report_serial_number: None,
            ltp_metadata: Some(metadata),
        }
    }

    /// Creates an `LtpInspection` from a parsed [`LtpSegmentHeader`] and parse status.
    #[must_use]
    pub fn from_segment_header(header: &LtpSegmentHeader, parse_status: LtpParseStatus) -> Self {
        let mut insp = Self::new(
            header.session_originator,
            header.session_number,
            header.segment_type,
        );
        insp.version = Some(header.version);
        insp.parse_status = Some(parse_status);
        insp.client_service_id = header.client_service_id;
        insp.offset = header.offset;
        insp.length = header.length;
        insp.checkpoint_serial_number = header.checkpoint_serial_number;
        insp.report_serial_number = header.report_serial_number;
        if let Some(ref mut meta) = insp.ltp_metadata {
            meta.version = Some(header.version);
            meta.parse_status = Some(parse_status);
            meta.client_service_id = header.client_service_id;
            meta.offset = header.offset;
            meta.length = header.length;
            meta.checkpoint_serial_number = header.checkpoint_serial_number;
            meta.report_serial_number = header.report_serial_number;
        }
        insp
    }

    /// Session Originator Engine ID.
    #[must_use]
    pub fn session_originator(&self) -> u64 {
        self.session_originator
    }

    /// Session Originator Engine ID.
    #[must_use]
    pub fn session_originator_engine_id(&self) -> u64 {
        self.session_originator
    }

    /// Session number.
    #[must_use]
    pub fn session_number(&self) -> u64 {
        self.session_number
    }

    /// LTP Segment Type.
    #[must_use]
    pub fn segment_type(&self) -> SegmentType {
        self.segment_type
    }

    /// Parse outcome status.
    #[must_use]
    pub fn parse_status(&self) -> Option<LtpParseStatus> {
        self.parse_status
    }

    /// Sets the stream identifier.
    #[must_use]
    pub fn with_stream_id(mut self, stream_id: impl Into<String>) -> Self {
        self.stream_id = Some(stream_id.into());
        self
    }

    /// Sets monotonic and wall-clock timestamps.
    #[must_use]
    pub fn with_timestamps(mut self, monotonic: u64, wall_clock: u64) -> Self {
        self.monotonic_timestamp = Some(monotonic);
        self.wall_clock_timestamp = Some(wall_clock);
        self
    }

    /// Sets the parse status.
    #[must_use]
    pub fn with_parse_status(mut self, status: LtpParseStatus) -> Self {
        self.parse_status = Some(status);
        if let Some(ref mut meta) = self.ltp_metadata {
            meta.parse_status = Some(status);
        }
        self
    }

    /// Sets the client service ID.
    #[must_use]
    pub fn with_client_service_id(mut self, client_service_id: u64) -> Self {
        self.client_service_id = Some(client_service_id);
        if let Some(ref mut meta) = self.ltp_metadata {
            meta.client_service_id = Some(client_service_id);
        }
        self
    }

    /// Sets offset and length.
    #[must_use]
    pub fn with_offset_and_length(mut self, offset: u64, length: u64) -> Self {
        self.offset = Some(offset);
        self.length = Some(length);
        if let Some(ref mut meta) = self.ltp_metadata {
            meta.offset = Some(offset);
            meta.length = Some(length);
        }
        self
    }
}

impl From<LtpInspection> for DiagnosticEvent {
    fn from(li: LtpInspection) -> Self {
        let mono = li.monotonic_timestamp.unwrap_or(0);
        let wall = li.wall_clock_timestamp.unwrap_or(0);
        let stream = li.stream_id.clone().unwrap_or_else(|| "ltp".to_string());
        let mut event = DiagnosticEvent::new(
            mono,
            wall,
            stream,
            DiagnosticStage::LtpInspection,
            TransportType::Udp,
            0,
        );
        event.session_originator = Some(li.session_originator);
        event.session_number = Some(li.session_number);
        event.segment_type = Some(li.segment_type);
        event.ltp_parse_status = li.parse_status;
        event.ltp_metadata = li.ltp_metadata.clone();
        event.ltp_inspection = Some(li);
        event
    }
}

const fn default_srt_inspection_stage() -> DiagnosticStage {
    DiagnosticStage::SrtInspection
}

/// Structured SRT metadata extracted during passive packet inspection (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrtMetadata {
    /// 32-bit Destination Socket ID.
    pub destination_socket_id: u32,

    /// 32-bit timestamp in microseconds.
    pub timestamp_us: u32,

    /// 32-bit timestamp in microseconds (redundant key for explicit timestamp access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u32>,

    /// SRT packet kind (data or control).
    pub packet_kind: SrtPacketKind,

    /// SRT packet kind (redundant key for explicit packet_type access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_type: Option<SrtPacketKind>,

    /// 31-bit sequence number (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u32>,

    /// 26-bit message number (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_number: Option<u32>,

    /// Packet position flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_position: Option<PacketPosition>,

    /// In-order delivery flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_order: Option<bool>,

    /// Retransmitted packet flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmitted: Option<bool>,

    /// Key-based encryption flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_flag: Option<u8>,

    /// Control packet type (for control packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_type: Option<SrtControlType>,

    /// Control subtype / extension / reserved (for control packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<u16>,

    /// Type-specific information (for control packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_specific_info: Option<u32>,

    /// Handshake type integer (for handshake packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_type: Option<u32>,

    /// Sender SRT socket ID (for handshake packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_socket_id: Option<u32>,

    /// Anti-spoofing challenge cookie (for handshake packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syn_cookie: Option<u32>,

    /// Stream ID string from handshake extensions (SRT_CMD_SID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Parse outcome status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_status: Option<SrtParseStatus>,
}

/// Diagnostic event representing an SRT passive inspection event (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SrtInspection {
    /// Monotonic timestamp in nanoseconds when this event was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monotonic_timestamp: Option<u64>,

    /// Wall-clock timestamp in nanoseconds since UNIX epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_timestamp: Option<u64>,

    /// Forwarding stream identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Diagnostic stage or event category (defaults to `srt_inspection`).
    #[serde(default = "default_srt_inspection_stage")]
    pub stage: DiagnosticStage,

    /// 32-bit Destination Socket ID.
    #[serde(alias = "dest_socket_id", alias = "socket_id")]
    pub destination_socket_id: u32,

    /// 32-bit timestamp in microseconds.
    pub timestamp: u32,

    /// 32-bit timestamp in microseconds (redundant key for timestamp_us access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_us: Option<u32>,

    /// SRT Packet Kind (Data or Control).
    pub packet_kind: SrtPacketKind,

    /// SRT Packet Kind (redundant key for packet_type access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_type: Option<SrtPacketKind>,

    /// Parse outcome status of the SRT packet.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "status")]
    pub parse_status: Option<SrtParseStatus>,

    /// 31-bit sequence number (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u32>,

    /// 26-bit message number (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_number: Option<u32>,

    /// Packet position flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_position: Option<PacketPosition>,

    /// In-order delivery flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_order: Option<bool>,

    /// Retransmitted packet flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retransmitted: Option<bool>,

    /// Key-based encryption flag (for data packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_flag: Option<u8>,

    /// Control packet type (for control packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_type: Option<SrtControlType>,

    /// Subtype / extension / reserved (for control packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<u16>,

    /// Type-specific information (for control packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_specific_info: Option<u32>,

    /// Handshake type integer (for handshake packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_type: Option<u32>,

    /// Sender SRT socket ID (for handshake packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_socket_id: Option<u32>,

    /// SYN cookie (for handshake packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syn_cookie: Option<u32>,

    /// Stream ID from handshake extension records (SRT_CMD_SID).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id_extension: Option<String>,

    /// Structured SRT metadata.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "metadata",
        alias = "srt"
    )]
    pub srt_metadata: Option<SrtMetadata>,
}

pub type SrtInspectionEvent = SrtInspection;

impl SrtInspection {
    /// Creates a new `SrtInspection` event with destination socket ID, timestamp, and packet kind.
    #[must_use]
    pub fn new(destination_socket_id: u32, timestamp: u32, packet_kind: SrtPacketKind) -> Self {
        let metadata = SrtMetadata {
            destination_socket_id,
            timestamp_us: timestamp,
            timestamp: Some(timestamp),
            packet_kind,
            packet_type: Some(packet_kind),
            sequence_number: None,
            message_number: None,
            packet_position: None,
            in_order: None,
            retransmitted: None,
            encryption_flag: None,
            control_type: None,
            subtype: None,
            type_specific_info: None,
            handshake_type: None,
            srt_socket_id: None,
            syn_cookie: None,
            stream_id: None,
            parse_status: Some(SrtParseStatus::Valid),
        };
        Self {
            monotonic_timestamp: None,
            wall_clock_timestamp: None,
            stream_id: None,
            stage: DiagnosticStage::SrtInspection,
            destination_socket_id,
            timestamp,
            timestamp_us: Some(timestamp),
            packet_kind,
            packet_type: Some(packet_kind),
            parse_status: Some(SrtParseStatus::Valid),
            sequence_number: None,
            message_number: None,
            packet_position: None,
            in_order: None,
            retransmitted: None,
            encryption_flag: None,
            control_type: None,
            subtype: None,
            type_specific_info: None,
            handshake_type: None,
            srt_socket_id: None,
            syn_cookie: None,
            stream_id_extension: None,
            srt_metadata: Some(metadata),
        }
    }

    /// Creates an `SrtInspection` from a parsed [`SrtHeader`] and parse status.
    #[must_use]
    pub fn from_header(header: &SrtHeader, parse_status: SrtParseStatus) -> Self {
        let mut insp = Self::new(
            header.destination_socket_id,
            header.timestamp,
            header.packet_kind,
        );
        insp.parse_status = Some(parse_status);
        insp.sequence_number = header.sequence_number;
        insp.message_number = header.message_number;
        insp.packet_position = header.packet_position;
        insp.in_order = header.in_order;
        insp.retransmitted = header.retransmitted;
        insp.encryption_flag = header.encryption_flag;
        insp.control_type = header.control_type;
        insp.subtype = header.subtype;
        insp.type_specific_info = header.type_specific_info;
        insp.handshake_type = header.handshake_type;
        insp.srt_socket_id = header.srt_socket_id;
        insp.syn_cookie = header.syn_cookie;
        insp.stream_id_extension = header.stream_id.clone();
        if let Some(ref mut meta) = insp.srt_metadata {
            meta.parse_status = Some(parse_status);
            meta.sequence_number = header.sequence_number;
            meta.message_number = header.message_number;
            meta.packet_position = header.packet_position;
            meta.in_order = header.in_order;
            meta.retransmitted = header.retransmitted;
            meta.encryption_flag = header.encryption_flag;
            meta.control_type = header.control_type;
            meta.subtype = header.subtype;
            meta.type_specific_info = header.type_specific_info;
            meta.handshake_type = header.handshake_type;
            meta.srt_socket_id = header.srt_socket_id;
            meta.syn_cookie = header.syn_cookie;
            meta.stream_id = header.stream_id.clone();
        }
        insp
    }

    /// Creates an `SrtInspection` from a parsed [`SrtDataHeader`] and parse status.
    #[must_use]
    pub fn from_data_header(header: &SrtDataHeader, parse_status: SrtParseStatus) -> Self {
        let mut insp = Self::new(
            header.destination_socket_id,
            header.timestamp,
            SrtPacketKind::Data,
        );
        insp.parse_status = Some(parse_status);
        insp.sequence_number = Some(header.sequence_number);
        insp.message_number = Some(header.message_number);
        insp.packet_position = Some(header.packet_position);
        insp.in_order = Some(header.in_order);
        insp.retransmitted = Some(header.retransmitted);
        insp.encryption_flag = Some(header.encryption_flag);
        if let Some(ref mut meta) = insp.srt_metadata {
            meta.parse_status = Some(parse_status);
            meta.sequence_number = Some(header.sequence_number);
            meta.message_number = Some(header.message_number);
            meta.packet_position = Some(header.packet_position);
            meta.in_order = Some(header.in_order);
            meta.retransmitted = Some(header.retransmitted);
            meta.encryption_flag = Some(header.encryption_flag);
        }
        insp
    }

    /// Creates an `SrtInspection` from a parsed [`SrtControlHeader`] and parse status.
    #[must_use]
    pub fn from_control_header(header: &SrtControlHeader, parse_status: SrtParseStatus) -> Self {
        let mut insp = Self::new(
            header.destination_socket_id,
            header.timestamp,
            SrtPacketKind::Control,
        );
        insp.parse_status = Some(parse_status);
        insp.control_type = Some(header.control_type);
        insp.subtype = Some(header.subtype);
        insp.type_specific_info = Some(header.type_specific_info);
        if let Some(ref mut meta) = insp.srt_metadata {
            meta.parse_status = Some(parse_status);
            meta.control_type = Some(header.control_type);
            meta.subtype = Some(header.subtype);
            meta.type_specific_info = Some(header.type_specific_info);
        }
        insp
    }

    /// Destination Socket ID.
    #[must_use]
    pub fn destination_socket_id(&self) -> u32 {
        self.destination_socket_id
    }

    /// Timestamp in microseconds.
    #[must_use]
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Timestamp in microseconds.
    #[must_use]
    pub fn timestamp_us(&self) -> u32 {
        self.timestamp
    }

    /// SRT packet kind (Data or Control).
    #[must_use]
    pub fn packet_kind(&self) -> SrtPacketKind {
        self.packet_kind
    }

    /// SRT packet kind (Data or Control).
    #[must_use]
    pub fn packet_type(&self) -> SrtPacketKind {
        self.packet_kind
    }

    /// Parse outcome status.
    #[must_use]
    pub fn parse_status(&self) -> Option<SrtParseStatus> {
        self.parse_status
    }

    /// Sets the stream identifier.
    #[must_use]
    pub fn with_stream_id(mut self, stream_id: impl Into<String>) -> Self {
        self.stream_id = Some(stream_id.into());
        self
    }

    /// Sets monotonic and wall-clock timestamps.
    #[must_use]
    pub fn with_timestamps(mut self, monotonic: u64, wall_clock: u64) -> Self {
        self.monotonic_timestamp = Some(monotonic);
        self.wall_clock_timestamp = Some(wall_clock);
        self
    }

    /// Sets the parse status.
    #[must_use]
    pub fn with_parse_status(mut self, status: SrtParseStatus) -> Self {
        self.parse_status = Some(status);
        if let Some(ref mut meta) = self.srt_metadata {
            meta.parse_status = Some(status);
        }
        self
    }

    /// Sets sequence number.
    #[must_use]
    pub fn with_sequence_number(mut self, seq: u32) -> Self {
        self.sequence_number = Some(seq);
        if let Some(ref mut meta) = self.srt_metadata {
            meta.sequence_number = Some(seq);
        }
        self
    }

    /// Sets message number.
    #[must_use]
    pub fn with_message_number(mut self, msg: u32) -> Self {
        self.message_number = Some(msg);
        if let Some(ref mut meta) = self.srt_metadata {
            meta.message_number = Some(msg);
        }
        self
    }

    /// Sets control type.
    #[must_use]
    pub fn with_control_type(mut self, ct: SrtControlType) -> Self {
        self.control_type = Some(ct);
        if let Some(ref mut meta) = self.srt_metadata {
            meta.control_type = Some(ct);
        }
        self
    }

    /// Sets stream ID string extension.
    #[must_use]
    pub fn with_stream_id_extension(mut self, sid: impl Into<String>) -> Self {
        let s = sid.into();
        self.stream_id_extension = Some(s.clone());
        if let Some(ref mut meta) = self.srt_metadata {
            meta.stream_id = Some(s);
        }
        self
    }
}

impl From<SrtInspection> for DiagnosticEvent {
    fn from(insp: SrtInspection) -> Self {
        let mono = insp.monotonic_timestamp.unwrap_or(0);
        let wall = insp.wall_clock_timestamp.unwrap_or(0);
        let stream = insp.stream_id.clone().unwrap_or_else(|| "srt".to_string());
        let mut event = DiagnosticEvent::new(
            mono,
            wall,
            stream,
            DiagnosticStage::SrtInspection,
            TransportType::Udp,
            0,
        );
        event.destination_socket_id = Some(insp.destination_socket_id);
        event.srt_timestamp = Some(insp.timestamp);
        event.srt_timestamp_us = Some(insp.timestamp);
        event.srt_packet_kind = Some(insp.packet_kind);
        event.srt_packet_type = Some(insp.packet_kind);
        event.srt_control_type = insp.control_type;
        event.srt_parse_status = insp.parse_status;
        event.srt_sequence_number = insp.sequence_number;
        if let Some(seq) = insp.sequence_number {
            event.sequence_number = Some(seq as u64);
        }
        event.srt_metadata = insp.srt_metadata.clone();
        event.srt_inspection = Some(insp);
        event
    }
}

const fn default_mavlink_inspection_stage() -> DiagnosticStage {
    DiagnosticStage::MavlinkInspection
}

/// Structured MAVLink packet metadata extracted during passive packet inspection (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MavlinkMetadata {
    /// Sending vehicle/node system ID (1 to 255).
    pub system_id: u8,

    /// Sending subsystem component ID (1 to 255).
    pub component_id: u8,

    /// Packet sequence number (0 to 255).
    pub sequence: u8,

    /// Packet sequence number (alias for compatibility).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "seq")]
    pub sequence_number: Option<u8>,

    /// Message schema identifier (8-bit for v1, 24-bit for v2).
    pub message_id: u32,

    /// Protocol version (1 or 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,

    /// Payload length in octets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_length: Option<u8>,

    /// Incompatibility flags bitfield.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incompat_flags: Option<u8>,

    /// Compatibility flags bitfield.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compat_flags: Option<u8>,

    /// True if the packet carries a 13-octet signature block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_signed: Option<bool>,

    /// Calculated total packet length in octets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_packet_length: Option<usize>,
}

/// Diagnostic event representing a MAVLink passive inspection event (SPEC §14, §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MavlinkInspection {
    /// Monotonic timestamp in nanoseconds when this event was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monotonic_timestamp: Option<u64>,

    /// Wall-clock timestamp in nanoseconds since UNIX epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock_timestamp: Option<u64>,

    /// Forwarding stream identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,

    /// Diagnostic stage or event category (defaults to `mavlink_inspection`).
    #[serde(default = "default_mavlink_inspection_stage")]
    pub stage: DiagnosticStage,

    /// Sending vehicle/node system ID.
    pub system_id: u8,

    /// Sending subsystem component ID.
    pub component_id: u8,

    /// Packet sequence number.
    pub sequence: u8,

    /// Message schema identifier (24-bit).
    pub message_id: u32,

    /// Protocol version (1 or 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,

    /// Parse outcome status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_status: Option<crate::mavlink::MavlinkParseStatus>,

    /// Structured MAVLink metadata.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "metadata",
        alias = "mavlink"
    )]
    pub mavlink_metadata: Option<MavlinkMetadata>,
}

pub type MavlinkInspectionEvent = MavlinkInspection;

impl MavlinkInspection {
    /// Creates a new `MavlinkInspection` event.
    #[must_use]
    pub fn new(system_id: u8, component_id: u8, sequence: u8, message_id: u32) -> Self {
        let metadata = MavlinkMetadata {
            system_id,
            component_id,
            sequence,
            sequence_number: Some(sequence),
            message_id,
            version: None,
            payload_length: None,
            incompat_flags: None,
            compat_flags: None,
            is_signed: None,
            total_packet_length: None,
        };
        Self {
            monotonic_timestamp: None,
            wall_clock_timestamp: None,
            stream_id: None,
            stage: DiagnosticStage::MavlinkInspection,
            system_id,
            component_id,
            sequence,
            message_id,
            version: None,
            parse_status: None,
            mavlink_metadata: Some(metadata),
        }
    }
}

impl From<MavlinkInspection> for DiagnosticEvent {
    fn from(insp: MavlinkInspection) -> Self {
        let mono = insp.monotonic_timestamp.unwrap_or(0);
        let wall = insp.wall_clock_timestamp.unwrap_or(0);
        let stream = insp
            .stream_id
            .clone()
            .unwrap_or_else(|| "mavlink".to_string());
        let mut event = DiagnosticEvent::new(
            mono,
            wall,
            stream,
            DiagnosticStage::MavlinkInspection,
            TransportType::Udp,
            0,
        );
        event.mavlink_system_id = Some(insp.system_id);
        event.mavlink_component_id = Some(insp.component_id);
        event.mavlink_sequence = Some(insp.sequence);
        event.sequence_number = Some(u64::from(insp.sequence));
        event.mavlink_message_id = Some(insp.message_id);
        event.mavlink_version = insp.version;
        event.mavlink_parse_status = insp.parse_status;
        event.mavlink_metadata = insp.mavlink_metadata.clone();
        event.mavlink_inspection = Some(insp);
        event
    }
}

/// Structured diagnostic event (SPEC §8, §10).
///
/// Contains packet inspection metadata and lifecycle status without retaining payload bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    /// Monotonic timestamp in nanoseconds.
    #[serde(alias = "monotonic_timestamp_ns", alias = "monotonic")]
    pub monotonic_timestamp: u64,

    /// Wall-clock timestamp in nanoseconds since UNIX epoch.
    #[serde(alias = "wall_clock_timestamp_ns", alias = "wall_clock")]
    pub wall_clock_timestamp: u64,

    /// Forwarding stream identifier.
    #[serde(alias = "stream")]
    pub stream_id: String,

    /// Packet processing stage or event category.
    pub stage: DiagnosticStage,

    /// Optional source endpoint address (e.g. "127.0.0.1:8000" or "[::1]:8000").
    #[serde(default, alias = "source", skip_serializing_if = "Option::is_none")]
    pub source_endpoint: Option<String>,

    /// Optional destination endpoint address.
    #[serde(
        default,
        alias = "destination",
        skip_serializing_if = "Option::is_none"
    )]
    pub destination_endpoint: Option<String>,

    /// Transport protocol (UDP or TCP).
    pub transport: TransportType,

    /// Length of payload in bytes (the event itself does not retain payload bytes).
    #[serde(alias = "length", alias = "bytes")]
    pub payload_length: u64,

    /// Optional correlation identifier spanning multiple relays.
    #[serde(
        default,
        alias = "correlation",
        skip_serializing_if = "Option::is_none"
    )]
    pub correlation_id: Option<String>,

    /// Optional reason or failure diagnostic description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Extracted sequence number when sequence tracking is configured (SPEC §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,

    /// CCSDS Application Process Identifier (APID) (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apid: Option<u16>,

    /// CCSDS 14-bit sequence count (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccsds_sequence: Option<u16>,

    /// CCSDS 2-bit sequence flags (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ccsds_flags: Option<u8>,

    /// Opt-in hexadecimal preview of payload bytes (SPEC §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex_preview: Option<String>,

    /// Opt-in ASCII preview of payload bytes (SPEC §8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ascii_preview: Option<String>,

    /// BPv7 destination endpoint identifier (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_destination: Option<String>,

    /// BPv7 source endpoint identifier (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_source: Option<String>,

    /// BPv7 DTN creation timestamp in milliseconds (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtn_timestamp: Option<u64>,

    /// BPv7 bundle lifetime in milliseconds (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_lifetime: Option<u64>,

    /// BPv7 bundle parse evaluation status (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_status: Option<BundleParseStatus>,

    /// BPv7 bundle inspection metadata (SPEC §14, §8).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "bpv7",
        alias = "bundle_metadata"
    )]
    pub bundle_inspection: Option<BundleInspection>,

    /// LTP session originator engine ID (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_originator: Option<u64>,

    /// LTP session number (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_number: Option<u64>,

    /// LTP segment type (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_type: Option<SegmentType>,

    /// LTP parse evaluation status (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ltp_parse_status: Option<LtpParseStatus>,

    /// LTP inspection metadata (SPEC §14, §8).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "ltp")]
    pub ltp_inspection: Option<LtpInspection>,

    /// Structured LTP metadata (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ltp_metadata: Option<LtpMetadata>,

    /// SRT destination socket ID (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_socket_id: Option<u32>,

    /// SRT timestamp in microseconds (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_timestamp: Option<u32>,

    /// SRT timestamp in microseconds (alias for timestamp access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_timestamp_us: Option<u32>,

    /// SRT packet kind (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_packet_kind: Option<SrtPacketKind>,

    /// SRT packet kind (alias for packet_type access).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_packet_type: Option<SrtPacketKind>,

    /// SRT control type (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_control_type: Option<SrtControlType>,

    /// SRT sequence number (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_sequence_number: Option<u32>,

    /// SRT parse evaluation status (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_parse_status: Option<SrtParseStatus>,

    /// SRT inspection metadata (SPEC §14, §8).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "srt")]
    pub srt_inspection: Option<SrtInspection>,

    /// Structured SRT metadata (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srt_metadata: Option<SrtMetadata>,

    /// MAVLink system ID (SPEC §14, §8).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "system_id")]
    pub mavlink_system_id: Option<u8>,

    /// MAVLink component ID (SPEC §14, §8).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "component_id"
    )]
    pub mavlink_component_id: Option<u8>,

    /// MAVLink sequence number (SPEC §14, §8).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "mavlink_sequence_number"
    )]
    pub mavlink_sequence: Option<u8>,

    /// MAVLink 24-bit message ID (SPEC §14, §8).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "mavlink_msg_id",
        alias = "message_id"
    )]
    pub mavlink_message_id: Option<u32>,

    /// MAVLink version (1 or 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mavlink_version: Option<u8>,

    /// MAVLink parse evaluation status (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mavlink_parse_status: Option<crate::mavlink::MavlinkParseStatus>,

    /// MAVLink inspection metadata (SPEC §14, §8).
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "mavlink")]
    pub mavlink_inspection: Option<MavlinkInspection>,

    /// Structured MAVLink metadata (SPEC §14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mavlink_metadata: Option<MavlinkMetadata>,
}

impl DiagnosticEvent {
    /// Creates a new diagnostic event.
    #[must_use]
    pub fn new(
        monotonic_timestamp: u64,
        wall_clock_timestamp: u64,
        stream_id: impl Into<String>,
        stage: DiagnosticStage,
        transport: TransportType,
        payload_length: u64,
    ) -> Self {
        Self {
            monotonic_timestamp,
            wall_clock_timestamp,
            stream_id: stream_id.into(),
            stage,
            source_endpoint: None,
            destination_endpoint: None,
            transport,
            payload_length,
            correlation_id: None,
            reason: None,
            sequence_number: None,
            apid: None,
            ccsds_sequence: None,
            ccsds_flags: None,
            hex_preview: None,
            ascii_preview: None,
            bundle_destination: None,
            bundle_source: None,
            dtn_timestamp: None,
            bundle_lifetime: None,
            parse_status: None,
            bundle_inspection: None,
            session_originator: None,
            session_number: None,
            segment_type: None,
            ltp_parse_status: None,
            ltp_inspection: None,
            ltp_metadata: None,
            destination_socket_id: None,
            srt_timestamp: None,
            srt_timestamp_us: None,
            srt_packet_kind: None,
            srt_packet_type: None,
            srt_control_type: None,
            srt_sequence_number: None,
            srt_parse_status: None,
            srt_inspection: None,
            srt_metadata: None,
            mavlink_system_id: None,
            mavlink_component_id: None,
            mavlink_sequence: None,
            mavlink_message_id: None,
            mavlink_version: None,
            mavlink_parse_status: None,
            mavlink_inspection: None,
            mavlink_metadata: None,
        }
    }

    /// Sets the source endpoint.
    #[must_use]
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_endpoint = Some(source.into());
        self
    }

    /// Sets the destination endpoint.
    #[must_use]
    pub fn with_destination(mut self, destination: impl Into<String>) -> Self {
        self.destination_endpoint = Some(destination.into());
        self
    }

    /// Sets the correlation identifier.
    #[must_use]
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Sets the reason string.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Sets the extracted sequence number.
    #[must_use]
    pub fn with_sequence_number(mut self, seq: u64) -> Self {
        self.sequence_number = Some(seq);
        self
    }

    /// Sets the CCSDS APID.
    #[must_use]
    pub fn with_apid(mut self, apid: u16) -> Self {
        self.apid = Some(apid);
        self
    }

    /// Sets the CCSDS sequence count.
    #[must_use]
    pub fn with_ccsds_sequence(mut self, seq: u16) -> Self {
        self.ccsds_sequence = Some(seq);
        self
    }

    /// Sets the CCSDS sequence flags.
    #[must_use]
    pub fn with_ccsds_flags(mut self, flags: u8) -> Self {
        self.ccsds_flags = Some(flags);
        self
    }

    /// Sets the hex preview.
    #[must_use]
    pub fn with_hex_preview(mut self, hex: impl Into<String>) -> Self {
        self.hex_preview = Some(hex.into());
        self
    }

    /// Sets the ASCII preview.
    #[must_use]
    pub fn with_ascii_preview(mut self, ascii: impl Into<String>) -> Self {
        self.ascii_preview = Some(ascii.into());
        self
    }

    /// Sets the BPv7 destination endpoint identifier.
    #[must_use]
    pub fn with_bundle_destination(mut self, dest: impl Into<String>) -> Self {
        let d = dest.into();
        self.bundle_destination = Some(d.clone());
        if let Some(ref mut insp) = self.bundle_inspection {
            *insp = insp.clone().with_destination(d);
        }
        self
    }

    /// Sets the BPv7 source endpoint identifier.
    #[must_use]
    pub fn with_bundle_source(mut self, src: impl Into<String>) -> Self {
        let s = src.into();
        self.bundle_source = Some(s.clone());
        if let Some(ref mut insp) = self.bundle_inspection {
            *insp = insp.clone().with_source(s);
        }
        self
    }

    /// Sets the BPv7 DTN creation timestamp in milliseconds.
    #[must_use]
    pub fn with_dtn_timestamp(mut self, ts: impl IntoDtnTimestamp) -> Self {
        let (t, _) = ts.into_dtn_timestamp();
        self.dtn_timestamp = Some(t);
        if let Some(ref mut insp) = self.bundle_inspection {
            *insp = insp.clone().with_dtn_timestamp(t);
        }
        self
    }

    /// Sets the BPv7 bundle lifetime in milliseconds.
    #[must_use]
    pub fn with_bundle_lifetime(mut self, lifetime: u64) -> Self {
        self.bundle_lifetime = Some(lifetime);
        if let Some(ref mut insp) = self.bundle_inspection {
            *insp = insp.clone().with_lifetime(lifetime);
        }
        self
    }

    /// Sets the BPv7 bundle parse evaluation status.
    #[must_use]
    pub fn with_parse_status(mut self, status: BundleParseStatus) -> Self {
        self.parse_status = Some(status);
        if let Some(ref mut insp) = self.bundle_inspection {
            *insp = insp.clone().with_parse_status(status);
        }
        self
    }

    /// Attaches BPv7 bundle inspection metadata.
    #[must_use]
    pub fn with_bundle_inspection(mut self, inspection: BundleInspection) -> Self {
        self.bundle_destination = Some(inspection.destination_eid.clone());
        self.bundle_source = Some(inspection.source_eid.clone());
        self.dtn_timestamp = Some(inspection.dtn_timestamp);
        self.bundle_lifetime = Some(inspection.lifetime);
        self.parse_status = Some(inspection.parse_status);
        if self.stage == DiagnosticStage::Received || self.stage == DiagnosticStage::Accepted {
            self.stage = DiagnosticStage::BundleInspection;
        }
        self.bundle_inspection = Some(inspection);
        self
    }

    /// Creates a diagnostic event specifically for BPv7 bundle inspection.
    #[must_use]
    pub fn bundle_inspection(
        destination: impl Into<String>,
        source: impl Into<String>,
        dtn_timestamp: impl IntoDtnTimestamp,
        lifetime: u64,
        parse_status: BundleParseStatus,
    ) -> Self {
        BundleInspection::new(destination, source, dtn_timestamp, lifetime, parse_status).into()
    }

    /// Sets the LTP session originator engine ID.
    #[must_use]
    pub fn with_session_originator(mut self, originator: u64) -> Self {
        self.session_originator = Some(originator);
        if let Some(ref mut insp) = self.ltp_inspection {
            insp.session_originator = originator;
            insp.session_originator_engine_id = Some(originator);
            if let Some(ref mut meta) = insp.ltp_metadata {
                meta.session_originator = originator;
                meta.session_originator_engine_id = Some(originator);
            }
        }
        if let Some(ref mut meta) = self.ltp_metadata {
            meta.session_originator = originator;
            meta.session_originator_engine_id = Some(originator);
        }
        self
    }

    /// Sets the LTP session number.
    #[must_use]
    pub fn with_session_number(mut self, session_number: u64) -> Self {
        self.session_number = Some(session_number);
        if let Some(ref mut insp) = self.ltp_inspection {
            insp.session_number = session_number;
            if let Some(ref mut meta) = insp.ltp_metadata {
                meta.session_number = session_number;
            }
        }
        if let Some(ref mut meta) = self.ltp_metadata {
            meta.session_number = session_number;
        }
        self
    }

    /// Sets the LTP segment type.
    #[must_use]
    pub fn with_segment_type(mut self, segment_type: SegmentType) -> Self {
        self.segment_type = Some(segment_type);
        if let Some(ref mut insp) = self.ltp_inspection {
            insp.segment_type = segment_type;
            if let Some(ref mut meta) = insp.ltp_metadata {
                meta.segment_type = segment_type;
            }
        }
        if let Some(ref mut meta) = self.ltp_metadata {
            meta.segment_type = segment_type;
        }
        self
    }

    /// Sets the LTP parse evaluation status.
    #[must_use]
    pub fn with_ltp_parse_status(mut self, status: LtpParseStatus) -> Self {
        self.ltp_parse_status = Some(status);
        if let Some(ref mut insp) = self.ltp_inspection {
            insp.parse_status = Some(status);
            if let Some(ref mut meta) = insp.ltp_metadata {
                meta.parse_status = Some(status);
            }
        }
        if let Some(ref mut meta) = self.ltp_metadata {
            meta.parse_status = Some(status);
        }
        self
    }

    /// Attaches LTP segment inspection metadata.
    #[must_use]
    pub fn with_ltp_inspection(mut self, inspection: LtpInspection) -> Self {
        self.session_originator = Some(inspection.session_originator);
        self.session_number = Some(inspection.session_number);
        self.segment_type = Some(inspection.segment_type);
        self.ltp_parse_status = inspection.parse_status;
        if self.stage == DiagnosticStage::Received || self.stage == DiagnosticStage::Accepted {
            self.stage = DiagnosticStage::LtpInspection;
        }
        self.ltp_metadata = inspection.ltp_metadata.clone();
        self.ltp_inspection = Some(inspection);
        self
    }

    /// Creates a diagnostic event specifically for LTP segment inspection.
    #[must_use]
    pub fn ltp_inspection(
        session_originator: u64,
        session_number: u64,
        segment_type: SegmentType,
    ) -> Self {
        LtpInspection::new(session_originator, session_number, segment_type).into()
    }

    /// Sets the SRT destination socket ID.
    #[must_use]
    pub fn with_destination_socket_id(mut self, socket_id: u32) -> Self {
        self.destination_socket_id = Some(socket_id);
        if let Some(ref mut insp) = self.srt_inspection {
            insp.destination_socket_id = socket_id;
            if let Some(ref mut meta) = insp.srt_metadata {
                meta.destination_socket_id = socket_id;
            }
        }
        if let Some(ref mut meta) = self.srt_metadata {
            meta.destination_socket_id = socket_id;
        }
        self
    }

    /// Attaches SRT packet inspection metadata.
    #[must_use]
    pub fn with_srt_inspection(mut self, inspection: SrtInspection) -> Self {
        self.destination_socket_id = Some(inspection.destination_socket_id);
        self.srt_timestamp = Some(inspection.timestamp);
        self.srt_timestamp_us = Some(inspection.timestamp);
        self.srt_packet_kind = Some(inspection.packet_kind);
        self.srt_packet_type = Some(inspection.packet_kind);
        self.srt_control_type = inspection.control_type;
        self.srt_parse_status = inspection.parse_status;
        self.srt_sequence_number = inspection.sequence_number;
        if let Some(seq) = inspection.sequence_number {
            self.sequence_number = Some(seq as u64);
        }
        if self.stage == DiagnosticStage::Received || self.stage == DiagnosticStage::Accepted {
            self.stage = DiagnosticStage::SrtInspection;
        }
        self.srt_metadata = inspection.srt_metadata.clone();
        self.srt_inspection = Some(inspection);
        self
    }

    /// Creates a diagnostic event specifically for SRT packet inspection.
    #[must_use]
    pub fn srt_inspection(
        destination_socket_id: u32,
        timestamp: u32,
        packet_kind: SrtPacketKind,
    ) -> Self {
        SrtInspection::new(destination_socket_id, timestamp, packet_kind).into()
    }

    fn ensure_mavlink_metadata(&mut self) -> &mut MavlinkMetadata {
        self.mavlink_metadata
            .get_or_insert_with(|| MavlinkMetadata {
                system_id: self.mavlink_system_id.unwrap_or(0),
                component_id: self.mavlink_component_id.unwrap_or(0),
                sequence: self.mavlink_sequence.unwrap_or(0),
                sequence_number: self.mavlink_sequence,
                message_id: self.mavlink_message_id.unwrap_or(0),
                version: self.mavlink_version,
                payload_length: None,
                incompat_flags: None,
                compat_flags: None,
                is_signed: None,
                total_packet_length: None,
            })
    }

    /// Sets MAVLink system ID.
    #[must_use]
    pub fn with_mavlink_system_id(mut self, sysid: u8) -> Self {
        self.mavlink_system_id = Some(sysid);
        self.ensure_mavlink_metadata().system_id = sysid;
        self
    }

    /// Sets MAVLink component ID.
    #[must_use]
    pub fn with_mavlink_component_id(mut self, compid: u8) -> Self {
        self.mavlink_component_id = Some(compid);
        self.ensure_mavlink_metadata().component_id = compid;
        self
    }

    /// Sets MAVLink sequence number.
    #[must_use]
    pub fn with_mavlink_sequence(mut self, seq: u8) -> Self {
        self.mavlink_sequence = Some(seq);
        if self.sequence_number.is_none() {
            self.sequence_number = Some(u64::from(seq));
        }
        let m = self.ensure_mavlink_metadata();
        m.sequence = seq;
        m.sequence_number = Some(seq);
        self
    }

    /// Sets MAVLink sequence number (alias).
    #[must_use]
    pub fn with_mavlink_sequence_number(self, seq: u8) -> Self {
        self.with_mavlink_sequence(seq)
    }

    /// Sets MAVLink message ID.
    #[must_use]
    pub fn with_mavlink_message_id(mut self, msgid: u32) -> Self {
        self.mavlink_message_id = Some(msgid);
        self.ensure_mavlink_metadata().message_id = msgid;
        self
    }

    /// Sets MAVLink version.
    #[must_use]
    pub fn with_mavlink_version(mut self, ver: u8) -> Self {
        self.mavlink_version = Some(ver);
        self.ensure_mavlink_metadata().version = Some(ver);
        self
    }

    /// Sets MAVLink metadata.
    #[must_use]
    pub fn with_mavlink_metadata(mut self, metadata: MavlinkMetadata) -> Self {
        self.mavlink_system_id = Some(metadata.system_id);
        self.mavlink_component_id = Some(metadata.component_id);
        self.mavlink_sequence = Some(metadata.sequence);
        self.mavlink_message_id = Some(metadata.message_id);
        if let Some(v) = metadata.version {
            self.mavlink_version = Some(v);
        }
        if self.sequence_number.is_none() {
            self.sequence_number = Some(u64::from(metadata.sequence));
        }
        self.mavlink_metadata = Some(metadata);
        self
    }

    /// Enriches event with a parsed MAVLink header.
    #[must_use]
    pub fn with_mavlink_header(self, header: &crate::mavlink::MavlinkHeader) -> Self {
        let meta = MavlinkMetadata {
            system_id: header.system_id,
            component_id: header.component_id,
            sequence: header.sequence,
            sequence_number: Some(header.sequence),
            message_id: header.message_id,
            version: Some(if header.version.is_v1() { 1 } else { 2 }),
            payload_length: Some(header.payload_length),
            incompat_flags: Some(header.incompat_flags),
            compat_flags: Some(header.compat_flags),
            is_signed: Some(header.is_signed),
            total_packet_length: Some(header.total_packet_length),
        };
        self.with_mavlink_metadata(meta)
    }

    /// Attaches MAVLink inspection event metadata.
    #[must_use]
    pub fn with_mavlink_inspection(mut self, inspection: MavlinkInspection) -> Self {
        self.mavlink_system_id = Some(inspection.system_id);
        self.mavlink_component_id = Some(inspection.component_id);
        self.mavlink_sequence = Some(inspection.sequence);
        self.mavlink_message_id = Some(inspection.message_id);
        self.mavlink_version = inspection.version;
        self.mavlink_parse_status = inspection.parse_status;
        if self.sequence_number.is_none() {
            self.sequence_number = Some(u64::from(inspection.sequence));
        }
        if self.stage == DiagnosticStage::Received || self.stage == DiagnosticStage::Accepted {
            self.stage = DiagnosticStage::MavlinkInspection;
        }
        self.mavlink_metadata = inspection.mavlink_metadata.clone();
        self.mavlink_inspection = Some(inspection);
        self
    }

    /// Creates a diagnostic event specifically for MAVLink packet inspection.
    #[must_use]
    pub fn mavlink_inspection(
        system_id: u8,
        component_id: u8,
        sequence: u8,
        message_id: u32,
    ) -> Self {
        MavlinkInspection::new(system_id, component_id, sequence, message_id).into()
    }
}

/// Injected clock abstraction for deterministic testing without reading wall clock or sleeping.
pub trait Clock: fmt::Debug + Send + Sync {
    /// Monotonic timestamp in nanoseconds.
    fn monotonic_nanos(&self) -> u64;

    /// Wall-clock timestamp in nanoseconds since UNIX epoch.
    fn wall_clock_nanos(&self) -> u64;

    /// Monotonic timestamp as Duration.
    fn monotonic_duration(&self) -> Duration {
        Duration::from_nanos(self.monotonic_nanos())
    }

    /// Wall-clock timestamp as SystemTime.
    fn wall_clock_time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(self.wall_clock_nanos())
    }
}

impl<T: Clock + ?Sized> Clock for Arc<T> {
    fn monotonic_nanos(&self) -> u64 {
        (**self).monotonic_nanos()
    }

    fn wall_clock_nanos(&self) -> u64 {
        (**self).wall_clock_nanos()
    }
}

/// Default production clock backed by standard library Instant and SystemTime.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl SystemClock {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn monotonic_nanos(&self) -> u64 {
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = START.get_or_init(Instant::now);
        start.elapsed().as_nanos() as u64
    }

    fn wall_clock_nanos(&self) -> u64 {
        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as u64,
            Err(_) => 0,
        }
    }
}

/// Deterministic manual clock with atomic controls for testing without sleeping.
#[derive(Debug, Clone)]
pub struct ManualClock {
    monotonic_ns: Arc<AtomicU64>,
    wall_clock_ns: Arc<AtomicU64>,
}

impl ManualClock {
    /// Creates a manual clock with given initial monotonic and wall-clock nanoseconds.
    #[must_use]
    pub fn new(monotonic_ns: u64, wall_clock_ns: u64) -> Self {
        Self {
            monotonic_ns: Arc::new(AtomicU64::new(monotonic_ns)),
            wall_clock_ns: Arc::new(AtomicU64::new(wall_clock_ns)),
        }
    }

    /// Advances both monotonic and wall-clock times by `duration`.
    pub fn advance(&self, duration: Duration) {
        let nanos = duration.as_nanos() as u64;
        self.monotonic_ns.fetch_add(nanos, Ordering::SeqCst);
        self.wall_clock_ns.fetch_add(nanos, Ordering::SeqCst);
    }

    /// Advances both monotonic and wall-clock times by `secs` seconds.
    pub fn advance_secs(&self, secs: u64) {
        self.advance(Duration::from_secs(secs));
    }

    /// Advances both monotonic and wall-clock times by `millis` milliseconds.
    pub fn advance_millis(&self, millis: u64) {
        self.advance(Duration::from_millis(millis));
    }

    /// Advances both monotonic and wall-clock times by `nanos` nanoseconds.
    pub fn advance_nanos(&self, nanos: u64) {
        self.advance(Duration::from_nanos(nanos));
    }

    /// Sets the monotonic time in nanoseconds.
    pub fn set_monotonic_nanos(&self, ns: u64) {
        self.monotonic_ns.store(ns, Ordering::SeqCst);
    }

    /// Sets the wall-clock time in nanoseconds.
    pub fn set_wall_clock_nanos(&self, ns: u64) {
        self.wall_clock_ns.store(ns, Ordering::SeqCst);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl Clock for ManualClock {
    fn monotonic_nanos(&self) -> u64 {
        self.monotonic_ns.load(Ordering::SeqCst)
    }

    fn wall_clock_nanos(&self) -> u64 {
        self.wall_clock_ns.load(Ordering::SeqCst)
    }
}

/// Thread-safe manager for operational diagnostic profiles, bounded test runs,
/// correlation IDs, expiry, and reversion to prior diagnostic levels (SPEC §10).
#[derive(Debug)]
pub struct DiagnosticTestState {
    instance_id: String,
    configured_mode: OperationalMode,
    prior_mode: OperationalMode,
    correlation_id: Option<String>,
    duration_nanos: Option<u64>,
    expiry_seconds: Option<u64>,
    max_events: Option<u64>,
    start_monotonic_ns: u64,
    recorded_events: AtomicU64,
    ended: AtomicBool,
    end_reason: Mutex<Option<String>>,
    pending_end_event: Mutex<Option<DiagnosticEvent>>,
    clock: Arc<dyn Clock>,
}

impl DiagnosticTestState {
    /// Creates a new operational mode and test state manager.
    #[must_use]
    pub fn new(
        instance_id: impl Into<String>,
        mode: OperationalMode,
        correlation_id: Option<String>,
        expiry_seconds: Option<u64>,
        max_events: Option<u64>,
        prior_mode: Option<OperationalMode>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let duration_nanos = expiry_seconds.map(|s| s.saturating_mul(1_000_000_000));
        let start_monotonic_ns = clock.monotonic_nanos();
        let prior_mode = prior_mode.unwrap_or(OperationalMode::Production);
        Self {
            instance_id: instance_id.into(),
            configured_mode: mode,
            prior_mode,
            correlation_id,
            duration_nanos,
            expiry_seconds,
            max_events,
            start_monotonic_ns,
            recorded_events: AtomicU64::new(0),
            ended: AtomicBool::new(false),
            end_reason: Mutex::new(None),
            pending_end_event: Mutex::new(None),
            clock,
        }
    }

    /// Returns the current operational mode, checking bounds/expiry and reverting to prior_mode if ended.
    pub fn current_mode(&self) -> OperationalMode {
        if self.configured_mode != OperationalMode::Test {
            return self.configured_mode;
        }

        if self.ended.load(Ordering::SeqCst) {
            return self.prior_mode;
        }

        // Check duration bound / expiry
        if let Some(dur_ns) = self.duration_nanos {
            let now_ns = self.clock.monotonic_nanos();
            if now_ns.saturating_sub(self.start_monotonic_ns) >= dur_ns {
                self.end_run(format!(
                    "test run ended: reached duration bound (configured expiry of {}s)",
                    self.expiry_seconds.unwrap_or(0)
                ));
                return self.prior_mode;
            }
        }

        // Check event count bound
        if let Some(max) = self.max_events {
            if self.recorded_events.load(Ordering::SeqCst) >= max {
                self.end_run(format!(
                    "test run ended: reached event bound (maximum {} events recorded)",
                    max
                ));
                return self.prior_mode;
            }
        }

        OperationalMode::Test
    }

    /// Ends the test run with the given reason, recording an end event and switching mode to prior_mode.
    pub fn end_run(&self, reason: impl Into<String>) {
        if !self.ended.swap(true, Ordering::SeqCst) {
            let r = reason.into();
            if let Ok(mut lock) = self.end_reason.lock() {
                *lock = Some(r.clone());
            }
            let mut event = DiagnosticEvent::new(
                self.clock.monotonic_nanos(),
                self.clock.wall_clock_nanos(),
                self.instance_id.clone(),
                DiagnosticStage::HealthTransition,
                TransportType::Udp,
                0,
            )
            .with_reason(r);
            if let Some(ref cid) = self.correlation_id {
                event = event.with_correlation_id(cid.clone());
            }
            if let Ok(mut lock) = self.pending_end_event.lock() {
                *lock = Some(event);
            }
        }
    }

    /// Whether packet-level diagnostic events should currently be emitted.
    #[must_use]
    pub fn should_emit_packet_events(&self) -> bool {
        match self.current_mode() {
            OperationalMode::Debug | OperationalMode::Test => true,
            OperationalMode::Production => false,
        }
    }

    /// Configured correlation identifier if currently active in test run.
    #[must_use]
    pub fn active_correlation_id(&self) -> Option<String> {
        if self.current_mode() == OperationalMode::Test {
            self.correlation_id.clone()
        } else {
            None
        }
    }

    /// Configured expiry seconds if currently active in test mode.
    #[must_use]
    pub fn current_expiry_seconds(&self) -> Option<u64> {
        if self.current_mode() == OperationalMode::Test {
            self.expiry_seconds
        } else {
            None
        }
    }

    /// Configured correlation identifier regardless of active state.
    #[must_use]
    pub fn configured_correlation_id(&self) -> Option<String> {
        self.correlation_id.clone()
    }

    /// Reason why the test run ended (if ended).
    #[must_use]
    pub fn end_reason(&self) -> Option<String> {
        self.end_reason.lock().ok().and_then(|r| r.clone())
    }

    /// Total events recorded during the test run.
    #[must_use]
    pub fn recorded_events(&self) -> u64 {
        self.recorded_events.load(Ordering::SeqCst)
    }

    /// Takes any pending diagnostic end event.
    pub fn take_pending_end_event(&self) -> Option<DiagnosticEvent> {
        self.pending_end_event
            .lock()
            .ok()
            .and_then(|mut g| g.take())
    }

    /// Records an event in the test run, returning the correlation ID to attach (if active).
    /// If the recorded count reaches the event bound, the test run is ended.
    pub fn on_event_recorded(&self) -> Option<String> {
        if self.current_mode() != OperationalMode::Test {
            return None;
        }

        let count = self.recorded_events.fetch_add(1, Ordering::SeqCst) + 1;
        let corr = self.correlation_id.clone();

        if let Some(max) = self.max_events {
            if count >= max {
                self.end_run(format!(
                    "test run ended: reached event bound (maximum {} events recorded)",
                    max
                ));
            }
        }

        corr
    }
}

/// Per-second rate limiter for diagnostic events.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    max_per_second: u64,
    current_second: Option<u64>,
    count_in_current_second: u64,
}

impl RateLimiter {
    /// Creates a rate limiter allowing up to `max_per_second` events per second.
    #[must_use]
    pub fn new(max_per_second: u64) -> Self {
        Self {
            max_per_second,
            current_second: None,
            count_in_current_second: 0,
        }
    }

    /// Configured maximum events allowed per second.
    #[must_use]
    pub fn max_per_second(&self) -> u64 {
        self.max_per_second
    }

    /// Evaluates if an event at `now_ns` monotonic nanoseconds is accepted under rate limit.
    pub fn check_and_record(&mut self, now_ns: u64) -> bool {
        if self.max_per_second == 0 {
            return false;
        }

        let second = now_ns / 1_000_000_000;
        match self.current_second {
            Some(curr) if curr == second => {
                if self.count_in_current_second >= self.max_per_second {
                    false
                } else {
                    self.count_in_current_second += 1;
                    true
                }
            }
            _ => {
                self.current_second = Some(second);
                self.count_in_current_second = 1;
                true
            }
        }
    }

    /// Resets the rate limiter counters.
    pub fn reset(&mut self) {
        self.current_second = None;
        self.count_in_current_second = 0;
    }
}

/// Internal buffer state protected by non-blocking lock.
#[derive(Debug)]
pub struct DiagnosticBufferInner {
    events: VecDeque<DiagnosticEvent>,
    capacity: usize,
    rate_limiter: Option<RateLimiter>,
}

impl DiagnosticBufferInner {
    /// Reference to internal deque of events.
    #[must_use]
    pub fn events(&self) -> &VecDeque<DiagnosticEvent> {
        &self.events
    }

    /// Configured buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Snapshot of diagnostic buffer contents and dropped event count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticSnapshot {
    /// Diagnostic events in arrival order (oldest to newest).
    pub events: Vec<DiagnosticEvent>,
    /// Number of diagnostic events dropped due to capacity, contention, or rate limits.
    pub dropped_count: u64,
}

impl DiagnosticSnapshot {
    #[must_use]
    pub fn new(events: Vec<DiagnosticEvent>, dropped_count: u64) -> Self {
        Self {
            events,
            dropped_count,
        }
    }
}

impl From<DiagnosticSnapshot> for (Vec<DiagnosticEvent>, u64) {
    fn from(snap: DiagnosticSnapshot) -> Self {
        (snap.events, snap.dropped_count)
    }
}

/// Bounded, non-blocking diagnostic event buffer (SPEC §8, §10).
///
/// Ensures emitting diagnostic events never blocks packet forwarding threads.
#[derive(Debug, Clone)]
pub struct DiagnosticBuffer {
    inner: Arc<Mutex<DiagnosticBufferInner>>,
    dropped_count: Arc<AtomicU64>,
    clock: Arc<dyn Clock>,
    test_state: Arc<Mutex<Option<Arc<DiagnosticTestState>>>>,
}

impl DiagnosticBuffer {
    /// Creates a buffer with `capacity`, using `SystemClock` and no rate limit.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_clock_and_rate_limit_opt(capacity, Arc::new(SystemClock::new()), None)
    }

    /// Creates a buffer with injected `clock` and no rate limit.
    #[must_use]
    pub fn with_clock(capacity: usize, clock: Arc<dyn Clock>) -> Self {
        Self::with_clock_and_rate_limit_opt(capacity, clock, None)
    }

    /// Creates a buffer with `SystemClock` and per-second rate limit.
    #[must_use]
    pub fn with_rate_limit(capacity: usize, max_events_per_second: u64) -> Self {
        Self::with_clock_and_rate_limit_opt(
            capacity,
            Arc::new(SystemClock::new()),
            Some(max_events_per_second),
        )
    }

    /// Creates a buffer with injected `clock` and per-second rate limit.
    #[must_use]
    pub fn with_clock_and_rate_limit(
        capacity: usize,
        clock: Arc<dyn Clock>,
        max_events_per_second: u64,
    ) -> Self {
        Self::with_clock_and_rate_limit_opt(capacity, clock, Some(max_events_per_second))
    }

    /// Creates a buffer with optional rate limit.
    #[must_use]
    pub fn with_clock_and_rate_limit_opt(
        capacity: usize,
        clock: Arc<dyn Clock>,
        rate_limit_per_second: Option<u64>,
    ) -> Self {
        let rate_limiter = rate_limit_per_second.map(RateLimiter::new);
        Self {
            inner: Arc::new(Mutex::new(DiagnosticBufferInner {
                events: VecDeque::with_capacity(capacity),
                capacity,
                rate_limiter,
            })),
            dropped_count: Arc::new(AtomicU64::new(0)),
            clock,
            test_state: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns a builder for configuring a `DiagnosticBuffer`.
    #[must_use]
    pub fn builder(capacity: usize) -> DiagnosticBufferBuilder {
        DiagnosticBufferBuilder::new(capacity)
    }

    /// Returns the active test state manager, if configured.
    #[must_use]
    pub fn test_state(&self) -> Option<Arc<DiagnosticTestState>> {
        self.test_state.lock().ok().and_then(|g| g.clone())
    }

    /// Sets or replaces the operational test state manager.
    pub fn set_test_state(&self, state: Arc<DiagnosticTestState>) {
        if let Ok(mut g) = self.test_state.lock() {
            *g = Some(state);
        }
    }

    /// Returns the current operational mode (checking test expiry/bounds).
    #[must_use]
    pub fn current_mode(&self) -> OperationalMode {
        self.test_state()
            .map(|ts| ts.current_mode())
            .unwrap_or(OperationalMode::Production)
    }

    /// Returns whether packet-level diagnostic events should currently be emitted.
    #[must_use]
    pub fn should_emit_packet_events(&self) -> bool {
        self.test_state()
            .map(|ts| ts.should_emit_packet_events())
            .unwrap_or(false)
    }

    /// Returns configured expiry seconds if currently in test mode.
    #[must_use]
    pub fn current_expiry(&self) -> Option<u64> {
        self.test_state().and_then(|ts| ts.current_expiry_seconds())
    }

    /// Returns the active test run correlation ID.
    #[must_use]
    pub fn correlation_id(&self) -> Option<String> {
        self.test_state().and_then(|ts| {
            ts.active_correlation_id()
                .or_else(|| ts.configured_correlation_id())
        })
    }

    /// Returns the reason why the test run ended (if ended).
    #[must_use]
    pub fn test_end_reason(&self) -> Option<String> {
        self.test_state().and_then(|ts| ts.end_reason())
    }

    /// Total number of diagnostic events dropped (full capacity, contention, or rate limit).
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::SeqCst)
    }

    /// Current number of events stored in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.events.len())
    }

    /// True if buffer currently contains zero events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Configured buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.lock().map_or(0, |g| g.capacity)
    }

    /// Reference to injected clock.
    #[must_use]
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Acquires buffer lock directly for testing lock contention.
    pub fn hold_lock(&self) -> MutexGuard<'_, DiagnosticBufferInner> {
        self.inner.lock().unwrap()
    }

    /// Alias for `hold_lock` for internal test use.
    pub fn lock_internal(&self) -> MutexGuard<'_, DiagnosticBufferInner> {
        self.hold_lock()
    }

    fn push_event_locked(&self, inner: &mut DiagnosticBufferInner, event: DiagnosticEvent) -> bool {
        // Check rate limit if configured
        if let Some(ref mut limiter) = inner.rate_limiter {
            let now_ns = self.clock.monotonic_nanos();
            if !limiter.check_and_record(now_ns) {
                self.dropped_count.fetch_add(1, Ordering::SeqCst);
                return false;
            }
        }

        // Check capacity
        if inner.capacity == 0 {
            self.dropped_count.fetch_add(1, Ordering::SeqCst);
            return false;
        }

        if inner.events.len() >= inner.capacity {
            inner.events.pop_front();
            self.dropped_count.fetch_add(1, Ordering::SeqCst);
        }

        inner.events.push_back(event);
        true
    }

    /// Emits a diagnostic event.
    ///
    /// This method is strictly non-blocking. If another thread holds the buffer,
    /// it returns immediately with `false`, and increments the dropped count.
    /// If a per-second rate limit is exceeded, it returns immediately with `false`
    /// and increments the dropped count.
    /// If the buffer is full, the oldest event is overwritten and the dropped count is incremented.
    pub fn emit(&self, event: impl Into<DiagnosticEvent>) -> bool {
        let mut event = event.into();
        let mut pending_event = None;
        if let Some(ts) = self.test_state() {
            if ts.current_mode() == OperationalMode::Test {
                if let Some(corr) = ts.on_event_recorded() {
                    if event.correlation_id.is_none() {
                        event.correlation_id = Some(corr);
                    }
                }
            }
            pending_event = ts.take_pending_end_event();
        }

        let Ok(mut inner) = self.inner.try_lock() else {
            self.dropped_count.fetch_add(1, Ordering::SeqCst);
            return false;
        };

        let res = self.push_event_locked(&mut inner, event);

        if let Some(end_ev) = pending_event {
            self.push_event_locked(&mut inner, end_ev);
        }

        res
    }

    /// Creates a [`BundleInspection`] event populated with buffer clock timestamps.
    #[must_use]
    pub fn create_bundle_inspection(
        &self,
        stream_id: impl Into<String>,
        destination: impl Into<String>,
        source: impl Into<String>,
        dtn_timestamp: impl IntoDtnTimestamp,
        lifetime: u64,
        parse_status: BundleParseStatus,
    ) -> BundleInspection {
        let mut insp =
            BundleInspection::new(destination, source, dtn_timestamp, lifetime, parse_status);
        insp.stream_id = Some(stream_id.into());
        insp.monotonic_timestamp = Some(self.clock.monotonic_nanos());
        insp.wall_clock_timestamp = Some(self.clock.wall_clock_nanos());
        insp
    }

    /// Emits a [`BundleInspection`] event into the diagnostic buffer.
    pub fn emit_bundle_inspection(&self, inspection: BundleInspection) -> bool {
        self.emit(inspection)
    }

    /// Creates an [`LtpInspection`] event populated with buffer clock timestamps.
    #[must_use]
    pub fn create_ltp_inspection(
        &self,
        stream_id: impl Into<String>,
        session_originator: u64,
        session_number: u64,
        segment_type: SegmentType,
    ) -> LtpInspection {
        let mut insp = LtpInspection::new(session_originator, session_number, segment_type);
        insp.stream_id = Some(stream_id.into());
        insp.monotonic_timestamp = Some(self.clock.monotonic_nanos());
        insp.wall_clock_timestamp = Some(self.clock.wall_clock_nanos());
        insp
    }

    /// Emits an [`LtpInspection`] event into the diagnostic buffer.
    pub fn emit_ltp_inspection(&self, inspection: LtpInspection) -> bool {
        self.emit(inspection)
    }

    /// Creates an [`SrtInspection`] event populated with buffer clock timestamps.
    #[must_use]
    pub fn create_srt_inspection(
        &self,
        stream_id: impl Into<String>,
        destination_socket_id: u32,
        timestamp: u32,
        packet_kind: SrtPacketKind,
    ) -> SrtInspection {
        let mut insp = SrtInspection::new(destination_socket_id, timestamp, packet_kind);
        insp.stream_id = Some(stream_id.into());
        insp.monotonic_timestamp = Some(self.clock.monotonic_nanos());
        insp.wall_clock_timestamp = Some(self.clock.wall_clock_nanos());
        insp
    }

    /// Emits an [`SrtInspection`] event into the diagnostic buffer.
    pub fn emit_srt_inspection(&self, inspection: SrtInspection) -> bool {
        self.emit(inspection)
    }

    /// Creates a diagnostic event using the buffer's injected clock timestamps.
    #[must_use]
    pub fn create_event(
        &self,
        stream_id: impl Into<String>,
        stage: DiagnosticStage,
        transport: TransportType,
        payload_length: u64,
    ) -> DiagnosticEvent {
        DiagnosticEvent::new(
            self.clock.monotonic_nanos(),
            self.clock.wall_clock_nanos(),
            stream_id,
            stage,
            transport,
            payload_length,
        )
    }

    /// Creates and emits a diagnostic event using the buffer's injected clock.
    pub fn emit_stage(
        &self,
        stream_id: impl Into<String>,
        stage: DiagnosticStage,
        transport: TransportType,
        payload_length: u64,
    ) -> bool {
        let event = self.create_event(stream_id, stage, transport, payload_length);
        self.emit(event)
    }

    /// Returns a snapshot of events in arrival order along with dropped event counter.
    pub fn snapshot(&self) -> DiagnosticSnapshot {
        if let Some(ts) = self.test_state() {
            let _ = ts.current_mode();
            if let Some(end_ev) = ts.take_pending_end_event() {
                if let Ok(mut inner) = self.inner.lock() {
                    self.push_event_locked(&mut inner, end_ev);
                }
            }
        }

        let events = self
            .inner
            .lock()
            .map(|g| g.events.iter().cloned().collect())
            .unwrap_or_default();
        let dropped_count = self.dropped_count.load(Ordering::SeqCst);
        DiagnosticSnapshot::new(events, dropped_count)
    }

    /// Returns a snapshot as tuple `(events, dropped_count)`.
    pub fn snapshot_events(&self) -> (Vec<DiagnosticEvent>, u64) {
        let snap = self.snapshot();
        (snap.events, snap.dropped_count)
    }

    /// Clears all events from buffer while preserving dropped count.
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.events.clear();
        }
    }

    /// Resets all events and the dropped counter.
    pub fn reset(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.events.clear();
            if let Some(ref mut limiter) = inner.rate_limiter {
                limiter.reset();
            }
        }
        self.dropped_count.store(0, Ordering::SeqCst);
    }
}

/// Builder for constructing a `DiagnosticBuffer`.
#[derive(Debug)]
pub struct DiagnosticBufferBuilder {
    capacity: usize,
    clock: Option<Arc<dyn Clock>>,
    rate_limit_per_second: Option<u64>,
}

impl DiagnosticBufferBuilder {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            clock: None,
            rate_limit_per_second: None,
        }
    }

    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    #[must_use]
    pub fn rate_limit(mut self, max_per_second: u64) -> Self {
        self.rate_limit_per_second = Some(max_per_second);
        self
    }

    #[must_use]
    pub fn build(self) -> DiagnosticBuffer {
        let clock = self.clock.unwrap_or_else(|| Arc::new(SystemClock::new()));
        DiagnosticBuffer::with_clock_and_rate_limit_opt(
            self.capacity,
            clock,
            self.rate_limit_per_second,
        )
    }
}

/// Formats a length-bounded hexadecimal preview of packet payload bytes (SPEC §8).
#[must_use]
pub fn format_hex_preview(bytes: &[u8], max_bytes: usize) -> String {
    let bound = bytes.len().min(max_bytes.min(1024));
    let slice = &bytes[..bound];
    let mut hex = String::with_capacity(slice.len() * 2);
    for b in slice {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Formats a length-bounded ASCII preview of packet payload bytes (SPEC §8).
/// Non-printable characters are replaced with '.'.
#[must_use]
pub fn format_ascii_preview(bytes: &[u8], max_bytes: usize) -> String {
    let bound = bytes.len().min(max_bytes.min(1024));
    let slice = &bytes[..bound];
    slice
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Point-in-time sequence tracking and continuity state for a stream (SPEC §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceState {
    pub stream_id: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_order: Option<ByteOrder>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollover_threshold: Option<u64>,
    pub packets_evaluated: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_sequence: Option<u64>,
    pub gap_count: u64,
    pub duplicate_count: u64,
    pub out_of_order_count: u64,
    pub rollover_count: u64,
    pub hex_preview_enabled: bool,
    pub ascii_preview_enabled: bool,
    pub max_preview_bytes: usize,
}

/// Outcome of evaluating an individual packet sequence number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SequenceTrackingEvent {
    Initial {
        sequence: u64,
    },
    InOrder {
        sequence: u64,
    },
    Gap {
        expected: u64,
        actual: u64,
        missing_count: u64,
    },
    Duplicate {
        sequence: u64,
    },
    OutOfOrder {
        sequence: u64,
        previous_highest: u64,
    },
    Rollover {
        sequence: u64,
        missing_count: u64,
    },
}

fn default_modulus_for_width(width: usize) -> u128 {
    match width {
        1 => 256,
        2 => 65536,
        4 => 4_294_967_296,
        8 => u64::MAX as u128 + 1,
        _ => 4_294_967_296,
    }
}

/// Stateful sequence extractor and continuity tracker for an individual stream.
#[derive(Debug, Clone)]
pub struct SequenceTracker {
    stream_id: String,
    enabled: bool,
    offset: usize,
    width: usize,
    byte_order: ByteOrder,
    rollover_threshold: Option<u64>,
    hex_preview_enabled: bool,
    ascii_preview_enabled: bool,
    max_preview_bytes: usize,
    packets_evaluated: u64,
    last_sequence: Option<u64>,
    highest_sequence: Option<u64>,
    gap_count: u64,
    duplicate_count: u64,
    out_of_order_count: u64,
    rollover_count: u64,
    recent_seen_queue: VecDeque<u64>,
    recent_seen_set: HashSet<u64>,
}

impl SequenceTracker {
    /// Creates a new sequence tracker from optional sequence and inspection configurations.
    #[must_use]
    pub fn new(
        stream_id: impl Into<String>,
        seq_cfg: Option<&SequenceConfig>,
        insp_cfg: Option<&InspectionConfig>,
    ) -> Self {
        let stream_id = stream_id.into();
        let enabled = seq_cfg.map(|c| c.enabled).unwrap_or(false);
        let offset = seq_cfg.map(|c| c.offset).unwrap_or(0);
        let width = seq_cfg.map(|c| c.width).unwrap_or(4);
        let byte_order = seq_cfg.map(|c| c.byte_order).unwrap_or_default();
        let rollover_threshold = seq_cfg.and_then(|c| c.rollover_threshold);

        let hex_preview_enabled = insp_cfg.map(|i| i.hex_preview).unwrap_or(false)
            || seq_cfg.and_then(|c| c.hex_preview).unwrap_or(false);
        let ascii_preview_enabled = insp_cfg.map(|i| i.ascii_preview).unwrap_or(false)
            || seq_cfg.and_then(|c| c.ascii_preview).unwrap_or(false);
        let max_preview_bytes = insp_cfg
            .map(|i| i.max_preview_bytes)
            .or_else(|| seq_cfg.and_then(|c| c.max_preview_bytes))
            .unwrap_or(64);

        Self {
            stream_id,
            enabled,
            offset,
            width,
            byte_order,
            rollover_threshold,
            hex_preview_enabled,
            ascii_preview_enabled,
            max_preview_bytes,
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

    /// Creates a disabled sequence tracker.
    #[must_use]
    pub fn disabled(stream_id: impl Into<String>) -> Self {
        Self::new(stream_id, None, None)
    }

    /// Returns whether sequence extraction is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the last sequence number processed, if any.
    #[must_use]
    pub fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    /// Extracts the raw sequence number from a packet payload slice according to configured offset, width, and byte order.
    #[must_use]
    pub fn extract_sequence(&self, payload: &[u8]) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        if payload.len() < self.offset + self.width {
            return None;
        }
        let slice = &payload[self.offset..self.offset + self.width];
        let val = match self.width {
            1 => slice[0] as u64,
            2 => match self.byte_order {
                ByteOrder::BigEndian => u16::from_be_bytes(slice.try_into().ok()?) as u64,
                ByteOrder::LittleEndian => u16::from_le_bytes(slice.try_into().ok()?) as u64,
            },
            4 => match self.byte_order {
                ByteOrder::BigEndian => u32::from_be_bytes(slice.try_into().ok()?) as u64,
                ByteOrder::LittleEndian => u32::from_le_bytes(slice.try_into().ok()?) as u64,
            },
            8 => match self.byte_order {
                ByteOrder::BigEndian => u64::from_be_bytes(slice.try_into().ok()?),
                ByteOrder::LittleEndian => u64::from_le_bytes(slice.try_into().ok()?),
            },
            _ => return None,
        };
        Some(val)
    }

    /// Formats hex and ASCII previews if configured.
    #[must_use]
    pub fn format_previews(&self, payload: &[u8]) -> (Option<String>, Option<String>) {
        let hex = if self.hex_preview_enabled {
            Some(format_hex_preview(payload, self.max_preview_bytes))
        } else {
            None
        };
        let ascii = if self.ascii_preview_enabled {
            Some(format_ascii_preview(payload, self.max_preview_bytes))
        } else {
            None
        };
        (hex, ascii)
    }

    /// Extracts and records the sequence number from a payload slice.
    pub fn process_packet(&mut self, payload: &[u8]) -> Option<SequenceTrackingEvent> {
        if !self.enabled {
            return None;
        }
        let seq = self.extract_sequence(payload)?;
        Some(self.record_sequence(seq))
    }

    /// Evaluates an extracted sequence number and updates continuity counters.
    pub fn record_sequence(&mut self, seq: u64) -> SequenceTrackingEvent {
        self.packets_evaluated += 1;
        let last = match self.last_sequence {
            None => {
                self.last_sequence = Some(seq);
                self.highest_sequence = Some(seq);
                self.remember_seen(seq);
                return SequenceTrackingEvent::Initial { sequence: seq };
            }
            Some(l) => l,
        };

        let modulus = self
            .rollover_threshold
            .map(|t| t as u128)
            .unwrap_or_else(|| default_modulus_for_width(self.width));

        let seq_u = seq as u128;
        let last_u = last as u128;

        if seq == last || self.recent_seen_set.contains(&seq) {
            self.duplicate_count += 1;
            return SequenceTrackingEvent::Duplicate { sequence: seq };
        }

        self.remember_seen(seq);

        if seq > last {
            let dist_forward = seq_u - last_u;
            if dist_forward < modulus / 2 {
                self.last_sequence = Some(seq);
                if seq > self.highest_sequence.unwrap_or(0) {
                    self.highest_sequence = Some(seq);
                }
                if dist_forward == 1 {
                    SequenceTrackingEvent::InOrder { sequence: seq }
                } else {
                    let missing = (dist_forward - 1) as u64;
                    self.gap_count += missing;
                    let expected = ((last_u + 1) % modulus) as u64;
                    SequenceTrackingEvent::Gap {
                        expected,
                        actual: seq,
                        missing_count: missing,
                    }
                }
            } else {
                self.out_of_order_count += 1;
                SequenceTrackingEvent::OutOfOrder {
                    sequence: seq,
                    previous_highest: self.highest_sequence.unwrap_or(last),
                }
            }
        } else {
            // seq < last
            let dist_backward = last_u - seq_u;
            let dist_rollover = (seq_u + modulus) - last_u;

            if dist_rollover < modulus / 2 {
                self.rollover_count += 1;
                self.last_sequence = Some(seq);
                self.highest_sequence = Some(seq);
                if dist_rollover == 1 {
                    SequenceTrackingEvent::Rollover {
                        sequence: seq,
                        missing_count: 0,
                    }
                } else {
                    let missing = (dist_rollover - 1) as u64;
                    self.gap_count += missing;
                    SequenceTrackingEvent::Rollover {
                        sequence: seq,
                        missing_count: missing,
                    }
                }
            } else {
                let _ = dist_backward;
                self.out_of_order_count += 1;
                SequenceTrackingEvent::OutOfOrder {
                    sequence: seq,
                    previous_highest: self.highest_sequence.unwrap_or(last),
                }
            }
        }
    }

    fn remember_seen(&mut self, seq: u64) {
        if self.recent_seen_queue.len() >= 10_000 {
            if let Some(old) = self.recent_seen_queue.pop_front() {
                self.recent_seen_set.remove(&old);
            }
        }
        self.recent_seen_queue.push_back(seq);
        self.recent_seen_set.insert(seq);
    }

    /// Captures a point-in-time snapshot of the sequence state.
    #[must_use]
    pub fn snapshot(&self) -> SequenceState {
        SequenceState {
            stream_id: self.stream_id.clone(),
            enabled: self.enabled,
            offset: if self.enabled {
                Some(self.offset)
            } else {
                None
            },
            width: if self.enabled { Some(self.width) } else { None },
            byte_order: if self.enabled {
                Some(self.byte_order)
            } else {
                None
            },
            rollover_threshold: if self.enabled {
                self.rollover_threshold
                    .or_else(|| Some(default_modulus_for_width(self.width) as u64))
            } else {
                None
            },
            packets_evaluated: self.packets_evaluated,
            last_sequence: self.last_sequence,
            highest_sequence: self.highest_sequence,
            gap_count: self.gap_count,
            duplicate_count: self.duplicate_count,
            out_of_order_count: self.out_of_order_count,
            rollover_count: self.rollover_count,
            hex_preview_enabled: self.hex_preview_enabled,
            ascii_preview_enabled: self.ascii_preview_enabled,
            max_preview_bytes: self.max_preview_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn test_stage_serialization_pinned() {
        let stages = [
            (DiagnosticStage::Received, "\"received\""),
            (DiagnosticStage::Accepted, "\"accepted\""),
            (DiagnosticStage::RoutedOrQueued, "\"routed_or_queued\""),
            (DiagnosticStage::SendAttempted, "\"send_attempted\""),
            (DiagnosticStage::SendSucceeded, "\"send_succeeded\""),
            (DiagnosticStage::Dropped, "\"dropped\""),
            (DiagnosticStage::Failure, "\"failure\""),
            (DiagnosticStage::HealthTransition, "\"health_transition\""),
            (DiagnosticStage::BundleInspection, "\"bundle_inspection\""),
            (DiagnosticStage::LtpInspection, "\"ltp_inspection\""),
        ];

        for (stage, expected_json) in stages {
            let serialized = serde_json::to_string(&stage).expect("failed to serialize stage");
            assert_eq!(serialized, expected_json);

            let deserialized: DiagnosticStage =
                serde_json::from_str(expected_json).expect("failed to deserialize stage");
            assert_eq!(deserialized, stage);

            // Display and FromStr roundtrip
            let display_str = stage.to_string();
            let parsed: DiagnosticStage = display_str.parse().expect("failed to parse stage");
            assert_eq!(parsed, stage);
        }
    }

    #[test]
    fn test_bundle_inspection_event_serialization_contains_structured_metadata() {
        let event = BundleInspection::new(
            "ipn:10.1",
            "dtn://node-alpha/telemetry",
            123_456_789u64,
            86_400_000u64,
            BundleParseStatus::Valid,
        );

        let json = serde_json::to_string(&event).expect("must serialize to JSON");
        let val: serde_json::Value = serde_json::from_str(&json).expect("must parse JSON");

        // Verify endpoint identifiers
        assert_eq!(val["destination"], "ipn:10.1");
        assert_eq!(val["source"], "dtn://node-alpha/telemetry");
        assert_eq!(val["destination_eid"], "ipn:10.1");
        assert_eq!(val["source_eid"], "dtn://node-alpha/telemetry");

        // Verify DTN timestamp
        assert_eq!(val["dtn_timestamp"], 123_456_789);
        assert_eq!(val["creation_timestamp"]["time"], 123_456_789);

        // Verify lifetime and status
        assert_eq!(val["lifetime"], 86_400_000);
        assert_eq!(val["parse_status"], "valid");

        // Verify structured bundle metadata nested object
        assert!(val["bundle_metadata"].is_object());
        assert_eq!(val["bundle_metadata"]["destination"], "ipn:10.1");
        assert_eq!(
            val["bundle_metadata"]["source"],
            "dtn://node-alpha/telemetry"
        );
        assert_eq!(val["bundle_metadata"]["dtn_timestamp"], 123_456_789);
        assert_eq!(val["bundle_metadata"]["lifetime"], 86_400_000);
        assert_eq!(val["bundle_metadata"]["parse_status"], "valid");

        // Also test serialization when converted to DiagnosticEvent
        let diag_event: DiagnosticEvent = event.into();
        let diag_json = serde_json::to_string(&diag_event).expect("must serialize DiagnosticEvent");
        let diag_val: serde_json::Value =
            serde_json::from_str(&diag_json).expect("must parse DiagnosticEvent JSON");
        assert_eq!(diag_val["stage"], "bundle_inspection");
        assert_eq!(diag_val["destination_endpoint"], "ipn:10.1");
        assert_eq!(diag_val["source_endpoint"], "dtn://node-alpha/telemetry");
        assert_eq!(diag_val["bundle_destination"], "ipn:10.1");
        assert_eq!(diag_val["bundle_source"], "dtn://node-alpha/telemetry");
        assert_eq!(diag_val["dtn_timestamp"], 123_456_789);
        assert_eq!(diag_val["bundle_lifetime"], 86_400_000);
        assert_eq!(diag_val["parse_status"], "valid");
        assert!(diag_val["bundle_inspection"].is_object());
    }

    #[test]
    fn test_emitting_bundle_inspection_into_full_buffer_drops_without_blocking_or_panicking() {
        let clock = Arc::new(ManualClock::new(100, 200));
        let buffer = DiagnosticBuffer::with_clock(2, clock);
        assert_eq!(buffer.capacity(), 2);

        // Fill buffer to capacity
        let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Udp, 100);
        let ev2 = buffer.create_event("s1", DiagnosticStage::Accepted, TransportType::Udp, 100);
        assert!(buffer.emit(ev1));
        assert!(buffer.emit(ev2));
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.dropped_count(), 0);

        // Emit BundleInspection into the full buffer
        let bundle_ev = BundleInspection::new(
            "ipn:1.1",
            "dtn:none",
            1000u64,
            3600u64,
            BundleParseStatus::Valid,
        );

        // This must drop without blocking or panicking
        let emitted = buffer.emit(bundle_ev);
        assert!(emitted);
        assert_eq!(buffer.len(), 2);
        assert_eq!(
            buffer.dropped_count(),
            1,
            "emitting into full buffer must increment dropped_count"
        );

        // Verify in snapshot that the oldest was dropped and buffer contains the bundle inspection
        let snap = buffer.snapshot();
        assert_eq!(snap.dropped_count, 1);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[1].stage, DiagnosticStage::BundleInspection);
        assert_eq!(
            snap.events[1].destination_endpoint.as_deref(),
            Some("ipn:1.1")
        );

        // Also test with capacity 0 buffer
        let zero_buf = DiagnosticBuffer::new(0);
        let bundle_ev2 = BundleInspection::new(
            "ipn:2.2",
            "dtn:none",
            2000u64,
            7200u64,
            BundleParseStatus::Valid,
        );
        let zero_emitted = zero_buf.emit(bundle_ev2);
        assert!(!zero_emitted);
        assert_eq!(zero_buf.dropped_count(), 1);
    }

    #[test]
    fn test_ltp_inspection_event_serialization_contains_structured_metadata() {
        let event = LtpInspection::new(0xABC, 0x1234, SegmentType::RedData);

        let json = serde_json::to_string(&event).expect("must serialize to JSON");
        let val: serde_json::Value = serde_json::from_str(&json).expect("must parse JSON");

        // Verify session originator, session number, and segment type
        assert_eq!(val["session_originator"], 0xABC);
        assert_eq!(val["session_number"], 0x1234);
        assert_eq!(val["segment_type"], "RedData");

        // Verify structured LTP metadata nested object
        assert!(
            val["ltp_metadata"].is_object(),
            "must contain structured LTP metadata"
        );
        assert_eq!(val["ltp_metadata"]["session_originator"], 0xABC);
        assert_eq!(val["ltp_metadata"]["session_number"], 0x1234);
        assert_eq!(val["ltp_metadata"]["segment_type"], "RedData");

        // Also test serialization when converted to DiagnosticEvent
        let diag_event: DiagnosticEvent = event.into();
        let diag_json = serde_json::to_string(&diag_event).expect("must serialize DiagnosticEvent");
        let diag_val: serde_json::Value =
            serde_json::from_str(&diag_json).expect("must parse DiagnosticEvent JSON");
        assert_eq!(diag_val["stage"], "ltp_inspection");
        assert_eq!(diag_val["session_originator"], 0xABC);
        assert_eq!(diag_val["session_number"], 0x1234);
        assert_eq!(diag_val["segment_type"], "RedData");
        assert!(diag_val["ltp_inspection"].is_object());
        assert!(diag_val["ltp_metadata"].is_object());
    }

    #[test]
    fn test_emitting_ltp_inspection_into_full_buffer_drops_without_blocking_or_panicking() {
        let clock = Arc::new(ManualClock::new(100, 200));
        let buffer = DiagnosticBuffer::with_clock(2, clock);
        assert_eq!(buffer.capacity(), 2);

        // Fill buffer to capacity
        let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Udp, 100);
        let ev2 = buffer.create_event("s1", DiagnosticStage::Accepted, TransportType::Udp, 100);
        assert!(buffer.emit(ev1));
        assert!(buffer.emit(ev2));
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.dropped_count(), 0);

        // Emit LtpInspection into the full buffer
        let ltp_ev = LtpInspection::new(0xABC, 0x1234, SegmentType::RedData);

        // This must drop without blocking or panicking
        let emitted = buffer.emit(ltp_ev);
        assert!(emitted);
        assert_eq!(buffer.len(), 2);
        assert_eq!(
            buffer.dropped_count(),
            1,
            "emitting into full buffer must increment dropped_count"
        );

        // Verify in snapshot that the oldest was dropped and buffer contains the LTP inspection
        let snap = buffer.snapshot();
        assert_eq!(snap.dropped_count, 1);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[1].stage, DiagnosticStage::LtpInspection);
        assert_eq!(snap.events[1].session_originator, Some(0xABC));
        assert_eq!(snap.events[1].session_number, Some(0x1234));

        // Also test with capacity 0 buffer
        let zero_buf = DiagnosticBuffer::new(0);
        let ltp_ev2 = LtpInspection::new(0xDEF, 0x5678, SegmentType::Report);
        let zero_emitted = zero_buf.emit(ltp_ev2);
        assert!(!zero_emitted);
        assert_eq!(zero_buf.dropped_count(), 1);
    }

    #[test]
    fn test_srt_inspection_event_serialization_contains_structured_metadata() {
        let event = SrtInspection::new(0x2A, 123_456, SrtPacketKind::Data);

        let json = serde_json::to_string(&event).expect("must serialize to JSON");
        let val: serde_json::Value = serde_json::from_str(&json).expect("must parse JSON");

        // Verify destination socket ID, timestamp, and packet kind
        assert_eq!(val["destination_socket_id"], 0x2A);
        assert_eq!(val["timestamp"], 123_456);
        assert_eq!(val["packet_kind"], "data");

        // Verify structured SRT metadata nested object
        assert!(
            val["srt_metadata"].is_object(),
            "must contain structured SRT metadata"
        );
        assert_eq!(val["srt_metadata"]["destination_socket_id"], 0x2A);
        assert_eq!(val["srt_metadata"]["timestamp_us"], 123_456);
        assert_eq!(val["srt_metadata"]["packet_kind"], "data");

        // Also test serialization when converted to DiagnosticEvent
        let diag_event: DiagnosticEvent = event.into();
        let diag_json = serde_json::to_string(&diag_event).expect("must serialize DiagnosticEvent");
        let diag_val: serde_json::Value =
            serde_json::from_str(&diag_json).expect("must parse DiagnosticEvent JSON");
        assert_eq!(diag_val["stage"], "srt_inspection");
        assert_eq!(diag_val["destination_socket_id"], 0x2A);
        assert_eq!(diag_val["srt_timestamp"], 123_456);
        assert_eq!(diag_val["srt_packet_kind"], "data");
        assert!(diag_val["srt_inspection"].is_object());
        assert!(diag_val["srt_metadata"].is_object());
    }

    #[test]
    fn test_emitting_srt_inspection_into_full_buffer_drops_without_blocking_or_panicking() {
        let clock = Arc::new(ManualClock::new(100, 200));
        let buffer = DiagnosticBuffer::with_clock(2, clock);
        assert_eq!(buffer.capacity(), 2);

        // Fill buffer to capacity
        let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Udp, 100);
        let ev2 = buffer.create_event("s1", DiagnosticStage::Accepted, TransportType::Udp, 100);
        assert!(buffer.emit(ev1));
        assert!(buffer.emit(ev2));
        assert_eq!(buffer.len(), 2);
        assert_eq!(buffer.dropped_count(), 0);

        // Emit SrtInspection into the full buffer
        let srt_ev = SrtInspection::new(0x2A, 123_456, SrtPacketKind::Data);

        // This must drop without blocking or panicking
        let emitted = buffer.emit(srt_ev);
        assert!(emitted);
        assert_eq!(buffer.len(), 2);
        assert_eq!(
            buffer.dropped_count(),
            1,
            "emitting into full buffer must increment dropped_count"
        );

        // Verify in snapshot that the oldest was dropped and buffer contains the SRT inspection
        let snap = buffer.snapshot();
        assert_eq!(snap.dropped_count, 1);
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[1].stage, DiagnosticStage::SrtInspection);
        assert_eq!(snap.events[1].destination_socket_id, Some(0x2A));
        assert_eq!(snap.events[1].srt_timestamp, Some(123_456));
        assert_eq!(snap.events[1].srt_packet_kind, Some(SrtPacketKind::Data));

        // Also test with capacity 0 buffer
        let zero_buf = DiagnosticBuffer::new(0);
        let srt_ev2 = SrtInspection::new(0x2B, 654_321, SrtPacketKind::Control);
        let zero_emitted = zero_buf.emit(srt_ev2);
        assert!(!zero_emitted);
        assert_eq!(zero_buf.dropped_count(), 1);
    }

    #[test]
    fn test_diagnostic_event_serialization_and_fields() {
        let event = DiagnosticEvent::new(
            1_000_000_000,
            1_700_000_000_000_000_000,
            "stream-udp-1",
            DiagnosticStage::Received,
            TransportType::Udp,
            1400,
        )
        .with_source("192.168.1.100:5000")
        .with_destination("192.168.1.200:5000")
        .with_correlation_id("test-corr-42")
        .with_reason("forwarded cleanly");

        let json = serde_json::to_string(&event).expect("failed to serialize event");
        assert!(json.contains("\"monotonic_timestamp\":1000000000"));
        assert!(json.contains("\"wall_clock_timestamp\":1700000000000000000"));
        assert!(json.contains("\"stream_id\":\"stream-udp-1\""));
        assert!(json.contains("\"stage\":\"received\""));
        assert!(json.contains("\"source_endpoint\":\"192.168.1.100:5000\""));
        assert!(json.contains("\"destination_endpoint\":\"192.168.1.200:5000\""));
        assert!(json.contains("\"transport\":\"udp\""));
        assert!(json.contains("\"payload_length\":1400"));
        assert!(json.contains("\"correlation_id\":\"test-corr-42\""));
        assert!(json.contains("\"reason\":\"forwarded cleanly\""));

        let deserialized: DiagnosticEvent =
            serde_json::from_str(&json).expect("failed to deserialize event");
        assert_eq!(deserialized, event);

        // Verify deserialization with alias names
        let alias_json = r#"{
            "monotonic": 500,
            "wall_clock": 600,
            "stream": "alias-stream",
            "stage": "send_attempted",
            "source": "10.0.0.1:80",
            "destination": "10.0.0.2:80",
            "transport": "tcp",
            "length": 256,
            "correlation": "c-1",
            "reason": null
        }"#;
        let from_alias: DiagnosticEvent =
            serde_json::from_str(alias_json).expect("failed to parse alias json");
        assert_eq!(from_alias.monotonic_timestamp, 500);
        assert_eq!(from_alias.wall_clock_timestamp, 600);
        assert_eq!(from_alias.stream_id, "alias-stream");
        assert_eq!(from_alias.stage, DiagnosticStage::SendAttempted);
        assert_eq!(from_alias.source_endpoint.as_deref(), Some("10.0.0.1:80"));
        assert_eq!(
            from_alias.destination_endpoint.as_deref(),
            Some("10.0.0.2:80")
        );
        assert_eq!(from_alias.transport, TransportType::Tcp);
        assert_eq!(from_alias.payload_length, 256);
        assert_eq!(from_alias.correlation_id.as_deref(), Some("c-1"));
        assert_eq!(from_alias.reason, None);
    }

    #[test]
    fn test_diagnostic_event_has_no_payload_bytes_field() {
        // Assert that the event records only the metadata and length,
        // and cannot hold packet payload bytes.
        let event = DiagnosticEvent::new(
            100,
            200,
            "stream-test",
            DiagnosticStage::Accepted,
            TransportType::Udp,
            512,
        );
        let value = serde_json::to_value(&event).expect("failed to convert to value");
        let map = value.as_object().expect("expected json object");

        assert!(map.contains_key("payload_length"));
        assert!(!map.contains_key("payload"));
        assert!(!map.contains_key("data"));
        assert!(!map.contains_key("bytes"));
        assert!(!map.contains_key("packet"));
        assert!(!map.contains_key("body"));
    }

    #[test]
    fn test_buffer_capacity_overwrites_oldest_and_counts_drops() {
        let clock = Arc::new(ManualClock::new(1000, 2000));
        let buffer = DiagnosticBuffer::with_clock(3, clock.clone());
        assert_eq!(buffer.capacity(), 3);
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.dropped_count(), 0);

        // Emit 3 events to fill capacity
        for i in 1..=3 {
            clock.advance_millis(10);
            let ev = buffer.create_event(
                format!("stream-{i}"),
                DiagnosticStage::Accepted,
                TransportType::Udp,
                100 * i,
            );
            assert!(buffer.emit(ev));
        }

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.dropped_count(), 0);
        let snap1 = buffer.snapshot();
        assert_eq!(snap1.events.len(), 3);
        assert_eq!(snap1.events[0].stream_id, "stream-1");
        assert_eq!(snap1.events[1].stream_id, "stream-2");
        assert_eq!(snap1.events[2].stream_id, "stream-3");
        assert_eq!(snap1.dropped_count, 0);

        // Emit 4th event: oldest (stream-1) must be overwritten, dropped_count increases to 1
        clock.advance_millis(10);
        let ev4 = buffer.create_event(
            "stream-4",
            DiagnosticStage::SendAttempted,
            TransportType::Udp,
            400,
        );
        assert!(buffer.emit(ev4));

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.dropped_count(), 1);
        let snap2 = buffer.snapshot();
        assert_eq!(snap2.events.len(), 3);
        // Arrival order: stream-2, stream-3, stream-4
        assert_eq!(snap2.events[0].stream_id, "stream-2");
        assert_eq!(snap2.events[1].stream_id, "stream-3");
        assert_eq!(snap2.events[2].stream_id, "stream-4");
        assert_eq!(snap2.dropped_count, 1);

        // Emit 5th event: oldest (stream-2) is overwritten, dropped_count increases to 2
        clock.advance_millis(10);
        let ev5 = buffer.create_event(
            "stream-5",
            DiagnosticStage::SendSucceeded,
            TransportType::Udp,
            500,
        );
        assert!(buffer.emit(ev5));

        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.dropped_count(), 2);
        let snap3 = buffer.snapshot();
        assert_eq!(snap3.events.len(), 3);
        assert_eq!(snap3.events[0].stream_id, "stream-3");
        assert_eq!(snap3.events[1].stream_id, "stream-4");
        assert_eq!(snap3.events[2].stream_id, "stream-5");
        assert_eq!(snap3.dropped_count, 2);
    }

    #[test]
    fn test_buffer_snapshot_in_arrival_order() {
        let clock = Arc::new(ManualClock::new(10, 20));
        let buffer = DiagnosticBuffer::with_clock(5, clock.clone());

        for i in 1..=5 {
            clock.advance_secs(1);
            assert!(buffer.emit_stage(
                format!("stream-{i}"),
                DiagnosticStage::RoutedOrQueued,
                TransportType::Tcp,
                64 * i,
            ));
        }

        let snap = buffer.snapshot();
        assert_eq!(snap.events.len(), 5);
        assert_eq!(snap.dropped_count, 0);

        for (idx, ev) in snap.events.iter().enumerate() {
            let expected_i = (idx + 1) as u64;
            assert_eq!(ev.stream_id, format!("stream-{expected_i}"));
            assert_eq!(ev.payload_length, 64 * expected_i);
        }
    }

    #[test]
    fn test_emitting_never_blocks_when_another_thread_holds_buffer() {
        let clock = Arc::new(ManualClock::new(0, 0));
        let buffer = DiagnosticBuffer::with_clock(10, clock);

        let (tx_held, rx_held) = mpsc::channel();
        let (tx_done, rx_done) = mpsc::channel();

        let buffer_clone = buffer.clone();
        let handle = thread::spawn(move || {
            // Explicitly hold the lock
            let guard = buffer_clone.hold_lock();
            // Signal main thread that the buffer lock is currently held
            tx_held.send(()).expect("failed to send held signal");
            // Wait for main thread to finish its emit attempt
            rx_done.recv().expect("failed to receive done signal");
            drop(guard);
        });

        // Wait until background thread holds the lock
        rx_held.recv().expect("failed to receive held signal");

        // Attempting to emit MUST return immediately without blocking!
        let event = DiagnosticEvent::new(
            1,
            2,
            "contention-stream",
            DiagnosticStage::Received,
            TransportType::Udp,
            128,
        );

        let emitted = buffer.emit(event);
        assert!(!emitted, "emit must fail when buffer lock is held");
        assert_eq!(
            buffer.dropped_count(),
            1,
            "dropped count must increment on lock contention"
        );

        // Tell background thread to release lock
        tx_done.send(()).expect("failed to send done signal");
        handle.join().expect("thread join failed");

        // After release, snapshot reflects the dropped event and empty buffer
        let snap = buffer.snapshot();
        assert_eq!(snap.events.len(), 0);
        assert_eq!(snap.dropped_count, 1);

        // New emit succeeds now that lock is free
        let ev2 = DiagnosticEvent::new(
            3,
            4,
            "free-stream",
            DiagnosticStage::Accepted,
            TransportType::Udp,
            256,
        );
        assert!(buffer.emit(ev2));
        assert_eq!(buffer.snapshot().events.len(), 1);
        assert_eq!(buffer.dropped_count(), 1);
    }

    #[test]
    fn test_per_second_rate_limiting_across_second_boundary_without_sleeping() {
        let clock = Arc::new(ManualClock::new(0, 0));
        // Rate limit: 2 events per second
        let buffer = DiagnosticBuffer::with_clock_and_rate_limit(10, clock.clone(), 2);

        // Second 0 (monotonic time = 0 ns)
        let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Udp, 100);
        assert!(buffer.emit(ev1), "event 1 in second 0 should be accepted");

        clock.advance_millis(200); // monotonic = 200_000_000 ns (still second 0)
        let ev2 = buffer.create_event("s2", DiagnosticStage::Accepted, TransportType::Udp, 200);
        assert!(buffer.emit(ev2), "event 2 in second 0 should be accepted");

        clock.advance_millis(200); // monotonic = 400_000_000 ns (still second 0)
        let ev3 = buffer.create_event(
            "s3",
            DiagnosticStage::SendAttempted,
            TransportType::Udp,
            300,
        );
        assert!(
            !buffer.emit(ev3),
            "event 3 in second 0 must be rejected by rate limit"
        );
        assert_eq!(buffer.dropped_count(), 1);

        clock.advance_millis(100); // monotonic = 500_000_000 ns (still second 0)
        let ev4 = buffer.create_event(
            "s4",
            DiagnosticStage::SendAttempted,
            TransportType::Udp,
            400,
        );
        assert!(
            !buffer.emit(ev4),
            "event 4 in second 0 must be rejected by rate limit"
        );
        assert_eq!(buffer.dropped_count(), 2);

        // Cross the second boundary: advance to second 1 (monotonic = 1_000_000_000 ns)
        // No sleeping!
        clock.set_monotonic_nanos(1_000_000_000);

        let ev5 = buffer.create_event(
            "s5",
            DiagnosticStage::SendSucceeded,
            TransportType::Udp,
            500,
        );
        assert!(
            buffer.emit(ev5),
            "event 5 in second 1 should be accepted after boundary crossing"
        );

        clock.advance_millis(300); // monotonic = 1_300_000_000 ns (second 1)
        let ev6 = buffer.create_event("s6", DiagnosticStage::Received, TransportType::Udp, 600);
        assert!(buffer.emit(ev6), "event 6 in second 1 should be accepted");

        clock.advance_millis(300); // monotonic = 1_600_000_000 ns (second 1)
        let ev7 = buffer.create_event("s7", DiagnosticStage::Accepted, TransportType::Udp, 700);
        assert!(
            !buffer.emit(ev7),
            "event 7 in second 1 must be rejected by rate limit"
        );
        assert_eq!(buffer.dropped_count(), 3);

        let snap = buffer.snapshot();
        assert_eq!(snap.events.len(), 4); // s1, s2, s5, s6
        assert_eq!(snap.events[0].stream_id, "s1");
        assert_eq!(snap.events[1].stream_id, "s2");
        assert_eq!(snap.events[2].stream_id, "s5");
        assert_eq!(snap.events[3].stream_id, "s6");
        assert_eq!(snap.dropped_count, 3);
    }

    #[test]
    fn test_fractional_second_boundary_rate_limiting() {
        let clock = Arc::new(ManualClock::new(500_000_000, 500_000_000)); // 0.5s
        let buffer = DiagnosticBuffer::with_clock_and_rate_limit(5, clock.clone(), 1);

        // At 0.5s: event 1 accepted
        let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Udp, 10);
        assert!(buffer.emit(ev1));

        // At 0.8s: event 2 rejected (still second 0)
        clock.advance_millis(300);
        let ev2 = buffer.create_event("s2", DiagnosticStage::Received, TransportType::Udp, 20);
        assert!(!buffer.emit(ev2));
        assert_eq!(buffer.dropped_count(), 1);

        // Advance 300ms to 1.1s: crosses integer second boundary into second 1
        clock.advance_millis(300);
        let ev3 = buffer.create_event("s3", DiagnosticStage::Received, TransportType::Udp, 30);
        assert!(buffer.emit(ev3));

        let snap = buffer.snapshot();
        assert_eq!(snap.events.len(), 2);
        assert_eq!(snap.events[0].stream_id, "s1");
        assert_eq!(snap.events[1].stream_id, "s3");
        assert_eq!(snap.dropped_count, 1);
    }

    #[test]
    fn test_zero_capacity_buffer() {
        let clock = Arc::new(ManualClock::new(0, 0));
        let buffer = DiagnosticBuffer::with_clock(0, clock);

        assert_eq!(buffer.capacity(), 0);
        let ev = DiagnosticEvent::new(
            1,
            2,
            "zero-cap",
            DiagnosticStage::Received,
            TransportType::Udp,
            10,
        );
        assert!(!buffer.emit(ev));
        assert_eq!(buffer.dropped_count(), 1);

        let snap = buffer.snapshot();
        assert_eq!(snap.events.len(), 0);
        assert_eq!(snap.dropped_count, 1);
    }

    #[test]
    fn test_builder_and_constructors() {
        let clock = Arc::new(ManualClock::new(100, 200));
        let buf1 = DiagnosticBuffer::builder(8)
            .clock(clock.clone())
            .rate_limit(50)
            .build();
        assert_eq!(buf1.capacity(), 8);

        let buf2 = DiagnosticBuffer::new(16);
        assert_eq!(buf2.capacity(), 16);

        let buf3 = DiagnosticBuffer::with_rate_limit(32, 100);
        assert_eq!(buf3.capacity(), 32);
    }

    #[test]
    fn test_system_clock_non_zero() {
        let sys_clock = SystemClock::new();
        let mono = sys_clock.monotonic_nanos();
        let wall = sys_clock.wall_clock_nanos();
        assert!(wall > 0);
        assert!(sys_clock.wall_clock_time() > SystemTime::UNIX_EPOCH);
        let _ = mono;
    }

    #[test]
    fn test_criterion3_mavlink_diagnostic_event_serialization() {
        // Acceptance criterion: In crates/rer/src/diagnostics.rs, serializing a DiagnosticEvent
        // containing MAVLink system ID, component ID, sequence number, and 24-bit message ID
        // produces a JSON object containing the structured MAVLink metadata fields.
        let msgid_24bit: u32 = 16_777_215; // 0xFFFFFF (24-bit max message ID)
        let event = DiagnosticEvent::new(
            1000,
            2000,
            "mavlink-stream",
            DiagnosticStage::MavlinkInspection,
            TransportType::Udp,
            128,
        )
        .with_mavlink_system_id(1)
        .with_mavlink_component_id(2)
        .with_mavlink_sequence(42)
        .with_mavlink_message_id(msgid_24bit);

        let json_str = serde_json::to_string(&event).expect("serialize diagnostic event");
        let val: serde_json::Value = serde_json::from_str(&json_str).expect("deserialize json");
        let obj = val.as_object().expect("json object expected");

        assert_eq!(
            obj.get("mavlink_system_id").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            obj.get("mavlink_component_id").and_then(|v| v.as_u64()),
            Some(2)
        );
        assert_eq!(
            obj.get("mavlink_sequence").and_then(|v| v.as_u64()),
            Some(42)
        );
        assert_eq!(
            obj.get("sequence_number").and_then(|v| v.as_u64()),
            Some(42)
        );
        assert_eq!(
            obj.get("mavlink_message_id").and_then(|v| v.as_u64()),
            Some(u64::from(msgid_24bit))
        );

        let meta = obj
            .get("mavlink_metadata")
            .and_then(|v| v.as_object())
            .expect("mavlink_metadata object");
        assert_eq!(meta.get("system_id").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(meta.get("component_id").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(meta.get("sequence").and_then(|v| v.as_u64()), Some(42));
        assert_eq!(
            meta.get("message_id").and_then(|v| v.as_u64()),
            Some(u64::from(msgid_24bit))
        );
    }
}
