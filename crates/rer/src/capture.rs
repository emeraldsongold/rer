//! PCAP and PCAPNG capture file parsing and validation (SPEC §12, §17).
//!
//! Supports an initial subset of link-layer header types:
//! - `Null` (DLT 0): BSD Loopback encapsulation (4-byte family)
//! - `Ethernet` (DLT 1): IEEE 802.3 Ethernet frames (with optional 802.1Q VLAN tags)
//! - `Raw` (DLT 12): Raw IPv4 / IPv6 packets
//! - `Loop` (DLT 108): OpenBSD Loopback encapsulation
//! - `LinuxSll` (DLT 113): Linux "cooked" capture encapsulation v1
//! - `Ipv4` (DLT 228): Raw IPv4 packets
//! - `Ipv6` (DLT 229): Raw IPv6 packets
//! - `LinuxSll2` (DLT 276): Linux "cooked" capture encapsulation v2
//!
//! Unsupported link types or malformed files are safely rejected without panicking.

use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Maximum file size supported for in-memory capture ingestion (128 MB).
pub const MAX_CAPTURE_FILE_SIZE: usize = 128 * 1024 * 1024;
/// Maximum single packet size allowed (1 MB).
pub const MAX_PACKET_SIZE: usize = 1024 * 1024;
/// Maximum PCAPNG block size allowed (16 MB).
pub const MAX_BLOCK_SIZE: usize = 16 * 1024 * 1024;
/// Maximum total packets ingested in a single session.
pub const MAX_PACKETS: usize = 1_000_000;

/// Supported link-layer header types (DLT / LINKTYPE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkType {
    /// BSD loopback encapsulation (DLT 0).
    Null = 0,
    /// IEEE 802.3 Ethernet (DLT 1).
    Ethernet = 1,
    /// Raw IPv4 / IPv6 without link-layer header (DLT 12).
    Raw = 12,
    /// OpenBSD loopback encapsulation (DLT 108).
    Loop = 108,
    /// Linux "cooked" capture encapsulation v1 (DLT 113).
    LinuxSll = 113,
    /// Raw IPv4 (DLT 228).
    Ipv4 = 228,
    /// Raw IPv6 (DLT 229).
    Ipv6 = 229,
    /// Linux "cooked" capture encapsulation v2 (DLT 276).
    LinuxSll2 = 276,
}

impl LinkType {
    /// Parses a link-layer type from its numeric u32 identifier.
    pub fn from_u32(val: u32) -> Result<Self, CaptureError> {
        match val {
            0 => Ok(LinkType::Null),
            1 => Ok(LinkType::Ethernet),
            12 => Ok(LinkType::Raw),
            108 => Ok(LinkType::Loop),
            113 => Ok(LinkType::LinuxSll),
            228 => Ok(LinkType::Ipv4),
            229 => Ok(LinkType::Ipv6),
            276 => Ok(LinkType::LinuxSll2),
            other => Err(CaptureError::UnsupportedLinkType(
                other,
                format!(
                    "unsupported capture link type {other}; supported: Ethernet (1), Linux SLL (113), Linux SLL2 (276), BSD Null (0), OpenBSD Loop (108), Raw IP (12/228/229)"
                ),
            )),
        }
    }

    /// Descriptive name of the link type.
    pub fn name(&self) -> &'static str {
        match self {
            LinkType::Null => "BSD Loopback (Null)",
            LinkType::Ethernet => "Ethernet",
            LinkType::Raw => "Raw IP",
            LinkType::Loop => "OpenBSD Loopback",
            LinkType::LinuxSll => "Linux Cooked v1 (SLL)",
            LinkType::Ipv4 => "IPv4",
            LinkType::Ipv6 => "IPv6",
            LinkType::LinuxSll2 => "Linux Cooked v2 (SLL2)",
        }
    }
}

/// Capture container format detected from file magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureFormat {
    /// Classic libpcap format (.pcap)
    Pcap,
    /// PCAP Next Generation format (.pcapng)
    PcapNg,
}

/// Errors encountered while reading or parsing capture records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureError {
    EmptyInput,
    FileTooLarge(usize, usize),
    TruncatedHeader(&'static str),
    InvalidMagic(u32),
    UnsupportedVersion(u16, u16),
    UnsupportedLinkType(u32, String),
    MalformedPacket(String),
    MalformedBlock(String),
    IoError(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::EmptyInput => write!(f, "capture file is empty"),
            CaptureError::FileTooLarge(actual, max) => write!(
                f,
                "capture file exceeds maximum size limit (got {} bytes, max {} bytes)",
                actual, max
            ),
            CaptureError::TruncatedHeader(h) => write!(f, "truncated header: {h}"),
            CaptureError::InvalidMagic(m) => {
                write!(f, "unrecognized capture file magic: 0x{m:08x}")
            }
            CaptureError::UnsupportedVersion(maj, min) => {
                write!(f, "unsupported capture file version {maj}.{min}")
            }
            CaptureError::UnsupportedLinkType(_lt, desc) => write!(f, "{desc}"),
            CaptureError::MalformedPacket(msg) => write!(f, "malformed packet: {msg}"),
            CaptureError::MalformedBlock(msg) => write!(f, "malformed PCAPNG block: {msg}"),
            CaptureError::IoError(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<std::io::Error> for CaptureError {
    fn from(err: std::io::Error) -> Self {
        CaptureError::IoError(err.to_string())
    }
}

/// A parsed packet record extracted from a capture file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedPacket {
    /// Zero-based packet index in capture
    pub index: usize,
    /// Capture timestamp
    pub timestamp: Duration,
    /// Original on-the-wire packet length
    pub orig_len: usize,
    /// Link type of the packet
    pub link_type: LinkType,
    /// Extracted network protocol (IPv4 or IPv6)
    pub network_protocol: Option<String>,
    /// Extracted source IP address
    pub src_ip: Option<IpAddr>,
    /// Extracted destination IP address
    pub dst_ip: Option<IpAddr>,
    /// Extracted transport protocol (UDP or TCP)
    pub transport_protocol: Option<String>,
    /// Extracted source port
    pub src_port: Option<u16>,
    /// Extracted destination port
    pub dst_port: Option<u16>,
    /// Extracted payload to replay
    pub payload: Vec<u8>,
}

impl CapturedPacket {
    /// Returns a string describing the stream 5-tuple, e.g. "127.0.0.1:5000->127.0.0.1:6000".
    pub fn stream_key(&self) -> String {
        match (self.src_ip, self.src_port, self.dst_ip, self.dst_port) {
            (Some(s_ip), Some(s_port), Some(d_ip), Some(d_port)) => {
                format!("{s_ip}:{s_port}->{d_ip}:{d_port}")
            }
            (_, Some(s_port), _, Some(d_port)) => {
                format!("{s_port}->{d_port}")
            }
            _ => format!("pkt-{}", self.index),
        }
    }
}

/// High-level capture inspection summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureSummary {
    pub format: CaptureFormat,
    pub link_type: LinkType,
    pub packet_count: usize,
    pub start_time: Option<Duration>,
    pub end_time: Option<Duration>,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
struct InterfaceInfo {
    link_type: LinkType,
    ts_resol: u8,
}

#[inline]
fn read_u16(buf: &[u8], be: bool) -> u16 {
    let bytes = [buf[0], buf[1]];
    if be {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    }
}

#[inline]
fn read_u32(buf: &[u8], be: bool) -> u32 {
    let bytes = [buf[0], buf[1], buf[2], buf[3]];
    if be {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

/// Parses a capture file from disk.
pub fn parse_capture_file<P: AsRef<Path>>(path: P) -> Result<Vec<CapturedPacket>, CaptureError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let size = metadata.len() as usize;
    if size == 0 {
        return Err(CaptureError::EmptyInput);
    }
    if size > MAX_CAPTURE_FILE_SIZE {
        return Err(CaptureError::FileTooLarge(size, MAX_CAPTURE_FILE_SIZE));
    }
    let mut buf = Vec::with_capacity(size);
    file.read_to_end(&mut buf)?;
    parse_capture(&buf)
}

/// Parses capture bytes (auto-detecting PCAP or PCAPNG).
pub fn parse_capture(buf: &[u8]) -> Result<Vec<CapturedPacket>, CaptureError> {
    if buf.is_empty() {
        return Err(CaptureError::EmptyInput);
    }
    if buf.len() > MAX_CAPTURE_FILE_SIZE {
        return Err(CaptureError::FileTooLarge(buf.len(), MAX_CAPTURE_FILE_SIZE));
    }
    if buf.len() < 4 {
        return Err(CaptureError::TruncatedHeader("capture magic header"));
    }

    // Check for PCAPNG Section Header Block magic (0x0A0D0D0A)
    if buf.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        parse_pcapng(buf)
    } else {
        // Validate PCAP magic
        match &buf[0..4] {
            [0xd4, 0xc3, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0x3c, 0x4d] => parse_pcap(buf),
            other => {
                let magic = u32::from_be_bytes([other[0], other[1], other[2], other[3]]);
                Err(CaptureError::InvalidMagic(magic))
            }
        }
    }
}

/// Parses classic libpcap format bytes.
pub fn parse_pcap(buf: &[u8]) -> Result<Vec<CapturedPacket>, CaptureError> {
    if buf.len() < 24 {
        return Err(CaptureError::TruncatedHeader("PCAP global header"));
    }

    let (is_big_endian, is_nanosecond) = match &buf[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        other => {
            let magic = u32::from_be_bytes([other[0], other[1], other[2], other[3]]);
            return Err(CaptureError::InvalidMagic(magic));
        }
    };

    let version_major = read_u16(&buf[4..6], is_big_endian);
    let version_minor = read_u16(&buf[6..8], is_big_endian);
    if version_major != 2 {
        return Err(CaptureError::UnsupportedVersion(
            version_major,
            version_minor,
        ));
    }

    let link_type_val = read_u32(&buf[20..24], is_big_endian);
    let link_type = LinkType::from_u32(link_type_val)?;

    let mut offset = 24;
    let mut index = 0;
    let mut packets = Vec::new();

    while offset < buf.len() {
        if buf.len() - offset < 16 {
            return Err(CaptureError::TruncatedHeader("PCAP packet record header"));
        }

        let ts_sec = read_u32(&buf[offset..offset + 4], is_big_endian);
        let ts_subsec = read_u32(&buf[offset + 4..offset + 8], is_big_endian);
        let incl_len = read_u32(&buf[offset + 8..offset + 12], is_big_endian) as usize;
        let orig_len = read_u32(&buf[offset + 12..offset + 16], is_big_endian) as usize;
        offset += 16;

        if incl_len > MAX_PACKET_SIZE {
            return Err(CaptureError::MalformedPacket(format!(
                "packet length {incl_len} exceeds limit {MAX_PACKET_SIZE}"
            )));
        }

        if offset + incl_len > buf.len() {
            return Err(CaptureError::MalformedPacket(format!(
                "packet data truncated: expected {incl_len} bytes, remaining {}",
                buf.len() - offset
            )));
        }

        let pkt_bytes = &buf[offset..offset + incl_len];
        offset += incl_len;

        let timestamp = if is_nanosecond {
            Duration::from_secs(ts_sec as u64) + Duration::from_nanos(ts_subsec as u64)
        } else {
            Duration::from_secs(ts_sec as u64) + Duration::from_micros(ts_subsec as u64)
        };

        let packet = decode_packet(index, timestamp, orig_len, link_type, pkt_bytes)?;
        packets.push(packet);
        index += 1;
        if index >= MAX_PACKETS {
            break;
        }
    }

    Ok(packets)
}

/// Parses PCAP Next Generation (PCAPNG) format bytes.
pub fn parse_pcapng(buf: &[u8]) -> Result<Vec<CapturedPacket>, CaptureError> {
    let mut offset = 0;
    let mut is_big_endian = false;
    let mut interfaces = Vec::new();
    let mut packets = Vec::new();
    let mut index = 0;

    while offset < buf.len() {
        if buf.len() - offset < 12 {
            return Err(CaptureError::TruncatedHeader("PCAPNG block header"));
        }

        let is_shb = buf[offset..offset + 4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if is_shb {
            if buf.len() - offset < 16 {
                return Err(CaptureError::TruncatedHeader("PCAPNG SHB"));
            }
            let bom = &buf[offset + 8..offset + 12];
            if bom == [0x1a, 0x2b, 0x3c, 0x4d] {
                is_big_endian = true;
            } else if bom == [0x4d, 0x3c, 0x2b, 0x1a] {
                is_big_endian = false;
            } else {
                return Err(CaptureError::MalformedBlock(
                    "invalid PCAPNG byte-order magic".to_string(),
                ));
            }
            interfaces.clear();
        }

        let block_type = read_u32(&buf[offset..offset + 4], is_big_endian);
        let block_len = read_u32(&buf[offset + 4..offset + 8], is_big_endian) as usize;

        if block_len < 12 {
            return Err(CaptureError::MalformedBlock(format!(
                "invalid block length {block_len} (minimum 12)"
            )));
        }
        if block_len % 4 != 0 {
            return Err(CaptureError::MalformedBlock(format!(
                "block length {block_len} is not 32-bit aligned"
            )));
        }
        if block_len > MAX_BLOCK_SIZE {
            return Err(CaptureError::MalformedBlock(format!(
                "block length {block_len} exceeds limit {MAX_BLOCK_SIZE}"
            )));
        }
        if offset + block_len > buf.len() {
            return Err(CaptureError::MalformedBlock(format!(
                "block length {block_len} extends past EOF (remaining {})",
                buf.len() - offset
            )));
        }

        let trailing_len = read_u32(
            &buf[offset + block_len - 4..offset + block_len],
            is_big_endian,
        ) as usize;
        if trailing_len != block_len {
            return Err(CaptureError::MalformedBlock(format!(
                "trailing block length {trailing_len} does not match leading {block_len}"
            )));
        }

        let body = &buf[offset + 8..offset + block_len - 4];
        match block_type {
            0x0A0D0D0A => {
                // Section Header Block (SHB)
                let version_major = read_u16(&body[4..6], is_big_endian);
                let version_minor = read_u16(&body[6..8], is_big_endian);
                if version_major != 1 {
                    return Err(CaptureError::UnsupportedVersion(
                        version_major,
                        version_minor,
                    ));
                }
            }
            0x00000001 => {
                // Interface Description Block (IDB)
                if body.len() < 8 {
                    return Err(CaptureError::MalformedBlock(
                        "truncated IDB body".to_string(),
                    ));
                }
                let link_val = read_u16(&body[0..2], is_big_endian) as u32;
                let link_type = LinkType::from_u32(link_val)?;
                let mut ts_resol = 6u8; // default: 10^-6 (microseconds)

                let mut opt_offset = 8;
                while opt_offset + 4 <= body.len() {
                    let opt_code = read_u16(&body[opt_offset..opt_offset + 2], is_big_endian);
                    let opt_len =
                        read_u16(&body[opt_offset + 2..opt_offset + 4], is_big_endian) as usize;
                    opt_offset += 4;
                    if opt_code == 0 {
                        break;
                    }
                    if opt_offset + opt_len > body.len() {
                        break;
                    }
                    if opt_code == 9 && opt_len >= 1 {
                        ts_resol = body[opt_offset];
                    }
                    let pad = (4 - (opt_len % 4)) % 4;
                    opt_offset += opt_len + pad;
                }
                interfaces.push(InterfaceInfo {
                    link_type,
                    ts_resol,
                });
            }
            0x00000006 => {
                // Enhanced Packet Block (EPB)
                if body.len() < 20 {
                    return Err(CaptureError::MalformedBlock(
                        "truncated EPB body".to_string(),
                    ));
                }
                let iface_id = read_u32(&body[0..4], is_big_endian) as usize;
                if iface_id >= interfaces.len() {
                    return Err(CaptureError::MalformedBlock(format!(
                        "EPB references unknown interface {iface_id} (interfaces count: {})",
                        interfaces.len()
                    )));
                }
                let ts_high = read_u32(&body[4..8], is_big_endian) as u64;
                let ts_low = read_u32(&body[8..12], is_big_endian) as u64;
                let caplen = read_u32(&body[12..16], is_big_endian) as usize;
                let origlen = read_u32(&body[16..20], is_big_endian) as usize;

                if caplen > MAX_PACKET_SIZE {
                    return Err(CaptureError::MalformedBlock(format!(
                        "EPB captured len {caplen} exceeds limit {MAX_PACKET_SIZE}"
                    )));
                }
                if 20 + caplen > body.len() {
                    return Err(CaptureError::MalformedBlock(format!(
                        "EPB captured len {caplen} extends past block body (body: {})",
                        body.len()
                    )));
                }

                let iface = &interfaces[iface_id];
                let raw_ts = (ts_high << 32) | ts_low;
                let timestamp = calculate_pcapng_timestamp(raw_ts, iface.ts_resol);
                let pkt_bytes = &body[20..20 + caplen];

                let packet = decode_packet(index, timestamp, origlen, iface.link_type, pkt_bytes)?;
                packets.push(packet);
                index += 1;
                if index >= MAX_PACKETS {
                    break;
                }
            }
            0x00000003 => {
                // Simple Packet Block (SPB)
                if body.len() < 4 {
                    return Err(CaptureError::MalformedBlock(
                        "truncated SPB body".to_string(),
                    ));
                }
                if interfaces.is_empty() {
                    return Err(CaptureError::MalformedBlock(
                        "SPB encountered without preceding IDB".to_string(),
                    ));
                }
                let origlen = read_u32(&body[0..4], is_big_endian) as usize;
                let caplen = body.len() - 4;
                let take = caplen.min(origlen);
                let pkt_bytes = &body[4..4 + take];
                let iface = &interfaces[0];
                let packet =
                    decode_packet(index, Duration::ZERO, origlen, iface.link_type, pkt_bytes)?;
                packets.push(packet);
                index += 1;
                if index >= MAX_PACKETS {
                    break;
                }
            }
            _ => {
                // Safely ignore unknown or optional block types
            }
        }

        offset += block_len;
    }

    Ok(packets)
}

fn calculate_pcapng_timestamp(raw_ts: u64, ts_resol: u8) -> Duration {
    if (ts_resol & 0x80) == 0 {
        let exp = (ts_resol as u32).min(18);
        let divisor = 10u128.pow(exp);
        let raw = raw_ts as u128;
        let secs = (raw / divisor) as u64;
        let rem = raw % divisor;
        let nanos = ((rem * 1_000_000_000) / divisor) as u64;
        Duration::from_secs(secs) + Duration::from_nanos(nanos)
    } else {
        let power = ((ts_resol & 0x7f) as u32).min(63);
        let divisor = 1u128 << power;
        let raw = raw_ts as u128;
        let secs = (raw / divisor) as u64;
        let rem = raw % divisor;
        let nanos = ((rem * 1_000_000_000) / divisor) as u64;
        Duration::from_secs(secs) + Duration::from_nanos(nanos)
    }
}

/// Decodes packet bytes according to link type, extracting network and transport headers.
pub fn decode_packet(
    index: usize,
    timestamp: Duration,
    orig_len: usize,
    link_type: LinkType,
    raw_bytes: &[u8],
) -> Result<CapturedPacket, CaptureError> {
    let mut ip_offset;
    let mut is_ipv4 = false;
    let mut is_ipv6 = false;

    match link_type {
        LinkType::Ethernet => {
            if raw_bytes.len() < 14 {
                return Err(CaptureError::MalformedPacket(
                    "truncated Ethernet header".to_string(),
                ));
            }
            let mut ethertype = u16::from_be_bytes([raw_bytes[12], raw_bytes[13]]);
            ip_offset = 14;
            // Handle 802.1Q / 802.1ad VLAN tagging
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if raw_bytes.len() < ip_offset + 4 {
                    return Err(CaptureError::MalformedPacket(
                        "truncated VLAN header".to_string(),
                    ));
                }
                ethertype =
                    u16::from_be_bytes([raw_bytes[ip_offset + 2], raw_bytes[ip_offset + 3]]);
                ip_offset += 4;
            }
            if ethertype == 0x0800 {
                is_ipv4 = true;
            } else if ethertype == 0x86dd {
                is_ipv6 = true;
            }
        }
        LinkType::LinuxSll => {
            if raw_bytes.len() < 16 {
                return Err(CaptureError::MalformedPacket(
                    "truncated Linux SLL header".to_string(),
                ));
            }
            let proto = u16::from_be_bytes([raw_bytes[14], raw_bytes[15]]);
            ip_offset = 16;
            if proto == 0x0800 {
                is_ipv4 = true;
            } else if proto == 0x86dd {
                is_ipv6 = true;
            }
        }
        LinkType::LinuxSll2 => {
            if raw_bytes.len() < 20 {
                return Err(CaptureError::MalformedPacket(
                    "truncated Linux SLL2 header".to_string(),
                ));
            }
            let proto = u16::from_be_bytes([raw_bytes[0], raw_bytes[1]]);
            ip_offset = 20;
            if proto == 0x0800 {
                is_ipv4 = true;
            } else if proto == 0x86dd {
                is_ipv6 = true;
            }
        }
        LinkType::Null | LinkType::Loop => {
            if raw_bytes.len() < 4 {
                return Err(CaptureError::MalformedPacket(
                    "truncated loopback header".to_string(),
                ));
            }
            ip_offset = 4;
            if raw_bytes.len() > 4 {
                let first_nibble = raw_bytes[4] >> 4;
                if first_nibble == 4 {
                    is_ipv4 = true;
                } else if first_nibble == 6 {
                    is_ipv6 = true;
                } else {
                    let fam_le = u32::from_le_bytes([
                        raw_bytes[0],
                        raw_bytes[1],
                        raw_bytes[2],
                        raw_bytes[3],
                    ]);
                    let fam_be = u32::from_be_bytes([
                        raw_bytes[0],
                        raw_bytes[1],
                        raw_bytes[2],
                        raw_bytes[3],
                    ]);
                    if fam_le == 2 || fam_be == 2 {
                        is_ipv4 = true;
                    } else if fam_le == 24
                        || fam_be == 24
                        || fam_le == 28
                        || fam_be == 28
                        || fam_le == 30
                        || fam_be == 30
                    {
                        is_ipv6 = true;
                    }
                }
            }
        }
        LinkType::Raw | LinkType::Ipv4 | LinkType::Ipv6 => {
            ip_offset = 0;
            if !raw_bytes.is_empty() {
                let first_nibble = raw_bytes[0] >> 4;
                if first_nibble == 4 {
                    is_ipv4 = true;
                } else if first_nibble == 6 {
                    is_ipv6 = true;
                }
            }
        }
    }

    if is_ipv4 && raw_bytes.len() >= ip_offset + 20 {
        let ip_bytes = &raw_bytes[ip_offset..];
        let ihl = ((ip_bytes[0] & 0x0f) * 4) as usize;
        if ihl < 20 || ip_bytes.len() < ihl {
            return Err(CaptureError::MalformedPacket(
                "invalid IPv4 header length".to_string(),
            ));
        }

        let total_ip_len = u16::from_be_bytes([ip_bytes[2], ip_bytes[3]]) as usize;
        let proto = ip_bytes[9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(
            ip_bytes[12],
            ip_bytes[13],
            ip_bytes[14],
            ip_bytes[15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            ip_bytes[16],
            ip_bytes[17],
            ip_bytes[18],
            ip_bytes[19],
        ));

        let transport_offset = ip_offset + ihl;
        let max_transport_len =
            if total_ip_len >= ihl && ip_offset + total_ip_len <= raw_bytes.len() {
                total_ip_len - ihl
            } else {
                raw_bytes.len().saturating_sub(transport_offset)
            };

        if proto == 17 && raw_bytes.len() >= transport_offset + 8 {
            // UDP
            let udp_bytes = &raw_bytes[transport_offset..];
            let src_port = u16::from_be_bytes([udp_bytes[0], udp_bytes[1]]);
            let dst_port = u16::from_be_bytes([udp_bytes[2], udp_bytes[3]]);
            let udp_len = u16::from_be_bytes([udp_bytes[4], udp_bytes[5]]) as usize;
            let payload_len = if udp_len >= 8 {
                (udp_len - 8).min(max_transport_len.saturating_sub(8))
            } else {
                max_transport_len.saturating_sub(8)
            };
            let payload_start = transport_offset + 8;
            let payload_end = (payload_start + payload_len).min(raw_bytes.len());
            let payload = raw_bytes[payload_start..payload_end].to_vec();

            return Ok(CapturedPacket {
                index,
                timestamp,
                orig_len,
                link_type,
                network_protocol: Some("ipv4".to_string()),
                src_ip: Some(src_ip),
                dst_ip: Some(dst_ip),
                transport_protocol: Some("udp".to_string()),
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                payload,
            });
        } else if proto == 6 && raw_bytes.len() >= transport_offset + 20 {
            // TCP
            let tcp_bytes = &raw_bytes[transport_offset..];
            let src_port = u16::from_be_bytes([tcp_bytes[0], tcp_bytes[1]]);
            let dst_port = u16::from_be_bytes([tcp_bytes[2], tcp_bytes[3]]);
            let data_offset = ((tcp_bytes[12] >> 4) * 4) as usize;
            let payload_start = transport_offset + data_offset;
            let payload = if payload_start <= raw_bytes.len() {
                let end = (transport_offset + max_transport_len).min(raw_bytes.len());
                if payload_start < end {
                    raw_bytes[payload_start..end].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            return Ok(CapturedPacket {
                index,
                timestamp,
                orig_len,
                link_type,
                network_protocol: Some("ipv4".to_string()),
                src_ip: Some(src_ip),
                dst_ip: Some(dst_ip),
                transport_protocol: Some("tcp".to_string()),
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                payload,
            });
        }

        let payload = raw_bytes[transport_offset..].to_vec();
        return Ok(CapturedPacket {
            index,
            timestamp,
            orig_len,
            link_type,
            network_protocol: Some("ipv4".to_string()),
            src_ip: Some(src_ip),
            dst_ip: Some(dst_ip),
            transport_protocol: None,
            src_port: None,
            dst_port: None,
            payload,
        });
    }

    if is_ipv6 && raw_bytes.len() >= ip_offset + 40 {
        let ip_bytes = &raw_bytes[ip_offset..];
        let mut src_octets = [0u8; 16];
        let mut dst_octets = [0u8; 16];
        src_octets.copy_from_slice(&ip_bytes[8..24]);
        dst_octets.copy_from_slice(&ip_bytes[24..40]);
        let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets));

        let mut next_header = ip_bytes[6];
        let mut curr_offset = ip_offset + 40;

        // Skip standard IPv6 extension headers
        while curr_offset < raw_bytes.len() {
            if next_header == 0 || next_header == 43 || next_header == 60 {
                // Hop-by-hop (0), Routing (43), Destination options (60)
                if curr_offset + 2 > raw_bytes.len() {
                    break;
                }
                next_header = raw_bytes[curr_offset];
                let ext_len = (raw_bytes[curr_offset + 1] as usize + 1) * 8;
                curr_offset += ext_len;
            } else if next_header == 44 {
                // Fragment header (8 bytes fixed)
                if curr_offset + 8 > raw_bytes.len() {
                    break;
                }
                next_header = raw_bytes[curr_offset];
                curr_offset += 8;
            } else {
                break;
            }
        }

        if next_header == 17 && raw_bytes.len() >= curr_offset + 8 {
            let udp_bytes = &raw_bytes[curr_offset..];
            let src_port = u16::from_be_bytes([udp_bytes[0], udp_bytes[1]]);
            let dst_port = u16::from_be_bytes([udp_bytes[2], udp_bytes[3]]);
            let udp_len = u16::from_be_bytes([udp_bytes[4], udp_bytes[5]]) as usize;
            let payload_len = udp_len.saturating_sub(8);
            let payload_start = curr_offset + 8;
            let payload_end = (payload_start + payload_len).min(raw_bytes.len());
            let payload = raw_bytes[payload_start..payload_end].to_vec();

            return Ok(CapturedPacket {
                index,
                timestamp,
                orig_len,
                link_type,
                network_protocol: Some("ipv6".to_string()),
                src_ip: Some(src_ip),
                dst_ip: Some(dst_ip),
                transport_protocol: Some("udp".to_string()),
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                payload,
            });
        } else if next_header == 6 && raw_bytes.len() >= curr_offset + 20 {
            let tcp_bytes = &raw_bytes[curr_offset..];
            let src_port = u16::from_be_bytes([tcp_bytes[0], tcp_bytes[1]]);
            let dst_port = u16::from_be_bytes([tcp_bytes[2], tcp_bytes[3]]);
            let data_offset = ((tcp_bytes[12] >> 4) * 4) as usize;
            let payload_start = curr_offset + data_offset;
            let payload = if payload_start <= raw_bytes.len() {
                raw_bytes[payload_start..].to_vec()
            } else {
                Vec::new()
            };

            return Ok(CapturedPacket {
                index,
                timestamp,
                orig_len,
                link_type,
                network_protocol: Some("ipv6".to_string()),
                src_ip: Some(src_ip),
                dst_ip: Some(dst_ip),
                transport_protocol: Some("tcp".to_string()),
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                payload,
            });
        }

        let payload = raw_bytes[curr_offset..].to_vec();
        return Ok(CapturedPacket {
            index,
            timestamp,
            orig_len,
            link_type,
            network_protocol: Some("ipv6".to_string()),
            src_ip: Some(src_ip),
            dst_ip: Some(dst_ip),
            transport_protocol: None,
            src_port: None,
            dst_port: None,
            payload,
        });
    }

    // Fallback for non-IP or raw payload
    let payload = raw_bytes[ip_offset..].to_vec();
    Ok(CapturedPacket {
        index,
        timestamp,
        orig_len,
        link_type,
        network_protocol: None,
        src_ip: None,
        dst_ip: None,
        transport_protocol: None,
        src_port: None,
        dst_port: None,
        payload,
    })
}

/// Synthetic packet definition for test fixture generation.
#[derive(Debug, Clone)]
pub struct SyntheticPacket {
    pub timestamp: Duration,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

/// Computes the 16-bit one's complement Internet checksum for IPv4 headers.
#[must_use]
pub fn compute_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds the link-layer and network/transport headers for a synthetic packet.
pub fn build_synthetic_frame(link_type: LinkType, pkt: &SyntheticPacket) -> Vec<u8> {
    let mut frame = Vec::new();

    // 1. Link layer header
    match link_type {
        LinkType::Ethernet => {
            // Dst MAC: 00:11:22:33:44:55, Src MAC: 00:aa:bb:cc:dd:ee
            frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
            frame.extend_from_slice(&[0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
            let ethertype: u16 = if pkt.src_ip.is_ipv4() { 0x0800 } else { 0x86dd };
            frame.extend_from_slice(&ethertype.to_be_bytes());
        }
        LinkType::LinuxSll => {
            frame.extend_from_slice(&[0u8; 14]);
            let proto: u16 = if pkt.src_ip.is_ipv4() { 0x0800 } else { 0x86dd };
            frame.extend_from_slice(&proto.to_be_bytes());
        }
        LinkType::LinuxSll2 => {
            let proto: u16 = if pkt.src_ip.is_ipv4() { 0x0800 } else { 0x86dd };
            frame.extend_from_slice(&proto.to_be_bytes());
            frame.extend_from_slice(&[0u8; 18]);
        }
        LinkType::Null => {
            // BSD family (little-endian AF_INET = 2, AF_INET6 = 24)
            let fam: u32 = if pkt.src_ip.is_ipv4() { 2 } else { 24 };
            frame.extend_from_slice(&fam.to_le_bytes());
        }
        LinkType::Loop => {
            // OpenBSD family (network byte order AF_INET = 2, AF_INET6 = 24)
            let fam: u32 = if pkt.src_ip.is_ipv4() { 2 } else { 24 };
            frame.extend_from_slice(&fam.to_be_bytes());
        }
        LinkType::Raw | LinkType::Ipv4 | LinkType::Ipv6 => {
            // No link-layer header
        }
    }

    // 2. Network and Transport headers
    match (pkt.src_ip, pkt.dst_ip) {
        (IpAddr::V4(s4), IpAddr::V4(d4)) => {
            let total_len = (20 + 8 + pkt.payload.len()) as u16;
            let mut ip_hdr = [0u8; 20];
            ip_hdr[0] = 0x45; // Version 4, IHL 5
            ip_hdr[2..4].copy_from_slice(&total_len.to_be_bytes());
            ip_hdr[4..6].copy_from_slice(&1u16.to_be_bytes()); // ID
            ip_hdr[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
            ip_hdr[8] = 64; // TTL
            ip_hdr[9] = 17; // UDP
            ip_hdr[12..16].copy_from_slice(&s4.octets());
            ip_hdr[16..20].copy_from_slice(&d4.octets());
            let cksum = compute_ipv4_checksum(&ip_hdr);
            ip_hdr[10..12].copy_from_slice(&cksum.to_be_bytes());
            frame.extend_from_slice(&ip_hdr);

            let udp_len = (8 + pkt.payload.len()) as u16;
            frame.extend_from_slice(&pkt.src_port.to_be_bytes());
            frame.extend_from_slice(&pkt.dst_port.to_be_bytes());
            frame.extend_from_slice(&udp_len.to_be_bytes());
            frame.extend_from_slice(&[0, 0]); // UDP checksum optional
            frame.extend_from_slice(&pkt.payload);
        }
        (IpAddr::V6(s6), IpAddr::V6(d6)) => {
            let payload_len = (8 + pkt.payload.len()) as u16;
            frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version 6
            frame.extend_from_slice(&payload_len.to_be_bytes());
            frame.push(17); // UDP
            frame.push(64); // Hop limit
            frame.extend_from_slice(&s6.octets());
            frame.extend_from_slice(&d6.octets());

            let udp_len = (8 + pkt.payload.len()) as u16;
            frame.extend_from_slice(&pkt.src_port.to_be_bytes());
            frame.extend_from_slice(&pkt.dst_port.to_be_bytes());
            frame.extend_from_slice(&udp_len.to_be_bytes());
            frame.extend_from_slice(&[0, 0]);
            frame.extend_from_slice(&pkt.payload);
        }
        _ => {
            // Mixed family fallback
            frame.extend_from_slice(&pkt.payload);
        }
    }

    frame
}

/// Generates synthetic PCAP file bytes in memory (SPEC §12).
pub fn build_synthetic_pcap(
    link_type: LinkType,
    packets: &[SyntheticPacket],
    nanoseconds: bool,
) -> Vec<u8> {
    let mut out = Vec::new();

    // Global Header (24 bytes)
    // Little-endian magic
    if nanoseconds {
        out.extend_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]);
    } else {
        out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    }
    out.extend_from_slice(&2u16.to_le_bytes()); // Major 2
    out.extend_from_slice(&4u16.to_le_bytes()); // Minor 4
    out.extend_from_slice(&0i32.to_le_bytes()); // Thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // Sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // Snaplen
    out.extend_from_slice(&(link_type as u32).to_le_bytes()); // Network / LinkType

    for pkt in packets {
        let frame = build_synthetic_frame(link_type, pkt);
        let ts_sec = pkt.timestamp.as_secs() as u32;
        let ts_subsec = if nanoseconds {
            pkt.timestamp.subsec_nanos()
        } else {
            pkt.timestamp.subsec_micros()
        };
        let incl_len = frame.len() as u32;
        let orig_len = incl_len;

        out.extend_from_slice(&ts_sec.to_le_bytes());
        out.extend_from_slice(&ts_subsec.to_le_bytes());
        out.extend_from_slice(&incl_len.to_le_bytes());
        out.extend_from_slice(&orig_len.to_le_bytes());
        out.extend_from_slice(&frame);
    }

    out
}

/// Generates synthetic PCAPNG file bytes in memory (SPEC §12).
pub fn build_synthetic_pcapng(link_type: LinkType, packets: &[SyntheticPacket]) -> Vec<u8> {
    let mut out = Vec::new();

    // 1. Section Header Block (SHB)
    let mut shb_body = Vec::new();
    shb_body.extend_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a]); // Byte-Order Magic (Little-Endian)
    shb_body.extend_from_slice(&1u16.to_le_bytes()); // Major 1
    shb_body.extend_from_slice(&0u16.to_le_bytes()); // Minor 0
    shb_body.extend_from_slice(&(-1i64).to_le_bytes()); // Section Length unspecified

    let shb_len = (12 + shb_body.len()) as u32;
    out.extend_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]); // SHB Block Type
    out.extend_from_slice(&shb_len.to_le_bytes());
    out.extend_from_slice(&shb_body);
    out.extend_from_slice(&shb_len.to_le_bytes());

    // 2. Interface Description Block (IDB)
    let mut idb_body = Vec::new();
    idb_body.extend_from_slice(&(link_type as u16).to_le_bytes()); // LinkType
    idb_body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    idb_body.extend_from_slice(&65535u32.to_le_bytes()); // SnapLen
                                                         // Option: if_tsresol = 6 (microsecond)
    idb_body.extend_from_slice(&9u16.to_le_bytes()); // Option Code 9
    idb_body.extend_from_slice(&1u16.to_le_bytes()); // Option Length 1
    idb_body.push(6); // 10^-6 microsecond resolution
    idb_body.extend_from_slice(&[0, 0, 0]); // 3 bytes padding
                                            // End of options
    idb_body.extend_from_slice(&0u32.to_le_bytes());

    let idb_len = (12 + idb_body.len()) as u32;
    out.extend_from_slice(&1u32.to_le_bytes()); // IDB Block Type
    out.extend_from_slice(&idb_len.to_le_bytes());
    out.extend_from_slice(&idb_body);
    out.extend_from_slice(&idb_len.to_le_bytes());

    // 3. Enhanced Packet Blocks (EPB)
    for pkt in packets {
        let frame = build_synthetic_frame(link_type, pkt);
        let mut epb_body = Vec::new();
        epb_body.extend_from_slice(&0u32.to_le_bytes()); // Interface ID 0
        let ts_micros = pkt.timestamp.as_micros() as u64;
        let ts_high = (ts_micros >> 32) as u32;
        let ts_low = (ts_micros & 0xffff_ffff) as u32;
        epb_body.extend_from_slice(&ts_high.to_le_bytes());
        epb_body.extend_from_slice(&ts_low.to_le_bytes());
        let caplen = frame.len() as u32;
        let origlen = caplen;
        epb_body.extend_from_slice(&caplen.to_le_bytes());
        epb_body.extend_from_slice(&origlen.to_le_bytes());
        epb_body.extend_from_slice(&frame);
        let pad = (4 - (frame.len() % 4)) % 4;
        epb_body.resize(epb_body.len() + pad, 0);

        let epb_len = (12 + epb_body.len()) as u32;
        out.extend_from_slice(&6u32.to_le_bytes()); // EPB Block Type
        out.extend_from_slice(&epb_len.to_le_bytes());
        out.extend_from_slice(&epb_body);
        out.extend_from_slice(&epb_len.to_le_bytes());
    }

    out
}
