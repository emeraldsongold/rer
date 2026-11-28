//! In-tree QUIC packet header parser and variable-length integer codec (SPEC §8, §14).
//!
//! Provides a zero-dependency in-tree QUIC packet header parser and RFC 9000 §16
//! variable-length integer codec for passive metadata inspection.
//!
//! # Disclaimer
//!
//! In accordance with SPEC §8 and §14, RER implements passive metadata inspection of
//! cleartext QUIC packet headers. RER does NOT implement TLS 1.3 decryption, header
//! protection removal, stateful congestion control, stream reassembly, or QUIC
//! endpoint termination. Forwarded datagrams are transmitted byte-unmodified.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// QUIC Version 1 (RFC 9000).
pub const QUIC_VERSION_1: u32 = 0x0000_0001;

/// QUIC Version 2 (RFC 9369).
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;

/// QUIC Version Negotiation sentinel version (RFC 9000 §17.2.1).
pub const QUIC_VERSION_NEGOTIATION: u32 = 0x0000_0000;

/// Maximum Connection ID length in bytes for QUIC Version 1 (RFC 9000 §17.2).
pub const QUIC_MAX_CID_LEN: usize = 20;

/// Minimum Long Header length in bytes (1 flags + 4 version + 1 DCIL + 1 SCIL).
pub const QUIC_MIN_LONG_HEADER_LEN: usize = 7;

/// Header Form bit mask (bit 7): 1 = Long Header, 0 = Short Header.
pub const QUIC_HEADER_FORM_BIT: u8 = 0x80;

/// Fixed Bit mask (bit 6): must be 1 for RFC 9000 packets (except Version Negotiation).
pub const QUIC_FIXED_BIT: u8 = 0x40;

/// Short Header Spin Bit mask (bit 5, RFC 9000 §17.4).
pub const QUIC_SPIN_BIT: u8 = 0x20;

/// Short Header Key Phase bit mask (bit 2, RFC 9000 §17.3.1).
pub const QUIC_KEY_PHASE_BIT: u8 = 0x04;

/// Maximum 62-bit value representable as a QUIC variable-length integer (RFC 9000 §16).
pub const QUIC_MAX_VARINT: u64 = (1_u64 << 62) - 1;

/// QUIC header form (RFC 9000 §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuicHeaderForm {
    /// Long Header packet (bit 7 = 1).
    Long,
    /// Short Header / 1-RTT packet (bit 7 = 0).
    Short,
}

/// QUIC packet type (RFC 9000 §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuicPacketType {
    /// Initial packet (Long Header type 0x0).
    Initial,
    /// 0-RTT packet (Long Header type 0x1).
    ZeroRtt,
    /// Handshake packet (Long Header type 0x2).
    Handshake,
    /// Retry packet (Long Header type 0x3).
    Retry,
    /// Version Negotiation packet (Long Header with Version 0x00000000).
    VersionNegotiation,
    /// Short Header (1-RTT) packet.
    Short,
}

/// Diagnostic evaluation status for QUIC packet parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QuicParseStatus {
    /// Packet header parsed cleanly.
    Valid,
    /// Packet or header truncated before all required fields could be read.
    TruncatedHeader,
    /// Fixed Bit (bit 6) was 0 on a non-Version-Negotiation packet.
    InvalidFixedBit,
    /// Connection ID length exceeded 20 bytes.
    InvalidCidLength,
    /// Variable-length integer was truncated or invalid.
    InvalidVarint,
}

/// Errors returned by the QUIC header parser and variable-length integer codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicParseError {
    /// Input buffer is empty.
    EmptyPacket,
    /// Header is truncated before all declared fields could be read.
    TruncatedHeader { expected: usize, actual: usize },
    /// Variable-length integer is truncated.
    TruncatedVarint { expected: usize, actual: usize },
    /// Fixed Bit (bit 6) is 0 on a non-Version-Negotiation packet.
    InvalidFixedBit { first_byte: u8 },
    /// Connection ID length exceeds [`QUIC_MAX_CID_LEN`] (20 bytes).
    InvalidCidLength { kind: &'static str, len: usize },
    /// Version Negotiation packet has trailing bytes not aligned to 4-byte version entries.
    InvalidVersionNegotiation { trailing_bytes: usize },
    /// Variable-length integer value exceeds [`QUIC_MAX_VARINT`] (2^62 - 1).
    VarintOverflow { value: u64 },
}

impl QuicParseError {
    /// Maps this error to its corresponding [`QuicParseStatus`].
    #[must_use]
    pub const fn status(&self) -> QuicParseStatus {
        match self {
            Self::EmptyPacket
            | Self::TruncatedHeader { .. }
            | Self::InvalidVersionNegotiation { .. } => QuicParseStatus::TruncatedHeader,
            Self::TruncatedVarint { .. } | Self::VarintOverflow { .. } => {
                QuicParseStatus::InvalidVarint
            }
            Self::InvalidFixedBit { .. } => QuicParseStatus::InvalidFixedBit,
            Self::InvalidCidLength { .. } => QuicParseStatus::InvalidCidLength,
        }
    }
}

impl fmt::Display for QuicParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPacket => write!(f, "empty QUIC packet"),
            Self::TruncatedHeader { expected, actual } => {
                write!(
                    f,
                    "truncated QUIC header: expected at least {expected} bytes, got {actual}"
                )
            }
            Self::TruncatedVarint { expected, actual } => {
                write!(
                    f,
                    "truncated QUIC varint: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidFixedBit { first_byte } => {
                write!(
                    f,
                    "invalid QUIC fixed bit in first byte 0x{first_byte:02x} (expected bit 6 = 1)"
                )
            }
            Self::InvalidCidLength { kind, len } => {
                write!(
                    f,
                    "invalid QUIC {kind} length {len}: exceeds maximum {QUIC_MAX_CID_LEN} bytes"
                )
            }
            Self::InvalidVersionNegotiation { trailing_bytes } => {
                write!(
                    f,
                    "invalid QUIC Version Negotiation supported versions length: {trailing_bytes} bytes is not a multiple of 4"
                )
            }
            Self::VarintOverflow { value } => {
                write!(
                    f,
                    "QUIC varint value {value} exceeds maximum {QUIC_MAX_VARINT}"
                )
            }
        }
    }
}

impl std::error::Error for QuicParseError {}

/// Structured QUIC metadata extracted from a packet header (RFC 9000 §17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QuicMetadata {
    /// Header form (Long or Short).
    pub header_form: QuicHeaderForm,
    /// Decoded QUIC packet type.
    pub packet_type: QuicPacketType,
    /// 32-bit QUIC version (present on Long Header packets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Destination Connection ID formatted as lowercase hexadecimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_cid: Option<String>,
    /// Source Connection ID formatted as lowercase hexadecimal (Long Header packets only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_cid: Option<String>,
    /// Short Header Spin Bit (bit 5), if Short Header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spin_bit: Option<bool>,
    /// Short Header Key Phase bit (bit 2, subject to header protection), if Short Header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_phase: Option<bool>,
    /// Initial packet Token Length (varint), if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_len: Option<usize>,
    /// Supported 32-bit versions extracted from Version Negotiation packets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_versions: Vec<u32>,
    /// Total header bytes inspected.
    pub header_len: usize,
}

/// Formats a byte slice as lowercase hexadecimal.
#[must_use]
pub fn format_cid_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Decodes a QUIC variable-length integer (RFC 9000 §16).
///
/// Returns `(decoded_value, bytes_consumed)` on success.
pub fn parse_quic_varint(input: &[u8]) -> Result<(u64, usize), QuicParseError> {
    let Some(&first) = input.first() else {
        return Err(QuicParseError::TruncatedVarint {
            expected: 1,
            actual: 0,
        });
    };

    let prefix = first >> 6;
    let len = 1_usize << prefix;
    if input.len() < len {
        return Err(QuicParseError::TruncatedVarint {
            expected: len,
            actual: input.len(),
        });
    }

    let mut value = u64::from(first & 0x3F);
    for &byte in &input[1..len] {
        value = (value << 8) | u64::from(byte);
    }
    Ok((value, len))
}

/// Encodes a 62-bit unsigned integer as a QUIC variable-length integer (RFC 9000 §16).
pub fn encode_quic_varint(value: u64) -> Result<Vec<u8>, QuicParseError> {
    if value > QUIC_MAX_VARINT {
        return Err(QuicParseError::VarintOverflow { value });
    }
    if value < (1 << 6) {
        Ok(vec![value as u8])
    } else if value < (1 << 14) {
        let v = (value as u16) | 0x4000;
        Ok(v.to_be_bytes().to_vec())
    } else if value < (1 << 30) {
        let v = (value as u32) | 0x8000_0000;
        Ok(v.to_be_bytes().to_vec())
    } else {
        let v = value | 0xC000_0000_0000_0000;
        Ok(v.to_be_bytes().to_vec())
    }
}

/// Parses a QUIC packet header (Long or Short) without modifying or decrypting payload data.
///
/// For Short Header (1-RTT) packets, `fixed_short_dcid_len` specifies the expected
/// Destination Connection ID length (0..=20 bytes). When `None`, the packet type is
/// reported as [`QuicPacketType::Short`] without extracting a Destination Connection ID.
pub fn parse_quic_header(
    input: &[u8],
    fixed_short_dcid_len: Option<usize>,
) -> Result<QuicMetadata, QuicParseError> {
    let Some(&first_byte) = input.first() else {
        return Err(QuicParseError::EmptyPacket);
    };

    if (first_byte & QUIC_HEADER_FORM_BIT) != 0 {
        parse_long_header(input, first_byte)
    } else {
        parse_short_header(input, first_byte, fixed_short_dcid_len)
    }
}

/// Extracted `(destination_cid, source_cid)` byte vectors from a QUIC packet header.
pub type ExtractedConnectionIds = (Option<Vec<u8>>, Option<Vec<u8>>);

/// Extracts raw Destination and Source Connection ID byte slices from a QUIC packet header.
///
/// Returns `(destination_cid, source_cid)`. For Short Headers, `source_cid` is always `None`,
/// and `destination_cid` is `None` unless `fixed_short_dcid_len` is `Some(_)`.
pub fn extract_connection_ids(
    input: &[u8],
    fixed_short_dcid_len: Option<usize>,
) -> Result<ExtractedConnectionIds, QuicParseError> {
    let Some(&first_byte) = input.first() else {
        return Err(QuicParseError::EmptyPacket);
    };

    if (first_byte & QUIC_HEADER_FORM_BIT) != 0 {
        let (dcid, scid, _) = parse_long_header_cids(input, first_byte)?;
        Ok((Some(dcid.to_vec()), Some(scid.to_vec())))
    } else {
        if (first_byte & QUIC_FIXED_BIT) == 0 {
            return Err(QuicParseError::InvalidFixedBit { first_byte });
        }
        match fixed_short_dcid_len {
            Some(dcid_len) => {
                if dcid_len > QUIC_MAX_CID_LEN {
                    return Err(QuicParseError::InvalidCidLength {
                        kind: "fixed_short_dcid",
                        len: dcid_len,
                    });
                }
                let needed = 1 + dcid_len;
                if input.len() < needed {
                    return Err(QuicParseError::TruncatedHeader {
                        expected: needed,
                        actual: input.len(),
                    });
                }
                Ok((Some(input[1..needed].to_vec()), None))
            }
            None => Ok((None, None)),
        }
    }
}

fn parse_long_header_cids(
    input: &[u8],
    first_byte: u8,
) -> Result<(&[u8], &[u8], usize), QuicParseError> {
    if input.len() < 5 {
        return Err(QuicParseError::TruncatedHeader {
            expected: 5,
            actual: input.len(),
        });
    }

    let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
    // RFC 9000 §17.2.1: Version Negotiation packets have Version == 0 and arbitrary unused bits
    // in byte 0 (Fixed Bit is not required to be 1). All other Long Headers require Fixed Bit == 1.
    if version != QUIC_VERSION_NEGOTIATION && (first_byte & QUIC_FIXED_BIT) == 0 {
        return Err(QuicParseError::InvalidFixedBit { first_byte });
    }

    if input.len() < 6 {
        return Err(QuicParseError::TruncatedHeader {
            expected: 6,
            actual: input.len(),
        });
    }
    let dcil = usize::from(input[5]);
    if dcil > QUIC_MAX_CID_LEN {
        return Err(QuicParseError::InvalidCidLength {
            kind: "destination_cid",
            len: dcil,
        });
    }

    let scil_offset = 6 + dcil;
    if input.len() < scil_offset + 1 {
        return Err(QuicParseError::TruncatedHeader {
            expected: scil_offset + 1,
            actual: input.len(),
        });
    }
    let dcid = &input[6..scil_offset];

    let scil = usize::from(input[scil_offset]);
    if scil > QUIC_MAX_CID_LEN {
        return Err(QuicParseError::InvalidCidLength {
            kind: "source_cid",
            len: scil,
        });
    }

    let after_scid = scil_offset + 1 + scil;
    if input.len() < after_scid {
        return Err(QuicParseError::TruncatedHeader {
            expected: after_scid,
            actual: input.len(),
        });
    }
    let scid = &input[scil_offset + 1..after_scid];

    Ok((dcid, scid, after_scid))
}

fn parse_long_header(input: &[u8], first_byte: u8) -> Result<QuicMetadata, QuicParseError> {
    let (dcid, scid, after_scid) = parse_long_header_cids(input, first_byte)?;
    let version = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);

    if version == QUIC_VERSION_NEGOTIATION {
        let trailing = &input[after_scid..];
        if trailing.len() % 4 != 0 {
            return Err(QuicParseError::InvalidVersionNegotiation {
                trailing_bytes: trailing.len(),
            });
        }
        let supported_versions = trailing
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();

        return Ok(QuicMetadata {
            header_form: QuicHeaderForm::Long,
            packet_type: QuicPacketType::VersionNegotiation,
            version: Some(version),
            destination_cid: Some(format_cid_hex(dcid)),
            source_cid: Some(format_cid_hex(scid)),
            spin_bit: None,
            key_phase: None,
            token_len: None,
            supported_versions,
            header_len: input.len(),
        });
    }

    let packet_type = match (first_byte >> 4) & 0x03 {
        0x00 => QuicPacketType::Initial,
        0x01 => QuicPacketType::ZeroRtt,
        0x02 => QuicPacketType::Handshake,
        _ => QuicPacketType::Retry,
    };

    let mut header_len = after_scid;
    let mut token_len = None;
    if packet_type == QuicPacketType::Initial && after_scid < input.len() {
        let (tlen, consumed) = parse_quic_varint(&input[after_scid..])?;
        let tlen_usize = usize::try_from(tlen).unwrap_or(usize::MAX);
        let token_end = after_scid
            .saturating_add(consumed)
            .saturating_add(tlen_usize);
        if input.len() < token_end {
            return Err(QuicParseError::TruncatedHeader {
                expected: token_end,
                actual: input.len(),
            });
        }
        token_len = Some(tlen_usize);
        header_len = token_end;
    }

    Ok(QuicMetadata {
        header_form: QuicHeaderForm::Long,
        packet_type,
        version: Some(version),
        destination_cid: Some(format_cid_hex(dcid)),
        source_cid: Some(format_cid_hex(scid)),
        spin_bit: None,
        key_phase: None,
        token_len,
        supported_versions: Vec::new(),
        header_len,
    })
}

fn parse_short_header(
    input: &[u8],
    first_byte: u8,
    fixed_short_dcid_len: Option<usize>,
) -> Result<QuicMetadata, QuicParseError> {
    if (first_byte & QUIC_FIXED_BIT) == 0 {
        return Err(QuicParseError::InvalidFixedBit { first_byte });
    }

    let (destination_cid, header_len) = match fixed_short_dcid_len {
        Some(dcid_len) => {
            if dcid_len > QUIC_MAX_CID_LEN {
                return Err(QuicParseError::InvalidCidLength {
                    kind: "fixed_short_dcid",
                    len: dcid_len,
                });
            }
            let needed = 1 + dcid_len;
            if input.len() < needed {
                return Err(QuicParseError::TruncatedHeader {
                    expected: needed,
                    actual: input.len(),
                });
            }
            (Some(format_cid_hex(&input[1..needed])), needed)
        }
        None => (None, 1),
    };

    Ok(QuicMetadata {
        header_form: QuicHeaderForm::Short,
        packet_type: QuicPacketType::Short,
        version: None,
        destination_cid,
        source_cid: None,
        spin_bit: Some((first_byte & QUIC_SPIN_BIT) != 0),
        key_phase: Some((first_byte & QUIC_KEY_PHASE_BIT) != 0),
        token_len: None,
        supported_versions: Vec::new(),
        header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_decode_rfc9000_examples() {
        // RFC 9000 §16 / Appendix A.1: [0x40, 0x25] -> 37, 2 bytes consumed
        assert_eq!(parse_quic_varint(&[0x40, 0x25]), Ok((37, 2)));
        // 1-byte: 0x25 -> 37
        assert_eq!(parse_quic_varint(&[0x25]), Ok((37, 1)));
        // 2-byte: [0x7b, 0xbd] -> 15293
        assert_eq!(parse_quic_varint(&[0x7b, 0xbd]), Ok((15_293, 2)));
        // 4-byte: [0x9d, 0x7f, 0x3e, 0x7d] -> 494878333
        assert_eq!(
            parse_quic_varint(&[0x9d, 0x7f, 0x3e, 0x7d]),
            Ok((494_878_333, 4))
        );
        // 8-byte: [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c] -> 151288809941952652
        assert_eq!(
            parse_quic_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Ok((151_288_809_941_952_652, 8))
        );
    }

    #[test]
    fn test_varint_roundtrip_and_errors() {
        for &val in &[
            0_u64,
            1,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            QUIC_MAX_VARINT,
        ] {
            let encoded = encode_quic_varint(val).expect("encode varint");
            let (decoded, consumed) = parse_quic_varint(&encoded).expect("decode varint");
            assert_eq!(decoded, val);
            assert_eq!(consumed, encoded.len());
        }

        assert_eq!(
            parse_quic_varint(&[]),
            Err(QuicParseError::TruncatedVarint {
                expected: 1,
                actual: 0
            })
        );
        assert_eq!(
            parse_quic_varint(&[0x40]),
            Err(QuicParseError::TruncatedVarint {
                expected: 2,
                actual: 1
            })
        );
        assert_eq!(
            encode_quic_varint(QUIC_MAX_VARINT + 1),
            Err(QuicParseError::VarintOverflow {
                value: QUIC_MAX_VARINT + 1
            })
        );
    }

    #[test]
    fn test_parse_long_header_initial_packet() {
        let dcid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let scid = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22];
        let mut pkt = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 8];
        pkt.extend_from_slice(&dcid);
        pkt.push(8);
        pkt.extend_from_slice(&scid);

        let meta = parse_quic_header(&pkt, None).expect("parse Initial");
        assert_eq!(meta.header_form, QuicHeaderForm::Long);
        assert_eq!(meta.packet_type, QuicPacketType::Initial);
        assert_eq!(meta.version, Some(QUIC_VERSION_1));
        assert_eq!(meta.destination_cid.as_deref(), Some("0102030405060708"));
        assert_eq!(meta.source_cid.as_deref(), Some("aabbccddeeff1122"));
        assert_eq!(meta.token_len, None);

        let (raw_dcid, raw_scid) = extract_connection_ids(&pkt, None).expect("extract CIDs");
        assert_eq!(raw_dcid, Some(dcid.to_vec()));
        assert_eq!(raw_scid, Some(scid.to_vec()));
    }

    #[test]
    fn test_parse_long_header_initial_with_token() {
        let mut pkt = vec![0xC3, 0x00, 0x00, 0x00, 0x01, 4, 1, 2, 3, 4, 2, 5, 6];
        // Token length = 4, followed by 4 token bytes
        pkt.extend_from_slice(&[0x04, 0xde, 0xad, 0xbe, 0xef]);

        let meta = parse_quic_header(&pkt, None).expect("parse Initial with token");
        assert_eq!(meta.packet_type, QuicPacketType::Initial);
        assert_eq!(meta.token_len, Some(4));
    }

    #[test]
    fn test_parse_long_header_other_types() {
        // 0-RTT (0xD0), Handshake (0xE0), Retry (0xF0)
        for (first_byte, expected_type) in [
            (0xD0, QuicPacketType::ZeroRtt),
            (0xE0, QuicPacketType::Handshake),
            (0xF0, QuicPacketType::Retry),
        ] {
            let pkt = vec![first_byte, 0x00, 0x00, 0x00, 0x01, 2, 0x11, 0x22, 0];
            let meta = parse_quic_header(&pkt, None).expect("parse long header");
            assert_eq!(meta.header_form, QuicHeaderForm::Long);
            assert_eq!(meta.packet_type, expected_type);
            assert_eq!(meta.version, Some(1));
            assert_eq!(meta.destination_cid.as_deref(), Some("1122"));
            assert_eq!(meta.source_cid.as_deref(), Some(""));
        }
    }

    #[test]
    fn test_parse_version_negotiation_packet() {
        // First byte 0x80 (Fixed Bit = 0 is valid for Version Negotiation), version = 0x00000000
        let mut pkt = vec![
            0x80, 0x00, 0x00, 0x00, 0x00, 4, 0x0a, 0x0b, 0x0c, 0x0d, 2, 0x1e, 0x2f,
        ];
        // Supported versions: 0x00000001 and 0x6b3343cf
        pkt.extend_from_slice(&QUIC_VERSION_1.to_be_bytes());
        pkt.extend_from_slice(&QUIC_VERSION_2.to_be_bytes());

        let meta = parse_quic_header(&pkt, None).expect("parse Version Negotiation");
        assert_eq!(meta.header_form, QuicHeaderForm::Long);
        assert_eq!(meta.packet_type, QuicPacketType::VersionNegotiation);
        assert_eq!(meta.version, Some(0));
        assert_eq!(meta.destination_cid.as_deref(), Some("0a0b0c0d"));
        assert_eq!(meta.source_cid.as_deref(), Some("1e2f"));
        assert_eq!(
            meta.supported_versions,
            vec![QUIC_VERSION_1, QUIC_VERSION_2]
        );
    }

    #[test]
    fn test_parse_short_header_with_and_without_dcid_len() {
        let mut pkt = vec![0x40];
        pkt.extend_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
        pkt.extend_from_slice(&[0xff, 0xee]); // protected payload bytes

        let with_dcid = parse_quic_header(&pkt, Some(8)).expect("parse short header with DCID");
        assert_eq!(with_dcid.header_form, QuicHeaderForm::Short);
        assert_eq!(with_dcid.packet_type, QuicPacketType::Short);
        assert_eq!(
            with_dcid.destination_cid.as_deref(),
            Some("1020304050607080")
        );
        assert_eq!(with_dcid.source_cid, None);
        assert_eq!(with_dcid.spin_bit, Some(false));
        assert_eq!(with_dcid.key_phase, Some(false));

        let without_dcid =
            parse_quic_header(&pkt, None).expect("parse short header without DCID len");
        assert_eq!(without_dcid.header_form, QuicHeaderForm::Short);
        assert_eq!(without_dcid.packet_type, QuicPacketType::Short);
        assert_eq!(without_dcid.destination_cid, None);
        assert_eq!(without_dcid.source_cid, None);

        // Spin bit (0x20) and Key Phase (0x04)
        let pkt_bits = vec![0x64, 0x01, 0x02];
        let meta_bits = parse_quic_header(&pkt_bits, Some(2)).expect("parse short header bits");
        assert_eq!(meta_bits.spin_bit, Some(true));
        assert_eq!(meta_bits.key_phase, Some(true));
    }

    #[test]
    fn test_reject_cid_exceeding_20_bytes_and_malformed_headers() {
        // Long Header declaring DCID length of 21 bytes
        let mut bad_dcid = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 21];
        bad_dcid.extend_from_slice(&[0xAA; 21]);
        bad_dcid.push(0);
        let err = parse_quic_header(&bad_dcid, None).expect_err("reject 21-byte DCID");
        assert_eq!(
            err,
            QuicParseError::InvalidCidLength {
                kind: "destination_cid",
                len: 21
            }
        );
        assert_eq!(err.status(), QuicParseStatus::InvalidCidLength);

        // Long Header declaring SCID length of 21 bytes
        let mut bad_scid = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0, 21];
        bad_scid.extend_from_slice(&[0xBB; 21]);
        assert!(matches!(
            parse_quic_header(&bad_scid, None),
            Err(QuicParseError::InvalidCidLength {
                kind: "source_cid",
                len: 21
            })
        ));

        // Empty packet
        assert_eq!(
            parse_quic_header(&[], None),
            Err(QuicParseError::EmptyPacket)
        );

        // Truncated Long Header (< 5 bytes)
        assert!(matches!(
            parse_quic_header(&[0xC0, 0x00, 0x00], None),
            Err(QuicParseError::TruncatedHeader { .. })
        ));

        // Non-VN Long Header with Fixed Bit = 0
        assert_eq!(
            parse_quic_header(&[0x80, 0x00, 0x00, 0x00, 0x01, 0, 0], None),
            Err(QuicParseError::InvalidFixedBit { first_byte: 0x80 })
        );

        // Short Header with Fixed Bit = 0
        assert_eq!(
            parse_quic_header(&[0x00, 0x01, 0x02], Some(2)),
            Err(QuicParseError::InvalidFixedBit { first_byte: 0x00 })
        );
    }
}
