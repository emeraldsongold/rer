use serde::{Deserialize, Serialize};
use std::fmt;

use super::sha256::sha256_hex;

const MAGIC: &[u8; 4] = b"RER1";

/// Error type encountered when encoding or decoding a simulation Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    PayloadTooShort,
    InvalidMagic,
    InvalidUtf8(String),
    MalformedHeader(&'static str),
    JsonError(String),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooShort => write!(f, "packet buffer too short"),
            Self::InvalidMagic => write!(f, "invalid packet magic prefix"),
            Self::InvalidUtf8(err) => write!(f, "invalid utf-8 string in packet: {}", err),
            Self::MalformedHeader(msg) => write!(f, "malformed packet header: {}", msg),
            Self::JsonError(err) => write!(f, "json parse error: {}", err),
        }
    }
}

impl std::error::Error for PacketError {}

/// A simulation datagram containing a unique identifier, sequence number,
/// timestamp, payload bytes, and payload SHA-256 verification hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packet {
    /// Unique identifier for this packet (e.g. UUID v4)
    pub id: String,
    /// Strictly increasing sequence number within the stream
    pub sequence: u64,
    /// Nanosecond timestamp when packet was generated
    pub timestamp_ns: u64,
    /// Raw payload bytes
    #[serde(with = "serde_bytes_base64")]
    pub payload: Vec<u8>,
    /// SHA-256 hex digest of the payload
    pub payload_hash: String,
}

mod serde_bytes_base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(hex, "{:02x}", b);
        }
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom("odd length hex string"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| serde::de::Error::custom(e.to_string()))
            })
            .collect()
    }
}

impl Packet {
    /// Constructs a new packet and computes its SHA-256 payload hash automatically.
    pub fn new(id: String, sequence: u64, timestamp_ns: u64, payload: Vec<u8>) -> Self {
        let payload_hash = sha256_hex(&payload);
        Self {
            id,
            sequence,
            timestamp_ns,
            payload,
            payload_hash,
        }
    }

    /// Verifies that the packet's `payload_hash` matches the SHA-256 hash of `payload`.
    #[must_use]
    pub fn verify_hash(&self) -> bool {
        sha256_hex(&self.payload) == self.payload_hash
    }

    /// Encodes this packet into a compact binary wire format.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let id_bytes = self.id.as_bytes();
        let hash_bytes = self.payload_hash.as_bytes();
        let total_size =
            4 + 8 + 8 + 2 + id_bytes.len() + 2 + hash_bytes.len() + 4 + self.payload.len();
        let mut buf = Vec::with_capacity(total_size);

        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(id_bytes);
        buf.extend_from_slice(&(hash_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(hash_bytes);
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Decodes a packet from bytes. Supports both the binary format and JSON.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PacketError> {
        if data.is_empty() {
            return Err(PacketError::PayloadTooShort);
        }

        if data[0] == b'{' {
            return serde_json::from_slice(data).map_err(|e| PacketError::JsonError(e.to_string()));
        }

        if data.len() < 4 + 8 + 8 + 2 + 2 + 4 {
            return Err(PacketError::PayloadTooShort);
        }

        if &data[0..4] != MAGIC {
            return Err(PacketError::InvalidMagic);
        }

        let mut offset = 4;
        let sequence = u64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .map_err(|_| PacketError::MalformedHeader("sequence"))?,
        );
        offset += 8;

        let timestamp_ns = u64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .map_err(|_| PacketError::MalformedHeader("timestamp"))?,
        );
        offset += 8;

        let id_len = u16::from_be_bytes(
            data[offset..offset + 2]
                .try_into()
                .map_err(|_| PacketError::MalformedHeader("id_len"))?,
        ) as usize;
        offset += 2;

        if data.len() < offset + id_len + 2 {
            return Err(PacketError::PayloadTooShort);
        }
        let id = std::str::from_utf8(&data[offset..offset + id_len])
            .map_err(|e| PacketError::InvalidUtf8(e.to_string()))?
            .to_string();
        offset += id_len;

        let hash_len = u16::from_be_bytes(
            data[offset..offset + 2]
                .try_into()
                .map_err(|_| PacketError::MalformedHeader("hash_len"))?,
        ) as usize;
        offset += 2;

        if data.len() < offset + hash_len + 4 {
            return Err(PacketError::PayloadTooShort);
        }
        let payload_hash = std::str::from_utf8(&data[offset..offset + hash_len])
            .map_err(|e| PacketError::InvalidUtf8(e.to_string()))?
            .to_string();
        offset += hash_len;

        let payload_len = u32::from_be_bytes(
            data[offset..offset + 4]
                .try_into()
                .map_err(|_| PacketError::MalformedHeader("payload_len"))?,
        ) as usize;
        offset += 4;

        if data.len() < offset + payload_len {
            return Err(PacketError::PayloadTooShort);
        }
        let payload = data[offset..offset + payload_len].to_vec();

        Ok(Self {
            id,
            sequence,
            timestamp_ns,
            payload,
            payload_hash,
        })
    }

    /// Serializes this packet to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserializes a packet from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_binary_roundtrip() {
        let pkt = Packet::new("pkt-001".to_string(), 42, 1000, b"hello world".to_vec());
        assert!(pkt.verify_hash());

        let bytes = pkt.to_bytes();
        let decoded = Packet::from_bytes(&bytes).expect("decode binary");
        assert_eq!(pkt, decoded);
        assert!(decoded.verify_hash());
    }

    #[test]
    fn test_packet_json_roundtrip() {
        let pkt = Packet::new("pkt-002".to_string(), 100, 2000, b"json payload".to_vec());
        let json = pkt.to_json().expect("to json");
        let decoded = Packet::from_bytes(json.as_bytes()).expect("decode json bytes");
        assert_eq!(pkt, decoded);
    }
}
