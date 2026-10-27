//! Framing between TCP byte streams and datagrams (SPEC §5).
//!
//! TCP provides a continuous stream of bytes without inherent message boundaries.
//! To reliably convey discrete datagrams or packets over TCP, RER employs explicit
//! length-prefixed framing.
//!
//! ### Wire Format
//!
//! Each frame consists of a 4-byte big-endian unsigned 32-bit integer indicating
//! the payload length `N` in bytes, followed immediately by the `N` payload bytes:
//!
//! ```text
//! +---------------------------+------------------------------------+
//! | Length Prefix (4 bytes)   | Payload Bytes (N bytes)            |
//! | uint32 big-endian (N)     | [u8; N]                            |
//! +---------------------------+------------------------------------+
//! ```
//!
//! - **UDP-to-TCP**: When a UDP datagram is received, RER encapsulates it into a TCP
//!   frame with a 4-byte big-endian length prefix.
//! - **TCP-to-UDP**: RER reads the 4-byte length prefix from the TCP stream, validates
//!   that it does not exceed the configured `max_packet_size`, reads exactly `N` payload
//!   bytes, and transmits them as an individual UDP datagram preserving message boundaries.
//! - **TCP-to-TCP**: Frames read from an ingress TCP stream are forwarded with length
//!   framing intact to the egress TCP stream.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::mavlink::{
    MAVLINK_IFLAG_SIGNED, MAVLINK_STX_V1, MAVLINK_STX_V2, MAVLINK_V1_OVERHEAD,
    MAVLINK_V2_OVERHEAD_SIGNED, MAVLINK_V2_OVERHEAD_UNSIGNED,
};

/// Encodes a payload into a length-prefixed frame.
#[must_use]
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Reads exact number of bytes from `reader` into `buf`, interruptible by `shutdown`.
///
/// Returns:
/// - `Ok(true)` if all `buf.len()` bytes were read.
/// - `Ok(false)` if EOF occurred at `pos == 0`, or `shutdown` was signaled before any byte read.
/// - `Err(e)` if an I/O error occurred or unexpected EOF occurred mid-buffer.
pub fn read_exact_interruptible<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    shutdown: &AtomicBool,
) -> io::Result<bool> {
    let mut pos = 0;
    while pos < buf.len() {
        if shutdown.load(Ordering::Relaxed) && pos == 0 {
            return Ok(false);
        }
        match reader.read(&mut buf[pos..]) {
            Ok(0) => {
                if pos == 0 {
                    return Ok(false);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF while reading frame",
                    ));
                }
            }
            Ok(n) => pos += n,
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if pos == 0 {
                    return Err(io::Error::new(e.kind(), "read timeout"));
                }
                if shutdown.load(Ordering::Relaxed) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "shutdown signaled during frame read",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Reads a single length-prefixed frame from `reader`.
///
/// Validates that payload length does not exceed `max_frame_size`.
pub fn read_frame<R: Read>(
    reader: &mut R,
    max_frame_size: usize,
    shutdown: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let ok = read_exact_interruptible(reader, &mut len_buf, shutdown)?;
    if !ok {
        return Ok(None);
    }

    let payload_len = u32::from_be_bytes(len_buf) as usize;
    if payload_len > max_frame_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "frame payload length {} exceeds maximum allowed {}",
                payload_len, max_frame_size
            ),
        ));
    }

    let mut payload = vec![0u8; payload_len];
    let ok = read_exact_interruptible(reader, &mut payload, shutdown)?;
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stream closed before full frame payload was read",
        ));
    }

    Ok(Some(payload))
}

pub use crate::config::FramingMode;

/// Reads a single CCSDS Space Packet frame from `reader`.
///
/// In CCSDS length-based framing, the 6-byte Space Packet Primary Header contains
/// a 16-bit big-endian Packet Data Length field C at bytes 4..6.
/// The total packet length is `C + 7` bytes (6-byte header + `C + 1` data bytes).
///
/// Validates that total packet length does not exceed `max_frame_size`.
pub fn read_ccsds_frame<R: Read>(
    reader: &mut R,
    max_frame_size: usize,
    shutdown: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 6];
    let ok = read_exact_interruptible(reader, &mut header, shutdown)?;
    if !ok {
        return Ok(None);
    }

    let packet_data_length = u16::from_be_bytes([header[4], header[5]]) as usize;
    let total_packet_length = packet_data_length + 7;

    if total_packet_length > max_frame_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "CCSDS frame total length {} exceeds maximum allowed {}",
                total_packet_length, max_frame_size
            ),
        ));
    }

    let mut packet = vec![0u8; total_packet_length];
    packet[..6].copy_from_slice(&header);

    let ok = read_exact_interruptible(reader, &mut packet[6..], shutdown)?;
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stream closed before full CCSDS frame payload was read",
        ));
    }

    Ok(Some(packet))
}

/// Writes a CCSDS Space Packet frame to `writer`.
///
/// In CCSDS length-based framing, the packet is self-delimiting via its 6-byte
/// primary header data length field, so the raw Space Packet bytes are transmitted
/// directly without an additional length prefix.
pub fn write_ccsds_frame<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet)
}

/// Reads a single MAVLink 1 or MAVLink 2 frame from `reader`.
///
/// In MAVLink self-delimiting TCP framing (SPEC §14, §5):
/// - MAVLink 1 frame begins with magic byte `0xFE` (`MAVLINK_STX_V1`).
///   The payload length `L` is at byte offset 1.
///   Total packet length is `L + 8` bytes (6-byte header + `L` payload + 2 checksum bytes).
/// - MAVLink 2 frame begins with magic byte `0xFD` (`MAVLINK_STX_V2`).
///   The payload length `L` is at byte offset 1, and incompatibility flags are at byte offset 2.
///   If incompatibility flag bit 0 (`MAVLINK_IFLAG_SIGNED` = 0x01) is set, the packet includes
///   a 13-byte signature block, making the framing overhead 25 bytes (`L + 25` total).
///   Otherwise, framing overhead is 12 bytes (`L + 12` total: 10 header + `L` payload + 2 checksum).
///
/// Validates that total packet length does not exceed `max_frame_size`.
pub fn read_mavlink_frame<R: Read>(
    reader: &mut R,
    max_frame_size: usize,
    shutdown: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    let mut magic_buf = [0u8; 1];
    let ok = read_exact_interruptible(reader, &mut magic_buf, shutdown)?;
    if !ok {
        return Ok(None);
    }

    let magic = magic_buf[0];
    match magic {
        MAVLINK_STX_V1 => {
            let mut header_rest = [0u8; 5];
            let ok = read_exact_interruptible(reader, &mut header_rest, shutdown)?;
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed before full MAVLink 1 header was read",
                ));
            }

            let payload_len = header_rest[0] as usize;
            let total_packet_length = payload_len + MAVLINK_V1_OVERHEAD;

            if total_packet_length > max_frame_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "MAVLink 1 frame total length {} exceeds maximum allowed {}",
                        total_packet_length, max_frame_size
                    ),
                ));
            }

            let mut packet = vec![0u8; total_packet_length];
            packet[0] = magic;
            packet[1..6].copy_from_slice(&header_rest);

            let ok = read_exact_interruptible(reader, &mut packet[6..], shutdown)?;
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed before full MAVLink 1 frame payload was read",
                ));
            }

            Ok(Some(packet))
        }
        MAVLINK_STX_V2 => {
            let mut header_rest = [0u8; 9];
            let ok = read_exact_interruptible(reader, &mut header_rest, shutdown)?;
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed before full MAVLink 2 header was read",
                ));
            }

            let payload_len = header_rest[0] as usize;
            let incompat_flags = header_rest[1];
            let is_signed = (incompat_flags & MAVLINK_IFLAG_SIGNED) != 0;
            let overhead = if is_signed {
                MAVLINK_V2_OVERHEAD_SIGNED
            } else {
                MAVLINK_V2_OVERHEAD_UNSIGNED
            };
            let total_packet_length = payload_len + overhead;

            if total_packet_length > max_frame_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "MAVLink 2 frame total length {} exceeds maximum allowed {}",
                        total_packet_length, max_frame_size
                    ),
                ));
            }

            let mut packet = vec![0u8; total_packet_length];
            packet[0] = magic;
            packet[1..10].copy_from_slice(&header_rest);

            let ok = read_exact_interruptible(reader, &mut packet[10..], shutdown)?;
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed before full MAVLink 2 frame payload was read",
                ));
            }

            Ok(Some(packet))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid MAVLink magic byte: 0x{:02X} (expected 0xFE or 0xFD)",
                magic
            ),
        )),
    }
}

/// Writes a MAVLink frame to `writer`.
///
/// In MAVLink self-delimiting TCP framing, packets are self-delimiting via their STX byte
/// and header length fields, so the raw MAVLink packet bytes are transmitted directly
/// without prepending a 4-byte length prefix.
pub fn write_mavlink_frame<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet)
}

/// Reads a single MQTT packet frame from `reader`.
///
/// In MQTT TCP stream framing (OASIS MQTT 3.1.1 and 5.0, SPEC §5, §8, §14):
/// - The packet begins with a 1-byte fixed header containing the 4-bit Control Packet Type
///   and 4-bit flags. Packet type 0 is reserved/forbidden.
/// - The remaining length is encoded as a Variable Byte Integer (1 to 4 octets).
///   Each octet uses 7 bits for length data and the MSB (bit 7) as a continuation bit.
///   If the continuation bit is set on the 4th octet, the variable byte integer exceeds 4 octets
///   and is invalid.
/// - The remaining payload follows immediately for `remaining_length` octets.
///
/// Validates that declared remaining length and total packet length do not exceed `max_frame_size`.
/// Validates that variable byte integer does not exceed 4 octets.
pub fn read_mqtt_frame<R: Read>(
    reader: &mut R,
    max_frame_size: usize,
    shutdown: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    let mut byte1 = [0u8; 1];
    let ok = read_exact_interruptible(reader, &mut byte1, shutdown)?;
    if !ok {
        return Ok(None);
    }

    let packet_type = byte1[0] >> 4;
    if packet_type == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MQTT packet type: 0 is forbidden",
        ));
    }

    let mut multiplier: usize = 1;
    let mut remaining_length: usize = 0;
    let mut varint_bytes = Vec::with_capacity(4);

    loop {
        let mut b = [0u8; 1];
        let ok = read_exact_interruptible(reader, &mut b, shutdown)?;
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream closed before full MQTT variable byte integer was read",
            ));
        }
        let encoded_byte = b[0];
        varint_bytes.push(encoded_byte);

        remaining_length += ((encoded_byte & 0x7F) as usize) * multiplier;

        if (encoded_byte & 0x80) == 0 {
            break;
        }

        if varint_bytes.len() >= 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MQTT variable byte integer exceeds 4 octets",
            ));
        }

        multiplier *= 128;
    }

    let header_len = 1 + varint_bytes.len();
    let total_packet_length = header_len.saturating_add(remaining_length);

    if remaining_length > max_frame_size || total_packet_length > max_frame_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "MQTT frame remaining length {} (total length {}) exceeds maximum allowed {}",
                remaining_length, total_packet_length, max_frame_size
            ),
        ));
    }

    let mut packet = vec![0u8; total_packet_length];
    packet[0] = byte1[0];
    packet[1..header_len].copy_from_slice(&varint_bytes);

    let ok = read_exact_interruptible(reader, &mut packet[header_len..], shutdown)?;
    if !ok {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stream closed before full MQTT packet payload was read",
        ));
    }

    Ok(Some(packet))
}

/// Writes an MQTT packet frame to `writer`.
///
/// In MQTT TCP stream framing, packets are self-delimiting via their fixed header,
/// so the raw MQTT packet bytes are transmitted directly without prepending a 4-byte length prefix.
pub fn write_mqtt_frame<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    writer.write_all(packet)
}

/// KISS framing delimiter byte (Frame End).
pub const KISS_FEND: u8 = 0xC0;

/// KISS framing escape byte (Frame Escape).
pub const KISS_FESC: u8 = 0xDB;

/// KISS framing transposed frame end byte.
pub const KISS_TFEND: u8 = 0xDC;

/// KISS framing transposed frame escape byte.
pub const KISS_TFESC: u8 = 0xDD;

/// Encodes a payload into a KISS frame delimited by FEND bytes with byte escaping.
#[must_use]
pub fn encode_kiss_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 2);
    frame.push(KISS_FEND);
    for &b in payload {
        match b {
            KISS_FEND => {
                frame.push(KISS_FESC);
                frame.push(KISS_TFEND);
            }
            KISS_FESC => {
                frame.push(KISS_FESC);
                frame.push(KISS_TFESC);
            }
            other => frame.push(other),
        }
    }
    frame.push(KISS_FEND);
    frame
}

/// Reads a single KISS frame from `reader`.
///
/// In KISS TCP stream framing (SPEC §5, §8, §14):
/// - Frames are delimited by `FEND` (`0xC0`) bytes.
/// - Any leading or consecutive `FEND` bytes are discarded.
/// - The escape byte `FESC` (`0xDB`) followed by `TFEND` (`0xDC`) decodes to `0xC0`.
/// - The escape byte `FESC` (`0xDB`) followed by `TFESC` (`0xDD`) decodes to `0xDB`.
/// - An escape byte followed by any unexpected byte returns an [`io::ErrorKind::InvalidData`] error.
/// - Validates that unescaped frame length does not exceed `max_frame_size`.
pub fn read_kiss_frame<R: Read>(
    reader: &mut R,
    max_frame_size: usize,
    shutdown: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    let mut started = false;
    let mut frame = Vec::new();
    let mut b = [0u8; 1];

    while read_exact_interruptible(reader, &mut b, shutdown)? {
        let byte = b[0];
        if byte == KISS_FEND {
            if started {
                return Ok(Some(frame));
            }
            // Discard leading or consecutive FEND delimiter bytes
            continue;
        }

        started = true;
        let decoded = if byte == KISS_FESC {
            let mut esc_buf = [0u8; 1];
            let ok = read_exact_interruptible(reader, &mut esc_buf, shutdown)?;
            if !ok {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed unexpectedly after KISS escape byte",
                ));
            }
            match esc_buf[0] {
                KISS_TFEND => KISS_FEND,
                KISS_TFESC => KISS_FESC,
                unexpected => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected byte 0x{:02X} after KISS escape byte 0xDB",
                            unexpected
                        ),
                    ));
                }
            }
        } else {
            byte
        };

        if frame.len() >= max_frame_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "KISS frame unescaped length exceeds maximum allowed {}",
                    max_frame_size
                ),
            ));
        }
        frame.push(decoded);
    }

    if started {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "stream closed before full KISS frame was read",
        ))
    } else {
        Ok(None)
    }
}

/// Writes a single KISS frame to `writer`.
///
/// In KISS TCP stream framing, frames are delimited by `FEND` (`0xC0`) bytes
/// and internal `FEND` and `FESC` bytes are escaped.
pub fn write_kiss_frame<W: Write>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    let frame = encode_kiss_frame(packet);
    writer.write_all(&frame)
}

/// Reads a single frame from `reader` using the specified [`FramingMode`].
pub fn read_frame_with_mode<R: Read>(
    reader: &mut R,
    mode: FramingMode,
    max_frame_size: usize,
    shutdown: &AtomicBool,
) -> io::Result<Option<Vec<u8>>> {
    match mode {
        FramingMode::LengthPrefix => read_frame(reader, max_frame_size, shutdown),
        FramingMode::Ccsds => read_ccsds_frame(reader, max_frame_size, shutdown),
        FramingMode::Mavlink => read_mavlink_frame(reader, max_frame_size, shutdown),
        FramingMode::Mqtt => read_mqtt_frame(reader, max_frame_size, shutdown),
        FramingMode::Kiss => read_kiss_frame(reader, max_frame_size, shutdown),
    }
}

/// Writes a complete length-prefixed frame to `writer`.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let frame = encode_frame(payload);
    writer.write_all(&frame)
}

/// Writes a single frame to `writer` using the specified [`FramingMode`].
pub fn write_frame_with_mode<W: Write>(
    writer: &mut W,
    mode: FramingMode,
    payload: &[u8],
) -> io::Result<()> {
    match mode {
        FramingMode::LengthPrefix => write_frame(writer, payload),
        FramingMode::Ccsds => write_ccsds_frame(writer, payload),
        FramingMode::Mavlink => write_mavlink_frame(writer, payload),
        FramingMode::Mqtt => write_mqtt_frame(writer, payload),
        FramingMode::Kiss => write_kiss_frame(writer, payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_encode_and_read_single_frame() {
        let payload = b"hello tcp framing world".to_vec();
        let frame = encode_frame(&payload);
        assert_eq!(frame.len(), 4 + payload.len());
        assert_eq!(&frame[0..4], &(payload.len() as u32).to_be_bytes());

        let mut cursor = Cursor::new(frame);
        let shutdown = AtomicBool::new(false);
        let decoded = read_frame(&mut cursor, 1024, &shutdown)
            .expect("read frame")
            .expect("some frame");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_zero_byte_frame() {
        let payload = Vec::<u8>::new();
        let frame = encode_frame(&payload);
        assert_eq!(frame.len(), 4);

        let mut cursor = Cursor::new(frame);
        let shutdown = AtomicBool::new(false);
        let decoded = read_frame(&mut cursor, 1024, &shutdown)
            .expect("read frame")
            .expect("some frame");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_multiple_sequential_frames() {
        let mut stream_bytes = Vec::new();
        let p1 = b"first message".to_vec();
        let p2 = b"second message with more data".to_vec();
        let p3 = b"3".to_vec();

        stream_bytes.extend(encode_frame(&p1));
        stream_bytes.extend(encode_frame(&p2));
        stream_bytes.extend(encode_frame(&p3));

        let mut cursor = Cursor::new(stream_bytes);
        let shutdown = AtomicBool::new(false);

        let r1 = read_frame(&mut cursor, 1024, &shutdown).unwrap().unwrap();
        let r2 = read_frame(&mut cursor, 1024, &shutdown).unwrap().unwrap();
        let r3 = read_frame(&mut cursor, 1024, &shutdown).unwrap().unwrap();
        let r4 = read_frame(&mut cursor, 1024, &shutdown).unwrap();

        assert_eq!(r1, p1);
        assert_eq!(r2, p2);
        assert_eq!(r3, p3);
        assert!(r4.is_none());
    }

    #[test]
    fn test_oversized_frame_rejection() {
        let payload = vec![0xAB; 200];
        let frame = encode_frame(&payload);
        let mut cursor = Cursor::new(frame);
        let shutdown = AtomicBool::new(false);

        // Max frame size is 100, payload is 200
        let err = read_frame(&mut cursor, 100, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum allowed"));
    }

    #[test]
    fn test_unexpected_eof_in_header() {
        let partial_header = vec![0x00, 0x00]; // only 2 bytes instead of 4
        let mut cursor = Cursor::new(partial_header);
        let shutdown = AtomicBool::new(false);

        let err = read_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_unexpected_eof_in_payload() {
        let mut frame = 10u32.to_be_bytes().to_vec();
        frame.extend_from_slice(b"12345"); // only 5 bytes, promised 10
        let mut cursor = Cursor::new(frame);
        let shutdown = AtomicBool::new(false);

        let err = read_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Simulates chunked TCP reads (1 byte per read call).
    struct ChunkedReader<R> {
        inner: R,
        chunk_size: usize,
    }

    impl<R: Read> Read for ChunkedReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let limit = buf.len().min(self.chunk_size);
            self.inner.read(&mut buf[..limit])
        }
    }

    #[test]
    fn test_fragmented_tcp_chunks_defragmentation() {
        let payload = b"stream fragmentation should be handled transparently".to_vec();
        let frame = encode_frame(&payload);
        let cursor = Cursor::new(frame);
        let mut chunked = ChunkedReader {
            inner: cursor,
            chunk_size: 1, // Deliver exactly 1 byte per read() call
        };
        let shutdown = AtomicBool::new(false);

        let decoded = read_frame(&mut chunked, 1024, &shutdown)
            .expect("read chunked")
            .expect("payload");
        assert_eq!(decoded, payload);
    }

    fn make_test_ccsds_packet(apid: u16, seq: u16, payload_data: &[u8]) -> Vec<u8> {
        let payload_len = payload_data.len().max(1);
        let c = (payload_len - 1) as u16;
        let mut pkt = Vec::with_capacity(6 + payload_len);
        let word1: u16 = apid & 0x07FF;
        pkt.extend_from_slice(&word1.to_be_bytes());
        let word2: u16 = (3 << 14) | (seq & 0x3FFF);
        pkt.extend_from_slice(&word2.to_be_bytes());
        pkt.extend_from_slice(&c.to_be_bytes());
        pkt.extend_from_slice(payload_data);
        if payload_data.is_empty() {
            pkt.push(0x00);
        }
        pkt
    }

    #[test]
    fn test_ccsds_single_frame() {
        let pkt = make_test_ccsds_packet(42, 100, b"space packet payload");
        let mut cursor = Cursor::new(pkt.clone());
        let shutdown = AtomicBool::new(false);

        let decoded = read_ccsds_frame(&mut cursor, 1024, &shutdown)
            .expect("read frame")
            .expect("some frame");
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn test_ccsds_fragmented_tcp_chunks_defragmentation() {
        let pkt = make_test_ccsds_packet(101, 7, b"fragmented ccsds delivery byte-by-byte");
        let cursor = Cursor::new(pkt.clone());
        let mut chunked = ChunkedReader {
            inner: cursor,
            chunk_size: 1, // Deliver exactly 1 byte per read() call
        };
        let shutdown = AtomicBool::new(false);

        let decoded = read_ccsds_frame(&mut chunked, 1024, &shutdown)
            .expect("read chunked ccsds")
            .expect("payload");
        assert_eq!(decoded, pkt);
    }

    #[test]
    fn test_ccsds_three_concatenated_packets_in_single_read_buffer() {
        let p1 = make_test_ccsds_packet(10, 1, b"first space packet");
        let p2 = make_test_ccsds_packet(20, 2, b"second packet with different len");
        let p3 = make_test_ccsds_packet(30, 3, b"3");

        let mut stream_bytes = Vec::new();
        stream_bytes.extend_from_slice(&p1);
        stream_bytes.extend_from_slice(&p2);
        stream_bytes.extend_from_slice(&p3);

        let mut cursor = Cursor::new(stream_bytes);
        let shutdown = AtomicBool::new(false);

        let r1 = read_ccsds_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r2 = read_ccsds_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r3 = read_ccsds_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r4 = read_ccsds_frame(&mut cursor, 1024, &shutdown).unwrap();

        assert_eq!(r1, p1);
        assert_eq!(r2, p2);
        assert_eq!(r3, p3);
        assert!(r4.is_none());
    }

    #[test]
    fn test_ccsds_oversized_frame_rejection() {
        // Declared data length 200 -> total length 207 bytes
        let pkt = make_test_ccsds_packet(5, 1, &[0xAA; 200]);
        let mut cursor = Cursor::new(pkt);
        let shutdown = AtomicBool::new(false);

        // Limit is 100
        let err = read_ccsds_frame(&mut cursor, 100, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum allowed"));
    }

    #[test]
    fn test_ccsds_unexpected_eof_in_header() {
        let partial_header = vec![0x00, 0x01, 0x02]; // only 3 bytes instead of 6
        let mut cursor = Cursor::new(partial_header);
        let shutdown = AtomicBool::new(false);

        let err = read_ccsds_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_ccsds_unexpected_eof_in_payload() {
        let pkt = make_test_ccsds_packet(1, 1, b"0123456789");
        // Truncate payload
        let truncated = pkt[..pkt.len() - 3].to_vec();
        let mut cursor = Cursor::new(truncated);
        let shutdown = AtomicBool::new(false);

        let err = read_ccsds_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_read_and_write_frame_with_mode() {
        let shutdown = AtomicBool::new(false);

        // LengthPrefix mode
        let payload = b"hello length prefix".to_vec();
        let mut lp_buf = Vec::new();
        write_frame_with_mode(&mut lp_buf, FramingMode::LengthPrefix, &payload).unwrap();
        let mut lp_cursor = Cursor::new(lp_buf);
        let decoded =
            read_frame_with_mode(&mut lp_cursor, FramingMode::LengthPrefix, 1024, &shutdown)
                .unwrap()
                .unwrap();
        assert_eq!(decoded, payload);

        // Ccsds mode
        let ccsds_pkt = make_test_ccsds_packet(99, 1, b"hello ccsds mode");
        let mut ccsds_buf = Vec::new();
        write_frame_with_mode(&mut ccsds_buf, FramingMode::Ccsds, &ccsds_pkt).unwrap();
        let mut ccsds_cursor = Cursor::new(ccsds_buf);
        let decoded_ccsds =
            read_frame_with_mode(&mut ccsds_cursor, FramingMode::Ccsds, 1024, &shutdown)
                .unwrap()
                .unwrap();
        assert_eq!(decoded_ccsds, ccsds_pkt);

        // Mavlink mode
        let mavlink_pkt = make_test_mavlink1_packet(1, 10, 20, 30, b"hello mavlink mode");
        let mut mavlink_buf = Vec::new();
        assert!(
            write_frame_with_mode(&mut mavlink_buf, FramingMode::Mavlink, &mavlink_pkt).is_ok()
        );
        assert_eq!(mavlink_buf, mavlink_pkt); // Raw packet bytes, no 4-byte prefix
        let mut mavlink_cursor = Cursor::new(mavlink_buf);
        let decoded_mavlink =
            read_frame_with_mode(&mut mavlink_cursor, FramingMode::Mavlink, 1024, &shutdown);
        assert!(matches!(
            decoded_mavlink,
            Ok(Some(ref pkt)) if pkt == &mavlink_pkt
        ));
    }

    fn make_test_mavlink1_packet(
        seq: u8,
        sysid: u8,
        compid: u8,
        msgid: u8,
        payload_data: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(6 + payload_data.len() + 2);
        pkt.push(MAVLINK_STX_V1); // 0xFE
        pkt.push(payload_data.len() as u8);
        pkt.push(seq);
        pkt.push(sysid);
        pkt.push(compid);
        pkt.push(msgid);
        pkt.extend_from_slice(payload_data);
        pkt.push(0x12);
        pkt.push(0x34);
        pkt
    }

    fn make_test_mavlink2_packet(
        seq: u8,
        sysid: u8,
        compid: u8,
        msgid: u32,
        is_signed: bool,
        payload_data: &[u8],
    ) -> Vec<u8> {
        let incompat_flags = if is_signed { MAVLINK_IFLAG_SIGNED } else { 0 };
        let overhead = if is_signed {
            MAVLINK_V2_OVERHEAD_SIGNED
        } else {
            MAVLINK_V2_OVERHEAD_UNSIGNED
        };
        let mut pkt = Vec::with_capacity(overhead + payload_data.len());
        pkt.push(MAVLINK_STX_V2); // 0xFD
        pkt.push(payload_data.len() as u8);
        pkt.push(incompat_flags);
        pkt.push(0x00); // compat_flags
        pkt.push(seq);
        pkt.push(sysid);
        pkt.push(compid);
        pkt.push((msgid & 0xFF) as u8);
        pkt.push(((msgid >> 8) & 0xFF) as u8);
        pkt.push(((msgid >> 16) & 0xFF) as u8);
        pkt.extend_from_slice(payload_data);
        pkt.push(0xAB);
        pkt.push(0xCD);
        if is_signed {
            pkt.extend_from_slice(&[0x55; 13]);
        }
        pkt
    }

    #[test]
    fn test_criterion1_mavlink1_and_mavlink2_fragmented_one_byte_reads() -> io::Result<()> {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading from a TCP stream
        // delivering a MAVLink 1 or MAVLink 2 frame fragmented across multiple 1-byte reads
        // reassembles the complete frame matching the original transmitted bytes.
        let shutdown = AtomicBool::new(false);

        // MAVLink 1 fragmented
        let v1_pkt = make_test_mavlink1_packet(5, 1, 1, 42, b"fragmented mavlink 1 payload");
        let cursor_v1 = Cursor::new(v1_pkt.clone());
        let mut chunked_v1 = ChunkedReader {
            inner: cursor_v1,
            chunk_size: 1, // Deliver exactly 1 byte per read() call
        };
        let decoded_v1 = read_mavlink_frame(&mut chunked_v1, 1024, &shutdown)?;
        assert_eq!(decoded_v1.as_deref(), Some(v1_pkt.as_slice()));

        // MAVLink 2 unsigned fragmented
        let v2_unsigned =
            make_test_mavlink2_packet(10, 2, 1, 300, false, b"fragmented mavlink 2 payload");
        let cursor_v2_u = Cursor::new(v2_unsigned.clone());
        let mut chunked_v2_u = ChunkedReader {
            inner: cursor_v2_u,
            chunk_size: 1,
        };
        let decoded_v2_u = read_mavlink_frame(&mut chunked_v2_u, 1024, &shutdown)?;
        assert_eq!(decoded_v2_u.as_deref(), Some(v2_unsigned.as_slice()));

        // MAVLink 2 signed fragmented
        let v2_signed = make_test_mavlink2_packet(
            15,
            3,
            2,
            65535,
            true,
            b"fragmented signed mavlink 2 telemetry packet with full signature",
        );
        let cursor_v2_s = Cursor::new(v2_signed.clone());
        let mut chunked_v2_s = ChunkedReader {
            inner: cursor_v2_s,
            chunk_size: 1,
        };
        let decoded_v2_s = read_mavlink_frame(&mut chunked_v2_s, 1024, &shutdown)?;
        assert_eq!(decoded_v2_s.as_deref(), Some(v2_signed.as_slice()));
        Ok(())
    }

    #[test]
    fn test_criterion2_concatenated_mavlink_frames_in_single_read_buffer() -> io::Result<()> {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading from a TCP stream
        // delivering two concatenated MAVLink frames in a single read buffer yields
        // the two frames individually at their calculated frame length boundaries.
        let p1 = make_test_mavlink1_packet(1, 10, 1, 0, b"mavlink1 first");
        let p2 =
            make_test_mavlink2_packet(2, 20, 2, 1000, false, b"mavlink2 second with different len");

        let mut stream_bytes = Vec::new();
        stream_bytes.extend_from_slice(&p1);
        stream_bytes.extend_from_slice(&p2);

        let mut cursor = Cursor::new(stream_bytes);
        let shutdown = AtomicBool::new(false);

        let r1 = read_mavlink_frame(&mut cursor, 1024, &shutdown)?;
        let r2 = read_mavlink_frame(&mut cursor, 1024, &shutdown)?;
        let r3 = read_mavlink_frame(&mut cursor, 1024, &shutdown)?;

        assert_eq!(r1.as_deref(), Some(p1.as_slice()));
        assert_eq!(r2.as_deref(), Some(p2.as_slice()));
        assert!(r3.is_none());

        // Concatenated signed MAVLink 2 and unsigned MAVLink 2
        let ps1 = make_test_mavlink2_packet(10, 1, 1, 50, true, b"signed pkt");
        let ps2 = make_test_mavlink2_packet(11, 1, 1, 51, false, b"unsigned pkt");

        let mut stream_signed = Vec::new();
        stream_signed.extend_from_slice(&ps1);
        stream_signed.extend_from_slice(&ps2);

        let mut cursor2 = Cursor::new(stream_signed);
        let s1 = read_mavlink_frame(&mut cursor2, 1024, &shutdown)?;
        let s2 = read_mavlink_frame(&mut cursor2, 1024, &shutdown)?;
        let s3 = read_mavlink_frame(&mut cursor2, 1024, &shutdown)?;

        assert_eq!(s1.as_deref(), Some(ps1.as_slice()));
        assert_eq!(s2.as_deref(), Some(ps2.as_slice()));
        assert!(s3.is_none());
        Ok(())
    }

    #[test]
    fn test_criterion3_oversized_mavlink_frame_rejection() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading a MAVLink TCP frame
        // declaring a length that exceeds the configured maximum frame size returns an
        // invalid data error without panicking.
        let shutdown = AtomicBool::new(false);

        // MAVLink 1: payload length 100 -> total length 108. Max allowed 50.
        let v1_pkt = make_test_mavlink1_packet(1, 1, 1, 1, &[0xAA; 100]);
        let mut cursor_v1 = Cursor::new(v1_pkt);
        assert!(matches!(
            read_mavlink_frame(&mut cursor_v1, 50, &shutdown),
            Err(ref e) if e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("exceeds maximum allowed")
        ));

        // MAVLink 2 unsigned: payload length 100 -> total length 112. Max allowed 50.
        let v2_pkt = make_test_mavlink2_packet(1, 1, 1, 1, false, &[0xBB; 100]);
        let mut cursor_v2 = Cursor::new(v2_pkt);
        assert!(matches!(
            read_mavlink_frame(&mut cursor_v2, 50, &shutdown),
            Err(ref e) if e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("exceeds maximum allowed")
        ));

        // MAVLink 2 signed: payload length 50 -> total length 75 (50 + 25). Max allowed 60.
        let v2_signed = make_test_mavlink2_packet(1, 1, 1, 1, true, &[0xCC; 50]);
        let mut cursor_v2_signed = Cursor::new(v2_signed);
        assert!(matches!(
            read_mavlink_frame(&mut cursor_v2_signed, 60, &shutdown),
            Err(ref e) if e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("exceeds maximum allowed")
        ));
    }

    #[test]
    fn test_criterion4_write_frame_with_mode_mavlink_raw_packet() -> io::Result<()> {
        // Acceptance criterion: In crates/rer/src/framing.rs, writing a MAVLink frame
        // using write_frame_with_mode transmits raw packet bytes without prepending a 4-byte length prefix.
        let v1_pkt = make_test_mavlink1_packet(42, 5, 10, 15, b"telemetry raw");
        let mut out_v1 = Vec::new();
        write_frame_with_mode(&mut out_v1, FramingMode::Mavlink, &v1_pkt)?;
        assert_eq!(out_v1, v1_pkt);
        // Explicitly assert that no 4-byte big-endian length prefix was prepended
        assert_ne!(&out_v1[0..4], &(v1_pkt.len() as u32).to_be_bytes());
        assert_eq!(out_v1[0], MAVLINK_STX_V1);

        let v2_pkt = make_test_mavlink2_packet(99, 1, 1, 246, true, b"signed telemetry");
        let mut out_v2 = Vec::new();
        write_frame_with_mode(&mut out_v2, FramingMode::Mavlink, &v2_pkt)?;
        assert_eq!(out_v2, v2_pkt);
        assert_ne!(&out_v2[0..4], &(v2_pkt.len() as u32).to_be_bytes());
        assert_eq!(out_v2[0], MAVLINK_STX_V2);
        Ok(())
    }

    #[test]
    fn test_mavlink_invalid_magic_returns_invalid_data() {
        let bad_packet = vec![0x42, 0x05, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = Cursor::new(bad_packet);
        let shutdown = AtomicBool::new(false);
        assert!(matches!(
            read_mavlink_frame(&mut cursor, 1024, &shutdown),
            Err(ref e) if e.kind() == io::ErrorKind::InvalidData && e.to_string().contains("invalid MAVLink magic byte")
        ));
    }

    #[test]
    fn test_mavlink_unexpected_eof_in_header() {
        // Only STX byte, no remaining header
        let partial = vec![MAVLINK_STX_V1, 0x05];
        let mut cursor = Cursor::new(partial);
        let shutdown = AtomicBool::new(false);
        assert!(matches!(
            read_mavlink_frame(&mut cursor, 1024, &shutdown),
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn test_mavlink_unexpected_eof_in_payload() {
        let full = make_test_mavlink1_packet(1, 1, 1, 1, b"promised payload bytes");
        // Truncate last 5 bytes
        let truncated = full[..full.len() - 5].to_vec();
        let mut cursor = Cursor::new(truncated);
        let shutdown = AtomicBool::new(false);
        assert!(matches!(
            read_mavlink_frame(&mut cursor, 1024, &shutdown),
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    fn make_test_mqtt_packet(packet_type: u8, flags: u8, payload_data: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.push((packet_type << 4) | (flags & 0x0F));
        let mut varint = [0u8; 4];
        let n = crate::mqtt::encode_variable_byte_integer(payload_data.len(), &mut varint).unwrap();
        pkt.extend_from_slice(&varint[..n]);
        pkt.extend_from_slice(payload_data);
        pkt
    }

    #[test]
    fn test_criterion1_mqtt_fragmented_one_byte_reads() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading from a TCP stream
        // delivering an MQTT packet fragmented across 1-byte reads reassembles the
        // complete packet matching the transmitted bytes.
        let shutdown = AtomicBool::new(false);

        // 1. Single-byte varint MQTT PUBLISH packet
        let pkt1 =
            make_test_mqtt_packet(3, 0, b"fragmented mqtt publish packet across 1-byte reads");
        let cursor1 = Cursor::new(pkt1.clone());
        let mut chunked1 = ChunkedReader {
            inner: cursor1,
            chunk_size: 1, // Deliver exactly 1 byte per read()
        };
        let decoded1 = read_mqtt_frame(&mut chunked1, 1024, &shutdown)
            .expect("read chunked mqtt packet")
            .expect("payload");
        assert_eq!(decoded1, pkt1);

        // 2. Multi-byte varint MQTT PUBLISH packet (payload > 127 bytes -> 2-byte varint)
        let large_payload = vec![0x42; 300];
        let pkt2 = make_test_mqtt_packet(3, 0, &large_payload);
        assert!(pkt2.len() > 300);
        let cursor2 = Cursor::new(pkt2.clone());
        let mut chunked2 = ChunkedReader {
            inner: cursor2,
            chunk_size: 1,
        };
        let decoded2 = read_mqtt_frame(&mut chunked2, 1024, &shutdown)
            .expect("read chunked multibyte varint mqtt packet")
            .expect("payload");
        assert_eq!(decoded2, pkt2);

        // 3. 2-byte PINGREQ packet ([0xC0, 0x00]) fragmented 1 byte at a time
        let pingreq = vec![0xC0, 0x00];
        let cursor3 = Cursor::new(pingreq.clone());
        let mut chunked3 = ChunkedReader {
            inner: cursor3,
            chunk_size: 1,
        };
        let decoded3 = read_mqtt_frame(&mut chunked3, 1024, &shutdown)
            .expect("read chunked pingreq")
            .expect("payload");
        assert_eq!(decoded3, pingreq);
    }

    #[test]
    fn test_criterion2_concatenated_mqtt_packets_in_single_read_buffer() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading from a TCP stream
        // delivering two concatenated MQTT packets in a single read buffer yields
        // the two packets individually at their calculated remaining length boundaries.
        let p1 = make_test_mqtt_packet(3, 0, b"first mqtt publish packet");
        let p2 = vec![0xC0, 0x00]; // PINGREQ packet
        let p3 = make_test_mqtt_packet(1, 0, b"third mqtt connect packet");

        let mut stream_bytes = Vec::new();
        stream_bytes.extend_from_slice(&p1);
        stream_bytes.extend_from_slice(&p2);
        stream_bytes.extend_from_slice(&p3);

        let mut cursor = Cursor::new(stream_bytes);
        let shutdown = AtomicBool::new(false);

        let r1 = read_mqtt_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r2 = read_mqtt_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r3 = read_mqtt_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r4 = read_mqtt_frame(&mut cursor, 1024, &shutdown).unwrap();

        assert_eq!(r1, p1);
        assert_eq!(r2, p2);
        assert_eq!(r3, p3);
        assert!(r4.is_none());
    }

    #[test]
    fn test_criterion3_oversized_mqtt_frame_rejection() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading an MQTT TCP frame
        // declaring a remaining length that exceeds the configured maximum frame size
        // returns an invalid data error without allocating the declared frame size.
        let shutdown = AtomicBool::new(false);

        // Packet with declared remaining length 200, but max frame size is 100
        let payload = vec![0xEE; 200];
        let pkt = make_test_mqtt_packet(3, 0, &payload);
        let mut cursor = Cursor::new(pkt);
        let err = read_mqtt_frame(&mut cursor, 100, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum allowed"));
        assert!(err.to_string().contains("remaining length"));

        // Frame declaring huge remaining length (e.g. 50 MB) with small stream buffer
        // Must return invalid data error immediately without allocating 50 MB
        let mut huge_pkt = Vec::new();
        huge_pkt.push(0x30); // PUBLISH
        let mut varint = [0u8; 4];
        let n = crate::mqtt::encode_variable_byte_integer(50_000_000, &mut varint).unwrap();
        huge_pkt.extend_from_slice(&varint[..n]);
        // Cursor only has header, not 50 MB
        let mut huge_cursor = Cursor::new(huge_pkt);
        let err_huge = read_mqtt_frame(&mut huge_cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err_huge.kind(), io::ErrorKind::InvalidData);
        assert!(err_huge.to_string().contains("exceeds maximum allowed"));

        // Also verify via read_frame_with_mode
        let pkt_mode = make_test_mqtt_packet(3, 0, &[0xAA; 150]);
        let mut cursor_mode = Cursor::new(pkt_mode);
        let res_mode = read_frame_with_mode(&mut cursor_mode, FramingMode::Mqtt, 80, &shutdown);
        assert!(res_mode.is_err());
        assert_eq!(res_mode.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_criterion4_mqtt_varint_exceeding_four_octets_returns_invalid_data() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading an MQTT frame
        // from a TCP stream with a variable byte integer exceeding 4 octets returns
        // an invalid data error and terminates the stream.
        let shutdown = AtomicBool::new(false);

        // 5-byte varint: 4 bytes with continuation bit set (0x80) followed by 5th byte
        let bad_varint_packet = vec![0x30, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00];
        let mut cursor = Cursor::new(bad_varint_packet);
        let err = read_mqtt_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds 4 octets"));

        // Also test via read_frame_with_mode
        let bad_varint2 = vec![0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        let mut cursor2 = Cursor::new(bad_varint2);
        let err2 =
            read_frame_with_mode(&mut cursor2, FramingMode::Mqtt, 1024, &shutdown).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidData);
        assert!(err2.to_string().contains("exceeds 4 octets"));
    }

    #[test]
    fn test_criterion5_write_frame_with_mode_mqtt_raw_packet() {
        // Acceptance criterion: In crates/rer/src/framing.rs, writing an MQTT packet
        // using write_frame_with_mode transmits raw packet bytes without prepending a 4-byte length prefix.
        let payload = b"mqtt raw packet payload";
        let pkt = make_test_mqtt_packet(3, 0, payload);

        let mut out = Vec::new();
        write_frame_with_mode(&mut out, FramingMode::Mqtt, &pkt).expect("write mqtt frame");

        // Exactly matches raw packet bytes
        assert_eq!(out, pkt);
        assert_eq!(out.len(), pkt.len());
        // Verify no 4-byte big-endian length prefix was prepended
        assert_ne!(&out[0..4], &(pkt.len() as u32).to_be_bytes());
        assert_eq!(out[0], pkt[0]);

        // Direct write_mqtt_frame helper
        let mut out_direct = Vec::new();
        write_mqtt_frame(&mut out_direct, &pkt).expect("write_mqtt_frame");
        assert_eq!(out_direct, pkt);
    }

    #[test]
    fn test_mqtt_invalid_packet_type_zero() {
        let bad_packet = vec![0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut cursor = Cursor::new(bad_packet);
        let shutdown = AtomicBool::new(false);
        let err = read_mqtt_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("0 is forbidden"));
    }

    #[test]
    fn test_mqtt_unexpected_eof_in_varint() {
        // First byte is PUBLISH, but continuation bit is set and stream ends
        let truncated = vec![0x30, 0x80];
        let mut cursor = Cursor::new(truncated);
        let shutdown = AtomicBool::new(false);
        let err = read_mqtt_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_mqtt_unexpected_eof_in_payload() {
        let full = make_test_mqtt_packet(3, 0, b"payload that will be truncated");
        let truncated = full[..full.len() - 5].to_vec();
        let mut cursor = Cursor::new(truncated);
        let shutdown = AtomicBool::new(false);
        let err = read_mqtt_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_criterion1_kiss_fragmented_one_byte_reads() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading from a TCP stream
        // delivering a KISS frame fragmented across multiple 1-byte reads reassembles the
        // complete unescaped frame matching the original transmitted payload bytes.
        let shutdown = AtomicBool::new(false);

        // 1. Unescaped payload
        let payload1 = b"\x00hello kiss packet radio world".to_vec();
        let wire1 = encode_kiss_frame(&payload1);
        let cursor1 = Cursor::new(wire1);
        let mut chunked1 = ChunkedReader {
            inner: cursor1,
            chunk_size: 1, // Deliver 1 byte per read()
        };
        let decoded1 = read_kiss_frame(&mut chunked1, 1024, &shutdown)
            .expect("read chunked kiss frame")
            .expect("some frame");
        assert_eq!(decoded1, payload1);

        // 2. Payload containing characters requiring escaping (FEND 0xC0 and FESC 0xDB)
        let payload2 = vec![0x00, 0xC0, 0x11, 0xDB, 0x22, 0xC0, 0xDB];
        let wire2 = encode_kiss_frame(&payload2);
        let cursor2 = Cursor::new(wire2);
        let mut chunked2 = ChunkedReader {
            inner: cursor2,
            chunk_size: 1,
        };
        let decoded2 = read_frame_with_mode(&mut chunked2, FramingMode::Kiss, 1024, &shutdown)
            .expect("read chunked kiss frame with mode")
            .expect("some frame");
        assert_eq!(decoded2, payload2);
    }

    #[test]
    fn test_criterion2_concatenated_kiss_frames_in_single_read_buffer() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading from a TCP stream
        // delivering two concatenated KISS frames separated by FEND delimiter byte 0xC0
        // in a single read buffer yields the two frames individually.
        let shutdown = AtomicBool::new(false);

        let frame1 = vec![0x00, 0x01, 0x02, 0x03];
        let frame2 = vec![0x00, 0xAA, 0xBB, 0xCC, 0xDD];

        // Frame 1 followed by FEND (0xC0), followed directly by Frame 2, ending with FEND
        // Single FEND separator between frame1 and frame2
        let mut stream_bytes = Vec::new();
        stream_bytes.push(KISS_FEND);
        stream_bytes.extend_from_slice(&frame1);
        stream_bytes.push(KISS_FEND); // Delimiter ending frame 1 and separating from frame 2
        stream_bytes.extend_from_slice(&frame2);
        stream_bytes.push(KISS_FEND);

        let mut cursor = Cursor::new(stream_bytes);
        let r1 = read_kiss_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .expect("frame 1");
        let r2 = read_kiss_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .expect("frame 2");
        let r3 = read_kiss_frame(&mut cursor, 1024, &shutdown).unwrap();

        assert_eq!(r1, frame1);
        assert_eq!(r2, frame2);
        assert!(r3.is_none());

        // Also test when both frames have their own leading and trailing FENDs
        let mut stream_bytes2 = Vec::new();
        stream_bytes2.extend_from_slice(&encode_kiss_frame(&frame1));
        stream_bytes2.extend_from_slice(&encode_kiss_frame(&frame2));

        let mut cursor2 = Cursor::new(stream_bytes2);
        let r1_2 = read_frame_with_mode(&mut cursor2, FramingMode::Kiss, 1024, &shutdown)
            .unwrap()
            .expect("frame 1");
        let r2_2 = read_frame_with_mode(&mut cursor2, FramingMode::Kiss, 1024, &shutdown)
            .unwrap()
            .expect("frame 2");
        let r3_2 = read_frame_with_mode(&mut cursor2, FramingMode::Kiss, 1024, &shutdown).unwrap();

        assert_eq!(r1_2, frame1);
        assert_eq!(r2_2, frame2);
        assert!(r3_2.is_none());
    }

    #[test]
    fn test_criterion3_kiss_escape_sequences_decode() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading from a TCP stream
        // delivering an escaped sequence of 0xDB followed by 0xDC decodes byte 0xC0,
        // and 0xDB followed by 0xDD decodes byte 0xDB.
        let shutdown = AtomicBool::new(false);

        // 1. [0xDB, 0xDC] decodes to 0xC0
        let raw1 = vec![KISS_FEND, 0x00, 0xDB, 0xDC, 0x01, KISS_FEND];
        let mut c1 = Cursor::new(raw1);
        let res1 = read_kiss_frame(&mut c1, 1024, &shutdown)
            .unwrap()
            .expect("frame");
        assert_eq!(res1, vec![0x00, 0xC0, 0x01]);

        // 2. [0xDB, 0xDD] decodes to 0xDB
        let raw2 = vec![KISS_FEND, 0x00, 0xDB, 0xDD, 0x02, KISS_FEND];
        let mut c2 = Cursor::new(raw2);
        let res2 = read_kiss_frame(&mut c2, 1024, &shutdown)
            .unwrap()
            .expect("frame");
        assert_eq!(res2, vec![0x00, 0xDB, 0x02]);

        // 3. Combined in a single frame
        let raw3 = vec![
            KISS_FEND, 0x00, 0xDB, 0xDC, 0xAA, 0xDB, 0xDD, 0xBB, KISS_FEND,
        ];
        let mut c3 = Cursor::new(raw3);
        let res3 = read_kiss_frame(&mut c3, 1024, &shutdown)
            .unwrap()
            .expect("frame");
        assert_eq!(res3, vec![0x00, 0xC0, 0xAA, 0xDB, 0xBB]);
    }

    #[test]
    fn test_criterion4_kiss_unexpected_escape_byte_returns_invalid_data() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading a KISS frame
        // containing escape byte 0xDB followed by an unexpected byte returns
        // an io::ErrorKind::InvalidData error.
        let shutdown = AtomicBool::new(false);

        // 0xDB followed by 0x42
        let bad1 = vec![KISS_FEND, 0x00, 0xDB, 0x42, KISS_FEND];
        let mut c1 = Cursor::new(bad1);
        let err1 = read_kiss_frame(&mut c1, 1024, &shutdown).unwrap_err();
        assert_eq!(err1.kind(), io::ErrorKind::InvalidData);
        assert!(err1.to_string().contains("unexpected byte"));

        // 0xDB followed by 0x00
        let bad2 = vec![KISS_FEND, 0x00, 0xDB, 0x00, KISS_FEND];
        let mut c2 = Cursor::new(bad2);
        let err2 = read_kiss_frame(&mut c2, 1024, &shutdown).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidData);

        // 0xDB followed immediately by FEND (0xC0)
        let bad3 = vec![KISS_FEND, 0x00, 0xDB, KISS_FEND];
        let mut c3 = Cursor::new(bad3);
        let err3 = read_kiss_frame(&mut c3, 1024, &shutdown).unwrap_err();
        assert_eq!(err3.kind(), io::ErrorKind::InvalidData);

        // Also test via read_frame_with_mode
        let bad4 = vec![KISS_FEND, 0xDB, 0xFF, KISS_FEND];
        let mut c4 = Cursor::new(bad4);
        let err4 = read_frame_with_mode(&mut c4, FramingMode::Kiss, 1024, &shutdown).unwrap_err();
        assert_eq!(err4.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_criterion5_oversized_kiss_frame_rejection() {
        // Acceptance criterion: In crates/rer/src/framing.rs, reading a KISS frame
        // whose unescaped length exceeds the configured max_frame_size returns
        // an io::ErrorKind::InvalidData error.
        let shutdown = AtomicBool::new(false);

        // Frame with unescaped length 6, but max_frame_size is 5
        let oversized = vec![KISS_FEND, 1, 2, 3, 4, 5, 6, KISS_FEND];
        let mut c1 = Cursor::new(oversized);
        let err1 = read_kiss_frame(&mut c1, 5, &shutdown).unwrap_err();
        assert_eq!(err1.kind(), io::ErrorKind::InvalidData);
        assert!(err1.to_string().contains("exceeds maximum allowed"));

        // Escaped frame: on wire it is 8 bytes, unescapes to 6 bytes, max_frame_size is 5
        let raw_escaped = vec![KISS_FEND, 1, 2, 3, 4, 5, 0xDB, 0xDC, KISS_FEND];
        let mut c2 = Cursor::new(raw_escaped);
        let err2 = read_kiss_frame(&mut c2, 5, &shutdown).unwrap_err();
        assert_eq!(err2.kind(), io::ErrorKind::InvalidData);

        // Frame with exact max_frame_size (5) should succeed
        let exact = vec![KISS_FEND, 1, 2, 3, 4, 5, KISS_FEND];
        let mut c3 = Cursor::new(exact);
        let res3 = read_kiss_frame(&mut c3, 5, &shutdown).unwrap();
        assert_eq!(res3, Some(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn test_kiss_write_frame_and_encoding() {
        let payload = vec![0x00, 0xC0, 0x11, 0xDB, 0x22];
        let wire = encode_kiss_frame(&payload);
        assert_eq!(wire[0], KISS_FEND);
        assert_eq!(*wire.last().unwrap(), KISS_FEND);
        // 0xC0 escaped to [0xDB, 0xDC]
        assert_eq!(&wire[2..4], &[0xDB, 0xDC]);
        // 0xDB escaped to [0xDB, 0xDD]
        assert_eq!(&wire[5..7], &[0xDB, 0xDD]);

        let mut out = Vec::new();
        write_kiss_frame(&mut out, &payload).unwrap();
        assert_eq!(out, wire);

        let mut out_mode = Vec::new();
        write_frame_with_mode(&mut out_mode, FramingMode::Kiss, &payload).unwrap();
        assert_eq!(out_mode, wire);
    }

    #[test]
    fn test_kiss_eof_and_empty_handling() {
        let shutdown = AtomicBool::new(false);

        // Empty stream
        let mut c1 = Cursor::new(Vec::new());
        assert_eq!(read_kiss_frame(&mut c1, 1024, &shutdown).unwrap(), None);

        // Stream with only FEND bytes
        let mut c2 = Cursor::new(vec![KISS_FEND, KISS_FEND, KISS_FEND]);
        assert_eq!(read_kiss_frame(&mut c2, 1024, &shutdown).unwrap(), None);

        // Truncated frame (EOF before closing FEND)
        let mut c3 = Cursor::new(vec![KISS_FEND, 0x00, 0x11, 0x22]);
        let err3 = read_kiss_frame(&mut c3, 1024, &shutdown).unwrap_err();
        assert_eq!(err3.kind(), io::ErrorKind::UnexpectedEof);

        // Truncated escape (EOF after 0xDB)
        let mut c4 = Cursor::new(vec![KISS_FEND, 0x00, 0xDB]);
        let err4 = read_kiss_frame(&mut c4, 1024, &shutdown).unwrap_err();
        assert_eq!(err4.kind(), io::ErrorKind::UnexpectedEof);
    }
}
