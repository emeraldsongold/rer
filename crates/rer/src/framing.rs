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
        write_frame_with_mode(&mut mavlink_buf, FramingMode::Mavlink, &mavlink_pkt).unwrap();
        assert_eq!(mavlink_buf, mavlink_pkt); // Raw packet bytes, no 4-byte prefix
        let mut mavlink_cursor = Cursor::new(mavlink_buf);
        let decoded_mavlink =
            read_frame_with_mode(&mut mavlink_cursor, FramingMode::Mavlink, 1024, &shutdown)
                .unwrap()
                .unwrap();
        assert_eq!(decoded_mavlink, mavlink_pkt);
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
    fn test_criterion1_mavlink1_and_mavlink2_fragmented_one_byte_reads() {
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
        let decoded_v1 = read_mavlink_frame(&mut chunked_v1, 1024, &shutdown)
            .expect("read chunked mavlink 1")
            .expect("payload");
        assert_eq!(decoded_v1, v1_pkt);

        // MAVLink 2 unsigned fragmented
        let v2_unsigned =
            make_test_mavlink2_packet(10, 2, 1, 300, false, b"fragmented mavlink 2 payload");
        let cursor_v2_u = Cursor::new(v2_unsigned.clone());
        let mut chunked_v2_u = ChunkedReader {
            inner: cursor_v2_u,
            chunk_size: 1,
        };
        let decoded_v2_u = read_mavlink_frame(&mut chunked_v2_u, 1024, &shutdown)
            .expect("read chunked mavlink 2 unsigned")
            .expect("payload");
        assert_eq!(decoded_v2_u, v2_unsigned);

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
        let decoded_v2_s = read_mavlink_frame(&mut chunked_v2_s, 1024, &shutdown)
            .expect("read chunked mavlink 2 signed")
            .expect("payload");
        assert_eq!(decoded_v2_s, v2_signed);
    }

    #[test]
    fn test_criterion2_concatenated_mavlink_frames_in_single_read_buffer() {
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

        let r1 = read_mavlink_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r2 = read_mavlink_frame(&mut cursor, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let r3 = read_mavlink_frame(&mut cursor, 1024, &shutdown).unwrap();

        assert_eq!(r1, p1);
        assert_eq!(r2, p2);
        assert!(r3.is_none());

        // Concatenated signed MAVLink 2 and unsigned MAVLink 2
        let ps1 = make_test_mavlink2_packet(10, 1, 1, 50, true, b"signed pkt");
        let ps2 = make_test_mavlink2_packet(11, 1, 1, 51, false, b"unsigned pkt");

        let mut stream_signed = Vec::new();
        stream_signed.extend_from_slice(&ps1);
        stream_signed.extend_from_slice(&ps2);

        let mut cursor2 = Cursor::new(stream_signed);
        let s1 = read_mavlink_frame(&mut cursor2, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let s2 = read_mavlink_frame(&mut cursor2, 1024, &shutdown)
            .unwrap()
            .unwrap();
        let s3 = read_mavlink_frame(&mut cursor2, 1024, &shutdown).unwrap();

        assert_eq!(s1, ps1);
        assert_eq!(s2, ps2);
        assert!(s3.is_none());
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
        let err_v1 = read_mavlink_frame(&mut cursor_v1, 50, &shutdown).unwrap_err();
        assert_eq!(err_v1.kind(), io::ErrorKind::InvalidData);
        assert!(err_v1.to_string().contains("exceeds maximum allowed"));

        // MAVLink 2 unsigned: payload length 100 -> total length 112. Max allowed 50.
        let v2_pkt = make_test_mavlink2_packet(1, 1, 1, 1, false, &[0xBB; 100]);
        let mut cursor_v2 = Cursor::new(v2_pkt);
        let err_v2 = read_mavlink_frame(&mut cursor_v2, 50, &shutdown).unwrap_err();
        assert_eq!(err_v2.kind(), io::ErrorKind::InvalidData);
        assert!(err_v2.to_string().contains("exceeds maximum allowed"));

        // MAVLink 2 signed: payload length 50 -> total length 75 (50 + 25). Max allowed 60.
        let v2_signed = make_test_mavlink2_packet(1, 1, 1, 1, true, &[0xCC; 50]);
        let mut cursor_v2_signed = Cursor::new(v2_signed);
        let err_v2_signed = read_mavlink_frame(&mut cursor_v2_signed, 60, &shutdown).unwrap_err();
        assert_eq!(err_v2_signed.kind(), io::ErrorKind::InvalidData);
        assert!(err_v2_signed
            .to_string()
            .contains("exceeds maximum allowed"));
    }

    #[test]
    fn test_criterion4_write_frame_with_mode_mavlink_raw_packet() {
        // Acceptance criterion: In crates/rer/src/framing.rs, writing a MAVLink frame
        // using write_frame_with_mode transmits raw packet bytes without prepending a 4-byte length prefix.
        let v1_pkt = make_test_mavlink1_packet(42, 5, 10, 15, b"telemetry raw");
        let mut out_v1 = Vec::new();
        write_frame_with_mode(&mut out_v1, FramingMode::Mavlink, &v1_pkt)
            .expect("write mavlink frame");
        assert_eq!(out_v1, v1_pkt);
        // Explicitly assert that no 4-byte big-endian length prefix was prepended
        assert_ne!(&out_v1[0..4], &(v1_pkt.len() as u32).to_be_bytes());
        assert_eq!(out_v1[0], MAVLINK_STX_V1);

        let v2_pkt = make_test_mavlink2_packet(99, 1, 1, 246, true, b"signed telemetry");
        let mut out_v2 = Vec::new();
        write_frame_with_mode(&mut out_v2, FramingMode::Mavlink, &v2_pkt)
            .expect("write mavlink frame");
        assert_eq!(out_v2, v2_pkt);
        assert_ne!(&out_v2[0..4], &(v2_pkt.len() as u32).to_be_bytes());
        assert_eq!(out_v2[0], MAVLINK_STX_V2);
    }

    #[test]
    fn test_mavlink_invalid_magic_returns_invalid_data() {
        let bad_packet = vec![0x42, 0x05, 0x00, 0x00, 0x00, 0x00];
        let mut cursor = Cursor::new(bad_packet);
        let shutdown = AtomicBool::new(false);
        let err = read_mavlink_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid MAVLink magic byte"));
    }

    #[test]
    fn test_mavlink_unexpected_eof_in_header() {
        // Only STX byte, no remaining header
        let partial = vec![MAVLINK_STX_V1, 0x05];
        let mut cursor = Cursor::new(partial);
        let shutdown = AtomicBool::new(false);
        let err = read_mavlink_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_mavlink_unexpected_eof_in_payload() {
        let full = make_test_mavlink1_packet(1, 1, 1, 1, b"promised payload bytes");
        // Truncate last 5 bytes
        let truncated = full[..full.len() - 5].to_vec();
        let mut cursor = Cursor::new(truncated);
        let shutdown = AtomicBool::new(false);
        let err = read_mavlink_frame(&mut cursor, 1024, &shutdown).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
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
}
