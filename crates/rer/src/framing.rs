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

/// Writes a complete length-prefixed frame to `writer`.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    let frame = encode_frame(payload);
    writer.write_all(&frame)
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
}
