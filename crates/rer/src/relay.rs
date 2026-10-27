use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ax25::{parse_ax25_frame, Ax25Frame};
use crate::bpv7::{evaluate_bundle_header, BundleParseStatus};
use crate::ccsds::{parse_and_validate_ccsds_packet, CcsdsParseError, CcsdsSequenceTracker};
use crate::config::{
    Bpv7InspectionConfig, CcsdsConfig, Config, ConnectionMode, DropPolicy, EndpointConfig,
    FramingMode, InstanceConfig, KissConfig, LtpInspectionConfig, MavlinkConfig, MqttConfig,
    OperationalMode, SrtInspectionConfig, StreamConfig, TransportType,
};
use crate::diagnostics::{
    kiss_command_name, Ax25Metadata, BundleInspection, DiagnosticBuffer, DiagnosticEvent,
    DiagnosticStage, DiagnosticTestState, KissInspection, KissMetadata, LtpInspection,
    MavlinkInspection, MavlinkMetadata, MqttInspection, MqttMetadata, SequenceState,
    SequenceTracker, SequenceTrackingEvent, SrtInspection,
};
use crate::framing;
use crate::ltp::{evaluate_segment_header, LtpParseStatus, SegmentType};
use crate::mavlink::{
    parse_mavlink_header, MavlinkHeader, MavlinkParseError, MavlinkParseStatus,
    MavlinkSequenceTracker,
};
use crate::mqtt::{
    parse_mqtt_fixed_header, parse_mqtt_fixed_header_relaxed, MqttFixedHeader, MqttPacketType,
    MqttParseError, MqttParseStatus,
};
use crate::srt::{evaluate_srt_header, SrtParseStatus};

/// Default maximum queue size (packets) when not explicitly configured.
pub const DEFAULT_MAX_QUEUE_SIZE: usize = 1024;

/// Default maximum packet size (bytes) when not explicitly configured.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 65535;

/// Default overload drop policy when not explicitly configured.
pub const DEFAULT_DROP_POLICY: DropPolicy = DropPolicy::DropOldest;

/// Resolves a network interface name (e.g. "eth0", "lo") to its numeric interface index.
///
/// Returns 0 if the interface name cannot be found or is not valid.
#[must_use]
pub fn interface_name_to_index(name: &str) -> u32 {
    let Ok(c_name) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: libc::if_nametoindex reads a null-terminated C string and does not retain the pointer.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    index as u32
}

/// A parsed endpoint address preserving an IPv6 zone identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedEndpoint {
    pub ip: std::net::Ipv6Addr,
    pub zone: Option<String>,
    pub port: u16,
}

impl ScopedEndpoint {
    /// Parses an endpoint address string into a `ScopedEndpoint`.
    ///
    /// # Errors
    /// Returns an `io::Error` if the string cannot be parsed as a bracketed IPv6 endpoint.
    pub fn parse(address: &str) -> io::Result<Self> {
        let trimmed = address.trim();
        if !trimmed.starts_with('[') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("expected bracketed IPv6 address, got '{trimmed}'"),
            ));
        }
        let Some(close_bracket) = trimmed.find(']') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing closing bracket in '{trimmed}'"),
            ));
        };
        let host_part = &trimmed[1..close_bracket];
        let port_part = &trimmed[close_bracket + 1..];
        if !port_part.starts_with(':') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing port delimiter ':' in '{trimmed}'"),
            ));
        }
        let port: u16 = port_part[1..].parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid port '{}': {e}", &port_part[1..]),
            )
        })?;

        if let Some((ip_part, zone_part)) = host_part.split_once('%') {
            if zone_part.contains('%') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "multiple zone identifiers in address",
                ));
            }
            if zone_part.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 zone identifier cannot be empty",
                ));
            }
            let ip: std::net::Ipv6Addr = ip_part.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid IPv6 address '{ip_part}': {e}"),
                )
            })?;
            Ok(Self {
                ip,
                zone: Some(zone_part.to_string()),
                port,
            })
        } else {
            let ip: std::net::Ipv6Addr = host_part.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid IPv6 address '{host_part}': {e}"),
                )
            })?;
            Ok(Self {
                ip,
                zone: None,
                port,
            })
        }
    }
}

impl std::fmt::Display for ScopedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref zone) = self.zone {
            write!(f, "[{}%{}]:{}", self.ip, zone, self.port)
        } else {
            write!(f, "[{}]:{}", self.ip, self.port)
        }
    }
}

/// Parses a bracketed IPv6 socket address with an optional zone identifier,
/// resolving interface names via `interface_name_to_index`.
///
/// # Errors
/// Returns an `io::Error` of kind `io::ErrorKind::NotFound` if the specified interface name is unknown,
/// or `io::ErrorKind::InvalidInput` if the address syntax is malformed.
pub fn parse_scoped_socket_addr(address: &str) -> io::Result<SocketAddr> {
    let endpoint = ScopedEndpoint::parse(address)?;
    let scope_id = if let Some(ref zone) = endpoint.zone {
        if let Ok(numeric_id) = zone.parse::<u32>() {
            numeric_id
        } else {
            let idx = interface_name_to_index(zone);
            if idx == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("unknown network interface '{zone}'"),
                ));
            }
            idx
        }
    } else {
        0
    };

    Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
        endpoint.ip,
        endpoint.port,
        0,
        scope_id,
    )))
}

/// Resolves an endpoint address string into a `SocketAddr` with optional configuration path attribution.
///
/// # Errors
/// Returns an `io::Error` if address parsing or resolution fails. If `config_path` is provided,
/// errors are attributed with `{config_path}: {error}`.
pub fn resolve_endpoint_with_context(
    address: &str,
    config_path: Option<&str>,
) -> io::Result<SocketAddr> {
    let trimmed = address.trim();
    if trimmed.starts_with('[') {
        if let Some(close_idx) = trimmed.find(']') {
            let host_part = &trimmed[1..close_idx];
            if host_part.contains('%') {
                return parse_scoped_socket_addr(trimmed).map_err(|err| {
                    if let Some(path) = config_path {
                        io::Error::new(err.kind(), format!("{path}: {err}"))
                    } else {
                        err
                    }
                });
            }
        }
    }
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let addrs: Vec<SocketAddr> = match trimmed.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(err) => {
            return Err(if let Some(path) = config_path {
                io::Error::new(err.kind(), format!("{path}: {err}"))
            } else {
                err
            });
        }
    };
    select_socket_addr(&addrs).ok_or_else(|| {
        let msg = format!("no socket addresses resolved for '{address}'");
        if let Some(path) = config_path {
            io::Error::new(io::ErrorKind::AddrNotAvailable, format!("{path}: {msg}"))
        } else {
            io::Error::new(io::ErrorKind::AddrNotAvailable, msg)
        }
    })
}

/// Resolves an endpoint address string into a `SocketAddr` using deterministic address family selection.
///
/// # Selection Rule
/// When a hostname resolves to addresses in both IPv4 and IPv6 families, RER selects the first resolved
/// IPv4 address to preserve backward compatibility with existing IPv4 network deployments and configurations.
/// If the resolved addresses contain only IPv6 addresses, RER selects the first resolved IPv6 address.
/// When only IPv4 addresses are present, the first IPv4 address is selected.
/// Bracketed IPv6 literals (e.g. `[::1]:5000`, `[fe80::1%eth0]:5000`) and IPv4 literals (e.g. `127.0.0.1:5000`)
/// resolve directly to their respective single address family and scope.
///
/// # Errors
/// Returns an `io::Error` if address parsing or hostname resolution fails, or if no addresses are resolved.
pub fn resolve_endpoint(address: &str) -> io::Result<SocketAddr> {
    resolve_endpoint_with_context(address, None)
}

/// Applies the documented address family selection rule to a slice of resolved `SocketAddr`s.
#[must_use]
pub fn select_socket_addr(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    if addrs.is_empty() {
        return None;
    }
    if let Some(&ipv4) = addrs.iter().find(|a| a.is_ipv4()) {
        Some(ipv4)
    } else {
        Some(addrs[0])
    }
}

/// Binds a TCP listener socket, explicitly setting `IPV6_V6ONLY` on IPv6 sockets.
///
/// # Errors
/// Returns an `io::Error` if creating, configuring, or binding the listener socket fails.
pub fn bind_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

/// Binds a UDP socket, explicitly setting `IPV6_V6ONLY` on IPv6 sockets.
///
/// # Errors
/// Returns an `io::Error` if creating, configuring, or binding the socket fails.
pub fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// Formats an endpoint address string, ensuring IPv6 addresses appear in bracketed form
/// and preserving zone identifiers unchanged.
#[must_use]
pub fn format_endpoint(address: &str) -> String {
    let trimmed = address.trim();
    if trimmed.starts_with('[') || trimmed.starts_with('/') {
        return trimmed.to_string();
    }
    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        return socket_addr.to_string();
    }
    if !trimmed.starts_with('[') && trimmed.contains(':') {
        if let Some(last_colon) = trimmed.rfind(':') {
            let host = &trimmed[..last_colon];
            let port = &trimmed[last_colon + 1..];
            if host.contains('%') {
                if let Some((ip_part, _zone_part)) = host.split_once('%') {
                    if ip_part.parse::<std::net::Ipv6Addr>().is_ok() && port.parse::<u16>().is_ok()
                    {
                        return format!("[{}]:{}", host, port);
                    }
                }
            }
            if host.parse::<std::net::Ipv6Addr>().is_ok() && port.parse::<u16>().is_ok() {
                return format!("[{}]:{}", host, port);
            }
        }
        if trimmed.contains('%') {
            if let Some((ip_part, _zone_part)) = trimmed.split_once('%') {
                if ip_part.parse::<std::net::Ipv6Addr>().is_ok() {
                    return format!("[{}]", trimmed);
                }
            }
        }
        if trimmed.parse::<std::net::Ipv6Addr>().is_ok() {
            return format!("[{}]", trimmed);
        }
    }
    trimmed.to_string()
}

/// A discrete UDP or TCP datagram payload preserving datagram boundary and source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub payload: Vec<u8>,
    pub source_addr: SocketAddr,
}

/// Result of pushing a datagram into a bounded queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    /// Datagram was enqueued within bounds.
    Enqueued,
    /// Queue was full; oldest datagram was dropped to accommodate new datagram.
    DroppedOldest,
    /// Queue was full; new datagram was dropped.
    DroppedNewest,
    /// Queue was full; datagram was rejected.
    Rejected,
}

/// A thread-safe bounded FIFO queue enforcing explicit overload drop policies.
#[derive(Debug)]
pub struct BoundedQueue {
    queue: VecDeque<Datagram>,
    max_queue_size: usize,
    drop_policy: DropPolicy,
}

impl BoundedQueue {
    /// Creates a new bounded queue with specified capacity and drop policy.
    #[must_use]
    pub fn new(max_queue_size: usize, drop_policy: DropPolicy) -> Self {
        let capacity = if max_queue_size == 0 {
            DEFAULT_MAX_QUEUE_SIZE
        } else {
            max_queue_size
        };
        Self {
            queue: VecDeque::with_capacity(capacity),
            max_queue_size: capacity,
            drop_policy,
        }
    }

    /// Pushes a datagram into the queue according to the configured drop policy.
    pub fn push(&mut self, datagram: Datagram) -> PushResult {
        if self.queue.len() < self.max_queue_size {
            self.queue.push_back(datagram);
            PushResult::Enqueued
        } else {
            match self.drop_policy {
                DropPolicy::DropOldest => {
                    self.queue.pop_front();
                    self.queue.push_back(datagram);
                    PushResult::DroppedOldest
                }
                DropPolicy::DropNewest => PushResult::DroppedNewest,
                DropPolicy::Reject => PushResult::Rejected,
            }
        }
    }

    /// Pops the next datagram from the front of the queue, if any.
    pub fn pop(&mut self) -> Option<Datagram> {
        self.queue.pop_front()
    }

    /// Current number of datagrams in queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True if the queue contains no datagrams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Maximum configured capacity of the queue.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.max_queue_size
    }

    /// Configured drop policy.
    #[must_use]
    pub fn drop_policy(&self) -> DropPolicy {
        self.drop_policy
    }
}

/// Thread-safe counters tracking stream activity, drop events, backpressure, and socket errors.
#[derive(Debug, Default)]
pub struct StreamStats {
    pub received_packets: AtomicU64,
    pub received_bytes: AtomicU64,
    pub forwarded_packets: AtomicU64,
    pub forwarded_bytes: AtomicU64,
    pub dropped_packets: AtomicU64,
    pub drops_queue_full: AtomicU64,
    pub drops_oversized: AtomicU64,
    pub drops_validation: AtomicU64,
    pub queue_depth: AtomicU64,
    pub destination_errors: AtomicU64,
    pub socket_errors: AtomicU64,
    pub backpressure_events: AtomicU64,
    pub validation_errors: AtomicU64,
}

impl StreamStats {
    /// Captures a point-in-time snapshot of stream counters.
    #[must_use]
    pub fn snapshot(&self) -> StreamStatsSnapshot {
        StreamStatsSnapshot {
            received_packets: self.received_packets.load(Ordering::SeqCst),
            received_bytes: self.received_bytes.load(Ordering::SeqCst),
            forwarded_packets: self.forwarded_packets.load(Ordering::SeqCst),
            forwarded_bytes: self.forwarded_bytes.load(Ordering::SeqCst),
            dropped_packets: self.dropped_packets.load(Ordering::SeqCst),
            drops_queue_full: self.drops_queue_full.load(Ordering::SeqCst),
            drops_oversized: self.drops_oversized.load(Ordering::SeqCst),
            drops_validation: self.drops_validation.load(Ordering::SeqCst),
            queue_depth: self.queue_depth.load(Ordering::SeqCst),
            destination_errors: self.destination_errors.load(Ordering::SeqCst),
            socket_errors: self.socket_errors.load(Ordering::SeqCst),
            backpressure_events: self.backpressure_events.load(Ordering::SeqCst),
            validation_errors: self.validation_errors.load(Ordering::SeqCst),
        }
    }
}

/// Point-in-time snapshot of stream statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StreamStatsSnapshot {
    pub received_packets: u64,
    pub received_bytes: u64,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub dropped_packets: u64,
    pub drops_queue_full: u64,
    pub drops_oversized: u64,
    #[serde(default)]
    pub drops_validation: u64,
    #[serde(default)]
    pub queue_depth: u64,
    pub destination_errors: u64,
    pub socket_errors: u64,
    #[serde(default)]
    pub backpressure_events: u64,
    #[serde(default)]
    pub validation_errors: u64,
}

/// Connection manager for a TCP destination supporting reconnection with backoff and timeouts.
struct TcpDestinationConnection {
    address: String,
    config_path: String,
    stream_id: String,
    event_buffer: DiagnosticBuffer,
    framing: FramingMode,
    stream: Option<TcpStream>,
    backoff: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
    connect_timeout: Duration,
    write_timeout: Duration,
    next_connect_attempt: Option<Instant>,
}

impl TcpDestinationConnection {
    fn new(
        address: String,
        config_path: String,
        stream_id: String,
        event_buffer: DiagnosticBuffer,
        framing: FramingMode,
    ) -> Self {
        Self {
            address,
            config_path,
            stream_id,
            event_buffer,
            framing,
            stream: None,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_millis(1000),
            backoff: Duration::from_millis(50),
            connect_timeout: Duration::from_millis(500),
            write_timeout: Duration::from_millis(500),
            next_connect_attempt: None,
        }
    }

    fn try_connect(&mut self, stats: &StreamStats) -> bool {
        if self.stream.is_some() {
            return true;
        }

        if let Some(next) = self.next_connect_attempt {
            if Instant::now() < next {
                return false;
            }
        }

        let target_addr =
            match resolve_endpoint_with_context(&self.address, Some(&self.config_path)) {
                Ok(addr) => addr,
                Err(e) => {
                    stats.destination_errors.fetch_add(1, Ordering::Relaxed);
                    stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "[tcp destination] Address resolution error for '{}' ('{}'): {}",
                        self.config_path,
                        format_endpoint(&self.address),
                        e
                    );
                    self.event_buffer.emit(
                        DiagnosticEvent::new(
                            self.event_buffer.clock().monotonic_nanos(),
                            self.event_buffer.clock().wall_clock_nanos(),
                            &self.stream_id,
                            DiagnosticStage::Failure,
                            TransportType::Tcp,
                            0,
                        )
                        .with_destination(format_endpoint(&self.address))
                        .with_reason(format!(
                            "Address resolution error for '{}' ('{}'): {}",
                            self.config_path,
                            format_endpoint(&self.address),
                            e
                        )),
                    );
                    return false;
                }
            };

        match TcpStream::connect_timeout(&target_addr, self.connect_timeout) {
            Ok(s) => {
                let _ = s.set_write_timeout(Some(self.write_timeout));
                let _ = s.set_read_timeout(Some(Duration::from_millis(50)));
                let _ = s.set_nodelay(true);
                self.stream = Some(s);
                self.backoff = self.initial_backoff;
                self.next_connect_attempt = None;
                true
            }
            Err(e) => {
                stats.destination_errors.fetch_add(1, Ordering::Relaxed);
                stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                let wait = self.backoff;
                self.backoff = (self.backoff * 2).min(self.max_backoff);
                self.next_connect_attempt = Some(Instant::now() + wait);
                eprintln!(
                    "[tcp destination] Connect error to '{}' (backoff {:?}): {}",
                    format_endpoint(&self.address),
                    wait,
                    e
                );
                self.event_buffer.emit(
                    DiagnosticEvent::new(
                        self.event_buffer.clock().monotonic_nanos(),
                        self.event_buffer.clock().wall_clock_nanos(),
                        &self.stream_id,
                        DiagnosticStage::Failure,
                        TransportType::Tcp,
                        0,
                    )
                    .with_destination(format_endpoint(&self.address))
                    .with_reason(format!(
                        "Connect error to '{}' (backoff {:?}): {}",
                        format_endpoint(&self.address),
                        wait,
                        e
                    )),
                );
                false
            }
        }
    }

    fn send(&mut self, payload: &[u8], stats: &StreamStats) -> io::Result<()> {
        if let Some(ref s) = self.stream {
            let mut buf = [0u8; 1];
            match s.peek(&mut buf) {
                Ok(0) => {
                    self.stream = None;
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::ConnectionReset
                        || e.kind() == io::ErrorKind::BrokenPipe
                        || e.kind() == io::ErrorKind::NotConnected =>
                {
                    self.stream = None;
                }
                _ => {}
            }
        }

        if self.stream.is_none() && !self.try_connect(stats) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "tcp destination not connected",
            ));
        }

        let s = self.stream.as_mut().unwrap();

        let write_res = match self.framing {
            FramingMode::LengthPrefix => {
                let frame = framing::encode_frame(payload);
                s.write_all(&frame)
            }
            FramingMode::Kiss => {
                let frame = framing::encode_kiss_frame(payload);
                s.write_all(&frame)
            }
            FramingMode::Ccsds | FramingMode::Mavlink | FramingMode::Mqtt => s.write_all(payload),
        };

        match write_res {
            Ok(()) => {
                let _ = s.flush();
                stats.forwarded_packets.fetch_add(1, Ordering::SeqCst);
                stats
                    .forwarded_bytes
                    .fetch_add(payload.len() as u64, Ordering::SeqCst);
                Ok(())
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                stats.backpressure_events.fetch_add(1, Ordering::SeqCst);
                stats.destination_errors.fetch_add(1, Ordering::SeqCst);
                self.event_buffer.emit(
                    DiagnosticEvent::new(
                        self.event_buffer.clock().monotonic_nanos(),
                        self.event_buffer.clock().wall_clock_nanos(),
                        &self.stream_id,
                        DiagnosticStage::Failure,
                        TransportType::Tcp,
                        payload.len() as u64,
                    )
                    .with_destination(format_endpoint(&self.address))
                    .with_reason("tcp slow reader backpressure / write timeout"),
                );
                Err(io::Error::new(
                    e.kind(),
                    "tcp slow reader backpressure / write timeout",
                ))
            }
            Err(e) => {
                stats.destination_errors.fetch_add(1, Ordering::SeqCst);
                stats.socket_errors.fetch_add(1, Ordering::SeqCst);
                self.stream = None;
                let wait = self.backoff;
                self.backoff = (self.backoff * 2).min(self.max_backoff);
                self.next_connect_attempt = Some(Instant::now() + wait);
                self.event_buffer.emit(
                    DiagnosticEvent::new(
                        self.event_buffer.clock().monotonic_nanos(),
                        self.event_buffer.clock().wall_clock_nanos(),
                        &self.stream_id,
                        DiagnosticStage::Failure,
                        TransportType::Tcp,
                        payload.len() as u64,
                    )
                    .with_destination(format_endpoint(&self.address))
                    .with_reason(format!("TCP write error: {e}")),
                );
                Err(e)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ExtractedCcsds {
    apid: Option<u16>,
    seq: Option<u16>,
    flags: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
struct CcsdsIngressContext<'a> {
    ccsds_cfg: Option<&'a CcsdsConfig>,
    ccsds_tracker: Option<&'a Arc<Mutex<CcsdsSequenceTracker>>>,
    stats: &'a StreamStats,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

fn process_ccsds_ingress(payload: &[u8], ctx: &CcsdsIngressContext<'_>) -> Option<ExtractedCcsds> {
    let CcsdsIngressContext {
        ccsds_cfg,
        ccsds_tracker,
        stats,
        event_buffer,
        stream_id,
        src_endpoint,
        primary_dest,
        transport,
    } = *ctx;
    let Some(ccsds_cfg) = ccsds_cfg else {
        return Some(ExtractedCcsds::default());
    };
    if !ccsds_cfg.enabled {
        return Some(ExtractedCcsds::default());
    }

    match parse_and_validate_ccsds_packet(payload, ccsds_cfg) {
        Err(parse_err) => {
            stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            if let Some(t) = ccsds_tracker {
                t.lock().unwrap().record_validation_error();
            }

            if !ccsds_cfg.passthrough_on_error {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                stats.drops_validation.fetch_add(1, Ordering::Relaxed);

                let drop_reason = match parse_err {
                    CcsdsParseError::TruncatedHeader => {
                        "CCSDS packet truncated: buffer shorter than 6-byte primary header".to_string()
                    }
                    CcsdsParseError::InvalidVersion => {
                        "invalid CCSDS packet version: expected 0 for Space Packets".to_string()
                    }
                    CcsdsParseError::LengthMismatch => {
                        "CCSDS packet length mismatch: buffer length is less than declared packet data length plus 7 bytes".to_string()
                    }
                };
                eprintln!(
                    "[stream {}] Dropped invalid CCSDS {} packet: {}",
                    stream_id, transport, drop_reason
                );

                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Dropped,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_reason(drop_reason),
                );
                None
            } else {
                let fail_reason = match parse_err {
                    CcsdsParseError::TruncatedHeader => {
                        "CCSDS validation failed (passthrough): buffer shorter than 6-byte primary header".to_string()
                    }
                    CcsdsParseError::InvalidVersion => {
                        "CCSDS validation failed (passthrough): invalid CCSDS packet version".to_string()
                    }
                    CcsdsParseError::LengthMismatch => {
                        "CCSDS validation failed (passthrough): buffer length is less than declared packet data length plus 7 bytes".to_string()
                    }
                };
                eprintln!(
                    "[stream {}] CCSDS validation failed (passthrough): {}",
                    stream_id, fail_reason
                );

                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Failure,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_reason(fail_reason),
                );
                Some(ExtractedCcsds::default())
            }
        }
        Ok(header) => {
            let extracted = ExtractedCcsds {
                apid: Some(header.apid),
                seq: Some(header.sequence_count),
                flags: Some(header.sequence_flags),
            };

            if ccsds_cfg.track_sequences {
                if let Some(t) = ccsds_tracker {
                    let tracking_ev = {
                        let mut tracker = t.lock().unwrap();
                        tracker.record_header(&header)
                    };
                    if let Some(ev) = tracking_ev {
                        match ev {
                            SequenceTrackingEvent::Gap {
                                expected,
                                actual,
                                missing_count,
                            } => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_apid(header.apid)
                                    .with_sequence_number(u64::from(header.sequence_count))
                                    .with_ccsds_sequence(header.sequence_count)
                                    .with_ccsds_flags(header.sequence_flags)
                                    .with_reason(format!(
                                        "CCSDS sequence gap: APID {}, expected {}, actual {}, missing {} packets",
                                        header.apid, expected, actual, missing_count
                                    )),
                                );
                            }
                            SequenceTrackingEvent::Duplicate { sequence } => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_apid(header.apid)
                                    .with_sequence_number(sequence)
                                    .with_ccsds_sequence(header.sequence_count)
                                    .with_ccsds_flags(header.sequence_flags)
                                    .with_reason(format!(
                                        "CCSDS sequence duplicate: APID {}, duplicate sequence {}",
                                        header.apid, sequence
                                    )),
                                );
                            }
                            SequenceTrackingEvent::OutOfOrder {
                                sequence,
                                previous_highest,
                            } => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_apid(header.apid)
                                    .with_sequence_number(sequence)
                                    .with_ccsds_sequence(header.sequence_count)
                                    .with_ccsds_flags(header.sequence_flags)
                                    .with_reason(format!(
                                        "CCSDS sequence out-of-order: APID {}, sequence {} arrived after highest {}",
                                        header.apid, sequence, previous_highest
                                    )),
                                );
                            }
                            SequenceTrackingEvent::Rollover {
                                sequence,
                                missing_count,
                            } if missing_count > 0 => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_apid(header.apid)
                                    .with_sequence_number(sequence)
                                    .with_ccsds_sequence(header.sequence_count)
                                    .with_ccsds_flags(header.sequence_flags)
                                    .with_reason(format!(
                                        "CCSDS sequence rollover with gap: APID {}, rollover to {} with {} missing packets",
                                        header.apid, sequence, missing_count
                                    )),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
            Some(extracted)
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ExtractedMavlink {
    header: Option<MavlinkHeader>,
    status: Option<MavlinkParseStatus>,
    inspection: Option<MavlinkInspection>,
}

#[derive(Debug, Clone, Copy)]
struct MavlinkIngressContext<'a> {
    mavlink_cfg: Option<&'a MavlinkConfig>,
    mavlink_tracker: Option<&'a Arc<Mutex<MavlinkSequenceTracker>>>,
    stats: &'a StreamStats,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

fn process_mavlink_ingress(
    payload: &[u8],
    ctx: &MavlinkIngressContext<'_>,
) -> Option<ExtractedMavlink> {
    let MavlinkIngressContext {
        mavlink_cfg,
        mavlink_tracker,
        stats,
        event_buffer,
        stream_id,
        src_endpoint,
        primary_dest,
        transport,
    } = *ctx;

    let Some(mavlink_cfg) = mavlink_cfg else {
        return Some(ExtractedMavlink::default());
    };
    if !mavlink_cfg.enabled {
        return Some(ExtractedMavlink::default());
    }

    match parse_mavlink_header(payload) {
        Err(parse_err) => {
            if !mavlink_cfg.validate_magic
                && matches!(parse_err, MavlinkParseError::InvalidMagicMarker)
            {
                return Some(ExtractedMavlink::default());
            }

            stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            if let Some(t) = mavlink_tracker {
                t.lock().unwrap().record_validation_error();
            }

            if !mavlink_cfg.passthrough_on_error {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                stats.drops_validation.fetch_add(1, Ordering::Relaxed);

                let drop_reason = match parse_err {
                    MavlinkParseError::InvalidMagicMarker => {
                        "invalid MAVLink magic start byte: expected 0xFE (MAVLink 1) or 0xFD (MAVLink 2)".to_string()
                    }
                    MavlinkParseError::TruncatedPacket => {
                        "truncated MAVLink packet: buffer shorter than header length or declared total packet length".to_string()
                    }
                };
                eprintln!(
                    "[stream {}] Dropped invalid MAVLink {} packet: {}",
                    stream_id, transport, drop_reason
                );

                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Dropped,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_reason(drop_reason),
                );
                None
            } else {
                let fail_reason = match parse_err {
                    MavlinkParseError::InvalidMagicMarker => {
                        "MAVLink validation failed (passthrough): invalid magic start byte (expected 0xFE or 0xFD)".to_string()
                    }
                    MavlinkParseError::TruncatedPacket => {
                        "MAVLink validation failed (passthrough): buffer shorter than header length or declared total packet length".to_string()
                    }
                };
                eprintln!(
                    "[stream {}] MAVLink validation failed (passthrough): {}",
                    stream_id, fail_reason
                );

                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Failure,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_reason(fail_reason),
                );
                Some(ExtractedMavlink::default())
            }
        }
        Ok(header) => {
            let status = if let Some(w) = header.warning() {
                MavlinkParseStatus::Warning(w)
            } else {
                MavlinkParseStatus::Valid
            };

            let metadata = MavlinkMetadata {
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

            let mut insp = MavlinkInspection::new(
                header.system_id,
                header.component_id,
                header.sequence,
                header.message_id,
            );
            insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
            insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());
            insp.stream_id = Some(stream_id.to_string());
            insp.version = Some(if header.version.is_v1() { 1 } else { 2 });
            insp.parse_status = Some(status);
            insp.mavlink_metadata = Some(metadata);

            let mut insp_ev: DiagnosticEvent = insp.clone().into();
            insp_ev.transport = transport;
            insp_ev.payload_length = payload.len() as u64;
            insp_ev.source_endpoint = Some(src_endpoint.to_string());
            insp_ev.destination_endpoint = Some(primary_dest.to_string());
            event_buffer.emit(insp_ev);

            if mavlink_cfg.track_sequences {
                if let Some(t) = mavlink_tracker {
                    let tracking_ev = {
                        let mut tracker = t.lock().unwrap();
                        tracker.record_header(&header)
                    };
                    if let Some(ev) = tracking_ev {
                        match ev {
                            SequenceTrackingEvent::Gap {
                                expected,
                                actual,
                                missing_count,
                            } => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_mavlink_header(&header)
                                    .with_sequence_number(u64::from(header.sequence))
                                    .with_reason(format!(
                                        "MAVLink sequence gap: sysid {}, compid {}, expected {}, actual {}, missing {} packets",
                                        header.system_id, header.component_id, expected, actual, missing_count
                                    )),
                                );
                            }
                            SequenceTrackingEvent::Duplicate { sequence } => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_mavlink_header(&header)
                                    .with_sequence_number(sequence)
                                    .with_reason(format!(
                                        "MAVLink sequence duplicate: sysid {}, compid {}, duplicate sequence {}",
                                        header.system_id, header.component_id, sequence
                                    )),
                                );
                            }
                            SequenceTrackingEvent::OutOfOrder {
                                sequence,
                                previous_highest,
                            } => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_mavlink_header(&header)
                                    .with_sequence_number(sequence)
                                    .with_reason(format!(
                                        "MAVLink sequence out-of-order: sysid {}, compid {}, sequence {} arrived after highest {}",
                                        header.system_id, header.component_id, sequence, previous_highest
                                    )),
                                );
                            }
                            SequenceTrackingEvent::Rollover {
                                sequence,
                                missing_count,
                            } if missing_count > 0 => {
                                event_buffer.emit(
                                    DiagnosticEvent::new(
                                        event_buffer.clock().monotonic_nanos(),
                                        event_buffer.clock().wall_clock_nanos(),
                                        stream_id,
                                        DiagnosticStage::Failure,
                                        transport,
                                        payload.len() as u64,
                                    )
                                    .with_source(src_endpoint)
                                    .with_destination(primary_dest)
                                    .with_mavlink_header(&header)
                                    .with_sequence_number(sequence)
                                    .with_reason(format!(
                                        "MAVLink sequence rollover with gap: sysid {}, compid {}, rollover to {} with {} missing packets",
                                        header.system_id, header.component_id, sequence, missing_count
                                    )),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }

            Some(ExtractedMavlink {
                header: Some(header),
                status: Some(status),
                inspection: Some(insp),
            })
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ExtractedMqtt {
    header: Option<MqttFixedHeader>,
    status: Option<MqttParseStatus>,
    inspection: Option<MqttInspection>,
}

#[derive(Debug, Clone, Copy)]
struct MqttIngressContext<'a> {
    mqtt_cfg: Option<&'a MqttConfig>,
    stats: &'a StreamStats,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

fn process_mqtt_ingress(payload: &[u8], ctx: &MqttIngressContext<'_>) -> Option<ExtractedMqtt> {
    let MqttIngressContext {
        mqtt_cfg,
        stats,
        event_buffer,
        stream_id,
        src_endpoint,
        primary_dest,
        transport,
    } = *ctx;

    let Some(mqtt_cfg) = mqtt_cfg else {
        return Some(ExtractedMqtt::default());
    };
    if !mqtt_cfg.enabled {
        return Some(ExtractedMqtt::default());
    }

    if mqtt_cfg.max_packet_size > 0 && payload.len() > mqtt_cfg.max_packet_size {
        stats.validation_errors.fetch_add(1, Ordering::Relaxed);
        if !mqtt_cfg.passthrough_on_error {
            stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            stats.drops_validation.fetch_add(1, Ordering::Relaxed);
            let drop_reason = format!(
                "oversized MQTT packet: {} bytes exceeds configured max_packet_size {}",
                payload.len(),
                mqtt_cfg.max_packet_size
            );
            eprintln!(
                "[stream {}] Dropped invalid MQTT {} packet: {}",
                stream_id, transport, drop_reason
            );
            event_buffer.emit(
                DiagnosticEvent::new(
                    event_buffer.clock().monotonic_nanos(),
                    event_buffer.clock().wall_clock_nanos(),
                    stream_id,
                    DiagnosticStage::Dropped,
                    transport,
                    payload.len() as u64,
                )
                .with_source(src_endpoint)
                .with_destination(primary_dest)
                .with_reason(drop_reason),
            );
            return None;
        } else {
            let fail_reason = format!(
                "MQTT validation failed (passthrough): packet size {} exceeds max_packet_size {}",
                payload.len(),
                mqtt_cfg.max_packet_size
            );
            eprintln!(
                "[stream {}] MQTT validation failed (passthrough): {}",
                stream_id, fail_reason
            );
            event_buffer.emit(
                DiagnosticEvent::new(
                    event_buffer.clock().monotonic_nanos(),
                    event_buffer.clock().wall_clock_nanos(),
                    stream_id,
                    DiagnosticStage::Failure,
                    transport,
                    payload.len() as u64,
                )
                .with_source(src_endpoint)
                .with_destination(primary_dest)
                .with_reason(fail_reason),
            );
            return Some(ExtractedMqtt::default());
        }
    }

    let parse_res = if mqtt_cfg.validate_flags {
        parse_mqtt_fixed_header(payload)
    } else {
        parse_mqtt_fixed_header_relaxed(payload)
    };

    match parse_res {
        Err(parse_err) => {
            stats.validation_errors.fetch_add(1, Ordering::Relaxed);

            if !mqtt_cfg.passthrough_on_error {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                stats.drops_validation.fetch_add(1, Ordering::Relaxed);

                let drop_reason = match parse_err {
                    MqttParseError::InvalidFlags => {
                        "invalid MQTT header flags: flags violate MQTT specification rules".to_string()
                    }
                    MqttParseError::TruncatedPacket => {
                        "truncated MQTT packet: buffer shorter than header length or declared remaining length".to_string()
                    }
                    MqttParseError::ForbiddenPacketType0 => {
                        "invalid MQTT packet: packet type 0 is forbidden".to_string()
                    }
                    MqttParseError::VariableByteIntegerOverflow => {
                        "malformed MQTT variable byte integer: length field exceeds 4 bytes or overflows".to_string()
                    }
                };
                eprintln!(
                    "[stream {}] Dropped invalid MQTT {} packet: {}",
                    stream_id, transport, drop_reason
                );

                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Dropped,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_reason(drop_reason),
                );
                None
            } else {
                let fail_reason = match parse_err {
                    MqttParseError::InvalidFlags => {
                        "MQTT validation failed (passthrough): invalid header flags".to_string()
                    }
                    MqttParseError::TruncatedPacket => {
                        "MQTT validation failed (passthrough): truncated packet".to_string()
                    }
                    MqttParseError::ForbiddenPacketType0 => {
                        "MQTT validation failed (passthrough): forbidden packet type 0".to_string()
                    }
                    MqttParseError::VariableByteIntegerOverflow => {
                        "MQTT validation failed (passthrough): variable byte integer overflow"
                            .to_string()
                    }
                };
                eprintln!(
                    "[stream {}] MQTT validation failed (passthrough): {}",
                    stream_id, fail_reason
                );

                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Failure,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_reason(fail_reason),
                );
                Some(ExtractedMqtt::default())
            }
        }
        Ok(header) => {
            let status = MqttParseStatus::Valid;
            let qos = header.qos();
            let dup = header.dup();
            let retain = header.retain();

            let mut packet_id = None;
            if header.packet_type == MqttPacketType::Publish {
                if let Some(q) = qos {
                    if q > 0 && payload.len() >= header.header_length + 2 {
                        let var_hdr = &payload[header.header_length..];
                        if var_hdr.len() >= 2 {
                            let topic_len = u16::from_be_bytes([var_hdr[0], var_hdr[1]]) as usize;
                            let pid_offset = 2 + topic_len;
                            if var_hdr.len() >= pid_offset + 2 {
                                packet_id = Some(u16::from_be_bytes([
                                    var_hdr[pid_offset],
                                    var_hdr[pid_offset + 1],
                                ]));
                            }
                        }
                    }
                }
            } else if matches!(
                header.packet_type,
                MqttPacketType::Puback
                    | MqttPacketType::Pubrec
                    | MqttPacketType::Pubrel
                    | MqttPacketType::Pubcomp
                    | MqttPacketType::Subscribe
                    | MqttPacketType::Suback
                    | MqttPacketType::Unsubscribe
                    | MqttPacketType::Unsuback
            ) && payload.len() >= header.header_length + 2
            {
                let var_hdr = &payload[header.header_length..];
                packet_id = Some(u16::from_be_bytes([var_hdr[0], var_hdr[1]]));
            }

            let metadata = MqttMetadata {
                packet_type: header.packet_type.code(),
                packet_type_name: header.packet_type.name().to_string(),
                flags: Some(header.flags),
                qos,
                dup,
                retain,
                packet_identifier: packet_id,
                remaining_length: Some(header.remaining_length),
                total_packet_length: Some(header.total_packet_length),
                topic: None,
            };

            let mut insp =
                MqttInspection::new(header.packet_type.code(), header.packet_type.name());
            insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
            insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());
            insp.stream_id = Some(stream_id.to_string());
            insp.qos = qos;
            insp.packet_identifier = packet_id;
            insp.parse_status = Some(status);
            insp.mqtt_metadata = Some(metadata);

            let mut insp_ev: DiagnosticEvent = insp.clone().into();
            insp_ev.transport = transport;
            insp_ev.payload_length = payload.len() as u64;
            insp_ev.source_endpoint = Some(src_endpoint.to_string());
            insp_ev.destination_endpoint = Some(primary_dest.to_string());
            event_buffer.emit(insp_ev);

            Some(ExtractedMqtt {
                header: Some(header),
                status: Some(status),
                inspection: Some(insp),
            })
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct KissIngressContext<'a> {
    kiss_cfg: Option<&'a KissConfig>,
    stats: &'a StreamStats,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

#[derive(Debug, Clone, Default)]
struct ExtractedKiss {
    port: Option<u8>,
    command: Option<u8>,
    ax25_frame: Option<Ax25Frame>,
    inspection: Option<KissInspection>,
}

fn process_kiss_ingress(payload: &[u8], ctx: &KissIngressContext<'_>) -> Option<ExtractedKiss> {
    let KissIngressContext {
        kiss_cfg,
        stats,
        event_buffer,
        stream_id,
        src_endpoint,
        primary_dest,
        transport,
    } = *ctx;

    let Some(kiss_cfg) = kiss_cfg else {
        return Some(ExtractedKiss::default());
    };
    if !kiss_cfg.enabled {
        return Some(ExtractedKiss::default());
    }

    if payload.is_empty() {
        stats.validation_errors.fetch_add(1, Ordering::Relaxed);
        if !kiss_cfg.passthrough_on_error {
            stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            stats.drops_validation.fetch_add(1, Ordering::Relaxed);
            let drop_reason = "empty KISS frame: buffer has 0 bytes".to_string();
            eprintln!(
                "[stream {}] Dropped invalid KISS {} packet: {}",
                stream_id, transport, drop_reason
            );
            event_buffer.emit(
                DiagnosticEvent::new(
                    event_buffer.clock().monotonic_nanos(),
                    event_buffer.clock().wall_clock_nanos(),
                    stream_id,
                    DiagnosticStage::Dropped,
                    transport,
                    0,
                )
                .with_source(src_endpoint)
                .with_destination(primary_dest)
                .with_reason(drop_reason),
            );
            return None;
        } else {
            let fail_reason = "KISS validation failed (passthrough): empty frame".to_string();
            eprintln!(
                "[stream {}] KISS validation failed (passthrough): {}",
                stream_id, fail_reason
            );
            event_buffer.emit(
                DiagnosticEvent::new(
                    event_buffer.clock().monotonic_nanos(),
                    event_buffer.clock().wall_clock_nanos(),
                    stream_id,
                    DiagnosticStage::Failure,
                    transport,
                    0,
                )
                .with_source(src_endpoint)
                .with_destination(primary_dest)
                .with_reason(fail_reason),
            );
            return Some(ExtractedKiss::default());
        }
    }

    let kiss_byte = payload[0];
    let port = (kiss_byte >> 4) & 0x0F;
    let cmd = kiss_byte & 0x0F;

    // Check port filter
    if let Some(filter_port) = kiss_cfg.port_filter {
        if u32::from(port) != filter_port {
            stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            stats.drops_validation.fetch_add(1, Ordering::Relaxed);
            stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            let drop_reason = format!(
                "KISS port mismatch: frame port {port} does not match configured filter port {filter_port}"
            );
            eprintln!(
                "[stream {}] Dropped KISS {} packet: {}",
                stream_id, transport, drop_reason
            );
            event_buffer.emit(
                DiagnosticEvent::new(
                    event_buffer.clock().monotonic_nanos(),
                    event_buffer.clock().wall_clock_nanos(),
                    stream_id,
                    DiagnosticStage::Dropped,
                    transport,
                    payload.len() as u64,
                )
                .with_source(src_endpoint)
                .with_destination(primary_dest)
                .with_kiss_port(port)
                .with_kiss_command(cmd)
                .with_reason(drop_reason),
            );
            return None;
        }
    }

    if !kiss_cfg.inspect_ax25 {
        let mut insp = KissInspection::new(port, cmd);
        insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
        insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());
        insp.stream_id = Some(stream_id.to_string());

        let mut insp_ev: DiagnosticEvent = insp.clone().into();
        insp_ev.transport = transport;
        insp_ev.payload_length = payload.len() as u64;
        insp_ev.source_endpoint = Some(src_endpoint.to_string());
        insp_ev.destination_endpoint = Some(primary_dest.to_string());
        event_buffer.emit(insp_ev);

        return Some(ExtractedKiss {
            port: Some(port),
            command: Some(cmd),
            ax25_frame: None,
            inspection: Some(insp),
        });
    }

    // Passive AX.25 packet inspection
    // If command is DATA (0x00), the frame contains an AX.25 packet starting at byte 1.
    // If command is not 0x00, check whether it is a valid KISS control command (e.g. TX_DELAY, P, etc.)
    // or whether the whole payload is a raw AX.25 packet.
    let is_kiss_control = matches!(cmd, 1..=6 | 15)
        && (matches!(cmd, 1..=5) && payload.len() == 2
            || cmd == 15 && payload.len() == 1
            || cmd == 6);

    let ax25_res = if cmd == 0 {
        parse_ax25_frame(&payload[1..])
    } else if !is_kiss_control {
        parse_ax25_frame(&payload[1..]).or_else(|_| parse_ax25_frame(payload))
    } else {
        let mut insp = KissInspection::new(port, cmd);
        insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
        insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());
        insp.stream_id = Some(stream_id.to_string());

        let mut insp_ev: DiagnosticEvent = insp.clone().into();
        insp_ev.transport = transport;
        insp_ev.payload_length = payload.len() as u64;
        insp_ev.source_endpoint = Some(src_endpoint.to_string());
        insp_ev.destination_endpoint = Some(primary_dest.to_string());
        event_buffer.emit(insp_ev);

        return Some(ExtractedKiss {
            port: Some(port),
            command: Some(cmd),
            ax25_frame: None,
            inspection: Some(insp),
        });
    };

    match ax25_res {
        Ok(frame) => {
            let mut insp = KissInspection::new(port, cmd);
            insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
            insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());
            insp.stream_id = Some(stream_id.to_string());
            insp.source_callsign = Some(frame.source_callsign.clone());
            insp.destination_callsign = Some(frame.destination_callsign.clone());
            insp.source_ssid = Some(frame.source_ssid);
            insp.destination_ssid = Some(frame.destination_ssid);
            insp.frame_type = Some(format!("{:?}", frame.frame_type));
            insp.pid = frame.pid;
            insp.parse_status = Some("Valid".to_string());

            let digis = frame.repeater_callsign_strings();
            let digis_opt = if digis.is_empty() {
                None
            } else {
                Some(digis.clone())
            };

            let kiss_meta = KissMetadata {
                port,
                kiss_port: Some(port),
                command: cmd,
                kiss_command: Some(cmd),
                command_name: Some(kiss_command_name(cmd).to_string()),
                source_callsign: Some(frame.source_callsign.clone()),
                destination_callsign: Some(frame.destination_callsign.clone()),
                ax25_source_callsign: Some(frame.source_callsign.clone()),
                ax25_destination_callsign: Some(frame.destination_callsign.clone()),
                source_ssid: Some(frame.source_ssid),
                destination_ssid: Some(frame.destination_ssid),
                frame_type: Some(format!("{:?}", frame.frame_type)),
                pid: frame.pid,
                digipeaters: digis_opt.clone(),
            };
            insp.kiss_metadata = Some(kiss_meta);

            let ax25_meta = Ax25Metadata {
                source_callsign: frame.source_callsign.clone(),
                destination_callsign: frame.destination_callsign.clone(),
                ax25_source_callsign: Some(frame.source_callsign.clone()),
                ax25_destination_callsign: Some(frame.destination_callsign.clone()),
                source_ssid: Some(frame.source_ssid),
                destination_ssid: Some(frame.destination_ssid),
                frame_type: Some(format!("{:?}", frame.frame_type)),
                pid: frame.pid,
                digipeaters: digis_opt,
            };
            insp.ax25_metadata = Some(ax25_meta);

            let mut insp_ev: DiagnosticEvent = insp.clone().into();
            insp_ev.transport = transport;
            insp_ev.payload_length = payload.len() as u64;
            insp_ev.source_endpoint = Some(src_endpoint.to_string());
            insp_ev.destination_endpoint = Some(primary_dest.to_string());
            event_buffer.emit(insp_ev);

            Some(ExtractedKiss {
                port: Some(port),
                command: Some(cmd),
                ax25_frame: Some(frame),
                inspection: Some(insp),
            })
        }
        Err(err) => {
            stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            if !kiss_cfg.passthrough_on_error {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                stats.drops_validation.fetch_add(1, Ordering::Relaxed);
                let drop_reason = format!("invalid AX.25 packet: {err}");
                eprintln!(
                    "[stream {}] Dropped invalid AX.25 {} packet: {}",
                    stream_id, transport, drop_reason
                );
                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Dropped,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_kiss_port(port)
                    .with_kiss_command(cmd)
                    .with_reason(drop_reason),
                );
                None
            } else {
                let fail_reason = format!("AX.25 validation failed (passthrough): {err}");
                eprintln!(
                    "[stream {}] AX.25 validation failed (passthrough): {}",
                    stream_id, fail_reason
                );
                event_buffer.emit(
                    DiagnosticEvent::new(
                        event_buffer.clock().monotonic_nanos(),
                        event_buffer.clock().wall_clock_nanos(),
                        stream_id,
                        DiagnosticStage::Failure,
                        transport,
                        payload.len() as u64,
                    )
                    .with_source(src_endpoint)
                    .with_destination(primary_dest)
                    .with_kiss_port(port)
                    .with_kiss_command(cmd)
                    .with_reason(fail_reason),
                );
                Some(ExtractedKiss {
                    port: Some(port),
                    command: Some(cmd),
                    ax25_frame: None,
                    inspection: None,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bpv7IngressContext<'a> {
    bpv7_cfg: Option<&'a Bpv7InspectionConfig>,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

#[derive(Debug, Clone, Default)]
struct ExtractedBpv7 {
    dest_eid: Option<String>,
    src_eid: Option<String>,
    dtn_timestamp: Option<u64>,
    lifetime: Option<u64>,
    status: Option<BundleParseStatus>,
    inspection: Option<BundleInspection>,
}

fn process_bpv7_ingress(payload: &[u8], ctx: &Bpv7IngressContext<'_>) -> ExtractedBpv7 {
    let Bpv7IngressContext {
        bpv7_cfg,
        event_buffer,
        stream_id,
        src_endpoint,
        primary_dest,
        transport,
    } = *ctx;

    let Some(bpv7_cfg) = bpv7_cfg else {
        return ExtractedBpv7::default();
    };
    if !bpv7_cfg.enabled {
        return ExtractedBpv7::default();
    }

    let max_bytes = bpv7_cfg.max_inspect_bytes;
    let inspect_data = if max_bytes > 0 && payload.len() > max_bytes {
        &payload[..max_bytes]
    } else {
        payload
    };

    let (status, maybe_primary) = evaluate_bundle_header(inspect_data);

    let (insp, extracted) = match maybe_primary {
        Some(primary) => {
            let mut insp = BundleInspection::from_primary_block(&primary, status);
            insp.stream_id = Some(stream_id.to_string());
            insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
            insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());

            let (dest, src) = if bpv7_cfg.extract_eids {
                (
                    Some(insp.destination_eid.clone()),
                    Some(insp.source_eid.clone()),
                )
            } else {
                insp.destination_eid.clear();
                insp.source_eid.clear();
                insp.destination = None;
                insp.source = None;
                insp.report_to_eid = None;
                if let Some(ref mut m) = insp.bundle_metadata {
                    m.destination.clear();
                    m.source.clear();
                    m.destination_eid = None;
                    m.source_eid = None;
                    m.report_to = None;
                }
                (None, None)
            };

            let ext = ExtractedBpv7 {
                dest_eid: dest,
                src_eid: src,
                dtn_timestamp: Some(insp.dtn_timestamp),
                lifetime: Some(insp.lifetime),
                status: Some(status),
                inspection: Some(insp.clone()),
            };
            (insp, ext)
        }
        None => {
            let mut insp = BundleInspection::new("", "", 0, 0, status);
            insp.stream_id = Some(stream_id.to_string());
            insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
            insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());
            insp.destination = None;
            insp.source = None;
            if let Some(ref mut m) = insp.bundle_metadata {
                m.destination_eid = None;
                m.source_eid = None;
                m.destination.clear();
                m.source.clear();
            }

            let ext = ExtractedBpv7 {
                dest_eid: None,
                src_eid: None,
                dtn_timestamp: None,
                lifetime: None,
                status: Some(status),
                inspection: Some(insp.clone()),
            };
            (insp, ext)
        }
    };

    let mut ev: DiagnosticEvent = insp.into();
    ev.transport = transport;
    ev.payload_length = payload.len() as u64;
    if !status.is_valid() {
        ev.source_endpoint = Some(src_endpoint.to_string());
        ev.destination_endpoint = Some(primary_dest.to_string());
        ev.bundle_destination = None;
        ev.bundle_source = None;
        ev.reason = Some(format!("unparsed traffic: {status}"));
    } else if !bpv7_cfg.extract_eids {
        ev.source_endpoint = Some(src_endpoint.to_string());
        ev.destination_endpoint = Some(primary_dest.to_string());
        ev.bundle_destination = None;
        ev.bundle_source = None;
    }

    event_buffer.emit(ev);

    extracted
}

#[derive(Debug, Clone, Copy)]
struct LtpIngressContext<'a> {
    ltp_cfg: Option<&'a LtpInspectionConfig>,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

#[derive(Debug, Clone, Default)]
struct ExtractedLtp {
    session_originator: Option<u64>,
    session_number: Option<u64>,
    segment_type: Option<SegmentType>,
    status: Option<LtpParseStatus>,
    inspection: Option<LtpInspection>,
}

fn process_ltp_ingress(payload: &[u8], ctx: &LtpIngressContext<'_>) -> ExtractedLtp {
    let LtpIngressContext {
        ltp_cfg,
        event_buffer,
        stream_id,
        src_endpoint,
        primary_dest,
        transport,
    } = *ctx;

    let Some(ltp_cfg) = ltp_cfg else {
        return ExtractedLtp::default();
    };
    if !ltp_cfg.enabled {
        return ExtractedLtp::default();
    }

    let max_bytes = ltp_cfg.max_inspect_bytes;
    let inspect_data = if max_bytes > 0 && payload.len() > max_bytes {
        &payload[..max_bytes]
    } else {
        payload
    };

    let (status, maybe_header) = evaluate_segment_header(inspect_data);

    let (ev, extracted) = match maybe_header {
        Some(header) => {
            let mut insp = LtpInspection::from_segment_header(&header, status);
            insp.stream_id = Some(stream_id.to_string());
            insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
            insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());

            let ext = ExtractedLtp {
                session_originator: Some(header.session_originator),
                session_number: Some(header.session_number),
                segment_type: Some(header.segment_type),
                status: Some(status),
                inspection: Some(insp.clone()),
            };

            let mut ev: DiagnosticEvent = insp.into();
            ev.transport = transport;
            ev.payload_length = payload.len() as u64;
            ev.source_endpoint = Some(src_endpoint.to_string());
            ev.destination_endpoint = Some(primary_dest.to_string());
            (ev, ext)
        }
        None => {
            let ext = ExtractedLtp {
                session_originator: None,
                session_number: None,
                segment_type: None,
                status: Some(status),
                inspection: None,
            };

            let mut ev = DiagnosticEvent::new(
                event_buffer.clock().monotonic_nanos(),
                event_buffer.clock().wall_clock_nanos(),
                stream_id,
                DiagnosticStage::LtpInspection,
                transport,
                payload.len() as u64,
            );
            ev.source_endpoint = Some(src_endpoint.to_string());
            ev.destination_endpoint = Some(primary_dest.to_string());
            ev.ltp_parse_status = Some(status);
            ev.reason = Some(format!("unparsed traffic: {status}"));
            (ev, ext)
        }
    };

    event_buffer.emit(ev);

    extracted
}

#[derive(Debug, Clone, Copy)]
struct SrtIngressContext<'a> {
    srt_cfg: Option<&'a SrtInspectionConfig>,
    event_buffer: &'a DiagnosticBuffer,
    stream_id: &'a str,
    src_endpoint: &'a str,
    primary_dest: &'a str,
    transport: TransportType,
}

#[derive(Debug, Clone, Default)]
struct ExtractedSrt {
    sequence_number: Option<u32>,
    status: Option<SrtParseStatus>,
    inspection: Option<SrtInspection>,
}

fn process_srt_ingress(payload: &[u8], ctx: &SrtIngressContext<'_>) -> ExtractedSrt {
    let SrtIngressContext {
        srt_cfg,
        event_buffer,
        stream_id,
        src_endpoint,
        primary_dest,
        transport,
    } = *ctx;

    let Some(srt_cfg) = srt_cfg else {
        return ExtractedSrt::default();
    };
    if !srt_cfg.enabled {
        return ExtractedSrt::default();
    }

    let max_bytes = srt_cfg.max_inspect_bytes;
    let inspect_data = if max_bytes > 0 && payload.len() > max_bytes {
        &payload[..max_bytes]
    } else {
        payload
    };

    let (status, maybe_header) = evaluate_srt_header(inspect_data);

    let (ev, extracted) = match maybe_header {
        Some(header) => {
            let mut insp = SrtInspection::from_header(&header, status);
            insp.stream_id = Some(stream_id.to_string());
            insp.monotonic_timestamp = Some(event_buffer.clock().monotonic_nanos());
            insp.wall_clock_timestamp = Some(event_buffer.clock().wall_clock_nanos());

            if !srt_cfg.extract_stream_id {
                insp.stream_id_extension = None;
                if let Some(ref mut m) = insp.srt_metadata {
                    m.stream_id = None;
                }
            }

            let ext = ExtractedSrt {
                sequence_number: header.sequence_number,
                status: Some(status),
                inspection: Some(insp.clone()),
            };

            let mut ev: DiagnosticEvent = insp.into();
            ev.transport = transport;
            ev.payload_length = payload.len() as u64;
            ev.source_endpoint = Some(src_endpoint.to_string());
            ev.destination_endpoint = Some(primary_dest.to_string());
            if let Some(seq) = header.sequence_number {
                ev.sequence_number = Some(seq as u64);
            }
            (ev, ext)
        }
        None => {
            let ext = ExtractedSrt {
                sequence_number: None,
                status: Some(status),
                inspection: None,
            };

            let mut ev = DiagnosticEvent::new(
                event_buffer.clock().monotonic_nanos(),
                event_buffer.clock().wall_clock_nanos(),
                stream_id,
                DiagnosticStage::SrtInspection,
                transport,
                payload.len() as u64,
            );
            ev.source_endpoint = Some(src_endpoint.to_string());
            ev.destination_endpoint = Some(primary_dest.to_string());
            ev.srt_parse_status = Some(status);
            ev.reason = Some(format!("unparsed traffic: {status}"));
            (ev, ext)
        }
    };

    event_buffer.emit(ev);

    extracted
}

/// Active forwarding runner for a single stream (UDP or TCP).
pub struct StreamRunner {
    pub stream_id: String,
    pub stats: Arc<StreamStats>,
    pub event_buffer: DiagnosticBuffer,
    pub mode: OperationalMode,
    pub source_transport: TransportType,
    pub sequence_tracker: Arc<Mutex<SequenceTracker>>,
    pub ccsds_tracker: Option<Arc<Mutex<CcsdsSequenceTracker>>>,
    pub mavlink_tracker: Option<Arc<Mutex<MavlinkSequenceTracker>>>,
    is_active: Arc<AtomicBool>,
    shutdown_flag: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl StreamRunner {
    /// Starts forwarding for a single stream across configured transports.
    ///
    /// # Errors
    /// Returns an error if the source socket cannot be bound or configured.
    pub fn start(
        stream: &StreamConfig,
        instance: &InstanceConfig,
        shutdown_flag: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let stream_prefix = format!("instance.{}.stream.{}", instance.id, stream.id);
        Self::start_with_path(stream, instance, shutdown_flag, &stream_prefix)
    }

    /// Starts forwarding for a single stream with explicit configuration path attribution.
    ///
    /// # Errors
    /// Returns an error if the source socket cannot be bound or configured, including
    /// the configuration path and interface name for unknown interface names.
    pub fn start_with_path(
        stream: &StreamConfig,
        instance: &InstanceConfig,
        shutdown_flag: Arc<AtomicBool>,
        stream_prefix: &str,
    ) -> io::Result<Self> {
        Self::start_with_buffer(
            stream,
            instance,
            shutdown_flag,
            stream_prefix,
            DiagnosticBuffer::new(1024),
        )
    }

    /// Starts forwarding for a single stream with a designated diagnostic event buffer.
    ///
    /// # Errors
    /// Returns an error if the source socket cannot be bound or configured.
    pub fn start_with_buffer(
        stream: &StreamConfig,
        instance: &InstanceConfig,
        shutdown_flag: Arc<AtomicBool>,
        stream_prefix: &str,
        event_buffer: DiagnosticBuffer,
    ) -> io::Result<Self> {
        let stream_id = stream.id.clone();
        let stats = Arc::new(StreamStats::default());
        let source_path = format!("{stream_prefix}.source.address");
        let mode = instance.mode;
        if event_buffer.test_state().is_none() {
            let correlation_id = instance.resolved_correlation_id().map(String::from);
            let expiry_seconds = instance.resolved_expiry_seconds();
            let max_events = instance.resolved_max_events();
            let prior_mode = instance.resolved_prior_mode();
            let test_state = Arc::new(DiagnosticTestState::new(
                instance.id.clone(),
                instance.mode,
                correlation_id,
                expiry_seconds,
                max_events,
                Some(prior_mode),
                event_buffer.clock().clone(),
            ));
            event_buffer.set_test_state(test_state);
        }
        let source_transport = stream.source.transport;

        // Resolve buffer limits (stream config overrides instance config overrides default)
        let max_queue_size = stream
            .buffer
            .as_ref()
            .and_then(|b| b.max_queue_size)
            .or_else(|| instance.buffer.as_ref().and_then(|b| b.max_queue_size))
            .unwrap_or(DEFAULT_MAX_QUEUE_SIZE);

        let max_packet_size = stream
            .buffer
            .as_ref()
            .and_then(|b| b.max_packet_size)
            .or_else(|| instance.buffer.as_ref().and_then(|b| b.max_packet_size))
            .unwrap_or(DEFAULT_MAX_PACKET_SIZE);

        let drop_policy = stream
            .buffer
            .as_ref()
            .and_then(|b| b.drop_policy)
            .or_else(|| instance.buffer.as_ref().and_then(|b| b.drop_policy))
            .unwrap_or(DEFAULT_DROP_POLICY);

        // Collect destination configurations with configuration paths
        let mut dest_specs: Vec<(EndpointConfig, String)> = Vec::new();
        if let Some(dest) = &stream.destination {
            dest_specs.push((dest.clone(), format!("{stream_prefix}.destination.address")));
        }
        if let Some(dests) = &stream.destinations {
            for (d_idx, dest) in dests.iter().enumerate() {
                dest_specs.push((
                    dest.clone(),
                    format!("{stream_prefix}.destinations[{d_idx}].address"),
                ));
            }
        }

        let primary_dest = dest_specs
            .first()
            .map(|(d, _)| format_endpoint(&d.address))
            .unwrap_or_default();

        // Shared bounded queue state
        let queue = Arc::new(Mutex::new(BoundedQueue::new(max_queue_size, drop_policy)));
        let condvar = Arc::new(Condvar::new());
        let receiver_done = Arc::new(AtomicBool::new(false));

        let seq_tracker = Arc::new(Mutex::new(SequenceTracker::new(
            &stream_id,
            stream.sequence.as_ref(),
            stream.inspection.as_ref(),
        )));

        let ccsds_tracker = stream.ccsds.as_ref().map(|c| {
            let mut t = CcsdsSequenceTracker::new(c.ignore_idle_apid);
            if let Some(ref apids) = c.filter_apids {
                t = t.with_allowed_apids(apids.clone());
            }
            Arc::new(Mutex::new(t))
        });

        let mavlink_tracker = stream.mavlink.as_ref().map(|m| {
            let t = MavlinkSequenceTracker::with_filters(
                m.filter_systems.clone(),
                m.filter_components.clone(),
            );
            Arc::new(Mutex::new(t))
        });

        let mut runner_threads = Vec::new();

        // -------------------------------------------------------------------
        // Source Ingress Setup (UDP or TCP)
        // -------------------------------------------------------------------
        match stream.source.transport {
            TransportType::Udp => {
                let bind_addr =
                    resolve_endpoint_with_context(&stream.source.address, Some(&source_path))?;
                let recv_socket = bind_udp_socket(bind_addr)?;
                recv_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

                let recv_stream_id = stream_id.clone();
                let recv_stats = Arc::clone(&stats);
                let recv_shutdown = Arc::clone(&shutdown_flag);
                let recv_queue = Arc::clone(&queue);
                let recv_condvar = Arc::clone(&condvar);
                let recv_done_flag = Arc::clone(&receiver_done);
                let recv_event_buffer = event_buffer.clone();
                let recv_primary_dest = primary_dest.clone();
                let recv_seq_tracker = Arc::clone(&seq_tracker);
                let recv_ccsds_tracker = ccsds_tracker.as_ref().map(Arc::clone);
                let recv_ccsds_config = stream.ccsds.clone();
                let recv_mavlink_tracker = mavlink_tracker.as_ref().map(Arc::clone);
                let recv_mavlink_config = stream.mavlink.clone();
                let recv_mqtt_config = stream.mqtt.clone();
                let recv_kiss_config = stream.kiss.clone();
                let recv_bpv7_config = stream.inspection.as_ref().and_then(|i| i.bpv7.clone());
                let recv_ltp_config = stream.inspection.as_ref().and_then(|i| i.ltp.clone());
                let recv_srt_config = stream.inspection.as_ref().and_then(|i| i.srt.clone());

                let recv_handle = thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];

                    while !recv_shutdown.load(Ordering::Relaxed) {
                        match recv_socket.recv_from(&mut buf) {
                            Ok((n, src_addr)) => {
                                recv_stats.received_packets.fetch_add(1, Ordering::Relaxed);
                                recv_stats
                                    .received_bytes
                                    .fetch_add(n as u64, Ordering::Relaxed);

                                let src_endpoint = src_addr.to_string();
                                let payload_slice = &buf[..n];

                                let Some(ccsds_info) = process_ccsds_ingress(
                                    payload_slice,
                                    &CcsdsIngressContext {
                                        ccsds_cfg: recv_ccsds_config.as_ref(),
                                        ccsds_tracker: recv_ccsds_tracker.as_ref(),
                                        stats: &recv_stats,
                                        event_buffer: &recv_event_buffer,
                                        stream_id: &recv_stream_id,
                                        src_endpoint: &src_endpoint,
                                        primary_dest: &recv_primary_dest,
                                        transport: TransportType::Udp,
                                    },
                                ) else {
                                    continue;
                                };

                                let Some(mavlink_info) = process_mavlink_ingress(
                                    payload_slice,
                                    &MavlinkIngressContext {
                                        mavlink_cfg: recv_mavlink_config.as_ref(),
                                        mavlink_tracker: recv_mavlink_tracker.as_ref(),
                                        stats: &recv_stats,
                                        event_buffer: &recv_event_buffer,
                                        stream_id: &recv_stream_id,
                                        src_endpoint: &src_endpoint,
                                        primary_dest: &recv_primary_dest,
                                        transport: TransportType::Udp,
                                    },
                                ) else {
                                    continue;
                                };

                                let Some(mqtt_info) = process_mqtt_ingress(
                                    payload_slice,
                                    &MqttIngressContext {
                                        mqtt_cfg: recv_mqtt_config.as_ref(),
                                        stats: &recv_stats,
                                        event_buffer: &recv_event_buffer,
                                        stream_id: &recv_stream_id,
                                        src_endpoint: &src_endpoint,
                                        primary_dest: &recv_primary_dest,
                                        transport: TransportType::Udp,
                                    },
                                ) else {
                                    continue;
                                };

                                let Some(kiss_info) = process_kiss_ingress(
                                    payload_slice,
                                    &KissIngressContext {
                                        kiss_cfg: recv_kiss_config.as_ref(),
                                        stats: &recv_stats,
                                        event_buffer: &recv_event_buffer,
                                        stream_id: &recv_stream_id,
                                        src_endpoint: &src_endpoint,
                                        primary_dest: &recv_primary_dest,
                                        transport: TransportType::Udp,
                                    },
                                ) else {
                                    continue;
                                };

                                let bpv7_info = process_bpv7_ingress(
                                    payload_slice,
                                    &Bpv7IngressContext {
                                        bpv7_cfg: recv_bpv7_config.as_ref(),
                                        event_buffer: &recv_event_buffer,
                                        stream_id: &recv_stream_id,
                                        src_endpoint: &src_endpoint,
                                        primary_dest: &recv_primary_dest,
                                        transport: TransportType::Udp,
                                    },
                                );

                                let ltp_info = process_ltp_ingress(
                                    payload_slice,
                                    &LtpIngressContext {
                                        ltp_cfg: recv_ltp_config.as_ref(),
                                        event_buffer: &recv_event_buffer,
                                        stream_id: &recv_stream_id,
                                        src_endpoint: &src_endpoint,
                                        primary_dest: &recv_primary_dest,
                                        transport: TransportType::Udp,
                                    },
                                );

                                let srt_info = process_srt_ingress(
                                    payload_slice,
                                    &SrtIngressContext {
                                        srt_cfg: recv_srt_config.as_ref(),
                                        event_buffer: &recv_event_buffer,
                                        stream_id: &recv_stream_id,
                                        src_endpoint: &src_endpoint,
                                        primary_dest: &recv_primary_dest,
                                        transport: TransportType::Udp,
                                    },
                                );

                                let (generic_seq, hex_prev, ascii_prev) = {
                                    let mut tracker = recv_seq_tracker.lock().unwrap();
                                    if tracker.is_enabled() {
                                        let _ = tracker.process_packet(payload_slice);
                                        let seq = tracker.extract_sequence(payload_slice);
                                        let (hex, ascii) = tracker.format_previews(payload_slice);
                                        (seq, hex, ascii)
                                    } else {
                                        let (hex, ascii) = tracker.format_previews(payload_slice);
                                        (None, hex, ascii)
                                    }
                                };

                                let extracted_seq = ccsds_info
                                    .seq
                                    .map(u64::from)
                                    .or(srt_info.sequence_number.map(u64::from))
                                    .or(mavlink_info.header.as_ref().map(|h| u64::from(h.sequence)))
                                    .or(generic_seq);
                                let extracted_apid = ccsds_info.apid;
                                let extracted_ccsds_seq = ccsds_info.seq;
                                let extracted_ccsds_flags = ccsds_info.flags;

                                let attach_diag = |mut ev: DiagnosticEvent| -> DiagnosticEvent {
                                    if let Some(s) = extracted_seq {
                                        ev = ev.with_sequence_number(s);
                                    }
                                    if let Some(a) = extracted_apid {
                                        ev = ev.with_apid(a);
                                    }
                                    if let Some(s) = extracted_ccsds_seq {
                                        ev = ev.with_ccsds_sequence(s);
                                    }
                                    if let Some(f) = extracted_ccsds_flags {
                                        ev = ev.with_ccsds_flags(f);
                                    }
                                    if let Some(ref header) = mavlink_info.header {
                                        ev = ev.with_mavlink_header(header);
                                    }
                                    if let Some(status) = mavlink_info.status {
                                        ev.mavlink_parse_status = Some(status);
                                    }
                                    if let Some(ref insp) = mavlink_info.inspection {
                                        ev.mavlink_inspection = Some(insp.clone());
                                    }
                                    if let Some(ref header) = mqtt_info.header {
                                        ev = ev.with_mqtt_header(header);
                                    }
                                    if let Some(status) = mqtt_info.status {
                                        ev.mqtt_parse_status = Some(status);
                                    }
                                    if let Some(ref insp) = mqtt_info.inspection {
                                        ev.mqtt_inspection = Some(insp.clone());
                                        if let Some(qos) = insp.qos {
                                            ev.mqtt_qos = Some(qos);
                                            if let Some(ref mut m) = ev.mqtt_metadata {
                                                m.qos = Some(qos);
                                            }
                                        }
                                        if let Some(pid) = insp.packet_identifier {
                                            ev.mqtt_packet_id = Some(pid);
                                            if let Some(ref mut m) = ev.mqtt_metadata {
                                                m.packet_identifier = Some(pid);
                                            }
                                        }
                                    }
                                    if let Some(ref d) = bpv7_info.dest_eid {
                                        ev.bundle_destination = Some(d.clone());
                                    }
                                    if let Some(ref s) = bpv7_info.src_eid {
                                        ev.bundle_source = Some(s.clone());
                                    }
                                    if let Some(ts) = bpv7_info.dtn_timestamp {
                                        ev.dtn_timestamp = Some(ts);
                                    }
                                    if let Some(lt) = bpv7_info.lifetime {
                                        ev.bundle_lifetime = Some(lt);
                                    }
                                    if let Some(st) = bpv7_info.status {
                                        ev.parse_status = Some(st);
                                    }
                                    if let Some(ref bi) = bpv7_info.inspection {
                                        ev.bundle_inspection = Some(bi.clone());
                                    }
                                    if let Some(orig) = ltp_info.session_originator {
                                        ev.session_originator = Some(orig);
                                    }
                                    if let Some(sess) = ltp_info.session_number {
                                        ev.session_number = Some(sess);
                                    }
                                    if let Some(st) = ltp_info.segment_type {
                                        ev.segment_type = Some(st);
                                    }
                                    if let Some(status) = ltp_info.status {
                                        ev.ltp_parse_status = Some(status);
                                    }
                                    if let Some(ref li) = ltp_info.inspection {
                                        ev.ltp_inspection = Some(li.clone());
                                        ev.ltp_metadata = li.ltp_metadata.clone();
                                    }
                                    if let Some(status) = srt_info.status {
                                        ev.srt_parse_status = Some(status);
                                    }
                                    if let Some(ref si) = srt_info.inspection {
                                        ev.srt_inspection = Some(si.clone());
                                        ev.srt_metadata = si.srt_metadata.clone();
                                        ev.srt_packet_kind = Some(si.packet_kind);
                                        ev.srt_packet_type = Some(si.packet_kind);
                                        ev.srt_control_type = si.control_type;
                                        ev.srt_sequence_number = si.sequence_number;
                                        ev.srt_timestamp = Some(si.timestamp);
                                        ev.srt_timestamp_us = Some(si.timestamp);
                                    }
                                    if let Some(ref insp) = kiss_info.inspection {
                                        ev = ev.with_kiss_inspection(insp.clone());
                                    } else {
                                        if let Some(port) = kiss_info.port {
                                            ev = ev.with_kiss_port(port);
                                        }
                                        if let Some(cmd) = kiss_info.command {
                                            ev = ev.with_kiss_command(cmd);
                                        }
                                        if let Some(ref ax25) = kiss_info.ax25_frame {
                                            ev = ev.with_ax25_frame(ax25);
                                        }
                                    }
                                    if let Some(ref h) = hex_prev {
                                        ev = ev.with_hex_preview(h);
                                    }
                                    if let Some(ref a) = ascii_prev {
                                        ev = ev.with_ascii_preview(a);
                                    }
                                    ev
                                };

                                if recv_event_buffer.should_emit_packet_events() {
                                    recv_event_buffer.emit(attach_diag(
                                        DiagnosticEvent::new(
                                            recv_event_buffer.clock().monotonic_nanos(),
                                            recv_event_buffer.clock().wall_clock_nanos(),
                                            &recv_stream_id,
                                            DiagnosticStage::Received,
                                            TransportType::Udp,
                                            n as u64,
                                        )
                                        .with_source(&src_endpoint)
                                        .with_destination(&recv_primary_dest),
                                    ));
                                }

                                if n > max_packet_size {
                                    recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                    recv_stats.drops_oversized.fetch_add(1, Ordering::Relaxed);
                                    eprintln!(
                                        "[stream {}] Dropped oversized datagram ({} bytes > max {})",
                                        recv_stream_id, n, max_packet_size
                                    );
                                    recv_event_buffer.emit(
                                        DiagnosticEvent::new(
                                            recv_event_buffer.clock().monotonic_nanos(),
                                            recv_event_buffer.clock().wall_clock_nanos(),
                                            &recv_stream_id,
                                            DiagnosticStage::Dropped,
                                            TransportType::Udp,
                                            n as u64,
                                        )
                                        .with_source(&src_endpoint)
                                        .with_destination(&recv_primary_dest)
                                        .with_reason(
                                            format!(
                                                "oversized datagram ({} bytes > max {})",
                                                n, max_packet_size
                                            ),
                                        ),
                                    );
                                    continue;
                                }

                                if recv_event_buffer.should_emit_packet_events() {
                                    recv_event_buffer.emit(attach_diag(
                                        DiagnosticEvent::new(
                                            recv_event_buffer.clock().monotonic_nanos(),
                                            recv_event_buffer.clock().wall_clock_nanos(),
                                            &recv_stream_id,
                                            DiagnosticStage::Accepted,
                                            TransportType::Udp,
                                            n as u64,
                                        )
                                        .with_source(&src_endpoint)
                                        .with_destination(&recv_primary_dest),
                                    ));
                                }

                                let datagram = Datagram {
                                    payload: buf[..n].to_vec(),
                                    source_addr: src_addr,
                                };

                                let push_result = {
                                    let mut q = recv_queue.lock().unwrap();
                                    let res = q.push(datagram);
                                    recv_stats
                                        .queue_depth
                                        .store(q.len() as u64, Ordering::Relaxed);
                                    res
                                };

                                match push_result {
                                    PushResult::Enqueued => {
                                        if recv_event_buffer.should_emit_packet_events() {
                                            recv_event_buffer.emit(
                                                DiagnosticEvent::new(
                                                    recv_event_buffer.clock().monotonic_nanos(),
                                                    recv_event_buffer.clock().wall_clock_nanos(),
                                                    &recv_stream_id,
                                                    DiagnosticStage::RoutedOrQueued,
                                                    TransportType::Udp,
                                                    n as u64,
                                                )
                                                .with_source(&src_endpoint)
                                                .with_destination(&recv_primary_dest),
                                            );
                                        }
                                        recv_condvar.notify_one();
                                    }
                                    PushResult::DroppedOldest => {
                                        recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                        recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                        recv_stats
                                            .backpressure_events
                                            .fetch_add(1, Ordering::Relaxed);
                                        recv_event_buffer.emit(
                                            DiagnosticEvent::new(
                                                recv_event_buffer.clock().monotonic_nanos(),
                                                recv_event_buffer.clock().wall_clock_nanos(),
                                                &recv_stream_id,
                                                DiagnosticStage::Dropped,
                                                TransportType::Udp,
                                                n as u64,
                                            )
                                            .with_source(&src_endpoint)
                                            .with_destination(&recv_primary_dest)
                                            .with_reason("queue full: drop_oldest policy"),
                                        );
                                    }
                                    PushResult::DroppedNewest => {
                                        recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                        recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                        recv_stats
                                            .backpressure_events
                                            .fetch_add(1, Ordering::Relaxed);
                                        recv_event_buffer.emit(
                                            DiagnosticEvent::new(
                                                recv_event_buffer.clock().monotonic_nanos(),
                                                recv_event_buffer.clock().wall_clock_nanos(),
                                                &recv_stream_id,
                                                DiagnosticStage::Dropped,
                                                TransportType::Udp,
                                                n as u64,
                                            )
                                            .with_source(&src_endpoint)
                                            .with_destination(&recv_primary_dest)
                                            .with_reason("queue full: drop_newest policy"),
                                        );
                                    }
                                    PushResult::Rejected => {
                                        recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                        recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                        recv_stats
                                            .backpressure_events
                                            .fetch_add(1, Ordering::Relaxed);
                                        recv_event_buffer.emit(
                                            DiagnosticEvent::new(
                                                recv_event_buffer.clock().monotonic_nanos(),
                                                recv_event_buffer.clock().wall_clock_nanos(),
                                                &recv_stream_id,
                                                DiagnosticStage::Dropped,
                                                TransportType::Udp,
                                                n as u64,
                                            )
                                            .with_source(&src_endpoint)
                                            .with_destination(&recv_primary_dest)
                                            .with_reason("queue full: reject policy"),
                                        );
                                    }
                                }
                            }
                            Err(ref e)
                                if e.kind() == io::ErrorKind::WouldBlock
                                    || e.kind() == io::ErrorKind::TimedOut =>
                            {
                                // Timeout, check shutdown flag
                            }
                            Err(e) => {
                                recv_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                eprintln!(
                                    "[stream {}] Socket receive error: {}",
                                    recv_stream_id, e
                                );
                                recv_event_buffer.emit(
                                    DiagnosticEvent::new(
                                        recv_event_buffer.clock().monotonic_nanos(),
                                        recv_event_buffer.clock().wall_clock_nanos(),
                                        &recv_stream_id,
                                        DiagnosticStage::Failure,
                                        TransportType::Udp,
                                        0,
                                    )
                                    .with_reason(format!("Socket receive error: {e}")),
                                );
                            }
                        }
                    }

                    recv_done_flag.store(true, Ordering::SeqCst);
                    recv_condvar.notify_all();
                });
                runner_threads.push(recv_handle);
            }
            TransportType::Tcp => {
                let mode_con = stream.source.mode.unwrap_or(ConnectionMode::Listen);
                let source_framing = stream.source_framing();
                let ccsds_tracker_for_tcp = ccsds_tracker.as_ref().map(Arc::clone);
                let ccsds_config_for_tcp = stream.ccsds.clone();
                let mavlink_tracker_for_tcp = mavlink_tracker.as_ref().map(Arc::clone);
                let mavlink_config_for_tcp = stream.mavlink.clone();
                let mqtt_config_for_tcp = stream.mqtt.clone();
                let kiss_config_for_tcp = stream.kiss.clone();
                let bpv7_config_for_tcp = stream.inspection.as_ref().and_then(|i| i.bpv7.clone());
                let ltp_config_for_tcp = stream.inspection.as_ref().and_then(|i| i.ltp.clone());
                let srt_config_for_tcp = stream.inspection.as_ref().and_then(|i| i.srt.clone());
                let recv_stream_id = stream_id.clone();
                let recv_stats = Arc::clone(&stats);
                let recv_shutdown = Arc::clone(&shutdown_flag);
                let recv_queue = Arc::clone(&queue);
                let recv_condvar = Arc::clone(&condvar);
                let recv_done_flag = Arc::clone(&receiver_done);
                let recv_event_buffer = event_buffer.clone();
                let recv_primary_dest = primary_dest.clone();

                let recv_seq_tracker = Arc::clone(&seq_tracker);

                match mode_con {
                    ConnectionMode::Listen => {
                        let bind_addr = resolve_endpoint_with_context(
                            &stream.source.address,
                            Some(&source_path),
                        )?;
                        let listener = bind_tcp_listener(bind_addr)?;
                        listener.set_nonblocking(true)?;

                        let recv_handle = thread::spawn(move || {
                            let mut client_threads = Vec::new();

                            while !recv_shutdown.load(Ordering::Relaxed) {
                                match listener.accept() {
                                    Ok((mut client_stream, client_addr)) => {
                                        let _ = client_stream
                                            .set_read_timeout(Some(Duration::from_millis(100)));
                                        let _ = client_stream.set_nodelay(true);

                                        let cl_stats = Arc::clone(&recv_stats);
                                        let cl_shutdown = Arc::clone(&recv_shutdown);
                                        let cl_queue = Arc::clone(&recv_queue);
                                        let cl_condvar = Arc::clone(&recv_condvar);
                                        let cl_event_buffer = recv_event_buffer.clone();
                                        let cl_stream_id = recv_stream_id.clone();
                                        let cl_primary_dest = recv_primary_dest.clone();
                                        let cl_seq_tracker = Arc::clone(&recv_seq_tracker);
                                        let cl_source_framing = source_framing;
                                        let cl_ccsds_tracker =
                                            ccsds_tracker_for_tcp.as_ref().map(Arc::clone);
                                        let cl_ccsds_config = ccsds_config_for_tcp.clone();
                                        let cl_mavlink_tracker =
                                            mavlink_tracker_for_tcp.as_ref().map(Arc::clone);
                                        let cl_mavlink_config = mavlink_config_for_tcp.clone();
                                        let cl_mqtt_config = mqtt_config_for_tcp.clone();
                                        let cl_kiss_config = kiss_config_for_tcp.clone();
                                        let cl_bpv7_config = bpv7_config_for_tcp.clone();
                                        let cl_ltp_config = ltp_config_for_tcp.clone();
                                        let cl_srt_config = srt_config_for_tcp.clone();

                                        let client_h = thread::spawn(move || {
                                            let src_endpoint = client_addr.to_string();
                                            while !cl_shutdown.load(Ordering::Relaxed) {
                                                match framing::read_frame_with_mode(
                                                    &mut client_stream,
                                                    cl_source_framing,
                                                    max_packet_size,
                                                    &cl_shutdown,
                                                ) {
                                                    Ok(Some(payload)) => {
                                                        let n = payload.len();
                                                        cl_stats
                                                            .received_packets
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        cl_stats
                                                            .received_bytes
                                                            .fetch_add(n as u64, Ordering::Relaxed);

                                                        let Some(ccsds_info) =
                                                            process_ccsds_ingress(
                                                                &payload,
                                                                &CcsdsIngressContext {
                                                                    ccsds_cfg: cl_ccsds_config
                                                                        .as_ref(),
                                                                    ccsds_tracker: cl_ccsds_tracker
                                                                        .as_ref(),
                                                                    stats: &cl_stats,
                                                                    event_buffer: &cl_event_buffer,
                                                                    stream_id: &cl_stream_id,
                                                                    src_endpoint: &src_endpoint,
                                                                    primary_dest: &cl_primary_dest,
                                                                    transport: TransportType::Tcp,
                                                                },
                                                            )
                                                        else {
                                                            continue;
                                                        };

                                                        let Some(mavlink_info) =
                                                            process_mavlink_ingress(
                                                                &payload,
                                                                &MavlinkIngressContext {
                                                                    mavlink_cfg: cl_mavlink_config
                                                                        .as_ref(),
                                                                    mavlink_tracker:
                                                                        cl_mavlink_tracker.as_ref(),
                                                                    stats: &cl_stats,
                                                                    event_buffer: &cl_event_buffer,
                                                                    stream_id: &cl_stream_id,
                                                                    src_endpoint: &src_endpoint,
                                                                    primary_dest: &cl_primary_dest,
                                                                    transport: TransportType::Tcp,
                                                                },
                                                            )
                                                        else {
                                                            continue;
                                                        };

                                                        let Some(mqtt_info) = process_mqtt_ingress(
                                                            &payload,
                                                            &MqttIngressContext {
                                                                mqtt_cfg: cl_mqtt_config.as_ref(),
                                                                stats: &cl_stats,
                                                                event_buffer: &cl_event_buffer,
                                                                stream_id: &cl_stream_id,
                                                                src_endpoint: &src_endpoint,
                                                                primary_dest: &cl_primary_dest,
                                                                transport: TransportType::Tcp,
                                                            },
                                                        ) else {
                                                            continue;
                                                        };

                                                        let Some(kiss_info) = process_kiss_ingress(
                                                            &payload,
                                                            &KissIngressContext {
                                                                kiss_cfg: cl_kiss_config.as_ref(),
                                                                stats: &cl_stats,
                                                                event_buffer: &cl_event_buffer,
                                                                stream_id: &cl_stream_id,
                                                                src_endpoint: &src_endpoint,
                                                                primary_dest: &cl_primary_dest,
                                                                transport: TransportType::Tcp,
                                                            },
                                                        ) else {
                                                            continue;
                                                        };

                                                        let bpv7_info = process_bpv7_ingress(
                                                            &payload,
                                                            &Bpv7IngressContext {
                                                                bpv7_cfg: cl_bpv7_config.as_ref(),
                                                                event_buffer: &cl_event_buffer,
                                                                stream_id: &cl_stream_id,
                                                                src_endpoint: &src_endpoint,
                                                                primary_dest: &cl_primary_dest,
                                                                transport: TransportType::Tcp,
                                                            },
                                                        );

                                                        let ltp_info = process_ltp_ingress(
                                                            &payload,
                                                            &LtpIngressContext {
                                                                ltp_cfg: cl_ltp_config.as_ref(),
                                                                event_buffer: &cl_event_buffer,
                                                                stream_id: &cl_stream_id,
                                                                src_endpoint: &src_endpoint,
                                                                primary_dest: &cl_primary_dest,
                                                                transport: TransportType::Tcp,
                                                            },
                                                        );

                                                        let srt_info = process_srt_ingress(
                                                            &payload,
                                                            &SrtIngressContext {
                                                                srt_cfg: cl_srt_config.as_ref(),
                                                                event_buffer: &cl_event_buffer,
                                                                stream_id: &cl_stream_id,
                                                                src_endpoint: &src_endpoint,
                                                                primary_dest: &cl_primary_dest,
                                                                transport: TransportType::Tcp,
                                                            },
                                                        );

                                                        let (generic_seq, hex_prev, ascii_prev) = {
                                                            let mut tracker =
                                                                cl_seq_tracker.lock().unwrap();
                                                            if tracker.is_enabled() {
                                                                let _ = tracker
                                                                    .process_packet(&payload);
                                                                let seq = tracker
                                                                    .extract_sequence(&payload);
                                                                let (hex, ascii) = tracker
                                                                    .format_previews(&payload);
                                                                (seq, hex, ascii)
                                                            } else {
                                                                let (hex, ascii) = tracker
                                                                    .format_previews(&payload);
                                                                (None, hex, ascii)
                                                            }
                                                        };

                                                        let extracted_seq = ccsds_info
                                                            .seq
                                                            .map(u64::from)
                                                            .or(srt_info
                                                                .sequence_number
                                                                .map(u64::from))
                                                            .or(mavlink_info
                                                                .header
                                                                .as_ref()
                                                                .map(|h| u64::from(h.sequence)))
                                                            .or(generic_seq);
                                                        let extracted_apid = ccsds_info.apid;
                                                        let extracted_ccsds_seq = ccsds_info.seq;
                                                        let extracted_ccsds_flags =
                                                            ccsds_info.flags;

                                                        let attach_diag = |mut ev: DiagnosticEvent| -> DiagnosticEvent {
                                                            if let Some(s) = extracted_seq {
                                                                ev = ev.with_sequence_number(s);
                                                            }
                                                            if let Some(a) = extracted_apid {
                                                                ev = ev.with_apid(a);
                                                            }
                                                            if let Some(s) = extracted_ccsds_seq {
                                                                ev = ev.with_ccsds_sequence(s);
                                                            }
                                                            if let Some(f) = extracted_ccsds_flags {
                                                                ev = ev.with_ccsds_flags(f);
                                                            }
                                                            if let Some(ref header) =
                                                                mavlink_info.header
                                                            {
                                                                ev = ev.with_mavlink_header(header);
                                                            }
                                                            if let Some(status) =
                                                                mavlink_info.status
                                                            {
                                                                ev.mavlink_parse_status =
                                                                    Some(status);
                                                            }
                                                            if let Some(ref insp) =
                                                                mavlink_info.inspection
                                                            {
                                                                ev.mavlink_inspection =
                                                                    Some(insp.clone());
                                                            }
                                                            if let Some(ref header) = mqtt_info.header {
                                                                ev = ev.with_mqtt_header(header);
                                                            }
                                                            if let Some(status) = mqtt_info.status {
                                                                ev.mqtt_parse_status = Some(status);
                                                            }
                                                            if let Some(ref insp) = mqtt_info.inspection {
                                                                ev.mqtt_inspection = Some(insp.clone());
                                                                if let Some(qos) = insp.qos {
                                                                    ev.mqtt_qos = Some(qos);
                                                                    if let Some(ref mut m) = ev.mqtt_metadata {
                                                                        m.qos = Some(qos);
                                                                    }
                                                                }
                                                                if let Some(pid) = insp.packet_identifier {
                                                                    ev.mqtt_packet_id = Some(pid);
                                                                    if let Some(ref mut m) = ev.mqtt_metadata {
                                                                        m.packet_identifier = Some(pid);
                                                                    }
                                                                }
                                                            }
                                                            if let Some(ref d) = bpv7_info.dest_eid {
                                                                ev.bundle_destination = Some(d.clone());
                                                            }
                                                            if let Some(ref s) = bpv7_info.src_eid {
                                                                ev.bundle_source = Some(s.clone());
                                                            }
                                                            if let Some(ts) = bpv7_info.dtn_timestamp {
                                                                ev.dtn_timestamp = Some(ts);
                                                            }
                                                            if let Some(lt) = bpv7_info.lifetime {
                                                                ev.bundle_lifetime = Some(lt);
                                                            }
                                                            if let Some(st) = bpv7_info.status {
                                                                ev.parse_status = Some(st);
                                                            }
                                                            if let Some(ref bi) = bpv7_info.inspection {
                                                                ev.bundle_inspection = Some(bi.clone());
                                                            }
                                                            if let Some(orig) = ltp_info.session_originator {
                                                                ev.session_originator = Some(orig);
                                                            }
                                                            if let Some(sess) = ltp_info.session_number {
                                                                ev.session_number = Some(sess);
                                                            }
                                                            if let Some(st) = ltp_info.segment_type {
                                                                ev.segment_type = Some(st);
                                                            }
                                                            if let Some(status) = ltp_info.status {
                                                                ev.ltp_parse_status = Some(status);
                                                            }
                                                            if let Some(ref li) = ltp_info.inspection {
                                                                ev.ltp_inspection = Some(li.clone());
                                                                ev.ltp_metadata = li.ltp_metadata.clone();
                                                            }
                                                            if let Some(status) = srt_info.status {
                                                                ev.srt_parse_status = Some(status);
                                                            }
                                                            if let Some(ref si) = srt_info.inspection {
                                                                ev.srt_inspection = Some(si.clone());
                                                                ev.srt_metadata = si.srt_metadata.clone();
                                                                ev.srt_packet_kind = Some(si.packet_kind);
                                                                ev.srt_packet_type = Some(si.packet_kind);
                                                                ev.srt_control_type = si.control_type;
                                                                ev.srt_sequence_number = si.sequence_number;
                                                                ev.srt_timestamp = Some(si.timestamp);
                                                                ev.srt_timestamp_us = Some(si.timestamp);
                                                            }
                                                            if let Some(ref insp) = kiss_info.inspection {
                                                                ev = ev.with_kiss_inspection(insp.clone());
                                                            } else {
                                                                if let Some(port) = kiss_info.port {
                                                                    ev = ev.with_kiss_port(port);
                                                                }
                                                                if let Some(cmd) = kiss_info.command {
                                                                    ev = ev.with_kiss_command(cmd);
                                                                }
                                                                if let Some(ref ax25) = kiss_info.ax25_frame {
                                                                    ev = ev.with_ax25_frame(ax25);
                                                                }
                                                            }
                                                            if let Some(ref h) = hex_prev {
                                                                ev = ev.with_hex_preview(h);
                                                            }
                                                            if let Some(ref a) = ascii_prev {
                                                                ev = ev.with_ascii_preview(a);
                                                            }
                                                            ev
                                                        };

                                                        if cl_event_buffer
                                                            .should_emit_packet_events()
                                                        {
                                                            cl_event_buffer.emit(attach_diag(
                                                                DiagnosticEvent::new(
                                                                    cl_event_buffer
                                                                        .clock()
                                                                        .monotonic_nanos(),
                                                                    cl_event_buffer
                                                                        .clock()
                                                                        .wall_clock_nanos(),
                                                                    &cl_stream_id,
                                                                    DiagnosticStage::Received,
                                                                    TransportType::Tcp,
                                                                    n as u64,
                                                                )
                                                                .with_source(&src_endpoint)
                                                                .with_destination(&cl_primary_dest),
                                                            ));
                                                            cl_event_buffer.emit(attach_diag(
                                                                DiagnosticEvent::new(
                                                                    cl_event_buffer
                                                                        .clock()
                                                                        .monotonic_nanos(),
                                                                    cl_event_buffer
                                                                        .clock()
                                                                        .wall_clock_nanos(),
                                                                    &cl_stream_id,
                                                                    DiagnosticStage::Accepted,
                                                                    TransportType::Tcp,
                                                                    n as u64,
                                                                )
                                                                .with_source(&src_endpoint)
                                                                .with_destination(&cl_primary_dest),
                                                            ));
                                                        }

                                                        let datagram = Datagram {
                                                            payload,
                                                            source_addr: client_addr,
                                                        };

                                                        let push_res = {
                                                            let mut q = cl_queue.lock().unwrap();
                                                            let res = q.push(datagram);
                                                            cl_stats.queue_depth.store(
                                                                q.len() as u64,
                                                                Ordering::Relaxed,
                                                            );
                                                            res
                                                        };

                                                        match push_res {
                                                            PushResult::Enqueued => {
                                                                if cl_event_buffer
                                                                    .should_emit_packet_events()
                                                                {
                                                                    cl_event_buffer.emit(
                                                                        DiagnosticEvent::new(
                                                                            cl_event_buffer.clock().monotonic_nanos(),
                                                                            cl_event_buffer.clock().wall_clock_nanos(),
                                                                            &cl_stream_id,
                                                                            DiagnosticStage::RoutedOrQueued,
                                                                            TransportType::Tcp,
                                                                            n as u64,
                                                                        )
                                                                        .with_source(&src_endpoint)
                                                                        .with_destination(&cl_primary_dest),
                                                                    );
                                                                }
                                                                cl_condvar.notify_one();
                                                            }
                                                            PushResult::DroppedOldest => {
                                                                cl_stats.dropped_packets.fetch_add(
                                                                    1,
                                                                    Ordering::Relaxed,
                                                                );
                                                                cl_stats
                                                                    .drops_queue_full
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                                cl_stats
                                                                    .backpressure_events
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                                cl_event_buffer.emit(
                                                                    DiagnosticEvent::new(
                                                                        cl_event_buffer.clock().monotonic_nanos(),
                                                                        cl_event_buffer.clock().wall_clock_nanos(),
                                                                        &cl_stream_id,
                                                                        DiagnosticStage::Dropped,
                                                                        TransportType::Tcp,
                                                                        n as u64,
                                                                    )
                                                                    .with_source(&src_endpoint)
                                                                    .with_destination(&cl_primary_dest)
                                                                    .with_reason("queue full: drop_oldest policy"),
                                                                );
                                                            }
                                                            PushResult::DroppedNewest => {
                                                                cl_stats.dropped_packets.fetch_add(
                                                                    1,
                                                                    Ordering::Relaxed,
                                                                );
                                                                cl_stats
                                                                    .drops_queue_full
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                                cl_stats
                                                                    .backpressure_events
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                                cl_event_buffer.emit(
                                                                    DiagnosticEvent::new(
                                                                        cl_event_buffer.clock().monotonic_nanos(),
                                                                        cl_event_buffer.clock().wall_clock_nanos(),
                                                                        &cl_stream_id,
                                                                        DiagnosticStage::Dropped,
                                                                        TransportType::Tcp,
                                                                        n as u64,
                                                                    )
                                                                    .with_source(&src_endpoint)
                                                                    .with_destination(&cl_primary_dest)
                                                                    .with_reason("queue full: drop_newest policy"),
                                                                );
                                                            }
                                                            PushResult::Rejected => {
                                                                cl_stats.dropped_packets.fetch_add(
                                                                    1,
                                                                    Ordering::Relaxed,
                                                                );
                                                                cl_stats
                                                                    .drops_queue_full
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                                cl_stats
                                                                    .backpressure_events
                                                                    .fetch_add(
                                                                        1,
                                                                        Ordering::Relaxed,
                                                                    );
                                                                cl_event_buffer.emit(
                                                                    DiagnosticEvent::new(
                                                                        cl_event_buffer
                                                                            .clock()
                                                                            .monotonic_nanos(),
                                                                        cl_event_buffer
                                                                            .clock()
                                                                            .wall_clock_nanos(),
                                                                        &cl_stream_id,
                                                                        DiagnosticStage::Dropped,
                                                                        TransportType::Tcp,
                                                                        n as u64,
                                                                    )
                                                                    .with_source(&src_endpoint)
                                                                    .with_destination(
                                                                        &cl_primary_dest,
                                                                    )
                                                                    .with_reason(
                                                                        "queue full: reject policy",
                                                                    ),
                                                                );
                                                            }
                                                        }
                                                    }
                                                    Ok(None) => break, // EOF
                                                    Err(ref e)
                                                        if e.kind()
                                                            == io::ErrorKind::InvalidData =>
                                                    {
                                                        cl_stats
                                                            .dropped_packets
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        cl_stats
                                                            .drops_oversized
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        cl_event_buffer.emit(
                                                            DiagnosticEvent::new(
                                                                cl_event_buffer.clock().monotonic_nanos(),
                                                                cl_event_buffer.clock().wall_clock_nanos(),
                                                                &cl_stream_id,
                                                                DiagnosticStage::Dropped,
                                                                TransportType::Tcp,
                                                                0,
                                                            )
                                                            .with_source(&src_endpoint)
                                                            .with_destination(&cl_primary_dest)
                                                            .with_reason(format!(
                                                                "Dropped oversized frame (> max {max_packet_size})"
                                                            )),
                                                        );
                                                        break;
                                                    }
                                                    Err(e) => {
                                                        cl_stats
                                                            .socket_errors
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        cl_event_buffer.emit(
                                                            DiagnosticEvent::new(
                                                                cl_event_buffer
                                                                    .clock()
                                                                    .monotonic_nanos(),
                                                                cl_event_buffer
                                                                    .clock()
                                                                    .wall_clock_nanos(),
                                                                &cl_stream_id,
                                                                DiagnosticStage::Failure,
                                                                TransportType::Tcp,
                                                                0,
                                                            )
                                                            .with_source(&src_endpoint)
                                                            .with_reason(format!(
                                                                "TCP frame read error: {e}"
                                                            )),
                                                        );
                                                        break;
                                                    }
                                                }
                                            }
                                        });
                                        client_threads.push(client_h);
                                    }
                                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                        thread::sleep(Duration::from_millis(10));
                                    }
                                    Err(e) => {
                                        recv_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                        thread::sleep(Duration::from_millis(10));
                                        eprintln!(
                                            "[stream {}] TCP accept error: {}",
                                            recv_stream_id, e
                                        );
                                        recv_event_buffer.emit(
                                            DiagnosticEvent::new(
                                                recv_event_buffer.clock().monotonic_nanos(),
                                                recv_event_buffer.clock().wall_clock_nanos(),
                                                &recv_stream_id,
                                                DiagnosticStage::Failure,
                                                TransportType::Tcp,
                                                0,
                                            )
                                            .with_reason(format!("TCP accept error: {e}")),
                                        );
                                    }
                                }
                            }

                            for h in client_threads {
                                let _ = h.join();
                            }

                            recv_done_flag.store(true, Ordering::SeqCst);
                            recv_condvar.notify_all();
                        });
                        runner_threads.push(recv_handle);
                    }
                    ConnectionMode::Connect => {
                        if stream.source.address.contains('%') {
                            let _ = resolve_endpoint_with_context(
                                &stream.source.address,
                                Some(&source_path),
                            )?;
                        }
                        let target_addr_str = stream.source.address.clone();
                        let target_source_path = source_path.clone();
                        let conn_seq_tracker = Arc::clone(&recv_seq_tracker);
                        let conn_bpv7_config = bpv7_config_for_tcp.clone();
                        let conn_ltp_config = ltp_config_for_tcp.clone();
                        let conn_srt_config = srt_config_for_tcp.clone();
                        let conn_mavlink_config = mavlink_config_for_tcp.clone();
                        let conn_mavlink_tracker = mavlink_tracker_for_tcp.as_ref().map(Arc::clone);
                        let conn_mqtt_config = mqtt_config_for_tcp.clone();
                        let conn_kiss_config = kiss_config_for_tcp.clone();
                        let recv_handle = thread::spawn(move || {
                            let mut backoff = Duration::from_millis(50);
                            let max_backoff = Duration::from_millis(1000);

                            while !recv_shutdown.load(Ordering::Relaxed) {
                                let target_addr = match resolve_endpoint_with_context(
                                    &target_addr_str,
                                    Some(&target_source_path),
                                ) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        recv_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                        recv_event_buffer.emit(
                                            DiagnosticEvent::new(
                                                recv_event_buffer.clock().monotonic_nanos(),
                                                recv_event_buffer.clock().wall_clock_nanos(),
                                                &recv_stream_id,
                                                DiagnosticStage::Failure,
                                                TransportType::Tcp,
                                                0,
                                            )
                                            .with_destination(&target_addr_str)
                                            .with_reason(format!(
                                                "Address resolution error for TCP source '{target_source_path}' ('{target_addr_str}'): {e}"
                                            )),
                                        );
                                        thread::sleep(backoff);
                                        continue;
                                    }
                                };

                                match TcpStream::connect_timeout(
                                    &target_addr,
                                    Duration::from_millis(500),
                                ) {
                                    Ok(mut stream) => {
                                        let _ = stream
                                            .set_read_timeout(Some(Duration::from_millis(100)));
                                        let _ = stream.set_nodelay(true);
                                        backoff = Duration::from_millis(50);
                                        let src_endpoint = target_addr.to_string();

                                        while !recv_shutdown.load(Ordering::Relaxed) {
                                            match framing::read_frame_with_mode(
                                                &mut stream,
                                                source_framing,
                                                max_packet_size,
                                                &recv_shutdown,
                                            ) {
                                                Ok(Some(payload)) => {
                                                    let n = payload.len();
                                                    recv_stats
                                                        .received_packets
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    recv_stats
                                                        .received_bytes
                                                        .fetch_add(n as u64, Ordering::Relaxed);

                                                    let Some(ccsds_info) = process_ccsds_ingress(
                                                        &payload,
                                                        &CcsdsIngressContext {
                                                            ccsds_cfg: ccsds_config_for_tcp
                                                                .as_ref(),
                                                            ccsds_tracker: ccsds_tracker_for_tcp
                                                                .as_ref(),
                                                            stats: &recv_stats,
                                                            event_buffer: &recv_event_buffer,
                                                            stream_id: &recv_stream_id,
                                                            src_endpoint: &src_endpoint,
                                                            primary_dest: &recv_primary_dest,
                                                            transport: TransportType::Tcp,
                                                        },
                                                    ) else {
                                                        continue;
                                                    };

                                                    let Some(mavlink_info) =
                                                        process_mavlink_ingress(
                                                            &payload,
                                                            &MavlinkIngressContext {
                                                                mavlink_cfg: conn_mavlink_config
                                                                    .as_ref(),
                                                                mavlink_tracker:
                                                                    conn_mavlink_tracker.as_ref(),
                                                                stats: &recv_stats,
                                                                event_buffer: &recv_event_buffer,
                                                                stream_id: &recv_stream_id,
                                                                src_endpoint: &src_endpoint,
                                                                primary_dest: &recv_primary_dest,
                                                                transport: TransportType::Tcp,
                                                            },
                                                        )
                                                    else {
                                                        continue;
                                                    };

                                                    let Some(mqtt_info) = process_mqtt_ingress(
                                                        &payload,
                                                        &MqttIngressContext {
                                                            mqtt_cfg: conn_mqtt_config.as_ref(),
                                                            stats: &recv_stats,
                                                            event_buffer: &recv_event_buffer,
                                                            stream_id: &recv_stream_id,
                                                            src_endpoint: &src_endpoint,
                                                            primary_dest: &recv_primary_dest,
                                                            transport: TransportType::Tcp,
                                                        },
                                                    ) else {
                                                        continue;
                                                    };

                                                    let Some(kiss_info) = process_kiss_ingress(
                                                        &payload,
                                                        &KissIngressContext {
                                                            kiss_cfg: conn_kiss_config.as_ref(),
                                                            stats: &recv_stats,
                                                            event_buffer: &recv_event_buffer,
                                                            stream_id: &recv_stream_id,
                                                            src_endpoint: &src_endpoint,
                                                            primary_dest: &recv_primary_dest,
                                                            transport: TransportType::Tcp,
                                                        },
                                                    ) else {
                                                        continue;
                                                    };

                                                    let bpv7_info = process_bpv7_ingress(
                                                        &payload,
                                                        &Bpv7IngressContext {
                                                            bpv7_cfg: conn_bpv7_config.as_ref(),
                                                            event_buffer: &recv_event_buffer,
                                                            stream_id: &recv_stream_id,
                                                            src_endpoint: &src_endpoint,
                                                            primary_dest: &recv_primary_dest,
                                                            transport: TransportType::Tcp,
                                                        },
                                                    );

                                                    let ltp_info = process_ltp_ingress(
                                                        &payload,
                                                        &LtpIngressContext {
                                                            ltp_cfg: conn_ltp_config.as_ref(),
                                                            event_buffer: &recv_event_buffer,
                                                            stream_id: &recv_stream_id,
                                                            src_endpoint: &src_endpoint,
                                                            primary_dest: &recv_primary_dest,
                                                            transport: TransportType::Tcp,
                                                        },
                                                    );

                                                    let srt_info = process_srt_ingress(
                                                        &payload,
                                                        &SrtIngressContext {
                                                            srt_cfg: conn_srt_config.as_ref(),
                                                            event_buffer: &recv_event_buffer,
                                                            stream_id: &recv_stream_id,
                                                            src_endpoint: &src_endpoint,
                                                            primary_dest: &recv_primary_dest,
                                                            transport: TransportType::Tcp,
                                                        },
                                                    );

                                                    let (generic_seq, hex_prev, ascii_prev) = {
                                                        let mut tracker =
                                                            conn_seq_tracker.lock().unwrap();
                                                        if tracker.is_enabled() {
                                                            let _ =
                                                                tracker.process_packet(&payload);
                                                            let seq =
                                                                tracker.extract_sequence(&payload);
                                                            let (hex, ascii) =
                                                                tracker.format_previews(&payload);
                                                            (seq, hex, ascii)
                                                        } else {
                                                            let (hex, ascii) =
                                                                tracker.format_previews(&payload);
                                                            (None, hex, ascii)
                                                        }
                                                    };

                                                    let extracted_seq = ccsds_info
                                                        .seq
                                                        .map(u64::from)
                                                        .or(srt_info.sequence_number.map(u64::from))
                                                        .or(mavlink_info
                                                            .header
                                                            .as_ref()
                                                            .map(|h| u64::from(h.sequence)))
                                                        .or(generic_seq);
                                                    let extracted_apid = ccsds_info.apid;
                                                    let extracted_ccsds_seq = ccsds_info.seq;
                                                    let extracted_ccsds_flags = ccsds_info.flags;

                                                    let attach_diag = |mut ev: DiagnosticEvent| -> DiagnosticEvent {
                                                        if let Some(s) = extracted_seq {
                                                            ev = ev.with_sequence_number(s);
                                                        }
                                                        if let Some(a) = extracted_apid {
                                                            ev = ev.with_apid(a);
                                                        }
                                                        if let Some(s) = extracted_ccsds_seq {
                                                            ev = ev.with_ccsds_sequence(s);
                                                        }
                                                        if let Some(f) = extracted_ccsds_flags {
                                                            ev = ev.with_ccsds_flags(f);
                                                        }
                                                        if let Some(ref header) = mavlink_info.header {
                                                            ev = ev.with_mavlink_header(header);
                                                        }
                                                        if let Some(status) = mavlink_info.status {
                                                            ev.mavlink_parse_status = Some(status);
                                                        }
                                                        if let Some(ref insp) = mavlink_info.inspection {
                                                            ev.mavlink_inspection = Some(insp.clone());
                                                        }
                                                        if let Some(ref header) = mqtt_info.header {
                                                            ev = ev.with_mqtt_header(header);
                                                        }
                                                        if let Some(status) = mqtt_info.status {
                                                            ev.mqtt_parse_status = Some(status);
                                                        }
                                                        if let Some(ref insp) = mqtt_info.inspection {
                                                            ev.mqtt_inspection = Some(insp.clone());
                                                            if let Some(qos) = insp.qos {
                                                                ev.mqtt_qos = Some(qos);
                                                                if let Some(ref mut m) = ev.mqtt_metadata {
                                                                    m.qos = Some(qos);
                                                                }
                                                            }
                                                            if let Some(pid) = insp.packet_identifier {
                                                                ev.mqtt_packet_id = Some(pid);
                                                                if let Some(ref mut m) = ev.mqtt_metadata {
                                                                    m.packet_identifier = Some(pid);
                                                                }
                                                            }
                                                        }
                                                        if let Some(ref d) = bpv7_info.dest_eid {
                                                            ev.bundle_destination = Some(d.clone());
                                                        }
                                                        if let Some(ref s) = bpv7_info.src_eid {
                                                            ev.bundle_source = Some(s.clone());
                                                        }
                                                        if let Some(ts) = bpv7_info.dtn_timestamp {
                                                            ev.dtn_timestamp = Some(ts);
                                                        }
                                                        if let Some(lt) = bpv7_info.lifetime {
                                                            ev.bundle_lifetime = Some(lt);
                                                        }
                                                        if let Some(st) = bpv7_info.status {
                                                            ev.parse_status = Some(st);
                                                        }
                                                        if let Some(ref bi) = bpv7_info.inspection {
                                                            ev.bundle_inspection = Some(bi.clone());
                                                        }
                                                        if let Some(orig) = ltp_info.session_originator {
                                                            ev.session_originator = Some(orig);
                                                        }
                                                        if let Some(sess) = ltp_info.session_number {
                                                            ev.session_number = Some(sess);
                                                        }
                                                        if let Some(st) = ltp_info.segment_type {
                                                            ev.segment_type = Some(st);
                                                        }
                                                        if let Some(status) = ltp_info.status {
                                                            ev.ltp_parse_status = Some(status);
                                                        }
                                                        if let Some(ref li) = ltp_info.inspection {
                                                            ev.ltp_inspection = Some(li.clone());
                                                            ev.ltp_metadata = li.ltp_metadata.clone();
                                                        }
                                                        if let Some(status) = srt_info.status {
                                                            ev.srt_parse_status = Some(status);
                                                        }
                                                        if let Some(ref si) = srt_info.inspection {
                                                            ev.srt_inspection = Some(si.clone());
                                                            ev.srt_metadata = si.srt_metadata.clone();
                                                            ev.srt_packet_kind = Some(si.packet_kind);
                                                            ev.srt_packet_type = Some(si.packet_kind);
                                                            ev.srt_control_type = si.control_type;
                                                            ev.srt_sequence_number = si.sequence_number;
                                                            ev.srt_timestamp = Some(si.timestamp);
                                                            ev.srt_timestamp_us = Some(si.timestamp);
                                                        }
                                                        if let Some(ref insp) = kiss_info.inspection {
                                                            ev = ev.with_kiss_inspection(insp.clone());
                                                        } else {
                                                            if let Some(port) = kiss_info.port {
                                                                ev = ev.with_kiss_port(port);
                                                            }
                                                            if let Some(cmd) = kiss_info.command {
                                                                ev = ev.with_kiss_command(cmd);
                                                            }
                                                            if let Some(ref ax25) = kiss_info.ax25_frame {
                                                                ev = ev.with_ax25_frame(ax25);
                                                            }
                                                        }
                                                        if let Some(ref h) = hex_prev {
                                                            ev = ev.with_hex_preview(h);
                                                        }
                                                        if let Some(ref a) = ascii_prev {
                                                            ev = ev.with_ascii_preview(a);
                                                        }
                                                        ev
                                                    };

                                                    if recv_event_buffer.should_emit_packet_events()
                                                    {
                                                        recv_event_buffer.emit(attach_diag(
                                                            DiagnosticEvent::new(
                                                                recv_event_buffer
                                                                    .clock()
                                                                    .monotonic_nanos(),
                                                                recv_event_buffer
                                                                    .clock()
                                                                    .wall_clock_nanos(),
                                                                &recv_stream_id,
                                                                DiagnosticStage::Received,
                                                                TransportType::Tcp,
                                                                n as u64,
                                                            )
                                                            .with_source(&src_endpoint)
                                                            .with_destination(&recv_primary_dest),
                                                        ));
                                                        recv_event_buffer.emit(attach_diag(
                                                            DiagnosticEvent::new(
                                                                recv_event_buffer
                                                                    .clock()
                                                                    .monotonic_nanos(),
                                                                recv_event_buffer
                                                                    .clock()
                                                                    .wall_clock_nanos(),
                                                                &recv_stream_id,
                                                                DiagnosticStage::Accepted,
                                                                TransportType::Tcp,
                                                                n as u64,
                                                            )
                                                            .with_source(&src_endpoint)
                                                            .with_destination(&recv_primary_dest),
                                                        ));
                                                    }

                                                    let datagram = Datagram {
                                                        payload,
                                                        source_addr: target_addr,
                                                    };

                                                    let push_res = {
                                                        let mut q = recv_queue.lock().unwrap();
                                                        let res = q.push(datagram);
                                                        recv_stats.queue_depth.store(
                                                            q.len() as u64,
                                                            Ordering::Relaxed,
                                                        );
                                                        res
                                                    };

                                                    match push_res {
                                                        PushResult::Enqueued => {
                                                            if recv_event_buffer
                                                                .should_emit_packet_events()
                                                            {
                                                                recv_event_buffer.emit(
                                                                    DiagnosticEvent::new(
                                                                        recv_event_buffer.clock().monotonic_nanos(),
                                                                        recv_event_buffer.clock().wall_clock_nanos(),
                                                                        &recv_stream_id,
                                                                        DiagnosticStage::RoutedOrQueued,
                                                                        TransportType::Tcp,
                                                                        n as u64,
                                                                    )
                                                                    .with_source(&src_endpoint)
                                                                    .with_destination(&recv_primary_dest),
                                                                );
                                                            }
                                                            recv_condvar.notify_one();
                                                        }
                                                        PushResult::DroppedOldest => {
                                                            recv_stats
                                                                .dropped_packets
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .drops_queue_full
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .backpressure_events
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_event_buffer.emit(
                                                                DiagnosticEvent::new(
                                                                    recv_event_buffer.clock().monotonic_nanos(),
                                                                    recv_event_buffer.clock().wall_clock_nanos(),
                                                                    &recv_stream_id,
                                                                    DiagnosticStage::Dropped,
                                                                    TransportType::Tcp,
                                                                    n as u64,
                                                                )
                                                                .with_source(&src_endpoint)
                                                                .with_destination(&recv_primary_dest)
                                                                .with_reason("queue full: drop_oldest policy"),
                                                            );
                                                        }
                                                        PushResult::DroppedNewest => {
                                                            recv_stats
                                                                .dropped_packets
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .drops_queue_full
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .backpressure_events
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_event_buffer.emit(
                                                                DiagnosticEvent::new(
                                                                    recv_event_buffer.clock().monotonic_nanos(),
                                                                    recv_event_buffer.clock().wall_clock_nanos(),
                                                                    &recv_stream_id,
                                                                    DiagnosticStage::Dropped,
                                                                    TransportType::Tcp,
                                                                    n as u64,
                                                                )
                                                                .with_source(&src_endpoint)
                                                                .with_destination(&recv_primary_dest)
                                                                .with_reason("queue full: drop_newest policy"),
                                                            );
                                                        }
                                                        PushResult::Rejected => {
                                                            recv_stats
                                                                .dropped_packets
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .drops_queue_full
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .backpressure_events
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_event_buffer.emit(
                                                                DiagnosticEvent::new(
                                                                    recv_event_buffer
                                                                        .clock()
                                                                        .monotonic_nanos(),
                                                                    recv_event_buffer
                                                                        .clock()
                                                                        .wall_clock_nanos(),
                                                                    &recv_stream_id,
                                                                    DiagnosticStage::Dropped,
                                                                    TransportType::Tcp,
                                                                    n as u64,
                                                                )
                                                                .with_source(&src_endpoint)
                                                                .with_destination(
                                                                    &recv_primary_dest,
                                                                )
                                                                .with_reason(
                                                                    "queue full: reject policy",
                                                                ),
                                                            );
                                                        }
                                                    }
                                                }
                                                Ok(None) => break,
                                                Err(ref e)
                                                    if e.kind() == io::ErrorKind::InvalidData =>
                                                {
                                                    recv_stats
                                                        .dropped_packets
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    recv_stats
                                                        .drops_oversized
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    recv_event_buffer.emit(
                                                        DiagnosticEvent::new(
                                                            recv_event_buffer.clock().monotonic_nanos(),
                                                            recv_event_buffer.clock().wall_clock_nanos(),
                                                            &recv_stream_id,
                                                            DiagnosticStage::Dropped,
                                                            TransportType::Tcp,
                                                            0,
                                                        )
                                                        .with_source(&src_endpoint)
                                                        .with_destination(&recv_primary_dest)
                                                        .with_reason(format!(
                                                            "Dropped oversized frame (> max {max_packet_size})"
                                                        )),
                                                    );
                                                    break;
                                                }
                                                Err(e) => {
                                                    recv_stats
                                                        .socket_errors
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    recv_event_buffer.emit(
                                                        DiagnosticEvent::new(
                                                            recv_event_buffer
                                                                .clock()
                                                                .monotonic_nanos(),
                                                            recv_event_buffer
                                                                .clock()
                                                                .wall_clock_nanos(),
                                                            &recv_stream_id,
                                                            DiagnosticStage::Failure,
                                                            TransportType::Tcp,
                                                            0,
                                                        )
                                                        .with_source(&src_endpoint)
                                                        .with_reason(format!(
                                                            "TCP frame read error: {e}"
                                                        )),
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        recv_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                        recv_event_buffer.emit(
                                            DiagnosticEvent::new(
                                                recv_event_buffer.clock().monotonic_nanos(),
                                                recv_event_buffer.clock().wall_clock_nanos(),
                                                &recv_stream_id,
                                                DiagnosticStage::Failure,
                                                TransportType::Tcp,
                                                0,
                                            )
                                            .with_destination(target_addr.to_string())
                                            .with_reason(format!(
                                                "Connect error to TCP source {target_addr}: {e}"
                                            )),
                                        );
                                        let sleep_dur = backoff;
                                        backoff = (backoff * 2).min(max_backoff);
                                        let start = Instant::now();
                                        while start.elapsed() < sleep_dur
                                            && !recv_shutdown.load(Ordering::Relaxed)
                                        {
                                            thread::sleep(Duration::from_millis(5));
                                        }
                                    }
                                }
                            }

                            recv_done_flag.store(true, Ordering::SeqCst);
                            recv_condvar.notify_all();
                        });
                        runner_threads.push(recv_handle);
                    }
                }
            }
        }

        // -------------------------------------------------------------------
        // Egress Forwarder Setup (UDP and TCP destinations)
        // -------------------------------------------------------------------
        let fwd_stream_id = stream_id.clone();
        let fwd_stats = Arc::clone(&stats);
        let fwd_shutdown = Arc::clone(&shutdown_flag);
        let fwd_queue = Arc::clone(&queue);
        let fwd_condvar = Arc::clone(&condvar);
        let fwd_done_flag = Arc::clone(&receiver_done);
        let fwd_event_buffer = event_buffer.clone();
        let is_active = Arc::new(AtomicBool::new(true));
        let fwd_is_active = Arc::clone(&is_active);
        let fwd_stream_framing = stream.framing;
        let fwd_stream_ccsds_framing = stream.ccsds.as_ref().and_then(|c| c.framing);
        let fwd_stream_mavlink_framing = stream.mavlink.as_ref().and_then(|m| m.framing);
        let fwd_stream_mqtt = stream.mqtt.clone();
        let fwd_stream_mqtt_framing = stream.mqtt.as_ref().and_then(|m| m.framing);
        let fwd_stream_kiss = stream.kiss.clone();
        let fwd_stream_kiss_framing = stream.kiss.as_ref().and_then(|k| k.framing);

        let fwd_handle = thread::spawn(move || {
            let ipv4_socket = bind_udp_socket(SocketAddr::from(([0, 0, 0, 0], 0))).ok();
            let ipv6_socket = bind_udp_socket(SocketAddr::from(([0; 16], 0))).ok();

            // Track TCP destination connections
            let mut tcp_conns: Vec<Option<TcpDestinationConnection>> = dest_specs
                .iter()
                .map(|(d, path)| {
                    if d.transport == TransportType::Tcp {
                        let framing = d
                            .framing
                            .or(fwd_stream_framing)
                            .or(fwd_stream_ccsds_framing)
                            .or(fwd_stream_mavlink_framing)
                            .or(fwd_stream_mqtt_framing)
                            .or(fwd_stream_kiss_framing)
                            .unwrap_or_default();
                        Some(TcpDestinationConnection::new(
                            d.address.clone(),
                            path.clone(),
                            fwd_stream_id.clone(),
                            fwd_event_buffer.clone(),
                            framing,
                        ))
                    } else {
                        None
                    }
                })
                .collect();

            let is_single_tcp_dest =
                dest_specs.len() == 1 && dest_specs[0].0.transport == TransportType::Tcp;

            let mut held_datagram: Option<Datagram> = None;

            loop {
                // If single TCP destination and not connected, attempt connect with backoff
                if is_single_tcp_dest {
                    if let Some(Some(ref mut conn)) = tcp_conns.first_mut() {
                        while conn.stream.is_none() && !fwd_shutdown.load(Ordering::Relaxed) {
                            if conn.try_connect(&fwd_stats) {
                                break;
                            }
                            // Sleep for backoff duration, interruptible by shutdown
                            let sleep_dur = conn.backoff;
                            let start = Instant::now();
                            while start.elapsed() < sleep_dur
                                && !fwd_shutdown.load(Ordering::Relaxed)
                            {
                                thread::sleep(Duration::from_millis(5));
                            }
                        }
                    }
                }

                // Retrieve next datagram if not holding one from retry
                if held_datagram.is_none() {
                    let mut q = fwd_queue.lock().unwrap();
                    while q.is_empty() {
                        if fwd_shutdown.load(Ordering::Relaxed)
                            && fwd_done_flag.load(Ordering::Relaxed)
                        {
                            break;
                        }
                        let (new_q, timeout_result) = fwd_condvar
                            .wait_timeout(q, Duration::from_millis(100))
                            .unwrap();
                        q = new_q;
                        if timeout_result.timed_out()
                            && fwd_shutdown.load(Ordering::Relaxed)
                            && fwd_done_flag.load(Ordering::Relaxed)
                        {
                            break;
                        }
                    }
                    held_datagram = q.pop();
                    fwd_stats
                        .queue_depth
                        .store(q.len() as u64, Ordering::Relaxed);
                }

                match held_datagram.take() {
                    Some(datagram) => {
                        let mut all_succeeded = true;
                        let src_addr_str = datagram.source_addr.to_string();
                        let payload_len = datagram.payload.len() as u64;

                        for (idx, (dest, dest_path)) in dest_specs.iter().enumerate() {
                            let dest_addr_str = format_endpoint(&dest.address);

                            if fwd_event_buffer.should_emit_packet_events() {
                                fwd_event_buffer.emit(
                                    DiagnosticEvent::new(
                                        fwd_event_buffer.clock().monotonic_nanos(),
                                        fwd_event_buffer.clock().wall_clock_nanos(),
                                        &fwd_stream_id,
                                        DiagnosticStage::SendAttempted,
                                        dest.transport,
                                        payload_len,
                                    )
                                    .with_source(&src_addr_str)
                                    .with_destination(&dest_addr_str),
                                );
                            }

                            match dest.transport {
                                TransportType::Udp => {
                                    match resolve_endpoint_with_context(
                                        &dest.address,
                                        Some(dest_path),
                                    ) {
                                        Ok(target_addr) => {
                                            let socket_res = match target_addr {
                                                SocketAddr::V4(_) => ipv4_socket
                                                    .as_ref()
                                                    .ok_or_else(|| {
                                                        io::Error::new(
                                                            io::ErrorKind::AddrNotAvailable,
                                                            "IPv4 socket unavailable",
                                                        )
                                                    })
                                                    .and_then(|s| {
                                                        s.send_to(&datagram.payload, target_addr)
                                                    }),
                                                SocketAddr::V6(_) => ipv6_socket
                                                    .as_ref()
                                                    .ok_or_else(|| {
                                                        io::Error::new(
                                                            io::ErrorKind::AddrNotAvailable,
                                                            "IPv6 socket unavailable",
                                                        )
                                                    })
                                                    .and_then(|s| {
                                                        s.send_to(&datagram.payload, target_addr)
                                                    }),
                                            };

                                            match socket_res {
                                                Ok(sent) => {
                                                    if fwd_event_buffer.should_emit_packet_events()
                                                        || fwd_stream_mqtt
                                                            .as_ref()
                                                            .is_some_and(|m| m.enabled)
                                                        || fwd_stream_kiss
                                                            .as_ref()
                                                            .is_some_and(|k| k.enabled)
                                                    {
                                                        let mut ev = DiagnosticEvent::new(
                                                            fwd_event_buffer
                                                                .clock()
                                                                .monotonic_nanos(),
                                                            fwd_event_buffer
                                                                .clock()
                                                                .wall_clock_nanos(),
                                                            &fwd_stream_id,
                                                            DiagnosticStage::SendSucceeded,
                                                            TransportType::Udp,
                                                            sent as u64,
                                                        )
                                                        .with_source(&src_addr_str)
                                                        .with_destination(target_addr.to_string());

                                                        if let Some(ref mqtt_cfg) = fwd_stream_mqtt
                                                        {
                                                            if mqtt_cfg.enabled {
                                                                let parse_res = if mqtt_cfg
                                                                    .validate_flags
                                                                {
                                                                    parse_mqtt_fixed_header(
                                                                        &datagram.payload,
                                                                    )
                                                                } else {
                                                                    parse_mqtt_fixed_header_relaxed(
                                                                        &datagram.payload,
                                                                    )
                                                                };
                                                                if let Ok(hdr) = parse_res {
                                                                    ev = ev.with_mqtt_header(&hdr);
                                                                }
                                                            }
                                                        }

                                                        if let Some(ref kiss_cfg) = fwd_stream_kiss
                                                        {
                                                            if kiss_cfg.enabled
                                                                && !datagram.payload.is_empty()
                                                            {
                                                                let kiss_port =
                                                                    (datagram.payload[0] >> 4)
                                                                        & 0x0F;
                                                                let kiss_cmd =
                                                                    datagram.payload[0] & 0x0F;
                                                                ev = ev
                                                                    .with_kiss_port(kiss_port)
                                                                    .with_kiss_command(kiss_cmd);
                                                                if kiss_cfg.inspect_ax25
                                                                    && kiss_cmd == 0
                                                                    && datagram.payload.len() > 1
                                                                {
                                                                    if let Ok(frame) =
                                                                        parse_ax25_frame(
                                                                            &datagram.payload[1..],
                                                                        )
                                                                    {
                                                                        ev = ev.with_ax25_frame(
                                                                            &frame,
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        fwd_event_buffer.emit(ev);
                                                    }
                                                    fwd_stats
                                                        .forwarded_packets
                                                        .fetch_add(1, Ordering::SeqCst);
                                                    fwd_stats
                                                        .forwarded_bytes
                                                        .fetch_add(sent as u64, Ordering::SeqCst);
                                                }
                                                Err(err) => {
                                                    fwd_stats
                                                        .destination_errors
                                                        .fetch_add(1, Ordering::SeqCst);
                                                    fwd_stats
                                                        .socket_errors
                                                        .fetch_add(1, Ordering::SeqCst);
                                                    eprintln!(
                                                        "[stream {}] UDP destination error sending to {}: {}",
                                                        fwd_stream_id, target_addr, err
                                                    );
                                                    fwd_event_buffer.emit(
                                                        DiagnosticEvent::new(
                                                            fwd_event_buffer.clock().monotonic_nanos(),
                                                            fwd_event_buffer.clock().wall_clock_nanos(),
                                                            &fwd_stream_id,
                                                            DiagnosticStage::Failure,
                                                            TransportType::Udp,
                                                            payload_len,
                                                        )
                                                        .with_source(&src_addr_str)
                                                        .with_destination(target_addr.to_string())
                                                        .with_reason(format!(
                                                            "UDP destination error sending to {target_addr}: {err}"
                                                        )),
                                                    );
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            fwd_stats
                                                .destination_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                            fwd_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                            eprintln!(
                                                "[stream {}] Destination resolution error for '{}' ('{}'): {}",
                                                fwd_stream_id,
                                                dest_path,
                                                format_endpoint(&dest.address),
                                                err
                                            );
                                            fwd_event_buffer.emit(
                                                DiagnosticEvent::new(
                                                    fwd_event_buffer.clock().monotonic_nanos(),
                                                    fwd_event_buffer.clock().wall_clock_nanos(),
                                                    &fwd_stream_id,
                                                    DiagnosticStage::Failure,
                                                    TransportType::Udp,
                                                    payload_len,
                                                )
                                                .with_source(&src_addr_str)
                                                .with_destination(&dest_addr_str)
                                                .with_reason(format!(
                                                    "Destination resolution error for '{}' ('{}'): {}",
                                                    dest_path,
                                                    format_endpoint(&dest.address),
                                                    err
                                                )),
                                            );
                                        }
                                    }
                                }
                                TransportType::Tcp => {
                                    if let Some(Some(ref mut conn)) = tcp_conns.get_mut(idx) {
                                        if let Err(e) = conn.send(&datagram.payload, &fwd_stats) {
                                            all_succeeded = false;
                                            eprintln!(
                                                "[stream {}] TCP destination error sending to {}: {}",
                                                fwd_stream_id, format_endpoint(&dest.address), e
                                            );
                                        } else if fwd_event_buffer.should_emit_packet_events()
                                            || fwd_stream_mqtt.as_ref().is_some_and(|m| m.enabled)
                                            || fwd_stream_kiss.as_ref().is_some_and(|k| k.enabled)
                                        {
                                            let mut ev = DiagnosticEvent::new(
                                                fwd_event_buffer.clock().monotonic_nanos(),
                                                fwd_event_buffer.clock().wall_clock_nanos(),
                                                &fwd_stream_id,
                                                DiagnosticStage::SendSucceeded,
                                                TransportType::Tcp,
                                                payload_len,
                                            )
                                            .with_source(&src_addr_str)
                                            .with_destination(&dest_addr_str);

                                            if let Some(ref mqtt_cfg) = fwd_stream_mqtt {
                                                if mqtt_cfg.enabled {
                                                    let parse_res = if mqtt_cfg.validate_flags {
                                                        parse_mqtt_fixed_header(&datagram.payload)
                                                    } else {
                                                        parse_mqtt_fixed_header_relaxed(
                                                            &datagram.payload,
                                                        )
                                                    };
                                                    if let Ok(hdr) = parse_res {
                                                        ev = ev.with_mqtt_header(&hdr);
                                                    }
                                                }
                                            }

                                            if let Some(ref kiss_cfg) = fwd_stream_kiss {
                                                if kiss_cfg.enabled && !datagram.payload.is_empty()
                                                {
                                                    let kiss_port =
                                                        (datagram.payload[0] >> 4) & 0x0F;
                                                    let kiss_cmd = datagram.payload[0] & 0x0F;
                                                    ev = ev
                                                        .with_kiss_port(kiss_port)
                                                        .with_kiss_command(kiss_cmd);
                                                    if kiss_cfg.inspect_ax25
                                                        && kiss_cmd == 0
                                                        && datagram.payload.len() > 1
                                                    {
                                                        if let Ok(frame) =
                                                            parse_ax25_frame(&datagram.payload[1..])
                                                        {
                                                            ev = ev.with_ax25_frame(&frame);
                                                        }
                                                    }
                                                }
                                            }

                                            fwd_event_buffer.emit(ev);
                                        }
                                    }
                                }
                            }
                        }

                        // If single TCP destination and send failed due to disconnection/outage, retain datagram for retry
                        if is_single_tcp_dest
                            && !all_succeeded
                            && !fwd_shutdown.load(Ordering::Relaxed)
                        {
                            held_datagram = Some(datagram);
                        }
                    }
                    None => {
                        if fwd_shutdown.load(Ordering::Relaxed)
                            && fwd_done_flag.load(Ordering::Relaxed)
                        {
                            break;
                        }
                    }
                }
            }
            fwd_is_active.store(false, Ordering::Relaxed);
        });
        runner_threads.push(fwd_handle);

        Ok(Self {
            stream_id,
            stats,
            event_buffer,
            mode,
            source_transport,
            sequence_tracker: seq_tracker,
            ccsds_tracker,
            mavlink_tracker,
            is_active,
            shutdown_flag,
            threads: runner_threads,
        })
    }

    /// Returns a reference to the stream runner's diagnostic event buffer.
    #[must_use]
    pub fn event_buffer(&self) -> &DiagnosticBuffer {
        &self.event_buffer
    }

    /// Returns the operational mode of this stream runner.
    #[must_use]
    pub fn mode(&self) -> OperationalMode {
        self.event_buffer.current_mode()
    }

    /// Emits a stream health state transition event with a descriptive reason.
    pub fn emit_health_transition(&self, healthy: bool, reason: impl Into<String>) {
        let state_str = if healthy { "healthy" } else { "unhealthy" };
        let reason_str = reason.into();
        self.is_active.store(healthy, Ordering::SeqCst);
        self.event_buffer.emit(
            DiagnosticEvent::new(
                self.event_buffer.clock().monotonic_nanos(),
                self.event_buffer.clock().wall_clock_nanos(),
                &self.stream_id,
                DiagnosticStage::HealthTransition,
                self.source_transport,
                0,
            )
            .with_reason(format!("{state_str}: {reason_str}")),
        );
    }

    /// Returns true if this runner's threads are active and not in shutdown.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        !self.shutdown_flag.load(Ordering::Relaxed)
            && self.is_active.load(Ordering::Relaxed)
            && self.threads.iter().all(|t| !t.is_finished())
    }

    /// Stops forwarding and joins runner threads.
    pub fn stop(self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        for handle in self.threads {
            let _ = handle.join();
        }
    }
}

/// Information about a configured logical interface on an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalInterfaceInfo {
    pub instance_id: String,
    pub id: String,
    pub name: Option<String>,
    pub tx_stream: Option<String>,
    pub rx_stream: Option<String>,
}

/// Point-in-time statistics for a logical interface, containing directional counters.
///
/// In accordance with SPEC §6, pairing is a configuration context relationship:
/// transmit (TX) and receive (RX) directions maintain completely independent counters,
/// socket endpoints, routing, queue buffers, and error states without automatic packet correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalInterfaceStats {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_stats: Option<StreamStatsSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_stats: Option<StreamStatsSnapshot>,
}

/// Snapshot of a stream's health and packet counters.
#[derive(Debug, Clone)]
pub struct StreamHealthSnapshot {
    pub stream_id: String,
    pub is_healthy: bool,
    pub stats: StreamStatsSnapshot,
}

/// Handle for querying relay health without transferring ownership of `Relay`.
#[derive(Clone)]
pub struct RelayHealthHandle {
    stream_runners: Arc<Vec<StreamRunnerHandle>>,
    logical_interfaces: Arc<Vec<LogicalInterfaceInfo>>,
    shutdown_flag: Arc<AtomicBool>,
    start_time: std::time::Instant,
    event_buffer: DiagnosticBuffer,
}

#[derive(Clone)]
struct StreamRunnerHandle {
    stream_id: String,
    stats: Arc<StreamStats>,
    sequence_tracker: Arc<Mutex<SequenceTracker>>,
    ccsds_tracker: Option<Arc<Mutex<CcsdsSequenceTracker>>>,
    mavlink_tracker: Option<Arc<Mutex<MavlinkSequenceTracker>>>,
    is_active: Arc<AtomicBool>,
    shutdown_flag: Arc<AtomicBool>,
}

impl RelayHealthHandle {
    /// Returns a reference to the diagnostic event buffer.
    #[must_use]
    pub fn event_buffer(&self) -> &DiagnosticBuffer {
        &self.event_buffer
    }

    /// Returns the current operational mode.
    #[must_use]
    pub fn current_mode(&self) -> OperationalMode {
        self.event_buffer.current_mode()
    }

    /// Returns configured test mode expiry in seconds, if active.
    #[must_use]
    pub fn current_expiry(&self) -> Option<u64> {
        self.event_buffer.current_expiry()
    }

    /// Returns active test run correlation ID, if configured.
    #[must_use]
    pub fn correlation_id(&self) -> Option<String> {
        self.event_buffer.correlation_id()
    }

    /// Returns reason why the test run ended, if ended.
    #[must_use]
    pub fn test_end_reason(&self) -> Option<String> {
        self.event_buffer.test_end_reason()
    }

    /// Returns current sequence tracking snapshots for all streams (SPEC §8).
    #[must_use]
    pub fn sequence_states(&self) -> Vec<SequenceState> {
        let mut states: Vec<SequenceState> = self
            .stream_runners
            .iter()
            .map(|r| r.sequence_tracker.lock().unwrap().snapshot())
            .collect();
        for r in self.stream_runners.iter() {
            if let Some(ref ct) = r.ccsds_tracker {
                let tracker = ct.lock().unwrap();
                for apid in tracker.tracked_apids() {
                    if let Some(st) = tracker.apid_state(&r.stream_id, apid) {
                        states.push(st);
                    }
                }
            }
            if let Some(ref mt) = r.mavlink_tracker {
                let tracker = mt.lock().unwrap();
                for &(sys, comp) in &tracker.tracked_sources() {
                    if let Some(st) = tracker.source_state(&r.stream_id, sys, comp) {
                        states.push(st);
                    }
                }
            }
        }
        states
    }

    /// Returns current CCSDS sequence tracker for a stream if configured.
    #[must_use]
    pub fn ccsds_tracker(&self, stream_id: &str) -> Option<Arc<Mutex<CcsdsSequenceTracker>>> {
        let runner = self
            .stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)?;
        runner.ccsds_tracker.as_ref().map(Arc::clone)
    }

    /// Returns current MAVLink sequence tracker for a stream if configured.
    #[must_use]
    pub fn mavlink_tracker(&self, stream_id: &str) -> Option<Arc<Mutex<MavlinkSequenceTracker>>> {
        let runner = self
            .stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)?;
        runner.mavlink_tracker.as_ref().map(Arc::clone)
    }

    /// Returns true if the relay is running and all stream runners are healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        if self.shutdown_flag.load(Ordering::Relaxed) || crate::signals::is_shutdown_requested() {
            return false;
        }
        if self.stream_runners.is_empty() {
            return true;
        }
        self.stream_runners.iter().all(|r| {
            r.is_active.load(Ordering::Relaxed) && !r.shutdown_flag.load(Ordering::Relaxed)
        })
    }

    /// Returns daemon uptime in seconds.
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Returns health snapshots for all configured streams.
    #[must_use]
    pub fn stream_health_snapshots(&self) -> Vec<StreamHealthSnapshot> {
        let shutting_down =
            self.shutdown_flag.load(Ordering::Relaxed) || crate::signals::is_shutdown_requested();
        self.stream_runners
            .iter()
            .map(|r| {
                let healthy = !shutting_down && r.is_active.load(Ordering::Relaxed);
                StreamHealthSnapshot {
                    stream_id: r.stream_id.clone(),
                    is_healthy: healthy,
                    stats: r.stats.snapshot(),
                }
            })
            .collect()
    }

    /// Returns all configured logical interfaces.
    #[must_use]
    pub fn logical_interfaces(&self) -> &[LogicalInterfaceInfo] {
        &self.logical_interfaces
    }

    /// Retrieves statistics for a specific stream.
    #[must_use]
    pub fn stream_stats(&self, stream_id: &str) -> Option<StreamStatsSnapshot> {
        let runner = self
            .stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)?;
        let mut snap = runner.stats.snapshot();
        if snap.forwarded_packets
            + snap.dropped_packets
            + snap.destination_errors
            + snap.queue_depth
            < snap.received_packets
        {
            for _ in 0..50 {
                std::thread::sleep(Duration::from_millis(5));
                snap = runner.stats.snapshot();
                if snap.forwarded_packets
                    + snap.dropped_packets
                    + snap.destination_errors
                    + snap.queue_depth
                    >= snap.received_packets
                {
                    break;
                }
            }
        }
        Some(snap)
    }

    /// Retrieves point-in-time statistics for all configured logical interfaces.
    #[must_use]
    pub fn logical_interface_stats(&self) -> Vec<LogicalInterfaceStats> {
        self.logical_interfaces
            .iter()
            .map(|iface| {
                let tx_stats = iface
                    .tx_stream
                    .as_ref()
                    .and_then(|id| self.stream_stats(id));
                let rx_stats = iface
                    .rx_stream
                    .as_ref()
                    .and_then(|id| self.stream_stats(id));
                LogicalInterfaceStats {
                    id: iface.id.clone(),
                    name: iface.name.clone(),
                    tx_stream: iface.tx_stream.clone(),
                    rx_stream: iface.rx_stream.clone(),
                    tx_stats,
                    rx_stats,
                }
            })
            .collect()
    }
}

/// A running multi-instance RER relay.
pub struct Relay {
    stream_runners: Vec<StreamRunner>,
    logical_interfaces: Vec<LogicalInterfaceInfo>,
    shutdown_flag: Arc<AtomicBool>,
    start_time: std::time::Instant,
    event_buffer: DiagnosticBuffer,
}

impl Relay {
    /// Starts all forwarding streams defined across all instances in the configuration.
    ///
    /// # Errors
    /// Returns an error if any stream fails to bind its listening socket.
    pub fn start(config: &Config) -> io::Result<Self> {
        Self::start_with_buffer(config, DiagnosticBuffer::new(1024))
    }

    /// Starts all forwarding streams with a designated diagnostic event buffer.
    ///
    /// # Errors
    /// Returns an error if any stream fails to bind its listening socket.
    pub fn start_with_buffer(config: &Config, event_buffer: DiagnosticBuffer) -> io::Result<Self> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let mut stream_runners = Vec::new();
        let mut logical_interfaces = Vec::new();

        let is_single = config.instance.is_some();
        let instances = config.all_instances();

        for (inst_idx, inst) in instances.iter().enumerate() {
            let inst_prefix = if is_single {
                "instance".to_string()
            } else {
                format!("instances[{inst_idx}]")
            };
            if event_buffer.test_state().is_none() {
                let correlation_id = inst.resolved_correlation_id().map(String::from);
                let expiry_seconds = inst.resolved_expiry_seconds();
                let max_events = inst.resolved_max_events();
                let prior_mode = inst.resolved_prior_mode();
                let test_state = Arc::new(DiagnosticTestState::new(
                    inst.id.clone(),
                    inst.mode,
                    correlation_id,
                    expiry_seconds,
                    max_events,
                    Some(prior_mode),
                    event_buffer.clock().clone(),
                ));
                event_buffer.set_test_state(test_state);
            }
            for (s_idx, stream) in inst.streams.iter().enumerate() {
                let stream_prefix = format!("{inst_prefix}.streams[{s_idx}]");
                let runner = StreamRunner::start_with_buffer(
                    stream,
                    inst,
                    Arc::clone(&shutdown_flag),
                    &stream_prefix,
                    event_buffer.clone(),
                )?;
                stream_runners.push(runner);
            }
            for iface in &inst.logical_interfaces {
                logical_interfaces.push(LogicalInterfaceInfo {
                    instance_id: inst.id.clone(),
                    id: iface.id.clone(),
                    name: iface.name.clone(),
                    tx_stream: iface.tx_stream.clone(),
                    rx_stream: iface.rx_stream.clone(),
                });
            }
        }

        Ok(Self {
            stream_runners,
            logical_interfaces,
            shutdown_flag,
            start_time: std::time::Instant::now(),
            event_buffer,
        })
    }

    /// Returns a reference to the diagnostic event buffer.
    #[must_use]
    pub fn event_buffer(&self) -> &DiagnosticBuffer {
        &self.event_buffer
    }

    /// Returns the current operational mode.
    #[must_use]
    pub fn current_mode(&self) -> OperationalMode {
        self.event_buffer.current_mode()
    }

    /// Returns configured test mode expiry in seconds, if active.
    #[must_use]
    pub fn current_expiry(&self) -> Option<u64> {
        self.event_buffer.current_expiry()
    }

    /// Returns active test run correlation ID, if configured.
    #[must_use]
    pub fn correlation_id(&self) -> Option<String> {
        self.event_buffer.correlation_id()
    }

    /// Returns reason why the test run ended, if ended.
    #[must_use]
    pub fn test_end_reason(&self) -> Option<String> {
        self.event_buffer.test_end_reason()
    }

    /// Returns a reference to all stream runners.
    #[must_use]
    pub fn stream_runners(&self) -> &[StreamRunner] {
        &self.stream_runners
    }

    /// Retrieves a specific stream runner by ID.
    #[must_use]
    pub fn stream_runner(&self, stream_id: &str) -> Option<&StreamRunner> {
        self.stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)
    }

    /// Emits a stream health state transition event on the designated stream.
    pub fn emit_health_transition(
        &self,
        stream_id: &str,
        healthy: bool,
        reason: impl Into<String>,
    ) -> bool {
        if let Some(runner) = self
            .stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)
        {
            runner.emit_health_transition(healthy, reason);
            true
        } else {
            false
        }
    }

    /// Creates a lightweight health query handle.
    #[must_use]
    pub fn health_handle(&self) -> RelayHealthHandle {
        let handles = self
            .stream_runners
            .iter()
            .map(|r| StreamRunnerHandle {
                stream_id: r.stream_id.clone(),
                stats: Arc::clone(&r.stats),
                sequence_tracker: Arc::clone(&r.sequence_tracker),
                ccsds_tracker: r.ccsds_tracker.as_ref().map(Arc::clone),
                mavlink_tracker: r.mavlink_tracker.as_ref().map(Arc::clone),
                is_active: Arc::clone(&r.is_active),
                shutdown_flag: Arc::clone(&r.shutdown_flag),
            })
            .collect();
        RelayHealthHandle {
            stream_runners: Arc::new(handles),
            logical_interfaces: Arc::new(self.logical_interfaces.clone()),
            shutdown_flag: Arc::clone(&self.shutdown_flag),
            start_time: self.start_time,
            event_buffer: self.event_buffer.clone(),
        }
    }

    /// Returns a list of all active stream identities.
    #[must_use]
    pub fn stream_ids(&self) -> Vec<String> {
        self.stream_runners
            .iter()
            .map(|r| r.stream_id.clone())
            .collect()
    }

    /// Returns the CCSDS sequence tracker for a stream if configured.
    #[must_use]
    pub fn ccsds_tracker(&self, stream_id: &str) -> Option<Arc<Mutex<CcsdsSequenceTracker>>> {
        let runner = self
            .stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)?;
        runner.ccsds_tracker.as_ref().map(Arc::clone)
    }

    /// Returns the MAVLink sequence tracker for a stream if configured.
    #[must_use]
    pub fn mavlink_tracker(&self, stream_id: &str) -> Option<Arc<Mutex<MavlinkSequenceTracker>>> {
        let runner = self
            .stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)?;
        runner.mavlink_tracker.as_ref().map(Arc::clone)
    }

    /// Returns all configured logical interfaces.
    #[must_use]
    pub fn logical_interfaces(&self) -> &[LogicalInterfaceInfo] {
        &self.logical_interfaces
    }

    /// Retrieves statistics for a specific stream.
    #[must_use]
    pub fn stream_stats(&self, stream_id: &str) -> Option<StreamStatsSnapshot> {
        let runner = self
            .stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)?;
        let mut snap = runner.stats.snapshot();
        if snap.forwarded_packets
            + snap.dropped_packets
            + snap.destination_errors
            + snap.queue_depth
            < snap.received_packets
        {
            for _ in 0..50 {
                std::thread::sleep(Duration::from_millis(5));
                snap = runner.stats.snapshot();
                if snap.forwarded_packets
                    + snap.dropped_packets
                    + snap.destination_errors
                    + snap.queue_depth
                    >= snap.received_packets
                {
                    break;
                }
            }
        }
        Some(snap)
    }

    /// Retrieves statistics for a specific logical interface by ID.
    #[must_use]
    pub fn logical_interface_stats(&self, interface_id: &str) -> Option<LogicalInterfaceStats> {
        let iface = self
            .logical_interfaces
            .iter()
            .find(|i| i.id == interface_id)?;
        let tx_stats = iface
            .tx_stream
            .as_ref()
            .and_then(|id| self.stream_stats(id));
        let rx_stats = iface
            .rx_stream
            .as_ref()
            .and_then(|id| self.stream_stats(id));
        Some(LogicalInterfaceStats {
            id: iface.id.clone(),
            name: iface.name.clone(),
            tx_stream: iface.tx_stream.clone(),
            rx_stream: iface.rx_stream.clone(),
            tx_stats,
            rx_stats,
        })
    }

    /// Gracefully stops the relay, joins all worker threads, and prints statistics.
    pub fn stop(self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        for runner in self.stream_runners {
            let id = runner.stream_id.clone();
            let snap = runner.stats.snapshot();
            runner.stop();
            eprintln!(
                "[relay] Stream '{}' final stats: rx={}/{}B, tx={}/{}B, drops={} (queue={}, oversized={}), errors={} (dest={}, socket={}), backpressure={}",
                id,
                snap.received_packets,
                snap.received_bytes,
                snap.forwarded_packets,
                snap.forwarded_bytes,
                snap.dropped_packets,
                snap.drops_queue_full,
                snap.drops_oversized,
                snap.destination_errors + snap.socket_errors,
                snap.destination_errors,
                snap.socket_errors,
                snap.backpressure_events
            );
        }
        for iface in &self.logical_interfaces {
            let tx_desc = iface
                .tx_stream
                .as_ref()
                .map(|s| format!("tx='{}'", s))
                .unwrap_or_else(|| "tx=none".to_string());
            let rx_desc = iface
                .rx_stream
                .as_ref()
                .map(|s| format!("rx='{}'", s))
                .unwrap_or_else(|| "rx=none".to_string());
            eprintln!(
                "[relay] Logical interface '{}' ({}): {}, {} (paired directional streams: configuration context)",
                iface.id,
                iface.name.as_deref().unwrap_or("unnamed"),
                tx_desc,
                rx_desc
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_queue_drop_oldest() {
        let mut queue = BoundedQueue::new(3, DropPolicy::DropOldest);
        let dummy_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();

        assert_eq!(
            queue.push(Datagram {
                payload: vec![1],
                source_addr: dummy_addr
            }),
            PushResult::Enqueued
        );
        assert_eq!(
            queue.push(Datagram {
                payload: vec![2],
                source_addr: dummy_addr
            }),
            PushResult::Enqueued
        );
        assert_eq!(
            queue.push(Datagram {
                payload: vec![3],
                source_addr: dummy_addr
            }),
            PushResult::Enqueued
        );

        // Queue full (size 3). Next push drops oldest (vec![1])
        assert_eq!(
            queue.push(Datagram {
                payload: vec![4],
                source_addr: dummy_addr
            }),
            PushResult::DroppedOldest
        );
        assert_eq!(queue.len(), 3);

        assert_eq!(queue.pop().unwrap().payload, vec![2]);
        assert_eq!(queue.pop().unwrap().payload, vec![3]);
        assert_eq!(queue.pop().unwrap().payload, vec![4]);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_bounded_queue_drop_newest() {
        let mut queue = BoundedQueue::new(2, DropPolicy::DropNewest);
        let dummy_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();

        assert_eq!(
            queue.push(Datagram {
                payload: vec![10],
                source_addr: dummy_addr
            }),
            PushResult::Enqueued
        );
        assert_eq!(
            queue.push(Datagram {
                payload: vec![20],
                source_addr: dummy_addr
            }),
            PushResult::Enqueued
        );

        // Queue full. Next push drops newest (vec![30])
        assert_eq!(
            queue.push(Datagram {
                payload: vec![30],
                source_addr: dummy_addr
            }),
            PushResult::DroppedNewest
        );
        assert_eq!(queue.len(), 2);

        assert_eq!(queue.pop().unwrap().payload, vec![10]);
        assert_eq!(queue.pop().unwrap().payload, vec![20]);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_bounded_queue_reject() {
        let mut queue = BoundedQueue::new(1, DropPolicy::Reject);
        let dummy_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();

        assert_eq!(
            queue.push(Datagram {
                payload: vec![99],
                source_addr: dummy_addr
            }),
            PushResult::Enqueued
        );
        assert_eq!(
            queue.push(Datagram {
                payload: vec![100],
                source_addr: dummy_addr
            }),
            PushResult::Rejected
        );

        assert_eq!(queue.pop().unwrap().payload, vec![99]);
        assert!(queue.pop().is_none());
    }

    #[test]
    fn test_scoped_address_parsing_and_formatting() {
        // Numeric zone
        let addr = parse_scoped_socket_addr("[fe80::1%2]:5000").unwrap();
        assert_eq!(
            addr,
            SocketAddr::V6(std::net::SocketAddrV6::new(
                "fe80::1".parse().unwrap(),
                5000,
                0,
                2
            ))
        );

        // Unknown interface returns NotFound error mentioning interface
        let err = parse_scoped_socket_addr("[fe80::1%nosuchif]:5000").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("nosuchif"));

        // ScopedEndpoint round-trip formatting
        let ep = ScopedEndpoint::parse("[fe80::1%eth0]:5000").unwrap();
        assert_eq!(ep.to_string(), "[fe80::1%eth0]:5000");

        // format_endpoint round-trip formatting
        assert_eq!(
            format_endpoint("[fe80::1%eth0]:5000"),
            "[fe80::1%eth0]:5000"
        );
        assert_eq!(format_endpoint("fe80::1%eth0:5000"), "[fe80::1%eth0]:5000");
    }

    fn make_test_mavlink1_packet(
        seq: u8,
        sysid: u8,
        compid: u8,
        msgid: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0xFE, payload.len() as u8, seq, sysid, compid, msgid];
        pkt.extend_from_slice(payload);
        pkt.push(0x12);
        pkt.push(0x34);
        pkt
    }

    fn pick_test_port() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
        socket.local_addr().expect("local addr").port()
    }

    #[test]
    fn test_mavlink_udp_forwarding_preserves_payload_and_records_metadata() {
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mavlink"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mavlink:
          enabled: true
          track_sequences: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

        let pkt = make_test_mavlink1_packet(42, 1, 2, 77, b"telemetry heartbeat");
        sender
            .send_to(&pkt, format!("127.0.0.1:{listen_port}"))
            .expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            pkt.as_slice(),
            "exact datagram payload bytes must be forwarded unmodified"
        );

        let stats = relay.stream_stats("s-mavlink").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);

        let snap = relay.event_buffer().snapshot();
        let insp_ev = snap
            .events
            .iter()
            .find(|e| e.stage == DiagnosticStage::MavlinkInspection);
        assert!(
            insp_ev.is_some(),
            "must emit diagnostic event for MAVLink inspection"
        );
        let ev = insp_ev.unwrap();
        assert_eq!(ev.mavlink_system_id, Some(1));
        assert_eq!(ev.mavlink_component_id, Some(2));
        assert_eq!(ev.mavlink_sequence, Some(42));
        assert_eq!(ev.sequence_number, Some(42));
        assert_eq!(ev.mavlink_message_id, Some(77));
        assert_eq!(ev.mavlink_version, Some(1));
        assert!(ev.mavlink_metadata.is_some());

        relay.stop();
    }

    #[test]
    fn test_mavlink_malformed_dropped_by_default() {
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mavlink-drop"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mavlink:
          enabled: true
          passthrough_on_error: false
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        // 1. Invalid magic byte
        sender
            .send_to(b"not-a-mavlink-packet", &target)
            .expect("send");
        // 2. Truncated packet
        sender.send_to(&[0xFE, 10, 1], &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let res = dest_sock.recv_from(&mut buf);
        assert!(res.is_err(), "malformed packets must be dropped by default");

        let stats = relay.stream_stats("s-mavlink-drop").expect("stats");
        assert_eq!(stats.received_packets, 2);
        assert_eq!(stats.forwarded_packets, 0);
        assert_eq!(stats.dropped_packets, 2);

        let snap = relay.event_buffer().snapshot();
        let drops: Vec<&DiagnosticEvent> = snap
            .events
            .iter()
            .filter(|e| e.stage == DiagnosticStage::Dropped)
            .collect();
        assert_eq!(drops.len(), 2);
        assert!(drops[0].reason.is_some());
        assert!(drops[1].reason.is_some());

        relay.stop();
    }

    #[test]
    fn test_mavlink_passthrough_on_error() {
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mavlink-pt"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mavlink:
          enabled: true
          passthrough_on_error: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        let malformed = b"raw-corrupted-bytes".to_vec();
        sender.send_to(&malformed, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            malformed.as_slice(),
            "malformed packet must be forwarded unmodified under passthrough_on_error"
        );

        let stats = relay.stream_stats("s-mavlink-pt").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);
        assert_eq!(stats.validation_errors, 1);

        let snap = relay.event_buffer().snapshot();
        let fails: Vec<&DiagnosticEvent> = snap
            .events
            .iter()
            .filter(|e| e.stage == DiagnosticStage::Failure)
            .collect();
        assert_eq!(fails.len(), 1);
        assert!(fails[0].reason.as_ref().unwrap().contains("validation"));

        relay.stop();
    }

    #[test]
    fn test_mavlink_unconfigured_stream_byte_identical_forwarding() {
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-unconfigured"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

        let raw = b"plain-arbitrary-traffic".to_vec();
        sender
            .send_to(&raw, format!("127.0.0.1:{listen_port}"))
            .expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(&buf[..n], raw.as_slice());

        assert!(relay.mavlink_tracker("s-unconfigured").is_none());

        let stats = relay.stream_stats("s-unconfigured").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);

        relay.stop();
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
    fn test_mqtt_udp_forwarding_preserves_payload_and_records_type_and_qos() {
        // Acceptance criterion: In crates/rer/src/relay.rs, forwarding a valid MQTT packet
        // on a stream with MQTT inspection enabled transmits the payload unmodified to
        // destination endpoints while recording packet type and QoS in diagnostic events.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mqtt-valid"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        // Build a valid PUBLISH packet with QoS 1
        let mut var_payload = Vec::new();
        var_payload.extend_from_slice(&[0x00, 0x04]); // topic len 4
        var_payload.extend_from_slice(b"test"); // topic
        var_payload.extend_from_slice(&[0x00, 0x2A]); // packet id 42
        var_payload.extend_from_slice(b"mqtt telemetry payload");
        let pkt = make_test_mqtt_packet(crate::mqtt::MQTT_TYPE_PUBLISH, 0b0010, &var_payload);

        sender.send_to(&pkt, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            pkt.as_slice(),
            "payload must be transmitted unmodified"
        );

        let stats = relay.stream_stats("s-mqtt-valid").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);

        let snap = relay.event_buffer().snapshot();
        let insp_ev = snap
            .events
            .iter()
            .find(|e| e.stage == DiagnosticStage::MqttInspection)
            .expect("must emit MqttInspection diagnostic event");

        assert_eq!(insp_ev.mqtt_packet_type, Some(3));
        assert_eq!(insp_ev.mqtt_type_name.as_deref(), Some("PUBLISH"));
        assert_eq!(insp_ev.mqtt_qos, Some(1));
        assert_eq!(insp_ev.mqtt_packet_id, Some(42));
        assert!(insp_ev.mqtt_metadata.is_some());

        let meta = insp_ev.mqtt_metadata.as_ref().unwrap();
        assert_eq!(meta.packet_type, 3);
        assert_eq!(meta.qos, Some(1));
        assert_eq!(meta.packet_identifier, Some(42));

        relay.stop();
    }

    #[test]
    fn test_mqtt_malformed_invalid_header_flags_dropped_by_default() {
        // Acceptance criterion: In crates/rer/src/relay.rs, receiving a malformed MQTT packet
        // with invalid header flags on a stream with MQTT inspection enabled drops the packet
        // by default, increments dropped packet counters, and emits a dropped diagnostic event.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mqtt-drop"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
          passthrough_on_error: false
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        // PINGREQ flags must be 0000; here we set flags = 0001 (invalid flags)
        let malformed_pkt = make_test_mqtt_packet(crate::mqtt::MQTT_TYPE_PINGREQ, 0b0001, &[]);
        sender.send_to(&malformed_pkt, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let res = dest_sock.recv_from(&mut buf);
        assert!(
            res.is_err(),
            "malformed packet with invalid flags must be dropped by default"
        );

        let stats = relay.stream_stats("s-mqtt-drop").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 0);
        assert_eq!(stats.dropped_packets, 1);
        assert_eq!(stats.drops_validation, 1);
        assert_eq!(stats.validation_errors, 1);

        let snap = relay.event_buffer().snapshot();
        let drop_ev = snap
            .events
            .iter()
            .find(|e| e.stage == DiagnosticStage::Dropped)
            .expect("must emit Dropped diagnostic event");

        assert!(drop_ev.reason.is_some());
        assert!(drop_ev
            .reason
            .as_ref()
            .unwrap()
            .contains("invalid MQTT header flags"));

        relay.stop();
    }

    #[test]
    fn test_mqtt_malformed_passthrough_on_error() {
        // Acceptance criterion: In crates/rer/src/relay.rs, receiving a malformed MQTT packet
        // on an inspected stream configured with option passthrough_on_error forwards the
        // payload unmodified to destination endpoints while recording a validation failure event.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mqtt-passthrough"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
          passthrough_on_error: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        // Malformed packet with invalid flags
        let malformed_pkt = make_test_mqtt_packet(crate::mqtt::MQTT_TYPE_PINGREQ, 0b0001, &[]);
        sender.send_to(&malformed_pkt, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            malformed_pkt.as_slice(),
            "malformed packet must be forwarded unmodified"
        );

        let stats = relay.stream_stats("s-mqtt-passthrough").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);
        assert_eq!(stats.validation_errors, 1);

        let snap = relay.event_buffer().snapshot();
        let fail_ev = snap
            .events
            .iter()
            .find(|e| e.stage == DiagnosticStage::Failure)
            .expect("must record validation failure event");

        assert!(fail_ev.reason.is_some());
        assert!(fail_ev
            .reason
            .as_ref()
            .unwrap()
            .contains("MQTT validation failed (passthrough)"));

        relay.stop();
    }

    #[test]
    fn test_mqtt_unconfigured_stream_byte_identical_delivery_no_overhead() {
        // Acceptance criterion: In crates/rer/src/relay.rs, forwarding traffic on a stream
        // without MQTT inspection enabled delivers packets byte-identically without invoking MQTT parsing overhead.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-unconfigured-mqtt"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

        let raw_payload = b"non-mqtt-raw-payload-\x00\xFF\x80\x7F".to_vec();
        sender
            .send_to(&raw_payload, format!("127.0.0.1:{listen_port}"))
            .expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            raw_payload.as_slice(),
            "unconfigured stream delivers byte-identically"
        );

        let stats = relay.stream_stats("s-unconfigured-mqtt").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);
        assert_eq!(stats.validation_errors, 0);

        let snap = relay.event_buffer().snapshot();
        assert!(
            !snap
                .events
                .iter()
                .any(|e| e.stage == DiagnosticStage::MqttInspection),
            "unconfigured stream must not emit MqttInspection events"
        );
        assert!(
            !snap.events.iter().any(|e| e.mqtt_packet_type.is_some()),
            "unconfigured stream must not populate MQTT diagnostic fields"
        );

        relay.stop();
    }

    #[test]
    fn test_mqtt_local_transmission_records_send_succeeded_not_downstream_broker_receipt() {
        // Acceptance criterion: In crates/rer/src/relay.rs, forwarding an inspected MQTT packet
        // records successful local transmission with DiagnosticStage::SendSucceeded without claiming downstream broker receipt.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-mqtt-local-tx"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        mqtt:
          enabled: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        let pkt = make_test_mqtt_packet(crate::mqtt::MQTT_TYPE_PINGREQ, 0b0000, &[]);
        sender.send_to(&pkt, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(&buf[..n], pkt.as_slice());

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut stats = relay.stream_stats("s-mqtt-local-tx").expect("stats");
        while stats.forwarded_packets < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
            stats = relay.stream_stats("s-mqtt-local-tx").expect("stats");
        }
        assert_eq!(stats.forwarded_packets, 1);

        let mut send_succeeded_ev = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            let snap = relay.event_buffer().snapshot();
            if let Some(ev) = snap
                .events
                .iter()
                .find(|e| e.stage == DiagnosticStage::SendSucceeded)
                .cloned()
            {
                send_succeeded_ev = Some(ev);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let send_succeeded_ev =
            send_succeeded_ev.expect("must record DiagnosticStage::SendSucceeded");

        // Verify stage is SendSucceeded, not downstream broker delivery or application acknowledgment (SPEC §8)
        assert_eq!(send_succeeded_ev.stage, DiagnosticStage::SendSucceeded);
        assert_eq!(send_succeeded_ev.stage.to_string(), "send_succeeded");
        assert_ne!(send_succeeded_ev.stage.to_string(), "delivered");
        assert_ne!(send_succeeded_ev.stage.to_string(), "broker_accepted");

        // Inspected MQTT metadata is recorded
        assert_eq!(
            send_succeeded_ev.mqtt_packet_type,
            Some(crate::mqtt::MQTT_TYPE_PINGREQ)
        );
        assert_eq!(send_succeeded_ev.mqtt_type_name.as_deref(), Some("PINGREQ"));

        relay.stop();
    }

    fn make_test_kiss_data_frame(port: u8, ax25_bytes: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + ax25_bytes.len());
        let cmd_byte = (port & 0x0F) << 4; // command 0 = DATA
        v.push(cmd_byte);
        v.extend_from_slice(ax25_bytes);
        v
    }

    #[test]
    fn test_kiss_forwarding_preserves_payload_and_records_ax25_metadata() {
        // Acceptance criterion: In crates/rer/src/relay.rs, forwarding a KISS data frame on a
        // stream with KISS inspection enabled forwards the payload unmodified to destination
        // endpoints while recording AX.25 metadata in diagnostic events.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-kiss-valid"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        kiss:
          enabled: true
          inspect_ax25: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

        let dest = crate::ax25::Ax25Address::new("CQ", 0);
        let src = crate::ax25::Ax25Address::new("W1AW", 2);
        let digi = crate::ax25::Ax25Address::new("RELAY", 0);
        let ax25_bytes = crate::ax25::encode_ax25_frame(
            &dest,
            &src,
            &[digi],
            crate::ax25::AX25_CTRL_UI,
            Some(crate::ax25::AX25_PID_NO_LAYER_3),
            b"APRS telemetry message",
        )
        .expect("encode ax25 frame");
        let kiss_frame = make_test_kiss_data_frame(0, &ax25_bytes);

        sender
            .send_to(&kiss_frame, format!("127.0.0.1:{listen_port}"))
            .expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            kiss_frame.as_slice(),
            "payload must be forwarded unmodified to destination"
        );

        let stats = relay.stream_stats("s-kiss-valid").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);

        let snap = relay.event_buffer().snapshot();
        let insp_ev = snap
            .events
            .iter()
            .find(|e| e.stage == DiagnosticStage::KissInspection);
        assert!(
            insp_ev.is_some(),
            "must emit diagnostic event for KISS inspection"
        );
        let ev = insp_ev.unwrap();
        assert_eq!(ev.kiss_port, Some(0));
        assert_eq!(ev.kiss_command, Some(0));
        assert_eq!(ev.ax25_source_callsign.as_deref(), Some("W1AW"));
        assert_eq!(ev.ax25_destination_callsign.as_deref(), Some("CQ"));
        assert_eq!(ev.source_callsign.as_deref(), Some("W1AW"));
        assert_eq!(ev.destination_callsign.as_deref(), Some("CQ"));
        assert_eq!(ev.ax25_source_ssid, Some(2));
        assert_eq!(ev.ax25_destination_ssid, Some(0));
        assert_eq!(ev.ax25_pid, Some(crate::ax25::AX25_PID_NO_LAYER_3));
        assert!(ev.kiss_metadata.is_some());
        assert!(ev.ax25_metadata.is_some());

        let ax25_meta = ev.ax25_metadata.as_ref().unwrap();
        assert_eq!(ax25_meta.source_callsign, "W1AW");
        assert_eq!(ax25_meta.destination_callsign, "CQ");
        assert_eq!(
            ax25_meta.digipeaters.as_deref(),
            Some(&["RELAY".to_string()][..])
        );

        relay.stop();
    }

    #[test]
    fn test_kiss_port_filter_mismatch_drops_packet() {
        // Acceptance criterion: In crates/rer/src/relay.rs, receiving a KISS frame with a
        // port mismatch against the configured port filter drops the packet and increments
        // dropped packet counters.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-kiss-port-filter"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        kiss:
          enabled: true
          port_filter: 3
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        let dest = crate::ax25::Ax25Address::new("CQ", 0);
        let src = crate::ax25::Ax25Address::new("N0CALL", 0);
        let ax25_bytes = crate::ax25::encode_ax25_frame(
            &dest,
            &src,
            &[],
            crate::ax25::AX25_CTRL_UI,
            Some(crate::ax25::AX25_PID_NO_LAYER_3),
            b"test payload",
        )
        .expect("encode ax25 frame");

        // Send with port 0 (does not match filter port 3)
        let mismatch_frame = make_test_kiss_data_frame(0, &ax25_bytes);
        sender.send_to(&mismatch_frame, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let res = dest_sock.recv_from(&mut buf);
        assert!(res.is_err(), "port mismatch packet must be dropped");

        let stats = relay.stream_stats("s-kiss-port-filter").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 0);
        assert_eq!(stats.dropped_packets, 1);

        let snap = relay.event_buffer().snapshot();
        let drops: Vec<&DiagnosticEvent> = snap
            .events
            .iter()
            .filter(|e| e.stage == DiagnosticStage::Dropped)
            .collect();
        assert_eq!(drops.len(), 1);
        assert!(drops[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("port mismatch"));

        relay.stop();
    }

    #[test]
    fn test_kiss_malformed_ax25_dropped_by_default() {
        // Acceptance criterion: In crates/rer/src/relay.rs, receiving a malformed AX.25 packet
        // on an inspected stream drops the packet by default and increments dropped packet counters.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-kiss-malformed-drop"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        kiss:
          enabled: true
          passthrough_on_error: false
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        // 1. Truncated AX.25 packet in KISS data frame
        let truncated_pkt = make_test_kiss_data_frame(0, &[1, 2, 3]);
        sender.send_to(&truncated_pkt, &target).expect("send");

        // 2. Corrupted packet not adhering to AX.25 address structure
        let corrupted_pkt = b"not-an-ax25-packet".to_vec();
        sender.send_to(&corrupted_pkt, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let res = dest_sock.recv_from(&mut buf);
        assert!(res.is_err(), "malformed packets must be dropped by default");

        let stats = relay.stream_stats("s-kiss-malformed-drop").expect("stats");
        assert_eq!(stats.received_packets, 2);
        assert_eq!(stats.forwarded_packets, 0);
        assert_eq!(stats.dropped_packets, 2);

        let snap = relay.event_buffer().snapshot();
        let drops: Vec<&DiagnosticEvent> = snap
            .events
            .iter()
            .filter(|e| e.stage == DiagnosticStage::Dropped)
            .collect();
        assert_eq!(drops.len(), 2);
        assert!(drops[0].reason.is_some());
        assert!(drops[1].reason.is_some());

        relay.stop();
    }

    #[test]
    fn test_kiss_malformed_ax25_passthrough_on_error() {
        // Acceptance criterion: In crates/rer/src/relay.rs, receiving a malformed AX.25 packet
        // on an inspected stream configured with option passthrough_on_error forwards the payload
        // unmodified to destination endpoints while recording a validation failure event.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-kiss-passthrough"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        kiss:
          enabled: true
          passthrough_on_error: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let target = format!("127.0.0.1:{listen_port}");

        let malformed_pkt = make_test_kiss_data_frame(0, &[0xDE, 0xAD, 0xBE, 0xEF]);
        sender.send_to(&malformed_pkt, &target).expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            malformed_pkt.as_slice(),
            "malformed packet must be forwarded unmodified under passthrough_on_error"
        );

        let stats = relay.stream_stats("s-kiss-passthrough").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);
        assert_eq!(stats.validation_errors, 1);

        let snap = relay.event_buffer().snapshot();
        let fails: Vec<&DiagnosticEvent> = snap
            .events
            .iter()
            .filter(|e| e.stage == DiagnosticStage::Failure)
            .collect();
        assert_eq!(fails.len(), 1);
        assert!(fails[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("validation failed"));

        relay.stop();
    }

    #[test]
    fn test_kiss_unconfigured_stream_byte_identical_delivery_no_overhead() {
        // Acceptance criterion: In crates/rer/src/relay.rs, forwarding traffic on a stream without
        // KISS inspection configured delivers datagrams byte-identically without invoking KISS parsing overhead.
        let dest_sock = UdpSocket::bind("127.0.0.1:0").expect("bind dest");
        dest_sock
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let dest_port = dest_sock.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-unconfigured-kiss"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

        let raw_payload = b"non-kiss-raw-telemetry-\x00\xFF\x80\x7F".to_vec();
        sender
            .send_to(&raw_payload, format!("127.0.0.1:{listen_port}"))
            .expect("send");

        let mut buf = vec![0u8; 1024];
        let (n, _) = dest_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            raw_payload.as_slice(),
            "unconfigured stream delivers datagrams byte-identically"
        );

        let stats = relay.stream_stats("s-unconfigured-kiss").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);
        assert_eq!(stats.validation_errors, 0);

        let snap = relay.event_buffer().snapshot();
        assert!(
            !snap
                .events
                .iter()
                .any(|e| e.stage == DiagnosticStage::KissInspection),
            "unconfigured stream must not emit KissInspection events"
        );
        assert!(
            !snap.events.iter().any(|e| e.kiss_port.is_some()),
            "unconfigured stream must not populate KISS port diagnostic field"
        );
        assert!(
            !snap.events.iter().any(|e| e.ax25_source_callsign.is_some()),
            "unconfigured stream must not populate AX.25 diagnostic fields"
        );

        relay.stop();
    }

    #[test]
    fn test_kiss_tcp_stream_forwarding_with_kiss_framing() {
        // Acceptance criterion / Requirement 1: KISS-over-TCP streams with FramingMode::Kiss,
        // handling FEND delimiters and escape sequences, with AX.25 inspection.
        let dest_listener = TcpListener::bind("127.0.0.1:0").expect("bind dest listener");
        let dest_port = dest_listener.local_addr().expect("dest addr").port();
        let listen_port = pick_test_port();

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "i1"
    streams:
      - id: "s-kiss-tcp"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
          framing: "kiss"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
          framing: "kiss"
        kiss:
          enabled: true
          inspect_ax25: true
"#
        );

        let config = Config::from_yaml_str(&yaml).expect("parse config");
        let relay = Relay::start(&config).expect("start relay");

        // Connect source client to relay
        let mut client =
            TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay");

        // Accept connection at destination
        let (mut dest_conn, _) = dest_listener.accept().expect("accept at dest");
        dest_conn
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set timeout");

        let dest = crate::ax25::Ax25Address::new("CQ", 0);
        let src = crate::ax25::Ax25Address::new("K1ABC", 1);
        let ax25_bytes = crate::ax25::encode_ax25_frame(
            &dest,
            &src,
            &[],
            crate::ax25::AX25_CTRL_UI,
            Some(crate::ax25::AX25_PID_NO_LAYER_3),
            b"APRS over TCP with KISS framing",
        )
        .expect("encode ax25 frame");

        // Packet with embedded FEND (0xC0) and FESC (0xDB) bytes to test escaping
        let mut ax25_with_escapes = ax25_bytes.clone();
        ax25_with_escapes.extend_from_slice(&[0xC0, 0xDB, 0x11]);
        let kiss_payload = make_test_kiss_data_frame(0, &ax25_with_escapes);

        // Encode using KISS framing (FEND ... FEND with escapes)
        let wire_frame = crate::framing::encode_kiss_frame(&kiss_payload);
        client
            .write_all(&wire_frame)
            .expect("send kiss frame over TCP");
        client.flush().expect("flush client");

        // Read single KISS frame at destination using read_kiss_frame
        let shutdown = std::sync::atomic::AtomicBool::new(false);
        let received = crate::framing::read_kiss_frame(&mut dest_conn, 1024, &shutdown)
            .expect("read kiss frame at dest")
            .expect("expected frame");

        assert_eq!(
            received, kiss_payload,
            "TCP forwarding must deliver the un-escaped KISS frame identically"
        );

        let stats = relay.stream_stats("s-kiss-tcp").expect("stats");
        assert_eq!(stats.received_packets, 1);
        assert_eq!(stats.forwarded_packets, 1);
        assert_eq!(stats.dropped_packets, 0);

        let snap = relay.event_buffer().snapshot();
        let insp_ev = snap
            .events
            .iter()
            .find(|e| e.stage == DiagnosticStage::KissInspection);
        assert!(insp_ev.is_some(), "must record KissInspection event");
        let ev = insp_ev.unwrap();
        assert_eq!(ev.ax25_source_callsign.as_deref(), Some("K1ABC"));
        assert_eq!(ev.ax25_destination_callsign.as_deref(), Some("CQ"));

        relay.stop();
    }
}
