use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{
    Config, ConnectionMode, DropPolicy, InstanceConfig, StreamConfig, TransportType,
};
use crate::framing;

/// Default maximum queue size (packets) when not explicitly configured.
pub const DEFAULT_MAX_QUEUE_SIZE: usize = 1024;

/// Default maximum packet size (bytes) when not explicitly configured.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 65535;

/// Default overload drop policy when not explicitly configured.
pub const DEFAULT_DROP_POLICY: DropPolicy = DropPolicy::DropOldest;

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
    pub destination_errors: AtomicU64,
    pub socket_errors: AtomicU64,
    pub backpressure_events: AtomicU64,
}

impl StreamStats {
    /// Captures a point-in-time snapshot of stream counters.
    #[must_use]
    pub fn snapshot(&self) -> StreamStatsSnapshot {
        StreamStatsSnapshot {
            received_packets: self.received_packets.load(Ordering::Relaxed),
            received_bytes: self.received_bytes.load(Ordering::Relaxed),
            forwarded_packets: self.forwarded_packets.load(Ordering::Relaxed),
            forwarded_bytes: self.forwarded_bytes.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            drops_queue_full: self.drops_queue_full.load(Ordering::Relaxed),
            drops_oversized: self.drops_oversized.load(Ordering::Relaxed),
            destination_errors: self.destination_errors.load(Ordering::Relaxed),
            socket_errors: self.socket_errors.load(Ordering::Relaxed),
            backpressure_events: self.backpressure_events.load(Ordering::Relaxed),
        }
    }
}

/// Point-in-time snapshot of stream statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamStatsSnapshot {
    pub received_packets: u64,
    pub received_bytes: u64,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub dropped_packets: u64,
    pub drops_queue_full: u64,
    pub drops_oversized: u64,
    pub destination_errors: u64,
    pub socket_errors: u64,
    #[serde(default)]
    pub backpressure_events: u64,
}

/// Connection manager for a TCP destination supporting reconnection with backoff and timeouts.
struct TcpDestinationConnection {
    address: String,
    stream: Option<TcpStream>,
    backoff: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
    connect_timeout: Duration,
    write_timeout: Duration,
    next_connect_attempt: Option<Instant>,
}

impl TcpDestinationConnection {
    fn new(address: String) -> Self {
        Self {
            address,
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

        let addrs = match self.address.to_socket_addrs() {
            Ok(addrs) => addrs.collect::<Vec<_>>(),
            Err(e) => {
                stats.destination_errors.fetch_add(1, Ordering::Relaxed);
                stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "[tcp destination] Address resolution error for '{}': {}",
                    self.address, e
                );
                return false;
            }
        };

        if addrs.is_empty() {
            stats.destination_errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        match TcpStream::connect_timeout(&addrs[0], self.connect_timeout) {
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
                    self.address, wait, e
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

        let frame = framing::encode_frame(payload);
        let s = self.stream.as_mut().unwrap();

        match s.write_all(&frame) {
            Ok(()) => {
                let _ = s.flush();
                stats.forwarded_packets.fetch_add(1, Ordering::Relaxed);
                stats
                    .forwarded_bytes
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                stats.backpressure_events.fetch_add(1, Ordering::Relaxed);
                stats.destination_errors.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::new(
                    e.kind(),
                    "tcp slow reader backpressure / write timeout",
                ))
            }
            Err(e) => {
                stats.destination_errors.fetch_add(1, Ordering::Relaxed);
                stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                self.stream = None;
                let wait = self.backoff;
                self.backoff = (self.backoff * 2).min(self.max_backoff);
                self.next_connect_attempt = Some(Instant::now() + wait);
                Err(e)
            }
        }
    }
}

/// Active forwarding runner for a single stream (UDP or TCP).
pub struct StreamRunner {
    pub stream_id: String,
    pub stats: Arc<StreamStats>,
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
        let stream_id = stream.id.clone();
        let stats = Arc::new(StreamStats::default());

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

        // Collect destination configurations
        let mut dest_specs = Vec::new();
        if let Some(dest) = &stream.destination {
            dest_specs.push(dest.clone());
        }
        if let Some(dests) = &stream.destinations {
            dest_specs.extend(dests.clone());
        }

        // Shared bounded queue state
        let queue = Arc::new(Mutex::new(BoundedQueue::new(max_queue_size, drop_policy)));
        let condvar = Arc::new(Condvar::new());
        let receiver_done = Arc::new(AtomicBool::new(false));

        let mut runner_threads = Vec::new();

        // -------------------------------------------------------------------
        // Source Ingress Setup (UDP or TCP)
        // -------------------------------------------------------------------
        match stream.source.transport {
            TransportType::Udp => {
                let recv_socket = UdpSocket::bind(&stream.source.address)?;
                recv_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

                let recv_stream_id = stream_id.clone();
                let recv_stats = Arc::clone(&stats);
                let recv_shutdown = Arc::clone(&shutdown_flag);
                let recv_queue = Arc::clone(&queue);
                let recv_condvar = Arc::clone(&condvar);
                let recv_done_flag = Arc::clone(&receiver_done);

                let recv_handle = thread::spawn(move || {
                    let mut buf = vec![0u8; 65536];

                    while !recv_shutdown.load(Ordering::Relaxed) {
                        match recv_socket.recv_from(&mut buf) {
                            Ok((n, src_addr)) => {
                                recv_stats.received_packets.fetch_add(1, Ordering::Relaxed);
                                recv_stats
                                    .received_bytes
                                    .fetch_add(n as u64, Ordering::Relaxed);

                                if n > max_packet_size {
                                    recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                    recv_stats.drops_oversized.fetch_add(1, Ordering::Relaxed);
                                    eprintln!(
                                        "[stream {}] Dropped oversized datagram ({} bytes > max {})",
                                        recv_stream_id, n, max_packet_size
                                    );
                                    continue;
                                }

                                let datagram = Datagram {
                                    payload: buf[..n].to_vec(),
                                    source_addr: src_addr,
                                };

                                let push_result = {
                                    let mut q = recv_queue.lock().unwrap();
                                    let res = q.push(datagram);
                                    recv_condvar.notify_one();
                                    res
                                };

                                match push_result {
                                    PushResult::Enqueued => {}
                                    PushResult::DroppedOldest => {
                                        recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                        recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                        recv_stats
                                            .backpressure_events
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    PushResult::DroppedNewest => {
                                        recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                        recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                        recv_stats
                                            .backpressure_events
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    PushResult::Rejected => {
                                        recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                        recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                        recv_stats
                                            .backpressure_events
                                            .fetch_add(1, Ordering::Relaxed);
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
                            }
                        }
                    }

                    recv_done_flag.store(true, Ordering::SeqCst);
                    recv_condvar.notify_all();
                });
                runner_threads.push(recv_handle);
            }
            TransportType::Tcp => {
                let mode = stream.source.mode.unwrap_or(ConnectionMode::Listen);
                let recv_stream_id = stream_id.clone();
                let recv_stats = Arc::clone(&stats);
                let recv_shutdown = Arc::clone(&shutdown_flag);
                let recv_queue = Arc::clone(&queue);
                let recv_condvar = Arc::clone(&condvar);
                let recv_done_flag = Arc::clone(&receiver_done);

                match mode {
                    ConnectionMode::Listen => {
                        let listener = TcpListener::bind(&stream.source.address)?;
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

                                        let client_h = thread::spawn(move || {
                                            while !cl_shutdown.load(Ordering::Relaxed) {
                                                match framing::read_frame(
                                                    &mut client_stream,
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

                                                        let datagram = Datagram {
                                                            payload,
                                                            source_addr: client_addr,
                                                        };

                                                        let push_res = {
                                                            let mut q = cl_queue.lock().unwrap();
                                                            let res = q.push(datagram);
                                                            cl_condvar.notify_one();
                                                            res
                                                        };

                                                        match push_res {
                                                            PushResult::Enqueued => {}
                                                            PushResult::DroppedOldest
                                                            | PushResult::DroppedNewest
                                                            | PushResult::Rejected => {
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
                                                        break;
                                                    }
                                                    Err(_) => {
                                                        cl_stats
                                                            .socket_errors
                                                            .fetch_add(1, Ordering::Relaxed);
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
                        let target_addr_str = stream.source.address.clone();
                        let recv_handle = thread::spawn(move || {
                            let mut backoff = Duration::from_millis(50);
                            let max_backoff = Duration::from_millis(1000);

                            while !recv_shutdown.load(Ordering::Relaxed) {
                                let addrs = match target_addr_str.to_socket_addrs() {
                                    Ok(a) => a.collect::<Vec<_>>(),
                                    Err(_) => {
                                        recv_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                        thread::sleep(backoff);
                                        continue;
                                    }
                                };

                                if addrs.is_empty() {
                                    thread::sleep(backoff);
                                    continue;
                                }

                                match TcpStream::connect_timeout(
                                    &addrs[0],
                                    Duration::from_millis(500),
                                ) {
                                    Ok(mut stream) => {
                                        let _ = stream
                                            .set_read_timeout(Some(Duration::from_millis(100)));
                                        let _ = stream.set_nodelay(true);
                                        backoff = Duration::from_millis(50);

                                        while !recv_shutdown.load(Ordering::Relaxed) {
                                            match framing::read_frame(
                                                &mut stream,
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

                                                    let datagram = Datagram {
                                                        payload,
                                                        source_addr: addrs[0],
                                                    };

                                                    let push_res = {
                                                        let mut q = recv_queue.lock().unwrap();
                                                        let res = q.push(datagram);
                                                        recv_condvar.notify_one();
                                                        res
                                                    };

                                                    match push_res {
                                                        PushResult::Enqueued => {}
                                                        PushResult::DroppedOldest
                                                        | PushResult::DroppedNewest
                                                        | PushResult::Rejected => {
                                                            recv_stats
                                                                .dropped_packets
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .drops_queue_full
                                                                .fetch_add(1, Ordering::Relaxed);
                                                            recv_stats
                                                                .backpressure_events
                                                                .fetch_add(1, Ordering::Relaxed);
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
                                                    break;
                                                }
                                                Err(_) => {
                                                    recv_stats
                                                        .socket_errors
                                                        .fetch_add(1, Ordering::Relaxed);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        recv_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
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
        let is_active = Arc::new(AtomicBool::new(true));
        let fwd_is_active = Arc::clone(&is_active);

        let fwd_handle = thread::spawn(move || {
            let ipv4_socket = UdpSocket::bind("0.0.0.0:0").ok();
            let ipv6_socket = UdpSocket::bind("[::]:0").ok();

            // Track TCP destination connections
            let mut tcp_conns: Vec<Option<TcpDestinationConnection>> = dest_specs
                .iter()
                .map(|d| {
                    if d.transport == TransportType::Tcp {
                        Some(TcpDestinationConnection::new(d.address.clone()))
                    } else {
                        None
                    }
                })
                .collect();

            let is_single_tcp_dest =
                dest_specs.len() == 1 && dest_specs[0].transport == TransportType::Tcp;

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
                }

                match held_datagram.take() {
                    Some(datagram) => {
                        let mut all_succeeded = true;

                        for (idx, dest) in dest_specs.iter().enumerate() {
                            match dest.transport {
                                TransportType::Udp => {
                                    let addrs_res = dest.address.to_socket_addrs();
                                    match addrs_res {
                                        Ok(mut addrs) => {
                                            if let Some(target_addr) = addrs.next() {
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
                                                            s.send_to(
                                                                &datagram.payload,
                                                                target_addr,
                                                            )
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
                                                            s.send_to(
                                                                &datagram.payload,
                                                                target_addr,
                                                            )
                                                        }),
                                                };

                                                match socket_res {
                                                    Ok(sent) => {
                                                        fwd_stats
                                                            .forwarded_packets
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        fwd_stats.forwarded_bytes.fetch_add(
                                                            sent as u64,
                                                            Ordering::Relaxed,
                                                        );
                                                    }
                                                    Err(err) => {
                                                        fwd_stats
                                                            .destination_errors
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        fwd_stats
                                                            .socket_errors
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        eprintln!(
                                                            "[stream {}] UDP destination error sending to {}: {}",
                                                            fwd_stream_id, target_addr, err
                                                        );
                                                    }
                                                }
                                            } else {
                                                fwd_stats
                                                    .destination_errors
                                                    .fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Err(err) => {
                                            fwd_stats
                                                .destination_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                            fwd_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                            eprintln!(
                                                "[stream {}] Destination resolution error for '{}': {}",
                                                fwd_stream_id, dest.address, err
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
                                                fwd_stream_id, dest.address, e
                                            );
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
            is_active,
            shutdown_flag,
            threads: runner_threads,
        })
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
}

#[derive(Clone)]
struct StreamRunnerHandle {
    stream_id: String,
    stats: Arc<StreamStats>,
    is_active: Arc<AtomicBool>,
    shutdown_flag: Arc<AtomicBool>,
}

impl RelayHealthHandle {
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
        self.stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)
            .map(|r| r.stats.snapshot())
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
}

impl Relay {
    /// Starts all forwarding streams defined across all instances in the configuration.
    ///
    /// # Errors
    /// Returns an error if any stream fails to bind its listening socket.
    pub fn start(config: &Config) -> io::Result<Self> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let mut stream_runners = Vec::new();
        let mut logical_interfaces = Vec::new();

        for inst in config.all_instances() {
            for stream in &inst.streams {
                let runner = StreamRunner::start(stream, &inst, Arc::clone(&shutdown_flag))?;
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
        })
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
                is_active: Arc::clone(&r.is_active),
                shutdown_flag: Arc::clone(&r.shutdown_flag),
            })
            .collect();
        RelayHealthHandle {
            stream_runners: Arc::new(handles),
            logical_interfaces: Arc::new(self.logical_interfaces.clone()),
            shutdown_flag: Arc::clone(&self.shutdown_flag),
            start_time: self.start_time,
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

    /// Returns all configured logical interfaces.
    #[must_use]
    pub fn logical_interfaces(&self) -> &[LogicalInterfaceInfo] {
        &self.logical_interfaces
    }

    /// Retrieves statistics for a specific stream.
    #[must_use]
    pub fn stream_stats(&self, stream_id: &str) -> Option<StreamStatsSnapshot> {
        self.stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)
            .map(|r| r.stats.snapshot())
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
}
