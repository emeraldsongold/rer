use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::{Config, DropPolicy, InstanceConfig, StreamConfig, TransportType};

/// Default maximum queue size (packets) when not explicitly configured.
pub const DEFAULT_MAX_QUEUE_SIZE: usize = 1024;

/// Default maximum packet size (bytes) when not explicitly configured.
pub const DEFAULT_MAX_PACKET_SIZE: usize = 65535;

/// Default overload drop policy when not explicitly configured.
pub const DEFAULT_DROP_POLICY: DropPolicy = DropPolicy::DropOldest;

/// A discrete UDP datagram payload preserving datagram boundary and source.
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

/// Thread-safe counters tracking stream activity, drop events, and socket errors.
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
}

/// Active forwarding runner for a single stream.
pub struct StreamRunner {
    pub stream_id: String,
    pub stats: Arc<StreamStats>,
    is_active: Arc<AtomicBool>,
    shutdown_flag: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl StreamRunner {
    /// Starts forwarding for a single stream.
    ///
    /// # Errors
    /// Returns an error if the source socket cannot be bound.
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

        // Bind source UDP socket
        let recv_socket = UdpSocket::bind(&stream.source.address)?;
        recv_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        // Collect destination addresses
        let mut dest_specs = Vec::new();
        if let Some(dest) = &stream.destination {
            dest_specs.push(dest.clone());
        }
        if let Some(dests) = &stream.destinations {
            dest_specs.extend(dests.clone());
        }

        // Shared queue state
        let queue = Arc::new(Mutex::new(BoundedQueue::new(max_queue_size, drop_policy)));
        let condvar = Arc::new(Condvar::new());
        let receiver_done = Arc::new(AtomicBool::new(false));

        // Receiver thread
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
                                eprintln!(
                                    "[stream {}] Queue overload ({}/{}): dropped oldest packet (policy: drop_oldest)",
                                    recv_stream_id, max_queue_size, max_queue_size
                                );
                            }
                            PushResult::DroppedNewest => {
                                recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                eprintln!(
                                    "[stream {}] Queue overload ({}/{}): dropped newest packet (policy: drop_newest)",
                                    recv_stream_id, max_queue_size, max_queue_size
                                );
                            }
                            PushResult::Rejected => {
                                recv_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                recv_stats.drops_queue_full.fetch_add(1, Ordering::Relaxed);
                                eprintln!(
                                    "[stream {}] Queue overload ({}/{}): rejected packet (policy: reject)",
                                    recv_stream_id, max_queue_size, max_queue_size
                                );
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        // Check shutdown flag
                    }
                    Err(e) => {
                        recv_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[stream {}] Socket receive error: {}", recv_stream_id, e);
                    }
                }
            }

            recv_done_flag.store(true, Ordering::SeqCst);
            recv_condvar.notify_all();
        });

        // Forwarder thread
        let fwd_stream_id = stream_id.clone();
        let fwd_stats = Arc::clone(&stats);
        let fwd_shutdown = Arc::clone(&shutdown_flag);
        let fwd_queue = Arc::clone(&queue);
        let fwd_condvar = Arc::clone(&condvar);
        let fwd_done_flag = Arc::clone(&receiver_done);
        let is_active = Arc::new(AtomicBool::new(true));
        let fwd_is_active = Arc::clone(&is_active);

        let fwd_handle = thread::spawn(move || {
            // Bind outbound sockets
            let ipv4_socket = UdpSocket::bind("0.0.0.0:0").ok();
            let ipv6_socket = UdpSocket::bind("[::]:0").ok();

            loop {
                let datagram_opt = {
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
                    q.pop()
                };

                match datagram_opt {
                    Some(datagram) => {
                        // Forward to all destinations
                        for dest in &dest_specs {
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
                                                fwd_stats
                                                    .forwarded_packets
                                                    .fetch_add(1, Ordering::Relaxed);
                                                fwd_stats
                                                    .forwarded_bytes
                                                    .fetch_add(sent as u64, Ordering::Relaxed);
                                            }
                                            Err(err) => {
                                                fwd_stats
                                                    .destination_errors
                                                    .fetch_add(1, Ordering::Relaxed);
                                                fwd_stats
                                                    .socket_errors
                                                    .fetch_add(1, Ordering::Relaxed);
                                                eprintln!(
                                                    "[stream {}] Destination error sending to {}: {}",
                                                    fwd_stream_id, target_addr, err
                                                );
                                            }
                                        }
                                    } else {
                                        fwd_stats
                                            .destination_errors
                                            .fetch_add(1, Ordering::Relaxed);
                                        eprintln!(
                                            "[stream {}] No socket address resolved for '{}'",
                                            fwd_stream_id, dest.address
                                        );
                                    }
                                }
                                Err(err) => {
                                    fwd_stats.destination_errors.fetch_add(1, Ordering::Relaxed);
                                    fwd_stats.socket_errors.fetch_add(1, Ordering::Relaxed);
                                    eprintln!(
                                        "[stream {}] Destination resolution error for '{}': {}",
                                        fwd_stream_id, dest.address, err
                                    );
                                }
                            }
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

        Ok(Self {
            stream_id,
            stats,
            is_active,
            shutdown_flag,
            threads: vec![recv_handle, fwd_handle],
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
}

/// A running multi-instance RER relay.
pub struct Relay {
    stream_runners: Vec<StreamRunner>,
    shutdown_flag: Arc<AtomicBool>,
    start_time: std::time::Instant,
}

impl Relay {
    /// Starts all UDP relay streams defined across all instances in the configuration.
    ///
    /// # Errors
    /// Returns an error if any stream fails to bind its listening socket.
    pub fn start(config: &Config) -> io::Result<Self> {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let mut stream_runners = Vec::new();

        for inst in config.all_instances() {
            for stream in &inst.streams {
                if stream.source.transport == TransportType::Udp {
                    let runner = StreamRunner::start(stream, &inst, Arc::clone(&shutdown_flag))?;
                    stream_runners.push(runner);
                }
            }
        }

        Ok(Self {
            stream_runners,
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

    /// Retrieves statistics for a specific stream.
    #[must_use]
    pub fn stream_stats(&self, stream_id: &str) -> Option<StreamStatsSnapshot> {
        self.stream_runners
            .iter()
            .find(|r| r.stream_id == stream_id)
            .map(|r| r.stats.snapshot())
    }

    /// Gracefully stops the relay, joins all worker threads, and prints statistics.
    pub fn stop(self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        for runner in self.stream_runners {
            let id = runner.stream_id.clone();
            let snap = runner.stats.snapshot();
            runner.stop();
            eprintln!(
                "[relay] Stream '{}' final stats: rx={}/{}B, tx={}/{}B, drops={} (queue={}, oversized={}), errors={} (dest={}, socket={})",
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
                snap.socket_errors
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
