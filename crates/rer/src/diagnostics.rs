//! Diagnostic event model with a bounded, non-blocking event buffer (SPEC §8, §10).
//!
//! Provides structured packet inspection events, lifecycle stages, clock abstraction
//! for deterministic testing, rate limiting, and a non-blocking ring buffer that never
//! stalls packet forwarding threads.

use std::collections::VecDeque;
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::config::TransportType;

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
            other => Err(format!("Unknown diagnostic stage: '{other}'")),
        }
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
        }
    }

    /// Returns a builder for configuring a `DiagnosticBuffer`.
    #[must_use]
    pub fn builder(capacity: usize) -> DiagnosticBufferBuilder {
        DiagnosticBufferBuilder::new(capacity)
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

    /// Emits a diagnostic event.
    ///
    /// This method is strictly non-blocking. If another thread holds the buffer,
    /// it returns immediately with `false`, and increments the dropped count.
    /// If a per-second rate limit is exceeded, it returns immediately with `false`
    /// and increments the dropped count.
    /// If the buffer is full, the oldest event is overwritten and the dropped count is incremented.
    pub fn emit(&self, event: DiagnosticEvent) -> bool {
        let Ok(mut inner) = self.inner.try_lock() else {
            self.dropped_count.fetch_add(1, Ordering::SeqCst);
            return false;
        };

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
}
