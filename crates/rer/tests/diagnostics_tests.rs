//! Integration tests for RER diagnostic event model and bounded non-blocking buffer (SPEC §8, §10).

use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

use rer::config::TransportType;
use rer::diagnostics::{DiagnosticBuffer, DiagnosticEvent, DiagnosticStage, ManualClock};

#[test]
fn test_stage_names_and_snake_case_pinned() {
    let cases = [
        (DiagnosticStage::Received, "\"received\""),
        (DiagnosticStage::Accepted, "\"accepted\""),
        (DiagnosticStage::RoutedOrQueued, "\"routed_or_queued\""),
        (DiagnosticStage::SendAttempted, "\"send_attempted\""),
        (DiagnosticStage::SendSucceeded, "\"send_succeeded\""),
        (DiagnosticStage::Dropped, "\"dropped\""),
        (DiagnosticStage::Failure, "\"failure\""),
        (DiagnosticStage::HealthTransition, "\"health_transition\""),
    ];

    for (stage, expected_json) in cases {
        let serialized = serde_json::to_string(&stage).expect("failed to serialize stage");
        assert_eq!(serialized, expected_json);

        let deserialized: DiagnosticStage =
            serde_json::from_str(expected_json).expect("failed to deserialize stage");
        assert_eq!(deserialized, stage);
    }
}

#[test]
fn test_event_has_no_payload_bytes_field() {
    let event = DiagnosticEvent::new(
        1000,
        2000,
        "stream-test",
        DiagnosticStage::Accepted,
        TransportType::Udp,
        1400,
    )
    .with_source("127.0.0.1:4000")
    .with_destination("127.0.0.1:5000")
    .with_correlation_id("corr-xyz")
    .with_reason("ok");

    let val = serde_json::to_value(&event).expect("serialize event");
    let obj = val.as_object().expect("object expected");

    assert_eq!(
        obj.get("payload_length").and_then(|v| v.as_u64()),
        Some(1400)
    );
    assert!(!obj.contains_key("payload"));
    assert!(!obj.contains_key("data"));
    assert!(!obj.contains_key("bytes"));
    assert!(!obj.contains_key("packet"));
    assert!(!obj.contains_key("body"));
}

#[test]
fn test_buffer_full_overwrites_oldest_and_snapshot_arrival_order() {
    let clock = Arc::new(ManualClock::new(100, 200));
    let buffer = DiagnosticBuffer::with_clock(3, clock.clone());

    // Push 3 events
    for i in 1..=3 {
        clock.advance_millis(10);
        let ev = buffer.create_event(
            format!("s-{i}"),
            DiagnosticStage::Received,
            TransportType::Udp,
            50 * i,
        );
        assert!(buffer.emit(ev));
    }

    assert_eq!(buffer.dropped_count(), 0);
    assert_eq!(buffer.len(), 3);

    // Push 4th event -> s-1 is overwritten, dropped_count becomes 1
    clock.advance_millis(10);
    let ev4 = buffer.create_event(
        "s-4",
        DiagnosticStage::SendAttempted,
        TransportType::Tcp,
        200,
    );
    assert!(buffer.emit(ev4));

    assert_eq!(buffer.dropped_count(), 1);
    let snap = buffer.snapshot();
    assert_eq!(snap.dropped_count, 1);
    assert_eq!(snap.events.len(), 3);
    assert_eq!(snap.events[0].stream_id, "s-2");
    assert_eq!(snap.events[1].stream_id, "s-3");
    assert_eq!(snap.events[2].stream_id, "s-4");

    // Push 5th event -> s-2 overwritten, dropped_count becomes 2
    clock.advance_millis(10);
    let ev5 = buffer.create_event(
        "s-5",
        DiagnosticStage::SendSucceeded,
        TransportType::Tcp,
        250,
    );
    assert!(buffer.emit(ev5));

    assert_eq!(buffer.dropped_count(), 2);
    let (events, drops) = buffer.snapshot_events();
    assert_eq!(drops, 2);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].stream_id, "s-3");
    assert_eq!(events[1].stream_id, "s-4");
    assert_eq!(events[2].stream_id, "s-5");
}

#[test]
fn test_emitting_never_blocks_under_contention() {
    let clock = Arc::new(ManualClock::new(0, 0));
    let buffer = DiagnosticBuffer::with_clock(10, clock);

    let (tx_held, rx_held) = mpsc::channel();
    let (tx_continue, rx_continue) = mpsc::channel();

    let buf_bg = buffer.clone();
    let bg_thread = thread::spawn(move || {
        let guard = buf_bg.hold_lock();
        tx_held.send(()).unwrap();
        rx_continue.recv().unwrap();
        drop(guard);
    });

    rx_held.recv().unwrap();

    // Buffer is currently held by background thread
    let ev = DiagnosticEvent::new(
        1,
        2,
        "s",
        DiagnosticStage::Received,
        TransportType::Udp,
        100,
    );
    let accepted = buffer.emit(ev);

    assert!(
        !accepted,
        "emit must return at once with false when buffer is held"
    );
    assert_eq!(buffer.dropped_count(), 1);

    tx_continue.send(()).unwrap();
    bg_thread.join().unwrap();

    assert_eq!(buffer.snapshot().events.len(), 0);
    assert_eq!(buffer.dropped_count(), 1);
}

#[test]
fn test_rate_limiting_across_second_boundary_without_sleeping() {
    let clock = Arc::new(ManualClock::new(0, 0));
    // 3 events per second
    let buffer = DiagnosticBuffer::with_clock_and_rate_limit(10, clock.clone(), 3);

    // Second 0
    let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Udp, 10);
    let ev2 = buffer.create_event("s2", DiagnosticStage::Accepted, TransportType::Udp, 20);
    let ev3 = buffer.create_event(
        "s3",
        DiagnosticStage::RoutedOrQueued,
        TransportType::Udp,
        30,
    );
    let ev4 = buffer.create_event("s4", DiagnosticStage::SendAttempted, TransportType::Udp, 40);

    assert!(buffer.emit(ev1));
    assert!(buffer.emit(ev2));
    assert!(buffer.emit(ev3));
    assert!(
        !buffer.emit(ev4),
        "4th event in second 0 must be rate-limited"
    );
    assert_eq!(buffer.dropped_count(), 1);

    // Advance clock past the 1-second boundary: monotonic = 1_000_000_000 ns
    // No sleeping!
    clock.advance_secs(1);

    let ev5 = buffer.create_event("s5", DiagnosticStage::SendSucceeded, TransportType::Udp, 50);
    let ev6 = buffer.create_event("s6", DiagnosticStage::Received, TransportType::Udp, 60);
    let ev7 = buffer.create_event("s7", DiagnosticStage::Accepted, TransportType::Udp, 70);
    let ev8 = buffer.create_event("s8", DiagnosticStage::SendAttempted, TransportType::Udp, 80);

    assert!(
        buffer.emit(ev5),
        "boundary crossed: 1st event in second 1 accepted"
    );
    assert!(buffer.emit(ev6), "2nd event in second 1 accepted");
    assert!(buffer.emit(ev7), "3rd event in second 1 accepted");
    assert!(!buffer.emit(ev8), "4th event in second 1 rejected");
    assert_eq!(buffer.dropped_count(), 2);

    let snap = buffer.snapshot();
    assert_eq!(snap.events.len(), 6);
    assert_eq!(snap.dropped_count, 2);
}
