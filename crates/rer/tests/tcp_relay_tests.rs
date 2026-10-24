use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rer::config::{Config, DropPolicy, TransportType};
use rer::framing::{encode_frame, read_frame};
use rer::relay::Relay;
use rer::sim::{GeneratorConfig, HarnessConfig, SimulationHarness};

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

// ===========================================================================
// Acceptance Criterion 1: Harness-driven integration tests for all 4
// transport conversion combinations (UDP->UDP, UDP->TCP, TCP->UDP, TCP->TCP)
// ===========================================================================

#[test]
fn test_harness_integration_udp_to_udp() {
    let harness_config = HarnessConfig {
        test_id: Some("harness-udp-to-udp".into()),
        generator: GeneratorConfig {
            seed: 1001,
            packet_size: 128,
            rate: Some(500.0),
            burst: Some(2),
            duration: None,
            count: Some(30),
        },
        impairments: None,
        use_relay: true,
        relay_queue_capacity: Some(100),
        relay_drop_policy: Some(DropPolicy::DropOldest),
        source_transport: TransportType::Udp,
        destination_transport: TransportType::Udp,
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("run harness udp-to-udp");
    assert!(report.pass, "UDP-to-UDP harness test must pass");
    assert_eq!(report.received_count, 30);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.corrupted_count, 0);
    assert!(report.payload_hashes_verified);
    assert_eq!(report.actual_stream_hash, report.expected_stream_hash);
}

#[test]
fn test_harness_integration_udp_to_tcp() {
    let harness_config = HarnessConfig {
        test_id: Some("harness-udp-to-tcp".into()),
        generator: GeneratorConfig {
            seed: 1002,
            packet_size: 256,
            rate: Some(400.0),
            burst: Some(2),
            duration: None,
            count: Some(30),
        },
        impairments: None,
        use_relay: true,
        relay_queue_capacity: Some(100),
        relay_drop_policy: Some(DropPolicy::DropOldest),
        source_transport: TransportType::Udp,
        destination_transport: TransportType::Tcp,
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("run harness udp-to-tcp");
    assert!(report.pass, "UDP-to-TCP harness test must pass");
    assert_eq!(report.received_count, 30);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.corrupted_count, 0);
    assert!(report.payload_hashes_verified);
    assert_eq!(report.actual_stream_hash, report.expected_stream_hash);
}

#[test]
fn test_harness_integration_tcp_to_udp() {
    let harness_config = HarnessConfig {
        test_id: Some("harness-tcp-to-udp".into()),
        generator: GeneratorConfig {
            seed: 1003,
            packet_size: 200,
            rate: Some(400.0),
            burst: Some(2),
            duration: None,
            count: Some(30),
        },
        impairments: None,
        use_relay: true,
        relay_queue_capacity: Some(100),
        relay_drop_policy: Some(DropPolicy::DropOldest),
        source_transport: TransportType::Tcp,
        destination_transport: TransportType::Udp,
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("run harness tcp-to-udp");
    assert!(report.pass, "TCP-to-UDP harness test must pass");
    assert_eq!(report.received_count, 30);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.corrupted_count, 0);
    assert!(report.payload_hashes_verified);
    assert_eq!(report.actual_stream_hash, report.expected_stream_hash);
}

#[test]
fn test_harness_integration_tcp_to_tcp() {
    let harness_config = HarnessConfig {
        test_id: Some("harness-tcp-to-tcp".into()),
        generator: GeneratorConfig {
            seed: 1004,
            packet_size: 512,
            rate: Some(500.0),
            burst: Some(2),
            duration: None,
            count: Some(30),
        },
        impairments: None,
        use_relay: true,
        relay_queue_capacity: Some(100),
        relay_drop_policy: Some(DropPolicy::DropOldest),
        source_transport: TransportType::Tcp,
        destination_transport: TransportType::Tcp,
        ..Default::default()
    };

    let report = SimulationHarness::run(harness_config).expect("run harness tcp-to-tcp");
    assert!(report.pass, "TCP-to-TCP harness test must pass");
    assert_eq!(report.received_count, 30);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert_eq!(report.corrupted_count, 0);
    assert!(report.payload_hashes_verified);
    assert_eq!(report.actual_stream_hash, report.expected_stream_hash);
}

// ===========================================================================
// Acceptance Criterion 2: Framing between TCP byte streams and UDP datagrams
// is explicit, documented, and tested (boundary preservation & fidelity)
// ===========================================================================

#[test]
fn test_framing_preserves_datagram_boundaries_udp_to_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-framing-u2t"
    streams:
      - id: "s-u2t"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    // Sender sends UDP datagrams of diverse sizes
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let test_payloads: Vec<Vec<u8>> = vec![
        b"datagram-first".to_vec(),
        b"".to_vec(), // 0-byte datagram
        vec![0xAA; 1],
        vec![0xBB; 64],
        vec![0xCC; 1024],
        (0..1400).map(|i| (i % 256) as u8).collect(),
    ];

    // Accept TCP connection from relay
    let (mut stream, _) = listener.accept().expect("accept tcp connection");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let shutdown = AtomicBool::new(false);
    for payload in &test_payloads {
        sender
            .send_to(payload, format!("127.0.0.1:{listen_port}"))
            .expect("send udp datagram");

        let frame = read_frame(&mut stream, 65535, &shutdown)
            .expect("read frame")
            .expect("expected frame");
        assert_eq!(
            &frame, payload,
            "TCP frame payload must match UDP datagram payload exactly"
        );
    }

    relay.stop();
}

#[test]
fn test_framing_preserves_datagram_boundaries_tcp_to_udp() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-framing-t2u"
    streams:
      - id: "s-t2u"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    // Give relay listener a moment to start
    thread::sleep(Duration::from_millis(30));

    // Client connects to relay TCP source
    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay tcp");
    client.set_nodelay(true).unwrap();

    let test_payloads: Vec<Vec<u8>> = vec![
        b"tcp-datagram-1".to_vec(),
        b"".to_vec(),
        vec![0x11; 42],
        vec![0x22; 512],
        (0..1200).map(|i| (i % 256) as u8).collect(),
    ];

    for payload in &test_payloads {
        let frame = encode_frame(payload);
        client.write_all(&frame).expect("write tcp frame");

        let mut buf = vec![0u8; 2048];
        let (n, _) = receiver.recv_from(&mut buf).expect("receive udp datagram");
        assert_eq!(
            &buf[..n],
            payload.as_slice(),
            "UDP datagram received must match framed TCP payload exactly"
        );
    }

    relay.stop();
}

#[test]
fn test_framing_oversized_packets_dropped_and_counted() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-oversized"
    streams:
      - id: "s-oversized"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_packet_size: 100
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    thread::sleep(Duration::from_millis(30));

    let mut client =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect to relay");

    // Send valid frame (50 bytes <= 100)
    let valid_payload = vec![0x42; 50];
    client
        .write_all(&encode_frame(&valid_payload))
        .expect("write valid frame");

    let mut buf = vec![0u8; 256];
    let (n, _) = receiver.recv_from(&mut buf).expect("receive valid packet");
    assert_eq!(&buf[..n], valid_payload.as_slice());

    // Send oversized frame (200 bytes > 100)
    let oversized_payload = vec![0x99; 200];
    let _ = client.write_all(&encode_frame(&oversized_payload));

    thread::sleep(Duration::from_millis(50));
    let stats = relay.stream_stats("s-oversized").expect("stream stats");
    assert_eq!(stats.drops_oversized, 1);
    assert_eq!(stats.dropped_packets, 1);

    relay.stop();
}

// ===========================================================================
// Acceptance Criterion 3: TCP connection lifecycle, reconnect with backoff
// and timeouts tested against destination outages
// ===========================================================================

#[test]
fn test_tcp_destination_outage_at_startup_reconnects_with_backoff() {
    let dest_port = pick_unused_port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-reconnect-startup"
    streams:
      - id: "s-reconnect"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    // Sender sends UDP packets while TCP destination is NOT running (outage)
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for i in 0..5 {
        sender
            .send_to(
                format!("pkt-outage-{}", i).as_bytes(),
                format!("127.0.0.1:{listen_port}"),
            )
            .expect("send datagram");
    }

    // Give relay a moment to attempt connection, fail, and enter backoff
    thread::sleep(Duration::from_millis(100));

    let stats_before = relay.stream_stats("s-reconnect").expect("stats");
    assert!(
        stats_before.destination_errors > 0,
        "Destination error should be counted during outage"
    );

    // Now start destination TCP listener!
    let listener = TcpListener::bind(format!("127.0.0.1:{dest_port}")).expect("bind dest listener");
    listener
        .set_nonblocking(false)
        .expect("blocking mode for accept");

    // Accept connection from relay reconnecting with backoff
    let (mut stream, _) = listener
        .accept()
        .expect("relay must reconnect to destination");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let shutdown = AtomicBool::new(false);
    let mut received_count = 0;
    while received_count < 5 {
        match read_frame(&mut stream, 1024, &shutdown) {
            Ok(Some(frame)) => {
                let msg = String::from_utf8_lossy(&frame);
                assert!(msg.starts_with("pkt-outage-"));
                received_count += 1;
            }
            Ok(None) => break,
            Err(e) => panic!("error reading reconnected frame: {}", e),
        }
    }

    assert_eq!(
        received_count, 5,
        "All buffered packets must be forwarded upon reconnect"
    );

    let stats_after = relay.stream_stats("s-reconnect").expect("stats");
    assert_eq!(stats_after.forwarded_packets, 5);
    assert!(stats_after.destination_errors > 0);

    relay.stop();
}

#[test]
fn test_tcp_destination_outage_mid_stream_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind dest listener");
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-reconnect-mid"
    streams:
      - id: "s-mid"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Phase 1: Destination is up, receive 3 packets
    let (mut stream1, _) = listener.accept().expect("accept initial connection");
    stream1
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    for i in 0..3 {
        sender
            .send_to(
                format!("phase1-{}", i).as_bytes(),
                format!("127.0.0.1:{listen_port}"),
            )
            .unwrap();
        let frame = read_frame(&mut stream1, 1024, &AtomicBool::new(false))
            .unwrap()
            .unwrap();
        assert_eq!(frame, format!("phase1-{}", i).into_bytes());
    }

    // Phase 2: Kill destination connection and listener (outage)
    let _ = stream1.shutdown(std::net::Shutdown::Both);
    drop(stream1);
    drop(listener);
    thread::sleep(Duration::from_millis(50));

    // Send packets during outage
    for i in 0..3 {
        sender
            .send_to(
                format!("phase2-{}", i).as_bytes(),
                format!("127.0.0.1:{listen_port}"),
            )
            .unwrap();
    }

    // Wait for relay to detect outage and record destination error
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while relay
        .stream_stats("s-mid")
        .map(|s| s.destination_errors)
        .unwrap_or(0)
        == 0
    {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for relay to detect destination outage"
        );
        thread::sleep(Duration::from_millis(5));
    }

    // Phase 3: Destination comes back up on same port
    let listener2 =
        TcpListener::bind(format!("127.0.0.1:{dest_port}")).expect("rebind dest listener");
    let (mut stream2, _) = listener2
        .accept()
        .expect("relay must reconnect after outage");
    stream2
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut received_phase2 = 0;
    while received_phase2 < 3 {
        match read_frame(&mut stream2, 1024, &AtomicBool::new(false)) {
            Ok(Some(frame)) => {
                let msg = String::from_utf8_lossy(&frame);
                assert!(msg.starts_with("phase2-"));
                received_phase2 += 1;
            }
            Ok(None) => break,
            Err(e) => panic!("error reading reconnected frame: {}", e),
        }
    }

    assert_eq!(
        received_phase2, 3,
        "All packets sent during outage must arrive after reconnect"
    );

    let stats = relay.stream_stats("s-mid").expect("stats");
    assert_eq!(stats.forwarded_packets, 6);
    assert!(stats.destination_errors > 0);

    relay.stop();
}

// ===========================================================================
// Acceptance Criterion 4: Backpressure from slow TCP readers is bounded
// and counted
// ===========================================================================

#[test]
fn test_slow_tcp_reader_backpressure_bounded_and_counted() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind dest listener");
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    // Small queue capacity of 5 with drop_oldest policy
    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-backpressure"
    streams:
      - id: "s-backpressure"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_queue_size: 5
          drop_policy: "drop_oldest"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let relay = Relay::start(&config).expect("start relay");

    // Accept TCP connection, but read VERY slowly or don't read (stall reader)
    let (mut slow_stream, _) = listener.accept().expect("accept connection");
    slow_stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();

    let stop_slow_reader = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop_slow_reader);

    // Reader does NOT read or reads once, keeping TCP socket receive window stalled
    let reader_handle = thread::spawn(move || {
        let shutdown = AtomicBool::new(false);
        // Read 1 frame to establish connection, then sleep to stall reader
        let _ = read_frame(&mut slow_stream, 65535, &shutdown);
        while !stop_flag.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(50));
        }
    });

    // Rapidly blast 60 large packets (40KB each = 2.4MB) into relay UDP source
    // Linux loopback TCP buffer is ~200KB, so kernel buffer saturates quickly,
    // stalling the forwarder and filling the relay's bounded queue of 5.
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let payload = vec![0x77; 40000];
    for _i in 0..60 {
        let _ = sender.send_to(&payload, format!("127.0.0.1:{listen_port}"));
        thread::sleep(Duration::from_millis(1));
    }

    // Give relay a moment to process overload
    thread::sleep(Duration::from_millis(150));

    let stats = relay.stream_stats("s-backpressure").expect("stats");

    // Backpressure verification:
    // 1. Packets must have been dropped due to bounded queue exhaustion
    assert!(
        stats.dropped_packets > 0,
        "Slow reader backpressure must cause packets to be dropped within bounds"
    );
    assert!(
        stats.drops_queue_full > 0,
        "Overload drops must be tracked under drops_queue_full"
    );
    // 2. Backpressure events must be counted
    assert!(
        stats.backpressure_events > 0,
        "Backpressure events must be counted (was: {})",
        stats.backpressure_events
    );

    stop_slow_reader.store(true, Ordering::Relaxed);
    let _ = reader_handle.join();

    relay.stop();
}
