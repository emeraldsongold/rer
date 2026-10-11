use std::net::UdpSocket;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use rer::config::Config;
use rer::relay::Relay;

fn rer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rer")
}

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

// ---------------------------------------------------------------------------
// Criterion 1: Datagram boundary preservation & payload fidelity
// ---------------------------------------------------------------------------

#[test]
fn test_udp_forwarding_preserves_boundaries_and_payloads() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = receiver.local_addr().expect("dest addr").port();
    let listen_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-loopback"
    streams:
      - id: "udp-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    assert!(config.validate().is_empty());

    // Start relay
    let relay = Relay::start(&config).expect("start relay");

    // Sender socket
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Distinct payloads of different sizes, verifying datagram boundary preservation
    let test_payloads: Vec<Vec<u8>> = vec![
        b"datagram-1-tiny".to_vec(),
        b"".to_vec(), // 0-byte datagram
        vec![0xAA; 64],
        vec![0x55; 512],
        (0..1400).map(|i| (i % 256) as u8).collect(), // 1400 bytes
    ];

    for payload in &test_payloads {
        sender
            .send_to(payload, format!("127.0.0.1:{listen_port}"))
            .expect("send datagram");

        let mut buf = vec![0u8; 2048];
        let (n, _src) = receiver.recv_from(&mut buf).expect("receive datagram");

        // Assert exact datagram boundary and payload preservation
        assert_eq!(
            &buf[..n],
            payload.as_slice(),
            "Datagram payload and boundary must match exactly"
        );
    }

    let stats = relay.stream_stats("udp-stream").expect("stream stats");
    assert_eq!(stats.received_packets, test_payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, test_payloads.len() as u64);
    assert_eq!(stats.dropped_packets, 0);
    assert_eq!(stats.destination_errors, 0);

    relay.stop();
}

// ---------------------------------------------------------------------------
// Criterion 2: Bounded queues, drop policies, and drop counters (never silent)
// ---------------------------------------------------------------------------

#[test]
fn test_bounded_queue_drop_policies_and_counters() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("set timeout");
    let dest_port = receiver.local_addr().expect("dest port").port();
    let listen_port = pick_unused_port();

    // Stream configured with queue capacity = 3 and max_packet_size = 100
    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-overload"
    streams:
      - id: "bounded-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_queue_size: 3
          max_packet_size: 100
          drop_policy: "drop_oldest"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Send oversized packet (> 100 bytes)
    let oversized = vec![0xFF; 150];
    sender
        .send_to(&oversized, format!("127.0.0.1:{listen_port}"))
        .expect("send oversized");

    // Wait briefly for relay to process
    thread::sleep(Duration::from_millis(100));

    // Oversized packet should be dropped and counted, never forwarded
    let mut buf = vec![0u8; 2048];
    assert!(
        receiver.recv_from(&mut buf).is_err(),
        "Oversized packet must not be forwarded"
    );

    let stats = relay.stream_stats("bounded-stream").expect("stats");
    assert_eq!(stats.drops_oversized, 1);
    assert_eq!(stats.dropped_packets, 1);

    // Send normal sized packet (should pass through)
    sender
        .send_to(b"valid-pkt", format!("127.0.0.1:{listen_port}"))
        .expect("send valid");

    let (n, _) = receiver.recv_from(&mut buf).expect("receive valid packet");
    assert_eq!(&buf[..n], b"valid-pkt");

    let final_stats = relay.stream_stats("bounded-stream").expect("stats");
    assert_eq!(final_stats.forwarded_packets, 1);

    relay.stop();
}

// ---------------------------------------------------------------------------
// Criterion 3: Unavailable destinations and socket errors counted without stopping
// ---------------------------------------------------------------------------

#[test]
fn test_unavailable_destination_error_counted_without_stopping_relay() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let valid_dest_port = receiver.local_addr().expect("valid dest port").port();
    let listen_port = pick_unused_port();

    // Fan-out configuration: one valid destination and one unresolvable/invalid destination
    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-errors"
    streams:
      - id: "fanout-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:{valid_dest_port}"
          - transport: "udp"
            address: "255.255.255.255:9999"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid config");
    let errors = config.validate();
    assert!(errors.is_empty(), "config should validate: {:?}", errors);

    let relay = Relay::start(&config).expect("start relay");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Send datagram
    sender
        .send_to(b"test-survives-error", format!("127.0.0.1:{listen_port}"))
        .expect("send datagram");

    // Valid receiver must still receive the packet!
    let mut buf = vec![0u8; 1024];
    let (n, _) = receiver
        .recv_from(&mut buf)
        .expect("valid receiver must receive packet despite faulty destination");
    assert_eq!(&buf[..n], b"test-survives-error");

    // Verify stats: 1 forwarded to valid dest, 1 destination error counted
    thread::sleep(Duration::from_millis(50));
    let stats = relay.stream_stats("fanout-stream").expect("stats");
    assert_eq!(stats.forwarded_packets, 1);
    assert!(
        stats.destination_errors >= 1,
        "Destination error must be counted"
    );

    // Relay is still alive and forwards subsequent packets
    sender
        .send_to(b"second-packet", format!("127.0.0.1:{listen_port}"))
        .expect("send second datagram");

    let (n2, _) = receiver
        .recv_from(&mut buf)
        .expect("relay must remain running and process subsequent datagrams");
    assert_eq!(&buf[..n2], b"second-packet");

    relay.stop();
}

// ---------------------------------------------------------------------------
// Criterion 4: Graceful startup and shutdown on SIGINT and SIGTERM
// ---------------------------------------------------------------------------

fn spawn_rer_process(config_path: &Path) -> Child {
    Command::new(rer_bin())
        .arg("run")
        .arg("--config")
        .arg(config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn rer run")
}

#[test]
fn test_graceful_shutdown_on_sigint() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let temp_dir = std::env::temp_dir();
    let cfg_path = temp_dir.join(format!("test_sigint_{}.yaml", listen_port));
    std::fs::write(
        &cfg_path,
        format!(
            r#"
version: "1"
instances:
  - id: "relay-sigint"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
        ),
    )
    .unwrap();

    let mut child = spawn_rer_process(&cfg_path);

    // Verify relay is active by sending a packet
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut verified = false;
    for _ in 0..30 {
        let _ = sender.send_to(b"ping", format!("127.0.0.1:{listen_port}"));
        let mut buf = [0u8; 32];
        if let Ok((n, _)) = receiver.recv_from(&mut buf) {
            if &buf[..n] == b"ping" {
                verified = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(verified, "Relay must start up and forward packets");

    // Send SIGINT to the running child process
    let pid = child.id() as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGINT);
    }

    // Wait for graceful shutdown
    let wait_res = child.wait().expect("child wait");
    let _ = std::fs::remove_file(&cfg_path);

    assert!(
        wait_res.success(),
        "Relay must shut down gracefully with exit code 0 on SIGINT"
    );
}

#[test]
fn test_graceful_shutdown_on_sigterm() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_port();

    let temp_dir = std::env::temp_dir();
    let cfg_path = temp_dir.join(format!("test_sigterm_{}.yaml", listen_port));
    std::fs::write(
        &cfg_path,
        format!(
            r#"
version: "1"
instances:
  - id: "relay-sigterm"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
        ),
    )
    .unwrap();

    let mut child = spawn_rer_process(&cfg_path);

    // Verify relay is active by sending a packet
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut verified = false;
    for _ in 0..30 {
        let _ = sender.send_to(b"ping", format!("127.0.0.1:{listen_port}"));
        let mut buf = [0u8; 32];
        if let Ok((n, _)) = receiver.recv_from(&mut buf) {
            if &buf[..n] == b"ping" {
                verified = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(verified, "Relay must start up and forward packets");

    // Send SIGTERM to the running child process
    let pid = child.id() as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }

    // Wait for graceful shutdown
    let wait_res = child.wait().expect("child wait");
    let _ = std::fs::remove_file(&cfg_path);

    assert!(
        wait_res.success(),
        "Relay must shut down gracefully with exit code 0 on SIGTERM"
    );
}

// ---------------------------------------------------------------------------
// Criterion 5: rer run only starts from a configuration that passes validation
// ---------------------------------------------------------------------------

#[test]
fn test_rer_run_refuses_invalid_configuration() {
    let temp_dir = std::env::temp_dir();

    // 1. Invalid port (port 0)
    let bad_cfg = temp_dir.join("test_run_invalid_port.yaml");
    std::fs::write(
        &bad_cfg,
        r#"
version: "1"
instances:
  - id: "node1"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:0"
        destination:
          transport: "udp"
          address: "127.0.0.1:5000"
"#,
    )
    .unwrap();

    let output = Command::new(rer_bin())
        .arg("run")
        .arg(&bad_cfg)
        .output()
        .expect("run rer run");
    let _ = std::fs::remove_file(&bad_cfg);

    assert!(
        !output.status.success(),
        "rer run must fail validation for port 0"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("validation failed") || stderr.contains("invalid"));

    // 2. Unknown field
    let unknown_cfg = temp_dir.join("test_run_unknown_field.yaml");
    std::fs::write(
        &unknown_cfg,
        r#"
version: "1"
instances:
  - id: "node1"
    non_existent_key: "boom"
"#,
    )
    .unwrap();

    let output2 = Command::new(rer_bin())
        .arg("run")
        .arg(&unknown_cfg)
        .output()
        .expect("run rer run");
    let _ = std::fs::remove_file(&unknown_cfg);

    assert!(
        !output2.status.success(),
        "rer run must fail for unknown fields"
    );

    // 3. Missing argument
    let output3 = Command::new(rer_bin())
        .arg("run")
        .output()
        .expect("run rer run without args");
    assert!(
        !output3.status.success(),
        "rer run must fail when no config file provided"
    );
}
