use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use rer::config::Config;
use rer::framing::{encode_frame, read_frame};
use rer::relay::{
    bind_tcp_listener, bind_udp_socket, format_endpoint, resolve_endpoint, select_socket_addr,
    Relay,
};

fn check_ipv6_loopback() -> bool {
    match UdpSocket::bind("[::1]:0") {
        Ok(_) => true,
        Err(err) => {
            let msg = format!(
                "SKIPPED: IPv6 loopback ([::1]) is unavailable in this environment ({err}); skipping IPv6 loopback test.\n"
            );
            let _ = std::io::stderr().write_all(msg.as_bytes());
            eprintln!("{msg}");
            println!("{msg}");
            false
        }
    }
}

fn pick_unused_ipv4_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral ipv4 socket");
    s.local_addr().expect("local addr").port()
}

fn pick_unused_ipv6_port() -> u16 {
    let s = UdpSocket::bind("[::1]:0").expect("bind ephemeral ipv6 socket");
    s.local_addr().expect("local addr").port()
}

// ============================================================================
// 1. IPV6_V6ONLY Listener Isolation
// ============================================================================

#[test]
fn test_ipv6_v6only_listener_isolation() {
    // 1. TCP Listener isolation on [::]:0
    let tcp_listener = bind_tcp_listener("[::]:0".parse().unwrap()).expect("bind [::]:0 TCP");
    let tcp_port = tcp_listener.local_addr().unwrap().port();

    // An IPv4 client connecting to 127.0.0.1:{tcp_port} MUST be refused/fail
    // because IPV6_V6ONLY explicitly isolates the IPv6 listener.
    let connect_res = TcpStream::connect_timeout(
        &SocketAddr::V4(format!("127.0.0.1:{tcp_port}").parse().unwrap()),
        Duration::from_millis(200),
    );
    assert!(
        connect_res.is_err(),
        "IPv4 client must not connect to [::] listener when IPV6_V6ONLY is set (expected connection failure, got: {:?})",
        connect_res
    );

    // 2. UDP Socket isolation on [::]:0
    let udp_listener = bind_udp_socket("[::]:0".parse().unwrap()).expect("bind [::]:0 UDP");
    let udp_port = udp_listener.local_addr().unwrap().port();
    udp_listener
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();

    let ipv4_sender = UdpSocket::bind("127.0.0.1:0").expect("bind IPv4 sender");
    ipv4_sender
        .send_to(b"ipv4-probe", format!("127.0.0.1:{udp_port}"))
        .expect("send IPv4 datagram");

    let mut buf = [0u8; 64];
    let recv_res = udp_listener.recv_from(&mut buf);
    assert!(
        recv_res.is_err(),
        "IPv4 datagram must not reach [::] UDP listener with IPV6_V6ONLY set (expected timeout/error, got: {:?})",
        recv_res
    );
}

// ============================================================================
// 2. Hostname and Address Selection Rule Unit Tests
// ============================================================================

#[test]
fn test_endpoint_address_selection_rule() {
    let v4: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let v6: SocketAddr = "[::1]:5000".parse().unwrap();

    // Documented selection rule: when both IPv4 and IPv6 families are present,
    // select the first IPv4 address.
    assert_eq!(select_socket_addr(&[v6, v4]), Some(v4));
    assert_eq!(select_socket_addr(&[v4, v6]), Some(v4));

    // When only IPv6 is present, select first IPv6 address
    assert_eq!(select_socket_addr(&[v6]), Some(v6));

    // When only IPv4 is present, select first IPv4 address
    assert_eq!(select_socket_addr(&[v4]), Some(v4));

    // Empty list returns None
    assert_eq!(select_socket_addr(&[]), None);

    // resolve_endpoint on literals
    assert_eq!(resolve_endpoint("[::1]:5000").unwrap(), v6);
    assert_eq!(resolve_endpoint("127.0.0.1:5000").unwrap(), v4);

    // format_endpoint ensures bracketed IPv6 representation
    assert_eq!(format_endpoint("[::1]:5000"), "[::1]:5000");
    assert_eq!(format_endpoint("127.0.0.1:5000"), "127.0.0.1:5000");
    assert_eq!(format_endpoint("::1:5000"), "[::1]:5000");
    assert_eq!(format_endpoint("::1"), "[::1]");
}

// ============================================================================
// 3. Unresolvable Destination Resilience & Error Counting
// ============================================================================

#[test]
fn test_unresolvable_and_unreachable_destination_resilience_and_counters() {
    // 1. Direct unit verification: unresolvable addresses return Err
    assert!(resolve_endpoint("").is_err());

    // 2. Relay fan-out resilience: unreachable destinations (IPv6 & IPv4) are counted
    // while valid destinations continue receiving all packets without interruption.
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set timeout");
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv4_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-unreachable-test"
    streams:
      - id: "fanout-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:{dest_port}"
          - transport: "udp"
            address: "[100::1]:5000"
          - transport: "udp"
            address: "255.255.255.255:9999"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let test_payloads = [b"pkt-1", b"pkt-2", b"pkt-3", b"pkt-4", b"pkt-5"];

    for p in &test_payloads {
        sender
            .send_to(*p, format!("127.0.0.1:{listen_port}"))
            .expect("send pkt");

        let mut buf = [0u8; 128];
        let (n, _) = receiver.recv_from(&mut buf).expect("receive pkt");
        assert_eq!(&buf[..n], *p);
    }

    let stats = relay.stream_stats("fanout-stream").expect("stream stats");
    assert_eq!(stats.received_packets, 5);
    assert_eq!(stats.forwarded_packets, 5);
    assert!(
        stats.destination_errors >= 5,
        "destination_errors should be >= 5 (got {})",
        stats.destination_errors
    );
    assert!(
        relay.health_handle().is_healthy(),
        "relay must remain healthy"
    );

    relay.stop();
}

// ============================================================================
// 4. IPv4 to IPv6 Loopback Integration Tests (All 4 transport combinations)
// ============================================================================

#[test]
fn test_loopback_ipv4_to_ipv6_udp_to_udp() {
    if !check_ipv6_loopback() {
        return;
    }

    let receiver = UdpSocket::bind("[::1]:0").expect("bind ipv6 receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv4_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v4-to-v6-u2u"
    streams:
      - id: "s-u2u"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "[::1]:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let payloads: Vec<Vec<u8>> = vec![
        b"alpha-boundary".to_vec(),
        b"".to_vec(),
        vec![0x33; 100],
        (0..1200).map(|i| (i % 255) as u8).collect(),
    ];

    for p in &payloads {
        sender
            .send_to(p, format!("127.0.0.1:{listen_port}"))
            .expect("send");
        let mut buf = vec![0u8; 2048];
        let (n, _) = receiver.recv_from(&mut buf).expect("recv");
        assert_eq!(
            &buf[..n],
            p.as_slice(),
            "payload bytes and boundaries must match"
        );
    }

    let stats = relay.stream_stats("s-u2u").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

#[test]
fn test_loopback_ipv4_to_ipv6_udp_to_tcp() {
    if !check_ipv6_loopback() {
        return;
    }

    let listener = TcpListener::bind("[::1]:0").expect("bind ipv6 tcp listener");
    listener.set_nonblocking(false).unwrap();
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv4_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v4-to-v6-u2t"
    streams:
      - id: "s-u2t"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "tcp"
          address: "[::1]:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let (mut client_stream, _) = listener.accept().expect("accept relay connection");
    client_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let shutdown = Arc::new(AtomicBool::new(false));
    let payloads = vec![b"udp-to-tcp-1".to_vec(), vec![0x99; 250], b"".to_vec()];

    for p in &payloads {
        sender
            .send_to(p, format!("127.0.0.1:{listen_port}"))
            .expect("send");
        let recvd = read_frame(&mut client_stream, 65535, &shutdown)
            .expect("read frame")
            .expect("got payload");
        assert_eq!(&recvd, p.as_slice(), "framed payload must match");
    }

    let stats = relay.stream_stats("s-u2t").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

#[test]
fn test_loopback_ipv4_to_ipv6_tcp_to_udp() {
    if !check_ipv6_loopback() {
        return;
    }

    let receiver = UdpSocket::bind("[::1]:0").expect("bind ipv6 udp receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv4_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v4-to-v6-t2u"
    streams:
      - id: "s-t2u"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "[::1]:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let mut sender =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect tcp sender");
    let payloads = vec![b"tcp-to-udp-msg".to_vec(), vec![0x77; 300]];

    for p in &payloads {
        let frame = encode_frame(p);
        sender.write_all(&frame).expect("send frame");

        let mut buf = vec![0u8; 1024];
        let (n, _) = receiver.recv_from(&mut buf).expect("recv udp datagram");
        assert_eq!(
            &buf[..n],
            p.as_slice(),
            "datagram boundaries and payload must match"
        );
    }

    let stats = relay.stream_stats("s-t2u").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

#[test]
fn test_loopback_ipv4_to_ipv6_tcp_to_tcp() {
    if !check_ipv6_loopback() {
        return;
    }

    let listener = TcpListener::bind("[::1]:0").expect("bind ipv6 tcp listener");
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv4_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v4-to-v6-t2t"
    streams:
      - id: "s-t2t"
        source:
          transport: "tcp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "tcp"
          address: "[::1]:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let (mut client_stream, _) = listener.accept().expect("accept connection");
    let mut sender =
        TcpStream::connect(format!("127.0.0.1:{listen_port}")).expect("connect tcp sender");
    let shutdown = Arc::new(AtomicBool::new(false));

    let payloads = vec![b"tcp-to-tcp-v4-to-v6".to_vec(), vec![0xAB; 150]];
    for p in &payloads {
        sender.write_all(&encode_frame(p)).expect("send frame");
        let recvd = read_frame(&mut client_stream, 65535, &shutdown)
            .expect("read frame")
            .expect("got payload");
        assert_eq!(&recvd, p.as_slice());
    }

    let stats = relay.stream_stats("s-t2t").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

// ============================================================================
// 5. IPv6 to IPv4 Loopback Integration Tests (All 4 transport combinations)
// ============================================================================

#[test]
fn test_loopback_ipv6_to_ipv4_udp_to_udp() {
    if !check_ipv6_loopback() {
        return;
    }

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind ipv4 receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv6_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v6-to-v4-u2u"
    streams:
      - id: "s-v6-u2u"
        source:
          transport: "udp"
          address: "[::1]:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let sender = UdpSocket::bind("[::1]:0").expect("bind ipv6 sender");
    let payloads = vec![b"ipv6-to-ipv4-udp".to_vec(), vec![0x55; 500]];

    for p in &payloads {
        sender
            .send_to(p, format!("[::1]:{listen_port}"))
            .expect("send");
        let mut buf = vec![0u8; 1024];
        let (n, _) = receiver.recv_from(&mut buf).expect("recv");
        assert_eq!(&buf[..n], p.as_slice(), "payloads must match");
    }

    let stats = relay.stream_stats("s-v6-u2u").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

#[test]
fn test_loopback_ipv6_to_ipv4_udp_to_tcp() {
    if !check_ipv6_loopback() {
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ipv4 tcp listener");
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv6_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v6-to-v4-u2t"
    streams:
      - id: "s-v6-u2t"
        source:
          transport: "udp"
          address: "[::1]:{listen_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let (mut client_stream, _) = listener.accept().expect("accept connection");
    let sender = UdpSocket::bind("[::1]:0").expect("bind sender");
    let shutdown = Arc::new(AtomicBool::new(false));

    let payloads = vec![b"v6-udp-to-v4-tcp".to_vec(), vec![0x11; 80]];
    for p in &payloads {
        sender
            .send_to(p, format!("[::1]:{listen_port}"))
            .expect("send");
        let recvd = read_frame(&mut client_stream, 65535, &shutdown)
            .expect("read frame")
            .expect("got payload");
        assert_eq!(&recvd, p.as_slice());
    }

    let stats = relay.stream_stats("s-v6-u2t").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

#[test]
fn test_loopback_ipv6_to_ipv4_tcp_to_udp() {
    if !check_ipv6_loopback() {
        return;
    }

    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let dest_port = receiver.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv6_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v6-to-v4-t2u"
    streams:
      - id: "s-v6-t2u"
        source:
          transport: "tcp"
          address: "[::1]:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let mut sender =
        TcpStream::connect(format!("[::1]:{listen_port}")).expect("connect tcp v6 sender");
    let payloads = vec![b"v6-tcp-to-v4-udp".to_vec(), vec![0x88; 120]];

    for p in &payloads {
        sender.write_all(&encode_frame(p)).expect("send frame");
        let mut buf = vec![0u8; 1024];
        let (n, _) = receiver.recv_from(&mut buf).expect("recv datagram");
        assert_eq!(&buf[..n], p.as_slice());
    }

    let stats = relay.stream_stats("s-v6-t2u").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

#[test]
fn test_loopback_ipv6_to_ipv4_tcp_to_tcp() {
    if !check_ipv6_loopback() {
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let dest_port = listener.local_addr().unwrap().port();
    let listen_port = pick_unused_ipv6_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-v6-to-v4-t2t"
    streams:
      - id: "s-v6-t2t"
        source:
          transport: "tcp"
          address: "[::1]:{listen_port}"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let (mut client_stream, _) = listener.accept().expect("accept connection");
    let mut sender =
        TcpStream::connect(format!("[::1]:{listen_port}")).expect("connect tcp sender");
    let shutdown = Arc::new(AtomicBool::new(false));

    let payloads = vec![b"v6-to-v4-tcp-stream".to_vec(), vec![0xCC; 200]];
    for p in &payloads {
        sender.write_all(&encode_frame(p)).expect("send frame");
        let recvd = read_frame(&mut client_stream, 65535, &shutdown)
            .expect("read frame")
            .expect("got payload");
        assert_eq!(&recvd, p.as_slice());
    }

    let stats = relay.stream_stats("s-v6-t2t").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, payloads.len() as u64);
    relay.stop();
}

// ============================================================================
// 6. Mixed-Family Fan-Out Preservation & Independence
// ============================================================================

#[test]
fn test_mixed_family_fanout_preserves_payload_and_boundaries() {
    if !check_ipv6_loopback() {
        return;
    }

    // 4 destinations of mixed families:
    // Dest 1: IPv4 UDP
    let d1_receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    d1_receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let d1_port = d1_receiver.local_addr().unwrap().port();

    // Dest 2: IPv6 UDP
    let d2_receiver = UdpSocket::bind("[::1]:0").unwrap();
    d2_receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let d2_port = d2_receiver.local_addr().unwrap().port();

    // Dest 3: IPv6 TCP
    let d3_listener = TcpListener::bind("[::1]:0").unwrap();
    let d3_port = d3_listener.local_addr().unwrap().port();

    // Dest 4: IPv4 TCP
    let d4_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let d4_port = d4_listener.local_addr().unwrap().port();

    let listen_port = pick_unused_ipv4_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-mixed-fanout"
    streams:
      - id: "stream-mixed-fanout"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:{d1_port}"
          - transport: "udp"
            address: "[::1]:{d2_port}"
          - transport: "tcp"
            address: "[::1]:{d3_port}"
          - transport: "tcp"
            address: "127.0.0.1:{d4_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let payloads: Vec<Vec<u8>> = vec![b"mixed-payload-1".to_vec(), vec![0x7A; 64], vec![0x2B; 512]];

    let payloads_d3 = payloads.clone();
    let d3_handle = std::thread::spawn(move || {
        let (mut d3_stream, _) = d3_listener.accept().unwrap();
        d3_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut frames = Vec::new();
        for _ in 0..payloads_d3.len() {
            let f = read_frame(&mut d3_stream, 65535, &shutdown)
                .expect("read frame d3")
                .expect("got payload d3");
            frames.push(f);
        }
        frames
    });

    let payloads_d4 = payloads.clone();
    let d4_handle = std::thread::spawn(move || {
        let (mut d4_stream, _) = d4_listener.accept().unwrap();
        d4_stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut frames = Vec::new();
        for _ in 0..payloads_d4.len() {
            let f = read_frame(&mut d4_stream, 65535, &shutdown)
                .expect("read frame d4")
                .expect("got payload d4");
            frames.push(f);
        }
        frames
    });

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

    for p in &payloads {
        sender
            .send_to(p, format!("127.0.0.1:{listen_port}"))
            .unwrap();

        // Check Dest 1 (IPv4 UDP)
        let mut b1 = vec![0u8; 1024];
        let (n1, _) = d1_receiver.recv_from(&mut b1).unwrap();
        assert_eq!(&b1[..n1], p.as_slice(), "Dest 1 (IPv4 UDP) mismatch");

        // Check Dest 2 (IPv6 UDP)
        let mut b2 = vec![0u8; 1024];
        let (n2, _) = d2_receiver.recv_from(&mut b2).unwrap();
        assert_eq!(&b2[..n2], p.as_slice(), "Dest 2 (IPv6 UDP) mismatch");
    }

    let d3_frames = d3_handle.join().unwrap();
    let d4_frames = d4_handle.join().unwrap();
    assert_eq!(d3_frames, payloads, "Dest 3 (IPv6 TCP) mismatch");
    assert_eq!(d4_frames, payloads, "Dest 4 (IPv4 TCP) mismatch");

    let stats = relay.stream_stats("stream-mixed-fanout").unwrap();
    assert_eq!(stats.received_packets, payloads.len() as u64);
    assert_eq!(stats.forwarded_packets, (payloads.len() * 4) as u64);
    relay.stop();
}

// ============================================================================
// 7. Diagnostics and Management Format Inspection
// ============================================================================

#[test]
fn test_diagnostic_and_management_bracketed_ipv6() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-bracketed-mgmt"
    management:
      enabled: true
      endpoint: "[::1]:9090"
    streams:
      - id: "s-ipv6"
        source:
          transport: "udp"
          address: "[::1]:5000"
        destination:
          transport: "tcp"
          address: "[::1]:5001"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse config");
    let errors = config.validate();
    assert!(
        errors.is_empty(),
        "Configuration with bracketed IPv6 literals must validate without errors: {:?}",
        errors
    );

    // Verify format_endpoint preserves bracketed literals
    assert_eq!(format_endpoint("[::1]:9090"), "[::1]:9090");
    assert_eq!(format_endpoint("[::1]:5000"), "[::1]:5000");
    assert_eq!(format_endpoint("[::1]:5001"), "[::1]:5001");
}
