use std::io::Write;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use rer::config::Config;
use rer::framing;
use rer::relay::Relay;

fn get_available_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral udp");
    socket.local_addr().expect("local addr").port()
}

#[test]
fn test_paired_interface_independent_counters_and_endpoints() {
    let tx_src_port = get_available_port();
    let tx_dst_port = get_available_port();
    let rx_src_port = get_available_port();
    let rx_dst_port = get_available_port();

    // Destination receivers
    let tx_receiver = UdpSocket::bind(format!("127.0.0.1:{}", tx_dst_port)).expect("bind tx dst");
    tx_receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let rx_receiver_listener =
        TcpListener::bind(format!("127.0.0.1:{}", rx_dst_port)).expect("bind rx dst");
    rx_receiver_listener.set_nonblocking(true).unwrap();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-paired-test"
    streams:
      - id: "stream-tx"
        source:
          transport: "tcp"
          address: "127.0.0.1:{tx_src_port}"
          mode: "listen"
        destination:
          transport: "udp"
          address: "127.0.0.1:{tx_dst_port}"
      - id: "stream-rx"
        source:
          transport: "udp"
          address: "127.0.0.1:{rx_src_port}"
          mode: "listen"
        destination:
          transport: "tcp"
          address: "127.0.0.1:{rx_dst_port}"
    logical_interfaces:
      - id: "link-command-telemetry"
        name: "Paired Comm Link"
        tx_stream: "stream-tx"
        rx_stream: "stream-rx"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse yaml");
    assert!(config.validate().is_empty());

    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(50));

    // Phase 1: Send traffic ONLY on TX direction (TCP client to TX source)
    let mut tx_sender =
        TcpStream::connect(format!("127.0.0.1:{}", tx_src_port)).expect("connect tx src");
    let frame1 = framing::encode_frame(b"command-packet-1");
    tx_sender.write_all(&frame1).unwrap();
    tx_sender.flush().unwrap();

    let mut buf = vec![0u8; 512];
    let (n, _) = tx_receiver.recv_from(&mut buf).expect("receive on tx dst");
    assert_eq!(&buf[..n], b"command-packet-1");

    thread::sleep(Duration::from_millis(50));

    // Check independent stats: TX should have 1 packet, RX should have 0 packets!
    let iface_stats = relay
        .logical_interface_stats("link-command-telemetry")
        .expect("iface stats");
    assert_eq!(iface_stats.id, "link-command-telemetry");
    assert_eq!(iface_stats.tx_stream.as_deref(), Some("stream-tx"));
    assert_eq!(iface_stats.rx_stream.as_deref(), Some("stream-rx"));

    let tx_snap = iface_stats.tx_stats.expect("tx stats");
    let rx_snap = iface_stats.rx_stats.expect("rx stats");

    assert_eq!(tx_snap.received_packets, 1);
    assert_eq!(tx_snap.forwarded_packets, 1);
    assert_eq!(
        rx_snap.received_packets, 0,
        "RX direction must not count TX packets"
    );
    assert_eq!(
        rx_snap.forwarded_packets, 0,
        "RX direction must not count TX packets"
    );

    // Phase 2: Send traffic ONLY on RX direction (UDP sender to RX source)
    let rx_sender = UdpSocket::bind("127.0.0.1:0").expect("bind rx sender");
    rx_sender
        .send_to(b"telemetry-packet-1", format!("127.0.0.1:{}", rx_src_port))
        .expect("send to rx src");

    // Accept incoming connection on rx_receiver_listener
    let start = std::time::Instant::now();
    let mut accepted_stream = loop {
        match rx_receiver_listener.accept() {
            Ok((s, _)) => break s,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > Duration::from_secs(2) {
                    panic!("timeout waiting for rx tcp connection");
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("accept error: {}", e),
        }
    };
    accepted_stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let rx_frame = framing::read_frame(
        &mut accepted_stream,
        65535,
        &std::sync::atomic::AtomicBool::new(false),
    )
    .expect("read frame")
    .expect("frame present");
    assert_eq!(rx_frame, b"telemetry-packet-1");

    thread::sleep(Duration::from_millis(50));

    // Check updated stats: TX unchanged at 1, RX now at 1!
    let iface_stats_after = relay
        .logical_interface_stats("link-command-telemetry")
        .expect("iface stats");
    let tx_snap2 = iface_stats_after.tx_stats.expect("tx stats");
    let rx_snap2 = iface_stats_after.rx_stats.expect("rx stats");

    assert_eq!(tx_snap2.received_packets, 1);
    assert_eq!(tx_snap2.forwarded_packets, 1);
    assert_eq!(rx_snap2.received_packets, 1);
    assert_eq!(rx_snap2.forwarded_packets, 1);

    relay.stop();
}

#[test]
fn test_paired_interface_independent_errors_and_routing() {
    let tx_src_port = get_available_port();
    let _tx_dst_port = get_available_port(); // Unused port; destination uses invalid broadcast
    let rx_src_port = get_available_port();
    let rx_dst_port = get_available_port();

    let rx_receiver = UdpSocket::bind(format!("127.0.0.1:{}", rx_dst_port)).expect("bind rx dst");
    rx_receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // Use an unroutable/invalid IP for TX destination to induce destination error
    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-err-isolation"
    streams:
      - id: "failing-tx"
        source:
          transport: "udp"
          address: "127.0.0.1:{tx_src_port}"
        destination:
          transport: "udp"
          address: "255.255.255.255:9999"
      - id: "healthy-rx"
        source:
          transport: "udp"
          address: "127.0.0.1:{rx_src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{rx_dst_port}"
    logical_interfaces:
      - id: "isolated-comm-link"
        tx_stream: "failing-tx"
        rx_stream: "healthy-rx"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse yaml");
    let relay = Relay::start(&config).expect("start relay");
    thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");

    // Send packet on failing TX direction
    sender
        .send_to(b"tx-packet-fails", format!("127.0.0.1:{}", tx_src_port))
        .expect("send to tx src");

    thread::sleep(Duration::from_millis(50));

    // Send packet on healthy RX direction
    sender
        .send_to(b"rx-packet-succeeds", format!("127.0.0.1:{}", rx_src_port))
        .expect("send to rx src");

    let mut buf = vec![0u8; 256];
    let (n, _) = rx_receiver.recv_from(&mut buf).expect("receive on rx");
    assert_eq!(&buf[..n], b"rx-packet-succeeds");

    thread::sleep(Duration::from_millis(50));

    let stats = relay
        .logical_interface_stats("isolated-comm-link")
        .expect("stats");
    let tx_s = stats.tx_stats.unwrap();
    let rx_s = stats.rx_stats.unwrap();

    // Failing TX has destination error
    assert!(
        tx_s.destination_errors >= 1,
        "TX direction should have recorded destination error"
    );

    // Healthy RX has 0 destination errors and 1 forwarded packet
    assert_eq!(
        rx_s.destination_errors, 0,
        "RX direction must have 0 errors"
    );
    assert_eq!(
        rx_s.forwarded_packets, 1,
        "RX direction must forward packet cleanly"
    );

    relay.stop();
}

#[test]
fn test_single_directional_interfaces_tx_only_and_rx_only() {
    let tx_src_port = get_available_port();
    let tx_dst_port = get_available_port();
    let rx_src_port = get_available_port();
    let rx_dst_port = get_available_port();

    let tx_dst = UdpSocket::bind(format!("127.0.0.1:{}", tx_dst_port)).unwrap();
    tx_dst
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let rx_dst = UdpSocket::bind(format!("127.0.0.1:{}", rx_dst_port)).unwrap();
    rx_dst
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-single-dir"
    streams:
      - id: "stream-tx-only"
        source:
          transport: "udp"
          address: "127.0.0.1:{tx_src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{tx_dst_port}"
      - id: "stream-rx-only"
        source:
          transport: "udp"
          address: "127.0.0.1:{rx_src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{rx_dst_port}"
    logical_interfaces:
      - id: "iface-tx-only"
        tx_stream: "stream-tx-only"
      - id: "iface-rx-only"
        rx_stream: "stream-rx-only"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse");
    let relay = Relay::start(&config).expect("start");

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"data-tx", format!("127.0.0.1:{}", tx_src_port))
        .unwrap();
    sender
        .send_to(b"data-rx", format!("127.0.0.1:{}", rx_src_port))
        .unwrap();

    let mut buf = vec![0u8; 128];
    let (n1, _) = tx_dst.recv_from(&mut buf).expect("recv tx");
    assert_eq!(&buf[..n1], b"data-tx");

    let (n2, _) = rx_dst.recv_from(&mut buf).expect("recv rx");
    assert_eq!(&buf[..n2], b"data-rx");

    thread::sleep(Duration::from_millis(50));

    let iface_tx = relay.logical_interface_stats("iface-tx-only").unwrap();
    assert!(iface_tx.tx_stats.is_some());
    assert!(iface_tx.rx_stats.is_none());
    assert_eq!(iface_tx.tx_stats.unwrap().forwarded_packets, 1);

    let iface_rx = relay.logical_interface_stats("iface-rx-only").unwrap();
    assert!(iface_rx.tx_stats.is_none());
    assert!(iface_rx.rx_stats.is_some());
    assert_eq!(iface_rx.rx_stats.unwrap().forwarded_packets, 1);

    relay.stop();
}

#[test]
fn test_multiple_simultaneous_interfaces_in_one_instance() {
    let p_tx_src = get_available_port();
    let p_tx_dst = get_available_port();
    let p_rx_src = get_available_port();
    let p_rx_dst = get_available_port();

    let s_tx_src = get_available_port();
    let s_tx_dst = get_available_port();
    let s_rx_src = get_available_port();
    let s_rx_dst = get_available_port();

    let aux_src = get_available_port();
    let aux_dst1 = get_available_port();
    let aux_dst2 = get_available_port();

    // Bind all destination receivers
    let r_p_tx = UdpSocket::bind(format!("127.0.0.1:{}", p_tx_dst)).unwrap();
    r_p_tx
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let r_p_rx = UdpSocket::bind(format!("127.0.0.1:{}", p_rx_dst)).unwrap();
    r_p_rx
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let r_s_tx = UdpSocket::bind(format!("127.0.0.1:{}", s_tx_dst)).unwrap();
    r_s_tx
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let r_s_rx = UdpSocket::bind(format!("127.0.0.1:{}", s_rx_dst)).unwrap();
    r_s_rx
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let r_aux1 = UdpSocket::bind(format!("127.0.0.1:{}", aux_dst1)).unwrap();
    r_aux1
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let r_aux2 = UdpSocket::bind(format!("127.0.0.1:{}", aux_dst2)).unwrap();
    r_aux2
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-multi-simultaneous"
    name: "Multi-Interface Ground Station"
    streams:
      - id: "prim-tx"
        source:
          transport: "udp"
          address: "127.0.0.1:{p_tx_src}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{p_tx_dst}"
      - id: "prim-rx"
        source:
          transport: "udp"
          address: "127.0.0.1:{p_rx_src}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{p_rx_dst}"
      - id: "sec-tx"
        source:
          transport: "udp"
          address: "127.0.0.1:{s_tx_src}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{s_tx_dst}"
      - id: "sec-rx"
        source:
          transport: "udp"
          address: "127.0.0.1:{s_rx_src}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{s_rx_dst}"
      - id: "aux-fanout"
        source:
          transport: "udp"
          address: "127.0.0.1:{aux_src}"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:{aux_dst1}"
          - transport: "udp"
            address: "127.0.0.1:{aux_dst2}"
    logical_interfaces:
      - id: "iface-primary"
        name: "Primary S-Band"
        tx_stream: "prim-tx"
        rx_stream: "prim-rx"
      - id: "iface-secondary"
        name: "Secondary X-Band"
        tx_stream: "sec-tx"
        rx_stream: "sec-rx"
      - id: "iface-aux"
        name: "Auxiliary Fan-out Downlink"
        rx_stream: "aux-fanout"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse");
    let relay = Relay::start(&config).expect("start multi-interface relay");
    thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

    // Send on all 5 streams simultaneously
    sender
        .send_to(b"msg-prim-tx", format!("127.0.0.1:{}", p_tx_src))
        .unwrap();
    sender
        .send_to(b"msg-prim-rx", format!("127.0.0.1:{}", p_rx_src))
        .unwrap();
    sender
        .send_to(b"msg-sec-tx", format!("127.0.0.1:{}", s_tx_src))
        .unwrap();
    sender
        .send_to(b"msg-sec-rx", format!("127.0.0.1:{}", s_rx_src))
        .unwrap();
    sender
        .send_to(b"msg-aux-fanout", format!("127.0.0.1:{}", aux_src))
        .unwrap();

    let mut buf = vec![0u8; 128];

    // Verify all 5 receivers get their messages
    let (n, _) = r_p_tx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"msg-prim-tx");

    let (n, _) = r_p_rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"msg-prim-rx");

    let (n, _) = r_s_tx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"msg-sec-tx");

    let (n, _) = r_s_rx.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"msg-sec-rx");

    let (n, _) = r_aux1.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"msg-aux-fanout");

    let (n, _) = r_aux2.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"msg-aux-fanout");

    thread::sleep(Duration::from_millis(50));

    // Verify stats across all interfaces
    let stats_prim = relay.logical_interface_stats("iface-primary").unwrap();
    assert_eq!(stats_prim.tx_stats.unwrap().forwarded_packets, 1);
    assert_eq!(stats_prim.rx_stats.unwrap().forwarded_packets, 1);

    let stats_sec = relay.logical_interface_stats("iface-secondary").unwrap();
    assert_eq!(stats_sec.tx_stats.unwrap().forwarded_packets, 1);
    assert_eq!(stats_sec.rx_stats.unwrap().forwarded_packets, 1);

    let stats_aux = relay.logical_interface_stats("iface-aux").unwrap();
    assert!(stats_aux.tx_stats.is_none());
    // Fanout forwarded 2 packets (one to each destination)
    assert_eq!(stats_aux.rx_stats.unwrap().forwarded_packets, 2);

    relay.stop();
}

#[test]
fn test_fanout_resilience_one_destination_failing_others_continue() {
    let src_port = get_available_port();
    let dst1_port = get_available_port();
    let dst2_port = get_available_port();

    let receiver1 = UdpSocket::bind(format!("127.0.0.1:{}", dst1_port)).unwrap();
    receiver1
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let receiver2 = UdpSocket::bind(format!("127.0.0.1:{}", dst2_port)).unwrap();
    receiver2
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // 3 destinations: dst1 (valid), dst2 (valid), dst3 (invalid broadcast that fails)
    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-fanout-resilience"
    streams:
      - id: "fanout-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{src_port}"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:{dst1_port}"
          - transport: "udp"
            address: "255.255.255.255:9999"
          - transport: "udp"
            address: "127.0.0.1:{dst2_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse");
    let relay = Relay::start(&config).expect("start");
    thread::sleep(Duration::from_millis(50));

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

    // Send packet 1
    sender
        .send_to(b"fanout-packet-1", format!("127.0.0.1:{}", src_port))
        .unwrap();

    let mut buf = vec![0u8; 128];
    let (n1, _) = receiver1.recv_from(&mut buf).expect("receiver1 packet 1");
    assert_eq!(&buf[..n1], b"fanout-packet-1");

    let (n2, _) = receiver2.recv_from(&mut buf).expect("receiver2 packet 1");
    assert_eq!(&buf[..n2], b"fanout-packet-1");

    // Send packet 2
    sender
        .send_to(b"fanout-packet-2", format!("127.0.0.1:{}", src_port))
        .unwrap();

    let (n3, _) = receiver1.recv_from(&mut buf).expect("receiver1 packet 2");
    assert_eq!(&buf[..n3], b"fanout-packet-2");

    let (n4, _) = receiver2.recv_from(&mut buf).expect("receiver2 packet 2");
    assert_eq!(&buf[..n4], b"fanout-packet-2");

    thread::sleep(Duration::from_millis(50));

    let stats = relay.stream_stats("fanout-stream").expect("stats");
    // 2 packets received by relay
    assert_eq!(stats.received_packets, 2);
    // 4 packets forwarded (2 to receiver1, 2 to receiver2)
    assert_eq!(stats.forwarded_packets, 4);
    // At least 2 destination errors recorded for the failing destination
    assert!(
        stats.destination_errors >= 2,
        "Destination errors must be recorded: {}",
        stats.destination_errors
    );

    relay.stop();
}

#[test]
fn test_fanout_mixed_tcp_and_udp_resilience() {
    let src_port = get_available_port();
    let udp_dst_port = get_available_port();
    let tcp_healthy_dst_port = get_available_port();
    let tcp_failing_dst_port = get_available_port(); // No listener running!

    let udp_receiver = UdpSocket::bind(format!("127.0.0.1:{}", udp_dst_port)).unwrap();
    udp_receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let tcp_listener = TcpListener::bind(format!("127.0.0.1:{}", tcp_healthy_dst_port)).unwrap();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-fanout-mixed"
    streams:
      - id: "fanout-mixed-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{src_port}"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:{udp_dst_port}"
          - transport: "tcp"
            address: "127.0.0.1:{tcp_healthy_dst_port}"
          - transport: "tcp"
            address: "127.0.0.1:{tcp_failing_dst_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse");
    let relay = Relay::start(&config).expect("start");

    // Spawn accept thread for healthy TCP destination
    let tcp_healthy_handle = thread::spawn(move || {
        let (mut tcp_stream, _) = tcp_listener.accept().expect("accept tcp destination");
        tcp_stream
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();

        let frame1 = framing::read_frame(
            &mut tcp_stream,
            65535,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .expect("read tcp frame 1")
        .expect("frame 1 present");
        let frame2 = framing::read_frame(
            &mut tcp_stream,
            65535,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .expect("read tcp frame 2")
        .expect("frame 2 present");
        (frame1, frame2)
    });

    thread::sleep(Duration::from_millis(50));
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"mixed-payload-1", format!("127.0.0.1:{}", src_port))
        .unwrap();

    // Verify UDP destination received packet 1
    let mut buf = vec![0u8; 128];
    let (n, _) = udp_receiver.recv_from(&mut buf).expect("udp recv");
    assert_eq!(&buf[..n], b"mixed-payload-1");

    // Send packet 2
    sender
        .send_to(b"mixed-payload-2", format!("127.0.0.1:{}", src_port))
        .unwrap();

    let (n2, _) = udp_receiver.recv_from(&mut buf).expect("udp recv 2");
    assert_eq!(&buf[..n2], b"mixed-payload-2");

    let (frame1, frame2) = tcp_healthy_handle.join().expect("join tcp receiver thread");
    assert_eq!(frame1, b"mixed-payload-1");
    assert_eq!(frame2, b"mixed-payload-2");

    thread::sleep(Duration::from_millis(50));

    let stats = relay.stream_stats("fanout-mixed-stream").unwrap();
    assert_eq!(stats.received_packets, 2);
    // 4 successful forwards (2 to UDP, 2 to healthy TCP)
    assert_eq!(stats.forwarded_packets, 4);
    // Failing TCP destination recorded errors
    assert!(
        stats.destination_errors >= 1,
        "Failing TCP destination must record errors"
    );

    relay.stop();
}
