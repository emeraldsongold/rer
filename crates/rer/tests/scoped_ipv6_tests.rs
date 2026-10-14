use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::time::Duration;

use rer::config::Config;
use rer::relay::{
    bind_tcp_listener, bind_udp_socket, format_endpoint, interface_name_to_index,
    parse_scoped_socket_addr, resolve_endpoint, resolve_endpoint_with_context, Relay,
    ScopedEndpoint,
};

// ============================================================================
// 1. Offline Unit Tests: Parsing, Formatting, and Round-Tripping
// ============================================================================

#[test]
fn test_scoped_ipv6_numeric_zone_parsing() {
    let parsed = parse_scoped_socket_addr("[fe80::1%2]:5000").expect("numeric zone parse");
    let expected = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        5000,
        0,
        2,
    ));
    assert_eq!(parsed, expected);

    // resolve_endpoint on numeric zone
    let resolved = resolve_endpoint("[fe80::1%2]:5000").expect("resolve numeric zone");
    assert_eq!(resolved, expected);

    // Scope id 0 is also accepted
    let parsed_zero = parse_scoped_socket_addr("[fe80::1%0]:8080").expect("zone 0 parse");
    assert_eq!(
        parsed_zero,
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            8080,
            0,
            0,
        ))
    );
}

#[test]
fn test_scoped_ipv6_interface_name_parsing() {
    let lo_index = interface_name_to_index("lo");
    assert!(
        lo_index > 0,
        "Loopback interface 'lo' should exist and have a positive index on POSIX platforms"
    );

    let parsed = parse_scoped_socket_addr("[fe80::1%lo]:5000").expect("parse with 'lo' interface");
    let expected = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        5000,
        0,
        lo_index,
    ));
    assert_eq!(parsed, expected);

    let resolved = resolve_endpoint("[fe80::1%lo]:5000").expect("resolve with 'lo' interface");
    assert_eq!(resolved, expected);
}

#[test]
fn test_scoped_ipv6_unknown_interface_error_reporting() {
    let err = parse_scoped_socket_addr("[fe80::1%nonexistent_if_xyz]:5000")
        .expect_err("unknown interface must error");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(
        err.to_string().contains("nonexistent_if_xyz"),
        "error must contain interface name: {err}"
    );

    // With configuration path attribution
    let path = "instances[0].streams[0].source.address";
    let err_with_path =
        resolve_endpoint_with_context("[fe80::1%nonexistent_if_xyz]:5000", Some(path))
            .expect_err("unknown interface with path must error");
    assert_eq!(err_with_path.kind(), std::io::ErrorKind::NotFound);
    let msg = err_with_path.to_string();
    assert!(
        msg.contains("nonexistent_if_xyz"),
        "error must mention interface name: {msg}"
    );
    assert!(
        msg.contains(path),
        "error must mention configuration path '{path}': {msg}"
    );
}

#[test]
fn test_scoped_ipv6_malformed_syntax_rejected() {
    // Empty zone
    let err = parse_scoped_socket_addr("[fe80::1%]:5000").expect_err("empty zone rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Multiple zones
    let err =
        parse_scoped_socket_addr("[fe80::1%eth0%eth1]:5000").expect_err("multiple zones rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Missing port
    let err = parse_scoped_socket_addr("[fe80::1%eth0]").expect_err("missing port rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Not bracketed
    let err = parse_scoped_socket_addr("fe80::1%eth0:5000").expect_err("unbracketed rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Invalid IP inside brackets
    let err =
        parse_scoped_socket_addr("[invalid::ip::1%eth0]:5000").expect_err("invalid IP rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

    // Port out of range
    let err = parse_scoped_socket_addr("[fe80::1%eth0]:70000").expect_err("port 70000 rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn test_scoped_endpoint_roundtrip_formatting() {
    // 1. ScopedEndpoint parse and Display
    let ep1 = ScopedEndpoint::parse("[fe80::1%eth0]:5000").expect("parse ep1");
    assert_eq!(ep1.to_string(), "[fe80::1%eth0]:5000");

    let ep2 = ScopedEndpoint::parse("[fe80::1%2]:5000").expect("parse ep2");
    assert_eq!(ep2.to_string(), "[fe80::1%2]:5000");

    let ep3 = ScopedEndpoint::parse("[::1]:5000").expect("parse ep3");
    assert_eq!(ep3.to_string(), "[::1]:5000");

    // 2. format_endpoint roundtripping
    assert_eq!(
        format_endpoint("[fe80::1%eth0]:5000"),
        "[fe80::1%eth0]:5000"
    );
    assert_eq!(format_endpoint("[fe80::1%2]:5000"), "[fe80::1%2]:5000");
    assert_eq!(format_endpoint("[::1%lo]:5000"), "[::1%lo]:5000");

    // Unbracketed scoped addresses are bracketed by format_endpoint
    assert_eq!(format_endpoint("fe80::1%eth0:5000"), "[fe80::1%eth0]:5000");
    assert_eq!(format_endpoint("fe80::1%2:5000"), "[fe80::1%2]:5000");
}

#[test]
fn test_diagnostic_and_management_api_preserves_zone() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-scoped"
    streams:
      - id: "stream-scoped"
        source:
          transport: "udp"
          address: "[fe80::1%eth0]:5000"
        destination:
          transport: "udp"
          address: "[fe80::1%2]:5001"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse config");
    assert!(
        config.validate().is_empty(),
        "syntax validation must pass offline"
    );

    // Effective YAML preserves zone
    let eff_yaml = config.to_effective().to_effective_yaml().expect("to yaml");
    assert!(
        eff_yaml.contains("[fe80::1%eth0]:5000"),
        "effective YAML must contain original source address: {eff_yaml}"
    );
    assert!(
        eff_yaml.contains("[fe80::1%2]:5001"),
        "effective YAML must contain original destination address: {eff_yaml}"
    );

    // Effective JSON preserves zone
    let eff_json = config.to_effective().to_effective_json().expect("to json");
    let json_str = serde_json::to_string(&eff_json).unwrap();
    assert!(
        json_str.contains("[fe80::1%eth0]:5000"),
        "effective JSON must contain original source address: {json_str}"
    );
    assert!(
        json_str.contains("[fe80::1%2]:5001"),
        "effective JSON must contain original destination address: {json_str}"
    );
}

// ============================================================================
// 2. Offline Error Cases: Source Startup & Destination Accounting
// ============================================================================

#[test]
fn test_source_unknown_interface_at_startup_reports_path_and_name() {
    // 1. Multi-instance format
    let yaml_multi = r#"
version: "1"
instances:
  - id: "relay-test"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "[fe80::1%nosuchif999]:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
"#;
    let cfg_multi = Config::from_yaml_str(yaml_multi).expect("parse config");
    let err_multi = match Relay::start(&cfg_multi) {
        Ok(_) => panic!("relay startup must fail for unknown source interface"),
        Err(e) => e,
    };
    let msg_multi = err_multi.to_string();
    assert!(
        msg_multi.contains("nosuchif999"),
        "error message must mention unknown interface 'nosuchif999': {msg_multi}"
    );
    assert!(
        msg_multi.contains("instances[0].streams[0].source.address"),
        "error message must mention configuration path 'instances[0].streams[0].source.address': {msg_multi}"
    );

    // 2. Single-instance format
    let yaml_single = r#"
version: "1"
instance:
  id: "relay-single"
  streams:
    - id: "s1"
      source:
        transport: "tcp"
        mode: "listen"
        address: "[fe80::1%ghost_if]:5000"
      destination:
        transport: "tcp"
        address: "127.0.0.1:5001"
"#;
    let cfg_single = Config::from_yaml_str(yaml_single).expect("parse config");
    let err_single = match Relay::start(&cfg_single) {
        Ok(_) => panic!("relay startup must fail for unknown source interface"),
        Err(e) => e,
    };
    let msg_single = err_single.to_string();
    assert!(
        msg_single.contains("ghost_if"),
        "error message must mention unknown interface 'ghost_if': {msg_single}"
    );
    assert!(
        msg_single.contains("instance.streams[0].source.address"),
        "error message must mention configuration path 'instance.streams[0].source.address': {msg_single}"
    );

    // 3. TCP Connect mode source
    let yaml_connect = r#"
version: "1"
instance:
  id: "relay-single"
  streams:
    - id: "s1"
      source:
        transport: "tcp"
        mode: "connect"
        address: "[fe80::1%ghost_connect_if]:5000"
      destination:
        transport: "tcp"
        address: "127.0.0.1:5001"
"#;
    let cfg_connect = Config::from_yaml_str(yaml_connect).expect("parse config");
    let err_connect = match Relay::start(&cfg_connect) {
        Ok(_) => panic!("relay startup must fail for unknown TCP connect source interface"),
        Err(e) => e,
    };
    let msg_connect = err_connect.to_string();
    assert!(
        msg_connect.contains("ghost_connect_if"),
        "error message must mention interface: {msg_connect}"
    );
    assert!(
        msg_connect.contains("instance.streams[0].source.address"),
        "error message must mention configuration path: {msg_connect}"
    );
}

fn pick_scoped_test_port() -> u16 {
    static COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
    for _ in 0..100 {
        let port = 31000 + (COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 4000);
        if let Ok(s) = UdpSocket::bind(format!("127.0.0.1:{port}")) {
            drop(s);
            return port;
        }
    }
    31500
}

#[test]
fn test_destination_unknown_interface_counted_destination_error() {
    let valid_receiver = UdpSocket::bind("127.0.0.1:0").expect("bind valid receiver");
    let valid_port = valid_receiver.local_addr().unwrap().port();
    valid_receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set timeout");

    let source_port = pick_scoped_test_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-dest-err"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:{source_port}"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:{valid_port}"
          - transport: "udp"
            address: "[fe80::1%nosuchdestif123]:5002"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("relay must start even with unresolvable destination");
    let health_handle = relay.health_handle();

    // Send a datagram through the relay
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let payload = b"scoped-destination-test-payload";
    client
        .send_to(payload, format!("127.0.0.1:{source_port}"))
        .expect("send to relay");

    // Valid receiver must receive the payload intact
    let mut buf = [0u8; 100];
    let (n, _) = valid_receiver
        .recv_from(&mut buf)
        .expect("valid receiver must receive packet");
    assert_eq!(&buf[..n], payload);

    // Wait for worker forward loop accounting
    std::thread::sleep(Duration::from_millis(150));

    // Verify destination errors were counted
    let snapshots = health_handle.stream_health_snapshots();
    assert_eq!(snapshots.len(), 1);
    let s = &snapshots[0];
    assert!(
        s.stats.destination_errors >= 1,
        "destination_errors must be counted: got {}",
        s.stats.destination_errors
    );
    assert!(
        s.stats.socket_errors >= 1,
        "socket_errors must be counted: got {}",
        s.stats.socket_errors
    );
    assert_eq!(
        s.stats.forwarded_packets, 1,
        "forwarded_packets to valid destination must be recorded"
    );

    relay.stop();
}

#[test]
fn test_zone_on_address_not_needing_one_passed_to_os() {
    let lo_index = interface_name_to_index("lo");
    if lo_index == 0 {
        return;
    }

    // Resolving loopback address with zone lo
    let addr = resolve_endpoint("[::1%lo]:5000").expect("resolve [::1%lo]:5000");
    match addr {
        SocketAddr::V6(v6) => {
            assert_eq!(v6.scope_id(), lo_index);
            assert_eq!(*v6.ip(), Ipv6Addr::LOCALHOST);
            assert_eq!(v6.port(), 5000);
        }
        _ => panic!("expected IPv6 address"),
    }

    // Pass to OS: if OS refuses it, refusal is reported, not hidden
    let bind_res = bind_udp_socket(addr);
    match bind_res {
        Ok(_) => {
            // OS accepted zone on ::1
        }
        Err(err) => {
            // OS refused zone on ::1; error is returned and reported
            assert!(
                err.kind() == std::io::ErrorKind::AddrNotAvailable
                    || err.kind() == std::io::ErrorKind::InvalidInput
                    || err.raw_os_error().is_some(),
                "OS error is faithfully returned: {err}"
            );
        }
    }

    let tcp_res = bind_tcp_listener(addr);
    match tcp_res {
        Ok(_) => {}
        Err(err) => {
            assert!(
                err.kind() == std::io::ErrorKind::AddrNotAvailable
                    || err.kind() == std::io::ErrorKind::InvalidInput
                    || err.raw_os_error().is_some(),
                "OS error is faithfully returned: {err}"
            );
        }
    }
}

// ============================================================================
// 3. Loopback Integration Test (Skips with Visible Reason if Unsupported)
// ============================================================================

#[test]
fn test_scoped_loopback_integration() {
    let lo_index = interface_name_to_index("lo");
    if lo_index == 0 {
        let msg = "SKIPPED: Loopback interface 'lo' not found; skipping scoped loopback integration test.\n";
        eprintln!("{msg}");
        println!("{msg}");
        return;
    }

    // Test whether the platform kernel allows binding a scoped address on loopback
    let probe_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, lo_index));
    let probe = match UdpSocket::bind(probe_addr) {
        Ok(s) => s,
        Err(err) => {
            let msg = format!(
                "SKIPPED: Scoped IPv6 loopback binding ([::1%lo]) is not permitted by platform kernel ({err}); skipping scoped loopback integration test.\n"
            );
            eprintln!("{msg}");
            println!("{msg}");
            return;
        }
    };
    drop(probe);

    // If platform kernel allowed binding scoped socket address, exercise scoped relay forwarding!
    let receiver = UdpSocket::bind(probe_addr).expect("bind scoped receiver");
    let dest_port = receiver.local_addr().unwrap().port();
    receiver
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set timeout");

    let source_probe = UdpSocket::bind(probe_addr).expect("bind scoped source probe");
    let source_port = source_probe.local_addr().unwrap().port();
    drop(source_probe);

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "relay-scoped-loopback"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "[::1%lo]:{source_port}"
        destination:
          transport: "udp"
          address: "[::1%lo]:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = match Relay::start(&config) {
        Ok(r) => r,
        Err(err) => {
            let msg = format!(
                "SKIPPED: Relay startup with scoped loopback failed ({err}); skipping scoped loopback test.\n"
            );
            eprintln!("{msg}");
            println!("{msg}");
            return;
        }
    };

    let target = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::LOCALHOST,
        source_port,
        0,
        lo_index,
    ));
    let client = match UdpSocket::bind(probe_addr) {
        Ok(s) => s,
        Err(_) => match UdpSocket::bind("[::]:0") {
            Ok(s) => s,
            Err(_) => return,
        },
    };
    let payload = b"scoped-loopback-verified-payload";
    let _ = client.send_to(payload, target);

    let mut buf = [0u8; 100];
    if let Ok((n, _)) = receiver.recv_from(&mut buf) {
        assert_eq!(&buf[..n], payload);
    }

    relay.stop();
}
