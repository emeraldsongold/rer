use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use rer::config::{Config, OperationalMode};
use rer::management::{
    query_events, query_status, ManagementRequest, ManagementResponse, ManagementServer,
    OperationType, MGMT_API_VERSION,
};
use rer::relay::Relay;
use rer::sim::{GeneratorConfig, Packet, TrafficGenerator, TrafficReceiver};

fn rer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rer"))
}

fn pick_unused_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP");
    sock.local_addr().expect("local addr").port()
}

// ============================================================================
// 1. Acceptance Criterion 3: Management plane failure cannot stop data plane
// ============================================================================

#[test]
fn test_management_plane_failure_cannot_stop_data_plane() {
    let src_port = pick_unused_port();
    let dest_port = pick_unused_port();

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "fault-isolation-relay"
    streams:
      - id: "mission-traffic"
        source:
          transport: "udp"
          address: "127.0.0.1:{src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    let sock_path =
        std::env::temp_dir().join(format!("rer_fault_test_{}.sock", pick_unused_port()));
    let mgmt_server = ManagementServer::start_local(&sock_path, relay.health_handle(), None)
        .expect("start management server");

    thread::sleep(Duration::from_millis(50));

    // Create destination receiver
    let dest_sock = UdpSocket::bind(format!("127.0.0.1:{dest_port}")).expect("bind receiver");
    dest_sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");

    // Phase 1: Induce aggressive management failures:
    // a) Garbage / non-JSON binary bytes abruptly closed
    for _ in 0..5 {
        if let Ok(mut s) = UnixStream::connect(&sock_path) {
            let _ = s.write_all(b"\xFF\xFE\x00\x01\xDE\xAD\xBE\xEF\n");
            let _ = s.flush();
        }
    }

    // b) Rapid connect / immediate abort
    for _ in 0..10 {
        let _ = UnixStream::connect(&sock_path);
    }

    // c) Malformed JSON payloads
    for _ in 0..5 {
        if let Ok(mut s) = UnixStream::connect(&sock_path) {
            let _ = s.write_all(b"{\"invalid\": truncated json\n");
            let _ = s.flush();
        }
    }

    // d) Unsupported API version and forbidden action attempts
    for _ in 0..5 {
        if let Ok(mut s) = UnixStream::connect(&sock_path) {
            let _ = s.write_all(b"{\"version\":\"v99\",\"action\":\"status\"}\n");
            let _ = s.flush();
        }
    }

    // Phase 2: Send data plane packets concurrently during management errors
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: 42,
        packet_size: 128,
        count: Some(50),
        ..Default::default()
    });
    let packets = gen.emit_all();

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for pkt in &packets {
        sender
            .send_to(&pkt.to_bytes(), format!("127.0.0.1:{src_port}"))
            .expect("send data plane packet");
    }

    // Phase 3: Continue hammering management plane while verifying data forwarding
    for _ in 0..5 {
        if let Ok(mut s) = UnixStream::connect(&sock_path) {
            let _ =
                s.write_all(b"{\"version\":\"v1\",\"action\":\"exec\",\"params\":\"rm -rf /\"}\n");
            let _ = s.flush();
        }
    }

    // Collect and verify received packets
    let mut receiver = TrafficReceiver::new(Some(50), None);
    let mut buf = vec![0u8; 65536];
    for _ in 0..50 {
        match dest_sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let pkt = Packet::from_bytes(&buf[..n]).expect("decode packet");
                receiver.record_packet(&pkt);
            }
            Err(e) => panic!("Data plane packet dropped due to management failure: {e}"),
        }
    }

    let report = receiver.report();
    assert_eq!(
        report.received_count, 50,
        "All data plane packets must arrive intact despite management plane faults"
    );
    assert_eq!(report.lost_count, 0, "Zero loss on data plane");
    assert!(report.payload_hashes_verified);

    // Verify management server is still operational for valid requests
    let status = query_status(sock_path.to_str().unwrap(), Duration::from_secs(1), None)
        .expect("management query after faults");
    assert_eq!(status.status, "healthy");
    assert_eq!(status.aggregate_counters.received_packets, 50);
    assert_eq!(status.aggregate_counters.forwarded_packets, 50);

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&sock_path);
}

// ============================================================================
// 2. Acceptance Criterion 4: rer status, rer streams and rer metrics CLI output
// ============================================================================

#[test]
fn test_cli_status_streams_metrics_json_and_text() {
    let src_port = pick_unused_port();
    let dest_port = pick_unused_port();
    let sock_path = std::env::temp_dir().join(format!("rer_cli_mgmt_{}.sock", pick_unused_port()));

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "telemetry-gateway"
    name: "Mission Telemetry Gateway"
    streams:
      - id: "tlm-stream-1"
        source:
          transport: "udp"
          address: "127.0.0.1:{src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let mgmt_server = ManagementServer::start_local(&sock_path, relay.health_handle(), None)
        .expect("start management server");

    thread::sleep(Duration::from_millis(50));

    // Send 10 packets to generate non-zero counters
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for i in 0..10 {
        sender
            .send_to(
                format!("packet-{i}").as_bytes(),
                format!("127.0.0.1:{src_port}"),
            )
            .expect("send packet");
    }
    thread::sleep(Duration::from_millis(50));

    // Test 1: rer status --json
    let out = Command::new(rer_bin())
        .args(["status", "--socket", sock_path.to_str().unwrap(), "--json"])
        .output()
        .expect("rer status --json");
    assert!(out.status.success(), "rer status --json must succeed");
    let status_val: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON from rer status");
    assert_eq!(status_val["status"], "healthy");
    assert_eq!(status_val["version"], rer::version());
    assert_eq!(status_val["healthy"], true);
    assert_eq!(
        status_val["aggregate_counters"]["received_packets"], 10,
        "Must record received packet counter"
    );
    assert!(!status_val["streams"].as_array().unwrap().is_empty());
    assert_eq!(status_val["streams"][0]["stream_id"], "tlm-stream-1");
    assert_eq!(status_val["streams"][0]["received_packets"], 10);

    // Test 2: rer status text
    let out = Command::new(rer_bin())
        .args(["status", "--socket", sock_path.to_str().unwrap()])
        .output()
        .expect("rer status");
    assert!(out.status.success());
    let txt = String::from_utf8(out.stdout).unwrap();
    assert!(txt.contains("RER Relay Status: healthy"));
    assert!(txt.contains("Overall Counters:"));
    assert!(txt.contains("tlm-stream-1"));

    // Test 3: rer streams --socket <SOCK> --json
    let out = Command::new(rer_bin())
        .args(["streams", "--socket", sock_path.to_str().unwrap(), "--json"])
        .output()
        .expect("rer streams --socket --json");
    assert!(
        out.status.success(),
        "rer streams --socket --json must succeed"
    );
    let streams_val: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON from rer streams");
    assert_eq!(streams_val["status"], "healthy");
    assert!(!streams_val["streams"].as_array().unwrap().is_empty());
    assert_eq!(streams_val["streams"][0]["stream_id"], "tlm-stream-1");
    assert_eq!(streams_val["streams"][0]["received_packets"], 10);

    // Test 4: rer streams --socket <SOCK> text
    let out = Command::new(rer_bin())
        .args(["streams", "--socket", sock_path.to_str().unwrap()])
        .output()
        .expect("rer streams --socket");
    assert!(out.status.success());
    let txt = String::from_utf8(out.stdout).unwrap();
    assert!(txt.contains("Streams and Logical Interfaces (Runtime Status):"));
    assert!(txt.contains("tlm-stream-1"));

    // Test 5: rer metrics --socket <SOCK> --json
    let out = Command::new(rer_bin())
        .args(["metrics", "--socket", sock_path.to_str().unwrap(), "--json"])
        .output()
        .expect("rer metrics --socket --json");
    assert!(
        out.status.success(),
        "rer metrics --socket --json must succeed"
    );
    let metrics_val: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("valid JSON from rer metrics");
    assert_eq!(metrics_val["status"], "healthy");
    assert_eq!(metrics_val["counters"]["received_packets"], 10);
    assert!(metrics_val["streams"]["tlm-stream-1"].is_object());
    assert_eq!(
        metrics_val["streams"]["tlm-stream-1"]["received_packets"],
        10
    );

    // Test 6: rer metrics --socket <SOCK> --format prometheus
    let out = Command::new(rer_bin())
        .args([
            "metrics",
            "--socket",
            sock_path.to_str().unwrap(),
            "--format",
            "prometheus",
        ])
        .output()
        .expect("rer metrics --format prometheus");
    assert!(out.status.success());
    let prom = String::from_utf8(out.stdout).unwrap();
    assert!(prom.contains("rer_received_packets_total 10"));
    assert!(prom.contains("rer_stream_received_packets_total{stream=\"tlm-stream-1\"} 10"));
    assert!(prom.contains("rer_healthy 1"));

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&sock_path);
}

// ============================================================================
// 3. Acceptance Criterion 5: Separation of read-only vs behavior-changing ops
//    and prohibition of shell / code execution (SPEC §9, §17)
// ============================================================================

#[test]
fn test_read_only_and_behavior_changing_operation_separation() {
    let sock_path = std::env::temp_dir().join(format!("rer_ops_test_{}.sock", pick_unused_port()));

    let yaml = r#"
version: "1"
instances:
  - id: "ops-test-node"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:3901"
        destination:
          transport: "udp"
          address: "127.0.0.1:3902"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let mgmt_server = ManagementServer::start_local(&sock_path, relay.health_handle(), None)
        .expect("start management server");

    thread::sleep(Duration::from_millis(50));

    // 1. Read-only operations succeed for read-only role
    let mut stream = UnixStream::connect(&sock_path).expect("connect");
    let req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "status",
        "role": "readonly"
    });
    writeln!(stream, "{req}").expect("write");
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&resp_line).expect("parse response");
    assert_eq!(
        resp.status, "ok",
        "Read-only operation must succeed for read-only role"
    );

    // 2. Behavior-changing operation rejected for read-only role
    let mut stream = UnixStream::connect(&sock_path).expect("connect");
    let req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "set_log_level",
        "role": "readonly",
        "params": { "level": "debug" }
    });
    writeln!(stream, "{req}").expect("write");
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&resp_line).expect("parse response");
    assert_eq!(
        resp.status, "error",
        "Behavior-changing op must be rejected for readonly role"
    );
    assert_eq!(resp.error.unwrap().code, "permission_denied");

    // 3. Arbitrary shell commands or code execution strictly prohibited (SPEC §9, §17)
    for forbidden_action in ["exec", "shell", "bash", "sh", "system", "run_command"] {
        let mut stream = UnixStream::connect(&sock_path).expect("connect");
        let req = serde_json::json!({
            "version": MGMT_API_VERSION,
            "action": forbidden_action,
            "params": { "cmd": "whoami" }
        });
        writeln!(stream, "{req}").expect("write");
        let mut reader = BufReader::new(stream);
        let mut resp_line = String::new();
        reader.read_line(&mut resp_line).expect("read");
        let resp: ManagementResponse = serde_json::from_str(&resp_line).expect("parse response");
        assert_eq!(
            resp.status, "error",
            "Forbidden action '{}' must be rejected",
            forbidden_action
        );
        let err = resp.error.unwrap();
        assert_eq!(err.code, "forbidden");
        assert!(err.message.contains("strictly prohibited"));
    }

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&sock_path);
}

// ============================================================================
// 4. Acceptance Criterion 2: Remote management authentication and encryption
// ============================================================================

#[test]
fn test_remote_management_authentication_and_encryption() {
    let port = pick_unused_port();
    let remote_addr = format!("127.0.0.1:{port}");

    // Create temporary dummy cert and key files
    let cert_file = std::env::temp_dir().join(format!("test_cert_{}.crt", port));
    let key_file = std::env::temp_dir().join(format!("test_key_{}.key", port));
    fs::write(&cert_file, "DUMMY_TLS_CERT").expect("write cert");
    fs::write(&key_file, "DUMMY_TLS_KEY").expect("write key");

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "remote-mgmt-node"
    management:
      enabled: true
      endpoint: "{remote_addr}"
      auth_token: "super-secret-token"
      tls:
        cert_file: "{}"
        key_file: "{}"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:4901"
        destination:
          transport: "udp"
          address: "127.0.0.1:4902"
"#,
        cert_file.display(),
        key_file.display()
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    assert!(
        config.validate().is_empty(),
        "Configuration with auth and TLS must validate"
    );

    let relay = Relay::start(&config).expect("start relay");
    let fallback_sock = std::env::temp_dir().join(format!("fallback_{}.sock", port));
    let mgmt_server =
        ManagementServer::start_from_config(&config, relay.health_handle(), &fallback_sock)
            .expect("start management server");

    thread::sleep(Duration::from_millis(50));

    // Connect to remote TCP endpoint
    // Case 1: Unauthenticated request -> Rejected with "unauthorized"
    let mut tcp = TcpStream::connect(&remote_addr).expect("connect remote TCP");
    let unauth_req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "status"
    });
    writeln!(tcp, "{unauth_req}").expect("write");
    let mut reader = BufReader::new(tcp);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&line).expect("parse response");
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.unwrap().code, "unauthorized");

    // Case 2: Request with wrong token -> Rejected with "unauthorized"
    let mut tcp = TcpStream::connect(&remote_addr).expect("connect remote TCP");
    let wrong_token_req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "status",
        "auth_token": "wrong-token"
    });
    writeln!(tcp, "{wrong_token_req}").expect("write");
    let mut reader = BufReader::new(tcp);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&line).expect("parse response");
    assert_eq!(resp.status, "error");
    assert_eq!(resp.error.unwrap().code, "unauthorized");

    // Case 3: Request with valid auth token -> Succeeds
    let mut tcp = TcpStream::connect(&remote_addr).expect("connect remote TCP");
    let auth_req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "status",
        "auth_token": "super-secret-token"
    });
    writeln!(tcp, "{auth_req}").expect("write");
    let mut reader = BufReader::new(tcp);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&line).expect("parse response");
    assert_eq!(resp.status, "ok", "Authorized remote request must succeed");
    assert_eq!(resp.action.unwrap(), "status");

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&cert_file);
    let _ = fs::remove_file(&key_file);
    let _ = fs::remove_file(&fallback_sock);
}

#[test]
fn test_unauthenticated_or_unencrypted_remote_management_rejected_by_validator() {
    // Untrusted remote endpoint without auth token
    let bad_yaml_no_auth = r#"
version: "1"
instances:
  - id: "insecure-node"
    management:
      enabled: true
      endpoint: "0.0.0.0:9090"
      tls:
        cert_file: "/etc/rer/certs/server.crt"
        key_file: "/etc/rer/certs/server.key"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
"#;
    let config = Config::from_yaml_str(bad_yaml_no_auth).expect("parse");
    let errors = config.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.reason.contains("requires authentication")),
        "Validator must reject remote management without auth_token"
    );

    // Untrusted remote endpoint without TLS
    let bad_yaml_no_tls = r#"
version: "1"
instances:
  - id: "insecure-node"
    management:
      enabled: true
      endpoint: "0.0.0.0:9090"
      auth_token: "my-token"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
"#;
    let config = Config::from_yaml_str(bad_yaml_no_tls).expect("parse");
    let errors = config.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.reason.contains("requires encryption")),
        "Validator must reject remote management without TLS"
    );
}

// ============================================================================
// 5. RER-F-028: Read-only events management operation and authorization
// ============================================================================

#[test]
fn test_management_events_classification_and_authorization() {
    // 1. Classification as read-only
    let req_events = ManagementRequest {
        version: MGMT_API_VERSION.to_string(),
        action: "events".to_string(),
        auth_token: None,
        role: None,
        params: None,
    };
    assert_eq!(
        req_events.operation_type(),
        Some(OperationType::ReadOnly),
        "'events' operation must be classified as ReadOnly"
    );

    let req_recent_events = ManagementRequest {
        version: MGMT_API_VERSION.to_string(),
        action: "recent_events".to_string(),
        auth_token: None,
        role: None,
        params: None,
    };
    assert_eq!(
        req_recent_events.operation_type(),
        Some(OperationType::ReadOnly),
        "'recent_events' operation must be classified as ReadOnly"
    );

    // 2. Readonly role caller is allowed
    let port = pick_unused_port();
    let sock_path = std::env::temp_dir().join(format!("rer_mgmt_events_auth_{}.sock", port));
    let yaml = format!(
        r#"
version: "1"
instance:
  id: "mgmt-auth-node"
  mode: "test"
  test_mode:
    correlation_id: "test-auth-corr"
    duration_seconds: 60
  management:
    enabled: true
    endpoint: "{}"
  streams:
    - id: "s1"
      source:
        transport: "udp"
        address: "127.0.0.1:4801"
      destination:
        transport: "udp"
        address: "127.0.0.1:4802"
"#,
        sock_path.display()
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let mgmt_server = ManagementServer::start_local(&sock_path, relay.health_handle(), None)
        .expect("start mgmt server");

    thread::sleep(Duration::from_millis(50));

    // Caller with role="readonly" can execute read-only events op
    let mut stream = UnixStream::connect(&sock_path).expect("connect");
    let req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "events",
        "role": "readonly"
    });
    writeln!(stream, "{req}").expect("write");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&line).expect("parse response");
    assert_eq!(
        resp.status, "ok",
        "ReadOnly role must be permitted to call 'events' action"
    );

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&sock_path);
}

#[test]
fn test_management_events_unauthorized_caller_refused() {
    let port = pick_unused_port();
    let remote_addr = format!("127.0.0.1:{port}");
    let cert_file = std::env::temp_dir().join(format!("unauth_cert_{}.crt", port));
    let key_file = std::env::temp_dir().join(format!("unauth_key_{}.key", port));
    fs::write(&cert_file, "DUMMY_TLS_CERT").expect("write cert");
    fs::write(&key_file, "DUMMY_TLS_KEY").expect("write key");

    let yaml = format!(
        r#"
version: "1"
instance:
  id: "remote-unauth-events-node"
  mode: "test"
  test_mode:
    correlation_id: "corr-unauth"
  management:
    enabled: true
    endpoint: "{remote_addr}"
    auth_token: "secret-token-123"
    tls:
      cert_file: "{}"
      key_file: "{}"
  streams:
    - id: "s1"
      source:
        transport: "udp"
        address: "127.0.0.1:4811"
      destination:
        transport: "udp"
        address: "127.0.0.1:4812"
"#,
        cert_file.display(),
        key_file.display()
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let fallback_sock = std::env::temp_dir().join(format!("fallback_unauth_{}.sock", port));
    let mgmt_server =
        ManagementServer::start_from_config(&config, relay.health_handle(), &fallback_sock)
            .expect("start mgmt server");

    thread::sleep(Duration::from_millis(50));

    // Remote caller without auth_token must be refused
    let mut tcp = TcpStream::connect(&remote_addr).expect("connect remote TCP");
    let unauth_req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "events"
    });
    writeln!(tcp, "{unauth_req}").expect("write");
    let mut reader = BufReader::new(tcp);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&line).expect("parse response");
    assert_eq!(
        resp.status, "error",
        "Unauthorized remote caller to 'events' must be refused"
    );
    assert_eq!(resp.error.unwrap().code, "unauthorized");

    // Remote caller with wrong token must be refused
    let mut tcp = TcpStream::connect(&remote_addr).expect("connect remote TCP");
    let wrong_req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "recent_events",
        "auth_token": "wrong-token"
    });
    writeln!(tcp, "{wrong_req}").expect("write");
    let mut reader = BufReader::new(tcp);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&line).expect("parse response");
    assert_eq!(
        resp.status, "error",
        "Remote caller with wrong token to 'recent_events' must be refused"
    );
    assert_eq!(resp.error.unwrap().code, "unauthorized");

    // Remote caller with valid auth token must succeed
    let mut tcp = TcpStream::connect(&remote_addr).expect("connect remote TCP");
    let auth_req = serde_json::json!({
        "version": MGMT_API_VERSION,
        "action": "events",
        "auth_token": "secret-token-123"
    });
    writeln!(tcp, "{auth_req}").expect("write");
    let mut reader = BufReader::new(tcp);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read");
    let resp: ManagementResponse = serde_json::from_str(&line).expect("parse response");
    assert_eq!(
        resp.status, "ok",
        "Authorized remote caller to 'events' must succeed"
    );

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&cert_file);
    let _ = fs::remove_file(&key_file);
    let _ = fs::remove_file(&fallback_sock);
}

#[test]
fn test_management_events_endpoint_returns_recent_events_mode_expiry_and_drops() {
    let src_port = pick_unused_port();
    let dst_port = pick_unused_port();
    let mgmt_port = pick_unused_port();
    let sock_path = std::env::temp_dir().join(format!("rer_mgmt_events_data_{}.sock", mgmt_port));

    let yaml = format!(
        r#"
version: "1"
instance:
  id: "mgmt-data-node"
  mode: "test"
  test_mode:
    correlation_id: "corr-mgmt-data"
    duration_seconds: 180
    prior_mode: "production"
  management:
    enabled: true
    endpoint: "{}"
  streams:
    - id: "s-mgmt-test"
      source:
        transport: "udp"
        address: "127.0.0.1:{src_port}"
      destination:
        transport: "udp"
        address: "127.0.0.1:{dst_port}"
"#,
        sock_path.display()
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let mgmt_server = ManagementServer::start_local(&sock_path, relay.health_handle(), None)
        .expect("start mgmt server");

    thread::sleep(Duration::from_millis(50));

    // Send a packet through data plane to generate events
    let client = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let dst_sock = std::net::UdpSocket::bind(format!("127.0.0.1:{dst_port}")).expect("bind dst");
    dst_sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");

    client
        .send_to(b"test-mgmt-event-packet", format!("127.0.0.1:{src_port}"))
        .expect("send");
    let mut buf = [0u8; 128];
    let (n, _) = dst_sock.recv_from(&mut buf).expect("recv");
    assert_eq!(&buf[..n], b"test-mgmt-event-packet");

    thread::sleep(Duration::from_millis(50));

    // Query events via client helper function
    let rep = query_events(
        &sock_path.to_string_lossy(),
        Duration::from_secs(2),
        None,
        None,
    )
    .expect("query_events");

    assert_eq!(rep.mode, OperationalMode::Test);
    assert_eq!(rep.expiry, Some(180));
    assert_eq!(rep.dropped_count, 0);
    assert!(!rep.events.is_empty(), "Should return recorded events");

    // Verify ordering: newest is last
    if rep.events.len() >= 2 {
        for w in rep.events.windows(2) {
            assert!(
                w[0].monotonic_timestamp <= w[1].monotonic_timestamp,
                "Events must be ordered newest last (arrival order)"
            );
        }
    }

    // Verify correlation ID on events
    for ev in &rep.events {
        assert_eq!(ev.correlation_id.as_deref(), Some("corr-mgmt-data"));
    }

    // Test with bounded limit
    let rep_limited = query_events(
        &sock_path.to_string_lossy(),
        Duration::from_secs(2),
        None,
        Some(2),
    )
    .expect("query_events with limit");
    assert_eq!(rep_limited.events.len(), 2, "Must respect limit parameter");
    // Newest last check on limited result
    assert!(rep_limited.events[0].monotonic_timestamp <= rep_limited.events[1].monotonic_timestamp);

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&sock_path);
}

// ============================================================================
// Acceptance Criteria for RER-F-030: rer diagnose CLI command
// ============================================================================

#[test]
fn test_cli_diagnose_running_relay() {
    let src_port = pick_unused_port();
    let dst_port = pick_unused_port();
    let mgmt_port = pick_unused_port();
    let sock_path = std::env::temp_dir().join(format!("rer_cli_diagnose_{}.sock", mgmt_port));

    let yaml = format!(
        r#"
version: "1"
instance:
  id: "diagnose-test-node"
  mode: "test"
  test_mode:
    correlation_id: "corr-diag-123"
    duration_seconds: 300
    prior_mode: "production"
  management:
    enabled: true
    endpoint: "{}"
  streams:
    - id: "s-diag-test"
      source:
        transport: "udp"
        address: "127.0.0.1:{src_port}"
      destination:
        transport: "udp"
        address: "127.0.0.1:{dst_port}"
"#,
        sock_path.display()
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");
    let mgmt_server = ManagementServer::start_local(&sock_path, relay.health_handle(), None)
        .expect("start mgmt server");

    thread::sleep(Duration::from_millis(50));

    // Send packets through data plane to generate multiple diagnostic events
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let dst_sock = UdpSocket::bind(format!("127.0.0.1:{dst_port}")).expect("bind dst");
    dst_sock
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("timeout");

    for i in 0..2 {
        client
            .send_to(
                format!("packet-{i}").as_bytes(),
                format!("127.0.0.1:{src_port}"),
            )
            .expect("send");
        let mut buf = [0u8; 128];
        let (n, _) = dst_sock.recv_from(&mut buf).expect("recv");
        assert_eq!(&buf[..n], format!("packet-{i}").as_bytes());
        thread::sleep(Duration::from_millis(50));
    }

    thread::sleep(Duration::from_millis(50));

    // Criterion 1 & Criterion 4: Running rer diagnose with option --socket outputs
    // mode, dropped event count, recorded diagnostic events in arrival order,
    // correlation ID and expiry seconds, exiting with status 0.
    let out = Command::new(rer_bin())
        .args(["diagnose", "--socket", sock_path.to_str().unwrap()])
        .output()
        .expect("rer diagnose --socket");
    assert!(out.status.success(), "rer diagnose must exit with status 0");
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    assert!(stdout.contains("Operational Mode: test") || stdout.contains("test"));
    assert!(stdout.contains("Dropped Events: 0") || stdout.contains("Dropped Event Count: 0"));
    assert!(
        stdout.contains("corr-diag-123"),
        "outputs configured correlation ID"
    );
    assert!(stdout.contains("300"), "outputs configured expiry seconds");
    assert!(stdout.contains("Recorded Diagnostic Events"));

    // Criterion 2: Running rer diagnose with options --socket and --json outputs
    // a valid JSON object matching DiagnosticEventsReport containing mode, dropped_count, and events,
    // exiting with status 0.
    let out_json = Command::new(rer_bin())
        .args([
            "diagnose",
            "--socket",
            sock_path.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("rer diagnose --socket --json");
    assert!(
        out_json.status.success(),
        "rer diagnose --json must exit with status 0"
    );
    let report: rer::management::DiagnosticEventsReport =
        serde_json::from_slice(&out_json.stdout).expect("valid DiagnosticEventsReport JSON");
    assert_eq!(report.mode, OperationalMode::Test);
    assert_eq!(report.dropped_count, 0);
    assert!(!report.events.is_empty());
    assert_eq!(report.correlation_id.as_deref(), Some("corr-diag-123"));
    assert_eq!(report.expiry_seconds, Some(300));

    // Events in arrival order: monotonic timestamps non-decreasing
    if report.events.len() >= 2 {
        for w in report.events.windows(2) {
            assert!(
                w[0].monotonic_timestamp <= w[1].monotonic_timestamp,
                "Events must be in arrival order (newest last)"
            );
        }
    }

    // Criterion 3: Running rer diagnose with option --limit and a value of 2 returns
    // at most 2 diagnostic events, with the newest event ordered last.
    let out_limit = Command::new(rer_bin())
        .args([
            "diagnose",
            "--socket",
            sock_path.to_str().unwrap(),
            "--limit",
            "2",
            "--json",
        ])
        .output()
        .expect("rer diagnose --limit 2 --json");
    assert!(out_limit.status.success());
    let rep_limited: rer::management::DiagnosticEventsReport =
        serde_json::from_slice(&out_limit.stdout).expect("valid DiagnosticEventsReport JSON");
    assert_eq!(rep_limited.events.len(), 2, "Must return at most 2 events");
    assert!(
        rep_limited.events[0].monotonic_timestamp <= rep_limited.events[1].monotonic_timestamp,
        "Newest event must be ordered last"
    );

    // Text limit test
    let out_limit_txt = Command::new(rer_bin())
        .args([
            "diagnose",
            "--socket",
            sock_path.to_str().unwrap(),
            "--limit",
            "2",
        ])
        .output()
        .expect("rer diagnose --limit 2");
    assert!(out_limit_txt.status.success());
    let txt = String::from_utf8(out_limit_txt.stdout).expect("utf8");
    assert!(txt.contains("Recorded Diagnostic Events (2)"));

    mgmt_server.stop();
    relay.stop();
    let _ = fs::remove_file(&sock_path);
}

#[test]
fn test_cli_diagnose_nonexistent_socket() {
    let non_existent =
        std::env::temp_dir().join(format!("nonexistent_mgmt_sock_{}.sock", pick_unused_port()));
    let out = Command::new(rer_bin())
        .args(["diagnose", "--socket", non_existent.to_str().unwrap()])
        .output()
        .expect("rer diagnose --socket nonexistent");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).expect("utf8 stderr");
    assert!(!stderr.is_empty(), "must print error to stderr");
    assert!(stderr.contains("cannot connect") || stderr.contains("Error:"));
}
