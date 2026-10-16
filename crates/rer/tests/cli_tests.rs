use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn rer_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rer")
}

#[test]
fn test_cli_version() {
    let output = Command::new(rer_bin())
        .arg("version")
        .output()
        .expect("failed to execute rer version");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("rer "));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_cli_validate_example_text() {
    let example = repo_root().join("examples").join("minimal.yaml");
    let output = Command::new(rer_bin())
        .arg("validate")
        .arg(&example)
        .output()
        .expect("failed to execute rer validate");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("is valid"));
}

#[test]
fn test_cli_validate_example_json() {
    let example = repo_root().join("examples").join("minimal.yaml");
    let output = Command::new(rer_bin())
        .arg("validate")
        .arg("--json")
        .arg(&example)
        .output()
        .expect("failed to execute rer validate --json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    assert_eq!(val["valid"], true);
    assert!(val["errors"].as_array().unwrap().is_empty());
}

#[test]
fn test_cli_validate_invalid_config_text() {
    let temp_dir = std::env::temp_dir();
    let bad_config = temp_dir.join("test_bad_config.yaml");
    std::fs::write(
        &bad_config,
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
        .arg("validate")
        .arg(&bad_config)
        .output()
        .expect("failed to execute rer validate");

    let _ = std::fs::remove_file(&bad_config);

    assert!(
        !output.status.success(),
        "invalid config must exit non-zero"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("is invalid"));
    assert!(stderr.contains("instances[0].streams[0].source.address"));
    assert!(stderr.contains("port 0 is invalid"));
}

#[test]
fn test_cli_validate_invalid_config_json() {
    let temp_dir = std::env::temp_dir();
    let bad_config = temp_dir.join("test_bad_config_json.yaml");
    std::fs::write(
        &bad_config,
        r#"
version: "1"
instances:
  - id: "node1"
    unknown_field: 42
"#,
    )
    .unwrap();

    let output = Command::new(rer_bin())
        .arg("validate")
        .arg("--json")
        .arg(&bad_config)
        .output()
        .expect("failed to execute rer validate --json");

    let _ = std::fs::remove_file(&bad_config);

    assert!(
        !output.status.success(),
        "invalid config must exit non-zero"
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    assert_eq!(val["valid"], false);
    let errors = val["errors"].as_array().expect("errors array");
    assert!(!errors.is_empty());
    assert_eq!(errors[0]["path"], "instances[0].unknown_field");
    assert!(errors[0]["reason"]
        .as_str()
        .unwrap()
        .contains("unknown field `unknown_field`"));
}

#[test]
fn test_cli_effective_config_redacts_secrets() {
    let example = repo_root().join("examples").join("management_auth.yaml");
    let output = Command::new(rer_bin())
        .arg("validate")
        .arg("--effective")
        .arg(&example)
        .output()
        .expect("failed to execute rer validate --effective");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("example-token-for-testing"));
    assert!(stdout.contains("[REDACTED]"));

    // Also test rer inspect
    let inspect_output = Command::new(rer_bin())
        .arg("inspect")
        .arg(&example)
        .output()
        .expect("failed to execute rer inspect");

    assert!(inspect_output.status.success());
    let inspect_stdout = String::from_utf8(inspect_output.stdout).unwrap();
    assert!(!inspect_stdout.contains("example-token-for-testing"));
    assert!(inspect_stdout.contains("[REDACTED]"));
}

#[test]
fn test_cli_test_harness_json() {
    let output = Command::new(rer_bin())
        .arg("test")
        .arg("--count")
        .arg("20")
        .arg("--size")
        .arg("128")
        .arg("--seed")
        .arg("12345")
        .arg("--json")
        .output()
        .expect("failed to execute rer test");

    assert!(output.status.success(), "rer test must exit 0 on success");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    assert_eq!(val["pass"], true);
    assert_eq!(val["expected_count"], 20);
    assert_eq!(val["received_count"], 20);
    assert_eq!(val["lost_count"], 0);
    assert_eq!(val["duplicate_count"], 0);
    assert_eq!(val["reordered_count"], 0);
    assert_eq!(val["payload_hashes_verified"], true);
}

#[test]
fn test_cli_streams_paired_text() {
    let example = repo_root().join("examples").join("paired_streams.yaml");
    let output = Command::new(rer_bin())
        .arg("streams")
        .arg(&example)
        .output()
        .expect("failed to execute rer streams");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Streams and Logical Interfaces:"));
    assert!(stdout.contains("spacecraft-link-0"));
    assert!(stdout.contains("Primary Spacecraft Comm Link"));
    assert!(stdout.contains("Paired directional streams (TX + RX)"));
    assert!(stdout.contains("cmd-uplink"));
    assert!(stdout.contains("telem-downlink"));
    assert!(stdout.contains("Configuration and operator context"));
    assert!(stdout.contains("no automatic packet correlation"));
}

#[test]
fn test_cli_streams_paired_json() {
    let example = repo_root().join("examples").join("paired_streams.yaml");
    let output = Command::new(rer_bin())
        .arg("streams")
        .arg("--json")
        .arg(&example)
        .output()
        .expect("failed to execute rer streams --json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    let instances = val["instances"].as_array().expect("instances array");
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0]["id"], "relay-paired");

    let ifaces = instances[0]["logical_interfaces"]
        .as_array()
        .expect("logical_interfaces array");
    assert_eq!(ifaces.len(), 1);
    assert_eq!(ifaces[0]["id"], "spacecraft-link-0");
    assert_eq!(ifaces[0]["pairing_type"], "paired");
    assert_eq!(ifaces[0]["tx_stream"], "cmd-uplink");
    assert_eq!(ifaces[0]["rx_stream"], "telem-downlink");
    assert!(ifaces[0]["pairing_context"]
        .as_str()
        .unwrap()
        .contains("without automatic packet correlation"));
    assert_eq!(ifaces[0]["tx"]["id"], "cmd-uplink");
    assert_eq!(ifaces[0]["rx"]["id"], "telem-downlink");
}

#[test]
fn test_cli_streams_multi_interface_json() {
    let example = repo_root().join("examples").join("multi_interface.yaml");
    let output = Command::new(rer_bin())
        .arg("streams")
        .arg("--json")
        .arg(&example)
        .output()
        .expect("failed to execute rer streams --json on multi_interface.yaml");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    let instances = val["instances"].as_array().expect("instances array");
    let ifaces = instances[0]["logical_interfaces"]
        .as_array()
        .expect("logical_interfaces array");
    assert_eq!(ifaces.len(), 3);

    // Primary paired link
    assert_eq!(ifaces[0]["id"], "primary-comm-link");
    assert_eq!(ifaces[0]["pairing_type"], "paired");

    // Emergency single-direction (TX only)
    assert_eq!(ifaces[1]["id"], "emergency-cmd-link");
    assert_eq!(ifaces[1]["pairing_type"], "tx_only");
    assert_eq!(ifaces[1]["tx_stream"], "backup-cmd-uplink");
    assert!(ifaces[1]["rx_stream"].is_null());

    // Payload single-direction (RX only with fanout)
    assert_eq!(ifaces[2]["id"], "payload-downlink");
    assert_eq!(ifaces[2]["pairing_type"], "rx_only");
    assert!(ifaces[2]["tx_stream"].is_null());
    assert_eq!(ifaces[2]["rx_stream"], "science-payload-fanout");
    assert_eq!(ifaces[2]["rx"]["destinations"].as_array().unwrap().len(), 2);
}

#[test]
fn test_cli_streams_missing_file_error() {
    let output = Command::new(rer_bin())
        .arg("streams")
        .output()
        .expect("failed to execute rer streams without file");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("missing configuration file argument"));
}

#[test]
fn test_cli_inspect_text_format() {
    let example = repo_root().join("examples").join("minimal.yaml");
    let output = Command::new(rer_bin())
        .arg("inspect")
        .arg(&example)
        .arg("--format")
        .arg("text")
        .output()
        .expect("failed to execute rer inspect --format text");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Per-Stream Sequence Tracking and Inspection:"));
    assert!(stdout.contains("udp-forwarder"));
    assert!(stdout.contains("Sequence tracking: disabled (off by default)"));
}

#[test]
fn test_cli_inspect_json_format() {
    let example = repo_root().join("examples").join("minimal.yaml");
    let output = Command::new(rer_bin())
        .arg("inspect")
        .arg(&example)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to execute rer inspect --format json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    let streams = val["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty());
    assert_eq!(streams[0]["stream_id"], "udp-forwarder");
    assert_eq!(streams[0]["enabled"], false);
}

#[test]
fn test_cli_inspect_json_flag() {
    let example = repo_root().join("examples").join("minimal.yaml");
    let output = Command::new(rer_bin())
        .arg("inspect")
        .arg(&example)
        .arg("--json")
        .output()
        .expect("failed to execute rer inspect --json");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    let streams = val["streams"].as_array().expect("streams array");
    assert!(!streams.is_empty());
    assert_eq!(streams[0]["stream_id"], "udp-forwarder");
}

#[test]
fn test_cli_replay_missing_file_error() {
    let output = Command::new(rer_bin())
        .arg("replay")
        .arg("--destination")
        .arg("127.0.0.1:5000")
        .output()
        .expect("failed to execute rer replay");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("missing capture file"));
}

#[test]
fn test_cli_replay_missing_destination_error() {
    let temp_file = std::env::temp_dir().join("test_cli_missing_dest.pcap");
    std::fs::write(&temp_file, b"dummy content").unwrap();

    let output = Command::new(rer_bin())
        .arg("replay")
        .arg(&temp_file)
        .output()
        .expect("failed to execute rer replay");

    let _ = std::fs::remove_file(&temp_file);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("explicit destination endpoint"));
}

#[test]
fn test_cli_replay_non_test_destination_refused_by_default() {
    let pkts = vec![rer::capture::SyntheticPacket {
        timestamp: std::time::Duration::ZERO,
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
        src_port: 5000,
        dst_port: 6000,
        payload: b"cli-safety-check".to_vec(),
    }];
    let pcap = rer::capture::build_synthetic_pcap(rer::capture::LinkType::Ethernet, &pkts, false);
    let temp_file = std::env::temp_dir().join("test_cli_safety.pcap");
    std::fs::write(&temp_file, &pcap).unwrap();

    let output = Command::new(rer_bin())
        .arg("replay")
        .arg(&temp_file)
        .arg("--destination")
        .arg("8.8.8.8:53")
        .output()
        .expect("failed to execute rer replay");

    let _ = std::fs::remove_file(&temp_file);

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("refusing to replay capture to non-test endpoint"));
}

#[test]
fn test_cli_replay_json_output() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind listener");
    let port = socket.local_addr().unwrap().port();
    let dest = format!("127.0.0.1:{port}");

    let pkts = vec![
        rer::capture::SyntheticPacket {
            timestamp: std::time::Duration::ZERO,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5001,
            dst_port: port,
            payload: b"json-packet-1".to_vec(),
        },
        rer::capture::SyntheticPacket {
            timestamp: std::time::Duration::from_millis(10),
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            src_port: 5002,
            dst_port: port,
            payload: b"json-packet-2".to_vec(),
        },
    ];
    let pcap = rer::capture::build_synthetic_pcap(rer::capture::LinkType::Ethernet, &pkts, false);
    let temp_file = std::env::temp_dir().join(format!("test_cli_json_{}.pcap", port));
    std::fs::write(&temp_file, &pcap).unwrap();

    let output = Command::new(rer_bin())
        .arg("replay")
        .arg(&temp_file)
        .arg("--destination")
        .arg(&dest)
        .arg("--max-rate")
        .arg("--json")
        .output()
        .expect("failed to execute rer replay --json");

    let _ = std::fs::remove_file(&temp_file);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON expected");
    assert_eq!(val["selected"], 2);
    assert_eq!(val["attempted"], 2);
    assert_eq!(val["injected"], 2);
    assert_eq!(val["failed"], 0);
    assert_eq!(val["success"], true);
}
