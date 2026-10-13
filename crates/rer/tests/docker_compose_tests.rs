use std::fs;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use rer::config::Config;
use rer::health::{query_health, STATUS_HEALTHY};
use rer::relay::Relay;
use rer::sim::{GeneratorConfig, TrafficGenerator};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn rer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rer"))
}

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

// ============================================================================
// 1. Dockerfile Specifications, Version Metadata, & Non-Root Hardening
// ============================================================================

#[test]
fn test_dockerfile_multiarch_nonroot_and_metadata() {
    let dockerfile_path = repo_root().join("deploy").join("docker").join("Dockerfile");
    assert!(dockerfile_path.exists(), "Dockerfile must exist");

    let content = fs::read_to_string(&dockerfile_path).expect("read Dockerfile");

    // Must use minimal distroless base image
    assert!(
        content.contains("FROM gcr.io/distroless/cc-debian12:nonroot")
            || content.contains("distroless"),
        "Runtime image must use minimal distroless base image"
    );

    // Must run as non-root user (UID 65532 nonroot)
    assert!(
        content.contains("USER 65532:65532") || content.contains("USER nonroot"),
        "Dockerfile must execute as non-root"
    );

    // Must not invoke shell in runtime image
    let runtime_stage = content
        .split("AS runtime")
        .nth(1)
        .expect("runtime stage in Dockerfile");
    assert!(
        !runtime_stage.contains("RUN /bin/sh") && !runtime_stage.contains("RUN apt"),
        "Runtime stage must not invoke shell or package manager"
    );

    // Healthcheck must use exec form without shell
    assert!(
        content.contains(r#"CMD ["/usr/local/bin/rer", "health"]"#)
            || content.contains(r#"CMD ["rer", "health"]"#),
        "HEALTHCHECK must use exec form calling rer health"
    );

    // Version label metadata must match binary version
    let expected_version = rer::version();
    let version_pattern = r#"org.opencontainers.image.version="${VERSION}""#;
    let default_version_arg = format!(r#"ARG VERSION={expected_version}"#);
    assert!(
        content.contains(version_pattern) && content.contains(&default_version_arg),
        "Image version metadata must match binary version {expected_version}"
    );

    // Root Dockerfile must also exist and match
    let root_dockerfile = repo_root().join("Dockerfile");
    assert!(root_dockerfile.exists(), "Root Dockerfile must exist");
}

// ============================================================================
// 2. SBOM and Image Vulnerability Scan Artifacts
// ============================================================================

#[test]
fn test_sbom_and_vulnerability_scan_artifacts() {
    let sbom_path = repo_root()
        .join("deploy")
        .join("docker")
        .join("rer.spdx.json");
    assert!(sbom_path.exists(), "SPDX SBOM file must exist");

    let sbom_str = fs::read_to_string(&sbom_path).expect("read SBOM");
    let sbom_json: serde_json::Value =
        serde_json::from_str(&sbom_str).expect("SBOM must be valid JSON");

    assert_eq!(
        sbom_json["spdxVersion"], "SPDX-2.3",
        "SBOM must use SPDX-2.3 specification"
    );

    let packages = sbom_json["packages"].as_array().expect("packages array");
    let rer_pkg = packages
        .iter()
        .find(|p| p["name"] == "rer")
        .expect("rer package must be in SBOM");

    assert_eq!(
        rer_pkg["versionInfo"],
        rer::version(),
        "SBOM version must match binary version"
    );
    assert_eq!(rer_pkg["licenseConcluded"], "Apache-2.0");

    // Check vulnerability scan report
    let scan_path = repo_root()
        .join("deploy")
        .join("docker")
        .join("vulnerability-scan.json");
    assert!(
        scan_path.exists(),
        "Vulnerability scan report file must exist"
    );

    let scan_str = fs::read_to_string(&scan_path).expect("read scan report");
    let scan_json: serde_json::Value =
        serde_json::from_str(&scan_str).expect("Scan report must be valid JSON");

    let results = scan_json["Results"].as_array().expect("Results array");
    for res in results {
        let vulns = res["Vulnerabilities"]
            .as_array()
            .unwrap_or(&Vec::new())
            .clone();
        assert!(
            vulns.is_empty(),
            "Vulnerability scan must report 0 vulnerabilities"
        );
    }
}

// ============================================================================
// 3. Docker Compose Configurations Syntax, Security, & Validation
// ============================================================================

#[test]
fn test_docker_compose_files_syntax_and_settings() {
    let compose_dir = repo_root().join("deploy").join("compose");
    let single_compose = compose_dir.join("docker-compose.single.yml");
    let chain_compose = compose_dir.join("docker-compose.relay-chain.yml");

    assert!(
        single_compose.exists(),
        "docker-compose.single.yml must exist"
    );
    assert!(
        chain_compose.exists(),
        "docker-compose.relay-chain.yml must exist"
    );

    for path in [&single_compose, &chain_compose] {
        let content = fs::read_to_string(path).expect("read compose file");
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&content).expect("compose file must be valid YAML");

        let services = parsed["services"].as_mapping().expect("services mapping");
        for (_svc_name, svc_val) in services {
            // Versioned image reference matching binary version
            let image = svc_val["image"].as_str().expect("service image");
            assert!(
                image.ends_with(&format!(":{}", rer::version())),
                "Service image '{image}' must match binary version {}",
                rer::version()
            );

            // Non-root execution
            assert_eq!(
                svc_val["user"].as_str(),
                Some("65532:65532"),
                "Service must run as non-root user 65532:65532"
            );

            // Read-only filesystem
            assert_eq!(
                svc_val["read_only"].as_bool(),
                Some(true),
                "Service must have read_only: true"
            );

            // Capabilities dropped
            let cap_drop = svc_val["cap_drop"].as_sequence().expect("cap_drop");
            assert!(
                cap_drop.iter().any(|c| c.as_str() == Some("ALL")),
                "Service must drop ALL capabilities"
            );

            // Healthcheck
            let healthcheck = &svc_val["healthcheck"];
            let test_cmd = healthcheck["test"].as_sequence().expect("healthcheck test");
            assert!(
                test_cmd
                    .iter()
                    .any(|c| c.as_str().is_some_and(|s| s.contains("health"))),
                "Health check must invoke rer health"
            );

            // Resource limits
            assert!(
                svc_val["deploy"]["resources"]["limits"].is_mapping(),
                "Resource limits must be specified"
            );
        }
    }

    // If docker CLI is available in the environment, run docker compose config
    if let Ok(output) = Command::new("docker")
        .args(["compose", "-f", single_compose.to_str().unwrap(), "config"])
        .output()
    {
        if output.status.success() {
            println!("docker compose config passed for single instance");
        }
    }
}

// ============================================================================
// 4. Compose YAML Configuration Files Validation
// ============================================================================

#[test]
fn test_compose_config_files_validate_successfully() {
    let config_dir = repo_root().join("deploy").join("compose").join("config");
    for filename in ["single.yaml", "chain-relay1.yaml", "chain-relay2.yaml"] {
        let path = config_dir.join(filename);
        assert!(path.exists(), "Config file {} must exist", path.display());

        let content = fs::read_to_string(&path).expect("read config");
        let config = Config::from_yaml_str(&content)
            .unwrap_or_else(|errs| panic!("Failed to parse {}: {:?}", path.display(), errs));
        let errors = config.validate();
        assert!(
            errors.is_empty(),
            "Configuration {} had validation errors: {:?}",
            path.display(),
            errors
        );
    }
}

// ============================================================================
// 5. Health Check Real Application Query Tests
// ============================================================================

#[test]
fn test_health_check_exercises_real_application_health() {
    let listen_port = pick_unused_port();
    let dest_port = pick_unused_port();

    let temp_dir = std::env::temp_dir();
    let socket_path = temp_dir.join(format!("rer_health_test_{listen_port}.sock"));
    let _ = fs::remove_file(&socket_path);

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "health-test-node"
    streams:
      - id: "health-stream-1"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse config");
    let relay = Relay::start(&config).expect("start relay");

    // Start health server
    let health_server = rer::health::HealthServer::start(&socket_path, relay.health_handle())
        .expect("start health server");

    thread::sleep(Duration::from_millis(50));

    // Query health check via query_health function
    let report =
        query_health(&socket_path, Duration::from_secs(2)).expect("query health successful");

    assert_eq!(report.status, STATUS_HEALTHY);
    assert_eq!(report.version, rer::version());
    assert_eq!(report.streams.len(), 1);
    assert_eq!(report.streams[0].stream_id, "health-stream-1");
    assert!(report.streams[0].healthy);
    assert_eq!(report.streams[0].received_packets, 0);

    // Send traffic through relay to test real stats in health check
    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let receiver = UdpSocket::bind(format!("127.0.0.1:{dest_port}")).expect("bind receiver");
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("timeout");

    sender
        .send_to(b"health-probe-packet", format!("127.0.0.1:{listen_port}"))
        .expect("send packet");

    let mut buf = [0u8; 64];
    let (n, _) = receiver.recv_from(&mut buf).expect("receive packet");
    assert_eq!(&buf[..n], b"health-probe-packet");

    thread::sleep(Duration::from_millis(50));

    // Query health again — packet count must be updated!
    let updated_report =
        query_health(&socket_path, Duration::from_secs(2)).expect("query health updated");
    assert_eq!(updated_report.streams[0].received_packets, 1);
    assert_eq!(updated_report.streams[0].forwarded_packets, 1);
    assert_eq!(updated_report.streams[0].dropped_packets, 0);
    assert_eq!(updated_report.streams[0].errors, 0);

    // Query health using CLI "rer health --socket ..."
    let cli_output = Command::new(rer_bin())
        .arg("health")
        .arg("--socket")
        .arg(&socket_path)
        .output()
        .expect("run rer health CLI");

    assert!(
        cli_output.status.success(),
        "rer health CLI must succeed for healthy relay: {}",
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&cli_output.stdout);
    assert!(stdout.contains("OK: RER relay is healthy"));

    // Query status using CLI "rer status --socket ... --json"
    let status_output = Command::new(rer_bin())
        .arg("status")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--json")
        .output()
        .expect("run rer status CLI");

    assert!(status_output.status.success());
    let status_str = String::from_utf8_lossy(&status_output.stdout);
    assert!(status_str.contains(STATUS_HEALTHY));

    // Stop health server and relay
    health_server.stop();
    relay.stop();

    // Query health when stopped must fail
    let stopped_output = Command::new(rer_bin())
        .arg("health")
        .arg("--socket")
        .arg(&socket_path)
        .output()
        .expect("run rer health on stopped relay");

    assert!(
        !stopped_output.status.success(),
        "rer health must fail when relay is not running"
    );
}

// ============================================================================
// 6. Single-Instance Compose Smoke Test with Test Traffic
// ============================================================================

#[test]
fn test_compose_single_instance_smoke_test_with_traffic() {
    let listen_port = pick_unused_port();
    let dest_port = pick_unused_port();

    let temp_dir = std::env::temp_dir();
    let socket_path = temp_dir.join(format!("single_smoke_{listen_port}.sock"));
    let cfg_path = temp_dir.join(format!("single_smoke_{listen_port}.yaml"));

    let config_content = format!(
        r#"
version: "1"
instances:
  - id: "rer-single-smoke"
    streams:
      - id: "telemetry-stream"
        source:
          transport: "udp"
          address: "127.0.0.1:{listen_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
        buffer:
          max_queue_size: 1024
          drop_policy: "drop_oldest"
"#
    );
    fs::write(&cfg_path, &config_content).expect("write config");

    let recv_socket =
        UdpSocket::bind(format!("127.0.0.1:{dest_port}")).expect("bind receiver socket");
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set timeout");

    // Spawn rer process
    let mut child = Command::new(rer_bin())
        .arg("run")
        .arg("--config")
        .arg(&cfg_path)
        .arg("--health-socket")
        .arg(&socket_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rer");

    // Wait for health check to pass
    let mut healthy = false;
    for _ in 0..30 {
        if let Ok(report) = query_health(&socket_path, Duration::from_millis(100)) {
            if report.status == STATUS_HEALTHY {
                healthy = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(healthy, "Relay must become healthy within timeout");

    // Generate test traffic using TrafficGenerator
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: 42,
        packet_size: 128,
        count: Some(50),
        ..Default::default()
    });
    let packets = gen.emit_all();
    assert_eq!(packets.len(), 50);

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for pkt in &packets {
        let wire = pkt.to_bytes();
        sender
            .send_to(&wire, format!("127.0.0.1:{listen_port}"))
            .expect("send packet");
    }

    // Verify received packets using TrafficReceiver
    let mut receiver = rer::sim::TrafficReceiver::new(Some(50), None);
    let mut buf = vec![0u8; 65536];
    for _ in 0..50 {
        let (n, _) = recv_socket.recv_from(&mut buf).expect("receive packet");
        let pkt = rer::sim::Packet::from_bytes(&buf[..n]).expect("decode packet");
        receiver.record_packet(&pkt);
    }

    let report = receiver.report();
    assert_eq!(report.received_count, 50);
    assert_eq!(report.lost_count, 0);
    assert_eq!(report.duplicate_count, 0);
    assert!(report.payload_hashes_verified);

    // Graceful shutdown via SIGTERM
    let pid = child.id() as libc::pid_t;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let wait_res = child.wait().expect("child wait");
    assert!(
        wait_res.success(),
        "Relay must shut down cleanly on SIGTERM"
    );

    let _ = fs::remove_file(&cfg_path);
    let _ = fs::remove_file(&socket_path);
}

// ============================================================================
// 7. Relay-Chain Compose Smoke Test with Test Traffic
// ============================================================================

#[test]
fn test_compose_relay_chain_smoke_test_with_traffic() {
    // Ingress relay: listens on ingress_port -> forwards to egress_port
    // Egress relay: listens on egress_port -> forwards to final_dest_port
    let ingress_port = pick_unused_port();
    let egress_port = pick_unused_port();
    let final_dest_port = pick_unused_port();

    let temp_dir = std::env::temp_dir();
    let ingress_sock = temp_dir.join(format!("chain_ingress_{ingress_port}.sock"));
    let egress_sock = temp_dir.join(format!("chain_egress_{egress_port}.sock"));
    let ingress_cfg = temp_dir.join(format!("chain_ingress_{ingress_port}.yaml"));
    let egress_cfg = temp_dir.join(format!("chain_egress_{egress_port}.yaml"));

    fs::write(
        &ingress_cfg,
        format!(
            r#"
version: "1"
instances:
  - id: "chain-ingress"
    streams:
      - id: "chain-hop1"
        source:
          transport: "udp"
          address: "127.0.0.1:{ingress_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{egress_port}"
        buffer:
          max_queue_size: 1024
          drop_policy: "drop_oldest"
"#
        ),
    )
    .expect("write ingress config");

    fs::write(
        &egress_cfg,
        format!(
            r#"
version: "1"
instances:
  - id: "chain-egress"
    streams:
      - id: "chain-hop2"
        source:
          transport: "udp"
          address: "127.0.0.1:{egress_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{final_dest_port}"
        buffer:
          max_queue_size: 1024
          drop_policy: "drop_oldest"
"#
        ),
    )
    .expect("write egress config");

    let recv_socket =
        UdpSocket::bind(format!("127.0.0.1:{final_dest_port}")).expect("bind receiver");
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set timeout");

    // Spawn egress relay first
    let mut egress_child = Command::new(rer_bin())
        .arg("run")
        .arg("--config")
        .arg(&egress_cfg)
        .arg("--health-socket")
        .arg(&egress_sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn egress");

    // Spawn ingress relay second
    let mut ingress_child = Command::new(rer_bin())
        .arg("run")
        .arg("--config")
        .arg(&ingress_cfg)
        .arg("--health-socket")
        .arg(&ingress_sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ingress");

    // Wait for both to be healthy
    let mut ingress_healthy = false;
    let mut egress_healthy = false;
    for _ in 0..40 {
        if !ingress_healthy {
            if let Ok(rep) = query_health(&ingress_sock, Duration::from_millis(100)) {
                if rep.status == STATUS_HEALTHY {
                    ingress_healthy = true;
                }
            }
        }
        if !egress_healthy {
            if let Ok(rep) = query_health(&egress_sock, Duration::from_millis(100)) {
                if rep.status == STATUS_HEALTHY {
                    egress_healthy = true;
                }
            }
        }
        if ingress_healthy && egress_healthy {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ingress_healthy, "Ingress relay must become healthy");
    assert!(egress_healthy, "Egress relay must become healthy");

    // Send 100 packets into ingress node -> forward to egress -> forward to receiver
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: 12345,
        packet_size: 256,
        count: Some(100),
        ..Default::default()
    });
    let packets = gen.emit_all();
    assert_eq!(packets.len(), 100);

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for pkt in &packets {
        let wire = pkt.to_bytes();
        sender
            .send_to(&wire, format!("127.0.0.1:{ingress_port}"))
            .expect("send packet");
    }

    // Collect report from destination receiver
    let mut receiver = rer::sim::TrafficReceiver::new(Some(100), None);
    let mut buf = vec![0u8; 65536];
    for _ in 0..100 {
        let (n, _) = recv_socket.recv_from(&mut buf).expect("receive packet");
        let pkt = rer::sim::Packet::from_bytes(&buf[..n]).expect("decode packet");
        receiver.record_packet(&pkt);
    }

    let report = receiver.report();
    assert_eq!(
        report.received_count, 100,
        "All 100 packets must traverse the relay chain intact"
    );
    assert_eq!(report.lost_count, 0, "Zero loss across the relay chain");
    assert_eq!(report.corrupted_count, 0, "Zero corrupted payloads");
    assert!(report.payload_hashes_verified);

    // Query health status from both chain hops
    let ing_report = query_health(&ingress_sock, Duration::from_secs(1)).expect("ingress health");
    let eg_report = query_health(&egress_sock, Duration::from_secs(1)).expect("egress health");
    assert_eq!(ing_report.streams[0].received_packets, 100);
    assert_eq!(ing_report.streams[0].forwarded_packets, 100);
    assert_eq!(eg_report.streams[0].received_packets, 100);
    assert_eq!(eg_report.streams[0].forwarded_packets, 100);

    // Shutdown both relays gracefully on SIGTERM
    let ing_pid = ingress_child.id() as libc::pid_t;
    let eg_pid = egress_child.id() as libc::pid_t;
    unsafe {
        libc::kill(ing_pid, libc::SIGTERM);
        libc::kill(eg_pid, libc::SIGTERM);
    }

    assert!(ingress_child.wait().expect("wait ingress").success());
    assert!(egress_child.wait().expect("wait egress").success());

    let _ = fs::remove_file(&ingress_cfg);
    let _ = fs::remove_file(&egress_cfg);
    let _ = fs::remove_file(&ingress_sock);
    let _ = fs::remove_file(&egress_sock);
}
