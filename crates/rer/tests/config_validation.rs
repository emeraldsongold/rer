use std::fs;
use std::path::{Path, PathBuf};

use rer::config::{generate_schema, Config};
use rer::secret::SecretString;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn test_all_examples_validate_successfully() {
    let examples_dir = repo_root().join("examples");
    assert!(examples_dir.exists(), "examples directory must exist");

    let mut found_count = 0;
    for entry in fs::read_dir(&examples_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            let content = fs::read_to_string(&path).unwrap();
            let config = Config::from_yaml_str(&content).unwrap_or_else(|errs| {
                panic!("Failed to parse example {}: {:?}", path.display(), errs)
            });
            let errors = config.validate();
            assert!(
                errors.is_empty(),
                "Example configuration {} had validation errors: {:?}",
                path.display(),
                errors
            );
            found_count += 1;
        }
    }
    assert!(
        found_count >= 5,
        "Expected at least 5 example configurations, found {}",
        found_count
    );
}

#[test]
fn test_schema_file_is_up_to_date() {
    let schema_file = repo_root().join("schema").join("rer-config.schema.json");
    assert!(schema_file.exists(), "schema file must exist");

    let existing = fs::read_to_string(&schema_file).unwrap();
    let generated = serde_json::to_string_pretty(&generate_schema()).unwrap() + "\n";

    assert_eq!(
        existing.trim(),
        generated.trim(),
        "schema/rer-config.schema.json is out of date with Rust Config structs."
    );
}

#[test]
fn test_unknown_fields_rejected() {
    let bad_yaml = r#"
version: "1"
instances:
  - id: "test-node"
    unknown_top_field: 123
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
"#;

    let res = Config::from_yaml_str(bad_yaml);
    assert!(res.is_err());
    let errors = res.unwrap_err();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].path, "instances[0].unknown_top_field");
    assert!(errors[0]
        .reason
        .contains("unknown field `unknown_top_field`"));
}

#[test]
fn test_duplicate_instance_identities_rejected() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-duplicate"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
  - id: "relay-duplicate"
    streams:
      - id: "s2"
        source:
          transport: "udp"
          address: "127.0.0.1:5002"
        destination:
          transport: "udp"
          address: "127.0.0.1:5003"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse succeeded");
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| {
        e.path == "instances[1].id"
            && e.reason
                .contains("duplicate instance identity 'relay-duplicate'")
    }));
}

#[test]
fn test_duplicate_stream_identities_rejected() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-1"
    streams:
      - id: "stream-dup"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
      - id: "stream-dup"
        source:
          transport: "udp"
          address: "127.0.0.1:6000"
        destination:
          transport: "udp"
          address: "127.0.0.1:6001"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse succeeded");
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].streams[1].id"
            && e.reason.contains("duplicate stream identity 'stream-dup'")
    }));
}

#[test]
fn test_conflicting_destination_and_destinations_rejected() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-1"
    streams:
      - id: "stream-conflict"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
        destinations:
          - transport: "udp"
            address: "127.0.0.1:5002"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse succeeded");
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].streams[0]"
            && e.reason
                .contains("cannot specify both 'destination' and 'destinations'")
    }));
}

#[test]
fn test_missing_destination_rejected() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-1"
    streams:
      - id: "stream-no-dest"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse succeeded");
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].streams[0]"
            && e.reason.contains(
                "missing destination: either 'destination' or 'destinations' must be specified",
            )
    }));
}

#[test]
fn test_conflicting_instance_and_instances_rejected() {
    let yaml = r#"
version: "1"
instance:
  id: "inst-single"
  streams:
    - id: "s1"
      source:
        transport: "udp"
        address: "127.0.0.1:5000"
      destination:
        transport: "udp"
        address: "127.0.0.1:5001"
instances:
  - id: "inst-multi"
    streams:
      - id: "s2"
        source:
          transport: "udp"
          address: "127.0.0.1:5002"
        destination:
          transport: "udp"
          address: "127.0.0.1:5003"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse succeeded");
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| {
        e.path == "instances"
            && e.reason
                .contains("cannot specify both 'instance' and 'instances'")
    }));
}

#[test]
fn test_logical_interface_conflicting_and_invalid_streams() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-1"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
    logical_interfaces:
      - id: "iface-same"
        tx_stream: "s1"
        rx_stream: "s1"
      - id: "iface-nonexistent"
        tx_stream: "ghost-stream"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse succeeded");
    let errors = config.validate();
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].logical_interfaces[0]"
            && e.reason.contains("cannot reference the same stream ID")
    }));
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].logical_interfaces[1].tx_stream"
            && e.reason.contains("not found in instance streams")
    }));
}

#[test]
fn test_invalid_ports_and_modes_rejected() {
    let yaml = r#"
version: "1"
instances:
  - id: "relay-1"
    streams:
      - id: "s-bad-port"
        source:
          transport: "udp"
          address: "127.0.0.1:0"
          mode: "connect"
        destination:
          transport: "udp"
          address: "127.0.0.1:70000"
"#;

    let config = Config::from_yaml_str(yaml).expect("parse succeeded");
    let errors = config.validate();
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].streams[0].source.address" && e.reason.contains("port 0 is invalid")
    }));
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].streams[0].source.mode"
            && e.reason.contains("UDP source cannot be in 'connect' mode")
    }));
    assert!(errors.iter().any(|e| {
        e.path == "instances[0].streams[0].destination.address"
            && e.reason.contains("out of valid range")
    }));
}

#[test]
fn test_effective_config_never_leaks_secrets() {
    let secret_value = "super-confidential-token-998877";
    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "secure-node"
    management:
      enabled: true
      endpoint: "127.0.0.1:9090"
      auth_token: "{}"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
"#,
        secret_value
    );

    let config = Config::from_yaml_str(&yaml).unwrap();
    assert_eq!(
        config.instances[0]
            .management
            .as_ref()
            .unwrap()
            .auth_token
            .as_ref()
            .unwrap()
            .expose_secret(),
        secret_value
    );

    // Test effective YAML
    let eff_yaml = config.to_effective_yaml().unwrap();
    assert!(
        !eff_yaml.contains(secret_value),
        "Secret value must NEVER appear in effective YAML!"
    );
    assert!(
        eff_yaml.contains("[REDACTED]"),
        "Effective YAML must contain '[REDACTED]'"
    );

    // Test effective JSON
    let eff_json = config.to_effective_json().unwrap();
    let eff_json_str = serde_json::to_string(&eff_json).unwrap();
    assert!(
        !eff_json_str.contains(secret_value),
        "Secret value must NEVER appear in effective JSON!"
    );
    assert!(
        eff_json_str.contains("[REDACTED]"),
        "Effective JSON must contain '[REDACTED]'"
    );

    // Test SecretString Debug and Display
    let sec = SecretString::new(secret_value);
    assert_eq!(format!("{}", sec), "[REDACTED]");
    assert_eq!(format!("{:?}", sec), "SecretString([REDACTED])");
}

fn rer_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rer"))
}

#[test]
fn test_endpoint_address_table_driven_accepted() {
    let mut accepted = vec![
        // IPv4 literals
        "127.0.0.1:80".to_string(),
        "0.0.0.0:5000".to_string(),
        "192.168.1.1:65535".to_string(),
        "10.0.0.1:1".to_string(),
        // Bracketed IPv6 literals
        "[::1]:80".to_string(),
        "[::]:5000".to_string(),
        "[2001:db8::1]:8080".to_string(),
        "[fe80::1]:1234".to_string(),
        // Bracketed IPv6 with zone identifiers
        "[fe80::1%eth0]:80".to_string(),
        "[fe80::1%2]:8080".to_string(),
        "[fe80::1%enp0s3]:5000".to_string(),
        "[::1%lo]:1".to_string(),
        "[fe80::1%123456789012345]:80".to_string(), // exactly 15 bytes zone
        // Syntactically valid hostnames
        "localhost:80".to_string(),
        "example.com:443".to_string(),
        "relay-1.internal.net:5000".to_string(),
        "a.b.c:80".to_string(),
        "host-with-hyphens.example.org:8080".to_string(),
        "999.1.1.com:80".to_string(), // numeric labels allowed if TLD is not all-numeric
    ];

    // Max label length (63 bytes)
    accepted.push(format!("{}.com:80", "a".repeat(63)));

    // Max hostname length (253 bytes): 63 + 1 + 63 + 1 + 63 + 1 + 59 = 251 + 2 = 253
    let long_host = format!(
        "{}.{}.{}.{}:80",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(long_host.split(':').next().unwrap().len(), 253);
    accepted.push(long_host);

    for addr in &accepted {
        let mut errors = Vec::new();
        rer::config::validate_endpoint_address(
            addr,
            "instances[0].streams[0].source.address",
            &mut errors,
        );
        assert!(
            errors.is_empty(),
            "Expected address '{}' to be accepted, but got errors: {:?}",
            addr,
            errors
        );

        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "test-node"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "{addr}"
        destination:
          transport: "udp"
          address: "127.0.0.1:5000"
"#
        );
        let config = Config::from_yaml_str(&yaml).expect("parse valid config YAML");
        let validation_errors = config.validate();
        assert!(
            validation_errors.is_empty(),
            "Expected config with address '{}' to validate cleanly, got: {:?}",
            addr,
            validation_errors
        );
    }
}

fn rejected_address_test_cases() -> Vec<(&'static str, &'static str)> {
    vec![
        // IPv4 out of range / malformed octets
        ("999.1.1.1:80", "invalid IPv4 address"),
        ("1.2.3:80", "invalid IPv4 address"),
        ("1.2.3.4.5:80", "invalid IPv4 address"),
        ("256.0.0.1:80", "invalid IPv4 address"),
        ("1.2.3.-4:80", "cannot start or end with a hyphen"),
        // Malformed IPv6 brackets / unbracketed
        ("[::1:80", "missing closing ']'"),
        ("::1:80", "IPv6 literals must be bracketed"),
        ("[::1]", "missing port after bracketed IPv6"),
        ("[::1]80", "expected ':port'"),
        ("[::1]bad:80", "expected ':port'"),
        ("[]:80", "cannot be empty"),
        ("[invalid::ipv6::1]:80", "invalid IPv6 address"),
        // Zone identifier errors
        ("[fe80::1%]:80", "zone identifier cannot be empty"),
        ("[fe80::1%eth0 long]:80", "whitespace or control characters"),
        ("[fe80::1%eth0\t]:80", "whitespace or control characters"),
        ("[fe80::1%eth0\x01]:80", "whitespace or control characters"),
        (
            "[fe80::1%1234567890123456]:80",
            "exceeds maximum length of 15 bytes",
        ), // 16 bytes
        (
            "[fe80::1%eth0%eth1]:80",
            "cannot contain multiple zone identifiers",
        ),
        // Port errors (each with their own message)
        ("127.0.0.1:0", "port 0 is invalid"),
        ("127.0.0.1:-1", "negative port"),
        ("127.0.0.1:-80", "negative port"),
        ("127.0.0.1:65536", "out of valid range"),
        ("127.0.0.1:70000", "out of valid range"),
        ("127.0.0.1:", "port must not be empty"),
        ("127.0.0.1:abc", "non-numeric port"),
        ("127.0.0.1:80a", "non-numeric port"),
        // Hostname errors
        ("host name:80", "contains spaces or control characters"),
        ("host\x01name:80", "contains spaces or control characters"),
        ("-host.com:80", "cannot start or end with a hyphen"),
        ("host-.com:80", "cannot start or end with a hyphen"),
        ("host_name.com:80", "contains invalid character"),
        ("host..com:80", "contains empty label"),
        (".host.com:80", "contains empty label"),
        ("host.com.:80", "contains empty label"),
        ("host.123:80", "all-numeric top-level domain"),
        // Address format errors
        (":80", "address host part must not be empty"),
        ("localhost", "expected 'host:port'"),
        ("/path/to/stream.sock", "expected 'host:port'"),
    ]
}

#[test]
fn test_endpoint_address_table_driven_rejected() {
    let cases = rejected_address_test_cases();

    // 64-byte label (> 63 bytes)
    let label_64 = format!("{}.com:80", "a".repeat(64));
    // 254-byte host (> 253 bytes)
    let host_254 = format!(
        "{}.{}.{}.{}:80",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    assert_eq!(host_254.split(':').next().unwrap().len(), 254);

    let extra_cases = vec![
        (label_64.as_str(), "exceeds maximum length of 63 bytes"),
        (host_254.as_str(), "exceeds maximum length of 253 bytes"),
    ];

    for (addr, expected_reason) in cases.iter().copied().chain(extra_cases) {
        let mut errors = Vec::new();
        rer::config::validate_endpoint_address(
            addr,
            "instances[0].streams[0].source.address",
            &mut errors,
        );
        assert!(
            !errors.is_empty(),
            "Expected address '{}' to be rejected, but it had no errors",
            addr
        );
        assert_eq!(
            errors[0].path, "instances[0].streams[0].source.address",
            "Error for '{}' should have matching path",
            addr
        );
        assert!(
            errors[0].reason.contains(expected_reason),
            "Expected address '{}' error reason '{}' to contain '{}'",
            addr,
            errors[0].reason,
            expected_reason
        );

        // Also test through Config::validate()
        let addr_json = serde_json::to_string(addr).unwrap();
        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "test-node"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: {addr_json}
        destination:
          transport: "udp"
          address: "127.0.0.1:5000"
"#
        );
        match Config::from_yaml_str(&yaml) {
            Ok(config) => {
                let val_errors = config.validate();
                assert!(
                    !val_errors.is_empty(),
                    "Expected Config::validate() to reject address '{}'",
                    addr
                );
                assert!(
                    val_errors.iter().any(|e| e.path == "instances[0].streams[0].source.address"
                        && e.reason.contains(expected_reason)),
                    "Expected Config::validate() for '{}' to report error on source.address containing '{}', got: {:?}",
                    addr,
                    expected_reason,
                    val_errors
                );
            }
            Err(parse_errors) => {
                // If YAML parser strictly rejected malformed character before validate
                assert!(
                    !parse_errors.is_empty(),
                    "Expected parse errors for invalid address '{}'",
                    addr
                );
            }
        }
    }
}

#[test]
fn test_rer_run_refuses_to_start_on_all_rejected_classes() {
    let cases = rejected_address_test_cases();
    let label_64 = format!("{}.com:80", "a".repeat(64));
    let host_254 = format!(
        "{}.{}.{}.{}:80",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );
    let extra_cases = vec![
        (label_64.as_str(), "exceeds maximum length of 63 bytes"),
        (host_254.as_str(), "exceeds maximum length of 253 bytes"),
    ];

    let temp_dir = std::env::temp_dir();
    let bin = rer_bin();

    for (idx, (addr, _)) in cases.iter().copied().chain(extra_cases).enumerate() {
        let cfg_path = temp_dir.join(format!("test_reject_run_{}.yaml", idx));
        let addr_json = serde_json::to_string(addr).unwrap();
        let yaml = format!(
            r#"
version: "1"
instances:
  - id: "node-reject"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: {addr_json}
        destination:
          transport: "udp"
          address: "127.0.0.1:5000"
"#
        );
        std::fs::write(&cfg_path, &yaml).expect("write temp config");

        let output = std::process::Command::new(&bin)
            .arg("run")
            .arg(&cfg_path)
            .output()
            .expect("execute rer run");

        let _ = std::fs::remove_file(&cfg_path);

        assert!(
            !output.status.success(),
            "rer run MUST refuse to start on rejected address '{}'",
            addr
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("validation failed")
                || stderr.contains("invalid")
                || stderr.contains("parse failed"),
            "stderr for '{}' must report validation failure, got: {}",
            addr,
            stderr
        );
    }
}

#[test]
fn test_unix_domain_socket_management_endpoint_kept() {
    // Unix domain socket in management: keeps current handling and is NOT run through host validation
    let valid_uds_yaml = r#"
version: "1"
instances:
  - id: "uds-node"
    management:
      enabled: true
      endpoint: "/tmp/local_mgmt.sock"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
"#;
    let config = Config::from_yaml_str(valid_uds_yaml).expect("parse config");
    let errors = config.validate();
    assert!(
        errors.is_empty(),
        "Unix domain socket in management endpoint must not produce validation errors: {:?}",
        errors
    );

    // Invalid remote management endpoint: must be caught
    let invalid_remote_mgmt_yaml = r#"
version: "1"
instances:
  - id: "remote-mgmt-node"
    management:
      enabled: true
      endpoint: "999.1.1.1:9090"
      auth_token: "secret-token"
      tls:
        cert_file: "/path/cert.pem"
        key_file: "/path/key.pem"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:5000"
        destination:
          transport: "udp"
          address: "127.0.0.1:5001"
"#;
    let config2 = Config::from_yaml_str(invalid_remote_mgmt_yaml).expect("parse config");
    let errors2 = config2.validate();
    assert!(
        errors2
            .iter()
            .any(|e| e.path == "instances[0].management.endpoint"
                && e.reason.contains("invalid IPv4 address")),
        "Invalid remote management endpoint must be rejected with host validation error: {:?}",
        errors2
    );
}
