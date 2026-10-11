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
