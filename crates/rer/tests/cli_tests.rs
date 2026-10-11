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
