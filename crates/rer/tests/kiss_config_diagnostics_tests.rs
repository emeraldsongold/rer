//! Integration tests for Task RER-F-062:
//! KISS configuration and AX.25 diagnostic event enrichment.

use std::process::Command;
use std::sync::Arc;

use rer::config::{Config, FramingMode, KissConfig, TransportType};
use rer::diagnostics::{
    DiagnosticBuffer, DiagnosticEvent, DiagnosticStage, KissInspection, ManualClock,
};

#[test]
fn test_criterion1_kiss_config_deserialization_defaults() {
    // Acceptance criterion:
    // Deserializing a configuration YAML containing stream option kiss defaults
    // field enabled to true and field inspect_ax25 to true.
    let yaml = r#"
version: "1"
instances:
  - id: "inst-kiss-1"
    streams:
      - id: "stream-kiss-1"
        kiss: {}
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
"#;
    let config = Config::from_yaml_str(yaml).expect("parse yaml with kiss option");
    let stream = &config.instances[0].streams[0];
    let kiss_cfg = stream
        .kiss
        .as_ref()
        .expect("option kiss must deserialize into Some(KissConfig)");

    assert!(kiss_cfg.enabled, "default enabled must be true");
    assert!(kiss_cfg.inspect_ax25, "default inspect_ax25 must be true");
    assert_eq!(kiss_cfg.port_filter, None);
    assert!(!kiss_cfg.passthrough_on_error);
    assert_eq!(kiss_cfg.framing, None);

    // Also verify with empty scalar (kiss:)
    let yaml_scalar = r#"
version: "1"
instances:
  - id: "inst-kiss-2"
    streams:
      - id: "stream-kiss-2"
        kiss:
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
"#;
    let config2 = Config::from_yaml_str(yaml_scalar).expect("parse yaml with scalar kiss");
    let kiss_cfg2 = config2.instances[0].streams[0]
        .kiss
        .as_ref()
        .expect("scalar kiss must deserialize into Some(KissConfig)");
    assert_eq!(kiss_cfg2, &KissConfig::default());
    assert!(kiss_cfg2.enabled);
    assert!(kiss_cfg2.inspect_ax25);

    // Also verify with boolean true (kiss: true)
    let yaml_bool = r#"
version: "1"
instances:
  - id: "inst-kiss-3"
    streams:
      - id: "stream-kiss-3"
        kiss: true
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
"#;
    let config3 = Config::from_yaml_str(yaml_bool).expect("parse yaml with boolean kiss");
    let kiss_cfg3 = config3.instances[0].streams[0]
        .kiss
        .as_ref()
        .expect("boolean kiss must deserialize into Some(KissConfig)");
    assert!(kiss_cfg3.enabled);
    assert!(kiss_cfg3.inspect_ax25);
}

#[test]
fn test_criterion2_rer_validate_port_filter_greater_than_15_returns_validation_error() {
    // Acceptance criterion:
    // Running rer validate on a configuration with option kiss containing a port filter value
    // greater than 15 returns a validation error reporting an invalid port number.
    let yaml_invalid = r#"
version: "1"
instances:
  - id: "inst-invalid-kiss"
    streams:
      - id: "stream-invalid-port"
        kiss:
          port_filter: 16
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
"#;

    // 1. Programmatic validation via Config::validate()
    let config = Config::from_yaml_str(yaml_invalid).expect("parse yaml config");
    let errors = config.validate();
    assert!(
        !errors.is_empty(),
        "Config::validate() must return errors for port_filter > 15"
    );
    let port_error = errors
        .iter()
        .find(|e| e.reason.contains("invalid port number"));
    assert!(
        port_error.is_some(),
        "expected validation error reporting 'invalid port number', got: {:?}",
        errors
    );

    // 2. CLI execution via `rer validate <file>`
    let temp_file = std::env::temp_dir().join(format!(
        "rer_test_kiss_port_filter_{}.yaml",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&temp_file, yaml_invalid).expect("write temporary test config");

    let output = Command::new(env!("CARGO_BIN_EXE_rer"))
        .arg("validate")
        .arg(&temp_file)
        .output()
        .expect("execute rer validate");

    let _ = std::fs::remove_file(&temp_file);

    assert!(
        !output.status.success(),
        "rer validate must exit with non-zero exit code for invalid port number"
    );
    let combined_out = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined_out.contains("invalid port number"),
        "rer validate output must report 'invalid port number', got: {}",
        combined_out
    );

    // Also verify valid port 15 passes cleanly
    let yaml_valid = r#"
version: "1"
instances:
  - id: "inst-valid-kiss"
    streams:
      - id: "stream-valid-port"
        kiss:
          port_filter: 15
        source:
          transport: "tcp"
          address: "127.0.0.1:8001"
        destination:
          transport: "tcp"
          address: "127.0.0.1:8002"
"#;
    let config_valid = Config::from_yaml_str(yaml_valid).expect("parse valid yaml config");
    assert!(
        config_valid.validate().is_empty(),
        "configuration with port_filter: 15 must validate without errors"
    );
}

#[test]
fn test_criterion3_diagnostic_event_kiss_metadata_serialization() {
    // Acceptance criterion:
    // In crates/rer/src/diagnostics.rs, serializing a DiagnosticEvent containing KISS port,
    // KISS command, AX.25 source callsign, and destination callsign produces a JSON object
    // containing the structured metadata fields.
    let event = DiagnosticEvent::new(
        1_000_000,
        2_000_000,
        "kiss-stream",
        DiagnosticStage::KissInspection,
        TransportType::Tcp,
        128,
    )
    .with_kiss_port(3)
    .with_kiss_command(0)
    .with_ax25_source_callsign("W1AW")
    .with_ax25_destination_callsign("CQ");

    let json_str = serde_json::to_string(&event).expect("serialize DiagnosticEvent to JSON");
    let val: serde_json::Value =
        serde_json::from_str(&json_str).expect("parse serialized event as JSON Value");
    let obj = val
        .as_object()
        .expect("serialized event must be a JSON object");

    // Root-level fields
    assert_eq!(
        obj.get("kiss_port").and_then(|v| v.as_u64()),
        Some(3),
        "JSON must contain kiss_port = 3"
    );
    assert_eq!(
        obj.get("kiss_command").and_then(|v| v.as_u64()),
        Some(0),
        "JSON must contain kiss_command = 0"
    );
    assert_eq!(
        obj.get("ax25_source_callsign").and_then(|v| v.as_str()),
        Some("W1AW"),
        "JSON must contain ax25_source_callsign = W1AW"
    );
    assert_eq!(
        obj.get("ax25_destination_callsign")
            .and_then(|v| v.as_str()),
        Some("CQ"),
        "JSON must contain ax25_destination_callsign = CQ"
    );

    // Structured metadata objects
    let kiss_meta = obj
        .get("kiss_metadata")
        .and_then(|v| v.as_object())
        .expect("JSON must contain structured kiss_metadata object");
    assert_eq!(
        kiss_meta.get("port").and_then(|v| v.as_u64()),
        Some(3),
        "structured metadata must contain port = 3"
    );
    assert_eq!(
        kiss_meta.get("command").and_then(|v| v.as_u64()),
        Some(0),
        "structured metadata must contain command = 0"
    );
    assert_eq!(
        kiss_meta.get("command_name").and_then(|v| v.as_str()),
        Some("DATA"),
        "structured metadata must contain command_name = DATA"
    );
    assert_eq!(
        kiss_meta.get("source_callsign").and_then(|v| v.as_str()),
        Some("W1AW"),
        "structured metadata must contain source_callsign = W1AW"
    );
    assert_eq!(
        kiss_meta
            .get("destination_callsign")
            .and_then(|v| v.as_str()),
        Some("CQ"),
        "structured metadata must contain destination_callsign = CQ"
    );

    let ax25_meta = obj
        .get("ax25_metadata")
        .and_then(|v| v.as_object())
        .expect("JSON must contain structured ax25_metadata object");
    assert_eq!(
        ax25_meta.get("source_callsign").and_then(|v| v.as_str()),
        Some("W1AW"),
        "ax25 metadata must contain source_callsign = W1AW"
    );
    assert_eq!(
        ax25_meta
            .get("destination_callsign")
            .and_then(|v| v.as_str()),
        Some("CQ"),
        "ax25 metadata must contain destination_callsign = CQ"
    );

    // Also verify roundtrip deserialization
    let deserialized: DiagnosticEvent =
        serde_json::from_str(&json_str).expect("roundtrip deserialization of DiagnosticEvent");
    assert_eq!(deserialized.kiss_port, Some(3));
    assert_eq!(deserialized.kiss_command, Some(0));
    assert_eq!(deserialized.ax25_source_callsign.as_deref(), Some("W1AW"));
    assert_eq!(
        deserialized.ax25_destination_callsign.as_deref(),
        Some("CQ")
    );
}

#[test]
fn test_criterion4_emitting_kiss_metadata_into_full_buffer_drops_without_blocking_or_panicking() {
    // Acceptance criterion:
    // In crates/rer/src/diagnostics.rs, emitting a DiagnosticEvent with KISS metadata
    // into a full DiagnosticBuffer drops the event without blocking or panicking.
    let clock = Arc::new(ManualClock::new(100, 200));
    let buffer = DiagnosticBuffer::with_clock(2, clock);
    assert_eq!(buffer.capacity(), 2);

    // Fill buffer to capacity
    let ev1 = buffer.create_event("s1", DiagnosticStage::Received, TransportType::Tcp, 64);
    let ev2 = buffer.create_event("s1", DiagnosticStage::Accepted, TransportType::Tcp, 64);
    assert!(buffer.emit(ev1));
    assert!(buffer.emit(ev2));
    assert_eq!(buffer.len(), 2);
    assert_eq!(buffer.dropped_count(), 0);

    // Emit DiagnosticEvent with KISS metadata into the full buffer
    let kiss_event = DiagnosticEvent::new(
        300,
        400,
        "s1",
        DiagnosticStage::KissInspection,
        TransportType::Tcp,
        64,
    )
    .with_kiss_port(1)
    .with_kiss_command(0)
    .with_ax25_source_callsign("K1ABC")
    .with_ax25_destination_callsign("CQ");

    // Must drop without blocking or panicking
    let emitted = buffer.emit(kiss_event);
    assert!(emitted);
    assert_eq!(buffer.len(), 2);
    assert_eq!(
        buffer.dropped_count(),
        1,
        "emitting into full buffer must increment dropped_count"
    );

    // Verify snapshot
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.dropped_count, 1);
    assert_eq!(snapshot.events.len(), 2);
    assert_eq!(snapshot.events[1].stage, DiagnosticStage::KissInspection);
    assert_eq!(snapshot.events[1].kiss_port, Some(1));
    assert_eq!(snapshot.events[1].kiss_command, Some(0));
    assert_eq!(
        snapshot.events[1].ax25_source_callsign.as_deref(),
        Some("K1ABC")
    );
    assert_eq!(
        snapshot.events[1].ax25_destination_callsign.as_deref(),
        Some("CQ")
    );

    // Test with buffer of capacity 0
    let zero_buf = DiagnosticBuffer::new(0);
    let zero_event = KissInspection::new(0, 0)
        .with_source_callsign("N0CALL")
        .with_destination_callsign("APRS");
    let zero_emitted = zero_buf.emit(zero_event);
    assert!(!zero_emitted);
    assert_eq!(zero_buf.dropped_count(), 1);
}

#[test]
fn test_criterion5_omitting_kiss_defaults_to_none_and_preserves_values() {
    // Acceptance criterion:
    // Deserializing a configuration YAML containing a stream without option kiss defaults
    // to None and preserves existing configuration behavior.
    let yaml = r#"
version: "1"
instances:
  - id: "inst-no-kiss"
    streams:
      - id: "stream-tcp-forward"
        description: "Standard TCP forwarding stream without KISS"
        framing: "length_prefix"
        source:
          transport: "tcp"
          address: "127.0.0.1:9000"
        destination:
          transport: "tcp"
          address: "127.0.0.1:9001"
"#;
    let config = Config::from_yaml_str(yaml).expect("parse yaml omitting option kiss");
    let stream = &config.instances[0].streams[0];

    // Field kiss must default to None
    assert_eq!(
        stream.kiss, None,
        "omitting option kiss must default stream.kiss to None"
    );

    // Preserves existing configuration values and behavior
    assert_eq!(stream.id, "stream-tcp-forward");
    assert_eq!(
        stream.description.as_deref(),
        Some("Standard TCP forwarding stream without KISS")
    );
    assert_eq!(stream.framing, Some(FramingMode::LengthPrefix));
    assert_eq!(stream.source.transport, TransportType::Tcp);
    assert_eq!(stream.source.address, "127.0.0.1:9000");
    let dest = stream.destination.as_ref().unwrap();
    assert_eq!(dest.transport, TransportType::Tcp);
    assert_eq!(dest.address, "127.0.0.1:9001");
    assert_eq!(stream.source_framing(), FramingMode::LengthPrefix);
    assert_eq!(stream.destination_framing(dest), FramingMode::LengthPrefix);

    // Configuration validates cleanly
    assert!(
        config.validate().is_empty(),
        "configuration without option kiss must validate cleanly"
    );
}
