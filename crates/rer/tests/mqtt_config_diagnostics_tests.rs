//! Integration tests for Task RER-F-058:
//! MQTT stream configuration model and diagnostic event telemetry.

use rer::config::{Config, FramingMode, MqttConfig, TransportType};
use rer::diagnostics::{
    record_mqtt_local_transmission, DiagnosticBuffer, DiagnosticEvent, DiagnosticStage,
    MqttInspection,
};

#[test]
fn test_criterion1_configuring_option_mqtt_deserializes_with_default_validation_settings() {
    // Acceptance criterion:
    // In crates/rer/src/config.rs, configuring option mqtt deserializes into MqttConfig
    // with default validation settings.
    let yaml = r#"
version: "1"
instances:
  - id: "inst-mqtt-1"
    streams:
      - id: "stream-mqtt-1"
        mqtt: {}
        source:
          transport: "tcp"
          address: "127.0.0.1:1883"
        destination:
          transport: "tcp"
          address: "127.0.0.1:1884"
"#;
    let config = Config::from_yaml_str(yaml).expect("parse yaml with mqtt option");
    let stream = &config.instances[0].streams[0];
    let mqtt_cfg = stream
        .mqtt
        .as_ref()
        .expect("option mqtt must deserialize into Some(MqttConfig)");

    // Verify default validation settings
    assert!(mqtt_cfg.enabled, "default enabled must be true");
    assert!(
        mqtt_cfg.validate_flags,
        "default validate_flags must be true"
    );
    assert!(
        mqtt_cfg.is_validation_enabled(),
        "validation must be enabled by default"
    );
    assert_eq!(
        mqtt_cfg.max_packet_size, 65_536,
        "default max packet size must be 65,536"
    );
    assert!(
        !mqtt_cfg.passthrough_on_error,
        "default passthrough_on_error must be false"
    );
    assert_eq!(mqtt_cfg.framing, None, "default framing must be None");

    // Also verify deserialization with empty scalar (mqtt:)
    let yaml_empty_scalar = r#"
version: "1"
instances:
  - id: "inst-mqtt-2"
    streams:
      - id: "stream-mqtt-2"
        mqtt:
        source:
          transport: "tcp"
          address: "127.0.0.1:1883"
        destination:
          transport: "tcp"
          address: "127.0.0.1:1884"
"#;
    let config2 =
        Config::from_yaml_str(yaml_empty_scalar).expect("parse yaml with empty mqtt scalar");
    let stream2 = &config2.instances[0].streams[0];
    let mqtt_cfg2 = stream2
        .mqtt
        .as_ref()
        .expect("option mqtt with empty scalar must deserialize into Some(MqttConfig)");
    assert_eq!(mqtt_cfg2, &MqttConfig::default());
    assert!(mqtt_cfg2.enabled);
    assert!(mqtt_cfg2.validate_flags);

    // Verify configuration validates cleanly
    assert!(
        config.validate().is_empty(),
        "config with default mqtt settings must validate without errors"
    );
}

#[test]
fn test_criterion2_source_framing_with_option_mqtt_framing_mqtt() {
    // Acceptance criterion:
    // In crates/rer/src/config.rs, calling source_framing on a StreamConfig configured
    // with option mqtt specifying framing mqtt returns FramingMode::Mqtt.
    let yaml = r#"
version: "1"
instances:
  - id: "inst-mqtt-framing"
    streams:
      - id: "stream-mqtt-framing"
        mqtt:
          framing: mqtt
        source:
          transport: "tcp"
          address: "127.0.0.1:1883"
        destination:
          transport: "tcp"
          address: "127.0.0.1:1884"
"#;
    let config = Config::from_yaml_str(yaml).expect("parse yaml with mqtt framing");
    let stream = &config.instances[0].streams[0];

    // Assert that source_framing returns FramingMode::Mqtt
    assert_eq!(
        stream.source_framing(),
        FramingMode::Mqtt,
        "stream with mqtt framing must return FramingMode::Mqtt from source_framing()"
    );

    // Also assert destination_framing returns FramingMode::Mqtt
    let dest = stream.destination.as_ref().unwrap();
    assert_eq!(
        stream.destination_framing(dest),
        FramingMode::Mqtt,
        "stream with mqtt framing must return FramingMode::Mqtt from destination_framing()"
    );
}

#[test]
fn test_criterion3_diagnostic_event_mqtt_metadata_serialization() {
    // Acceptance criterion:
    // In crates/rer/src/diagnostics.rs, serializing a DiagnosticEvent populated with
    // MQTT packet type 3, packet type name PUBLISH, QoS 1, and packet identifier 100
    // emits a JSON object containing the structured MQTT metadata fields.
    let event = DiagnosticEvent::new(
        1_000_000,
        2_000_000,
        "mqtt-diagnostic-stream",
        DiagnosticStage::MqttInspection,
        TransportType::Tcp,
        256,
    )
    .with_mqtt_packet_type(3, "PUBLISH")
    .with_mqtt_qos(1)
    .with_mqtt_packet_identifier(100);

    let json_str = serde_json::to_string(&event).expect("serialize DiagnosticEvent to JSON");
    let val: serde_json::Value =
        serde_json::from_str(&json_str).expect("parse serialized event as JSON Value");
    let obj = val
        .as_object()
        .expect("serialized event must be a JSON object");

    // Root-level fields
    assert_eq!(
        obj.get("mqtt_packet_type").and_then(|v| v.as_u64()),
        Some(3),
        "JSON must contain mqtt_packet_type = 3"
    );
    assert_eq!(
        obj.get("mqtt_type_name").and_then(|v| v.as_str()),
        Some("PUBLISH"),
        "JSON must contain mqtt_type_name = PUBLISH"
    );
    assert_eq!(
        obj.get("mqtt_qos").and_then(|v| v.as_u64()),
        Some(1),
        "JSON must contain mqtt_qos = 1"
    );
    assert_eq!(
        obj.get("mqtt_packet_id").and_then(|v| v.as_u64()),
        Some(100),
        "JSON must contain mqtt_packet_id = 100"
    );

    // Structured metadata object
    let meta = obj
        .get("mqtt_metadata")
        .and_then(|v| v.as_object())
        .expect("JSON must contain structured mqtt_metadata object");
    assert_eq!(
        meta.get("packet_type").and_then(|v| v.as_u64()),
        Some(3),
        "structured metadata must contain packet_type = 3"
    );
    assert_eq!(
        meta.get("packet_type_name").and_then(|v| v.as_str()),
        Some("PUBLISH"),
        "structured metadata must contain packet_type_name = PUBLISH"
    );
    assert_eq!(
        meta.get("qos").and_then(|v| v.as_u64()),
        Some(1),
        "structured metadata must contain qos = 1"
    );
    assert_eq!(
        meta.get("packet_identifier").and_then(|v| v.as_u64()),
        Some(100),
        "structured metadata must contain packet_identifier = 100"
    );

    // Roundtrip deserialization
    let deserialized: DiagnosticEvent =
        serde_json::from_str(&json_str).expect("roundtrip deserialization of DiagnosticEvent");
    assert_eq!(deserialized.mqtt_packet_type, Some(3));
    assert_eq!(deserialized.mqtt_type_name.as_deref(), Some("PUBLISH"));
    assert_eq!(deserialized.mqtt_qos, Some(1));
    assert_eq!(deserialized.mqtt_packet_id, Some(100));
}

#[test]
fn test_criterion4_recording_local_transmission_sets_stage_send_succeeded() {
    // Acceptance criterion:
    // In crates/rer/src/diagnostics.rs, recording local transmission of an inspected MQTT
    // packet sets stage to DiagnosticStage::SendSucceeded without asserting downstream broker delivery.
    let event = DiagnosticEvent::mqtt_inspection(3, "PUBLISH")
        .with_mqtt_qos(1)
        .with_mqtt_packet_identifier(100);
    assert_eq!(event.stage, DiagnosticStage::MqttInspection);

    // 1. Record local transmission via DiagnosticEvent method
    let transmitted = event.clone().record_local_transmission();
    assert_eq!(
        transmitted.stage,
        DiagnosticStage::SendSucceeded,
        "recording local transmission must set stage to SendSucceeded"
    );

    // In accordance with SPEC §8 truthfulness: verify no downstream broker receipt is claimed
    assert_ne!(transmitted.stage.to_string(), "broker_receipt");
    assert_ne!(transmitted.stage.to_string(), "broker_acknowledged");
    assert_ne!(transmitted.stage.to_string(), "delivered");
    assert_eq!(transmitted.stage.to_string(), "send_succeeded");

    // 2. Record local transmission via top-level helper
    let transmitted_helper = record_mqtt_local_transmission(event.clone());
    assert_eq!(
        transmitted_helper.stage,
        DiagnosticStage::SendSucceeded,
        "record_mqtt_local_transmission must set stage to SendSucceeded"
    );

    // 3. Record local transmission via MqttInspection method
    let insp = MqttInspection::new(3, "PUBLISH")
        .with_qos(1)
        .with_packet_identifier(100)
        .record_local_transmission();
    assert_eq!(insp.stage, DiagnosticStage::SendSucceeded);
    let event_from_insp: DiagnosticEvent = insp.into();
    assert_eq!(event_from_insp.stage, DiagnosticStage::SendSucceeded);

    // 4. Record local transmission via DiagnosticBuffer
    let buffer = DiagnosticBuffer::new(10);
    assert!(buffer.record_mqtt_transmission(event));
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.events.len(), 1);
    assert_eq!(snapshot.events[0].stage, DiagnosticStage::SendSucceeded);
}

#[test]
fn test_criterion5_omitting_mqtt_defaults_to_none_and_preserves_values() {
    // Acceptance criterion:
    // In crates/rer/src/config.rs, deserializing a stream configuration YAML omitting
    // option mqtt defaults field mqtt to None and preserves existing stream configuration values.
    let yaml = r#"
version: "1"
instances:
  - id: "inst-no-mqtt"
    streams:
      - id: "stream-tcp-forward"
        description: "Standard TCP forwarding stream without MQTT"
        framing: "length_prefix"
        source:
          transport: "tcp"
          address: "127.0.0.1:9000"
        destination:
          transport: "tcp"
          address: "127.0.0.1:9001"
"#;
    let config = Config::from_yaml_str(yaml).expect("parse yaml omitting option mqtt");
    let stream = &config.instances[0].streams[0];

    // Field mqtt must default to None
    assert_eq!(
        stream.mqtt, None,
        "omitting option mqtt must default stream.mqtt to None"
    );

    // Preserves existing stream configuration values
    assert_eq!(stream.id, "stream-tcp-forward");
    assert_eq!(
        stream.description.as_deref(),
        Some("Standard TCP forwarding stream without MQTT")
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
        "configuration without option mqtt must validate cleanly"
    );
}
