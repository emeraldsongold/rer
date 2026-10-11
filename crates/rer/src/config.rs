use std::collections::HashSet;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::secret::SecretString;

/// Top-level configuration for RER.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Configuration format version (e.g. "1" or "1.0").
    pub version: String,

    /// Single instance configuration (alternative to `instances`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<InstanceConfig>,

    /// List of RER relay instances.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instances: Vec<InstanceConfig>,
}

/// Configuration for an individual RER relay instance.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstanceConfig {
    /// Unique identity of the instance.
    pub id: String,

    /// Human-readable name or label for the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Diagnostic and operational profile ("production", "debug", or "test").
    #[serde(default = "default_operational_mode")]
    pub mode: OperationalMode,

    /// Management and diagnostics interface configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<ManagementConfig>,

    /// Forwarding streams configured on this instance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<StreamConfig>,

    /// Logical interfaces pairing directional streams.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logical_interfaces: Vec<LogicalInterfaceConfig>,

    /// Instance-level bounded buffer and queue limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer: Option<BufferConfig>,
}

/// Operational diagnostic modes (SPEC §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationalMode {
    Production,
    Debug,
    Test,
}

fn default_operational_mode() -> OperationalMode {
    OperationalMode::Production
}

/// Management plane configuration (SPEC §9).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    /// Whether the management plane is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Bind address or socket path (e.g. "127.0.0.1:9090" or "/run/rer/mgmt.sock").
    pub endpoint: String,

    /// Optional authentication token for remote management.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<SecretString>,

    /// Optional TLS configuration for remote management.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

fn default_true() -> bool {
    true
}

/// TLS configuration for management traffic encryption.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to TLS certificate file.
    pub cert_file: String,

    /// Path to TLS private key file.
    pub key_file: String,
}

/// Configuration for a forwarding stream (SPEC §5).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    /// Unique identity of the stream.
    pub id: String,

    /// Optional description of the stream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Stream forwarding source.
    pub source: EndpointConfig,

    /// Stream destination endpoint (conflicts with `destinations`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<EndpointConfig>,

    /// Multiple destination endpoints for fan-out (conflicts with `destination`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destinations: Option<Vec<EndpointConfig>>,

    /// Optional stream-level buffer and queue limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer: Option<BufferConfig>,
}

/// Network endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EndpointConfig {
    /// Transport protocol ("udp" or "tcp").
    pub transport: TransportType,

    /// Network endpoint address in "host:port" format (e.g. "127.0.0.1:5000").
    pub address: String,

    /// Connection mode ("listen" or "connect").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ConnectionMode>,
}

/// Supported transport protocols (SPEC §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    Udp,
    Tcp,
}

/// Connection modes for endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionMode {
    Listen,
    Connect,
}

/// Logical interface pairing directional streams (SPEC §6).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LogicalInterfaceConfig {
    /// Unique identity of the logical interface.
    pub id: String,

    /// Human-readable label or description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Transmit / uplink stream identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_stream: Option<String>,

    /// Receive / downlink stream identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rx_stream: Option<String>,
}

/// Buffer and queue bounding configuration (SPEC §17).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BufferConfig {
    /// Maximum queue size in packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queue_size: Option<usize>,

    /// Maximum packet size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packet_size: Option<usize>,

    /// Drop policy under queue exhaustion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drop_policy: Option<DropPolicy>,
}

/// Drop policies under queue exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DropPolicy {
    DropOldest,
    DropNewest,
    Reject,
}

/// A validation error reporting the exact path and reason for the failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationError {
    /// Path to the invalid field (e.g. "instances[0].streams[1].source.address").
    pub path: String,
    /// Explanation of why the field or configuration is invalid.
    pub reason: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

/// Machine-readable validation report for automation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationReport {
    /// True if configuration is valid; false if any errors exist.
    pub valid: bool,
    /// List of validation errors.
    pub errors: Vec<ValidationError>,
    /// Effective configuration with defaults resolved and secrets redacted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_config: Option<Config>,
}

impl Config {
    /// Parses and deserializes configuration from a YAML string.
    ///
    /// Unknown fields are rejected and reported with their path and reason.
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, Vec<ValidationError>> {
        let deserializer = serde_yaml::Deserializer::from_str(yaml_str);
        match serde_path_to_error::deserialize::<_, Self>(deserializer) {
            Ok(config) => Ok(config),
            Err(err) => {
                let path = err.path().to_string();
                let path = if path.is_empty() || path == "." {
                    "file".to_string()
                } else {
                    path
                };
                let reason = err.inner().to_string();
                Err(vec![ValidationError { path, reason }])
            }
        }
    }

    /// Resolves and returns all configured instances (supporting both `instances` and `instance`).
    pub fn all_instances(&self) -> Vec<InstanceConfig> {
        if let Some(inst) = &self.instance {
            vec![inst.clone()]
        } else {
            self.instances.clone()
        }
    }

    /// Performs semantic validation across the configuration.
    ///
    /// Validates duplicate instance/stream IDs, conflicting settings,
    /// endpoint addresses, and referenced stream identities.
    pub fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();

        if self.version.trim().is_empty() {
            errors.push(ValidationError {
                path: "version".to_string(),
                reason: "version must not be empty".to_string(),
            });
        }

        // Validate instance vs instances
        if self.instance.is_some() && !self.instances.is_empty() {
            errors.push(ValidationError {
                path: "instances".to_string(),
                reason: "conflicting settings: cannot specify both 'instance' and 'instances'"
                    .to_string(),
            });
        } else if self.instance.is_none() && self.instances.is_empty() {
            errors.push(ValidationError {
                path: "instances".to_string(),
                reason: "at least one instance must be configured".to_string(),
            });
            return errors;
        }

        let instances_to_check = if let Some(inst) = &self.instance {
            vec![(None, inst)]
        } else {
            self.instances
                .iter()
                .enumerate()
                .map(|(i, inst)| (Some(i), inst))
                .collect()
        };

        let mut seen_instance_ids = HashSet::new();
        let mut global_stream_ids = HashSet::new();

        for (idx_opt, inst) in instances_to_check {
            let inst_prefix = match idx_opt {
                Some(i) => format!("instances[{}]", i),
                None => "instance".to_string(),
            };

            // Check instance ID
            if inst.id.trim().is_empty() {
                errors.push(ValidationError {
                    path: format!("{}.id", inst_prefix),
                    reason: "instance id must not be empty".to_string(),
                });
            } else if !seen_instance_ids.insert(inst.id.clone()) {
                errors.push(ValidationError {
                    path: format!("{}.id", inst_prefix),
                    reason: format!("duplicate instance identity '{}'", inst.id),
                });
            }

            // Check management
            if let Some(mgmt) = &inst.management {
                let mgmt_prefix = format!("{}.management", inst_prefix);
                if mgmt.enabled && mgmt.endpoint.trim().is_empty() {
                    errors.push(ValidationError {
                        path: format!("{}.endpoint", mgmt_prefix),
                        reason: "management endpoint must not be empty when enabled".to_string(),
                    });
                }
                if let Some(tls) = &mgmt.tls {
                    if tls.cert_file.trim().is_empty() {
                        errors.push(ValidationError {
                            path: format!("{}.tls.cert_file", mgmt_prefix),
                            reason: "cert_file must not be empty".to_string(),
                        });
                    }
                    if tls.key_file.trim().is_empty() {
                        errors.push(ValidationError {
                            path: format!("{}.tls.key_file", mgmt_prefix),
                            reason: "key_file must not be empty".to_string(),
                        });
                    }
                }
            }

            // Check instance buffer
            if let Some(buf) = &inst.buffer {
                validate_buffer(buf, &format!("{}.buffer", inst_prefix), &mut errors);
            }

            // Check streams
            let mut inst_stream_ids = HashSet::new();
            for (s_idx, stream) in inst.streams.iter().enumerate() {
                let stream_prefix = format!("{}.streams[{}]", inst_prefix, s_idx);

                // Stream ID check
                if stream.id.trim().is_empty() {
                    errors.push(ValidationError {
                        path: format!("{}.id", stream_prefix),
                        reason: "stream id must not be empty".to_string(),
                    });
                } else {
                    if !inst_stream_ids.insert(stream.id.clone()) {
                        errors.push(ValidationError {
                            path: format!("{}.id", stream_prefix),
                            reason: format!("duplicate stream identity '{}'", stream.id),
                        });
                    }
                    if !global_stream_ids.insert(stream.id.clone()) {
                        // Check if duplicate across instances
                        if inst_stream_ids.contains(&stream.id) && inst_stream_ids.len() == 1 {
                            // Only report once per instance
                        }
                    }
                }

                // Stream destination conflicts
                if stream.destination.is_some() && stream.destinations.is_some() {
                    errors.push(ValidationError {
                        path: stream_prefix.clone(),
                        reason: "conflicting settings: cannot specify both 'destination' and 'destinations'".to_string(),
                    });
                } else if stream.destination.is_none() && stream.destinations.is_none() {
                    errors.push(ValidationError {
                        path: stream_prefix.clone(),
                        reason: "missing destination: either 'destination' or 'destinations' must be specified".to_string(),
                    });
                } else if let Some(dests) = &stream.destinations {
                    if dests.is_empty() {
                        errors.push(ValidationError {
                            path: format!("{}.destinations", stream_prefix),
                            reason: "'destinations' list cannot be empty".to_string(),
                        });
                    }
                }

                // Validate source endpoint
                validate_endpoint(
                    &stream.source,
                    &format!("{}.source", stream_prefix),
                    true,
                    &mut errors,
                );

                // Validate destination endpoint(s)
                if let Some(dest) = &stream.destination {
                    validate_endpoint(
                        dest,
                        &format!("{}.destination", stream_prefix),
                        false,
                        &mut errors,
                    );
                }
                if let Some(dests) = &stream.destinations {
                    for (d_idx, dest) in dests.iter().enumerate() {
                        validate_endpoint(
                            dest,
                            &format!("{}.destinations[{}]", stream_prefix, d_idx),
                            false,
                            &mut errors,
                        );
                    }
                }

                // Validate stream buffer
                if let Some(buf) = &stream.buffer {
                    validate_buffer(buf, &format!("{}.buffer", stream_prefix), &mut errors);
                }
            }

            // Check logical interfaces
            let mut iface_ids = HashSet::new();
            for (l_idx, iface) in inst.logical_interfaces.iter().enumerate() {
                let iface_prefix = format!("{}.logical_interfaces[{}]", inst_prefix, l_idx);

                if iface.id.trim().is_empty() {
                    errors.push(ValidationError {
                        path: format!("{}.id", iface_prefix),
                        reason: "logical interface id must not be empty".to_string(),
                    });
                } else if !iface_ids.insert(iface.id.clone()) {
                    errors.push(ValidationError {
                        path: format!("{}.id", iface_prefix),
                        reason: format!("duplicate logical interface identity '{}'", iface.id),
                    });
                }

                if iface.tx_stream.is_none() && iface.rx_stream.is_none() {
                    errors.push(ValidationError {
                        path: iface_prefix.clone(),
                        reason: "logical interface must specify at least one directional stream ('tx_stream' or 'rx_stream')".to_string(),
                    });
                }

                if let (Some(tx), Some(rx)) = (&iface.tx_stream, &iface.rx_stream) {
                    if tx == rx {
                        errors.push(ValidationError {
                            path: iface_prefix.clone(),
                            reason: "conflicting settings: 'tx_stream' and 'rx_stream' cannot reference the same stream ID".to_string(),
                        });
                    }
                }

                if let Some(tx) = &iface.tx_stream {
                    if !inst_stream_ids.contains(tx) {
                        errors.push(ValidationError {
                            path: format!("{}.tx_stream", iface_prefix),
                            reason: format!("stream ID '{}' referenced by logical interface not found in instance streams", tx),
                        });
                    }
                }

                if let Some(rx) = &iface.rx_stream {
                    if !inst_stream_ids.contains(rx) {
                        errors.push(ValidationError {
                            path: format!("{}.rx_stream", iface_prefix),
                            reason: format!("stream ID '{}' referenced by logical interface not found in instance streams", rx),
                        });
                    }
                }
            }
        }

        errors
    }

    /// Returns the effective configuration with all defaults resolved and secrets redacted.
    pub fn to_effective(&self) -> Self {
        let instances = self
            .all_instances()
            .into_iter()
            .map(|mut inst| {
                // Apply default mode
                // For endpoints, apply default mode if not present
                for stream in &mut inst.streams {
                    if stream.source.mode.is_none() {
                        stream.source.mode = Some(ConnectionMode::Listen);
                    }
                    if let Some(dest) = &mut stream.destination {
                        if dest.mode.is_none() {
                            dest.mode = Some(ConnectionMode::Connect);
                        }
                    }
                    if let Some(dests) = &mut stream.destinations {
                        for dest in dests.iter_mut() {
                            if dest.mode.is_none() {
                                dest.mode = Some(ConnectionMode::Connect);
                            }
                        }
                    }
                }
                inst
            })
            .collect();

        Self {
            version: self.version.clone(),
            instance: None,
            instances,
        }
    }

    /// Serializes effective configuration as YAML.
    pub fn to_effective_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(&self.to_effective())
    }

    /// Serializes effective configuration as JSON.
    pub fn to_effective_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self.to_effective())
    }
}

fn validate_buffer(buf: &BufferConfig, path: &str, errors: &mut Vec<ValidationError>) {
    if let Some(q) = buf.max_queue_size {
        if q == 0 {
            errors.push(ValidationError {
                path: format!("{}.max_queue_size", path),
                reason: "max_queue_size must be greater than 0".to_string(),
            });
        }
    }
    if let Some(p) = buf.max_packet_size {
        if p == 0 {
            errors.push(ValidationError {
                path: format!("{}.max_packet_size", path),
                reason: "max_packet_size must be greater than 0".to_string(),
            });
        }
    }
}

fn validate_endpoint(
    ep: &EndpointConfig,
    path: &str,
    is_source: bool,
    errors: &mut Vec<ValidationError>,
) {
    // Address validation
    let addr = ep.address.trim();
    if addr.is_empty() {
        errors.push(ValidationError {
            path: format!("{}.address", path),
            reason: "address must not be empty".to_string(),
        });
        return;
    }

    if let Some(last_colon) = addr.rfind(':') {
        let host = &addr[..last_colon];
        let port_str = &addr[last_colon + 1..];

        if host.is_empty() {
            errors.push(ValidationError {
                path: format!("{}.address", path),
                reason: "address host part must not be empty".to_string(),
            });
        }

        match port_str.parse::<u32>() {
            Ok(0) => {
                errors.push(ValidationError {
                    path: format!("{}.address", path),
                    reason: "port 0 is invalid; must be between 1 and 65535".to_string(),
                });
            }
            Ok(port) if port > 65535 => {
                errors.push(ValidationError {
                    path: format!("{}.address", path),
                    reason: format!("port {} is out of valid range 1..=65535", port),
                });
            }
            Ok(_) => {}
            Err(_) => {
                errors.push(ValidationError {
                    path: format!("{}.address", path),
                    reason: format!(
                        "invalid port '{}'; must be an integer between 1 and 65535",
                        port_str
                    ),
                });
            }
        }
    } else {
        errors.push(ValidationError {
            path: format!("{}.address", path),
            reason: "invalid address format: expected 'host:port' (e.g. '127.0.0.1:5000')"
                .to_string(),
        });
    }

    // Conflicting modes
    if is_source && ep.transport == TransportType::Udp && ep.mode == Some(ConnectionMode::Connect) {
        errors.push(ValidationError {
            path: format!("{}.mode", path),
            reason: "conflicting settings: UDP source cannot be in 'connect' mode".to_string(),
        });
    }
}

/// Generates the canonical JSON Schema for RER configuration.
pub fn generate_schema() -> schemars::schema::RootSchema {
    let mut schema = schemars::schema_for!(Config);
    if let Some(ref mut meta) = schema.schema.metadata {
        meta.title = Some("RER Configuration Schema".to_string());
        meta.description = Some("Configuration schema for RER (RER Engineering Relay)".to_string());
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_matches_generated() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let schema_path = repo_root.join("schema").join("rer-config.schema.json");
        let generated = serde_json::to_string_pretty(&generate_schema()).unwrap() + "\n";

        if !schema_path.exists() {
            std::fs::create_dir_all(schema_path.parent().unwrap()).unwrap();
            std::fs::write(&schema_path, &generated).unwrap();
        }

        let existing = std::fs::read_to_string(&schema_path).unwrap();
        assert_eq!(
            existing.trim(),
            generated.trim(),
            "schema/rer-config.schema.json is out of date with Config models."
        );
    }
}
