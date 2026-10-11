//! RER — RER Engineering Relay
//!
//! An open-source network relay, telemetry/command routing, and distributed
//! network diagnostics tool.

pub mod cli;
pub mod config;
pub mod relay;
pub mod secret;
pub mod signals;

pub use config::{
    Config, DropPolicy, InstanceConfig, StreamConfig, ValidationError, ValidationReport,
};
pub use relay::{BoundedQueue, Datagram, Relay, StreamStats, StreamStatsSnapshot};
pub use secret::SecretString;

/// Returns the current version of RER.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert!(!version().is_empty());
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }
}
