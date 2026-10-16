//! Interface-level packet capture replay engine (SPEC §12, §17).
//!
//! Provides controlled, timed, and filtered packet replay with:
//! - Original timing, configurable speed scaling, or maximum rate.
//! - Stream, endpoint, and time-range filters.
//! - Safety checks: explicit destination required, non-test destinations refused by default.
//! - Machine-readable JSON reporting of selected, attempted, injected, and failed packet counts.

use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::capture::{parse_capture_file, CapturedPacket};
use crate::framing::encode_frame;

fn default_transport() -> String {
    "udp".to_string()
}

fn default_speed() -> f64 {
    1.0
}

/// Configuration options for a capture replay session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Explicit target destination endpoint (e.g. "127.0.0.1:5000").
    pub destination: String,
    /// Destination transport protocol ("udp" or "tcp", default: "udp").
    #[serde(default = "default_transport")]
    pub transport: String,
    /// Speed multiplier (1.0 = original timing, >1.0 = faster, <1.0 = slower, 0 = max rate).
    #[serde(default = "default_speed")]
    pub speed: f64,
    /// Whether to replay at maximum feasible rate without timing delays.
    #[serde(default)]
    pub max_rate: bool,
    /// Maximum rate limit in packets per second (optional throttle).
    #[serde(default)]
    pub pps: Option<f64>,
    /// Filter by stream identifier or 5-tuple.
    #[serde(default)]
    pub stream_filter: Option<String>,
    /// Filter by source endpoint or IP.
    #[serde(default)]
    pub src_filter: Option<String>,
    /// Filter by destination endpoint or IP.
    #[serde(default)]
    pub dst_filter: Option<String>,
    /// Filter by endpoint (matches source or destination).
    #[serde(default)]
    pub endpoint_filter: Option<String>,
    /// Replay packets starting at or after relative time in seconds.
    #[serde(default)]
    pub start_time: Option<f64>,
    /// Replay packets up to relative time in seconds.
    #[serde(default)]
    pub end_time: Option<f64>,
    /// Maximum duration of replay session in seconds.
    #[serde(default)]
    pub duration: Option<f64>,
    /// Maximum number of packets to inject.
    #[serde(default)]
    pub max_packets: Option<u64>,
    /// Safety override allowing replaying to non-test/production endpoints.
    #[serde(default)]
    pub allow_non_test_destinations: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            destination: String::new(),
            transport: default_transport(),
            speed: default_speed(),
            max_rate: false,
            pps: None,
            stream_filter: None,
            src_filter: None,
            dst_filter: None,
            endpoint_filter: None,
            start_time: None,
            end_time: None,
            duration: None,
            max_packets: None,
            allow_non_test_destinations: false,
        }
    }
}

/// JSON-serializable report of replay execution results (SPEC §12).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayReport {
    /// Number of packets selected by active filters.
    pub selected: u64,
    /// Number of packets whose injection was attempted.
    pub attempted: u64,
    /// Number of packets successfully injected.
    pub injected: u64,
    /// Number of packets that failed during injection.
    pub failed: u64,
    /// Total number of packets scanned in the capture file.
    #[serde(default)]
    pub total_packets: u64,
    /// Total payload bytes successfully injected.
    #[serde(default)]
    pub bytes_injected: u64,
    /// Duration of the replay session in milliseconds.
    #[serde(default)]
    pub duration_ms: u64,
    /// Detected link type name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_type: Option<String>,
    /// Explicit destination used for replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Timing mode utilized ("original", "scaled-<N>x", "max-rate").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing_mode: Option<String>,
    /// Whether all attempted packets were successfully injected without error.
    pub success: bool,
    /// Error messages encountered during replay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl ReplayReport {
    /// Serializes this report to a formatted JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Deserializes a report from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Evaluates whether an endpoint string points to an authorized test or loopback destination.
///
/// Refuses production and non-test destinations by default (SPEC §12, §17).
/// Authorized test endpoints include:
/// - Loopback addresses (`127.0.0.0/8`, `::1`, `localhost`)
/// - IETF documentation & test networks (RFC 5737): `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
/// - IPv6 documentation prefix (RFC 3849): `2001:db8::/32`
/// - Benchmarking prefix (RFC 2544): `198.18.0.0/15`
/// - Reserved test domain suffixes: `.test`, `.example`, `.invalid`, `.localhost`
/// - Unix domain socket paths
#[must_use]
pub fn is_test_endpoint(endpoint: &str) -> bool {
    let ep = endpoint.trim();
    if ep.is_empty() {
        return false;
    }

    // Unix domain sockets
    if ep.starts_with('/')
        || ep.starts_with("./")
        || ep.starts_with("../")
        || ep.ends_with(".sock")
        || ep.contains(".sock")
    {
        return true;
    }

    // Strip URI protocol scheme if provided
    let clean = ep
        .trim_start_matches("udp://")
        .trim_start_matches("tcp://")
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    // Extract host part
    let host_part = if clean.starts_with('[') {
        if let Some(close_idx) = clean.find(']') {
            &clean[1..close_idx]
        } else {
            clean
        }
    } else if let Some(colon_idx) = clean.rfind(':') {
        &clean[..colon_idx]
    } else {
        clean
    };

    let host = host_part.split('%').next().unwrap_or(host_part);

    // Check IP addresses
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() {
                    return true;
                }
                let octets = v4.octets();
                // 192.0.2.0/24 (TEST-NET-1)
                if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                    return true;
                }
                // 198.51.100.0/24 (TEST-NET-2)
                if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                    return true;
                }
                // 203.0.113.0/24 (TEST-NET-3)
                if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                    return true;
                }
                // 198.18.0.0/15 (Benchmarking)
                if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                    return true;
                }
                return false;
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return true;
                }
                let segments = v6.segments();
                // 2001:db8::/32 (Documentation prefix)
                if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                    return true;
                }
                return false;
            }
        }
    }

    // Check domain names
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" {
        return true;
    }
    if lower.ends_with(".localhost")
        || lower.ends_with(".test")
        || lower.ends_with(".example")
        || lower.ends_with(".invalid")
    {
        return true;
    }

    false
}

/// Matches a packet against configured stream, endpoint, and time-range filters.
#[must_use]
pub fn matches_filter(pkt: &CapturedPacket, first_ts: Duration, config: &ReplayConfig) -> bool {
    // 1. Stream filter
    if let Some(ref sf) = config.stream_filter {
        let key = pkt.stream_key();
        let idx_str = pkt.index.to_string();
        let src_port_str = pkt.src_port.map(|p| p.to_string());
        let dst_port_str = pkt.dst_port.map(|p| p.to_string());

        let matches_stream = key == *sf
            || key.contains(sf)
            || idx_str == *sf
            || src_port_str.as_deref() == Some(sf.as_str())
            || dst_port_str.as_deref() == Some(sf.as_str());

        if !matches_stream {
            return false;
        }
    }

    // 2. Source filter
    if let Some(ref src) = config.src_filter {
        let mut matched = false;
        if let Some(ip) = pkt.src_ip {
            if ip.to_string() == *src {
                matched = true;
            }
            if let Some(port) = pkt.src_port {
                if format!("{ip}:{port}") == *src || port.to_string() == *src {
                    matched = true;
                }
            }
        }
        if !matched {
            return false;
        }
    }

    // 3. Destination filter
    if let Some(ref dst) = config.dst_filter {
        let mut matched = false;
        if let Some(ip) = pkt.dst_ip {
            if ip.to_string() == *dst {
                matched = true;
            }
            if let Some(port) = pkt.dst_port {
                if format!("{ip}:{port}") == *dst || port.to_string() == *dst {
                    matched = true;
                }
            }
        }
        if !matched {
            return false;
        }
    }

    // 4. Generic endpoint filter (matches either src or dst)
    if let Some(ref ep) = config.endpoint_filter {
        let mut matched = false;
        if let Some(ip) = pkt.src_ip {
            if ip.to_string() == *ep {
                matched = true;
            }
            if let Some(port) = pkt.src_port {
                if format!("{ip}:{port}") == *ep || port.to_string() == *ep {
                    matched = true;
                }
            }
        }
        if let Some(ip) = pkt.dst_ip {
            if ip.to_string() == *ep {
                matched = true;
            }
            if let Some(port) = pkt.dst_port {
                if format!("{ip}:{port}") == *ep || port.to_string() == *ep {
                    matched = true;
                }
            }
        }
        if !matched {
            return false;
        }
    }

    // 5. Time-range filters
    let rel_secs = pkt.timestamp.saturating_sub(first_ts).as_secs_f64();
    if let Some(st) = config.start_time {
        if rel_secs < st {
            return false;
        }
    }
    if let Some(et) = config.end_time {
        if rel_secs > et {
            return false;
        }
    }

    true
}

/// Executes capture replay against a target destination with explicit safety verification.
pub fn execute_replay_session<P: AsRef<Path>>(
    capture_path: P,
    config: &ReplayConfig,
) -> Result<ReplayReport, String> {
    // 1. Safety verification
    let dest = config.destination.trim();
    if dest.is_empty() {
        return Err(
            "replay requires an explicit destination endpoint (e.g. --destination 127.0.0.1:5000)"
                .to_string(),
        );
    }

    if !config.allow_non_test_destinations && !is_test_endpoint(dest) {
        return Err(format!(
            "refusing to replay capture to non-test endpoint '{dest}'. Replay targets are restricted to loopback and test networks by default for operational safety (SPEC §12, §17). Use --allow-non-test-destinations to override."
        ));
    }

    // 2. Load capture file
    let packets = parse_capture_file(capture_path.as_ref())
        .map_err(|e| format!("failed to read capture file: {e}"))?;

    let total_packets = packets.len() as u64;
    let detected_link = packets
        .first()
        .map(|p| p.link_type.name().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    if packets.is_empty() {
        return Ok(ReplayReport {
            selected: 0,
            attempted: 0,
            injected: 0,
            failed: 0,
            total_packets: 0,
            bytes_injected: 0,
            duration_ms: 0,
            link_type: Some(detected_link),
            destination: Some(dest.to_string()),
            timing_mode: Some("none".to_string()),
            success: true,
            errors: Vec::new(),
        });
    }

    // 3. Filter packets
    let first_ts = packets[0].timestamp;
    let mut selected_packets = Vec::new();
    for pkt in &packets {
        if matches_filter(pkt, first_ts, config) {
            selected_packets.push(pkt);
            if let Some(max_pkts) = config.max_packets {
                if selected_packets.len() as u64 >= max_pkts {
                    break;
                }
            }
        }
    }

    let selected_count = selected_packets.len() as u64;
    if selected_packets.is_empty() {
        return Ok(ReplayReport {
            selected: 0,
            attempted: 0,
            injected: 0,
            failed: 0,
            total_packets,
            bytes_injected: 0,
            duration_ms: 0,
            link_type: Some(detected_link),
            destination: Some(dest.to_string()),
            timing_mode: Some("none".to_string()),
            success: true,
            errors: Vec::new(),
        });
    }

    // 4. Resolve destination
    let addrs = dest
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve destination '{dest}': {e}"))?
        .collect::<Vec<SocketAddr>>();

    if addrs.is_empty() {
        return Err(format!(
            "no socket addresses resolved for destination '{dest}'"
        ));
    }
    let target_addr = addrs[0];

    // Determine timing mode string
    let timing_mode = if config.max_rate || config.speed <= 0.0 {
        "max-rate".to_string()
    } else if (config.speed - 1.0).abs() < 1e-6 {
        "original".to_string()
    } else {
        format!("scaled-{}x", config.speed)
    };

    let pps_interval = config
        .pps
        .filter(|&r| r > 0.0)
        .map(|r| Duration::from_secs_f64(1.0 / r));

    let max_duration = config.duration.map(Duration::from_secs_f64);

    let start_instant = Instant::now();
    let mut attempted = 0u64;
    let mut injected = 0u64;
    let mut failed = 0u64;
    let mut bytes_injected = 0u64;
    let mut errors = Vec::new();

    let first_selected_ts = selected_packets[0].timestamp;
    let mut last_packet_time = Instant::now();

    // 5. Ingestion and Replay Loop
    let transport = config.transport.trim().to_ascii_lowercase();
    if transport == "tcp" {
        let mut stream = TcpStream::connect_timeout(&target_addr, Duration::from_secs(5))
            .map_err(|e| format!("failed to connect to TCP destination '{dest}': {e}"))?;
        let _ = stream.set_nodelay(true);
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

        for pkt in selected_packets {
            if let Some(dur) = max_duration {
                if start_instant.elapsed() >= dur {
                    break;
                }
            }

            // Timing pacing
            if !config.max_rate && config.speed > 0.0 {
                let delta = pkt.timestamp.saturating_sub(first_selected_ts);
                let target_delay = Duration::from_secs_f64(delta.as_secs_f64() / config.speed);
                let target_time = start_instant + target_delay;
                let now = Instant::now();
                if target_time > now {
                    thread::sleep(target_time - now);
                }
            }

            // PPS throttling
            if let Some(interval) = pps_interval {
                let next_allowed = last_packet_time + interval;
                let now = Instant::now();
                if next_allowed > now {
                    thread::sleep(next_allowed - now);
                }
            }
            last_packet_time = Instant::now();

            attempted += 1;
            let frame = encode_frame(&pkt.payload);
            match stream.write_all(&frame) {
                Ok(()) => {
                    injected += 1;
                    bytes_injected += pkt.payload.len() as u64;
                }
                Err(e) => {
                    failed += 1;
                    if errors.len() < 10 {
                        errors.push(format!("TCP send error on packet {}: {e}", pkt.index));
                    }
                }
            }
        }
    } else {
        // Default: UDP
        let bind_addr = if target_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr)
            .or_else(|_| UdpSocket::bind("127.0.0.1:0"))
            .map_err(|e| format!("failed to bind UDP socket for replay: {e}"))?;

        for pkt in selected_packets {
            if let Some(dur) = max_duration {
                if start_instant.elapsed() >= dur {
                    break;
                }
            }

            // Timing pacing
            if !config.max_rate && config.speed > 0.0 {
                let delta = pkt.timestamp.saturating_sub(first_selected_ts);
                let target_delay = Duration::from_secs_f64(delta.as_secs_f64() / config.speed);
                let target_time = start_instant + target_delay;
                let now = Instant::now();
                if target_time > now {
                    thread::sleep(target_time - now);
                }
            }

            // PPS throttling
            if let Some(interval) = pps_interval {
                let next_allowed = last_packet_time + interval;
                let now = Instant::now();
                if next_allowed > now {
                    thread::sleep(next_allowed - now);
                }
            }
            last_packet_time = Instant::now();

            attempted += 1;
            match socket.send_to(&pkt.payload, target_addr) {
                Ok(n) => {
                    injected += 1;
                    bytes_injected += n as u64;
                }
                Err(e) => {
                    failed += 1;
                    if errors.len() < 10 {
                        errors.push(format!("UDP send error on packet {}: {e}", pkt.index));
                    }
                }
            }
        }
    }

    let elapsed = start_instant.elapsed();
    let success = failed == 0 && attempted == selected_count;

    Ok(ReplayReport {
        selected: selected_count,
        attempted,
        injected,
        failed,
        total_packets,
        bytes_injected,
        duration_ms: elapsed.as_millis() as u64,
        link_type: Some(detected_link),
        destination: Some(dest.to_string()),
        timing_mode: Some(timing_mode),
        success,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_test_endpoint_accepted() {
        assert!(is_test_endpoint("127.0.0.1:5000"));
        assert!(is_test_endpoint("127.0.0.2:8080"));
        assert!(is_test_endpoint("[::1]:9000"));
        assert!(is_test_endpoint("localhost:5000"));
        assert!(is_test_endpoint("test.localhost:5000"));
        assert!(is_test_endpoint("host.test:5000"));
        assert!(is_test_endpoint("host.example:5000"));
        assert!(is_test_endpoint("host.invalid:5000"));
        assert!(is_test_endpoint("192.0.2.1:5000")); // TEST-NET-1
        assert!(is_test_endpoint("198.51.100.2:5000")); // TEST-NET-2
        assert!(is_test_endpoint("203.0.113.10:5000")); // TEST-NET-3
        assert!(is_test_endpoint("198.18.0.5:5000")); // Benchmarking
        assert!(is_test_endpoint("198.19.1.1:5000")); // Benchmarking
        assert!(is_test_endpoint("[2001:db8::1]:5000")); // Documentation IPv6
        assert!(is_test_endpoint("/var/run/test.sock"));
        assert!(is_test_endpoint("./rer.sock"));
    }

    #[test]
    fn test_is_test_endpoint_refused() {
        assert!(!is_test_endpoint("8.8.8.8:53"));
        assert!(!is_test_endpoint("1.1.1.1:53"));
        assert!(!is_test_endpoint("10.0.0.1:5000"));
        assert!(!is_test_endpoint("172.16.0.1:5000"));
        assert!(!is_test_endpoint("192.168.1.1:5000"));
        assert!(!is_test_endpoint("mission.space:5000"));
        assert!(!is_test_endpoint("relay.prod.internal:5000"));
        assert!(!is_test_endpoint(""));
    }

    #[test]
    fn test_replay_report_json_roundtrip() {
        let report = ReplayReport {
            selected: 10,
            attempted: 10,
            injected: 10,
            failed: 0,
            total_packets: 15,
            bytes_injected: 2560,
            duration_ms: 12,
            link_type: Some("Ethernet".to_string()),
            destination: Some("127.0.0.1:5000".to_string()),
            timing_mode: Some("original".to_string()),
            success: true,
            errors: Vec::new(),
        };

        let json = report.to_json();
        assert!(json.contains("\"selected\": 10"));
        assert!(json.contains("\"attempted\": 10"));
        assert!(json.contains("\"injected\": 10"));
        assert!(json.contains("\"failed\": 0"));

        let deserialized = ReplayReport::from_json(&json).expect("deserialize valid report");
        assert_eq!(report, deserialized);
    }
}
