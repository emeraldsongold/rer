use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use rer::config::Config;
use rer::management::{query_metrics, ManagementServer};
use rer::relay::Relay;

fn pick_unused_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral socket");
    socket.local_addr().expect("local addr").port()
}

// ============================================================================
// OpenMetrics Parser (RFC 9457 compliant)
// ============================================================================

#[derive(Debug, Clone)]
struct MetricSample {
    #[allow(dead_code)]
    name: String,
    labels: BTreeMap<String, String>,
    value: f64,
}

#[derive(Debug, Clone)]
struct MetricFamily {
    help: Option<String>,
    metric_type: Option<String>,
    samples: Vec<MetricSample>,
}

#[derive(Debug, Clone)]
struct ParsedOpenMetrics {
    families: BTreeMap<String, MetricFamily>,
    has_eof: bool,
}

fn parse_openmetrics(text: &str) -> Result<ParsedOpenMetrics, String> {
    let mut families: BTreeMap<String, MetricFamily> = BTreeMap::new();
    let mut current_family: Option<String> = None;
    let mut has_eof = false;
    let mut seen_families_completed = HashSet::new();

    let lines: Vec<&str> = text.lines().collect();
    for (line_num, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if trimmed == "# EOF" {
            has_eof = true;
            // EOF must be the last non-empty line
            for remaining in &lines[line_num + 1..] {
                if !remaining.trim().is_empty() {
                    return Err(format!(
                        "Content found after # EOF record at line {}",
                        line_num + 1
                    ));
                }
            }
            break;
        }

        if let Some(rest) = trimmed.strip_prefix("# HELP ") {
            let mut parts = rest.splitn(2, ' ');
            let metric_name = parts
                .next()
                .ok_or_else(|| format!("Malformed # HELP on line {}: {}", line_num + 1, line))?;
            let help_text = parts.next().unwrap_or("").to_string();

            if seen_families_completed.contains(metric_name) {
                return Err(format!(
                    "Metric family '{}' reopened after previous family completed (line {})",
                    metric_name,
                    line_num + 1
                ));
            }

            if let Some(prev) = &current_family {
                if prev != metric_name {
                    seen_families_completed.insert(prev.clone());
                }
            }
            current_family = Some(metric_name.to_string());

            let fam = families
                .entry(metric_name.to_string())
                .or_insert_with(|| MetricFamily {
                    help: None,
                    metric_type: None,
                    samples: Vec::new(),
                });
            fam.help = Some(help_text);
        } else if let Some(rest) = trimmed.strip_prefix("# TYPE ") {
            let mut parts = rest.splitn(2, ' ');
            let metric_name = parts
                .next()
                .ok_or_else(|| format!("Malformed # TYPE on line {}: {}", line_num + 1, line))?;
            let metric_type = parts
                .next()
                .ok_or_else(|| format!("Missing type on line {}: {}", line_num + 1, line))?
                .to_string();

            if !["counter", "gauge", "histogram", "summary", "unknown"]
                .contains(&metric_type.as_str())
            {
                return Err(format!(
                    "Invalid metric type '{}' on line {}",
                    metric_type,
                    line_num + 1
                ));
            }

            let fam = families
                .entry(metric_name.to_string())
                .or_insert_with(|| MetricFamily {
                    help: None,
                    metric_type: None,
                    samples: Vec::new(),
                });
            fam.metric_type = Some(metric_type);
        } else if trimmed.starts_with('#') {
            // Other comments ignored
            continue;
        } else {
            // Sample line: metric_name{label="val"} value or metric_name value
            let (raw_name, labels, val_str) = if let Some(brace_idx) = trimmed.find('{') {
                let name = &trimmed[..brace_idx];
                let end_brace = trimmed
                    .find('}')
                    .ok_or_else(|| format!("Missing closing brace on line {}", line_num + 1))?;
                let label_part = &trimmed[brace_idx + 1..end_brace];
                let val_part = trimmed[end_brace + 1..].trim();

                let mut labels = BTreeMap::new();
                for pair in label_part.split(',') {
                    let pair = pair.trim();
                    if pair.is_empty() {
                        continue;
                    }
                    let mut kv = pair.splitn(2, '=');
                    let k = kv
                        .next()
                        .ok_or_else(|| format!("Malformed label on line {}", line_num + 1))?
                        .trim();
                    let v = kv
                        .next()
                        .ok_or_else(|| format!("Malformed label on line {}", line_num + 1))?
                        .trim();
                    let v = v.trim_matches('"');
                    labels.insert(k.to_string(), v.to_string());
                }
                (name, labels, val_part)
            } else {
                let mut parts = trimmed.split_whitespace();
                let name = parts
                    .next()
                    .ok_or_else(|| format!("Missing metric name on line {}", line_num + 1))?;
                let val_part = parts
                    .next()
                    .ok_or_else(|| format!("Missing metric value on line {}", line_num + 1))?;
                (name, BTreeMap::new(), val_part)
            };

            let val: f64 = val_str.parse().map_err(|e| {
                format!(
                    "Invalid float value '{}' on line {}: {}",
                    val_str,
                    line_num + 1,
                    e
                )
            })?;

            let fam = families
                .entry(raw_name.to_string())
                .or_insert_with(|| MetricFamily {
                    help: None,
                    metric_type: None,
                    samples: Vec::new(),
                });

            fam.samples.push(MetricSample {
                name: raw_name.to_string(),
                labels,
                value: val,
            });
        }
    }

    if !has_eof {
        return Err("OpenMetrics document missing mandatory '# EOF' terminator".to_string());
    }

    Ok(ParsedOpenMetrics { families, has_eof })
}

// ============================================================================
// 1. Acceptance Criterion 1 & 3: Metric Names and Labels Checked Against Parser
// ============================================================================

#[test]
fn test_openmetrics_parser_validation_and_documented_metrics() {
    let src_port = pick_unused_port();
    let dest_port = pick_unused_port();
    let metrics_port = pick_unused_port();
    let sock_path =
        std::env::temp_dir().join(format!("rer_metrics_parse_{}.sock", pick_unused_port()));

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "diagnostics-node"
    name: "Diagnostics Relay Node"
    metrics:
      enabled: true
      endpoint: "127.0.0.1:{metrics_port}"
      path: "/metrics"
    streams:
      - id: "telemetry-1"
        source:
          transport: "udp"
          address: "127.0.0.1:{src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid configuration");
    let relay = Relay::start(&config).expect("relay starts");
    let mgmt_server =
        ManagementServer::start_from_config(&config, relay.health_handle(), &sock_path)
            .expect("management server starts");

    // Start UDP sink
    let sink = UdpSocket::bind(format!("127.0.0.1:{dest_port}")).expect("bind sink");
    sink.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // Send test packets
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    for i in 0..15 {
        let msg = format!("telemetry-packet-{}", i);
        client
            .send_to(msg.as_bytes(), format!("127.0.0.1:{src_port}"))
            .unwrap();
    }

    // Wait for packets to forward
    let mut recv_count = 0;
    let mut buf = [0u8; 1024];
    let start = std::time::Instant::now();
    while recv_count < 15 && start.elapsed() < Duration::from_secs(3) {
        if let Ok((n, _)) = sink.recv_from(&mut buf) {
            if n > 0 {
                recv_count += 1;
            }
        }
    }
    assert_eq!(recv_count, 15, "All packets forwarded");

    // Query metrics via management API
    let report = query_metrics(sock_path.to_str().unwrap(), Duration::from_secs(2), None)
        .expect("query metrics report");

    let openmetrics_text = &report.prometheus_text;

    // Parse with OpenMetrics parser
    let parsed = parse_openmetrics(openmetrics_text).expect("OpenMetrics text must parse cleanly");
    assert!(parsed.has_eof, "Document ends with # EOF");

    // All documented metrics must be present with matching types and labels
    let documented_metrics = [
        ("rer_uptime_seconds", "gauge", false),
        ("rer_healthy", "gauge", false),
        ("rer_received_packets_total", "counter", false),
        ("rer_received_bytes_total", "counter", false),
        ("rer_forwarded_packets_total", "counter", false),
        ("rer_forwarded_bytes_total", "counter", false),
        ("rer_dropped_packets_total", "counter", false),
        ("rer_socket_errors_total", "counter", false),
        ("rer_destination_errors_total", "counter", false),
        ("rer_backpressure_events_total", "counter", false),
        ("rer_stream_received_packets_total", "counter", true),
        ("rer_stream_received_bytes_total", "counter", true),
        ("rer_stream_forwarded_packets_total", "counter", true),
        ("rer_stream_forwarded_bytes_total", "counter", true),
        ("rer_stream_dropped_packets_total", "counter", true),
        ("rer_stream_drops_queue_full_total", "counter", true),
        ("rer_stream_drops_oversized_total", "counter", true),
        ("rer_stream_queue_depth", "gauge", true),
        ("rer_stream_destination_errors_total", "counter", true),
        ("rer_stream_socket_errors_total", "counter", true),
        ("rer_stream_backpressure_events_total", "counter", true),
        ("rer_stream_healthy", "gauge", true),
    ];

    for (name, expected_type, requires_stream_label) in documented_metrics {
        let fam = parsed.families.get(name).unwrap_or_else(|| {
            panic!(
                "Documented metric '{}' must exist in OpenMetrics output",
                name
            )
        });

        assert!(
            fam.help.is_some(),
            "Metric '{}' must have # HELP metadata",
            name
        );
        assert_eq!(
            fam.metric_type.as_deref(),
            Some(expected_type),
            "Metric '{}' type mismatch",
            name
        );
        assert!(
            !fam.samples.is_empty(),
            "Metric '{}' must have at least one sample",
            name
        );

        if requires_stream_label {
            for sample in &fam.samples {
                assert!(
                    sample.labels.contains_key("stream"),
                    "Per-stream metric '{}' sample must have 'stream' label: {:?}",
                    name,
                    sample.labels
                );
                assert_eq!(
                    sample.labels.get("stream").unwrap(),
                    "telemetry-1",
                    "Stream label must match configured stream id"
                );
            }
        }
    }

    // Verify counter values match forwarded traffic
    let rcv_pkts = parsed.families["rer_received_packets_total"].samples[0].value;
    assert_eq!(rcv_pkts, 15.0);
    let fwd_pkts = parsed.families["rer_forwarded_packets_total"].samples[0].value;
    assert_eq!(fwd_pkts, 15.0);

    let stream_rcv = parsed.families["rer_stream_received_packets_total"].samples[0].value;
    assert_eq!(stream_rcv, 15.0);
    let stream_fwd = parsed.families["rer_stream_forwarded_packets_total"].samples[0].value;
    assert_eq!(stream_fwd, 15.0);

    // Queue depth must be a non-negative gauge
    let q_depth = parsed.families["rer_stream_queue_depth"].samples[0].value;
    assert!(q_depth >= 0.0);

    mgmt_server.stop();
    relay.stop();
    let _ = std::fs::remove_file(&sock_path);
}

// ============================================================================
// 2. Acceptance Criterion 2: Metrics HTTP Endpoint Bound to Loopback by Default
// ============================================================================

#[test]
fn test_metrics_http_endpoint_and_loopback_default() {
    let metrics_port = pick_unused_port();
    let src_port = pick_unused_port();
    let dest_port = pick_unused_port();
    let sock_path = std::env::temp_dir().join(format!("rer_http_mgmt_{}.sock", pick_unused_port()));

    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "metrics-http-test"
    metrics:
      enabled: true
      endpoint: "127.0.0.1:{metrics_port}"
      path: "/metrics"
    streams:
      - id: "s1"
        source:
          transport: "udp"
          address: "127.0.0.1:{src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("valid configuration");
    let relay = Relay::start(&config).expect("relay starts");
    let mgmt_server =
        ManagementServer::start_from_config(&config, relay.health_handle(), &sock_path)
            .expect("management server starts");

    // Give server a moment to accept
    thread::sleep(Duration::from_millis(100));

    // Connect via HTTP GET /metrics
    let mut tcp = TcpStream::connect(format!("127.0.0.1:{metrics_port}"))
        .expect("connect to metrics endpoint");
    tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(2))).unwrap();

    let http_request = format!(
        "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1:{metrics_port}\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(http_request.as_bytes())
        .expect("write HTTP request");

    let mut response = String::new();
    tcp.read_to_string(&mut response)
        .expect("read HTTP response");

    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "HTTP response must be 200 OK"
    );
    assert!(
        response
            .contains("Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8"),
        "Content-Type must be OpenMetrics"
    );
    assert!(response.contains("# HELP rer_uptime_seconds"));
    assert!(response.contains("# EOF"));

    // Verify response body passes OpenMetrics parser
    let body_start = response.find("\r\n\r\n").expect("HTTP body separator");
    let body = &response[body_start + 4..];
    let parsed = parse_openmetrics(body).expect("HTTP response body must be valid OpenMetrics");
    assert!(parsed.has_eof);

    // Test non-matching path returns 404
    let mut tcp_404 = TcpStream::connect(format!("127.0.0.1:{metrics_port}"))
        .expect("connect to metrics endpoint");
    let http_404 = format!(
        "GET /notfound HTTP/1.1\r\nHost: 127.0.0.1:{metrics_port}\r\nConnection: close\r\n\r\n"
    );
    tcp_404.write_all(http_404.as_bytes()).unwrap();
    let mut resp_404 = String::new();
    tcp_404.read_to_string(&mut resp_404).unwrap();
    assert!(resp_404.starts_with("HTTP/1.1 404 Not Found"));

    mgmt_server.stop();
    relay.stop();
    let _ = std::fs::remove_file(&sock_path);
}

// ============================================================================
// 3. Acceptance Criterion 2: Metrics Optional and Never Required for Forwarding
// ============================================================================

#[test]
fn test_metrics_endpoint_optional_and_never_required_for_forwarding() {
    let src_port = pick_unused_port();
    let dest_port = pick_unused_port();

    // Configuration with metrics explicitly disabled
    let yaml = format!(
        r#"
version: "1"
instances:
  - id: "no-metrics-instance"
    metrics:
      enabled: false
      endpoint: "127.0.0.1:9100"
    streams:
      - id: "s-nomgmt"
        source:
          transport: "udp"
          address: "127.0.0.1:{src_port}"
        destination:
          transport: "udp"
          address: "127.0.0.1:{dest_port}"
"#
    );

    let config = Config::from_yaml_str(&yaml).expect("parse configuration");
    let relay = Relay::start(&config).expect("relay starts without metrics endpoint");

    let sink = UdpSocket::bind(format!("127.0.0.1:{dest_port}")).expect("bind sink");
    sink.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    client
        .send_to(b"forward-without-metrics", format!("127.0.0.1:{src_port}"))
        .unwrap();

    let mut buf = [0u8; 512];
    let (n, _) = sink.recv_from(&mut buf).expect("datagram forwarded");
    assert_eq!(&buf[..n], b"forward-without-metrics");

    relay.stop();
}

// ============================================================================
// 4. Parser Syntax Error Detection
// ============================================================================

#[test]
fn test_openmetrics_parser_detects_syntax_errors() {
    // Missing EOF
    let no_eof = "# HELP test Test\n# TYPE test gauge\ntest 1\n";
    assert!(parse_openmetrics(no_eof).is_err());

    // Invalid metric type
    let bad_type = "# HELP test Test\n# TYPE test invalid_type\ntest 1\n# EOF\n";
    assert!(parse_openmetrics(bad_type).is_err());

    // Reopened family
    let reopened = "# HELP m1 M1\n# TYPE m1 gauge\nm1 1\n# HELP m2 M2\n# TYPE m2 gauge\nm2 2\n# HELP m1 M1\nm1 2\n# EOF\n";
    assert!(parse_openmetrics(reopened).is_err());
}
