use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::config::{Config, ConnectionMode, ValidationError, ValidationReport};
use crate::sim::{
    GeneratorConfig, HarnessConfig, ImpairmentConfig, SimulationHarness, TrafficGenerator,
    TrafficReceiver,
};

/// RER — RER Engineering Relay CLI
#[derive(Parser, Debug)]
#[command(name = "rer", version, about = "RER Engineering Relay")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Validate configuration file(s)
    Validate(ValidateArgs),

    /// Inspect effective configuration without leaking secrets
    Inspect(InspectArgs),

    /// Print version information
    Version,

    /// Run the relay
    Run(RunArgs),

    /// Check health of running relay instance
    Health(HealthArgs),

    /// Show status of relay instances
    Status(StatusArgs),

    /// Diagnose network issues (planned)
    Diagnose(PlaceholderArgs),

    /// Inspect stream configurations and logical interfaces
    Streams(StreamsArgs),

    /// View Prometheus / OpenMetrics metrics and relay counters
    Metrics(MetricsArgs),

    /// Capture network traffic (planned)
    Capture(PlaceholderArgs),

    /// Replay captured traffic (planned)
    Replay(PlaceholderArgs),

    /// Run network simulation and tests
    Test(TestArgs),
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Path to YAML configuration file
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Path to YAML configuration file (alternative flag)
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Output format for validation report
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Machine-readable JSON output (convenience alias for --format json)
    #[arg(long)]
    pub json: bool,

    /// Output effective configuration (with secrets redacted)
    #[arg(long, alias = "show-effective", alias = "print-effective")]
    pub effective: bool,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to YAML configuration file
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Path to YAML configuration file
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Output format: yaml or json
    #[arg(short, long, value_enum, default_value_t = InspectFormat::Yaml)]
    pub format: InspectFormat,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Path to YAML configuration file
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Path to YAML configuration file (alternative flag)
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Path to Unix domain socket for health and status checks
    #[arg(long, default_value = "/tmp/relay_health.sock")]
    pub health_socket: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct HealthArgs {
    /// Path to Unix domain socket for health probe
    #[arg(long, default_value = "/tmp/relay_health.sock")]
    pub socket: PathBuf,

    /// Timeout in seconds to wait for health response
    #[arg(short, long, default_value = "2.0")]
    pub timeout: f64,

    /// Output report as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    /// Path to Unix domain socket for status probe
    #[arg(long, default_value = "/tmp/relay_health.sock")]
    pub socket: PathBuf,

    /// Remote management endpoint for status probe (e.g. 127.0.0.1:9443)
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Authentication token for management probe
    #[arg(long)]
    pub auth_token: Option<String>,

    /// Timeout in seconds to wait for status response
    #[arg(short, long, default_value = "2.0")]
    pub timeout: f64,

    /// Output report as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct MetricsArgs {
    /// Path to Unix domain socket for metrics probe
    #[arg(long, default_value = "/tmp/relay_health.sock")]
    pub socket: PathBuf,

    /// Remote management endpoint for metrics probe (e.g. 127.0.0.1:9443)
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Authentication token for management probe
    #[arg(long)]
    pub auth_token: Option<String>,

    /// Timeout in seconds to wait for metrics response
    #[arg(short, long, default_value = "2.0")]
    pub timeout: f64,

    /// Output format: text, json, or prometheus
    #[arg(short, long, value_enum, default_value_t = MetricsFormat::Text)]
    pub format: MetricsFormat,

    /// Machine-readable JSON output (convenience alias for --format json)
    #[arg(long)]
    pub json: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsFormat {
    Text,
    Json,
    Prometheus,
}

#[derive(Args, Debug)]
pub struct StreamsArgs {
    /// Path to YAML configuration file
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,

    /// Path to YAML configuration file (alternative flag)
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Path to Unix domain socket for querying running instance
    #[arg(long)]
    pub socket: Option<PathBuf>,

    /// Remote management endpoint for querying running instance
    #[arg(long)]
    pub endpoint: Option<String>,

    /// Authentication token for management probe
    #[arg(long)]
    pub auth_token: Option<String>,

    /// Timeout in seconds to wait for response
    #[arg(long, default_value = "2.0")]
    pub timeout: f64,

    /// Output format: text or json
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Machine-readable JSON output (convenience alias for --format json)
    #[arg(long)]
    pub json: bool,
}

/// Inspection report for streams and logical interfaces.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StreamsReport {
    pub instances: Vec<InstanceStreamsReport>,
}

/// Streams and logical interfaces report for an instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstanceStreamsReport {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub logical_interfaces: Vec<LogicalInterfaceReport>,
    pub standalone_streams: Vec<StreamReport>,
}

/// Representation of a logical interface pairing directional streams.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogicalInterfaceReport {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_stream: Option<String>,
    pub pairing_type: String,
    pub pairing_context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx: Option<StreamReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx: Option<StreamReport>,
}

/// Representation of an individual stream for inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StreamReport {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source: EndpointReport,
    pub destinations: Vec<EndpointReport>,
}

/// Representation of an endpoint for inspection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EndpointReport {
    pub transport: String,
    pub address: String,
    pub mode: String,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectFormat {
    Yaml,
    Json,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    #[command(subcommand)]
    pub command: Option<TestSubcommand>,

    /// Number of packets to generate and verify
    #[arg(short = 'c', long, default_value = "100")]
    pub count: u64,

    /// Payload size in bytes
    #[arg(short = 's', long, default_value = "256")]
    pub size: usize,

    /// Rate in packets per second (0 for unthrottled)
    #[arg(short = 'r', long, default_value = "0")]
    pub rate: f64,

    /// Burst size
    #[arg(short = 'b', long, default_value = "1")]
    pub burst: usize,

    /// Duration in seconds
    #[arg(short = 'd', long)]
    pub duration: Option<f64>,

    /// PRNG seed
    #[arg(long, default_value = "42")]
    pub seed: u64,

    /// Simulated packet loss rate (0.0 to 1.0)
    #[arg(long, default_value = "0.0")]
    pub loss_rate: f64,

    /// Simulated packet duplication rate (0.0 to 1.0)
    #[arg(long, default_value = "0.0")]
    pub duplicate_rate: f64,

    /// Simulated packet reorder rate (0.0 to 1.0)
    #[arg(long, default_value = "0.0")]
    pub reorder_rate: f64,

    /// Output report as JSON
    #[arg(long, default_value = "true")]
    pub json: bool,
}

#[derive(Subcommand, Debug)]
pub enum TestSubcommand {
    /// Run an end-to-end unprivileged simulation harness
    Harness(HarnessArgs),
    /// Run traffic generator standalone
    Generate(GenerateArgs),
    /// Run traffic receiver standalone
    Receive(ReceiveArgs),
}

#[derive(Args, Debug)]
pub struct HarnessArgs {
    /// Number of packets to generate and verify
    #[arg(short = 'c', long, default_value = "100")]
    pub count: u64,

    /// Payload size in bytes
    #[arg(short = 's', long, default_value = "256")]
    pub size: usize,

    /// Rate in packets per second (0 for unthrottled)
    #[arg(short = 'r', long, default_value = "0")]
    pub rate: f64,

    /// Burst size
    #[arg(short = 'b', long, default_value = "1")]
    pub burst: usize,

    /// Duration in seconds
    #[arg(short = 'd', long)]
    pub duration: Option<f64>,

    /// PRNG seed
    #[arg(long, default_value = "42")]
    pub seed: u64,

    /// Simulated packet loss rate (0.0 to 1.0)
    #[arg(long, default_value = "0.0")]
    pub loss_rate: f64,

    /// Simulated packet duplication rate (0.0 to 1.0)
    #[arg(long, default_value = "0.0")]
    pub duplicate_rate: f64,

    /// Simulated packet reorder rate (0.0 to 1.0)
    #[arg(long, default_value = "0.0")]
    pub reorder_rate: f64,

    /// Output report as JSON
    #[arg(long, default_value = "true")]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GenerateArgs {
    /// Target UDP address (e.g. 127.0.0.1:5000)
    #[arg(short, long)]
    pub target: String,

    /// Number of packets to generate
    #[arg(short = 'c', long, default_value = "100")]
    pub count: u64,

    /// Payload size in bytes
    #[arg(short = 's', long, default_value = "256")]
    pub size: usize,

    /// Rate in packets per second
    #[arg(short = 'r', long, default_value = "0")]
    pub rate: f64,

    /// Burst size
    #[arg(short = 'b', long, default_value = "1")]
    pub burst: usize,

    /// PRNG seed
    #[arg(long, default_value = "42")]
    pub seed: u64,
}

#[derive(Args, Debug)]
pub struct ReceiveArgs {
    /// Bind UDP address (e.g. 127.0.0.1:5000)
    #[arg(short, long, default_value = "127.0.0.1:5000")]
    pub bind: String,

    /// Expected packet count
    #[arg(short = 'c', long)]
    pub count: Option<u64>,

    /// Timeout in seconds to wait for packets
    #[arg(short = 't', long, default_value = "2.0")]
    pub timeout: f64,
}

#[derive(Args, Debug)]
pub struct PlaceholderArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// Executes the CLI command and returns an ExitCode.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    execute(cli)
}

/// Executes parsed CLI options.
pub fn execute(cli: Cli) -> ExitCode {
    match cli.command {
        Commands::Validate(args) => execute_validate(args),
        Commands::Inspect(args) => execute_inspect(args),
        Commands::Version => {
            println!("rer {}", crate::version());
            ExitCode::SUCCESS
        }
        Commands::Run(args) => execute_run(args),
        Commands::Health(args) => execute_health(args),
        Commands::Status(args) => execute_status(args),
        Commands::Diagnose(_) => {
            eprintln!("rer diagnose is not yet implemented (scheduled in roadmap milestone RER-F-008). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Streams(args) => execute_streams(args),
        Commands::Metrics(args) => execute_metrics(args),
        Commands::Capture(_) => {
            eprintln!("rer capture is not yet implemented (scheduled in roadmap milestone RER-F-011). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Replay(_) => {
            eprintln!("rer replay is not yet implemented (scheduled in roadmap milestone RER-F-011). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Test(args) => execute_test(args),
    }
}

fn execute_validate(args: ValidateArgs) -> ExitCode {
    let is_json = args.json || args.format == OutputFormat::Json;

    let target_path = match args.file.or(args.config) {
        Some(p) => p,
        None => {
            let error = ValidationError {
                path: "args".to_string(),
                reason:
                    "missing configuration file argument; provide a path or use --config <FILE>"
                        .to_string(),
            };
            if is_json {
                let report = ValidationReport {
                    valid: false,
                    errors: vec![error],
                    effective_config: None,
                };
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                eprintln!("Error: {}", error.reason);
            }
            return ExitCode::from(1);
        }
    };

    let content = match fs::read_to_string(&target_path) {
        Ok(c) => c,
        Err(err) => {
            let error = ValidationError {
                path: "file".to_string(),
                reason: format!("failed to read '{}': {}", target_path.display(), err),
            };
            if is_json {
                let report = ValidationReport {
                    valid: false,
                    errors: vec![error],
                    effective_config: None,
                };
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                eprintln!("Error: {}", error.reason);
            }
            return ExitCode::from(1);
        }
    };

    let mut errors = Vec::new();
    let config = match Config::from_yaml_str(&content) {
        Ok(cfg) => {
            errors.extend(cfg.validate());
            Some(cfg)
        }
        Err(errs) => {
            errors.extend(errs);
            None
        }
    };

    let is_valid = errors.is_empty();
    let effective_config = if is_valid && args.effective {
        config.as_ref().map(|c| c.to_effective())
    } else {
        None
    };

    if is_json {
        let report = ValidationReport {
            valid: is_valid,
            errors,
            effective_config,
        };
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else if is_valid {
        let total_streams: usize = config
            .as_ref()
            .map(|c| c.all_instances().iter().map(|i| i.streams.len()).sum())
            .unwrap_or(0);
        let total_ifaces: usize = config
            .as_ref()
            .map(|c| {
                c.all_instances()
                    .iter()
                    .map(|i| i.logical_interfaces.len())
                    .sum()
            })
            .unwrap_or(0);
        let inst_count = config
            .as_ref()
            .map(|c| c.all_instances().len())
            .unwrap_or(0);
        println!(
            "Configuration '{}' is valid ({} instance(s), {} stream(s), {} logical interface(s)).",
            target_path.display(),
            inst_count,
            total_streams,
            total_ifaces
        );
        if let Some(eff) = effective_config {
            println!("--- Effective Configuration (secrets redacted) ---");
            println!("{}", eff.to_effective_yaml().unwrap());
        }
    } else {
        eprintln!(
            "Configuration '{}' is invalid ({} error(s)):",
            target_path.display(),
            errors.len()
        );
        for err in &errors {
            eprintln!("  - {}", err);
        }
    }

    if is_valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn execute_inspect(args: InspectArgs) -> ExitCode {
    let target_path = match args.file.or(args.config) {
        Some(p) => p,
        None => {
            eprintln!(
                "Error: missing configuration file argument; provide a path or use --config <FILE>"
            );
            return ExitCode::from(1);
        }
    };

    let content = match fs::read_to_string(&target_path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Error reading '{}': {}", target_path.display(), err);
            return ExitCode::from(1);
        }
    };

    let config = match Config::from_yaml_str(&content) {
        Ok(cfg) => cfg,
        Err(errs) => {
            eprintln!("Cannot inspect invalid configuration (parse failed):");
            for err in errs {
                eprintln!("  - {}", err);
            }
            return ExitCode::from(1);
        }
    };

    let semantic_errors = config.validate();
    if !semantic_errors.is_empty() {
        eprintln!("Cannot inspect invalid configuration (validation failed):");
        for err in semantic_errors {
            eprintln!("  - {}", err);
        }
        return ExitCode::from(1);
    }

    let effective = config.to_effective();
    match args.format {
        InspectFormat::Yaml => {
            println!("{}", effective.to_effective_yaml().unwrap());
        }
        InspectFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&effective.to_effective_json().unwrap()).unwrap()
            );
        }
    }

    ExitCode::SUCCESS
}

fn execute_run(args: RunArgs) -> ExitCode {
    let target_path = match args.file.or(args.config) {
        Some(p) => p,
        None => {
            eprintln!(
                "Error: missing configuration file argument; provide a path or use --config <FILE>"
            );
            return ExitCode::from(1);
        }
    };

    let content = match fs::read_to_string(&target_path) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("Error reading '{}': {}", target_path.display(), err);
            return ExitCode::from(1);
        }
    };

    let config = match Config::from_yaml_str(&content) {
        Ok(cfg) => cfg,
        Err(errs) => {
            eprintln!("Cannot run invalid configuration (parse failed):");
            for err in errs {
                eprintln!("  - {}", err);
            }
            return ExitCode::from(1);
        }
    };

    let errors = config.validate();
    if !errors.is_empty() {
        eprintln!("Cannot run invalid configuration (validation failed):");
        for err in errors {
            eprintln!("  - {}", err);
        }
        return ExitCode::from(1);
    }

    if let Err(err) = crate::signals::register_signal_handlers() {
        eprintln!("Warning: failed to register signal handlers: {}", err);
    }

    let socket_path = std::env::var("RER_MGMT_SOCKET")
        .or_else(|_| std::env::var("RER_HEALTH_SOCKET"))
        .map(PathBuf::from)
        .unwrap_or(args.health_socket);

    match crate::relay::Relay::start(&config) {
        Ok(relay) => {
            let mgmt_server = match crate::management::ManagementServer::start_from_config(
                &config,
                relay.health_handle(),
                &socket_path,
            ) {
                Ok(srv) => Some(srv),
                Err(err) => {
                    eprintln!(
                        "Warning: management server unavailable at '{}': {}",
                        socket_path.display(),
                        err
                    );
                    None
                }
            };

            println!("RER relay running. Press Ctrl-C or send SIGTERM to stop.");
            for inst in config.all_instances() {
                if !inst.logical_interfaces.is_empty() {
                    println!(
                        "[relay] Active logical interfaces on instance '{}':",
                        inst.id
                    );
                    for iface in &inst.logical_interfaces {
                        let tx_name = iface.tx_stream.as_deref().unwrap_or("none");
                        let rx_name = iface.rx_stream.as_deref().unwrap_or("none");
                        let iface_label = iface.name.as_deref().unwrap_or(&iface.id);
                        println!(
                            "[relay]   - Interface '{}' ({}): tx='{}', rx='{}' (paired directional streams: configuration context)",
                            iface.id, iface_label, tx_name, rx_name
                        );
                    }
                }
            }
            while !crate::signals::is_shutdown_requested() {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            println!("Shutdown signal received. Stopping relay gracefully...");
            if let Some(srv) = mgmt_server {
                srv.stop();
            }
            relay.stop();
            println!("RER relay stopped gracefully.");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Failed to start relay: {}", err);
            ExitCode::from(1)
        }
    }
}

fn execute_health(args: HealthArgs) -> ExitCode {
    let socket_path = std::env::var("RER_HEALTH_SOCKET")
        .map(PathBuf::from)
        .unwrap_or(args.socket);

    let timeout = Duration::from_secs_f64(args.timeout.max(0.1));
    match crate::health::query_health(&socket_path, timeout) {
        Ok(report) => {
            let is_healthy = report.status == crate::health::STATUS_HEALTHY;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else if is_healthy {
                println!(
                    "OK: RER relay is healthy (uptime: {}s, streams: {})",
                    report.uptime_seconds,
                    report.streams.len()
                );
            } else {
                eprintln!(
                    "Health check failed: relay status is '{}' (uptime: {}s)",
                    report.status, report.uptime_seconds
                );
            }

            if is_healthy {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            if args.json {
                let err_obj = serde_json::json!({
                    "status": "unhealthy",
                    "error": format!("unable to connect to relay health socket at '{}': {}", socket_path.display(), err)
                });
                println!("{}", serde_json::to_string_pretty(&err_obj).unwrap());
            } else {
                eprintln!(
                    "Health check failed: unable to connect to relay health socket at '{}': {}",
                    socket_path.display(),
                    err
                );
            }
            ExitCode::from(1)
        }
    }
}

fn execute_status(args: StatusArgs) -> ExitCode {
    let timeout = Duration::from_secs_f64(args.timeout.max(0.1));
    let target = args.endpoint.unwrap_or_else(|| {
        std::env::var("RER_MGMT_SOCKET")
            .or_else(|_| std::env::var("RER_HEALTH_SOCKET"))
            .unwrap_or_else(|_| args.socket.to_string_lossy().to_string())
    });

    match crate::management::query_status(&target, timeout, args.auth_token.as_deref()) {
        Ok(report) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                println!("RER Relay Status: {}", report.status);
                println!("Version: {}", report.version);
                println!("Uptime: {}s", report.uptime_seconds);
                println!(
                    "Overall Counters: rx: {} pkts ({} B), tx: {} pkts ({} B), drops: {}, errors: {}",
                    report.aggregate_counters.received_packets,
                    report.aggregate_counters.received_bytes,
                    report.aggregate_counters.forwarded_packets,
                    report.aggregate_counters.forwarded_bytes,
                    report.aggregate_counters.dropped_packets,
                    report.aggregate_counters.destination_errors
                        + report.aggregate_counters.socket_errors
                );
                println!("Streams ({}):", report.streams.len());
                for s in &report.streams {
                    println!(
                        "  - {}: {} (rx: {} pkts / {} B, tx: {} pkts / {} B, drops: {}, errors: {})",
                        s.stream_id,
                        s.state,
                        s.received_packets,
                        s.received_bytes,
                        s.forwarded_packets,
                        s.forwarded_bytes,
                        s.dropped_packets,
                        s.destination_errors + s.socket_errors
                    );
                }
            }
            if report.healthy {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            if args.json {
                let err_obj = serde_json::json!({
                    "status": "unknown",
                    "error": format!("cannot connect to relay at '{}': {}", target, err)
                });
                println!("{}", serde_json::to_string_pretty(&err_obj).unwrap());
            } else {
                eprintln!(
                    "Error: cannot connect to RER relay at '{}': {}",
                    target, err
                );
            }
            ExitCode::from(1)
        }
    }
}

fn execute_metrics(args: MetricsArgs) -> ExitCode {
    let timeout = Duration::from_secs_f64(args.timeout.max(0.1));
    let target = args.endpoint.unwrap_or_else(|| {
        std::env::var("RER_MGMT_SOCKET")
            .or_else(|_| std::env::var("RER_HEALTH_SOCKET"))
            .unwrap_or_else(|_| args.socket.to_string_lossy().to_string())
    });

    let is_json = args.json || args.format == MetricsFormat::Json;

    match crate::management::query_metrics(&target, timeout, args.auth_token.as_deref()) {
        Ok(report) => {
            if is_json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else if args.format == MetricsFormat::Prometheus {
                print!("{}", report.prometheus_text);
            } else {
                println!("RER Relay Metrics:");
                println!("==================");
                println!(
                    "Status: {} (Uptime: {}s, Healthy: {})",
                    report.status, report.uptime_seconds, report.healthy
                );
                println!("Aggregate Counters:");
                println!(
                    "  - Received: {} packets ({} bytes)",
                    report.counters.received_packets, report.counters.received_bytes
                );
                println!(
                    "  - Forwarded: {} packets ({} bytes)",
                    report.counters.forwarded_packets, report.counters.forwarded_bytes
                );
                println!(
                    "  - Dropped: {} packets (queue full: {}, oversized: {})",
                    report.counters.dropped_packets,
                    report.counters.drops_queue_full,
                    report.counters.drops_oversized
                );
                println!(
                    "  - Errors: {} destination, {} socket, {} backpressure",
                    report.counters.destination_errors,
                    report.counters.socket_errors,
                    report.counters.backpressure_events
                );
                if !report.streams.is_empty() {
                    println!("Per-Stream Counters ({}):", report.streams.len());
                    for (id, s) in &report.streams {
                        println!(
                            "  - Stream '{}': rx: {} pkts / {} B, tx: {} pkts / {} B, drops: {}, errors: {}",
                            id,
                            s.received_packets,
                            s.received_bytes,
                            s.forwarded_packets,
                            s.forwarded_bytes,
                            s.dropped_packets,
                            s.destination_errors + s.socket_errors
                        );
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": format!("cannot connect to management endpoint at '{}': {}", target, err)
                    })
                );
            } else {
                eprintln!(
                    "Error: cannot connect to RER metrics at '{}': {}",
                    target, err
                );
            }
            ExitCode::from(1)
        }
    }
}

fn execute_test(args: TestArgs) -> ExitCode {
    match args.command {
        Some(TestSubcommand::Harness(h_args)) => run_harness_cli(h_args),
        Some(TestSubcommand::Generate(g_args)) => run_generate_cli(g_args),
        Some(TestSubcommand::Receive(r_args)) => run_receive_cli(r_args),
        None => {
            let h_args = HarnessArgs {
                count: args.count,
                size: args.size,
                rate: args.rate,
                burst: args.burst,
                duration: args.duration,
                seed: args.seed,
                loss_rate: args.loss_rate,
                duplicate_rate: args.duplicate_rate,
                reorder_rate: args.reorder_rate,
                json: args.json,
            };
            run_harness_cli(h_args)
        }
    }
}

fn run_harness_cli(args: HarnessArgs) -> ExitCode {
    let duration = args.duration.map(Duration::from_secs_f64);
    let rate = if args.rate > 0.0 {
        Some(args.rate)
    } else {
        None
    };
    let burst = if args.burst > 1 {
        Some(args.burst)
    } else {
        None
    };

    let generator = GeneratorConfig {
        seed: args.seed,
        packet_size: args.size,
        rate,
        burst,
        duration,
        count: Some(args.count),
    };

    let impairments =
        if args.loss_rate > 0.0 || args.duplicate_rate > 0.0 || args.reorder_rate > 0.0 {
            Some(ImpairmentConfig {
                seed: args.seed.wrapping_add(1),
                loss_rate: args.loss_rate,
                duplicate_rate: args.duplicate_rate,
                reorder_rate: args.reorder_rate,
                delay_ms: 0,
                jitter_ms: 0,
            })
        } else {
            None
        };

    let harness_config = HarnessConfig {
        test_id: Some("cli-sim-test".to_string()),
        generator,
        impairments,
        use_relay: true,
        relay_queue_capacity: None,
        relay_drop_policy: None,
        ..Default::default()
    };

    match SimulationHarness::run(harness_config) {
        Ok(report) => {
            if args.json {
                println!("{}", report.to_json());
            } else {
                println!("--- Simulation Test Report ---");
                println!("Result: {}", if report.pass { "PASS" } else { "FAIL" });
                println!("Expected: {:?}", report.expected_count);
                println!("Received: {}", report.received_count);
                println!(
                    "Lost: {} (loss rate: {:.2}%)",
                    report.lost_count,
                    report.loss_rate * 100.0
                );
                println!("Duplicates: {}", report.duplicate_count);
                println!("Reordered: {}", report.reordered_count);
                println!(
                    "Payload Hashes Verified: {}",
                    report.payload_hashes_verified
                );
            }
            if report.pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("Simulation harness error: {}", err);
            ExitCode::from(1)
        }
    }
}

fn run_generate_cli(args: GenerateArgs) -> ExitCode {
    let rate = if args.rate > 0.0 {
        Some(args.rate)
    } else {
        None
    };
    let burst = if args.burst > 1 {
        Some(args.burst)
    } else {
        None
    };
    let mut gen = TrafficGenerator::new(GeneratorConfig {
        seed: args.seed,
        packet_size: args.size,
        rate,
        burst,
        duration: None,
        count: Some(args.count),
    });

    match gen.run_udp(&args.target) {
        Ok(stats) => {
            println!("{}", serde_json::to_string_pretty(&stats).unwrap());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Traffic generation failed: {}", err);
            ExitCode::from(1)
        }
    }
}

fn run_receive_cli(args: ReceiveArgs) -> ExitCode {
    let socket = match UdpSocket::bind(&args.bind) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("Failed to bind to '{}': {}", args.bind, err);
            return ExitCode::from(1);
        }
    };

    let mut receiver = TrafficReceiver::new(args.count, None);
    let timeout = Duration::from_secs_f64(args.timeout);
    match receiver.listen_udp(&socket, timeout) {
        Ok(report) => {
            println!("{}", report.to_json());
            if report.pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("Traffic receiver failed: {}", err);
            ExitCode::from(1)
        }
    }
}

fn execute_streams(args: StreamsArgs) -> ExitCode {
    let is_json = args.json || args.format == OutputFormat::Json;

    if args.file.is_some() || args.config.is_some() {
        return execute_streams_file(args);
    }

    if args.socket.is_some() || args.endpoint.is_some() || std::env::var("RER_MGMT_SOCKET").is_ok()
    {
        let target = args.endpoint.unwrap_or_else(|| {
            args.socket
                .map(|p| p.to_string_lossy().to_string())
                .or_else(|| std::env::var("RER_MGMT_SOCKET").ok())
                .unwrap_or_else(|| "/tmp/relay_health.sock".to_string())
        });
        let timeout = Duration::from_secs_f64(args.timeout.max(0.1));

        match crate::management::query_streams(&target, timeout, args.auth_token.as_deref()) {
            Ok(report) => {
                if is_json {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                } else {
                    println!("Streams and Logical Interfaces (Runtime Status):");
                    println!("===============================================");
                    println!(
                        "Status: {} (Uptime: {}s)",
                        report.status, report.uptime_seconds
                    );
                    println!("Streams ({}):", report.streams.len());
                    for s in &report.streams {
                        println!(
                            "  - Stream '{}': {} (rx: {} pkts / {} B, tx: {} pkts / {} B, drops: {}, errors: {})",
                            s.stream_id,
                            s.state,
                            s.received_packets,
                            s.received_bytes,
                            s.forwarded_packets,
                            s.forwarded_bytes,
                            s.dropped_packets,
                            s.destination_errors + s.socket_errors
                        );
                    }
                    if !report.logical_interfaces.is_empty() {
                        println!("Logical Interfaces ({}):", report.logical_interfaces.len());
                        for iface in &report.logical_interfaces {
                            let tx_name = iface.tx_stream.as_deref().unwrap_or("none");
                            let rx_name = iface.rx_stream.as_deref().unwrap_or("none");
                            let iface_label = iface.name.as_deref().unwrap_or(&iface.id);
                            println!(
                                "  - Interface '{}' ({}): tx='{}', rx='{}'",
                                iface.id, iface_label, tx_name, rx_name
                            );
                            if let Some(ref tx) = iface.tx_stats {
                                println!(
                                    "      TX: rx: {} pkts ({} B), tx: {} pkts ({} B), drops: {}, errors: {}",
                                    tx.received_packets, tx.received_bytes, tx.forwarded_packets, tx.forwarded_bytes, tx.dropped_packets, tx.destination_errors + tx.socket_errors
                                );
                            }
                            if let Some(ref rx) = iface.rx_stats {
                                println!(
                                    "      RX: rx: {} pkts ({} B), tx: {} pkts ({} B), drops: {}, errors: {}",
                                    rx.received_packets, rx.received_bytes, rx.forwarded_packets, rx.forwarded_bytes, rx.dropped_packets, rx.destination_errors + rx.socket_errors
                                );
                            }
                        }
                    }
                }
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                if is_json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "error": format!("cannot connect to management endpoint at '{}': {}", target, err)
                        })
                    );
                } else {
                    eprintln!(
                        "Error: cannot connect to management endpoint at '{}': {}",
                        target, err
                    );
                }
                return ExitCode::from(1);
            }
        }
    }

    if is_json {
        println!(
            "{}",
            serde_json::json!({
                "error": "missing configuration file argument; provide a path or use --config <FILE>"
            })
        );
    } else {
        eprintln!(
            "Error: missing configuration file argument; provide a path or use --config <FILE>"
        );
    }
    ExitCode::from(1)
}

fn execute_streams_file(args: StreamsArgs) -> ExitCode {
    let is_json = args.json || args.format == OutputFormat::Json;

    let target_path = match args.file.or(args.config) {
        Some(p) => p,
        None => {
            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": "missing configuration file argument; provide a path or use --config <FILE>"
                    })
                );
            } else {
                eprintln!(
                    "Error: missing configuration file argument; provide a path or use --config <FILE>"
                );
            }
            return ExitCode::from(1);
        }
    };

    let content = match fs::read_to_string(&target_path) {
        Ok(c) => c,
        Err(err) => {
            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": format!("failed to read '{}': {}", target_path.display(), err)
                    })
                );
            } else {
                eprintln!("Error reading '{}': {}", target_path.display(), err);
            }
            return ExitCode::from(1);
        }
    };

    let config = match Config::from_yaml_str(&content) {
        Ok(cfg) => cfg,
        Err(errs) => {
            if is_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "error": "parse failed",
                        "details": errs.iter().map(|e| e.to_string()).collect::<Vec<_>>()
                    })
                );
            } else {
                eprintln!("Cannot inspect streams from invalid configuration (parse failed):");
                for err in errs {
                    eprintln!("  - {}", err);
                }
            }
            return ExitCode::from(1);
        }
    };

    let semantic_errors = config.validate();
    if !semantic_errors.is_empty() {
        if is_json {
            println!(
                "{}",
                serde_json::json!({
                    "error": "validation failed",
                    "details": semantic_errors.iter().map(|e| e.to_string()).collect::<Vec<_>>()
                })
            );
        } else {
            eprintln!("Cannot inspect streams from invalid configuration (validation failed):");
            for err in semantic_errors {
                eprintln!("  - {}", err);
            }
        }
        return ExitCode::from(1);
    }

    let report = build_streams_report(&config);

    if is_json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_streams_report_text(&report);
    }

    ExitCode::SUCCESS
}

fn build_streams_report(config: &Config) -> StreamsReport {
    let mut instances = Vec::new();

    for inst in config.all_instances() {
        let mut paired_stream_ids = std::collections::HashSet::new();
        let mut logical_interfaces = Vec::new();

        for iface in &inst.logical_interfaces {
            let tx_report = iface.tx_stream.as_ref().and_then(|tx_id| {
                paired_stream_ids.insert(tx_id.clone());
                inst.streams
                    .iter()
                    .find(|s| &s.id == tx_id)
                    .map(stream_to_report)
            });

            let rx_report = iface.rx_stream.as_ref().and_then(|rx_id| {
                paired_stream_ids.insert(rx_id.clone());
                inst.streams
                    .iter()
                    .find(|s| &s.id == rx_id)
                    .map(stream_to_report)
            });

            let pairing_type = match (iface.tx_stream.is_some(), iface.rx_stream.is_some()) {
                (true, true) => "paired".to_string(),
                (true, false) => "tx_only".to_string(),
                (false, true) => "rx_only".to_string(),
                (false, false) => "none".to_string(),
            };

            let pairing_context = "Directional pairing is an operator configuration relationship; directions have independent counters, endpoints, routing, and errors without automatic packet correlation.".to_string();

            logical_interfaces.push(LogicalInterfaceReport {
                id: iface.id.clone(),
                name: iface.name.clone(),
                tx_stream: iface.tx_stream.clone(),
                rx_stream: iface.rx_stream.clone(),
                pairing_type,
                pairing_context,
                tx: tx_report,
                rx: rx_report,
            });
        }

        let standalone_streams = inst
            .streams
            .iter()
            .filter(|s| !paired_stream_ids.contains(&s.id))
            .map(stream_to_report)
            .collect();

        instances.push(InstanceStreamsReport {
            id: inst.id.clone(),
            name: inst.name.clone(),
            logical_interfaces,
            standalone_streams,
        });
    }

    StreamsReport { instances }
}

fn stream_to_report(stream: &crate::config::StreamConfig) -> StreamReport {
    let source_mode = stream.source.mode.unwrap_or(ConnectionMode::Listen);
    let source = EndpointReport {
        transport: format!("{:?}", stream.source.transport).to_lowercase(),
        address: stream.source.address.clone(),
        mode: format!("{:?}", source_mode).to_lowercase(),
    };

    let mut destinations = Vec::new();
    if let Some(dest) = &stream.destination {
        let dest_mode = dest.mode.unwrap_or(ConnectionMode::Connect);
        destinations.push(EndpointReport {
            transport: format!("{:?}", dest.transport).to_lowercase(),
            address: dest.address.clone(),
            mode: format!("{:?}", dest_mode).to_lowercase(),
        });
    }
    if let Some(dests) = &stream.destinations {
        for dest in dests {
            let dest_mode = dest.mode.unwrap_or(ConnectionMode::Connect);
            destinations.push(EndpointReport {
                transport: format!("{:?}", dest.transport).to_lowercase(),
                address: dest.address.clone(),
                mode: format!("{:?}", dest_mode).to_lowercase(),
            });
        }
    }

    StreamReport {
        id: stream.id.clone(),
        description: stream.description.clone(),
        source,
        destinations,
    }
}

fn print_streams_report_text(report: &StreamsReport) {
    println!("Streams and Logical Interfaces:");
    println!("===============================");
    for inst in &report.instances {
        let inst_label = match &inst.name {
            Some(name) => format!("Instance '{}' ({}):", inst.id, name),
            None => format!("Instance '{}':", inst.id),
        };
        println!("{}", inst_label);

        println!("  Logical Interfaces ({}):", inst.logical_interfaces.len());
        if inst.logical_interfaces.is_empty() {
            println!("    (none configured)");
        } else {
            for iface in &inst.logical_interfaces {
                let iface_label = match &iface.name {
                    Some(name) => format!("'{}' ({})", iface.id, name),
                    None => format!("'{}'", iface.id),
                };
                println!("    - Interface {}:", iface_label);
                let pairing_desc = match iface.pairing_type.as_str() {
                    "paired" => "Paired directional streams (TX + RX)",
                    "tx_only" => "Single directional stream (TX only)",
                    "rx_only" => "Single directional stream (RX only)",
                    _ => "Unspecified",
                };
                println!("      Type: {}", pairing_desc);
                println!(
                    "      Context: Configuration and operator context (independent counters, endpoints, routing; no automatic packet correlation)"
                );

                if let Some(tx) = &iface.tx {
                    print_stream_details("TX Direction", tx, "      ");
                }
                if let Some(rx) = &iface.rx {
                    print_stream_details("RX Direction", rx, "      ");
                }
            }
        }

        println!("  Standalone Streams ({}):", inst.standalone_streams.len());
        if inst.standalone_streams.is_empty() {
            println!("    (none configured)");
        } else {
            for stream in &inst.standalone_streams {
                print_stream_details(&format!("Stream '{}'", stream.id), stream, "    ");
            }
        }
    }
}

fn print_stream_details(label: &str, stream: &StreamReport, indent: &str) {
    println!("{}{}:", indent, label);
    println!("{}  Stream ID: {}", indent, stream.id);
    if let Some(desc) = &stream.description {
        println!("{}  Description: {}", indent, desc);
    }
    println!(
        "{}  Source: {} {} ({})",
        indent, stream.source.transport, stream.source.address, stream.source.mode
    );
    println!("{}  Destination(s):", indent);
    for dest in &stream.destinations {
        println!(
            "{}    * {} {} ({})",
            indent, dest.transport, dest.address, dest.mode
        );
    }
}
