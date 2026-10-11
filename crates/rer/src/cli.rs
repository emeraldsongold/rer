use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::{Config, ValidationError, ValidationReport};

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

    /// Show status of relay instances (planned)
    Status(PlaceholderArgs),

    /// Diagnose network issues (planned)
    Diagnose(PlaceholderArgs),

    /// Inspect stream configurations and state (planned)
    Streams(PlaceholderArgs),

    /// View Prometheus / OpenMetrics metrics (planned)
    Metrics(PlaceholderArgs),

    /// Capture network traffic (planned)
    Capture(PlaceholderArgs),

    /// Replay captured traffic (planned)
    Replay(PlaceholderArgs),

    /// Run network simulation and tests (planned)
    Test(PlaceholderArgs),
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
        Commands::Status(_) => {
            eprintln!("rer status is not yet implemented (scheduled in roadmap milestone RER-F-007). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Diagnose(_) => {
            eprintln!("rer diagnose is not yet implemented (scheduled in roadmap milestone RER-F-008). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Streams(_) => {
            eprintln!("rer streams is not yet implemented (scheduled in roadmap milestone RER-F-006). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Metrics(_) => {
            eprintln!("rer metrics is not yet implemented (scheduled in roadmap milestone RER-F-012). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Capture(_) => {
            eprintln!("rer capture is not yet implemented (scheduled in roadmap milestone RER-F-011). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Replay(_) => {
            eprintln!("rer replay is not yet implemented (scheduled in roadmap milestone RER-F-011). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
        Commands::Test(_) => {
            eprintln!("rer test is not yet implemented (scheduled in roadmap milestone RER-F-004). See KNOWN_ISSUES.md.");
            ExitCode::from(1)
        }
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
        println!("Configuration '{}' is valid.", target_path.display());
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

    // Verify all configured streams use supported UDP transport
    for inst in config.all_instances() {
        for stream in &inst.streams {
            if stream.source.transport != crate::config::TransportType::Udp {
                eprintln!(
                    "Cannot run configuration: stream '{}' uses TCP source transport which is not yet implemented (scheduled in milestone RER-F-005)",
                    stream.id
                );
                return ExitCode::from(1);
            }
            if let Some(dest) = &stream.destination {
                if dest.transport != crate::config::TransportType::Udp {
                    eprintln!(
                        "Cannot run configuration: stream '{}' uses TCP destination transport which is not yet implemented (scheduled in milestone RER-F-005)",
                        stream.id
                    );
                    return ExitCode::from(1);
                }
            }
            if let Some(dests) = &stream.destinations {
                for dest in dests {
                    if dest.transport != crate::config::TransportType::Udp {
                        eprintln!(
                            "Cannot run configuration: stream '{}' uses TCP destination transport which is not yet implemented (scheduled in milestone RER-F-005)",
                            stream.id
                        );
                        return ExitCode::from(1);
                    }
                }
            }
        }
    }

    if let Err(err) = crate::signals::register_signal_handlers() {
        eprintln!("Warning: failed to register signal handlers: {}", err);
    }

    match crate::relay::Relay::start(&config) {
        Ok(relay) => {
            println!("RER relay running. Press Ctrl-C or send SIGTERM to stop.");
            while !crate::signals::is_shutdown_requested() {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            println!("Shutdown signal received. Stopping relay gracefully...");
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
