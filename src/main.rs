//! Zentinel Audit Logger Agent CLI
//!
//! A comprehensive audit logging agent for the Zentinel API Gateway.
//! Supports Protocol v2 with gRPC and UDS transports.

use clap::Parser;
use zentinel_agent_audit_logger::{AuditLoggerAgent, AuditLoggerConfig};
use zentinel_agent_sdk::v2::AgentRunnerV2;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "zentinel-audit-logger",
    about = "Audit logging agent for Zentinel API Gateway (v2 protocol)",
    version
)]
struct Args {
    /// Configuration file path (YAML)
    #[arg(short, long, default_value = "audit-logger.yaml")]
    config: PathBuf,

    /// Unix socket path for agent communication
    #[arg(short, long, default_value = "/tmp/zentinel-audit-logger.sock")]
    socket: PathBuf,

    /// gRPC server address (e.g., "0.0.0.0:50051")
    /// When specified, enables gRPC transport in addition to UDS
    #[arg(long, value_name = "ADDR")]
    grpc_address: Option<SocketAddr>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short = 'L', long, default_value = "info")]
    log_level: String,

    /// Print default configuration and exit
    #[arg(long)]
    print_config: bool,

    /// Validate configuration and exit
    #[arg(long)]
    validate: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = args.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(log_level))
        .init();

    // Print default config if requested
    if args.print_config {
        let config = AuditLoggerConfig::default();
        let yaml = serde_yaml::to_string(&config)?;
        println!("{}", yaml);
        return Ok(());
    }

    // Load configuration
    let config = if args.config.exists() {
        let content = tokio::fs::read_to_string(&args.config).await?;
        let config: AuditLoggerConfig = serde_yaml::from_str(&content)?;
        info!(path = %args.config.display(), "Loaded configuration");
        config
    } else if args.validate {
        error!(path = %args.config.display(), "Configuration file not found");
        std::process::exit(1);
    } else {
        info!("Using default configuration");
        AuditLoggerConfig::default()
    };

    // Validate only mode
    if args.validate {
        info!("Configuration is valid");
        // Print summary
        println!("Configuration Summary:");
        println!("  Format: {:?}", config.format.format_type);
        println!("  Outputs: {}", config.outputs.len());
        println!("  Redaction enabled: {}", config.redaction.enabled);
        println!("  Sample rate: {:.1}%", config.sample_rate * 100.0);
        println!("  Filters: {}", config.filters.len());
        if let Some(template) = config.compliance_template {
            println!("  Compliance template: {:?}", template);
        }
        return Ok(());
    }

    // Create agent
    let agent = AuditLoggerAgent::new(config).await;

    // Start server using the SDK's AgentRunnerV2 (v2 protocol)
    info!(
        socket = %args.socket.display(),
        grpc_address = ?args.grpc_address,
        "Starting audit logger agent (v2 protocol)"
    );

    // Configure transport based on CLI options
    let runner = AgentRunnerV2::new(agent)
        .with_name("audit-logger");

    // Start with appropriate transport configuration
    match args.grpc_address {
        Some(grpc_addr) => {
            // Both gRPC and UDS
            info!(
                grpc_address = %grpc_addr,
                uds_socket = %args.socket.display(),
                "Running with gRPC and UDS transports"
            );
            runner
                .with_both(grpc_addr, args.socket)
                .run()
                .await?;
        }
        None => {
            // UDS only (default)
            info!(
                uds_socket = %args.socket.display(),
                "Running with UDS transport only"
            );
            runner
                .with_uds(args.socket)
                .run()
                .await?;
        }
    }

    Ok(())
}
