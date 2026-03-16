use clap::{Parser, Subcommand};

mod check;
mod demo;
mod events;
mod init;
mod run;
mod suggest;
mod ui;

#[derive(Parser)]
#[command(name = "gvm", version, about = "Analemma GVM — governance CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Query and inspect audit events
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },

    /// Run interactive demo: finance, assistant, devops, data
    Demo {
        /// Scenario name (finance, assistant, devops, data)
        scenario: Option<String>,

        /// Proxy URL
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy: String,

        /// Mock server port
        #[arg(long, default_value = "9090")]
        mock_port: u16,
    },

    /// Initialize or customize config from industry templates
    Init {
        /// Industry template: finance, saas
        #[arg(long)]
        industry: String,

        /// Config output directory
        #[arg(long, default_value = "config")]
        config_dir: String,
    },

    /// Run an agent through GVM governance (proxy + audit trail)
    Run {
        /// Path to agent script (e.g. agent.py)
        script: String,

        /// Agent ID for audit trail
        #[arg(long, default_value = "agent-001")]
        agent_id: String,

        /// GVM proxy URL
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy: String,

        /// Interactive mode: suggest SRR rules for unregistered URLs after the run.
        /// When Default-to-Caution triggers, prompts you to add an explicit rule.
        #[arg(long, short = 'i')]
        interactive: bool,

        /// Use Linux-native sandbox (Layer 3: namespace + seccomp isolation).
        /// Recommended for production on Linux. No Docker required.
        #[arg(long)]
        sandbox: bool,

        /// Use Docker containment (Layer 3: network isolation).
        /// Alternative to --sandbox for dev/CI or non-Linux platforms.
        #[arg(long)]
        contained: bool,

        /// Docker image (only with --contained)
        #[arg(long, default_value = "python:3.12-slim")]
        image: String,

        /// Memory limit (only with --contained)
        #[arg(long, default_value = "512m")]
        memory: String,

        /// CPU limit (only with --contained)
        #[arg(long, default_value = "1.0")]
        cpus: String,

        /// Run in background (only with --contained)
        #[arg(long)]
        detach: bool,
    },

    /// Dry-run policy check without calling external APIs
    Check {
        /// Operation name (e.g. "gvm.payment.charge")
        #[arg(long)]
        operation: String,

        /// Resource service
        #[arg(long, default_value = "unknown")]
        service: String,

        /// Resource tier: internal, external, customer-facing
        #[arg(long, default_value = "external")]
        tier: String,

        /// Sensitivity: low, medium, high, critical
        #[arg(long, default_value = "medium")]
        sensitivity: String,

        /// Target host for SRR check
        #[arg(long, default_value = "example.com")]
        host: String,

        /// HTTP method for SRR check
        #[arg(long, default_value = "POST")]
        method: String,

        /// Proxy URL
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy: String,
    },
}

#[derive(Subcommand)]
enum EventsAction {
    /// List recent events
    List {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,

        /// Time window (e.g. "1h", "30m", "7d")
        #[arg(long, default_value = "1h")]
        last: String,

        /// Read events from WAL file instead of NATS
        #[arg(long)]
        wal_file: Option<String>,

        /// Output format: table or json
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Show causal chain for a trace
    Trace {
        /// Trace ID to follow
        #[arg(long)]
        trace_id: String,

        /// Read events from WAL file instead of NATS
        #[arg(long)]
        wal_file: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Events { action } => match action {
            EventsAction::List {
                agent,
                last,
                wal_file,
                format,
            } => {
                events::list_events(agent, &last, wal_file.as_deref(), &format).await?;
            }
            EventsAction::Trace {
                trace_id,
                wal_file,
            } => {
                events::trace_events(&trace_id, wal_file.as_deref()).await?;
            }
        },

        Commands::Init { industry, config_dir } => {
            init::run_init(&industry, &config_dir)?;
        }

        Commands::Demo { scenario, proxy, mock_port } => {
            demo::run_demo(&proxy, mock_port, scenario.as_deref()).await?;
        }

        Commands::Run {
            script,
            agent_id,
            proxy,
            interactive,
            sandbox,
            contained,
            image,
            memory,
            cpus,
            detach,
        } => {
            run::run_agent(&script, &agent_id, &proxy, &image, &memory, &cpus, detach, contained, sandbox, interactive).await?;
        }

        Commands::Check {
            operation,
            service,
            tier,
            sensitivity,
            host,
            method,
            proxy,
        } => {
            check::run_check(&operation, &service, &tier, &sensitivity, &host, &method, &proxy)
                .await?;
        }
    }

    Ok(())
}
