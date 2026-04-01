use clap::{Parser, Subcommand};

mod approve;
mod audit;
mod check;
mod demo;
mod events;
mod init;
mod pipeline;
mod proxy_manager;
mod run;
mod stats;
mod suggest;
mod ui;
mod watch;

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

    /// Cost tracking and governance statistics
    Stats {
        #[command(subcommand)]
        action: StatsAction,
    },

    /// WAL integrity verification and event export
    Audit {
        #[command(subcommand)]
        action: AuditAction,
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

    /// Run a command through GVM governance (proxy + audit trail).
    ///
    /// Supports scripts and arbitrary binaries:
    ///   gvm run agent.py                          # auto-detect interpreter
    ///   gvm run -- openclaw gateway               # arbitrary binary
    ///   gvm run --sandbox -- openclaw gateway      # with kernel isolation
    ///   gvm run --contained -- python agent.py     # with Docker
    Run {
        /// Command to run. Can be a script (auto-detects interpreter) or
        /// arbitrary binary args after `--` (e.g. `-- openclaw gateway`).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,

        /// Agent ID for audit trail
        #[arg(long, default_value = "agent-001")]
        agent_id: String,

        /// GVM proxy URL
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy: String,

        /// Interactive mode: suggest SRR rules for unregistered URLs after the run.
        #[arg(long, short = 'i')]
        interactive: bool,

        /// Use Linux-native sandbox (Layer 3: namespace + seccomp isolation).
        #[arg(long)]
        sandbox: bool,

        /// Use Docker containment (Layer 3: network isolation).
        #[arg(long)]
        contained: bool,

        /// Docker image (only with --contained)
        #[arg(long, default_value = "gvm-agent:latest")]
        image: String,

        /// Memory limit (--contained: Docker limit; --sandbox: cgroup v2 limit).
        /// Format: "512m", "1g", "2048m". Default: 512m.
        #[arg(long, default_value = "512m")]
        memory: String,

        /// CPU limit (--contained: Docker CPU quota; --sandbox: cgroup v2 cpu.max).
        /// Format: fraction of one CPU (e.g. "1.0" = 1 CPU, "0.5" = half). Default: 1.0.
        #[arg(long, default_value = "1.0")]
        cpus: String,

        /// Disable MITM TLS inspection. HTTPS uses CONNECT relay (domain-level only).
        /// Sandbox/contained isolation, seccomp, WAL audit still active.
        /// Use when: mTLS endpoints, certificate pinning, or policy prohibits MITM.
        #[arg(long)]
        no_mitm: bool,

        /// Run in background (only with --contained)
        #[arg(long)]
        detach: bool,

        /// Override the default policy for unmatched URLs (overrides proxy.toml setting).
        /// "delay" = allow after delay (dev), "require_approval" = hold for human (prod),
        /// "deny" = block immediately (lockdown).
        #[arg(long)]
        default_policy: Option<String>,
    },

    /// Monitor and respond to pending IC-3 approval requests.
    ///
    /// Polls the proxy for pending approval requests and presents them
    /// interactively for human approval or denial.
    ///
    ///   gvm approve                        # interactive approval prompt
    ///   gvm approve --auto-deny            # auto-deny all pending after timeout
    Approve {
        /// GVM admin API URL (separate from agent-facing proxy port).
        #[arg(long, default_value = "http://127.0.0.1:9090")]
        admin: String,

        /// Poll interval in seconds
        #[arg(long, default_value = "2")]
        poll_interval: u64,

        /// Auto-deny all pending requests (non-interactive, for CI)
        #[arg(long)]
        auto_deny: bool,
    },

    /// Watch an agent's API calls in real-time (observation only, no enforcement).
    ///
    /// By default, all requests are allowed through (no blocking). Use --with-rules
    /// to apply existing SRR rules while observing.
    ///
    ///   gvm watch agent.py                     # observe all API calls
    ///   gvm watch -- node my_agent.js           # arbitrary binary
    ///   gvm watch --with-rules agent.py         # observe with existing rules active
    ///   gvm watch --output json agent.py        # JSON output for piping/CI
    Watch {
        /// Command to run (same syntax as `gvm run`).
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,

        /// Agent ID for audit trail
        #[arg(long, default_value = "agent-001")]
        agent_id: String,

        /// GVM proxy URL
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy: String,

        /// Apply existing SRR rules while watching (default: allow all, observe only).
        #[arg(long)]
        with_rules: bool,

        /// Use Linux-native sandbox for observation.
        #[arg(long)]
        sandbox: bool,

        /// Use Docker containment for observation.
        #[arg(long)]
        contained: bool,

        /// Disable MITM TLS inspection (domain-level only).
        #[arg(long)]
        no_mitm: bool,

        /// Docker image (only with --contained)
        #[arg(long, default_value = "gvm-agent:latest")]
        image: String,

        /// Docker memory limit (only with --contained)
        #[arg(long, default_value = "512m")]
        memory: String,

        /// Docker CPU limit (only with --contained)
        #[arg(long, default_value = "1.0")]
        cpus: String,

        /// Output format: text (default) or json
        #[arg(long, default_value = "text")]
        output: String,
    },

    /// Clean up orphaned sandbox resources (veth, iptables, mounts, cgroups).
    ///
    /// Scans for state files from previously crashed sandbox sessions and
    /// removes all orphaned resources. Also removes any veth-gvm-* interfaces
    /// without corresponding state files (defense-in-depth).
    ///
    ///   gvm cleanup                   # clean up and report
    ///   gvm cleanup --dry-run         # show what would be cleaned
    Cleanup {
        /// Show what would be cleaned without actually cleaning.
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate SRR rules from watch session JSON log.
    ///
    /// Reads a watch session log (--output json) and generates TOML rules
    /// for all URLs that hit Default-to-Caution (no explicit SRR rule).
    ///
    ///   gvm suggest --from session.jsonl --output new-rules.toml
    ///   gvm suggest --from session.jsonl --decision allow    # all Allow
    ///   gvm suggest --from session.jsonl --decision delay    # all Delay(300ms)
    Suggest {
        /// Path to watch session JSON log file (one JSON event per line).
        #[arg(long = "from")]
        from_file: String,

        /// Output TOML file for generated rules (default: stdout).
        #[arg(long, short)]
        output: Option<String>,

        /// Default decision for all rules: allow, delay, deny (default: allow).
        #[arg(long, default_value = "allow")]
        decision: String,
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

        /// Filter by decision type (e.g. "Deny", "Delay", "Allow")
        #[arg(long)]
        decision: Option<String>,
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

#[derive(Subcommand)]
enum StatsAction {
    /// Per-agent token usage and governance summary
    Tokens {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,

        /// Time window (e.g. "1h", "24h", "7d")
        #[arg(long, default_value = "24h")]
        since: String,

        /// Read events from WAL file instead of NATS
        #[arg(long)]
        wal_file: Option<String>,
    },

    /// Show tokens saved by governance (denied LLM calls)
    RollbackSavings {
        /// Time window
        #[arg(long, default_value = "24h")]
        since: String,

        /// Read events from WAL file instead of NATS
        #[arg(long)]
        wal_file: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Verify WAL file integrity
    Verify {
        /// Path to WAL file
        #[arg(long)]
        wal: String,
    },

    /// Export events as JSON or JSONL
    Export {
        /// Time window (e.g. "1h", "7d")
        #[arg(long, default_value = "7d")]
        since: String,

        /// Path to WAL file
        #[arg(long)]
        wal: String,

        /// Output format: json or jsonl
        #[arg(long, default_value = "json")]
        format: String,
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
                decision,
            } => {
                events::list_events(
                    agent,
                    &last,
                    wal_file.as_deref(),
                    &format,
                    decision.as_deref(),
                )
                .await?;
            }
            EventsAction::Trace { trace_id, wal_file } => {
                events::trace_events(&trace_id, wal_file.as_deref()).await?;
            }
        },

        Commands::Stats { action } => match action {
            StatsAction::Tokens {
                agent,
                since,
                wal_file,
            } => {
                stats::show_token_stats(agent, &since, wal_file.as_deref()).await?;
            }
            StatsAction::RollbackSavings { since, wal_file } => {
                stats::show_rollback_savings(&since, wal_file.as_deref()).await?;
            }
        },

        Commands::Audit { action } => match action {
            AuditAction::Verify { wal } => {
                audit::verify_wal(&wal).await?;
            }
            AuditAction::Export { since, wal, format } => {
                audit::export_events(&since, &wal, &format).await?;
            }
        },

        Commands::Init {
            industry,
            config_dir,
        } => {
            init::run_init(&industry, &config_dir)?;
        }

        Commands::Demo {
            scenario,
            proxy,
            mock_port,
        } => {
            demo::run_demo(&proxy, mock_port, scenario.as_deref()).await?;
        }

        Commands::Run {
            command,
            agent_id,
            proxy,
            interactive,
            sandbox,
            contained,
            no_mitm,
            image,
            memory,
            cpus,
            detach,
            default_policy,
        } => {
            // Set env var for proxy to pick up (overrides proxy.toml default_unknown)
            if let Some(ref policy) = default_policy {
                std::env::set_var("GVM_DEFAULT_UNKNOWN", policy);
            }
            run::run_agent(
                &command,
                &agent_id,
                &proxy,
                &image,
                &memory,
                &cpus,
                detach,
                contained,
                sandbox,
                interactive,
                no_mitm,
            )
            .await?;
        }

        Commands::Approve {
            admin,
            poll_interval,
            auto_deny,
        } => {
            approve::run_approve(&admin, poll_interval, auto_deny).await?;
        }

        Commands::Watch {
            command,
            agent_id,
            proxy,
            with_rules,
            sandbox,
            contained,
            no_mitm,
            image,
            memory,
            cpus,
            output,
        } => {
            watch::run_watch(
                &command, &agent_id, &proxy, with_rules, sandbox, contained, no_mitm, &image,
                &memory, &cpus, &output,
            )
            .await?;
        }

        Commands::Cleanup { dry_run } => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = dry_run;
                eprintln!("Sandbox cleanup is only supported on Linux.");
            }
            #[cfg(target_os = "linux")]
            {
                if dry_run {
                    eprintln!("Scanning for orphaned sandbox resources (dry run)...");
                    let pattern = "/tmp/gvm-sandbox-*.state";
                    let mut found = 0u32;
                    for entry in
                        glob::glob(pattern).unwrap_or_else(|_| glob::glob("").unwrap())
                    {
                        if let Ok(path) = entry {
                            if let Ok(content) = std::fs::read_to_string(&path) {
                                if let Ok(state) =
                                    serde_json::from_str::<serde_json::Value>(&content)
                                {
                                    let pid = state["pid"].as_u64().unwrap_or(0) as u32;
                                    let alive =
                                        unsafe { libc::kill(pid as i32, 0) == 0 };
                                    let status =
                                        if alive { "ACTIVE" } else { "ORPHANED" };
                                    eprintln!(
                                        "  {} PID={} veth={} mounts={}",
                                        status,
                                        pid,
                                        state["veth_host"].as_str().unwrap_or("?"),
                                        state["mount_paths"]
                                            .as_array()
                                            .map(|a| a.len())
                                            .unwrap_or(0),
                                    );
                                    if !alive {
                                        found += 1;
                                    }
                                }
                            }
                        }
                    }
                    if found == 0 {
                        eprintln!("No orphaned sandboxes found.");
                    } else {
                        eprintln!("{} orphaned sandbox(es) would be cleaned.", found);
                    }
                } else {
                    eprintln!("Cleaning up orphaned sandbox resources...");
                    match gvm_sandbox::cleanup_all_orphans() {
                        Ok(0) => eprintln!("No orphaned sandboxes found."),
                        Ok(n) => eprintln!("Cleaned up {} orphaned sandbox(es).", n),
                        Err(e) => eprintln!("Cleanup error: {:#}", e),
                    }
                }
            }
        }

        Commands::Suggest {
            from_file,
            output,
            decision,
        } => {
            suggest::suggest_rules_batch(&from_file, output.as_deref(), &decision);
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
            check::run_check(
                &operation,
                &service,
                &tier,
                &sensitivity,
                &host,
                &method,
                &proxy,
            )
            .await?;
        }
    }

    Ok(())
}
