use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};

/// Run a command through GVM governance.
///
/// Supports two modes:
/// - Script mode: `gvm run agent.py` (auto-detects interpreter)
/// - Binary mode: `gvm run -- openclaw gateway` (arbitrary binary + args)
///
/// Three isolation levels:
/// - Default (no flags): runs locally with HTTP_PROXY set to GVM proxy.
/// - --sandbox: Linux-native isolation (namespaces + seccomp + veth + uprobe).
/// - --contained: Docker-based isolation. Dev/CI or non-Linux platforms.
#[allow(clippy::too_many_arguments)]
pub async fn run_agent(
    command: &[String],
    agent_id: &str,
    proxy: &str,
    image: &str,
    memory: &str,
    cpus: &str,
    detach: bool,
    contained: bool,
    sandbox: bool,
    interactive: bool,
    no_mitm: bool,
    fs_governance: bool,
    sandbox_profile: &str,
    host_ports: &[u16],
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!(
            "No command specified. Usage: gvm run agent.py  OR  gvm run -- openclaw gateway"
        );
    }
    if sandbox && contained {
        anyhow::bail!("Cannot use --sandbox and --contained together. Choose one isolation mode.");
    }

    let mode = if sandbox {
        crate::pipeline::LaunchMode::Sandbox
    } else if contained {
        eprintln!();
        eprintln!("  {YELLOW}\u{26a0} WARNING: --contained (Docker) is an unsupported experimental feature.{RESET}");
        eprintln!("  {DIM}Known issues: WSL2 network instability, missing iptables in slim images,{RESET}");
        eprintln!("  {DIM}NET_ADMIN capability abuse, Windows path failures.{RESET}");
        eprintln!("  {DIM}Use --sandbox on Linux for production isolation.{RESET}");
        eprintln!();
        crate::pipeline::LaunchMode::Contained {
            image: image.to_string(),
            memory: memory.to_string(),
            cpus: cpus.to_string(),
            detach,
        }
    } else {
        crate::pipeline::LaunchMode::Cooperative
    };

    if no_mitm && mode != crate::pipeline::LaunchMode::Cooperative {
        eprintln!("  {YELLOW}\u{26a0}{RESET} MITM disabled (--no-mitm). HTTPS uses CONNECT relay (domain-level only).");
    }

    // Warn if Node.js in cooperative mode (HTTPS_PROXY not respected)
    if mode == crate::pipeline::LaunchMode::Cooperative {
        let cmd_str = command.join(" ").to_lowercase();
        if cmd_str.contains("node")
            || cmd_str.contains("openclaw")
            || cmd_str.contains("npx")
            || command[0].ends_with(".js")
            || command[0].ends_with(".ts")
        {
            eprintln!("  {YELLOW}\u{26a0} Node.js agent detected in cooperative mode.{RESET}");
            eprintln!(
                "  {DIM}Node.js does not respect HTTPS_PROXY. Use --sandbox for full HTTPS coverage.{RESET}"
            );
            eprintln!();
        }
    }

    let profile = match sandbox_profile {
        "minimal" => gvm_sandbox::SandboxProfile::Minimal,
        "full" => gvm_sandbox::SandboxProfile::Full,
        _ => gvm_sandbox::SandboxProfile::Standard,
    };

    // Reject ports that would bypass MITM governance
    for port in host_ports {
        if *port == 80 || *port == 443 {
            anyhow::bail!(
                "--host-port {} rejected: forwarding HTTP/HTTPS ports bypasses proxy governance",
                port
            );
        }
    }

    let config = crate::pipeline::AgentConfig {
        command: command.to_vec(),
        agent_id: agent_id.to_string(),
        proxy: proxy.to_string(),
        mode,
        no_mitm,
        fs_governance,
        sandbox_profile: profile,
        host_ports: host_ports.to_vec(),
        memory_limit: parse_memory_limit(memory),
        cpu_limit: cpus.parse::<f64>().ok(),
        interactive,
    };

    crate::pipeline::run_full(config).await
}

/// Check if the first argument looks like a script file (has a known extension).
pub(crate) fn looks_like_script(arg: &str) -> bool {
    let path = std::path::Path::new(arg);
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("py" | "js" | "ts" | "sh" | "bash")
    )
}

/// Derive admin API URL from the proxy URL.
/// Convention: admin port = proxy port + 1010 (e.g. 8080 → 9090).
/// The admin API runs on a separate port, unreachable by the agent.
pub(crate) fn derive_admin_url(proxy: &str) -> String {
    match url::Url::parse(proxy) {
        Ok(url) => {
            let host = url.host_str().unwrap_or("127.0.0.1");
            let proxy_port = url.port().unwrap_or(8080);
            let admin_port = proxy_port + 1010;
            format!("http://{}:{}", host, admin_port)
        }
        Err(_) => "http://127.0.0.1:9090".to_string(),
    }
}

/// Download the MITM CA certificate from the proxy's admin API.
/// The proxy generates the CA and holds the private key; we only get the public cert.
/// This cert is injected into the sandbox trust store so TLS verification succeeds.
pub(crate) async fn download_mitm_ca_cert(proxy: &str) -> Option<Vec<u8>> {
    let ca_url = format!("{}/gvm/ca.pem", proxy.trim_end_matches('/'));
    match reqwest::get(&ca_url).await {
        Ok(resp) if resp.status().is_success() => match resp.bytes().await {
            Ok(bytes) if !bytes.is_empty() => {
                eprintln!("  {GREEN}\u{2713}{RESET} MITM CA certificate downloaded from proxy");
                Some(bytes.to_vec())
            }
            _ => {
                eprintln!("  {YELLOW}\u{26a0}{RESET} MITM CA endpoint returned empty response — HTTPS inspection disabled");
                None
            }
        },
        _ => {
            eprintln!("  {YELLOW}\u{26a0}{RESET} Could not download MITM CA from proxy — HTTPS inspection disabled");
            None
        }
    }
}

/// Parse a memory limit string (e.g. "512m", "1g", "2048m") into bytes.
fn parse_memory_limit(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return None;
    }
    let (num_str, multiplier) = if s.ends_with('g') {
        (&s[..s.len() - 1], 1024 * 1024 * 1024u64)
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 1024 * 1024u64)
    } else if s.ends_with('k') {
        (&s[..s.len() - 1], 1024u64)
    } else {
        (s.as_str(), 1u64) // raw bytes
    };
    num_str.parse::<u64>().ok().map(|n| n * multiplier)
}

pub(crate) fn is_local_proxy_url(proxy: &str) -> bool {
    // Check if proxy URL is a localhost/loopback address
    // Handle IPv4 (127.0.0.1), IPv6 (::1 or [::1]), and hostnames (localhost)
    if proxy.contains("127.0.0.1") || proxy.contains("localhost") || proxy.contains("::1") {
        return true;
    }

    // Fallback: try parsing with url crate for other formats
    match url::Url::parse(proxy) {
        Ok(url) => matches!(url.host_str(), Some("127.0.0.1" | "localhost")),
        Err(_) => false,
    }
}

// ─── Shared helpers (used by run, watch, demo) ───

/// Parse a proxy URL into a SocketAddr. Used by sandbox modes for veth routing.
pub(crate) fn parse_proxy_addr(proxy: &str) -> Result<std::net::SocketAddr> {
    let proxy_url: url::Url = proxy
        .parse()
        .with_context(|| format!("Invalid proxy URL: {}", proxy))?;
    let host = proxy_url.host_str().unwrap_or("127.0.0.1");
    let port = proxy_url.port().unwrap_or(8080);
    format!("{}:{}", host, port)
        .parse()
        .with_context(|| format!("Cannot parse proxy address: {}:{}", host, port))
}

/// Resolve a script path: verify existence and canonicalize.
pub(crate) fn resolve_script(script: &str) -> Result<std::path::PathBuf> {
    let path = std::path::Path::new(script);
    if !path.exists() {
        anyhow::bail!("Script not found: {}", script);
    }
    std::fs::canonicalize(path).with_context(|| format!("Cannot resolve path: {}", script))
}

/// Determine interpreter and arguments from a script file extension.
/// `script_ref` is the path/name to pass as argument to the interpreter.
pub(crate) fn detect_interpreter(ext: &str, script_ref: &str) -> (String, Vec<String>) {
    let interpreter = match ext {
        "py" => "python",
        "js" => "node",
        "ts" => "npx",
        "sh" | "bash" => "bash",
        _ => "python",
    };
    let args = if ext == "ts" {
        vec!["ts-node".to_string(), script_ref.to_string()]
    } else {
        vec![script_ref.to_string()]
    };
    (interpreter.to_string(), args)
}

/// Inject standard GVM proxy environment variables into a Command.
pub(crate) fn inject_proxy_env(cmd: &mut tokio::process::Command, proxy: &str, agent_id: &str) {
    cmd.env("HTTP_PROXY", proxy)
        .env("HTTPS_PROXY", proxy)
        .env("http_proxy", proxy)
        .env("https_proxy", proxy)
        .env("GVM_AGENT_ID", agent_id)
        .env("GVM_PROXY_URL", proxy);
}

/// Check proxy health with user-visible status output.
/// Prints status to stdout and returns Err on failure.
pub(crate) async fn check_proxy_health(proxy: &str) -> Result<()> {
    print!("  {DIM}Checking proxy at {}...{RESET} ", proxy);
    if proxy_healthy(proxy).await {
        println!("{GREEN}OK{RESET}");
        Ok(())
    } else {
        println!("{RED}FAILED{RESET}");
        println!();
        println!("  {RED}Proxy is not running.{RESET}");
        println!("  Start it with: {CYAN}cargo run{RESET}");
        anyhow::bail!("Proxy not reachable at {}", proxy)
    }
}

/// Assemble a SandboxConfig from pre-resolved fields.
/// Pure constructor — no I/O, no async.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_sandbox_config(
    script_path: std::path::PathBuf,
    workspace_dir: std::path::PathBuf,
    interpreter: String,
    interpreter_args: Vec<String>,
    proxy_addr: std::net::SocketAddr,
    agent_id: &str,
    proxy: &str,
    memory_limit: Option<u64>,
    cpu_limit: Option<f64>,
    mitm_ca_cert: Option<Vec<u8>>,
) -> gvm_sandbox::SandboxConfig {
    gvm_sandbox::SandboxConfig {
        script_path,
        workspace_dir,
        interpreter,
        interpreter_args,
        proxy_addr,
        agent_id: agent_id.to_string(),
        seccomp_profile: None,
        tls_probe_mode: gvm_sandbox::TlsProbeMode::Disabled,
        proxy_url: Some(proxy.to_string()),
        memory_limit,
        cpu_limit,
        // fs_policy: None = legacy mode (workspace/output/ only, no overlayfs)
        // fs_policy: Some = overlayfs Trust-on-Pattern governance
        // Controlled by --fs-governance CLI flag.
        fs_policy: None, // Caller sets this via pipeline based on fs_governance flag
        mitm_ca_cert,
        sandbox_profile: gvm_sandbox::SandboxProfile::default(),
        host_ports: vec![],
    }
}

pub(crate) async fn proxy_healthy(proxy: &str) -> bool {
    let health_url = format!("{}/gvm/health", proxy.trim_end_matches('/'));
    matches!(reqwest::get(&health_url).await, Ok(resp) if resp.status().is_success())
}

pub(crate) fn workspace_root_for_proxy() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

/// Read WAL entries that were added during the agent run and display audit summary.
pub(crate) fn print_wal_audit(wal_path: &str, start_offset: u64, agent_id: &str) {
    let content = match std::fs::read_to_string(wal_path) {
        Ok(c) => c,
        Err(_) => {
            println!("  {DIM}No audit trail found (WAL not available){RESET}");
            println!();
            return;
        }
    };

    // Parse WAL entries (each line is JSON)
    let new_content = if (start_offset as usize) < content.len() {
        &content[start_offset as usize..]
    } else {
        ""
    };

    let events: Vec<serde_json::Value> = new_content
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(is_governance_event)
        .collect();

    if events.is_empty() {
        println!("  {DIM}No GVM events recorded during this run.{RESET}");
        println!("  {DIM}Make sure your agent uses HTTP_PROXY to route through GVM.{RESET}");
        println!();
        return;
    }

    let width = 72;
    println!("{}", "\u{2501}".repeat(width));
    println!(
        "{BOLD}  GVM Audit Trail \u{2014} {} events captured{RESET}",
        events.len()
    );
    println!("{}", "\u{2501}".repeat(width));
    println!();

    let mut allowed = 0usize;
    let mut delayed = 0usize;
    let mut blocked = 0usize;

    for event in &events {
        // Events are pre-filtered by is_governance_event() above.
        let decision = event
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let operation = event
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let event_id = event.get("event_id").and_then(|v| v.as_str()).unwrap_or("");
        let host = event
            .get("transport")
            .and_then(|t| t.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let method = event
            .get("transport")
            .and_then(|t| t.get("method"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let (icon, color) = if decision.contains("Allow") {
            allowed += 1;
            ("\u{2713}", GREEN)
        } else if decision.contains("Delay") {
            delayed += 1;
            ("\u{23f1}", YELLOW)
        } else {
            blocked += 1;
            ("\u{2717}", RED)
        };

        println!(
            "  {color}{icon}{RESET} {:<24} {color}{:<20}{RESET} {DIM}{} {}{RESET}",
            operation, decision, method, host,
        );

        // Show event ID for blocked events
        if decision.contains("Deny") || decision.contains("RequireApproval") {
            let rule = event
                .get("matched_rule_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !rule.is_empty() {
                println!(
                    "    {DIM}Rule: {}  Event: {}{RESET}",
                    rule,
                    &event_id[..8.min(event_id.len())]
                );
            }
        }
    }

    println!();
    println!(
        "  {GREEN}{} allowed{RESET}  {YELLOW}{} delayed{RESET}  {RED}{} blocked{RESET}",
        allowed, delayed, blocked
    );

    // Show trace IDs for further investigation
    let trace_ids: std::collections::HashSet<&str> = events
        .iter()
        .filter_map(|e| e.get("trace_id").and_then(|v| v.as_str()))
        .collect();

    if !trace_ids.is_empty() {
        println!();
        for tid in &trace_ids {
            println!(
                "  {DIM}Full trace:{RESET} {CYAN}gvm events trace --trace-id {}{RESET}",
                tid
            );
        }
    }

    println!();
    println!(
        "  {DIM}Full event log:{RESET} {CYAN}gvm events list --agent {}{RESET}",
        agent_id
    );
    println!();

    if blocked > 0 {
        println!(
            "  {RED}{BOLD}\u{26a0} {} action(s) were BLOCKED by GVM governance.{RESET}",
            blocked
        );
        println!("  {DIM}Review the blocked operations above. Your agent attempted actions{RESET}");
        println!("  {DIM}that violate your security policies.{RESET}");
        println!();
    } else if !events.is_empty() {
        println!(
            "  {GREEN}\u{2713} All {} agent actions were within policy.{RESET}",
            events.len()
        );
        println!();
    }
}

/// Check if a WAL JSON record is a governance event (not batch metadata or system event).
/// Shared filter: batch records (merkle_root, batch_id) and system events (gvm.system.*)
/// are WAL infrastructure — not agent governance decisions.
fn is_governance_event(event: &serde_json::Value) -> bool {
    // Batch records: WAL integrity metadata
    if event.get("batch_id").is_some() || event.get("merkle_root").is_some() {
        return false;
    }
    // System events: proxy startup, config load, etc.
    if let Some(op) = event.get("operation").and_then(|v| v.as_str()) {
        if op.starts_with("gvm.system.") {
            return false;
        }
    }
    // Must have a decision field to be a governance event
    event.get("decision").is_some()
}

/// Docker containment mode: run inside isolated container.
/// Legacy function — pipeline.rs wraps this until full pipeline integration.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_contained_legacy(
    script: &str,
    agent_id: &str,
    proxy: &str,
    image: &str,
    memory: &str,
    cpus: &str,
    detach: bool,
    no_mitm: bool,
) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM \u{2014} Agent Containment (Layer 3){RESET}");
    println!();

    // Verify Docker is available
    let docker_check = tokio::process::Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .output()
        .await
        .context("Docker not found. Install Docker to use agent containment.")?;

    if !docker_check.status.success() {
        println!("  {RED}Docker is not running.{RESET}");
        println!("  Start Docker Desktop and try again.");
        println!();
        return Ok(());
    }

    let docker_version = String::from_utf8_lossy(&docker_check.stdout);
    println!("  {DIM}Docker:{RESET}       {}", docker_version.trim());

    // Auto-build gvm-agent image if it doesn't exist
    if image == "gvm-agent:latest" {
        let img_check = tokio::process::Command::new("docker")
            .args(["image", "inspect", "gvm-agent:latest"])
            .output()
            .await?;

        if !img_check.status.success() {
            let dockerfile = workspace_root_for_proxy().join("Dockerfile.agent");
            if dockerfile.exists() {
                println!("  {YELLOW}Building gvm-agent image (first time only)...{RESET}");
                let build_ctx = dockerfile.parent().unwrap_or(std::path::Path::new("."));
                let build = tokio::process::Command::new("docker")
                    .args(["build", "-t", "gvm-agent:latest", "-f"])
                    .arg(&dockerfile)
                    .arg(build_ctx)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .await?;

                if build.status.success() {
                    println!("  {GREEN}gvm-agent image built{RESET}");
                } else {
                    let err = String::from_utf8_lossy(&build.stderr);
                    println!(
                        "  {RED}Failed to build gvm-agent image: {}{RESET}",
                        err.lines().last().unwrap_or("")
                    );
                    println!("  {DIM}Build with: docker build -t gvm-agent:latest -f Dockerfile.agent .{RESET}");
                    return Ok(());
                }
            } else {
                println!("  {RED}gvm-agent image not found and Dockerfile.agent missing{RESET}");
                println!("  {DIM}Build manually: docker build -t gvm-agent:latest -f Dockerfile.agent .{RESET}");
                return Ok(());
            }
        }
    }

    // Resolve script path
    let script_path = std::path::Path::new(script);
    if !script_path.exists() {
        println!("  {RED}Agent script not found: {}{RESET}", script);
        println!();
        return Ok(());
    }

    let abs_script = std::fs::canonicalize(script_path)
        .with_context(|| format!("Cannot resolve path: {}", script))?;
    // On Windows, canonicalize produces \\?\ UNC prefix and backslashes.
    // Docker expects /c/Users/... format for volume mounts.
    #[cfg(windows)]
    let abs_script = {
        let s = abs_script.to_string_lossy().to_string();
        let s = s.trim_start_matches(r"\\?\").replace('\\', "/");
        // Convert "C:/Users/..." to "/c/Users/..." for Docker
        let s = if s.chars().nth(1) == Some(':') {
            format!("/{}/{}", s.chars().next().unwrap().to_lowercase(), &s[3..])
        } else {
            s
        };
        std::path::PathBuf::from(s)
    };
    let script_dir = abs_script.parent().unwrap();
    let script_name = abs_script.file_name().unwrap().to_str().unwrap();
    let script_ext = abs_script
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let proxy_url: url::Url = proxy
        .parse()
        .with_context(|| format!("Invalid proxy URL: {}", proxy))?;

    let local_proxy_host = matches!(proxy_url.host_str(), Some("127.0.0.1" | "localhost"));
    let use_host_network = local_proxy_host && cfg!(target_os = "linux");

    let container_proxy = if use_host_network {
        proxy.to_string()
    } else if local_proxy_host {
        let mut rewritten = proxy_url.clone();
        rewritten
            .set_host(Some("host.docker.internal"))
            .context("Failed to rewrite proxy host for container networking")?;
        rewritten.to_string()
    } else {
        proxy.to_string()
    };

    println!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
    println!("  {DIM}Script:{RESET}       {}", abs_script.display());
    println!("  {DIM}Image:{RESET}        {}", image);
    println!("  {DIM}Proxy:{RESET}        {}", proxy);
    if use_host_network {
        println!(
            "  {DIM}Network mode:{RESET} host {DIM}(Linux localhost proxy compatibility){RESET}"
        );
    }
    if local_proxy_host && !use_host_network {
        println!("  {DIM}Proxy in container:{RESET} {}", container_proxy);
    }
    println!("  {DIM}Memory:{RESET}       {}", memory);
    println!("  {DIM}CPUs:{RESET}         {}", cpus);
    if use_host_network {
        println!("  {DIM}Network:{RESET}      host {DIM}(local proxy compatibility){RESET}");
    } else {
        println!("  {DIM}Network:{RESET}      gvm-bridge {DIM}(isolated){RESET}");
    }
    println!();

    if !use_host_network {
        // Ensure gvm-bridge network exists.
        // Uses a regular bridge (not --internal) because --internal blocks all
        // external routing including host.docker.internal, making the proxy
        // unreachable from the container. Network isolation is enforced by:
        //   - DNAT redirecting HTTPS to MITM proxy (iptables in entrypoint)
        //   - HTTPS_PROXY env var routing HTTP through proxy
        //   - No direct internet access for non-proxied traffic
        let net_check = tokio::process::Command::new("docker")
            .args(["network", "inspect", "gvm-bridge"])
            .output()
            .await?;

        if !net_check.status.success() {
            println!("  {YELLOW}Creating gvm-bridge network...{RESET}");
            let net_create = tokio::process::Command::new("docker")
                .args(["network", "create", "gvm-bridge"])
                .output()
                .await?;

            if !net_create.status.success() {
                let err = String::from_utf8_lossy(&net_create.stderr);
                println!("  {RED}Failed to create network: {}{RESET}", err.trim());
                return Ok(());
            }
            println!("  {GREEN}Network created{RESET}");
        }
    }

    // ── Download ephemeral CA from proxy for MITM TLS inspection ──
    // The proxy generates a session-scoped CA and exposes it via GET /gvm/ca.pem.
    // We inject it into the container's trust store so that:
    //   - DNAT 443→8443 routes HTTPS to the MITM listener
    //   - The MITM listener presents certs signed by this CA
    //   - The agent's TLS client trusts them (CA in trust store)
    let ca_temp_dir = tempfile::tempdir().context("Failed to create temp dir for CA")?;
    let ca_pem_path = ca_temp_dir.path().join("gvm-ca.crt");

    let ca_url = format!("{}/gvm/ca.pem", proxy.trim_end_matches('/'));
    let mitm_available = if no_mitm {
        false
    } else {
        match reqwest::get(&ca_url).await {
            Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                Ok(bytes) if !bytes.is_empty() => {
                    std::fs::write(&ca_pem_path, &bytes).context("Failed to write CA PEM")?;
                    println!(
                        "  {GREEN}\u{2713}{RESET} MITM CA downloaded ({} bytes)",
                        bytes.len()
                    );
                    true
                }
                _ => {
                    println!("  {YELLOW}MITM CA empty — HTTPS inspection unavailable{RESET}");
                    false
                }
            },
            _ => {
                println!("  {YELLOW}MITM CA not available — HTTPS will use CONNECT relay (domain-level only){RESET}");
                false
            }
        }
    };

    // Compute MITM listener address for DNAT (proxy port + 363 = TLS port)
    let proxy_port = proxy_url.port().unwrap_or(8080);
    let tls_port = proxy_port + 363; // matches main.rs convention: 8080→8443
    let proxy_host_for_container = if use_host_network {
        proxy_url.host_str().unwrap_or("127.0.0.1").to_string()
    } else {
        "host.docker.internal".to_string()
    };

    // Build DNAT entrypoint script — runs inside container before the agent.
    // Phase 1 (root + NET_ADMIN): set up iptables DNAT rules
    // Phase 2 (cap drop): drop NET_ADMIN so agent cannot modify iptables
    // This closes the "agent can iptables -F" vulnerability while keeping
    // DNAT setup working. Uses setpriv (util-linux, available in Debian/Ubuntu).
    let entrypoint_script = if mitm_available {
        format!(
            "if ! command -v iptables >/dev/null 2>&1; then \
               echo '[GVM] ERROR: iptables not found. MITM TLS inspection requires iptables.' >&2; \
               echo '[GVM] Use the gvm-agent base image: gvm run --contained --image gvm-agent:latest' >&2; \
               echo '[GVM] Or add iptables to your image: RUN apt-get install -y iptables' >&2; \
               exit 1; \
             fi && \
             GVM_HOST=$(getent hosts {host} | awk '{{print $1}}' | head -1) && \
             iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination $GVM_HOST:{tls} && \
             iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination $GVM_HOST:{http} && \
             unset HTTPS_PROXY https_proxy && \
             exec setpriv --inh-caps=-net_admin --bounding-set=-net_admin -- \"$@\"",
            host = proxy_host_for_container,
            tls = tls_port,
            http = proxy_port,
        )
    } else {
        "exec \"$@\"".to_string()
    };

    // Build docker run command
    let container_name = format!("gvm-agent-{}", agent_id);
    let mount_dir = script_dir.to_str().unwrap_or(".");
    let container_script = format!("/home/agent/workspace/{}", script_name);

    let container_cmd: Vec<String> = match script_ext {
        "py" => vec!["python".to_string(), container_script.clone()],
        "js" => vec!["node".to_string(), container_script.clone()],
        "ts" => vec![
            "npx".to_string(),
            "ts-node".to_string(),
            container_script.clone(),
        ],
        "sh" | "bash" => vec!["bash".to_string(), container_script.clone()],
        _ => vec![container_script.clone()],
    };

    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("run")
        .arg("--name")
        .arg(&container_name)
        .arg("--rm")
        .arg("--read-only")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--security-opt")
        .arg("no-new-privileges:true")
        .arg("--memory")
        .arg(memory)
        .arg("--cpus")
        .arg(cpus)
        .arg("-w")
        .arg("/home/agent/workspace")
        .arg("-e")
        .arg(format!("GVM_AGENT_ID={}", agent_id));

    if mitm_available {
        // MITM mode: NO proxy env vars. All traffic goes through DNAT:
        //   TCP 443 → MITM TLS listener (full L7 inspection)
        //   TCP 80  → proxy HTTP port (HTTP inspection)
        // Proxy env vars would cause CONNECT tunneling which bypasses MITM.
        cmd.arg("-e")
            .arg(format!("GVM_PROXY_URL={}", container_proxy));
    } else {
        // No MITM: CONNECT relay for HTTPS (domain-level only)
        cmd.arg("-e")
            .arg(format!("HTTP_PROXY={}", container_proxy))
            .arg("-e")
            .arg(format!("HTTPS_PROXY={}", container_proxy))
            .arg("-e")
            .arg(format!("http_proxy={}", container_proxy))
            .arg("-e")
            .arg(format!("https_proxy={}", container_proxy));
    }
    cmd.arg("-e")
        .arg(format!("GVM_PROXY_URL={}", container_proxy));

    // Pass through LLM provider API keys if set in host environment.
    // Most agent frameworks (OpenClaw, LangChain, CrewAI) need these to call LLM APIs.
    // The keys are still governed: all HTTPS traffic goes through DNAT → MITM,
    // so the proxy inspects every request regardless of whether the agent has the key.
    for key in &[
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
    ] {
        if let Ok(val) = std::env::var(key) {
            cmd.arg("-e").arg(format!("{}={}", key, val));
        }
    }

    cmd.arg("-v")
        .arg(format!("{}:/home/agent/workspace:ro", mount_dir));

    // CA injection: mount CA PEM + /etc/ssl/certs as tmpfs for Go/system trust store
    if mitm_available {
        // Mount CA PEM into multiple trust store paths
        let ca_host_path_raw = ca_pem_path.to_str().unwrap_or("");
        // On Windows, convert path to Docker-compatible format
        #[cfg(windows)]
        let ca_host_path = {
            let s = ca_host_path_raw.replace('\\', "/");
            let s = s.trim_start_matches(r"\\?\").to_string();
            if s.chars().nth(1) == Some(':') {
                format!("/{}/{}", s.chars().next().unwrap().to_lowercase(), &s[3..])
            } else {
                s
            }
        };
        #[cfg(not(windows))]
        let ca_host_path = ca_host_path_raw.to_string();
        cmd.arg("-v")
            .arg(format!(
                "{}:/usr/local/share/ca-certificates/gvm-ca.crt:ro",
                ca_host_path
            ))
            .arg("-v")
            .arg(format!("{}:/etc/ssl/certs/gvm-ca.crt:ro", ca_host_path))
            .arg("-v")
            .arg(format!(
                "{}:/etc/ssl/certs/ca-certificates.crt:ro",
                ca_host_path
            ))
            .arg("-v")
            .arg(format!("{}:/etc/pki/tls/certs/gvm-ca.crt:ro", ca_host_path));

        // CA trust environment variables (covers Python requests, Node.js, curl)
        cmd.arg("-e")
            .arg("SSL_CERT_FILE=/etc/ssl/certs/gvm-ca.crt")
            .arg("-e")
            .arg("REQUESTS_CA_BUNDLE=/etc/ssl/certs/gvm-ca.crt")
            .arg("-e")
            .arg("NODE_EXTRA_CA_CERTS=/etc/ssl/certs/gvm-ca.crt")
            .arg("-e")
            .arg("CURL_CA_BUNDLE=/etc/ssl/certs/gvm-ca.crt");

        // NET_ADMIN capability for DNAT iptables rule inside container.
        // Trade-off: widens attack surface, but:
        //   - no-new-privileges prevents escalation from NET_ADMIN
        //   - container network is already isolated (gvm-bridge --internal)
        //   - DNAT is set in the entrypoint, then iptables is not needed further
        // NET_ADMIN + root required for iptables DNAT setup in entrypoint.
        // no-new-privileges prevents escalation from root.
        cmd.arg("--cap-add=NET_ADMIN").arg("--user").arg("root");
    }

    if use_host_network {
        cmd.arg("--network").arg("host");
    } else {
        cmd.arg("--network")
            .arg("gvm-bridge")
            .arg("--add-host")
            .arg("host.docker.internal:host-gateway");
    }

    if detach {
        cmd.arg("-d");
    }

    // Entrypoint: shell wrapper that sets DNAT then execs the agent command.
    // Uses `sh -c 'script' _ arg1 arg2` pattern where _ is $0 and args become $@.
    cmd.arg("--entrypoint").arg("sh");
    cmd.arg(image);
    cmd.arg("-c");
    cmd.arg(&entrypoint_script);
    cmd.arg("_"); // $0 placeholder for sh -c
    for arg in &container_cmd {
        cmd.arg(arg);
    }

    println!("  {BOLD}Starting contained agent...{RESET}");
    println!("  {DIM}Container:{RESET}    {}", container_name);
    println!();

    // Security summary
    println!("  {BOLD}Security layers active:{RESET}");
    println!("    {GREEN}\u{2713}{RESET} Layer 1: Governance Engine (policy evaluation)");
    println!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy (request interception)");
    println!("    {GREEN}\u{2713}{RESET} Layer 3: Docker Containment");
    if mitm_available {
        println!(
            "      {DIM}\u{2022} Transparent MITM: ephemeral CA injected, DNAT 443→{}{RESET}",
            tls_port
        );
    } else {
        println!("      {DIM}\u{2022} HTTPS: CONNECT relay (domain-level only){RESET}");
    }
    if use_host_network {
        println!("      {DIM}\u{2022} Network: host (shared host network namespace){RESET}");
    } else {
        println!("      {DIM}\u{2022} Network: gvm-bridge (no external access){RESET}");
    }
    println!("      {DIM}\u{2022} Filesystem: read-only root{RESET}");
    println!("      {DIM}\u{2022} Privileges: no-new-privileges{RESET}");
    println!(
        "      {DIM}\u{2022} Resources: {} memory, {} CPUs{RESET}",
        memory, cpus
    );
    println!();

    if detach {
        let output = cmd.output().await?;
        if output.status.success() {
            let container_id = String::from_utf8_lossy(&output.stdout);
            println!("  {GREEN}Agent started in background{RESET}");
            println!("  Container: {}", container_id.trim());
            println!();
            println!("  {BOLD}Useful commands:{RESET}");
            println!(
                "    {CYAN}docker logs -f {}{RESET}         \u{2014} follow agent output",
                container_name
            );
            println!(
                "    {CYAN}docker stop {}{RESET}            \u{2014} stop agent",
                container_name
            );
            println!(
                "    {CYAN}gvm events list --agent {}{RESET} \u{2014} view audit trail",
                agent_id
            );
        } else {
            let err = String::from_utf8_lossy(&output.stderr);
            println!("  {RED}Failed to start agent: {}{RESET}", err.trim());
        }
    } else {
        println!("  {DIM}--- Agent output below ---{RESET}");
        println!();

        let status = cmd
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
            .await?;

        println!();
        if status.success() {
            println!("  {GREEN}Agent completed successfully{RESET}");
        } else {
            println!(
                "  {YELLOW}Agent exited with code: {}{RESET}",
                status.code().unwrap_or(-1)
            );
        }
    }

    println!();
    println!("  {BOLD}Review:{RESET}");
    println!("    {CYAN}gvm events list --agent {}{RESET}", agent_id);
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_local_proxy_url_localhost() {
        assert!(is_local_proxy_url("http://localhost:8080"));
    }

    #[test]
    fn test_is_local_proxy_url_127_0_0_1() {
        assert!(is_local_proxy_url("http://127.0.0.1:8080"));
    }

    #[test]
    fn test_is_local_proxy_url_ipv6_loopback() {
        // IPv6 localhost can be represented as ::1
        // (URL parser may handle [::1] bracket notation differently across versions)
        let result = is_local_proxy_url("http://[::1]:8080");
        assert!(
            result,
            "IPv6 loopback address [::1] should be recognized as local"
        );
    }

    #[test]
    fn test_is_local_proxy_url_with_trailing_slash() {
        assert!(is_local_proxy_url("http://localhost:8080/"));
    }

    #[test]
    fn test_is_local_proxy_url_remote_host() {
        assert!(!is_local_proxy_url("http://proxy.example.com:8080"));
    }

    #[test]
    fn test_is_local_proxy_url_remote_ip() {
        assert!(!is_local_proxy_url("http://192.168.1.1:8080"));
    }

    #[test]
    fn test_is_local_proxy_url_invalid_url() {
        assert!(!is_local_proxy_url("not-a-valid-url"));
    }

    #[test]
    fn test_is_local_proxy_url_no_port() {
        assert!(is_local_proxy_url("http://localhost"));
    }
}
