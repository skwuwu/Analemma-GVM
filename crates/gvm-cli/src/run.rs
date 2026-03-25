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
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!(
            "No command specified. Usage: gvm run agent.py  OR  gvm run -- openclaw gateway"
        );
    }
    if sandbox && contained {
        anyhow::bail!("Cannot use --sandbox and --contained together. Choose one isolation mode.");
    }

    // Determine mode: script (single file) or binary (arbitrary command)
    let is_binary_mode = command.len() > 1 || !looks_like_script(&command[0]);
    let script = &command[0];

    ensure_proxy_available(proxy).await?;

    if sandbox {
        let mem_limit = parse_memory_limit(memory);
        let cpu_limit = cpus.parse::<f64>().ok();
        if is_binary_mode {
            run_binary_sandboxed(command, agent_id, proxy, interactive, mem_limit, cpu_limit).await
        } else {
            run_sandboxed(script, agent_id, proxy, interactive, mem_limit, cpu_limit).await
        }
    } else if contained {
        run_contained(script, agent_id, proxy, image, memory, cpus, detach).await
    } else if is_binary_mode {
        run_binary_local(command, agent_id, proxy, interactive).await
    } else {
        run_local(script, agent_id, proxy, interactive).await
    }
}

/// Check if the first argument looks like a script file (has a known extension).
pub(crate) fn looks_like_script(arg: &str) -> bool {
    let path = std::path::Path::new(arg);
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("py" | "js" | "ts" | "sh" | "bash")
    )
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

/// Run an arbitrary binary with GVM proxy environment (Layer 2 only).
///
/// Example: `gvm run -- openclaw gateway`
async fn run_binary_local(
    command: &[String],
    agent_id: &str,
    proxy: &str,
    interactive: bool,
) -> Result<()> {
    let binary = &command[0];
    let args = &command[1..];

    // All GVM banner/status output goes to stderr to keep stdout clean
    // for the child process output (piping, JSON parsing, etc.)
    eprintln!();
    eprintln!("{BOLD}Analemma GVM \u{2014} Binary Mode (Layer 2){RESET}");
    eprintln!("{DIM}All outbound HTTP/HTTPS routed through GVM proxy.{RESET}");
    eprintln!();
    eprintln!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
    eprintln!("  {DIM}Command:{RESET}      {} {}", binary, args.join(" "));
    eprintln!("  {DIM}Proxy:{RESET}        {}", proxy);
    eprintln!();

    eprintln!("  {BOLD}Security layers active:{RESET}");
    eprintln!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy (HTTPS_PROXY)");
    eprintln!("    {DIM}\u{25cb}{RESET} Layer 3: OS Containment {DIM}(add --sandbox for kernel isolation){RESET}");
    eprintln!();

    let wal_path = "data/wal.log";
    let wal_start_len = std::fs::metadata(wal_path).map(|m| m.len()).unwrap_or(0);

    eprintln!("  {DIM}--- Output below ---{RESET}");
    eprintln!();

    // Run agent, watchdog, and IC-3 approval poller in parallel
    let proxy_url = proxy.to_string();
    let watchdog_handle = tokio::spawn(proxy_watchdog(proxy_url));

    let (approval_cancel_tx, approval_cancel_rx) = tokio::sync::watch::channel(false);
    let approval_proxy = proxy.to_string();
    let approval_handle = tokio::spawn(async move {
        crate::approve::poll_and_prompt_background(&approval_proxy, approval_cancel_rx).await;
    });

    let status = tokio::process::Command::new(binary)
        .args(args)
        .env("HTTP_PROXY", proxy)
        .env("HTTPS_PROXY", proxy)
        .env("http_proxy", proxy)
        .env("https_proxy", proxy)
        .env("GVM_AGENT_ID", agent_id)
        .env("GVM_PROXY_URL", proxy)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("Failed to execute: {}", binary))?;

    // Abort background tasks when agent exits
    watchdog_handle.abort();
    let _ = approval_cancel_tx.send(true);
    approval_handle.abort();

    eprintln!();
    if status.success() {
        eprintln!("  {GREEN}Process completed successfully{RESET}");
    } else {
        eprintln!(
            "  {YELLOW}Process exited with code: {}{RESET}",
            status.code().unwrap_or(-1)
        );
    }
    eprintln!();

    // WAL audit goes to stderr in binary mode to keep stdout clean for piping
    // Use `gvm events list` for detailed audit inspection
    let events_count = std::fs::metadata(wal_path)
        .map(|m| m.len().saturating_sub(wal_start_len))
        .unwrap_or(0);
    if events_count > 0 {
        eprintln!(
            "  {DIM}WAL: {} new bytes recorded. Run: gvm events list{RESET}",
            events_count
        );
    }

    if interactive {
        crate::suggest::suggest_rules_interactive(
            wal_path,
            wal_start_len,
            "config/srr_network.toml",
        );
    }
    Ok(())
}

/// Run an arbitrary binary inside Linux-native sandbox (Layer 2 + 3).
///
/// Example: `gvm run --sandbox -- openclaw gateway`
async fn run_binary_sandboxed(
    command: &[String],
    agent_id: &str,
    proxy: &str,
    _interactive: bool,
    memory_limit: Option<u64>,
    cpu_limit: Option<f64>,
) -> Result<()> {
    let binary = &command[0];
    let args = &command[1..];

    eprintln!();
    eprintln!("{BOLD}Analemma GVM \u{2014} Binary Sandbox Mode (Layer 2 + 3){RESET}");
    eprintln!("{DIM}Kernel isolation: namespace + seccomp + veth + uprobe.{RESET}");
    eprintln!();
    eprintln!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
    eprintln!("  {DIM}Command:{RESET}      {} {}", binary, args.join(" "));
    eprintln!("  {DIM}Proxy:{RESET}        {}", proxy);
    eprintln!();

    // Resolve binary path
    let binary_path =
        which::which(binary).with_context(|| format!("Binary not found: {}", binary))?;

    let proxy_url: url::Url = proxy
        .parse()
        .with_context(|| format!("Invalid proxy URL: {}", proxy))?;
    let proxy_host = proxy_url.host_str().unwrap_or("127.0.0.1");
    let proxy_port = proxy_url.port().unwrap_or(8080);
    let proxy_addr: std::net::SocketAddr = format!("{}:{}", proxy_host, proxy_port)
        .parse()
        .with_context(|| format!("Cannot parse proxy address: {}:{}", proxy_host, proxy_port))?;

    let config = gvm_sandbox::SandboxConfig {
        script_path: binary_path.clone(),
        workspace_dir: std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        interpreter: binary_path.to_str().unwrap_or(binary).to_string(),
        interpreter_args: args.iter().map(|s| s.to_string()).collect(),
        proxy_addr,
        agent_id: agent_id.to_string(),
        seccomp_profile: None,
        tls_probe_mode: gvm_sandbox::TlsProbeMode::Disabled,
        proxy_url: Some(proxy.to_string()),
        memory_limit,
        cpu_limit,
        fs_policy: Some(gvm_sandbox::FilesystemPolicy::default()),
    };

    eprintln!("  {BOLD}Security layers active:{RESET}");
    eprintln!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy");
    eprintln!("    {GREEN}\u{2713}{RESET} Layer 3: Linux Namespace Isolation");
    eprintln!("      {DIM}\u{2022} PID namespace: isolated process tree{RESET}");
    eprintln!("      {DIM}\u{2022} Mount namespace: minimal rootfs{RESET}");
    eprintln!("      {DIM}\u{2022} Network namespace: veth pair, proxy-only routing{RESET}");
    eprintln!("      {DIM}\u{2022} Seccomp-BPF: syscall whitelist{RESET}");
    eprintln!("      {DIM}\u{2022} Transparent MITM: ephemeral CA, full L7 HTTPS inspection{RESET}");
    eprintln!();
    eprintln!("  {DIM}--- Output below ---{RESET}");
    eprintln!();

    // Run sandbox and proxy watchdog in parallel.
    // Sandbox blocks on waitpid (sync) — wrap in spawn_blocking.
    // Watchdog polls /gvm/health and restarts proxy on crash.
    let proxy_url = proxy.to_string();
    let sandbox_task = tokio::task::spawn_blocking(move || {
        gvm_sandbox::launch_sandboxed(config)
    });

    let watchdog_handle = tokio::spawn(proxy_watchdog(proxy_url));

    // Wait for sandbox to finish (primary task)
    let result = sandbox_task.await.unwrap_or_else(|e| Err(anyhow::anyhow!("Sandbox task panicked: {e}")));

    // Abort watchdog when sandbox exits
    watchdog_handle.abort();

    eprintln!();
    match result {
        Ok(sr) => {
            if sr.exit_code == 0 {
                eprintln!("  {GREEN}Process completed successfully{RESET}");
            } else {
                eprintln!(
                    "  {YELLOW}Process exited with code: {}{RESET}",
                    sr.exit_code
                );
            }
            eprintln!("  {DIM}Sandbox setup: {}ms{RESET}", sr.setup_ms);
        }
        Err(e) => {
            eprintln!("  {RED}Sandbox execution failed: {}{RESET}", e);
            eprintln!("  {DIM}Try without --sandbox, or use --contained for Docker.{RESET}");
        }
    }
    eprintln!();
    Ok(())
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

pub(crate) async fn proxy_healthy(proxy: &str) -> bool {
    let health_url = format!("{}/gvm/health", proxy.trim_end_matches('/'));
    matches!(reqwest::get(&health_url).await, Ok(resp) if resp.status().is_success())
}

/// Background proxy watchdog: polls `/gvm/health` every 3 seconds.
///
/// Restart policy:
/// - **unreachable** (ECONNREFUSED/timeout): restart after 3 consecutive failures
/// - **degraded** (HTTP 200 but status="degraded"): log warning, do NOT restart
///   (WAL degraded + restart = worse state)
/// - Maximum 3 restarts before giving up
///
/// NOTE: After proxy restart, sandbox agent's in-flight connections are broken.
/// The agent will see ECONNREFUSED until the new proxy binds to the same port.
/// The next request from the agent will succeed on the new proxy instance.
/// If the agent's HTTP client does not retry, the agent may crash — this is
/// the agent's responsibility, not GVM's. Document this limitation.
pub(crate) async fn proxy_watchdog(proxy_url: String) {
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
    const MAX_RESTARTS: u32 = 3;
    const FAILURES_BEFORE_RESTART: u32 = 3;

    let mut consecutive_failures: u32 = 0;
    let mut restarts: u32 = 0;

    // Wait a bit for initial proxy startup
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        let health_url = format!("{}/gvm/health", proxy_url.trim_end_matches('/'));
        match reqwest::get(&health_url).await {
            Ok(resp) if resp.status().is_success() => {
                // Check if degraded
                if let Ok(body) = resp.text().await {
                    if body.contains("\"degraded\"") {
                        if consecutive_failures == 0 {
                            // Log once when entering degraded state
                            eprintln!(
                                "  \x1b[1;33mWATCHDOG\x1b[0m: proxy is degraded (WAL issue) — \
                                 monitoring but NOT restarting"
                            );
                        }
                    }
                }
                consecutive_failures = 0;
            }
            _ => {
                consecutive_failures += 1;
                if consecutive_failures >= FAILURES_BEFORE_RESTART {
                    if restarts >= MAX_RESTARTS {
                        eprintln!(
                            "  \x1b[0;31mWATCHDOG\x1b[0m: proxy unreachable, max restarts ({}) \
                             exceeded — giving up",
                            MAX_RESTARTS
                        );
                        return;
                    }

                    eprintln!(
                        "  \x1b[1;33mWATCHDOG\x1b[0m: proxy unreachable ({} consecutive failures) \
                         — attempting restart ({}/{})",
                        consecutive_failures,
                        restarts + 1,
                        MAX_RESTARTS
                    );

                    match ensure_proxy_available(&proxy_url).await {
                        Ok(()) => {
                            restarts += 1;
                            consecutive_failures = 0;
                            eprintln!(
                                "  \x1b[0;32mWATCHDOG\x1b[0m: proxy restarted successfully \
                                 (restart {}/{})",
                                restarts, MAX_RESTARTS
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "  \x1b[0;31mWATCHDOG\x1b[0m: proxy restart failed: {}",
                                e
                            );
                            restarts += 1;
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn workspace_root_for_proxy() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

pub(crate) async fn ensure_proxy_available(proxy: &str) -> Result<()> {
    if proxy_healthy(proxy).await {
        return Ok(());
    }

    if !is_local_proxy_url(proxy) {
        anyhow::bail!(
            "Proxy is not reachable at {}. For non-local proxy URLs, start it manually and retry.",
            proxy
        );
    }

    println!(
        "  {YELLOW}Proxy not reachable at {}. Attempting auto-start...{RESET}",
        proxy
    );

    let workspace_root = workspace_root_for_proxy();
    let mut child = tokio::process::Command::new("cargo")
        .arg("run")
        .arg("-p")
        .arg("gvm-proxy")
        .current_dir(workspace_root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("Failed to spawn gvm-proxy with cargo")?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        if proxy_healthy(proxy).await {
            println!("  {GREEN}Proxy auto-started successfully.{RESET}");
            return Ok(());
        }

        if let Some(status) = child
            .try_wait()
            .context("Failed to poll auto-started proxy process")?
        {
            anyhow::bail!(
                "Auto-started proxy exited early (status: {}). Start it manually with `cargo run -p gvm-proxy`.",
                status
            );
        }

        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Timed out waiting for proxy startup at {}. Start it manually with `cargo run -p gvm-proxy`.",
                proxy
            );
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Simple mode: run the script locally with HTTP_PROXY pointing to GVM.
/// After the script exits, read WAL and display audit summary.
async fn run_local(script: &str, agent_id: &str, proxy: &str, interactive: bool) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM \u{2014} Agent Governance Monitor{RESET}");
    println!("{DIM}All HTTP traffic will be routed through GVM proxy for governance.{RESET}");
    println!();

    // Check proxy health
    print!("  {DIM}Checking proxy at {}...{RESET} ", proxy);
    let health_url = format!("{}/gvm/health", proxy);
    match reqwest::get(&health_url).await {
        Ok(resp) if resp.status().is_success() => {
            println!("{GREEN}OK{RESET}");
        }
        _ => {
            println!("{RED}FAILED{RESET}");
            println!();
            println!("  {RED}Proxy is not running.{RESET}");
            println!("  Start it with: {CYAN}cargo run{RESET}");
            println!();
            return Ok(());
        }
    }

    // Resolve script path
    let script_path = std::path::Path::new(script);
    if !script_path.exists() {
        println!("  {RED}Script not found: {}{RESET}", script);
        println!();
        return Ok(());
    }

    let abs_script = std::fs::canonicalize(script_path)
        .with_context(|| format!("Cannot resolve path: {}", script))?;

    println!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
    println!("  {DIM}Script:{RESET}       {}", abs_script.display());
    println!("  {DIM}Proxy:{RESET}        {}", proxy);
    println!("  {DIM}Mode:{RESET}         local {DIM}(Layer 2 only \u{2014} use --sandbox or --contained for Layer 3){RESET}");
    println!();

    // Security summary
    println!("  {BOLD}Security layers active:{RESET}");
    println!("    {GREEN}\u{2713}{RESET} Layer 1: Governance Engine (policy evaluation)");
    println!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy (request interception)");
    println!("    {DIM}\u{25cb}{RESET} Layer 3: OS Containment {DIM}(add --sandbox for Linux or --contained for Docker){RESET}");
    println!();

    // Record WAL position before run (to show only new events)
    let wal_path = "data/wal.log";
    let wal_start_len = std::fs::metadata(wal_path).map(|m| m.len()).unwrap_or(0);

    // Determine interpreter from extension
    let ext = abs_script
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let (interpreter, script_arg) = match ext {
        "py" => ("python", abs_script.to_str().unwrap_or(script)),
        "js" => ("node", abs_script.to_str().unwrap_or(script)),
        "ts" => ("npx", "ts-node"),
        "sh" | "bash" => ("bash", abs_script.to_str().unwrap_or(script)),
        _ => ("python", abs_script.to_str().unwrap_or(script)),
    };

    println!("  {DIM}--- Agent output below ---{RESET}");
    println!();

    let script_dir = abs_script.parent().unwrap_or(std::path::Path::new("."));

    let mut cmd = tokio::process::Command::new(interpreter);
    if ext == "ts" {
        cmd.arg(script_arg)
            .arg(abs_script.to_str().unwrap_or(script));
    } else {
        cmd.arg(script_arg);
    }

    cmd.current_dir(script_dir)
        .env("HTTP_PROXY", proxy)
        .env("HTTPS_PROXY", proxy)
        .env("http_proxy", proxy)
        .env("https_proxy", proxy)
        .env("GVM_AGENT_ID", agent_id)
        .env("GVM_PROXY_URL", proxy)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    // Run agent, watchdog, and IC-3 approval poller in parallel
    let proxy_url = proxy.to_string();
    let watchdog_handle = tokio::spawn(proxy_watchdog(proxy_url));

    let (approval_cancel_tx, approval_cancel_rx) = tokio::sync::watch::channel(false);
    let approval_proxy = proxy.to_string();
    let approval_handle = tokio::spawn(async move {
        crate::approve::poll_and_prompt_background(&approval_proxy, approval_cancel_rx).await;
    });

    let status = cmd
        .status()
        .await
        .with_context(|| format!("Failed to execute: {} {}", interpreter, script_arg))?;

    // Abort background tasks when agent exits
    watchdog_handle.abort();
    let _ = approval_cancel_tx.send(true);
    approval_handle.abort();

    println!();
    if status.success() {
        println!("  {GREEN}Agent completed successfully{RESET}");
    } else {
        println!(
            "  {YELLOW}Agent exited with code: {}{RESET}",
            status.code().unwrap_or(-1)
        );
    }
    println!();

    // ── Read WAL for audit trail ──
    print_wal_audit(wal_path, wal_start_len, agent_id);

    // ── Interactive SRR rule suggestions ──
    if interactive {
        crate::suggest::suggest_rules_interactive(
            wal_path,
            wal_start_len,
            "config/srr_network.toml",
        );
    }

    Ok(())
}

/// Linux-native sandbox mode: run inside namespace + seccomp isolation.
/// Production-recommended on Linux. No Docker required.
async fn run_sandboxed(script: &str, agent_id: &str, proxy: &str, interactive: bool, memory_limit: Option<u64>, cpu_limit: Option<f64>) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM \u{2014} Linux-Native Sandbox (Layer 3){RESET}");
    println!(
        "{DIM}Agent will be isolated using namespaces, seccomp-BPF, and veth networking.{RESET}"
    );
    println!();

    // Check proxy health
    print!("  {DIM}Checking proxy at {}...{RESET} ", proxy);
    let health_url = format!("{}/gvm/health", proxy);
    match reqwest::get(&health_url).await {
        Ok(resp) if resp.status().is_success() => {
            println!("{GREEN}OK{RESET}");
        }
        _ => {
            println!("{RED}FAILED{RESET}");
            println!();
            println!("  {RED}Proxy is not running.{RESET}");
            println!("  Start it with: {CYAN}cargo run{RESET}");
            println!();
            return Ok(());
        }
    }

    // Resolve script path
    let script_path = std::path::Path::new(script);
    if !script_path.exists() {
        println!("  {RED}Script not found: {}{RESET}", script);
        println!();
        return Ok(());
    }

    let abs_script = std::fs::canonicalize(script_path)
        .with_context(|| format!("Cannot resolve path: {}", script))?;
    let script_dir = abs_script.parent().unwrap_or(std::path::Path::new("."));
    let script_name = abs_script
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(script)
        .to_string();

    // Determine interpreter from extension
    let ext = abs_script
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let interpreter = match ext {
        "py" => "python",
        "js" => "node",
        "ts" => "npx",
        "sh" | "bash" => "bash",
        _ => "python",
    };

    let interpreter_args = if ext == "ts" {
        vec!["ts-node".to_string(), script_name.clone()]
    } else {
        vec![script_name.clone()]
    };

    // Parse proxy address for sandbox config
    let proxy_url: url::Url = proxy
        .parse()
        .with_context(|| format!("Invalid proxy URL: {}", proxy))?;
    let proxy_host = proxy_url.host_str().unwrap_or("127.0.0.1");
    let proxy_port = proxy_url.port().unwrap_or(8080);
    let proxy_addr: std::net::SocketAddr = format!("{}:{}", proxy_host, proxy_port)
        .parse()
        .with_context(|| format!("Cannot parse proxy address: {}:{}", proxy_host, proxy_port))?;

    let config = gvm_sandbox::SandboxConfig {
        script_path: abs_script.clone(),
        workspace_dir: script_dir.to_path_buf(),
        interpreter: interpreter.to_string(),
        interpreter_args,
        proxy_addr,
        agent_id: agent_id.to_string(),
        seccomp_profile: None,
        tls_probe_mode: gvm_sandbox::TlsProbeMode::Disabled,
        proxy_url: Some(proxy.to_string()),
        memory_limit,
        cpu_limit,
        fs_policy: Some(gvm_sandbox::FilesystemPolicy::default()),
    };

    // Clean up orphaned network from previous crash (if any)
    match gvm_sandbox::cleanup_orphaned_network() {
        Ok(true) => eprintln!("  {YELLOW}Cleaned up orphaned sandbox network from previous crash{RESET}"),
        Ok(false) => {} // No orphans
        Err(e) => eprintln!("  {DIM}Orphan cleanup: {e}{RESET}"),
    }

    // Run pre-flight checks
    print!("  {DIM}Running pre-flight checks...{RESET} ");
    let preflight = gvm_sandbox::preflight_check(&config);

    let missing_critical = !preflight.user_namespaces
        || !preflight.seccomp_available
        || !preflight.net_admin_capability
        || !preflight.ip_command_available
        || !preflight.iptables_command_available
        || !preflight.interpreter_found;

    if !preflight.issues.is_empty() {
        println!("{YELLOW}WARNINGS{RESET}");
        for issue in &preflight.issues {
            println!("    {YELLOW}\u{26a0}{RESET} {}", issue);
        }

        // Fail if critical features are missing
        if missing_critical {
            println!();
            println!(
                "  {RED}Cannot proceed: required sandbox prerequisites are unavailable.{RESET}"
            );
            println!("  {DIM}Use --contained for Docker-based isolation instead.{RESET}");
            println!();
            return Ok(());
        }
    } else {
        println!("{GREEN}OK{RESET}");
    }

    println!();
    println!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
    println!("  {DIM}Script:{RESET}       {}", abs_script.display());
    println!("  {DIM}Proxy:{RESET}        {}", proxy);
    println!("  {DIM}Mode:{RESET}         sandbox {DIM}(Linux-native isolation){RESET}");
    println!();

    // Security summary
    println!("  {BOLD}Security layers active:{RESET}");
    println!("    {GREEN}\u{2713}{RESET} Layer 1: Governance Engine (policy evaluation)");
    println!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy (request interception)");
    println!("    {GREEN}\u{2713}{RESET} Layer 3: OS Containment (Linux-native sandbox)");
    println!("      {DIM}\u{2022} User namespace: UID remapping{RESET}");
    println!("      {DIM}\u{2022} PID namespace: isolated process tree{RESET}");
    println!("      {DIM}\u{2022} Mount namespace: read-only workspace, minimal rootfs{RESET}");
    println!("      {DIM}\u{2022} Network namespace: veth pair, proxy-only routing{RESET}");
    println!("      {DIM}\u{2022} Seccomp-BPF: syscall whitelist (~45 calls){RESET}");
    println!();

    // Record WAL position before run
    let wal_path = "data/wal.log";
    let wal_start_len = std::fs::metadata(wal_path).map(|m| m.len()).unwrap_or(0);

    println!("  {DIM}--- Agent output below ---{RESET}");
    println!();

    // Launch the sandboxed agent (blocking call — waits for agent to exit)
    let result = gvm_sandbox::launch_sandboxed(config);

    println!();
    match result {
        Ok(sandbox_result) => {
            if sandbox_result.exit_code == 0 {
                println!("  {GREEN}Agent completed successfully{RESET}");
            } else {
                println!(
                    "  {YELLOW}Agent exited with code: {}{RESET}",
                    sandbox_result.exit_code
                );
            }
            println!("  {DIM}Sandbox setup: {}ms{RESET}", sandbox_result.setup_ms);
            if sandbox_result.seccomp_violations > 0 {
                println!(
                    "  {RED}\u{26a0} {} seccomp violation(s) detected{RESET}",
                    sandbox_result.seccomp_violations
                );
            }
        }
        Err(e) => {
            println!("  {RED}Sandbox execution failed: {}{RESET}", e);
            println!();
            println!("  {DIM}If this is not a Linux system, use --contained for Docker isolation.{RESET}");
        }
    }
    println!();

    // Read WAL for audit trail
    print_wal_audit(wal_path, wal_start_len, agent_id);

    // Interactive SRR rule suggestions
    if interactive {
        crate::suggest::suggest_rules_interactive(
            wal_path,
            wal_start_len,
            "config/srr_network.toml",
        );
    }

    Ok(())
}

/// Read WAL entries that were added during the agent run and display audit summary.
fn print_wal_audit(wal_path: &str, start_offset: u64, agent_id: &str) {
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
        .filter_map(|line| serde_json::from_str(line).ok())
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
        let operation = event
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let decision = event
            .get("decision")
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

/// Docker containment mode: run inside isolated container.
async fn run_contained(
    script: &str,
    agent_id: &str,
    proxy: &str,
    image: &str,
    memory: &str,
    cpus: &str,
    detach: bool,
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

    // Resolve script path
    let script_path = std::path::Path::new(script);
    if !script_path.exists() {
        println!("  {RED}Agent script not found: {}{RESET}", script);
        println!();
        return Ok(());
    }

    let abs_script = std::fs::canonicalize(script_path)
        .with_context(|| format!("Cannot resolve path: {}", script))?;
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
        println!("  {DIM}Network:{RESET}      gvm-internal {DIM}(isolated){RESET}");
    }
    println!();

    if !use_host_network {
        // Ensure gvm-internal network exists
        let net_check = tokio::process::Command::new("docker")
            .args(["network", "inspect", "gvm-internal"])
            .output()
            .await?;

        if !net_check.status.success() {
            println!("  {YELLOW}Creating gvm-internal network (isolated)...{RESET}");
            let net_create = tokio::process::Command::new("docker")
                .args(["network", "create", "--internal", "gvm-internal"])
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
    let ca_temp_dir = tempfile::tempdir()
        .context("Failed to create temp dir for CA")?;
    let ca_pem_path = ca_temp_dir.path().join("gvm-ca.crt");

    let ca_url = format!("{}/gvm/ca.pem", proxy.trim_end_matches('/'));
    let mitm_available = match reqwest::get(&ca_url).await {
        Ok(resp) if resp.status().is_success() => {
            match resp.bytes().await {
                Ok(bytes) if !bytes.is_empty() => {
                    std::fs::write(&ca_pem_path, &bytes)
                        .context("Failed to write CA PEM")?;
                    println!("  {GREEN}\u{2713}{RESET} MITM CA downloaded ({} bytes)", bytes.len());
                    true
                }
                _ => {
                    println!("  {YELLOW}MITM CA empty — HTTPS inspection unavailable{RESET}");
                    false
                }
            }
        }
        _ => {
            println!("  {YELLOW}MITM CA not available — HTTPS will use CONNECT relay (domain-level only){RESET}");
            false
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

    // Build DNAT entrypoint script — runs inside container before the agent
    // Redirects all outbound 443 traffic to the proxy's MITM listener.
    // Requires NET_ADMIN capability (added to docker run below).
    let entrypoint_script = if mitm_available {
        format!(
            "iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination {}:{} 2>/dev/null || true && exec \"$@\"",
            proxy_host_for_container, tls_port,
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
        .arg(format!("GVM_AGENT_ID={}", agent_id))
        .arg("-e")
        .arg(format!("HTTP_PROXY={}", container_proxy))
        .arg("-e")
        .arg(format!("HTTPS_PROXY={}", container_proxy))
        .arg("-e")
        .arg(format!("http_proxy={}", container_proxy))
        .arg("-e")
        .arg(format!("https_proxy={}", container_proxy))
        .arg("-v")
        .arg(format!("{}:/home/agent/workspace:ro", mount_dir));

    // CA injection: mount CA PEM + /etc/ssl/certs as tmpfs for Go/system trust store
    if mitm_available {
        // Mount CA PEM into multiple trust store paths
        let ca_host_path = ca_pem_path.to_str().unwrap_or("");
        cmd.arg("-v")
            .arg(format!("{}:/usr/local/share/ca-certificates/gvm-ca.crt:ro", ca_host_path))
            .arg("-v")
            .arg(format!("{}:/etc/ssl/certs/gvm-ca.crt:ro", ca_host_path))
            .arg("-v")
            .arg(format!("{}:/etc/pki/tls/certs/gvm-ca.crt:ro", ca_host_path));

        // CA trust environment variables (covers Python requests, Node.js, curl)
        cmd.arg("-e").arg("SSL_CERT_FILE=/etc/ssl/certs/gvm-ca.crt")
            .arg("-e").arg("REQUESTS_CA_BUNDLE=/etc/ssl/certs/gvm-ca.crt")
            .arg("-e").arg("NODE_EXTRA_CA_CERTS=/etc/ssl/certs/gvm-ca.crt")
            .arg("-e").arg("CURL_CA_BUNDLE=/etc/ssl/certs/gvm-ca.crt");

        // NET_ADMIN capability for DNAT iptables rule inside container.
        // Trade-off: widens attack surface, but:
        //   - no-new-privileges prevents escalation from NET_ADMIN
        //   - container network is already isolated (gvm-internal --internal)
        //   - DNAT is set in the entrypoint, then iptables is not needed further
        cmd.arg("--cap-add=NET_ADMIN");
    }

    if use_host_network {
        cmd.arg("--network").arg("host");
    } else {
        cmd.arg("--network")
            .arg("gvm-internal")
            .arg("--add-host")
            .arg("host.docker.internal:host-gateway");
    }

    // Entrypoint: shell wrapper that sets DNAT then execs the agent command
    cmd.arg("--entrypoint").arg("sh");
    cmd.arg(image);
    cmd.arg("-c");
    // Build the full command: entrypoint_script uses "exec $@" pattern
    let agent_cmd_str = container_cmd
        .iter()
        .map(|s| format!("\"{}\"", s))
        .collect::<Vec<_>>()
        .join(" ");
    cmd.arg(format!("{} -- {}", entrypoint_script, agent_cmd_str));

    if detach {
        cmd.arg("-d");
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
        println!("      {DIM}\u{2022} Transparent MITM: ephemeral CA injected, DNAT 443→{}{RESET}", tls_port);
    } else {
        println!("      {DIM}\u{2022} HTTPS: CONNECT relay (domain-level only){RESET}");
    }
    if use_host_network {
        println!("      {DIM}\u{2022} Network: host (shared host network namespace){RESET}");
    } else {
        println!("      {DIM}\u{2022} Network: gvm-internal (no external access){RESET}");
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
