use anyhow::{Context, Result};
use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};

/// Run an AI agent through GVM governance.
///
/// Three isolation modes:
/// - Default (no flags): runs locally with HTTP_PROXY set to GVM proxy.
/// - --sandbox: Linux-native isolation (namespaces + seccomp + veth). Production recommended.
/// - --contained: Docker-based isolation. Dev/CI or non-Linux platforms.
pub async fn run_agent(
    script: &str,
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
    if sandbox && contained {
        anyhow::bail!("Cannot use --sandbox and --contained together. Choose one isolation mode.");
    }
    if sandbox {
        run_sandboxed(script, agent_id, proxy, interactive).await
    } else if contained {
        run_contained(script, agent_id, proxy, image, memory, cpus, detach).await
    } else {
        run_local(script, agent_id, proxy, interactive).await
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
    let wal_start_len = std::fs::metadata(wal_path)
        .map(|m| m.len())
        .unwrap_or(0);

    // Determine interpreter from extension
    let ext = abs_script.extension()
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
        cmd.arg(script_arg).arg(abs_script.to_str().unwrap_or(script));
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

    let status = cmd.status().await
        .with_context(|| format!("Failed to execute: {} {}", interpreter, script_arg))?;

    println!();
    if status.success() {
        println!("  {GREEN}Agent completed successfully{RESET}");
    } else {
        println!("  {YELLOW}Agent exited with code: {}{RESET}",
            status.code().unwrap_or(-1));
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
async fn run_sandboxed(script: &str, agent_id: &str, proxy: &str, interactive: bool) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM \u{2014} Linux-Native Sandbox (Layer 3){RESET}");
    println!("{DIM}Agent will be isolated using namespaces, seccomp-BPF, and veth networking.{RESET}");
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
    let script_name = abs_script.file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(script)
        .to_string();

    // Determine interpreter from extension
    let ext = abs_script.extension()
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
    let proxy_url: url::Url = proxy.parse()
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
    };

    // Run pre-flight checks
    print!("  {DIM}Running pre-flight checks...{RESET} ");
    let preflight = gvm_sandbox::preflight_check(&config);

    if !preflight.issues.is_empty() {
        println!("{YELLOW}WARNINGS{RESET}");
        for issue in &preflight.issues {
            println!("    {YELLOW}\u{26a0}{RESET} {}", issue);
        }

        // Fail if critical features are missing
        if !preflight.user_namespaces || !preflight.seccomp_available {
            println!();
            println!("  {RED}Cannot proceed: kernel features required for sandbox are unavailable.{RESET}");
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
    let wal_start_len = std::fs::metadata(wal_path)
        .map(|m| m.len())
        .unwrap_or(0);

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
                println!("  {YELLOW}Agent exited with code: {}{RESET}", sandbox_result.exit_code);
            }
            println!("  {DIM}Sandbox setup: {}ms{RESET}", sandbox_result.setup_ms);
            if sandbox_result.seccomp_violations > 0 {
                println!("  {RED}\u{26a0} {} seccomp violation(s) detected{RESET}",
                    sandbox_result.seccomp_violations);
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
    println!("{BOLD}  GVM Audit Trail \u{2014} {} events captured{RESET}", events.len());
    println!("{}", "\u{2501}".repeat(width));
    println!();

    let mut allowed = 0usize;
    let mut delayed = 0usize;
    let mut blocked = 0usize;

    for event in &events {
        let operation = event.get("operation")
            .and_then(|v| v.as_str()).unwrap_or("unknown");
        let decision = event.get("decision")
            .and_then(|v| v.as_str()).unwrap_or("unknown");
        let event_id = event.get("event_id")
            .and_then(|v| v.as_str()).unwrap_or("");
        let host = event.get("transport")
            .and_then(|t| t.get("host"))
            .and_then(|v| v.as_str()).unwrap_or("");
        let method = event.get("transport")
            .and_then(|t| t.get("method"))
            .and_then(|v| v.as_str()).unwrap_or("");

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
            let rule = event.get("matched_rule_id")
                .and_then(|v| v.as_str()).unwrap_or("");
            if !rule.is_empty() {
                println!("    {DIM}Rule: {}  Event: {}{RESET}", rule, &event_id[..8.min(event_id.len())]);
            }
        }
    }

    println!();
    println!("  {GREEN}{} allowed{RESET}  {YELLOW}{} delayed{RESET}  {RED}{} blocked{RESET}",
        allowed, delayed, blocked);

    // Show trace IDs for further investigation
    let trace_ids: std::collections::HashSet<&str> = events.iter()
        .filter_map(|e| e.get("trace_id").and_then(|v| v.as_str()))
        .collect();

    if !trace_ids.is_empty() {
        println!();
        for tid in &trace_ids {
            println!("  {DIM}Full trace:{RESET} {CYAN}gvm events trace --trace-id {}{RESET}", tid);
        }
    }

    println!();
    println!("  {DIM}Full event log:{RESET} {CYAN}gvm events list --agent {}{RESET}", agent_id);
    println!();

    if blocked > 0 {
        println!("  {RED}{BOLD}\u{26a0} {} action(s) were BLOCKED by GVM governance.{RESET}", blocked);
        println!("  {DIM}Review the blocked operations above. Your agent attempted actions{RESET}");
        println!("  {DIM}that violate your security policies.{RESET}");
        println!();
    } else if events.len() > 0 {
        println!("  {GREEN}\u{2713} All {} agent actions were within policy.{RESET}", events.len());
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

    println!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", agent_id);
    println!("  {DIM}Script:{RESET}       {}", abs_script.display());
    println!("  {DIM}Image:{RESET}        {}", image);
    println!("  {DIM}Proxy:{RESET}        {}", proxy);
    println!("  {DIM}Memory:{RESET}       {}", memory);
    println!("  {DIM}CPUs:{RESET}         {}", cpus);
    println!("  {DIM}Network:{RESET}      gvm-internal {DIM}(isolated){RESET}");
    println!();

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

    // Build docker run command
    let container_name = format!("gvm-agent-{}", agent_id);
    let mount_dir = script_dir.to_str().unwrap_or(".");

    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("run")
        .arg("--name").arg(&container_name)
        .arg("--rm")
        .arg("--network").arg("gvm-internal")
        .arg("--read-only")
        .arg("--tmpfs").arg("/tmp")
        .arg("--security-opt").arg("no-new-privileges:true")
        .arg("--memory").arg(memory)
        .arg("--cpus").arg(cpus)
        .arg("-e").arg(format!("GVM_AGENT_ID={}", agent_id))
        .arg("-e").arg(format!("HTTP_PROXY={}", proxy))
        .arg("-e").arg(format!("HTTPS_PROXY={}", proxy))
        .arg("-e").arg(format!("http_proxy={}", proxy))
        .arg("-e").arg(format!("https_proxy={}", proxy))
        .arg("-v").arg(format!("{}:/home/agent/workspace:ro", mount_dir))
        .arg(image)
        .arg(script_name);

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
    println!("    {GREEN}\u{2713}{RESET} Layer 3: OS Containment (network isolation)");
    println!("      {DIM}\u{2022} Network: gvm-internal (no external access){RESET}");
    println!("      {DIM}\u{2022} Filesystem: read-only root{RESET}");
    println!("      {DIM}\u{2022} Privileges: no-new-privileges{RESET}");
    println!("      {DIM}\u{2022} Resources: {} memory, {} CPUs{RESET}", memory, cpus);
    println!();

    if detach {
        let output = cmd.output().await?;
        if output.status.success() {
            let container_id = String::from_utf8_lossy(&output.stdout);
            println!("  {GREEN}Agent started in background{RESET}");
            println!("  Container: {}", container_id.trim());
            println!();
            println!("  {BOLD}Useful commands:{RESET}");
            println!("    {CYAN}docker logs -f {}{RESET}         \u{2014} follow agent output", container_name);
            println!("    {CYAN}docker stop {}{RESET}            \u{2014} stop agent", container_name);
            println!("    {CYAN}gvm events list --agent {}{RESET} \u{2014} view audit trail", agent_id);
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
            println!("  {YELLOW}Agent exited with code: {}{RESET}",
                status.code().unwrap_or(-1));
        }
    }

    println!();
    println!("  {BOLD}Review:{RESET}");
    println!("    {CYAN}gvm events list --agent {}{RESET}", agent_id);
    println!();

    Ok(())
}
