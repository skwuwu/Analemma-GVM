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
/// - --sandbox: Linux-native isolation (namespaces + seccomp + veth + TC filter).
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
) -> Result<i32> {
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
        crate::pipeline::LaunchMode::Contained {
            image: image.to_string(),
            memory: memory.to_string(),
            cpus: cpus.to_string(),
            detach,
        }
    } else {
        crate::pipeline::LaunchMode::Cooperative
    };

    // MITM is only available in --sandbox mode (Linux kernel namespace +
    // veth-level DNAT). Docker mode does not support MITM — the DNAT +
    // CA injection approach was unstable across WSL2 / slim images and
    // has been removed. Silently ignore --no-mitm in Docker mode, warn
    // only when it would change sandbox behavior.
    if no_mitm && mode == crate::pipeline::LaunchMode::Sandbox {
        eprintln!("  {YELLOW}\u{26a0}{RESET} MITM disabled (--no-mitm). HTTPS uses CONNECT relay (domain-level only).");
    }
    if matches!(mode, crate::pipeline::LaunchMode::Contained { .. }) {
        eprintln!(
            "  {DIM}Note: Docker mode uses SNI-level SRR (no MITM payload inspection). \
             Use --sandbox on Linux for full HTTPS L7 inspection.{RESET}"
        );
    }

    // Warn if Node.js in cooperative mode (HTTPS_PROXY not respected)
    if mode == crate::pipeline::LaunchMode::Cooperative {
        warn_if_node_cooperative(command);
    }

    let profile = match sandbox_profile {
        "minimal" => gvm_sandbox::SandboxProfile::Minimal,
        "full" => gvm_sandbox::SandboxProfile::Full,
        _ => gvm_sandbox::SandboxProfile::Standard,
    };

    let config = crate::pipeline::AgentConfig {
        command: command.to_vec(),
        agent_id: agent_id.to_string(),
        proxy: proxy.to_string(),
        mode,
        no_mitm,
        fs_governance,
        sandbox_profile: profile,
        memory_limit: parse_memory_limit(memory),
        cpu_limit: cpus.parse::<f64>().ok(),
        interactive,
        suppress_output: false,
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
///
/// Picks the first interpreter that actually exists in PATH from a list of
/// candidates. Modern distros (Ubuntu 22.04+, Debian 12+) ship `python3` but
/// not `python`, so naively returning `"python"` would break sandbox preflight
/// on default installs. Falls through to the first candidate when none are
/// found so the caller still gets a name to surface in the error message.
pub(crate) fn detect_interpreter(ext: &str, script_ref: &str) -> (String, Vec<String>) {
    let candidates: &[&str] = match ext {
        "py" => &["python3", "python"],
        "js" => &["node"],
        "ts" => &["npx"],
        "sh" | "bash" => &["bash"],
        _ => &["python3", "python"],
    };
    let interpreter = candidates
        .iter()
        .find(|c| gvm_sandbox::which_interpreter(c).is_some())
        .copied()
        .unwrap_or(candidates[0])
        .to_string();
    let args = if ext == "ts" {
        vec!["ts-node".to_string(), script_ref.to_string()]
    } else {
        vec![script_ref.to_string()]
    };
    (interpreter, args)
}

/// Detect Node.js-based agents and warn that the standard `HTTPS_PROXY` env
/// variable is silently ignored by Node's `http`/`https` modules and `undici`,
/// so cooperative-mode interception will miss most or all of the agent's
/// outbound HTTPS traffic. The recommended path is `--sandbox` (Linux), which
/// rewrites traffic at the kernel level. Called by both the enforce and watch
/// code paths so the warning fires consistently regardless of how the agent
/// was launched.
pub(crate) fn warn_if_node_cooperative(command: &[String]) {
    if command.is_empty() {
        return;
    }
    let cmd_str = command.join(" ").to_lowercase();
    let looks_like_node = cmd_str.contains("node")
        || cmd_str.contains("openclaw")
        || cmd_str.contains("npx")
        || command[0].ends_with(".js")
        || command[0].ends_with(".ts")
        || command[0].ends_with(".cmd"); // Windows npm shim wrapping a Node binary
    if looks_like_node {
        eprintln!("  {YELLOW}\u{26a0} Node.js agent detected in cooperative mode.{RESET}");
        eprintln!(
            "  {DIM}Node.js does not respect HTTPS_PROXY. Use --sandbox for full HTTPS coverage.{RESET}"
        );
        eprintln!();
    }
}

/// Inject standard GVM proxy environment variables into a Command.
pub(crate) fn inject_proxy_env(cmd: &mut tokio::process::Command, proxy: &str, agent_id: &str) {
    cmd.env("HTTP_PROXY", proxy)
        .env("HTTPS_PROXY", proxy)
        .env("http_proxy", proxy)
        .env("https_proxy", proxy)
        .env("NO_PROXY", "127.0.0.1,localhost,::1")
        .env("no_proxy", "127.0.0.1,localhost,::1")
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
    memory_limit: Option<u64>,
    cpu_limit: Option<f64>,
    mitm_ca_cert: Option<Vec<u8>>,
) -> gvm_sandbox::SandboxConfig {
    // Generate placeholder API key env vars from secrets.toml so agents that
    // validate credentials at startup don't refuse to start. The proxy strips
    // these placeholders and injects real credentials post-enforcement.
    let extra_env = load_placeholder_env_vars();

    gvm_sandbox::SandboxConfig {
        script_path,
        workspace_dir,
        interpreter,
        interpreter_args,
        proxy_addr,
        agent_id: agent_id.to_string(),
        seccomp_profile: None,
        memory_limit,
        cpu_limit,
        fs_policy: None, // Caller sets this via pipeline based on fs_governance flag
        mitm_ca_cert,
        sandbox_profile: gvm_sandbox::SandboxProfile::default(),
        extra_env,
    }
}

/// Load credentials and generate placeholder env vars for agent startup.
///
/// Checks gvm.toml first (unified config), then falls back to secrets.toml.
/// Generates dummy values that satisfy agent startup validation (non-empty,
/// correct prefix) without exposing real keys. The proxy strips these and
/// injects real credentials post-enforcement.
fn load_placeholder_env_vars() -> Vec<(String, String)> {
    // Try gvm.toml first
    let gvm_candidates = ["gvm.toml", "config/gvm.toml"];
    for gvm_path in &gvm_candidates {
        let path = std::path::Path::new(gvm_path);
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(parsed) = toml::from_str::<toml::Value>(&content) {
                    if let Some(credentials) = parsed.get("credentials").and_then(|c| c.as_table())
                    {
                        if !credentials.is_empty() {
                            return generate_placeholder_vars(credentials);
                        }
                    }
                }
            }
        }
    }

    // Fallback to secrets.toml
    let secrets_path = std::path::Path::new("config/secrets.toml");
    if !secrets_path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(secrets_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let parsed: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let credentials = match parsed.get("credentials").and_then(|c| c.as_table()) {
        Some(t) => t,
        None => return Vec::new(),
    };

    generate_placeholder_vars(credentials)
}

/// Generate placeholder env vars from a credential table.
fn generate_placeholder_vars(
    credentials: &toml::map::Map<String, toml::Value>,
) -> Vec<(String, String)> {
    let mut env_vars = Vec::new();
    for (host, cred) in credentials {
        let cred_type = cred
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("Bearer");

        let (env_name, placeholder) = match host.as_str() {
            h if h.contains("stripe.com") => (
                "STRIPE_API_KEY".into(),
                "sk_test_gvm_placeholder_do_not_use".into(),
            ),
            h if h.contains("openai.com") => (
                "OPENAI_API_KEY".into(),
                "sk-gvm-placeholder-do-not-use".into(),
            ),
            h if h.contains("anthropic.com") => (
                "ANTHROPIC_API_KEY".into(),
                "sk-ant-gvm-placeholder-do-not-use".into(),
            ),
            h if h.contains("slack.com") => (
                "SLACK_BOT_TOKEN".into(),
                "xoxb-gvm-placeholder-do-not-use".into(),
            ),
            h if h.contains("sendgrid.") => (
                "SENDGRID_API_KEY".into(),
                "SG.gvm-placeholder-do-not-use".into(),
            ),
            h if h.contains("github.com") => (
                "GITHUB_TOKEN".into(),
                "ghp_gvm_placeholder_do_not_use_000000".into(),
            ),
            _ => {
                let name = host
                    .replace("api.", "")
                    .replace(".com", "")
                    .replace(".io", "")
                    .replace(['.', '-'], "_")
                    .to_uppercase();
                (
                    format!("{}_API_KEY", name),
                    format!("gvm-placeholder-{}-{}", cred_type.to_lowercase(), name),
                )
            }
        };
        env_vars.push((env_name, placeholder));
    }
    env_vars
}

pub(crate) async fn proxy_healthy(proxy: &str) -> bool {
    let health_url = format!("{}/gvm/health", proxy.trim_end_matches('/'));
    matches!(reqwest::get(&health_url).await, Ok(resp) if resp.status().is_success())
}

/// Resolve the workspace root for proxy startup at runtime.
///
/// Priority:
///   1. `GVM_WORKSPACE` env var (explicit override)
///   2. Current working directory if it contains `config/operation_registry.toml`
///   3. Directory containing the running executable (unpacked release archive)
///   4. Fallback: current working directory (downstream surfaces a clean
///      "config not found" error if it really is missing)
///
/// Compile-time `env!("CARGO_MANIFEST_DIR")` was previously used here, which
/// baked the build host's path into release binaries — breaking every
/// distributed artifact (e.g. GitHub Actions runner paths leaking into the
/// Windows release zip). Resolution is now fully runtime-driven.
pub(crate) fn workspace_root_for_proxy() -> std::path::PathBuf {
    // Detect workspace by presence of gvm.toml or config/srr_network.toml
    let markers: &[&str] = &[
        "gvm.toml",
        "config/gvm.toml",
        "config/srr_network.toml",
        "config/proxy.toml",
    ];

    let has_marker =
        |dir: &std::path::Path| -> bool { markers.iter().any(|m| dir.join(m).exists()) };

    if let Ok(p) = std::env::var("GVM_WORKSPACE") {
        let path = std::path::PathBuf::from(p);
        if has_marker(&path) {
            return path;
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        if has_marker(&cwd) {
            return cwd;
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            if has_marker(dir) {
                return dir.to_path_buf();
            }
        }
    }

    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
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

    // Each request that hits a Delay/RequireApproval rule produces TWO WAL
    // entries with the same event_id: one with status=Pending (written before
    // the request is forwarded, IC-2 fail-close audit) and one with the final
    // status=Confirmed/Failed (written after the upstream response). Without
    // dedup the audit summary inflates the counts: 1 actual call shows up as
    // "2 delayed". Dedup by event_id, keeping the LAST occurrence which has
    // the resolved status.
    let mut by_id: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for line in new_content.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if !is_governance_event(&value) {
            continue;
        }
        let id = value
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            // No id - keep as-is, can't dedup. Use a synthetic key.
            let synthetic = format!("__noid_{}", order.len());
            order.push(synthetic.clone());
            by_id.insert(synthetic, value);
            continue;
        }
        if !by_id.contains_key(&id) {
            order.push(id.clone());
        }
        by_id.insert(id, value); // overwrite -> keep latest
    }
    let events: Vec<serde_json::Value> = order
        .iter()
        .filter_map(|id| by_id.get(id).cloned())
        .collect();

    if events.is_empty() {
        // Two very different reasons we land here, and the user needs to
        // know which one. Check proxy.log for recent classification lines:
        // if any are present, the agent DID hit the proxy and every call
        // was Allowed (IC-1 events use `append_async` which is a NATS-only
        // stub today and intentionally never lands in the file WAL — so
        // an entirely-Allow run produces an empty audit by design). If the
        // proxy.log has nothing, the agent really did bypass HTTP_PROXY.
        // proxy.log contains ANSI color escapes by default (it's the same
        // tracing-subscriber output the user sees on stderr), so naive
        // substring matching like `l.contains("decision=Allow")` fails —
        // the actual bytes are `decision\x1b[0m\x1b[2m=\x1b[0mAllow`. Strip
        // ESC sequences before matching, or just match two looser substrings
        // separately. The cheap path is to detect the two anchors
        // independently per line.
        let allow_signal = std::fs::read_to_string("data/proxy.log")
            .ok()
            .map(|log| {
                log.lines()
                    .rev()
                    .take(500)
                    .filter(|l| {
                        l.contains("Request classified")
                            && l.contains("decision")
                            && l.contains("Allow")
                    })
                    .count()
            })
            .unwrap_or(0);

        if allow_signal > 0 {
            println!(
                "  {GREEN}\u{2713} {} request(s) classified as Allow (IC-1 fast-path).{RESET}",
                allow_signal
            );
            println!(
                "  {DIM}IC-1 Allow uses async dispatch and is not recorded in the durable WAL{RESET}"
            );
            println!(
                "  {DIM}by design (loss tolerated at <0.1%). See data/proxy.log for the live trace.{RESET}"
            );
        } else {
            println!("  {DIM}No GVM events recorded during this run.{RESET}");
            println!("  {DIM}Make sure your agent uses HTTP_PROXY to route through GVM.{RESET}");
        }
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

/// Docker containment mode: run inside isolated container with host-side
/// iptables enforcement on a dedicated `gvm-docker-{slot}` bridge.
///
/// Design (see docs/user-guide.md, "Docker mode"):
///   - Host-side iptables on a GVM-prefixed bridge forces ALL egress
///     through the proxy port (incl. Node.js HTTPS that ignores HTTP_PROXY).
///   - No MITM: Docker mode gives up HTTPS payload inspection in exchange
///     for stability. SNI-level host decisions still work via SRR. Use
///     `--sandbox` on Linux for full MITM L7 inspection.
///   - No in-container iptables, no NET_ADMIN capability: agents run
///     non-privileged; all enforcement is on the host.
///   - Linux + WSL2 only (iptables lives in the Docker host kernel).
///     macOS / native Windows fall back to cooperative HTTP_PROXY only,
///     with a clear warning.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_contained_legacy(
    script: &str,
    agent_id: &str,
    proxy: &str,
    image: &str,
    memory: &str,
    cpus: &str,
    detach: bool,
    _no_mitm: bool, // reserved; Docker mode never enables MITM.
) -> Result<()> {
    println!();
    println!("{BOLD}Analemma-GVM \u{2014} Docker Containment{RESET}");
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
        // Convert "C:/Users/..." to "/c/Users/..." for Docker. Match
        // both the drive letter AND the ':' in one pattern so the
        // nth(1)==':' guard and the chars().next() read are derived
        // from the same iterator step (no separately-fallible
        // `unwrap()` chained to a length-checked guard).
        let s = match s.split_once(':') {
            Some((drive, rest)) if drive.len() == 1 && rest.starts_with('/') => {
                let drive_lower = drive.to_ascii_lowercase();
                format!("/{}{}", drive_lower, rest)
            }
            _ => s,
        };
        std::path::PathBuf::from(s)
    };
    let script_dir = abs_script.parent().with_context(|| {
        format!(
            "Resolved script path has no parent: {}",
            abs_script.display()
        )
    })?;
    let script_name = abs_script
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| {
            format!(
                "Resolved script path has no file name: {}",
                abs_script.display()
            )
        })?;
    let script_ext = abs_script
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let proxy_url: url::Url = proxy
        .parse()
        .with_context(|| format!("Invalid proxy URL: {}", proxy))?;

    // ── Allocate a dedicated Docker bridge for this run ──
    //
    // Each `gvm run --contained` gets its own `gvm-docker-{slot}` bridge with
    // a unique 172.30.{slot}.0/24 subnet. The bridge + host-side iptables are
    // the enforcement primitive: non-HTTP_PROXY-respecting clients (Node.js,
    // raw sockets) hit the DROP rule and fail, instead of silently bypassing.
    //
    // Host iptables setup is Linux-only. On non-Linux (macOS, native Windows),
    // we fall back to the plain `gvm-bridge` + HTTP_PROXY cooperative mode
    // with a visible warning.
    let enforcement_enabled = cfg!(target_os = "linux");
    #[cfg(target_os = "linux")]
    let bridge_cfg: Option<gvm_sandbox::DockerBridgeConfig> = {
        let proxy_port = proxy_url.port().unwrap_or(8080);
        match gvm_sandbox::allocate_docker_slot() {
            Ok(slot) => Some(gvm_sandbox::DockerBridgeConfig::from_slot(slot, proxy_port)),
            Err(e) => {
                println!("  {RED}Failed to allocate Docker bridge slot: {}{RESET}", e);
                return Ok(());
            }
        }
    };

    // Build container-visible proxy URL. On Linux with an enforced bridge,
    // the bridge gateway IP is the host's reachable proxy address. On other
    // platforms we fall back to the existing `host.docker.internal` trick.
    #[cfg(not(target_os = "linux"))]
    let local_proxy_host = matches!(proxy_url.host_str(), Some("127.0.0.1" | "localhost"));
    #[cfg(target_os = "linux")]
    let container_proxy = {
        let cfg = bridge_cfg.as_ref().expect("bridge_cfg set on linux");
        let mut rewritten = proxy_url.clone();
        // Proxy must listen on 0.0.0.0 or on the bridge gateway IP so the
        // container can reach it. The gateway IP (e.g. 172.30.0.1) is the
        // host-side endpoint of the bridge and is reachable from the container.
        rewritten
            .set_host(Some(&cfg.host_ip))
            .context("Failed to rewrite proxy host for bridge gateway")?;
        rewritten.to_string()
    };
    #[cfg(not(target_os = "linux"))]
    let container_proxy = if local_proxy_host {
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
    println!("  {DIM}Proxy in container:{RESET} {}", container_proxy);
    println!("  {DIM}Memory:{RESET}       {}", memory);
    println!("  {DIM}CPUs:{RESET}         {}", cpus);
    #[cfg(target_os = "linux")]
    if let Some(cfg) = bridge_cfg.as_ref() {
        println!(
            "  {DIM}Network:{RESET}      {} {DIM}({}){RESET}",
            cfg.bridge, cfg.subnet
        );
    }
    #[cfg(not(target_os = "linux"))]
    println!("  {DIM}Network:{RESET}      gvm-bridge {DIM}(cooperative HTTP_PROXY only){RESET}");
    println!();

    if !enforcement_enabled {
        println!(
            "  {YELLOW}\u{26A0}{RESET} Non-Linux host: Docker mode falls back to cooperative \
             HTTP_PROXY routing."
        );
        println!(
            "    {DIM}Agents that ignore HTTP_PROXY (e.g. Node.js raw `https`) may bypass \
             the proxy.{RESET}"
        );
        println!(
            "    {DIM}For guaranteed enforcement, run `gvm run` from a Linux host or WSL2.{RESET}"
        );
        println!();
    }

    // ── Create the dedicated bridge + install host iptables rules ──
    #[cfg(target_os = "linux")]
    if let Some(cfg) = bridge_cfg.as_ref() {
        // 1. docker network create with a pinned bridge interface name.
        //
        // Critical: without `com.docker.network.bridge.name`, Docker
        // auto-generates a `br-<hash>` interface name. Our iptables rules
        // filter by `-i {bridge}`, so without this pin the DROP rule
        // would never match and non-cooperative clients would silently
        // bypass — the exact failure mode this refactor exists to fix.
        let bridge_opt = format!("com.docker.network.bridge.name={}", cfg.bridge);
        let net_create = tokio::process::Command::new("docker")
            .args([
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                &cfg.subnet,
                "--gateway",
                &cfg.host_ip,
                "--opt",
                &bridge_opt,
                &cfg.bridge,
            ])
            .output()
            .await?;
        if !net_create.status.success() {
            let err = String::from_utf8_lossy(&net_create.stderr);
            println!(
                "  {RED}Failed to create bridge {}: {}{RESET}",
                cfg.bridge,
                err.trim()
            );
            return Ok(());
        }
        // 2. Install host-side iptables rules (DOCKER-USER JUMP to GVM chain).
        if let Err(e) = gvm_sandbox::setup_docker_bridge_iptables(cfg) {
            // Clean up partially-created resources before returning.
            let _ = tokio::process::Command::new("docker")
                .args(["network", "rm", &cfg.bridge])
                .output()
                .await;
            println!("  {RED}Failed to install host iptables: {}{RESET}", e);
            println!(
                "    {DIM}Hint: host-side iptables requires Linux + iptables tool. On \
                 Docker Desktop (Windows/macOS outside WSL2), the Docker host VM is not \
                 accessible; use cooperative mode or run gvm from WSL2.{RESET}"
            );
            return Ok(());
        }
        println!(
            "  {GREEN}\u{2713}{RESET} Bridge {} + host iptables installed",
            cfg.bridge
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Ensure legacy gvm-bridge exists (non-enforcing, HTTP_PROXY only).
        let net_check = tokio::process::Command::new("docker")
            .args(["network", "inspect", "gvm-bridge"])
            .output()
            .await?;
        if !net_check.status.success() {
            let _ = tokio::process::Command::new("docker")
                .args(["network", "create", "gvm-bridge"])
                .output()
                .await?;
        }
    }

    // Ensure cleanup of the bridge + iptables runs even on early return or
    // agent error. Uses a scope guard pattern via defer semantics.
    // Also removes the per-PID state file so the orphan sweeper on the next
    // launch does not try to clean resources we already released.
    #[cfg(target_os = "linux")]
    struct BridgeCleanup {
        bridge: String,
    }
    #[cfg(target_os = "linux")]
    impl Drop for BridgeCleanup {
        fn drop(&mut self) {
            let _ = gvm_sandbox::cleanup_docker_bridge_iptables(&self.bridge);
            let _ = std::process::Command::new("docker")
                .args(["network", "rm", &self.bridge])
                .output();
            let pid = std::process::id();
            let _ = std::fs::remove_file(format!("/run/gvm/gvm-sandbox-{}.state", pid));
        }
    }
    #[cfg(target_os = "linux")]
    let _bridge_cleanup = bridge_cfg.as_ref().map(|cfg| BridgeCleanup {
        bridge: cfg.bridge.clone(),
    });

    // ── Build docker run command ──
    let container_name = format!("gvm-agent-{}", agent_id);

    // Record state file AFTER bridge is up and BEFORE container launch,
    // so SIGKILL between here and container exit still has a path to
    // orphan cleanup.
    #[cfg(target_os = "linux")]
    if let Some(cfg) = bridge_cfg.as_ref() {
        if let Err(e) = gvm_sandbox::record_docker_state(cfg, &container_name) {
            eprintln!(
                "  {YELLOW}\u{26a0}{RESET} Failed to record Docker state file: {} \
                 (orphan cleanup may miss this run)",
                e
            );
        }
    }
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
        .arg("no-new-privileges:true");
    // Resource limits are opt-in. Docker rejects `--memory ""` and
    // `--cpus ""`, so skip the flag entirely when the user didn't
    // specify a value.
    if !memory.is_empty() {
        cmd.arg("--memory").arg(memory);
    }
    if !cpus.is_empty() {
        cmd.arg("--cpus").arg(cpus);
    }
    cmd.arg("-w")
        .arg("/home/agent/workspace")
        .arg("-e")
        .arg(format!("GVM_AGENT_ID={}", agent_id));

    // Proxy env vars — always set. Non-cooperative clients are caught by the
    // host iptables DROP rule on Linux; on other platforms they silently
    // bypass (the warning above makes this explicit).
    cmd.arg("-e")
        .arg(format!("HTTP_PROXY={}", container_proxy))
        .arg("-e")
        .arg(format!("HTTPS_PROXY={}", container_proxy))
        .arg("-e")
        .arg(format!("http_proxy={}", container_proxy))
        .arg("-e")
        .arg(format!("https_proxy={}", container_proxy))
        .arg("-e")
        .arg(format!("GVM_PROXY_URL={}", container_proxy))
        .arg("-e")
        .arg("NO_PROXY=127.0.0.1,localhost,::1")
        .arg("-e")
        .arg("no_proxy=127.0.0.1,localhost,::1");

    // Pass through LLM provider API keys if set in host environment.
    // Most agent frameworks (OpenClaw, LangChain, CrewAI) need these to call
    // LLM APIs. The keys are still governed: on Linux all egress is either
    // through the proxy (allowed) or dropped (iptables). On other platforms,
    // only HTTP_PROXY-respecting clients are governed.
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

    // ── Network attach ──
    #[cfg(target_os = "linux")]
    if let Some(cfg) = bridge_cfg.as_ref() {
        cmd.arg("--network").arg(&cfg.bridge);
    } else {
        cmd.arg("--network").arg("bridge");
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = local_proxy_host; // declared above only on non-linux; read here
        cmd.arg("--network")
            .arg("gvm-bridge")
            .arg("--add-host")
            .arg("host.docker.internal:host-gateway");
    }

    if detach {
        cmd.arg("-d");
    }

    cmd.arg(image);
    for arg in &container_cmd {
        cmd.arg(arg);
    }

    println!("  {BOLD}Starting contained agent...{RESET}");
    println!("  {DIM}Container:{RESET}    {}", container_name);
    println!();

    // Security summary
    println!("  {BOLD}Security layers active:{RESET}");
    println!("    {GREEN}\u{2713}{RESET} SRR enforcement (on proxy)");
    println!("    {GREEN}\u{2713}{RESET} Docker isolation (read-only FS, no-new-privileges, resource limits)");
    if enforcement_enabled {
        println!(
            "    {GREEN}\u{2713}{RESET} Host iptables egress lock (force-route through proxy)"
        );
    } else {
        println!("    {YELLOW}\u{26A0}{RESET} HTTP_PROXY only (no egress lock — non-Linux)");
    }
    println!("      {DIM}\u{2022} HTTPS: SNI-level SRR (no MITM payload inspection; use --sandbox for MITM){RESET}");
    println!("      {DIM}\u{2022} Filesystem: read-only root{RESET}");
    println!("      {DIM}\u{2022} Privileges: no-new-privileges (non-root), no NET_ADMIN{RESET}");
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

    // ── looks_like_script() ──

    #[test]
    fn looks_like_script_python() {
        assert!(looks_like_script("agent.py"));
        assert!(looks_like_script("/home/user/agent.py"));
    }

    #[test]
    fn looks_like_script_javascript() {
        assert!(looks_like_script("main.js"));
        assert!(looks_like_script("main.ts"));
    }

    #[test]
    fn looks_like_script_shell() {
        assert!(looks_like_script("run.sh"));
        assert!(looks_like_script("run.bash"));
    }

    #[test]
    fn looks_like_script_binary() {
        assert!(!looks_like_script("gvm-proxy"));
        assert!(!looks_like_script("./target/release/agent"));
        assert!(!looks_like_script("agent.exe"));
    }

    #[test]
    fn looks_like_script_no_extension() {
        assert!(!looks_like_script("python3"));
        assert!(!looks_like_script("node"));
    }

    // ── parse_memory_limit() ──

    #[test]
    fn parse_memory_limit_megabytes() {
        assert_eq!(parse_memory_limit("512m"), Some(512 * 1024 * 1024));
        assert_eq!(parse_memory_limit("512M"), Some(512 * 1024 * 1024));
    }

    #[test]
    fn parse_memory_limit_gigabytes() {
        assert_eq!(parse_memory_limit("2g"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_memory_limit("1G"), Some(1024 * 1024 * 1024));
    }

    #[test]
    fn parse_memory_limit_kilobytes() {
        assert_eq!(parse_memory_limit("1024k"), Some(1024 * 1024));
    }

    #[test]
    fn parse_memory_limit_raw_bytes() {
        assert_eq!(parse_memory_limit("1048576"), Some(1048576));
    }

    #[test]
    fn parse_memory_limit_empty() {
        assert_eq!(parse_memory_limit(""), None);
        assert_eq!(parse_memory_limit("  "), None);
    }

    #[test]
    fn parse_memory_limit_invalid() {
        assert_eq!(parse_memory_limit("not-a-number"), None);
        assert_eq!(parse_memory_limit("abcm"), None);
    }

    #[test]
    fn parse_memory_limit_whitespace_trimmed() {
        assert_eq!(parse_memory_limit("  256m  "), Some(256 * 1024 * 1024));
    }

    // ── derive_admin_url() ──

    #[test]
    fn derive_admin_url_standard() {
        assert_eq!(
            derive_admin_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:9090"
        );
    }

    #[test]
    fn derive_admin_url_custom_port() {
        assert_eq!(
            derive_admin_url("http://localhost:3000"),
            "http://localhost:4010"
        );
    }

    #[test]
    fn derive_admin_url_invalid_url_fallback() {
        assert_eq!(derive_admin_url("not-a-url"), "http://127.0.0.1:9090");
    }

    // ── detect_interpreter() ──

    #[test]
    fn detect_interpreter_python() {
        let (interp, args) = detect_interpreter("py", "agent.py");
        assert!(
            interp == "python3" || interp == "python",
            "interpreter should be python3 or python, got: {}",
            interp
        );
        assert_eq!(args, vec!["agent.py"]);
    }

    #[test]
    fn detect_interpreter_javascript() {
        let (interp, args) = detect_interpreter("js", "main.js");
        assert_eq!(interp, "node");
        assert_eq!(args, vec!["main.js"]);
    }

    #[test]
    fn detect_interpreter_typescript() {
        let (interp, args) = detect_interpreter("ts", "main.ts");
        assert_eq!(interp, "npx");
        assert_eq!(args, vec!["ts-node", "main.ts"]);
    }

    #[test]
    fn detect_interpreter_shell() {
        let (interp, args) = detect_interpreter("sh", "run.sh");
        assert_eq!(interp, "bash");
        assert_eq!(args, vec!["run.sh"]);
    }

    #[test]
    fn detect_interpreter_unknown_defaults_to_python() {
        let (interp, _args) = detect_interpreter("xyz", "script.xyz");
        assert!(
            interp == "python3" || interp == "python",
            "unknown ext should default to python, got: {}",
            interp
        );
    }
}
