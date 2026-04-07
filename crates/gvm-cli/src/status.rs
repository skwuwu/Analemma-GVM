use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::Result;

/// Show proxy status: health, SRR rules, WAL state, pending approvals.
pub async fn run_status(proxy_url: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let health_url = format!("{}/gvm/health", proxy_url);
    let proxy_reachable = client.get(&health_url).send().await.ok();

    eprintln!();
    eprintln!("  {BOLD}GVM Proxy Status{RESET}");
    eprintln!();

    match proxy_reachable {
        Some(resp) => {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            print_proxy_health(&body, proxy_url);
        }
        None => {
            eprintln!("  {RED}\u{2717}{RESET} {BOLD}Proxy not reachable{RESET} at {proxy_url}");
            eprintln!("    Start with: gvm run <agent>");
        }
    }

    // ── Sandbox view (independent of proxy reachability) ──
    // When proxy is up: shows ACTIVE sandboxes (live PIDs).
    // When proxy is down: shows ORPHANED sandboxes that need cleanup.
    print_active_sandboxes();

    // ── Isolation profile (static — derived from compiled seccomp filter) ──
    print_isolation_profile();

    eprintln!();
    Ok(())
}

/// Render the parsed `/gvm/health` JSON with the proxy-running view.
fn print_proxy_health(body: &serde_json::Value, proxy_url: &str) {
    let status = body["status"].as_str().unwrap_or("unknown");
    let version = body["version"].as_str().unwrap_or("?");
    let srr_rules = body["srr_rules"].as_u64().unwrap_or(0);
    let wal_status = body["wal"].as_str().unwrap_or("unknown");
    let wal_failures = body["wal_failures"].as_u64().unwrap_or(0);
    let emergency = body["emergency_writes"].as_u64().unwrap_or(0);
    let pending = body["pending_approvals"].as_u64().unwrap_or(0);
    let tls_ready = body["tls_ready"].as_bool().unwrap_or(false);

    // Optional fields — only printed if the proxy reports them. Older proxy
    // builds without uptime/request counters still render cleanly.
    let uptime_secs = body["uptime_secs"].as_u64();
    let total_requests = body["total_requests"].as_u64();
    let ca_expires_days = body["ca_expires_days"].as_i64();

    let status_color = match status {
        "healthy" => GREEN,
        "degraded" => YELLOW,
        _ => RED,
    };
    let status_icon = match status {
        "healthy" => "\u{2713}",
        _ => "\u{26a0}",
    };

    eprintln!("  {status_color}{status_icon}{RESET} {BOLD}{status}{RESET}  {DIM}v{version}{RESET}");
    eprintln!("  {DIM}Listen:{RESET}       {CYAN}{proxy_url}{RESET}");
    if let Some(secs) = uptime_secs {
        eprintln!("  {DIM}Uptime:{RESET}       {}", format_uptime(secs));
    }
    if let Some(total) = total_requests {
        eprintln!(
            "  {DIM}Requests:{RESET}     {} total",
            format_thousands(total)
        );
    }
    eprintln!("  {DIM}SRR rules:{RESET}    {srr_rules}");
    if tls_ready {
        if let Some(days) = ca_expires_days {
            eprintln!("  {DIM}TLS MITM:{RESET}     ready (CA expires in {days} days)");
        } else {
            eprintln!("  {DIM}TLS MITM:{RESET}     ready");
        }
    } else {
        eprintln!("  {YELLOW}TLS MITM:{RESET}     warming up");
    }
    eprintln!("  {DIM}WAL:{RESET}          {wal_status}");
    if wal_failures > 0 {
        eprintln!("  {YELLOW}WAL failures:{RESET} {wal_failures}");
    }
    if emergency > 0 {
        eprintln!("  {YELLOW}Emergency writes:{RESET} {emergency}");
    }
    if pending > 0 {
        eprintln!("  {YELLOW}Pending approvals:{RESET} {pending} (run gvm approve)");
    }
}

/// Format seconds as "2h 15m" / "5m 12s" / "42s".
fn format_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Insert thousands separators: 12345 → "12,345".
fn format_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// Scan /run/gvm/ for sandbox state files and partition them into active/orphan.
/// Orphan = state file exists but PID is dead. Active = PID is still alive.
/// Renders the appropriate header so users see "Active Sandboxes" in the
/// happy path and "Orphan Sandboxes" + cleanup hint in the recovery path.
#[cfg(target_os = "linux")]
fn print_active_sandboxes() {
    let pattern = "/run/gvm/gvm-sandbox-*.state";
    let entries: Vec<_> = match glob::glob(pattern) {
        Ok(g) => g.flatten().collect(),
        Err(_) => return,
    };

    #[derive(Debug)]
    struct SandboxRow {
        pid: u32,
        veth: String,
        host_ip: String,
        created: String,
    }

    let mut active: Vec<SandboxRow> = Vec::new();
    let mut orphaned: Vec<SandboxRow> = Vec::new();

    for path in entries {
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let state: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let pid = state["pid"].as_u64().unwrap_or(0) as u32;
        if pid == 0 {
            continue;
        }
        let row = SandboxRow {
            pid,
            veth: state["veth_host"].as_str().unwrap_or("?").to_string(),
            host_ip: state["host_ip"].as_str().unwrap_or("?").to_string(),
            created: state["created_at"].as_str().unwrap_or("?").to_string(),
        };
        // Liveness check: kill(pid, 0) returns 0 if alive (no signal sent).
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if alive {
            active.push(row);
        } else {
            orphaned.push(row);
        }
    }

    if !active.is_empty() {
        eprintln!();
        eprintln!("  {BOLD}Active Sandboxes:{RESET} {}", active.len());
        eprintln!();
        active.sort_by_key(|r| r.pid);
        for r in &active {
            eprintln!(
                "  {DIM}PID {}{RESET}  {CYAN}{}{RESET}  {DIM}{}/30{RESET}  {DIM}started {}{RESET}",
                r.pid, r.veth, r.host_ip, r.created
            );
        }
    }

    if !orphaned.is_empty() {
        eprintln!();
        eprintln!("  {YELLOW}Orphan Sandboxes:{RESET} {}", orphaned.len());
        eprintln!();
        orphaned.sort_by_key(|r| r.pid);
        for r in &orphaned {
            eprintln!(
                "  {DIM}PID {} (dead){RESET}  {CYAN}{}{RESET}  {DIM}cleanup needed{RESET}",
                r.pid, r.veth
            );
        }
        eprintln!("    Run: {BOLD}gvm cleanup{RESET}");
    }

    if active.is_empty() && orphaned.is_empty() {
        eprintln!();
        eprintln!("  {DIM}Active Sandboxes: 0{RESET}");
    }
}

#[cfg(not(target_os = "linux"))]
fn print_active_sandboxes() {
    eprintln!();
    eprintln!("  {DIM}Active sandboxes: (Linux-only feature){RESET}");
}

/// Print the isolation surface — counts pulled from the compiled seccomp profile
/// and overlay/TC capability checks. Static info; not a per-sandbox view.
#[cfg(target_os = "linux")]
fn print_isolation_profile() {
    let allowed = gvm_sandbox::allowed_syscall_count();
    let overlay_supported = std::fs::read_to_string("/proc/filesystems")
        .map(|s| s.lines().any(|l| l.contains("overlay")))
        .unwrap_or(false);
    let tc_supported = gvm_sandbox::preflight_check(&dummy_sandbox_config()).tc_filter_available;

    eprintln!();
    eprintln!("  {BOLD}Isolation profile:{RESET}");
    eprintln!(
        "  {DIM}seccomp:{RESET}      {} syscalls allowed, ENOSYS default for unrecognised",
        allowed
    );
    eprintln!(
        "  {DIM}overlayfs:{RESET}    {}",
        if overlay_supported {
            format!("{GREEN}supported{RESET}")
        } else {
            format!("{YELLOW}unsupported (kernel < 5.11 or no overlay module){RESET}")
        }
    );
    eprintln!(
        "  {DIM}TC ingress:{RESET}   {}",
        if tc_supported {
            format!("{GREEN}available{RESET}")
        } else {
            format!("{YELLOW}unavailable (iptables fallback active){RESET}")
        }
    );
}

#[cfg(not(target_os = "linux"))]
fn print_isolation_profile() {
    eprintln!();
    eprintln!("  {DIM}Isolation profile: (Linux-only feature){RESET}");
}

/// preflight_check needs a SandboxConfig, but for a status query we only care
/// about the host capabilities — the config fields are irrelevant. Build a
/// throwaway with safe defaults.
#[cfg(target_os = "linux")]
fn dummy_sandbox_config() -> gvm_sandbox::SandboxConfig {
    gvm_sandbox::SandboxConfig {
        workspace_dir: std::path::PathBuf::from("/tmp"),
        interpreter: "python3".to_string(),
        interpreter_args: vec![],
        proxy_addr: "127.0.0.1:8080".parse().unwrap(),
        agent_id: "status-probe".to_string(),
        seccomp_profile: None,
        tls_probe_mode: gvm_sandbox::TlsProbeMode::Disabled,
        proxy_url: None,
        memory_limit: None,
        cpu_limit: None,
        fs_policy: None,
        mitm_ca_cert: None,
        sandbox_profile: gvm_sandbox::SandboxProfile::Standard,
    }
}
