//! Proxy lifecycle manager — starts, monitors, and reuses the GVM proxy.
//!
//! Key design decisions:
//! - Proxy runs as an independent daemon (setsid, detached from CLI)
//! - PID file (data/proxy.pid) enables reuse across gvm CLI invocations
//! - Release binary preferred over cargo run
//! - Working directory = repo root (config/ and data/ live here)
//! - Logs go to data/proxy.log (append mode)
//! - CLI exit does NOT kill the proxy

use crate::ui::{DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Check if the proxy is reachable and healthy.
pub async fn proxy_healthy(proxy: &str) -> bool {
    proxy_healthy_with_tls(proxy, false).await
}

/// Check if the proxy is reachable, healthy, and TLS MITM cert cache is warm.
/// `require_tls` = true blocks until tls_ready is true (for sandbox mode).
pub async fn proxy_healthy_with_tls(proxy: &str, require_tls: bool) -> bool {
    let health_url = format!("{}/gvm/health", proxy.trim_end_matches('/'));
    match reqwest::get(&health_url).await {
        Ok(resp) if resp.status().is_success() => {
            if !require_tls {
                return true;
            }
            // Parse tls_ready from health response
            match resp.json::<serde_json::Value>().await {
                Ok(body) => body["tls_ready"].as_bool().unwrap_or(false),
                Err(_) => false,
            }
        }
        _ => false,
    }
}

/// Ensure the proxy is available. If not running, start it as an independent daemon.
/// If already running (checked via health endpoint + PID file), reuse it.
/// `require_tls`: if true, waits for MITM cert pre-warm to complete before returning.
/// Set to true for sandbox mode (agents need warm cert cache), false for cooperative.
pub async fn ensure_available(proxy: &str, workspace: &Path, require_tls: bool) -> Result<()> {
    // 1. Check health endpoint first (fastest path)
    if proxy_healthy_with_tls(proxy, require_tls).await {
        // Health OK — but verify PID file matches the actual process.
        // If PID file is stale (points to dead process while a different proxy
        // is alive on the port), update it so future operations work correctly.
        #[cfg(unix)]
        {
            let pid_path = workspace.join("data/proxy.pid");
            let file_pid = read_pid_file(&pid_path);
            let stale = match file_pid {
                Some(pid) => !is_process_alive(pid),
                None => true,
            };
            if stale {
                // Find actual PID holding the port
                let port = proxy
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.trim_end_matches('/').parse::<u16>().ok())
                    .unwrap_or(8080);
                if let Ok(out) = std::process::Command::new("lsof")
                    .args(["-ti", &format!(":{port}")])
                    .output()
                {
                    let pids_str = String::from_utf8_lossy(&out.stdout);
                    if let Some(actual_pid) = pids_str
                        .split_whitespace()
                        .filter_map(|s| s.parse::<u32>().ok())
                        .find(|&p| is_process_alive(p))
                    {
                        std::fs::write(&pid_path, actual_pid.to_string()).ok();
                        eprintln!(
                            "  {DIM}Updated stale PID file: {} → {actual_pid}{RESET}",
                            file_pid.unwrap_or(0)
                        );
                    }
                }
            }
        }
        return Ok(());
    }

    // 2. Check PID file — maybe proxy is starting up
    let pid_path = workspace.join("data/proxy.pid");
    if let Some(pid) = read_pid_file(&pid_path) {
        if is_process_alive(pid) {
            // PID is alive but health check failed — wait briefly
            eprintln!("  {DIM}Proxy PID {pid} found, waiting for health...{RESET}");
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                if proxy_healthy_with_tls(proxy, require_tls).await {
                    return Ok(());
                }
            }
            // Still unhealthy — kill stale process and restart
            eprintln!("  {YELLOW}Stale proxy (PID {pid}) — killing and restarting{RESET}");
            kill_process(pid);
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    // 3. Not running — start as daemon
    if !is_local_proxy(proxy) {
        anyhow::bail!(
            "Proxy not reachable at {}. For remote proxies, start manually.",
            proxy
        );
    }

    start_daemon(proxy, workspace, require_tls).await
}

/// Start the proxy as an independent daemon process.
async fn start_daemon(proxy: &str, workspace: &Path, require_tls: bool) -> Result<()> {
    let binary = find_proxy_binary(workspace)?;

    // Before starting, kill any stale process occupying our port.
    // This handles the case where a proxy was started outside proxy_manager
    // (e.g., by a script or manual invocation) and its PID is not in our PID file.
    kill_stale_port_holder(proxy);

    eprintln!(
        "  {YELLOW}Proxy not reachable at {}. Starting...{RESET}",
        proxy
    );

    // Ensure data/ directory exists and is owned by the original user (not root)
    let data_dir = workspace.join("data");
    std::fs::create_dir_all(&data_dir).ok();
    fix_data_dir_ownership(&data_dir);

    // Log file (append mode)
    let log_path = data_dir.join("proxy.log");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Cannot open proxy log: {}", log_path.display()))?;
    let stderr_file = log_file
        .try_clone()
        .with_context(|| "Cannot clone log file handle")?;
    // Fix ownership of log file if created as root
    fix_file_ownership(&log_path);

    eprintln!("  {DIM}Binary: {}{RESET}", binary.display());
    eprintln!("  {DIM}Log:    {}{RESET}", log_path.display());

    // Spawn as independent daemon:
    // - setsid: new session group (survives CLI exit)
    // - working directory: workspace root (config/ and data/ relative paths work)
    // - stdout/stderr: proxy.log (not /dev/null)
    // - stdin: /dev/null
    #[cfg(unix)]
    let child = {
        use std::os::unix::process::CommandExt;
        let mut cmd = std::process::Command::new(&binary);
        cmd.current_dir(workspace)
            .stdin(std::process::Stdio::null())
            .stdout(log_file)
            .stderr(stderr_file);

        // If running as root via sudo, drop back to the original user.
        // The proxy doesn't need root — only the sandbox does.
        // This prevents data/ files from becoming root-owned.
        if let (Some(uid_str), Some(gid_str)) = (
            std::env::var("SUDO_UID").ok(),
            std::env::var("SUDO_GID").ok(),
        ) {
            if let (Ok(uid), Ok(gid)) = (uid_str.parse::<u32>(), gid_str.parse::<u32>()) {
                cmd.uid(uid).gid(gid);
                eprintln!("  {DIM}Proxy will run as uid={uid} gid={gid} (original user){RESET}");
            }
        }

        // SAFETY: pre_exec runs in forked child before exec.
        // setsid() creates a new session so the proxy is independent.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd.spawn()
            .with_context(|| format!("Failed to spawn proxy: {}", binary.display()))?
    };

    #[cfg(not(unix))]
    let child = {
        std::process::Command::new(&binary)
            .current_dir(workspace)
            .stdin(std::process::Stdio::null())
            .stdout(log_file)
            .stderr(stderr_file)
            .spawn()
            .with_context(|| format!("Failed to spawn proxy: {}", binary.display()))?
    };

    // Write PID file and fix ownership
    let pid = child.id();
    let pid_path = workspace.join("data/proxy.pid");
    if let Err(e) = std::fs::write(&pid_path, pid.to_string()) {
        eprintln!("  {DIM}Warning: cannot write PID file: {e}{RESET}");
    }
    fix_file_ownership(&pid_path);

    // Wait for proxy to become healthy (and TLS ready if required)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if proxy_healthy_with_tls(proxy, require_tls).await {
            eprintln!("  {GREEN}Proxy started (PID {pid}){RESET}");
            return Ok(());
        }

        if std::time::Instant::now() >= deadline {
            // Check if process is still alive
            if !is_process_alive(pid) {
                eprintln!("  {RED}Proxy exited immediately.{RESET}");
                eprintln!("  Check log: {}", log_path.display());
                eprintln!("  Common causes:");
                eprintln!("    - Port 8080 already in use (another proxy or service)");
                eprintln!("    - Missing config/proxy.toml (run from project root)");
                eprintln!("    - data/ directory not writable (check permissions)");
                anyhow::bail!("Proxy failed to start. See {}", log_path.display());
            }
            eprintln!("  {RED}Proxy started but not responding to health checks.{RESET}");
            eprintln!("  Check log: {}", log_path.display());
            eprintln!("  Try: curl http://127.0.0.1:8080/gvm/health");
            anyhow::bail!(
                "Proxy did not become healthy within 15s. Check {}",
                log_path.display()
            );
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Find the proxy binary. Prefer release > debug > cargo fallback.
fn find_proxy_binary(workspace: &Path) -> Result<PathBuf> {
    // 1. Same directory as the currently-running `gvm` executable.
    //    This is the most reliable lookup: when `gvm` is extracted from a
    //    release tarball, `gvm-proxy` sits right next to it regardless of
    //    which directory the user `cd`d into before running it.
    if let Ok(gvm_exe) = std::env::current_exe() {
        if let Some(dir) = gvm_exe.parent() {
            let sibling = dir.join(if cfg!(windows) {
                "gvm-proxy.exe"
            } else {
                "gvm-proxy"
            });
            if sibling.exists() {
                return Ok(sibling);
            }
        }
    }

    // 2. Workspace-relative (cargo build layout: <repo>/target/release/).
    let release = workspace.join("target/release/gvm-proxy");
    if release.exists() {
        return Ok(release);
    }

    let debug = workspace.join("target/debug/gvm-proxy");
    if debug.exists() {
        return Ok(debug);
    }

    // 3. Walk up from CWD looking for a sibling target/ dir. Handles
    //    `cd workspace-stress && gvm run` style invocations where the
    //    stress harness switches directory before launching the agent.
    let mut cursor: Option<&Path> = Some(workspace);
    for _ in 0..6 {
        let Some(dir) = cursor else { break };
        let r = dir.join("target/release/gvm-proxy");
        if r.exists() {
            return Ok(r);
        }
        let d = dir.join("target/debug/gvm-proxy");
        if d.exists() {
            return Ok(d);
        }
        cursor = dir.parent();
    }

    // 4. PATH lookup as a last resort (system install case).
    if let Ok(path) = which::which("gvm-proxy") {
        return Ok(path);
    }

    anyhow::bail!(
        "gvm-proxy binary not found. Expected it next to `gvm`, in \
         target/release/ (or target/debug/), walking up from the current \
         directory, or on $PATH. Build with: cargo build --release -p gvm-proxy"
    )
}

/// Check if a proxy URL is a local address.
fn is_local_proxy(proxy: &str) -> bool {
    crate::run::is_local_proxy_url(proxy)
}

/// Read PID from file, return None if file doesn't exist or is invalid.
fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Check if a process with given PID is alive AND is actually gvm-proxy.
/// Guards against PID reuse: if the OS recycled the PID for a different
/// process (e.g., bash, sshd), we must not treat it as our proxy.
fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Step 1: signal 0 = liveness check (no actual signal sent)
        if unsafe { libc::kill(pid as i32, 0) != 0 } {
            return false;
        }
        // Step 2: verify /proc/{pid}/cmdline contains "gvm-proxy"
        // This prevents false positives from PID reuse by unrelated processes.
        match std::fs::read_to_string(format!("/proc/{pid}/cmdline")) {
            Ok(cmdline) => cmdline.contains("gvm-proxy"),
            Err(_) => false, // cannot read cmdline → treat as dead
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Fix ownership of a file to SUDO_UID:SUDO_GID if running as root via sudo.
/// Prevents data/ files from being root-owned after sandbox execution.
fn fix_file_ownership(path: &Path) {
    #[cfg(unix)]
    {
        if let (Some(uid_str), Some(gid_str)) = (
            std::env::var("SUDO_UID").ok(),
            std::env::var("SUDO_GID").ok(),
        ) {
            if let (Ok(uid), Ok(gid)) = (uid_str.parse::<u32>(), gid_str.parse::<u32>()) {
                unsafe {
                    let c_path =
                        std::ffi::CString::new(path.to_str().unwrap_or("")).unwrap_or_default();
                    libc::chown(c_path.as_ptr(), uid, gid);
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Fix ownership of data directory and common files inside it.
fn fix_data_dir_ownership(data_dir: &Path) {
    fix_file_ownership(data_dir);
    for name in &[
        "wal.log",
        "wal.log.watermark",
        "wal_emergency.log",
        "proxy.log",
        "proxy.pid",
    ] {
        let p = data_dir.join(name);
        if p.exists() {
            fix_file_ownership(&p);
        }
    }
}

/// Kill any gvm-proxy process that is holding the port we need.
/// This handles stale proxies started outside proxy_manager (scripts, manual runs).
#[cfg(unix)]
fn kill_stale_port_holder(proxy_url: &str) {
    // Extract port from proxy URL (e.g., "http://127.0.0.1:8080" → 8080)
    let port = proxy_url
        .rsplit(':')
        .next()
        .and_then(|p| p.trim_end_matches('/').parse::<u16>().ok())
        .unwrap_or(8080);

    // Use lsof to find PID holding the port
    let output = std::process::Command::new("lsof")
        .args(["-ti", &format!(":{port}")])
        .output();

    if let Ok(out) = output {
        let pids_str = String::from_utf8_lossy(&out.stdout);
        for pid_str in pids_str.split_whitespace() {
            if let Ok(pid) = pid_str.parse::<u32>() {
                // Verify it's actually gvm-proxy (not some other service)
                if is_process_alive(pid) {
                    eprintln!("  {YELLOW}Killing stale proxy on port {port} (PID {pid}){RESET}");
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                    }
                    // Wait briefly for graceful shutdown
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                    // Force kill if still alive
                    if unsafe { libc::kill(pid as i32, 0) } == 0 {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGKILL);
                        }
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
        }
    }
}

#[cfg(not(unix))]
fn kill_stale_port_holder(_proxy_url: &str) {}

/// Kill a process by PID.
fn kill_process(pid: u32) {
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

/// Result of attempting to stop the GVM proxy daemon.
pub enum StopOutcome {
    /// SIGTERM caused graceful exit within the deadline.
    GracefulExit { pid: u32, elapsed_ms: u128 },
    /// Graceful exit timed out, SIGKILL was required.
    ForcedKill { pid: u32, elapsed_ms: u128 },
    /// PID file existed but the process was already dead.
    AlreadyDead { pid: u32 },
    /// No PID file at all — proxy was never started, or PID file was cleaned.
    NotRunning,
}

/// Stop the GVM proxy daemon: read PID file → SIGTERM → poll for exit → SIGKILL fallback.
///
/// Pure lifecycle logic — does NOT touch sandbox cleanup. The CLI handler
/// orchestrates `stop_proxy()` + `cleanup_all_orphans_report()` separately
/// so each step is observable.
pub fn stop_proxy(workspace: &Path) -> StopOutcome {
    let pid_path = workspace.join("data/proxy.pid");
    let pid = match read_pid_file(&pid_path) {
        Some(p) => p,
        None => return StopOutcome::NotRunning,
    };

    if !is_process_alive(pid) {
        // Stale PID file — clean it up so next status query is accurate.
        let _ = std::fs::remove_file(&pid_path);
        return StopOutcome::AlreadyDead { pid };
    }

    let start = std::time::Instant::now();
    kill_process(pid); // SIGTERM (graceful)

    // Poll for up to 5s, 200ms intervals — matches the proxy's drain timeout.
    let deadline = start + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if !is_process_alive(pid) {
            let _ = std::fs::remove_file(&pid_path);
            return StopOutcome::GracefulExit {
                pid,
                elapsed_ms: start.elapsed().as_millis(),
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Still alive after grace period — escalate to SIGKILL.
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = std::fs::remove_file(&pid_path);
    StopOutcome::ForcedKill {
        pid,
        elapsed_ms: start.elapsed().as_millis(),
    }
}

/// Background proxy watchdog: polls health, restarts on crash.
/// Uses PID file for restart instead of cargo run.
pub async fn watchdog(proxy: String, workspace: PathBuf) {
    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
    const MAX_RESTARTS: u32 = 3;
    const FAILURES_BEFORE_RESTART: u32 = 3;

    let mut consecutive_failures: u32 = 0;
    let mut restarts: u32 = 0;

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    loop {
        tokio::time::sleep(POLL_INTERVAL).await;

        if proxy_healthy(&proxy).await {
            consecutive_failures = 0;
            continue;
        }

        consecutive_failures += 1;
        if consecutive_failures < FAILURES_BEFORE_RESTART {
            continue;
        }

        if restarts >= MAX_RESTARTS {
            eprintln!(
                "  {RED}WATCHDOG: proxy unreachable, max restarts ({}) exceeded{RESET}",
                MAX_RESTARTS
            );
            return;
        }

        eprintln!(
            "  {YELLOW}WATCHDOG: proxy unreachable ({} failures) — restarting ({}/{}){RESET}",
            consecutive_failures,
            restarts + 1,
            MAX_RESTARTS
        );

        match start_daemon(&proxy, &workspace, false).await {
            Ok(()) => {
                restarts += 1;
                consecutive_failures = 0;
                eprintln!(
                    "  {GREEN}WATCHDOG: proxy restarted ({}/{}){RESET}",
                    restarts, MAX_RESTARTS
                );
            }
            Err(e) => {
                eprintln!("  {RED}WATCHDOG: restart failed: {e}{RESET}");
            }
        }
    }
}
