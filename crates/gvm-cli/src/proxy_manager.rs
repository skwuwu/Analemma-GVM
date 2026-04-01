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
    let health_url = format!("{}/gvm/health", proxy.trim_end_matches('/'));
    matches!(reqwest::get(&health_url).await, Ok(resp) if resp.status().is_success())
}

/// Ensure the proxy is available. If not running, start it as an independent daemon.
/// If already running (checked via health endpoint + PID file), reuse it.
pub async fn ensure_available(proxy: &str, workspace: &Path) -> Result<()> {
    // 1. Check health endpoint first (fastest path)
    if proxy_healthy(proxy).await {
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
                if proxy_healthy(&proxy).await {
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

    start_daemon(proxy, workspace).await
}

/// Start the proxy as an independent daemon process.
async fn start_daemon(proxy: &str, workspace: &Path) -> Result<()> {
    let binary = find_proxy_binary(workspace)?;

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

    // Wait for proxy to become healthy
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if proxy_healthy(&proxy).await {
            eprintln!("  {GREEN}Proxy started (PID {pid}){RESET}");
            return Ok(());
        }

        if std::time::Instant::now() >= deadline {
            // Check if process is still alive
            if !is_process_alive(pid) {
                eprintln!("  {RED}Proxy exited immediately. Check {}{RESET}", log_path.display());
                anyhow::bail!("Proxy failed to start. See {}", log_path.display());
            }
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
    let release = workspace.join("target/release/gvm-proxy");
    if release.exists() {
        return Ok(release);
    }

    let debug = workspace.join("target/debug/gvm-proxy");
    if debug.exists() {
        return Ok(debug);
    }

    // Check if gvm-proxy is in PATH
    if let Ok(path) = which::which("gvm-proxy") {
        return Ok(path);
    }

    anyhow::bail!(
        "gvm-proxy binary not found. Build with: cargo build --release -p gvm-proxy"
    )
}

/// Check if a proxy URL is a local address.
fn is_local_proxy(proxy: &str) -> bool {
    crate::run::is_local_proxy_url(proxy)
}

/// Read PID from file, return None if file doesn't exist or is invalid.
fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Check if a process with given PID is alive.
fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // kill(pid, 0) checks if process exists without sending a signal
        unsafe { libc::kill(pid as i32, 0) == 0 }
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
                    let c_path = std::ffi::CString::new(
                        path.to_str().unwrap_or("")
                    ).unwrap_or_default();
                    libc::chown(c_path.as_ptr(), uid, gid);
                }
            }
        }
    }
    #[cfg(not(unix))]
    { let _ = path; }
}

/// Fix ownership of data directory and common files inside it.
fn fix_data_dir_ownership(data_dir: &Path) {
    fix_file_ownership(data_dir);
    for name in &["wal.log", "wal.log.watermark", "wal_emergency.log", "proxy.log", "proxy.pid"] {
        let p = data_dir.join(name);
        if p.exists() {
            fix_file_ownership(&p);
        }
    }
}

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

        match start_daemon(&proxy, &workspace).await {
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
