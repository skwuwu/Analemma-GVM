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
/// Config files whose mtime determines whether a running proxy is "stale".
/// Edits to any of these after the proxy started should trigger a reload
/// so the new rules actually take effect.
const TRACKED_CONFIG_FILES: &[&str] = &[
    "config/srr_network.toml",
    "config/proxy.toml",
    "config/operation_registry.toml",
    "config/secrets.toml",
];

/// Returns true if any tracked config file is newer than the proxy PID file.
/// The PID file is written by the proxy on startup, so its mtime is a proxy
/// for "when did this proxy first read the config".
///
/// Honors `GVM_CONFIG` (and the corresponding `srr_network.toml` next to it)
/// when set, in addition to the default `config/` paths under `workspace`.
/// Without this, an isolated test config under `/tmp/gvm-e2e-config-XXX/`
/// is invisible to the detector — `gvm suggest` writes the new rules,
/// `gvm run` checks `workspace/config/srr_network.toml` (unchanged), sees
/// no edit, never triggers reload, and the next agent run still hits the
/// stale in-memory ruleset. That breakage was caught by Test 82 on the
/// 2026-04-09 EC2 dry run after the v0.4.4 reload-on-stale-config fix
/// landed but was never validated against the 8668d30 SRR isolation.
fn config_changed_since_proxy_start(workspace: &Path) -> bool {
    let pid_path = workspace.join("data/proxy.pid");
    let proxy_started_at = match std::fs::metadata(&pid_path).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return false, // can't tell — leave the proxy alone
    };

    // Default tracked paths under the workspace root.
    let mut candidates: Vec<PathBuf> = TRACKED_CONFIG_FILES
        .iter()
        .map(|p| workspace.join(p))
        .collect();

    // Also include every TOML under workspace/config/policies/
    if let Ok(entries) = std::fs::read_dir(workspace.join("config/policies")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                candidates.push(path);
            }
        }
    }

    // Override / extension via $GVM_CONFIG. The proxy honors this env var
    // to load proxy.toml from a non-default location (used by the e2e
    // test isolation pattern). We also probe a sibling `srr_network.toml`
    // and a `policies/` directory next to it so the same convention holds
    // end-to-end without requiring callers to set extra env vars.
    if let Ok(gvm_config) = std::env::var("GVM_CONFIG") {
        let gvm_config = PathBuf::from(gvm_config);
        if let Some(parent) = gvm_config.parent() {
            candidates.push(gvm_config.clone());
            candidates.push(parent.join("srr_network.toml"));
            candidates.push(parent.join("operation_registry.toml"));
            candidates.push(parent.join("secrets.toml"));
            if let Ok(entries) = std::fs::read_dir(parent.join("policies")) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                        candidates.push(path);
                    }
                }
            }
        }
    }

    for path in candidates {
        if let Ok(meta) = std::fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                if modified > proxy_started_at {
                    return true;
                }
            }
        }
    }
    false
}

/// Ask a running proxy to atomically reload its rule set via the localhost-only
/// `/gvm/reload` endpoint. This avoids killing and restarting the daemon when
/// the user has only edited config files (e.g. via `gvm suggest`).
async fn reload_running_proxy(proxy: &str) -> Result<()> {
    let url = format!("{}/gvm/reload", proxy.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("Failed to build reload HTTP client")?;
    let resp = client
        .post(&url)
        .send()
        .await
        .with_context(|| format!("POST {} failed", url))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Proxy reload returned {}: {}", status, body);
    }
    Ok(())
}

pub async fn ensure_available(proxy: &str, workspace: &Path, require_tls: bool) -> Result<()> {
    // 1. Check health endpoint first (fastest path)
    if proxy_healthy_with_tls(proxy, require_tls).await {
        // 1a. Proxy is alive — but if config files have been edited since the
        // proxy last started, its in-memory rules are stale. Hot-reload them
        // via the localhost-only /gvm/reload endpoint instead of restarting
        // the daemon. This is what makes `gvm suggest` -> `gvm run` actually
        // pick up the freshly written srr_network.toml.
        if config_changed_since_proxy_start(workspace) {
            eprintln!("  {DIM}Config changed since proxy startup — reloading rules...{RESET}");
            match reload_running_proxy(proxy).await {
                Ok(()) => {
                    eprintln!("  {GREEN}Rules reloaded{RESET}");
                    // Touch the PID file so its mtime moves forward to "now"
                    // and subsequent invocations don't keep retriggering the
                    // reload until the user actually edits config again.
                    let pid_path = workspace.join("data/proxy.pid");
                    if let Ok(pid) = std::fs::read_to_string(&pid_path) {
                        let _ = std::fs::write(&pid_path, pid);
                    }
                }
                Err(e) => {
                    eprintln!("  {YELLOW}Reload failed ({e}) — falling back to restart{RESET}");
                    let pid_path = workspace.join("data/proxy.pid");
                    if let Some(pid) = read_pid_file(&pid_path) {
                        kill_process(pid);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                    return start_daemon(proxy, workspace, require_tls).await;
                }
            }
        }

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

    // Fix config/secrets.toml ownership — when tests run as sudo,
    // scripts may create/append to this file as root. Since the proxy
    // drops to SUDO_UID, it needs read access. chmod 600 by api_keys.rs
    // makes this fatal when owner != proxy user.
    let secrets_path = workspace.join("config/secrets.toml");
    if secrets_path.exists() {
        fix_file_ownership(&secrets_path);
    }

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
