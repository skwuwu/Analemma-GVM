//! Agent launch pipeline — shared execution flow for run, watch, and demo.
//!
//! Architecture:
//!   Phase 1 (pre_launch): ensure proxy, orphan cleanup, CA download, preflight
//!   Phase 2 (launch):     mode-specific agent execution (cooperative/sandbox/contained)
//!   Phase 3 (post_exit):  cleanup, audit output, SRR restore
//!
//! Key invariant: mode-specific branching happens ONLY in Phase 2.
//! Phase 1 and 3 are identical for all modes, preventing feature drift.

use crate::run;
use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use anyhow::{Context, Result};
use std::path::PathBuf;

// ─── Configuration ───

/// Agent launch configuration — the single source of truth for all execution modes.
#[derive(Clone)]
pub struct AgentConfig {
    pub command: Vec<String>,
    pub agent_id: String,
    pub proxy: String,
    pub mode: LaunchMode,
    pub no_mitm: bool,
    pub memory_limit: Option<u64>,
    pub cpu_limit: Option<f64>,
    pub interactive: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub enum LaunchMode {
    Cooperative,
    Sandbox,
    Contained {
        image: String,
        memory: String,
        cpus: String,
        detach: bool,
    },
}

/// State produced by pre-launch phase, consumed by launch and post-exit.
pub struct PreLaunchState {
    pub mitm_ca: Option<Vec<u8>>,
    pub wal_offset: u64,
    pub is_binary_mode: bool,
}

// ─── Phase 1: Pre-launch (shared across all modes) ───

pub async fn pre_launch(config: &AgentConfig) -> Result<PreLaunchState> {
    let is_binary_mode = config.command.len() > 1 || !run::looks_like_script(&config.command[0]);

    // 1. Ensure proxy is running (auto-start as independent daemon if needed)
    let workspace = run::workspace_root_for_proxy();
    crate::proxy_manager::ensure_available(&config.proxy, &workspace).await?;

    // 2. Orphan cleanup (sandbox only — prevent stale iptables/veth)
    if config.mode == LaunchMode::Sandbox {
        match gvm_sandbox::cleanup_all_orphans() {
            Ok(0) => {}
            Ok(n) => eprintln!("  {YELLOW}Cleaned up {n} orphaned sandbox(es) from previous crash{RESET}"),
            Err(e) => eprintln!("  {DIM}Orphan cleanup failed (non-fatal): {e}{RESET}"),
        }
    }

    // 3. Download MITM CA (sandbox/contained, skip if --no-mitm)
    let mitm_ca = if config.no_mitm || config.mode == LaunchMode::Cooperative {
        None
    } else {
        run::download_mitm_ca_cert(&config.proxy).await
    };

    // 4. Record WAL position (for post-exit audit)
    let wal_offset = std::fs::metadata("data/wal.log")
        .map(|m| m.len())
        .unwrap_or(0);

    Ok(PreLaunchState {
        mitm_ca,
        wal_offset,
        is_binary_mode,
    })
}

// ─── Phase 2: Launch (mode-specific) ───

/// Launch the agent and return its exit code.
/// This is the ONLY place where mode-specific branching occurs.
pub async fn launch(config: &AgentConfig, pre: &PreLaunchState) -> Result<i32> {
    match &config.mode {
        LaunchMode::Cooperative => launch_cooperative(config, pre).await,
        LaunchMode::Sandbox => launch_sandbox(config, pre).await,
        LaunchMode::Contained { .. } => launch_contained_wrapper(config, pre).await,
    }
}

async fn launch_cooperative(config: &AgentConfig, pre: &PreLaunchState) -> Result<i32> {
    if pre.is_binary_mode {
        launch_cooperative_binary(config).await
    } else {
        launch_cooperative_script(config).await
    }
}

async fn launch_cooperative_binary(config: &AgentConfig) -> Result<i32> {
    let binary = &config.command[0];
    let args = &config.command[1..];

    let mut cmd = tokio::process::Command::new(binary);
    cmd.args(args);
    run::inject_proxy_env(&mut cmd, &config.proxy, &config.agent_id);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd
        .status()
        .await
        .with_context(|| format!("Failed to execute: {}", binary))?;
    Ok(status.code().unwrap_or(-1))
}

async fn launch_cooperative_script(config: &AgentConfig) -> Result<i32> {
    let abs_script = run::resolve_script(&config.command[0])?;
    let ext = abs_script.extension().and_then(|e| e.to_str()).unwrap_or("");
    let (interpreter, interpreter_args) =
        run::detect_interpreter(ext, abs_script.to_str().unwrap_or(&config.command[0]));
    let script_dir = abs_script.parent().unwrap_or(std::path::Path::new("."));

    let mut cmd = tokio::process::Command::new(&interpreter);
    for arg in &interpreter_args {
        cmd.arg(arg);
    }
    cmd.current_dir(script_dir);
    run::inject_proxy_env(&mut cmd, &config.proxy, &config.agent_id);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    let status = cmd
        .status()
        .await
        .with_context(|| format!("Failed to execute: {}", interpreter))?;
    Ok(status.code().unwrap_or(-1))
}

async fn launch_sandbox(config: &AgentConfig, pre: &PreLaunchState) -> Result<i32> {
    let proxy_addr = run::parse_proxy_addr(&config.proxy)?;

    let sandbox_config = if pre.is_binary_mode {
        let binary = &config.command[0];
        let args = &config.command[1..];
        let binary_path =
            which::which(binary).with_context(|| format!("Binary not found: {}", binary))?;
        run::assemble_sandbox_config(
            binary_path.clone(),
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            binary_path.to_str().unwrap_or(binary).to_string(),
            args.iter().map(|s| s.to_string()).collect(),
            proxy_addr,
            &config.agent_id,
            &config.proxy,
            config.memory_limit,
            config.cpu_limit,
            pre.mitm_ca.clone(),
        )
    } else {
        let abs_script = run::resolve_script(&config.command[0])?;
        let script_dir = abs_script.parent().unwrap_or(std::path::Path::new("."));
        let script_name = abs_script
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(&config.command[0])
            .to_string();
        let ext = abs_script.extension().and_then(|e| e.to_str()).unwrap_or("");
        let (interpreter, interpreter_args) = run::detect_interpreter(ext, &script_name);

        run::assemble_sandbox_config(
            abs_script.clone(),
            script_dir.to_path_buf(),
            interpreter,
            interpreter_args,
            proxy_addr,
            &config.agent_id,
            &config.proxy,
            config.memory_limit,
            config.cpu_limit,
            pre.mitm_ca.clone(),
        )
    };

    // Preflight check (sandbox only)
    let preflight = gvm_sandbox::preflight_check(&sandbox_config);
    let missing_critical = !preflight.user_namespaces
        || !preflight.seccomp_available
        || !preflight.net_admin_capability
        || !preflight.ip_command_available
        || !preflight.iptables_command_available
        || !preflight.interpreter_found;

    if missing_critical {
        eprintln!("  {RED}Pre-flight check failed:{RESET}");
        if !preflight.user_namespaces {
            eprintln!("    {RED}\u{2717}{RESET} User namespaces not available");
        }
        if !preflight.interpreter_found {
            eprintln!("    {RED}\u{2717}{RESET} Interpreter not found");
        }
        anyhow::bail!("Sandbox pre-flight check failed");
    }

    // Phase 2: pure sandbox launch — no watchdog here.
    // Watchdog runs in BackgroundTasks (spawned by run_full/watch),
    // keeping Phase 2 as a single-responsibility launch step.
    let result = tokio::task::spawn_blocking(move || gvm_sandbox::launch_sandboxed(sandbox_config))
        .await
        .unwrap_or_else(|e| Err(anyhow::anyhow!("Sandbox task panicked: {e}")))?;

    if result.seccomp_violations > 0 {
        eprintln!(
            "  {RED}\u{26a0} {} seccomp violation(s) detected{RESET}",
            result.seccomp_violations
        );
    }

    // Display filesystem diff report + interactive review (overlayfs Trust-on-Pattern)
    if let Some(ref diff) = result.fs_diff {
        if diff.overlayfs_active {
            let workspace = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            print_fs_diff_report(diff, &workspace);
        }
    }

    Ok(result.exit_code)
}

async fn launch_contained_wrapper(config: &AgentConfig, _pre: &PreLaunchState) -> Result<i32> {
    // Contained mode delegates to run.rs's existing run_contained which has
    // complex Docker-specific logic (image building, volume mounts, DNAT entrypoint).
    // For now, we call the legacy function. Full pipeline integration is Phase 2.
    if let LaunchMode::Contained {
        ref image,
        ref memory,
        ref cpus,
        detach,
    } = config.mode
    {
        run::run_contained_legacy(
            &config.command[0],
            &config.agent_id,
            &config.proxy,
            image,
            memory,
            cpus,
            detach,
            config.no_mitm,
        )
        .await
        .map(|_| 0)
    } else {
        unreachable!()
    }
}

// ─── Phase 3: Post-exit (shared) ───

/// Standard post-exit: print audit summary.
pub fn post_exit_audit(config: &AgentConfig, pre: &PreLaunchState, exit_code: i32) {
    eprintln!();
    if exit_code == 0 {
        eprintln!("  {GREEN}Process completed successfully{RESET}");
    } else {
        eprintln!("  {YELLOW}Process exited with code: {}{RESET}", exit_code);
    }
    eprintln!();

    run::print_wal_audit("data/wal.log", pre.wal_offset, &config.agent_id);

    if config.interactive {
        crate::suggest::suggest_rules_interactive(
            "data/wal.log",
            pre.wal_offset,
            "config/srr_network.toml",
        );
    } else {
        // Non-interactive: count default-caution hits and suggest batch rule generation.
        let caution_count = crate::suggest::count_default_caution_hits(
            "data/wal.log",
            pre.wal_offset,
        );
        if caution_count > 0 {
            eprintln!(
                "  {YELLOW}{} request(s) hit Default-to-Caution (no explicit rule).{RESET}",
                caution_count
            );
            eprintln!(
                "  {DIM}Generate rules: gvm suggest --from data/wal.log --output config/srr_network.toml{RESET}"
            );
            eprintln!(
                "  {DIM}Or use interactive mode: gvm run -i {}{RESET}",
                config.command.first().map(|s| s.as_str()).unwrap_or("agent.py")
            );
            eprintln!();
        }
    }
}

// ─── Background tasks ───

/// Handles for background tasks that run alongside the agent.
pub struct BackgroundTasks {
    watchdog: tokio::task::JoinHandle<()>,
    approval: tokio::task::JoinHandle<()>,
    approval_cancel: tokio::sync::watch::Sender<bool>,
}

impl BackgroundTasks {
    /// Spawn watchdog and IC-3 approval poller.
    pub fn spawn(proxy: &str) -> Self {
        let proxy_url = proxy.to_string();
        let workspace = run::workspace_root_for_proxy();
        let watchdog = tokio::spawn(crate::proxy_manager::watchdog(proxy_url, workspace));

        let (approval_cancel, approval_rx) = tokio::sync::watch::channel(false);
        let admin_url = run::derive_admin_url(proxy);
        let approval = tokio::spawn(async move {
            crate::approve::poll_and_prompt_background(&admin_url, approval_rx).await;
        });

        Self {
            watchdog,
            approval,
            approval_cancel,
        }
    }

    /// Abort all background tasks.
    pub fn abort(self) {
        self.watchdog.abort();
        let _ = self.approval_cancel.send(true);
        self.approval.abort();
    }
}

// ─── Convenience: full run pipeline ───

/// Execute the full run pipeline: pre-launch → banner → launch → post-exit.
/// Used by `gvm run`. Watch uses pre_launch/launch separately with its own wrapping.
pub async fn run_full(config: AgentConfig) -> Result<()> {
    // Print mode-specific banner
    print_banner(&config);

    // Phase 1
    let pre = pre_launch(&config).await?;

    // Print security layers
    print_security_layers(&config);

    // Background tasks
    let tasks = BackgroundTasks::spawn(&config.proxy);

    // Phase 2
    let exit_code = launch(&config, &pre).await.unwrap_or_else(|e| {
        eprintln!("  {RED}Execution failed: {e}{RESET}");
        1
    });

    // Stop background tasks
    tasks.abort();

    // Phase 3
    post_exit_audit(&config, &pre, exit_code);

    Ok(())
}

fn print_banner(config: &AgentConfig) {
    eprintln!();
    match &config.mode {
        LaunchMode::Cooperative => {
            if config.command.len() > 1 || !run::looks_like_script(&config.command[0]) {
                eprintln!("{BOLD}Analemma GVM \u{2014} Binary Mode (Layer 2){RESET}");
                eprintln!("{DIM}All outbound HTTP/HTTPS routed through GVM proxy.{RESET}");
            } else {
                eprintln!("{BOLD}Analemma-GVM \u{2014} Agent Governance Monitor{RESET}");
                eprintln!("{DIM}All HTTP traffic will be routed through GVM proxy for governance.{RESET}");
            }
        }
        LaunchMode::Sandbox => {
            eprintln!("{BOLD}Analemma GVM \u{2014} Sandbox Mode (Layer 2 + 3){RESET}");
            eprintln!("{DIM}Kernel isolation: namespace + seccomp + veth + uprobe.{RESET}");
        }
        LaunchMode::Contained { .. } => {
            eprintln!("{BOLD}Analemma-GVM \u{2014} Agent Containment (Layer 3){RESET}");
        }
    }
    eprintln!();
    eprintln!("  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}", config.agent_id);
    eprintln!("  {DIM}Command:{RESET}      {}", config.command.join(" "));
    eprintln!("  {DIM}Proxy:{RESET}        {}", config.proxy);
    eprintln!();
}

fn print_security_layers(config: &AgentConfig) {
    eprintln!("  {BOLD}Security layers active:{RESET}");
    match &config.mode {
        LaunchMode::Cooperative => {
            eprintln!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy");
            eprintln!("    {DIM}\u{25cb}{RESET} Layer 3: OS Containment {DIM}(add --sandbox or --contained){RESET}");
        }
        LaunchMode::Sandbox => {
            eprintln!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy");
            eprintln!("    {GREEN}\u{2713}{RESET} Layer 3: Linux Namespace Isolation");
            eprintln!("      {DIM}\u{2022} PID namespace: isolated process tree{RESET}");
            eprintln!("      {DIM}\u{2022} Mount namespace: minimal rootfs{RESET}");
            eprintln!("      {DIM}\u{2022} Network namespace: veth pair, proxy-only routing{RESET}");
            eprintln!("      {DIM}\u{2022} Seccomp-BPF: syscall whitelist{RESET}");
            eprintln!("      {DIM}\u{2022} Transparent MITM: ephemeral CA, full L7 HTTPS inspection{RESET}");
        }
        LaunchMode::Contained { .. } => {
            eprintln!("    {GREEN}\u{2713}{RESET} Layer 2: Enforcement Proxy");
            eprintln!("    {GREEN}\u{2713}{RESET} Layer 3: Docker Containment");
        }
    }
    eprintln!();
    eprintln!("  {DIM}--- Output below ---{RESET}");
    eprintln!();
}

fn print_fs_diff_report(diff: &gvm_sandbox::filesystem::FsDiffReport, workspace: &std::path::Path) {
    use gvm_sandbox::filesystem::ChangeKind;

    eprintln!();
    eprintln!("  {BOLD}\u{2500}\u{2500} File Changes \u{2500}\u{2500}{RESET}");

    if diff.auto_merged.is_empty() && diff.needs_review.is_empty() && diff.discarded.is_empty() {
        eprintln!("    {DIM}No file changes detected.{RESET}");
        return;
    }

    // Auto-merged: quiet, one line each
    for f in &diff.auto_merged {
        let dst = workspace.join(&f.path);
        eprintln!("    {GREEN}Created:{RESET}  {} ({})  {DIM}auto-merged \u{2192} {}{RESET}",
            f.path.display(), format_size(f.size), dst.display());
    }

    // Needs review: show kind + reason
    for f in &diff.needs_review {
        let kind_str = match f.kind {
            ChangeKind::Created => "Created",
            ChangeKind::Modified => "Modified",
            ChangeKind::Deleted => "Deleted",
        };
        eprintln!("    {YELLOW}{kind_str}:{RESET}  {} ({})  {DIM}needs review ({}){RESET}",
            f.path.display(), format_size(f.size), f.matched_pattern);
    }

    // Discarded: summary only
    if !diff.discarded.is_empty() {
        eprintln!("    {DIM}Discarded: {} file(s){RESET}", diff.discarded.len());
    }

    // Interactive review for needs_review files (TTY only)
    if !diff.needs_review.is_empty() {
        let staging_dir = std::path::PathBuf::from(format!(
            "data/sandbox-staging/{}", std::process::id()
        ));

        if atty::is(atty::Stream::Stdin) && staging_dir.exists() {
            eprintln!();
            let mut accepted = 0usize;
            let mut rejected = 0usize;

            for (i, f) in diff.needs_review.iter().enumerate() {
                let staged = staging_dir.join(&f.path);
                eprintln!("  {BOLD}[{}/{}]{RESET} {} ({}, {})",
                    i + 1, diff.needs_review.len(),
                    f.path.display(),
                    match f.kind {
                        ChangeKind::Created => "Created",
                        ChangeKind::Modified => "Modified",
                        ChangeKind::Deleted => "Deleted",
                    },
                    format_size(f.size),
                );

                // Show diff/content preview
                if staged.exists() {
                    if let Ok(content) = std::fs::read_to_string(&staged) {
                        let lines: Vec<&str> = content.lines().take(10).collect();
                        for line in &lines {
                            eprintln!("  {GREEN}+{RESET}{}", line);
                        }
                        if content.lines().count() > 10 {
                            eprintln!("  {DIM}... ({} more lines){RESET}", content.lines().count() - 10);
                        }
                    } else {
                        eprintln!("  {DIM}(binary file){RESET}");
                    }
                }

                eprintln!();
                eprint!("  ({GREEN}a{RESET})ccept  ({RED}r{RESET})eject  ({DIM}s{RESET})kip all \u{2192} ");

                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_ok() {
                    let choice = input.trim().to_lowercase();
                    match choice.as_str() {
                        "a" | "accept" | "y" | "yes" => {
                            // Copy staged file to workspace
                            let dst = workspace.join(&f.path);
                            if let Some(parent) = dst.parent() {
                                std::fs::create_dir_all(parent).ok();
                            }
                            if std::fs::copy(&staged, &dst).is_ok() {
                                eprintln!("  {GREEN}\u{2713}{RESET} {} \u{2192} {}", f.path.display(), dst.display());
                                accepted += 1;
                            } else {
                                eprintln!("  {RED}\u{2717}{RESET} copy failed");
                            }
                        }
                        "s" | "skip" => {
                            eprintln!("  {DIM}Skipping remaining files{RESET}");
                            break;
                        }
                        _ => {
                            eprintln!("  {RED}\u{2717}{RESET} {} rejected (original preserved)", f.path.display());
                            rejected += 1;
                        }
                    }
                }
            }

            eprintln!();
            eprintln!("  {BOLD}Summary:{RESET} {} merged, {} accepted, {} rejected, {} discarded",
                diff.auto_merged.len(), accepted, rejected, diff.discarded.len());

            // Clean up staging
            std::fs::remove_dir_all(&staging_dir).ok();
        } else {
            // Non-TTY: print staging path
            eprintln!();
            if staging_dir.exists() {
                eprintln!("  {DIM}Files staged at: {}{RESET}", staging_dir.display());
                eprintln!("  {DIM}Review and approve: {CYAN}gvm fs approve{RESET}");
            } else {
                eprintln!("  {DIM}{} file(s) need review but staging unavailable{RESET}",
                    diff.needs_review.len());
            }
        }
    }

    eprintln!();
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
