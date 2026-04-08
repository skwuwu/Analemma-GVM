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
use std::io::IsTerminal;
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
    /// Enable overlayfs Trust-on-Pattern filesystem governance.
    /// false (default) = legacy mode (workspace/output/ writable only).
    /// true = overlayfs with auto-merge/ManualCommit at session end.
    pub fs_governance: bool,
    pub sandbox_profile: gvm_sandbox::SandboxProfile,
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
    //    Sandbox mode: wait for TLS cert pre-warm (tls_ready=true) so agents
    //    don't hit cold MITM cert cache on their first HTTPS request.
    let workspace = run::workspace_root_for_proxy();
    let require_tls = config.mode == LaunchMode::Sandbox;
    crate::proxy_manager::ensure_available(&config.proxy, &workspace, require_tls).await?;

    // 2. Orphan cleanup (sandbox only — prevent stale iptables/veth)
    if config.mode == LaunchMode::Sandbox {
        match gvm_sandbox::cleanup_all_orphans() {
            Ok(0) => {}
            Ok(n) => eprintln!(
                "  {YELLOW}Cleaned up {n} orphaned sandbox(es) from previous crash{RESET}"
            ),
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
    let ext = abs_script
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
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
        let ext = abs_script
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        // Inside the sandbox, the parent script_dir is bind-mounted at
        // /workspace and the agent's working directory is /workspace/output.
        // A bare `python3 script.py` therefore looks for /workspace/output/script.py
        // which doesn't exist. Pass the sandbox-absolute path instead.
        let sandbox_script_path = format!("/workspace/{}", script_name);
        let (interpreter, interpreter_args) = run::detect_interpreter(ext, &sandbox_script_path);

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

    // Filesystem governance mode and sandbox profile.
    //
    // Overlayfs is ALWAYS on for --sandbox — this is what makes /workspace
    // writable end-to-end (agents expect a normal writable working dir).
    // The --fs-governance flag used to gate overlayfs itself, but that left
    // --sandbox alone in a confusing read-only legacy mode where even
    // `mkdir /workspace/foo` failed. Now --sandbox means: namespace isolation
    // + overlayfs + file-pattern classification + diff report on exit.
    // The --fs-governance flag is retained for backwards compatibility but
    // no longer changes behaviour when --sandbox is set.
    let mut sandbox_config = sandbox_config;
    sandbox_config.fs_policy = Some(gvm_sandbox::FilesystemPolicy::default());
    sandbox_config.sandbox_profile = config.sandbox_profile.clone();
    let _fs_governance_flag = config.fs_governance; // reserved for future opt-out

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

    // Print actionable termination diagnostic so users understand WHY the agent
    // died and what to do about it. Generic "killed by signal: SIGKILL" was
    // useless — OOM, timeout, and external kill all looked identical.
    print_exit_reason(&result.exit_reason, result.cpu_throttled_us);

    // Verify that cleanup actually released every host resource we claim
    // to have released. Surfaces leaks immediately rather than letting
    // them accumulate silently across runs.
    print_cleanup_verification(&result.cleanup_verification);

    // Display filesystem diff report + interactive review (overlayfs Trust-on-Pattern)
    if let Some(ref diff) = result.fs_diff {
        if diff.overlayfs_active {
            let workspace = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            print_fs_diff_report(diff, &workspace);
        }
    }

    Ok(result.exit_code)
}

/// Print a one-line, actionable diagnostic for why the agent terminated.
///
/// Distinguishes OOM/timeout/seccomp/external SIGKILL so users know what to fix.
/// Silent on Normal exit (success — nothing to say).
fn print_exit_reason(reason: &gvm_sandbox::ExitReason, cpu_throttled_us: Option<u64>) {
    use gvm_sandbox::ExitReason::*;
    match reason {
        Normal => {}
        AgentError { code } => {
            eprintln!(
                "  {YELLOW}\u{26a0} Agent exited with error code {}{RESET}",
                code
            );
        }
        Timeout { secs } => {
            eprintln!(
                "  {RED}\u{26a0} Agent timed out after {}s{RESET}\n    \
                 Increase via: GVM_SANDBOX_TIMEOUT={} gvm run ...",
                secs,
                secs * 2
            );
        }
        UserInterrupt { signal } => {
            eprintln!("  {DIM}Agent terminated by user signal ({signal}){RESET}");
        }
        SeccompViolation {
            count,
            syscall: Some(name),
        } => {
            // We resolved the exact syscall via dmesg AUDIT_SECCOMP scan.
            // Show the user the syscall name and an actionable next step.
            eprintln!(
                "  {RED}\u{26a0} Agent killed: seccomp violation \u{2014} attempted {}(2){RESET}\n    \
                 This syscall is blocked by the sandbox profile. {} violation(s) total.\n    \
                 Either remove the call from the agent or run without --sandbox.",
                name, count
            );
        }
        SeccompViolation {
            count,
            syscall: None,
        } => {
            // dmesg unavailable or no matching record — fall back to the
            // pointer message so the user can inspect manually.
            eprintln!(
                "  {RED}\u{26a0} Agent killed: {} seccomp violation(s){RESET}\n    \
                 Inspect blocked syscall(s): dmesg | grep SECCOMP",
                count
            );
        }
        OomKill {
            memory_limit_mb: Some(mb),
        } => {
            eprintln!(
                "  {RED}\u{26a0} Agent killed: out of memory (limit: {}MB){RESET}\n    \
                 Try: gvm run --sandbox --memory {}m ...",
                mb,
                mb * 2
            );
        }
        OomKill {
            memory_limit_mb: None,
        } => {
            eprintln!(
                "  {RED}\u{26a0} Agent killed: out of memory (system OOM, no --memory limit set){RESET}"
            );
        }
        ExternalKill { signal } => {
            eprintln!(
                "  {YELLOW}\u{26a0} Agent killed by external signal {} (not GVM-initiated){RESET}\n    \
                 Another process sent SIGKILL/SIGTERM. Check: ps, systemd, OOM killer outside cgroup",
                signal
            );
        }
    }

    // CPU throttling note (independent of exit reason — agent may have completed
    // successfully but slowly because of --cpus limit).
    if let Some(throttled) = cpu_throttled_us {
        if throttled > 1_000_000 {
            eprintln!(
                "  {DIM}Note: agent CPU throttled for {:.1}s. Increase --cpus if performance matters.{RESET}",
                throttled as f64 / 1_000_000.0
            );
        }
    }
}

/// Print the post-cleanup residual report. Silent on a fully-clean exit
/// (the common case) so we don't add noise; verbose with manual recovery
/// commands when leaks exist so users have an actionable next step.
pub fn print_cleanup_verification(v: &gvm_sandbox::CleanupVerification) {
    use crate::ui::{DIM, GREEN, RED, RESET, YELLOW};

    if v.is_clean() {
        // Don't spam the happy path. The diagnostic exists for when something
        // goes wrong — silence is the success signal.
        eprintln!("  {DIM}Cleanup verified: network, mounts, cgroup, state file all clean.{RESET}");
        return;
    }

    eprintln!();
    eprintln!(
        "  {YELLOW}Cleanup verification: {} residual(s) detected{RESET}",
        v.total()
    );

    // Network category
    if v.network_residuals.is_empty() {
        eprintln!("  {GREEN}\u{2713}{RESET} Network: clean");
    } else {
        for r in &v.network_residuals {
            eprintln!("  {RED}\u{2717}{RESET} Network: {}", r);
        }
        // Recovery hint — `gvm cleanup` re-runs the orphan sweep and will
        // catch leftover veth/iptables on a second pass.
        eprintln!("    Run: {}gvm cleanup{}", DIM, RESET);
    }

    // Mount category
    if v.mount_residuals.is_empty() {
        eprintln!("  {GREEN}\u{2713}{RESET} Mounts: clean");
    } else {
        for path in &v.mount_residuals {
            eprintln!(
                "  {RED}\u{2717}{RESET} Mount: {} still in /proc/mounts",
                path
            );
            eprintln!("    Run: sudo umount -l {}", path);
        }
    }

    // Cgroup category
    match &v.cgroup_residual {
        None => eprintln!("  {GREEN}\u{2713}{RESET} Cgroup: removed"),
        Some(path) => {
            eprintln!("  {RED}\u{2717}{RESET} Cgroup: {} still present", path);
            eprintln!("    Run: sudo rmdir {}", path);
        }
    }

    // State file category
    match &v.state_file_residual {
        None => eprintln!("  {GREEN}\u{2713}{RESET} State file: removed"),
        Some(path) => {
            eprintln!("  {RED}\u{2717}{RESET} State file: {} still present", path);
            eprintln!("    Run: sudo rm {}", path);
        }
    }
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
pub fn post_exit_audit(
    config: &AgentConfig,
    pre: &PreLaunchState,
    exit_code: i32,
    runtime_secs: u64,
) {
    eprintln!();
    if exit_code == 0 {
        eprintln!("  {GREEN}Process completed successfully{RESET}");
    } else {
        eprintln!("  {YELLOW}Process exited with code: {}{RESET}", exit_code);
    }

    // Fast exit warning: agent died very quickly, likely a startup failure.
    // Common causes: missing API key, bad arguments, sandbox fs/network issue.
    if runtime_secs < 10 && exit_code != 0 {
        eprintln!(
            "  {RED}\u{26a0} Agent exited in {}s with code {} — possible startup failure.{RESET}",
            runtime_secs, exit_code
        );
        if config.mode == LaunchMode::Sandbox {
            eprintln!(
                "  {DIM}Try running without --sandbox to see the agent's error output.{RESET}"
            );
        }
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
        let caution_count =
            crate::suggest::count_default_caution_hits("data/wal.log", pre.wal_offset);
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
                config
                    .command
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("agent.py")
            );
            eprintln!();
        }
    }
}

// ─── Background tasks ───

/// Handles for background tasks that run alongside the agent.
///
/// Previously this also spawned an IC-3 approval poller that interleaved
/// y/n prompts with the agent's stdout — that was removed because it
/// fought for stdin with the running agent and produced confusing
/// interleaved output. The single supported channel for human approval
/// is now `gvm approve` in a separate terminal (or `--auto-deny` in CI).
/// `gvm run` itself only forwards a one-line hint when it sees that the
/// proxy has at least one rule that can produce `RequireApproval`.
pub struct BackgroundTasks {
    watchdog: tokio::task::JoinHandle<()>,
}

impl BackgroundTasks {
    /// Spawn watchdog only. IC-3 approvals are no longer polled inline.
    pub fn spawn(proxy: &str) -> Self {
        let proxy_url = proxy.to_string();
        let workspace = run::workspace_root_for_proxy();
        let watchdog = tokio::spawn(crate::proxy_manager::watchdog(proxy_url, workspace));
        Self { watchdog }
    }

    /// Abort all background tasks.
    pub fn abort(self) {
        self.watchdog.abort();
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
    let launch_start = std::time::Instant::now();
    let exit_code = launch(&config, &pre).await.unwrap_or_else(|e| {
        eprintln!("  {RED}Execution failed: {e}{RESET}");
        1
    });
    let runtime_secs = launch_start.elapsed().as_secs();

    // Stop background tasks
    tasks.abort();

    // Phase 3
    post_exit_audit(&config, &pre, exit_code, runtime_secs);

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
                eprintln!(
                    "{DIM}All HTTP traffic will be routed through GVM proxy for governance.{RESET}"
                );
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
    eprintln!(
        "  {DIM}Agent ID:{RESET}     {CYAN}{}{RESET}",
        config.agent_id
    );
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
            eprintln!(
                "      {DIM}\u{2022} Network namespace: veth pair, proxy-only routing{RESET}"
            );
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
        eprintln!(
            "    {GREEN}Created:{RESET}  {} ({})  {DIM}auto-merged \u{2192} {}{RESET}",
            f.path.display(),
            format_size(f.size),
            dst.display()
        );
    }

    // Needs review: show kind + reason
    for f in &diff.needs_review {
        let kind_str = match f.kind {
            ChangeKind::Created => "Created",
            ChangeKind::Modified => "Modified",
            ChangeKind::Deleted => "Deleted",
        };
        eprintln!(
            "    {YELLOW}{kind_str}:{RESET}  {} ({})  {DIM}needs review ({}){RESET}",
            f.path.display(),
            format_size(f.size),
            f.matched_pattern
        );
    }

    // Discarded: summary only
    if !diff.discarded.is_empty() {
        eprintln!(
            "    {DIM}Discarded: {} file(s){RESET}",
            diff.discarded.len()
        );
    }

    // Interactive review for needs_review files (TTY only)
    if !diff.needs_review.is_empty() {
        let staging_dir =
            std::path::PathBuf::from(format!("data/sandbox-staging/{}", std::process::id()));

        // Write a manifest.json sidecar so `gvm fs approve` can drain
        // staged files later. The manifest records the workspace
        // destination (staging is keyed by PID, but the workspace is only
        // known here), the agent identity, and per-file metadata so the
        // standalone approver can render the same prompt without
        // re-running the sandbox. We write this UNCONDITIONALLY before
        // interactive review — even the TTY user can choose `s` (skip
        // all), in which case the manifest is the only thing that lets
        // them come back later.
        if staging_dir.exists() {
            write_staging_manifest(&staging_dir, workspace, diff);
        }

        if is_interactive_foreground() && staging_dir.exists() {
            eprintln!();
            let mut accepted = 0usize;
            let mut rejected = 0usize;

            for (i, f) in diff.needs_review.iter().enumerate() {
                let staged = staging_dir.join(&f.path);
                eprintln!(
                    "  {BOLD}[{}/{}]{RESET} {} ({}, {})",
                    i + 1,
                    diff.needs_review.len(),
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
                            eprintln!(
                                "  {DIM}... ({} more lines){RESET}",
                                content.lines().count() - 10
                            );
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
                            // Copy staged file to workspace, then remove
                            // the staged source so a partial-accept session
                            // (skip rest, run `gvm fs approve` later) does
                            // not re-prompt this file.
                            if !staged.exists() {
                                eprintln!(
                                    "  {YELLOW}\u{26a0}{RESET} {} {DIM}(staged file gone — \
                                     concurrent gvm fs approve --reject-all?){RESET}",
                                    f.path.display()
                                );
                            } else {
                                let dst = workspace.join(&f.path);
                                if let Some(parent) = dst.parent() {
                                    std::fs::create_dir_all(parent).ok();
                                }
                                match std::fs::copy(&staged, &dst) {
                                    Ok(_) => {
                                        let _ = std::fs::remove_file(&staged);
                                        eprintln!(
                                            "  {GREEN}\u{2713}{RESET} {} \u{2192} {}",
                                            f.path.display(),
                                            dst.display()
                                        );
                                        accepted += 1;
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                        eprintln!(
                                            "  {YELLOW}\u{26a0}{RESET} {} {DIM}(vanished \
                                             mid-copy){RESET}",
                                            f.path.display()
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!("  {RED}\u{2717}{RESET} copy failed: {}", e);
                                    }
                                }
                            }
                        }
                        "s" | "skip" => {
                            eprintln!("  {DIM}Skipping remaining files{RESET}");
                            break;
                        }
                        _ => {
                            eprintln!(
                                "  {RED}\u{2717}{RESET} {} rejected (original preserved)",
                                f.path.display()
                            );
                            rejected += 1;
                        }
                    }
                }
            }

            eprintln!();
            eprintln!(
                "  {BOLD}Summary:{RESET} {} merged, {} accepted, {} rejected, {} discarded",
                diff.auto_merged.len(),
                accepted,
                rejected,
                diff.discarded.len()
            );

            // Clean up staging only if the user actually drained the
            // queue interactively. If they hit `s` (skip all), there
            // are still files left and the manifest is the audit trail
            // for `gvm fs approve` to pick up later — we keep both so
            // disk leak prevention falls back to that path instead of
            // silently deleting their pending files.
            if accepted + rejected >= diff.needs_review.len() {
                std::fs::remove_dir_all(&staging_dir).ok();
            } else {
                eprintln!(
                    "  {DIM}{} file(s) still pending. Drain later with: \
                     {CYAN}gvm fs approve{RESET}",
                    diff.needs_review.len() - accepted - rejected
                );
            }
        } else {
            // Non-TTY: print staging path
            eprintln!();
            if staging_dir.exists() {
                eprintln!("  {DIM}Files staged at: {}{RESET}", staging_dir.display());
                eprintln!("  {DIM}Review and approve: {CYAN}gvm fs approve{RESET}");
            } else {
                eprintln!(
                    "  {DIM}{} file(s) need review but staging unavailable{RESET}",
                    diff.needs_review.len()
                );
            }
        }
    }

    eprintln!();
}

/// Persist a manifest sidecar so `gvm fs approve` can drain this staging
/// dir without needing the original sandbox process. Best-effort: a
/// failed write is logged but never aborts the run, because the agent
/// has already exited and the staged files are still on disk regardless.
fn write_staging_manifest(
    staging_dir: &std::path::Path,
    workspace: &std::path::Path,
    diff: &gvm_sandbox::filesystem::FsDiffReport,
) {
    use gvm_sandbox::filesystem::ChangeKind;

    let entries: Vec<serde_json::Value> = diff
        .needs_review
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path.display().to_string(),
                "size": f.size,
                "kind": match f.kind {
                    ChangeKind::Created => "Created",
                    ChangeKind::Modified => "Modified",
                    ChangeKind::Deleted => "Deleted",
                },
                "matched_pattern": f.matched_pattern,
            })
        })
        .collect();

    let manifest = serde_json::json!({
        "version": 1,
        "pid": std::process::id(),
        "workspace": workspace.display().to_string(),
        "created_at": chrono::Utc::now().to_rfc3339(),
        "entries": entries,
    });

    let manifest_path = staging_dir.join("manifest.json");
    if let Err(e) = std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    ) {
        eprintln!(
            "  {YELLOW}\u{26a0}{RESET} {DIM}Failed to write fs staging manifest \
             ({}): {}. `gvm fs approve` will not see this batch.{RESET}",
            manifest_path.display(),
            e
        );
    }
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

/// Return true only when the process can safely prompt the user interactively.
///
/// `is_terminal()` alone is not enough. In a pipeline like
/// `sudo gvm run --sandbox -- python ... | grep ...`, gvm inherits the shell's
/// controlling tty on stdin (so `is_terminal()` returns true) but sits in a
/// *background* process group because of the pipeline. A bare `read_line()`
/// on stdin in that state triggers `SIGTTIN` and the kernel puts the process
/// into state `T` (stopped) — `timeout 30` can't even kill it because SIGTERM
/// queues behind the stop and never delivers. Every test doing
/// `sudo gvm run --sandbox -- ... | grep ...` hangs forever.
///
/// Fix: require stdin AND stderr to be ttys *and* the current process group
/// to be the foreground group of that tty. When any of those fails we skip
/// the prompt and rely on the staging manifest so the user can drain the
/// batch later with `gvm fs approve`.
#[cfg(unix)]
fn is_interactive_foreground() -> bool {
    use std::io::IsTerminal;
    use std::os::unix::io::AsRawFd;

    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return false;
    }

    // tcgetpgrp(stdin) == getpgrp() means "we own the foreground of this tty".
    // Background pipeline: tcgetpgrp returns the shell's pgrp, not ours.
    let stdin_fd = std::io::stdin().as_raw_fd();
    // SAFETY: we just checked stdin is a terminal; getpgrp is infallible.
    unsafe {
        let tty_pgrp = libc::tcgetpgrp(stdin_fd);
        if tty_pgrp < 0 {
            return false; // no controlling terminal
        }
        let our_pgrp = libc::getpgrp();
        tty_pgrp == our_pgrp
    }
}

#[cfg(not(unix))]
fn is_interactive_foreground() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}
