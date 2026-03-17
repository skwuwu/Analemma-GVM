//! Main sandbox orchestration: clone, setup, exec.
//!
//! Coordinates namespace creation, mount setup, network configuration,
//! and seccomp application into a single launch sequence.

use crate::capability::which_interpreter;
use crate::mount::setup_mount_namespace;
use crate::namespace::{
    coordination_pipe, sandbox_clone_flags, signal_child_ready, wait_for_parent, write_uid_map,
};
use crate::network::{cleanup_host_network, setup_host_network, setup_sandbox_network, VethConfig};
use crate::seccomp::apply_seccomp_filter;
use crate::{SandboxConfig, SandboxResult};
use anyhow::{Context, Result};
use nix::sys::wait::{waitpid, WaitStatus};

/// Stack size for the cloned child process (2 MB).
const CHILD_STACK_SIZE: usize = 2 * 1024 * 1024;

/// Launch an agent inside a fully isolated Linux sandbox.
pub fn launch(config: SandboxConfig) -> Result<SandboxResult> {
    let start = std::time::Instant::now();

    // Pre-flight: resolve interpreter path
    let interpreter_path = which_interpreter(&config.interpreter)
        .with_context(|| format!("Interpreter '{}' not found in PATH", config.interpreter))?;

    // Create coordination pipe
    let (parent_fd, child_fd) = coordination_pipe()?;

    // Allocate child stack
    let mut stack = vec![0u8; CHILD_STACK_SIZE];

    // Clone with full namespace isolation
    let clone_flags = sandbox_clone_flags();

    // Prepare data for the child closure
    let child_config = config.clone();
    let child_interpreter_path = interpreter_path.clone();

    let child_pid = unsafe {
        nix::sched::clone(
            Box::new(move || {
                // ── Child process (inside new namespaces) ──
                child_entry(child_fd, &child_config, &child_interpreter_path)
            }),
            &mut stack,
            clone_flags,
            Some(nix::sys::signal::SIGCHLD as i32),
        )
    }
    .context("clone() failed — ensure user namespaces are enabled")?;

    tracing::info!(
        child_pid = child_pid.as_raw(),
        "Sandbox child process created"
    );

    // ── Parent process: set up UID mapping and network ──

    // 1. Write UID/GID mapping
    write_uid_map(child_pid)?;

    // 2. Set up veth network pair
    let veth_config = VethConfig::from_pid(child_pid.as_raw() as u32, config.proxy_addr);
    let network_result = setup_host_network(&veth_config);

    if let Err(ref e) = network_result {
        tracing::warn!(error = %e, "Host network setup failed — sandbox will have no network");
    }

    // 3. Signal child that setup is complete
    signal_child_ready(parent_fd, child_pid.as_raw() as u32)?;

    let setup_ms = start.elapsed().as_millis() as u64;
    tracing::info!(setup_ms = setup_ms, "Sandbox setup complete, waiting for agent");

    // 4. Wait for child to exit
    let exit_code = match waitpid(child_pid, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        Ok(WaitStatus::Signaled(_, signal, _)) => {
            tracing::warn!(signal = ?signal, "Agent killed by signal");
            128 + signal as i32
        }
        Ok(status) => {
            tracing::warn!(status = ?status, "Unexpected wait status");
            1
        }
        Err(e) => {
            tracing::error!(error = %e, "waitpid failed");
            1
        }
    };

    // 5. Clean up host-side network
    if network_result.is_ok() {
        cleanup_host_network(&veth_config);
    }

    Ok(SandboxResult {
        exit_code,
        setup_ms,
        seccomp_violations: 0, // TODO: track via SECCOMP_RET_LOG
    })
}

/// Child process entry point (runs inside new namespaces).
fn child_entry(
    coord_fd: std::os::unix::io::RawFd,
    config: &SandboxConfig,
    interpreter_path: &std::path::Path,
) -> isize {
    // Wait for parent to complete UID mapping and network setup
    let network_seed = match wait_for_parent(coord_fd) {
        Ok(seed) => seed,
        Err(e) => {
            eprintln!("gvm-sandbox: coordination failed: {}", e);
            return 1;
        }
    };

    // Use parent-provided seed so interface names/IPs match host-side setup.
    let veth_config = VethConfig::from_pid(network_seed, config.proxy_addr);

    // Set up network inside the sandbox
    if let Err(e) = setup_sandbox_network(&veth_config) {
        // Network failure is non-fatal for debugging — agent just won't have connectivity
        eprintln!("gvm-sandbox: network setup failed (non-fatal): {}", e);
    }

    // Set up mount namespace (pivot_root)
    // DNS server must match the OUTPUT iptables rule (host veth IP)
    if let Err(e) = setup_mount_namespace(&config.workspace_dir, interpreter_path, &veth_config.host_ip) {
        eprintln!("gvm-sandbox: mount namespace setup failed: {}", e);
        return 1;
    }

    // Apply seccomp-BPF filter (must be last before exec)
    if let Err(e) = apply_seccomp_filter(&config.seccomp_profile) {
        eprintln!("gvm-sandbox: seccomp filter failed: {}", e);
        return 1;
    }

    // Prepare environment variables
    let proxy_url = format!("http://{}:{}", veth_config.host_ip, config.proxy_addr.port());

    // Build exec arguments
    let interpreter_name = interpreter_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&config.interpreter);

    let bin_path = format!("/bin/{}", interpreter_name);

    // Set environment and exec
    std::env::set_var("HTTP_PROXY", &proxy_url);
    std::env::set_var("HTTPS_PROXY", &proxy_url);
    std::env::set_var("http_proxy", &proxy_url);
    std::env::set_var("https_proxy", &proxy_url);
    std::env::set_var("GVM_AGENT_ID", &config.agent_id);
    std::env::set_var("GVM_PROXY_URL", &proxy_url);
    std::env::set_var("HOME", "/workspace");
    std::env::set_var("TMPDIR", "/tmp");

    // Build argv: [interpreter, ...args]
    let c_bin = std::ffi::CString::new(bin_path.clone()).unwrap();
    let mut c_args: Vec<std::ffi::CString> = vec![c_bin.clone()];
    for arg in &config.interpreter_args {
        c_args.push(std::ffi::CString::new(arg.as_str()).unwrap());
    }

    // exec replaces the process — this never returns on success
    match nix::unistd::execv(&c_bin, &c_args) {
        Ok(_) => unreachable!(),
        Err(e) => {
            eprintln!("gvm-sandbox: exec failed: {} (path: {})", e, bin_path);
            1
        }
    }
}
