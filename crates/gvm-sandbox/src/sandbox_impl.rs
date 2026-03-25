//! Main sandbox orchestration: clone, setup, exec.
//!
//! Coordinates namespace creation, mount setup, network configuration,
//! and seccomp application into a single launch sequence.

use crate::capability::which_interpreter;
use crate::ebpf::{self, EbpfAttachResult};
use crate::mount::setup_mount_namespace;
use crate::namespace::{
    coordination_pipe, sandbox_clone_flags, signal_child_ready, wait_for_parent, write_uid_map,
};
use crate::network::{cleanup_host_network, setup_host_network, setup_sandbox_network, VethConfig};
use crate::seccomp::{apply_seccomp_filter, count_seccomp_violations};
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

    // Generate ephemeral CA for transparent MITM (if proxy_url set)
    let ca_cert_pem: Option<Vec<u8>> = if config.proxy_url.is_some() {
        match crate::ca::EphemeralCA::generate() {
            Ok(ca) => {
                tracing::info!("Ephemeral CA generated for sandbox MITM");
                Some(ca.ca_cert_pem().to_vec())
            }
            Err(e) => {
                tracing::warn!(error = %e, "CA generation failed — HTTPS inspection disabled");
                None
            }
        }
    } else {
        None
    };

    // Create coordination pipe
    let (parent_fd, child_fd) = coordination_pipe()?;

    // Allocate child stack
    let mut stack = vec![0u8; CHILD_STACK_SIZE];

    // Clone with full namespace isolation
    let clone_flags = sandbox_clone_flags();

    // Prepare data for the child closure
    let child_config = config.clone();
    let child_interpreter_path = interpreter_path.clone();
    let child_ca_pem = ca_cert_pem.clone();

    let child_pid = unsafe {
        nix::sched::clone(
            Box::new(move || {
                // ── Child process (inside new namespaces) ──
                child_entry(
                    child_fd,
                    &child_config,
                    &child_interpreter_path,
                    child_ca_pem.as_deref(),
                )
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
    } else {
        // Record network state for orphan cleanup on crash
        if let Err(e) = network::record_network_state(&veth_config) {
            tracing::debug!(error = %e, "Failed to record network state (orphan cleanup unavailable)");
        }
    }

    // 2.5. Attach eBPF TC ingress filter on host-side veth (unbypassable enforcement)
    //      This runs BEFORE signaling the child, so enforcement is active from first packet.
    //      If eBPF is unavailable, iptables provides baseline enforcement and
    //      seccomp AF_NETLINK blocking prevents iptables modification (defense-in-depth).
    let ebpf_attached = if network_result.is_ok() {
        let proxy_ip: std::net::Ipv4Addr = veth_config
            .host_ip
            .parse()
            .unwrap_or(std::net::Ipv4Addr::new(10, 200, 0, 1));
        match ebpf::try_attach_tc_filter(
            &veth_config.host_iface,
            proxy_ip,
            veth_config.proxy_addr.port(),
        ) {
            EbpfAttachResult::Attached { interface } => {
                tracing::info!(
                    interface = %interface,
                    "eBPF TC filter ACTIVE — unbypassable proxy enforcement"
                );
                true
            }
            EbpfAttachResult::Unavailable { reason } => {
                tracing::warn!(
                    reason = %reason,
                    "eBPF TC filter unavailable — using iptables with seccomp defense-in-depth"
                );
                false
            }
        }
    } else {
        false
    };

    // 2.7. Set up cgroup resource limits (if configured)
    let _cgroup_guard = if config.memory_limit.is_some() || config.cpu_limit.is_some() {
        match crate::cgroup::CgroupGuard::create(
            child_pid.as_raw() as u32,
            config.memory_limit,
            config.cpu_limit,
        ) {
            Ok(guard) => guard,
            Err(e) => {
                tracing::warn!(error = %e, "cgroup setup failed — continuing without resource limits");
                None
            }
        }
    } else {
        None
    };

    // 3. Signal child that setup is complete
    signal_child_ready(parent_fd, child_pid.as_raw() as u32)?;

    let setup_ms = start.elapsed().as_millis() as u64;
    tracing::info!(
        setup_ms = setup_ms,
        "Sandbox setup complete, waiting for agent"
    );

    // 3.5. TLS uprobe (experimental, observation-only — gated behind `uprobe` feature flag)
    //
    // The uprobe attaches to SSL_write_ex and captures plaintext before encryption.
    // MITM (transparent TLS proxy on port 8443) is the primary HTTPS inspection mechanism.
    // The uprobe is an optional defense-in-depth layer for environments where MITM is not
    // available or as a secondary observation channel.
    //
    // Enable at compile time: cargo build --features uprobe
    #[cfg(feature = "uprobe")]
    let _tls_probe_handle = {
        let child_raw = child_pid.as_raw() as u32;
        let probe_mode = &config.tls_probe_mode;
        let audit_only = matches!(probe_mode, crate::TlsProbeMode::Audit);
        let disabled = matches!(probe_mode, crate::TlsProbeMode::Disabled);

        if disabled {
            tracing::debug!("TLS probe disabled by config");
            None
        } else {
            std::thread::sleep(std::time::Duration::from_millis(500));

            let policy_callback: crate::tls_probe::PolicyCheckFn = if let Some(ref proxy_url) =
                config.proxy_url
            {
                let check_url = format!("{}/gvm/check", proxy_url.trim_end_matches('/'));
                let agent = ureq::AgentBuilder::new()
                    .timeout_connect(std::time::Duration::from_millis(50))
                    .timeout_read(std::time::Duration::from_millis(50))
                    .timeout_write(std::time::Duration::from_millis(50))
                    .build();
                Box::new(move |method: &str, host: &str, path: &str| {
                    let body = serde_json::json!({
                        "method": method,
                        "target_host": host,
                        "target_path": path,
                        "operation": "uprobe",
                    });
                    match agent
                        .post(&check_url)
                        .set("Content-Type", "application/json")
                        .set("X-GVM-Uprobe-Token", "internal")
                        .send_string(&body.to_string())
                    {
                        Ok(resp) => {
                            let text = resp.into_string().unwrap_or_default();
                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                let decision = json
                                    .get("decision")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Deny");
                                match decision {
                                    d if d.contains("Allow") => {
                                        crate::tls_probe::PolicyDecision::Allow
                                    }
                                    d if d.contains("Delay") => {
                                        let ms = json
                                            .get("delay_ms")
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(300);
                                        crate::tls_probe::PolicyDecision::Delay { milliseconds: ms }
                                    }
                                    _ => {
                                        let reason = json
                                            .get("next_action")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("blocked by policy")
                                            .to_string();
                                        crate::tls_probe::PolicyDecision::Deny { reason }
                                    }
                                }
                            } else {
                                crate::tls_probe::PolicyDecision::Deny {
                                    reason: "uprobe: unparseable proxy response".into(),
                                }
                            }
                        }
                        Err(_e) => {
                            crate::tls_probe::PolicyDecision::Deny {
                                reason: "uprobe: proxy unreachable — fail-closed".into(),
                            }
                        }
                    }
                })
            } else {
                Box::new(|_method: &str, _host: &str, _path: &str| {
                    crate::tls_probe::PolicyDecision::Allow
                })
            };

            match crate::tls_probe::start_tls_probe_thread(child_raw, policy_callback, audit_only) {
                Ok(handle) => {
                    let mode = if audit_only { "audit" } else { "enforce" };
                    tracing::info!(pid = child_raw, mode, "TLS uprobe started (experimental)");
                    Some(handle)
                }
                Err(e) => {
                    tracing::debug!(
                        pid = child_raw, error = %e,
                        "TLS probe not available — MITM is primary HTTPS inspection"
                    );
                    None
                }
            }
        }
    };
    #[cfg(not(feature = "uprobe"))]
    let _tls_probe_handle: Option<()> = None;

    // 4. Wait for child to exit and detect seccomp violations
    let wait_result = waitpid(child_pid, None);
    let seccomp_violations = match &wait_result {
        Ok(status) => count_seccomp_violations(status),
        Err(_) => 0,
    };

    let exit_code = match wait_result {
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

    if seccomp_violations > 0 {
        tracing::error!(
            violations = seccomp_violations,
            child_pid = child_pid.as_raw(),
            "Seccomp violations detected — agent attempted blocked syscall(s). \
             Check 'dmesg | grep SECCOMP' or 'ausearch -m SECCOMP' for details."
        );
    }

    // 5. Clean up host-side network (eBPF filter + iptables rules + veth pair)
    if network_result.is_ok() {
        if ebpf_attached {
            ebpf::detach_tc_filter(&veth_config.host_iface);
        }
        cleanup_host_network(&veth_config);
        network::clear_network_state();
    }

    Ok(SandboxResult {
        exit_code,
        setup_ms,
        seccomp_violations,
    })
}

/// Child process entry point (runs inside new namespaces).
fn child_entry(
    coord_fd: std::os::unix::io::RawFd,
    config: &SandboxConfig,
    interpreter_path: &std::path::Path,
    ca_cert_pem: Option<&[u8]>,
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
    if let Err(e) = setup_mount_namespace(
        &config.workspace_dir,
        interpreter_path,
        &veth_config.host_ip,
        ca_cert_pem,
    ) {
        eprintln!("gvm-sandbox: mount namespace setup failed: {}", e);
        return 1;
    }

    // Apply seccomp-BPF filter (must be last before exec)
    if let Err(e) = apply_seccomp_filter(&config.seccomp_profile) {
        eprintln!("gvm-sandbox: seccomp filter failed: {}", e);
        return 1;
    }

    // Prepare environment variables
    let proxy_url = format!(
        "http://{}:{}",
        veth_config.host_ip,
        config.proxy_addr.port()
    );

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

    // CA trust store env vars (for transparent MITM in sandbox)
    if ca_cert_pem.is_some() {
        let ca_path = "/etc/ssl/certs/gvm-ca.crt";
        std::env::set_var("SSL_CERT_FILE", ca_path);
        std::env::set_var("REQUESTS_CA_BUNDLE", ca_path);
        std::env::set_var("NODE_EXTRA_CA_CERTS", ca_path);
        std::env::set_var("CURL_CA_BUNDLE", ca_path);
    }

    // Build argv: [interpreter, ...args]
    let c_bin = std::ffi::CString::new(bin_path.clone()).unwrap();
    let mut c_args: Vec<std::ffi::CString> = vec![c_bin.clone()];
    for arg in &config.interpreter_args {
        c_args.push(std::ffi::CString::new(arg.as_str()).unwrap());
    }

    // ── PID 1 init reaper ──
    //
    // We are PID 1 inside CLONE_NEWPID. If we exec directly, the agent
    // interpreter becomes PID 1 but does NOT reap orphaned children.
    // When the agent spawns subprocesses (subprocess.Popen, child_process.exec)
    // that exit, they become zombies (Z state). Eventually the PID table fills
    // and the agent can't fork at all.
    //
    // Fix: fork(). The child execs the agent. This process (PID 1) stays alive
    // as a minimal init: it loops on waitpid(-1) to reap ANY child (including
    // orphans reparented to PID 1), and exits with the agent's exit code.
    //
    // This is equivalent to tini/dumb-init but without an external dependency.
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("gvm-sandbox: fork() for init reaper failed");
            1
        }
        0 => {
            // ── Child: exec the agent ──
            match nix::unistd::execv(&c_bin, &c_args) {
                Ok(_) => unreachable!(),
                Err(e) => {
                    eprintln!("gvm-sandbox: exec failed: {} (path: {})", e, bin_path);
                    // _exit to avoid running destructors in forked child
                    unsafe { libc::_exit(1) };
                }
            }
        }
        agent_pid => {
            // ── PID 1 (init reaper): wait for agent + reap orphans ──
            let mut agent_exit_code: i32 = 1;

            loop {
                let mut status: i32 = 0;
                let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
                if pid < 0 {
                    // ECHILD: no more children — all reaped, agent is gone
                    break;
                }
                if pid == agent_pid {
                    // Agent exited — record its exit code
                    if libc::WIFEXITED(status) {
                        agent_exit_code = libc::WEXITSTATUS(status);
                    } else if libc::WIFSIGNALED(status) {
                        agent_exit_code = 128 + libc::WTERMSIG(status);
                    }
                    // Don't break yet — there may still be orphaned children
                    // that need reaping. Continue until ECHILD.
                }
                // Any other PID: orphaned child reaped (zombie cleaned up).
            }

            // Use _exit to avoid running Rust destructors in the clone'd process.
            // The parent process (outside the namespace) handles cleanup.
            unsafe { libc::_exit(agent_exit_code) };
        }
    }
}
