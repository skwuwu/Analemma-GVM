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

    // 3. Signal child that setup is complete
    signal_child_ready(parent_fd, child_pid.as_raw() as u32)?;

    let setup_ms = start.elapsed().as_millis() as u64;
    tracing::info!(
        setup_ms = setup_ms,
        "Sandbox setup complete, waiting for agent"
    );

    // 3.5. Start TLS probe (uprobe on SSL_write_ex for HTTPS L7 inspection)
    // Captures plaintext before encryption — enables path/method-level HTTPS enforcement.
    // Verified on WSL2 kernel 6.6 + OpenSSL 3.x: captures "GET /path HTTP/1.1" from SSL_write_ex.
    let _tls_probe_handle = {
        let child_raw = child_pid.as_raw() as u32;
        let probe_mode = &config.tls_probe_mode;
        let audit_only = matches!(probe_mode, crate::TlsProbeMode::Audit);
        let disabled = matches!(probe_mode, crate::TlsProbeMode::Disabled);

        if disabled {
            tracing::debug!("TLS probe disabled by config");
            None
        } else {
            // Give the child process time to exec and load TLS libraries
            std::thread::sleep(std::time::Duration::from_millis(500));

            // Build policy callback: query proxy /gvm/check for SRR decisions.
            //
            // Security notes:
            //   1. Race condition: SSL_write_ex fires AFTER the kernel queues the
            //      packet. SIGSTOP freezes the process but the triggering write may
            //      already be on the wire. This is "immediate session freeze on
            //      violation", not "pre-transmission block". Documented as known
            //      limitation — proxy CONNECT-level enforcement is the primary gate.
            //   2. Fail-closed: if the proxy is unreachable or times out, the
            //      callback returns Deny (SIGSTOP). This prevents bypass via proxy
            //      DoS but may freeze the agent on transient proxy hiccups.
            //   3. Timeout: 50ms cap. The uprobe thread is not on the hot path, but
            //      long blocks would delay SIGSTOP delivery.
            //   4. Auth: X-GVM-Uprobe-Token header prevents sandboxed agents from
            //      spoofing policy check requests to /gvm/check.
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
                                // Unparseable response: fail-closed
                                crate::tls_probe::PolicyDecision::Deny {
                                    reason: "uprobe: unparseable proxy response".into(),
                                }
                            }
                        }
                        Err(_e) => {
                            // Proxy unreachable or timeout: fail-closed (SIGSTOP)
                            crate::tls_probe::PolicyDecision::Deny {
                                reason: "uprobe: proxy unreachable — fail-closed".into(),
                            }
                        }
                    }
                })
            } else {
                // No proxy URL: audit-only (no enforcement possible)
                Box::new(|_method: &str, _host: &str, _path: &str| {
                    crate::tls_probe::PolicyDecision::Allow
                })
            };

            match crate::tls_probe::start_tls_probe_thread(child_raw, policy_callback, audit_only) {
                Ok(handle) => {
                    let mode = if audit_only { "audit" } else { "enforce" };
                    tracing::info!(pid = child_raw, mode, "TLS uprobe started");
                    Some(handle)
                }
                Err(e) => {
                    tracing::debug!(
                        pid = child_raw, error = %e,
                        "TLS probe not available — using domain-level HTTPS policy only"
                    );
                    None
                }
            }
        }
    };

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
