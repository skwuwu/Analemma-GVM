//! Pre-flight capability checks for sandbox creation.
//!
//! Verifies kernel features (user namespaces, seccomp), interpreter availability,
//! and network configuration before attempting to create a sandbox.

use crate::{PreflightReport, SandboxConfig};
use std::path::Path;

/// Run all pre-flight checks and return a structured report.
pub fn check(config: &SandboxConfig) -> PreflightReport {
    let mut issues = Vec::new();

    let user_namespaces = check_user_namespaces();
    if !user_namespaces {
        issues.push(
            "User namespaces are disabled. Enable with: \
             sudo sysctl kernel.unprivileged_userns_clone=1"
                .to_string(),
        );
    }

    let seccomp_available = check_seccomp();
    if !seccomp_available {
        issues.push("seccomp-BPF is not supported by this kernel.".to_string());
    }

    let net_admin_capability = check_cap_net_admin();
    if !net_admin_capability {
        issues.push(
            "CAP_NET_ADMIN is missing. veth and iptables setup requires elevated network capabilities.".to_string(),
        );
    }

    let ip_forward = check_ip_forward();
    if !ip_forward {
        issues.push(
            "IP forwarding is disabled. Enable with: \
             sudo sysctl net.ipv4.ip_forward=1"
                .to_string(),
        );
    }

    let ip_command_available = check_interpreter("ip");
    if !ip_command_available {
        issues.push("`ip` command not found in PATH (install iproute2).".to_string());
    }

    let iptables_command_available = check_interpreter("iptables");
    if !iptables_command_available {
        issues.push("`iptables` command not found in PATH.".to_string());
    }

    // ip6tables is optional but recommended — without it the sandbox cannot
    // disable IPv6 inside the netns and AAAA-resolving agents may bypass v4
    // enforcement. Surfaced as a non-blocking warning.
    let ip6tables_command_available = check_interpreter("ip6tables");
    if !ip6tables_command_available {
        issues.push(
            "`ip6tables` command not found — sandbox cannot disable IPv6 inside the netns. \
             AAAA-resolving agents may bypass v4 rules. Install via your distro's iptables package."
                .to_string(),
        );
    }

    let interpreter_found = check_interpreter(&config.interpreter);
    if !interpreter_found {
        issues.push(format!(
            "Interpreter '{}' not found in PATH.",
            config.interpreter
        ));
    }

    if !check_command_exists("iptables") {
        issues.push(
            "iptables not found. Required for sandbox network lockdown. \
             Install with: sudo apt install iptables"
                .to_string(),
        );
    }

    let tc_filter_available = crate::tc_filter::check_tc_support().is_ok();
    if !tc_filter_available {
        issues.push(
            "TC ingress filter unavailable — falling back to iptables \
             (seccomp AF_NETLINK blocking provides defense-in-depth)."
                .to_string(),
        );
    }

    // ── Environment detection (non-blocking, diagnostic only) ──

    // route_localnet: required for DNAT from veth to loopback proxy.
    // Without this, packets DNAT'd to 127.0.0.1 are dropped by kernel.
    let route_localnet = check_route_localnet();
    if !route_localnet {
        issues.push(
            "route_localnet is disabled. Sandbox DNAT to loopback may fail. \
             Will be auto-enabled during sandbox setup."
                .to_string(),
        );
    }

    // DNS resolver type: systemd-resolved vs direct
    let has_systemd_resolved = Path::new("/run/systemd/resolve/resolv.conf").exists();
    if !has_systemd_resolved {
        // Not a hard error — resolve_host_dns() falls back to /etc/resolv.conf → 8.8.8.8
        tracing::debug!(
            "systemd-resolved not detected — DNS will use /etc/resolv.conf or fallback"
        );
    }

    // Kernel version (diagnostic logging, no blocking)
    if let Ok(utsname) = nix::sys::utsname::uname() {
        if let Some(version) = utsname.release().to_str() {
            tracing::info!(kernel = version, "Sandbox environment kernel version");
            // Warn about known problematic kernels
            if version.starts_with("6.17.") {
                tracing::warn!(
                    "Kernel 6.17.x detected — ldd-in-PID-namespace panic workaround active"
                );
            }
        }
    }

    PreflightReport {
        user_namespaces,
        seccomp_available,
        net_admin_capability,
        ip_forward,
        ip_command_available,
        iptables_command_available,
        ip6tables_command_available,
        interpreter_found,
        tc_filter_available,
        issues,
    }
}

/// Check if unprivileged user namespaces are enabled.
fn check_user_namespaces() -> bool {
    // Check sysctl kernel.unprivileged_userns_clone
    match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(val) => val.trim() == "1",
        // If the file doesn't exist, user namespaces may still be available
        // (some kernels don't have this sysctl but support user namespaces)
        Err(_) => {
            // Fallback: check /proc/sys/user/max_user_namespaces
            std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
                .map(|v| v.trim().parse::<u64>().unwrap_or(0) > 0)
                .unwrap_or(false)
        }
    }
}

/// Check if seccomp-BPF is supported.
fn check_seccomp() -> bool {
    // prctl(PR_GET_SECCOMP) returns 0 if seccomp is disabled but supported,
    // or the current mode if active. Returns -1/EINVAL if not supported.
    unsafe {
        let ret = libc::prctl(libc::PR_GET_SECCOMP);
        ret >= 0
    }
}

/// Check if current process has CAP_NET_ADMIN in effective capabilities.
///
/// Uses the `procfs` crate's structured `/proc/self/status` parser instead
/// of hand-rolled hex parsing — eliminates a class of off-by-one and
/// radix-parsing bugs.
fn check_cap_net_admin() -> bool {
    let cap_eff = match procfs::process::Process::myself().and_then(|p| p.status()) {
        Ok(status) => status.capeff,
        Err(_) => return false,
    };

    // Linux capability index for CAP_NET_ADMIN.
    const CAP_NET_ADMIN_BIT: u64 = 12;
    (cap_eff & (1u64 << CAP_NET_ADMIN_BIT)) != 0
}

/// Check if IP forwarding is enabled.
fn check_ip_forward() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Check if route_localnet is enabled (required for DNAT to loopback).
fn check_route_localnet() -> bool {
    // Check both global and per-interface settings.
    // Sandbox setup enables this automatically, but preflight warns if it's off.
    std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/route_localnet")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Check if the interpreter binary exists in PATH.
fn check_interpreter(interpreter: &str) -> bool {
    which_interpreter(interpreter).is_some()
}

/// Check if a command exists in PATH.
fn check_command_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Resolve interpreter binary path.
pub fn which_interpreter(interpreter: &str) -> Option<std::path::PathBuf> {
    // Check if it's an absolute path
    let path = Path::new(interpreter);
    if path.is_absolute() && path.exists() {
        return Some(path.to_path_buf());
    }

    // Search PATH
    if let Ok(paths) = std::env::var("PATH") {
        for dir in paths.split(':') {
            let candidate = Path::new(dir).join(interpreter);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}
