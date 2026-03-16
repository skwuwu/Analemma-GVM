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

    let ip_forward = check_ip_forward();
    if !ip_forward {
        issues.push(
            "IP forwarding is disabled. Enable with: \
             sudo sysctl net.ipv4.ip_forward=1"
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

    PreflightReport {
        user_namespaces,
        seccomp_available,
        ip_forward,
        interpreter_found,
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

/// Check if IP forwarding is enabled.
fn check_ip_forward() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
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
