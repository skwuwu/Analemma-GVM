//! Linux-native agent sandboxing for Analemma-GVM.
//!
//! Provides OS-level isolation using Linux namespaces (user, PID, mount, network),
//! seccomp-BPF syscall filtering, and a veth network pair that restricts agent
//! traffic to the GVM proxy only.
//!
//! On non-Linux platforms, the crate compiles but all operations return an error
//! directing the user to use `--contained` (Docker) instead.
//!
//! Architecture:
//! ```text
//! gvm run --sandbox my_agent.py
//!
//!   Parent (host)                Child (sandboxed)
//!   ┌────────────┐               ┌────────────────────────┐
//!   │ clone()    │──────────────>│ PID 1 (init)           │
//!   │ uid_map    │               │ mount namespace:        │
//!   │ veth setup │               │   /workspace (ro bind)  │
//!   │ iptables   │               │   /proc, /dev/null only │
//!   │ wait()     │               │ network namespace:      │
//!   └────────────┘               │   veth → proxy only     │
//!                                │ seccomp-BPF:            │
//!                                │   45 syscalls allowed   │
//!                                │ exec(python, agent.py)  │
//!                                └────────────────────────┘
//! ```
//!
//! Analogous to Firecracker's MicroVM approach: direct Linux syscalls,
//! no Docker overhead, no container runtime dependency.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Configuration for the sandbox environment.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Absolute path to the agent script.
    pub script_path: PathBuf,
    /// Directory to expose inside the sandbox (typically the script's parent).
    pub workspace_dir: PathBuf,
    /// Interpreter to use (python, node, bash).
    pub interpreter: String,
    /// Arguments to pass to the interpreter (e.g., the script filename).
    pub interpreter_args: Vec<String>,
    /// GVM proxy address for the veth network route.
    pub proxy_addr: SocketAddr,
    /// Agent ID for environment variable injection.
    pub agent_id: String,
    /// Optional seccomp profile override (None = default whitelist).
    pub seccomp_profile: Option<SeccompProfile>,
}

/// Seccomp profile selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SeccompProfile {
    /// Default whitelist: HTTP-capable agent (networking + file I/O).
    Default,
    /// Strict: no network sockets (offline computation only).
    Strict,
    /// Custom: path to a JSON seccomp profile.
    Custom(PathBuf),
}

/// Result of a sandboxed agent execution.
#[derive(Debug)]
pub struct SandboxResult {
    /// Agent process exit code.
    pub exit_code: i32,
    /// Sandbox setup time in milliseconds.
    pub setup_ms: u64,
    /// Whether seccomp violations were detected.
    pub seccomp_violations: u32,
}

/// Pre-flight check results.
#[derive(Debug)]
pub struct PreflightReport {
    /// Whether user namespaces are available (kernel.unprivileged_userns_clone).
    pub user_namespaces: bool,
    /// Whether seccomp-BPF is supported.
    pub seccomp_available: bool,
    /// Whether current process has CAP_NET_ADMIN (needed for veth/iptables setup).
    pub net_admin_capability: bool,
    /// Whether IP forwarding is enabled.
    pub ip_forward: bool,
    /// Whether the `ip` command is available.
    pub ip_command_available: bool,
    /// Whether the `iptables` command is available.
    pub iptables_command_available: bool,
    /// Whether the interpreter binary exists.
    pub interpreter_found: bool,
    /// Whether eBPF TC filter is available (kernel >= 4.15, tc command, BPF JIT).
    /// When true, TC ingress filter provides unbypassable proxy enforcement.
    /// When false, falls back to iptables (with seccomp AF_NETLINK defense-in-depth).
    pub ebpf_available: bool,
    /// Human-readable remediation messages for failures.
    pub issues: Vec<String>,
}

// ── Platform-specific implementation ──

#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod mount;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
mod capability;
#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod tls_probe;

#[cfg(target_os = "linux")]
mod sandbox_impl;

/// Launch an agent inside a Linux-native sandbox.
///
/// Orchestrates the full isolation sequence:
/// 1. Pre-flight checks (kernel features, interpreter, capabilities)
/// 2. clone(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET)
/// 3. Parent: uid_map, veth pair, IP routing, iptables DNAT
/// 4. Child: mount namespace (pivot_root), network config, seccomp-BPF, exec
///
/// Returns the agent's exit code wrapped in SandboxResult.
#[cfg(target_os = "linux")]
pub fn launch_sandboxed(config: SandboxConfig) -> Result<SandboxResult> {
    sandbox_impl::launch(config)
}

/// Stub for non-Linux platforms — returns an error with guidance.
#[cfg(not(target_os = "linux"))]
pub fn launch_sandboxed(_config: SandboxConfig) -> Result<SandboxResult> {
    Err(anyhow::anyhow!(
        "Linux-native sandbox requires Linux (namespaces, seccomp-BPF). \
         On this platform, use --contained for Docker-based isolation instead."
    ))
}

/// Run pre-flight checks to verify the system supports sandboxing.
#[cfg(target_os = "linux")]
pub fn preflight_check(config: &SandboxConfig) -> PreflightReport {
    capability::check(config)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn preflight_check(_config: &SandboxConfig) -> PreflightReport {
    PreflightReport {
        user_namespaces: false,
        seccomp_available: false,
        net_admin_capability: false,
        ip_forward: false,
        ip_command_available: false,
        iptables_command_available: false,
        interpreter_found: false,
        ebpf_available: false,
        issues: vec![
            "Linux-native sandbox is not available on this platform.".to_string(),
            "Use --contained for Docker-based isolation.".to_string(),
        ],
    }
}
