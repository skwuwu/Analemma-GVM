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
    /// TLS probe mode: "enforce" (block denied requests), "audit" (log only), "disabled".
    /// Default: "audit". Requires Linux 5.5+ and root/CAP_BPF.
    pub tls_probe_mode: TlsProbeMode,
    /// GVM proxy URL for uprobe policy enforcement (e.g., "http://127.0.0.1:8080").
    /// When set, uprobe queries the proxy's /gvm/check endpoint for SRR decisions.
    /// When None, uprobe uses allow-all (audit-only regardless of tls_probe_mode).
    pub proxy_url: Option<String>,
    /// Memory limit for the sandboxed agent (bytes). None = no limit.
    /// Applied via cgroup v2 `memory.max`. Example: Some(512 * 1024 * 1024) = 512MB.
    pub memory_limit: Option<u64>,
    /// CPU limit for the sandboxed agent as a fraction of one CPU. None = no limit.
    /// Applied via cgroup v2 `cpu.max`. Example: Some(1.0) = 1 CPU, Some(0.5) = half CPU.
    pub cpu_limit: Option<f64>,
    /// Filesystem governance policy. None = legacy mode (/workspace/output only).
    /// When set, overlayfs is used to capture all file changes, and Trust-on-Pattern
    /// rules determine which changes are auto-merged, need manual commit, or discarded.
    pub fs_policy: Option<FilesystemPolicy>,
    /// PEM-encoded CA certificate for MITM trust store injection.
    /// Downloaded from the proxy's `GET /gvm/ca.pem` endpoint. The proxy holds the
    /// private key; the sandbox only receives the public certificate. This ensures
    /// the CA injected into the sandbox matches the one used by the TLS MITM listener.
    /// None = HTTPS MITM disabled (no CA injection into sandbox).
    pub mitm_ca_cert: Option<Vec<u8>>,
}

/// Trust-on-Pattern filesystem governance policy.
///
/// Analogous to SRR for network traffic: file glob patterns determine
/// how agent-generated files are handled at session end.
///
/// ```toml
/// [filesystem]
/// auto_merge = ["*.csv", "*.pdf", "*.txt"]
/// manual_commit = ["*.sh", "*.py", "*.js", "*.json"]
/// discard = ["/tmp/*", "*.log", "__pycache__/*"]
/// default = "manual_commit"
/// upper_size_mb = 256
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FilesystemPolicy {
    /// Glob patterns for files auto-merged to host immediately (safe outputs).
    #[serde(default)]
    pub auto_merge: Vec<String>,
    /// Glob patterns for files requiring manual approval at session end (potentially dangerous).
    #[serde(default)]
    pub manual_commit: Vec<String>,
    /// Glob patterns for files discarded on exit (temporary artifacts).
    #[serde(default)]
    pub discard: Vec<String>,
    /// Default policy for files matching no pattern: "auto_merge" | "manual_commit" | "discard".
    #[serde(default = "default_fs_policy")]
    pub default: String,
    /// Size limit for overlayfs upper layer in MB (default: 256).
    #[serde(default = "default_upper_size_mb")]
    pub upper_size_mb: u64,
}

fn default_fs_policy() -> String {
    "manual_commit".to_string()
}

fn default_upper_size_mb() -> u64 {
    256
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            auto_merge: vec![
                "*.csv".into(),
                "*.pdf".into(),
                "*.txt".into(),
                "*.png".into(),
                "*.jpg".into(),
                "*.xml".into(),
            ],
            manual_commit: vec![
                "*.sh".into(),
                "*.py".into(),
                "*.js".into(),
                "*.ts".into(),
                "*.toml".into(),
                "*.yaml".into(),
                "*.conf".into(),
                "*.env".into(),
                "*.json".into(),
            ],
            discard: vec![
                "/tmp/*".into(),
                "*.log".into(),
                "*.cache".into(),
                "__pycache__/*".into(),
                "*.pyc".into(),
                ".git/*".into(),
            ],
            default: "manual_commit".into(),
            upper_size_mb: 256,
        }
    }
}

/// TLS probe operating mode.
///
/// Default: Disabled. The uprobe is experimental and gated behind the `uprobe` feature flag.
/// MITM (transparent TLS proxy) is the primary HTTPS inspection mechanism.
#[derive(Debug, Clone, Default)]
pub enum TlsProbeMode {
    /// Log HTTPS plaintext but don't block.
    Audit,
    /// Log and block denied HTTPS requests via SIGSTOP.
    Enforce,
    /// Disable TLS probing entirely (default).
    #[default]
    Disabled,
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

// ── Cross-platform modules ──

pub mod ca;
pub mod filesystem;

// ── Platform-specific implementation ──

#[cfg(target_os = "linux")]
mod capability;
#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
pub mod ebpf;
#[cfg(target_os = "linux")]
mod mount;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(all(target_os = "linux", feature = "uprobe"))]
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

/// Clean up orphaned network resources from a previous sandbox crash.
/// Call this before launching a new sandbox to ensure a clean state.
#[cfg(target_os = "linux")]
pub fn cleanup_orphaned_network() -> Result<bool> {
    network::cleanup_orphaned_network()
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn cleanup_orphaned_network() -> Result<bool> {
    Ok(false)
}

/// Scan for all orphaned sandbox resources (veth, mounts, cgroups, iptables)
/// and clean them up. Returns the number of orphaned sandboxes cleaned.
/// Used by `gvm cleanup` command and auto-cleanup on sandbox startup.
#[cfg(target_os = "linux")]
pub fn cleanup_all_orphans() -> Result<u32> {
    network::cleanup_all_orphans()
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn cleanup_all_orphans() -> Result<u32> {
    Ok(0)
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
