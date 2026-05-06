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
    /// Extra environment variables to inject into the sandbox child process.
    /// Used for placeholder API keys that satisfy agent startup validation
    /// while the real credentials are held by the proxy (secrets.toml).
    pub extra_env: Vec<(String, String)>,
    /// PEM-encoded CA certificate for MITM trust store injection.
    /// Downloaded from the proxy's `GET /gvm/ca.pem` endpoint. The proxy holds the
    /// private key; the sandbox only receives the public certificate. This ensures
    /// the CA injected into the sandbox matches the one used by the TLS MITM listener.
    /// None = HTTPS MITM disabled (no CA injection into sandbox).
    pub mitm_ca_cert: Option<Vec<u8>>,
    /// Per-sandbox CA identity (CA-3/4). Set when the launcher first
    /// calls `POST /gvm/sandbox/launch` to mint a per-sandbox CA, then
    /// passes the returned `sandbox_id` here so the sandbox state file
    /// records it. The MITM TLS resolver in the proxy uses this field
    /// (via `lookup_sandbox_id_by_ip`) to pick the right per-sandbox
    /// CA at TLS-handshake time. None = legacy single-CA path.
    pub sandbox_id: Option<String>,
    /// Sandbox filesystem profile. Controls how much of the host userland is
    /// exposed inside the sandbox.
    pub sandbox_profile: SandboxProfile,
}

/// Sandbox filesystem profile — controls the trade-off between isolation and compatibility.
#[derive(Debug, Clone, Default)]
pub enum SandboxProfile {
    /// Interpreter binary + ldd-resolved libraries only. Maximum isolation,
    /// but agents that spawn subprocesses (bash), use SSL config, or expect
    /// coreutils will fail. Use for trusted, simple scripts.
    Minimal,
    /// /usr, /lib, /lib64, /bin, /sbin read-only. Complete runtime environment
    /// matching Docker's approach. Agents work the same as outside the sandbox.
    /// Security maintained by read-only + seccomp + pivot_root.
    #[default]
    Standard,
    /// Entire host root filesystem read-only (excluding /proc, /sys, /dev which
    /// are mounted separately). Maximum compatibility for complex agents.
    Full,
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

/// Why the sandboxed agent terminated.
///
/// Distinguishes user-friendly cases (OOM, timeout, seccomp) from generic
/// SIGKILL so the CLI can give actionable hints. Priority for SIGKILL
/// classification: OOM > Timeout > UserInterrupt > ExternalKill (root cause first).
#[derive(Debug, Clone)]
pub enum ExitReason {
    /// Agent exited with code 0.
    Normal,
    /// Agent exited with non-zero code (its own error path).
    AgentError { code: i32 },
    /// GVM SIGKILL'd the agent because GVM_SANDBOX_TIMEOUT was exceeded.
    Timeout { secs: u64 },
    /// GVM SIGKILL'd the agent because the parent received a termination
    /// signal (SIGTERM from systemd / `gvm stop`, SIGINT from Ctrl+C, or
    /// SIGHUP from SSH disconnect). Carries the signal name so the CLI
    /// can print an accurate diagnostic instead of always claiming SIGTERM.
    UserInterrupt { signal: &'static str },
    /// Killed by SIGSYS — seccomp filter blocked a syscall.
    ///
    /// `syscall` is populated when we successfully parsed the AUDIT_SECCOMP
    /// record from `dmesg` for the dying child PID. `None` means dmesg was
    /// unavailable, no audit record matched, or the syscall number wasn't
    /// in our lookup table — caller should fall back to the generic
    /// "check dmesg" message.
    SeccompViolation { count: u32, syscall: Option<String> },
    /// Killed by cgroup OOM killer (memory limit exceeded).
    OomKill { memory_limit_mb: Option<u64> },
    /// Killed by an external signal not initiated by GVM and not from cgroup OOM.
    ExternalKill { signal: i32 },
}

/// Result of a sandboxed agent execution.
#[derive(Debug)]
pub struct SandboxResult {
    /// Agent process exit code (128 + signal for signaled exits).
    pub exit_code: i32,
    /// Classified reason for termination — used by CLI to print actionable hints.
    pub exit_reason: ExitReason,
    /// Sandbox setup time in milliseconds.
    pub setup_ms: u64,
    /// Whether seccomp violations were detected.
    pub seccomp_violations: u32,
    /// CPU throttle time in microseconds (from cgroup cpu.stat).
    /// None if cgroup unavailable or no CPU limit was set.
    pub cpu_throttled_us: Option<u64>,
    /// Filesystem diff report (overlayfs upper layer scan).
    /// None if overlayfs was not active or scan failed.
    pub fs_diff: Option<filesystem::FsDiffReport>,
    /// Post-cleanup residual report. Lists any veth/iptables/mount/cgroup/state
    /// resources that survived the cleanup pass. `is_clean()` is the success
    /// signal — if it's false, the CLI surfaces actionable manual recovery
    /// commands rather than silently leaking host resources.
    pub cleanup_verification: CleanupVerification,
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
    /// Whether the `ip6tables` command is available. Used by `network.rs` to
    /// disable IPv6 inside the sandbox netns as a fallback when IPv6 is enabled
    /// on the host. Optional — sandbox still launches without it, but agents
    /// that resolve AAAA records may bypass v4 enforcement.
    pub ip6tables_command_available: bool,
    /// Whether the interpreter binary exists.
    pub interpreter_found: bool,
    /// Whether TC ingress filter is available (kernel >= 4.15, tc command).
    /// When true, kernel-level u32 classifier provides unbypassable proxy enforcement.
    /// When false, falls back to iptables (with seccomp AF_NETLINK defense-in-depth).
    pub tc_filter_available: bool,
    /// Human-readable remediation messages for failures.
    pub issues: Vec<String>,
}

// ── Cross-platform modules ──

pub mod ca;
pub mod filesystem;

// Pure parsers — OS-independent so they can be unit-tested on any host.
mod cgroup_parse;
// dmesg-line parser is OS-independent; the runtime invocation is linux-only.
mod seccomp_audit;
// Syscall number → name lookup. Linux-only because libc::SYS_* constants
// only exist on Linux; gated at module level so Windows builds skip it.
#[cfg(target_os = "linux")]
mod syscall_names;
// Cleanup residual scanner. Pure parsers cross-platform; runtime gated linux.
mod cleanup_verify;
pub use cleanup_verify::{verify_cleanup, CleanupVerification};

// ── Platform-specific implementation ──

#[cfg(target_os = "linux")]
mod capability;
#[cfg(target_os = "linux")]
mod cgroup;
#[cfg(target_os = "linux")]
mod mount;
#[cfg(target_os = "linux")]
mod namespace;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod seccomp;
#[cfg(target_os = "linux")]
pub mod tc_filter;
#[cfg(target_os = "linux")]
mod tools;

#[cfg(target_os = "linux")]
mod sandbox_impl;

// Parent-process liveness heartbeat. Linux-only because flock + per-PID
// lockfile under /run/gvm/ are the implementation primitives. On other
// platforms the sandbox is unavailable anyway.
#[cfg(target_os = "linux")]
pub mod heartbeat;

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

/// Per-resource cleanup breakdown — used by `gvm cleanup` for user-facing
/// progress output (which veth/mount/iptables resources were released).
#[cfg(target_os = "linux")]
pub use network::CleanupReport;

/// Per-sandbox CA routing helper (CA-4). Resolves a peer's veth IP back
/// to the proxy-issued `sandbox_id` so the MITM TLS dispatch can pick
/// the right per-sandbox CA at handshake time.
#[cfg(target_os = "linux")]
pub use network::lookup_sandbox_id_by_ip;

/// Docker bridge iptables integration for `--contained` mode.
#[cfg(target_os = "linux")]
pub use network::{
    allocate_docker_slot, cleanup_docker_bridge_iptables, cleanup_stale_docker_chains,
    record_docker_state, setup_docker_bridge_iptables, DockerBridgeConfig, DOCKER_BRIDGE_PREFIX,
};

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Default)]
pub struct CleanupReport {
    pub sandboxes: u32,
    pub veth_interfaces: u32,
    pub veth_names: Vec<String>,
    pub mount_paths: u32,
    pub cgroups: u32,
    pub iptables_chains: u32,
    pub orphan_veths_swept: u32,
}

#[cfg(not(target_os = "linux"))]
impl CleanupReport {
    pub fn is_empty(&self) -> bool {
        true
    }
}

/// Cleanup with per-resource breakdown for the `gvm cleanup` UX.
#[cfg(target_os = "linux")]
pub fn cleanup_all_orphans_report() -> Result<CleanupReport> {
    network::cleanup_all_orphans_report()
}

#[cfg(not(target_os = "linux"))]
pub fn cleanup_all_orphans_report() -> Result<CleanupReport> {
    Ok(CleanupReport::default())
}

/// Number of syscalls in the default seccomp whitelist (excludes the implicit
/// ENOSYS-default for everything else). Used by `gvm status`.
#[cfg(target_os = "linux")]
pub fn allowed_syscall_count() -> usize {
    seccomp::allowed_syscall_count()
}

#[cfg(not(target_os = "linux"))]
pub fn allowed_syscall_count() -> usize {
    0
}

/// Resolve an interpreter binary by name. Returns the absolute path if it
/// exists in PATH, `None` otherwise. Used by the CLI to pick the first
/// available candidate (e.g. `python3` vs `python`) before sandbox launch.
#[cfg(target_os = "linux")]
pub fn which_interpreter(interpreter: &str) -> Option<std::path::PathBuf> {
    capability::which_interpreter(interpreter)
}

#[cfg(not(target_os = "linux"))]
pub fn which_interpreter(_interpreter: &str) -> Option<std::path::PathBuf> {
    None
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
        ip6tables_command_available: false,
        interpreter_found: false,
        tc_filter_available: false,
        issues: vec![
            "Linux-native sandbox is not available on this platform.".to_string(),
            "Use --contained for Docker-based isolation.".to_string(),
        ],
    }
}
