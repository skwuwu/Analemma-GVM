//! Network namespace setup: veth pair with proxy-only routing.
//!
//! Creates a point-to-point network between the sandbox and the host.
//! The sandbox can ONLY reach the GVM proxy via the veth pair.
//!
//! Enforcement layers (defense-in-depth):
//! 1. **TC ingress filter** on host-side veth (when available) — unbypassable
//!    kernel-level filtering. The agent cannot modify this even with CAP_NET_ADMIN.
//! 2. **iptables OUTPUT rules** inside sandbox namespace — traditional firewall.
//! 3. **seccomp AF_NETLINK blocking** — prevents the agent from creating netlink
//!    sockets to modify iptables rules inside the sandbox.
//!
//! Topology:
//! ```text
//!   Host netns                Sandbox netns
//!   ┌──────────────────┐      ┌──────────┐
//!   │ veth-host        │──────│ veth-sb  │
//!   │  ↓ TC ingress    │      │ 10.200.  │
//!   │  ↓ eBPF filter   │      │ X.2/30   │
//!   │ 10.200.X.1/30    │      └──────────┘
//!   └────┬─────────────┘        OUTPUT:
//!        │ DNAT                  proxy → ACCEPT
//!        ▼                       DNS   → ACCEPT
//!   GVM Proxy (host)             lo    → ACCEPT
//!                                *     → DROP
//! ```
//!
//! The /30 subnet allows exactly 2 hosts. X is derived from the child PID
//! to support multiple concurrent sandboxes.
//!
//! Security properties:
//! - No direct internet access from sandbox (TC filter + OUTPUT DROP)
//! - IPv6 fully disabled (prevents IPv6 bypass)
//! - DNS queries routed through host veth IP only
//! - MASQUERADE restricted to proxy port traffic only
//! - AF_NETLINK sockets blocked by seccomp (cannot modify iptables)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;

/// Network configuration for the sandbox.
pub struct VethConfig {
    /// Host-side interface name.
    pub host_iface: String,
    /// Sandbox-side interface name.
    pub sandbox_iface: String,
    /// Host-side IP (e.g., 10.200.X.1).
    pub host_ip: String,
    /// Sandbox-side IP (e.g., 10.200.X.2).
    pub sandbox_ip: String,
    /// Subnet mask in CIDR notation.
    pub cidr: u8,
    /// Child PID (for moving veth into namespace).
    pub child_pid: u32,
    /// Proxy listen address on the host.
    pub proxy_addr: SocketAddr,
}

impl VethConfig {
    /// Create a VethConfig using the child PID to derive unique IPs.
    pub fn from_pid(child_pid: u32, proxy_addr: SocketAddr) -> Self {
        // Derive unique /30 subnet from PID: 10.200.(pid % 256).(pid / 256 * 4)
        // This supports up to 16K concurrent sandboxes
        let third_octet = (child_pid % 256) as u8;
        let fourth_base = ((child_pid / 256) % 64) as u8 * 4;

        Self {
            host_iface: format!("veth-gvm-h{}", child_pid % 10000),
            sandbox_iface: format!("veth-gvm-s{}", child_pid % 10000),
            host_ip: format!("10.200.{}.{}", third_octet, fourth_base + 1),
            sandbox_ip: format!("10.200.{}.{}", third_octet, fourth_base + 2),
            cidr: 30,
            child_pid,
            proxy_addr,
        }
    }
}

/// Host-side network setup: create veth pair, move one end into sandbox, configure routing.
/// Returns the DNS target used for DNAT (for deterministic cleanup).
pub fn setup_host_network(config: &VethConfig) -> Result<String> {
    // 1. Create veth pair
    run_ip(&[
        "link",
        "add",
        &config.host_iface,
        "type",
        "veth",
        "peer",
        "name",
        &config.sandbox_iface,
    ])?;

    // 2. Move sandbox end into child's network namespace
    run_ip(&[
        "link",
        "set",
        &config.sandbox_iface,
        "netns",
        &config.child_pid.to_string(),
    ])?;

    // 3. Configure host-side interface
    run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", config.host_ip, config.cidr),
        "dev",
        &config.host_iface,
    ])?;
    run_ip(&["link", "set", &config.host_iface, "up"])?;

    // 4. Enable IP forwarding.
    //
    // SECURITY: Global ip_forward=1 changes the kernel's packet processing for the
    // entire host — on EC2, this can interact with source/dest checks and cause
    // SSH connectivity loss. We enable per-interface forwarding on the veth pair
    // and the default outbound interface, plus global forwarding (required by
    // DNAT/MASQUERADE on most kernels).
    //
    // The FORWARD chain ESTABLISHED/RELATED protection rule (step 7) ensures
    // existing connections (SSH) survive even with global forwarding enabled.
    let _ = save_ip_forward_state();
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("Failed to enable global IP forwarding")?;
    // Per-interface forwarding for the veth
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/forwarding", config.host_iface),
        "1",
    )
    .ok();
    // Also enable on the default outbound interface (e.g., ens5 on EC2)
    // so that DNAT'd packets can be forwarded out.
    if let Ok(output) = std::process::Command::new("ip")
        .args(["route", "get", "8.8.8.8"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(dev) = stdout.split_whitespace()
            .position(|w| w == "dev")
            .and_then(|i| stdout.split_whitespace().nth(i + 1))
        {
            std::fs::write(
                format!("/proc/sys/net/ipv4/conf/{}/forwarding", dev),
                "1",
            ).ok();
        }
    }
    // Enable route_localnet so DNAT to 127.0.0.1 works on the veth interface.
    // Without this, packets DNATed to 127.0.0.1 are silently dropped as martians.
    std::fs::write(
        format!(
            "/proc/sys/net/ipv4/conf/{}/route_localnet",
            config.host_iface
        ),
        "1",
    )
    .ok();

    // 5. DNAT: traffic from sandbox to proxy port → actual proxy address
    let proxy_port = config.proxy_addr.port();
    run_iptables(&[
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-i",
        &config.host_iface,
        "-p",
        "tcp",
        "--dport",
        &proxy_port.to_string(),
        "-j",
        "DNAT",
        "--to-destination",
        &config.proxy_addr.to_string(),
    ])?;

    // 5b. DNAT: DNS queries from sandbox → host's upstream DNS resolver
    // The sandbox resolv.conf points to host_ip, but no DNS server listens there.
    // PREROUTING DNAT redirects UDP 53 to the actual upstream DNS resolver.
    //
    // Cannot use 127.0.0.53 (systemd-resolved stub) because it binds to lo only —
    // packets arriving on veth with DNAT to 127.0.0.53 are delivered via INPUT on
    // the veth interface, but the socket only accepts packets on lo.
    let dns_target = resolve_host_dns();
    run_iptables(&[
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-i",
        &config.host_iface,
        "-p",
        "udp",
        "--dport",
        "53",
        "-j",
        "DNAT",
        "--to-destination",
        &format!("{}:53", dns_target),
    ])?;
    tracing::debug!(dns_target = %dns_target, "DNS DNAT configured");

    // 6. MASQUERADE for proxy TCP and DNS UDP traffic
    run_iptables(&[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        &format!("{}/{}", config.sandbox_ip, config.cidr),
        "-p",
        "tcp",
        "--dport",
        &proxy_port.to_string(),
        "-j",
        "MASQUERADE",
    ])?;
    run_iptables(&[
        "-t",
        "nat",
        "-A",
        "POSTROUTING",
        "-s",
        &format!("{}/{}", config.sandbox_ip, config.cidr),
        "-p",
        "udp",
        "--dport",
        "53",
        "-j",
        "MASQUERADE",
    ])?;

    // 7. FORWARD chain setup.
    //
    // CRITICAL: Protect existing host connections (SSH, etc.) BEFORE adding DROP rules.
    // Without this, ip_forward=1 changes the kernel's packet processing path and
    // GVM's per-sandbox DROP rules can block host SSH on EC2 (P0 security issue).
    //
    // The protection rule allows ESTABLISHED/RELATED packets through FORWARD
    // regardless of GVM chains, ensuring existing connections survive.
    // We use -C (check) first to avoid duplicate rules across multiple sandboxes.
    let ssh_protect_args = [
        "-I", "FORWARD", "1",
        "-m", "state", "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT",
    ];
    if run_iptables(&[
        "-C", "FORWARD",
        "-m", "state", "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT",
    ]).is_err() {
        run_iptables(&ssh_protect_args)?;
        tracing::debug!("FORWARD ESTABLISHED/RELATED protection rule added");
    }

    // Per-sandbox FORWARD chain to avoid stale rule accumulation.
    let chain_name = format!("GVM-{}", config.host_iface);
    // Remove any stale chain from previous crash
    run_iptables(&["-D", "FORWARD", "-j", &chain_name]).ok();
    run_iptables(&["-F", &chain_name]).ok();
    run_iptables(&["-X", &chain_name]).ok();
    // Create fresh chain
    run_iptables(&["-N", &chain_name])?;
    run_iptables(&[
        "-A",
        &chain_name,
        "-i",
        &config.host_iface,
        "-o",
        "lo",
        "-j",
        "ACCEPT",
    ])?;
    run_iptables(&[
        "-A",
        &chain_name,
        "-i",
        "lo",
        "-o",
        &config.host_iface,
        "-j",
        "ACCEPT",
    ])?;
    // Allow DNS UDP forwarding after DNAT (veth → upstream DNS, typically via ens5)
    // Only port 53 UDP is allowed — all other non-proxy traffic is dropped below.
    run_iptables(&[
        "-A",
        &chain_name,
        "-i",
        &config.host_iface,
        "-p",
        "udp",
        "--dport",
        "53",
        "-j",
        "ACCEPT",
    ])?;
    // Allow DNS response packets back (ESTABLISHED/RELATED)
    run_iptables(&[
        "-A",
        &chain_name,
        "-o",
        &config.host_iface,
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;
    // DROP everything else from/to this veth (proxy bypass prevention)
    run_iptables(&["-A", &chain_name, "-i", &config.host_iface, "-j", "DROP"])?;
    // Jump to per-sandbox chain from FORWARD.
    // Insert at position 2 (after the ESTABLISHED/RELATED protection rule at position 1).
    // This ensures existing SSH connections are never blocked by per-sandbox DROP rules.
    run_iptables(&["-I", "FORWARD", "2", "-j", &chain_name])?;

    tracing::debug!(
        host_iface = %config.host_iface,
        host_ip = %config.host_ip,
        sandbox_ip = %config.sandbox_ip,
        "Host-side network configured (proxy-only, FORWARD DROP default)"
    );

    Ok(dns_target)
}

/// Sandbox-side network setup: configure interface, routing, and firewall lockdown.
/// Called from within the child's network namespace.
///
/// Security: after this function, the sandbox can only reach:
/// - host_ip:{proxy_port} via TCP (GVM proxy)
/// - host_ip:53 via UDP (DNS, resolved by host)
/// - loopback (127.0.0.1)
///
/// All other outbound traffic is dropped.
pub fn setup_sandbox_network(config: &VethConfig) -> Result<()> {
    // 1. Bring up loopback
    run_ip(&["link", "set", "lo", "up"])?;

    // 2. Configure sandbox-side interface
    run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", config.sandbox_ip, config.cidr),
        "dev",
        &config.sandbox_iface,
    ])?;
    run_ip(&["link", "set", &config.sandbox_iface, "up"])?;

    // 3. Default route via host side
    run_ip(&["route", "add", "default", "via", &config.host_ip])?;

    // ── Firewall lockdown inside sandbox namespace ──

    // 4. Disable IPv6 completely (prevents IPv6 bypass of IPv4 firewall rules)
    disable_ipv6();

    // 5. OUTPUT chain: allow only proxy, DNS, and loopback
    let proxy_port = config.proxy_addr.port().to_string();

    // Allow loopback traffic
    run_iptables(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;

    // Allow established/related connections (return traffic)
    run_iptables(&[
        "-A",
        "OUTPUT",
        "-m",
        "state",
        "--state",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;

    // Allow TCP to proxy HTTP port on host IP
    run_iptables(&[
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "-d",
        &config.host_ip,
        "--dport",
        &proxy_port,
        "-j",
        "ACCEPT",
    ])?;

    // Allow TCP to proxy TLS port (8443) for MITM inspection
    let tls_port = (config.proxy_addr.port() + 363).to_string(); // 8080→8443
    run_iptables(&[
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "-d",
        &config.host_ip,
        "--dport",
        &tls_port,
        "-j",
        "ACCEPT",
    ])?;

    // DNAT: redirect all outbound 443 traffic to proxy TLS port
    // This captures direct HTTPS (bypassing HTTPS_PROXY) and routes it
    // through the MITM proxy for full L7 inspection.
    run_iptables(&[
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "--dport",
        "443",
        "-j",
        "DNAT",
        "--to-destination",
        &format!("{}:{}", config.host_ip, tls_port),
    ])?;

    // Allow UDP DNS to host IP only (resolv.conf must point to host_ip)
    run_iptables(&[
        "-A",
        "OUTPUT",
        "-p",
        "udp",
        "-d",
        &config.host_ip,
        "--dport",
        "53",
        "-j",
        "ACCEPT",
    ])?;

    // DROP everything else — this is the core proxy bypass prevention
    run_iptables(&["-A", "OUTPUT", "-j", "DROP"])?;

    tracing::debug!(
        sandbox_ip = %config.sandbox_ip,
        gateway = %config.host_ip,
        proxy_port = %proxy_port,
        tls_port = %tls_port,
        "Sandbox network locked down: proxy-only OUTPUT + DNAT 443→TLS proxy"
    );

    Ok(())
}

/// Disable IPv6 in the sandbox network namespace.
/// Prevents agents from using IPv6 to bypass IPv4 iptables rules.
fn disable_ipv6() {
    // sysctl: disable IPv6 on all interfaces
    run_sysctl("net.ipv6.conf.all.disable_ipv6", "1").ok();
    run_sysctl("net.ipv6.conf.default.disable_ipv6", "1").ok();

    // Fallback: ip6tables DROP all output (in case sysctl fails)
    run_ip6tables(&["-P", "OUTPUT", "DROP"]).ok();
    run_ip6tables(&["-P", "INPUT", "DROP"]).ok();
    run_ip6tables(&["-P", "FORWARD", "DROP"]).ok();
}

/// Write a sysctl value.
fn run_sysctl(key: &str, value: &str) -> Result<()> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::write(&path, value).with_context(|| format!("Failed to set sysctl {}", key))?;
    Ok(())
}

/// Clean up host-side network resources.
/// `dns_target_override`: if Some, use this DNS target for DNAT rule deletion
/// instead of re-resolving (which may return a different value after DHCP renewal).
pub fn cleanup_host_network(config: &VethConfig, dns_target_override: Option<&str>) {
    let proxy_port = config.proxy_addr.port();

    // Remove iptables rules (best-effort, reverse order)
    // Remove per-sandbox FORWARD chain
    let chain_name = format!("GVM-{}", config.host_iface);
    run_iptables(&["-D", "FORWARD", "-j", &chain_name]).ok();
    run_iptables(&["-F", &chain_name]).ok();
    run_iptables(&["-X", &chain_name]).ok();

    // MASQUERADE (now port-restricted)
    run_iptables(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        &format!("{}/{}", config.sandbox_ip, config.cidr),
        "-p",
        "tcp",
        "--dport",
        &proxy_port.to_string(),
        "-j",
        "MASQUERADE",
    ])
    .ok();

    // DNAT (proxy TCP)
    run_iptables(&[
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "-i",
        &config.host_iface,
        "-p",
        "tcp",
        "--dport",
        &proxy_port.to_string(),
        "-j",
        "DNAT",
        "--to-destination",
        &config.proxy_addr.to_string(),
    ])
    .ok();

    // DNAT (DNS UDP) — use recorded dns_target to ensure exact rule match.
    // Falling back to resolve_host_dns() only if state file didn't record it.
    let dns_target = dns_target_override
        .map(|s| s.to_string())
        .unwrap_or_else(resolve_host_dns);
    run_iptables(&[
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "-i",
        &config.host_iface,
        "-p",
        "udp",
        "--dport",
        "53",
        "-j",
        "DNAT",
        "--to-destination",
        &format!("{}:53", dns_target),
    ])
    .ok();

    // MASQUERADE (DNS UDP)
    run_iptables(&[
        "-t",
        "nat",
        "-D",
        "POSTROUTING",
        "-s",
        &format!("{}/{}", config.sandbox_ip, config.cidr),
        "-p",
        "udp",
        "--dport",
        "53",
        "-j",
        "MASQUERADE",
    ])
    .ok();

    // Remove veth pair (removing one end removes both)
    run_ip(&["link", "del", &config.host_iface]).ok();

    // Restore ip_forward if this was the last sandbox
    restore_ip_forward_state();

    tracing::debug!(
        host_iface = %config.host_iface,
        "Host network cleaned up"
    );
}

/// Resolve the host's upstream DNS server for sandbox DNAT.
///
/// Reads `/run/systemd/resolve/resolv.conf` (upstream DNS, not the stub) first,
/// then falls back to `/etc/resolv.conf`. Returns the first non-loopback nameserver.
/// If no suitable DNS found, falls back to 8.8.8.8 (Google Public DNS).
///
/// Cannot use 127.0.0.53 (systemd-resolved stub) because it binds to `lo` only —
/// packets arriving on veth with DNAT to 127.0.0.53 are silently dropped.
const IP_FORWARD_SAVED_PATH: &str = "/tmp/gvm-ip-forward-original";

/// Save the original ip_forward state before enabling it.
/// Only saves if the file doesn't already exist (first sandbox wins).
fn save_ip_forward_state() {
    if std::path::Path::new(IP_FORWARD_SAVED_PATH).exists() {
        return; // Already saved by a previous sandbox
    }
    let original = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .unwrap_or_else(|_| "0".to_string());
    let _ = std::fs::write(IP_FORWARD_SAVED_PATH, original.trim());
}

/// Restore ip_forward to its original value, but only if no other
/// sandboxes are running (checked via state file count).
fn restore_ip_forward_state() {
    // Count active sandbox state files
    let pattern = format!("{}/*{}", STATE_DIR, STATE_SUFFIX);
    let active_count = glob::glob(&pattern)
        .ok()
        .map(|entries| entries.filter_map(|e| e.ok()).count())
        .unwrap_or(0);

    if active_count > 0 {
        tracing::debug!(
            active = active_count,
            "Other sandboxes still active — not restoring ip_forward"
        );
        return;
    }

    if let Ok(original) = std::fs::read_to_string(IP_FORWARD_SAVED_PATH) {
        let val = original.trim();
        if val == "0" {
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "0").ok();
            tracing::debug!("Restored ip_forward to 0 (original state)");
        }
        let _ = std::fs::remove_file(IP_FORWARD_SAVED_PATH);

        // Remove FORWARD ESTABLISHED/RELATED protection rule (no more sandboxes need it)
        run_iptables(&[
            "-D", "FORWARD",
            "-m", "state", "--state", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ]).ok();
        tracing::debug!("Removed FORWARD ESTABLISHED/RELATED protection rule");
    }
}

fn resolve_host_dns() -> String {
    // Allow explicit override via environment variable (useful for non-standard setups)
    if let Ok(dns) = std::env::var("GVM_DNS_TARGET") {
        tracing::info!(dns = %dns, "Using DNS target from GVM_DNS_TARGET");
        return dns;
    }

    // Try systemd-resolved upstream config first (has real DNS, not stub)
    for path in &["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if let Some(ns) = line.strip_prefix("nameserver") {
                    let ns = ns.trim();
                    // Skip loopback addresses (stub resolvers)
                    if !ns.starts_with("127.") {
                        tracing::debug!(dns = %ns, source = %path, "Resolved host upstream DNS");
                        return ns.to_string();
                    }
                }
            }
        }
    }

    tracing::warn!("No upstream DNS found, falling back to 8.8.8.8");
    "8.8.8.8".to_string()
}

/// Run an `ip` command, returning an error on failure.
fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .context("Failed to execute 'ip' command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

/// Run an `iptables` command, returning an error on failure.
fn run_iptables(args: &[&str]) -> Result<()> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .context("Failed to execute 'iptables' command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("iptables {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

// ─── Per-PID Sandbox State Tracking (Docker pattern) ───
//
// Each sandbox writes a state file at startup listing all resources it created.
// On normal exit, cleanup runs and the file is deleted.
// On crash (SIGKILL, power loss), the file persists. The next `gvm run --sandbox`
// scans for stale state files (PID dead) and auto-cleans orphan resources.
// This is the same pattern Docker uses for container state management.

const STATE_DIR: &str = "/tmp";
const STATE_PREFIX: &str = "gvm-sandbox-";
const STATE_SUFFIX: &str = ".state";
/// Legacy state file path (pre-v0.2). Cleaned up on first run.
const LEGACY_STATE_FILE: &str = "/run/gvm/interfaces.json";

/// Full resource manifest for a sandbox session.
/// Serialized to `/tmp/gvm-sandbox-{pid}.state` on startup.
/// All fields needed to deterministically clean up orphaned resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxState {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// PID of the parent GVM process (resource owner).
    pub pid: u32,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
    /// Host-side veth interface name.
    pub veth_host: String,
    /// Sandbox-side veth interface name.
    pub veth_sandbox: String,
    /// Host-side IP address.
    pub host_ip: String,
    /// Sandbox-side IP address.
    pub sandbox_ip: String,
    /// Proxy port for DNAT rules.
    pub proxy_port: u16,
    /// iptables FORWARD chain name (per-sandbox chain).
    pub forward_chain: String,
    /// Mount paths created for this sandbox.
    pub mount_paths: Vec<String>,
    /// Cgroup path (if resource limits were applied).
    pub cgroup_path: Option<String>,
    /// DNS target used for DNAT (recorded at setup time).
    /// Used by cleanup to delete the exact DNAT rule, even if
    /// /run/systemd/resolve/resolv.conf has changed since setup.
    #[serde(default)]
    pub dns_target: Option<String>,
}

/// Get the state file path for a given PID.
fn state_file_path(pid: u32) -> PathBuf {
    PathBuf::from(format!(
        "{}/{}{}{}", STATE_DIR, STATE_PREFIX, pid, STATE_SUFFIX
    ))
}

/// Record a sandbox's full resource manifest to a per-PID state file.
/// Called after host-side network setup succeeds.
pub fn record_sandbox_state(
    config: &VethConfig,
    mount_paths: &[PathBuf],
    cgroup_path: Option<&str>,
    dns_target: Option<&str>,
) -> Result<()> {
    let state = SandboxState {
        version: 1,
        pid: std::process::id(),
        created_at: time::OffsetDateTime::now_utc().to_string(),
        veth_host: config.host_iface.clone(),
        veth_sandbox: config.sandbox_iface.clone(),
        host_ip: config.host_ip.clone(),
        sandbox_ip: config.sandbox_ip.clone(),
        proxy_port: config.proxy_addr.port(),
        forward_chain: format!("GVM-{}", config.host_iface),
        mount_paths: mount_paths.iter().map(|p| p.display().to_string()).collect(),
        cgroup_path: cgroup_path.map(|s| s.to_string()),
        dns_target: dns_target.map(|s| s.to_string()),
    };

    let path = state_file_path(state.pid);
    std::fs::write(&path, serde_json::to_string_pretty(&state)?)
        .with_context(|| format!("Failed to write sandbox state to {}", path.display()))?;

    tracing::debug!(
        path = %path.display(),
        pid = state.pid,
        "Sandbox state recorded for orphan cleanup"
    );
    Ok(())
}

/// Remove the state file for the current process after successful cleanup.
pub fn clear_sandbox_state() {
    let path = state_file_path(std::process::id());
    let _ = std::fs::remove_file(&path);
}

/// Check if a process is still running (signal 0 = liveness check).
/// Check if a process is genuinely alive (not zombie, not PID-reused).
/// Returns false for:
/// - Dead processes (ESRCH)
/// - Zombie processes (state = Z in /proc/PID/stat)
/// - PID-reused processes (start time differs from state file creation)
fn is_pid_alive(pid: u32) -> bool {
    // Step 1: basic liveness check
    if unsafe { libc::kill(pid as i32, 0) != 0 } {
        return false;
    }

    // Step 2: check /proc/PID/stat for zombie state and process identity
    let stat_path = format!("/proc/{}/stat", pid);
    let stat_content = match std::fs::read_to_string(&stat_path) {
        Ok(c) => c,
        Err(_) => return false, // Cannot read → treat as dead
    };

    // Parse state field (3rd field, after PID and comm in parens)
    // Format: "PID (comm) S ..."  where S is the state character
    if let Some(close_paren) = stat_content.rfind(')') {
        let after_comm = &stat_content[close_paren + 2..];
        let state = after_comm.chars().next().unwrap_or('?');
        if state == 'Z' {
            // Zombie — process exists but is dead, parent hasn't reaped
            tracing::debug!(pid = pid, "PID is zombie — treating as dead for cleanup");
            return false;
        }
    }

    // Step 3: verify it's actually a GVM-related process (not PID reuse)
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    match std::fs::read_to_string(&cmdline_path) {
        Ok(cmdline) => cmdline.contains("gvm"),
        Err(_) => false,
    }
}

/// Clean up all resources listed in a SandboxState.
fn cleanup_state_resources(state: &SandboxState) {
    // 1. Unmount sandbox mount paths (reverse order for nested mounts)
    for mount_path in state.mount_paths.iter().rev() {
        let path = std::path::Path::new(mount_path);
        if path.exists() {
            nix::mount::umount2(path, nix::mount::MntFlags::MNT_DETACH).ok();
            std::fs::remove_dir_all(path).ok();
            tracing::debug!(path = mount_path, "Unmounted orphan mount");
        }
    }

    // 2. Clean up cgroup
    if let Some(ref cgroup) = state.cgroup_path {
        let cg = std::path::Path::new(cgroup);
        if cg.exists() {
            // Kill any remaining processes in the cgroup
            let procs_path = cg.join("cgroup.procs");
            if let Ok(content) = std::fs::read_to_string(&procs_path) {
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                }
            }
            std::fs::remove_dir(cg).ok();
            tracing::debug!(cgroup = cgroup, "Removed orphan cgroup");
        }
    }

    // 3. Clean up network (veth + iptables + eBPF)
    let veth_exists = Command::new("ip")
        .args(["link", "show", &state.veth_host])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if veth_exists {
        let veth_config = VethConfig {
            host_iface: state.veth_host.clone(),
            sandbox_iface: state.veth_sandbox.clone(),
            host_ip: state.host_ip.clone(),
            sandbox_ip: state.sandbox_ip.clone(),
            cidr: 30,
            child_pid: state.pid,
            proxy_addr: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                state.proxy_port,
            ),
        };
        // TC filter must be detached BEFORE veth deletion (cleanup_host_network
        // deletes the veth). Reversing this order makes detach a no-op.
        crate::ebpf::detach_tc_filter(&state.veth_host);
        cleanup_host_network(&veth_config, state.dns_target.as_deref());
        tracing::debug!(iface = %state.veth_host, "Cleaned orphan: TC filter + iptables + veth");
    }
}

/// Scan for stale state files and clean up orphaned sandbox resources.
///
/// Called at the start of every `gvm run --sandbox`. Finds state files
/// whose owning PID is no longer running, cleans up all listed resources,
/// and deletes the state files.
///
/// Also cleans up legacy single-file state from pre-v0.2 (`/run/gvm/interfaces.json`).
///
/// Returns the number of orphaned sandboxes cleaned up.
pub fn cleanup_all_orphans() -> Result<u32> {
    let mut cleaned = 0u32;

    // 1. Scan per-PID state files
    let pattern = format!("{}/{}*{}", STATE_DIR, STATE_PREFIX, STATE_SUFFIX);
    for entry in glob::glob(&pattern).unwrap_or_else(|_| glob::glob("").unwrap()) {
        let path = match entry {
            Ok(p) => p,
            Err(_) => continue,
        };

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        let state: SandboxState = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!(path = %path.display(), "Corrupt state file — removing");
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };

        // Skip if the owning process is still alive
        if is_pid_alive(state.pid) {
            continue;
        }

        tracing::info!(
            pid = state.pid,
            veth = %state.veth_host,
            mounts = state.mount_paths.len(),
            "Cleaning up orphaned sandbox (PID {} dead)",
            state.pid
        );

        cleanup_state_resources(&state);
        let _ = std::fs::remove_file(&path);
        cleaned += 1;
    }

    // 2. Clean up legacy single-file state (pre-v0.2 backward compat)
    if let Ok(content) = std::fs::read_to_string(LEGACY_STATE_FILE) {
        if let Ok(legacy) = serde_json::from_str::<serde_json::Value>(&content) {
            let pid = legacy["pid"].as_u64().unwrap_or(0) as u32;
            if pid == 0 || !is_pid_alive(pid) {
                let host_iface = legacy["veth_host"].as_str().unwrap_or("");
                if !host_iface.is_empty() {
                    let proxy_port = legacy["proxy_port"].as_u64().unwrap_or(8080) as u16;
                    let config = VethConfig {
                        host_iface: host_iface.to_string(),
                        sandbox_iface: legacy["veth_sandbox"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        host_ip: legacy["host_ip"]
                            .as_str()
                            .unwrap_or("10.200.0.1")
                            .to_string(),
                        sandbox_ip: legacy["sandbox_ip"]
                            .as_str()
                            .unwrap_or("10.200.0.2")
                            .to_string(),
                        cidr: 30,
                        child_pid: pid,
                        proxy_addr: SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                            proxy_port,
                        ),
                    };
                    cleanup_host_network(&config, None);
                    crate::ebpf::detach_tc_filter(host_iface);
                    tracing::info!("Cleaned up legacy state file");
                }
                let _ = std::fs::remove_file(LEGACY_STATE_FILE);
                cleaned += 1;
            }
        }
    }

    // 3. Defense-in-depth: find veth-gvm-* interfaces with no state file
    if let Ok(output) = Command::new("ip").args(["-o", "link", "show"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if let Some(iface) = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.strip_suffix(':'))
            {
                if iface.starts_with("veth-gvm-h") {
                    // Check if any state file references this interface
                    let has_state = glob::glob(&pattern)
                        .ok()
                        .map(|entries| {
                            entries.filter_map(|e| e.ok()).any(|p| {
                                std::fs::read_to_string(&p)
                                    .ok()
                                    .map(|c| c.contains(iface))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);

                    if !has_state {
                        tracing::warn!(
                            iface = iface,
                            "Found orphan veth with no state file — cleaning up"
                        );
                        // Clean iptables chain for this veth before deleting it
                        cleanup_orphan_iptables_chain(iface);
                        let _ = Command::new("ip")
                            .args(["link", "del", iface])
                            .output();
                        cleaned += 1;
                    }
                }
            }
        }
    }

    // 4. Defense-in-depth: scan FORWARD chain for stale GVM-* chains without matching veth
    // This catches iptables pollution from SIGKILL'd sandboxes where state file was never written.
    cleaned += cleanup_stale_forward_chains() as u32;

    if cleaned > 0 {
        tracing::info!(count = cleaned, "Orphan sandbox cleanup complete");
    }
    Ok(cleaned)
}

/// Remove iptables FORWARD chain and associated NAT/MASQUERADE rules for an orphan veth.
/// Best-effort: all operations use .ok() to avoid failing the cleanup.
fn cleanup_orphan_iptables_chain(host_iface: &str) {
    let chain_name = format!("GVM-{}", host_iface);
    // Remove jump from FORWARD
    run_iptables(&["-D", "FORWARD", "-j", &chain_name]).ok();
    // Flush and delete chain
    run_iptables(&["-F", &chain_name]).ok();
    run_iptables(&["-X", &chain_name]).ok();

    // Clean NAT rules that reference this interface (PREROUTING DNAT + POSTROUTING MASQUERADE).
    // These rules use -i {host_iface} so we can identify them.
    // Use iptables-save + grep to find and delete specific rules.
    if let Ok(output) = Command::new("iptables-save").args(["-t", "nat"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(host_iface) && line.starts_with("-A ") {
                // Convert "-A PREROUTING ..." to "-D PREROUTING ..." for deletion
                let delete_rule = line.replacen("-A ", "-D ", 1);
                let args: Vec<&str> = std::iter::once("-t")
                    .chain(std::iter::once("nat"))
                    .chain(delete_rule.split_whitespace())
                    .collect();
                run_iptables(&args).ok();
            }
        }
    }

    tracing::debug!(chain = %chain_name, "Cleaned orphan iptables chain + NAT rules for {}", host_iface);
}

/// Scan iptables FORWARD chains for stale GVM-* entries that have no corresponding veth interface.
/// Returns the number of stale chains cleaned.
fn cleanup_stale_forward_chains() -> usize {
    let mut cleaned = 0;

    // List all iptables chains
    let output = match Command::new("iptables").args(["-L", "-n"]).output() {
        Ok(o) => o,
        Err(_) => return 0,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Find GVM-veth-gvm-* chain references
    for line in stdout.lines() {
        // Lines like "Chain GVM-veth-gvm-h12345 (1 references)"
        if let Some(chain) = line.strip_prefix("Chain ") {
            if let Some(chain_name) = chain.split_whitespace().next() {
                if chain_name.starts_with("GVM-veth-gvm-") {
                    // Extract interface name: GVM-{iface} → {iface}
                    let iface = &chain_name[4..]; // strip "GVM-"

                    // Check if veth still exists
                    let veth_exists = Command::new("ip")
                        .args(["link", "show", iface])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);

                    if !veth_exists {
                        tracing::warn!(
                            chain = chain_name,
                            iface = iface,
                            "Stale iptables FORWARD chain (veth gone) — removing"
                        );
                        run_iptables(&["-D", "FORWARD", "-j", chain_name]).ok();
                        run_iptables(&["-F", chain_name]).ok();
                        run_iptables(&["-X", chain_name]).ok();
                        cleaned += 1;
                    }
                }
            }
        }
    }

    cleaned
}

// Backward-compatible aliases for existing callers during migration.

/// Record network state (legacy alias — delegates to per-PID state).
pub fn record_network_state(config: &VethConfig) -> Result<()> {
    record_sandbox_state(config, &[], None, None)
}

/// Clear network state (legacy alias — delegates to per-PID clear).
pub fn clear_network_state() {
    clear_sandbox_state();
}

/// Clean up orphaned network (legacy alias — delegates to full orphan scan).
pub fn cleanup_orphaned_network() -> Result<bool> {
    let count = cleanup_all_orphans()?;
    Ok(count > 0)
}

/// Run an `ip6tables` command, returning an error on failure.
fn run_ip6tables(args: &[&str]) -> Result<()> {
    let output = Command::new("ip6tables")
        .args(args)
        .output()
        .context("Failed to execute 'ip6tables' command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip6tables {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}
