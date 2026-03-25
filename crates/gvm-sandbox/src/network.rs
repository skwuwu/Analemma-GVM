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
use std::net::SocketAddr;
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
pub fn setup_host_network(config: &VethConfig) -> Result<()> {
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

    // 4. Enable IP forwarding (global + per-interface).
    // Global forwarding is required for DNAT/MASQUERADE to work.
    // Per-interface forwarding alone is not sufficient.
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("Failed to enable global IP forwarding")?;
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/forwarding", config.host_iface),
        "1",
    )
    .ok();
    // Enable route_localnet so DNAT to 127.0.0.1 works on the veth interface.
    // Without this, packets DNATed to 127.0.0.1 are silently dropped as martians.
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/route_localnet", config.host_iface),
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

    // 6. MASQUERADE restricted to proxy port traffic only (not all traffic)
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

    // 7. Use a per-sandbox FORWARD chain to avoid stale rule accumulation.
    // Previous sandbox crashes could leave DROP rules in FORWARD that block new runs.
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
    // DROP everything else from/to this veth (proxy bypass prevention)
    run_iptables(&["-A", &chain_name, "-i", &config.host_iface, "-j", "DROP"])?;
    // Jump to per-sandbox chain from FORWARD (insert at top to avoid stale DROPs)
    run_iptables(&["-I", "FORWARD", "1", "-j", &chain_name])?;

    tracing::debug!(
        host_iface = %config.host_iface,
        host_ip = %config.host_ip,
        sandbox_ip = %config.sandbox_ip,
        "Host-side network configured (proxy-only, FORWARD DROP default)"
    );

    Ok(())
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
pub fn cleanup_host_network(config: &VethConfig) {
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

    // DNAT
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

    // Remove veth pair (removing one end removes both)
    run_ip(&["link", "del", &config.host_iface]).ok();

    tracing::debug!(
        host_iface = %config.host_iface,
        "Host network cleaned up"
    );
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

// ─── Orphan Network Resource Tracking ───

const STATE_DIR: &str = "/run/gvm";
const STATE_FILE: &str = "/run/gvm/interfaces.json";

/// Record a sandbox's network resources in the state file.
/// Called after host-side network setup succeeds.
/// If the process crashes before cleanup, the next `gvm run` can read
/// this file and clean up orphaned interfaces/rules.
pub fn record_network_state(config: &VethConfig) -> Result<()> {
    let state = serde_json::json!({
        "veth_host": config.host_iface,
        "veth_sandbox": config.sandbox_iface,
        "host_ip": config.host_ip.to_string(),
        "sandbox_ip": config.sandbox_ip.to_string(),
        "proxy_port": config.proxy_addr.port(),
        "pid": std::process::id(),
        "created_at": time::OffsetDateTime::now_utc().to_string(),
    });

    if let Err(e) = std::fs::create_dir_all(STATE_DIR) {
        tracing::debug!(error = %e, "Cannot create {STATE_DIR} — orphan cleanup unavailable");
        return Ok(()); // Non-fatal: /run may not be writable in some environments
    }

    std::fs::write(STATE_FILE, serde_json::to_string_pretty(&state)?)
        .with_context(|| format!("Failed to write network state to {STATE_FILE}"))?;

    tracing::debug!(path = STATE_FILE, "Network state recorded for orphan cleanup");
    Ok(())
}

/// Remove the state file after successful cleanup.
pub fn clear_network_state() {
    let _ = std::fs::remove_file(STATE_FILE);
}

/// Clean up orphaned network resources from a previous crash.
/// Reads `/run/gvm/interfaces.json`, reconstructs a VethConfig,
/// calls `cleanup_host_network`, then removes the state file.
///
/// Returns Ok(true) if orphans were cleaned, Ok(false) if no state file,
/// Err on I/O failure (non-fatal — logged and continued).
pub fn cleanup_orphaned_network() -> Result<bool> {
    let content = match std::fs::read_to_string(STATE_FILE) {
        Ok(c) => c,
        Err(_) => return Ok(false), // No state file — nothing to clean
    };

    let state: serde_json::Value = serde_json::from_str(&content)
        .context("Failed to parse orphan state file")?;

    let host_iface = state["veth_host"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if host_iface.is_empty() {
        clear_network_state();
        return Ok(false);
    }

    // Check if the interface still exists
    let exists = Command::new("ip")
        .args(["link", "show", &host_iface])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !exists {
        // Interface already gone — just clean up state file
        tracing::debug!(iface = %host_iface, "Orphan veth already removed");
        clear_network_state();
        return Ok(false);
    }

    // Reconstruct VethConfig and clean up
    let proxy_port = state["proxy_port"].as_u64().unwrap_or(8080) as u16;

    let config = VethConfig {
        host_iface: host_iface.clone(),
        sandbox_iface: state["veth_sandbox"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        host_ip: state["host_ip"]
            .as_str()
            .unwrap_or("10.200.0.1")
            .to_string(),
        sandbox_ip: state["sandbox_ip"]
            .as_str()
            .unwrap_or("10.200.0.2")
            .to_string(),
        cidr: 30,
        child_pid: state["pid"].as_u64().unwrap_or(0) as u32,
        proxy_addr: std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            proxy_port,
        ),
    };

    tracing::info!(
        iface = %host_iface,
        pid = state["pid"].as_u64().unwrap_or(0),
        "Cleaning up orphaned sandbox network from previous crash"
    );

    cleanup_host_network(&config);
    crate::ebpf::detach_tc_filter(&host_iface);
    clear_network_state();

    tracing::info!("Orphaned network resources cleaned up");
    Ok(true)
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
