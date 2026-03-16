//! Network namespace setup: veth pair with proxy-only routing.
//!
//! Creates a point-to-point network between the sandbox and the host.
//! The sandbox can ONLY reach the GVM proxy via the veth pair.
//! All other network traffic is dropped by iptables OUTPUT rules
//! inside the sandbox namespace.
//!
//! Topology:
//! ```text
//!   Host netns                Sandbox netns
//!   ┌──────────┐              ┌──────────┐
//!   │ veth-host│──────────────│ veth-sb  │
//!   │ 10.200.  │              │ 10.200.  │
//!   │ X.1/30   │              │ X.2/30   │
//!   └────┬─────┘              └──────────┘
//!        │ DNAT                  OUTPUT:
//!        ▼                       proxy → ACCEPT
//!   GVM Proxy (host)             DNS   → ACCEPT (host_ip:53)
//!                                lo    → ACCEPT
//!                                *     → DROP
//! ```
//!
//! The /30 subnet allows exactly 2 hosts. X is derived from the child PID
//! to support multiple concurrent sandboxes.
//!
//! Security properties:
//! - No direct internet access from sandbox (OUTPUT DROP default)
//! - IPv6 fully disabled (prevents IPv6 bypass)
//! - DNS queries routed through host veth IP only
//! - MASQUERADE restricted to proxy port traffic only

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
        "link", "add", &config.host_iface,
        "type", "veth",
        "peer", "name", &config.sandbox_iface,
    ])?;

    // 2. Move sandbox end into child's network namespace
    run_ip(&[
        "link", "set", &config.sandbox_iface,
        "netns", &config.child_pid.to_string(),
    ])?;

    // 3. Configure host-side interface
    run_ip(&[
        "addr", "add",
        &format!("{}/{}", config.host_ip, config.cidr),
        "dev", &config.host_iface,
    ])?;
    run_ip(&["link", "set", &config.host_iface, "up"])?;

    // 4. Enable IP forwarding for this interface
    std::fs::write(
        format!("/proc/sys/net/ipv4/conf/{}/forwarding", config.host_iface),
        "1",
    )
    .ok(); // Best-effort, may need global forwarding

    // 5. DNAT: traffic from sandbox to proxy port → actual proxy address
    let proxy_port = config.proxy_addr.port();
    run_iptables(&[
        "-t", "nat", "-A", "PREROUTING",
        "-i", &config.host_iface,
        "-p", "tcp", "--dport", &proxy_port.to_string(),
        "-j", "DNAT",
        "--to-destination", &config.proxy_addr.to_string(),
    ])?;

    // 6. MASQUERADE restricted to proxy port traffic only (not all traffic)
    run_iptables(&[
        "-t", "nat", "-A", "POSTROUTING",
        "-s", &format!("{}/{}", config.sandbox_ip, config.cidr),
        "-p", "tcp", "--dport", &proxy_port.to_string(),
        "-j", "MASQUERADE",
    ])?;

    // 7. Allow forwarding between veth and loopback (proxy is on host)
    run_iptables(&[
        "-A", "FORWARD",
        "-i", &config.host_iface,
        "-o", "lo",
        "-j", "ACCEPT",
    ])?;
    run_iptables(&[
        "-A", "FORWARD",
        "-i", "lo",
        "-o", &config.host_iface,
        "-j", "ACCEPT",
    ])?;

    // 8. Explicit DROP for veth traffic to any other destination
    // This prevents proxy bypass via direct socket connections that
    // would otherwise be routed through the default gateway.
    run_iptables(&[
        "-A", "FORWARD",
        "-i", &config.host_iface,
        "-j", "DROP",
    ])?;

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
/// All other outbound traffic is dropped.
pub fn setup_sandbox_network(config: &VethConfig) -> Result<()> {
    // 1. Bring up loopback
    run_ip(&["link", "set", "lo", "up"])?;

    // 2. Configure sandbox-side interface
    run_ip(&[
        "addr", "add",
        &format!("{}/{}", config.sandbox_ip, config.cidr),
        "dev", &config.sandbox_iface,
    ])?;
    run_ip(&["link", "set", &config.sandbox_iface, "up"])?;

    // 3. Default route via host side
    run_ip(&[
        "route", "add", "default",
        "via", &config.host_ip,
    ])?;

    // ── Firewall lockdown inside sandbox namespace ──

    // 4. Disable IPv6 completely (prevents IPv6 bypass of IPv4 firewall rules)
    disable_ipv6();

    // 5. OUTPUT chain: allow only proxy, DNS, and loopback
    let proxy_port = config.proxy_addr.port().to_string();

    // Allow loopback traffic
    run_iptables(&[
        "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT",
    ])?;

    // Allow established/related connections (return traffic)
    run_iptables(&[
        "-A", "OUTPUT", "-m", "state",
        "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT",
    ])?;

    // Allow TCP to proxy port on host IP only
    run_iptables(&[
        "-A", "OUTPUT",
        "-p", "tcp", "-d", &config.host_ip,
        "--dport", &proxy_port,
        "-j", "ACCEPT",
    ])?;

    // Allow UDP DNS to host IP only (resolv.conf must point to host_ip)
    run_iptables(&[
        "-A", "OUTPUT",
        "-p", "udp", "-d", &config.host_ip,
        "--dport", "53",
        "-j", "ACCEPT",
    ])?;

    // DROP everything else — this is the core proxy bypass prevention
    run_iptables(&[
        "-A", "OUTPUT", "-j", "DROP",
    ])?;

    tracing::debug!(
        sandbox_ip = %config.sandbox_ip,
        gateway = %config.host_ip,
        proxy_port = %proxy_port,
        "Sandbox network locked down: proxy-only OUTPUT, IPv6 disabled"
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
    std::fs::write(&path, value)
        .with_context(|| format!("Failed to set sysctl {}", key))?;
    Ok(())
}

/// Clean up host-side network resources.
pub fn cleanup_host_network(config: &VethConfig) {
    let proxy_port = config.proxy_addr.port();

    // Remove iptables rules (best-effort, reverse order)
    // FORWARD DROP for veth
    run_iptables(&[
        "-D", "FORWARD",
        "-i", &config.host_iface,
        "-j", "DROP",
    ])
    .ok();

    // FORWARD lo→veth
    run_iptables(&[
        "-D", "FORWARD",
        "-i", "lo", "-o", &config.host_iface, "-j", "ACCEPT",
    ])
    .ok();

    // FORWARD veth→lo
    run_iptables(&[
        "-D", "FORWARD",
        "-i", &config.host_iface, "-o", "lo", "-j", "ACCEPT",
    ])
    .ok();

    // MASQUERADE (now port-restricted)
    run_iptables(&[
        "-t", "nat", "-D", "POSTROUTING",
        "-s", &format!("{}/{}", config.sandbox_ip, config.cidr),
        "-p", "tcp", "--dport", &proxy_port.to_string(),
        "-j", "MASQUERADE",
    ])
    .ok();

    // DNAT
    run_iptables(&[
        "-t", "nat", "-D", "PREROUTING",
        "-i", &config.host_iface,
        "-p", "tcp", "--dport", &proxy_port.to_string(),
        "-j", "DNAT",
        "--to-destination", &config.proxy_addr.to_string(),
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
