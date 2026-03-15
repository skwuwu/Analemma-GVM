//! Network namespace setup: veth pair with proxy-only routing.
//!
//! Creates a point-to-point network between the sandbox and the host.
//! The sandbox can only reach the GVM proxy via the veth pair.
//! All other network traffic is dropped.
//!
//! Topology:
//! ```text
//!   Host netns                Sandbox netns
//!   ┌──────────┐              ┌──────────┐
//!   │ veth-host│──────────────│ veth-sb  │
//!   │ 10.200.  │              │ 10.200.  │
//!   │ X.1/30   │              │ X.2/30   │
//!   └────┬─────┘              └──────────┘
//!        │ DNAT
//!        ▼
//!   GVM Proxy (host)
//! ```
//!
//! The /30 subnet allows exactly 2 hosts. X is derived from the child PID
//! to support multiple concurrent sandboxes.

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

    // 5. DNAT: traffic from sandbox to host_ip:proxy_port → actual proxy
    let proxy_port = config.proxy_addr.port();
    run_iptables(&[
        "-t", "nat", "-A", "PREROUTING",
        "-i", &config.host_iface,
        "-p", "tcp", "--dport", &proxy_port.to_string(),
        "-j", "DNAT",
        "--to-destination", &config.proxy_addr.to_string(),
    ])?;

    // 6. MASQUERADE for return traffic
    run_iptables(&[
        "-t", "nat", "-A", "POSTROUTING",
        "-s", &format!("{}/{}", config.sandbox_ip, config.cidr),
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

    tracing::debug!(
        host_iface = %config.host_iface,
        host_ip = %config.host_ip,
        sandbox_ip = %config.sandbox_ip,
        "Host-side network configured"
    );

    Ok(())
}

/// Sandbox-side network setup: configure interface and routing.
/// Called from within the child's network namespace.
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

    // 3. Default route via host side (all traffic goes to proxy)
    run_ip(&[
        "route", "add", "default",
        "via", &config.host_ip,
    ])?;

    tracing::debug!(
        sandbox_ip = %config.sandbox_ip,
        gateway = %config.host_ip,
        "Sandbox network configured"
    );

    Ok(())
}

/// Clean up host-side network resources.
pub fn cleanup_host_network(config: &VethConfig) {
    // Remove iptables rules (best-effort)
    let proxy_port = config.proxy_addr.port();
    run_iptables(&[
        "-t", "nat", "-D", "PREROUTING",
        "-i", &config.host_iface,
        "-p", "tcp", "--dport", &proxy_port.to_string(),
        "-j", "DNAT",
        "--to-destination", &config.proxy_addr.to_string(),
    ])
    .ok();

    run_iptables(&[
        "-t", "nat", "-D", "POSTROUTING",
        "-s", &format!("{}/{}", config.sandbox_ip, config.cidr),
        "-j", "MASQUERADE",
    ])
    .ok();

    run_iptables(&[
        "-D", "FORWARD",
        "-i", &config.host_iface, "-o", "lo", "-j", "ACCEPT",
    ])
    .ok();

    run_iptables(&[
        "-D", "FORWARD",
        "-i", "lo", "-o", &config.host_iface, "-j", "ACCEPT",
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
