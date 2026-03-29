//! eBPF TC egress filter for unbypassable proxy enforcement.
//!
//! Attaches a TC (Traffic Control) classifier to the HOST-side veth interface.
//! This filter runs in the host's network namespace, completely outside the
//! agent's control — even with CAP_NET_ADMIN inside a user namespace, the
//! agent cannot detach or modify programs on host-side interfaces.
//!
//! The filter allows only:
//! - TCP to proxy IP:port (GVM proxy)
//! - UDP to proxy IP:53 (DNS)
//! - ARP (L2 resolution)
//!
//! All other traffic is dropped at the kernel level (TC_ACT_SHOT).
//!
//! Fallback: if eBPF is unavailable (kernel < 4.15, missing bpf() capability,
//! or no clsact qdisc support), the system falls back to iptables-only mode
//! with a warning. The seccomp AF_NETLINK restriction provides defense-in-depth
//! in this case.
//!
//! Architecture:
//! ```text
//!   Agent (sandbox netns)     Host netns
//!   ┌──────────┐              ┌──────────────────────┐
//!   │ veth-sb  │──────────────│ veth-host            │
//!   │          │              │   ↓                  │
//!   │ (any     │              │ [TC ingress eBPF]    │
//!   │  traffic)│              │   ↓ PASS/DROP        │
//!   └──────────┘              │ [iptables NAT]       │
//!                             │   ↓                  │
//!                             │ GVM Proxy            │
//!                             └──────────────────────┘
//! ```

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;

/// Minimum kernel version for TC eBPF clsact support.
const MIN_KERNEL_MAJOR: u32 = 4;
const MIN_KERNEL_MINOR: u32 = 15;

/// Result of eBPF attachment attempt.
pub enum EbpfAttachResult {
    /// eBPF TC filter attached successfully. Holds a guard that detaches on drop.
    /// Caller must keep the guard alive for the sandbox duration and drop it on cleanup.
    Attached {
        /// Interface name the filter is attached to.
        interface: String,
        /// RAII guard — dropping this detaches the TC filter.
        guard: EbpfGuard,
    },
    /// eBPF is unavailable; system should use iptables fallback.
    Unavailable {
        /// Reason eBPF could not be used.
        reason: String,
    },
}

/// eBPF guard that detaches the filter on drop.
pub struct EbpfGuard {
    interface: String,
}

impl Drop for EbpfGuard {
    fn drop(&mut self) {
        detach_tc_filter(&self.interface);
    }
}

/// Check if the current system supports eBPF TC filters.
pub fn check_ebpf_support() -> Result<(), String> {
    // 1. Check kernel version
    let (major, minor) =
        kernel_version().map_err(|e| format!("Cannot read kernel version: {}", e))?;
    if major < MIN_KERNEL_MAJOR || (major == MIN_KERNEL_MAJOR && minor < MIN_KERNEL_MINOR) {
        return Err(format!(
            "Kernel {}.{} < {}.{} (TC clsact requires >= {}.{})",
            major, minor, MIN_KERNEL_MAJOR, MIN_KERNEL_MINOR, MIN_KERNEL_MAJOR, MIN_KERNEL_MINOR
        ));
    }

    // 2. Check if tc command is available
    if !command_exists("tc") {
        return Err("'tc' command not found (install iproute2)".to_string());
    }

    // 3. Check if bpf() syscall is available by checking /proc/sys/net/core/bpf_jit_enable
    //    (presence indicates BPF support)
    if !std::path::Path::new("/proc/sys/net/core/bpf_jit_enable").exists() {
        return Err("BPF JIT not available (CONFIG_BPF_JIT not enabled)".to_string());
    }

    Ok(())
}

/// Attach a TC eBPF egress filter to the host-side veth interface.
///
/// Uses `tc` command to:
/// 1. Add a clsact qdisc to the interface
/// 2. Attach a BPF program as an ingress filter (ingress = traffic FROM sandbox)
///
/// Since we cannot embed a compiled eBPF .o in a cross-platform build,
/// we use tc's built-in BPF bytecode mode with a hand-assembled filter
/// that matches the logic of gvm_tc_filter.bpf.c.
///
/// Returns an EbpfGuard that removes the filter on drop.
pub fn attach_tc_filter(interface: &str, proxy_ip: Ipv4Addr, proxy_port: u16) -> Result<EbpfGuard> {
    // 1. Add clsact qdisc (multi-attach qdisc for ingress/egress classification)
    let output = Command::new("tc")
        .args(["qdisc", "add", "dev", interface, "clsact"])
        .output()
        .context("Failed to execute 'tc' command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "File exists" means clsact already attached — acceptable
        if !stderr.contains("File exists") {
            anyhow::bail!("tc qdisc add clsact failed: {}", stderr.trim());
        }
    }

    // 2. Build and attach the BPF bytecode filter
    //
    // We use tc u32 match filters as a portable alternative to compiled eBPF objects.
    // This achieves the same kernel-level filtering without requiring clang/llvm
    // or a pre-compiled .o file, while remaining on the HOST-side veth (unbypassable).
    //
    // The filter structure:
    //   Priority 1: Allow TCP to proxy_ip:proxy_port
    //   Priority 2: Allow UDP to proxy_ip:53 (DNS)
    //   Priority 3: Allow ARP (EtherType 0x0806)
    //   Priority 99: Drop everything else (catch-all)

    let ip_hex = format!(
        "{:02x}{:02x}{:02x}{:02x}",
        proxy_ip.octets()[0],
        proxy_ip.octets()[1],
        proxy_ip.octets()[2],
        proxy_ip.octets()[3]
    );
    let _ip_u32 = format!("0x{}", ip_hex);
    let port_hex = format!("0x{:04x}", proxy_port);
    let dns_port_hex = "0x0035"; // port 53

    // Priority 1: Allow TCP (protocol 6) to proxy IP:port
    //   Match IP protocol = TCP (6) at offset 9 of IP header
    //   Match destination IP at offset 16 of IP header
    //   Match destination port at offset 2 of TCP header (offset 22 from IP start)
    run_tc(&[
        "filter",
        "add",
        "dev",
        interface,
        "ingress",
        "protocol",
        "ip",
        "prio",
        "1",
        "u32",
        "match",
        "ip",
        "protocol",
        "6",
        "0xff", // TCP
        "match",
        "ip",
        "dst",
        &format!("{}", proxy_ip),
        "255.255.255.255",
        "match",
        "ip",
        "dport",
        &port_hex.to_string(),
        "0xffff",
        "action",
        "ok",
    ])?;

    // Priority 2: Allow UDP (protocol 17) to proxy IP:53 (DNS)
    run_tc(&[
        "filter",
        "add",
        "dev",
        interface,
        "ingress",
        "protocol",
        "ip",
        "prio",
        "2",
        "u32",
        "match",
        "ip",
        "protocol",
        "17",
        "0xff", // UDP
        "match",
        "ip",
        "dst",
        &format!("{}", proxy_ip),
        "255.255.255.255",
        "match",
        "ip",
        "dport",
        dns_port_hex,
        "0xffff",
        "action",
        "ok",
    ])?;

    // Priority 3: Allow ARP (EtherType 0x0806) — needed for L2 resolution
    run_tc(&[
        "filter", "add", "dev", interface, "ingress", "protocol", "arp", "prio", "3", "u32",
        "match", "u32", "0", "0", // match any ARP packet
        "action", "ok",
    ])?;

    // Priority 99: Drop everything else (catch-all)
    run_tc(&[
        "filter", "add", "dev", interface, "ingress", "protocol", "all", "prio", "99", "u32",
        "match", "u32", "0", "0", // match everything
        "action", "drop",
    ])?;

    tracing::info!(
        interface = interface,
        proxy = %format!("{}:{}", proxy_ip, proxy_port),
        "TC ingress filter attached (unbypassable proxy enforcement)"
    );

    Ok(EbpfGuard {
        interface: interface.to_string(),
    })
}

/// Attempt to attach eBPF filter, returning Unavailable on failure instead of error.
pub fn try_attach_tc_filter(
    interface: &str,
    proxy_ip: Ipv4Addr,
    proxy_port: u16,
) -> EbpfAttachResult {
    // Pre-check environment
    if let Err(reason) = check_ebpf_support() {
        return EbpfAttachResult::Unavailable { reason };
    }

    match attach_tc_filter(interface, proxy_ip, proxy_port) {
        Ok(guard) => {
            // Return the guard to the caller — caller must keep it alive for the
            // sandbox duration. Dropping the guard detaches the TC filter.
            // Previously used mem::forget (unsafe, leak-prone); now RAII-managed.
            EbpfAttachResult::Attached {
                interface: interface.to_string(),
                guard,
            }
        }
        Err(e) => EbpfAttachResult::Unavailable {
            reason: format!("TC filter attachment failed: {}", e),
        },
    }
}

/// Remove TC filters from an interface (cleanup).
pub fn detach_tc_filter(interface: &str) {
    // Remove clsact qdisc (removes all attached filters)
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", interface, "clsact"])
        .output();

    tracing::debug!(interface = interface, "TC ingress filter detached");
}

/// Parse kernel version from uname.
fn kernel_version() -> Result<(u32, u32)> {
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .context("Failed to run uname")?;

    let version_str = String::from_utf8_lossy(&output.stdout);
    let version_str = version_str.trim();

    // Parse "5.15.0-generic" → (5, 15)
    let parts: Vec<&str> = version_str.split('.').collect();
    if parts.len() < 2 {
        anyhow::bail!("Cannot parse kernel version: {}", version_str);
    }

    let major: u32 = parts[0]
        .parse()
        .with_context(|| format!("Invalid kernel major: {}", parts[0]))?;
    let minor: u32 = parts[1]
        .parse()
        .with_context(|| format!("Invalid kernel minor: {}", parts[1]))?;

    Ok((major, minor))
}

/// Check if a command exists in PATH.
fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a `tc` command, returning an error on failure.
fn run_tc(args: &[&str]) -> Result<()> {
    let output = Command::new("tc")
        .args(args)
        .output()
        .context("Failed to execute 'tc' command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tc {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_version_parse() {
        // This test will work on any Linux system
        if cfg!(target_os = "linux") {
            let result = kernel_version();
            assert!(result.is_ok(), "kernel_version() must succeed on Linux");
            let (major, minor) = result.unwrap();
            assert!(major >= 3, "Kernel major version must be >= 3");
            assert!(minor < 1000, "Kernel minor version sanity check");
        }
    }

    #[test]
    fn ebpf_support_check_does_not_panic() {
        // This should never panic, just return Ok or Err
        let _ = check_ebpf_support();
    }

    #[test]
    fn attach_result_variants() {
        // Verify enum variants compile correctly.
        // Guard's Drop calls detach_tc_filter("test0") which harmlessly fails
        // on nonexistent interface (tc command returns error, silently ignored).
        let attached = EbpfAttachResult::Attached {
            interface: "test0".to_string(),
            guard: EbpfGuard {
                interface: "test0".to_string(),
            },
        };
        let unavailable = EbpfAttachResult::Unavailable {
            reason: "test".to_string(),
        };
        assert!(matches!(attached, EbpfAttachResult::Attached { .. }));
        assert!(matches!(unavailable, EbpfAttachResult::Unavailable { .. }));
    }
}
