//! Post-cleanup residual scanner.
//!
//! After a sandbox exit (or `gvm stop`), verify that all four resource
//! categories were actually released:
//!   1. Network — veth interface, filter chain, NAT rules
//!   2. Mounts  — entries in /proc/mounts under /run/gvm/
//!   3. Cgroup  — /sys/fs/cgroup/gvm-agent-{pid}
//!   4. State   — /run/gvm/gvm-sandbox-{pid}.state
//!
//! The pure parsers (`/proc/mounts`, `ip link show`, `iptables -S`) are
//! split out so unit tests run on Windows dev hosts. The runtime invocation
//! (`Command::new("ip")` etc.) is gated linux-only.
//!
//! Cost: one `ip link show`, two `iptables` calls, one `/proc/mounts` read,
//! three `Path::exists()` checks. Tens of milliseconds — safe to run after
//! every sandbox exit.

#![allow(dead_code)] // Some helpers are linux-only consumers; keep parsers cross-platform.

#[cfg(target_os = "linux")]
use std::path::Path;

/// Per-category residual report. Each `Vec<String>` is the list of leaked
/// resource identifiers (interface names, mount points, etc) — empty means
/// the category is clean.
#[derive(Debug, Clone, Default)]
pub struct CleanupVerification {
    /// Veth interfaces, filter chains, or NAT rules still referencing this sandbox.
    pub network_residuals: Vec<String>,
    /// Mount points still in /proc/mounts under /run/gvm/ for this PID.
    pub mount_residuals: Vec<String>,
    /// cgroup directory path if it still exists.
    pub cgroup_residual: Option<String>,
    /// State file path if it still exists.
    pub state_file_residual: Option<String>,
}

impl CleanupVerification {
    /// True iff every category is empty.
    pub fn is_clean(&self) -> bool {
        self.network_residuals.is_empty()
            && self.mount_residuals.is_empty()
            && self.cgroup_residual.is_none()
            && self.state_file_residual.is_none()
    }

    /// Total count of leaked resources across all categories.
    pub fn total(&self) -> usize {
        self.network_residuals.len()
            + self.mount_residuals.len()
            + usize::from(self.cgroup_residual.is_some())
            + usize::from(self.state_file_residual.is_some())
    }
}

// ─── Pure parsers (OS-independent, unit-testable) ─────────────────────

/// Scan `/proc/mounts` text and return entries whose mountpoint matches any
/// of the expected paths.
///
/// `/proc/mounts` format (one entry per line):
/// ```text
/// tmpfs /run/gvm/sandbox-root-12345 tmpfs rw,nosuid,nodev,size=64m 0 0
/// overlay /run/gvm/home-merged-12345 overlay rw,...           0 0
/// ```
/// Field 2 is the mountpoint. We compare it against `expected_paths`.
pub fn parse_mount_residuals(proc_mounts: &str, expected_paths: &[&str]) -> Vec<String> {
    let mut residuals = Vec::new();
    for line in proc_mounts.lines() {
        // Field 2 (zero-indexed: 1) is the mountpoint.
        let mountpoint = match line.split_whitespace().nth(1) {
            Some(m) => m,
            None => continue,
        };
        if expected_paths.contains(&mountpoint) {
            residuals.push(mountpoint.to_string());
        }
    }
    residuals
}

/// Scan `ip -o link show` output for a specific interface name.
///
/// Output format (one interface per line):
/// ```text
/// 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
/// 24: veth-gvm-h0@if23: <BROADCAST,MULTICAST,UP,LOWER_UP> ...
/// ```
/// Field 2 (after the index) contains the name, possibly with `@peer` suffix.
pub fn iface_present_in_link_show(ip_link_output: &str, iface: &str) -> bool {
    for line in ip_link_output.lines() {
        // Skip the index field, take the name token, strip `@peer` if present.
        let name_field = line.split_whitespace().nth(1);
        if let Some(name) = name_field {
            let stripped = name.trim_end_matches(':');
            let base = stripped.split('@').next().unwrap_or(stripped);
            if base == iface {
                return true;
            }
        }
    }
    false
}

/// Scan `iptables -S` output for a chain matching `GVM-{iface}`.
///
/// `iptables -S` lists rules and chain declarations:
/// ```text
/// -N GVM-veth-gvm-h0
/// -A FORWARD -j GVM-veth-gvm-h0
/// ```
/// Either form indicates the chain still exists.
pub fn chain_present_in_iptables(iptables_output: &str, chain_name: &str) -> bool {
    for line in iptables_output.lines() {
        // -N declares the chain; -A references it as a target.
        if (line.starts_with("-N ") || line.contains(" -j "))
            && line.split_whitespace().any(|t| t == chain_name)
        {
            return true;
        }
    }
    false
}

/// Scan `iptables-save -t nat` output for any rule referencing the given
/// interface (either `-i {iface}` or `-o {iface}`). NAT rules use these
/// flags to match traffic by interface.
pub fn nat_rule_references_iface(nat_output: &str, iface: &str) -> bool {
    for line in nat_output.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(t) = tokens.next() {
            if (t == "-i" || t == "-o") && tokens.next() == Some(iface) {
                return true;
            }
        }
    }
    false
}

// ─── Runtime checks (linux-only) ──────────────────────────────────────

/// Run all four residual checks and return a populated report.
///
/// `pid` is the parent process PID (used for state file + cgroup paths).
/// `host_iface` is the host-side veth name. `mount_paths` is the list
/// of paths recorded in the SandboxState's mount manifest.
#[cfg(target_os = "linux")]
pub fn verify_cleanup(pid: u32, host_iface: &str, mount_paths: &[String]) -> CleanupVerification {
    use std::process::Command;

    let mut report = CleanupVerification::default();

    // ── 1. Network: veth + filter chain + NAT rules ──
    let veth_chain = format!("GVM-{}", host_iface);

    if let Ok(out) = Command::new("ip").args(["-o", "link", "show"]).output() {
        if iface_present_in_link_show(&String::from_utf8_lossy(&out.stdout), host_iface) {
            report
                .network_residuals
                .push(format!("veth {}", host_iface));
        }
    }

    if let Ok(out) = Command::new("iptables").arg("-S").output() {
        if chain_present_in_iptables(&String::from_utf8_lossy(&out.stdout), &veth_chain) {
            report
                .network_residuals
                .push(format!("iptables chain {}", veth_chain));
        }
    }

    if let Ok(out) = Command::new("iptables-save").args(["-t", "nat"]).output() {
        if nat_rule_references_iface(&String::from_utf8_lossy(&out.stdout), host_iface) {
            report
                .network_residuals
                .push(format!("NAT rule referencing {}", host_iface));
        }
    }

    // ── 2. Mounts: /proc/mounts entries under /run/gvm/ for this PID ──
    if let Ok(content) = std::fs::read_to_string("/proc/mounts") {
        let expected: Vec<&str> = mount_paths.iter().map(|s| s.as_str()).collect();
        let residuals = parse_mount_residuals(&content, &expected);
        report.mount_residuals = residuals;
    }

    // ── 3. Cgroup: /sys/fs/cgroup/gvm-agent-{pid} ──
    let cgroup_path = format!("/sys/fs/cgroup/gvm-agent-{}", pid);
    if Path::new(&cgroup_path).exists() {
        report.cgroup_residual = Some(cgroup_path);
    }

    // ── 4. State file: /run/gvm/gvm-sandbox-{pid}.state ──
    let state_path = format!("/run/gvm/gvm-sandbox-{}.state", pid);
    if Path::new(&state_path).exists() {
        report.state_file_residual = Some(state_path);
    }

    report
}

#[cfg(not(target_os = "linux"))]
pub fn verify_cleanup(
    _pid: u32,
    _host_iface: &str,
    _mount_paths: &[String],
) -> CleanupVerification {
    CleanupVerification::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── /proc/mounts parser ──

    const PROC_MOUNTS_WITH_RESIDUAL: &str = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run/gvm/sandbox-root-12345 tmpfs rw,nosuid,nodev,size=64m 0 0
overlay /run/gvm/home-merged-12345 overlay rw,lowerdir=/home/user 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
";

    #[test]
    fn parse_mounts_finds_expected_residual() {
        let expected = ["/run/gvm/sandbox-root-12345"];
        let r = parse_mount_residuals(PROC_MOUNTS_WITH_RESIDUAL, &expected);
        assert_eq!(r, vec!["/run/gvm/sandbox-root-12345"]);
    }

    #[test]
    fn parse_mounts_finds_multiple_residuals() {
        let expected = ["/run/gvm/sandbox-root-12345", "/run/gvm/home-merged-12345"];
        let r = parse_mount_residuals(PROC_MOUNTS_WITH_RESIDUAL, &expected);
        assert_eq!(r.len(), 2);
        assert!(r.contains(&"/run/gvm/sandbox-root-12345".to_string()));
        assert!(r.contains(&"/run/gvm/home-merged-12345".to_string()));
    }

    #[test]
    fn parse_mounts_clean_returns_empty() {
        let expected = ["/run/gvm/sandbox-root-99999"];
        let r = parse_mount_residuals(PROC_MOUNTS_WITH_RESIDUAL, &expected);
        assert!(r.is_empty());
    }

    #[test]
    fn parse_mounts_substring_does_not_match() {
        // /run/gvm/sandbox-root-12345 must not match /run/gvm/sandbox-root-1
        let expected = ["/run/gvm/sandbox-root-1"];
        let r = parse_mount_residuals(PROC_MOUNTS_WITH_RESIDUAL, &expected);
        assert!(r.is_empty());
    }

    #[test]
    fn parse_mounts_handles_empty_input() {
        let r = parse_mount_residuals("", &["/run/gvm/anything"]);
        assert!(r.is_empty());
    }

    // ── ip link show parser ──

    const IP_LINK_OUTPUT: &str = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
24: veth-gvm-h0@if23: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
";

    #[test]
    fn link_show_finds_veth_with_peer_suffix() {
        assert!(iface_present_in_link_show(IP_LINK_OUTPUT, "veth-gvm-h0"));
    }

    #[test]
    fn link_show_finds_loopback() {
        assert!(iface_present_in_link_show(IP_LINK_OUTPUT, "lo"));
    }

    #[test]
    fn link_show_missing_returns_false() {
        assert!(!iface_present_in_link_show(IP_LINK_OUTPUT, "veth-gvm-h99"));
    }

    #[test]
    fn link_show_substring_does_not_match() {
        // veth-gvm-h must not match veth-gvm-h0
        assert!(!iface_present_in_link_show(IP_LINK_OUTPUT, "veth-gvm-h"));
    }

    // ── iptables -S parser ──

    const IPTABLES_OUTPUT: &str = "\
-P INPUT ACCEPT
-P FORWARD DROP
-P OUTPUT ACCEPT
-N GVM-veth-gvm-h0
-A FORWARD -j GVM-veth-gvm-h0
-A GVM-veth-gvm-h0 -i veth-gvm-h0 -j ACCEPT
";

    #[test]
    fn iptables_finds_chain_declaration() {
        assert!(chain_present_in_iptables(
            IPTABLES_OUTPUT,
            "GVM-veth-gvm-h0"
        ));
    }

    #[test]
    fn iptables_missing_chain_returns_false() {
        assert!(!chain_present_in_iptables(
            IPTABLES_OUTPUT,
            "GVM-veth-gvm-h99"
        ));
    }

    #[test]
    fn iptables_clean_returns_false() {
        let clean = "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n";
        assert!(!chain_present_in_iptables(clean, "GVM-veth-gvm-h0"));
    }

    // ── iptables-save -t nat parser ──

    const NAT_OUTPUT: &str = "\
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A PREROUTING -i veth-gvm-h0 -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8080
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
";

    #[test]
    fn nat_finds_input_iface_match() {
        assert!(nat_rule_references_iface(NAT_OUTPUT, "veth-gvm-h0"));
    }

    #[test]
    fn nat_finds_output_iface_match() {
        assert!(nat_rule_references_iface(NAT_OUTPUT, "eth0"));
    }

    #[test]
    fn nat_missing_iface_returns_false() {
        assert!(!nat_rule_references_iface(NAT_OUTPUT, "veth-gvm-h99"));
    }

    // ── CleanupVerification helpers ──

    #[test]
    fn empty_report_is_clean() {
        let v = CleanupVerification::default();
        assert!(v.is_clean());
        assert_eq!(v.total(), 0);
    }

    #[test]
    fn report_with_any_residual_is_dirty() {
        let v = CleanupVerification {
            cgroup_residual: Some("/sys/fs/cgroup/gvm-agent-12345".to_string()),
            ..Default::default()
        };
        assert!(!v.is_clean());
        assert_eq!(v.total(), 1);
    }

    #[test]
    fn total_counts_all_categories() {
        let v = CleanupVerification {
            network_residuals: vec!["veth-x".into(), "chain-y".into()],
            mount_residuals: vec!["/mnt/a".into()],
            cgroup_residual: Some("/sys/fs/cgroup/g".into()),
            state_file_residual: Some("/run/gvm/x.state".into()),
        };
        assert_eq!(v.total(), 5);
    }
}
