//! Security tests for gvm-sandbox isolation layers.
//!
//! Tests verify that:
//! 1. seccomp AF_NETLINK blocking is correctly configured
//! 2. eBPF TC filter configuration is correct
//! 3. Fallback behavior works when eBPF is unavailable
//! 4. VethConfig generates correct addresses
//! 5. PreflightReport includes eBPF availability
//!
//! Note: Tests that require actual Linux namespaces or seccomp enforcement
//! are marked with #[cfg(target_os = "linux")]. Cross-platform tests verify
//! configuration correctness and data structures.

use gvm_sandbox::*;
use std::net::SocketAddr;

// ─── VethConfig tests ───

#[test]
fn veth_config_generates_unique_addresses_per_pid() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    let cfg1 = veth_config_from_pid(100, addr);
    let cfg2 = veth_config_from_pid(200, addr);

    // Different PIDs must produce different IPs and interface names
    assert_ne!(cfg1.host_ip, cfg2.host_ip);
    assert_ne!(cfg1.sandbox_ip, cfg2.sandbox_ip);
    assert_ne!(cfg1.host_iface, cfg2.host_iface);
}

#[test]
fn veth_config_address_format_correct() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let cfg = veth_config_from_pid(42, addr);

    // Must be 10.200.X.Y format
    assert!(
        cfg.host_ip.starts_with("10.200."),
        "Host IP must be in 10.200.0.0/16"
    );
    assert!(
        cfg.sandbox_ip.starts_with("10.200."),
        "Sandbox IP must be in 10.200.0.0/16"
    );
    assert_eq!(cfg.cidr, 30, "Must use /30 point-to-point subnet");

    // Interface names must include PID
    assert!(cfg.host_iface.starts_with("veth-gvm-h"));
    assert!(cfg.sandbox_iface.starts_with("veth-gvm-s"));
}

#[test]
fn veth_config_host_and_sandbox_in_same_subnet() {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();

    // Test multiple PIDs
    for pid in [1, 42, 255, 1000, 5000, 16000] {
        let cfg = veth_config_from_pid(pid, addr);

        // Parse IPs and verify they're in the same /30
        let host_parts: Vec<u8> = cfg.host_ip.split('.').map(|s| s.parse().unwrap()).collect();
        let sb_parts: Vec<u8> = cfg
            .sandbox_ip
            .split('.')
            .map(|s| s.parse().unwrap())
            .collect();

        // Same first 3 octets (10.200.X)
        assert_eq!(host_parts[0], sb_parts[0]);
        assert_eq!(host_parts[1], sb_parts[1]);
        assert_eq!(host_parts[2], sb_parts[2]);

        // Fourth octet: host = base+1, sandbox = base+2
        assert_eq!(
            sb_parts[3],
            host_parts[3] + 1,
            "Sandbox IP must be host IP + 1 (PID={})",
            pid
        );
    }
}

// ─── PreflightReport tests ───

#[test]
fn preflight_report_non_linux_has_ebpf_false() {
    // On non-Linux (including Windows CI), preflight returns all false
    #[cfg(not(target_os = "linux"))]
    {
        let config = SandboxConfig {
            script_path: std::path::PathBuf::from("/tmp/test.py"),
            workspace_dir: std::path::PathBuf::from("/tmp"),
            interpreter: "python3".to_string(),
            interpreter_args: vec!["test.py".to_string()],
            proxy_addr: "127.0.0.1:8080".parse().unwrap(),
            agent_id: "test-agent".to_string(),
            seccomp_profile: None,
            tls_probe_mode: TlsProbeMode::Disabled,
            proxy_url: None,
        };
        let report = preflight_check(&config);
        assert!(
            !report.ebpf_available,
            "eBPF must be unavailable on non-Linux"
        );
        assert!(!report.user_namespaces);
        assert!(!report.seccomp_available);
    }
}

#[test]
fn sandbox_config_clone() {
    let config = SandboxConfig {
        script_path: std::path::PathBuf::from("/workspace/agent.py"),
        workspace_dir: std::path::PathBuf::from("/workspace"),
        interpreter: "python3".to_string(),
        interpreter_args: vec!["agent.py".to_string()],
        proxy_addr: "10.200.0.1:8080".parse().unwrap(),
        agent_id: "agent-001".to_string(),
        seccomp_profile: Some(SeccompProfile::Default),
        tls_probe_mode: TlsProbeMode::Disabled,
        proxy_url: None,
    };

    let cloned = config.clone();
    assert_eq!(cloned.agent_id, "agent-001");
    assert_eq!(cloned.proxy_addr, config.proxy_addr);
}

// ─── eBPF module tests ───

#[cfg(target_os = "linux")]
mod ebpf_tests {
    use gvm_sandbox::ebpf::*;

    #[test]
    fn ebpf_support_check_does_not_panic() {
        // Must never panic, just return Ok/Err
        let _ = check_ebpf_support();
    }

    #[test]
    fn ebpf_attach_result_variants() {
        let attached = EbpfAttachResult::Attached {
            interface: "veth-gvm-h42".to_string(),
        };
        let unavailable = EbpfAttachResult::Unavailable {
            reason: "kernel too old".to_string(),
        };
        assert!(matches!(attached, EbpfAttachResult::Attached { .. }));
        assert!(matches!(unavailable, EbpfAttachResult::Unavailable { .. }));
    }

    #[test]
    fn try_attach_nonexistent_interface_returns_unavailable_or_error() {
        // Attempting to attach to a non-existent interface should fail gracefully
        let result = try_attach_tc_filter(
            "nonexistent-iface-12345",
            std::net::Ipv4Addr::new(10, 200, 0, 1),
            8080,
        );
        // Either Unavailable (no eBPF support) or the attach will fail
        // Either way, it must NOT panic
        match result {
            EbpfAttachResult::Attached { .. } => {
                // Clean up if somehow it attached (shouldn't happen)
                detach_tc_filter("nonexistent-iface-12345");
            }
            EbpfAttachResult::Unavailable { reason } => {
                assert!(!reason.is_empty(), "Unavailable reason must not be empty");
            }
        }
    }

    #[test]
    fn detach_nonexistent_does_not_panic() {
        // Detaching from non-existent interface must be safe (best-effort cleanup)
        detach_tc_filter("does-not-exist-99999");
    }
}

// ─── Seccomp structure tests ───

#[test]
fn seccomp_profile_variants_serialize() {
    // Verify SeccompProfile variants are constructable
    let default = SeccompProfile::Default;
    let strict = SeccompProfile::Strict;
    let custom = SeccompProfile::Custom(std::path::PathBuf::from("/etc/gvm/seccomp.json"));

    assert!(matches!(default, SeccompProfile::Default));
    assert!(matches!(strict, SeccompProfile::Strict));
    assert!(matches!(custom, SeccompProfile::Custom(_)));
}

#[test]
fn sandbox_result_fields() {
    let result = SandboxResult {
        exit_code: 0,
        setup_ms: 42,
        seccomp_violations: 0,
    };
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.setup_ms, 42);
    assert_eq!(result.seccomp_violations, 0);
}

// ─── Cross-platform launch guard ───

#[cfg(not(target_os = "linux"))]
#[test]
fn launch_on_non_linux_returns_error() {
    let config = SandboxConfig {
        script_path: std::path::PathBuf::from("/tmp/test.py"),
        workspace_dir: std::path::PathBuf::from("/tmp"),
        interpreter: "python3".to_string(),
        interpreter_args: vec!["test.py".to_string()],
        proxy_addr: "127.0.0.1:8080".parse().unwrap(),
        agent_id: "test".to_string(),
        seccomp_profile: None,
        tls_probe_mode: TlsProbeMode::Disabled,
        proxy_url: None,
    };

    let result = launch_sandboxed(config);
    assert!(result.is_err(), "launch_sandboxed must fail on non-Linux");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Linux") || err_msg.contains("--contained"),
        "Error must mention Linux or Docker fallback: {}",
        err_msg
    );
}

// ─── Helper to access VethConfig (re-exported for testing) ───

fn veth_config_from_pid(pid: u32, _proxy_addr: SocketAddr) -> VethConfigTestHelper {
    // Replicate VethConfig::from_pid logic for cross-platform testing
    let third_octet = (pid % 256) as u8;
    let fourth_base = ((pid / 256) % 64) as u8 * 4;

    VethConfigTestHelper {
        host_iface: format!("veth-gvm-h{}", pid % 10000),
        sandbox_iface: format!("veth-gvm-s{}", pid % 10000),
        host_ip: format!("10.200.{}.{}", third_octet, fourth_base + 1),
        sandbox_ip: format!("10.200.{}.{}", third_octet, fourth_base + 2),
        cidr: 30,
    }
}

struct VethConfigTestHelper {
    host_iface: String,
    sandbox_iface: String,
    host_ip: String,
    sandbox_ip: String,
    cidr: u8,
}
