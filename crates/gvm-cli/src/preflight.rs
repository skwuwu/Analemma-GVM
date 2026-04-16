//! `gvm preflight` — environment check and mode availability report.
//!
//! Runs all pre-flight checks (kernel features, tools, config files) and maps
//! the results to available execution modes. Designed to answer: "what can I do
//! on this machine?" before ever launching an agent.

use crate::ui::{BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW};
use std::path::Path;

/// Check result for a single item.
struct Check {
    ok: bool,
    label: &'static str,
    detail: String,
}

/// Available execution mode.
struct Mode {
    available: bool,
    label: &'static str,
    command: &'static str,
    reason: Option<String>,
}

/// Run all environment checks and print a human-readable report.
pub fn run_preflight(config_dir: &str) {
    let config_path = Path::new(config_dir);

    // ── Environment checks ──

    let mut checks: Vec<Check> = Vec::new();

    // 1. Proxy config
    let proxy_toml = config_path.join("proxy.toml");
    checks.push(Check {
        ok: proxy_toml.exists(),
        label: "Proxy config",
        detail: if proxy_toml.exists() {
            format!("{}", proxy_toml.display())
        } else {
            "config/proxy.toml not found".to_string()
        },
    });

    // 2. SRR rules
    let srr_path = config_path.join("srr_network.toml");
    let srr_count = count_srr_rules(&srr_path);
    checks.push(Check {
        ok: srr_count > 0,
        label: "SRR rules",
        detail: if srr_count > 0 {
            format!("{} rules loaded", srr_count)
        } else {
            "no rules (run gvm watch + gvm suggest)".to_string()
        },
    });

    // 3. Credentials (check gvm.toml first, then secrets.toml)
    let gvm_toml_creds = count_gvm_toml_credentials();
    let secrets_path = config_path.join("secrets.toml");
    let legacy_cred_count = count_credentials(&secrets_path);
    let cred_count = if gvm_toml_creds > 0 {
        gvm_toml_creds
    } else {
        legacy_cred_count
    };
    checks.push(Check {
        ok: cred_count > 0,
        label: "Credentials",
        detail: if gvm_toml_creds > 0 {
            format!("{} hosts configured (gvm.toml)", gvm_toml_creds)
        } else if cred_count > 0 {
            format!("{} hosts configured (secrets.toml)", cred_count)
        } else if std::path::Path::new("gvm.toml").exists() || secrets_path.exists() {
            "config exists but no credentials".to_string()
        } else {
            "no gvm.toml or secrets.toml (optional)".to_string()
        },
    });

    // 4-8. Sandbox capabilities (Linux-specific)
    let sandbox = gather_sandbox_checks();

    for sc in &sandbox.checks {
        checks.push(Check {
            ok: sc.ok,
            label: sc.label,
            detail: sc.detail.clone(),
        });
    }

    // ── Print environment checks ──

    eprintln!();
    eprintln!("  {BOLD}Environment Check{RESET}");
    eprintln!();

    for c in &checks {
        let icon = if c.ok {
            format!("{GREEN}\u{2713}{RESET}")
        } else if is_optional(c.label) {
            format!("{YELLOW}\u{26a0}{RESET}")
        } else {
            format!("{RED}\u{2717}{RESET}")
        };
        eprintln!("  {} {:<24} {DIM}{}{RESET}", icon, c.label, c.detail);
    }

    // Kernel warning (if applicable)
    if let Some(ref warning) = sandbox.kernel_warning {
        eprintln!(
            "  {YELLOW}\u{26a0}{RESET} {:<24} {DIM}{}{RESET}",
            "Kernel", warning
        );
    }

    // ── Available modes ──

    let modes = compute_modes(&checks, &sandbox);

    eprintln!();
    eprintln!("  {BOLD}Available Modes{RESET}");
    eprintln!();

    for m in &modes {
        if m.available {
            eprintln!(
                "  {GREEN}\u{2713}{RESET} {:<24} {CYAN}{}{RESET}",
                m.label, m.command
            );
        } else {
            let reason = m.reason.as_deref().unwrap_or("not available");
            eprintln!(
                "  {RED}\u{2717}{RESET} {:<24} {DIM}{}{RESET}",
                m.label, reason
            );
        }
    }

    eprintln!();
}

// ── Sandbox capability gathering ──

struct SandboxCapabilities {
    checks: Vec<Check>,
    is_linux: bool,
    user_namespaces: bool,
    seccomp: bool,
    net_admin: bool,
    ip_cmd: bool,
    iptables_cmd: bool,
    ip6tables_cmd: bool,
    tc_filter: bool,
    kernel_warning: Option<String>,
}

fn gather_sandbox_checks() -> SandboxCapabilities {
    #[cfg(target_os = "linux")]
    {
        // Use a dummy config for preflight — interpreter is checked separately per mode
        let dummy_config = gvm_sandbox::SandboxConfig {
            script_path: std::path::PathBuf::from("/dev/null"),
            workspace_dir: std::path::PathBuf::from("/tmp"),
            interpreter: "python3".to_string(),
            interpreter_args: vec![],
            proxy_addr: "127.0.0.1:8080".parse().unwrap(),
            agent_id: "preflight".to_string(),
            seccomp_profile: None,
            memory_limit: None,
            cpu_limit: None,
            fs_policy: None,
            mitm_ca_cert: None,
            sandbox_profile: gvm_sandbox::SandboxProfile::default(),
            extra_env: vec![],
        };

        let report = gvm_sandbox::preflight_check(&dummy_config);

        let mut checks = vec![
            Check {
                ok: report.user_namespaces,
                label: "User namespaces",
                detail: if report.user_namespaces {
                    "enabled".to_string()
                } else {
                    "disabled (sudo sysctl kernel.unprivileged_userns_clone=1)".to_string()
                },
            },
            Check {
                ok: report.seccomp_available,
                label: "seccomp-BPF",
                detail: if report.seccomp_available {
                    "supported".to_string()
                } else {
                    "not supported by this kernel".to_string()
                },
            },
            Check {
                ok: report.net_admin_capability,
                label: "CAP_NET_ADMIN",
                detail: if report.net_admin_capability {
                    "available".to_string()
                } else {
                    "missing — run with sudo, or grant once: sudo setcap \
                     'cap_net_admin,cap_sys_admin,cap_sys_ptrace+ep' \
                     $(which gvm)"
                        .to_string()
                },
            },
            Check {
                ok: report.ip_command_available,
                label: "ip command",
                detail: if report.ip_command_available {
                    which_path("ip")
                } else {
                    format!("not found — {}", install_hint("iproute2"))
                },
            },
            Check {
                ok: report.iptables_command_available,
                label: "iptables",
                detail: if report.iptables_command_available {
                    which_path("iptables")
                } else {
                    format!("not found — {}", install_hint("iptables"))
                },
            },
            Check {
                ok: report.ip6tables_command_available,
                label: "ip6tables",
                detail: if report.ip6tables_command_available {
                    which_path("ip6tables")
                } else {
                    format!(
                        "not found — IPv6 cannot be disabled in sandbox netns; {}",
                        install_hint("iptables")
                    )
                },
            },
        ];

        // TC ingress filter (optional, has iptables fallback)
        checks.push(Check {
            ok: report.tc_filter_available,
            label: "TC ingress filter",
            detail: if report.tc_filter_available {
                "available (kernel-level proxy enforcement)".to_string()
            } else {
                "unavailable (iptables fallback active)".to_string()
            },
        });

        // Kernel version warning
        let kernel_warning = read_kernel_warning();

        SandboxCapabilities {
            is_linux: true,
            user_namespaces: report.user_namespaces,
            seccomp: report.seccomp_available,
            net_admin: report.net_admin_capability,
            ip_cmd: report.ip_command_available,
            iptables_cmd: report.iptables_command_available,
            ip6tables_cmd: report.ip6tables_command_available,
            tc_filter: report.tc_filter_available,
            kernel_warning,
            checks,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let platform = std::env::consts::OS;
        let checks = vec![
            Check {
                ok: false,
                label: "User namespaces",
                detail: format!("not available ({})", platform),
            },
            Check {
                ok: false,
                label: "seccomp-BPF",
                detail: format!("not available ({})", platform),
            },
        ];

        SandboxCapabilities {
            checks,
            is_linux: false,
            user_namespaces: false,
            seccomp: false,
            net_admin: false,
            ip_cmd: false,
            iptables_cmd: false,
            ip6tables_cmd: false,
            tc_filter: false,
            kernel_warning: None,
        }
    }
}

/// Determine available modes from check results.
fn compute_modes(_checks: &[Check], sandbox: &SandboxCapabilities) -> Vec<Mode> {
    // Cooperative mode: works on any OS
    let cooperative = Mode {
        available: true, // proxy is optional — gvm run works without config
        label: "cooperative",
        command: "gvm run agent.py",
        reason: None,
    };

    // Watch mode: always available
    let watch = Mode {
        available: true,
        label: "watch",
        command: "gvm watch agent.py",
        reason: None,
    };

    // MCP: always available if proxy can start
    let mcp = Mode {
        available: true,
        label: "MCP",
        command: "gvm_fetch / gvm_check tools",
        reason: None,
    };

    // Sandbox: requires Linux + user_ns + seccomp + net_admin + ip + iptables
    let sandbox_ready = sandbox.is_linux
        && sandbox.user_namespaces
        && sandbox.seccomp
        && sandbox.net_admin
        && sandbox.ip_cmd
        && sandbox.iptables_cmd;

    let sandbox_reason = if !sandbox.is_linux {
        Some("Linux only".to_string())
    } else if !sandbox.net_admin {
        Some("run with sudo (or `setcap cap_net_admin,cap_sys_admin+ep gvm`)".to_string())
    } else if !sandbox.user_namespaces {
        Some("enable user namespaces".to_string())
    } else if !sandbox.seccomp {
        Some("kernel lacks seccomp-BPF".to_string())
    } else if !sandbox.ip_cmd {
        Some(install_hint("iproute2"))
    } else if !sandbox.iptables_cmd {
        Some(install_hint("iptables"))
    } else {
        None
    };
    // ip6tables is intentionally non-blocking — sandbox launches without it
    // but operators should be aware of the IPv6 bypass risk. Surfaced in the
    // checks list above as a yellow warning, not in mode availability.
    let _ = sandbox.ip6tables_cmd;

    let sandbox_mode = Mode {
        available: sandbox_ready,
        label: "sandbox",
        command: "sudo gvm run --sandbox agent.py",
        reason: sandbox_reason,
    };

    // Sandbox + MITM
    let sandbox_mitm = Mode {
        available: sandbox_ready,
        label: "sandbox + MITM",
        command: "sudo gvm run --sandbox agent.py (HTTPS L7 inspection)",
        reason: if !sandbox_ready {
            Some("requires sandbox".to_string())
        } else {
            None
        },
    };

    // Sandbox + TC filter
    let sandbox_tc = Mode {
        available: sandbox_ready && sandbox.tc_filter,
        label: "sandbox + TC filter",
        command: "kernel-level proxy enforcement (tc u32)",
        reason: if !sandbox_ready {
            Some("requires sandbox".to_string())
        } else if !sandbox.tc_filter {
            Some("kernel upgrade needed (iptables fallback active)".to_string())
        } else {
            None
        },
    };

    vec![
        cooperative,
        sandbox_mode,
        sandbox_mitm,
        sandbox_tc,
        watch,
        mcp,
    ]
}

/// Count [[rules]] entries in srr_network.toml without fully parsing.
fn count_srr_rules(path: &Path) -> usize {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    content.lines().filter(|l| l.trim() == "[[rules]]").count()
}

/// Count [credentials."host"] entries in gvm.toml.
fn count_gvm_toml_credentials() -> usize {
    for candidate in &["gvm.toml", "config/gvm.toml"] {
        let path = Path::new(candidate);
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                return content
                    .lines()
                    .filter(|l| l.trim().starts_with("[credentials."))
                    .count();
            }
        }
    }
    0
}

/// Count [credentials."host"] entries in secrets.toml.
fn count_credentials(path: &Path) -> usize {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    content
        .lines()
        .filter(|l| l.trim().starts_with("[credentials."))
        .count()
}

/// Labels that are optional (warning instead of error).
fn is_optional(label: &str) -> bool {
    matches!(
        label,
        "TC ingress filter" | "Credentials" | "Kernel" | "ip6tables"
    )
}

/// Distro-aware install hint for a missing system package.
///
/// Reads `/etc/os-release` and maps `ID`/`ID_LIKE` to the appropriate package
/// manager invocation. Falls back to a generic message on unknown distros so
/// users at least see *what* is missing even if they have to look up *how*.
#[cfg(target_os = "linux")]
fn install_hint(pkg: &str) -> String {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let mut id = String::new();
    let mut id_like = String::new();
    for line in os_release.lines() {
        if let Some(rest) = line.strip_prefix("ID=") {
            id = rest.trim_matches('"').to_string();
        } else if let Some(rest) = line.strip_prefix("ID_LIKE=") {
            id_like = rest.trim_matches('"').to_string();
        }
    }
    let family = format!("{} {}", id, id_like);

    if family.contains("debian") || family.contains("ubuntu") {
        format!("sudo apt install {}", pkg)
    } else if family.contains("rhel")
        || family.contains("fedora")
        || family.contains("centos")
        || family.contains("amzn")
        || family.contains("rocky")
        || family.contains("almalinux")
    {
        // RHEL family uses different package names for the iproute2 package.
        let rhel_pkg = if pkg == "iproute2" { "iproute" } else { pkg };
        format!("sudo dnf install {}", rhel_pkg)
    } else if family.contains("alpine") {
        format!("sudo apk add {}  (note: musl build required)", pkg)
    } else if family.contains("arch") {
        format!("sudo pacman -S {}", pkg)
    } else if family.contains("suse") {
        format!("sudo zypper install {}", pkg)
    } else {
        format!("install '{}' via your distro's package manager", pkg)
    }
}

#[cfg(not(target_os = "linux"))]
fn install_hint(pkg: &str) -> String {
    format!("install '{}' (Linux only)", pkg)
}

/// Resolve a command to its path for display.
#[cfg(target_os = "linux")]
fn which_path(cmd: &str) -> String {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "found".to_string())
}

/// Read kernel version and return a warning if applicable.
#[cfg(target_os = "linux")]
fn read_kernel_warning() -> Option<String> {
    let version = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()?
        .trim()
        .to_string();
    if version.starts_with("6.17.") {
        Some(format!(
            "{} — ldd-in-PID-namespace workaround active",
            version
        ))
    } else {
        None
    }
}
