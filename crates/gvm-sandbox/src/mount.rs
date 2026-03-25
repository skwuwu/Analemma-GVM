//! Mount namespace setup: minimal filesystem with pivot_root.
//!
//! Creates a temporary root filesystem containing only:
//! - /workspace (read-only bind of agent directory)
//! - /tmp (tmpfs, writable)
//! - /proc (pid-namespace-aware)
//! - /dev/null, /dev/zero, /dev/urandom (bind from host)
//! - Interpreter binary + shared libraries (resolved via ldd)

use anyhow::{Context, Result};
use nix::mount::{mount, MsFlags};
use std::path::{Path, PathBuf};

/// Set up the mount namespace for the sandboxed agent.
///
/// 1. Create tmpfs staging root
/// 2. Bind-mount workspace (read-only)
/// 3. Bind-mount interpreter + shared libraries
/// 4. Mount /proc, /dev devices
/// 5. pivot_root to the new root
pub fn setup_mount_namespace(
    workspace_dir: &Path,
    interpreter_path: &Path,
    dns_server: &str,
    ca_cert_pem: Option<&[u8]>,
    fs_policy: Option<&crate::FilesystemPolicy>,
) -> Result<()> {
    let new_root = PathBuf::from("/tmp/gvm-sandbox-root");

    // Create staging root as tmpfs
    std::fs::create_dir_all(&new_root).context("Failed to create sandbox root")?;
    mount(
        Some("tmpfs"),
        &new_root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=64m"),
    )
    .context("Failed to mount tmpfs for sandbox root")?;

    // Create directory structure
    let dirs = [
        "workspace",
        "tmp",
        "proc",
        "dev",
        "usr",
        "lib",
        "lib64",
        "etc",
        "bin",
    ];
    for dir in &dirs {
        std::fs::create_dir_all(new_root.join(dir))?;
    }

    // ── Workspace mount: overlayfs (if fs_policy set + kernel supports) or legacy ──
    let overlayfs_mounted = if fs_policy.is_some() {
        try_mount_overlayfs(workspace_dir, &new_root, fs_policy.unwrap())
    } else {
        false
    };

    if !overlayfs_mounted {
        // Legacy mode: /workspace read-only + /workspace/output writable
        mount(
            Some(workspace_dir),
            &new_root.join("workspace"),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .context("Failed to bind-mount workspace")?;

        // Remount as truly read-only (bind mount needs two-step)
        mount(
            None::<&str>,
            &new_root.join("workspace"),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
            None::<&str>,
        )
        .ok();

        // /workspace/output — writable, persists to host
        let host_output = workspace_dir.join("output");
        std::fs::create_dir_all(&host_output).ok();
        let sandbox_output = new_root.join("workspace/output");
        std::fs::create_dir_all(&sandbox_output).ok();
        mount(
            Some(&host_output),
            &sandbox_output,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .context("Failed to bind-mount /workspace/output (writable)")?;
        tracing::debug!("Workspace mounted in legacy mode (read-only + output/)");
    }

    // Mount tmpfs for /tmp (writable scratch space)
    mount(
        Some("tmpfs"),
        &new_root.join("tmp"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=32m"),
    )
    .context("Failed to mount tmpfs for /tmp")?;

    // Mount /proc (PID namespace aware)
    mount(
        Some("proc"),
        &new_root.join("proc"),
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("Failed to mount /proc")?;

    // Bind-mount /dev devices
    create_dev_nodes(&new_root)?;

    // Bind-mount interpreter and shared libraries
    bind_mount_interpreter(&new_root, interpreter_path)?;

    // Create minimal /etc files (DNS points to veth host IP)
    create_minimal_etc(&new_root, dns_server)?;

    // Inject ephemeral CA into sandbox trust store (for transparent MITM)
    if let Some(ca_pem) = ca_cert_pem {
        inject_ca_cert(&new_root, ca_pem)?;
    }

    // pivot_root: swap root filesystem
    let old_root = new_root.join("old_root");
    std::fs::create_dir_all(&old_root)?;

    nix::unistd::pivot_root(&new_root, &old_root).context("pivot_root failed")?;

    // Set CWD to /workspace/output — agent writes here by default.
    // Source files are at /workspace (read-only, accessible via ../src etc).
    nix::unistd::chdir("/workspace/output")
        .or_else(|_| nix::unistd::chdir("/"))
        .context("chdir failed")?;

    // Unmount old root (lazy to handle busy mounts)
    nix::mount::umount2("/old_root", nix::mount::MntFlags::MNT_DETACH)
        .context("Failed to unmount old root")?;
    std::fs::remove_dir("/old_root").ok();

    tracing::debug!("Mount namespace configured: pivot_root complete");
    Ok(())
}

/// Create minimal /dev nodes by bind-mounting from host.
fn create_dev_nodes(new_root: &Path) -> Result<()> {
    let devices = ["null", "zero", "urandom", "random"];
    for dev in &devices {
        let target = new_root.join("dev").join(dev);
        // Create empty file as mount point
        std::fs::write(&target, "").with_context(|| format!("Failed to create /dev/{}", dev))?;
        mount(
            Some(&PathBuf::from(format!("/dev/{}", dev))),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("Failed to bind-mount /dev/{}", dev))?;
    }
    Ok(())
}

/// Resolve shared library dependencies and bind-mount them.
fn bind_mount_interpreter(new_root: &Path, interpreter_path: &Path) -> Result<()> {
    // Bind-mount the interpreter binary
    let interpreter_name = interpreter_path
        .file_name()
        .context("Invalid interpreter path")?;
    let target_bin = new_root.join("bin").join(interpreter_name);
    std::fs::write(&target_bin, "").context("Failed to create interpreter mount point")?;
    mount(
        Some(interpreter_path),
        &target_bin,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .context("Failed to bind-mount interpreter")?;

    // Resolve shared libraries via ldd
    let ldd_output = std::process::Command::new("ldd")
        .arg(interpreter_path)
        .output();

    match ldd_output {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for lib_path in parse_ldd_output(&stdout) {
                bind_mount_library(new_root, &lib_path).ok();
            }
        }
        _ => {
            // Fallback: bind-mount common library directories (less isolated but functional)
            tracing::warn!("ldd failed — falling back to bind-mounting /usr and /lib");
            for dir in &["/usr", "/lib", "/lib64"] {
                let src = Path::new(dir);
                if src.exists() {
                    let dst = new_root.join(dir.trim_start_matches('/'));
                    mount(
                        Some(src),
                        &dst,
                        None::<&str>,
                        MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                        None::<&str>,
                    )
                    .ok();
                }
            }
        }
    }

    Ok(())
}

/// Parse ldd output to extract library paths.
fn parse_ldd_output(output: &str) -> Vec<PathBuf> {
    let mut libs = Vec::new();
    for line in output.lines() {
        // Format: "libfoo.so.1 => /usr/lib/libfoo.so.1 (0x...)"
        // or:     "/lib64/ld-linux-x86-64.so.2 (0x...)"
        if let Some(arrow_pos) = line.find("=>") {
            let after_arrow = &line[arrow_pos + 2..];
            if let Some(path_str) = after_arrow.split_whitespace().next() {
                if path_str.starts_with('/') {
                    libs.push(PathBuf::from(path_str));
                }
            }
        } else {
            // Direct path without =>
            let trimmed = line.trim();
            if let Some(path_str) = trimmed.split_whitespace().next() {
                if path_str.starts_with('/') {
                    libs.push(PathBuf::from(path_str));
                }
            }
        }
    }
    libs
}

/// Bind-mount a single shared library into the sandbox.
fn bind_mount_library(new_root: &Path, lib_path: &Path) -> Result<()> {
    if !lib_path.exists() {
        return Ok(());
    }

    let relative = lib_path.strip_prefix("/").unwrap_or(lib_path);
    let target = new_root.join(relative);

    // Create parent directories
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Create mount point
    std::fs::write(&target, "")?;

    mount(
        Some(lib_path),
        &target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        None::<&str>,
    )?;

    Ok(())
}

/// Create minimal /etc files needed by most interpreters.
///
/// `dns_server` must match the iptables OUTPUT rules in the sandbox namespace.
/// The sandbox only allows UDP 53 to this address, so resolv.conf and firewall
/// must be consistent. Using any other DNS server will cause DNS resolution to
/// fail silently.
fn create_minimal_etc(new_root: &Path, dns_server: &str) -> Result<()> {
    // /etc/passwd — needed by Python for getpwuid
    std::fs::write(
        new_root.join("etc/passwd"),
        "agent:x:0:0:agent:/workspace:/bin/sh\n",
    )?;

    // /etc/group
    std::fs::write(new_root.join("etc/group"), "agent:x:0:\n")?;

    // /etc/hosts — only localhost (no IPv6 since it's disabled in sandbox)
    std::fs::write(new_root.join("etc/hosts"), "127.0.0.1 localhost\n")?;

    // /etc/resolv.conf — DNS via host veth IP (matches OUTPUT iptables rule)
    std::fs::write(
        new_root.join("etc/resolv.conf"),
        format!("nameserver {}\n", dns_server),
    )?;

    Ok(())
}

/// Attempt to mount workspace with overlayfs for Trust-on-Pattern governance.
///
/// overlayfs allows the agent to write anywhere in /workspace while preserving
/// the original files. All changes go to the upper layer (tmpfs), which is
/// scanned at session end for the diff report.
///
/// Requires kernel 5.11+ (overlayfs in user namespace). Falls back to legacy
/// mode on older kernels (returns false).
fn try_mount_overlayfs(
    workspace_dir: &Path,
    new_root: &Path,
    policy: &crate::FilesystemPolicy,
) -> bool {
    let upper_dir = new_root.join("tmp/gvm-overlay-upper");
    let work_dir = new_root.join("tmp/gvm-overlay-work");
    let merged_dir = new_root.join("workspace");

    // Create overlay directories
    if std::fs::create_dir_all(&upper_dir).is_err()
        || std::fs::create_dir_all(&work_dir).is_err()
    {
        tracing::debug!("Failed to create overlay directories — falling back to legacy mode");
        return false;
    }

    // Mount tmpfs for upper layer with size limit
    let upper_size = format!("size={}m", policy.upper_size_mb);
    if mount(
        Some("tmpfs"),
        upper_dir.parent().unwrap_or(&upper_dir),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(upper_size.as_str()),
    )
    .is_err()
    {
        tracing::debug!("Failed to mount tmpfs for overlay upper — falling back");
        return false;
    }

    // Re-create dirs on the new tmpfs
    std::fs::create_dir_all(&upper_dir).ok();
    std::fs::create_dir_all(&work_dir).ok();

    // Construct overlayfs mount options
    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        workspace_dir.display(),
        upper_dir.display(),
        work_dir.display(),
    );

    // Attempt overlayfs mount — this is where kernel 5.11+ check happens implicitly.
    // On older kernels, this returns EPERM in user namespace.
    match mount(
        Some("overlay"),
        &merged_dir,
        Some("overlay"),
        MsFlags::empty(),
        Some(mount_opts.as_str()),
    ) {
        Ok(()) => {
            tracing::info!(
                upper_size_mb = policy.upper_size_mb,
                "Workspace mounted with overlayfs (Trust-on-Pattern governance active)"
            );

            // Also mount /workspace/output for backward compat — writable bind on top of overlay
            let host_output = workspace_dir.join("output");
            std::fs::create_dir_all(&host_output).ok();
            let sandbox_output = merged_dir.join("output");
            std::fs::create_dir_all(&sandbox_output).ok();
            mount(
                Some(&host_output),
                &sandbox_output,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .ok(); // Best-effort — output/ still works via overlay too

            true
        }
        Err(e) => {
            tracing::info!(
                error = %e,
                "overlayfs mount failed (kernel < 5.11?) — falling back to legacy mode"
            );
            false
        }
    }
}

/// Inject ephemeral CA certificate into the sandbox's trust store.
///
/// Writes the CA PEM to multiple cert paths (Debian, RHEL, Alpine) so it
/// works regardless of the base image. Also sets environment variables
/// that Python/Node/curl use to find the CA.
///
/// The CA is written to tmpfs (sandbox root is tmpfs) — never touches host disk.
fn inject_ca_cert(new_root: &Path, ca_pem: &[u8]) -> Result<()> {
    // Write to multiple cert store paths (distribution-agnostic)
    let cert_dirs = [
        "etc/ssl/certs",       // Debian/Ubuntu
        "etc/pki/tls/certs",   // RHEL/CentOS
        "etc/ca-certificates", // Alpine
    ];

    let mut injected = false;
    for dir in &cert_dirs {
        let dir_path = new_root.join(dir);
        if std::fs::create_dir_all(&dir_path).is_ok() {
            let cert_path = dir_path.join("gvm-ca.crt");
            std::fs::write(&cert_path, ca_pem)
                .with_context(|| format!("Failed to write CA to {}", cert_path.display()))?;
            injected = true;
        }
    }

    if !injected {
        anyhow::bail!("Failed to inject CA into any trust store path");
    }

    tracing::debug!("Ephemeral CA injected into sandbox trust store");
    Ok(())
}
