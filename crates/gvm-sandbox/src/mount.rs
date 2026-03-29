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

/// Resolve shared library dependencies for Python lib-dynload extension modules.
///
/// Must be called in the PARENT process (before clone) because running ldd
/// from PID 1 of a new PID namespace triggers a kernel panic on 6.17.0-1009-aws.
/// The resolved paths are then passed to the child for bind-mounting.
pub fn resolve_dynload_libs(interpreter_path: &Path) -> Vec<PathBuf> {
    let name = interpreter_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !name.starts_with("python") {
        return Vec::new();
    }

    let mut libs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for search_dir in &["/usr/lib", "/usr/local/lib"] {
        let Ok(entries) = std::fs::read_dir(search_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            if !fname_str.starts_with("python3") || !entry.path().is_dir() {
                continue;
            }
            let dynload = entry.path().join("lib-dynload");
            if !dynload.is_dir() {
                continue;
            }
            let Ok(so_entries) = std::fs::read_dir(&dynload) else {
                continue;
            };
            for so_entry in so_entries.flatten() {
                let path = so_entry.path();
                if path.extension().is_none_or(|e| e != "so") {
                    continue;
                }
                if let Ok(output) = std::process::Command::new("ldd").arg(&path).output() {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for lib_path in parse_ldd_output(&stdout) {
                            if seen.insert(lib_path.clone()) {
                                libs.push(lib_path);
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::debug!(
        count = libs.len(),
        "Pre-resolved lib-dynload dependencies in parent process"
    );
    libs
}

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
    extra_lib_paths: &[PathBuf],
) -> Result<()> {
    // Make the entire mount tree private FIRST, before any new mounts.
    // pivot_root requires the new root to NOT be on a shared mount.
    // Doing this before all bind-mounts ensures they inherit private propagation.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("Failed to make root mount private")?;

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
    let overlayfs_mounted = if let Some(policy) = fs_policy {
        try_mount_overlayfs(workspace_dir, &new_root, policy)
    } else {
        false
    };

    if !overlayfs_mounted {
        // Legacy mode: /workspace read-only + /workspace/output writable
        // Use the staging path (/tmp/gvm-sandbox-staging-ws) which was pre-mounted
        // by the parent process before clone(). Kernel 6.17+ blocks bind-mount of
        // host paths inside user namespaces, but inherits parent mounts.
        let staging_ws = Path::new("/tmp/gvm-sandbox-staging-ws");
        let mount_src = if staging_ws.exists() {
            staging_ws
        } else {
            workspace_dir
        };
        let ws_target = new_root.join("workspace");
        mount(
            Some(mount_src),
            &ws_target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .with_context(|| {
            format!(
                "Failed to bind-mount workspace: src={} dst={} exists_src={} exists_dst={}",
                mount_src.display(),
                ws_target.display(),
                mount_src.exists(),
                ws_target.exists(),
            )
        })?;

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

    // Mount /proc (PID namespace aware, hidepid=2 for defense-in-depth).
    // hidepid=2: agent can only see its own /proc/<pid> entries.
    // Combined with CLONE_NEWPID, prevents inspection of host processes.
    mount(
        Some("proc"),
        &new_root.join("proc"),
        Some("proc"),
        MsFlags::empty(),
        Some("hidepid=2"),
    )
    .context("Failed to mount /proc")?;

    // Bind-mount /dev devices
    create_dev_nodes(&new_root)?;

    // Bind-mount interpreter and shared libraries
    bind_mount_interpreter(&new_root, interpreter_path, extra_lib_paths)?;

    // Create minimal /etc files (DNS points to veth host IP)
    create_minimal_etc(&new_root, dns_server)?;

    // Inject ephemeral CA into sandbox trust store (for transparent MITM)
    if let Some(ca_pem) = ca_cert_pem {
        inject_ca_cert(&new_root, ca_pem)?;
    }

    // pivot_root: swap root filesystem
    // MS_PRIVATE was already applied at the top of this function.
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
fn bind_mount_interpreter(
    new_root: &Path,
    interpreter_path: &Path,
    extra_lib_paths: &[PathBuf],
) -> Result<()> {
    // Track mounted libraries to prevent duplicate bind mounts.
    // Mounting the same file twice (mount-on-mount) triggers a kernel panic on 6.17.0-1009-aws.
    let mut mounted: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

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
            let libs: Vec<PathBuf> = parse_ldd_output(&stdout);
            for lib_path in libs {
                if mounted.insert(lib_path.clone()) {
                    bind_mount_library(new_root, &lib_path).ok();
                }
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

    // Bind-mount extra libraries pre-resolved by the parent process.
    // Skip any already mounted by interpreter's direct ldd (prevents mount-on-mount panic
    // on Linux 6.17.0-1009-aws — duplicate bind mounts trigger kernel panic).
    for lib_path in extra_lib_paths {
        if mounted.insert(lib_path.clone()) {
            bind_mount_library(new_root, lib_path).ok();
        }
    }

    // Mount interpreter runtime directories (Python stdlib, etc.).
    bind_mount_runtime_dirs(new_root, interpreter_path)?;

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

/// Bind-mount interpreter runtime directories that ldd does not cover.
///
/// ldd resolves C shared libraries (.so files), but interpreters need their
/// language-level standard library too:
/// - Python: /usr/lib/python3.X/ (*.py modules, encodings, etc.)
/// - Node.js: /usr/lib/node_modules/, /usr/share/nodejs/
/// - Ruby: /usr/lib/ruby/
///
/// This function probes the interpreter to discover its stdlib path and
/// bind-mounts the necessary directory trees read-only.
fn bind_mount_runtime_dirs(new_root: &Path, interpreter_path: &Path) -> Result<()> {
    let name = interpreter_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if name.starts_with("python") {
        // Scan for Python stdlib directories directly (no probe needed).
        // Probing with `python3 -c "import sysconfig"` is a chicken-and-egg
        // problem — sysconfig is part of stdlib which we're trying to mount.
        // Instead, scan the filesystem for /usr/lib/python3.X directories.
        let mut dirs_to_mount: Vec<PathBuf> = Vec::new();

        for search_dir in &["/usr/lib", "/usr/local/lib"] {
            if let Ok(entries) = std::fs::read_dir(search_dir) {
                for entry in entries.flatten() {
                    let fname = entry.file_name();
                    let fname_str = fname.to_string_lossy();
                    if fname_str.starts_with("python3") && entry.path().is_dir() {
                        dirs_to_mount.push(entry.path());
                    }
                }
            }
        }

        // Also mount dist-packages directory if it exists
        // (e.g., /usr/lib/python3/dist-packages on Debian/Ubuntu)
        let dist = PathBuf::from("/usr/lib/python3/dist-packages");
        if dist.exists() && !dirs_to_mount.contains(&dist) {
            dirs_to_mount.push(dist);
        }

        for dir in &dirs_to_mount {
            if let Err(e) = bind_mount_dir_readonly(new_root, dir) {
                tracing::warn!(dir = %dir.display(), error = %e, "Failed to mount Python runtime dir");
            }
        }

        // NOTE: lib-dynload shared library resolution is now done in the parent process
        // via resolve_dynload_libs() and passed as extra_lib_paths to avoid running
        // ldd from PID 1 of the new PID namespace (kernel panic on 6.17.0-1009-aws).
        tracing::debug!(
            count = dirs_to_mount.len(),
            "Python runtime directories mounted"
        );
    } else if name.starts_with("node") || name.starts_with("deno") || name.starts_with("bun") {
        // Node.js runtime dirs
        for dir in &["/usr/lib/node_modules", "/usr/share/nodejs"] {
            let src = Path::new(dir);
            if src.exists() {
                bind_mount_dir_readonly(new_root, src).ok();
            }
        }
    }

    // Always mount Node.js modules if they exist — many tools (openclaw, npx, etc.)
    // are Node.js wrappers that don't have "node" in their binary name but still
    // need /usr/lib/node_modules at runtime. The mount is read-only and harmless
    // for non-Node.js interpreters.
    if !name.starts_with("node") {
        for dir in &["/usr/lib/node_modules", "/usr/share/nodejs"] {
            let src = Path::new(dir);
            if src.exists() {
                bind_mount_dir_readonly(new_root, src).ok();
            }
        }
    }

    if name.starts_with("ruby") {
        for dir in &["/usr/lib/ruby", "/usr/share/rubygems-integration"] {
            let src = Path::new(dir);
            if src.exists() {
                bind_mount_dir_readonly(new_root, src).ok();
            }
        }
    }

    Ok(())
}

/// Bind-mount an entire directory tree read-only into the sandbox.
fn bind_mount_dir_readonly(new_root: &Path, src: &Path) -> Result<()> {
    let relative = src.strip_prefix("/").unwrap_or(src);
    let dst = new_root.join(relative);
    std::fs::create_dir_all(&dst)?;

    mount(
        Some(src),
        &dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .with_context(|| format!("Failed to bind-mount runtime dir {}", src.display()))?;

    // Remount read-only (bind needs two-step)
    mount(
        None::<&str>,
        &dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
        None::<&str>,
    )
    .ok();

    tracing::debug!(src = %src.display(), "Mounted interpreter runtime directory");
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
    // Use a dedicated directory for overlay layers — NOT under /tmp
    // (mounting tmpfs on /tmp would destroy other sandbox state)
    let overlay_base = new_root.join("gvm-overlay");
    let upper_dir = overlay_base.join("upper");
    let work_dir = overlay_base.join("work");
    let merged_dir = new_root.join("workspace");

    // Create the overlay base directory
    if std::fs::create_dir_all(&overlay_base).is_err() {
        tracing::debug!("Failed to create overlay base directory — falling back to legacy mode");
        return false;
    }

    // Mount tmpfs on the overlay base (contains both upper + work)
    let upper_size = format!("size={}m", policy.upper_size_mb);
    if mount(
        Some("tmpfs"),
        &overlay_base,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(upper_size.as_str()),
    )
    .is_err()
    {
        tracing::debug!("Failed to mount tmpfs for overlay — falling back");
        return false;
    }

    // Create upper + work dirs on the new tmpfs
    if std::fs::create_dir_all(&upper_dir).is_err() || std::fs::create_dir_all(&work_dir).is_err() {
        tracing::debug!("Failed to create overlay upper/work dirs — falling back");
        return false;
    }

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
            // Clean up: unmount the tmpfs we mounted on overlay_base
            // to avoid leaving stale mounts that could interfere with legacy mode
            nix::mount::umount(&overlay_base).ok();
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

    // Also write to the system CA bundle path that certifi/requests defaults to.
    // Python's `certifi.where()` returns `/etc/ssl/certs/ca-certificates.crt` on Ubuntu.
    // If this file doesn't exist, `requests` can't find any CAs even when
    // REQUESTS_CA_BUNDLE is set (internal urllib3 context creation reads it).
    let system_bundle = new_root.join("etc/ssl/certs/ca-certificates.crt");
    std::fs::write(&system_bundle, ca_pem).ok();

    // Also write to the certifi package's expected location
    let certifi_bundle = new_root.join("etc/ssl/certs/cert.pem");
    std::fs::write(&certifi_bundle, ca_pem).ok();

    tracing::debug!("Ephemeral CA injected into sandbox trust store");
    Ok(())
}
