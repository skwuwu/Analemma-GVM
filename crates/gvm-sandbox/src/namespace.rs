//! Linux namespace creation and UID/GID mapping.
//!
//! Uses CLONE_NEWUSER to avoid requiring root. The current user's UID is mapped
//! to UID 0 inside the namespace, giving apparent root inside the sandbox
//! without any actual host privileges.

use anyhow::{Context, Result};
use nix::sched::CloneFlags;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::os::unix::io::RawFd;

/// Flags for creating a fully isolated sandbox.
///
/// When running as root (sudo), CLONE_NEWUSER is omitted because:
/// 1. Kernel 6.17+ restricts bind-mount inside user namespaces (EACCES)
/// 2. Running as root already has all capabilities — user namespace is redundant
/// 3. Without CLONE_NEWUSER, mount/network setup works normally
///
/// When running as non-root, CLONE_NEWUSER is required for unprivileged namespace creation.
pub fn sandbox_clone_flags() -> CloneFlags {
    let base = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET;
    if nix::unistd::geteuid().is_root() {
        base // Root: no need for CLONE_NEWUSER, avoids kernel 6.17+ mount restrictions
    } else {
        base | CloneFlags::CLONE_NEWUSER // Non-root: needs user namespace for unprivileged isolation
    }
}

/// Write UID mapping for the child process.
/// Maps the host user's UID to UID 0 inside the namespace.
pub fn write_uid_map(child_pid: nix::unistd::Pid) -> Result<()> {
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    // Must deny setgroups before writing gid_map (kernel requirement)
    let setgroups_path = format!("/proc/{}/setgroups", child_pid);
    std::fs::write(&setgroups_path, "deny")
        .with_context(|| format!("Failed to write {}", setgroups_path))?;

    // Map host UID → 0 inside namespace
    let uid_map_path = format!("/proc/{}/uid_map", child_pid);
    std::fs::write(&uid_map_path, format!("0 {} 1\n", uid))
        .with_context(|| format!("Failed to write {}", uid_map_path))?;

    // Map host GID → 0 inside namespace
    let gid_map_path = format!("/proc/{}/gid_map", child_pid);
    std::fs::write(&gid_map_path, format!("0 {} 1\n", gid))
        .with_context(|| format!("Failed to write {}", gid_map_path))?;

    tracing::debug!(
        child_pid = child_pid.as_raw(),
        host_uid = uid.as_raw(),
        host_gid = gid.as_raw(),
        "UID/GID mapping written"
    );

    Ok(())
}

/// Create a Unix socketpair for parent-child coordination.
/// Parent sends a byte after completing setup; child blocks until received.
pub fn coordination_pipe() -> Result<(OwnedFd, RawFd)> {
    let (parent_fd, child_fd) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
    )
    .context("Failed to create coordination socketpair")?;

    Ok((parent_fd, child_fd.into_raw_fd()))
}

/// Parent signals the child that setup is complete and sends a network seed.
pub fn signal_child_ready(parent_fd: OwnedFd, network_seed: u32) -> Result<()> {
    let payload = network_seed.to_le_bytes();
    let mut written = 0;
    while written < payload.len() {
        let n = nix::unistd::write(&parent_fd, &payload[written..])
            .context("Failed to signal child")?;
        if n == 0 {
            anyhow::bail!("coordination socket closed while signaling child");
        }
        written += n;
    }
    Ok(())
}

/// Child waits for the parent to complete setup.
pub fn wait_for_parent(child_fd: RawFd) -> Result<u32> {
    let mut buf = [0u8; 4];
    let mut read_total = 0;

    while read_total < buf.len() {
        let n = nix::unistd::read(child_fd, &mut buf[read_total..])
            .context("Failed to read parent signal")?;
        if n == 0 {
            anyhow::bail!("coordination socket closed before setup signal");
        }
        read_total += n;
    }

    nix::unistd::close(child_fd).ok();
    Ok(u32::from_le_bytes(buf))
}
