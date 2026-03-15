//! Linux namespace creation and UID/GID mapping.
//!
//! Uses CLONE_NEWUSER to avoid requiring root. The current user's UID is mapped
//! to UID 0 inside the namespace, giving apparent root inside the sandbox
//! without any actual host privileges.

use anyhow::{Context, Result};
use nix::sched::CloneFlags;
use std::os::unix::io::RawFd;

/// Flags for creating a fully isolated sandbox.
pub fn sandbox_clone_flags() -> CloneFlags {
    CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET
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
pub fn coordination_pipe() -> Result<(RawFd, RawFd)> {
    let (parent_fd, child_fd) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
    )
    .context("Failed to create coordination socketpair")?;

    Ok((parent_fd.into(), child_fd.into()))
}

/// Parent signals the child that setup is complete.
pub fn signal_child_ready(parent_fd: RawFd) -> Result<()> {
    nix::unistd::write(parent_fd, &[1u8])
        .context("Failed to signal child")?;
    nix::unistd::close(parent_fd).ok();
    Ok(())
}

/// Child waits for the parent to complete setup.
pub fn wait_for_parent(child_fd: RawFd) -> Result<()> {
    let mut buf = [0u8; 1];
    nix::unistd::read(child_fd, &mut buf)
        .context("Failed to read parent signal")?;
    nix::unistd::close(child_fd).ok();
    Ok(())
}
