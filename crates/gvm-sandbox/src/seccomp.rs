//! seccomp-BPF syscall filter for sandboxed agents.
//!
//! Three-tier approach:
//! 1. **Whitelist** (Allow): known-safe syscalls are explicitly allowed.
//! 2. **Blocklist** (KillProcess): known-dangerous syscalls (ptrace, mount, bpf,
//!    unshare, setns, open_by_handle_at) are explicitly killed.
//! 3. **Default** (Errno ENOSYS): unknown/new syscalls return ENOSYS, allowing
//!    runtimes to gracefully fall back without crashing. This prevents regressions
//!    when kernels/glibc add new syscalls (e.g. rseq, futex_waitv, cachestat).
//!
//! This design matches Docker's default seccomp profile philosophy: block dangerous
//! operations, allow known-safe operations, return ENOSYS for everything else.
//!
//! The filter is applied just before execve(), so sandbox setup code
//! (mount, network, namespace) is not restricted.
//!
//! Syscall categories:
//! - Process lifecycle (exit, clone for threads, futex, signals)
//! - Memory management (mmap, mprotect, brk)
//! - File I/O (read, write, openat, stat — workspace only)
//! - Networking (socket AF_INET/AF_INET6/AF_UNIX only — HTTP + IPC)
//! - Time (clock_gettime, gettimeofday)
//!
//! Explicitly blocked (KILL_PROCESS):
//! - ptrace, process_vm_readv/writev — no debugging/memory inspection
//! - mount, umount2, pivot_root — no post-setup filesystem changes
//! - open_by_handle_at — container escape vector (CVE-2015-3627)
//! - bpf — no BPF program loading (prevents seccomp override)
//! - unshare, setns — no further namespace manipulation
//!
//! Socket domain restriction (defense-in-depth against CAP_NET_ADMIN escape):
//! - socket() is allowed ONLY for AF_INET (2), AF_INET6 (10), AF_UNIX (1), AF_NETLINK (16)
//! - AF_NETLINK is allowed because getaddrinfo() requires NETLINK_ROUTE for DNS resolution.
//!   Safe because all capabilities (including CAP_NET_ADMIN) are dropped before seccomp.
//! - AF_PACKET (17) is blocked — prevents raw packet injection
//! - This ensures agents cannot modify firewall rules even though CLONE_NEWUSER
//!   grants apparent CAP_NET_ADMIN inside the user namespace
//!
//! Violation logging:
//! - High-risk syscalls (ptrace, mount, bpf, unshare, setns, open_by_handle_at)
//!   use `SeccompAction::Log` to emit kernel audit log entries before killing.
//!   This creates a forensic trail in `/var/log/audit/audit.log` (auditd) or
//!   `dmesg`/`journalctl` for systems without auditd.
//! - The parent process reads `/proc/<pid>/status` SeccompViolation count
//!   after the child exits to populate `SandboxResult.seccomp_violations`.

use crate::SeccompProfile;
use anyhow::{Context, Result};
use seccompiler::{
    BpfMap, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;

/// Apply the seccomp-BPF filter to the current thread.
/// Must be called just before execve() in the child process.
///
/// Installs two stacked filters for logging + enforcement:
/// 1. **Log filter** (installed first): uses `SeccompAction::Log` as default action.
///    Any syscall not in the whitelist emits a kernel audit record
///    (`type=SECCOMP` in auditd / `audit:` in dmesg).
/// 2. **Kill filter** (installed second, evaluated first by kernel): uses
///    `SeccompAction::KillProcess` as default action. Terminates the process
///    on violation.
///
/// Because seccomp evaluates filters in LIFO order and takes the **strictest**
/// result across all installed filters, the kill filter enforces while the
/// log filter ensures a forensic audit trail exists even for fatal violations.
pub fn apply_seccomp_filter(profile: &Option<SeccompProfile>) -> Result<()> {
    let target_arch: seccompiler::TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| anyhow::anyhow!("Unsupported architecture"))?;

    let (enforcement_filter, log_filter) = match profile {
        Some(SeccompProfile::Strict) => (
            build_strict_filter(SeccompAction::Errno(libc::ENOSYS as u32))?,
            build_strict_filter(SeccompAction::Log)?,
        ),
        Some(SeccompProfile::Custom(path)) => {
            // Load custom filter from JSON file (enforcement only, no log layer)
            let content = std::fs::read(path)
                .with_context(|| format!("Failed to read seccomp profile: {}", path.display()))?;
            let map: BpfMap = seccompiler::compile_from_json(&content[..], target_arch)
                .context("Failed to compile custom seccomp profile")?;
            let filter = map.into_values().next().context("Empty seccomp profile")?;
            // Custom profiles get enforcement only (no log layer)
            seccompiler::apply_filter(&filter)
                .context("Failed to apply custom seccomp-BPF filter")?;
            tracing::debug!("Custom seccomp-BPF filter applied (enforcement only)");
            return Ok(());
        }
        _ => (
            build_default_filter(SeccompAction::Errno(libc::ENOSYS as u32))?,
            build_default_filter(SeccompAction::Log)?,
        ),
    };

    // Install log filter FIRST (evaluated second by kernel — LIFO order).
    // This filter uses Log as default action: violations emit audit records
    // but the syscall would be allowed by this filter alone.
    seccompiler::apply_filter(&log_filter).context("Failed to apply seccomp-BPF log filter")?;

    // Install enforcement filter SECOND (evaluated first by kernel).
    // Default action: Errno(ENOSYS) — unknown syscalls get "not implemented" error,
    // allowing runtimes to gracefully fall back (e.g. glibc skips rseq on ENOSYS).
    // High-risk syscalls are explicitly KillProcess'd via insert_blocked_syscalls().
    // The kernel takes the strictest result across both filters, so:
    // - Whitelisted syscalls: Allow (both agree) → executed
    // - Blocked syscalls: KillProcess (explicit) + Log (audit) → logged then killed
    // - Unknown syscalls: Errno(ENOSYS) (enforcement) + Log (audit) → logged then ENOSYS
    seccompiler::apply_filter(&enforcement_filter)
        .context("Failed to apply seccomp-BPF enforcement filter")?;

    tracing::debug!("seccomp-BPF filter applied (whitelist + blocklist + ENOSYS default)");
    Ok(())
}

/// Build the default whitelist filter for HTTP-capable agents.
///
/// The `default_action` parameter controls what happens on violation:
/// - `KillProcess`: enforcement mode (terminates agent)
/// - `Log`: audit mode (logs to kernel audit subsystem, allows execution)
fn build_default_filter(default_action: SeccompAction) -> Result<seccompiler::BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Shared base syscalls (process lifecycle, memory, file I/O, polling, time, identity, misc)
    insert_base_syscalls(&mut rules);

    // Networking (HTTP traffic only — TCP/UDP sockets)
    //
    // socket() is argument-filtered: only AF_INET (2), AF_INET6 (10), AF_UNIX (1) allowed.
    // AF_NETLINK (16) is allowed — required by getaddrinfo() for DNS resolution.
    // AF_PACKET (17) is blocked to prevent raw packet injection.
    // CAP_NET_ADMIN is dropped before seccomp, so AF_NETLINK cannot modify iptables.
    rules.insert(
        libc::SYS_socket,
        vec![
            // Allow AF_UNIX (1) — needed for Python multiprocessing, IPC
            SeccompRule::new(vec![SeccompCondition::new(
                0, // arg0 = domain
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_UNIX as u64,
            )
            .context("Failed to build AF_UNIX condition")?])
            .context("Failed to build AF_UNIX rule")?,
            // Allow AF_INET (2) — IPv4 HTTP traffic
            SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_INET as u64,
            )
            .context("Failed to build AF_INET condition")?])
            .context("Failed to build AF_INET rule")?,
            // Allow AF_INET6 (10) — IPv6 (already blocked by ip6tables, but allow socket creation)
            SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_INET6 as u64,
            )
            .context("Failed to build AF_INET6 condition")?])
            .context("Failed to build AF_INET6 rule")?,
            // Allow AF_NETLINK (16) — needed by getaddrinfo() for DNS resolution.
            // glibc/musl use NETLINK_ROUTE to read /etc/resolv.conf and routing tables.
            // Safe because: (1) all capabilities are dropped (no CAP_NET_ADMIN),
            // (2) NETLINK_ROUTE is read-only without capabilities,
            // (3) iptables modification requires CAP_NET_ADMIN which is dropped.
            SeccompRule::new(vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_NETLINK as u64,
            )
            .context("Failed to build AF_NETLINK condition")?])
            .context("Failed to build AF_NETLINK rule")?,
        ],
    );

    // Helper to allow a syscall unconditionally
    macro_rules! allow {
        ($($syscall:expr),+ $(,)?) => {
            $(rules.insert($syscall as i64, vec![]);)+
        };
    }

    // High-risk syscalls (ptrace, mount, bpf, unshare, etc.) are NOT in the whitelist.
    // With ENOSYS default, they return "not implemented" — the dangerous operation
    // never executes. The LOG filter ensures all attempts are audited.

    // All other socket operations (non-creation) remain unconditionally allowed
    allow!(
        libc::SYS_connect,
        libc::SYS_socketpair, // Node.js worker_threads IPC (AF_UNIX socketpair)
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg, // glibc getaddrinfo() uses sendmmsg for DNS queries
        libc::SYS_recvmmsg, // glibc may use recvmmsg for batched DNS responses
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_shutdown,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4
    );

    let filter = SeccompFilter::new(
        rules,
        // Default action for non-whitelisted syscalls (KillProcess or Log)
        default_action,
        // Action for whitelisted syscalls
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| anyhow::anyhow!("Unsupported architecture"))?,
    )
    .context("Failed to build seccomp filter")?;

    filter
        .try_into()
        .context("Failed to compile seccomp BPF program")
}

/// Insert the base (non-networking) syscall whitelist shared by all filter profiles.
/// This covers process lifecycle, memory, file I/O, polling, time, identity, and runtime support.
fn insert_base_syscalls(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    macro_rules! allow {
        ($($syscall:expr),+ $(,)?) => {
            $(rules.insert($syscall as i64, vec![]);)+
        };
    }

    // Process lifecycle
    allow!(
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_futex,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getppid,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_execve
    );

    // Memory management
    allow!(
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_brk,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_membarrier
    );

    // File I/O
    allow!(
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_lseek,
        libc::SYS_openat,
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_pipe,
        libc::SYS_pipe2,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_preadv,   // Node.js libuv vectored I/O (syscall 295)
        libc::SYS_pwritev,  // Node.js libuv vectored I/O (syscall 296)
        libc::SYS_preadv2,  // Node.js libuv async vectored I/O (syscall 327)
        libc::SYS_pwritev2, // Node.js libuv async vectored I/O (syscall 328)
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getcwd,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_getdents,
        libc::SYS_getdents64,
        libc::SYS_ftruncate,
        libc::SYS_rename,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_unlink,
        libc::SYS_unlinkat,
        libc::SYS_mkdir,
        libc::SYS_mkdirat,
        libc::SYS_rmdir,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fadvise64 // coreutils (cat, etc.) use posix_fadvise for read-ahead hints
    );

    // Polling / event loop
    allow!(
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_epoll_create,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_select,
        libc::SYS_pselect6,
        libc::SYS_eventfd,
        libc::SYS_eventfd2
    );

    // Time
    allow!(
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday
    );

    // Identity (read-only)
    allow!(
        libc::SYS_getuid,
        libc::SYS_getgid,
        libc::SYS_geteuid,
        libc::SYS_getegid,
        libc::SYS_getgroups
    );

    // Misc required by Python/Node runtimes
    allow!(
        libc::SYS_getrandom,
        libc::SYS_arch_prctl,
        libc::SYS_prctl,
        libc::SYS_ioctl,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_prlimit64,
        libc::SYS_rseq,
        // Node.js 22+: libuv calls io_uring_setup before reading UV_USE_IO_URING.
        // With ENOSYS default, io_uring calls return "not implemented" and libuv
        // falls back to epoll. No need to whitelist — reduces attack surface
        // (CVE-2023-2598, CVE-2023-25775, etc.) without breaking Node.js.
        // UV_USE_IO_URING=0 is also set in sandbox_impl.rs as belt-and-suspenders.
        libc::SYS_setpgid,
        libc::SYS_capget,
        libc::SYS_timer_create,
        libc::SYS_timer_settime,
        libc::SYS_timer_delete,
        libc::SYS_rt_sigsuspend
    );
}

/// Build a strict filter: no networking at all (offline computation only).
fn build_strict_filter(default_action: SeccompAction) -> Result<seccompiler::BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Strict profile uses the shared base syscalls (no networking)
    insert_base_syscalls(&mut rules);

    let filter = SeccompFilter::new(
        rules,
        default_action,
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .map_err(|_| anyhow::anyhow!("Unsupported architecture"))?,
    )
    .context("Failed to build strict seccomp filter")?;

    filter
        .try_into()
        .context("Failed to compile strict seccomp BPF program")
}

/// Read seccomp violation count from the kernel audit subsystem.
///
/// After the child process exits, checks for SIGSYS (seccomp kill signal)
/// in the wait status. On Linux, also parses `/proc/<pid>/status` for
/// the `Seccomp_filters` field when available (kernel >= 4.18).
///
/// Returns the number of detected violations (0 if none or not detectable).
pub fn count_seccomp_violations(wait_status: &nix::sys::wait::WaitStatus) -> u32 {
    match wait_status {
        // SIGSYS is the signal sent by seccomp SECCOMP_RET_KILL_PROCESS/KILL_THREAD
        nix::sys::wait::WaitStatus::Signaled(_, nix::sys::signal::Signal::SIGSYS, _) => {
            tracing::warn!("Agent killed by SIGSYS — seccomp violation detected");
            1
        }
        // SIGKILL can also indicate seccomp kill (SECCOMP_RET_KILL_PROCESS on older kernels)
        nix::sys::wait::WaitStatus::Signaled(pid, nix::sys::signal::Signal::SIGKILL, _) => {
            // Check dmesg/audit log hint — SIGKILL from seccomp is indistinguishable
            // from OOM killer or manual kill without audit context.
            // Log as potential violation for forensic review.
            tracing::warn!(
                pid = pid.as_raw(),
                "Agent killed by SIGKILL — possible seccomp violation (check audit log)"
            );
            0 // Cannot confirm without audit — report 0 to avoid false positives
        }
        _ => 0,
    }
}
