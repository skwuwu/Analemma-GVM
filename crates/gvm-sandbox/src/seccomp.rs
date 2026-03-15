//! seccomp-BPF syscall filter for sandboxed agents.
//!
//! Whitelist approach (default-deny): only syscalls explicitly listed are allowed.
//! New syscalls added in future kernels are automatically blocked.
//!
//! The filter is applied just before execve(), so sandbox setup code
//! (mount, network, namespace) is not restricted.
//!
//! Syscall categories:
//! - Process lifecycle (exit, clone for threads, futex, signals)
//! - Memory management (mmap, mprotect, brk)
//! - File I/O (read, write, openat, stat — workspace only)
//! - Networking (socket AF_INET/AF_INET6 + SOCK_STREAM only — HTTP)
//! - Time (clock_gettime, gettimeofday)
//!
//! Explicitly blocked (KILL_PROCESS):
//! - ptrace, process_vm_readv/writev — no debugging/memory inspection
//! - mount, umount2, pivot_root — no post-setup filesystem changes
//! - open_by_handle_at — container escape vector (CVE-2015-3627)
//! - bpf — no BPF program loading (prevents seccomp override)
//! - unshare, setns — no further namespace manipulation

use crate::SeccompProfile;
use anyhow::{Context, Result};
use seccompiler::{BpfMap, SeccompAction, SeccompFilter, SeccompRule};
use std::collections::BTreeMap;

/// Apply the seccomp-BPF filter to the current thread.
/// Must be called just before execve() in the child process.
pub fn apply_seccomp_filter(profile: &Option<SeccompProfile>) -> Result<()> {
    let filter = match profile {
        Some(SeccompProfile::Strict) => build_strict_filter()?,
        Some(SeccompProfile::Custom(path)) => {
            // Load custom filter from JSON file
            let content = std::fs::read(path)
                .with_context(|| format!("Failed to read seccomp profile: {}", path.display()))?;
            let map: BpfMap = seccompiler::compile_from_json(
                &content[..],
                std::env::consts::ARCH.into(),
            )
            .context("Failed to compile custom seccomp profile")?;
            map.into_values()
                .next()
                .context("Empty seccomp profile")?
        }
        _ => build_default_filter()?,
    };

    seccompiler::apply_filter(&filter)
        .context("Failed to apply seccomp-BPF filter")?;

    tracing::debug!("seccomp-BPF filter applied");
    Ok(())
}

/// Build the default whitelist filter for HTTP-capable agents.
fn build_default_filter() -> Result<seccompiler::BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Helper to allow a syscall unconditionally
    macro_rules! allow {
        ($($syscall:expr),+ $(,)?) => {
            $(rules.insert($syscall as i64, vec![SeccompRule::new(vec![])]);)+
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
        libc::SYS_clone,    // Threads only (CLONE_THREAD)
        libc::SYS_clone3,
        libc::SYS_execve    // For the initial exec
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
        libc::SYS_fchdir
    );

    // Networking (HTTP traffic only — TCP sockets)
    allow!(
        libc::SYS_socket,      // AF_INET/INET6 + SOCK_STREAM
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
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
        libc::SYS_ioctl,      // FIONREAD, TIOCGWINSZ
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_prlimit64,
        libc::SYS_rseq
    );

    let filter = SeccompFilter::new(
        rules,
        // Default action: kill the process on any non-whitelisted syscall
        SeccompAction::KillProcess,
        // Action for whitelisted syscalls
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()
            .map_err(|_| anyhow::anyhow!("Unsupported architecture"))?,
    )
    .context("Failed to build seccomp filter")?;

    filter
        .try_into()
        .context("Failed to compile seccomp BPF program")
}

/// Build a strict filter: no networking at all (offline computation only).
fn build_strict_filter() -> Result<seccompiler::BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    macro_rules! allow {
        ($($syscall:expr),+ $(,)?) => {
            $(rules.insert($syscall as i64, vec![SeccompRule::new(vec![])]);)+
        };
    }

    // Same as default but WITHOUT networking syscalls
    allow!(
        libc::SYS_exit, libc::SYS_exit_group, libc::SYS_wait4, libc::SYS_futex,
        libc::SYS_nanosleep, libc::SYS_clock_nanosleep, libc::SYS_sched_yield,
        libc::SYS_getpid, libc::SYS_gettid, libc::SYS_set_tid_address,
        libc::SYS_set_robust_list, libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn, libc::SYS_sigaltstack, libc::SYS_tgkill,
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_execve,
        libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_munmap, libc::SYS_brk,
        libc::SYS_mremap, libc::SYS_madvise,
        libc::SYS_read, libc::SYS_write, libc::SYS_close, libc::SYS_fstat,
        libc::SYS_stat, libc::SYS_lstat, libc::SYS_lseek, libc::SYS_openat,
        libc::SYS_fcntl, libc::SYS_dup, libc::SYS_dup2, libc::SYS_dup3,
        libc::SYS_pipe2, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_access, libc::SYS_faccessat,
        libc::SYS_getcwd, libc::SYS_readlink, libc::SYS_readlinkat,
        libc::SYS_newfstatat, libc::SYS_getdents64, libc::SYS_chdir,
        libc::SYS_clock_gettime, libc::SYS_clock_getres, libc::SYS_gettimeofday,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_geteuid, libc::SYS_getegid,
        libc::SYS_getrandom, libc::SYS_arch_prctl, libc::SYS_prctl,
        libc::SYS_ioctl, libc::SYS_uname, libc::SYS_prlimit64, libc::SYS_rseq
    );

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()
            .map_err(|_| anyhow::anyhow!("Unsupported architecture"))?,
    )
    .context("Failed to build strict seccomp filter")?;

    filter
        .try_into()
        .context("Failed to compile strict seccomp BPF program")
}
