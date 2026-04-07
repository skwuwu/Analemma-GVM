//! Syscall number → name lookup for SECCOMP audit messages.
//!
//! Built from `libc::SYS_*` constants so we never hardcode magic numbers
//! and stay correct as new syscalls are added by libc upstream. The table
//! covers every syscall the seccomp filter could plausibly block — both
//! the explicit blocklist (mount, ptrace, bpf, ...) and any
//! whitelisted-on-Linux call that an agent might trip on a non-default
//! profile.
//!
//! OS-independent: only references `libc::SYS_*` constants which are
//! present on Linux. On Windows the constants are absent, so the entire
//! module is gated behind `cfg(target_os = "linux")` at the call site.

#![cfg(target_os = "linux")]

/// Look up a Linux x86_64 syscall number and return its symbolic name.
///
/// Returns `None` for syscalls outside our table — caller should fall
/// back to printing the raw number. The table is built via macro from
/// `libc::SYS_*` constants, so it stays in sync with the libc crate.
pub fn name_for(num: i64) -> Option<&'static str> {
    macro_rules! table {
        ($($sys:ident),+ $(,)?) => {
            match num {
                $(n if n == libc::$sys as i64 => Some(stringify!($sys).trim_start_matches("SYS_")),)+
                _ => None,
            }
        };
    }

    // ── High-risk syscalls explicitly targeted by the sandbox seccomp filter ──
    // Anything an agent attempts that matches one of these is what users will
    // most often see in dmesg. Prioritised first for grep readability.
    let blocked = table!(
        SYS_mount,
        SYS_umount2,
        SYS_pivot_root,
        SYS_chroot,
        SYS_ptrace,
        SYS_process_vm_readv,
        SYS_process_vm_writev,
        SYS_bpf,
        SYS_unshare,
        SYS_setns,
        SYS_open_by_handle_at,
        SYS_name_to_handle_at,
        SYS_init_module,
        SYS_finit_module,
        SYS_delete_module,
        SYS_kexec_load,
        SYS_kexec_file_load,
        SYS_reboot,
        SYS_swapon,
        SYS_swapoff,
        SYS_syslog,
        SYS_personality,
        SYS_quotactl,
        SYS_iopl,
        SYS_ioperm,
        SYS_settimeofday,
        SYS_clock_settime,
        SYS_clock_adjtime,
        SYS_adjtimex,
        SYS_acct,
        SYS_lookup_dcookie,
        SYS_perf_event_open,
        SYS_keyctl,
        SYS_add_key,
        SYS_request_key,
        SYS_pkey_alloc,
        SYS_pkey_free,
        SYS_pkey_mprotect,
        SYS_io_uring_setup,
        SYS_io_uring_enter,
        SYS_io_uring_register,
        SYS_userfaultfd,
        SYS_fanotify_init,
        SYS_fanotify_mark,
        SYS_modify_ldt,
        SYS_uselib,
        SYS_ustat,
        SYS_sysfs,
        SYS_capset,
        SYS_setfsuid,
        SYS_setfsgid,
        SYS_setresuid,
        SYS_setresgid,
        SYS_setreuid,
        SYS_setregid,
        SYS_setuid,
        SYS_setgid,
        SYS_setgroups,
        SYS_seccomp,
        SYS_prctl,
        SYS_arch_prctl,
    );
    if blocked.is_some() {
        return blocked;
    }

    // ── Common allowed syscalls — included so error messages are useful even ──
    // when the agent dies on a syscall that's normally allowed (e.g. wrong
    // `socket()` domain triggers a conditional rule miss).
    table!(
        // Process / thread lifecycle
        SYS_exit,
        SYS_exit_group,
        SYS_clone,
        SYS_clone3,
        SYS_fork,
        SYS_vfork,
        SYS_execve,
        SYS_execveat,
        SYS_wait4,
        SYS_waitid,
        SYS_kill,
        SYS_tgkill,
        SYS_tkill,
        SYS_rt_sigaction,
        SYS_rt_sigprocmask,
        SYS_rt_sigreturn,
        SYS_rt_sigsuspend,
        SYS_rt_sigtimedwait,
        SYS_rt_sigqueueinfo,
        SYS_rt_sigpending,
        SYS_signalfd4,
        SYS_pause,
        // Memory management
        SYS_mmap,
        SYS_munmap,
        SYS_mremap,
        SYS_mprotect,
        SYS_madvise,
        SYS_brk,
        SYS_mlock,
        SYS_mlock2,
        SYS_munlock,
        SYS_mlockall,
        SYS_munlockall,
        SYS_msync,
        SYS_mincore,
        SYS_membarrier,
        // File I/O
        SYS_read,
        SYS_pread64,
        SYS_readv,
        SYS_preadv,
        SYS_preadv2,
        SYS_write,
        SYS_pwrite64,
        SYS_writev,
        SYS_pwritev,
        SYS_pwritev2,
        SYS_open,
        SYS_openat,
        SYS_openat2,
        SYS_close,
        SYS_close_range,
        SYS_creat,
        SYS_lseek,
        SYS_pipe,
        SYS_pipe2,
        SYS_dup,
        SYS_dup2,
        SYS_dup3,
        SYS_fcntl,
        SYS_flock,
        SYS_fsync,
        SYS_fdatasync,
        SYS_truncate,
        SYS_ftruncate,
        SYS_sendfile,
        SYS_splice,
        SYS_tee,
        SYS_vmsplice,
        SYS_copy_file_range,
        // File metadata
        SYS_stat,
        SYS_fstat,
        SYS_lstat,
        SYS_newfstatat,
        SYS_statx,
        SYS_access,
        SYS_faccessat,
        SYS_faccessat2,
        SYS_chmod,
        SYS_fchmod,
        SYS_fchmodat,
        SYS_chown,
        SYS_fchown,
        SYS_lchown,
        SYS_fchownat,
        SYS_umask,
        // Directory ops
        SYS_getcwd,
        SYS_chdir,
        SYS_fchdir,
        SYS_mkdir,
        SYS_mkdirat,
        SYS_rmdir,
        SYS_getdents,
        SYS_getdents64,
        SYS_link,
        SYS_linkat,
        SYS_unlink,
        SYS_unlinkat,
        SYS_symlink,
        SYS_symlinkat,
        SYS_readlink,
        SYS_readlinkat,
        SYS_rename,
        SYS_renameat,
        SYS_renameat2,
        // Networking
        SYS_socket,
        SYS_socketpair,
        SYS_bind,
        SYS_listen,
        SYS_accept,
        SYS_accept4,
        SYS_connect,
        SYS_getsockname,
        SYS_getpeername,
        SYS_sendto,
        SYS_recvfrom,
        SYS_sendmsg,
        SYS_recvmsg,
        SYS_sendmmsg,
        SYS_recvmmsg,
        SYS_setsockopt,
        SYS_getsockopt,
        SYS_shutdown,
        // Polling / events
        SYS_poll,
        SYS_ppoll,
        SYS_select,
        SYS_pselect6,
        SYS_epoll_create,
        SYS_epoll_create1,
        SYS_epoll_ctl,
        SYS_epoll_wait,
        SYS_epoll_pwait,
        SYS_eventfd,
        SYS_eventfd2,
        SYS_timerfd_create,
        SYS_timerfd_settime,
        SYS_timerfd_gettime,
        SYS_inotify_init,
        SYS_inotify_init1,
        SYS_inotify_add_watch,
        SYS_inotify_rm_watch,
        // Time
        SYS_gettimeofday,
        SYS_clock_gettime,
        SYS_clock_getres,
        SYS_clock_nanosleep,
        SYS_nanosleep,
        SYS_time,
        SYS_times,
        // Identity
        SYS_getpid,
        SYS_getppid,
        SYS_gettid,
        SYS_getuid,
        SYS_geteuid,
        SYS_getgid,
        SYS_getegid,
        SYS_getgroups,
        SYS_getsid,
        SYS_getpgid,
        SYS_getpgrp,
        SYS_setsid,
        SYS_setpgid,
        // Resource / scheduling
        SYS_getrlimit,
        SYS_setrlimit,
        SYS_prlimit64,
        SYS_getrusage,
        SYS_sched_yield,
        SYS_sched_getaffinity,
        SYS_sched_setaffinity,
        SYS_sched_getparam,
        SYS_sched_setparam,
        SYS_sched_getscheduler,
        SYS_sched_setscheduler,
        SYS_sched_get_priority_max,
        SYS_sched_get_priority_min,
        // Misc
        SYS_futex,
        SYS_set_robust_list,
        SYS_get_robust_list,
        SYS_set_tid_address,
        SYS_uname,
        SYS_getrandom,
        SYS_sysinfo,
        SYS_ioctl,
        SYS_rseq,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_blocked_mount() {
        // mount(2) is the canonical example used in our seccomp filter.
        let n = libc::SYS_mount as i64;
        assert_eq!(name_for(n), Some("mount"));
    }

    #[test]
    fn lookup_blocked_ptrace() {
        let n = libc::SYS_ptrace as i64;
        assert_eq!(name_for(n), Some("ptrace"));
    }

    #[test]
    fn lookup_blocked_bpf() {
        let n = libc::SYS_bpf as i64;
        assert_eq!(name_for(n), Some("bpf"));
    }

    #[test]
    fn lookup_allowed_read() {
        // Allowed syscalls are also in the table so error messages stay
        // useful when an agent dies on an unexpected syscall.
        let n = libc::SYS_read as i64;
        assert_eq!(name_for(n), Some("read"));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        // Number well outside any reasonable syscall table.
        assert_eq!(name_for(99999), None);
    }

    #[test]
    fn name_strips_sys_prefix() {
        // The macro strips "SYS_" so output is human-friendly.
        let n = libc::SYS_openat as i64;
        assert_eq!(name_for(n), Some("openat"));
    }
}
