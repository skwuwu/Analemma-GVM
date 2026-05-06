//! Parent-process liveness heartbeat for sandbox orphan detection.
//!
//! Defense-in-depth complement to `PR_SET_PDEATHSIG`. Two layered
//! signals on a per-parent lockfile under `/run/gvm/`:
//!
//! 1. **`flock(LOCK_EX)`** — held for the entire parent lifetime.
//!    The kernel atomically releases the lock when the holding
//!    process dies for any reason (clean exit, SIGKILL, OOM, panic,
//!    segfault). Cleanup probes with `LOCK_EX | LOCK_NB`: if it
//!    acquires, the parent is dead.
//!
//! 2. **mtime touch every `HEARTBEAT_INTERVAL`** — a background
//!    thread updates the file's mtime. Cleanup compares mtime to
//!    wall clock; if older than `HEARTBEAT_STALE_THRESHOLD`, the
//!    parent is hung (D-state, deadlocked tokio runtime, etc.) even
//!    though its PID is still in `/proc`.
//!
//! flock alone misses hung-but-not-dead parents. mtime alone misses
//! crashed parents on systems with skewed clocks. Combined, they
//! handle the failure modes that the existing PID/starttime check
//! does not.

#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

const HEARTBEAT_DIR: &str = "/run/gvm";
/// File-name prefix for parent heartbeat lockfiles (`gvm-{pid}.heartbeat`).
/// `pub(crate)` so `network::cleanup_all_orphans_report` can construct a
/// glob over orphan lockfiles whose state file never landed.
pub(crate) const HEARTBEAT_PREFIX: &str = "gvm-";
pub(crate) const HEARTBEAT_SUFFIX: &str = ".heartbeat";

/// Returns the heartbeat directory.
///
/// In production this is the hardcoded `/run/gvm`. Tests in this
/// module may override the path via a `#[cfg(test)]`-gated env var
/// so they can run as a non-root user (CI default) without silently
/// skipping. The override is COMPILED OUT of production binaries
/// (the `#[cfg(test)]` block is only present when the gvm-sandbox
/// crate is built with `--cfg test`), so an attacker who can set
/// env vars on the production gvm-proxy process cannot redirect
/// heartbeat files and bypass orphan detection.
/// `pub(crate)` accessor so the orphan-heartbeat sweep in
/// `network::cleanup_all_orphans_report` honors the same
/// `GVM_HEARTBEAT_DIR_TEST_ONLY` override the rest of the module uses.
pub(crate) fn heartbeat_dir_for_test_or_default() -> String {
    heartbeat_dir()
}

fn heartbeat_dir() -> String {
    #[cfg(test)]
    {
        if let Ok(test_dir) = std::env::var("GVM_HEARTBEAT_DIR_TEST_ONLY") {
            return test_dir;
        }
    }
    HEARTBEAT_DIR.to_string()
}

/// How often the parent touches the heartbeat file's mtime.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// If the file's mtime is older than this, the parent is considered
/// hung. Must be larger than `HEARTBEAT_INTERVAL` by enough margin
/// to absorb scheduler jitter, brief I/O stalls, and clock drift.
pub const HEARTBEAT_STALE_THRESHOLD: Duration = Duration::from_secs(30);

/// Liveness state of a parent process as reported by its heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentState {
    /// Lock held AND mtime fresh — parent is making progress.
    Alive,
    /// Lock released — kernel auto-released on parent death.
    Dead,
    /// Lock still held but mtime older than the stale threshold —
    /// parent is alive in /proc but its heartbeat thread stopped
    /// touching the file. Treat as orphan candidate.
    Hung,
    /// No heartbeat file. Parent never installed one (older version
    /// or non-sandbox path), or file was already swept. Caller
    /// should fall back to the PID/starttime check.
    NoHeartbeat,
}

/// Path to the heartbeat file for a given parent PID.
pub fn heartbeat_path(pid: u32) -> PathBuf {
    PathBuf::from(format!(
        "{}/{}{}{}",
        heartbeat_dir(),
        HEARTBEAT_PREFIX,
        pid,
        HEARTBEAT_SUFFIX
    ))
}

/// RAII guard held by the parent gvm process. Owns the lockfile FD
/// (with `LOCK_EX`) and a background thread that touches mtime.
///
/// On drop: signals the thread to stop, joins it, drops the FD
/// (releasing the lock), and removes the file.
pub struct ParentHeartbeat {
    path: PathBuf,
    // Held to keep flock alive for the lifetime of the guard. The
    // lock is associated with this open file description; closing
    // it releases the lock atomically (kernel guarantee).
    _lock_fd: OwnedFd,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ParentHeartbeat {
    /// Acquire the heartbeat lockfile for the given PID and start
    /// the touch thread. Errors if the file cannot be opened or the
    /// lock is already held by another process. The lock path
    /// embeds the PID, so contention indicates a duplicate gvm
    /// instance under the same PID — bail rather than launch.
    pub fn acquire(pid: u32) -> Result<Self> {
        Self::acquire_with_interval(pid, HEARTBEAT_INTERVAL)
    }

    /// Test/internal hook: same as [`acquire`] but with a custom
    /// touch interval. Production callers always go through
    /// [`acquire`].
    #[doc(hidden)]
    pub fn acquire_with_interval(pid: u32, interval: Duration) -> Result<Self> {
        let _ = std::fs::create_dir_all(heartbeat_dir());
        let path = heartbeat_path(pid);

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("Failed to open heartbeat file {}", path.display()))?;
        let lock_fd: OwnedFd = file.into();

        // SAFETY: flock() takes an integer fd and bitflags; no pointers are
        // dereferenced. lock_fd is a live OwnedFd we just opened, so the
        // raw fd is valid for the duration of this call.
        let ret = unsafe { libc::flock(lock_fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!(
                "Failed to acquire heartbeat lock {}: {} \
                 (another gvm process appears to hold this PID's lock)",
                path.display(),
                err
            );
        }

        // Initial touch so the mtime is fresh from the moment the
        // lock is held. Without this, a probe before the first
        // sleep cycle could see a stale mtime.
        touch_fd(lock_fd.as_raw_fd());

        let stop = Arc::new(AtomicBool::new(false));
        let touch_fd_dup = lock_fd
            .try_clone()
            .context("Failed to dup heartbeat fd for touch thread")?;
        let stop_clone = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("gvm-heartbeat".into())
            .spawn(move || {
                heartbeat_loop(touch_fd_dup, stop_clone, interval);
            })
            .context("Failed to spawn heartbeat thread")?;

        Ok(Self {
            path,
            _lock_fd: lock_fd,
            stop,
            thread: Some(thread),
        })
    }

    /// Path to this guard's lockfile. Exposed for tests and
    /// observability.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for ParentHeartbeat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            // Best-effort join; the thread only sleeps + touches,
            // so it cannot panic in normal flow.
            let _ = t.join();
        }
        // _lock_fd drops here, releasing the flock.
        // Remove the path; on race with a concurrent probe the
        // probe just sees ENOENT and reports NoHeartbeat.
        let _ = std::fs::remove_file(&self.path);
    }
}

fn heartbeat_loop(fd: OwnedFd, stop: Arc<AtomicBool>, interval: Duration) {
    // Sleep in small ticks so Drop can wake the thread promptly.
    // 50ms keeps the CPU cost negligible while bounding shutdown
    // latency to one tick. Tests use very short intervals
    // (e.g. 100ms), so the wake tick must be smaller than the
    // shortest reasonable test interval.
    const WAKE_INTERVAL: Duration = Duration::from_millis(50);
    let mut elapsed = Duration::ZERO;

    while !stop.load(Ordering::Acquire) {
        std::thread::sleep(WAKE_INTERVAL);
        elapsed += WAKE_INTERVAL;
        if elapsed >= interval {
            touch_fd(fd.as_raw_fd());
            elapsed = Duration::ZERO;
        }
    }
}

fn touch_fd(fd: std::os::unix::io::RawFd) {
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
    ];
    // Best-effort. If the syscall fails (very unusual on a tmpfs we
    // just opened), the next probe will see a stale mtime and the
    // parent will be incorrectly flagged Hung — but only after the
    // 30s threshold, so a transient failure is benign.
    // SAFETY: `times` is a stack-allocated [timespec; 2]; futimens()
    // reads exactly two elements via the pointer, matching the array
    // size. `fd` is owned by the caller and live for this call.
    unsafe {
        libc::futimens(fd, times.as_ptr());
    }
}

/// Probe a parent PID's liveness via its heartbeat file.
///
/// Used by the cleanup path to decide whether sandbox resources
/// owned by `pid` are orphaned. Order of checks:
///
///   1. File missing → `NoHeartbeat` (caller falls back to
///      PID/starttime).
///   2. `LOCK_EX | LOCK_NB` succeeds → `Dead` (kernel released the
///      lock on process death).
///   3. Lock held + mtime stale → `Hung`.
///   4. Lock held + mtime fresh → `Alive`.
pub fn parent_state(pid: u32, stale_threshold: Duration) -> ParentState {
    let path = heartbeat_path(pid);

    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(_) => return ParentState::NoHeartbeat,
    };

    let file = match std::fs::OpenOptions::new().read(true).open(&path) {
        Ok(f) => f,
        Err(_) => return ParentState::NoHeartbeat,
    };

    let fd = file.as_raw_fd();
    // SAFETY: flock() reads only the integer fd and flag bits; no pointer
    // arguments. `fd` is owned by `file` and stays live until this scope
    // ends, well after both flock() calls.
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        // We acquired the exclusive lock — parent's open file
        // description is gone. Release before our FD drops to
        // avoid muddling state for subsequent probes.
        // SAFETY: same fd as the LOCK_EX call above; still owned by `file`.
        unsafe {
            libc::flock(fd, libc::LOCK_UN);
        }
        return ParentState::Dead;
    }

    let errno = std::io::Error::last_os_error().raw_os_error();
    if errno != Some(libc::EWOULDBLOCK) {
        // Unexpected error — be conservative, do not claim death.
        return ParentState::NoHeartbeat;
    }

    let mtime = match metadata.modified() {
        Ok(t) => t,
        // Cannot read mtime — trust the lock signal alone.
        Err(_) => return ParentState::Alive,
    };

    let age = SystemTime::now()
        .duration_since(mtime)
        .unwrap_or(Duration::ZERO);
    if age > stale_threshold {
        ParentState::Hung
    } else {
        ParentState::Alive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    // These tests run only on Linux (the module itself is gated).
    // They no longer skip when /run/gvm is not writable: every test
    // forces GVM_HEARTBEAT_DIR_TEST_ONLY to a process-shared tempdir
    // so CI runs (non-root) actually exercise the flock/futimens paths
    // instead of silently passing.
    //
    // The env var read in `heartbeat_dir()` is gated by `#[cfg(test)]`
    // — production binaries never even compile the env-var lookup,
    // so an attacker who can set env vars cannot redirect heartbeat
    // files at runtime. The variable name carries `_TEST_ONLY` to
    // make the test-fixture intent unmistakable to anyone grepping.

    static TEST_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

    fn ensure_test_dir() {
        let dir = TEST_DIR
            .get_or_init(|| tempfile::tempdir().expect("create heartbeat tempdir for tests"));
        // SAFETY: process-wide env mutation is racy in general; here we
        // only ever set it to the same path (the OnceLock-protected
        // tempdir), so concurrent tests observe the same value.
        unsafe {
            std::env::set_var("GVM_HEARTBEAT_DIR_TEST_ONLY", dir.path());
        }
    }

    #[test]
    fn acquire_creates_file_and_drop_removes_it() {
        ensure_test_dir();
        // Use a synthetic PID well above the live range so we don't
        // collide with a real running gvm.
        let synthetic_pid = u32::MAX - 1;
        let path = heartbeat_path(synthetic_pid);
        let _ = std::fs::remove_file(&path);

        {
            let _hb = ParentHeartbeat::acquire(synthetic_pid).expect("acquire");
            assert!(path.exists(), "heartbeat file must exist while held");
        }
        assert!(
            !path.exists(),
            "heartbeat file must be removed on drop, found {}",
            path.display()
        );
    }

    #[test]
    fn parent_state_reports_alive_while_held() {
        ensure_test_dir();
        let synthetic_pid = u32::MAX - 2;
        let _ = std::fs::remove_file(heartbeat_path(synthetic_pid));

        let _hb = ParentHeartbeat::acquire(synthetic_pid).expect("acquire");
        assert_eq!(
            parent_state(synthetic_pid, HEARTBEAT_STALE_THRESHOLD),
            ParentState::Alive,
            "parent_state must report Alive while heartbeat held"
        );
    }

    #[test]
    fn parent_state_reports_dead_after_drop() {
        ensure_test_dir();
        let synthetic_pid = u32::MAX - 3;
        let path = heartbeat_path(synthetic_pid);
        let _ = std::fs::remove_file(&path);

        // Open + flock a fresh file ourselves, then drop the FD
        // without removing the file — this simulates a parent that
        // crashed (lock released) but the file persists. Subsequent
        // ParentHeartbeat::acquire from a hypothetical successor
        // would normally clean it up; here we just probe.
        {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .unwrap();
            let fd: OwnedFd = f.into();
            let r = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            assert_eq!(r, 0, "flock must succeed on fresh file");
            // Touch so mtime is fresh — confirm Dead is from lock
            // signal, not from staleness.
            touch_fd(fd.as_raw_fd());
            // fd drops here, releasing the lock.
        }

        assert_eq!(
            parent_state(synthetic_pid, HEARTBEAT_STALE_THRESHOLD),
            ParentState::Dead,
            "after holder drops the FD, parent_state must report Dead"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn parent_state_reports_hung_when_mtime_stale() {
        ensure_test_dir();
        let synthetic_pid = u32::MAX - 4;
        let path = heartbeat_path(synthetic_pid);
        let _ = std::fs::remove_file(&path);

        // Acquire the lock and then artificially backdate the mtime
        // to simulate a hung parent (lock held, but heartbeat thread
        // is wedged so mtime stops advancing).
        let hb = ParentHeartbeat::acquire(synthetic_pid).expect("acquire");

        // Set mtime to 60 seconds ago.
        let backdated = libc::timespec {
            tv_sec: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64)
                - 60,
            tv_nsec: 0,
        };
        let times = [backdated, backdated];
        let r = unsafe { libc::futimens(hb._lock_fd.as_raw_fd(), times.as_ptr()) };
        assert_eq!(r, 0, "futimens to backdate mtime must succeed");

        // Probe with a 30s stale threshold.
        let state = parent_state(synthetic_pid, Duration::from_secs(30));
        assert_eq!(
            state,
            ParentState::Hung,
            "lock held + mtime > threshold must be Hung, got {:?}",
            state
        );

        drop(hb);
    }

    #[test]
    fn parent_state_no_heartbeat_for_missing_file() {
        // No heartbeat file exists for this PID.
        let synthetic_pid = u32::MAX - 100;
        let _ = std::fs::remove_file(heartbeat_path(synthetic_pid));
        assert_eq!(
            parent_state(synthetic_pid, HEARTBEAT_STALE_THRESHOLD),
            ParentState::NoHeartbeat
        );
    }

    #[test]
    fn second_acquire_with_same_pid_fails() {
        ensure_test_dir();
        let synthetic_pid = u32::MAX - 5;
        let _ = std::fs::remove_file(heartbeat_path(synthetic_pid));

        let _hb1 = ParentHeartbeat::acquire(synthetic_pid).expect("first acquire");
        let r = ParentHeartbeat::acquire(synthetic_pid);
        assert!(
            r.is_err(),
            "second acquire on same PID must fail (lock held by hb1)"
        );
    }

    #[test]
    fn touch_thread_advances_mtime() {
        ensure_test_dir();
        let synthetic_pid = u32::MAX - 7;
        let _ = std::fs::remove_file(heartbeat_path(synthetic_pid));

        // Use a fast (100ms) touch interval so we can observe
        // mtime advance in a unit test without sleeping seconds.
        let hb = ParentHeartbeat::acquire_with_interval(synthetic_pid, Duration::from_millis(100))
            .expect("acquire");
        let path = hb.path().to_path_buf();

        let mtime1 = std::fs::metadata(&path).unwrap().modified().unwrap();
        // Wait long enough for at least 3 touch cycles.
        std::thread::sleep(Duration::from_millis(450));
        let mtime2 = std::fs::metadata(&path).unwrap().modified().unwrap();

        assert!(
            mtime2 > mtime1,
            "mtime must advance after several touch intervals (mtime1={:?}, mtime2={:?})",
            mtime1,
            mtime2
        );

        drop(hb);
    }

    #[test]
    fn drop_releases_lock_so_re_acquire_succeeds() {
        ensure_test_dir();
        let synthetic_pid = u32::MAX - 8;
        let _ = std::fs::remove_file(heartbeat_path(synthetic_pid));

        // First acquire → drop (file unlinked, lock released).
        {
            let _hb = ParentHeartbeat::acquire(synthetic_pid).expect("acquire");
        }
        // After drop, the file is gone. A re-acquire must succeed.
        let _hb2 = ParentHeartbeat::acquire(synthetic_pid)
            .expect("re-acquire after drop must succeed (lock was released)");
    }
}
