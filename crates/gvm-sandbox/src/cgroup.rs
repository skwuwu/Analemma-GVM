//! cgroup v2 resource limits for sandboxed agent processes.
//!
//! Creates a child cgroup under the unified cgroup v2 hierarchy, sets memory
//! and CPU limits, and moves the agent PID into it. Cleans up on sandbox exit.
//!
//! Fallback: if cgroup v2 is not available (legacy cgroup v1 only, or no write
//! access), logs a warning and continues without resource limits. This is a
//! best-effort defense layer — namespace + seccomp remain the primary isolation.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// CPU period in microseconds (100ms — standard Linux default).
const CPU_PERIOD_US: u64 = 100_000;

/// Cgroup handle — tracks the cgroup directory for cleanup.
pub struct CgroupGuard {
    path: PathBuf,
}

impl CgroupGuard {
    /// Create a cgroup for the given PID with optional memory and CPU limits.
    ///
    /// Returns `Ok(Some(guard))` on success, `Ok(None)` if cgroup v2 is unavailable
    /// (graceful fallback), or `Err` for unexpected failures.
    pub fn create(
        pid: u32,
        memory_limit: Option<u64>,
        cpu_limit: Option<f64>,
    ) -> Result<Option<Self>> {
        // Check if cgroup v2 unified hierarchy is mounted
        let cgroup_root = Path::new("/sys/fs/cgroup");
        if !cgroup_root.join("cgroup.controllers").exists() {
            tracing::warn!("cgroup v2 not available — resource limits disabled");
            return Ok(None);
        }

        // Create GVM cgroup directory
        let cgroup_name = format!("gvm-agent-{}", pid);
        let cgroup_path = cgroup_root.join(&cgroup_name);

        if let Err(e) = fs::create_dir_all(&cgroup_path) {
            tracing::warn!(
                error = %e,
                path = %cgroup_path.display(),
                "Cannot create cgroup directory — resource limits disabled"
            );
            return Ok(None);
        }

        let guard = Self {
            path: cgroup_path.clone(),
        };

        // Enable controllers in the parent cgroup (required for subtree delegation)
        // This may fail if we don't have permission — that's OK, limits may still work
        // if controllers are already enabled by systemd.
        let _ = enable_controllers(cgroup_root);

        // Set memory limit
        if let Some(bytes) = memory_limit {
            let memory_max = cgroup_path.join("memory.max");
            if let Err(e) = fs::write(&memory_max, bytes.to_string()) {
                tracing::warn!(
                    error = %e,
                    limit_bytes = bytes,
                    "Failed to set memory.max — memory limit not enforced"
                );
            } else {
                tracing::info!(limit_mb = bytes / (1024 * 1024), "cgroup: memory.max set");
            }
        }

        // Set CPU limit
        if let Some(fraction) = cpu_limit {
            let quota_us = (fraction * CPU_PERIOD_US as f64) as u64;
            let cpu_max = cgroup_path.join("cpu.max");
            let value = format!("{} {}", quota_us, CPU_PERIOD_US);
            if let Err(e) = fs::write(&cpu_max, &value) {
                tracing::warn!(
                    error = %e,
                    cpu_fraction = fraction,
                    "Failed to set cpu.max — CPU limit not enforced"
                );
            } else {
                tracing::info!(
                    cpu_fraction = fraction,
                    quota_us = quota_us,
                    "cgroup: cpu.max set"
                );
            }
        }

        // Move the PID into the cgroup
        let procs_file = cgroup_path.join("cgroup.procs");
        fs::write(&procs_file, pid.to_string())
            .with_context(|| format!("Failed to move PID {} into cgroup {}", pid, cgroup_name))?;

        tracing::info!(
            pid = pid,
            cgroup = %cgroup_path.display(),
            "Agent PID moved into cgroup"
        );

        Ok(Some(guard))
    }
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        // Kill any remaining processes in the cgroup before removal.
        // Retry up to 3 times — zombies may take time to be reaped.
        let procs_file = self.path.join("cgroup.procs");
        for attempt in 0..3 {
            if let Ok(content) = fs::read_to_string(&procs_file) {
                let mut killed = 0;
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        if pid > 0 {
                            unsafe { libc::kill(pid, libc::SIGKILL); }
                            killed += 1;
                        }
                    }
                }
                if killed == 0 {
                    break; // No more processes
                }
            }
            // Wait for processes to exit (increasing backoff)
            std::thread::sleep(std::time::Duration::from_millis(50 * (attempt + 1) as u64));
        }

        // Remove the cgroup directory (must be empty of processes)
        if let Err(e) = fs::remove_dir(&self.path) {
            // Last resort: try to move remaining procs to root cgroup
            if let Ok(content) = fs::read_to_string(&procs_file) {
                for line in content.lines() {
                    if let Ok(pid) = line.trim().parse::<i32>() {
                        fs::write("/sys/fs/cgroup/cgroup.procs", pid.to_string()).ok();
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
                fs::remove_dir(&self.path).ok();
            }
            tracing::debug!(
                error = %e,
                path = %self.path.display(),
                "cgroup cleanup: initial remove_dir failed, attempted process migration"
            );
        } else {
            tracing::debug!(path = %self.path.display(), "cgroup cleaned up");
        }
    }
}

/// Try to enable memory and cpu controllers in the parent cgroup's subtree_control.
/// This is best-effort — systemd-managed systems usually have this done already.
fn enable_controllers(cgroup_root: &Path) -> Result<()> {
    let subtree_control = cgroup_root.join("cgroup.subtree_control");
    fs::write(&subtree_control, "+memory +cpu")
        .context("Failed to enable cgroup controllers in subtree_control")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_path_format() {
        let expected = Path::new("/sys/fs/cgroup/gvm-agent-12345");
        let actual = Path::new("/sys/fs/cgroup").join("gvm-agent-12345");
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_cpu_quota_calculation() {
        // 1.0 CPU = 100000us quota in 100000us period
        let fraction = 1.0f64;
        let quota = (fraction * CPU_PERIOD_US as f64) as u64;
        assert_eq!(quota, 100_000);

        // 0.5 CPU = 50000us quota
        let fraction = 0.5f64;
        let quota = (fraction * CPU_PERIOD_US as f64) as u64;
        assert_eq!(quota, 50_000);

        // 2.0 CPU = 200000us quota (allows bursting across 2 cores)
        let fraction = 2.0f64;
        let quota = (fraction * CPU_PERIOD_US as f64) as u64;
        assert_eq!(quota, 200_000);
    }
}
