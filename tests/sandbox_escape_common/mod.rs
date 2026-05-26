//! Shared helpers for sandbox escape adversarial integration tests.
//!
//! Tests in this family launch a real sandbox via `gvm run --sandbox -- <probe>`
//! and assert against the probe's exit code, stdout, and stderr. This mirrors
//! how an operator would manually verify isolation, and stays compliant with
//! the CLI-only testing rule in CLAUDE.md (no direct gvm-sandbox API calls).
//!
//! Each helper is no-op on non-Linux: the sandbox primitives (namespaces,
//! seccomp, veth, iptables) only exist on Linux, and the test functions are
//! gated with `#[cfg(target_os = "linux")]` at the call site. Helpers still
//! compile cross-platform so `cargo check` on Windows/macOS does not break.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

/// Captured outcome of running a probe inside the sandbox.
pub struct ProbeResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl ProbeResult {
    pub fn combined(&self) -> String {
        format!("STDOUT:\n{}\nSTDERR:\n{}", self.stdout, self.stderr)
    }
}

/// Locate the `gvm` binary produced by `cargo build --release -p gvm-cli`.
///
/// Search order:
///   1. `GVM_BIN` environment variable (lets CI override).
///   2. `<workspace>/target/release/gvm[.exe]`.
///   3. `<workspace>/target/debug/gvm[.exe]` (fallback for local dev).
///
/// Returns `None` if no binary is found — caller should skip the test with a
/// loud `eprintln!` so the operator knows to run `cargo build --release` first.
pub fn gvm_binary_path() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("GVM_BIN") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let manifest = PathBuf::from(manifest);

    let exe = if cfg!(target_os = "windows") {
        "gvm.exe"
    } else {
        "gvm"
    };
    for profile in ["release", "debug"] {
        let candidate = manifest.join("target").join(profile).join(exe);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// True when the current process runs as root (euid == 0).
///
/// Sandbox launch needs root for namespace creation, mount, iptables, and
/// cgroup setup. Tests that need a real sandbox must skip when not root.
#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
}

/// Returns `true` if the test environment can actually launch a sandbox.
/// Logs a SKIP reason and returns `false` otherwise. Tests should early-return
/// when this returns `false`.
pub fn require_sandbox_env(test_name: &str) -> bool {
    if !cfg!(target_os = "linux") {
        eprintln!("SKIP[{test_name}]: sandbox tests require Linux");
        return false;
    }
    if !is_root() {
        eprintln!("SKIP[{test_name}]: sandbox launch requires root (run with sudo)");
        return false;
    }
    if gvm_binary_path().is_none() {
        eprintln!(
            "SKIP[{test_name}]: gvm binary not found. \
             Run: cargo build --release -p gvm-cli"
        );
        return false;
    }
    true
}

/// Run a shell command inside `gvm run --sandbox` and capture the result.
///
/// The probe is executed via `/bin/sh -c <cmd>`. Stdout, stderr, and exit
/// code are captured. A wall-clock timeout of `timeout` is enforced; if the
/// sandbox does not exit within that window, the child is killed and
/// `timed_out = true` is set on the result.
///
/// Each invocation uses a unique `--agent-id` (test name + nanosecond
/// timestamp) so concurrent test runs don't collide on WAL or proxy state.
pub fn run_sandboxed_probe(test_name: &str, cmd: &str, timeout: Duration) -> ProbeResult {
    let gvm = gvm_binary_path()
        .expect("gvm_binary_path() must succeed when require_sandbox_env() returned true");

    let agent_id = format!(
        "{}-{}",
        test_name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    let mut child = Command::new(&gvm)
        .args([
            "run",
            "--sandbox",
            "--agent-id",
            &agent_id,
            "--",
            "/bin/sh",
            "-c",
            cmd,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning gvm run --sandbox must succeed");

    // Wall-clock timeout: poll wait() with a busy sleep. We deliberately
    // avoid pulling in the `wait-timeout` crate — sandbox tests already need
    // root, and a 100ms poll cost is dwarfed by sandbox setup latency.
    let start = std::time::Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().expect("kill+wait must succeed");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("try_wait on gvm child failed: {e}"),
        }
    };

    let output: Output = {
        // Drain stdout/stderr after the child exited. We can't use
        // wait_with_output() because we already called try_wait/kill.
        let mut stdout = String::new();
        let mut stderr = String::new();
        use std::io::Read;
        if let Some(mut s) = child.stdout.take() {
            let _ = s.read_to_string(&mut stdout);
        }
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut stderr);
        }
        Output {
            status,
            stdout: stdout.into_bytes(),
            stderr: stderr.into_bytes(),
        }
    };

    ProbeResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        timed_out,
    }
}

/// Assert the probe was blocked: exit code non-zero AND stderr (or combined
/// output) contains at least one of the expected error fragments.
///
/// The fragments list lets a single test accept several equivalent kernel
/// responses — e.g., `mount(2)` can yield "Function not implemented" (ENOSYS
/// from seccomp) or "Operation not permitted" (EPERM from cap drop) depending
/// on which layer fires first. Either is a successful block.
pub fn assert_blocked_with(result: &ProbeResult, expected_any: &[&str], context: &str) {
    assert!(
        result.exit_code != 0 || result.timed_out,
        "{context}: expected non-zero exit (or timeout), got exit_code=0. \
         Probe may have succeeded — isolation breach? Output:\n{}",
        result.combined()
    );

    let haystack = format!("{}\n{}", result.stdout, result.stderr);
    let found = expected_any.iter().any(|needle| haystack.contains(needle));
    assert!(
        found,
        "{context}: expected stderr/stdout to contain one of {:?}, \
         got exit={}, timed_out={}, output:\n{}",
        expected_any,
        result.exit_code,
        result.timed_out,
        result.combined()
    );
}

/// Assert the probe's stdout, trimmed of whitespace, equals an expected value.
/// Useful for `ls -A | wc -l` style probes that count items behind a mask.
pub fn assert_stdout_eq(result: &ProbeResult, expected: &str, context: &str) {
    let got = result.stdout.trim();
    assert_eq!(
        got,
        expected,
        "{context}: expected stdout='{expected}', got='{got}'. \
         Full output:\n{}",
        result.combined()
    );
}
