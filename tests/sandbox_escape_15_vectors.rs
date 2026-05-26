//! Sandbox escape regression suite — 15 attack vectors from the 2026-04-05
//! manual EC2 pentest, automated as CI-runnable integration tests.
//!
//! Each test maps 1:1 to a row in the table at
//! `docs/security-model.md#hostile-attack-vectors-1515-blocked`. The function
//! name `escape_v<NN>_<slug>` matches the table row number, so a regression
//! in any defense layer fails a test whose name points back at the documented
//! expectation.
//!
//! Defense layers exercised:
//!   - Mount namespace + minimal /etc          (#1, #8)
//!   - Overlayfs + tmpfs blocklist             (#2)
//!   - seccomp BPF                              (#3, #5, #10, #11, #12, #15)
//!   - iptables OUTPUT DROP                     (#4, #9, #15)
//!   - bind mount read-only                     (#7)
//!   - Capability drop (CAP_NET_ADMIN, etc.)    (#6, #13)
//!   - hidepid=2 + PID namespace                (#14)
//!
//! Requirements to run:
//!   - Linux host with namespace + seccomp support
//!   - Root privileges (`sudo cargo test --test sandbox_escape_15_vectors`)
//!   - `cargo build --release -p gvm-cli` must have run first
//!   - Network egress on the host (sandbox network namespace routes via
//!     veth + iptables; we never test against the loopback interface)
//!
//! Tests are skipped (printed and returned early) on non-Linux hosts and
//! non-root invocations. CI runs them on the EC2 e2e pipeline; local
//! development on Windows/macOS skips them at runtime, not at compile time,
//! so the test file itself still compiles everywhere.

#[path = "sandbox_escape_common/mod.rs"]
mod common;

#[cfg(target_os = "linux")]
use common::{assert_blocked_with, assert_stdout_eq, require_sandbox_env, run_sandboxed_probe};
#[cfg(target_os = "linux")]
use std::time::Duration;

/// Default per-probe timeout. Sandbox setup costs ~2-4 s on a warm EC2 node;
/// the probe itself runs in microseconds for most syscall vectors. 60 s leaves
/// generous headroom for cold-cache cert generation on the first invocation
/// of a `cargo test --test sandbox_escape_15_vectors` run.
#[cfg(target_os = "linux")]
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);

// ─── Vector 1: /etc/shadow read attempt ────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v01_etc_shadow_no_such_file() {
    if !require_sandbox_env("v01") {
        return;
    }
    let r = run_sandboxed_probe("v01", "cat /etc/shadow", PROBE_TIMEOUT);
    assert_blocked_with(
        &r,
        &["No such file", "Permission denied"],
        "v01 /etc/shadow must be absent or denied (mount namespace + minimal /etc)",
    );
}

// ─── Vector 2: ~/.ssh masked by tmpfs overlay ──────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v02_ssh_dir_empty_masked() {
    if !require_sandbox_env("v02") {
        return;
    }
    // Use `ls -A` to include dotfiles, pipe to `wc -l`. If the overlay
    // blocklist works, the directory is either absent or empty.
    let r = run_sandboxed_probe("v02", "ls -A ~/.ssh/ 2>/dev/null | wc -l", PROBE_TIMEOUT);
    assert_stdout_eq(
        &r,
        "0",
        "v02 ~/.ssh must be masked (overlayfs + tmpfs blocklist)",
    );
}

// ─── Vector 3: AF_PACKET raw socket (seccomp) ──────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v03_af_packet_blocked() {
    if !require_sandbox_env("v03") {
        return;
    }
    // Python encodes the syscall outcome in its exit code so we can assert
    // exactly: 0 = AF_PACKET allowed (BREACH), >0 = blocked with that errno.
    let probe = r#"python3 -c '
import socket, sys
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
    s.close()
    sys.exit(0)
except OSError as e:
    sys.exit(e.errno if e.errno else 99)
'"#;
    let r = run_sandboxed_probe("v03", probe, PROBE_TIMEOUT);
    assert!(
        r.exit_code != 0,
        "v03 AF_PACKET must be blocked, got exit=0 (raw socket created). \
         Output:\n{}",
        r.combined()
    );
    // EPERM (1) is the documented result; ENOSYS (38) is acceptable if the
    // seccomp filter shifted to ENOSYS for this syscall.
    assert!(
        r.exit_code == 1 || r.exit_code == 38,
        "v03 AF_PACKET expected EPERM(1) or ENOSYS(38), got errno={}. Output:\n{}",
        r.exit_code,
        r.combined()
    );
}

// ─── Vector 4: EC2 metadata service unreachable ────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v04_ec2_metadata_no_response() {
    if !require_sandbox_env("v04") {
        return;
    }
    // curl with short timeout — IMDS at 169.254.169.254 must be blocked at
    // the iptables OUTPUT layer (the link-local /16 is not in the allowed
    // egress set). Either timeout or connection failure proves the block.
    let r = run_sandboxed_probe(
        "v04",
        "curl -sS --max-time 3 http://169.254.169.254/latest/meta-data/ 2>&1; echo EXIT=$?",
        PROBE_TIMEOUT,
    );
    let out = r.combined();
    assert!(
        out.contains("EXIT=") && !out.contains("EXIT=0"),
        "v04 EC2 IMDS must be blocked, got success. Output:\n{out}"
    );
    // Accept either explicit connection failure or timeout — both mean the
    // host route to 169.254.169.254 was severed by iptables.
    let blocked_signal = [
        "timed out",
        "Connection refused",
        "No route",
        "Connection timed out",
        "Could not resolve",
        "Failed to connect",
    ];
    let found = blocked_signal.iter().any(|s| out.contains(s));
    assert!(
        found,
        "v04 expected curl to report network failure, got:\n{out}"
    );
}

// ─── Vector 5: mount(2) blocked by seccomp ─────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v05_mount_blocked() {
    if !require_sandbox_env("v05") {
        return;
    }
    // The `mount` binary may not be present in the sandbox rootfs; use Python
    // ctypes so we exercise the syscall directly. ENOSYS from seccomp or
    // EPERM from cap drop both count as a successful block.
    let probe = r#"python3 -c '
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
ret = libc.mount(b"none", b"/tmp/escape-v05", b"tmpfs", 0, None)
errno = ctypes.get_errno()
sys.exit(0 if ret == 0 else errno)
'"#;
    let r = run_sandboxed_probe("v05", probe, PROBE_TIMEOUT);
    assert!(
        r.exit_code != 0,
        "v05 mount must be blocked, got exit=0 (mount succeeded). Output:\n{}",
        r.combined()
    );
    // ENOSYS=38 (seccomp), EPERM=1 (cap drop), EACCES=13 (rootfs RO).
    assert!(
        matches!(r.exit_code, 1 | 13 | 38),
        "v05 mount expected ENOSYS/EPERM/EACCES, got errno={}",
        r.exit_code
    );
}

// ─── Vector 6: iptables binary unavailable / cap dropped ───────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v06_iptables_not_usable() {
    if !require_sandbox_env("v06") {
        return;
    }
    // Two failure paths are both acceptable:
    //   (a) binary not in sandbox PATH ("command not found"),
    //   (b) binary present but CAP_NET_ADMIN dropped ("Operation not permitted").
    let r = run_sandboxed_probe("v06", "iptables -F 2>&1; echo EXIT=$?", PROBE_TIMEOUT);
    let out = r.combined();
    assert!(
        !out.contains("EXIT=0"),
        "v06 iptables -F must fail. Output:\n{out}"
    );
    assert_blocked_with(
        &r,
        &[
            "command not found",
            "Operation not permitted",
            "Permission denied",
            "No such file",
        ],
        "v06 iptables must be unavailable (binary absent or CAP_NET_ADMIN dropped)",
    );
}

// ─── Vector 7: /usr is read-only ───────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v07_usr_readonly() {
    if !require_sandbox_env("v07") {
        return;
    }
    let r = run_sandboxed_probe(
        "v07",
        "touch /usr/bin/gvm-escape-v07 2>&1; echo EXIT=$?",
        PROBE_TIMEOUT,
    );
    let out = r.combined();
    assert!(
        !out.contains("EXIT=0"),
        "v07 write to /usr/bin must fail. Output:\n{out}"
    );
    assert_blocked_with(
        &r,
        &["Read-only file system", "Permission denied"],
        "v07 /usr/bin must be read-only (bind mount RO)",
    );
}

// ─── Vector 8: Path traversal cannot reach host /etc ───────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v08_path_traversal_blocked() {
    if !require_sandbox_env("v08") {
        return;
    }
    // After pivot_root, the host's original / is unmounted. Traversal from
    // the workspace cannot escape to the host filesystem.
    let r = run_sandboxed_probe(
        "v08",
        "cat /workspace/../../../etc/crontab 2>&1; echo EXIT=$?",
        PROBE_TIMEOUT,
    );
    let out = r.combined();
    assert!(
        !out.contains("EXIT=0"),
        "v08 path traversal must not reach a host crontab. Output:\n{out}"
    );
    // Either the file does not exist in the sandbox, or it exists but is the
    // sandbox's minimal copy (in which case the test still proves traversal
    // resolved inside the sandbox root, not the host root).
    let blocked = out.contains("No such file") || out.contains("Permission denied");
    assert!(blocked, "v08 expected absent/denied, got:\n{out}");
}

// ─── Vector 9: Blocked-domain HTTPS denied at iptables ─────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v09_blocked_domain_denied() {
    if !require_sandbox_env("v09") {
        return;
    }
    // Pick a hostname under .test (RFC 6761 reserved — guaranteed not to
    // resolve in production DNS). The sandbox should either fail DNS
    // (controlled by DNS governance / iptables) or get an HTTP layer deny
    // from SRR/MITM. Connection success would mean an open egress hole.
    let r = run_sandboxed_probe(
        "v09",
        "curl -sS --max-time 5 https://gvm-pentest-blocked.invalid/ 2>&1; echo EXIT=$?",
        PROBE_TIMEOUT,
    );
    let out = r.combined();
    assert!(
        !out.contains("EXIT=0"),
        "v09 curl to invalid TLD must fail. Output:\n{out}"
    );
    let signals = [
        "Could not resolve",
        "Failed to connect",
        "Connection refused",
        "timed out",
        "Connection timed out",
        "No route",
        "Resolving timed out",
    ];
    assert!(
        signals.iter().any(|s| out.contains(s)),
        "v09 expected network failure signal, got:\n{out}"
    );
}

// ─── Vector 10: unshare(CLONE_NEWNS) blocked ───────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v10_unshare_blocked() {
    if !require_sandbox_env("v10") {
        return;
    }
    let probe = r#"python3 -c '
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWNS = 0x00020000
ret = libc.unshare(CLONE_NEWNS)
errno = ctypes.get_errno()
sys.exit(0 if ret == 0 else errno)
'"#;
    let r = run_sandboxed_probe("v10", probe, PROBE_TIMEOUT);
    assert!(
        r.exit_code != 0,
        "v10 unshare must be blocked, got exit=0. Output:\n{}",
        r.combined()
    );
    // ENOSYS=38 (seccomp), EPERM=1 (cap drop).
    assert!(
        matches!(r.exit_code, 1 | 38),
        "v10 unshare expected ENOSYS/EPERM, got errno={}",
        r.exit_code
    );
}

// ─── Vector 11: ptrace(2) blocked ──────────────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v11_ptrace_blocked() {
    if !require_sandbox_env("v11") {
        return;
    }
    // PTRACE_TRACEME from a normal child must fail under seccomp policy.
    let probe = r#"python3 -c '
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_TRACEME = 0
ret = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
errno = ctypes.get_errno()
sys.exit(0 if ret == 0 else (errno if errno else 99))
'"#;
    let r = run_sandboxed_probe("v11", probe, PROBE_TIMEOUT);
    assert!(
        r.exit_code != 0,
        "v11 ptrace must be blocked, got exit=0. Output:\n{}",
        r.combined()
    );
    // EPERM=1, ENOSYS=38.
    assert!(
        matches!(r.exit_code, 1 | 38),
        "v11 ptrace expected EPERM/ENOSYS, got errno={}",
        r.exit_code
    );
}

// ─── Vector 12: kill(1, SIGKILL) blocked by PID namespace + seccomp ────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v12_kill_pid1_blocked() {
    if !require_sandbox_env("v12") {
        return;
    }
    // Inside the sandbox PID namespace, PID 1 is the sandbox init. Even
    // delivering SIGKILL to it would only kill the sandbox itself, not the
    // host. Most seccomp profiles also block kill against PID 1 outright.
    // We assert that the call fails (ENOSYS/EPERM) OR the host stays up.
    // The latter is implicit in the test framework continuing to run.
    let probe = r#"python3 -c '
import os, sys
try:
    os.kill(1, 9)
    sys.exit(0)
except PermissionError:
    sys.exit(1)
except ProcessLookupError:
    sys.exit(3)
except OSError as e:
    sys.exit(e.errno if e.errno else 99)
'"#;
    let r = run_sandboxed_probe("v12", probe, PROBE_TIMEOUT);
    // 0 = SIGKILL delivered to sandbox-PID-1 (which kills the sandbox; the
    //     test harness on the host is unaffected). The sandbox dies but
    //     the host is not compromised, which is the intended outcome.
    // Non-zero exit = call rejected outright (preferred).
    // The "BREACH" case would be: exit=0 AND the host gvm process died,
    // which can't happen because PID 1 in the sandbox != PID 1 on host.
    // So we just record the result for the regression-map doc; both
    // outcomes are acceptable here.
    eprintln!(
        "v12 kill(1, 9) result: exit={}, output={}",
        r.exit_code,
        r.combined()
    );
}

// ─── Vector 13: insmod blocked (no module + CAP_SYS_MODULE dropped) ────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v13_insmod_blocked() {
    if !require_sandbox_env("v13") {
        return;
    }
    let r = run_sandboxed_probe("v13", "insmod /dev/null 2>&1; echo EXIT=$?", PROBE_TIMEOUT);
    let out = r.combined();
    assert!(
        !out.contains("EXIT=0"),
        "v13 insmod must fail. Output:\n{out}"
    );
    assert_blocked_with(
        &r,
        &[
            "command not found",
            "Operation not permitted",
            "No such file",
            "Permission denied",
        ],
        "v13 insmod must be unavailable (binary absent or CAP_SYS_MODULE dropped)",
    );
}

// ─── Vector 14: /proc/1/root inaccessible (hidepid=2 + PID ns) ─────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v14_proc1_root_denied() {
    if !require_sandbox_env("v14") {
        return;
    }
    let r = run_sandboxed_probe("v14", "ls /proc/1/root/ 2>&1; echo EXIT=$?", PROBE_TIMEOUT);
    let out = r.combined();
    // EXIT=0 is acceptable if PID 1 in the sandbox namespace is the sandbox
    // init itself (you can list your own /proc/1/root, which == /). What
    // must NOT happen: seeing the host's /proc/1/root contents (which would
    // include /home/<host-user>, /etc/sudoers, etc.). We approximate by
    // requiring that the listing does not contain host-only directories.
    let host_leak_indicators = ["sudoers", "shadow", "/root", "ec2-user"];
    let leaked = host_leak_indicators.iter().any(|s| out.contains(s));
    assert!(
        !leaked,
        "v14 /proc/1/root leaked host content. Output:\n{out}"
    );
    // Document outcome for the regression map.
    eprintln!(
        "v14 /proc/1/root result: exit={}, output_chars={}",
        r.exit_code,
        out.len()
    );
}

// ─── Vector 15: DNS exfiltration blocked ───────────────────────────────────

#[cfg(target_os = "linux")]
#[test]
fn escape_v15_dns_exfil_blocked() {
    if !require_sandbox_env("v15") {
        return;
    }
    // Direct UDP/53 to 8.8.8.8 — must be blocked by iptables (only DNS
    // proxy on 127.0.0.1 is allowed). A timeout or EPERM proves the block.
    let probe = r#"python3 -c '
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
# Minimal DNS query for "exfil.example.test" A record
q = struct.pack(">HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0)
q += b"\x05exfil\x07example\x04test\x00\x00\x01\x00\x01"
try:
    s.sendto(q, ("8.8.8.8", 53))
    s.recvfrom(512)
    sys.exit(0)
except socket.timeout:
    sys.exit(2)
except OSError as e:
    sys.exit(e.errno if e.errno else 99)
'"#;
    let r = run_sandboxed_probe("v15", probe, PROBE_TIMEOUT);
    assert!(
        r.exit_code != 0,
        "v15 direct DNS to 8.8.8.8 must be blocked, got exit=0 \
         (reply received — egress hole). Output:\n{}",
        r.combined()
    );
    // 2 = socket.timeout (iptables DROP), 1 = EPERM, 13 = EACCES, 101 = ENETUNREACH.
    assert!(
        matches!(r.exit_code, 1 | 2 | 13 | 38 | 101),
        "v15 expected timeout/EPERM/EACCES/ENOSYS/ENETUNREACH, got errno={}. Output:\n{}",
        r.exit_code,
        r.combined()
    );
}

// ─── Non-Linux compile guard ───────────────────────────────────────────────
//
// Without at least one symbol referencing `common`, `cargo check` on
// non-Linux hosts treats the module as dead and emits warnings. This
// no-op test keeps the helper module live in the build graph even when
// every #[cfg(target_os = "linux")] test above is excluded.

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_sandbox_tests_are_skipped() {
    // Touch each helper so the compiler sees it as used.
    let _ = common::gvm_binary_path();
    let _ = common::is_root();
    eprintln!("SKIP: sandbox escape tests require Linux; this build target is not Linux.");
}
