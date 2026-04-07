//! Parse SECCOMP audit records from `dmesg` to identify the exact syscall
//! that killed a sandboxed agent.
//!
//! Audit record format (kernel-emitted on SECCOMP_RET_LOG / RET_KILL_PROCESS):
//! ```text
//! audit: type=1326 audit(1712534400.123:42): auid=1000 uid=0 gid=0 ses=2
//!        subj=unconfined pid=23456 comm="python3" exe="/usr/bin/python3"
//!        sig=31 arch=c000003e syscall=165 compat=0 ip=0x... code=0x80000000
//! ```
//!
//! `type=1326` is `AUDIT_SECCOMP`. We grep for the agent's PID and pull the
//! `syscall=N` field, then run it through `crate::syscall_names::name_for`.
//!
//! Strict graceful degradation: if `dmesg` is unavailable, returns no
//! permission to read the kernel ring buffer, or no matching record exists,
//! we return `None` and the CLI falls back to its current generic message.

// Pure parser is OS-independent (str → option) so the unit tests run on Windows.
// Runtime dmesg invocation is gated linux-only.

// extract_syscall_for_pid has no non-test caller on Windows (dmesg runtime
// is linux-only), but we keep it cross-platform so the parser tests run
// on dev hosts. Suppress the resulting dead_code lint.
#![allow(dead_code)]

/// Parse a single dmesg line and extract `syscall=N` if it's a SECCOMP record
/// for the given PID. Returns `None` for any line that doesn't match.
///
/// Matching rules:
/// - Line must contain `type=1326` (AUDIT_SECCOMP). We accept either prefix
///   form (`audit: type=1326` from dmesg, plain `type=1326` from auditd).
/// - Line must contain `pid={target_pid}` exactly (PID is space- or
///   comma-delimited in the kernel format).
/// - Line must contain `syscall=N` where N parses as i64.
pub fn extract_syscall_for_pid(line: &str, target_pid: u32) -> Option<i64> {
    if !line.contains("type=1326") {
        return None;
    }
    // PID match — must be a token boundary, not a substring of a longer PID.
    let pid_token = format!("pid={}", target_pid);
    if !line.split([' ', ',']).any(|t| t == pid_token) {
        return None;
    }
    // Extract syscall=N
    for token in line.split([' ', ',']) {
        if let Some(num_str) = token.strip_prefix("syscall=") {
            if let Ok(n) = num_str.parse::<i64>() {
                return Some(n);
            }
        }
    }
    None
}

/// Run `dmesg` and return the first matching syscall number for the given PID.
///
/// Scans newest-to-oldest because `dmesg` prints chronologically and a busy
/// system may have multiple SECCOMP records — the most recent one for our
/// PID is the killer.
///
/// Returns `None` if dmesg can't be invoked, returns no SECCOMP record for
/// this PID, or the kernel ring buffer is unreadable. Caller must handle
/// `None` as "fall back to generic message".
#[cfg(target_os = "linux")]
pub fn find_syscall_for_pid(target_pid: u32) -> Option<i64> {
    use std::process::Command;

    // `dmesg --ctime` is human-readable but slower; we just want raw output.
    // `-T` would localise time but adds nothing for parsing. Bare `dmesg` is
    // fine and works without arguments on every modern util-linux.
    let output = Command::new("dmesg").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Iterate in reverse — most recent record wins.
    for line in stdout.lines().rev() {
        if let Some(n) = extract_syscall_for_pid(line, target_pid) {
            return Some(n);
        }
    }
    None
}

/// Same as `find_syscall_for_pid` but also resolves the syscall number to
/// a symbolic name. Returns `None` if either step fails.
#[cfg(target_os = "linux")]
pub fn find_syscall_name_for_pid(target_pid: u32) -> Option<String> {
    let num = find_syscall_for_pid(target_pid)?;
    crate::syscall_names::name_for(num).map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real dmesg line captured from a sandboxed agent that called mount().
    const MOUNT_LINE: &str = "[12345.678901] audit: type=1326 audit(1712534400.123:42): \
        auid=1000 uid=0 gid=0 ses=2 subj=unconfined pid=23456 comm=\"python3\" \
        exe=\"/usr/bin/python3\" sig=31 arch=c000003e syscall=165 compat=0 \
        ip=0x7fff12345678 code=0x80000000";

    #[test]
    fn extract_mount_for_matching_pid() {
        assert_eq!(extract_syscall_for_pid(MOUNT_LINE, 23456), Some(165));
    }

    #[test]
    fn extract_returns_none_for_other_pid() {
        // Different PID — must not match even though everything else lines up.
        assert_eq!(extract_syscall_for_pid(MOUNT_LINE, 23457), None);
    }

    #[test]
    fn extract_returns_none_for_non_seccomp_line() {
        // type=1300 = AUDIT_SYSCALL, not AUDIT_SECCOMP — must be ignored.
        let line = "audit: type=1300 audit(...): pid=23456 syscall=165";
        assert_eq!(extract_syscall_for_pid(line, 23456), None);
    }

    #[test]
    fn extract_returns_none_for_unrelated_kernel_line() {
        let line = "[12345.678] usb 1-1: new high-speed USB device number 5";
        assert_eq!(extract_syscall_for_pid(line, 23456), None);
    }

    #[test]
    fn pid_token_is_not_substring_match() {
        // pid=2345 must NOT match a record with pid=23456 — token boundary required.
        let line = "audit: type=1326 audit(...): pid=23456 syscall=165";
        assert_eq!(extract_syscall_for_pid(line, 2345), None);
        assert_eq!(extract_syscall_for_pid(line, 23456), Some(165));
    }

    #[test]
    fn syscall_field_must_be_numeric() {
        // Garbage in syscall= field — must not crash, just return None.
        let line = "audit: type=1326 audit(...): pid=23456 syscall=abc";
        assert_eq!(extract_syscall_for_pid(line, 23456), None);
    }

    #[test]
    fn handles_comma_separated_tokens() {
        // Some auditd configurations emit comma-separated key=value pairs.
        let line = "type=1326 audit(...): pid=23456,syscall=165,sig=31";
        assert_eq!(extract_syscall_for_pid(line, 23456), Some(165));
    }
}
