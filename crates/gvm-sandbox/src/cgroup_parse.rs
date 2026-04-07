//! Pure parsers for cgroup v2 stat files.
//!
//! Kept in a dedicated module (not gated on `target_os = "linux"`) so the
//! parsers can be unit-tested on Windows/macOS dev hosts. The runtime cgroup
//! reader (`crate::cgroup`) is linux-only and calls these parsers.

// Functions are only consumed on Linux (cgroup module is linux-only),
// but the file itself stays cross-platform so the unit tests run anywhere.
#![allow(dead_code)]

/// Parse the `oom_kill` counter from a cgroup `memory.events` file.
///
/// Format (one key per line):
/// ```text
/// low 0
/// high 0
/// max 0
/// oom 1
/// oom_kill 1
/// ```
/// Returns 0 if the field is missing or unparseable (graceful fallback —
/// older kernels may not expose `oom_kill`).
pub fn parse_oom_kill_count(content: &str) -> u64 {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("oom_kill") {
            return parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        }
    }
    0
}

/// Parse `throttled_usec` from a cgroup `cpu.stat` file.
///
/// Format (subset):
/// ```text
/// usage_usec 1234
/// nr_throttled 5
/// throttled_usec 12345
/// ```
/// Returns `None` if the field is missing (CPU controller not enabled),
/// `Some(0)` if the cgroup never throttled.
pub fn parse_cpu_throttled_us(content: &str) -> Option<u64> {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some("throttled_usec") {
            return parts.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_events_no_oom() {
        let content = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n";
        assert_eq!(parse_oom_kill_count(content), 0);
    }

    #[test]
    fn parse_memory_events_with_oom() {
        let content = "low 0\nhigh 2\nmax 1\noom 3\noom_kill 3\n";
        assert_eq!(parse_oom_kill_count(content), 3);
    }

    #[test]
    fn parse_memory_events_missing_field() {
        // Older kernels may not expose oom_kill — fall back to 0.
        let content = "low 0\nhigh 0\n";
        assert_eq!(parse_oom_kill_count(content), 0);
    }

    #[test]
    fn parse_memory_events_empty() {
        assert_eq!(parse_oom_kill_count(""), 0);
    }

    #[test]
    fn parse_memory_events_garbage_value() {
        // Malformed counter — must not panic, must return 0.
        let content = "oom_kill not_a_number\n";
        assert_eq!(parse_oom_kill_count(content), 0);
    }

    #[test]
    fn parse_cpu_stat_throttled() {
        let content = "usage_usec 1234567\nuser_usec 1000000\nsystem_usec 234567\n\
                       nr_periods 50\nnr_throttled 5\nthrottled_usec 12345\n";
        assert_eq!(parse_cpu_throttled_us(content), Some(12345));
    }

    #[test]
    fn parse_cpu_stat_no_throttle() {
        let content = "usage_usec 1000\nnr_throttled 0\nthrottled_usec 0\n";
        assert_eq!(parse_cpu_throttled_us(content), Some(0));
    }

    #[test]
    fn parse_cpu_stat_missing_field() {
        // CPU controller not enabled — no throttle stats reported.
        let content = "usage_usec 1000\n";
        assert_eq!(parse_cpu_throttled_us(content), None);
    }
}
