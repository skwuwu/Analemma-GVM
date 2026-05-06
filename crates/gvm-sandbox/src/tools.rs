//! System-tool path resolution.
//!
//! Cleanup paths shell out to `iptables`, `ip`, `tc`, `iptables-save`,
//! `docker`, etc. via `Command::new(<bare-name>)`, which relies on the
//! caller's `PATH` to locate the binary. When the daemon launches under
//! a stripped `PATH` (systemd unit without `Environment=PATH=...`,
//! sudoers `secure_path` mismatch, container with no `/sbin` on PATH),
//! `Command::new` fails to spawn with `ENOENT` — and every cleanup
//! helper's trailing `.ok()` swallows the error. Resources leak silently.
//!
//! On Linux these tools live in well-known root-only locations
//! regardless of distro: `/usr/sbin/`, `/sbin/`, `/usr/local/sbin/`.
//! `resolve_tool` probes those first and falls back to the bare name
//! only when none match (preserving the legacy behaviour for systems
//! with `PATH` configured correctly).
//!
//! Resolution is cached per-tool via `OnceLock` — first call walks the
//! probe list, subsequent calls return the cached `PathBuf`.

use std::path::PathBuf;
use std::sync::OnceLock;

/// Standard locations to search, in priority order. Most distros put
/// `iptables` and `ip` in `/usr/sbin`; some still keep them in `/sbin`.
/// We include `/usr/local/sbin` for hand-installed tools and the `bin`
/// counterparts for tools like `docker` that aren't sbin-only.
const PROBE_DIRS: &[&str] = &[
    "/usr/sbin/",
    "/sbin/",
    "/usr/local/sbin/",
    "/usr/bin/",
    "/bin/",
    "/usr/local/bin/",
];

/// Resolve a tool name to an absolute path, cached after first resolution.
///
/// Returns the bare name as a `PathBuf` if no candidate path matches —
/// `Command::new` will then fall back to `PATH`, which is the legacy
/// behaviour. Logs a one-time warning so operators see the failure mode.
pub(crate) fn resolve_tool(name: &'static str) -> PathBuf {
    macro_rules! tool_slot {
        ($n:expr) => {{
            static SLOT: OnceLock<PathBuf> = OnceLock::new();
            SLOT.get_or_init(|| {
                for prefix in PROBE_DIRS {
                    let candidate = PathBuf::from(format!("{}{}", prefix, $n));
                    if candidate.is_file() {
                        return candidate;
                    }
                }
                tracing::warn!(
                    tool = $n,
                    "Tool not found in standard sbin/bin locations; \
                     falling back to PATH lookup. Cleanup may silently \
                     fail if the daemon's PATH doesn't include it."
                );
                PathBuf::from($n)
            })
            .clone()
        }};
    }

    match name {
        "iptables" => tool_slot!("iptables"),
        "iptables-save" => tool_slot!("iptables-save"),
        "ip6tables" => tool_slot!("ip6tables"),
        "ip" => tool_slot!("ip"),
        "tc" => tool_slot!("tc"),
        "docker" => tool_slot!("docker"),
        // For tools we haven't added an explicit slot for, fall back to
        // bare name (no caching). Add a slot above when a new tool is
        // introduced.
        other => PathBuf::from(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_tool_returns_some_path() {
        // We don't assert which path — the test runner may not have
        // every tool installed. We do assert the function returns a
        // non-empty PathBuf and is idempotent.
        let p1 = resolve_tool("ip");
        let p2 = resolve_tool("ip");
        assert!(!p1.as_os_str().is_empty());
        assert_eq!(p1, p2, "resolution must be cached and stable");
    }

    #[test]
    fn resolve_tool_unknown_falls_back_to_bare_name() {
        let p = resolve_tool("totally-not-a-real-tool");
        assert_eq!(p.to_string_lossy(), "totally-not-a-real-tool");
    }
}
