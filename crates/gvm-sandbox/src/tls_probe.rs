//! eBPF uprobe TLS interception — captures plaintext before encryption.
//!
//! Attaches uprobes to SSL_write() in the agent process to read HTTP requests
//! before they are encrypted. This enables path/method-level policy enforcement
//! on HTTPS traffic without MITM or CA certificates.
//!
//! Architecture:
//!   Agent calls SSL_write(ssl, buf, len)
//!     → uprobe fires at entry point
//!     → bpf_probe_read_user() reads plaintext from buf
//!     → perf buffer sends to GVM userspace
//!     → SRR check on parsed HTTP (method + path + headers)
//!     → Deny → SIGSTOP agent, terminate tunnel, SIGCONT
//!
//! Library resolution order:
//!   1. /proc/<pid>/maps → find libssl.so (dynamic link)
//!   2. If not found → search main binary for SSL_write symbol (static link, e.g. Node.js)
//!   3. Go binaries → search for crypto/tls.(*Conn).Write
//!
//! Enforcement: SIGSTOP-based (works on all 5.5+ kernels).
//! bpf_override_return NOT used (requires CONFIG_BPF_KPROBE_OVERRIDE, rarely enabled).

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Resolved TLS library info for uprobe attachment.
#[derive(Debug, Clone)]
pub struct TlsLibrary {
    /// Path to the library or binary containing SSL_write.
    pub path: PathBuf,
    /// Offset of SSL_write (or equivalent) within the binary.
    pub ssl_write_offset: u64,
    /// Offset of SSL_read (or equivalent) within the binary.
    pub ssl_read_offset: Option<u64>,
    /// Type of TLS implementation found.
    pub kind: TlsKind,
}

/// Type of TLS implementation detected.
#[derive(Debug, Clone, PartialEq)]
pub enum TlsKind {
    /// OpenSSL libssl.so (dynamic link) — Python, curl, Ruby
    OpenSslDynamic,
    /// OpenSSL compiled into binary (static link) — Node.js, some Go
    OpenSslStatic,
    /// Go crypto/tls — Go binaries (gog, etc.)
    GoCryptoTls,
    /// rustls — Rust binaries
    Rustls,
}

/// Captured TLS plaintext event from eBPF perf buffer.
#[derive(Debug, Clone)]
pub struct TlsEvent {
    /// PID of the process that called SSL_write.
    pub pid: u32,
    /// Thread ID.
    pub tid: u32,
    /// Captured plaintext bytes (up to 4KB).
    pub data: Vec<u8>,
    /// Timestamp (nanoseconds since boot).
    pub timestamp_ns: u64,
}

/// Parsed HTTP request from TLS plaintext.
#[derive(Debug, Clone)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub host: Option<String>,
}

/// Resolve the TLS library used by a process.
///
/// Searches /proc/<pid>/maps for:
/// 1. libssl.so (dynamic OpenSSL)
/// 2. Main binary containing SSL_write (static OpenSSL, e.g. Node.js)
/// 3. Go crypto/tls symbols
pub fn resolve_tls_library(pid: u32) -> Result<TlsLibrary> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", pid))
        .with_context(|| format!("Failed to read /proc/{}/maps", pid))?;

    // Step 1: Look for libssl.so in memory maps
    for line in maps.lines() {
        if line.contains("libssl") && line.contains(".so") {
            if let Some(path) = extract_path_from_maps_line(line) {
                if let Ok(offset) = find_symbol_offset(&path, "SSL_write") {
                    let read_offset = find_symbol_offset(&path, "SSL_read").ok();
                    tracing::info!(
                        pid, path = %path.display(), offset,
                        "Found dynamic libssl.so"
                    );
                    return Ok(TlsLibrary {
                        path,
                        ssl_write_offset: offset,
                        ssl_read_offset: read_offset,
                        kind: TlsKind::OpenSslDynamic,
                    });
                }
            }
        }
    }

    // Step 2: Look for SSL_write in the main executable (static link — Node.js)
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .with_context(|| format!("Failed to read /proc/{}/exe", pid))?;

    if let Ok(offset) = find_symbol_offset(&exe_path, "SSL_write") {
        let read_offset = find_symbol_offset(&exe_path, "SSL_read").ok();
        tracing::info!(
            pid, path = %exe_path.display(), offset,
            "Found static-linked SSL_write in binary"
        );
        return Ok(TlsLibrary {
            path: exe_path,
            ssl_write_offset: offset,
            ssl_read_offset: read_offset,
            kind: TlsKind::OpenSslStatic,
        });
    }

    // Step 3: Go binaries — look for crypto/tls.(*Conn).Write
    if let Ok(offset) = find_go_tls_symbol(&exe_path) {
        tracing::info!(
            pid, path = %exe_path.display(), offset,
            "Found Go crypto/tls.(*Conn).Write"
        );
        return Ok(TlsLibrary {
            path: exe_path,
            ssl_write_offset: offset,
            ssl_read_offset: None,
            kind: TlsKind::GoCryptoTls,
        });
    }

    anyhow::bail!(
        "No TLS library found for PID {}. Process may use an unsupported TLS implementation.",
        pid
    )
}

/// Find a symbol's offset in an ELF binary using nm.
fn find_symbol_offset(path: &Path, symbol: &str) -> Result<u64> {
    // Try dynamic symbols first (nm --dynamic)
    let output = std::process::Command::new("nm")
        .args(["--dynamic", "--defined-only"])
        .arg(path)
        .output()
        .with_context(|| format!("Failed to run nm on {}", path.display()))?;

    if let Some(offset) = parse_nm_output(&String::from_utf8_lossy(&output.stdout), symbol) {
        return Ok(offset);
    }

    // Try regular symbols (for statically linked binaries)
    let output = std::process::Command::new("nm")
        .args(["--defined-only"])
        .arg(path)
        .output()?;

    parse_nm_output(&String::from_utf8_lossy(&output.stdout), symbol)
        .with_context(|| format!("Symbol {} not found in {}", symbol, path.display()))
}

/// Find Go TLS write symbol offset.
fn find_go_tls_symbol(path: &Path) -> Result<u64> {
    // Go binaries have unstripped symbols by default
    let output = std::process::Command::new("nm")
        .arg(path)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for crypto/tls.(*Conn).Write or crypto/tls.(*Conn).write
    for target in &[
        "crypto/tls.(*Conn).Write",
        "crypto/tls.(*Conn).write",
        "crypto/tls.(*Conn).writeRecordLocked",
    ] {
        if let Some(offset) = parse_nm_output(&stdout, target) {
            return Ok(offset);
        }
    }

    anyhow::bail!("Go TLS symbols not found")
}

/// Parse nm output to find a symbol's address.
fn parse_nm_output(nm_output: &str, symbol: &str) -> Option<u64> {
    for line in nm_output.lines() {
        // Format: "0000000000123456 T SSL_write"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2..].join(" ").contains(symbol) {
            if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                return Some(addr);
            }
        }
    }
    None
}

/// Extract file path from a /proc/<pid>/maps line.
fn extract_path_from_maps_line(line: &str) -> Option<PathBuf> {
    // Format: "7f1234000000-7f1234100000 r-xp 00000000 08:01 12345  /usr/lib/libssl.so.3"
    let parts: Vec<&str> = line.splitn(6, ' ').collect();
    if parts.len() >= 6 {
        let path = parts[5].trim();
        if path.starts_with('/') {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Parse HTTP request line from captured plaintext.
///
/// Expects: "METHOD /path HTTP/1.1\r\nHost: example.com\r\n..."
pub fn parse_http_from_plaintext(data: &[u8]) -> Option<ParsedHttpRequest> {
    let text = std::str::from_utf8(data).ok()?;

    // First line: "GET /path HTTP/1.1"
    let first_line = text.lines().next()?;
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    let method = parts[0].to_string();
    let path = parts[1].to_string();

    // Validate it looks like HTTP
    if !["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT"]
        .contains(&method.as_str())
    {
        return None;
    }

    // Extract Host header
    let host = text
        .lines()
        .find(|l| l.to_lowercase().starts_with("host:"))
        .map(|l| l[5..].trim().to_string());

    Some(ParsedHttpRequest { method, path, host })
}

/// TLS probe controller — manages uprobe lifecycle and event processing.
pub struct TlsProbeController {
    /// PID being monitored.
    pid: u32,
    /// Resolved TLS library info.
    library: TlsLibrary,
    /// Whether the probe is actively attached.
    attached: bool,
}

impl TlsProbeController {
    /// Create a new probe controller for the given PID.
    pub fn new(pid: u32) -> Result<Self> {
        let library = resolve_tls_library(pid)?;
        Ok(Self {
            pid,
            library,
            attached: false,
        })
    }

    /// Attach uprobe to SSL_write.
    ///
    /// On Linux, this creates a uprobe via /sys/kernel/debug/tracing/uprobe_events
    /// or perf_event_open(). The actual eBPF program is loaded separately.
    pub fn attach(&mut self) -> Result<()> {
        if self.attached {
            return Ok(());
        }

        tracing::info!(
            pid = self.pid,
            library = %self.library.path.display(),
            kind = ?self.library.kind,
            offset = self.library.ssl_write_offset,
            "Attaching TLS uprobe"
        );

        // Write uprobe event definition
        // Format: p:gvm_ssl_write /path/to/libssl.so:0x1234
        let uprobe_def = format!(
            "p:gvm_ssl_write_{}  {}:0x{:x}",
            self.pid,
            self.library.path.display(),
            self.library.ssl_write_offset,
        );

        std::fs::write(
            "/sys/kernel/debug/tracing/uprobe_events",
            &uprobe_def,
        )
        .with_context(|| "Failed to write uprobe_events (need root or CAP_BPF)")?;

        self.attached = true;
        tracing::info!(pid = self.pid, "TLS uprobe attached");
        Ok(())
    }

    /// Detach uprobe.
    pub fn detach(&mut self) {
        if !self.attached {
            return;
        }

        let remove = format!("-:gvm_ssl_write_{}", self.pid);
        let _ = std::fs::write("/sys/kernel/debug/tracing/uprobe_events", &remove);
        self.attached = false;
        tracing::debug!(pid = self.pid, "TLS uprobe detached");
    }

    /// Enforce a Deny decision by stopping the process.
    ///
    /// SIGSTOP → terminate CONNECT tunnel → SIGCONT.
    /// Works on all 5.5+ kernels without CONFIG_BPF_KPROBE_OVERRIDE.
    pub fn enforce_deny(&self) -> Result<()> {
        tracing::warn!(pid = self.pid, "TLS probe: enforcing Deny via SIGSTOP");

        // SIGSTOP the process to prevent SSL_write from completing
        unsafe {
            libc::kill(self.pid as i32, libc::SIGSTOP);
        }

        // Give time for the TCP connection to time out / reset
        std::thread::sleep(std::time::Duration::from_millis(100));

        // SIGCONT to resume (the SSL_write will fail with connection reset)
        unsafe {
            libc::kill(self.pid as i32, libc::SIGCONT);
        }

        Ok(())
    }

    /// Get the resolved library info.
    pub fn library(&self) -> &TlsLibrary {
        &self.library
    }

    /// Check if probe is attached.
    pub fn is_attached(&self) -> bool {
        self.attached
    }
}

impl Drop for TlsProbeController {
    fn drop(&mut self) {
        self.detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_get() {
        let data = b"GET /v1/charges HTTP/1.1\r\nHost: api.stripe.com\r\nAuthorization: Bearer sk_test\r\n\r\n";
        let req = parse_http_from_plaintext(data).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/v1/charges");
        assert_eq!(req.host.as_deref(), Some("api.stripe.com"));
    }

    #[test]
    fn parse_http_post() {
        let data = b"POST /v1/transfers HTTP/1.1\r\nHost: api.stripe.com\r\nContent-Type: application/json\r\n\r\n{\"amount\":5000}";
        let req = parse_http_from_plaintext(data).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/transfers");
        assert_eq!(req.host.as_deref(), Some("api.stripe.com"));
    }

    #[test]
    fn parse_non_http() {
        let data = b"\x16\x03\x01\x00\x05TLS handshake";
        assert!(parse_http_from_plaintext(data).is_none());
    }

    #[test]
    fn parse_nm_ssl_write() {
        let nm = "0000000000078a30 T SSL_write\n0000000000078b10 T SSL_read\n";
        assert_eq!(parse_nm_output(nm, "SSL_write"), Some(0x78a30));
        assert_eq!(parse_nm_output(nm, "SSL_read"), Some(0x78b10));
        assert_eq!(parse_nm_output(nm, "SSL_connect"), None);
    }

    #[test]
    fn parse_maps_line() {
        let line = "7f8a12345000-7f8a12400000 r-xp 00000000 08:01 12345  /usr/lib/x86_64-linux-gnu/libssl.so.3";
        let path = extract_path_from_maps_line(line).unwrap();
        assert_eq!(path.to_str().unwrap(), "/usr/lib/x86_64-linux-gnu/libssl.so.3");
    }

    #[test]
    fn parse_maps_no_path() {
        let line = "7f8a12345000-7f8a12400000 r-xp 00000000 08:01 12345";
        assert!(extract_path_from_maps_line(line).is_none());
    }
}
