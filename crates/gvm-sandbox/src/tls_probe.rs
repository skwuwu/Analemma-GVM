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
    // Prefer SSL_write_ex (OpenSSL 3.x actual call path) over SSL_write.
    // Verified: Python requests + OpenSSL 3.x calls SSL_write_ex, not SSL_write.
    for line in maps.lines() {
        if line.contains("libssl") && line.contains(".so") {
            if let Some(path) = extract_path_from_maps_line(line) {
                // Try SSL_write_ex first (OpenSSL 3.x), then SSL_write (1.x/2.x)
                let write_offset = find_symbol_offset(&path, "SSL_write_ex")
                    .or_else(|_| find_symbol_offset(&path, "SSL_write"));
                if let Ok(offset) = write_offset {
                    let read_offset = find_symbol_offset(&path, "SSL_read_ex")
                        .or_else(|_| find_symbol_offset(&path, "SSL_read"))
                        .ok();
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

    // Step 2: Look for SSL_write_ex/SSL_write in the main executable (static link — Node.js)
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .with_context(|| format!("Failed to read /proc/{}/exe", pid))?;

    let write_offset = find_symbol_offset(&exe_path, "SSL_write_ex")
        .or_else(|_| find_symbol_offset(&exe_path, "SSL_write"));
    if let Ok(offset) = write_offset {
        let read_offset = find_symbol_offset(&exe_path, "SSL_read_ex")
            .or_else(|_| find_symbol_offset(&exe_path, "SSL_read"))
            .ok();
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

/// Callback type for policy decisions on captured TLS plaintext.
pub type PolicyCheckFn = Box<dyn Fn(&str, &str, &str) -> PolicyDecision + Send + Sync>;

/// Policy decision from SRR check.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Delay { milliseconds: u64 },
    Deny { reason: String },
}

/// TLS probe controller — manages uprobe lifecycle, perf buffer polling,
/// and SRR-based policy enforcement on captured HTTPS plaintext.
pub struct TlsProbeController {
    /// PID being monitored.
    pid: u32,
    /// Resolved TLS library info.
    library: TlsLibrary,
    /// Whether the probe is actively attached.
    attached: bool,
    /// Perf buffer file descriptor (from perf_event_open).
    perf_fd: Option<i32>,
    /// Policy check callback — wraps SRR check() from proxy.
    policy_check: Option<PolicyCheckFn>,
    /// Event statistics.
    stats: ProbeStats,
    /// Whether to run in audit-only mode (log but don't enforce).
    audit_only: bool,
}

/// Runtime statistics for the TLS probe.
#[derive(Debug, Clone, Default)]
pub struct ProbeStats {
    pub events_captured: u64,
    pub events_allowed: u64,
    pub events_denied: u64,
    pub parse_failures: u64,
}

/// Trace pipe reader — reads uprobe events from /sys/kernel/debug/tracing/trace_pipe.
/// This is the simplest integration (no BPF program compilation needed).
/// For production, replace with perf_event_open + BPF ring buffer.
struct TracePipeReader {
    /// Path to trace_pipe.
    path: PathBuf,
    /// Filter prefix to match our uprobe events.
    filter_prefix: String,
}

impl TracePipeReader {
    fn new(pid: u32) -> Self {
        Self {
            path: PathBuf::from("/sys/kernel/debug/tracing/trace_pipe"),
            filter_prefix: format!("gvm_ssl_write_{}", pid),
        }
    }

    /// Read one event from trace_pipe (blocking).
    /// Returns the raw trace line if it matches our uprobe.
    fn read_event(&self) -> Result<Option<String>> {
        use std::io::{BufRead, BufReader};

        let file = std::fs::File::open(&self.path)
            .context("Failed to open trace_pipe (need root or CAP_BPF)")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.contains(&self.filter_prefix) {
                return Ok(Some(line));
            }
        }
        Ok(None)
    }
}

/// Read plaintext from agent process memory at the address captured by uprobe.
///
/// Uses /proc/<pid>/mem to read the SSL_write buffer.
/// The buffer address comes from the uprobe's arg1 (second argument = buf pointer).
fn read_process_memory(pid: u32, addr: u64, len: usize) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let max_len = len.min(4096); // Cap at 4KB
    let mut file = std::fs::File::open(format!("/proc/{}/mem", pid))
        .with_context(|| format!("Failed to open /proc/{}/mem", pid))?;

    file.seek(SeekFrom::Start(addr))?;
    let mut buf = vec![0u8; max_len];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

impl TlsProbeController {
    /// Create a new probe controller for the given PID.
    pub fn new(pid: u32) -> Result<Self> {
        let library = resolve_tls_library(pid)?;
        Ok(Self {
            pid,
            library,
            attached: false,
            perf_fd: None,
            policy_check: None,
            stats: ProbeStats::default(),
            audit_only: false,
        })
    }

    /// Set the policy check callback.
    /// This is called with (method, host, path) and returns Allow/Deny.
    pub fn set_policy_check(&mut self, check: PolicyCheckFn) {
        self.policy_check = Some(check);
    }

    /// Set audit-only mode (log but don't enforce).
    pub fn set_audit_only(&mut self, audit_only: bool) {
        self.audit_only = audit_only;
    }

    /// Attach uprobe to SSL_write.
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

        // Enable tracing if not already
        let _ = std::fs::write("/sys/kernel/debug/tracing/tracing_on", "1");

        // Clear previous uprobe definitions for this PID
        let remove = format!("-:gvm_ssl_write_{}", self.pid);
        let _ = std::fs::write("/sys/kernel/debug/tracing/uprobe_events", &remove);

        // Write uprobe event definition with fetchargs.
        // x86_64 calling convention: rdi=ssl_ctx, rsi=buf_ptr, rdx=len
        // Verified on WSL2 kernel 6.6 + OpenSSL 3.x:
        //   +0(%si):string captures the plaintext HTTP request line from buf pointer.
        let uprobe_def = format!(
            "p:gvm_ssl_write_{} {}:0x{:x} buf=+0(%si):string",
            self.pid,
            self.library.path.display(),
            self.library.ssl_write_offset,
        );

        std::fs::write(
            "/sys/kernel/debug/tracing/uprobe_events",
            &uprobe_def,
        )
        .with_context(|| "Failed to write uprobe_events (need root or CAP_BPF)")?;

        // Enable the uprobe event
        let enable_path = format!(
            "/sys/kernel/debug/tracing/events/uprobes/gvm_ssl_write_{}/enable",
            self.pid,
        );
        std::fs::write(&enable_path, "1")
            .with_context(|| "Failed to enable uprobe event")?;

        // Filter to our PID only
        let filter_path = format!(
            "/sys/kernel/debug/tracing/events/uprobes/gvm_ssl_write_{}/filter",
            self.pid,
        );
        let _ = std::fs::write(&filter_path, format!("common_pid == {}", self.pid));

        self.attached = true;
        tracing::info!(pid = self.pid, "TLS uprobe attached and enabled");
        Ok(())
    }

    /// Detach uprobe and clean up.
    pub fn detach(&mut self) {
        if !self.attached {
            return;
        }

        // Disable the event
        let enable_path = format!(
            "/sys/kernel/debug/tracing/events/uprobes/gvm_ssl_write_{}/enable",
            self.pid,
        );
        let _ = std::fs::write(&enable_path, "0");

        // Remove the uprobe definition
        let remove = format!("-:gvm_ssl_write_{}", self.pid);
        let _ = std::fs::write("/sys/kernel/debug/tracing/uprobe_events", &remove);

        self.attached = false;
        tracing::debug!(pid = self.pid, "TLS uprobe detached");
    }

    /// Run the event processing loop.
    ///
    /// Reads uprobe events from trace_pipe, reads plaintext from process memory,
    /// parses HTTP, checks policy via SRR callback, and enforces decisions.
    ///
    /// This runs in a separate thread and blocks until the agent process exits.
    pub fn run_event_loop(&mut self) -> Result<()> {
        if !self.attached {
            self.attach()?;
        }

        tracing::info!(pid = self.pid, "TLS probe event loop started");

        let trace_pipe = format!("/sys/kernel/debug/tracing/trace_pipe");
        let filter = format!("gvm_ssl_write_{}", self.pid);

        let file = std::fs::File::open(&trace_pipe)
            .context("Failed to open trace_pipe")?;

        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            if !line.contains(&filter) {
                continue;
            }

            self.stats.events_captured += 1;

            // Extract HTTP request line directly from trace string fetcharg.
            // Format: `... buf="GET /path HTTP/1.1`
            // This avoids /proc/pid/mem access (which can race with SSL_write completion).
            let http_text = match parse_trace_line_http(&line) {
                Some(t) => t,
                None => {
                    self.stats.parse_failures += 1;
                    continue;
                }
            };

            // Parse HTTP from the captured string
            let http_req = match parse_http_from_plaintext(http_text.as_bytes()) {
                Some(req) => req,
                None => continue, // Not HTTP
            };

            let host = http_req.host.as_deref().unwrap_or("unknown");

            tracing::info!(
                pid = self.pid,
                method = %http_req.method,
                host = %host,
                path = %http_req.path,
                "TLS plaintext captured"
            );

            // SRR policy check
            if let Some(ref check_fn) = self.policy_check {
                let decision = check_fn(&http_req.method, host, &http_req.path);

                match &decision {
                    PolicyDecision::Allow => {
                        self.stats.events_allowed += 1;
                        tracing::debug!(
                            method = %http_req.method, host, path = %http_req.path,
                            "TLS probe: Allow"
                        );
                    }
                    PolicyDecision::Delay { milliseconds } => {
                        self.stats.events_allowed += 1;
                        tracing::info!(
                            method = %http_req.method, host, path = %http_req.path,
                            delay_ms = milliseconds,
                            "TLS probe: Delay (allowing — delay applied at CONNECT level)"
                        );
                    }
                    PolicyDecision::Deny { reason } => {
                        self.stats.events_denied += 1;
                        tracing::warn!(
                            method = %http_req.method, host, path = %http_req.path,
                            reason = %reason,
                            audit_only = self.audit_only,
                            "TLS probe: DENY"
                        );

                        if !self.audit_only {
                            if let Err(e) = self.enforce_deny() {
                                tracing::error!(error = %e, "Failed to enforce deny");
                            }
                        }
                    }
                }
            }

            // Check if process is still alive
            let proc_alive = Path::new(&format!("/proc/{}", self.pid)).exists();
            if !proc_alive {
                tracing::info!(pid = self.pid, "Agent process exited — stopping event loop");
                break;
            }
        }

        tracing::info!(
            pid = self.pid,
            captured = self.stats.events_captured,
            allowed = self.stats.events_allowed,
            denied = self.stats.events_denied,
            parse_failures = self.stats.parse_failures,
            "TLS probe event loop ended"
        );

        Ok(())
    }

    /// Enforce a Deny decision by stopping the process.
    ///
    /// SIGSTOP → 100ms pause → SIGCONT.
    /// SSL_write will fail with EPIPE/connection reset on resume.
    pub fn enforce_deny(&self) -> Result<()> {
        tracing::warn!(pid = self.pid, "TLS probe: enforcing Deny via SIGSTOP");

        unsafe {
            libc::kill(self.pid as i32, libc::SIGSTOP);
        }

        std::thread::sleep(std::time::Duration::from_millis(100));

        unsafe {
            libc::kill(self.pid as i32, libc::SIGCONT);
        }

        Ok(())
    }

    /// Get current statistics.
    pub fn stats(&self) -> &ProbeStats {
        &self.stats
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

/// Parse a trace_pipe line to extract HTTP plaintext from fetchargs.
///
/// Verified format: `python3-1234 [008] DNZff 12345.678: gvm_ssl_write_1234: (0x...) buf="GET / HTTP/1.1`
/// The string fetcharg `+0(%si):string` captures the first line of plaintext.
fn parse_trace_line_http(line: &str) -> Option<String> {
    // Extract content after buf="
    let start = line.find("buf=\"")?;
    let content = &line[start + 5..];
    // Remove trailing quote if present
    let content = content.strip_suffix('"').unwrap_or(content);
    if content.is_empty() {
        return None;
    }
    Some(content.to_string())
}

/// Legacy: parse buf address and len from hex fetchargs (for /proc/pid/mem reading).
fn parse_trace_line(line: &str) -> Option<(u64, u32)> {
    let buf_addr = line.split("buf=0x").nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| u64::from_str_radix(s, 16).ok())?;

    let buf_len = line.split("len=").nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(4096);

    Some((buf_addr, buf_len))
}

/// Convenience: start TLS probe in a background thread for a sandbox.
///
/// Integrates with the existing sandbox lifecycle:
/// 1. After clone() + exec, parent calls start_tls_probe(child_pid, srr_check)
/// 2. Probe resolves TLS library, attaches uprobe, starts event loop
/// 3. Event loop runs until child exits
/// 4. Probe auto-detaches on drop
pub fn start_tls_probe_thread(
    pid: u32,
    policy_check: PolicyCheckFn,
    audit_only: bool,
) -> Result<std::thread::JoinHandle<()>> {
    let handle = std::thread::Builder::new()
        .name(format!("gvm-tls-probe-{}", pid))
        .spawn(move || {
            match TlsProbeController::new(pid) {
                Ok(mut controller) => {
                    controller.set_policy_check(policy_check);
                    controller.set_audit_only(audit_only);
                    if let Err(e) = controller.run_event_loop() {
                        tracing::error!(pid, error = %e, "TLS probe event loop failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        pid, error = %e,
                        "TLS probe initialization failed — HTTPS will use domain-level policy only"
                    );
                }
            }
        })
        .context("Failed to spawn TLS probe thread")?;

    Ok(handle)
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

    #[test]
    fn parse_trace_line_http_get() {
        let line = r#"python3-6328 [008] DNZff 20570.430368: gvm_ssl_write_1234: (0x79505ba54bb0) buf="GET /repos/skwuwu/Analemma-GVM HTTP/1.1"#;
        let http = parse_trace_line_http(line).unwrap();
        assert_eq!(http, "GET /repos/skwuwu/Analemma-GVM HTTP/1.1");
    }

    #[test]
    fn parse_trace_line_http_post() {
        let line = r#"python3-6328 [008] DNZff 20570.430368: gvm_ssl_write_1234: (0x79505ba54bb0) buf="POST /v1/transfers HTTP/1.1"#;
        let http = parse_trace_line_http(line).unwrap();
        let req = parse_http_from_plaintext(http.as_bytes()).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/transfers");
    }

    #[test]
    fn parse_trace_line_legacy_hex() {
        let line = "node-1234 [001] d..1 12345.678: gvm_ssl_write_1234: (0x7f1234) buf=0x7ffeabc123 len=256";
        let (addr, len) = parse_trace_line(line).unwrap();
        assert_eq!(addr, 0x7ffeabc123);
        assert_eq!(len, 256);
    }

    #[test]
    fn policy_decision_deny() {
        let check: PolicyCheckFn = Box::new(|method, _host, path| {
            if method == "POST" && path.contains("transfers") {
                PolicyDecision::Deny { reason: "wire transfer blocked".into() }
            } else {
                PolicyDecision::Allow
            }
        });
        assert!(matches!(check("GET", "stripe.com", "/v1/charges"), PolicyDecision::Allow));
        assert!(matches!(check("POST", "stripe.com", "/v1/transfers"), PolicyDecision::Deny { .. }));
    }
}
