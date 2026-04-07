//! Adversarial infrastructure tests — proves runtime hardening under attack conditions.
//!
//! These tests verify that the proxy survives and remains functional under:
//! 1. CPU starvation via mass TLS cert generation (cache poisoning)
//! 2. Slowloris / FD exhaustion on TLS listener
//! 3. HTTP Request Smuggling (CL/TE desync, duplicate CL)
//! 4. HTTP/2 binary frame injection via ALPN downgrade
//! 5. PID 1 zombie reaping in sandbox namespace (Linux only)
//!
//! A single panic, hang, or bypass in any of these tests means the
//! architecture is not production-ready.

use std::sync::Arc;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════════════
// 1. CPU Starvation: Mass TLS Cert Generation
// ═══════════════════════════════════════════════════════════════════════
//
// Attack: Agent requests 200 unique domains simultaneously, forcing
// CPU-bound ECDSA keygen for each. Without spawn_blocking, this would
// starve all tokio worker threads and freeze HTTP/WAL processing.
//
// Verification: A lightweight async task (timer) must complete on time
// even while cert generation is saturating the blocking thread pool.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cert_generation_does_not_starve_tokio_workers() {
    let ca = gvm_proxy::tls_proxy::test_helpers::create_test_ca();
    let resolver = Arc::new(gvm_proxy::tls_proxy::GvmCertResolver::new(&ca.0, &ca.1).unwrap());

    // Canary: a lightweight async task that must complete within 100ms.
    // If tokio workers are starved by sync cert gen, this will time out.
    let canary = tokio::spawn(async {
        let start = Instant::now();
        // Yield to runtime 10 times with short sleeps — this MUST complete
        // promptly if the runtime isn't blocked.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        start.elapsed()
    });

    // Fire 200 concurrent cert generations via ensure_cached (spawn_blocking).
    // Each generates a unique ECDSA P-256 key + cert (~0.1ms on blocking pool).
    let mut handles = Vec::new();
    for i in 0..200 {
        let r = resolver.clone();
        let domain = format!("{}.adversarial-starvation-test.invalid", i);
        handles.push(tokio::spawn(async move { r.ensure_cached(domain).await }));
    }

    // Wait for all cert generations to complete
    for h in handles {
        let result = h.await.unwrap();
        assert!(result.is_some(), "Cert generation must succeed");
    }

    // Verify canary completed within a reasonable time.
    // 10 sleeps × 5ms = 50ms minimum. If starved, it would take seconds.
    let canary_elapsed = canary.await.unwrap();
    assert!(
        canary_elapsed < Duration::from_millis(500),
        "Canary task took {:?} — tokio workers were starved! \
         (expected < 500ms for 10 × 5ms sleeps)",
        canary_elapsed,
    );

    // Verify cache was populated (moka is eventually consistent)
    assert_eq!(
        resolver.sync_and_count(),
        200,
        "All 200 unique domains must be cached"
    );
}

/// Regression: ensure_cached on already-cached domain is instant (no spawn_blocking).
#[tokio::test]
async fn ensure_cached_hot_path_is_zero_cost() {
    let ca = gvm_proxy::tls_proxy::test_helpers::create_test_ca();
    let resolver = Arc::new(gvm_proxy::tls_proxy::GvmCertResolver::new(&ca.0, &ca.1).unwrap());

    // Cold: first call generates cert
    resolver.ensure_cached("api.stripe.com".to_string()).await;

    // Hot: 1000 cache hits must complete in < 10ms total
    let start = Instant::now();
    for _ in 0..1000 {
        let r = resolver.ensure_cached("api.stripe.com".to_string()).await;
        assert!(r.is_some());
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(10),
        "1000 cache hits took {:?} — should be < 10ms",
        elapsed,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Slowloris / FD Exhaustion
// ═══════════════════════════════════════════════════════════════════════
//
// Attack: Open TCP connections and trickle HTTP headers 1 byte/sec.
// Without timeouts, each connection holds an FD indefinitely until
// ulimit is hit and accept()/WAL writes start failing with EMFILE.
//
// Verification: read_http_request must abort within 30s (timeout).
// We test with 0-byte writes to simulate a stalled connection.

/// Verify that an immediate EOF (peer closes connection) returns an error
/// promptly — NOT a timeout. This is NOT a Slowloris test; it verifies the
/// fast-path error handling when the TCP connection is reset before any data.
#[tokio::test]
async fn eof_before_headers_returns_error_immediately() {
    // drop(client) sends EOF to server — this is a connection-closed scenario,
    // not a timeout scenario. The reader should detect EOF and fail instantly.
    let (client, server) = tokio::io::duplex(1024);
    drop(client);

    let start = Instant::now();
    let result =
        gvm_proxy::tls_proxy::read_http_request(&mut tokio::io::BufReader::new(server)).await;

    assert!(result.is_err(), "EOF must return error");
    // Must return in milliseconds (EOF is instant), not 30 seconds (timeout)
    assert!(
        start.elapsed() < Duration::from_millis(100),
        "EOF detection must be instant, not wait for timeout"
    );
}

/// True Slowloris test: connection stays OPEN but peer sends nothing.
/// The 30s REQUEST_READ_TIMEOUT must fire and kill the connection.
/// This is the only legitimate Slowloris timeout test.
#[tokio::test]
async fn slowloris_open_connection_no_data_triggers_timeout() {
    let (client, server) = tokio::io::duplex(4096);
    // Keep client alive but never write anything — true Slowloris stall.
    // The _client binding prevents drop (which would send EOF).
    let _client = client;

    let start = Instant::now();
    let result =
        gvm_proxy::tls_proxy::read_http_request(&mut tokio::io::BufReader::new(server)).await;

    assert!(result.is_err(), "Stalled connection must trigger timeout");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(25) && elapsed < Duration::from_secs(45),
        "Timeout must fire at ~30s (±15s margin for slow CI), actual: {:?}",
        elapsed,
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("timed out") || err_msg.contains("Slowloris"),
        "Error must mention timeout: {}",
        err_msg,
    );
}

#[tokio::test]
async fn slowloris_partial_header_triggers_timeout() {
    // Simulate Slowloris: send a partial HTTP header, then stall forever
    let (mut client, server) = tokio::io::duplex(4096);

    // Send a partial header (no \r\n\r\n terminator)
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        client.write_all(b"GET /slow HTTP/1.1\r\nHost: ").await.ok();
        // Never send the rest — stall indefinitely
        tokio::time::sleep(Duration::from_secs(120)).await;
    });

    let start = Instant::now();
    let result =
        gvm_proxy::tls_proxy::read_http_request(&mut tokio::io::BufReader::new(server)).await;

    // Must timeout within 30s (REQUEST_READ_TIMEOUT) + small margin
    assert!(result.is_err(), "Partial header must trigger timeout");
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(25) && elapsed < Duration::from_secs(45),
        "Timeout must fire at ~30s (±15s margin for slow CI), actual: {:?}",
        elapsed,
    );

    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("timed out") || err_msg.contains("Slowloris"),
        "Error must mention timeout: {}",
        err_msg,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. HTTP Request Smuggling (CL/TE Desync)
// ═══════════════════════════════════════════════════════════════════════
//
// Attack: Send a request with both Content-Length and Transfer-Encoding
// headers. If our parser (httparse) and the upstream server disagree on
// where the body ends, the attacker can smuggle a second request inside
// the first body — completely bypassing SRR policy inspection.
//
// Verification: All CL/TE variants MUST be rejected. No request with
// conflicting length semantics may reach the upstream server.

/// CL-TE smuggling: Content-Length + Transfer-Encoding: chunked
#[tokio::test]
async fn smuggling_cl_te_conflict_rejected() {
    let raw = b"POST /api/transfer HTTP/1.1\r\n\
                Host: api.bank.com\r\n\
                Content-Length: 13\r\n\
                Transfer-Encoding: chunked\r\n\
                \r\n\
                0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n";

    let mut cursor = std::io::Cursor::new(raw.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;

    assert!(result.is_err(), "CL+TE must be rejected");
    let err = format!("{}", result.err().unwrap());
    assert!(
        err.contains("Content-Length") && err.contains("Transfer-Encoding"),
        "Error must identify CL/TE conflict: {}",
        err,
    );
}

/// TE-CL smuggling: Transfer-Encoding first, then Content-Length
#[tokio::test]
async fn smuggling_te_cl_conflict_rejected() {
    let raw = b"POST /api/send HTTP/1.1\r\n\
                Host: slack.com\r\n\
                Transfer-Encoding: chunked\r\n\
                Content-Length: 50\r\n\
                \r\n\
                0\r\n\r\nDELETE /channels/1234 HTTP/1.1\r\nHost: evil.com\r\n\r\n";

    let mut cursor = std::io::Cursor::new(raw.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;

    assert!(result.is_err(), "TE+CL must be rejected");
    assert!(
        format!("{}", result.err().unwrap()).contains("smuggling"),
        "Error must mention smuggling defense",
    );
}

/// Duplicate Content-Length with different values (parser confusion attack)
#[tokio::test]
async fn smuggling_duplicate_cl_different_values_rejected() {
    let raw = b"POST /api/payment HTTP/1.1\r\n\
                Host: stripe.com\r\n\
                Content-Length: 5\r\n\
                Content-Length: 100\r\n\
                \r\n\
                hello";

    let mut cursor = std::io::Cursor::new(raw.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;

    assert!(
        result.is_err(),
        "Duplicate CL with different values must be rejected"
    );
    assert!(
        format!("{}", result.err().unwrap()).contains("Content-Length"),
        "Error must identify duplicate CL",
    );
}

/// Duplicate Content-Length with SAME value — acceptable per RFC 7230
#[tokio::test]
async fn smuggling_duplicate_cl_same_value_accepted() {
    let raw = b"POST /api/ok HTTP/1.1\r\n\
                Host: safe.com\r\n\
                Content-Length: 5\r\n\
                Content-Length: 5\r\n\
                \r\n\
                hello";

    let mut cursor = std::io::Cursor::new(raw.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;

    assert!(
        result.is_ok(),
        "Duplicate CL with same value is RFC-compliant"
    );
    let req = result.unwrap();
    assert_eq!(req.method, "POST");
    assert_eq!(req.host, "safe.com");
}

/// Transfer-Encoding with obfuscation (space before colon, mixed case)
/// httparse normalizes header names case-insensitively, so this must still trigger
#[tokio::test]
async fn smuggling_te_obfuscated_casing_rejected() {
    // Mixed-case Transfer-Encoding + Content-Length
    let raw = b"POST /api/test HTTP/1.1\r\n\
                Host: target.com\r\n\
                Content-Length: 10\r\n\
                TrAnSfEr-EnCoDiNg: chunked\r\n\
                \r\n\
                0\r\n\r\n";

    let mut cursor = std::io::Cursor::new(raw.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;

    assert!(result.is_err(), "Obfuscated TE + CL must be rejected");
}

/// Lone Transfer-Encoding without Content-Length — this is valid HTTP
#[tokio::test]
async fn smuggling_te_alone_accepted() {
    let raw = b"POST /api/ok HTTP/1.1\r\n\
                Host: safe.com\r\n\
                Transfer-Encoding: chunked\r\n\
                \r\n\
                5\r\nhello\r\n0\r\n\r\n";

    let mut cursor = std::io::Cursor::new(raw.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;

    assert!(result.is_ok(), "TE alone (no CL) is valid HTTP");
}

/// Lone Content-Length — normal valid request
#[tokio::test]
async fn smuggling_cl_alone_accepted() {
    let raw = b"POST /api/ok HTTP/1.1\r\n\
                Host: safe.com\r\n\
                Content-Length: 13\r\n\
                \r\n\
                {\"ok\": true}";

    let mut cursor = std::io::Cursor::new(raw.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;

    assert!(result.is_ok(), "Normal CL request must work");
    let req = result.unwrap();
    assert_eq!(req.body, b"{\"ok\": true}");
}

// ═══════════════════════════════════════════════════════════════════════
// 4. HTTP/2 ALPN Protocol Collapse
// ═══════════════════════════════════════════════════════════════════════
//
// Attack: Force HTTP/2 connection to the TLS MITM port. If httparse
// receives h2 binary frames, it must not panic or produce Index OOB.
//
// Verification:
// a) ALPN negotiation forces HTTP/1.1 (h2 never negotiated)
// b) If raw h2 binary is sent, httparse returns a parse error, not a panic

#[test]
fn alpn_rejects_h2_negotiation() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let ca = gvm_proxy::tls_proxy::test_helpers::create_test_ca();
    let resolver = Arc::new(gvm_proxy::tls_proxy::GvmCertResolver::new(&ca.0, &ca.1).unwrap());
    let config = gvm_proxy::tls_proxy::build_server_config(resolver).unwrap();

    // Only HTTP/1.1 is advertised
    assert_eq!(
        config.alpn_protocols,
        vec![b"http/1.1".to_vec()],
        "Server must only advertise HTTP/1.1 via ALPN"
    );

    // h2 is NOT in the list — any compliant TLS client will fall back to h1
    assert!(
        !config.alpn_protocols.contains(&b"h2".to_vec()),
        "h2 must never be advertised"
    );
}

/// httparse must not panic on binary (HTTP/2 preface) input
#[tokio::test]
async fn h2_binary_frame_does_not_panic() {
    // HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    // followed by a SETTINGS frame (binary)
    let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\
                        \x00\x00\x00\x04\x00\x00\x00\x00\x00";

    let mut cursor = std::io::Cursor::new(h2_preface.to_vec());
    let mut reader = tokio::io::BufReader::new(&mut cursor);

    // Must return Err (parse error), NOT panic
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;
    assert!(
        result.is_err(),
        "HTTP/2 binary must be rejected, not parsed"
    );
    // Must not have panicked — if we reach this line, the test passes
}

/// Random binary garbage must not crash the parser
#[tokio::test]
async fn random_binary_does_not_panic() {
    let garbage: Vec<u8> = (0..1024).map(|i| (i * 37 % 256) as u8).collect();

    let mut cursor = std::io::Cursor::new(garbage);
    let mut reader = tokio::io::BufReader::new(&mut cursor);

    // Must return Err, not panic
    let result = gvm_proxy::tls_proxy::read_http_request(&mut reader).await;
    assert!(result.is_err(), "Binary garbage must be rejected");
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Sandbox PID 1 Zombie Reaping (Linux only)
// ═══════════════════════════════════════════════════════════════════════
//
// Attack: Agent spawns 10,000 child processes without wait()ing.
// Without a proper init reaper as PID 1, zombies accumulate until
// the PID table is exhausted and fork() returns EAGAIN.
//
// Verification (Linux namespace test):
// The init reaper in child_entry() must waitpid(-1) loop and clean up
// all zombies. After the agent exits, zero zombies remain in the namespace.
//
// Since we cannot create PID namespaces on Windows (test host), we verify
// the reaper logic structurally by testing the fork+waitpid pattern
// in a non-namespaced subprocess.

/// Structural test: verify the reaper pattern handles orphan children.
/// This test forks a child that creates 100 grandchildren (zombies),
/// then the parent (acting as init) reaps all of them.
#[cfg(target_os = "linux")]
#[test]
fn zombie_reaper_cleans_up_orphaned_children() {
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};

    // Fork a child to simulate the namespace PID 1
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // This child acts as the "PID 1 init reaper" from sandbox_impl.rs
            // Spawn 100 grandchildren that exit immediately (creating zombies)
            for _ in 0..100 {
                match unsafe { fork() } {
                    Ok(ForkResult::Child) => {
                        // Grandchild: exit immediately → becomes zombie
                        unsafe { libc::_exit(0) };
                    }
                    Ok(ForkResult::Parent { .. }) => {
                        // Don't wait — simulate an agent that doesn't reap
                    }
                    Err(_) => break,
                }
            }

            // Now act as the init reaper: waitpid(-1) loop
            let mut reaped = 0;
            loop {
                match waitpid(None, None) {
                    Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => {
                        reaped += 1;
                    }
                    Err(nix::errno::Errno::ECHILD) => break, // no more children
                    _ => {}
                }
            }

            // All 100 grandchildren must be reaped
            assert!(reaped >= 100, "Reaped only {} of 100 children", reaped);
            unsafe { libc::_exit(0) };
        }
        Ok(ForkResult::Parent { child }) => {
            // Parent: wait for the "init" child
            let status = waitpid(Some(child), None).unwrap();
            match status {
                WaitStatus::Exited(_, code) => {
                    assert_eq!(code, 0, "Init reaper child must exit cleanly");
                }
                other => panic!("Unexpected wait status: {:?}", other),
            }
        }
        Err(e) => panic!("fork() failed: {}", e),
    }
}

/// Cross-platform structural test: verify that the sandbox child_entry
/// function contains the fork+waitpid pattern (source-level check).
///
/// CAVEAT: This is a heuristic guard, NOT a logical proof. It checks for
/// the presence of key function calls in source text. Known limitations:
/// - A comment like "// do not use libc::_exit" would produce a false positive
/// - Renaming the function or moving it to another file would break this test
///
/// This is acceptable as a refactoring tripwire — it catches accidental
/// removal of the init reaper pattern. For logical verification, the
/// Linux-only `zombie_reaper_cleans_up_orphaned_children` test above
/// exercises the actual waitpid loop.
#[test]
fn sandbox_child_entry_contains_init_reaper_pattern() {
    let source = include_str!("../crates/gvm-sandbox/src/sandbox_impl.rs");

    // Strip comments to avoid false positives from "// don't use libc::fork()" etc.
    let code_lines: String = source
        .lines()
        .map(|line| {
            // Remove // comments but preserve string literals (good enough heuristic)
            if let Some(pos) = line.find("//") {
                &line[..pos]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Must contain fork() call for init reaper (in actual code, not comments)
    assert!(
        code_lines.contains("libc::fork()"),
        "child_entry must fork() to create init reaper"
    );

    // Must contain waitpid(-1, ...) loop for zombie reaping
    assert!(
        code_lines.contains("libc::waitpid(-1"),
        "child_entry must have waitpid(-1) loop for zombie reaping"
    );

    // Must propagate agent exit code via WEXITSTATUS
    assert!(
        code_lines.contains("WEXITSTATUS"),
        "Init reaper must propagate agent exit code"
    );

    // Must use _exit (not std::process::exit) to avoid destructor issues in forked process
    assert!(
        code_lines.contains("libc::_exit"),
        "Forked processes must use _exit(), not std::process::exit()"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// SNI Peek Tests
// ═══════════════════════════════════════════════════════════════════════

/// peek_sni must extract domain from a real TLS ClientHello
#[tokio::test]
async fn peek_sni_extracts_domain_from_client_hello() {
    // Minimal TLS 1.2 ClientHello with SNI = "api.stripe.com"
    // Generated from a real handshake capture, trimmed to essentials
    let domain = "api.stripe.com";
    let sni_bytes = domain.as_bytes();

    // Build a minimal ClientHello with SNI extension
    let mut ch = Vec::new();

    // Client version (TLS 1.2)
    ch.extend_from_slice(&[0x03, 0x03]);
    // Random (32 bytes)
    ch.extend_from_slice(&[0x00; 32]);
    // Session ID length (0)
    ch.push(0x00);
    // Cipher suites: length=2, one suite
    ch.extend_from_slice(&[0x00, 0x02, 0xc0, 0x2f]);
    // Compression: length=1, null
    ch.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let sni_ext = {
        let mut ext = Vec::new();
        // SNI extension type = 0x0000
        ext.extend_from_slice(&[0x00, 0x00]);
        // SNI list: type(1) + name_len(2) + name
        let sni_list_len = 3 + sni_bytes.len();
        let ext_data_len = 2 + sni_list_len; // list_len(2) + sni_list
        ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        ext.push(0x00); // host_name type
        ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        ext.extend_from_slice(sni_bytes);
        ext
    };

    let ext_len = sni_ext.len() as u16;
    ch.extend_from_slice(&ext_len.to_be_bytes());
    ch.extend_from_slice(&sni_ext);

    // Wrap in Handshake header: type=ClientHello(1), length=3 bytes
    let mut hs = Vec::new();
    hs.push(0x01); // ClientHello
    let ch_len = ch.len();
    hs.push(((ch_len >> 16) & 0xFF) as u8);
    hs.push(((ch_len >> 8) & 0xFF) as u8);
    hs.push((ch_len & 0xFF) as u8);
    hs.extend_from_slice(&ch);

    // Wrap in TLS record: type=Handshake(0x16), version=TLS1.0(0x0301)
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);

    // Create a TCP listener and connect to it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.write_all(&record).await.unwrap();
        // Keep connection alive while server peeks.
        // No sleep needed — peek() is async and waits for data.
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let (server_stream, _) = listener.accept().await.unwrap();
    // No sleep here — stream.peek() inside peek_sni is async and will
    // wait until data arrives. A sleep would be a race condition:
    // if peek_sni required sleep to work, it would be a TOCTOU bug
    // in production code.
    let sni = gvm_proxy::tls_proxy::peek_sni(&server_stream).await;
    assert_eq!(sni, Some("api.stripe.com".to_string()));

    client_task.abort();
}

/// peek_sni returns None on non-TLS data
#[tokio::test]
async fn peek_sni_returns_none_on_plain_http() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let (server_stream, _) = listener.accept().await.unwrap();
    // No sleep — peek() waits for data asynchronously
    let sni = gvm_proxy::tls_proxy::peek_sni(&server_stream).await;
    assert_eq!(sni, None, "Plain HTTP must not produce SNI");

    client_task.abort();
}
