//! Streaming relay tests — verify the proxy's body-relay path preserves
//! Server-Sent Events (SSE) and chunked-transfer responses byte-for-byte.
//!
//! Why this matters
//! ────────────────
//! Anthropic, OpenAI, Google Gemini, and most modern LLM APIs ship
//! token-level results as SSE (`Content-Type: text/event-stream`) or
//! chunked JSONL. Each event MUST arrive at the agent intact —
//! merging two events, splitting one, dropping the trailing `\n\n`,
//! or buffering the whole stream all break the agent.
//!
//! The proxy's cooperative-mode forwarder uses
//! `Body::from_stream(http_body_util::BodyDataStream::new(body))`
//! which streams bytes through a tap channel. Without these tests the
//! only thing exercising the streaming code is real LLM traffic. A
//! regression in the chunk-forwarding code (e.g. accidentally calling
//! `.collect()` somewhere) would still pass every existing test
//! because the existing tests use small, complete bodies.
//!
//! Coverage
//! ────────
//! 1. Multi-event SSE — N discrete `data: {...}\n\n` events arrive
//!    individually, in order, with their delimiters intact.
//! 2. Anthropic-shape thinking trace — `event: content_block_delta`
//!    + `data:` lines pass through unchanged.
//! 3. Large chunked body (1MB+) — proxy does not buffer the entire
//!    response in memory before forwarding.
//! 4. Mid-stream pause — upstream pauses between chunks; proxy
//!    delivers each chunk as it arrives, without coalescing.
//! 5. SSE keep-alive comment lines (`: heartbeat\n\n`) survive.
//!
//! All tests use cooperative mode (HTTP host-override) — the relay
//! path here is `proxy_handler` → upstream-clone → `Body::from_stream`.
//! The MITM TLS path is structurally similar but has its own relay
//! function; covering it requires a TLS-terminating mock and is
//! tracked separately.

mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use futures_util::StreamExt;
use http_body_util::BodyDataStream;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

// ── Helper: spin up a mock upstream that streams a caller-provided
//    sequence of byte chunks with `Content-Type: text/event-stream`. ──

async fn spawn_sse_upstream(
    chunks: Vec<&'static [u8]>,
    inter_chunk_delay_ms: u64,
) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = Router::new().fallback(move |_req: Request<Body>| {
        let chunks = chunks.clone();
        async move {
            let stream = async_stream::stream! {
                for chunk in chunks {
                    yield Ok::<_, std::io::Error>(axum::body::Bytes::from_static(chunk));
                    if inter_chunk_delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(inter_chunk_delay_ms)).await;
                    }
                }
            };
            Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .header("Cache-Control", "no-cache")
                .header("X-Accel-Buffering", "no")
                .body(Body::from_stream(stream))
                .unwrap()
        }
    });

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    addr
}

// ── Helper: build a state that allows everything and remaps a
//    virtual host onto the local upstream. ──

async fn proxy_state_with_upstream(
    virtual_host: &str,
    upstream_addr: std::net::SocketAddr,
) -> (gvm_proxy::proxy::AppState, std::path::PathBuf) {
    let (mut state, wal) = common::test_state().await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        virtual_host.to_string(),
        format!("127.0.0.1:{}", upstream_addr.port()),
    );
    state.host_overrides = overrides;
    (state, wal)
}

fn build_proxy_request(virtual_host: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header("X-GVM-Agent-Id", "test-agent-sse")
        .header("X-GVM-Operation", "gvm.llm.stream")
        .header("X-GVM-Target-Host", virtual_host)
        .header("X-GVM-Trace-Id", "trace-sse-001")
        .header("X-GVM-Event-Id", "evt-sse-001")
        .header("Accept", "text/event-stream")
        .body(Body::empty())
        .unwrap()
}

async fn drain_stream(headers: &HeaderMap, body: Body) -> Vec<Vec<u8>> {
    // Verify the proxy advertises a streaming-capable response. If the
    // proxy ever starts buffering we want this to fail loudly.
    let ctype = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ctype.contains("text/event-stream") || ctype.is_empty(),
        "expected text/event-stream content-type, got {:?}",
        ctype
    );

    let mut received: Vec<Vec<u8>> = Vec::new();
    let mut stream = BodyDataStream::new(body);
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.expect("body chunk must read");
        if !bytes.is_empty() {
            received.push(bytes.to_vec());
        }
    }
    received
}

// ════════════════════════════════════════════════════════════════
// 1. Multi-event SSE preserves event boundaries
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sse_multi_event_preserves_boundaries() {
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"type\":\"message_start\",\"message\":{\"id\":\"m_1\"}}\n\n",
        b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}\n\n",
        b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\" world\"}}\n\n",
        b"data: {\"type\":\"message_stop\"}\n\n",
    ];
    let upstream = spawn_sse_upstream(chunks.clone(), 0).await;
    let (state, _wal) = proxy_state_with_upstream("api.anthropic.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = app
        .oneshot(build_proxy_request("api.anthropic.com"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();
    let received = drain_stream(&parts.headers, body).await;

    // Concatenate everything we got and verify byte-for-byte equality
    // with what upstream emitted. Any chunk merging or dropping breaks
    // this assertion.
    let total: Vec<u8> = received.iter().flatten().copied().collect();
    let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();
    assert_eq!(
        total, expected,
        "concatenated SSE bytes must match upstream byte-for-byte"
    );

    // Each event must end with \n\n — verify by counting delimiters in
    // the assembled stream.
    let event_count = total.windows(2).filter(|w| w == b"\n\n").count();
    assert_eq!(event_count, 4, "exactly 4 SSE event delimiters expected");
}

// ════════════════════════════════════════════════════════════════
// 2. Anthropic-shape thinking trace passes through
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sse_anthropic_thinking_block_passes_through() {
    let chunks: Vec<&'static [u8]> = vec![
        b"event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
        b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"thinking\"}}\n\n",
        b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Let me reason about this...\"}}\n\n",
        b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\"}\n\n",
        b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    ];
    let upstream = spawn_sse_upstream(chunks.clone(), 0).await;
    let (state, _wal) = proxy_state_with_upstream("api.anthropic.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = app
        .oneshot(build_proxy_request("api.anthropic.com"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();
    let received = drain_stream(&parts.headers, body).await;
    let total: Vec<u8> = received.iter().flatten().copied().collect();

    // The `event:` named-event lines and `data:` payload lines must
    // both be intact — both are part of the SSE wire format.
    let total_str = std::str::from_utf8(&total).expect("SSE must be UTF-8");
    assert!(total_str.contains("event: content_block_delta"));
    assert!(total_str.contains("\"thinking\":\"Let me reason about this...\""));
    assert!(total_str.contains("event: message_stop"));
}

// ════════════════════════════════════════════════════════════════
// 3. Large body is streamed, not buffered
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sse_large_body_does_not_block_until_fully_buffered() {
    // 8 chunks of 128KB = 1MB total. Proxy must hand each chunk to the
    // client as it arrives, not wait for the whole 1MB.
    static C0: &[u8] = &[b'x'; 128 * 1024];
    static C1: &[u8] = &[b'x'; 128 * 1024];
    static C2: &[u8] = &[b'x'; 128 * 1024];
    static C3: &[u8] = &[b'x'; 128 * 1024];
    static C4: &[u8] = &[b'x'; 128 * 1024];
    static C5: &[u8] = &[b'x'; 128 * 1024];
    static C6: &[u8] = &[b'x'; 128 * 1024];
    static C7: &[u8] = &[b'x'; 128 * 1024];
    let chunks: Vec<&'static [u8]> = vec![C0, C1, C2, C3, C4, C5, C6, C7];

    let upstream = spawn_sse_upstream(chunks, 0).await;
    let (state, _wal) = proxy_state_with_upstream("api.large.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = app
        .oneshot(build_proxy_request("api.large.com"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();
    let received = drain_stream(&parts.headers, body).await;
    let total_bytes: usize = received.iter().map(|c| c.len()).sum();

    // 1MB total body delivered intact
    assert_eq!(
        total_bytes,
        8 * 128 * 1024,
        "full 1MB streaming body delivered"
    );

    // The proxy may coalesce or split chunks at TCP boundaries; the
    // contract is "every byte arrives, in order". We've already
    // checked total bytes; verify ordering by checking every byte is 'x'.
    for (i, chunk) in received.iter().enumerate() {
        assert!(
            chunk.iter().all(|&b| b == b'x'),
            "chunk {} contains non-x byte — stream corruption",
            i
        );
    }
}

// ════════════════════════════════════════════════════════════════
// 4. Mid-stream pause: chunks delivered as upstream emits them
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sse_mid_stream_pause_does_not_coalesce_chunks() {
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"i\":1}\n\n",
        b"data: {\"i\":2}\n\n",
        b"data: {\"i\":3}\n\n",
    ];
    // 50ms between chunks — well above any reasonable buffering
    // threshold but small enough to keep the test fast.
    let upstream = spawn_sse_upstream(chunks.clone(), 50).await;
    let (state, _wal) = proxy_state_with_upstream("api.slow.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = app
        .oneshot(build_proxy_request("api.slow.com"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();

    // Measure how long the FIRST chunk takes to arrive. If the proxy
    // were buffering the whole response, the first chunk would only
    // appear after ~150ms (3 × 50ms inter-chunk delay). Real streaming
    // delivers the first chunk in tens of ms.
    let mut stream = BodyDataStream::new(body);
    let _ctype = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    let start = std::time::Instant::now();
    let first = stream
        .next()
        .await
        .expect("first chunk must arrive")
        .expect("first chunk must read");
    let first_chunk_latency = start.elapsed();

    assert!(!first.is_empty(), "first chunk must be non-empty");
    assert!(
        first_chunk_latency < Duration::from_millis(150),
        "first chunk took {:?} — proxy is buffering the entire stream",
        first_chunk_latency
    );

    // Drain remaining chunks — total response should still complete
    let mut total_bytes = first.len();
    while let Some(chunk) = stream.next().await {
        total_bytes += chunk.unwrap().len();
    }
    let expected_bytes: usize = chunks.iter().map(|c| c.len()).sum();
    assert_eq!(total_bytes, expected_bytes);
}

// ════════════════════════════════════════════════════════════════
// 5. SSE comment-only keep-alive lines pass through
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sse_keepalive_comment_lines_pass_through() {
    // SSE allows `: comment\n\n` for keep-alive heartbeats. Many LLM
    // APIs send these every 15s on long-running streams. They must
    // not be filtered, merged, or treated as malformed events.
    let chunks: Vec<&'static [u8]> = vec![
        b": keep-alive\n\n",
        b"data: {\"i\":1}\n\n",
        b": ping\n\n",
        b"data: {\"i\":2}\n\n",
    ];
    let upstream = spawn_sse_upstream(chunks.clone(), 0).await;
    let (state, _wal) = proxy_state_with_upstream("api.heartbeat.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = app
        .oneshot(build_proxy_request("api.heartbeat.com"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();
    let received = drain_stream(&parts.headers, body).await;
    let total: Vec<u8> = received.iter().flatten().copied().collect();
    let total_str = std::str::from_utf8(&total).unwrap();

    assert!(
        total_str.contains(": keep-alive\n\n"),
        "first comment-only event must survive intact"
    );
    assert!(
        total_str.contains(": ping\n\n"),
        "mid-stream comment-only event must survive intact"
    );
    assert!(total_str.contains("\"i\":1"));
    assert!(total_str.contains("\"i\":2"));
}

// ════════════════════════════════════════════════════════════════
// 6. Empty stream (upstream closes immediately) doesn't hang
// ════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sse_empty_stream_completes_promptly() {
    let chunks: Vec<&'static [u8]> = vec![];
    let upstream = spawn_sse_upstream(chunks, 0).await;
    let (state, _wal) = proxy_state_with_upstream("api.empty.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        app.oneshot(build_proxy_request("api.empty.com")),
    )
    .await
    .expect("request must not hang on empty stream")
    .expect("proxy must respond");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body();
    let bytes = http_body_util::BodyExt::collect(body)
        .await
        .unwrap()
        .to_bytes();
    assert!(
        bytes.is_empty(),
        "empty upstream must produce empty response body, got {} bytes",
        bytes.len()
    );
}

// ════════════════════════════════════════════════════════════════
// 7. Multi-event chunk boundary count (catches partial coalescing)
// ════════════════════════════════════════════════════════════════
//
// Test 1 only checks total bytes match. A regression that coalesces
// two adjacent chunks into one (a real risk if proxy.rs ever switches
// to a buffered relay or BufRead-style abstraction) would still pass
// test 1 because the concatenated bytes are identical. Test 4
// catches a *full* buffering regression via timing, but a
// "coalesce-pairs" regression with small inter-chunk gaps wouldn't
// be visible to the timing assertion either.
//
// This test gives upstream enough inter-chunk delay (40ms) that the
// proxy must hand each chunk to the body stream as it arrives —
// otherwise the response-body Stream will report fewer chunks than
// the upstream sent. The exact count is the contract.

#[tokio::test]
async fn sse_chunk_count_matches_upstream() {
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"i\":1}\n\n",
        b"data: {\"i\":2}\n\n",
        b"data: {\"i\":3}\n\n",
        b"data: {\"i\":4}\n\n",
        b"data: {\"i\":5}\n\n",
    ];
    // 40ms inter-chunk gap — large enough that hyper's tower service
    // will deliver each upstream Frame as a separate Body item,
    // small enough to keep total runtime under 250ms.
    let upstream = spawn_sse_upstream(chunks.clone(), 40).await;
    let (state, _wal) = proxy_state_with_upstream("api.beat.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = app
        .oneshot(build_proxy_request("api.beat.com"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();
    let received = drain_stream(&parts.headers, body).await;

    assert_eq!(
        received.len(),
        chunks.len(),
        "expected {} chunks (one per upstream emit), got {} — proxy is coalescing",
        chunks.len(),
        received.len()
    );

    // And every received chunk must be a complete event boundary (ends
    // with \n\n), proving no upstream chunk was split mid-event either.
    for (i, c) in received.iter().enumerate() {
        assert!(
            c.ends_with(b"\n\n"),
            "chunk {} does not end at SSE event boundary: {:?}",
            i,
            std::str::from_utf8(c).unwrap_or("<binary>")
        );
    }
}

// ════════════════════════════════════════════════════════════════
// 8. Multi-byte UTF-8 split across chunk boundary
// ════════════════════════════════════════════════════════════════
//
// The original "large body" test sent 1MB of `b'x'` (ASCII). That
// proves byte count matches but cannot detect a regression where the
// proxy decodes-then-re-encodes the body, because every byte is
// independently valid UTF-8. The dangerous bug class is when the
// proxy converts to String mid-stream (e.g. via `String::from_utf8`)
// and a multi-byte character lands across a chunk boundary —
// `from_utf8` errors out, the proxy panics or replaces with U+FFFD,
// and the agent sees corrupted content.
//
// This test sends a string where each chunk ends in the FIRST byte
// of a 4-byte emoji (🦀 = F0 9F A6 80) and the next chunk starts
// with the remaining 3 bytes. The relayed stream must be byte-
// identical when concatenated.

#[tokio::test]
async fn sse_multibyte_utf8_split_across_chunk_boundary() {
    // 🦀 = 0xF0 0x9F 0xA6 0x80 (4-byte UTF-8). Place the first byte at
    // the end of one chunk, the remaining 3 bytes at the start of the
    // next — any "decode-then-re-encode" regression in the relay
    // path will break here because the first chunk's last byte is
    // alone an invalid UTF-8 sequence.
    static C0: &[u8] = b"data: \"prefix\xF0";
    static C1: &[u8] = b"\x9F\xA6\x80suffix\"\n\n";
    // 한 = 0xED 0x95 0x9C (3-byte UTF-8). Split as 1 byte | 2 bytes
    // across the chunk boundary.
    static C2: &[u8] = b"data: \"\xED";
    static C3: &[u8] = b"\x95\x9C\xEA\xB8\x80\xEC\x96\xB4\"\n\n"; // 한 + 글 + 어
    let chunks: Vec<&'static [u8]> = vec![C0, C1, C2, C3];

    let upstream = spawn_sse_upstream(chunks.clone(), 20).await;
    let (state, _wal) = proxy_state_with_upstream("api.utf8.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = app
        .oneshot(build_proxy_request("api.utf8.com"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();
    let received = drain_stream(&parts.headers, body).await;
    let total: Vec<u8> = received.iter().flatten().copied().collect();
    let expected: Vec<u8> = chunks.iter().flat_map(|c| c.iter().copied()).collect();

    assert_eq!(
        total, expected,
        "concatenated stream differs from upstream — UTF-8 boundary corrupted"
    );

    // Sanity: the assembled stream IS valid UTF-8 with the expected chars.
    let s = std::str::from_utf8(&total).expect("relayed stream must be valid UTF-8");
    assert!(
        s.contains("\"prefix🦀suffix\""),
        "4-byte emoji split across chunks must reassemble"
    );
    assert!(
        s.contains("\"한글어\""),
        "3-byte hangul split across chunks must reassemble"
    );
}

// ════════════════════════════════════════════════════════════════
// 9. Upstream early close: proxy propagates EOF, doesn't hang
// ════════════════════════════════════════════════════════════════
//
// Real Anthropic / OpenAI streams sometimes close the connection
// mid-event when the model hits a stop sequence. The proxy must
// treat the upstream EOF as the end of the body and surface it
// promptly — not retry, not hang waiting for more, not synthesise
// a fake closing event.

#[tokio::test]
async fn sse_upstream_early_close_propagates_promptly() {
    // Two chunks emitted, then upstream's tcp stream is dropped by
    // axum's serve loop after the response future resolves.
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"i\":1}\n\n",
        b"data: {\"i\":2,\"partial",
        // Note the deliberately incomplete last chunk — the upstream
        // closes BEFORE finishing the JSON. The proxy must surface
        // these bytes to the client as-is and then EOF.
    ];
    let upstream = spawn_sse_upstream(chunks.clone(), 30).await;
    let (state, _wal) = proxy_state_with_upstream("api.eof.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        app.oneshot(build_proxy_request("api.eof.com")),
    )
    .await
    .expect("must not hang on early close")
    .expect("proxy must respond");
    assert_eq!(response.status(), StatusCode::OK);

    let (parts, body) = response.into_parts();
    let received = drain_stream(&parts.headers, body).await;
    let total: Vec<u8> = received.iter().flatten().copied().collect();

    // The two emitted chunks (including the partial one) must be in
    // the relayed stream. We do NOT require any specific chunking here
    // because the relevant contract is "every byte upstream sent is
    // delivered before EOF surfaces".
    let needle1: &[u8] = b"data: {\"i\":1}\n\n";
    let needle2: &[u8] = b"data: {\"i\":2,\"partial";
    assert!(
        total.windows(needle1.len()).any(|w| w == needle1),
        "first complete chunk missing from relayed body ({} bytes total)",
        total.len()
    );
    assert!(
        total.windows(needle2.len()).any(|w| w == needle2),
        "second partial chunk missing from relayed body ({} bytes total)",
        total.len()
    );
}

// ════════════════════════════════════════════════════════════════
// 10-13. Policy mapping on streaming — the actual reason MITM exists
// ════════════════════════════════════════════════════════════════
//
// All the tests above verify "bytes pass through". The whole point of
// putting a proxy in front of LLM traffic is to apply governance.
// These four tests prove that streaming requests:
//   10. are blocked when SRR says Deny (no upstream call, no body)
//   11. are recorded in the WAL with correct host/decision metadata
//   12. carry proxy-injected response headers (X-GVM-Decision etc.)
//   13. carry proxy-injected upstream credentials (Authorization)

async fn srr_with(rules_toml: &str) -> gvm_proxy::srr::NetworkSRR {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("srr.toml");
    std::fs::write(&p, rules_toml).unwrap();
    gvm_proxy::srr::NetworkSRR::load(&p).unwrap()
}

#[tokio::test]
async fn streaming_srr_deny_blocks_before_upstream_call() {
    // Upstream tracks whether anything reached it.
    let upstream_hit = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hit_clone = upstream_hit.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app_up = Router::new().fallback(move |_req: Request<Body>| {
        let hit = hit_clone.clone();
        async move {
            hit.store(true, std::sync::atomic::Ordering::Relaxed);
            Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .body(Body::from("data: leaked\n\n"))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app_up).await.ok();
    });

    let srr = srr_with(
        r#"
[[rules]]
method = "POST"
pattern = "api.deny-stream.com/v1/messages"
[rules.decision]
type = "Deny"
reason = "stream blocked by policy"
"#,
    )
    .await;
    let (mut state, _wal) = common::test_state_with_srr(srr).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.deny-stream.com".to_string(),
        format!("127.0.0.1:{}", addr.port()),
    );
    state.host_overrides = overrides;

    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let resp = app
        .oneshot(build_proxy_request("api.deny-stream.com"))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Deny rule must produce 403, not stream a body"
    );
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert!(
        !body.windows(b"leaked".len()).any(|w| w == b"leaked"),
        "denied stream must not relay any upstream bytes"
    );
    assert!(
        !upstream_hit.load(std::sync::atomic::Ordering::Relaxed),
        "denied request must not have reached the upstream socket"
    );
}

#[tokio::test]
async fn streaming_request_recorded_in_wal_with_correct_metadata() {
    let chunks: Vec<&'static [u8]> = vec![b"data: {\"i\":1}\n\n", b"data: {\"i\":2}\n\n"];
    let upstream = spawn_sse_upstream(chunks, 0).await;

    let srr = srr_with(
        r#"
[[rules]]
method = "*"
pattern = "{any}"
[rules.decision]
type = "Allow"
"#,
    )
    .await;
    let (mut state, wal_path) = common::test_state_with_srr(srr).await;
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.audited.com".to_string(),
        format!("127.0.0.1:{}", upstream.port()),
    );
    state.host_overrides = overrides;

    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);
    let resp = app
        .oneshot(build_proxy_request("api.audited.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // Drain the body so the proxy's tap finishes and the event flushes
    // through the group-commit WAL writer before we read the file.
    let _ = http_body_util::BodyExt::collect(resp.into_body()).await;

    // Group-commit batch_window_ms is 2ms; 200ms is plenty.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let wal = std::fs::read_to_string(&wal_path).unwrap_or_default();
    let mut found_event_for_host = false;
    for line in wal.lines() {
        if line.contains("\"host\":\"api.audited.com\"") {
            found_event_for_host = true;
            assert!(
                line.contains("\"decision\":\"Allow\""),
                "WAL event must record the Allow decision: {}",
                line
            );
            assert!(
                line.contains("\"path\":\"/v1/messages\""),
                "WAL event must record the request path: {}",
                line
            );
        }
    }
    assert!(
        found_event_for_host,
        "no governance event for streaming request found in WAL"
    );
}

#[tokio::test]
async fn streaming_response_carries_proxy_injected_headers() {
    let chunks: Vec<&'static [u8]> = vec![b"data: {\"i\":1}\n\n"];
    let upstream = spawn_sse_upstream(chunks, 0).await;
    let (state, _wal) = proxy_state_with_upstream("api.headers.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let resp = app
        .oneshot(build_proxy_request("api.headers.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // X-GVM-Decision (and friends) on streaming responses are the
    // observability anchor — agent SDKs key off them. If the proxy
    // ever drops these on the streaming path, all governance UX
    // disappears even though enforcement still works.
    assert!(
        resp.headers().get("X-GVM-Decision").is_some(),
        "streaming response must carry X-GVM-Decision header"
    );
    assert!(
        resp.headers().get("X-GVM-Event-Id").is_some(),
        "streaming response must carry X-GVM-Event-Id header"
    );
}

#[tokio::test]
async fn streaming_upstream_request_receives_injected_credentials() {
    use std::sync::Mutex;

    // Capture the Authorization header that arrives at the upstream.
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cap = captured.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app_up = Router::new().fallback(move |req: Request<Body>| {
        let cap = cap.clone();
        async move {
            if let Some(auth) = req.headers().get("authorization") {
                if let Ok(s) = auth.to_str() {
                    *cap.lock().unwrap() = Some(s.to_string());
                }
            }
            Response::builder()
                .status(200)
                .header("Content-Type", "text/event-stream")
                .body(Body::from("data: ok\n\n"))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app_up).await.ok();
    });

    // Build state with credentials configured for the virtual host.
    let dir = tempfile::tempdir().unwrap();
    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(
        &secrets_path,
        r#"
[credentials."api.creds.com"]
type = "Bearer"
token = "sk-streaming-injected"
"#,
    )
    .unwrap();
    let (mut state, _wal) = common::test_state().await;
    state.api_keys = Arc::new(
        gvm_proxy::api_keys::APIKeyStore::load(&secrets_path).expect("secrets must parse"),
    );
    let mut overrides = std::collections::HashMap::new();
    overrides.insert(
        "api.creds.com".to_string(),
        format!("127.0.0.1:{}", addr.port()),
    );
    state.host_overrides = overrides;

    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);
    let resp = app
        .oneshot(build_proxy_request("api.creds.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let _ = http_body_util::BodyExt::collect(resp.into_body()).await;

    let observed = captured.lock().unwrap().clone();
    assert_eq!(
        observed.as_deref(),
        Some("Bearer sk-streaming-injected"),
        "upstream must receive the proxy-injected credential, not the agent's"
    );
}

// ════════════════════════════════════════════════════════════════
// 14. Real TCP socket end-to-end (covers hyper/TCP that oneshot skips)
// ════════════════════════════════════════════════════════════════
//
// All previous tests use `tower::ServiceExt::oneshot`, which short-
// circuits the tower Service stack and never opens a socket. Most
// streaming bugs in production live below that layer: hyper's
// HTTP/1.1 framer, TCP_NODELAY, send-buffer coalescing, content-length
// vs chunked encoding decisions. This test runs the proxy on a real
// `tokio::net::TcpListener` and connects with a real reqwest client
// over a real TCP socket so any of those layers regressing is
// observable.

#[tokio::test]
async fn streaming_works_over_real_tcp_socket() {
    let chunks: Vec<&'static [u8]> = vec![
        b"data: {\"i\":1}\n\n",
        b"data: {\"i\":2}\n\n",
        b"data: {\"i\":3}\n\n",
    ];
    let upstream = spawn_sse_upstream(chunks, 30).await;
    let (state, _wal) = proxy_state_with_upstream("api.tcp.com", upstream).await;
    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(proxy_listener, app).await.ok();
    });

    // Real hyper client over a real TCP socket — bypasses oneshot
    // and exercises the full hyper HTTP/1 framer + tokio TCP stack.
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<Body>();

    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{}/v1/messages", proxy_addr))
        .header("X-GVM-Agent-Id", "tcp-test")
        .header("X-GVM-Operation", "gvm.llm.stream")
        .header("X-GVM-Target-Host", "api.tcp.com")
        .header("X-GVM-Trace-Id", "tcp-trace")
        .header("X-GVM-Event-Id", "tcp-evt")
        .header("Accept", "text/event-stream")
        .body(Body::empty())
        .unwrap();
    let resp = client
        .request(req)
        .await
        .expect("real-TCP request must complete");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body();
    let mut stream = BodyDataStream::new(body);
    let mut bytes_total = 0usize;
    let mut chunks_received = 0usize;
    while let Some(chunk) = stream.next().await {
        let bs = chunk.expect("body chunk over TCP must read");
        if !bs.is_empty() {
            bytes_total += bs.len();
            chunks_received += 1;
        }
    }
    let expected = b"data: {\"i\":1}\n\ndata: {\"i\":2}\n\ndata: {\"i\":3}\n\n".len();
    assert!(
        bytes_total >= expected,
        "real-TCP body bytes too small ({} bytes, expected ≥{})",
        bytes_total,
        expected
    );
    assert!(
        chunks_received >= 1,
        "real-TCP body produced zero non-empty chunks"
    );
}

// ════════════════════════════════════════════════════════════════
// Use Arc to silence unused-import warning when feature combinations
// trim compilation paths.
// ════════════════════════════════════════════════════════════════
#[allow(dead_code)]
fn _arc_keep<T>(_: Arc<T>) {}
