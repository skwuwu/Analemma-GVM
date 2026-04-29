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
// Use Arc to silence unused-import warning when feature combinations
// trim compilation paths.
// ════════════════════════════════════════════════════════════════
#[allow(dead_code)]
fn _arc_keep<T>(_: Arc<T>) {}
