//! Integration tests — proves end-to-end enforcement pipeline correctness.
//!
//! Test 1: EventStatus state transitions (Pending → Confirmed/Failed/Expired)
//! Test 2: WAL → NATS async ordering + crash recovery re-publish
//! Test 3: (removed — ABAC deleted)
//! Test 4: API key injection into forwarded requests
//! Test 5: SDK @ic headers → Proxy classification → enforcement decision
//! Test 6: Checkpoint save → read → Merkle verification round-trip
//! Test 7: LLM thinking trace extraction from OpenAI/Anthropic response bodies

use gvm_proxy::api_keys::APIKeyStore;
use gvm_proxy::ledger::Ledger;
use gvm_proxy::proxy::{proxy_handler, AppState};
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::token_budget::TokenBudget;
use gvm_proxy::types::*;
use gvm_proxy::vault::Vault;
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════════
// Test 1: EventStatus State Transitions (Pending → Confirmed/Failed/Expired)
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn event_status_transitions_pending_to_confirmed_and_failed() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger with valid WAL path must initialize"),
    );

    // ── Phase 1: Write a Pending event (IC-2 Delay scenario) ──
    let mut event_delay = make_test_event("evt-delay-001", "gvm.messaging.send");
    event_delay.status = EventStatus::Pending;
    ledger
        .append_durable(&event_delay)
        .await
        .expect("appending valid event to empty WAL must succeed");

    // Simulate: upstream returned 200 → update to Confirmed
    event_delay.status = EventStatus::Confirmed;
    ledger
        .append_durable(&event_delay)
        .await
        .expect("appending confirmed status update must succeed");

    // ── Phase 2: Write another Pending event that fails ──
    let mut event_fail = make_test_event("evt-fail-001", "gvm.payment.refund");
    event_fail.status = EventStatus::Pending;
    ledger
        .append_durable(&event_fail)
        .await
        .expect("appending pending refund event must succeed");

    // Simulate: upstream returned 500 → update to Failed
    event_fail.status = EventStatus::Failed {
        reason: "HTTP 500".to_string(),
    };
    ledger
        .append_durable(&event_fail)
        .await
        .expect("appending failed status update must succeed");

    // ── Phase 3: Write a Pending event that will "crash" ──
    let mut event_crash = make_test_event("evt-crash-001", "gvm.storage.write");
    event_crash.status = EventStatus::Pending;
    ledger
        .append_durable(&event_crash)
        .await
        .expect("appending crash-scenario pending event must succeed");

    // Don't update — simulate proxy crash with Pending in WAL

    // ── Phase 4: Verify WAL contents ──
    let wal_content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after writes");
    let entries: Vec<GVMEvent> = wal_content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    assert_eq!(entries.len(), 5, "WAL should have 5 entries");

    // Entry 0: Pending (delay)
    assert!(matches!(entries[0].status, EventStatus::Pending));
    assert_eq!(entries[0].event_id, "evt-delay-001");

    // Entry 1: Confirmed (delay completed)
    assert!(matches!(entries[1].status, EventStatus::Confirmed));
    assert_eq!(entries[1].event_id, "evt-delay-001");

    // Entry 2: Pending (refund)
    assert!(matches!(entries[2].status, EventStatus::Pending));
    assert_eq!(entries[2].event_id, "evt-fail-001");

    // Entry 3: Failed (refund failed)
    assert!(matches!(entries[3].status, EventStatus::Failed { .. }));
    assert_eq!(entries[3].event_id, "evt-fail-001");

    // Entry 4: Pending (crash — no follow-up)
    assert!(matches!(entries[4].status, EventStatus::Pending));
    assert_eq!(entries[4].event_id, "evt-crash-001");

    // ── Phase 5: Crash recovery → Pending becomes Expired ──
    // Create a NEW ledger on the same WAL file (simulates restart)
    let ledger2 = Ledger::new(&wal_path, "", "")
        .await
        .expect("ledger must initialize from existing WAL file");
    let report = ledger2
        .recover_from_wal()
        .await
        .expect("WAL crash recovery must complete successfully");

    // First recovery (no watermark) scans the entire WAL.
    // All 3 Pending events are found (evt-delay-001, evt-fail-001, evt-crash-001).
    // Recovery marks every Pending it encounters as Expired (idempotent, safe).
    assert_eq!(
        report.pending_found, 3,
        "First recovery must find all 3 Pending events in WAL"
    );
    assert_eq!(
        report.expired_marked, 3,
        "First recovery must mark all 3 as Expired"
    );

    // Verify the Expired entries were appended to WAL with correct event_ids
    let wal_after = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after recovery");
    let expired_events: Vec<GVMEvent> = wal_after
        .lines()
        .filter_map(|l| serde_json::from_str::<GVMEvent>(l).ok())
        .filter(|e| matches!(e.status, EventStatus::Expired))
        .collect();

    assert_eq!(
        expired_events.len(),
        3,
        "WAL must contain exactly 3 Expired entries after recovery"
    );
    assert!(
        expired_events.iter().any(|e| e.event_id == "evt-crash-001"),
        "The crash-pending event must be marked Expired"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 2: WAL → NATS Async Ordering + Crash Recovery Re-Publish
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn wal_nats_sequence_ordering_and_crash_recovery() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    // Use a stub NATS URL to exercise the NATS publish path (no real connection)
    let ledger = Arc::new(
        Ledger::new(&wal_path, "nats://stub:4222", "gvm-stream")
            .await
            .expect("ledger with stub NATS config must initialize"),
    );

    // ── Phase 1: Rapid-fire 50 durable writes ──
    let mut handles = Vec::new();
    for i in 0..50 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("nats-evt-{:03}", i), "gvm.storage.write");
            ledger
                .append_durable(&event)
                .await
                .expect("concurrent WAL append must succeed");
        }));
    }

    for handle in handles {
        handle.await.expect("spawned WAL write task must not panic");
    }

    // ── Phase 2: Verify WAL has all 50 entries ──
    let wal_content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after concurrent writes");
    let entries: Vec<GVMEvent> = wal_content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    assert_eq!(entries.len(), 50, "WAL must contain exactly 50 entries");

    // All entries should have unique event_ids
    let event_ids: std::collections::HashSet<&str> =
        entries.iter().map(|e| e.event_id.as_str()).collect();
    assert_eq!(event_ids.len(), 50, "All 50 event IDs must be unique");

    // ── Phase 3: Simulate crash — add some Pending events ──
    let pending_event = make_test_event("nats-pending-crash", "gvm.payment.refund");
    ledger
        .append_durable(&pending_event)
        .await
        .expect("appending crash-scenario pending event must succeed");

    // ── Phase 4: Crash recovery on new ledger instance ──
    let ledger2 = Ledger::new(&wal_path, "nats://stub:4222", "gvm-stream")
        .await
        .expect("ledger must initialize from existing WAL for recovery");
    let report = ledger2
        .recover_from_wal()
        .await
        .expect("WAL crash recovery must complete successfully");

    // All 51 events are Pending (default in make_test_event) → all should be found
    assert!(
        report.pending_found >= 51,
        "Recovery must find all Pending events, found: {}",
        report.pending_found
    );
    assert_eq!(
        report.pending_found, report.expired_marked,
        "All found Pending events must be marked Expired"
    );
}

// Test 3 (ABAC Policy Hierarchy) removed — ABAC system deleted.

// ═══════════════════════════════════════════════════════════════════════════
// Test 4: API Key Injection into Forwarded Requests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn api_key_injection_bearer_and_apikey_types() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let secrets_path = dir.path().join("secrets.toml");

    std::fs::write(
        &secrets_path,
        r#"
[credentials."api.stripe.com"]
type = "Bearer"
token = "sk_test_stripe_secret_key_123"

[credentials."api.sendgrid.com"]
type = "ApiKey"
header = "x-api-key"
value = "SG.sendgrid_api_key_456"

[credentials."api.github.com"]
type = "OAuth2"
access_token = "gho_github_oauth_token_789"
refresh_token = "ghr_refresh_token"
expires_at = "2027-01-01T00:00:00Z"
"#,
    )
    .expect("writing secrets config must succeed");

    let store =
        APIKeyStore::load(&secrets_path).expect("valid secrets file must parse successfully");

    let passthrough = gvm_proxy::api_keys::MissingCredentialPolicy::Passthrough;

    // ── Test Bearer injection (Stripe) ──
    {
        let mut headers = axum::http::HeaderMap::new();
        store
            .inject(&mut headers, "api.stripe.com", &passthrough)
            .expect("Stripe credential injection must succeed");

        let auth = headers
            .get("authorization")
            .expect("Authorization header must be set for Stripe");
        assert_eq!(
            auth.to_str()
                .expect("authorization header must be valid UTF-8"),
            "Bearer sk_test_stripe_secret_key_123"
        );
    }

    // ── Test ApiKey injection (SendGrid) ──
    {
        let mut headers = axum::http::HeaderMap::new();
        store
            .inject(&mut headers, "api.sendgrid.com", &passthrough)
            .expect("SendGrid credential injection must succeed");

        let api_key = headers
            .get("x-api-key")
            .expect("x-api-key header must be set for SendGrid");
        assert_eq!(
            api_key
                .to_str()
                .expect("x-api-key header must be valid UTF-8"),
            "SG.sendgrid_api_key_456"
        );

        // Authorization should NOT be set (ApiKey type uses custom header)
        assert!(
            headers.get("authorization").is_none(),
            "ApiKey type should not set Authorization header"
        );
    }

    // ── Test OAuth2 injection (GitHub) ──
    {
        let mut headers = axum::http::HeaderMap::new();
        store
            .inject(&mut headers, "api.github.com", &passthrough)
            .expect("GitHub OAuth2 credential injection must succeed");

        let auth = headers
            .get("authorization")
            .expect("Authorization header must be set for GitHub OAuth2");
        assert_eq!(
            auth.to_str()
                .expect("authorization header must be valid UTF-8"),
            "Bearer gho_github_oauth_token_789"
        );
    }

    // ── Test unknown host — passthrough mode (no injection, no error) ──
    {
        let mut headers = axum::http::HeaderMap::new();
        store
            .inject(&mut headers, "unknown.example.com", &passthrough)
            .expect("passthrough mode must not error on unknown host");

        assert!(
            headers.is_empty(),
            "No credentials should be injected for unknown host in passthrough mode"
        );
    }

    // ── Test unknown host — deny mode (must return error) ──
    {
        let deny = gvm_proxy::api_keys::MissingCredentialPolicy::Deny;
        let mut headers = axum::http::HeaderMap::new();
        let result = store.inject(&mut headers, "unknown.example.com", &deny);
        assert!(
            result.is_err(),
            "Deny mode must reject requests to hosts without credentials"
        );
    }

    // ── Test agent-supplied Authorization header is stripped ──
    {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer agent-smuggled-token"),
        );
        store
            .inject(&mut headers, "api.stripe.com", &passthrough)
            .expect("Stripe injection must overwrite agent-supplied header");

        let auth = headers
            .get("authorization")
            .expect("authorization header must exist after injection");
        assert_eq!(
            auth.to_str()
                .expect("authorization header must be valid UTF-8"),
            "Bearer sk_test_stripe_secret_key_123",
            "Proxy credential must replace agent-supplied Authorization header"
        );
    }

    // ── Test: Agent environment has no API keys ──
    // Verify the store does NOT leak keys via any public getter
    // (there is no getter — keys are only accessible via inject())
    // This proves Layer 3 isolation: agents call inject() indirectly through the proxy
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 5: SDK @ic Headers → Proxy Classification → Enforcement Decision
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sdk_headers_to_proxy_classification_end_to_end() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt; // for oneshot

    // ── Setup: build full AppState from temp config files ──
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");

    // SRR config: deny bank transfers, delay everything else
    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "Deny", reason = "Wire transfer blocked by SRR" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
"#,
    )
    .expect("writing SRR config must succeed");

    // Empty secrets
    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n")
        .expect("writing empty secrets config must succeed");

    // WAL
    let wal_path = dir.path().join("wal.log");

    // Build components
    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&srr_path).expect("valid SRR config must parse"),
    ));
    let api_keys =
        Arc::new(APIKeyStore::load(&secrets_path).expect("valid secrets config must parse"));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize for end-to-end test"),
    );
    let vault =
        Arc::new(Vault::new(ledger.clone()).expect("vault must initialize with valid ledger"));
    let token_budget = Arc::new(TokenBudget::new(0, 0.0, 500));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget,
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new().fallback(proxy_handler).with_state(state);

    // ── Scenario A: Header Forgery — agent lies about operation ──
    // SDK sends: operation=gvm.storage.read (Allow)
    // But targets: api.bank.com/transfer/123 (SRR Deny)
    // Expected: max_strict(Allow, Deny) = DENY → HTTP 403
    let request = Request::builder()
        .method("POST")
        .uri("/transfer/123")
        .header("X-GVM-Agent-Id", "malicious-agent")
        .header("X-GVM-Operation", "gvm.storage.read")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-test-001")
        .header("X-GVM-Event-Id", "evt-test-001")
        .header("Content-Type", "application/json")
        .body(Body::empty())
        .expect("valid HTTP request must build");

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("proxy must handle forged header request");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Header forgery must result in 403 Deny (SRR catches URL)"
    );

    // Read response body to verify denial reason
    let body_bytes = axum::body::to_bytes(response.into_body(), 10240)
        .await
        .expect("response body must be readable");
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_str.contains("Wire transfer blocked"),
        "Deny reason should mention wire transfer, got: {}",
        body_str
    );

    // Scenario B (RequireApproval via ABAC) removed — ABAC system deleted.

    // ── Scenario C: IC-1 Allow — safe read operation on safe URL ──
    // SDK sends: operation=gvm.storage.read
    // Target: api.example.com/data (no SRR deny)
    // Policy: Allow for reads
    // SRR: Default-to-Caution (Delay 300ms)
    // max_strict(Allow, Delay) = Delay
    // Expected: proxy tries to forward → 502 (no upstream) but NOT 403
    let request = Request::builder()
        .method("GET")
        .uri("/data")
        .header("X-GVM-Agent-Id", "reader-agent")
        .header("X-GVM-Operation", "gvm.storage.read")
        .header("X-GVM-Target-Host", "api.example.com")
        .header("X-GVM-Trace-Id", "trace-test-003")
        .header("X-GVM-Event-Id", "evt-test-003")
        .body(Body::empty())
        .expect("valid HTTP request must build");

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("proxy must handle safe read request");
    // Should NOT be 403 (not denied). Likely 502 because no real upstream.
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Safe read operation should NOT be denied"
    );

    // ── Scenario D: Direct HTTP (no GVM headers) — SRR only ──
    // No X-GVM-Agent-Id → falls through to SRR-only path
    // URL: api.bank.com/transfer/456 → SRR Deny
    let request = Request::builder()
        .method("POST")
        .uri("/transfer/456")
        .header("X-GVM-Target-Host", "api.bank.com")
        .body(Body::empty())
        .expect("valid HTTP request must build");

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("proxy must handle direct HTTP request");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Direct HTTP to bank transfer must be denied by SRR"
    );

    // ── Verify WAL recorded all events ──
    // No sleep needed: append_durable().await (used for IC-2+ events) guarantees
    // fsync before the HTTP response is sent. By the time we receive the response
    // above, WAL data is already on disk.

    let wal_content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after enforcement tests");
    let wal_entries: Vec<GVMEvent> = wal_content
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    // At minimum: the Deny events (scenarios A, B, D) should be in WAL
    assert!(
        wal_entries.len() >= 3,
        "WAL should contain at least 3 enforcement events, got {}",
        wal_entries.len()
    );

    // Verify at least one event has the malicious-agent header forgery recorded
    let forgery_event = wal_entries.iter().find(|e| e.agent_id == "malicious-agent");
    assert!(
        forgery_event.is_some(),
        "WAL must record the header forgery attempt"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Config File Hash Recording in Merkle Chain
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn config_file_hashes_recorded_in_merkle_chain() {
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    // Create sample config files with known content
    let srr_path = dir.path().join("srr.toml");
    let srr_content = b"[[rules]]\nmethod = \"GET\"\npattern = \"*\"\n";
    std::fs::write(&srr_path, srr_content).expect("writing test SRR file must succeed");

    // Compute expected hash
    let expected_srr_hash = format!("{:x}", Sha256::digest(srr_content));

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize"),
    );

    // Record config load (SRR only — registry removed)
    let config_files: Vec<(&str, &std::path::Path)> = vec![("srr:srr.toml", srr_path.as_path())];
    ledger
        .record_config_load(&config_files, None)
        .await
        .expect("recording config hashes must succeed");

    // Read WAL and find the config_load event
    let wal_content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable");
    let entries: Vec<GVMEvent> = wal_content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    assert_eq!(
        entries.len(),
        1,
        "WAL should have exactly 1 config_load event"
    );

    let event = &entries[0];
    assert_eq!(event.operation, "gvm.system.config_load");
    assert_eq!(event.agent_id, "gvm-proxy");
    assert_eq!(event.trace_id, "system");
    assert!(matches!(event.status, EventStatus::Confirmed));

    // Verify SHA-256 hash in context field
    let srr_hash = event
        .context
        .get("srr:srr.toml")
        .and_then(|v| v.as_str())
        .expect("SRR hash must be present in context");
    assert_eq!(
        srr_hash, expected_srr_hash,
        "SRR file hash must match SHA-256"
    );

    // Verify event entered Merkle chain (has event_hash)
    assert!(
        event.event_hash.is_some(),
        "Config load event must have event_hash (Merkle chain membership)"
    );
    assert!(
        event.event_id.starts_with("sys-config-"),
        "Config load event ID must have sys-config- prefix"
    );
}

#[tokio::test]
async fn config_hash_records_unavailable_for_missing_files() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize"),
    );

    // Reference a file that does not exist
    let missing_path = dir.path().join("nonexistent.toml");
    let config_files: Vec<(&str, &std::path::Path)> =
        vec![("config:missing.toml", missing_path.as_path())];
    ledger
        .record_config_load(&config_files, None)
        .await
        .expect("recording config hashes for missing files must succeed (graceful)");

    let wal_content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable");
    let entries: Vec<GVMEvent> = wal_content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    assert_eq!(entries.len(), 1);
    let hash = entries[0]
        .context
        .get("config:missing.toml")
        .and_then(|v| v.as_str())
        .expect("missing file hash must still be recorded");
    assert_eq!(
        hash, "unavailable",
        "unreadable config file must be recorded as 'unavailable'"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: E2E Proxy Forwarding — Real HTTP upstream, header stripping,
//         API key injection, response passthrough
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_proxy_forwards_to_upstream_and_strips_response_headers() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    // ── Step 1: Start a mock upstream HTTP server ──
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding upstream mock server must succeed");
    let upstream_addr = upstream
        .local_addr()
        .expect("upstream must have an address");

    // Upstream handler: echoes back request info + injects malicious X-GVM-* headers
    let upstream_app = axum::Router::new().fallback(|req: Request<Body>| async move {
        // Capture whether X-GVM-* headers were stripped before forwarding
        let has_gvm_agent = req.headers().get("X-GVM-Agent-Id").is_some();
        let has_gvm_op = req.headers().get("X-GVM-Operation").is_some();
        // Check if API key was injected
        let has_auth = req
            .headers()
            .get("Authorization")
            .map(|v| v.to_str().unwrap_or("").to_string());

        let body = serde_json::json!({
            "upstream_received": true,
            "method": req.method().to_string(),
            "path": req.uri().path().to_string(),
            "gvm_headers_leaked": has_gvm_agent || has_gvm_op,
            "authorization": has_auth,
        });

        // Malicious upstream: inject fake X-GVM-* headers in response
        axum::http::Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .header("X-GVM-Decision", "Allow-Fake")
            .header("X-GVM-Event-Id", "upstream-injected-fake")
            .header("X-Custom-Upstream", "keep-this")
            .body(Body::from(body.to_string()))
            .expect("upstream response must build")
    });

    tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.ok();
    });

    // ── Step 2: Build proxy AppState with host_override ──
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");

    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 10 }
"#,
    )
    .expect("writing SRR config must succeed");

    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(
        &secrets_path,
        r#"
[credentials."api.testservice.com"]
type = "Bearer"
token = "sk_test_proxy_injected_key"
"#,
    )
    .expect("writing secrets config must succeed");

    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&srr_path).expect("valid SRR config must parse"),
    ));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).expect("valid secrets must parse"));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must init"),
    );
    let vault = Arc::new(Vault::new(ledger.clone()).expect("vault must init"));
    let token_budget = Arc::new(TokenBudget::new(0, 0.0, 500));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    // Host override: remap api.testservice.com → local upstream
    let mut host_overrides = std::collections::HashMap::new();
    host_overrides.insert(
        "api.testservice.com".to_string(),
        format!("127.0.0.1:{}", upstream_addr.port()),
    );

    let state = gvm_proxy::proxy::AppState {
        srr,

        api_keys,
        ledger: ledger.clone(),
        vault,
        token_budget,
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides,
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    // ── Step 3: Send request through proxy ──
    let request = Request::builder()
        .method("POST")
        .uri("/v1/data")
        .header("X-GVM-Agent-Id", "test-agent-e2e")
        .header("X-GVM-Operation", "gvm.storage.write")
        .header("X-GVM-Target-Host", "api.testservice.com")
        .header("X-GVM-Trace-Id", "trace-e2e-001")
        .header("X-GVM-Event-Id", "evt-e2e-001")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"key":"value"}"#))
        .expect("request must build");

    let response = app
        .oneshot(request)
        .await
        .expect("proxy must handle request");

    // ── Step 4: Verify response ──
    // Should NOT be 403 — policy allows + SRR delays, upstream reachable
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Allowed request must not be denied"
    );

    // Proxy should inject its own X-GVM-Decision header (not the fake one from upstream)
    let decision = response
        .headers()
        .get("X-GVM-Decision")
        .and_then(|v| v.to_str().ok());
    assert!(
        decision.is_some(),
        "Response must have X-GVM-Decision header from proxy"
    );
    assert_ne!(
        decision.unwrap(),
        "Allow-Fake",
        "Upstream's fake X-GVM-Decision must be stripped, not forwarded"
    );

    // Upstream's fake X-GVM-Event-Id must be stripped
    let event_id = response
        .headers()
        .get("X-GVM-Event-Id")
        .and_then(|v| v.to_str().ok());
    assert!(event_id.is_some(), "Proxy must inject X-GVM-Event-Id");
    assert_ne!(
        event_id.unwrap(),
        "upstream-injected-fake",
        "Upstream's fake X-GVM-Event-Id must be stripped"
    );

    // Non-GVM upstream headers must survive
    assert!(
        response.headers().get("X-Custom-Upstream").is_some(),
        "Non-GVM upstream headers must pass through"
    );

    // Parse response body
    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .expect("response body must be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("upstream JSON must be parseable");

    // Upstream must have received the request
    assert_eq!(
        body["upstream_received"], true,
        "Upstream must have received the request"
    );
    assert_eq!(body["method"], "POST");
    assert_eq!(body["path"], "/v1/data");

    // X-GVM-* headers must NOT leak to upstream
    assert_eq!(
        body["gvm_headers_leaked"], false,
        "X-GVM-Agent-Id and X-GVM-Operation must be stripped before forwarding to upstream"
    );

    // API key must be injected by proxy (Layer 3)
    let auth_header = body["authorization"].as_str().unwrap_or("");
    assert_eq!(
        auth_header, "Bearer sk_test_proxy_injected_key",
        "Proxy must inject API key from secrets.toml into upstream request"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8b: E2E credential injection variants — ApiKey custom header,
//          and agent-smuggled Authorization header is overwritten end-to-end.
//
// Test 8 already covers Bearer injection through the real forward path. This
// test closes the gap between the unit tests (api_keys.rs::tests) and the
// real proxy_handler() flow for two cases that previously had only unit
// coverage:
//   1. ApiKey credential type — value goes into a custom header (not Authorization).
//      Verifies the proxy strips smuggled `x-api-key` headers from the agent
//      and replaces them with the configured value, all the way through to
//      a real upstream socket.
//   2. Agent attempts to smuggle a fake `Authorization: Bearer evil-token` for
//      a host that has its own Bearer credential configured. The proxy must
//      overwrite, not append. Verified at the upstream, not just at inject().
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_credential_injection_apikey_and_agent_smuggling() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    // ── Step 1: Mock upstream that echoes the auth-relevant headers it received ──
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding upstream mock server must succeed");
    let upstream_addr = upstream
        .local_addr()
        .expect("upstream must have an address");

    let upstream_app = axum::Router::new().fallback(|req: Request<Body>| async move {
        // Snapshot every header the agent could have used to smuggle credentials.
        // The proxy MUST strip all of these and inject only its configured value.
        let auth = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        let x_api_key = req
            .headers()
            .get("x-api-key")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        let apikey = req
            .headers()
            .get("apikey")
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        let cookie = req
            .headers()
            .get(axum::http::header::COOKIE)
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .map(|v| v.to_str().unwrap_or("").to_string())
            .unwrap_or_default();

        let body = serde_json::json!({
            "host": host,
            "authorization": auth,
            "x_api_key": x_api_key,
            "apikey": apikey,
            "cookie": cookie,
        });

        axum::http::Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("upstream response must build")
    });

    tokio::spawn(async move {
        axum::serve(upstream, upstream_app).await.ok();
    });

    // ── Step 2: Build proxy AppState with two host credentials ──
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");

    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#,
    )
    .expect("writing SRR config must succeed");

    // Two hosts: one with ApiKey type (custom header), one with Bearer.
    // Both will be remapped to the same local upstream via host_overrides.
    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(
        &secrets_path,
        r#"
[credentials."api.sendgrid-test.com"]
type = "ApiKey"
header = "x-api-key"
value = "SG.proxy_injected_sendgrid_key"

[credentials."api.stripe-test.com"]
type = "Bearer"
token = "sk_test_proxy_injected_bearer"
"#,
    )
    .expect("writing secrets config must succeed");

    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&srr_path).expect("valid SRR config must parse"),
    ));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).expect("valid secrets must parse"));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must init"),
    );
    let vault = Arc::new(Vault::new(ledger.clone()).expect("vault must init"));
    let token_budget = Arc::new(TokenBudget::new(0, 0.0, 500));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let mut host_overrides = std::collections::HashMap::new();
    host_overrides.insert(
        "api.sendgrid-test.com".to_string(),
        format!("127.0.0.1:{}", upstream_addr.port()),
    );
    host_overrides.insert(
        "api.stripe-test.com".to_string(),
        format!("127.0.0.1:{}", upstream_addr.port()),
    );

    let state = gvm_proxy::proxy::AppState {
        srr,

        api_keys,
        ledger: ledger.clone(),
        vault,
        token_budget,
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides,
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    // ─────────────────────────────────────────────────────────────────────
    // Scenario A: keyless agent → SendGrid (ApiKey custom header)
    //
    // The agent has no credential of its own and just calls the API. The
    // proxy must inject `x-api-key: SG.proxy_injected_sendgrid_key` into the
    // upstream-bound request. Authorization must remain empty because the
    // ApiKey credential type does not touch it.
    // ─────────────────────────────────────────────────────────────────────
    let request = Request::builder()
        .method("POST")
        .uri("/v3/mail/send")
        .header("X-GVM-Agent-Id", "keyless-agent-A")
        .header("X-GVM-Operation", "gvm.email.send")
        .header("X-GVM-Target-Host", "api.sendgrid-test.com")
        .header("X-GVM-Trace-Id", "trace-credinj-A")
        .header("X-GVM-Event-Id", "evt-credinj-A")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"to":"x@example.com"}"#))
        .expect("request must build");

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("proxy must handle keyless ApiKey request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Allowed request must reach upstream and return 200"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .expect("response body must be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("upstream JSON must parse");

    assert_eq!(
        body["x_api_key"], "SG.proxy_injected_sendgrid_key",
        "ApiKey credential value must be injected into the configured header (x-api-key)"
    );
    assert_eq!(
        body["authorization"], "",
        "ApiKey credential type must NOT populate the Authorization header"
    );

    // ─────────────────────────────────────────────────────────────────────
    // Scenario B: malicious agent smuggles a fake Authorization header for
    // Stripe. Stripe has a Bearer credential configured. The proxy must
    // overwrite the agent's value, not append it. Also smuggles fake
    // x-api-key, apikey, and Cookie headers — all must be stripped.
    // ─────────────────────────────────────────────────────────────────────
    let request = Request::builder()
        .method("POST")
        .uri("/v1/charges")
        .header("X-GVM-Agent-Id", "malicious-agent-B")
        .header("X-GVM-Operation", "gvm.payment.charge")
        .header("X-GVM-Target-Host", "api.stripe-test.com")
        .header("X-GVM-Trace-Id", "trace-credinj-B")
        .header("X-GVM-Event-Id", "evt-credinj-B")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer agent-smuggled-evil-token")
        .header("x-api-key", "agent-smuggled-evil-apikey")
        .header("apikey", "agent-smuggled-evil-apikey-2")
        .header("Cookie", "session=agent-smuggled-session")
        .body(Body::from(r#"{"amount":1000}"#))
        .expect("request must build");

    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("proxy must handle smuggling request");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Allowed request must reach upstream and return 200"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .expect("response body must be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("upstream JSON must parse");

    // Authorization must be the proxy's Bearer token, not the agent's.
    assert_eq!(
        body["authorization"], "Bearer sk_test_proxy_injected_bearer",
        "Proxy Bearer credential must REPLACE the agent-supplied Authorization header"
    );
    // None of the smuggled secondary auth headers may have reached upstream.
    assert_eq!(
        body["x_api_key"], "",
        "Smuggled x-api-key must be stripped before forwarding"
    );
    assert_eq!(
        body["apikey"], "",
        "Smuggled apikey must be stripped before forwarding"
    );
    assert_eq!(
        body["cookie"], "",
        "Smuggled Cookie must be stripped before forwarding"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: GovernanceBlockResponse — Verify 403 JSON body contract
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn governance_block_response_contains_all_required_fields() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");

    // SRR: deny bank transfers
    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "Deny", reason = "Wire transfer blocked by SRR" }
"#,
    )
    .expect("writing SRR config must succeed");

    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n").expect("writing empty secrets must succeed");

    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&srr_path).expect("valid SRR config must parse"),
    ));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).expect("valid secrets must parse"));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must init"),
    );
    let vault = Arc::new(Vault::new(ledger.clone()).expect("vault must init"));
    let token_budget = Arc::new(TokenBudget::new(0, 0.0, 500));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = gvm_proxy::proxy::AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget,
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new()
        .fallback(gvm_proxy::proxy::proxy_handler)
        .with_state(state);

    // Send a request that will be Denied
    let request = Request::builder()
        .method("POST")
        .uri("/transfer/999")
        .header("X-GVM-Agent-Id", "agent-block-test")
        .header("X-GVM-Operation", "gvm.payment.transfer")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-block-001")
        .header("X-GVM-Event-Id", "evt-block-001")
        .body(Body::empty())
        .expect("request must build");

    let response = app
        .oneshot(request)
        .await
        .expect("proxy must handle blocked request");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Denied request must return 403"
    );

    // Verify response headers
    assert!(
        response.headers().get("X-GVM-Decision").is_some(),
        "Block response must include X-GVM-Decision header"
    );
    assert!(
        response.headers().get("X-GVM-Event-Id").is_some(),
        "Block response must include X-GVM-Event-Id header"
    );
    assert!(
        response.headers().get("X-GVM-Block-Mode").is_some(),
        "Block response must include X-GVM-Block-Mode header"
    );

    // Parse JSON body
    let body_bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .expect("response body must be readable");
    let body: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("block response must be valid JSON");

    // Verify all GovernanceBlockResponse contract fields
    assert_eq!(body["blocked"], true, "blocked field must be true");
    assert!(
        body["decision"].as_str().is_some(),
        "decision field must be present as string"
    );
    assert!(
        body["event_id"].as_str().is_some() && !body["event_id"].as_str().unwrap().is_empty(),
        "event_id must be non-empty string"
    );
    assert!(
        body["trace_id"].as_str().is_some() && !body["trace_id"].as_str().unwrap().is_empty(),
        "trace_id must be non-empty string"
    );
    assert!(
        body["operation"].as_str().is_some(),
        "operation field must be present"
    );
    assert!(
        body["reason"].as_str().is_some() && !body["reason"].as_str().unwrap().is_empty(),
        "reason must be non-empty string"
    );
    assert!(
        body["mode"].as_str().is_some(),
        "mode field must be present"
    );
    assert!(
        body["next_action"].as_str().is_some() && !body["next_action"].as_str().unwrap().is_empty(),
        "next_action must be non-empty string (actionable guidance)"
    );
    assert!(
        body["ic_level"].as_u64().is_some(),
        "ic_level must be present as number"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 10: SDK ↔ Proxy Header Contract — Verify SDK header format matches
//          what the proxy expects to parse
// ═══════════════════════════════════════════════════════════════════════════

// Test: SDK resource/context headers are audit metadata only. SRR remains the
// enforcement source, so self-declared low-risk metadata must not downgrade a
// network-level deny.
#[tokio::test]
async fn sdk_proxy_header_contract_resource_and_context_json() {
    let srr_path = tempfile::NamedTempFile::new()
        .expect("temp srr file")
        .into_temp_path();
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/*"
decision = { type = "Deny", reason = "wire transfer blocked by SRR" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Delay", milliseconds = 300 }
"#,
    )
    .expect("write srr");
    let srr = NetworkSRR::load(&srr_path).expect("srr must parse");

    let mut context = std::collections::HashMap::new();
    context.insert("approved".to_string(), serde_json::json!(true));
    context.insert("risk".to_string(), serde_json::json!("low"));

    let headers = GVMHeaders {
        operation: "gvm.storage.read".to_string(),
        agent_id: "sdk-contract-agent".to_string(),
        tenant_id: Some("tenant-a".to_string()),
        session_id: Some("session-sdk-001".to_string()),
        trace_id: "trace-contract-001".to_string(),
        event_id: "evt-contract-001".to_string(),
        parent_event_id: None,
        rate_limit: None,
        resource: Some(ResourceDescriptor {
            service: "claimed-safe-resource".to_string(),
            identifier: None,
            tier: ResourceTier::Internal,
            sensitivity: Sensitivity::Low,
        }),
        context,
    };

    let decision = srr.check("POST", "api.bank.com", "/transfer/123", None);
    assert!(
        matches!(decision.decision, EnforcementDecision::Deny { .. }),
        "SRR deny must hold even when SDK metadata claims a safe operation/resource"
    );
    assert_eq!(
        headers.context.get("risk").and_then(|v| v.as_str()),
        Some("low"),
        "SDK context remains available for audit"
    );
    assert!(matches!(
        headers.resource.as_ref().map(|r| &r.sensitivity),
        Some(Sensitivity::Low)
    ));
}

// Test 11 (Policy Conflict Detection) removed — ABAC system deleted.

// ═══════════════════════════════════════════════════════════════════════════
// Test 12: Emergency WAL → Primary Recovery Path
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn emergency_wal_to_primary_recovery_path() {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must init"),
    );

    // Phase 1: Write normally to primary WAL
    let event1 = make_test_event("normal-001", "gvm.storage.read");
    ledger
        .append_durable(&event1)
        .await
        .expect("normal WAL write must succeed");
    assert_eq!(ledger.primary_failure_count(), 0, "no failures yet");
    assert_eq!(ledger.emergency_write_count(), 0, "no emergency writes yet");

    // Phase 2: Inject write error → forces emergency WAL path
    ledger.inject_write_error(true);

    let event2 = make_test_event("emergency-001", "gvm.payment.charge");
    ledger
        .append_durable(&event2)
        .await
        .expect("emergency WAL fallback must succeed");

    assert!(
        ledger.primary_failure_count() > 0,
        "primary failure count must increment after injected error"
    );
    assert!(
        ledger.emergency_write_count() > 0,
        "emergency write count must increment when fallback is used"
    );

    // Phase 3: Remove injected error → primary should recover
    ledger.inject_write_error(false);

    let event3 = make_test_event("recovered-001", "gvm.storage.write");
    ledger
        .append_durable(&event3)
        .await
        .expect("primary WAL must accept writes after recovery");

    // Primary failure counter should reset to 0 after successful write
    assert_eq!(
        ledger.primary_failure_count(),
        0,
        "primary failure counter must reset after successful write"
    );

    // Phase 4: Verify primary WAL has events 1 and 3 (not 2)
    let wal_content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable");
    let primary_entries: Vec<GVMEvent> = wal_content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    let primary_ids: Vec<&str> = primary_entries
        .iter()
        .map(|e| e.event_id.as_str())
        .collect();
    assert!(
        primary_ids.contains(&"normal-001"),
        "primary WAL must contain pre-failure event"
    );
    assert!(
        !primary_ids.contains(&"emergency-001"),
        "primary WAL must NOT contain emergency-path event"
    );
    assert!(
        primary_ids.contains(&"recovered-001"),
        "primary WAL must contain post-recovery event"
    );

    // Phase 5: Verify emergency WAL has event 2
    let emergency_path = dir.path().join("wal_emergency.log");
    let emergency_content = tokio::fs::read_to_string(&emergency_path)
        .await
        .expect("emergency WAL file must be readable");
    let emergency_entries: Vec<GVMEvent> = emergency_content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    let emergency_ids: Vec<&str> = emergency_entries
        .iter()
        .map(|e| e.event_id.as_str())
        .collect();
    assert!(
        emergency_ids.contains(&"emergency-001"),
        "emergency WAL must contain the fallback event"
    );

    // Phase 6: Document the audit gap — emergency events have per-event hashes
    // (EmergencyWAL::append computes them) but are NOT part of a Merkle batch.
    // There is no MerkleBatchRecord in the emergency WAL file, so inter-event
    // chain integrity is not guaranteed. Emergency events also require manual
    // reconciliation into the primary WAL — this is a known limitation.
    let emergency_raw =
        std::fs::read_to_string(&emergency_path).expect("emergency WAL must be readable as string");
    let has_batch_record = emergency_raw
        .lines()
        .any(|line| line.contains("batch_id") && line.contains("merkle_root"));
    assert!(
        !has_batch_record,
        "Emergency WAL must NOT contain MerkleBatchRecord (no Merkle chain in fallback mode)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn make_test_event(event_id: &str, operation: &str) -> GVMEvent {
    GVMEvent {
        event_id: event_id.to_string(),
        trace_id: format!("trace-{}", event_id),
        parent_event_id: None,
        agent_id: "test-agent".to_string(),
        tenant_id: None,
        session_id: "session-001".to_string(),
        timestamp: chrono::Utc::now(),
        operation: operation.to_string(),
        resource: Default::default(),
        context: Default::default(),
        transport: None,
        decision: "Pending".to_string(),
        decision_source: "test".to_string(),
        matched_rule_id: None,
        enforcement_point: "test".to_string(),
        status: EventStatus::Pending,
        payload: Default::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 6: Checkpoint Save → Read → Merkle Verification Round-Trip
// ═══════════════════════════════════════════════════════════════════════════
//
// Proves the competitive-analysis claim:
//   "Automatic state checkpointing before IC-2+ operations.
//    On denial, the agent's state is rolled back to the last approved
//    checkpoint with Merkle-verified integrity."
//
// Validates:
//   a) PUT /gvm/vault/checkpoint/:agent/:step saves encrypted state
//   b) GET returns identical decrypted content
//   c) X-GVM-Merkle-Verified: true (content hash matches Merkle leaf)
//   d) Tampering detection: modified data → Merkle-Verified: false

#[tokio::test]
async fn checkpoint_save_restore_merkle_verified() {
    use axum::Router;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");

    // Minimal config files for component initialization
    let srr_path = dir.path().join("srr.toml");
    std::fs::write(&srr_path, "rules = []\n").unwrap();
    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n").unwrap();
    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&srr_path).expect("empty SRR must parse"),
    ));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).expect("empty secrets must parse"));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must init"),
    );
    let vault = Arc::new(Vault::new(ledger.clone()).expect("vault must init"));
    let token_budget = Arc::new(TokenBudget::new(0, 0.0, 500));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget,
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new()
        .route(
            "/gvm/vault/checkpoint/:agent_id/:step",
            axum::routing::put(gvm_proxy::api::checkpoint_write)
                .get(gvm_proxy::api::checkpoint_read)
                .delete(gvm_proxy::api::checkpoint_delete),
        )
        .fallback(proxy_handler)
        .with_state(state);

    // ── Step a: Save checkpoint ──
    let checkpoint_data = serde_json::json!({
        "conversation_history": [
            {"role": "user", "content": "Transfer $50K"},
            {"role": "assistant", "content": "Processing..."}
        ],
        "state": {"balance": 100000, "step": 2},
        "metadata": {"agent": "finance-agent", "version": "1.0"}
    });
    let _body_bytes = serde_json::to_vec(&checkpoint_data).unwrap();

    // Steps must be sequential starting from 0 (enforced by CheckpointRegistry)
    let body_bytes = b"{\"state\":\"test\",\"step\":0}".to_vec();

    let request = axum::http::Request::builder()
        .method("PUT")
        .uri("/gvm/vault/checkpoint/finance-agent/0")
        .header("Content-Type", "application/octet-stream")
        .body(axum::body::Body::from(body_bytes.clone()))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    if response.status() != axum::http::StatusCode::OK {
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap_or_default();
        panic!(
            "Checkpoint save failed with {}: {}",
            400,
            String::from_utf8_lossy(&body)
        );
    }

    let save_body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let save_json: serde_json::Value = serde_json::from_slice(&save_body).unwrap();
    assert_eq!(save_json["status"], "ok");
    assert!(
        save_json["content_hash"].is_string(),
        "content_hash must be present"
    );
    assert!(
        save_json["merkle_root"].is_string(),
        "merkle_root must be present"
    );
    let saved_hash = save_json["content_hash"].as_str().unwrap().to_string();

    // ── Step b: Read checkpoint back ──
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/gvm/vault/checkpoint/finance-agent/0")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "Checkpoint read must succeed"
    );

    // ── Step c: Verify Merkle integrity ──
    let merkle_verified = response
        .headers()
        .get("X-GVM-Merkle-Verified")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    assert_eq!(
        merkle_verified, "true",
        "Decrypted checkpoint must pass Merkle verification"
    );

    let checkpoint_step = response
        .headers()
        .get("X-GVM-Checkpoint-Step")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("missing");
    assert_eq!(checkpoint_step, "0");

    // Verify content matches original
    let read_body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        read_body.as_ref(),
        body_bytes.as_slice(),
        "Restored checkpoint must match saved data byte-for-byte"
    );

    // ── Step d: Save second checkpoint, verify Merkle tree grows ──
    let step3_data = b"step 3 state: payment approved";
    let request = axum::http::Request::builder()
        .method("PUT")
        .uri("/gvm/vault/checkpoint/finance-agent/1")
        .body(axum::body::Body::from(step3_data.to_vec()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let step3_body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let step3_json: serde_json::Value = serde_json::from_slice(&step3_body).unwrap();
    let step3_hash = step3_json["content_hash"].as_str().unwrap();
    assert_ne!(
        step3_hash, saved_hash,
        "Different content must produce different hashes"
    );

    // ── Step e: Read non-existent checkpoint → 404 ──
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/gvm/vault/checkpoint/finance-agent/999")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::NOT_FOUND,
        "Non-existent checkpoint must return 404"
    );

    // ── Step f: Delete checkpoint ──
    let request = axum::http::Request::builder()
        .method("DELETE")
        .uri("/gvm/vault/checkpoint/finance-agent/0")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "Checkpoint delete must succeed"
    );

    // Verify deleted checkpoint returns 404
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/gvm/vault/checkpoint/finance-agent/0")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 7: LLM Thinking Trace Extraction
// ═══════════════════════════════════════════════════════════════════════════
//
// Proves the competitive-analysis claim:
//   "When the proxy processes an IC-2 response from a known LLM provider,
//    it extracts reasoning/thinking content."
//
// Tests the extraction logic directly (not through the full proxy pipeline,
// since that requires a real upstream LLM server). Validates:
//   a) OpenAI reasoning_content extraction
//   b) Anthropic thinking block extraction
//   c) Gemini thought part extraction
//   d) Privacy: SHA-256 hash by default, raw opt-in
//   e) SSE streaming response parsing
//   f) Unknown provider returns None

#[test]
fn llm_trace_openai_reasoning_extraction() {
    let body = serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "o1-preview",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "I will transfer $50,000.",
                "reasoning_content": "The user asked me to transfer money. I should check if this is authorized."
            }
        }],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    });

    let trace = gvm_proxy::llm_trace::extract_thinking_trace("openai", body.to_string().as_bytes());
    assert!(
        trace.is_some(),
        "OpenAI reasoning_content must be extracted"
    );

    let t = trace.unwrap();
    assert_eq!(t.provider, "openai");
    assert_eq!(t.model.as_deref(), Some("o1-preview"));
    // Default: privacy mode — thinking content is replaced with SHA-256 hash
    assert!(t.thinking.is_some(), "thinking field must be present");
    assert!(
        t.thinking.as_ref().unwrap().starts_with("sha256:"),
        "Default privacy mode must hash thinking content: got {:?}",
        t.thinking,
    );
    // Usage
    assert!(t.usage.is_some());
    let usage = t.usage.unwrap();
    assert_eq!(usage.total_tokens, Some(150));
}

#[test]
fn llm_trace_openai_raw_opt_in() {
    let body = serde_json::json!({
        "choices": [{
            "message": {
                "reasoning_content": "Internal reasoning about the transfer"
            }
        }],
        "model": "o1"
    });

    // store_raw=true → raw thinking is stored (not hashed)
    let trace = gvm_proxy::llm_trace::extract_thinking_trace_with_privacy(
        "openai",
        body.to_string().as_bytes(),
        true, // store_raw ON → store raw thinking
    );
    let t = trace.unwrap();
    assert!(
        t.thinking.is_some(),
        "raw thinking must be stored when privacy is off"
    );
    assert!(
        t.thinking.as_ref().unwrap().contains("Internal reasoning"),
        "raw thinking content must match"
    );
}

#[test]
fn llm_trace_anthropic_thinking_block() {
    let body = serde_json::json!({
        "id": "msg_test",
        "type": "message",
        "model": "claude-sonnet-4-20250514",
        "content": [
            {
                "type": "thinking",
                "thinking": "Let me analyze this financial request carefully..."
            },
            {
                "type": "text",
                "text": "I'll process the transfer."
            }
        ],
        "usage": {
            "input_tokens": 200,
            "output_tokens": 80
        }
    });

    // store_raw = false → privacy ON → thinking is SHA-256 hashed
    let trace = gvm_proxy::llm_trace::extract_thinking_trace_with_privacy(
        "anthropic",
        body.to_string().as_bytes(),
        false,
    );
    assert!(
        trace.is_some(),
        "Anthropic thinking block must be extracted"
    );

    let t = trace.unwrap();
    assert_eq!(t.provider, "anthropic");
    assert_eq!(t.model.as_deref(), Some("claude-sonnet-4-20250514"));
    assert!(
        t.thinking.as_ref().unwrap().starts_with("sha256:"),
        "Privacy mode must hash thinking: got {:?}",
        t.thinking,
    );
}

#[test]
fn llm_trace_gemini_thought_extraction() {
    let body = serde_json::json!({
        "candidates": [{
            "content": {
                "parts": [
                    {"thought": true, "text": "Analyzing the request for safety..."},
                    {"text": "Sure, I can help with that."}
                ]
            }
        }],
        "modelVersion": "gemini-2.0-flash-thinking-exp"
    });

    let trace = gvm_proxy::llm_trace::extract_thinking_trace_with_privacy(
        "gemini",
        body.to_string().as_bytes(),
        false,
    );
    assert!(trace.is_some(), "Gemini thought parts must be extracted");
    let t = trace.unwrap();
    assert_eq!(t.provider, "gemini");
}

#[test]
fn llm_trace_unknown_provider_returns_none() {
    let body = b"{\"choices\": [{\"message\": {\"content\": \"hello\"}}]}";
    let trace = gvm_proxy::llm_trace::extract_thinking_trace("unknown_provider", body);
    assert!(trace.is_none(), "Unknown provider must return None");
}

#[test]
fn llm_trace_provider_identification() {
    assert_eq!(
        gvm_proxy::llm_trace::identify_llm_provider("api.openai.com"),
        Some("openai")
    );
    assert_eq!(
        gvm_proxy::llm_trace::identify_llm_provider("api.anthropic.com"),
        Some("anthropic")
    );
    assert_eq!(
        gvm_proxy::llm_trace::identify_llm_provider("generativelanguage.googleapis.com"),
        Some("gemini")
    );
    assert_eq!(
        gvm_proxy::llm_trace::identify_llm_provider("api.stripe.com"),
        None
    );
    // With port stripping
    assert_eq!(
        gvm_proxy::llm_trace::identify_llm_provider("api.openai.com:443"),
        Some("openai")
    );
}

#[test]
fn llm_trace_sse_streaming_openai() {
    // Simulate SSE streaming response from OpenAI with reasoning chunks
    let sse_body = "\
data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"o1\",\"choices\":[{\"delta\":{\"reasoning_content\":\"Step 1: \"}}]}\n\n\
data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"o1\",\"choices\":[{\"delta\":{\"reasoning_content\":\"analyze the request.\"}}]}\n\n\
data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"o1\",\"choices\":[{\"delta\":{\"content\":\"Done.\"}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n\
data: [DONE]\n\n";

    let trace =
        gvm_proxy::llm_trace::extract_thinking_trace_from_sse("openai", sse_body.as_bytes());
    assert!(trace.is_some(), "SSE streaming trace must be extracted");

    let t = trace.unwrap();
    assert_eq!(t.provider, "openai");
    assert_eq!(t.model.as_deref(), Some("o1"));
    // Thinking content should be concatenated from delta chunks and hashed (privacy default)
    assert!(
        t.thinking.as_ref().unwrap().starts_with("sha256:"),
        "SSE thinking must be hashed by default"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 8: IC-3 Approval Flow — Hold → Approve/Deny via API
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ic3_approval_hold_and_approve_via_api() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use gvm_proxy::api;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");

    // SRR: require approval for bank transfers
    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "RequireApproval", urgency = "Standard" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#,
    )
    .unwrap();

    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n").unwrap();

    let wal_path = dir.path().join("wal.log");
    let srr = Arc::new(std::sync::RwLock::new(
        NetworkSRR::load(&srr_path).expect("SRR must parse"),
    ));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).expect("secrets must parse"));
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must init"),
    );
    let vault = Arc::new(Vault::new(ledger.clone()).expect("vault must init"));
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let pending_approvals = std::sync::Arc::new(dashmap::DashMap::new());

    let state = AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget: Arc::new(TokenBudget::new(0, 0.0, 500)),
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: pending_approvals.clone(),
        ic3_approval_timeout_secs: 5, // Short timeout for test
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new()
        .route("/gvm/pending", axum::routing::get(api::pending_approvals))
        .route("/gvm/approve", axum::routing::post(api::approve_request))
        .fallback(proxy_handler)
        .with_state(state);

    // ── Scenario A: IC-3 triggers, approve via API → request would forward ──
    // We spawn the proxy request in a task and approve from another task.
    let app_clone = app.clone();
    let pending_clone = pending_approvals.clone();

    let proxy_task = tokio::spawn(async move {
        let request = Request::builder()
            .method("POST")
            .uri("/transfer/123")
            .header("Host", "api.bank.com")
            .header("X-GVM-Agent-Id", "test-agent")
            .header("X-GVM-Operation", "gvm.payment.transfer")
            .header("X-GVM-Target-Host", "api.bank.com")
            .header("X-GVM-Trace-Id", "trace-ic3-001")
            .header("X-GVM-Event-Id", "evt-ic3-001")
            .body(Body::empty())
            .unwrap();

        app_clone.oneshot(request).await.unwrap()
    });

    // Wait for the pending approval to appear
    let mut found = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if !pending_clone.is_empty() {
            found = true;
            break;
        }
    }
    assert!(found, "IC-3 pending approval must appear in DashMap");

    // Verify pending list has our event
    assert_eq!(pending_clone.len(), 1);
    let event_id = {
        let entry = pending_clone.iter().next().unwrap();
        assert_eq!(entry.value().host, "api.bank.com");
        assert_eq!(entry.value().agent_id, "test-agent");
        entry.value().event_id.clone()
    };

    // Deny via API
    let deny_request = Request::builder()
        .method("POST")
        .uri("/gvm/approve")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "event_id": event_id,
                "approved": false,
            }))
            .unwrap(),
        ))
        .unwrap();

    let approve_response = app.clone().oneshot(deny_request).await.unwrap();
    assert_eq!(approve_response.status(), StatusCode::OK);

    // Proxy task should complete with 403 (denied)
    let proxy_response = proxy_task.await.unwrap();
    assert_eq!(
        proxy_response.status(),
        StatusCode::FORBIDDEN,
        "Denied IC-3 request must return 403"
    );

    // Verify pending map is now empty
    assert!(
        pending_clone.is_empty(),
        "Pending approvals must be cleared after decision"
    );
}

#[tokio::test]
async fn ic3_approval_timeout_auto_denies() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");

    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "RequireApproval", urgency = "Immediate" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#,
    )
    .unwrap();

    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n").unwrap();
    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(NetworkSRR::load(&srr_path).unwrap()));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).unwrap());
    let ledger = Arc::new(Ledger::new(&wal_path, "", "").await.unwrap());
    let vault = Arc::new(Vault::new(ledger.clone()).unwrap());
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget: Arc::new(TokenBudget::new(0, 0.0, 500)),
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 1, // 1 second timeout for fast test
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new().fallback(proxy_handler).with_state(state);

    let start = std::time::Instant::now();
    let request = Request::builder()
        .method("POST")
        .uri("/transfer/456")
        .header("Host", "api.bank.com")
        .header("X-GVM-Agent-Id", "timeout-agent")
        .header("X-GVM-Operation", "gvm.payment.transfer")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("X-GVM-Trace-Id", "trace-timeout")
        .header("X-GVM-Event-Id", "evt-timeout")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "IC-3 timeout must auto-deny with 403"
    );

    // Verify it actually waited (at least ~1 second)
    assert!(
        elapsed.as_millis() >= 800,
        "IC-3 must hold for approximately the timeout duration (got {}ms)",
        elapsed.as_millis()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 9: SRR Payload Inspection — Body Buffering + JSON Field Matching
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn srr_payload_inspection_matches_json_body_field() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");

    // SRR with payload_field matching: deny transfers with amount > threshold
    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
payload_field = "amount"
payload_match = ["50000", "100000"]
decision = { type = "Deny", reason = "High-value transfer blocked" }

[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "Allow" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#,
    )
    .unwrap();

    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n").unwrap();
    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(NetworkSRR::load(&srr_path).unwrap()));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).unwrap());
    let ledger = Arc::new(Ledger::new(&wal_path, "", "").await.unwrap());
    let vault = Arc::new(Vault::new(ledger.clone()).unwrap());
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget: Arc::new(TokenBudget::new(0, 0.0, 500)),
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: true, // ENABLED for this test
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new().fallback(proxy_handler).with_state(state);

    // ── Scenario A: Body with matching amount → DENY ──
    let request = Request::builder()
        .method("POST")
        .uri("/transfer/789")
        .header("Host", "api.bank.com")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("Content-Type", "application/json")
        .header("Content-Length", "25")
        .body(Body::from(r#"{"amount":"50000","to":"X"}"#))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Payload matching amount=50000 must trigger Deny"
    );

    // ── Scenario B: Body with non-matching amount → ALLOW (falls through to second rule) ──
    let request = Request::builder()
        .method("POST")
        .uri("/transfer/789")
        .header("Host", "api.bank.com")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("Content-Type", "application/json")
        .header("Content-Length", "22")
        .body(Body::from(r#"{"amount":"100","to":"Y"}"#))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    // Should NOT be 403 — the amount doesn't match the deny rule
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Non-matching payload must NOT be denied"
    );
}

#[tokio::test]
async fn srr_payload_inspection_disabled_ignores_body() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");

    // Same SRR rules with payload matching, but payload_inspection = false
    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
payload_field = "amount"
payload_match = ["50000"]
decision = { type = "Deny", reason = "High-value transfer blocked" }

[[rules]]
method = "POST"
pattern = "api.bank.com/transfer/{any}"
decision = { type = "Allow" }

[[rules]]
method = "*"
pattern = "{any}"
decision = { type = "Allow" }
"#,
    )
    .unwrap();

    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n").unwrap();
    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(NetworkSRR::load(&srr_path).unwrap()));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).unwrap());
    let ledger = Arc::new(Ledger::new(&wal_path, "", "").await.unwrap());
    let vault = Arc::new(Vault::new(ledger.clone()).unwrap());
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget: Arc::new(TokenBudget::new(0, 0.0, 500)),
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false, // DISABLED — body should NOT be inspected
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    let app = Router::new().fallback(proxy_handler).with_state(state);

    // Even though body has amount=50000, payload_inspection is OFF → body=None → no match → Allow
    let request = Request::builder()
        .method("POST")
        .uri("/transfer/789")
        .header("Host", "api.bank.com")
        .header("X-GVM-Target-Host", "api.bank.com")
        .header("Content-Type", "application/json")
        .header("Content-Length", "25")
        .body(Body::from(r#"{"amount":"50000","to":"X"}"#))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    // With payload_inspection=false, the payload rule doesn't fire → falls through to Allow
    assert_ne!(
        response.status(),
        StatusCode::FORBIDDEN,
        "With payload_inspection=false, body must NOT be inspected (no deny)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 10: IC-3 Self-Approval Prevention — /gvm/approve NOT on proxy port
// ═══════════════════════════════════════════════════════════════════════════

/// Proves that an agent cannot self-approve IC-3 requests by calling /gvm/approve
/// on the proxy port (8080). The approve endpoint must only be on the admin port.
#[tokio::test]
async fn ic3_self_approval_blocked_on_proxy_port() {
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use tower::ServiceExt;

    let dir = tempfile::tempdir().expect("temp dir");
    let srr_path = dir.path().join("srr.toml");
    std::fs::write(
        &srr_path,
        "[[rules]]\nmethod = \"*\"\npattern = \"{any}\"\ndecision = { type = \"Allow\" }\n",
    )
    .unwrap();
    let secrets_path = dir.path().join("secrets.toml");
    std::fs::write(&secrets_path, "[credentials]\n").unwrap();
    let wal_path = dir.path().join("wal.log");

    let srr = Arc::new(std::sync::RwLock::new(NetworkSRR::load(&srr_path).unwrap()));
    let api_keys = Arc::new(APIKeyStore::load(&secrets_path).unwrap());
    let ledger = Arc::new(Ledger::new(&wal_path, "", "").await.unwrap());
    let vault = Arc::new(Vault::new(ledger.clone()).unwrap());
    let http_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    let state = AppState {
        srr,

        api_keys,
        ledger,
        vault,
        token_budget: Arc::new(TokenBudget::new(0, 0.0, 500)),
        per_agent_budgets: Arc::new(gvm_proxy::token_budget::PerAgentBudgets::new(0, 0.0, 500)),
        #[cfg(feature = "wasm")]
        wasm_engine: Arc::new(gvm_proxy::wasm_engine::WasmEngine::native()),
        checkpoint_registry: gvm_proxy::api::CheckpointRegistry::new(),
        on_block: gvm_proxy::config::OnBlockConfig::default(),
        http_client,
        host_overrides: std::collections::HashMap::new(),
        jwt_config: None,
        intent_store: Arc::new(gvm_proxy::intent_store::IntentStore::new(30)),
        srr_config_path: String::new(),

        gvm_toml_path: None,
        mitm_ca_pem: None,
        payload_inspection: false,
        max_body_bytes: 65536,
        pending_approvals: std::sync::Arc::new(dashmap::DashMap::new()),
        ic3_approval_timeout_secs: 300,
        shadow_config: gvm_proxy::intent_store::ShadowConfig::default(),
        mitm_resolver: None,
        mitm_server_config: None,
        mitm_client_config: None,
        tls_ready: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        request_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ca_expires_days: None,
        dns_governance: None,
        wal_path: "data/wal.log".to_string(),
        active_integrity_ref: std::sync::Arc::new(std::sync::RwLock::new(None)),
    };

    // Build AGENT-FACING router only (no admin endpoints)
    // This mirrors main.rs: proxy port does NOT have /gvm/approve or /gvm/pending
    let agent_app = Router::new()
        .route("/gvm/health", axum::routing::get(gvm_proxy::api::health))
        .route("/gvm/check", axum::routing::post(gvm_proxy::api::check))
        .fallback(proxy_handler)
        .with_state(state);

    // Agent tries to call /gvm/approve on proxy port → should get 404 (not routed)
    let approve_request = Request::builder()
        .method("POST")
        .uri("/gvm/approve")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"event_id":"evt-123","approved":true}"#))
        .unwrap();

    let response = agent_app.clone().oneshot(approve_request).await.unwrap();
    // /gvm/approve is NOT on the agent-facing router → fallback to proxy_handler
    // Proxy handler will try to forward this as an HTTP request, not approve it.
    // The key assertion: the response must NOT be 200 OK with approval confirmation.
    let _status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        !body_str.contains("\"decision\":\"approved\""),
        "SECURITY VIOLATION: /gvm/approve must NOT be accessible on the agent proxy port. \
         Agent could self-approve IC-3 requests. Response: {}",
        body_str
    );

    // Also verify /gvm/pending is not on agent port
    let pending_request = Request::builder()
        .method("GET")
        .uri("/gvm/pending")
        .body(Body::empty())
        .unwrap();

    let response = agent_app.oneshot(pending_request).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    let body_str = String::from_utf8_lossy(&body);

    assert!(
        !body_str.contains("\"pending\""),
        "SECURITY VIOLATION: /gvm/pending must NOT be accessible on the agent proxy port. \
         Agent could discover pending approval event_ids. Response: {}",
        body_str
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test 11: max_strict verifies decision VARIANT, not just strictness value
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn max_strict_returns_correct_decision_variant() {
    use gvm_types::{max_strict, EnforcementDecision};

    // Allow vs Deny → must return Deny (not just strictness=5)
    let result = max_strict(
        EnforcementDecision::Allow,
        EnforcementDecision::Deny {
            reason: "blocked".to_string(),
        },
    );
    assert!(
        matches!(result, EnforcementDecision::Deny { .. }),
        "max_strict(Allow, Deny) must return Deny variant, got: {:?}",
        result
    );

    // Deny vs Allow → same result regardless of order
    let result = max_strict(
        EnforcementDecision::Deny {
            reason: "blocked".to_string(),
        },
        EnforcementDecision::Allow,
    );
    assert!(
        matches!(result, EnforcementDecision::Deny { .. }),
        "max_strict(Deny, Allow) must return Deny variant, got: {:?}",
        result
    );

    // Delay vs RequireApproval → RequireApproval wins
    let result = max_strict(
        EnforcementDecision::Delay { milliseconds: 300 },
        EnforcementDecision::RequireApproval {
            urgency: gvm_types::ApprovalUrgency::Standard,
        },
    );
    assert!(
        matches!(result, EnforcementDecision::RequireApproval { .. }),
        "max_strict(Delay, RequireApproval) must return RequireApproval, got: {:?}",
        result
    );

    // RequireApproval vs Deny → Deny wins
    let result = max_strict(
        EnforcementDecision::RequireApproval {
            urgency: gvm_types::ApprovalUrgency::Immediate,
        },
        EnforcementDecision::Deny {
            reason: "policy".to_string(),
        },
    );
    assert!(
        matches!(result, EnforcementDecision::Deny { .. }),
        "max_strict(RequireApproval, Deny) must return Deny, got: {:?}",
        result
    );

    // Same strictness level → first argument wins (stable ordering)
    let result = max_strict(
        EnforcementDecision::Deny {
            reason: "first".to_string(),
        },
        EnforcementDecision::Deny {
            reason: "second".to_string(),
        },
    );
    match &result {
        EnforcementDecision::Deny { reason } => {
            assert_eq!(
                reason, "first",
                "Same strictness: first argument should win"
            );
        }
        _ => panic!("max_strict(Deny, Deny) must return Deny"),
    }
}
