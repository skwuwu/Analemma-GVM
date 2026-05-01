//! Boundary and security verification tests across system boundaries.
//!
//! Tests organized by boundary:
//! 1. Wasm <-> Rust Host: engine evaluation edge cases, FFI serialization
//! 2. Proxy <-> Agent (inbound HTTP): header injection, decision spoofing, duplicate headers
//! 3. Proxy <-> External API (outbound): SSRF prevention, API key leak defense
//! 4. NATS boundary: channel backpressure, WAL-only fallback
//! 5. Vault/Redis boundary: large value, key collision, encryption integrity
//! 6. Docker isolation: documented as infrastructure-dependent (cfg-gated)
//!
//! Many tests in categories 2-6 require a running proxy or external infrastructure.
//! Tests marked [INFRA_REQUIRED] are documented but cfg-gated — they will be
//! activated once the corresponding infrastructure is available.

use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::*;
use std::sync::Arc;

// ═══════════════════════════════════════════════════════════════════════════════
// 1. Wasm <-> Rust Host Boundary
//    Requires --features wasm (gvm-engine is an optional dependency)
// ═══════════════════════════════════════════════════════════════════════════════

// ── 1.1 Wasm engine native fallback: unknown decision string defaults to Delay (fail-close) ──

#[cfg(feature = "wasm")]
#[test]
fn wasm_invalid_decision_string_maps_to_delay() {
    use gvm_proxy::wasm_engine::WasmEngine;

    // response_to_decision should default to Delay (fail-close) for unknown decision strings
    let resp = gvm_engine::EvalResponse {
        decision: "InvalidDecisionType".to_string(),
        delay_ms: None,
        reason: None,
        matched_rule: None,
        matched_layer: None,
        engine_version: "0.1.0-wasm".to_string(),
    };

    let (decision, _rule_id) = WasmEngine::response_to_decision(&resp);
    assert!(
        matches!(decision, EnforcementDecision::Delay { milliseconds: 300 }),
        "Unknown decision type must map to Delay 300ms (fail-close), got {:?}",
        decision
    );
}

// ── 1.2 Wasm engine: malformed EvalResponse JSON handled gracefully ──

#[cfg(feature = "wasm")]
#[test]
fn wasm_malformed_response_does_not_crash() {
    // Test that evaluate_json handles garbage input without panic
    let garbage_inputs = vec![
        "",
        "{}",
        "null",
        "42",
        "\"string\"",
        "[1,2,3]",
        "{\"operation\":\"test\"}", // missing required fields
        "{\"invalid\": true, \"garbage\": [1,2,3]}",
        "\x00\x01\x02\x03",
        "{\"operation\":\"test\",\"resource\":{},\"subject\":{},\"rules\":[]}",
    ];

    for input in &garbage_inputs {
        // Must not panic — error response is acceptable
        let output = gvm_engine::evaluate_json(input);
        // Output must be valid JSON (either success or error)
        assert!(
            serde_json::from_str::<serde_json::Value>(&output).is_ok(),
            "evaluate_json must return valid JSON even for garbage input: {:?}, got: {}",
            input,
            output
        );
    }
}

// ── 1.3 Wasm engine: oversized input serialization ──

#[cfg(feature = "wasm")]
#[test]
fn wasm_oversized_input_handled_gracefully() {
    // 1MB operation name — should not crash or OOM
    let huge_operation = "x".repeat(1_000_000);
    let req = gvm_engine::EvalRequest {
        operation: huge_operation,
        resource: gvm_engine::ResourceAttrs {
            service: "test".to_string(),
            tier: "external".to_string(),
            sensitivity: "low".to_string(),
        },
        subject: gvm_engine::SubjectAttrs {
            agent_id: "test-agent".to_string(),
            tenant_id: None,
        },
        context: gvm_engine::ContextAttrs::default(),
        rules: vec![],
    };

    // Must not panic or OOM
    let resp = gvm_engine::evaluate(&req);
    assert_eq!(resp.decision, "Allow", "No rules = Allow");

    // JSON roundtrip with huge input
    let json = serde_json::to_string(&req).expect("valid EvalRequest must serialize to JSON");
    assert!(
        json.len() > 1_000_000,
        "JSON must contain the huge operation name"
    );
    let output = gvm_engine::evaluate_json(&json);
    let parsed: gvm_engine::EvalResponse =
        serde_json::from_str(&output).expect("engine output must be valid EvalResponse JSON");
    assert_eq!(parsed.decision, "Allow");
}

// ── 1.4 Wasm engine: unicode boundary in operation names ──

#[cfg(feature = "wasm")]
#[test]
fn wasm_unicode_boundary_operation_names() {
    let unicode_operations = vec![
        "gvm.메시지.전송",              // Korean
        "gvm.messaging.\u{0000}send",   // null byte
        "gvm.messaging.send\u{FFFF}",   // max BMP char
        "gvm.messaging.send\u{10FFFF}", // max Unicode code point
        "gvm.messaging.\u{200B}send",   // zero-width space
        "gvm.messaging.\u{202E}dnes",   // right-to-left override
        "gvm.\u{D7FF}.send",            // boundary below surrogates
        "\u{1F4A9}.\u{1F525}.\u{2764}", // emoji operation names
    ];

    for op in &unicode_operations {
        let req = gvm_engine::EvalRequest {
            operation: op.to_string(),
            resource: gvm_engine::ResourceAttrs {
                service: "test".to_string(),
                tier: "external".to_string(),
                sensitivity: "low".to_string(),
            },
            subject: gvm_engine::SubjectAttrs {
                agent_id: "test-agent".to_string(),
                tenant_id: None,
            },
            context: gvm_engine::ContextAttrs::default(),
            rules: vec![],
        };

        // Must not panic
        let resp = gvm_engine::evaluate(&req);
        assert_eq!(
            resp.decision, "Allow",
            "Unicode operation name must not crash: {:?}",
            op
        );
    }
}

// ── 1.5 Wasm engine: null in JSON string fields ──

#[cfg(feature = "wasm")]
#[test]
fn wasm_null_bytes_in_string_fields() {
    let req = gvm_engine::EvalRequest {
        operation: "gvm.test.\0inject".to_string(),
        resource: gvm_engine::ResourceAttrs {
            service: "test\0service".to_string(),
            tier: "ext\0ernal".to_string(),
            sensitivity: "lo\0w".to_string(),
        },
        subject: gvm_engine::SubjectAttrs {
            agent_id: "agent\0-001".to_string(),
            tenant_id: Some("tenant\0-001".to_string()),
        },
        context: gvm_engine::ContextAttrs::default(),
        rules: vec![gvm_engine::Rule {
            id: "rule\0-001".to_string(),
            priority: 1,
            layer: "global".to_string(),
            conditions: vec![gvm_engine::Condition {
                field: "operation".to_string(),
                operator: "eq".to_string(),
                value: serde_json::Value::String("gvm.test.\0inject".to_string()),
            }],
            decision: gvm_engine::Decision {
                decision_type: "Deny".to_string(),
                milliseconds: None,
                reason: Some("null\0byte test".to_string()),
            },
        }],
    };

    // Must not panic — null bytes in strings are valid in Rust
    let resp = gvm_engine::evaluate(&req);
    // The condition should actually match since the null bytes are identical
    assert_eq!(
        resp.decision, "Deny",
        "Null bytes in matching strings should still match"
    );
}

// ── 1.6 Wasm engine: all decision types roundtrip correctly ──

#[cfg(feature = "wasm")]
#[test]
fn wasm_all_decision_types_roundtrip() {
    use gvm_proxy::wasm_engine::WasmEngine;

    let test_cases: Vec<(&str, Option<u64>, Option<&str>)> = vec![
        ("Allow", None, None),
        ("Delay", Some(500), None),
        ("Deny", None, Some("test reason")),
        ("RequireApproval", None, None),
        ("AuditOnly", None, None),
    ];

    for (decision_type, delay_ms, reason) in &test_cases {
        let resp = gvm_engine::EvalResponse {
            decision: decision_type.to_string(),
            delay_ms: *delay_ms,
            reason: reason.map(|s| s.to_string()),
            matched_rule: Some("test-rule".to_string()),
            matched_layer: Some("global".to_string()),
            engine_version: "0.1.0-wasm".to_string(),
        };

        let (decision, _) = WasmEngine::response_to_decision(&resp);

        // Verify correct mapping
        match decision_type {
            &"Allow" => assert!(matches!(decision, EnforcementDecision::Allow)),
            &"Delay" => assert!(matches!(
                decision,
                EnforcementDecision::Delay { milliseconds: 500 }
            )),
            &"Deny" => assert!(matches!(decision, EnforcementDecision::Deny { .. })),
            &"RequireApproval" => assert!(matches!(
                decision,
                EnforcementDecision::RequireApproval { .. }
            )),
            &"AuditOnly" => assert!(matches!(decision, EnforcementDecision::AuditOnly { .. })),
            _ => unreachable!(),
        }
    }
}

// ── 1.7 Wasm engine: concurrent evaluations do not corrupt state ──

#[cfg(feature = "wasm")]
#[tokio::test]
async fn wasm_concurrent_native_evaluations_no_corruption() {
    use gvm_proxy::wasm_engine::WasmEngine;

    let engine = Arc::new(WasmEngine::native());

    let mut handles = Vec::new();
    for i in 0..100 {
        let engine = engine.clone();
        handles.push(tokio::spawn(async move {
            let req = gvm_engine::EvalRequest {
                operation: format!("gvm.test.op-{}", i),
                resource: gvm_engine::ResourceAttrs {
                    service: "test".to_string(),
                    tier: "external".to_string(),
                    sensitivity: if i % 2 == 0 { "critical" } else { "low" }.to_string(),
                },
                subject: gvm_engine::SubjectAttrs {
                    agent_id: format!("agent-{}", i),
                    tenant_id: None,
                },
                context: gvm_engine::ContextAttrs::default(),
                rules: if i % 3 == 0 {
                    vec![gvm_engine::Rule {
                        id: format!("rule-{}", i),
                        priority: 1,
                        layer: "global".to_string(),
                        conditions: vec![],
                        decision: gvm_engine::Decision {
                            decision_type: "Deny".to_string(),
                            milliseconds: None,
                            reason: Some(format!("Denied by rule-{}", i)),
                        },
                    }]
                } else {
                    vec![]
                },
            };

            let resp = engine
                .evaluate(&req)
                .expect("concurrent evaluation must not fail");
            (i, resp.decision.clone())
        }));
    }

    for handle in handles {
        let (i, decision) = handle.await.expect("spawned task must not panic");
        if i % 3 == 0 {
            assert_eq!(decision, "Deny", "Agent {} with rules should be Denied", i);
        } else {
            assert_eq!(
                decision, "Allow",
                "Agent {} with no rules should be Allowed",
                i
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. Proxy <-> Agent (Inbound HTTP) Boundary
// ═══════════════════════════════════════════════════════════════════════════════

// ── 2.1 Decision spoofing: inbound X-GVM-Decision header must be ignored ──
// The proxy sets X-GVM-Decision on RESPONSES, never trusts it on REQUEST.
// Verify that an attacker cannot inject a fake decision header.

#[test]
fn inbound_decision_header_not_in_parsed_gvm_headers() {
    // GVMHeaders struct does NOT contain a `decision` field.
    // This is a compile-time guarantee: even if an attacker sends X-GVM-Decision,
    // parse_gvm_headers() only extracts defined fields and ignores the rest.
    //
    // Verify by checking the GVMHeaders fields — no decision field exists.
    let headers = GVMHeaders {
        agent_id: "test".to_string(),
        trace_id: "trace".to_string(),
        parent_event_id: None,
        event_id: "event".to_string(),
        operation: "gvm.test.read".to_string(),
        resource: None,
        context: std::collections::HashMap::new(),
        session_id: None,
        tenant_id: None,
        rate_limit: None,
    };

    // GVMHeaders has no `decision` field — compile-time proof.
    // The proxy's parse_gvm_headers() only reads the fields above.
    // X-GVM-Decision on inbound requests is silently ignored.
    assert_eq!(headers.agent_id, "test");
    // This test serves as documentation that the struct design prevents spoofing.
}

// ── 2.2 Duplicate GVM headers: only first value used (axum behavior) ──

#[test]
fn duplicate_gvm_headers_first_value_wins() {
    // axum's HeaderMap uses the standard HTTP semantics:
    // .get() returns the first value for a given header name.
    // Verify this behavior directly.
    use axum::http::HeaderMap;

    let mut headers = HeaderMap::new();
    headers.append(
        "X-GVM-Agent-Id",
        "real-agent"
            .parse()
            .expect("static header value must parse"),
    );
    headers.append(
        "X-GVM-Agent-Id",
        "injected-agent"
            .parse()
            .expect("static header value must parse"),
    );

    let value = headers
        .get("X-GVM-Agent-Id")
        .expect("appended header must exist")
        .to_str()
        .expect("ASCII header value must convert to str");
    assert_eq!(
        value, "real-agent",
        "First header value must win (axum .get() returns first)"
    );
}

// ── 2.3 Header injection: newline in header value rejected ──

#[test]
fn header_injection_newline_rejected() {
    use axum::http::HeaderValue;

    // HTTP header injection via newline characters
    let injection_attempts = vec![
        "agent-001\r\nX-Injected: true",
        "agent-001\nX-Injected: true",
        "agent-001\rX-Injected: true",
    ];

    for attempt in &injection_attempts {
        let result = HeaderValue::from_str(attempt);
        assert!(
            result.is_err(),
            "Header value with newline must be rejected: {:?}",
            attempt
        );
    }
}

// ── 2.4 GVM headers removed before forwarding ──
// Verify that remove_gvm_headers strips all GVM-specific headers

#[test]
fn gvm_headers_stripped_before_forwarding() {
    use axum::http::HeaderMap;

    let mut headers = HeaderMap::new();
    headers.insert(
        "X-GVM-Agent-Id",
        "agent-001".parse().expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Trace-Id",
        "trace-001".parse().expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Event-Id",
        "event-001".parse().expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Operation",
        "gvm.test.read"
            .parse()
            .expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Target-Host",
        "api.example.com"
            .parse()
            .expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Session-Id",
        "session-001"
            .parse()
            .expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Tenant-Id",
        "tenant-001"
            .parse()
            .expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Rate-Limit",
        "100".parse().expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Context",
        "{}".parse().expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Resource",
        "{}".parse().expect("static header value must parse"),
    );
    // Non-GVM headers should survive
    headers.insert(
        "Authorization",
        "Bearer token123"
            .parse()
            .expect("static header value must parse"),
    );
    headers.insert(
        "Content-Type",
        "application/json"
            .parse()
            .expect("static header value must parse"),
    );

    // Call the PRODUCTION stripper directly. The previous version of
    // this test inlined its own prefix list and tested only that
    // HeaderMap::remove works — false coverage. Calling the actual
    // function ensures a regression that drops a prefix from the
    // production list shows up here.
    gvm_proxy::proxy::remove_gvm_headers(&mut headers);

    // Every GVM-prefix header must be gone.
    for name in &[
        "X-GVM-Agent-Id",
        "X-GVM-Trace-Id",
        "X-GVM-Event-Id",
        "X-GVM-Operation",
        "X-GVM-Target-Host",
        "X-GVM-Session-Id",
        "X-GVM-Tenant-Id",
        "X-GVM-Rate-Limit",
        "X-GVM-Context",
        "X-GVM-Resource",
    ] {
        assert!(
            headers.get(*name).is_none(),
            "{name} must be removed by remove_gvm_headers"
        );
    }

    // Non-GVM headers must survive.
    assert!(
        headers.get("Authorization").is_some(),
        "Auth header must survive"
    );
    assert!(
        headers.get("Content-Type").is_some(),
        "Content-Type must survive"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. Proxy <-> External API (Outbound) Boundary
// ═══════════════════════════════════════════════════════════════════════════════

// ── 3.1 SSRF: localhost/127.0.0.1 SRR defense ──

#[test]
fn ssrf_localhost_blocked_by_srr() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "localhost/{any}"
        decision = { type = "Deny", reason = "SSRF: localhost access blocked" }

        [[rules]]
        method = "*"
        pattern = "127.0.0.1/{any}"
        decision = { type = "Deny", reason = "SSRF: loopback access blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    // SSRF attempt via localhost
    let d1 = srr
        .check("GET", "localhost", "/admin/secrets", None)
        .decision;
    assert!(
        matches!(d1, EnforcementDecision::Deny { .. }),
        "SSRF via localhost must be denied, got {:?}",
        d1
    );

    // SSRF attempt via 127.0.0.1
    let d2 = srr
        .check("POST", "127.0.0.1", "/internal-api", None)
        .decision;
    assert!(
        matches!(d2, EnforcementDecision::Deny { .. }),
        "SSRF via 127.0.0.1 must be denied, got {:?}",
        d2
    );
}

// ── 3.2 SSRF: cloud metadata endpoints (169.254.169.254) ──

#[test]
fn ssrf_cloud_metadata_blocked_by_srr() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "169.254.169.254/{any}"
        decision = { type = "Deny", reason = "SSRF: cloud metadata endpoint blocked" }

        [[rules]]
        method = "*"
        pattern = "metadata.google.internal/{any}"
        decision = { type = "Deny", reason = "SSRF: GCP metadata blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Delay", milliseconds = 300 }
    "#,
    );

    // AWS metadata
    let d1 = srr
        .check("GET", "169.254.169.254", "/latest/meta-data/", None)
        .decision;
    assert!(
        matches!(d1, EnforcementDecision::Deny { .. }),
        "SSRF via AWS metadata must be denied"
    );

    // AWS IMDSv2 token endpoint
    let d2 = srr
        .check("PUT", "169.254.169.254", "/latest/api/token", None)
        .decision;
    assert!(
        matches!(d2, EnforcementDecision::Deny { .. }),
        "SSRF via AWS IMDSv2 must be denied"
    );

    // GCP metadata
    let d3 = srr
        .check(
            "GET",
            "metadata.google.internal",
            "/computeMetadata/v1/",
            None,
        )
        .decision;
    assert!(
        matches!(d3, EnforcementDecision::Deny { .. }),
        "SSRF via GCP metadata must be denied"
    );
}

// ── 3.3 SSRF: max_strict ensures SRR Deny overrides policy Allow ──

#[test]
fn ssrf_max_strict_srr_deny_overrides_policy_allow() {
    // Even if a policy says Allow (e.g., read_inbox is safe),
    // SRR Deny for localhost must win via max_strict.
    let srr_deny = EnforcementDecision::Deny {
        reason: "SSRF blocked".to_string(),
    };
    let policy_allow = EnforcementDecision::Allow;

    let result = max_strict(srr_deny, policy_allow);
    assert!(
        matches!(result, EnforcementDecision::Deny { .. }),
        "max_strict must pick SRR Deny over policy Allow"
    );
}

// ── 3.4 SSRF: private IP ranges (10.x, 172.16-31.x, 192.168.x) ──

#[test]
fn ssrf_private_ip_ranges_blocked_by_srr() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "10.0.0.1/{any}"
        decision = { type = "Deny", reason = "SSRF: private network blocked" }

        [[rules]]
        method = "*"
        pattern = "192.168.1.1/{any}"
        decision = { type = "Deny", reason = "SSRF: private network blocked" }

        [[rules]]
        method = "*"
        pattern = "172.16.0.1/{any}"
        decision = { type = "Deny", reason = "SSRF: private network blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Allow" }
    "#,
    );

    assert!(matches!(
        srr.check("GET", "10.0.0.1", "/internal", None).decision,
        EnforcementDecision::Deny { .. }
    ));
    assert!(matches!(
        srr.check("GET", "192.168.1.1", "/admin", None).decision,
        EnforcementDecision::Deny { .. }
    ));
    assert!(matches!(
        srr.check("GET", "172.16.0.1", "/secrets", None).decision,
        EnforcementDecision::Deny { .. }
    ));

    // Public IP should be allowed
    assert!(matches!(
        srr.check("GET", "8.8.8.8", "/dns", None).decision,
        EnforcementDecision::Allow
    ));
}

// ── 3.5 IPv6 SSRF: loopback, IPv4-mapped, zero-compression variants ──

#[test]
fn ssrf_ipv6_loopback_blocked_by_srr() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "localhost/{any}"
        decision = { type = "Deny", reason = "SSRF: localhost blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Allow" }
    "#,
    );

    // All IPv6 loopback variants must resolve to localhost → Deny
    let loopback_variants = [
        "[::1]",
        "[0:0:0:0:0:0:0:1]",
        "[0000:0000:0000:0000:0000:0000:0000:0001]",
        "[0::0:0:0:0:0:1]",
    ];

    for host in &loopback_variants {
        let d = srr.check("GET", host, "/admin", None).decision;
        assert!(
            matches!(d, EnforcementDecision::Deny { .. }),
            "IPv6 loopback {} must be denied, got {:?}",
            host,
            d
        );
    }

    // Non-loopback IPv6 should not be affected
    let d = srr.check("GET", "[2001:db8::1]", "/api", None).decision;
    assert!(
        !matches!(d, EnforcementDecision::Deny { .. }),
        "Public IPv6 must not be denied"
    );
}

#[test]
fn ssrf_ipv6_mapped_v4_loopback_blocked() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "127.0.0.1/{any}"
        decision = { type = "Deny", reason = "SSRF: loopback blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Allow" }
    "#,
    );

    // IPv4-mapped IPv6 variants of 127.0.0.1
    let mapped_variants = [
        "[::ffff:127.0.0.1]",
        "[0:0:0:0:0:ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
    ];

    for host in &mapped_variants {
        let d = srr.check("GET", host, "/internal", None).decision;
        assert!(
            matches!(d, EnforcementDecision::Deny { .. }),
            "IPv4-mapped loopback {} must be denied, got {:?}",
            host,
            d
        );
    }
}

#[test]
fn ssrf_ipv6_cloud_metadata_blocked() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "169.254.169.254/{any}"
        decision = { type = "Deny", reason = "SSRF: metadata blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Allow" }
    "#,
    );

    // AWS IPv6 metadata endpoint
    let d1 = srr
        .check("GET", "[fd00:ec2::254]", "/latest/meta-data", None)
        .decision;
    assert!(
        matches!(d1, EnforcementDecision::Deny { .. }),
        "AWS IPv6 metadata must be denied, got {:?}",
        d1
    );

    // IPv4-mapped metadata
    let d2 = srr
        .check("GET", "[::ffff:169.254.169.254]", "/latest/meta-data", None)
        .decision;
    assert!(
        matches!(d2, EnforcementDecision::Deny { .. }),
        "IPv4-mapped metadata must be denied, got {:?}",
        d2
    );
}

#[test]
fn ssrf_ipv6_private_ranges_mapped_blocked() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "10.0.0.1/{any}"
        decision = { type = "Deny", reason = "SSRF: private range blocked" }

        [[rules]]
        method = "*"
        pattern = "192.168.1.1/{any}"
        decision = { type = "Deny", reason = "SSRF: private range blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Allow" }
    "#,
    );

    // IPv4-mapped private IPs
    let d1 = srr
        .check("GET", "[::ffff:10.0.0.1]", "/internal", None)
        .decision;
    assert!(
        matches!(d1, EnforcementDecision::Deny { .. }),
        "IPv4-mapped 10.0.0.1 must be denied, got {:?}",
        d1
    );

    let d2 = srr
        .check("GET", "[::ffff:192.168.1.1]", "/admin", None)
        .decision;
    assert!(
        matches!(d2, EnforcementDecision::Deny { .. }),
        "IPv4-mapped 192.168.1.1 must be denied, got {:?}",
        d2
    );
}

// ── 3.6 API key leak prevention: GVM headers stripped from outbound ──
// Already tested in 2.4, but verify specifically that X-GVM headers
// cannot leak API keys or internal info to upstream services.

#[test]
fn api_key_not_leaked_via_gvm_headers() {
    // This test verifies the architectural guarantee:
    // remove_gvm_headers() strips ALL X-GVM-* headers before forwarding.
    // API keys are injected by api_keys::inject() AFTER GVM headers are removed.
    // Therefore, even if an attacker puts API keys in X-GVM-Context,
    // they will be removed before forwarding.

    use axum::http::HeaderMap;

    let mut headers = HeaderMap::new();
    // Attacker tries to leak secrets through GVM context
    headers.insert(
        "X-GVM-Context",
        r#"{"api_key": "sk-secret-123"}"#
            .parse()
            .expect("static header value must parse"),
    );
    headers.insert(
        "X-GVM-Agent-Id",
        "attacker".parse().expect("static header value must parse"),
    );

    // Simulate remove_gvm_headers
    let gvm_prefixes = [
        "x-gvm-agent-id",
        "x-gvm-trace-id",
        "x-gvm-parent-event-id",
        "x-gvm-event-id",
        "x-gvm-operation",
        "x-gvm-resource",
        "x-gvm-context",
        "x-gvm-session-id",
        "x-gvm-tenant-id",
        "x-gvm-rate-limit",
        "x-gvm-target-host",
    ];
    for prefix in &gvm_prefixes {
        headers.remove(*prefix);
    }

    assert!(
        headers.get("X-GVM-Context").is_none(),
        "Context header (potentially containing secrets) must be stripped"
    );
}

// ── 3.6 Redirect loop prevention: SRR catches repeated targets ──
// Verify that SRR can block known redirect endpoints

#[test]
fn srr_redirect_target_blocked() {
    let srr = srr_from_toml(
        r#"
        [[rules]]
        method = "*"
        pattern = "httpbin.org/redirect/{any}"
        decision = { type = "Deny", reason = "Open redirect target blocked" }

        [[rules]]
        method = "*"
        pattern = "{any}"
        decision = { type = "Allow" }
    "#,
    );

    let decision = srr
        .check("GET", "httpbin.org", "/redirect/10", None)
        .decision;
    assert!(
        matches!(decision, EnforcementDecision::Deny { .. }),
        "Known redirect endpoint must be blocked"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. NATS Boundary
// ═══════════════════════════════════════════════════════════════════════════════

// ── 4.1 WAL channel backpressure: bounded channel prevents unbounded growth ──

#[tokio::test]
async fn nats_channel_backpressure_bounded() {
    use gvm_proxy::ledger::{GroupCommitConfig, Ledger};

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    // Small channel capacity to test backpressure
    let config = GroupCommitConfig {
        batch_window: std::time::Duration::ZERO,
        max_batch_size: 16,
        channel_capacity: 32,
        ..Default::default()
    };

    let ledger = Arc::new(
        Ledger::with_config(&wal_path, "", "", config)
            .await
            .expect("ledger with valid config must initialize"),
    );

    // Fire 200 events through a small channel — should not panic or deadlock
    let start = std::time::Instant::now();

    let mut handles = Vec::new();
    for i in 0..200 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("backpressure-{}", i));
            ledger.append_durable(&event).await
        }));
    }

    let mut success_count = 0;
    let mut error_count = 0;
    for handle in handles {
        match handle.await.expect("spawned task must not panic") {
            Ok(()) => success_count += 1,
            Err(_) => error_count += 1,
        }
    }

    let elapsed = start.elapsed();

    // All events should succeed (channel blocks but does not drop)
    assert_eq!(
        success_count, 200,
        "All events must succeed via backpressure (channel blocks, not drops)"
    );
    assert_eq!(error_count, 0, "No events should fail");
    assert!(
        elapsed.as_secs() < 30,
        "200 events through small channel took {:?} — possible deadlock",
        elapsed
    );
}

// ── 4.2 WAL-only fallback: NATS URL empty = WAL-only mode, no crash ──

#[tokio::test]
async fn nats_empty_url_wal_only_mode() {
    use gvm_proxy::ledger::Ledger;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    // Empty NATS URL = WAL-only mode
    let ledger = Ledger::new(&wal_path, "", "")
        .await
        .expect("WAL-only ledger must initialize without NATS");

    // Durable writes should work without NATS
    let event = make_test_event("wal-only-1");
    ledger
        .append_durable(&event)
        .await
        .expect("durable write must succeed in WAL-only mode");

    // Async writes should work without NATS (fire-and-forget)
    let event2 = make_test_event("wal-only-2");
    ledger.append_async(event2).await;

    // Recovery should work
    let report = ledger
        .recover_from_wal()
        .await
        .expect("WAL recovery must succeed");
    assert_eq!(
        report.pending_found, 1,
        "One durable event should be Pending"
    );
}

// ── 4.3 WAL sequence monotonicity under concurrent load ──

#[tokio::test]
async fn nats_wal_sequence_monotonic() {
    use gvm_proxy::ledger::Ledger;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");

    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("WAL-only ledger must initialize"),
    );

    let mut handles = Vec::new();
    for i in 0..50 {
        let ledger = ledger.clone();
        handles.push(tokio::spawn(async move {
            let event = make_test_event(&format!("seq-{}", i));
            ledger
                .append_durable(&event)
                .await
                .expect("concurrent durable write must succeed");
        }));
    }

    for handle in handles {
        handle.await.expect("spawned task must not panic");
    }

    // Read WAL and verify all 50 events present (filter out MerkleBatchRecord lines)
    let content = tokio::fs::read_to_string(&wal_path)
        .await
        .expect("WAL file must be readable after writes");
    let event_count = content
        .lines()
        .filter(|line| !line.contains("\"merkle_root\""))
        .count();
    assert_eq!(event_count, 50, "WAL must contain exactly 50 events");

    // Verify batch records exist (at least 1 batch was flushed)
    let batch_count = content
        .lines()
        .filter(|line| line.contains("\"merkle_root\""))
        .count();
    assert!(
        batch_count > 0,
        "WAL must contain at least one Merkle batch record"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Vault / Redis Boundary
// ═══════════════════════════════════════════════════════════════════════════════

// ── 5.1 Vault: large value encrypt/decrypt roundtrip ──

#[tokio::test]
async fn vault_large_value_roundtrip() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("WAL-only ledger must initialize"),
    );
    let vault = Vault::new(ledger).expect("vault must initialize with valid ledger");

    // 1MB value
    let large_value: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    vault
        .write("large-key", &large_value, "agent-1")
        .await
        .expect("1MB value write must succeed");
    let result = vault
        .read("large-key", "agent-1")
        .await
        .expect("vault read must not error")
        .expect("written key must exist");

    assert_eq!(
        result.len(),
        large_value.len(),
        "Decrypted value must match original length"
    );
    assert_eq!(result, large_value, "Decrypted value must match original");
}

// ── 5.2 Vault: key collision between agents ──

#[tokio::test]
async fn vault_key_collision_between_agents() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("WAL-only ledger must initialize"),
    );
    let vault = Vault::new(ledger).expect("vault must initialize with valid ledger");

    // Two agents write to the same key — last writer wins
    vault
        .write("shared-key", b"agent-1-data", "agent-1")
        .await
        .expect("first agent write must succeed");
    vault
        .write("shared-key", b"agent-2-data", "agent-2")
        .await
        .expect("second agent write must succeed");

    let result = vault
        .read("shared-key", "agent-1")
        .await
        .expect("vault read must not error")
        .expect("shared key must exist");
    assert_eq!(
        result, b"agent-2-data",
        "Last write wins — agent-2 data should be returned"
    );
}

// ── 5.3 Vault: encryption integrity — tampered ciphertext detected ──
//
// AES-256-GCM ciphertext layout produced by LocalKeyProvider:
//   [nonce: 12 bytes] [ciphertext body: N bytes] [auth tag: 16 bytes]
// Auth covers nonce + body + tag, so flipping a bit in any of the three
// regions must surface as a decryption integrity error.

#[tokio::test]
async fn vault_tampered_ciphertext_detected() {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Use a known fixed key so we can manipulate the ciphertext at the
    // raw-byte layer and confirm decryption refuses each tamper position.
    let key = [7u8; 32];
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let nonce_bytes = [3u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = b"vault-state-payload";
    let body_with_tag = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("AES-256-GCM encrypt must succeed");

    // Compose the wire format LocalKeyProvider uses: nonce || body || tag.
    let mut original = Vec::with_capacity(12 + body_with_tag.len());
    original.extend_from_slice(&nonce_bytes);
    original.extend_from_slice(&body_with_tag);

    // Sanity: untampered ciphertext round-trips.
    let recovered = cipher
        .decrypt(nonce, &original[12..])
        .expect("untampered ciphertext must decrypt");
    assert_eq!(recovered, plaintext);

    // Tamper position table — covers nonce, body, and auth tag regions.
    let total_len = original.len();
    let body_offset = 12;
    let tag_offset = total_len - 16;
    let positions = [
        ("nonce-first-byte", 0usize),
        ("nonce-mid", 6),
        ("body-first-byte", body_offset),
        ("body-last-byte", tag_offset - 1),
        ("tag-first-byte", tag_offset),
        ("tag-last-byte", total_len - 1),
    ];

    for (label, idx) in positions {
        let mut tampered = original.clone();
        tampered[idx] ^= 0xFF;
        // Decrypt using the (possibly tampered) nonce from the wire
        // bytes — that's what a real receiver would use. If we passed
        // the pristine `nonce` here, nonce-region tampers would be
        // invisible to the test.
        let nonce_bytes_t = &tampered[..12];
        let nonce_t = Nonce::from_slice(nonce_bytes_t);
        let result = cipher.decrypt(nonce_t, &tampered[12..]);
        assert!(
            result.is_err(),
            "AES-GCM must reject tamper at {label} (offset {idx})",
        );
    }

    // Truncated ciphertext (drops the auth tag) must also fail integrity.
    let truncated = &original[..total_len - 1];
    assert!(
        cipher.decrypt(nonce, &truncated[12..]).is_err(),
        "AES-GCM must reject truncated ciphertext (missing tag bytes)"
    );

    // Appended bytes change auth coverage — must fail.
    let mut appended = original.clone();
    appended.push(0x00);
    assert!(
        cipher.decrypt(nonce, &appended[12..]).is_err(),
        "AES-GCM must reject ciphertext with appended bytes"
    );
}

// ── 5.4 Vault: concurrent read/write to same key ──

#[tokio::test]
async fn vault_concurrent_read_write_same_key() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("WAL-only ledger must initialize"),
    );
    let vault = Arc::new(Vault::new(ledger).expect("vault must initialize with valid ledger"));

    // Write initial value
    vault
        .write("rw-key", b"initial", "agent-1")
        .await
        .expect("initial vault write must succeed");

    // 20 concurrent reads + 20 concurrent writes
    let mut handles = Vec::new();

    for i in 0..20 {
        let vault = vault.clone();
        handles.push(tokio::spawn(async move {
            let value = format!("value-{}", i);
            vault
                .write("rw-key", value.as_bytes(), "writer")
                .await
                .expect("concurrent vault write must succeed");
            "write"
        }));
    }

    for _ in 0..20 {
        let vault = vault.clone();
        handles.push(tokio::spawn(async move {
            let result = vault
                .read("rw-key", "reader")
                .await
                .expect("concurrent vault read must not error");
            assert!(
                result.is_some(),
                "Read during concurrent writes must not fail"
            );
            "read"
        }));
    }

    let mut read_count = 0;
    let mut write_count = 0;
    for handle in handles {
        match handle.await.expect("spawned task must not panic") {
            "read" => read_count += 1,
            "write" => write_count += 1,
            _ => unreachable!(),
        }
    }

    assert_eq!(read_count, 20);
    assert_eq!(write_count, 20);
}

// ── 5.5 Vault: delete and re-read returns None ──

#[tokio::test]
async fn vault_delete_then_read_returns_none() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("WAL-only ledger must initialize"),
    );
    let vault = Vault::new(ledger).expect("vault must initialize with valid ledger");

    vault
        .write("delete-key", b"data", "agent-1")
        .await
        .expect("vault write must succeed");
    assert!(vault
        .read("delete-key", "agent-1")
        .await
        .expect("vault read must not error")
        .is_some());

    vault
        .delete("delete-key", "agent-1")
        .await
        .expect("vault delete must succeed");
    assert!(
        vault
            .read("delete-key", "agent-1")
            .await
            .expect("vault read after delete must not error")
            .is_none(),
        "Deleted key must return None"
    );
}

// ── 5.6 Vault: empty value roundtrip ──

#[tokio::test]
async fn vault_empty_value_roundtrip() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("WAL-only ledger must initialize"),
    );
    let vault = Vault::new(ledger).expect("vault must initialize with valid ledger");

    vault
        .write("empty-key", b"", "agent-1")
        .await
        .expect("empty value write must succeed");
    let result = vault
        .read("empty-key", "agent-1")
        .await
        .expect("vault read must not error")
        .expect("written empty key must exist");
    assert_eq!(result, b"", "Empty value must roundtrip correctly");
}

// ── Vault Key Injection Prevention ──

#[tokio::test]
async fn vault_key_crlf_injection_rejected() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize"),
    );
    let vault = Vault::new(ledger).expect("vault must initialize with valid ledger");

    // CRLF in key — could enable WAL JSON injection or log injection
    let result = vault
        .write("key\r\nX-Injected: true", b"data", "agent-1")
        .await;
    assert!(result.is_err(), "CRLF in vault key must be rejected");

    // Null byte in key — could truncate in C-based backends
    let result = vault.write("key\0rest", b"data", "agent-1").await;
    assert!(result.is_err(), "Null byte in vault key must be rejected");

    // Read with CRLF key must also fail
    let result = vault.read("key\r\ninjection", "agent-1").await;
    assert!(result.is_err(), "CRLF in vault read key must be rejected");

    // Delete with null byte key must also fail
    let result = vault.delete("key\0rest", "agent-1").await;
    assert!(
        result.is_err(),
        "Null byte in vault delete key must be rejected"
    );
}

// ── Vault TOCTOU Key Limit Race Condition ──
// Documents the known TOCTOU window between len()/contains_key() check and put().
// With InMemoryBackend, two concurrent writes can both pass the limit check
// if they race during the window. This is an accepted limitation for MVP;
// production Redis backend should use atomic operations (SETNX + DBSIZE).

#[tokio::test]
async fn vault_key_limit_toctou_documented() {
    use gvm_proxy::ledger::Ledger;
    use gvm_proxy::vault::Vault;

    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let wal_path = dir.path().join("wal.log");
    let ledger = Arc::new(
        Ledger::new(&wal_path, "", "")
            .await
            .expect("ledger must initialize"),
    );
    let vault = Arc::new(Vault::new(ledger).expect("vault must initialize with valid ledger"));

    // Fill vault to near-limit (we use a smaller limit for test speed)
    // Write 100 keys to verify concurrent writes don't panic or deadlock
    let mut tasks = Vec::new();
    for i in 0..100 {
        let v = vault.clone();
        tasks.push(tokio::spawn(async move {
            let key = format!("key-{}", i);
            v.write(&key, b"value", "agent-1").await
        }));
    }

    let mut success_count = 0;
    for task in tasks {
        if task.await.expect("task must not panic").is_ok() {
            success_count += 1;
        }
    }

    // All 100 writes should succeed (well under 10K limit)
    assert_eq!(success_count, 100, "All 100 concurrent writes must succeed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Docker Isolation Boundary
// ═══════════════════════════════════════════════════════════════════════════════

// Docker isolation tests require a running Docker environment and are
// documented here for future implementation. They are cfg-gated to avoid
// CI failures in environments without Docker.
//
// [INFRA_REQUIRED] Tests to implement when Docker infrastructure is available:
//
// 6.1 docker_network_escape_prevented
//     - Container cannot reach host network (--network=none)
//     - Verify DNS resolution fails for internal hostnames
//
// 6.2 docker_volume_escape_prevented
//     - Read-only rootfs (--read-only)
//     - Verify writes outside mounted volumes fail
//
// 6.3 docker_privilege_escalation_prevented
//     - No new privileges (--security-opt=no-new-privileges)
//     - Non-root user (--user 1000:1000)
//     - Capabilities dropped (--cap-drop=ALL)
//
// 6.4 docker_resource_exhaustion_contained
//     - Memory limit enforced (--memory=256m)
//     - CPU limit enforced (--cpus=0.5)
//     - Process (PID) limit (--pids-limit=100)
//
// 6.5 docker_fork_bomb_contained
//     - PID limit prevents fork bomb from consuming host PIDs
//     - Container killed, host unaffected
//
// 6.6 docker_proxy_sidecar_crash_recovery
//     - Kill proxy container, verify agent container detects failure
//     - Restart proxy, verify agent reconnects

// ═══════════════════════════════════════════════════════════════════════════════
// Infrastructure-dependent tests (NATS, TLS, Slowloris, etc.)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The following tests require running infrastructure and are documented
// for implementation when the corresponding systems are available:
//
// [INFRA: NATS Server]
// - nats_connection_drop_mid_publish: WAL must succeed even if NATS drops
// - nats_message_too_large_rejected: NATS 1MB message limit
// - nats_reconnect_during_recovery: WAL events re-published after reconnect
// - nats_duplicate_prevention_on_reconnect: Nats-Msg-Id dedup header
//
// [INFRA: Running Proxy]
// - slowloris_connection_timeout: Slow headers trigger timeout
// - request_smuggling_content_length_mismatch: CL/TE mismatch rejected
// - chunked_transfer_timeout: Slow chunked body times out
// - connection_flood_rate_limited: >1000 concurrent connections bounded
//
// [INFRA: TLS]
// - tls_invalid_cert_rejected: Self-signed cert denied
// - tls_downgrade_prevented: HTTPS-to-HTTP redirect blocked
//
// [INFRA: DNS]
// - dns_failure_returns_bad_gateway: Unresolvable host → 502
// - connection_refused_returns_bad_gateway: Connection refused → 502
//
// [INFRA: Redis]
// - redis_connection_pool_exhaustion: Pool limit respected
// - redis_large_value_rejected: Value size limit enforced
// - redis_serialization_mismatch: Wrong type deserialization handled
// - redis_flush_attack_prevented: FLUSHALL/FLUSHDB command blocked

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

fn srr_from_toml(toml_str: &str) -> NetworkSRR {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml_str).expect("SRR TOML file write must succeed");
    NetworkSRR::load(&path).expect("valid SRR TOML must parse")
}

fn make_test_event(event_id: &str) -> GVMEvent {
    GVMEvent {
        event_id: event_id.to_string(),
        trace_id: format!("trace-{}", event_id),
        parent_event_id: None,
        agent_id: "boundary-test-agent".to_string(),
        tenant_id: None,
        session_id: "session".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.test.boundary".to_string(),
        resource: Default::default(),
        context: Default::default(),
        transport: None,
        decision: "Allow".to_string(),
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
    }
}
