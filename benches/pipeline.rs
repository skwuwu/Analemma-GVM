use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use gvm_proxy::ledger::Ledger;
use gvm_proxy::policy::PolicyEngine;
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::*;
use gvm_proxy::vault::Vault;

// ─── Helpers ───

fn make_operation(
    op: &str,
    sensitivity: Sensitivity,
    tier: ResourceTier,
    tenant: Option<&str>,
    agent: &str,
) -> OperationMetadata {
    OperationMetadata {
        operation: op.to_string(),
        resource: ResourceDescriptor {
            service: "bench".to_string(),
            identifier: None,
            tier,
            sensitivity,
        },
        subject: SubjectDescriptor {
            agent_id: agent.to_string(),
            tenant_id: tenant.map(|s| s.to_string()),
            session_id: "bench-session".to_string(),
        },
        context: OperationContext {
            attributes: HashMap::new(),
        },
        payload: PayloadDescriptor::default(),
    }
}

fn make_test_event(id: &str) -> GVMEvent {
    GVMEvent {
        event_id: format!("evt-bench-{}", id),
        trace_id: "trace-bench".to_string(),
        parent_event_id: None,
        agent_id: "bench-agent".to_string(),
        tenant_id: None,
        session_id: "bench-session".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.bench.test".to_string(),
        resource: ResourceDescriptor::default(),
        context: HashMap::new(),
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "benchmark".to_string(),
        matched_rule_id: None,
        enforcement_point: "bench".to_string(),
        status: EventStatus::Pending,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
    }
}

// ═══════════════════════════════════════════════
// 1. Network SRR Benchmarks
// ═══════════════════════════════════════════════

fn bench_srr(c: &mut Criterion) {
    let srr = NetworkSRR::load(Path::new("config/srr_network.toml"))
        .expect("Failed to load SRR rules");

    let mut group = c.benchmark_group("srr");

    // Allow path (known safe host)
    group.bench_function("allow_safe_host", |b| {
        b.iter(|| {
            black_box(srr.check("GET", "api.openai.com", "/v1/chat/completions", None));
        });
    });

    // Deny path (blocked host)
    group.bench_function("deny_bank_transfer", |b| {
        b.iter(|| {
            black_box(srr.check("POST", "api.bank.com", "/transfer", None));
        });
    });

    // Default-to-Caution (unknown host)
    group.bench_function("default_caution_unknown", |b| {
        b.iter(|| {
            black_box(srr.check("GET", "unknown-service.example.com", "/api/data", None));
        });
    });

    // With payload inspection
    let payload = br#"{"query": "mutation { deleteAccount(id: 42) }"}"#;
    group.bench_function("payload_inspection", |b| {
        b.iter(|| {
            black_box(srr.check("POST", "api.example.com", "/graphql", Some(payload)));
        });
    });

    // Vary payload sizes
    for size in [64, 1024, 16384, 65536] {
        let body = vec![b'x'; size];
        group.bench_with_input(
            BenchmarkId::new("payload_size_bytes", size),
            &body,
            |b, body| {
                b.iter(|| {
                    black_box(srr.check("POST", "api.example.com", "/data", Some(body)));
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════
// 2. Policy Engine Benchmarks
// ═══════════════════════════════════════════════

fn bench_policy(c: &mut Criterion) {
    let engine = PolicyEngine::load(Path::new("config/policies"))
        .expect("Failed to load policies");

    let mut group = c.benchmark_group("policy");

    // Simple Allow (read operation)
    let op_read = make_operation(
        "gvm.storage.read",
        Sensitivity::Low,
        ResourceTier::Internal,
        None,
        "bench-agent",
    );
    group.bench_function("allow_read", |b| {
        b.iter(|| {
            black_box(engine.evaluate(&op_read));
        });
    });

    // Deny (delete critical)
    let op_delete = make_operation(
        "gvm.storage.delete",
        Sensitivity::Critical,
        ResourceTier::Internal,
        None,
        "bench-agent",
    );
    group.bench_function("deny_critical_delete", |b| {
        b.iter(|| {
            black_box(engine.evaluate(&op_delete));
        });
    });

    // Payment (RequireApproval)
    let op_payment = make_operation(
        "gvm.payment.charge",
        Sensitivity::High,
        ResourceTier::External,
        None,
        "bench-agent",
    );
    group.bench_function("payment_require_approval", |b| {
        b.iter(|| {
            black_box(engine.evaluate(&op_payment));
        });
    });

    // No match (falls through all rules)
    let op_custom = make_operation(
        "custom.vendor.obscure.action",
        Sensitivity::Low,
        ResourceTier::Internal,
        None,
        "bench-agent",
    );
    group.bench_function("no_match_fallthrough", |b| {
        b.iter(|| {
            black_box(engine.evaluate(&op_custom));
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 3. max_strict() Benchmarks
// ═══════════════════════════════════════════════

fn bench_max_strict(c: &mut Criterion) {
    let mut group = c.benchmark_group("max_strict");

    group.bench_function("allow_vs_deny", |b| {
        b.iter(|| {
            black_box(max_strict(
                EnforcementDecision::Allow,
                EnforcementDecision::Deny {
                    reason: "blocked".to_string(),
                },
            ));
        });
    });

    group.bench_function("delay_vs_require_approval", |b| {
        b.iter(|| {
            black_box(max_strict(
                EnforcementDecision::Delay { milliseconds: 300 },
                EnforcementDecision::RequireApproval {
                    urgency: ApprovalUrgency::Standard,
                },
            ));
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 4. Vault Encrypt/Decrypt Benchmarks
// ═══════════════════════════════════════════════

fn bench_vault(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let wal_path = tmp_dir.path().join("bench_wal.log");

    let ledger = rt.block_on(async {
        Arc::new(
            Ledger::new(
                &wal_path,
                "nats://localhost:4222",
                "gvm-bench",
            )
            .await
            .unwrap(),
        )
    });

    let vault = rt
        .block_on(async { Vault::new(ledger.clone()) })
        .expect("Vault init failed");
    let vault = Arc::new(vault);

    let mut group = c.benchmark_group("vault");

    // Write + Read roundtrip for varying sizes
    for size in [32, 256, 1024, 4096, 16384] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let v = vault.clone();

        group.bench_with_input(
            BenchmarkId::new("write_read_roundtrip_bytes", size),
            &plaintext,
            |b, pt| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| {
                        let v = v.clone();
                        let pt = pt.clone();
                        async move {
                            v.write("bench-key", &pt, "bench-agent").await.unwrap();
                            let result = v.read("bench-key", "bench-agent").await.unwrap();
                            black_box(result);
                        }
                    });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════
// 5. WAL Append Benchmarks
// ═══════════════════════════════════════════════

fn bench_wal(c: &mut Criterion) {
    let mut group = c.benchmark_group("wal");

    // Single durable append (fsync)
    group.bench_function("durable_append_fsync", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter_custom(|iters| async move {
                let tmp_dir = tempfile::tempdir().unwrap();
                let wal_path = tmp_dir.path().join("bench_wal.log");
                let ledger = Ledger::new(
                    &wal_path,
                    "nats://localhost:4222",
                    "gvm-bench",
                )
                .await
                .unwrap();

                let start = std::time::Instant::now();
                for i in 0..iters {
                    let event = make_test_event(&i.to_string());
                    ledger.append_durable(&event).await.unwrap();
                }
                start.elapsed()
            });
    });

    // Batch of 100 sequential appends
    group.bench_function("100_sequential_appends", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter_custom(|iters| async move {
                let tmp_dir = tempfile::tempdir().unwrap();
                let wal_path = tmp_dir.path().join("bench_wal.log");
                let ledger = Ledger::new(
                    &wal_path,
                    "nats://localhost:4222",
                    "gvm-bench",
                )
                .await
                .unwrap();

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    for i in 0..100 {
                        let event = make_test_event(&i.to_string());
                        ledger.append_durable(&event).await.unwrap();
                    }
                }
                start.elapsed()
            });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 6. End-to-End Classification Benchmarks
// ═══════════════════════════════════════════════

fn bench_classification(c: &mut Criterion) {
    let srr = NetworkSRR::load(Path::new("config/srr_network.toml"))
        .expect("Failed to load SRR rules");
    let policy = PolicyEngine::load(Path::new("config/policies"))
        .expect("Failed to load policies");

    let mut group = c.benchmark_group("classification_e2e");

    // SDK-routed: ABAC + SRR + max_strict
    group.bench_function("sdk_routed_full_pipeline", |b| {
        let op = make_operation(
            "gvm.payment.refund",
            Sensitivity::High,
            ResourceTier::External,
            None,
            "bench-agent",
        );
        b.iter(|| {
            // Layer 1: ABAC
            let (policy_decision, _rule_id) = policy.evaluate(&op);
            // Layer 2: SRR
            let srr_decision = srr.check("POST", "api.stripe.com", "/v1/refunds", None);
            // Combine
            let final_decision = max_strict(policy_decision, srr_decision);
            black_box(final_decision);
        });
    });

    // Direct HTTP: SRR only
    group.bench_function("direct_http_srr_only", |b| {
        b.iter(|| {
            let decision = srr.check("POST", "api.bank.com", "/transfer", None);
            black_box(decision);
        });
    });

    // Full pipeline with payload
    group.bench_function("full_pipeline_with_payload", |b| {
        let op = make_operation(
            "gvm.messaging.send",
            Sensitivity::Medium,
            ResourceTier::External,
            None,
            "bench-agent",
        );
        let payload = br#"{"to":"user@example.com","subject":"Hello","body":"Test message"}"#;
        b.iter(|| {
            let (policy_decision, _) = policy.evaluate(&op);
            let srr_decision =
                srr.check("POST", "smtp.gmail.com", "/send", Some(payload));
            let final_decision = max_strict(policy_decision, srr_decision);
            black_box(final_decision);
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 7. Group Commit Concurrent Benchmarks
// ═══════════════════════════════════════════════

fn bench_wal_group_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("wal_group_commit");

    for concurrency in [100, 500] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_appends", concurrency),
            &concurrency,
            |b, &n| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter_custom(|iters| async move {
                        let tmp_dir = tempfile::tempdir().unwrap();
                        let wal_path = tmp_dir.path().join("bench_gc_wal.log");
                        let ledger = Arc::new(
                            Ledger::new(&wal_path, "", "").await.unwrap(),
                        );

                        let start = std::time::Instant::now();
                        for _ in 0..iters {
                            let mut handles = Vec::with_capacity(n);
                            for i in 0..n {
                                let ledger = ledger.clone();
                                handles.push(tokio::spawn(async move {
                                    let event = make_test_event(&i.to_string());
                                    ledger.append_durable(&event).await.unwrap();
                                }));
                            }
                            for h in handles {
                                h.await.unwrap();
                            }
                        }
                        start.elapsed()
                    });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════
// 8. SRR Scale Benchmarks (1K/10K rules)
// ═══════════════════════════════════════════════

fn bench_srr_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("srr_scale");

    for rule_count in [100, 1_000, 10_000] {
        // Generate N deny rules + catch-all
        let mut toml = String::new();
        for i in 0..rule_count {
            toml.push_str(&format!(
                "[[rules]]\nmethod = \"POST\"\npattern = \"host-{}.example.com/{{any}}\"\ndecision = {{ type = \"Deny\", reason = \"Rule {}\" }}\n\n",
                i, i
            ));
        }
        toml.push_str("[[rules]]\nmethod = \"*\"\npattern = \"{any}\"\ndecision = { type = \"Delay\", milliseconds = 300 }\n");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("srr.toml");
        std::fs::write(&path, &toml).unwrap();
        let srr = NetworkSRR::load(&path).unwrap();

        // Best case: first rule match
        group.bench_with_input(
            BenchmarkId::new("first_rule_match", rule_count),
            &srr,
            |b, srr| {
                b.iter(|| {
                    black_box(srr.check("POST", "host-0.example.com", "/test", None));
                });
            },
        );

        // Worst case: falls through all rules to catch-all
        group.bench_with_input(
            BenchmarkId::new("fallthrough_all_rules", rule_count),
            &srr,
            |b, srr| {
                b.iter(|| {
                    black_box(srr.check("GET", "unknown.example.com", "/test", None));
                });
            },
        );

        // Middle rule match
        let mid_host = format!("host-{}.example.com", rule_count / 2);
        group.bench_function(
            BenchmarkId::new("mid_rule_match", rule_count),
            |b| {
                b.iter(|| {
                    black_box(srr.check("POST", &mid_host, "/test", None));
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════
// 9. Policy Scale Benchmarks (100/1K rules)
// ═══════════════════════════════════════════════

fn bench_policy_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_scale");

    for rule_count in [100, 500, 1_000] {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policies");
        std::fs::create_dir(&policy_dir).unwrap();

        let mut toml = String::new();
        for i in 0..rule_count {
            toml.push_str(&format!(
                r#"
[[rules]]
id = "rule-{i}"
priority = {i}
layer = "Global"
description = "Rule {i}"
conditions = [
    {{ field = "operation", operator = "Eq", value = "gvm.test.op{i}" }}
]
[rules.decision]
type = "Deny"
reason = "Matched {i}"
"#,
            ));
        }
        toml.push_str(
            r#"
[[rules]]
id = "catch-all"
priority = 99999
layer = "Global"
description = "Default"
[rules.decision]
type = "Allow"
"#,
        );

        std::fs::write(policy_dir.join("global.toml"), &toml).unwrap();
        let engine = PolicyEngine::load(&policy_dir).unwrap();

        // Best case: first rule match
        let op_first = make_operation("gvm.test.op0", Sensitivity::Low, ResourceTier::Internal, None, "bench");
        group.bench_function(
            BenchmarkId::new("first_rule_match", rule_count),
            |b| {
                b.iter(|| {
                    black_box(engine.evaluate(&op_first));
                });
            },
        );

        // Worst case: no match, falls through
        let op_nomatch = make_operation("gvm.nomatch.ever", Sensitivity::Low, ResourceTier::Internal, None, "bench");
        group.bench_function(
            BenchmarkId::new("fallthrough_all", rule_count),
            |b| {
                b.iter(|| {
                    black_box(engine.evaluate(&op_nomatch));
                });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════
// 10. IC-2 Delay Accuracy Benchmark
// ═══════════════════════════════════════════════

fn bench_ic2_delay_accuracy(c: &mut Criterion) {
    let mut group = c.benchmark_group("ic2_delay");
    group.sample_size(10); // Fewer samples since each takes 300ms+

    group.bench_function("300ms_delay_accuracy", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                let target = std::time::Duration::from_millis(300);
                let start = std::time::Instant::now();
                tokio::time::sleep(target).await;
                let elapsed = start.elapsed();
                let error_ms = (elapsed.as_millis() as i64 - 300).abs();
                black_box(error_ms);
                // In the benchmark, we're measuring the actual tokio::sleep accuracy
                // which is what the proxy uses for IC-2 delays
            });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 11. Vault Large Value Benchmarks
// ═══════════════════════════════════════════════

fn bench_vault_large(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let wal_path = tmp_dir.path().join("bench_vault_large.log");

    let ledger = rt.block_on(async {
        Arc::new(Ledger::new(&wal_path, "", "").await.unwrap())
    });

    let vault = Arc::new(Vault::new(ledger).expect("Vault init"));

    let mut group = c.benchmark_group("vault_large");

    // Large value sizes
    for size in [65536, 262144, 1048576] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let v = vault.clone();

        group.bench_with_input(
            BenchmarkId::new("write_read_bytes", size),
            &plaintext,
            |b, pt| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| {
                        let v = v.clone();
                        let pt = pt.clone();
                        async move {
                            v.write("bench-large", &pt, "bench-agent").await.unwrap();
                            let result = v.read("bench-large", "bench-agent").await.unwrap();
                            black_box(result);
                        }
                    });
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════
// 12. Wasm vs Native Policy Engine Benchmarks
// ═══════════════════════════════════════════════

fn bench_wasm_vs_native(c: &mut Criterion) {
    use gvm_proxy::wasm_engine::WasmEngine;

    let mut group = c.benchmark_group("wasm_vs_native");

    // Build evaluation request
    let rules = vec![
        gvm_engine::Rule {
            id: "deny-critical".to_string(),
            priority: 1,
            layer: "global".to_string(),
            conditions: vec![gvm_engine::Condition {
                field: "resource.sensitivity".to_string(),
                operator: "eq".to_string(),
                value: serde_json::Value::String("critical".to_string()),
            }],
            decision: gvm_engine::Decision {
                decision_type: "Deny".to_string(),
                milliseconds: None,
                reason: Some("Critical data protected".to_string()),
            },
        },
        gvm_engine::Rule {
            id: "delay-send".to_string(),
            priority: 10,
            layer: "global".to_string(),
            conditions: vec![gvm_engine::Condition {
                field: "operation".to_string(),
                operator: "starts_with".to_string(),
                value: serde_json::Value::String("gvm.messaging".to_string()),
            }],
            decision: gvm_engine::Decision {
                decision_type: "Delay".to_string(),
                milliseconds: Some(300),
                reason: None,
            },
        },
    ];

    let req_deny = gvm_engine::EvalRequest {
        operation: "gvm.storage.delete".to_string(),
        resource: gvm_engine::ResourceAttrs {
            service: "db".to_string(),
            tier: "internal".to_string(),
            sensitivity: "critical".to_string(),
        },
        subject: gvm_engine::SubjectAttrs {
            agent_id: "bench-agent".to_string(),
            tenant_id: None,
        },
        rules: rules.clone(),
    };

    let req_allow = gvm_engine::EvalRequest {
        operation: "gvm.storage.read".to_string(),
        resource: gvm_engine::ResourceAttrs {
            service: "db".to_string(),
            tier: "internal".to_string(),
            sensitivity: "low".to_string(),
        },
        subject: gvm_engine::SubjectAttrs {
            agent_id: "bench-agent".to_string(),
            tenant_id: None,
        },
        rules: rules.clone(),
    };

    // ── Native evaluation ──
    let native_engine = WasmEngine::native();
    group.bench_function("native_deny", |b| {
        b.iter(|| {
            let resp = native_engine.evaluate(black_box(&req_deny)).unwrap();
            black_box(resp);
        });
    });

    group.bench_function("native_allow", |b| {
        b.iter(|| {
            let resp = native_engine.evaluate(black_box(&req_allow)).unwrap();
            black_box(resp);
        });
    });

    // ── Wasm evaluation (warm call — module already loaded) ──
    let wasm_path = Path::new("data/gvm_engine.wasm");
    if wasm_path.exists() {
        let wasm_engine = WasmEngine::load(wasm_path).unwrap();
        assert!(wasm_engine.is_wasm(), "Wasm engine must be in Wasm mode");

        group.bench_function("wasm_deny", |b| {
            b.iter(|| {
                let resp = wasm_engine.evaluate(black_box(&req_deny)).unwrap();
                black_box(resp);
            });
        });

        group.bench_function("wasm_allow", |b| {
            b.iter(|| {
                let resp = wasm_engine.evaluate(black_box(&req_allow)).unwrap();
                black_box(resp);
            });
        });

        // ── End-to-end latency breakdown: Wasm evaluate as % of full pipeline ──
        let srr = NetworkSRR::load(Path::new("config/srr_network.toml"))
            .expect("Failed to load SRR for e2e bench");
        let policy = PolicyEngine::load(Path::new("config/policies"))
            .expect("Failed to load policy for e2e bench");
        let op = make_operation(
            "gvm.messaging.send",
            Sensitivity::Medium,
            ResourceTier::External,
            None,
            "bench-agent",
        );

        // Full pipeline with Wasm: SRR + Wasm policy + max_strict
        group.bench_function("e2e_with_wasm", |b| {
            b.iter(|| {
                let srr_decision = srr.check("POST", "smtp.gmail.com", "/send", None);
                let wasm_resp = wasm_engine.evaluate(black_box(&req_allow)).unwrap();
                let (wasm_decision, _) = WasmEngine::response_to_decision(&wasm_resp);
                let final_d = max_strict(wasm_decision, srr_decision);
                black_box(final_d);
            });
        });

        // Full pipeline with Native: SRR + Native policy + max_strict
        group.bench_function("e2e_with_native", |b| {
            b.iter(|| {
                let srr_decision = srr.check("POST", "smtp.gmail.com", "/send", None);
                let (policy_decision, _) = policy.evaluate(&op);
                let final_d = max_strict(policy_decision, srr_decision);
                black_box(final_d);
            });
        });

        // SRR-only baseline (for latency breakdown comparison)
        group.bench_function("srr_only_baseline", |b| {
            b.iter(|| {
                let d = srr.check("POST", "smtp.gmail.com", "/send", None);
                black_box(d);
            });
        });
    } else {
        eprintln!("Wasm module not found at data/gvm_engine.wasm — skipping Wasm benchmarks");
        eprintln!("Build with: cargo build -p gvm-engine --target wasm32-wasip1 --release");
    }

    group.finish();
}

// ═══════════════════════════════════════════════
// 13. Vault P99 Tail Latency Benchmarks
// ═══════════════════════════════════════════════

fn bench_vault_p99(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let tmp_dir = tempfile::tempdir().unwrap();
    let wal_path = tmp_dir.path().join("bench_vault_p99.log");

    let ledger = rt.block_on(async {
        Arc::new(Ledger::new(&wal_path, "", "").await.unwrap())
    });

    let vault = Arc::new(Vault::new(ledger).expect("Vault init"));

    let mut group = c.benchmark_group("vault_p99_tail");

    // Measure write latency at different sizes to show variance increase
    for size in [1024, 4096, 16384, 65536, 262144] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let v = vault.clone();

        // Write-only benchmark (isolate fsync variance)
        group.bench_with_input(
            BenchmarkId::new("write_only_bytes", size),
            &plaintext,
            |b, pt| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| {
                        let v = v.clone();
                        let pt = pt.clone();
                        async move {
                            v.write("bench-p99", &pt, "bench-agent").await.unwrap();
                            black_box(());
                        }
                    });
            },
        );
    }

    // Chunked write benchmark: 256KB as 16 x 16KB chunks vs monolithic
    let large_data: Vec<u8> = (0..262144).map(|i| (i % 256) as u8).collect();

    // Monolithic 256KB write
    let v = vault.clone();
    group.bench_function("monolithic_256kb", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| {
                let v = v.clone();
                let data = large_data.clone();
                async move {
                    v.write("bench-mono", &data, "bench-agent").await.unwrap();
                    black_box(());
                }
            });
    });

    // Chunked: 16 x 16KB writes
    let v = vault.clone();
    group.bench_function("chunked_16x16kb", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| {
                let v = v.clone();
                let data = large_data.clone();
                async move {
                    for i in 0..16 {
                        let chunk = &data[i * 16384..(i + 1) * 16384];
                        let key = format!("bench-chunk-{}", i);
                        v.write(&key, chunk, "bench-agent").await.unwrap();
                    }
                    black_box(());
                }
            });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 14. Rate Limiter Benchmarks
// ═══════════════════════════════════════════════

fn bench_rate_limiter(c: &mut Criterion) {
    use gvm_proxy::rate_limiter::RateLimiter;

    let mut group = c.benchmark_group("rate_limiter");

    // Single agent check (hot path)
    group.bench_function("single_agent_check", |b| {
        let limiter = RateLimiter::new();
        b.iter(|| {
            black_box(limiter.check("agent-bench", 1000));
        });
    });

    // Multiple agents
    group.bench_function("100_agents_round_robin", |b| {
        let limiter = RateLimiter::new();
        let mut i = 0u64;
        b.iter(|| {
            let agent_id = format!("agent-{}", i % 100);
            i += 1;
            black_box(limiter.check(&agent_id, 60));
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════

criterion_group!(
    benches,
    bench_srr,
    bench_policy,
    bench_max_strict,
    bench_vault,
    bench_wal,
    bench_wal_group_commit,
    bench_classification,
    bench_srr_scale,
    bench_policy_scale,
    bench_ic2_delay_accuracy,
    bench_vault_large,
    bench_rate_limiter,
    bench_wasm_vs_native,
    bench_vault_p99,
);
criterion_main!(benches);
