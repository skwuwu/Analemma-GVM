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
        let l = ledger.clone();

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

criterion_group!(
    benches,
    bench_srr,
    bench_policy,
    bench_max_strict,
    bench_vault,
    bench_wal,
    bench_wal_group_commit,
    bench_classification,
);
criterion_main!(benches);
