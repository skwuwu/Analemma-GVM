use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use gvm_proxy::ledger::Ledger;
use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::*;
use gvm_proxy::vault::Vault;

// ─── Helpers ───

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
        default_caution: false,
        config_integrity_ref: None,
        operation_descriptor: None,
    }
}

// ═══════════════════════════════════════════════
// 1. Network SRR Benchmarks
// ═══════════════════════════════════════════════

fn bench_srr(c: &mut Criterion) {
    let srr = NetworkSRR::load(Path::new("config/srr_network.toml"))
        .expect("valid SRR config must exist at config/srr_network.toml");

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

// bench_policy removed — ABAC system deleted.

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
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime must initialize for bench");

    let tmp_dir = tempfile::tempdir().expect("temp directory must be creatable for bench setup");
    let wal_path = tmp_dir.path().join("bench_wal.log");

    let ledger = rt.block_on(async {
        Arc::new(
            Ledger::new(&wal_path, "nats://localhost:4222", "gvm-bench")
                .await
                .expect("ledger must initialize with valid WAL path"),
        )
    });

    let vault = rt
        .block_on(async { Vault::new(ledger.clone()) })
        .expect("vault must initialize with valid ledger");
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
                b.to_async(
                    tokio::runtime::Runtime::new()
                        .expect("tokio runtime must initialize for bench iteration"),
                )
                .iter(|| {
                    let v = v.clone();
                    let pt = pt.clone();
                    async move {
                        v.write("bench-key", &pt, "bench-agent")
                            .await
                            .expect("vault write must succeed with valid key and data");
                        let result = v
                            .read("bench-key", "bench-agent")
                            .await
                            .expect("vault read must succeed for previously written key");
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
        b.to_async(
            tokio::runtime::Runtime::new()
                .expect("tokio runtime must initialize for bench iteration"),
        )
        .iter_custom(|iters| async move {
            let tmp_dir =
                tempfile::tempdir().expect("temp directory must be creatable for bench setup");
            let wal_path = tmp_dir.path().join("bench_wal.log");
            let ledger = Ledger::new(&wal_path, "nats://localhost:4222", "gvm-bench")
                .await
                .expect("ledger must initialize with valid WAL path");

            let start = std::time::Instant::now();
            for i in 0..iters {
                let event = make_test_event(&i.to_string());
                ledger
                    .append_durable(&event)
                    .await
                    .expect("durable append must succeed for valid event");
            }
            start.elapsed()
        });
    });

    // Batch of 100 sequential appends
    group.bench_function("100_sequential_appends", |b| {
        b.to_async(
            tokio::runtime::Runtime::new()
                .expect("tokio runtime must initialize for bench iteration"),
        )
        .iter_custom(|iters| async move {
            let tmp_dir =
                tempfile::tempdir().expect("temp directory must be creatable for bench setup");
            let wal_path = tmp_dir.path().join("bench_wal.log");
            let ledger = Ledger::new(&wal_path, "nats://localhost:4222", "gvm-bench")
                .await
                .expect("ledger must initialize with valid WAL path");

            let start = std::time::Instant::now();
            for _ in 0..iters {
                for i in 0..100 {
                    let event = make_test_event(&i.to_string());
                    ledger
                        .append_durable(&event)
                        .await
                        .expect("durable append must succeed for valid event");
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
        .expect("valid SRR config must exist at config/srr_network.toml");

    let mut group = c.benchmark_group("classification_e2e");

    // SRR classification (deny path)
    group.bench_function("srr_deny_path", |b| {
        b.iter(|| {
            let decision = srr.check("POST", "api.bank.com", "/transfer", None);
            black_box(decision);
        });
    });

    // SRR classification with payload
    group.bench_function("srr_with_payload", |b| {
        let payload = br#"{"to":"user@example.com","subject":"Hello","body":"Test message"}"#;
        b.iter(|| {
            let decision = srr.check("POST", "smtp.gmail.com", "/send", Some(payload));
            black_box(decision);
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
                b.to_async(
                    tokio::runtime::Runtime::new()
                        .expect("tokio runtime must initialize for bench iteration"),
                )
                .iter_custom(|iters| async move {
                    let tmp_dir = tempfile::tempdir()
                        .expect("temp directory must be creatable for bench setup");
                    let wal_path = tmp_dir.path().join("bench_gc_wal.log");
                    let ledger = Arc::new(
                        Ledger::new(&wal_path, "", "")
                            .await
                            .expect("ledger must initialize with valid WAL path"),
                    );

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        let mut handles = Vec::with_capacity(n);
                        for i in 0..n {
                            let ledger = ledger.clone();
                            handles.push(tokio::spawn(async move {
                                let event = make_test_event(&i.to_string());
                                ledger
                                    .append_durable(&event)
                                    .await
                                    .expect("concurrent durable append must succeed");
                            }));
                        }
                        for h in handles {
                            h.await.expect("spawned task must complete without panic");
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

        let dir = tempfile::tempdir().expect("temp directory must be creatable for bench setup");
        let path = dir.path().join("srr.toml");
        std::fs::write(&path, &toml).expect("generated SRR config must be writable to temp file");
        let srr = NetworkSRR::load(&path).expect("generated SRR config must parse as valid rules");

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
        group.bench_function(BenchmarkId::new("mid_rule_match", rule_count), |b| {
            b.iter(|| {
                black_box(srr.check("POST", &mid_host, "/test", None));
            });
        });
    }

    group.finish();
}

// bench_policy_scale removed — ABAC system deleted.

// ═══════════════════════════════════════════════
// 10. IC-2 Delay Accuracy Benchmark
// ═══════════════════════════════════════════════

fn bench_ic2_delay_accuracy(c: &mut Criterion) {
    let mut group = c.benchmark_group("ic2_delay");
    group.sample_size(10); // Fewer samples since each takes 300ms+

    group.bench_function("300ms_delay_accuracy", |b| {
        b.to_async(
            tokio::runtime::Runtime::new()
                .expect("tokio runtime must initialize for bench iteration"),
        )
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
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime must initialize for bench");

    let tmp_dir = tempfile::tempdir().expect("temp directory must be creatable for bench setup");
    let wal_path = tmp_dir.path().join("bench_vault_large.log");

    let ledger = rt.block_on(async {
        Arc::new(
            Ledger::new(&wal_path, "", "")
                .await
                .expect("ledger must initialize with valid WAL path"),
        )
    });

    let vault = Arc::new(Vault::new(ledger).expect("vault must initialize with valid ledger"));

    let mut group = c.benchmark_group("vault_large");

    // Large value sizes
    for size in [65536, 262144, 1048576] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let v = vault.clone();

        group.bench_with_input(
            BenchmarkId::new("write_read_bytes", size),
            &plaintext,
            |b, pt| {
                b.to_async(
                    tokio::runtime::Runtime::new()
                        .expect("tokio runtime must initialize for bench iteration"),
                )
                .iter(|| {
                    let v = v.clone();
                    let pt = pt.clone();
                    async move {
                        v.write("bench-large", &pt, "bench-agent")
                            .await
                            .expect("vault write must succeed with valid key and data");
                        let result = v
                            .read("bench-large", "bench-agent")
                            .await
                            .expect("vault read must succeed for previously written key");
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
//
// Wasm benches need both `gvm_proxy::wasm_engine` (gated on `wasm` feature)
// and the `gvm_engine` crate (only linked when wasm feature is on). Gating
// the entire bench function and its registration entry keeps the bench
// binary buildable on default features without needing a separate file.

#[cfg(feature = "wasm")]
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
        context: gvm_engine::ContextAttrs::default(),
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
        context: gvm_engine::ContextAttrs::default(),
        rules: rules.clone(),
    };

    // ── Native evaluation ──
    let native_engine = WasmEngine::native();
    group.bench_function("native_deny", |b| {
        b.iter(|| {
            let resp = native_engine
                .evaluate(black_box(&req_deny))
                .expect("native engine must evaluate valid deny request");
            black_box(resp);
        });
    });

    group.bench_function("native_allow", |b| {
        b.iter(|| {
            let resp = native_engine
                .evaluate(black_box(&req_allow))
                .expect("native engine must evaluate valid allow request");
            black_box(resp);
        });
    });

    // ── Wasm evaluation (warm call — module already loaded) ──
    let wasm_path = Path::new("data/gvm_engine.wasm");
    if wasm_path.exists() {
        let wasm_engine =
            WasmEngine::load(wasm_path).expect("wasm module must load from verified existing path");
        assert!(wasm_engine.is_wasm(), "Wasm engine must be in Wasm mode");

        group.bench_function("wasm_deny", |b| {
            b.iter(|| {
                let resp = wasm_engine
                    .evaluate(black_box(&req_deny))
                    .expect("wasm engine must evaluate valid deny request");
                black_box(resp);
            });
        });

        group.bench_function("wasm_allow", |b| {
            b.iter(|| {
                let resp = wasm_engine
                    .evaluate(black_box(&req_allow))
                    .expect("wasm engine must evaluate valid allow request");
                black_box(resp);
            });
        });

        // ── End-to-end latency breakdown: Wasm evaluate as % of full pipeline ──
        let srr = NetworkSRR::load(Path::new("config/srr_network.toml"))
            .expect("valid SRR config must exist for e2e bench");

        // Full pipeline with Wasm: SRR + Wasm policy + max_strict
        group.bench_function("e2e_with_wasm", |b| {
            b.iter(|| {
                let srr_decision = srr.check("POST", "smtp.gmail.com", "/send", None);
                let wasm_resp = wasm_engine
                    .evaluate(black_box(&req_allow))
                    .expect("wasm engine must evaluate valid request in e2e pipeline");
                let (wasm_decision, _) = WasmEngine::response_to_decision(&wasm_resp);
                let final_d = max_strict(wasm_decision, srr_decision.decision);
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
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime must initialize for bench");

    let tmp_dir = tempfile::tempdir().expect("temp directory must be creatable for bench setup");
    let wal_path = tmp_dir.path().join("bench_vault_p99.log");

    let ledger = rt.block_on(async {
        Arc::new(
            Ledger::new(&wal_path, "", "")
                .await
                .expect("ledger must initialize with valid WAL path"),
        )
    });

    let vault = Arc::new(Vault::new(ledger).expect("vault must initialize with valid ledger"));

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
                b.to_async(
                    tokio::runtime::Runtime::new()
                        .expect("tokio runtime must initialize for bench iteration"),
                )
                .iter(|| {
                    let v = v.clone();
                    let pt = pt.clone();
                    async move {
                        v.write("bench-p99", &pt, "bench-agent")
                            .await
                            .expect("vault write must succeed with valid key and data");
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
        b.to_async(
            tokio::runtime::Runtime::new()
                .expect("tokio runtime must initialize for bench iteration"),
        )
        .iter(|| {
            let v = v.clone();
            let data = large_data.clone();
            async move {
                v.write("bench-mono", &data, "bench-agent")
                    .await
                    .expect("vault monolithic write must succeed with valid data");
                black_box(());
            }
        });
    });

    // Chunked: 16 x 16KB writes
    let v = vault.clone();
    group.bench_function("chunked_16x16kb", |b| {
        b.to_async(
            tokio::runtime::Runtime::new()
                .expect("tokio runtime must initialize for bench iteration"),
        )
        .iter(|| {
            let v = v.clone();
            let data = large_data.clone();
            async move {
                for i in 0..16 {
                    let chunk = &data[i * 16384..(i + 1) * 16384];
                    let key = format!("bench-chunk-{}", i);
                    v.write(&key, chunk, "bench-agent")
                        .await
                        .expect("vault chunked write must succeed with valid chunk data");
                }
                black_box(());
            }
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 14. Rate Limiter benchmarks — REMOVED.
//     The rate_limiter module was deleted when Throttle decision type
//     was replaced by TokenBudget (see docs/internal/CHANGELOG.md,
//     "replace Throttle with token budget system"). Token budget
//     benchmarks live in src/token_budget.rs unit tests.
// ═══════════════════════════════════════════════

// ═══════════════════════════════════════════════
// 15. Vault Contention P99 — Tail Latency Under Load
// ═══════════════════════════════════════════════

fn bench_vault_contention_p99(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime must initialize for bench");

    let tmp_dir = tempfile::tempdir().expect("temp directory must be creatable for bench setup");
    let wal_path = tmp_dir.path().join("bench_vault_contention.log");

    let ledger = rt.block_on(async {
        Arc::new(
            Ledger::new(&wal_path, "", "")
                .await
                .expect("ledger must initialize with valid WAL path"),
        )
    });

    let vault = Arc::new(Vault::new(ledger).expect("vault must initialize with valid ledger"));

    let mut group = c.benchmark_group("vault_contention_p99");
    group.sample_size(100);

    // Vary concurrency levels — each iteration runs N concurrent write+read roundtrips
    // Criterion captures the per-iteration distribution; p99 is visible in HTML report
    for concurrency in [10, 50, 100] {
        for size in [4096, 16384, 65536] {
            let v = vault.clone();
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            group.bench_with_input(
                BenchmarkId::new(
                    format!("concurrent_{}_bytes_{}", concurrency, size),
                    concurrency,
                ),
                &concurrency,
                |b, &n| {
                    b.to_async(
                        tokio::runtime::Runtime::new()
                            .expect("tokio runtime must initialize for bench iteration"),
                    )
                    .iter_custom(|iters| {
                        let v = v.clone();
                        let pt = plaintext.clone();
                        async move {
                            let mut total = std::time::Duration::ZERO;
                            for _ in 0..iters {
                                let mut handles = Vec::with_capacity(n);
                                let start = std::time::Instant::now();
                                for i in 0..n {
                                    let v = v.clone();
                                    let pt = pt.clone();
                                    handles.push(tokio::spawn(async move {
                                        let key = format!("contention-{}", i);
                                        v.write(&key, &pt, "bench-agent")
                                            .await
                                            .expect("vault write must succeed under contention");
                                        let result = v
                                            .read(&key, "bench-agent")
                                            .await
                                            .expect("vault read must succeed under contention");
                                        black_box(result);
                                    }));
                                }
                                for h in handles {
                                    h.await.expect("contention task must complete");
                                }
                                total += start.elapsed();
                            }
                            total
                        }
                    });
                },
            );
        }
    }

    // Explicit p99 measurement: 500 individual timings, report worst-case
    let v = vault.clone();
    let plaintext_16k: Vec<u8> = (0..16384).map(|i| (i % 256) as u8).collect();

    group.bench_function("p99_explicit_16kb_50writers", |b| {
        b.to_async(
            tokio::runtime::Runtime::new()
                .expect("tokio runtime must initialize for bench iteration"),
        )
        .iter(|| {
            let v = v.clone();
            let pt = plaintext_16k.clone();
            async move {
                // Measure the slowest writer out of 50 concurrent writers
                let mut handles = Vec::with_capacity(50);
                for i in 0..50 {
                    let v = v.clone();
                    let pt = pt.clone();
                    handles.push(tokio::spawn(async move {
                        let start = std::time::Instant::now();
                        let key = format!("p99-{}", i);
                        v.write(&key, &pt, "bench-agent")
                            .await
                            .expect("vault write must succeed");
                        let _ = v
                            .read(&key, "bench-agent")
                            .await
                            .expect("vault read must succeed");
                        start.elapsed()
                    }));
                }
                let mut latencies = Vec::with_capacity(50);
                for h in handles {
                    latencies.push(h.await.expect("p99 task must complete"));
                }
                latencies.sort();
                // Return p99 latency (index 49 of 50 = 98th percentile)
                black_box(latencies[latencies.len() - 1]);
            }
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 16. Wasm Cold Start — Module Load Latency
// ═══════════════════════════════════════════════

#[cfg(feature = "wasm")]
fn bench_wasm_cold_start(c: &mut Criterion) {
    use gvm_proxy::wasm_engine::WasmEngine;

    let wasm_path = Path::new("data/gvm_engine.wasm");
    if !wasm_path.exists() {
        eprintln!("Wasm module not found at data/gvm_engine.wasm — skipping cold start benchmark");
        eprintln!("Build with: cargo build -p gvm-engine --target wasm32-wasip1 --release");
        return;
    }

    let mut group = c.benchmark_group("wasm_cold_start");
    group.sample_size(20); // Cold start is expensive, fewer samples needed

    // Full cold start: file read → SHA-256 → Cranelift compile → WASI setup → instantiation
    group.bench_function("full_load", |b| {
        b.iter(|| {
            let engine = WasmEngine::load(black_box(wasm_path))
                .expect("wasm module must load from valid path");
            assert!(engine.is_wasm());
            black_box(engine);
        });
    });

    // Cold start + first evaluation (JIT warmup)
    let rules = vec![gvm_engine::Rule {
        id: "cold-test".to_string(),
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
            reason: Some("Cold start test".to_string()),
        },
    }];

    let req = gvm_engine::EvalRequest {
        operation: "gvm.storage.delete".to_string(),
        resource: gvm_engine::ResourceAttrs {
            service: "db".to_string(),
            tier: "internal".to_string(),
            sensitivity: "critical".to_string(),
        },
        subject: gvm_engine::SubjectAttrs {
            agent_id: "cold-bench".to_string(),
            tenant_id: None,
        },
        context: gvm_engine::ContextAttrs::default(),
        rules,
    };

    group.bench_function("load_and_first_eval", |b| {
        b.iter(|| {
            let engine = WasmEngine::load(black_box(wasm_path))
                .expect("wasm module must load from valid path");
            let resp = engine
                .evaluate(black_box(&req))
                .expect("first evaluation must succeed");
            black_box(resp);
        });
    });

    // Warm evaluation baseline (for comparison with cold start)
    let warm_engine = WasmEngine::load(wasm_path).expect("wasm module must load for warm baseline");

    group.bench_function("warm_eval_baseline", |b| {
        b.iter(|| {
            let resp = warm_engine
                .evaluate(black_box(&req))
                .expect("warm evaluation must succeed");
            black_box(resp);
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 17. eBPF/TC Setup Teardown — Kernel Context Switch Cost
// ═══════════════════════════════════════════════

fn bench_ebpf_setup(c: &mut Criterion) {
    if cfg!(not(target_os = "linux")) {
        eprintln!("eBPF benchmarks are Linux-only — skipping on this platform");
        return;
    }

    // Check if 'tc' and 'ip' commands are available
    let tc_ok = std::process::Command::new("tc")
        .arg("-Version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let ip_ok = std::process::Command::new("ip")
        .arg("-Version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !tc_ok || !ip_ok {
        eprintln!("'tc' or 'ip' command not available — skipping eBPF kernel benchmark");
        return;
    }

    // Check minimum kernel version (4.15+ for TC clsact)
    let kernel_ok = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| {
            let ver = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let parts: Vec<&str> = ver.split('.').collect();
            if parts.len() >= 2 {
                let major: u32 = parts[0].parse().ok()?;
                let minor: u32 = parts[1].parse().ok()?;
                Some(major > 4 || (major == 4 && minor >= 15))
            } else {
                None
            }
        })
        .unwrap_or(false);

    if !kernel_ok {
        eprintln!("Kernel < 4.15 — TC clsact not supported, skipping eBPF benchmark");
        return;
    }

    let mut group = c.benchmark_group("ebpf_kernel");
    group.sample_size(20); // kernel operations, fewer samples

    let proxy_ip_str = "10.200.0.1";
    // Full attach + detach cycle on a dummy veth pair
    // Measures: clsact qdisc add + 4x tc filter add + qdisc del (kernel round-trips)
    group.bench_function("tc_attach_detach_cycle", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                // Create a temporary veth pair for benchmarking
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", "gvm-bench0"])
                    .output();
                let _ = std::process::Command::new("ip")
                    .args([
                        "link",
                        "add",
                        "gvm-bench0",
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "gvm-bench1",
                    ])
                    .output();
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", "gvm-bench0", "up"])
                    .output();

                // ── Measured section: TC filter lifecycle ──
                let start = std::time::Instant::now();

                // Attach: clsact qdisc + 4 filter rules
                let _ = std::process::Command::new("tc")
                    .args(["qdisc", "add", "dev", "gvm-bench0", "clsact"])
                    .output();

                // TCP to proxy
                let _ = std::process::Command::new("tc")
                    .args([
                        "filter",
                        "add",
                        "dev",
                        "gvm-bench0",
                        "ingress",
                        "protocol",
                        "ip",
                        "prio",
                        "1",
                        "u32",
                        "match",
                        "ip",
                        "protocol",
                        "6",
                        "0xff",
                        "match",
                        "ip",
                        "dst",
                        proxy_ip_str,
                        "255.255.255.255",
                        "match",
                        "ip",
                        "dport",
                        "0x1f90",
                        "0xffff",
                        "action",
                        "ok",
                    ])
                    .output();

                // UDP DNS
                let _ = std::process::Command::new("tc")
                    .args([
                        "filter",
                        "add",
                        "dev",
                        "gvm-bench0",
                        "ingress",
                        "protocol",
                        "ip",
                        "prio",
                        "2",
                        "u32",
                        "match",
                        "ip",
                        "protocol",
                        "17",
                        "0xff",
                        "match",
                        "ip",
                        "dst",
                        proxy_ip_str,
                        "255.255.255.255",
                        "match",
                        "ip",
                        "dport",
                        "0x0035",
                        "0xffff",
                        "action",
                        "ok",
                    ])
                    .output();

                // ARP
                let _ = std::process::Command::new("tc")
                    .args([
                        "filter",
                        "add",
                        "dev",
                        "gvm-bench0",
                        "ingress",
                        "protocol",
                        "arp",
                        "prio",
                        "3",
                        "u32",
                        "match",
                        "u32",
                        "0",
                        "0",
                        "action",
                        "ok",
                    ])
                    .output();

                // Drop all else
                let _ = std::process::Command::new("tc")
                    .args([
                        "filter",
                        "add",
                        "dev",
                        "gvm-bench0",
                        "ingress",
                        "protocol",
                        "all",
                        "prio",
                        "99",
                        "u32",
                        "match",
                        "u32",
                        "0",
                        "0",
                        "action",
                        "drop",
                    ])
                    .output();

                // Detach: remove clsact
                let _ = std::process::Command::new("tc")
                    .args(["qdisc", "del", "dev", "gvm-bench0", "clsact"])
                    .output();

                total += start.elapsed();

                // Cleanup veth pair
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", "gvm-bench0"])
                    .output();
            }
            total
        });
    });

    // Attach only (setup cost isolated — detach excluded from measurement)
    group.bench_function("tc_attach_only", |b| {
        b.iter_custom(|iters| {
            let mut total = std::time::Duration::ZERO;
            for _ in 0..iters {
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", "gvm-bench0"])
                    .output();
                let _ = std::process::Command::new("ip")
                    .args([
                        "link",
                        "add",
                        "gvm-bench0",
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "gvm-bench1",
                    ])
                    .output();
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", "gvm-bench0", "up"])
                    .output();

                let start = std::time::Instant::now();

                let _ = std::process::Command::new("tc")
                    .args(["qdisc", "add", "dev", "gvm-bench0", "clsact"])
                    .output();
                for (prio, args) in [
                    (
                        "1",
                        vec![
                            "protocol", "ip", "u32", "match", "ip", "protocol", "6", "0xff",
                            "action", "ok",
                        ],
                    ),
                    (
                        "99",
                        vec![
                            "protocol", "all", "u32", "match", "u32", "0", "0", "action", "drop",
                        ],
                    ),
                ] {
                    let mut cmd_args = vec!["filter", "add", "dev", "gvm-bench0", "ingress"];
                    cmd_args.push("prio");
                    cmd_args.push(prio);
                    cmd_args.extend(args.iter());
                    let _ = std::process::Command::new("tc").args(&cmd_args).output();
                }

                total += start.elapsed();

                // Cleanup (outside measurement)
                let _ = std::process::Command::new("tc")
                    .args(["qdisc", "del", "dev", "gvm-bench0", "clsact"])
                    .output();
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", "gvm-bench0"])
                    .output();
            }
            total
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════
// 18. v3 audit hot-path benchmarks
//
// After the v3 audit refactor (Phases A-E + dispatcher fixes), every
// behavioral event flows through:
//   1. compute_event_hash dispatcher (v1 vs v2 selection)
//   2. seal_hash() canonical input over the TripleState snapshot
//   3. compute_hash() for the per-batch GvmStateAnchor
//   4. compute_checkpoint_root over (agent_id, agent_root) pairs
//   5. compute_agent_checkpoint_root over BTreeMap<step, [u8;32]>
//
// These benches isolate each step so a future regression in any one
// of them shows up in CI/bench history rather than only as an
// end-to-end fsync slowdown.
// ═══════════════════════════════════════════════

fn bench_v3_event_hash_dispatcher(c: &mut Criterion) {
    use gvm_proxy::merkle::compute_event_hash;
    let mut group = c.benchmark_group("v3_event_hash");

    // v1 path: legacy event with operation_descriptor: None
    let v1_event = make_test_event("v1");
    group.bench_function("v1_legacy_operation_string", |b| {
        b.iter(|| {
            black_box(compute_event_hash(black_box(&v1_event)));
        });
    });

    // v2 path: descriptor present (production today)
    let mut v2_event = make_test_event("v2");
    v2_event.operation_descriptor = Some(gvm_types::OperationDescriptor::new(
        "http.POST",
        Some("/api/v1/user/12345/delete".to_string()),
        vec![7u8; 16],
    ));
    group.bench_function("v2_descriptor_with_detail", |b| {
        b.iter(|| {
            black_box(compute_event_hash(black_box(&v2_event)));
        });
    });

    // v2 category-only (config_load): no salt, deterministic digest
    let mut v2_cat_event = make_test_event("v2cat");
    v2_cat_event.operation_descriptor =
        Some(gvm_types::OperationDescriptor::category_only("gvm.system.config_load"));
    group.bench_function("v2_category_only_no_detail", |b| {
        b.iter(|| {
            black_box(compute_event_hash(black_box(&v2_cat_event)));
        });
    });

    group.finish();
}

fn bench_v3_seal_and_anchor(c: &mut Criterion) {
    let mut group = c.benchmark_group("v3_seal_anchor");

    let seal = gvm_types::BatchSealRecord {
        seal_id: 42,
        sealed_at: chrono::Utc::now(),
        context_hash: "a".repeat(64),
        checkpoint_root: Some("b".repeat(64)),
        prev_anchor: Some("c".repeat(64)),
    };

    group.bench_function("seal_hash_canonical", |b| {
        b.iter(|| {
            black_box(black_box(&seal).seal_hash());
        });
    });

    let batch_root = "d".repeat(64);
    group.bench_function("anchor_compute_hash", |b| {
        b.iter(|| {
            black_box(gvm_types::GvmStateAnchor::compute_hash(
                1,
                42,
                seal.sealed_at.timestamp(),
                black_box(&batch_root),
                &seal.context_hash,
                seal.checkpoint_root.as_deref(),
                seal.prev_anchor.as_deref(),
            ));
        });
    });

    group.bench_function("anchor_seal_full", |b| {
        b.iter(|| {
            let anchor = gvm_types::GvmStateAnchor::seal(1, &seal, batch_root.clone());
            black_box(anchor);
        });
    });

    // verify_self_hash is on every audit-time check; pin its cost.
    let anchor = gvm_types::GvmStateAnchor::seal(1, &seal, batch_root.clone());
    group.bench_function("anchor_verify_self_hash", |b| {
        b.iter(|| {
            black_box(black_box(&anchor).verify_self_hash());
        });
    });

    group.finish();
}

fn bench_v3_checkpoint_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("v3_checkpoint_root");

    // Global aggregator root over (agent_id, agent_root) pairs.
    for n in [10usize, 100, 1_000] {
        let leaves: Vec<(String, [u8; 32])> = (0..n)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0] = (i % 256) as u8;
                (format!("agent-{}", i), h)
            })
            .collect();
        group.bench_with_input(
            BenchmarkId::new("global_root_agents", n),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    black_box(gvm_types::compute_checkpoint_root(black_box(leaves)));
                });
            },
        );
    }

    // Per-agent per-step tree root.
    for steps in [10u32, 100, 1_000] {
        let mut tree: std::collections::BTreeMap<u32, [u8; 32]> = std::collections::BTreeMap::new();
        for i in 0..steps {
            let mut h = [0u8; 32];
            h[0] = (i % 256) as u8;
            tree.insert(i, h);
        }
        group.bench_with_input(
            BenchmarkId::new("agent_tree_root_steps", steps),
            &tree,
            |b, t| {
                b.iter(|| {
                    black_box(gvm_types::compute_agent_checkpoint_root(black_box(t)));
                });
            },
        );
    }

    // Step inclusion proof generation.
    let mut tree: std::collections::BTreeMap<u32, [u8; 32]> = std::collections::BTreeMap::new();
    for i in 0..100u32 {
        let mut h = [0u8; 32];
        h[0] = (i % 256) as u8;
        tree.insert(i, h);
    }
    group.bench_function("agent_proof_step_50_of_100", |b| {
        b.iter(|| {
            black_box(gvm_types::agent_checkpoint_proof(black_box(&tree), 50));
        });
    });

    group.finish();
}

// ═══════════════════════════════════════════════

// Native bench group — always built. Wasm benches are split out behind
// `--features wasm` so the bench binary builds on default features without
// pulling in `gvm_engine` (which is gated on the same flag).
criterion_group!(
    native_benches,
    bench_srr,
    bench_max_strict,
    bench_vault,
    bench_wal,
    bench_wal_group_commit,
    bench_classification,
    bench_srr_scale,
    bench_ic2_delay_accuracy,
    bench_vault_large,
    bench_vault_p99,
    bench_vault_contention_p99,
    bench_ebpf_setup,
    bench_v3_event_hash_dispatcher,
    bench_v3_seal_and_anchor,
    bench_v3_checkpoint_root,
);

#[cfg(feature = "wasm")]
criterion_group!(wasm_benches, bench_wasm_vs_native, bench_wasm_cold_start);

#[cfg(feature = "wasm")]
criterion_main!(native_benches, wasm_benches);

#[cfg(not(feature = "wasm"))]
criterion_main!(native_benches);
