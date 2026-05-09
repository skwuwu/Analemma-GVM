# Part 4: WAL-First Ledger & Audit

**Source**: `src/ledger.rs` | **Config**: `config/proxy.toml`

---

## 4.1 Overview

The Ledger provides crash-safe event recording with a WAL-first (Write-Ahead Log) architecture. Every enforcement decision is recorded locally before any external action, ensuring that even during proxy crashes or network failures, the audit trail remains intact.

**Design principle**: **WAL is the source of truth. Distribution to downstream consumers is operator-managed, not built in.** GVM owns the local audit trail (WAL + Merkle + anchor chain) but does not connect to any external streaming system on the operator's behalf — `commit f3d274c` removed the prior NATS / Redis stubs because shipping unactivated integration code in a runtime that operators install as `setuid root` was a confusing mismatch between marketing and reality. Off-host replication today is operator-supplied via the WAL file itself:

- **Tail-and-ship sidecar** — `tail -F data/wal.log | downstream-tool`. The WAL is newline-JSON; any log shipper (Vector, Fluent Bit, Filebeat, fluentd, rsyslog) consumes it directly without an integration layer.
- **rsync / S3 backup** — periodic snapshot to remote storage. The Merkle/anchor chain in each batch makes tampering during transit detectable on the receiver side.
- **Periodic batch proof upload** — cron + `gvm proof batch <id> --wal data/wal.log` to ship per-batch proofs to S3 or an external auditor as compact, single-anchor JSON documents.
- **Operator-built broker integration** — if NATS / Kafka / Pub/Sub is required, the operator runs a small consumer process tailing the WAL and publishing to their broker of choice. The `wal_sequence` field on every event is reserved for that consumer to reconstruct WAL order from out-of-order broker messages.

**The WAL stays authoritative regardless of how the operator distributes it.** If a downstream pipeline is unreachable (broker down, network partition, sidecar crashed), GVM continues to enforce — the local Merkle/anchor chain is the source of truth for `gvm audit verify` and `gvm proof verify`. Coupling enforcement to a specific message bus would create a single point of failure that the WAL-first design refuses; coupling it to one that GVM doesn't even ship would be worse.

---

## 4.2 Architecture

```
                IC-2/IC-3 Request
                      │
                      ▼
            ┌─────────────────┐
            │  WAL Append     │ ← group-commit batched fsync
            │  (durable)      │   (~6 ms /req solo, ~8 ms /100 concurrent
            │                 │    on EC2 EBS — see test-report D.1)
            └────────┬────────┘
                     │
                     ├──── ✓ Success → Continue to enforcement
                     │
                     └──── ✗ Failure → REJECT request (Fail-Close)
                                       "Audit log unavailable"

            (off-host replication is operator-managed:
             tail data/wal.log → fluentd / rsync / S3 / broker)
```

---

## 4.3 Dual-Path Write Strategy

| IC Level | WAL | Durability | Per-event latency (group commit, EC2 t3.medium) |
|----------|-----|------------|-------------------------------------------------|
| IC-1 (Allow) | `append_async` (fire-and-forget, loss tolerated < 0.1%) | Loss tolerated | ~0 ms |
| IC-2 (Delay) | `append_durable` (fsync first) | Guaranteed | ~6 ms solo / ~85 µs at 100 concurrent (8.48 ms ÷ 100) |
| IC-3 (RequireApproval) | `append_durable` (fsync first) | Guaranteed | ~6 ms solo |
| Deny | `append_durable` (fsync first) | Guaranteed | ~6 ms solo |

`append_async` skips the fsync and returns immediately; the event is buffered in the in-memory batch and lands on disk at the next group-commit tick. Acceptable for IC-1 because a lost Allow on a read operation is reversible (the read happened, the audit gap is recoverable from upstream logs). `append_durable` blocks the request on fsync — this is what makes "no Deny without a durable WAL entry" hold even across crashes.

**IC-1 rationale**: Read operations are reversible. Losing an audit entry for `gvm.storage.read` is acceptable at a rate below 0.1%. The performance gain (no disk I/O) is significant under high read volume.

**IC-2/3 rationale**: Write, payment, and approval operations must have a durable audit record before the action executes. WAL fsync provides this guarantee with single-event latency of ~6 ms on EBS, falling to ~85 µs under concurrent load thanks to group commit.

---

## 4.4 WAL (Write-Ahead Log) with Group Commit + Merkle Tree

### Structure

The WAL is a newline-delimited JSON file (`data/wal.log`) containing four kinds of lines (post-v3 audit refactor):

```json
{"event_id":"evt-001","trace_id":"tr-abc","operation":"gvm.payment.refund","operation_descriptor":{"category":"http.POST","detail_digest":"…"},"status":"Pending","event_hash":"a1b2…"}
{"event_id":"evt-002","trace_id":"tr-abc","operation":"gvm.messaging.send","operation_descriptor":{"category":"http.POST","detail_digest":"…"},"status":"Pending","event_hash":"c3d4…"}
{"seal_id":0,"sealed_at":"…","context_hash":"…","checkpoint_root":null,"prev_anchor":null}
{"batch_id":0,"merkle_root":"e5f6…","prev_batch_root":null,"event_count":2,"seal_position":2,"leaves_blob":"…","timestamp":"…"}
{"spec_version":1,"batch_id":0,"timestamp":"…","batch_root":"e5f6…","context_hash":"…","checkpoint_root":null,"prev_anchor":null,"anchor_hash":"…"}
```

Events within a batch + the seal record form a Merkle tree (intra-batch integrity); the seal's `seal_hash()` is the LAST leaf, so any tamper of seal fields propagates to `merkle_root` and into `anchor_hash`. Batches are chained both via `prev_batch_root` (inter-batch Merkle chain) and via `prev_anchor` on the anchor itself (state-anchor chain).

### Group Commit Architecture

```
Caller A (Deny) ──→  high lane mpsc (4096)  ─┐
Caller B (Delay)──→  normal lane mpsc (4096) ─┤  batch_loop          ┌─ event_1 line
Caller C (Allow)──→  low lane mpsc (4096)    ─┘  biased select       ├─ event_2 line
                                                 + drain_priority    ├─ ...
                                                 (high → normal      ├─ event_N line
                                                  → low until        ├─ seal line          (BatchSealRecord)
                                                  max_batch_size      ├─ batch_record line  (MerkleBatchRecord — leaves_blob includes seal_hash as last leaf)
                                                  = 512)              └─ anchor line        (GvmStateAnchor, anchor_hash binds all roots)
                                                                            │
                                                                            └─ write_all(all 4 line groups) → fsync(1x)
```

Event hashing and JSON serialization happen in **caller threads** (parallel). At `append`, an event's `decision` string is classified into one of three priority lanes (Phase F):

- **High** — `Deny` / `RequireApproval` (security-critical: must drain first)
- **Normal** — `Delay` / `AuditOnly`
- **Low** — `Allow` / unclassified

The batch loop runs a `biased tokio::select!` over the 3 receivers and a `drain_priority()` helper that fully drains high before normal, normal before low, until `max_batch_size` (512) is reached. **All admitted events share one fsync, one seal, one anchor** — the v3 audit chain (C2/C3 contracts) is unchanged. Priority only affects which pending events are admitted to the next batch.

```rust
pub enum WalPriority { High, Normal, Low }

impl WalPriority {
    pub fn from_event(event: &GVMEvent) -> Self {
        let d = event.decision.as_str();
        if d.starts_with("Deny") || d.starts_with("RequireApproval") { Self::High }
        else if d.starts_with("Delay") || d.starts_with("AuditOnly")
                || d == "Confirmed" || d == "Pending"               { Self::Normal }
        else                                                         { Self::Low }
    }
}

struct WAL {
    tx_high:   Option<tokio::sync::mpsc::Sender<GroupCommitRequest>>,
    tx_normal: Option<tokio::sync::mpsc::Sender<GroupCommitRequest>>,
    tx_low:    Option<tokio::sync::mpsc::Sender<GroupCommitRequest>>,
    batch_task: Option<tokio::task::JoinHandle<()>>,
    triple: Arc<arc_swap::ArcSwap<TripleState>>,
    signer: Arc<dyn AnchorSigner>,
    // ...
}

async fn append(&self, event: &GVMEvent) -> Result<()> {
    let hash = compute_event_hash(event);              // v1/v2 dispatcher
    let mut stamped = event.clone();
    stamped.event_hash = Some(hash.clone());
    let data = serde_json::to_vec(&stamped)?;

    let priority = WalPriority::from_event(event);
    let tx = match priority {
        WalPriority::High   => self.tx_high.as_ref(),
        WalPriority::Normal => self.tx_normal.as_ref(),
        WalPriority::Low    => self.tx_low.as_ref(),
    }.ok_or_else(|| anyhow!("WAL batch task shut down"))?;

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(GroupCommitRequest { data, event_hash: hash, reply: reply_tx }).await?;
    reply_rx.await?
}
```

**Key properties**:
- **One fsync per batch** — amortized across all events plus the seal/batch/anchor lines
- **Batch window (2ms default)** — waits briefly for concurrent events to batch together. Group commit reduces 100 sequential fsyncs from ~645 ms to ~11 ms at 100 concurrent (**57x improvement**); 500 concurrent absorbs into one batch at ~14.7 ms (post-Phase F: `max_batch_size 128 → 512`, was 25 ms at the old size). See [test-report D.1](../test-report.md#wal-write-ahead-log--post-phase-f-priority-lane--max_batch_size512). Configurable via `[wal] batch_window_ms` in `proxy.toml`.
- **3-tier priority lane** — high (Deny/RequireApproval) drains before normal (Delay/AuditOnly) before low (Allow). Tail latency for high-priority events is bounded by *one* fsync regardless of low-lane queue depth — no head-of-line blocking under noisy-neighbor bursts. See [tests/wal_priority_lane.rs](../../tests/wal_priority_lane.rs) for invariants.
- **Non-blocking drain** — `try_recv()` collects queued events across all 3 lanes
- **Bounded backpressure** — channel capacity 4096 *per lane*, max batch size 512
- **Caller-parallel serialization** — event hash + JSON computed before channel send. v2 hash dispatcher (descriptor-aware) is ~2 µs per event.
- **Size-based rotation** — `max_wal_bytes` (100MB default) triggers rotation to `wal.log.<N>`, `max_wal_segments` (10 default) prunes oldest segments. Merkle chain links across segments via `prev_batch_root`; anchor chain via `prev_anchor`.
- **Emergency WAL fallback** — if primary WAL fails, events go to `wal_emergency.log` (degraded mode, no Merkle)
- **Anchor signing (Phase 6)** — every anchor's `anchor_hash` is run through `AnchorSigner` after construction. Default `NoopSigner` leaves `signature: None`; `SelfSignedSigner` (Ed25519) attaches a 64-byte signature; `Hsm` / `Tsa` variants are reserved.

> **Long-term retention**: Default settings retain at most 100MB x 10 = 1GB of audit trail on local disk. When the 11th segment is created, the oldest segment is **permanently deleted**. Segments are plain JSON files — back up or archive however you like (cron + S3, rsync, etc.) before they are pruned.

### Global Merkle Chain Design

**All agents share a single WAL and a single Merkle chain.** This is a deliberate architectural choice:

| Property | Global chain (current) | Per-agent chains (rejected) |
|----------|----------------------|---------------------------|
| Cross-agent ordering | Cryptographically guaranteed | Impossible (timestamp-only, forgeable) |
| Collusion detection | "A denied → B retries same URL" provable | Requires timestamp merge (not tamper-proof) |
| Verification | Single `verify_wal()` pass | N passes + cross-chain reconciliation |
| WAL file management | 1 file | N files (one per agent) |
| Serialization point | Batch-level (group commit) | None (but N separate fsyncs) |

**Why global doesn't bottleneck**: The serialization point is the batch, not the event. At 100 agents × 10 ops/sec = 1,000 events/sec, with batch drain collecting ~10 events per batch, that's ~100 fsyncs/sec — trivial for any modern disk. Sharding becomes relevant only at ~100K events/sec, at which point an external broker (operator's choice — see §4.1) provides cross-shard ordering.

**Scaling path**: v1.x global WAL + Phase F priority lane → v2.x operator-chosen distribution channel handles ordering → v3.x proxy sharding by agent_id hash (if needed).

---

## 4.5 WAL Sequence Number (Ordering Guarantee)

```rust
pub struct Ledger {
    // group-commit batch channels (high / normal / low priority)
    tx_high:    Option<tokio::sync::mpsc::Sender<GroupCommitRequest>>,
    tx_normal:  Option<tokio::sync::mpsc::Sender<GroupCommitRequest>>,
    tx_low:     Option<tokio::sync::mpsc::Sender<GroupCommitRequest>>,
    batch_task: Option<tokio::task::JoinHandle<()>>,
    path:       PathBuf,
    triple:     Arc<arc_swap::ArcSwap<TripleState>>,  // Merkle root + last anchor + integrity context
    signer:     Arc<dyn AnchorSigner>,                // Ed25519 signer (NoopSigner if disabled)
    inject_error: Arc<AtomicBool>,                    // test-only fault injection
    // emergency fallback WAL on a separate path for primary fsync failure
    emergency_wal: EmergencyWAL,
    primary_failures:  AtomicU64,
    emergency_writes:  AtomicU64,
}
```

**Note on distribution channel**: There is no built-in publish hook. `Ledger::append_durable` writes to the local WAL and returns; the prior `tokio::spawn(nats_publish)` stub was removed in `commit f3d274c` because it advertised an integration the runtime never performed. Operators wiring a downstream consumer (Kafka publisher, fluentd, S3 backup, etc.) tail `data/wal.log` from outside the proxy process — see §4.1 for the menu of operator-managed options. The `wal_sequence` counter on every event is reserved so any such consumer can reconstruct WAL order from out-of-order broker messages.

**WAL sequence properties** (always active):
- Lock-free (`AtomicU64`) — zero performance impact
- Monotonic — strictly increasing, no gaps within a process lifetime
- SeqCst ordering — visible to all threads immediately
- **Restart recovery**: Initialized from existing WAL event count on startup — monotonic across restarts

---

## 4.6 Event Status Machine

```
                     ┌──────────┐
                     │ Pending  │ ← Written to WAL before action
                     └────┬─────┘
                          │
              ┌───────────┼───────────┐
              ▼           ▼           ▼
        ┌──────────┐ ┌─────────┐ ┌─────────┐
        │Confirmed │ │ Failed  │ │ Expired │
        │ (2xx)    │ │ (error) │ │ (crash) │
        └──────────┘ └─────────┘ └─────────┘
```

| Status | Meaning |
|--------|---------|
| `Pending` | Written to WAL, external API not yet called |
| `Executed` | External API call completed (response received) |
| `Confirmed` | External API returned success (2xx) |
| `Failed { reason }` | External API call failed or error response |
| `Expired` | Proxy restarted, found this event still Pending. Execution status uncertain |

**Expired** is the key innovation: on crash recovery, Pending events become Expired — explicitly marking "we don't know if this executed." This prevents phantom records where auditors assume an action happened when it may not have.

---

## 4.7 Crash Recovery

```rust
pub async fn recover_from_wal(&self) -> Result<RecoveryReport> {
    // High watermark: byte offset of last completed recovery.
    // Only scan events AFTER the watermark — O(1) memory.
    let watermark: u64 = read_watermark(&watermark_path).unwrap_or(0);
    let file_len = file.metadata()?.len();

    let mut reader = std::io::BufReader::new(file);
    if watermark > 0 && watermark <= file_len {
        reader.seek(SeekFrom::Start(watermark))?;
    }

    for line_result in reader.lines() {
        // ... parse, skip batch records / empty lines / corrupt entries ...
        match serde_json::from_str::<GVMEvent>(&line) {
            Ok(event) if event.status == Pending => {
                let mut expired = event;
                expired.status = EventStatus::Expired;
                self.wal.append(&expired).await?;
            }
            _ => {}
        }
    }

    // Persist watermark: everything before file_len is now resolved.
    // Atomic write (tmp + rename) prevents partial watermark on crash.
    write_watermark(&watermark_path, file_len)?;
}
```

**High watermark strategy**: Previous recoveries resolve ALL Pending events before the watermark offset, so subsequent recoveries skip them entirely. No `HashSet` needed — O(1) memory regardless of WAL size. If watermark write fails, next recovery re-scans from the old watermark (idempotent: re-expiring is harmless).

**Corruption resilience**: Corrupted WAL entries (from disk failure, truncation, or tampering) are **skipped**, not fatal. Recovery continues processing valid entries after the corruption.

---

## 4.8 Config File Hash Recording

At proxy startup, the Ledger records SHA-256 hashes of all loaded configuration files as a system event in the Merkle chain. This enables tamper detection: if a policy file is modified between proxy restarts, the hash mismatch is visible in the audit trail.

### Mechanism

```rust
ledger.record_config_load(&[
    ("gvm:gvm.toml", &gvm_toml_path),
]).await?;
```

This creates a `GVMEvent` with:
- `operation`: `gvm.system.config_load`
- `agent_id`: `gvm-proxy`
- `status`: `Confirmed`
- `context`: map of `label → SHA-256 hex digest` for each config file

The event enters the Merkle chain via `append_durable()`, so it has an `event_hash` and participates in batch Merkle roots — identical integrity guarantees as enforcement events.

### Tamper Detection Flow

```
Restart N:   config_load event → context: { "policy:global.toml": "a1b2c3..." }
                                                    ↓
             (attacker modifies global.toml on disk)
                                                    ↓
Restart N+1: config_load event → context: { "policy:global.toml": "d4e5f6..." }

Auditor: compare context fields across config_load events → hash mismatch detected
```

### Graceful Degradation

- If a config file is unreadable (permissions, deleted), its hash is recorded as `"unavailable"` with a warning log. The proxy continues startup.
- Config hash recording failure is non-fatal — the proxy logs a warning and continues. This prevents a secondary failure (e.g., WAL disk full) from blocking startup of a proxy that has valid config.

---

## 4.9 Test Coverage

| Test | Source | Assertion |
|------|--------|-----------|
| `wal_tampered_entry_does_not_crash_recovery` | `tests/hostile.rs` | Corrupted JSON between valid entries → recovery succeeds, finds 2 Pending events |
| `ledger_concurrent_spawns_stay_bounded` | `tests/hostile.rs` | 500 concurrent durable appends complete < 10s, WAL has exactly 500 entries |
| `config_file_hashes_recorded_in_merkle_chain` | `tests/integration.rs` | Config files → WAL event with correct SHA-256 hashes + event_hash (Merkle membership) |
| `config_hash_records_unavailable_for_missing_files` | `tests/integration.rs` | Missing config file → hash recorded as `"unavailable"`, no error |

---

## 4.10 Security Implications

- **Fail-Close**: WAL write failure → request rejected. No action without audit record. Both primary and emergency WAL must fail before Fail-Close triggers.
- **Tamper Detection**: Per-event SHA-256 hashes + Merkle batch roots. `verify_wal()` detects both event content tampering and batch chain breaks.
- **No Phantom Records**: Expired status explicitly marks uncertain execution state.
- **Cross-Agent Ordering**: Global Merkle chain provides cryptographic proof of event ordering across all agents. This enables collusion detection: "Agent A was denied at batch N, Agent B attempted the same URL at batch N+1" is provable, not just timestamp-correlated.
- **Ordering Guarantee**: AtomicU64 sequence on every event lets any operator-built downstream consumer (broker publisher, log shipper, S3 backup) reconstruct exact WAL order even when transport reorders.
- **Backpressure**: Bounded channel (4096) + max batch size (128) prevent unbounded resource consumption.
- **Config Integrity**: SHA-256 hashes of policy files are recorded in the Merkle chain at startup. Policy file tampering between restarts is detectable by comparing `gvm.system.config_load` events across restarts.

---

## 4.11 WAL Recording Points

Every governance decision is recorded to WAL at one of seven enforcement points. Each point populates the same `GVMEvent` schema but with different field values.

### Recording Points

| # | Enforcement Point | Source File | Trigger | operation | decision_source | Durability |
|---|-------------------|-------------|---------|-----------|-----------------|------------|
| 1 | `proxy` | `proxy.rs` | HTTP request through proxy | From HTTP method + host + path | `SRR` | Allow: async, AuditOnly/Delay/RequireApproval/Deny: durable |
| 2 | `proxy` | `proxy.rs` | CONNECT tunnel request | `connect:{host}` | `SRR` | async (loss tolerated) |
| 3 | `mitm` | `tls_proxy.rs` | Decrypted HTTPS request via MITM | From HTTP method + path | `SRR` | Always durable |
| 4 | `dns-proxy` | `dns_governance.rs` | DNS query from sandboxed agent | `gvm.dns.query` | `dns-governance` | Known/Unknown: async, Anomalous/Flood: durable |
| 5 | `proxy` | `vault.rs` | Vault secret operation | `gvm.vault.{op}` | `internal` | Write/Delete: durable, Read/List: async |
| 6 | `startup` | `ledger.rs` | Proxy start or hot-reload | `gvm.system.config_load` | `system` | Always durable |
| 7 | `proxy` | `proxy.rs` | LLM response with reasoning trace | (appended to existing event) | (inherited) | Always durable (separate entry) |

### enforcement_point Values

| Value | Meaning |
|-------|---------|
| `proxy` | SRR matched, token-budget check, vault, or fail-close |
| `mitm` | TLS MITM interception — decrypted HTTPS request |
| `mitm-ws-upgrade` | WebSocket upgrade detected during MITM |
| `dns-proxy` | DNS governance engine — UDP query classification |
| `startup` | System event at proxy startup or config reload |

### decision_source Values

| Value | Meaning |
|-------|---------|
| `SRR` | Network policy (host/path/method/payload pattern matching) |
| `dns-governance` | DNS tier classification (Known/Unknown/Anomalous/Flood) |
| `token-budget` | Per-agent cost/token budget decision |
| `system` | Internal system event (config load, startup) |
| `internal` | Vault operations (always Allow) |
| `fail-close` | Emergency path — classification failure or circuit breaker |

### GVMEvent Field Reference

```rust
pub struct GVMEvent {
    // ── Identification ──
    event_id: String,                    // UUID, unique per event
    trace_id: String,                    // Distributed trace correlation
    parent_event_id: Option<String>,     // Causal chain link

    // ── Subject ──
    agent_id: String,                    // Acting agent ID
    tenant_id: Option<String>,           // Org tag for audit correlation (single-org per runtime)
    session_id: String,                  // Session identifier
    timestamp: DateTime<Utc>,            // UTC timestamp

    // ── Operation ──
    operation: String,                   // Semantic operation name
    resource: ResourceDescriptor,        // Service, identifier, tier, sensitivity
    context: HashMap<String, Value>,     // Free-form context (DNS: tier, delay_ms, etc.)

    // ── Transport ──
    transport: Option<TransportInfo>,    // HTTP method, host, path, status_code

    // ── Decision ──
    decision: String,                    // "Allow", "Delay { milliseconds: 100 }", "Deny { reason: ... }"
    decision_source: String,             // See table above
    matched_rule_id: Option<String>,     // SRR rule that matched
    enforcement_point: String,           // See table above

    // ── Lifecycle ──
    status: EventStatus,                 // Pending → Confirmed / Failed / Expired

    // ── Payload ──
    payload: PayloadDescriptor,          // content_hash (SHA-256), size, flagged patterns

    // ── Integrity ──
    event_hash: Option<String>,          // SHA-256 of canonical fields
    wal_sequence: Option<u64>,           // Monotonic ordering counter (used by operator-built downstream consumers)

    // ── LLM Trace (IC-2 only, when LLM response detected) ──
    llm_trace: Option<LLMTrace>,         // provider, model, thinking, token usage
    default_caution: bool,               // Hit SRR catch-all (no matching rule)?
}
```

### Durability by Decision Type

Every governance decision is Merkle-chained. Non-governance internal
events (DNS Tier 1 `Known`, Vault read/list) are deliberately excluded
from the audit chain via `append_async` to bound log growth.

| Decision / Event | Strictness | WAL Write | Status Lifecycle |
|-----------------|------------|-----------|------------------|
| Allow | 0 | `append_durable` (group commit, ~2ms batched fsync) | → Confirmed |
| AuditOnly | 1 | `append_durable` | Pending → Confirmed/Failed |
| Delay { ms } | 2 | `append_durable` | Pending → delay → Confirmed/Failed |
| RequireApproval | 3 | `append_durable` | Pending → approval/timeout → Confirmed/Failed |
| Deny | 4 | `append_durable` | → Failed { reason } |
| TokenBudget exceeded | — | `append_durable` | → Failed (403, budget_exceeded) |
| DNS Tier 1 (Known) | — | `append_async` (fire-and-forget, **not in Merkle chain**) | — |
| DNS Tier 2+ (Unknown/Anomalous/Flood) | — | `append_durable` | Pending → Confirmed |
| Vault read / list_keys | — | `append_async` (fire-and-forget, **not in Merkle chain**) | — |
| Vault write / delete | — | `append_durable` | Pending → Confirmed |

### DNS Governance Context Fields

DNS events include additional context attributes for forensic analysis:

| Context Key | Type | Description |
|-------------|------|-------------|
| `dns_tier` | string | "Known", "Unknown", "Anomalous", "Flood" |
| `delay_ms` | number | Applied delay in milliseconds (0/200/3000/10000) |
| `dns_base_domain` | string | Base domain of the query |
| `dns_unique_subdomain_count` | number | Unique subdomains seen for this base in window |
| `dns_global_unique_count` | number | Global unique subdomain count across all domains |
| `dns_window_age_secs` | number | Age of the sliding window in seconds |

### Vault Event Operations

| operation | Durability | Payload |
|-----------|-----------|---------|
| `gvm.vault.vault_write` | Durable | SHA-256 hash of encrypted value |
| `gvm.vault.vault_read` | Async | None |
| `gvm.vault.vault_delete` | Durable | None |
| `gvm.vault.vault_list_keys` | Async | None |

All vault events use `decision: "Allow"`, `decision_source: "internal"`, `resource.sensitivity: High`.

---

[← Part 3: Network SRR](srr.md) | [Part 5: Encrypted Vault →](architecture/vault.md)
