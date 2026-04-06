# Part 4: WAL-First Ledger & Audit

**Source**: `src/ledger.rs` | **Config**: `config/proxy.toml` (NATS section)

---

## 4.1 Overview

The Ledger provides crash-safe event recording with a WAL-first (Write-Ahead Log) architecture. Every enforcement decision is recorded locally before any external action, ensuring that even during proxy crashes or network failures, the audit trail remains intact.

**Design principle**: WAL is the source of truth. NATS JetStream is the distribution layer. If NATS is unavailable, WAL has the complete record.

---

## 4.2 Architecture

```
                IC-2/IC-3 Request
                      │
                      ▼
            ┌─────────────────┐
            │  WAL Append     │ ← fsync to disk (< 1ms)
            │  (durable)      │
            └────────┬────────┘
                     │
                     ├──── ✓ Success → Continue to enforcement
                     │
                     └──── ✗ Failure → REJECT request (Fail-Close)
                                       "Audit log unavailable"

            ┌─────────────────┐
            │  NATS Publish   │ ← tokio::spawn (async, non-blocking)
            │  (fire-and-     │    Includes wal_sequence for ordering
            │   forget)       │
            └─────────────────┘
```

---

## 4.3 Dual-Path Write Strategy

| IC Level | WAL | NATS | Durability | Latency |
|----------|-----|------|------------|---------|
| IC-1 (Allow) | Skip | Async spawn | Loss tolerated (< 0.1%) | ~0ms |
| IC-2 (Delay) | fsync first | Async spawn | Guaranteed | < 1ms |
| IC-3 (RequireApproval) | fsync first | Async spawn | Guaranteed | < 1ms |
| Deny | fsync first | Async spawn | Guaranteed | < 1ms |

**IC-1 rationale**: Read operations are reversible. Losing an audit entry for `gvm.storage.read` is acceptable at a rate below 0.1%. The performance gain (no disk I/O) is significant under high read volume.

**IC-2/3 rationale**: Write, payment, and approval operations must have a durable audit record before the action executes. WAL fsync provides this guarantee in under 1ms.

---

## 4.4 WAL (Write-Ahead Log) with Group Commit + Merkle Tree

### Structure

The WAL is a newline-delimited JSON file (`data/wal.log`) containing interleaved event records and Merkle batch records:

```json
{"event_id":"evt-001","trace_id":"tr-abc","operation":"gvm.payment.refund","status":"Pending","event_hash":"a1b2..."}
{"event_id":"evt-002","trace_id":"tr-abc","operation":"gvm.messaging.send","status":"Pending","event_hash":"c3d4..."}
{"batch_id":0,"merkle_root":"e5f6...","prev_batch_root":null,"event_count":2,"timestamp":"..."}
```

Events within a batch form a Merkle tree (intra-batch integrity). Batches are chained via `prev_batch_root` (inter-batch integrity).

### Group Commit Architecture

```
Caller A ─┐
Caller B ──┤ mpsc channel (4096) → batch_loop → collect(try_recv drain) →
Caller C ──┘                         write_all(events + batch_record) → fsync(1x)
```

Event hashing and JSON serialization happen in **caller threads** (parallel). The batch loop collects all queued events via non-blocking `try_recv()` drain, then writes the entire batch + Merkle batch record in a single `write_all + fsync`.

```rust
struct WAL {
    tx: tokio::sync::mpsc::Sender<GroupCommitRequest>,
    _batch_task: tokio::task::JoinHandle<()>,
}

async fn append(&self, event: &GVMEvent) -> Result<()> {
    let hash = compute_event_hash(event);
    let mut stamped = event.clone();
    stamped.event_hash = Some(hash.clone());
    let data = serde_json::to_vec(&stamped)?;

    let (reply_tx, reply_rx) = oneshot::channel();
    self.tx.send(GroupCommitRequest { data, event_hash: hash, reply: reply_tx }).await?;
    reply_rx.await?
}
```

**Key properties**:
- **One fsync per batch** — amortized across all events in the batch (not per-event)
- **Batch window (2ms default)** — waits briefly for concurrent events to batch together, yielding 10-50x TPS under load vs per-event fsync. Configurable via `[wal] batch_window_ms` in `proxy.toml`.
- **Non-blocking drain** — `try_recv()` collects all queued events without timer overhead
- **Bounded backpressure** — channel capacity 4096, max batch size 128
- **Caller-parallel serialization** — event hash + JSON computed before channel send
- **Size-based rotation** — `max_wal_bytes` (100MB default) triggers rotation to `wal.log.<N>`, `max_wal_segments` (10 default) prunes oldest segments. Merkle chain links across segments via `prev_root`
- **Emergency WAL fallback** — if primary WAL fails, events go to `wal_emergency.log` (degraded mode, no Merkle)

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

**Why global doesn't bottleneck**: The serialization point is the batch, not the event. At 100 agents × 10 ops/sec = 1,000 events/sec, with batch drain collecting ~10 events per batch, that's ~100 fsyncs/sec — trivial for any modern disk. Sharding becomes relevant only at ~100K events/sec, at which point NATS JetStream provides cross-shard ordering.

**Scaling path**: v1.x global WAL → v2.x NATS JetStream handles ordering → v3.x proxy sharding by agent_id hash (if needed).

---

## 4.5 WAL Sequence Number (Ordering Guarantee)

```rust
pub struct Ledger {
    wal: WAL,
    emergency_wal: EmergencyWAL,
    primary_failures: AtomicU64,
    emergency_writes: AtomicU64,
    nats_url: String,
    stream_name: String,
    wal_sequence: AtomicU64,  // Monotonic counter
}
```

**Note**: NATS publishing is currently a **stub** — the `[nats]` config is accepted but events are only written to local WAL. The WAL sequence counter and NATS integration design are implemented in the code structure but actual NATS network I/O is not active. When NATS is connected in a future release, the monotonic `wal_sequence` ensures consumers can reconstruct WAL order from out-of-order NATS messages.

**WAL sequence properties** (active regardless of NATS):
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
    ("srr:srr_network.toml", &srr_path),
    ("registry:operation_registry.toml", &registry_path),
    ("policy:global.toml", &policy_path),
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
- **Ordering Guarantee**: AtomicU64 sequence allows NATS consumers to reconstruct exact WAL order.
- **Backpressure**: Bounded channel (4096) + max batch size (128) prevent unbounded resource consumption.
- **Config Integrity**: SHA-256 hashes of policy files are recorded in the Merkle chain at startup. Policy file tampering between restarts is detectable by comparing `gvm.system.config_load` events across restarts.

---

[← Part 3: Network SRR](srr.md) | [Part 5: Encrypted Vault →](architecture/vault.md)
