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

## 4.4 WAL (Write-Ahead Log)

### Structure

The WAL is a newline-delimited JSON file (`data/wal.log`):

```json
{"event_id":"evt-001","trace_id":"tr-abc","operation":"gvm.payment.refund","status":"Pending",...}
{"event_id":"evt-001","trace_id":"tr-abc","operation":"gvm.payment.refund","status":"Confirmed",...}
```

Each event may appear multiple times as its status transitions (Pending → Confirmed/Failed/Expired).

### Implementation

```rust
struct WAL {
    file: tokio::sync::Mutex<tokio::fs::File>,
    path: PathBuf,
}

async fn append(&self, event: &GVMEvent) -> Result<()> {
    let mut json = serde_json::to_vec(event)?;
    json.push(b'\n');

    let mut file = self.file.lock().await;
    file.write_all(&json).await?;
    file.sync_data().await?; // fsync — crash safe
    Ok(())
}
```

**Key properties**:
- `tokio::sync::Mutex` ensures serial WAL writes (no interleaving)
- `sync_data()` calls fsync — data survives process/OS crash
- Append-only — no in-place mutations, no corruption risk from partial writes

---

## 4.5 WAL Sequence Number (Ordering Guarantee)

```rust
pub struct Ledger {
    wal: WAL,
    nats_url: String,
    stream_name: String,
    wal_sequence: AtomicU64,  // Monotonic counter
}
```

**Problem**: NATS messages published via `tokio::spawn` may arrive out of order.

**Solution**: Each durable write assigns a monotonic `wal_sequence` (via `AtomicU64::fetch_add`) before the WAL write. This sequence is included as a NATS header, allowing consumers to reconstruct WAL order:

```rust
let wal_seq = self.wal_sequence.fetch_add(1, Ordering::SeqCst);
self.wal.append(event).await?;
// NATS publish includes wal_seq as header
```

**Properties**:
- Lock-free (`AtomicU64`) — zero performance impact
- Monotonic — strictly increasing, no gaps within a process lifetime
- SeqCst ordering — visible to all threads immediately

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
    let content = tokio::fs::read_to_string(&self.wal.path).await?;

    for line in content.lines() {
        match serde_json::from_str::<GVMEvent>(line) {
            Ok(event) if event.status == Pending => {
                // Mark as Expired — execution uncertain
                let mut expired = event;
                expired.status = EventStatus::Expired;
                self.wal.append(&expired).await?;
            }
            Err(e) => {
                // Corrupted entry — skip, log error, continue
                tracing::error!("Corrupt WAL entry, skipping");
                continue;
            }
            _ => {} // Non-Pending entries are fine
        }
    }
}
```

**Corruption resilience**: Corrupted WAL entries (from disk failure, truncation, or tampering) are **skipped**, not fatal. Recovery continues processing valid entries after the corruption.

---

## 4.8 Test Coverage

| Test | Source | Assertion |
|------|--------|-----------|
| `wal_tampered_entry_does_not_crash_recovery` | `tests/hostile.rs` | Corrupted JSON between valid entries → recovery succeeds, finds 2 Pending events |
| `ledger_concurrent_spawns_stay_bounded` | `tests/hostile.rs` | 500 concurrent durable appends complete < 10s, WAL has exactly 500 entries |

---

## 4.9 Security Implications

- **Fail-Close**: WAL write failure → request rejected. No action without audit record.
- **Tamper Resilience**: Corrupted entries are skipped; recovery continues with valid data.
- **No Phantom Records**: Expired status explicitly marks uncertain execution state.
- **Ordering Guarantee**: AtomicU64 sequence allows NATS consumers to reconstruct exact WAL order.
- **Backpressure**: WAL mutex serializes writes, preventing unbounded concurrent disk I/O.

---

[← Part 3: Network SRR](03-srr.md) | [Part 5: Encrypted Vault →](05-vault.md)
