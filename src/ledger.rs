use crate::merkle::compute_event_hash;
use crate::types::{EventStatus, GVMEvent, MerkleBatchRecord};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

// ─── Emergency WAL (Fallback Storage) ───

/// Fallback local file for emergency audit logging when the primary WAL fails.
///
/// When the primary WAL (group commit + Merkle) encounters I/O errors,
/// the Ledger falls back to this simple append-only file to preserve
/// a minimal audit trail. This ensures IC-2 requests can still be
/// processed (with degraded integrity guarantees) rather than returning
/// 500 errors during transient disk issues.
///
/// Limitations vs primary WAL:
/// - No Merkle tree integrity (no batch records)
/// - No group commit batching (single event per write)
/// - No fsync guarantee (best-effort durability)
/// - Events written here must be reconciled with the primary WAL on recovery
///
/// Thread safety: Uses a persistent file handle behind tokio::sync::Mutex
/// to prevent concurrent file open/close races (critical on Windows where
/// append-mode concurrent opens can cause lost writes).
struct EmergencyWAL {
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl EmergencyWAL {
    async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;
        tracing::info!(path = %path.display(), "Emergency WAL initialized");
        Ok(Self {
            file: tokio::sync::Mutex::new(file),
        })
    }

    /// Best-effort append: serialize event as JSON line, write to persistent handle.
    /// Mutex ensures serialized writes — no interleaving under concurrent load.
    /// Returns Ok(()) on success, Err on I/O failure.
    async fn append(&self, event: &GVMEvent) -> Result<()> {
        let hash = compute_event_hash(event);
        let mut stamped = event.clone();
        stamped.event_hash = Some(hash);

        let mut data = serde_json::to_vec(&stamped)?;
        data.push(b'\n');

        let mut file = self.file.lock().await;
        file.write_all(&data).await?;
        // Best-effort fsync — don't fail if sync fails
        let _ = file.sync_data().await;
        Ok(())
    }
}

// ─── Group Commit Configuration ───

/// Tuning knobs for WAL group commit batching.
///
/// The `batch_window` is the key latency/throughput tradeoff:
/// - `Duration::ZERO`: minimum latency per single request (no batching wait)
/// - `2ms` (default): amortizes fsync across concurrent requests, 10-50x TPS gain
/// - Higher values: more batching, higher throughput, but added latency per request
pub struct GroupCommitConfig {
    /// Maximum time to wait for more events before flushing (default: 2ms).
    pub batch_window: Duration,
    /// Maximum batch size before forcing an immediate flush (default: 128).
    pub max_batch_size: usize,
    /// Bounded channel capacity for backpressure (default: 4096).
    pub channel_capacity: usize,
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self {
            batch_window: Duration::from_millis(2),
            max_batch_size: 128,
            channel_capacity: 4096,
        }
    }
}

/// Internal request sent from callers to the batch task.
struct GroupCommitRequest {
    /// Pre-serialized JSON line (serialization done by caller for CPU parallelism).
    data: Vec<u8>,
    /// SHA-256 event hash (Merkle leaf) computed by caller before serialization.
    event_hash: String,
    /// Oneshot sender to notify the caller of success/failure.
    reply: tokio::sync::oneshot::Sender<Result<()>>,
}

// ─── WAL with Group Commit + Merkle Tree (PART 5.3) ───

/// Write-Ahead Log with group commit and Merkle tree integrity.
///
/// Architecture:
/// ```text
/// Caller → compute event_hash → serialize JSON (with hash) → channel.send → await
///                                      ↓
///            Batch Task: recv → collect(batch_window) →
///              write_all(events) → compute_merkle_root → write(batch_record) →
///              fsync(1x) → notify all
/// ```
///
/// Merkle structure:
/// - Intra-batch: events form a binary Merkle tree, root stored in MerkleBatchRecord
/// - Inter-batch: each batch references the previous batch's root (chain)
#[allow(clippy::upper_case_acronyms)]
struct WAL {
    /// Sender for submitting write requests to the batch task.
    tx: tokio::sync::mpsc::Sender<GroupCommitRequest>,
    /// Handle to the background batch task (for graceful shutdown).
    _batch_task: tokio::task::JoinHandle<()>,
    /// Path retained for crash recovery (read path).
    path: PathBuf,
    /// Test-only: when set to true, the batch task will reject all writes.
    inject_error: Arc<AtomicBool>,
}

impl WAL {
    async fn open(path: &Path, config: GroupCommitConfig) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        let (tx, rx) = tokio::sync::mpsc::channel(config.channel_capacity);
        let inject_error = Arc::new(AtomicBool::new(false));

        let batch_task = tokio::spawn(batch_loop(rx, file, config, inject_error.clone()));

        tracing::info!(path = %path.display(), "WAL opened (group commit + merkle)");

        Ok(Self {
            tx,
            _batch_task: batch_task,
            path: path.to_path_buf(),
            inject_error,
        })
    }

    /// Append an event to the WAL via group commit.
    /// Computes event_hash, sets it on the event, serializes, and submits to batch task.
    async fn append(&self, event: &GVMEvent) -> Result<()> {
        // Compute event hash and embed it in the serialized output
        let hash = compute_event_hash(event);
        let mut stamped = event.clone();
        stamped.event_hash = Some(hash.clone());

        let mut data = serde_json::to_vec(&stamped)?;
        data.push(b'\n');

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

        self.tx
            .send(GroupCommitRequest {
                data,
                event_hash: hash,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("WAL batch task shut down"))?;

        reply_rx
            .await
            .map_err(|_| anyhow!("WAL batch task dropped reply"))?
    }
}

/// Background batch task: collects writes, flushes in batches, single fsync per batch.
/// After flushing events, computes the Merkle root and appends a batch record.
async fn batch_loop(
    mut rx: tokio::sync::mpsc::Receiver<GroupCommitRequest>,
    mut file: tokio::fs::File,
    config: GroupCommitConfig,
    inject_error: Arc<AtomicBool>,
) {
    let mut batch: Vec<GroupCommitRequest> = Vec::with_capacity(config.max_batch_size);
    let mut batch_id: u64 = 0;
    let mut prev_batch_root: Option<String> = None;

    loop {
        // Phase 1: Wait for at least one request (blocks until work arrives)
        match rx.recv().await {
            Some(req) => batch.push(req),
            None => {
                // Channel closed — all senders dropped, shutdown.
                // Flush any remaining events that arrived before channel close.
                if !batch.is_empty() {
                    let result =
                        flush_batch_with_merkle(&mut file, &batch, batch_id, &prev_batch_root)
                            .await;
                    for req in batch.drain(..) {
                        let notify = match &result {
                            Ok(_) => Ok(()),
                            Err(e) => Err(anyhow!("WAL shutdown flush failed: {}", e)),
                        };
                        let _ = req.reply.send(notify);
                    }
                }
                break;
            }
        }

        // Phase 2a: Non-blocking drain of all immediately available requests.
        // This avoids paying the OS timer resolution penalty (15.6ms on Windows)
        // when items are already queued.
        while batch.len() < config.max_batch_size {
            match rx.try_recv() {
                Ok(req) => batch.push(req),
                Err(_) => break, // Channel empty or closed
            }
        }

        // Phase 2b: If batch is small and window is configured, briefly wait for more.
        // Skip if we already have a decent batch from the non-blocking drain.
        if batch.len() < config.max_batch_size / 4 && !config.batch_window.is_zero() {
            match tokio::time::timeout(config.batch_window, rx.recv()).await {
                Ok(Some(req)) => {
                    batch.push(req);
                    // Drain any additional items that arrived during the wait
                    while batch.len() < config.max_batch_size {
                        match rx.try_recv() {
                            Ok(req) => batch.push(req),
                            Err(_) => break,
                        }
                    }
                }
                Ok(None) => {} // Channel closed — flush what we have
                Err(_) => {}   // Timeout — flush now
            }
        }

        // Phase 3: Flush entire batch with single write_all + single fsync
        let result = if inject_error.load(Ordering::Relaxed) {
            Err(anyhow!("WAL I/O error (injected for testing)"))
        } else {
            flush_batch_with_merkle(&mut file, &batch, batch_id, &prev_batch_root).await
        };

        // Update batch chain state on success
        if let Ok(ref root) = result {
            prev_batch_root = Some(root.clone());
            batch_id += 1;
        }

        // Phase 4: Notify all waiters
        for req in batch.drain(..) {
            let notify_result = match &result {
                Ok(_) => Ok(()),
                Err(e) => Err(anyhow!("WAL group commit fsync failed: {}", e)),
            };
            let _ = req.reply.send(notify_result);
        }
    }
}

/// Flush event data + Merkle batch record in a single fsync.
///
/// 1. Concatenate all pre-serialized event JSON lines
/// 2. Compute Merkle root from event hashes
/// 3. Serialize and append MerkleBatchRecord
/// 4. Single write_all + fsync for the entire buffer (events + batch record)
async fn flush_batch_with_merkle(
    file: &mut tokio::fs::File,
    batch: &[GroupCommitRequest],
    batch_id: u64,
    prev_batch_root: &Option<String>,
) -> Result<String> {
    // Collect event hashes for Merkle tree
    let leaf_hashes: Vec<String> = batch.iter().map(|r| r.event_hash.clone()).collect();

    // Compute Merkle root
    let merkle_root = crate::merkle::compute_merkle_root(&leaf_hashes)?;

    // Build batch record
    let batch_record = MerkleBatchRecord {
        batch_id,
        merkle_root: merkle_root.clone(),
        prev_batch_root: prev_batch_root.clone(),
        event_count: batch.len(),
        timestamp: chrono::Utc::now(),
    };

    let mut batch_record_data = serde_json::to_vec(&batch_record)?;
    batch_record_data.push(b'\n');

    // Single buffer: all events + batch record
    let event_len: usize = batch.iter().map(|r| r.data.len()).sum();
    let mut buf = Vec::with_capacity(event_len + batch_record_data.len());
    for req in batch {
        buf.extend_from_slice(&req.data);
    }
    buf.extend_from_slice(&batch_record_data);

    // Single write + single fsync for the entire batch (events + merkle record)
    file.write_all(&buf).await?;
    file.sync_data().await?;

    Ok(merkle_root)
}

// ─── Ledger: WAL-first local write + async NATS JetStream forwarding ───

/// Ledger: WAL-first local write + async NATS JetStream forwarding.
///
/// Design (PART 5.3, v8.2 errata):
/// - IC-2/3 (durable): WAL append (group commit fsync) → async NATS publish
/// - IC-1 (async): skip WAL, fire-and-forget NATS publish (loss tolerated)
/// - Crash recovery: replay WAL, re-publish events missing from NATS
pub struct Ledger {
    wal: WAL,
    /// Emergency fallback WAL for when the primary WAL fails.
    /// Provides degraded-but-auditable operation during disk issues.
    emergency_wal: EmergencyWAL,
    /// Tracks consecutive primary WAL failures for circuit breaker logic.
    /// When this exceeds the threshold, the proxy should signal degraded mode.
    primary_failures: AtomicU64,
    /// Total events written to the emergency WAL (observable metric).
    emergency_writes: AtomicU64,
    // NATS JetStream connection — stubbed for MVP, will be connected in production
    nats_url: String,
    stream_name: String,
    /// Monotonic WAL sequence number.
    /// Guarantees ordering: NATS consumers can reconstruct WAL order
    /// even if async-published messages arrive out of order.
    ///
    /// NOTE: Resets to 0 on restart. When NATS is connected (P2),
    /// this should be initialized from the WAL event count during recovery
    /// to avoid duplicate sequences across restarts.
    wal_sequence: AtomicU64,
}

impl Ledger {
    /// Initialize the ledger with WAL and NATS configuration.
    pub async fn new(wal_path: &Path, nats_url: &str, stream_name: &str) -> Result<Self> {
        Self::with_config(
            wal_path,
            nats_url,
            stream_name,
            GroupCommitConfig::default(),
        )
        .await
    }

    /// Initialize the ledger with explicit group commit configuration.
    pub async fn with_config(
        wal_path: &Path,
        nats_url: &str,
        stream_name: &str,
        config: GroupCommitConfig,
    ) -> Result<Self> {
        let wal = WAL::open(wal_path, config).await?;

        // Emergency WAL path: same directory, separate file
        let emergency_path = wal_path.with_file_name("wal_emergency.log");
        let emergency_wal = EmergencyWAL::open(&emergency_path).await?;

        // NATS connection will be established when available
        if !nats_url.is_empty() {
            tracing::info!(
                url = nats_url,
                stream = stream_name,
                "NATS configured (connection deferred)"
            );
        }

        Ok(Self {
            wal,
            emergency_wal,
            primary_failures: AtomicU64::new(0),
            emergency_writes: AtomicU64::new(0),
            nats_url: nats_url.to_string(),
            stream_name: stream_name.to_string(),
            wal_sequence: AtomicU64::new(0),
        })
    }

    /// IC-2/3 durable write: WAL append first, then async NATS publish.
    ///
    /// Fallback behavior:
    /// - Primary WAL succeeds → normal path, reset failure counter
    /// - Primary WAL fails → attempt emergency WAL → if emergency succeeds,
    ///   return Ok (degraded mode) and increment failure counter
    /// - Both fail → return Err (true Fail-Close, request must be rejected)
    pub async fn append_durable(&self, event: &GVMEvent) -> Result<()> {
        // 1. Assign monotonic WAL sequence (atomic, lock-free)
        let wal_seq = self.wal_sequence.fetch_add(1, Ordering::SeqCst);

        // 2. Local WAL append (group commit — batched fsync + Merkle)
        match self.wal.append(event).await {
            Ok(()) => {
                // Primary succeeded — reset failure counter
                self.primary_failures.store(0, Ordering::Relaxed);
            }
            Err(primary_err) => {
                // Primary WAL failed — attempt emergency fallback
                let failures = self.primary_failures.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::error!(
                    error = %primary_err,
                    consecutive_failures = failures,
                    "Primary WAL write failed — falling back to emergency WAL"
                );

                match self.emergency_wal.append(event).await {
                    Ok(()) => {
                        let total = self.emergency_writes.fetch_add(1, Ordering::Relaxed) + 1;
                        tracing::warn!(
                            event_id = %event.event_id,
                            emergency_total = total,
                            "Event written to emergency WAL (degraded mode — no Merkle integrity)"
                        );
                        // Return Ok — request can proceed with degraded audit
                    }
                    Err(emergency_err) => {
                        // Both WALs failed — true Fail-Close
                        tracing::error!(
                            primary_error = %primary_err,
                            emergency_error = %emergency_err,
                            "Both primary and emergency WAL failed — Fail-Close"
                        );
                        return Err(anyhow!(
                            "All audit storage failed: primary={}, emergency={}",
                            primary_err,
                            emergency_err
                        ));
                    }
                }
            }
        }

        // 3. Async NATS publish (background, non-blocking)
        // wal_seq is included so NATS consumers can reconstruct WAL order
        // even if tokio::spawn tasks execute out of order.
        let event_json = serde_json::to_vec(event)?;
        let nats_url = self.nats_url.clone();
        let subject = format!("{}.events", self.stream_name);

        tokio::spawn(async move {
            if nats_url.is_empty() {
                return;
            }
            // NATS publish — stubbed for MVP
            // In production: include wal_seq as NATS header for ordering
            tracing::debug!(
                subject = subject,
                event_bytes = event_json.len(),
                wal_sequence = wal_seq,
                "NATS publish (stub)"
            );
        });

        Ok(())
    }

    /// Record a config load event in the Merkle chain.
    ///
    /// Computes SHA-256 hashes of the given config file paths and writes
    /// a system event (`gvm.system.config_load`) to the WAL via durable append.
    /// This embeds config file integrity into the same Merkle chain as enforcement
    /// events, enabling tamper detection: if a policy file is modified between
    /// proxy restarts, the hash mismatch is visible in the audit trail.
    ///
    /// Called at proxy startup (after config load) and on policy hot-reload.
    pub async fn record_config_load(
        &self,
        config_files: &[(&str, &std::path::Path)],
    ) -> Result<()> {
        use sha2::{Digest, Sha256};

        let mut file_hashes: HashMap<String, serde_json::Value> = HashMap::new();
        for (label, path) in config_files {
            let hash = match std::fs::read(path) {
                Ok(bytes) => {
                    let digest = Sha256::digest(&bytes);
                    format!("{:x}", digest)
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "Config file not readable — recording hash as 'unavailable'"
                    );
                    "unavailable".to_string()
                }
            };
            file_hashes.insert(label.to_string(), serde_json::Value::String(hash));
        }

        let event = GVMEvent {
            event_id: format!("sys-config-{}", uuid::Uuid::new_v4()),
            trace_id: "system".to_string(),
            parent_event_id: None,
            agent_id: "gvm-proxy".to_string(),
            tenant_id: None,
            session_id: "startup".to_string(),
            timestamp: chrono::Utc::now(),
            operation: "gvm.system.config_load".to_string(),
            resource: crate::types::ResourceDescriptor::default(),
            context: file_hashes,
            transport: None,
            decision: "Allow".to_string(),
            decision_source: "system".to_string(),
            matched_rule_id: None,
            enforcement_point: "startup".to_string(),
            status: EventStatus::Confirmed,
            payload: crate::types::PayloadDescriptor::default(),
            nats_sequence: None,
            event_hash: None,
            llm_trace: None,
            default_caution: false,
        };

        self.append_durable(&event).await?;
        tracing::info!(
            files = config_files.len(),
            "Config file hashes recorded in Merkle chain"
        );
        Ok(())
    }

    /// Return the number of consecutive primary WAL failures.
    /// Used by the circuit breaker to determine degraded state.
    pub fn primary_failure_count(&self) -> u64 {
        self.primary_failures.load(Ordering::Relaxed)
    }

    /// Return the total number of events written to the emergency WAL.
    pub fn emergency_write_count(&self) -> u64 {
        self.emergency_writes.load(Ordering::Relaxed)
    }

    /// IC-1 / Allow: async append with no durability guarantee.
    /// WAL is skipped (IC-1 is reversible, loss tolerated at < 0.1%).
    pub async fn append_async(&self, event: GVMEvent) {
        let event_json = match serde_json::to_vec(&event) {
            Ok(j) => j,
            Err(_) => return,
        };

        let nats_url = self.nats_url.clone();
        let subject = format!("{}.events", self.stream_name);

        tokio::spawn(async move {
            if nats_url.is_empty() {
                return;
            }
            tracing::debug!(
                subject = subject,
                event_bytes = event_json.len(),
                "NATS async publish (stub)"
            );
        });
    }

    /// Crash recovery: scan WAL for Pending events and reconcile.
    /// - Events confirmed in NATS are skipped (deduplicated by event_id)
    /// - Events not in NATS are re-published
    /// - Events still in Pending after recovery window are marked Expired
    pub async fn recover_from_wal(&self) -> Result<RecoveryReport> {
        let content = tokio::fs::read_to_string(&self.wal.path).await?;
        let mut pending_count = 0u64;
        let mut expired_count = 0u64;

        // Track event_ids we've already seen to handle duplicates.
        // WAL may contain both the original Pending event and a later Expired
        // version (from a previous recovery). We process forward, and skip
        // event_ids we've already processed to avoid re-expiring them.
        let mut processed_ids = std::collections::HashSet::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            // Skip MerkleBatchRecord lines (they have merkle_root field)
            if line.contains("\"merkle_root\"") {
                continue;
            }

            let event: GVMEvent = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(e) => {
                    tracing::error!(error = %e, "Corrupt WAL entry, skipping");
                    continue;
                }
            };

            // Record all event_ids we encounter (including non-Pending).
            // If a later Pending entry has an event_id we already saw as
            // Expired/Confirmed, skip it (it was already resolved).
            if !processed_ids.insert(event.event_id.clone()) {
                // Already processed this event_id — skip duplicate
                continue;
            }

            if matches!(event.status, EventStatus::Pending) {
                pending_count += 1;

                // In production: check NATS/external API for execution status
                // For now, mark as Expired (execution status uncertain)
                let mut expired_event = event;
                expired_event.status = EventStatus::Expired;

                // Re-append the Expired status to WAL
                if let Err(e) = self.wal.append(&expired_event).await {
                    tracing::error!(error = %e, "Failed to write Expired status to WAL");
                }
                expired_count += 1;
            }
        }

        if expired_count > 0 {
            tracing::warn!(
                pending = pending_count,
                expired = expired_count,
                "WAL recovery complete — expired events require operator review"
            );
        }

        Ok(RecoveryReport {
            pending_found: pending_count,
            expired_marked: expired_count,
        })
    }

    /// Test-only: inject I/O errors into the WAL batch task.
    /// When enabled, all subsequent append_durable calls will receive Err.
    pub fn inject_write_error(&self, enable: bool) {
        self.wal.inject_error.store(enable, Ordering::Relaxed);
    }
}

/// Report from WAL crash recovery
pub struct RecoveryReport {
    pub pending_found: u64,
    pub expired_marked: u64,
}
