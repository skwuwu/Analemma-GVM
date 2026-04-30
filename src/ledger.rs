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
    /// Maximum WAL file size in bytes before rotation (default: 100MB).
    pub max_wal_bytes: u64,
    /// Maximum number of rotated segments to keep (default: 10).
    pub max_wal_segments: usize,
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        Self {
            batch_window: Duration::from_millis(2),
            max_batch_size: 128,
            channel_capacity: 4096,
            max_wal_bytes: 100 * 1024 * 1024, // 100MB
            max_wal_segments: 10,
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
    /// Wrapped in `Option` so `shutdown()` can `take()` it, dropping
    /// the only sender held by the Ledger and closing the channel.
    /// `batch_loop` exits when `rx.recv()` returns `None`, completing
    /// the JoinHandle the shutdown path awaits. Without the take,
    /// the channel stayed open indefinitely and shutdown always hit
    /// the documented 5s timeout — turning every rolling restart
    /// into a 5s-per-pod stall.
    tx: Option<tokio::sync::mpsc::Sender<GroupCommitRequest>>,
    /// Handle to the background batch task — awaited during graceful shutdown.
    batch_task: Option<tokio::task::JoinHandle<()>>,
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

        let batch_task = tokio::spawn(batch_loop(
            rx,
            file,
            config,
            inject_error.clone(),
            path.to_path_buf(),
        ));

        tracing::info!(path = %path.display(), "WAL opened (group commit + merkle)");

        Ok(Self {
            tx: Some(tx),
            batch_task: Some(batch_task),
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

        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| anyhow!("WAL batch task shut down"))?;
        tx.send(GroupCommitRequest {
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
/// Handles size-based rotation when the WAL file exceeds `max_wal_bytes`.
async fn batch_loop(
    mut rx: tokio::sync::mpsc::Receiver<GroupCommitRequest>,
    mut file: tokio::fs::File,
    config: GroupCommitConfig,
    inject_error: Arc<AtomicBool>,
    wal_path: PathBuf,
) {
    let mut batch: Vec<GroupCommitRequest> = Vec::with_capacity(config.max_batch_size);
    let mut batch_id: u64 = 0;
    let mut prev_batch_root: Option<String> = None;
    let mut bytes_written: u64 = file.metadata().await.map(|m| m.len()).unwrap_or(0);

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

            // Track bytes written for rotation check
            let batch_bytes: u64 = batch.iter().map(|r| r.data.len() as u64).sum();
            bytes_written += batch_bytes + 256; // approximate batch record overhead

            // Phase 3.5: Size-based rotation check
            if config.max_wal_bytes > 0 && bytes_written >= config.max_wal_bytes {
                if let Err(e) = rotate_wal(&wal_path, &mut file, &config, &mut bytes_written).await
                {
                    tracing::error!(error = %e, "WAL rotation failed — continuing with current file");
                } else {
                    tracing::info!(
                        batch_id,
                        prev_root = ?prev_batch_root,
                        "WAL rotated — new segment started, Merkle chain linked via prev_batch_root"
                    );
                    // prev_batch_root carries over — the first batch in the new
                    // segment references the last root of the old segment.
                }
            }
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

/// Rotate the WAL file: rename current to `wal.log.<N>`, open a fresh file,
/// and prune old segments beyond `max_wal_segments`.
///
/// The inter-batch `prev_batch_root` field carries over across rotation —
/// the first batch in the new segment references the last root of the old one,
/// maintaining the Merkle chain across files.
async fn rotate_wal(
    wal_path: &Path,
    file: &mut tokio::fs::File,
    config: &GroupCommitConfig,
    bytes_written: &mut u64,
) -> Result<()> {
    // Flush any buffered data before rotation
    file.sync_data().await?;

    // Find next segment number
    let parent = wal_path.parent().unwrap_or(Path::new("."));
    let stem = wal_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wal.log");

    // Use tokio::fs for all filesystem operations in this async function.
    // Blocking std::fs calls starve the tokio executor during WAL rotation.
    let mut max_segment: u64 = 0;
    if let Ok(mut entries) = tokio::fs::read_dir(parent).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(suffix) = name_str.strip_prefix(&format!("{}.", stem)) {
                if let Ok(n) = suffix.parse::<u64>() {
                    max_segment = max_segment.max(n);
                }
            }
        }
    }

    let new_segment = max_segment + 1;
    let rotated_path = parent.join(format!("{}.{}", stem, new_segment));

    // Rename current WAL → rotated segment
    tokio::fs::rename(wal_path, &rotated_path)
        .await
        .map_err(|e| anyhow!("WAL rotation rename failed: {}", e))?;

    // Open fresh WAL file
    let new_file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(wal_path)
        .await
        .map_err(|e| anyhow!("WAL rotation: failed to create new file: {}", e))?;

    *file = new_file;
    *bytes_written = 0;

    tracing::info!(
        rotated_to = %rotated_path.display(),
        segment = new_segment,
        "WAL rotated"
    );

    // Prune old segments beyond max_wal_segments (async I/O)
    if config.max_wal_segments > 0 && new_segment as usize > config.max_wal_segments {
        let prune_up_to = new_segment - config.max_wal_segments as u64;
        for i in 1..=prune_up_to {
            let old_path = parent.join(format!("{}.{}", stem, i));
            if tokio::fs::try_exists(&old_path).await.unwrap_or(false) {
                if let Err(e) = tokio::fs::remove_file(&old_path).await {
                    tracing::warn!(path = %old_path.display(), error = %e, "Failed to prune old WAL segment");
                } else {
                    tracing::info!(path = %old_path.display(), "Pruned old WAL segment");
                }
                // Also remove the watermark for the pruned segment
                let old_watermark = PathBuf::from(format!("{}.watermark", old_path.display()));
                let _ = tokio::fs::remove_file(&old_watermark).await;
            }
        }
    }

    Ok(())
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
    /// Initialized from WAL event count during recovery to avoid
    /// duplicate sequences across restarts.
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
    // COLD PATH: blocking std::fs::read() acceptable — called at startup/reload, not per-request.
    /// Record config file hashes + GvmIntegrityContext in the Merkle chain.
    ///
    /// Creates an integrity context that records the config state for
    /// reproducibility and tamper detection.
    /// Behavioral events reference this context via `config_integrity_ref`.
    ///
    /// Returns the context hash (for attaching to subsequent behavioral events).
    pub async fn record_config_load(
        &self,
        config_files: &[(&str, &std::path::Path)],
        prev_config_hash: Option<String>,
    ) -> Result<String> {
        use sha2::{Digest, Sha256};

        let mut file_hashes: HashMap<String, serde_json::Value> = HashMap::new();
        let mut combined_hash_input = String::new();

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
            combined_hash_input.push_str(&hash);
            file_hashes.insert(label.to_string(), serde_json::Value::String(hash));
        }

        // Combined config hash (all files concatenated then hashed)
        let config_hash = format!("{:x}", Sha256::digest(combined_hash_input.as_bytes()));

        // Create integrity context (Local hash-only for standalone users)
        let integrity = gvm_types::GvmIntegrityContext::local(config_hash, prev_config_hash);
        let context_hash = integrity.context_hash();

        // Embed full context in config_load event (behavioral events only carry the hash)
        file_hashes.insert(
            "_integrity_context".to_string(),
            serde_json::to_value(&integrity).unwrap_or(serde_json::Value::Null),
        );

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
            config_integrity_ref: Some(context_hash.clone()),
        };

        self.append_durable(&event).await?;
        tracing::info!(
            files = config_files.len(),
            context_hash = %context_hash,
            auth_type = "local",
            "Integrity context recorded in Merkle chain"
        );
        Ok(context_hash)
    }

    /// Verify the integrity context chain in the WAL.
    ///
    /// Thin wrapper over `gvm_types::verify_integrity_chain` — kept as a
    /// `Ledger` associated function for backwards-compatible call sites.
    ///
    /// Returns (valid_count, first_break).
    pub fn check_chain_integrity(wal_path: &std::path::Path) -> (usize, Option<String>) {
        let report = gvm_types::verify_integrity_chain(wal_path);
        if let Some(ref event_id) = report.first_break {
            tracing::warn!(event_id = %event_id, "Integrity chain break detected");
        }
        (report.valid_links, report.first_break)
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
}

/// Build a WAL event for a DNS governance decision.
///
/// Includes the full sliding-window state snapshot so an auditor can
/// reproduce *why* this tier was assigned (Code Standard 4.5 — No Hidden
/// State). The context map records: tier, delay, unique subdomain count,
/// global unique count, window age, and base domain.
pub fn build_dns_event(
    domain: &str,
    tier_label: &str,
    delay: std::time::Duration,
    unique_subdomain_count: usize,
    global_unique_count: usize,
    window_age_secs: u64,
    base_domain: &str,
) -> GVMEvent {
    GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        parent_event_id: None,
        agent_id: "unknown".to_string(),
        tenant_id: None,
        session_id: "dns".to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.dns.query".to_string(),
        resource: crate::types::ResourceDescriptor::default(),
        context: {
            let mut ctx = std::collections::HashMap::new();
            ctx.insert(
                "dns_tier".to_string(),
                serde_json::Value::String(tier_label.to_string()),
            );
            ctx.insert(
                "delay_ms".to_string(),
                serde_json::Value::Number(serde_json::Number::from(delay.as_millis() as u64)),
            );
            ctx.insert(
                "dns_base_domain".to_string(),
                serde_json::Value::String(base_domain.to_string()),
            );
            ctx.insert(
                "dns_unique_subdomain_count".to_string(),
                serde_json::Value::Number(serde_json::Number::from(unique_subdomain_count as u64)),
            );
            ctx.insert(
                "dns_global_unique_count".to_string(),
                serde_json::Value::Number(serde_json::Number::from(global_unique_count as u64)),
            );
            ctx.insert(
                "dns_window_age_secs".to_string(),
                serde_json::Value::Number(serde_json::Number::from(window_age_secs)),
            );
            ctx
        },
        transport: Some(crate::types::TransportInfo {
            method: "DNS".to_string(),
            host: domain.to_string(),
            path: "".to_string(),
            status_code: None,
        }),
        decision: format!("Delay {{ milliseconds: {} }}", delay.as_millis()),
        decision_source: "dns-governance".to_string(),
        matched_rule_id: None,
        enforcement_point: "dns-proxy".to_string(),
        status: crate::types::EventStatus::Confirmed,
        payload: crate::types::PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None,
        llm_trace: None,
        default_caution: true,
        config_integrity_ref: None,
    }
}

impl Ledger {
    /// Low-audit-value, high-frequency events (DNS Tier 1 `Known`,
    /// Vault read / list_keys). Publishes to NATS only; WAL is
    /// **deliberately excluded from the audit chain** to bound log growth.
    ///
    /// **Do not use for governance decisions** (Allow / AuditOnly / Delay /
    /// RequireApproval / Deny). Those must go through [`append_durable`] so
    /// they reach the Merkle chain and are available for compliance
    /// verification, notarization, and `gvm suggest` rule generation.
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
    ///
    /// Uses a **high watermark** strategy (O(1) memory) instead of tracking
    /// all event_ids in a HashSet (O(N) memory — OOM risk on large WALs).
    ///
    /// The watermark is stored in a sidecar file (`<wal_path>.watermark`)
    /// containing the byte offset at which the last successful recovery ended.
    /// On subsequent recoveries, only events after the watermark are scanned.
    /// This works because recovery appends Expired entries for all unresolved
    /// Pendings — so everything before the watermark is fully resolved.
    // COLD PATH: blocking std::fs I/O acceptable — called at startup before accepting connections.
    pub async fn recover_from_wal(&self) -> Result<RecoveryReport> {
        use std::io::{BufRead, Seek, SeekFrom};

        // ── Phase 0: Initialize wal_sequence from existing WAL event count ──
        // Scan the entire file to count event lines (not batch records).
        // This ensures wal_sequence is monotonic across restarts.
        if let Ok(count_file) = std::fs::File::open(&self.wal.path) {
            let count_reader = std::io::BufReader::new(count_file);
            let mut event_count: u64 = 0;
            let mut batch_count: u64 = 0;
            for line in count_reader.lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                if line.contains("\"merkle_root\"") {
                    batch_count += 1;
                } else {
                    event_count += 1;
                }
            }
            self.wal_sequence.store(event_count, Ordering::SeqCst);
            tracing::info!(
                event_count,
                batch_count,
                "WAL sequence initialized from existing events (monotonic across restarts)"
            );
        }

        let watermark_path = PathBuf::from(format!("{}.watermark", self.wal.path.display()));

        // Read the high watermark: byte offset of last completed recovery.
        // If absent (first recovery), start from 0.
        let watermark_offset: u64 = match std::fs::read_to_string(&watermark_path) {
            Ok(s) => s.trim().parse().unwrap_or(0),
            Err(_) => 0,
        };

        let file = std::fs::File::open(&self.wal.path)
            .map_err(|e| anyhow!("Failed to open WAL for recovery: {}", e))?;

        // Record the file size BEFORE we start — new Expired entries we append
        // during this recovery will be beyond this point.
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);

        // Clamp watermark: if file was truncated (manual cleanup), reset to 0.
        let start_offset = if watermark_offset > file_len {
            tracing::warn!(
                watermark = watermark_offset,
                file_len,
                "WAL watermark beyond EOF — file was truncated? Scanning from beginning"
            );
            0
        } else {
            watermark_offset
        };

        let mut reader = std::io::BufReader::new(file);
        if start_offset > 0 {
            reader.seek(SeekFrom::Start(start_offset))?;
            tracing::info!(
                watermark = start_offset,
                file_len,
                scan_bytes = file_len - start_offset,
                "WAL recovery: resuming from high watermark"
            );
        }

        let mut pending_count = 0u64;
        let mut expired_count = 0u64;
        let mut corrupt_count = 0u64;
        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    // I/O error mid-read (e.g. truncated file from crash).
                    // Log and stop — remaining data is unreliable.
                    tracing::error!(error = %e, "WAL I/O error during recovery — stopping at this point");
                    corrupt_count += 1;
                    break;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            // Skip MerkleBatchRecord lines (they have merkle_root field)
            if line.contains("\"merkle_root\"") {
                continue;
            }

            let event: GVMEvent = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(e) => {
                    // Corrupt line — likely from crash mid-write (truncated JSON).
                    // Skip and continue: earlier complete lines are still valid.
                    tracing::warn!(error = %e, "Corrupt WAL entry, skipping");
                    corrupt_count += 1;
                    continue;
                }
            };

            // Only process Pending events — non-Pending (Expired/Confirmed) are
            // already resolved. Since we scan only events after the watermark,
            // there are no duplicates from previous recoveries to worry about.
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

        // Persist watermark: point to the pre-recovery file end.
        // Everything before this offset is now fully resolved.
        // Atomic write: write to temp, then rename (prevents partial watermark).
        let watermark_tmp = PathBuf::from(format!("{}.watermark.tmp", self.wal.path.display()));
        if let Err(e) = std::fs::write(&watermark_tmp, file_len.to_string())
            .and_then(|_| std::fs::rename(&watermark_tmp, &watermark_path))
        {
            // Non-fatal: next recovery will re-scan from old watermark.
            // Idempotent re-expiry is harmless (Expired → Expired again).
            tracing::warn!(error = %e, "Failed to persist recovery watermark — next recovery will re-scan");
        } else {
            tracing::info!(watermark = file_len, "Recovery watermark persisted");
        }

        if corrupt_count > 0 {
            tracing::warn!(
                corrupt_lines = corrupt_count,
                "WAL recovery encountered corrupt entries (likely from crash mid-write)"
            );
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

    /// Graceful shutdown: close the WAL channel and wait for the batch task
    /// to flush all remaining events. Called during two-phase proxy shutdown.
    ///
    /// After this returns:
    /// - All queued events have been fsynced to disk
    /// - The Merkle batch record for the final batch has been written
    /// - No more writes are possible (append_durable will return Err)
    pub async fn shutdown(&mut self) {
        // Two-step shutdown:
        //  1. Drop our sender by taking it out of the Option. This closes
        //     the mpsc channel because we hold the only sender (the
        //     batch task itself does NOT clone the sender — it just
        //     receives). Without this, the channel stays open forever
        //     and the batch task waits indefinitely on rx.recv(),
        //     making the timeout below fire on every shutdown.
        //  2. Await the batch task handle. batch_loop sees rx.recv()
        //     return None, flushes any remaining batch with Merkle
        //     record, and exits.
        let _ = self.wal.tx.take();

        if let Some(handle) = self.wal.batch_task.take() {
            tracing::info!("WAL shutdown: waiting for batch task to flush remaining events...");
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(())) => {
                    tracing::info!("WAL shutdown: batch task completed cleanly");
                }
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "WAL shutdown: batch task panicked");
                }
                Err(_) => {
                    tracing::warn!("WAL shutdown: batch task did not complete within 5s timeout");
                }
            }
        }
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
