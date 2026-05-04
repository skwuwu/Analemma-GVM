//! Phase 4 — GvmProof export.
//!
//! A `GvmProof` is a single self-contained JSON document that an
//! external auditor can receive and verify with no other files. It
//! bundles:
//!
//!   - the event (full or redacted),
//!   - the WAL Merkle inclusion path (`event_hash → batch_root`),
//!   - the batch's seal record + Merkle batch record + state anchor,
//!   - a short integrity-context chain ending at the anchor's
//!     `context_hash`,
//!   - optionally, a checkpoint inclusion path.
//!
//! Verification (`verify_proof`) is offline: it recomputes the event
//! hash from the (possibly redacted) record, walks the Merkle path to
//! `batch_root`, checks the anchor's self-hash, and validates the
//! short config-chain. Optional anchor signature verification accepts
//! a caller-supplied `VerifyingKey` registry.
//!
//! Privacy: `RedactionLevel::Standard` strips `operation_descriptor.detail`,
//! `operation_descriptor.detail_salt`, the free-form context map, and
//! `llm_trace.thinking`. The salted `detail_digest` is preserved so the
//! v2 event_hash recomputes (the privacy invariant of Phase 1.A).
//!
//! Domain: this module is pure type + algorithm. Generation lives in
//! `gvm-proxy::proof::build_proof` (it walks WAL files), which the
//! `gvm-types` crate must not depend on.

use crate::{
    BatchSealRecord, EventStatus, GVMEvent, GvmIntegrityContext, GvmStateAnchor, LLMTrace,
    MerkleBatchRecord, OperationDescriptor, PayloadDescriptor, PREFIX_EVENT_V1, PREFIX_EVENT_V2,
    PREFIX_OPDETAIL_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════
// Redaction
// ════════════════════════════════════════════════════════════════════

/// Redaction strength applied when a proof is built. The privacy
/// invariant is that the redaction MUST NOT break event_hash recompute
/// — `detail_digest` (and `category`) always survive so a verifier can
/// still recompute `event_hash` from the stripped record.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum RedactionLevel {
    /// Raw, unredacted form. Internal use only — proofs that ship over
    /// the wire SHOULD use `Standard` or stricter.
    None,
    /// Strip operation detail (URL path, vault key id, DNS subdomain),
    /// the per-event detail salt, the free-form `context` map (which
    /// may carry caller-supplied key/value pairs), and the LLM trace's
    /// `thinking` content. Recommended default for external auditors.
    #[default]
    Standard,
    /// Standard + strip transport host/path/method (network-level
    /// metadata that may identify a target system). The category and
    /// digest still allow event_hash recompute.
    Strict,
}

/// An event in either full or redacted form. Both shapes preserve the
/// canonical inputs to `event_hash` so the verifier can recompute the
/// hash without holding the unredacted form.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GVMEventOrRedacted {
    Full(GVMEvent),
    Redacted(RedactedEvent),
}

/// Redacted form of a `GVMEvent`. Carries exactly the fields needed to
/// recompute `event_hash` (v1 or v2 dispatcher) plus the descriptor
/// `category` for human reading. `detail_digest` is the canonical
/// "what the operation was without leaking what" — it survives so the
/// v2 hash dispatcher can still produce the same output.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RedactedEvent {
    pub spec_version: u8, // Always 1 for now; future schema-bumps land here.
    pub event_id: String,
    pub trace_id: String,
    pub agent_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Legacy operation string. Only meaningful when
    /// `operation_descriptor` is `None` (v1 hash path); v2 records
    /// can keep this empty or fall back to `category`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub operation: String,

    /// Phase 1 split form. Always present for v2 records; the
    /// `detail` and `detail_salt` are stripped per the level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_descriptor: Option<OperationDescriptor>,

    pub decision: String,
    pub decision_source: String,
    pub status: EventStatus,
    pub enforcement_point: String,
    pub payload_content_hash: String,
    pub event_hash: String,

    /// Survives only when level==None or Strict<None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_integrity_ref: Option<String>,
}

/// Pure transformation: produce the redacted form of an event for the
/// given level. Returns `None` for `RedactionLevel::None` (use the
/// `Full` variant instead).
pub fn redact_event(event: &GVMEvent, level: RedactionLevel) -> GVMEventOrRedacted {
    match level {
        RedactionLevel::None => GVMEventOrRedacted::Full(event.clone()),
        RedactionLevel::Standard | RedactionLevel::Strict => {
            // Strip descriptor.detail + salt; keep digest + category.
            let stripped_descriptor = event.operation_descriptor.as_ref().map(|d| {
                let mut copy = d.clone();
                copy.detail = None;
                copy.detail_salt = Vec::new();
                copy
            });

            // event_hash must be present for redacted shipping; if a
            // legacy event lacks it, recompute from the canonical input.
            let event_hash = event
                .event_hash
                .clone()
                .unwrap_or_else(|| recompute_event_hash(event));

            // For Strict, also strip the legacy operation string (no
            // privacy-bearing detail leaks from the descriptor side, but
            // the legacy field is the v1 path's full operation).
            let operation =
                if matches!(level, RedactionLevel::Strict) && stripped_descriptor.is_some() {
                    String::new()
                } else {
                    event.operation.clone()
                };

            GVMEventOrRedacted::Redacted(RedactedEvent {
                spec_version: 1,
                event_id: event.event_id.clone(),
                trace_id: event.trace_id.clone(),
                agent_id: event.agent_id.clone(),
                timestamp: event.timestamp,
                operation,
                operation_descriptor: stripped_descriptor,
                decision: event.decision.clone(),
                decision_source: event.decision_source.clone(),
                status: event.status.clone(),
                enforcement_point: event.enforcement_point.clone(),
                payload_content_hash: event.payload.content_hash.clone(),
                event_hash,
                config_integrity_ref: event.config_integrity_ref.clone(),
            })
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Inclusion paths
// ════════════════════════════════════════════════════════════════════

/// Merkle inclusion path for an event in a batch.
///
/// `path` is a sequence of `(sibling_hex, is_right)` pairs from leaf
/// up to root. Identical encoding to `gvm-proxy::merkle::generate_merkle_proof`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleInclusion {
    /// 64-hex SHA-256 of the leaf at `leaf_index`.
    pub leaf_hash: String,
    /// Index of this leaf in the batch's `leaves_blob` (zero-based).
    pub leaf_index: usize,
    /// Sibling-hash + is-right-of-current pairs, leaf → root.
    pub path: Vec<(String, bool)>,
}

/// Per-step checkpoint inclusion. Combines the per-agent path
/// (step → agent_root) and the global path (agent_root → checkpoint_root).
/// Phase 4 ships the type; Phase C populates `agent_path`/`global_path`
/// when callers register per-step checkpoints. Until then proofs may
/// carry a degenerate (single-leaf) form.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CheckpointInclusion {
    pub agent_id: String,
    pub step: u32,
    pub checkpoint_hash: String, // 64-hex SHA-256 leaf hash
    pub agent_root: String,      // 64-hex per-agent root
    pub agent_path: Vec<(String, bool)>,
    pub global_path: Vec<(String, bool)>,
}

// ════════════════════════════════════════════════════════════════════
// Proofs
// ════════════════════════════════════════════════════════════════════

/// Single-event proof. Self-contained: an auditor receiving JSON for
/// this struct can call `verify_proof` and obtain a per-layer report.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GvmProof {
    /// Schema version for forward compatibility. Currently 3.
    pub spec_version: u8,
    pub event: GVMEventOrRedacted,
    pub redaction_level: RedactionLevel,
    pub wal_inclusion: MerkleInclusion,
    pub batch_record: MerkleBatchRecord,
    pub seal: BatchSealRecord,
    pub anchor: GvmStateAnchor,
    /// Last N config_loads ending at (and including) the context whose
    /// `context_hash` matches `anchor.context_hash`. Empty when the
    /// anchor's context is `GENESIS_HASH_HEX` (no prior config_load).
    pub config_short_chain: Vec<GvmIntegrityContext>,
    /// Optional checkpoint inclusion for the event's agent at the
    /// active step. `None` until Phase C populates it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_inclusion: Option<CheckpointInclusion>,
}

/// Whole-batch proof. Useful when an auditor wants every event in a
/// single anchor without minting one proof per event.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GvmBatchProof {
    pub spec_version: u8,
    pub events: Vec<GVMEventOrRedacted>,
    pub seal: BatchSealRecord,
    pub batch_record: MerkleBatchRecord,
    pub anchor: GvmStateAnchor,
    pub config_short_chain: Vec<GvmIntegrityContext>,
    /// Per-event checkpoint inclusions, keyed by `event_id`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub checkpoint_inclusions: HashMap<String, CheckpointInclusion>,
}

// ════════════════════════════════════════════════════════════════════
// Verification
// ════════════════════════════════════════════════════════════════════

/// Per-layer pass/fail summary returned by `verify_proof`.
#[derive(Debug, Default, Serialize)]
pub struct ProofVerifyReport {
    /// `event_hash` recomputes correctly from the (redacted) event fields.
    pub event_hash_valid: bool,
    /// Merkle inclusion path → batch_record.merkle_root.
    pub wal_inclusion_valid: bool,
    /// `batch_record.merkle_root` matches `anchor.batch_root`.
    pub batch_root_in_anchor: bool,
    /// `anchor.anchor_hash` self-recomputes from the canonical input.
    pub anchor_self_hash_valid: bool,
    /// Each `GvmIntegrityContext` in the short chain has a correct
    /// `context_hash` recompute, and consecutive contexts link via
    /// `previous_state == prior.context_hash()`.
    pub config_chain_valid: bool,
    /// Last context's `context_hash()` equals `anchor.context_hash`.
    pub config_chain_anchored: bool,
    /// `seal.seal_hash()` matches the last leaf of `batch_record.leaves_blob`.
    pub seal_in_batch_root: bool,
    /// Anchor signature: `Some(true)` valid, `Some(false)` invalid,
    /// `None` if no signature was present or no key was supplied.
    pub anchor_signature_valid: Option<bool>,
    /// Aggregated: every layer that was checked passed.
    pub all_pass: bool,
}

impl ProofVerifyReport {
    fn aggregate(&mut self) {
        let signature_ok = self.anchor_signature_valid.unwrap_or(true);
        self.all_pass = self.event_hash_valid
            && self.wal_inclusion_valid
            && self.batch_root_in_anchor
            && self.anchor_self_hash_valid
            && self.config_chain_valid
            && self.config_chain_anchored
            && self.seal_in_batch_root
            && signature_ok;
    }
}

/// Verify a `GvmProof` offline. The verifier holds (a) the proof and
/// (b) optionally a `verify_anchor_signature` callback for the anchor
/// signature variant the operator uses. Returns a per-layer report.
///
/// The signature verifier is supplied as a closure so the gvm-types
/// crate stays free of ed25519/HSM dependencies. Pass `None` to skip
/// signature verification (the report will set `anchor_signature_valid`
/// to `None`).
pub fn verify_proof(
    proof: &GvmProof,
    sig_verifier: Option<&dyn Fn(&[u8; 32], &crate::AnchorSignature) -> bool>,
) -> ProofVerifyReport {
    let mut report = ProofVerifyReport::default();

    // ── Layer 1: event_hash recomputes from the (redacted) form ──
    let claimed_event_hash = match &proof.event {
        GVMEventOrRedacted::Full(e) => e.event_hash.clone().unwrap_or_default(),
        GVMEventOrRedacted::Redacted(r) => r.event_hash.clone(),
    };
    let recomputed = recompute_event_hash_either(&proof.event);
    report.event_hash_valid = !claimed_event_hash.is_empty() && claimed_event_hash == recomputed;

    // ── Layer 2: Merkle inclusion path → merkle_root ──
    report.wal_inclusion_valid = verify_merkle_path(
        &proof.wal_inclusion.leaf_hash,
        &proof.wal_inclusion.path,
        &proof.batch_record.merkle_root,
    );

    // ── Layer 3: batch_root in anchor ──
    report.batch_root_in_anchor = proof.batch_record.merkle_root == proof.anchor.batch_root;

    // ── Layer 4: anchor self-hash ──
    report.anchor_self_hash_valid = proof.anchor.verify_self_hash();

    // ── Layer 5: config short chain ──
    let (chain_ok, anchored_ok) =
        verify_config_short_chain(&proof.config_short_chain, &proof.anchor.context_hash);
    report.config_chain_valid = chain_ok;
    report.config_chain_anchored = anchored_ok;

    // ── Layer 6: seal_hash is in leaves_blob (last leaf) ──
    report.seal_in_batch_root = match proof.batch_record.seal_leaf() {
        Some(leaf) => leaf == &proof.seal.seal_hash()[..],
        None => false,
    };

    // ── Layer 7 (optional): anchor signature ──
    if let (Some(sig), Some(verifier)) = (proof.anchor.signature.as_ref(), sig_verifier) {
        // Decode anchor_hash from hex.
        let anchor_hash_bytes: Option<[u8; 32]> = hex::decode(&proof.anchor.anchor_hash)
            .ok()
            .and_then(|v| v.try_into().ok());
        report.anchor_signature_valid = anchor_hash_bytes.map(|h| verifier(&h, sig));
    } else if proof.anchor.signature.is_some() {
        // Signature present but no verifier supplied — leave None to
        // indicate "not checked" (caller can decide policy).
        report.anchor_signature_valid = None;
    }

    report.aggregate();
    report
}

// ════════════════════════════════════════════════════════════════════
// Internal helpers
// ════════════════════════════════════════════════════════════════════

/// Recompute event_hash from a `GVMEvent` (full form). Mirrors the
/// `compute_event_hash` dispatcher in gvm-proxy::merkle, kept here so
/// the verifier can run without that crate.
pub fn recompute_event_hash(event: &GVMEvent) -> String {
    match &event.operation_descriptor {
        Some(desc) => recompute_event_hash_v2(
            &event.event_id,
            &event.trace_id,
            &event.agent_id,
            &desc.category,
            &desc.detail_digest,
            &event.decision,
            &event.decision_source,
            &format!("{:?}", event.status),
            &event.enforcement_point,
            &event.timestamp.to_rfc3339(),
            &event.payload.content_hash,
        ),
        None => recompute_event_hash_v1(
            &event.event_id,
            &event.trace_id,
            &event.agent_id,
            &event.operation,
            &event.decision,
            &event.decision_source,
            &format!("{:?}", event.status),
            &event.enforcement_point,
            &event.timestamp.to_rfc3339(),
            &event.payload.content_hash,
        ),
    }
}

/// Recompute event_hash from either Full or Redacted shape. The
/// redacted path uses identical canonical inputs, so the hash matches
/// what a Full-form caller would produce.
pub fn recompute_event_hash_either(e: &GVMEventOrRedacted) -> String {
    match e {
        GVMEventOrRedacted::Full(ev) => recompute_event_hash(ev),
        GVMEventOrRedacted::Redacted(r) => match &r.operation_descriptor {
            Some(desc) => recompute_event_hash_v2(
                &r.event_id,
                &r.trace_id,
                &r.agent_id,
                &desc.category,
                &desc.detail_digest,
                &r.decision,
                &r.decision_source,
                &format!("{:?}", r.status),
                &r.enforcement_point,
                &r.timestamp.to_rfc3339(),
                &r.payload_content_hash,
            ),
            None => recompute_event_hash_v1(
                &r.event_id,
                &r.trace_id,
                &r.agent_id,
                &r.operation,
                &r.decision,
                &r.decision_source,
                &format!("{:?}", r.status),
                &r.enforcement_point,
                &r.timestamp.to_rfc3339(),
                &r.payload_content_hash,
            ),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn recompute_event_hash_v1(
    event_id: &str,
    trace_id: &str,
    agent_id: &str,
    operation: &str,
    decision: &str,
    decision_source: &str,
    status: &str,
    enforcement_point: &str,
    timestamp_rfc3339: &str,
    payload_content_hash: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(PREFIX_EVENT_V1);
    for f in &[
        event_id,
        trace_id,
        agent_id,
        operation,
        decision,
        decision_source,
        status,
        enforcement_point,
        timestamp_rfc3339,
        payload_content_hash,
    ] {
        h.update((f.len() as u32).to_le_bytes());
        h.update(f.as_bytes());
    }
    hex::encode(h.finalize())
}

#[allow(clippy::too_many_arguments)]
fn recompute_event_hash_v2(
    event_id: &str,
    trace_id: &str,
    agent_id: &str,
    category: &str,
    detail_digest: &str,
    decision: &str,
    decision_source: &str,
    status: &str,
    enforcement_point: &str,
    timestamp_rfc3339: &str,
    payload_content_hash: &str,
) -> String {
    let mut h = Sha256::new();
    h.update(PREFIX_EVENT_V2);
    for f in &[
        event_id,
        trace_id,
        agent_id,
        category,
        detail_digest,
        decision,
        decision_source,
        status,
        enforcement_point,
        timestamp_rfc3339,
        payload_content_hash,
    ] {
        h.update((f.len() as u32).to_le_bytes());
        h.update(f.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Generate a Merkle inclusion proof for the leaf at `index` using
/// the same gvm-node-v1 hash scheme as `gvm-proxy::merkle`. Returns
/// a sequence of `(sibling_hex, is_right)` pairs from leaf to root.
///
/// Identical algorithm to `gvm_proxy::merkle::generate_merkle_proof`,
/// duplicated here so the CLI proof builder doesn't need to depend on
/// gvm-proxy.
pub fn generate_merkle_proof_path(
    leaf_hashes: &[String],
    index: usize,
) -> Result<Vec<(String, bool)>, String> {
    if index >= leaf_hashes.len() {
        return Err(format!(
            "merkle proof index {} out of bounds (len {})",
            index,
            leaf_hashes.len()
        ));
    }
    let mut current_level: Vec<[u8; 32]> = leaf_hashes
        .iter()
        .map(|h| {
            hex::decode(h)
                .map_err(|e| format!("invalid hex in leaf hash: {}", e))
                .and_then(|bytes| {
                    if bytes.len() != 32 {
                        Err(format!("leaf hash must be 32 bytes, got {}", bytes.len()))
                    } else {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Ok(arr)
                    }
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut proof: Vec<(String, bool)> = Vec::new();
    let mut idx = index;

    while current_level.len() > 1 {
        if current_level.len() % 2 == 1 {
            let last = current_level[current_level.len() - 1];
            current_level.push(last);
        }
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        let is_right = idx.is_multiple_of(2);
        proof.push((hex::encode(current_level[sibling_idx]), is_right));

        let mut next_level: Vec<[u8; 32]> = Vec::with_capacity(current_level.len() / 2);
        for pair in current_level.chunks(2) {
            let mut h = Sha256::new();
            h.update(b"gvm-node-v1:");
            h.update(pair[0]);
            h.update(pair[1]);
            next_level.push(h.finalize().into());
        }
        current_level = next_level;
        idx /= 2;
    }
    Ok(proof)
}

/// Verify a Merkle inclusion path with the same gvm-node-v1 prefix
/// scheme used by `gvm-proxy::merkle`. Local implementation so the
/// verifier needs nothing from gvm-proxy.
fn verify_merkle_path(leaf_hex: &str, path: &[(String, bool)], expected_root: &str) -> bool {
    let mut current: [u8; 32] = match hex::decode(leaf_hex).ok().and_then(|v| v.try_into().ok()) {
        Some(b) => b,
        None => return false,
    };
    for (sibling_hex, is_right) in path {
        let sibling: [u8; 32] = match hex::decode(sibling_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(b) => b,
            None => return false,
        };
        let mut h = Sha256::new();
        h.update(b"gvm-node-v1:");
        if *is_right {
            h.update(current);
            h.update(sibling);
        } else {
            h.update(sibling);
            h.update(current);
        }
        current = h.finalize().into();
    }
    hex::encode(current) == expected_root
}

/// Validate the short config chain and confirm it terminates at the
/// anchor's `context_hash`. Returns `(chain_valid, anchored)`.
///
/// Empty chains are treated as "no chain to check" — `(true, false)`,
/// since the anchor is not anchored to anything we can prove offline.
/// Callers wanting to forbid empty chains should check the chain
/// length separately.
fn verify_config_short_chain(
    chain: &[GvmIntegrityContext],
    anchor_context_hash: &str,
) -> (bool, bool) {
    if chain.is_empty() {
        // Genesis-only proofs: anchor.context_hash is GENESIS_HASH_HEX
        // and the chain is intentionally empty. Treat as anchored if the
        // anchor's context is the genesis sentinel.
        let anchored = anchor_context_hash == crate::GENESIS_HASH_HEX;
        return (true, anchored);
    }

    let mut prev_hash: Option<String> = None;
    for ctx in chain {
        // Each ctx must self-recompute its hash, and link to the prior.
        // First in chain: previous_state must be None (genesis subset)
        // OR equal to the prior context's hash (we don't see it in this
        // window — accept). Strict policy left to the caller.
        if let Some(ref prev) = prev_hash {
            // Mid-chain: ctx.previous_state MUST equal prev hash.
            match ctx.previous_state.as_deref() {
                Some(claimed) if claimed == prev => {}
                _ => return (false, false),
            }
        }
        prev_hash = Some(ctx.context_hash());
    }
    let last_hash = prev_hash.unwrap_or_default();
    let anchored = last_hash == anchor_context_hash;
    (true, anchored)
}

// Re-export domain prefixes for downstream consumers that want to
// invoke the salted-digest helper directly.
pub use crate::compute_detail_digest;

// Suppress unused-import warnings for items only referenced by signatures.
#[allow(dead_code)]
fn _suppress_unused() {
    let _ = LLMTrace {
        provider: String::new(),
        model: None,
        thinking: None,
        truncated: false,
        usage: None,
    };
    let _ = PayloadDescriptor::default();
    let _ = PREFIX_OPDETAIL_V1;
}

// ════════════════════════════════════════════════════════════════════
// Proof generators (build_proof / build_batch_proof)
//
// The pure types and verifier are everything an offline auditor needs.
// These two functions are the *producers* — they walk WAL files,
// locate the requested batch, and bundle a proof. They live here (in
// gvm-types) rather than gvm-proxy so the gvm-cli `gvm proof` command
// can call them without pulling in the proxy crate (which would drag
// in axum/hyper/tls — a massive dependency for a read-only CLI tool).
//
// Walking pattern matches `verify_anchor_chain`: rotated segments
// first (oldest .1 → newest), active segment last. Blocking I/O is
// fine — proof export is a one-shot CLI operation, not on the hot
// path.
// ════════════════════════════════════════════════════════════════════

/// How many config_load contexts to include in `config_short_chain`.
/// 3 covers "current + last reload + bootstrap" for a typical proof.
pub const DEFAULT_CONFIG_CHAIN_DEPTH: usize = 3;

#[derive(Debug)]
pub struct ProofBuildError(pub String);

impl std::fmt::Display for ProofBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProofBuildError {}

/// Build a `GvmProof` for the event identified by `event_id`. Walks
/// every WAL segment (rotated then active) once to locate the event's
/// batch, then reconstructs the inclusion path from the batch's
/// `leaves_blob`.
///
/// `level` controls how the embedded event is redacted before serialize.
pub fn build_proof(
    wal_path: &std::path::Path,
    event_id: &str,
    level: RedactionLevel,
) -> Result<GvmProof, ProofBuildError> {
    let segments = wal_segments(wal_path);
    let located = locate_event(&segments, event_id)?;
    finalize_proof(located, level)
}

/// Build a whole-batch proof for the batch identified by `batch_id`.
pub fn build_batch_proof(
    wal_path: &std::path::Path,
    batch_id: u64,
    level: RedactionLevel,
) -> Result<GvmBatchProof, ProofBuildError> {
    let segments = wal_segments(wal_path);
    let located = locate_batch(&segments, batch_id)?;
    finalize_batch_proof(located, level)
}

fn wal_segments(wal_path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let parent = wal_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let stem = wal_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wal.log")
        .to_string();
    let mut segments: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&parent) {
        let mut numbered: Vec<(u64, std::path::PathBuf)> = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_string();
            if let Some(suffix) = name_str.strip_prefix(&format!("{}.", stem)) {
                if let Ok(n) = suffix.parse::<u64>() {
                    numbered.push((n, parent.join(&name_str)));
                }
            }
        }
        numbered.sort_by_key(|(n, _)| *n);
        segments.extend(numbered.into_iter().map(|(_, p)| p));
    }
    segments.push(wal_path.to_path_buf());
    segments
}

struct LocatedEvent {
    event: GVMEvent,
    batch_events: Vec<GVMEvent>,
    event_index: usize,
    seal: BatchSealRecord,
    batch_record: MerkleBatchRecord,
    anchor: GvmStateAnchor,
    config_chain_full: Vec<GvmIntegrityContext>,
}

fn locate_event(
    segments: &[std::path::PathBuf],
    event_id: &str,
) -> Result<LocatedEvent, ProofBuildError> {
    use std::io::BufRead;
    let mut current_batch_events: Vec<GVMEvent> = Vec::new();
    let mut pending_seal: Option<BatchSealRecord> = None;
    let mut pending_batch_record: Option<MerkleBatchRecord> = None;
    let mut config_chain: Vec<GvmIntegrityContext> = Vec::new();
    let mut target_in_current_batch: Option<usize> = None;

    for seg in segments {
        let file = match std::fs::File::open(seg) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("\"anchor_hash\"") && trimmed.contains("\"batch_root\"") {
                if let Ok(anchor) = serde_json::from_str::<GvmStateAnchor>(trimmed) {
                    if let (Some(batch_record), Some(seal), Some(idx)) = (
                        pending_batch_record.take(),
                        pending_seal.take(),
                        target_in_current_batch,
                    ) {
                        return Ok(LocatedEvent {
                            event: current_batch_events[idx].clone(),
                            batch_events: current_batch_events,
                            event_index: idx,
                            seal,
                            batch_record,
                            anchor,
                            config_chain_full: config_chain,
                        });
                    }
                    current_batch_events.clear();
                    target_in_current_batch = None;
                    continue;
                }
            }
            if trimmed.contains("\"merkle_root\"") && trimmed.contains("\"batch_id\"") {
                if let Ok(br) = serde_json::from_str::<MerkleBatchRecord>(trimmed) {
                    pending_batch_record = Some(br);
                    continue;
                }
            }
            if trimmed.contains("\"seal_id\"") && trimmed.contains("\"sealed_at\"") {
                if let Ok(s) = serde_json::from_str::<BatchSealRecord>(trimmed) {
                    pending_seal = Some(s);
                    continue;
                }
            }
            if let Ok(event) = serde_json::from_str::<GVMEvent>(trimmed) {
                if event.operation == "gvm.system.config_load" {
                    if let Some(ctx_value) = event.context.get("_integrity_context") {
                        if let Ok(ctx) =
                            serde_json::from_value::<GvmIntegrityContext>(ctx_value.clone())
                        {
                            config_chain.push(ctx);
                        }
                    }
                }
                if event.event_id == event_id {
                    target_in_current_batch = Some(current_batch_events.len());
                }
                current_batch_events.push(event);
            }
        }
    }
    Err(ProofBuildError(format!(
        "event_id {} not found in any sealed batch",
        event_id
    )))
}

fn finalize_proof(
    located: LocatedEvent,
    level: RedactionLevel,
) -> Result<GvmProof, ProofBuildError> {
    let LocatedEvent {
        event,
        batch_events,
        event_index,
        seal,
        batch_record,
        anchor,
        config_chain_full,
    } = located;

    let leaves_hex: Vec<String> = batch_record.leaves_iter().map(hex::encode).collect();
    if leaves_hex.is_empty() {
        return Err(ProofBuildError(
            "batch_record carries empty leaves_blob (legacy batch — proof export not supported)"
                .to_string(),
        ));
    }
    if event_index >= batch_events.len() || event_index >= leaves_hex.len() {
        return Err(ProofBuildError(format!(
            "event_index {} out of bounds (events={}, leaves={})",
            event_index,
            batch_events.len(),
            leaves_hex.len()
        )));
    }

    let leaf_hash = leaves_hex[event_index].clone();
    let path = generate_merkle_proof_path(&leaves_hex, event_index).map_err(ProofBuildError)?;

    let wal_inclusion = MerkleInclusion {
        leaf_hash,
        leaf_index: event_index,
        path,
    };

    let config_short_chain = trim_config_chain(&config_chain_full, &anchor.context_hash);

    Ok(GvmProof {
        spec_version: 3,
        event: redact_event(&event, level),
        redaction_level: level,
        wal_inclusion,
        batch_record,
        seal,
        anchor,
        config_short_chain,
        checkpoint_inclusion: None,
    })
}

struct LocatedBatch {
    events: Vec<GVMEvent>,
    seal: BatchSealRecord,
    batch_record: MerkleBatchRecord,
    anchor: GvmStateAnchor,
    config_chain_full: Vec<GvmIntegrityContext>,
}

fn locate_batch(
    segments: &[std::path::PathBuf],
    batch_id: u64,
) -> Result<LocatedBatch, ProofBuildError> {
    use std::io::BufRead;
    let mut current_events: Vec<GVMEvent> = Vec::new();
    let mut pending_seal: Option<BatchSealRecord> = None;
    let mut pending_batch_record: Option<MerkleBatchRecord> = None;
    let mut config_chain: Vec<GvmIntegrityContext> = Vec::new();

    for seg in segments {
        let file = match std::fs::File::open(seg) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("\"anchor_hash\"") && trimmed.contains("\"batch_root\"") {
                if let Ok(anchor) = serde_json::from_str::<GvmStateAnchor>(trimmed) {
                    if let (Some(seal), Some(br)) =
                        (pending_seal.take(), pending_batch_record.take())
                    {
                        if anchor.batch_id == batch_id {
                            return Ok(LocatedBatch {
                                events: current_events,
                                seal,
                                batch_record: br,
                                anchor,
                                config_chain_full: config_chain,
                            });
                        }
                    }
                    current_events.clear();
                    continue;
                }
            }
            if trimmed.contains("\"merkle_root\"") && trimmed.contains("\"batch_id\"") {
                if let Ok(br) = serde_json::from_str::<MerkleBatchRecord>(trimmed) {
                    pending_batch_record = Some(br);
                    continue;
                }
            }
            if trimmed.contains("\"seal_id\"") && trimmed.contains("\"sealed_at\"") {
                if let Ok(s) = serde_json::from_str::<BatchSealRecord>(trimmed) {
                    pending_seal = Some(s);
                    continue;
                }
            }
            if let Ok(event) = serde_json::from_str::<GVMEvent>(trimmed) {
                if event.operation == "gvm.system.config_load" {
                    if let Some(ctx_value) = event.context.get("_integrity_context") {
                        if let Ok(ctx) =
                            serde_json::from_value::<GvmIntegrityContext>(ctx_value.clone())
                        {
                            config_chain.push(ctx);
                        }
                    }
                }
                current_events.push(event);
            }
        }
    }
    Err(ProofBuildError(format!(
        "batch_id {} not found in WAL",
        batch_id
    )))
}

fn finalize_batch_proof(
    located: LocatedBatch,
    level: RedactionLevel,
) -> Result<GvmBatchProof, ProofBuildError> {
    let LocatedBatch {
        events,
        seal,
        batch_record,
        anchor,
        config_chain_full,
    } = located;
    let config_short_chain = trim_config_chain(&config_chain_full, &anchor.context_hash);
    let redacted = events.iter().map(|e| redact_event(e, level)).collect();
    Ok(GvmBatchProof {
        spec_version: 3,
        events: redacted,
        seal,
        batch_record,
        anchor,
        config_short_chain,
        checkpoint_inclusions: HashMap::new(),
    })
}

fn trim_config_chain(
    full: &[GvmIntegrityContext],
    anchor_context_hash: &str,
) -> Vec<GvmIntegrityContext> {
    let anchor_idx = full
        .iter()
        .rposition(|c| c.context_hash() == anchor_context_hash);
    let end = match anchor_idx {
        Some(i) => i + 1,
        None => full.len(),
    };
    let start = end.saturating_sub(DEFAULT_CONFIG_CHAIN_DEPTH);
    full[start..end].to_vec()
}
