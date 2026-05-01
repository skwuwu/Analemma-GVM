use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

// ─── Operation Namespace (PART 1) ───

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OperationMetadata {
    /// 3-segment or 4-segment operation name
    /// e.g. "gvm.messaging.send", "custom.acme.banking.wire_transfer"
    pub operation: String,

    /// Target resource descriptor
    pub resource: ResourceDescriptor,

    /// Acting subject (agent)
    pub subject: SubjectDescriptor,

    /// Execution context attributes
    pub context: OperationContext,

    /// Payload summary for audit (not the raw payload)
    pub payload: PayloadDescriptor,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResourceDescriptor {
    /// Resource service (e.g. "slack", "gmail", "postgres")
    pub service: String,
    /// Resource identifier (e.g. "#customer-support", "user@example.com")
    pub identifier: Option<String>,
    /// Resource tier
    pub tier: ResourceTier,
    /// Data sensitivity level
    pub sensitivity: Sensitivity,
}

impl Default for ResourceDescriptor {
    fn default() -> Self {
        Self {
            service: String::new(),
            identifier: None,
            tier: ResourceTier::External,
            sensitivity: Sensitivity::Medium,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceTier {
    Internal,
    External,
    CustomerFacing,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubjectDescriptor {
    pub agent_id: String,
    pub tenant_id: Option<String>,
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OperationContext {
    /// Additional context attributes (amount, region, customer tier, etc.)
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PayloadDescriptor {
    pub content_hash: String,
    pub size_bytes: u64,
    /// Flagged patterns from SRR pattern matching
    pub flagged_patterns: Vec<String>,
}

// ─── Enforcement Decision Model (PART 3.2) ───

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum EnforcementDecision {
    /// Immediate allow (IC-1)
    Allow,

    /// Allow execution but elevate audit priority (durable WAL)
    AuditOnly { alert_level: AlertLevel },

    /// Delay then allow (IC-2)
    Delay { milliseconds: u64 },

    /// Require human approval (IC-3)
    RequireApproval { urgency: ApprovalUrgency },

    /// Unconditional deny
    Deny { reason: String },
}

impl EnforcementDecision {
    /// Strictness order: Allow < AuditOnly < Delay < RequireApproval < Deny
    pub fn strictness(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::AuditOnly { .. } => 1,
            Self::Delay { .. } => 2,
            Self::RequireApproval { .. } => 3,
            Self::Deny { .. } => 4,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ApprovalUrgency {
    /// Immediate review required
    Immediate,
    /// Within 30 minutes
    Standard,
    /// Within 4 hours
    Low,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum AlertLevel {
    Info,
    Warning,
    Critical,
}

// ─── Operation descriptor (Phase 1 — privacy-preserving event_hash) ───
//
// Splits the previously-monolithic `operation: String` field into a
// non-sensitive `category` (e.g. "http.POST", "gvm.dns.query") and an
// optional `detail` (e.g. "/api/v1/user/12345/delete") plus a salted
// digest of the detail. The event_hash v2 input uses category + digest
// instead of the raw operation string, so an external auditor receiving
// a redacted proof can verify the event_hash without learning the
// detail (the salt stays with the unredacted form).
//
// Threat model:
// - Attacker holds an event_hash but not the salt → cannot brute-force
//   the detail string from a known operation alphabet.
// - Verifier with redacted proof (no salt, no detail, only digest) →
//   can still recompute event_hash via category + digest.
// - Verifier with full proof (salt + detail + digest) → can reconstruct
//   detail_digest and verify it matches the stored value.

/// Domain-separation prefix for `compute_detail_digest()`.
/// Versioned so a future digest-format migration (different salt size,
/// different hash algorithm) can coexist with v1 records.
pub const PREFIX_OPDETAIL_V1: &[u8] = b"gvm-opdetail-v1:";

/// Domain-separation prefix for the LEGACY event_hash function
/// (`compute_event_hash_v1` — uses raw operation string).
/// Kept for backward compatibility with WAL records written before
/// the v2 dispatcher landed.
pub const PREFIX_EVENT_V1: &[u8] = b"gvm-event-v1:";

/// Domain-separation prefix for `compute_event_hash_v2`.
/// Used when the event has `operation_descriptor: Some(...)`.
pub const PREFIX_EVENT_V2: &[u8] = b"gvm-event-v2:";

/// Operation descriptor — split-form replacement for the legacy
/// `operation: String` field. Production callers populate this when
/// the operation has a sensitive detail component (URL path, DNS
/// subdomain, vault key id, etc.).
///
/// JSON shape:
/// ```json
/// {
///   "category": "http.POST",
///   "detail": "/api/v1/user/1234/delete",
///   "detail_salt": "<base64 16 random bytes>",
///   "detail_digest": "<64 hex>"
/// }
/// ```
///
/// In a redacted form, `detail` and `detail_salt` are stripped and
/// only `detail_digest` survives — yet `event_hash` remains
/// recomputable.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OperationDescriptor {
    /// Non-sensitive category. Always exposed in proofs.
    /// Examples: "http.POST", "http.GET", "gvm.dns.query",
    /// "gvm.vault.write", "gvm.system.config_load".
    pub category: String,

    /// Sensitive detail. May be redacted in external proofs.
    /// `None` for category-only operations (e.g. config_load) where
    /// no detail exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// Per-event 16-byte random salt. Defeats dictionary attacks:
    /// without the salt, an external party with only `detail_digest`
    /// cannot enumerate plausible detail strings to find a match.
    /// Stripped together with `detail` during redaction.
    /// Empty (`Vec::new()`) when `detail` is None.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub detail_salt: Vec<u8>,

    /// `compute_detail_digest(detail_salt, detail.as_deref())`.
    /// Always present in v2 events (computed when descriptor is
    /// constructed). Survives redaction so the verifier can still
    /// recompute event_hash.
    pub detail_digest: String,
}

impl OperationDescriptor {
    /// Build a descriptor with caller-supplied salt. Production code
    /// generates the salt with `rand::thread_rng().fill(&mut salt)`;
    /// tests can pass a deterministic salt for reproducibility.
    ///
    /// `detail = None` produces a "category-only" descriptor — the
    /// salt is ignored (forced empty), and `detail_digest` is the
    /// canonical "no detail" marker.
    pub fn new(category: impl Into<String>, detail: Option<String>, salt: Vec<u8>) -> Self {
        let (detail_salt, digest) = match detail.as_deref() {
            Some(d) => {
                let dg = compute_detail_digest(&salt, Some(d));
                (salt, dg)
            }
            None => (Vec::new(), compute_detail_digest(&[], None)),
        };
        Self {
            category: category.into(),
            detail,
            detail_salt,
            detail_digest: digest,
        }
    }

    /// Convenience for category-only operations (no sensitive detail).
    pub fn category_only(category: impl Into<String>) -> Self {
        Self::new(category, None, Vec::new())
    }

    /// Re-compute `detail_digest` from the current `detail_salt` and
    /// `detail`. Returns true if the stored digest matches — used by
    /// verifiers that hold the un-redacted form to confirm the digest
    /// was computed correctly.
    pub fn verify_digest(&self) -> bool {
        let recomputed = compute_detail_digest(&self.detail_salt, self.detail.as_deref());
        recomputed == self.detail_digest
    }
}

/// Domain-separated SHA-256 over (salt, detail). Always returns 64-hex.
///
/// Canonical input: `PREFIX_OPDETAIL_V1 || u32_le(salt.len) || salt
/// || u32_le(detail.len) || detail`. `detail = None` is encoded as
/// length-0, producing a deterministic "no detail" digest.
pub fn compute_detail_digest(salt: &[u8], detail: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PREFIX_OPDETAIL_V1);
    h.update((salt.len() as u32).to_le_bytes());
    h.update(salt);
    let d = detail.unwrap_or("");
    h.update((d.len() as u32).to_le_bytes());
    h.update(d.as_bytes());
    hex::encode(h.finalize())
}

// ─── Event Schema (PART 6) ───

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GVMEvent {
    // ── Identification ──
    pub event_id: String,
    pub trace_id: String,
    pub parent_event_id: Option<String>,

    // ── Subject ──
    pub agent_id: String,
    pub tenant_id: Option<String>,
    pub session_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,

    // ── Operation (semantic) ──
    pub operation: String,
    pub resource: ResourceDescriptor,
    pub context: HashMap<String, serde_json::Value>,

    // ── Transport (network, supplementary) ──
    pub transport: Option<TransportInfo>,

    // ── Decision ──
    pub decision: String,
    pub decision_source: String,
    pub matched_rule_id: Option<String>,
    pub enforcement_point: String,

    // ── Event status (Phantom Record prevention) ──
    pub status: EventStatus,

    // ── Payload ──
    pub payload: PayloadDescriptor,

    // ── Integrity ──
    /// NATS JetStream sequence number (real-time integrity anchor).
    /// Hash chain verification runs in a separate async process.
    pub nats_sequence: Option<u64>,

    /// SHA-256 hash of this event's canonical fields (Merkle leaf).
    /// Computed before WAL write. Used for batch Merkle root verification.
    #[serde(default)]
    pub event_hash: Option<String>,

    /// LLM reasoning trace extracted from API response (IC-2/IC-3 only).
    /// Captures thinking/reasoning content for governance audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_trace: Option<LLMTrace>,

    /// True if this event hit the SRR catch-all / Default-to-Caution rule
    /// (no specific, intentional SRR rule exists for this URL).
    /// Used by the CLI to suggest adding explicit rules in interactive mode.
    #[serde(default)]
    pub default_caution: bool,

    /// Hash of the active integrity context at the time of this event.
    /// Links behavioral events to the config state that governed them
    /// without embedding the full context in every event (performance).
    /// Only config_load events carry the full GvmIntegrityContext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_integrity_ref: Option<String>,

    /// Phase 1 split form of the operation field — separates
    /// non-sensitive `category` from sensitive `detail` so external
    /// proofs can be redacted without invalidating `event_hash`.
    ///
    /// Behavior:
    /// - `None` (legacy events) → `compute_event_hash` uses the
    ///   v1 algorithm over `operation: String`.
    /// - `Some(desc)` (v2 events) → `compute_event_hash` uses the
    ///   v2 algorithm: `category` and `detail_digest` are hashed
    ///   instead of the raw operation string.
    ///
    /// New event-creation paths populate this when the operation
    /// carries PII-bearing detail (URL path, DNS subdomain, vault
    /// key). Category-only paths (config_load, etc.) may still
    /// supply an `OperationDescriptor::category_only(...)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_descriptor: Option<OperationDescriptor>,
}

// ─── Integrity Context (execution environment reproducibility) ───

/// Records the state of the execution environment at a point in time.
///
/// Design principles:
/// - **Reproducibility**: config hash + timestamp enable exact environment reconstruction
/// - **Pluggable trust architecture**: from local dev (hash-only) to HSM-backed signing
/// - **Immutable chain**: previous_state links create tamper-evident config history
///
/// Local environments: trust_model=Local, algorithm=None, signature empty.
/// Regulated environments: Ed25519 keypair over config_hash.
/// Hardware-backed: HSM/TPM attestation via opaque_extensions.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GvmIntegrityContext {
    /// Schema version for forward compatibility.
    pub spec_version: u8,

    /// How the system should trust this integrity record.
    pub trust_model: TrustModel,

    /// Origin identifier — where this config state was produced.
    /// Key ID, organizational unit, or "local-default".
    pub origin_id: String,

    /// Signing algorithm. None for local hash-only mode.
    pub algorithm: Algorithm,

    /// SHA-256 hash of the config content. Always computed regardless of trust model.
    pub config_hash: String,

    /// Digital signature over config_hash. Empty when algorithm=None.
    #[serde(default, with = "base64_bytes")]
    pub signature: Vec<u8>,

    /// Unix timestamp (seconds since epoch). Single numeric format avoids
    /// clock-skew ambiguity and timezone parsing overhead.
    pub timestamp: u64,

    /// Hash of the previous config state. Creates an immutable chain:
    /// context N points to context N-1's config_hash.
    /// None for the first config load after fresh install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state: Option<String>,

    /// WAL checkpoint at the time of this context. Enables point-in-time
    /// queries: "which config was active when event X happened".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<u64>,

    /// Vendor-neutral extension space for hardware security modules (Intel SGX,
    /// ARM TrustZone), external attestation services, or organization-specific
    /// metadata. Keys are string identifiers; values are opaque byte payloads.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub opaque_extensions: BTreeMap<String, Vec<u8>>,
}

/// Trust model — how the system should treat this integrity record.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum TrustModel {
    /// Local standalone — hash only, no cryptographic signature.
    Local,
    /// Static keypair — Ed25519 or similar offline signature.
    Static,
    /// Remote verification — central governance server or third-party authority.
    Remote,
}

/// Signing algorithm for integrity context.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Algorithm {
    /// No signature — hash-only integrity (local development).
    None,
    /// Ed25519 digital signature.
    Ed25519,
}

impl GvmIntegrityContext {
    /// Create a local integrity context (default for standalone users).
    /// config_hash is always computed; no signature.
    pub fn local(config_hash: String, previous_state: Option<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            spec_version: 1,
            trust_model: TrustModel::Local,
            origin_id: "local-default".to_string(),
            algorithm: Algorithm::None,
            config_hash,
            signature: Vec::new(),
            timestamp: now,
            previous_state,
            checkpoint_id: None,
            opaque_extensions: BTreeMap::new(),
        }
    }

    /// SHA-256 hash of this context (used as config_integrity_ref in behavioral events).
    pub fn context_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical = format!(
            "v{}:{}:{}:{}:{}:{}",
            self.spec_version,
            self.trust_model_str(),
            self.origin_id,
            self.config_hash,
            self.timestamp,
            self.previous_state.as_deref().unwrap_or("none"),
        );
        format!("{:x}", Sha256::digest(canonical.as_bytes()))
    }

    fn trust_model_str(&self) -> &str {
        match self.trust_model {
            TrustModel::Local => "local",
            TrustModel::Static => "static",
            TrustModel::Remote => "remote",
        }
    }
}

/// Report of integrity-chain verification over a WAL file.
pub struct IntegrityChainReport {
    /// Number of `gvm.system.config_load` events with a valid `previous_state` link.
    pub valid_links: usize,
    /// Total number of `gvm.system.config_load` events found.
    pub total_config_loads: usize,
    /// First event_id where the chain broke, or `None` if intact.
    pub first_break: Option<String>,
}

/// Scan a WAL file for `gvm.system.config_load` events and verify the integrity-context
/// chain: each event's `previous_state` must equal the preceding event's `config_hash`.
///
/// Detects manual WAL edits, truncation of config_load events, or forged
/// integrity contexts. Pure WAL-parsing — safe to run in both the proxy
/// (startup) and CLI (`gvm audit verify`) without duplicating logic.
pub fn verify_integrity_chain(wal_path: &std::path::Path) -> IntegrityChainReport {
    use std::io::BufRead;

    // Production WAL is rotated at `max_wal_bytes` — the bulk of the
    // audit history lives in `wal.log.1`, `wal.log.2`, ..., not in
    // the active `wal.log`. The verifier MUST traverse rotated
    // segments in chronological order (oldest .1 → newest active)
    // so the integrity-context chain that crosses rotation boundaries
    // can be validated end-to-end. Without this, a `gvm audit verify`
    // run would only see the events in the active segment and report
    // an artificially-low total_config_loads.
    //
    // Rotation naming, per ledger::rotate_wal: when wal.log fills,
    // it is renamed to wal.log.<N> where N is one greater than the
    // current max numeric suffix. So wal.log.1 is the OLDEST segment,
    // wal.log.<max> is the most-recently-rotated, and wal.log
    // is always the active head.
    let mut segments: Vec<std::path::PathBuf> = Vec::new();
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
    // Active segment last — that is the head of the chain.
    segments.push(wal_path.to_path_buf());

    let mut prev_config_hash: Option<String> = None;
    let mut valid_links = 0usize;
    let mut total_config_loads = 0usize;
    let mut first_break: Option<String> = None;

    for seg_path in &segments {
        let file = match std::fs::File::open(seg_path) {
            Ok(f) => f,
            // Active segment may not exist on a fresh WAL; rotated
            // segments may have been pruned per max_wal_segments —
            // both are non-fatal, just skip and continue the chain.
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

            let parsed: serde_json::Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if parsed.get("operation").and_then(|v| v.as_str()) != Some("gvm.system.config_load") {
                continue;
            }

            let Some(ctx) = parsed.pointer("/context/_integrity_context").cloned() else {
                continue;
            };

            total_config_loads += 1;
            // Chain link semantics: production callers (api.rs::reload_srr,
            // main.rs startup) pass the previous event's CONTEXT_HASH —
            // the canonical SHA-256 of the full integrity-context fields,
            // not just config_hash — as `prev_config_hash` to
            // record_config_load, and that is what gets stored in
            // `previous_state`. So `claimed_prev` we read off the wire
            // must be compared to the PREVIOUS event's context_hash, not
            // its config_hash. Reconstruct the IntegrityContext to call
            // its `context_hash()` method — that is the canonical hash
            // GvmIntegrityContext promises.
            let current_hash: Option<String> =
                match serde_json::from_value::<GvmIntegrityContext>(ctx.clone()) {
                    Ok(parsed_ctx) => Some(parsed_ctx.context_hash()),
                    Err(_) => None,
                };
            let current_hash = current_hash.as_deref();
            let claimed_prev = ctx.get("previous_state").and_then(|v| v.as_str());

            // §4.8 strip-evasion guard:
            //
            // The OLD rule was "(None, _) => accept" — accepting any
            // first observation regardless of what it claimed for
            // previous_state. That let an attacker truncate prior
            // segments and the surviving "first" config_load passed
            // even when it claimed Some(prior_hash).
            //
            // NEW rule:
            //   (None, None)        → genuine genesis (only valid first form)
            //   (None, Some(_))     → first observation claims prior history
            //                         that we cannot find in the WAL we
            //                         walked: truncation evidence → break
            //   (Some(exp), Some(c)) if exp == c → normal chain link
            //   anything else        → break
            //
            // The genesis case (None, None) is the ONE accepted "starts
            // here" form. In the proxy this is the first config_load
            // after a fresh install (record_config_load called with
            // prev_context_hash = None on startup).
            match (&prev_config_hash, claimed_prev) {
                (None, None) => {
                    // Genuine genesis — accept once.
                    valid_links += 1;
                }
                (None, Some(_)) => {
                    // First config_load we see references a prior we
                    // cannot validate against — that prior is missing
                    // from the WAL we just walked. Truncation evidence.
                    if first_break.is_none() {
                        let event_id = parsed
                            .get("event_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        first_break = Some(event_id);
                    }
                }
                (Some(expected), Some(claimed)) if expected == claimed => {
                    valid_links += 1;
                }
                (Some(_), _) => {
                    if first_break.is_none() {
                        let event_id = parsed
                            .get("event_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();
                        first_break = Some(event_id);
                    }
                }
            }

            if let Some(hash) = current_hash {
                prev_config_hash = Some(hash.to_string());
            }
        }
    } // end per-segment loop

    IntegrityChainReport {
        valid_links,
        total_config_loads,
        first_break,
    }
}

// ════════════════════════════════════════════════════════════════════
// Phase 2.5 — Anchor chain audit
// ════════════════════════════════════════════════════════════════════
//
// `verify_anchor_chain` walks every `GvmStateAnchor` record across
// rotated WAL segments and audits four invariants:
//
//   1. Self-consistency: each anchor's `anchor_hash` recomputes from
//      its other fields (catches in-place field tamper).
//   2. Chain link: `anchor[N].prev_anchor == anchor[N-1].anchor_hash`
//      (catches truncation, splice, or out-of-order reordering).
//   3. Monotonic batch_id: anchor[N].batch_id == anchor[N-1].batch_id+1
//      (catches batch deletion or insertion).
//   4. Monotonic timestamp: anchor[N].timestamp >= anchor[N-1].timestamp
//      (catches clock-rewind tampering, modulo a configurable skew
//      tolerance).
//
// Genesis: the first anchor in a fresh installation has
// `prev_anchor == None`. Per §4.8, the (None, None) form is accepted
// as genuine genesis; (None, Some(_)) flags truncation evidence.
//
// Signature verification (Ed25519, HSM, TSA) is OUT OF SCOPE for v1
// of `verify_anchor_chain` — it returns the count of signed anchors
// for the caller to inspect, but does not invoke vendor-specific
// verifiers. A signature-checking wrapper is a separate Phase 6
// deliverable.

/// Tunable thresholds for anchor-chain timing audits.
#[derive(Clone, Debug)]
pub struct AnchorAuditConfig {
    /// Maximum acceptable wall-clock gap between consecutive anchors.
    /// Anything larger is flagged as a `suspicious_gap` — operators
    /// should investigate (proxy paused, clock skew, log tampering).
    pub max_gap_secs: u64,
    /// Allowed clock-skew tolerance for the monotonic-timestamp check.
    /// `anchor[N].timestamp + skew_tolerance_secs >= anchor[N-1].timestamp`
    /// is the gentleness applied to the "monotonic" rule.
    pub skew_tolerance_secs: u64,
}

impl Default for AnchorAuditConfig {
    fn default() -> Self {
        Self {
            // 1 hour: catches multi-hour service pauses but tolerates
            // routine restarts. Operators with strict SLOs may shrink.
            max_gap_secs: 3600,
            // Allow 5 seconds of NTP skew. Anything larger is treated
            // as monotonic violation.
            skew_tolerance_secs: 5,
        }
    }
}

/// Report of `verify_anchor_chain`. Each violation list is empty when
/// the corresponding invariant held across the entire WAL.
#[derive(Debug, Default)]
pub struct AnchorChainReport {
    /// Total number of anchor records found across all segments.
    pub total_anchors: usize,
    /// Number of anchors whose `anchor_hash` self-recomputed correctly.
    pub valid_self_hashes: usize,
    /// Number of valid `prev_anchor` links (including genesis).
    pub valid_chain_links: usize,
    /// First batch_id where any audit invariant broke. `None` if all
    /// audits passed across the full chain.
    pub first_break: Option<u64>,
    /// Pairs `(anchor.batch_id, prior.batch_id)` where anchor's
    /// timestamp is more than `skew_tolerance_secs` BEFORE the prior's.
    pub clock_inversions: Vec<(u64, u64)>,
    /// Pairs `(anchor.batch_id, gap_secs)` where the wall-clock gap to
    /// the prior anchor exceeds `max_gap_secs`.
    pub suspicious_gaps: Vec<(u64, u64)>,
    /// Pairs `(expected_batch_id, observed_batch_id)` where consecutive
    /// anchors do not have batch_id differ by exactly 1.
    pub batch_id_skips: Vec<(u64, u64)>,
    /// Number of anchors carrying a `signature` (any variant).
    /// `verify_anchor_chain` does NOT verify the cryptographic signature
    /// — that is Phase 6. This count is informational.
    pub signed_anchor_count: usize,
}

/// Walk the WAL and audit the anchor chain (Phase 2.5).
///
/// Reads every rotated segment in chronological order (oldest .1 →
/// newest active), parses each line as `GvmStateAnchor`, and applies
/// the four invariants documented above plus the genesis rule.
///
/// `cfg` controls timing tolerances. `AnchorAuditConfig::default()` is
/// suitable for most operators (1-hour max gap, 5-second clock skew).
///
/// Returns an `AnchorChainReport` summarizing what was found. Callers
/// inspecting `first_break.is_some()` know the chain is broken and
/// must investigate the listed violation vectors.
pub fn verify_anchor_chain(
    wal_path: &std::path::Path,
    cfg: &AnchorAuditConfig,
) -> AnchorChainReport {
    use std::io::BufRead;

    // Same segment ordering as verify_integrity_chain.
    let mut segments: Vec<std::path::PathBuf> = Vec::new();
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

    let mut report = AnchorChainReport::default();
    let mut prev: Option<GvmStateAnchor> = None;
    let mut seen_first_anchor = false;

    let record_break = |r: &mut AnchorChainReport, batch_id: u64| {
        if r.first_break.is_none() {
            r.first_break = Some(batch_id);
        }
    };

    for seg_path in &segments {
        let file = match std::fs::File::open(seg_path) {
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
            // Cheap pre-filter: skip non-anchor lines fast. An anchor
            // line MUST contain "anchor_hash" because every anchor
            // serializes that field.
            if !trimmed.contains("\"anchor_hash\"") {
                continue;
            }
            let anchor: GvmStateAnchor = match serde_json::from_str(trimmed) {
                Ok(a) => a,
                Err(_) => continue,
            };

            report.total_anchors += 1;
            if anchor.signature.is_some() {
                report.signed_anchor_count += 1;
            }

            // (1) Self-hash check.
            if anchor.verify_self_hash() {
                report.valid_self_hashes += 1;
            } else {
                record_break(&mut report, anchor.batch_id);
            }

            // (2)/(3)/(4) Chain link, batch_id monotonic, timestamp.
            match (&prev, &anchor.prev_anchor) {
                (None, None) => {
                    if !seen_first_anchor {
                        // Genuine genesis. Accept once.
                        report.valid_chain_links += 1;
                    } else {
                        // We already saw at least one anchor, but this
                        // one claims genesis (prev_anchor=None). That
                        // means a fresh chain spliced in — break.
                        record_break(&mut report, anchor.batch_id);
                    }
                }
                (None, Some(_)) => {
                    // §4.8 strip-evasion guard: first observed anchor
                    // claims a prior we cannot find — truncation.
                    record_break(&mut report, anchor.batch_id);
                }
                (Some(p), Some(claimed)) if &p.anchor_hash == claimed => {
                    report.valid_chain_links += 1;
                    // Batch ID monotonic check.
                    if anchor.batch_id != p.batch_id + 1 {
                        report
                            .batch_id_skips
                            .push((p.batch_id + 1, anchor.batch_id));
                        record_break(&mut report, anchor.batch_id);
                    }
                    // Timestamp monotonic check (with skew tolerance).
                    let prev_ts = p.timestamp.timestamp();
                    let curr_ts = anchor.timestamp.timestamp();
                    if curr_ts + (cfg.skew_tolerance_secs as i64) < prev_ts {
                        report.clock_inversions.push((anchor.batch_id, p.batch_id));
                        record_break(&mut report, anchor.batch_id);
                    }
                    // Suspicious gap check.
                    let gap = (curr_ts - prev_ts).max(0) as u64;
                    if gap > cfg.max_gap_secs {
                        report.suspicious_gaps.push((anchor.batch_id, gap));
                    }
                }
                (Some(_), Some(_)) | (Some(_), None) => {
                    // prev_anchor mismatch OR claimed None despite
                    // a prior existing — chain broken.
                    record_break(&mut report, anchor.batch_id);
                }
            }

            seen_first_anchor = true;
            prev = Some(anchor);
        }
    }

    report
}

// ════════════════════════════════════════════════════════════════════
// Phase 2 — State Anchor Foundation
// ════════════════════════════════════════════════════════════════════
//
// Three forest/chain structures (WAL batch trees, Config integrity
// chain, Checkpoint forest) are tied together at every batch flush
// via a `GvmStateAnchor`. The anchor is the unit of finality:
// what is timestamped externally, what an HSM signs, what auditors
// receive as the trust root for a `GvmProof`.
//
// Genesis convention: the very first anchor in a system has
// `prev_anchor = None`. All subsequent anchors must reference the
// prior anchor's `anchor_hash` via `prev_anchor`. Audit detects
// truncation by walking the chain from genesis.
//
// Domain separation: every hash function in this module uses an
// explicit `gvm-<scope>-v<n>:` prefix (see §1.6 of GVM_CODE_STANDARDS.md).
// This prevents cross-context hash collisions and lets a future
// algorithm change be detected without ambiguity.

/// All-zeros 32-byte hash, hex-encoded. Acts as the canonical
/// "no-prior" sentinel for the very first context/anchor in a
/// fresh installation. Hashing functions that need to bind to
/// prior state but observe `None` substitute this value into the
/// canonical input — keeping the hash deterministic regardless
/// of whether the absence is genuine genesis or stripped history.
///
/// Verifier policy (§4.8 in GVM_CODE_STANDARDS.md):
///   - First context_load on disk MAY have previous_state = None.
///     Audit accepts (None, None) only. Any (None, Some(_)) is a
///     truncation signal — the prior is gone, history was lost.
///   - First anchor MAY have prev_anchor = None. Same rule applies.
pub const GENESIS_HASH_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Domain-separation prefix for `BatchSealRecord::seal_hash()`.
/// Versioned so future seal-record schema changes (added fields,
/// algorithm migration) do not silently produce colliding hashes.
pub const PREFIX_SEAL_V1: &[u8] = b"gvm-seal-v1:";

/// Domain-separation prefix for `GvmStateAnchor::compute_hash()`.
pub const PREFIX_ANCHOR_V1: &[u8] = b"gvm-anchor-v1:";

/// Per-batch seal record. Captured atomically at batch close from a
/// `TripleState` snapshot (Phase 2 ledger integration). The seal's
/// `seal_hash()` becomes the LAST leaf of the batch's Merkle tree —
/// any tamper of the seal fields invalidates the batch root and,
/// transitively, the anchor. This is the cryptographic enforcement
/// of "the values witnessed at seal time are the values bound to
/// this batch."
///
/// WAL line ordering for a Phase 2 batch:
///
///   1..N. event_1 .. event_N        (GVMEvent JSON)
///   N+1.  seal                      (BatchSealRecord JSON)
///   N+2.  batch_record              (MerkleBatchRecord JSON, leaves_blob
///                                    contains all event_hashes plus
///                                    the seal's seal_hash() at the end)
///   N+3.  anchor                    (GvmStateAnchor JSON, anchor_hash
///                                    binds batch_root + context + ckpt
///                                    + prev_anchor)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BatchSealRecord {
    /// Equals the batch_id of the immediately following MerkleBatchRecord.
    pub seal_id: u64,
    /// Wall-clock instant at which the seal was captured. The anchor's
    /// timestamp inherits this value — they MUST match.
    pub sealed_at: chrono::DateTime<chrono::Utc>,
    /// Active integrity-context hash at seal time. Pin: this is the
    /// system-level observation, NOT every event in the batch
    /// necessarily uses this ref (see §4.7 — per-event ref vs
    /// anchor context).
    pub context_hash: String,
    /// Global checkpoint aggregator root at seal time, or None if no
    /// checkpoints have been registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_root: Option<String>,
    /// Hash of the immediately previous anchor, or None at genesis.
    /// Bound into seal_hash so anchor-chain tampering breaks the
    /// batch_root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_anchor: Option<String>,
}

impl BatchSealRecord {
    /// Domain-separated SHA-256 over seal fields. This hash is the
    /// LAST LEAF of the batch Merkle tree, so any tamper propagates
    /// to merkle_root and to anchor_hash.
    pub fn seal_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(PREFIX_SEAL_V1);
        for f in [
            &self.seal_id.to_le_bytes()[..],
            &self.sealed_at.timestamp().to_le_bytes(),
            self.context_hash.as_bytes(),
            self.checkpoint_root
                .as_deref()
                .unwrap_or(GENESIS_HASH_HEX)
                .as_bytes(),
            self.prev_anchor
                .as_deref()
                .unwrap_or(GENESIS_HASH_HEX)
                .as_bytes(),
        ] {
            h.update((f.len() as u32).to_le_bytes());
            h.update(f);
        }
        h.finalize().into()
    }

    /// Hex-encoded form of `seal_hash()`. Convenience for logging
    /// and for embedding as a hex string in MerkleBatchRecord
    /// representations that prefer hex over binary.
    pub fn seal_hash_hex(&self) -> String {
        hex::encode(self.seal_hash())
    }
}

/// Per-batch state anchor — the finality binding for `(WAL batch,
/// active config, checkpoint state)` at the moment a batch was sealed.
///
/// External attestation (HSM signature, RFC 3161 timestamp) attaches
/// to `anchor_hash`. A `GvmProof` ships ONE anchor and lets a
/// verifier reconstruct everything else.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GvmStateAnchor {
    /// Schema version for forward compatibility. Currently 1.
    pub spec_version: u8,
    /// Identity of the batch this anchor seals. Equals
    /// `BatchSealRecord::seal_id` and `MerkleBatchRecord::batch_id`
    /// for the same group commit.
    pub batch_id: u64,
    /// Wall-clock at seal time. Inherited from the seal record;
    /// MUST equal `seal.sealed_at`.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Merkle root of this batch (events + seal_hash as last leaf).
    pub batch_root: String,
    /// Active integrity-context hash at seal time.
    pub context_hash: String,
    /// Global checkpoint aggregator root, or None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_root: Option<String>,
    /// Hash of the immediately previous anchor, or None at genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_anchor: Option<String>,
    /// Domain-separated SHA-256 over the canonical fields above.
    /// What an HSM signs; what an external auditor verifies.
    pub anchor_hash: String,
    /// Optional finality attestation. SelfSigned alone proves
    /// "GVM produced this anchor"; only TSA proves "this anchor
    /// existed by this wall-clock time according to a third party"
    /// (defeats clock rewind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<AnchorSignature>,
}

/// Anchor attestation variants.
///
/// Storage cost grows with attestation strength: SelfSigned ~64B,
/// Hsm ~1-2KB (attestation report), Tsa ~3-5KB (RFC 3161 token).
/// Operators may mix-and-match: every anchor SelfSigned, every
/// Nth anchor additionally Tsa-attested for cost amortization.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum AnchorSignature {
    /// Local Ed25519 keypair owned by the gvm-proxy process.
    /// Cheap (~50µs/sign) but does NOT defeat clock rewind on its own.
    SelfSigned {
        key_id: String,
        #[serde(with = "base64_bytes")]
        signature: Vec<u8>,
    },
    /// Hardware attestation (HSM, TPM, Intel SGX, AMD SEV).
    /// `attestation_report` carries the hardware-vendor blob.
    Hsm {
        key_id: String,
        #[serde(with = "base64_bytes")]
        signature: Vec<u8>,
        #[serde(with = "base64_bytes")]
        attestation_report: Vec<u8>,
    },
    /// RFC 3161 TimeStampToken from an external Time-Stamping
    /// Authority. The ONLY variant that provides "the anchor
    /// existed by this time" guarantee.
    Tsa {
        tsa_url: String,
        #[serde(with = "base64_bytes")]
        token: Vec<u8>,
    },
}

impl GvmStateAnchor {
    /// Compute the canonical anchor hash from the field values.
    /// Stored back into `anchor_hash` after construction.
    ///
    /// Genesis substitution: `prev_anchor == None` and
    /// `checkpoint_root == None` are both replaced with `GENESIS_HASH_HEX`
    /// in the canonical input. This keeps the hash deterministic
    /// across the genesis transition (None ↔ Some("0000...")).
    pub fn compute_hash(
        spec_version: u8,
        batch_id: u64,
        timestamp_secs: i64,
        batch_root: &str,
        context_hash: &str,
        checkpoint_root: Option<&str>,
        prev_anchor: Option<&str>,
    ) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(PREFIX_ANCHOR_V1);
        for f in [
            &[spec_version][..],
            &batch_id.to_le_bytes(),
            &timestamp_secs.to_le_bytes(),
            batch_root.as_bytes(),
            context_hash.as_bytes(),
            checkpoint_root.unwrap_or(GENESIS_HASH_HEX).as_bytes(),
            prev_anchor.unwrap_or(GENESIS_HASH_HEX).as_bytes(),
        ] {
            h.update((f.len() as u32).to_le_bytes());
            h.update(f);
        }
        h.finalize().into()
    }

    /// Build an anchor from a sealed batch. Caller is responsible
    /// for attaching `signature` (None for first cut, populated by
    /// signing layer). The returned anchor has `anchor_hash` filled.
    pub fn seal(spec_version: u8, seal: &BatchSealRecord, batch_root: String) -> Self {
        let anchor_hash_bytes = Self::compute_hash(
            spec_version,
            seal.seal_id,
            seal.sealed_at.timestamp(),
            &batch_root,
            &seal.context_hash,
            seal.checkpoint_root.as_deref(),
            seal.prev_anchor.as_deref(),
        );
        Self {
            spec_version,
            batch_id: seal.seal_id,
            timestamp: seal.sealed_at,
            batch_root,
            context_hash: seal.context_hash.clone(),
            checkpoint_root: seal.checkpoint_root.clone(),
            prev_anchor: seal.prev_anchor.clone(),
            anchor_hash: hex::encode(anchor_hash_bytes),
            signature: None,
        }
    }

    /// Verify that the stored `anchor_hash` matches a re-computation
    /// from the other fields. Catches in-place tampering of any
    /// canonical-input field.
    pub fn verify_self_hash(&self) -> bool {
        let recomputed = Self::compute_hash(
            self.spec_version,
            self.batch_id,
            self.timestamp.timestamp(),
            &self.batch_root,
            &self.context_hash,
            self.checkpoint_root.as_deref(),
            self.prev_anchor.as_deref(),
        );
        hex::encode(recomputed) == self.anchor_hash
    }
}

/// Serde helper for Vec<u8> as base64 in JSON.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

/// Event status machine — prevents phantom records
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum EventStatus {
    /// Written to WAL, external API not yet called. Remains in this state on crash.
    Pending,
    /// External API call completed (response received).
    Executed,
    /// External API returned success (2xx).
    Confirmed,
    /// External API call failed or error response.
    Failed { reason: String },
    /// Proxy restarted and found this event still in Pending state.
    /// "Record exists but execution status uncertain." Clearly marked for auditors.
    Expired,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransportInfo {
    pub method: String,
    pub host: String,
    pub path: String,
    pub status_code: Option<u16>,
}

/// Classification source — which enforcement layer produced the final decision
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ClassificationSource {
    /// Network SRR (host/path/method matching)
    SRR,
}

/// Internal classification result
#[derive(Clone, Debug)]
pub struct Classification {
    pub decision: EnforcementDecision,
    pub source: ClassificationSource,
    pub operation: Option<OperationMetadata>,
    pub matched_rule_id: Option<String>,
}

/// Parsed GVM headers from SDK-routed requests
#[derive(Clone, Debug)]
pub struct GVMHeaders {
    pub agent_id: String,
    pub trace_id: String,
    pub parent_event_id: Option<String>,
    pub event_id: String,
    pub operation: String,
    pub resource: Option<ResourceDescriptor>,
    pub context: HashMap<String, serde_json::Value>,
    pub session_id: Option<String>,
    pub tenant_id: Option<String>,
    pub rate_limit: Option<u64>,
}

/// Forwarding target extracted from the request
#[derive(Clone, Debug)]
pub struct Target {
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
}

impl Target {
    /// Strip port from host: "api.bank.com:443" → "api.bank.com".
    /// IPv6 bracket form (e.g. "[::1]:8080") is returned as-is (port handled by normalize_host).
    pub fn host_without_port(&self) -> &str {
        strip_port(&self.host)
    }
}

/// Strip port suffix from a host string: "api.bank.com:443" → "api.bank.com".
/// IPv6 bracket form (e.g. "[::1]:8080") is returned as-is.
pub fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

/// Split a host:port authority into (host, optional_port).
/// Returns the bare host plus the parsed port number when present.
///
/// IPv6 bracket form is preserved as-is in the host portion (port parsing
/// for IPv6 is intentionally out of scope — the only callers today are
/// SRR pattern compilation and request normalization, both of which feed
/// downstream code that already handles IPv6 separately).
///
/// Examples:
///   "api.bank.com"        -> ("api.bank.com", None)
///   "api.bank.com:443"    -> ("api.bank.com", Some(443))
///   "api.bank.com:abc"    -> ("api.bank.com:abc", None)  // unparseable, treat as opaque host
///   "[::1]:8080"          -> ("[::1]:8080", None)        // IPv6 bracket form passthrough
pub fn split_host_port(authority: &str) -> (&str, Option<u16>) {
    if authority.starts_with('[') {
        return (authority, None);
    }
    match authority.rsplit_once(':') {
        Some((host, port_str)) => match port_str.parse::<u16>() {
            Ok(p) => (host, Some(p)),
            Err(_) => (authority, None),
        },
        None => (authority, None),
    }
}

/// WAL batch record written after each group commit flush.
/// Contains the Merkle root of all events in the batch and a chain
/// pointer to the previous batch's root (inter-batch integrity).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleBatchRecord {
    /// Unique batch identifier (monotonic)
    pub batch_id: u64,
    /// Merkle root of all event_hash leaves in this batch
    pub merkle_root: String,
    /// Merkle root of the previous batch (None for the first batch)
    pub prev_batch_root: Option<String>,
    /// Number of events in this batch (excludes the seal record at
    /// the end). For batches written by Phase 2+ ledger, the actual
    /// leaf count is `event_count + 1` (events + 1 seal at
    /// `seal_position`).
    pub event_count: usize,
    /// Timestamp of batch flush
    pub timestamp: chrono::DateTime<chrono::Utc>,

    // ─── Phase 2: leaves blob + seal position (backward compatible) ───
    //
    // Behavior:
    // - Phase 1 (legacy) batches have these absent / empty / None.
    //   Verifiers fall back to leaf-recomputation from event lines.
    // - Phase 2+ batches have leaves_blob == 32 × (event_count + 1) bytes,
    //   contiguous concatenation of leaf hashes in WAL order.
    //   leaves[seal_position] is the seal record's seal_hash.
    // - leaves_format documents the encoding so a future format change
    //   (e.g. SHA3-256) can be detected without ambiguity.
    /// Concatenated 32-byte leaf hashes in WAL order. Length is exactly
    /// `(event_count + 1) * 32` for Phase 2+ batches: events first,
    /// then the BatchSealRecord's seal_hash. Empty for legacy batches.
    /// Stored as base64 in JSON to keep the record line-oriented.
    #[serde(default, with = "base64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub leaves_blob: Vec<u8>,

    /// Index into the leaves_blob where the seal_hash sits. Always
    /// `event_count` (the seal is appended after every event leaf).
    /// Explicit field guards against future leaf-ordering changes.
    /// `None` for legacy batches (no seal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_position: Option<usize>,

    /// Encoding of `leaves_blob`. `None` for legacy batches.
    /// Phase 2 sets this to `Sha256Concat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaves_format: Option<LeavesFormat>,
}

/// Encoding format of `MerkleBatchRecord::leaves_blob`.
///
/// Versioned so that future hash algorithm changes (e.g. SHA3, BLAKE3)
/// can coexist in the same WAL with explicit format detection rather
/// than implicit guesswork.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum LeavesFormat {
    /// Contiguous concatenation of 32-byte SHA-256 hashes, in WAL order.
    /// Length invariant: `leaves_blob.len() == (event_count + 1) * 32`.
    /// The trailing 32 bytes are the BatchSealRecord's `seal_hash()`.
    Sha256Concat,
}

impl MerkleBatchRecord {
    /// Iterate over the 32-byte leaf hashes without allocation.
    /// Returns an empty iterator for legacy batches (no leaves_blob).
    /// Use `chunks_exact(32)` so any malformed (non-multiple-of-32)
    /// blob produces an empty iterator rather than a panic.
    pub fn leaves_iter(&self) -> std::slice::ChunksExact<'_, u8> {
        self.leaves_blob.chunks_exact(32)
    }

    /// Return the leaf at `index` as a 32-byte slice, or None if the
    /// index is out of range or the blob is malformed.
    pub fn leaf(&self, index: usize) -> Option<&[u8]> {
        let start = index.checked_mul(32)?;
        let end = start.checked_add(32)?;
        if end > self.leaves_blob.len() {
            return None;
        }
        Some(&self.leaves_blob[start..end])
    }

    /// Return the seal record's hash (last leaf) if this batch carries
    /// a Phase 2+ seal; otherwise None.
    pub fn seal_leaf(&self) -> Option<&[u8]> {
        self.seal_position.and_then(|pos| self.leaf(pos))
    }

    /// Validate the leaves_blob length against event_count + seal.
    /// Returns Ok if either the blob is absent (legacy) or its length
    /// matches the Phase 2 invariant exactly.
    pub fn validate_leaves_invariant(&self) -> Result<(), String> {
        if self.leaves_blob.is_empty() {
            // Legacy batch — no seal expected.
            if self.seal_position.is_some() {
                return Err(format!(
                    "seal_position={:?} present but leaves_blob is empty",
                    self.seal_position
                ));
            }
            return Ok(());
        }
        if self.leaves_blob.len() % 32 != 0 {
            return Err(format!(
                "leaves_blob length {} is not a multiple of 32",
                self.leaves_blob.len()
            ));
        }
        let expected = (self.event_count + 1) * 32;
        if self.leaves_blob.len() != expected {
            return Err(format!(
                "leaves_blob length {} != expected {} (event_count {} + seal)",
                self.leaves_blob.len(),
                expected,
                self.event_count
            ));
        }
        match self.seal_position {
            Some(pos) if pos == self.event_count => Ok(()),
            Some(pos) => Err(format!(
                "seal_position {} != event_count {}",
                pos, self.event_count
            )),
            None => Err("Phase 2 batch missing seal_position".to_string()),
        }
    }
}

/// LLM reasoning/thinking trace extracted from API responses.
/// Only captured for IC-2/IC-3 paths where WAL write already occurs.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LLMTrace {
    /// LLM provider name (openai, anthropic, gemini)
    pub provider: String,
    /// Model identifier from the response
    pub model: Option<String>,
    /// Extracted reasoning/thinking content (truncated to 2KB)
    pub thinking: Option<String>,
    /// Whether the thinking content was truncated
    pub truncated: bool,
    /// Token usage from the response
    pub usage: Option<LLMUsage>,
}

/// Token usage statistics from LLM API response.
///
/// Vendors report usage differently:
/// - OpenAI: provides all three fields
/// - Anthropic: `input_tokens` + `output_tokens` only (no total)
/// - Gemini: `promptTokenCount` + `candidatesTokenCount` + `totalTokenCount`
///
/// Use `computed_total()` for a normalized total across all providers.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LLMUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

impl LLMUsage {
    /// Return total_tokens if available, otherwise compute from prompt + completion.
    /// Normalizes vendor differences (e.g., Anthropic omits total_tokens).
    pub fn computed_total(&self) -> Option<u64> {
        self.total_tokens
            .or_else(|| match (self.prompt_tokens, self.completion_tokens) {
                (Some(p), Some(c)) => Some(p + c),
                _ => None,
            })
    }
}

/// Select the stricter of two enforcement decisions
pub fn max_strict(a: EnforcementDecision, b: EnforcementDecision) -> EnforcementDecision {
    if a.strictness() >= b.strictness() {
        a
    } else {
        b
    }
}

// ─── Governance Block Response (PART 7) ───

/// How an agent should respond when its operation is blocked by governance.
///
/// Configured per-decision type via `[enforcement.on_block]` in proxy.toml.
/// The proxy includes this in every block response so agents can react
/// programmatically without hardcoding retry/halt logic.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponseMode {
    /// Stop execution immediately. Agent must not retry or continue.
    /// Use for Deny decisions where the operation is categorically forbidden.
    #[default]
    Halt,

    /// Suggest an alternative action. Agent may adapt and retry differently.
    /// Use for RequireApproval where the agent can downgrade scope or wait.
    SoftPivot,

    /// Roll back the current transaction and retry after conditions change.
    /// Use for Throttle/temporary blocks where retry is expected.
    Rollback,
}

/// Standard JSON response body returned when a governance decision blocks an operation.
///
/// This is the contract between the proxy and agent SDKs. Every blocked request
/// (Deny, RequireApproval, Throttle, WAL failure) returns this structure so agents
/// can programmatically decide their next action without parsing error strings.
///
/// ```json
/// {
///   "blocked": true,
///   "decision": "Deny",
///   "event_id": "evt-abc-123",
///   "trace_id": "trace-xyz",
///   "operation": "gvm.messaging.send",
///   "reason": "Policy rule finance-002 blocks transfers above $10,000",
///   "mode": "halt",
///   "next_action": "Contact administrator to request an exception",
///   "retry_after_secs": null,
///   "rollback_hint": "trace-xyz",
///   "matched_rule_id": "finance-002",
///   "ic_level": 3
/// }
/// ```
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GovernanceBlockResponse {
    /// Always true for block responses (discriminator for SDK parsing)
    pub blocked: bool,

    /// The enforcement decision that caused the block
    pub decision: String,

    /// Unique event ID for audit trail correlation
    pub event_id: String,

    /// Trace ID for distributed trace correlation
    pub trace_id: String,

    /// Operation that was blocked (e.g. "gvm.messaging.send")
    pub operation: String,

    /// Human-readable explanation of why the operation was blocked
    pub reason: String,

    /// How the agent should respond to this block
    pub mode: BlockResponseMode,

    /// Actionable next step for the agent or operator
    pub next_action: String,

    /// Seconds to wait before retrying (only for Rollback mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,

    /// Trace ID that the SDK can use to roll back to a checkpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_hint: Option<String>,

    /// Policy rule that triggered the block (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule_id: Option<String>,

    /// Impact Classification level (1-3, higher = more restrictive)
    pub ic_level: u8,
}
