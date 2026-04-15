use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    /// Number of events in this batch
    pub event_count: usize,
    /// Timestamp of batch flush
    pub timestamp: chrono::DateTime<chrono::Utc>,
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
