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

    /// Execution context (ABAC attributes)
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
    /// Referenced by ABAC policies
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PayloadDescriptor {
    pub content_hash: String,
    pub size_bytes: u64,
    /// Flagged patterns from SRR pattern matching
    pub flagged_patterns: Vec<String>,
}

impl Default for PayloadDescriptor {
    fn default() -> Self {
        Self {
            content_hash: String::new(),
            size_bytes: 0,
            flagged_patterns: Vec::new(),
        }
    }
}

// ─── Enforcement Decision Model (PART 3.2) ───

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum EnforcementDecision {
    /// Immediate allow (IC-1)
    Allow,

    /// Delay then allow (IC-2)
    Delay { milliseconds: u64 },

    /// Require human approval (IC-3)
    RequireApproval { urgency: ApprovalUrgency },

    /// Unconditional deny
    Deny { reason: String },

    /// Rate limit enforcement
    Throttle { max_per_minute: u64 },

    /// Allow execution but elevate audit priority
    AuditOnly { alert_level: AlertLevel },
}

impl EnforcementDecision {
    /// Strictness order: Allow < AuditOnly < Throttle < Delay < RequireApproval < Deny
    pub fn strictness(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::AuditOnly { .. } => 1,
            Self::Throttle { .. } => 2,
            Self::Delay { .. } => 3,
            Self::RequireApproval { .. } => 4,
            Self::Deny { .. } => 5,
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
    /// Layer 1: ABAC policy engine (semantic operation matching)
    ABAC,
    /// Layer 2: Network SRR (host/path/method matching)
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

/// Token usage statistics from LLM API response
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LLMUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

/// Select the stricter of two enforcement decisions
pub fn max_strict(a: EnforcementDecision, b: EnforcementDecision) -> EnforcementDecision {
    if a.strictness() >= b.strictness() {
        a
    } else {
        b
    }
}
