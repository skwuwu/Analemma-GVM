//! Unified governance classification — shared between proxy_handler and MITM.
//!
//! SRR-only enforcement: classifies requests by network pattern (host/path/method).
//! Single function ensures enforcement parity across all request paths (HTTP proxy, MITM TLS).

use crate::proxy::AppState;
use crate::token_budget::BudgetExceeded;
use crate::types::*;

/// Minimal request metadata for governance classification.
pub struct ClassifyInput<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub body: Option<&'a [u8]>,
    /// GVM SDK headers (None for direct HTTP / MITM without SDK).
    pub gvm_headers: Option<&'a GVMHeaders>,
}

/// Classification result.
pub struct ClassifyOutput {
    pub classification: Classification,
    pub is_default_caution: bool,
    pub agent_id: String,
}

/// Classify a request through SRR.
///
/// Single source of truth for enforcement classification.
/// Called by both `proxy_handler` and `handle_mitm_stream`.
pub fn classify(state: &AppState, input: &ClassifyInput<'_>) -> Result<ClassifyOutput, String> {
    let srr = state
        .srr
        .read()
        .map_err(|_| "SRR lock poisoned".to_string())?;
    let srr_result = srr.check(input.method, input.host, input.path, input.body);
    drop(srr);

    let operation = input.gvm_headers.map(|headers| OperationMetadata {
        operation: headers.operation.clone(),
        resource: headers.resource.clone().unwrap_or_default(),
        subject: SubjectDescriptor {
            agent_id: headers.agent_id.clone(),
            tenant_id: headers.tenant_id.clone(),
            session_id: headers
                .session_id
                .clone()
                .unwrap_or_else(|| headers.trace_id.clone()),
        },
        context: OperationContext {
            attributes: headers.context.clone(),
        },
        payload: PayloadDescriptor::default(),
    });

    let classification = Classification {
        decision: srr_result.decision,
        source: ClassificationSource::SRR,
        operation,
        matched_rule_id: srr_result.matched_description,
    };

    let agent_id = input
        .gvm_headers
        .map(|h| h.agent_id.clone())
        .unwrap_or_else(|| "unknown".to_string());

    Ok(ClassifyOutput {
        classification,
        is_default_caution: srr_result.is_catch_all,
        agent_id,
    })
}

// ─── Token budget enforcement (shared two-tier check) ───
//
// Single source of truth for the per-agent + global token budget
// composition (CLAUDE.md §Code Reuse). Both `proxy_handler` (cooperative
// HTTP) and `tls_proxy_hyper::serve_mitm` (HTTPS) call this helper so
// the order — per-agent first, then global ceiling, with rollback of
// the per-agent reservation on global failure — is implemented exactly
// once. Drift between the two paths would mean an agent could escape
// per-agent quota by routing through MITM (or vice versa).

/// Outcome of a token-budget check.
pub enum BudgetCheckOutcome {
    /// All applicable budgets have headroom; reservations were taken
    /// and the request may proceed.
    Allowed,
    /// The agent's per-agent quota was exceeded. No global reservation
    /// was taken (per-agent fired first).
    PerAgentDenied(BudgetExceeded),
    /// The org-wide ceiling was exceeded. Any per-agent reservation
    /// taken in this call has already been rolled back.
    GlobalDenied(BudgetExceeded),
}

/// Two-tier token budget check + reservation. Returns
/// `BudgetCheckOutcome::Allowed` only when both the per-agent quota
/// and the global ceiling pass; on either failure, returns the
/// specific BudgetExceeded so callers can include accurate detail in
/// the 429 response.
///
/// Caller contract: the caller is responsible for releasing the
/// reservations later via `record()` or `release_reservation()` —
/// this function takes them, it does not own their lifecycle.
///
/// Idempotent for disabled budgets: if neither tier is enabled, returns
/// Allowed without touching state.
pub fn check_and_reserve_token_budget(state: &AppState, agent_id: &str) -> BudgetCheckOutcome {
    if state.per_agent_budgets.is_enabled() {
        if let Err(exceeded) = state.per_agent_budgets.check_and_reserve(agent_id) {
            return BudgetCheckOutcome::PerAgentDenied(exceeded);
        }
    }
    if state.token_budget.is_enabled() {
        if let Err(exceeded) = state.token_budget.check_and_reserve() {
            // Roll back the per-agent reservation we just took so the
            // failed global path doesn't double-charge the agent.
            if state.per_agent_budgets.is_enabled() {
                state.per_agent_budgets.release_reservation(agent_id);
            }
            return BudgetCheckOutcome::GlobalDenied(exceeded);
        }
    }
    BudgetCheckOutcome::Allowed
}
