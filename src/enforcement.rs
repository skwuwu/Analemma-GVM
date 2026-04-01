//! Unified governance classification — shared between proxy_handler and MITM.
//!
//! Extracts ABAC + SRR + max_strict into a single function to ensure
//! enforcement parity across all request paths (HTTP proxy, MITM TLS).

use crate::proxy::AppState;
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

/// Classify a request through ABAC + SRR → max_strict.
///
/// Single source of truth for enforcement classification.
/// Called by both `proxy_handler` and `handle_mitm_stream`.
pub fn classify(state: &AppState, input: &ClassifyInput<'_>) -> Result<ClassifyOutput, String> {
    let (classification, is_default_caution) = if let Some(headers) = input.gvm_headers {
        // SDK-routed: Layer 1 ABAC + Layer 2 SRR → max_strict
        let operation = OperationMetadata {
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
        };

        let (policy_decision, matched_rule) = state
            .policy
            .read()
            .map_err(|_| "Policy lock poisoned".to_string())?
            .evaluate(&operation);

        let srr = state
            .srr
            .read()
            .map_err(|_| "SRR lock poisoned".to_string())?;
        let srr_result = srr.check(input.method, input.host, input.path, input.body);
        drop(srr);

        let final_decision = max_strict(srr_result.decision.clone(), policy_decision.clone());
        let srr_won = srr_result.decision.strictness() > policy_decision.strictness();
        let source = if srr_won {
            ClassificationSource::SRR
        } else {
            ClassificationSource::ABAC
        };
        let rule_id = if srr_won {
            srr_result.matched_description.clone()
        } else {
            matched_rule
        };

        (
            Classification {
                decision: final_decision,
                source,
                operation: Some(operation),
                matched_rule_id: rule_id,
            },
            srr_result.is_catch_all,
        )
    } else {
        // Direct HTTP / MITM: Layer 2 SRR only
        let srr = state
            .srr
            .read()
            .map_err(|_| "SRR lock poisoned".to_string())?;
        let srr_result = srr.check(input.method, input.host, input.path, input.body);
        drop(srr);

        (
            Classification {
                decision: srr_result.decision,
                source: ClassificationSource::SRR,
                operation: None,
                matched_rule_id: srr_result.matched_description,
            },
            srr_result.is_catch_all,
        )
    };

    let agent_id = input
        .gvm_headers
        .map(|h| h.agent_id.clone())
        .unwrap_or_else(|| "unknown".to_string());

    Ok(ClassifyOutput {
        classification,
        is_default_caution,
        agent_id,
    })
}
