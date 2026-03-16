//! GVM Governance Engine — Wasm-compatible policy evaluation module.
//!
//! This crate contains the core governance decision logic. It is designed to
//! compile to both native Rust and `wasm32-wasip1`, ensuring the policy
//! evaluation logic is **immutable** once deployed.
//!
//! # Security Model
//!
//! When compiled to Wasm and loaded via Wasmtime, the engine runs in a
//! memory-isolated sandbox. Even if the host proxy process is compromised,
//! the governance logic cannot be modified — it is a sealed, content-addressed
//! binary that the proxy verifies by hash before loading.
//!
//! # ABI
//!
//! The Wasm module exports:
//! - `evaluate(ptr, len) -> ptr` — evaluate a JSON policy request, return JSON result
//! - `engine_alloc(size) -> ptr` — allocate memory for the host to write input
//! - `engine_dealloc(ptr, len)` — free memory
//!
//! Input/output are JSON-encoded `EvalRequest` / `EvalResponse`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Public API Types ───

/// Policy evaluation request (JSON-serializable).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvalRequest {
    /// Operation name (e.g. "gvm.messaging.send")
    pub operation: String,
    /// Resource attributes
    pub resource: ResourceAttrs,
    /// Subject (who is performing the operation)
    pub subject: SubjectAttrs,
    /// Context attributes for ABAC condition matching (e.g., amount, currency).
    #[serde(default)]
    pub context: ContextAttrs,
    /// Rules to evaluate against
    pub rules: Vec<Rule>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ResourceAttrs {
    pub service: String,
    pub tier: String,
    pub sensitivity: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubjectAttrs {
    pub agent_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Context attributes for ABAC condition matching (e.g., amount, currency, time_of_day).
/// Flattened into the field map with "context." prefix so policies can match on
/// `context.amount > 500` or `context.currency == "USD"`.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ContextAttrs {
    #[serde(flatten)]
    pub attributes: std::collections::HashMap<String, serde_json::Value>,
}

/// A single policy rule.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub priority: u32,
    pub layer: String, // "global", "tenant", "agent"
    #[serde(default)]
    pub conditions: Vec<Condition>,
    pub decision: Decision,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Decision {
    #[serde(rename = "type")]
    pub decision_type: String, // "Allow", "Delay", "Deny", "RequireApproval"
    #[serde(default)]
    pub milliseconds: Option<u64>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Policy evaluation response.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvalResponse {
    /// Final decision: "Allow", "Delay", "Deny", "RequireApproval"
    pub decision: String,
    /// Milliseconds for Delay decisions
    pub delay_ms: Option<u64>,
    /// Reason for Deny/RequireApproval
    pub reason: Option<String>,
    /// ID of the rule that produced this decision
    pub matched_rule: Option<String>,
    /// Which policy layer matched: "global", "tenant", "agent"
    pub matched_layer: Option<String>,
    /// Engine version
    pub engine_version: String,
}

// ─── Core Evaluation Logic (pure, deterministic, no I/O) ───

/// Evaluate a policy request and return a decision.
/// This is the core governance function — deterministic and side-effect free.
pub fn evaluate(req: &EvalRequest) -> EvalResponse {
    let mut best_decision = "Allow".to_string();
    let mut best_strictness: u8 = 0;
    let mut matched_rule: Option<String> = None;
    let mut matched_layer: Option<String> = None;
    let mut delay_ms: Option<u64> = None;
    let mut reason: Option<String> = None;

    // Build field map for condition matching
    let fields = build_field_map(req);

    // Evaluate rules in priority order (pre-sorted by caller)
    // Hierarchy: global rules first, then tenant, then agent
    // Each layer can only make the decision STRICTER
    let layer_order = ["global", "tenant", "agent"];

    for layer in &layer_order {
        let layer_rules: Vec<&Rule> = req.rules.iter()
            .filter(|r| r.layer == *layer)
            .collect();

        // Sort by priority (ascending = higher priority first)
        let mut sorted = layer_rules;
        sorted.sort_by_key(|r| r.priority);

        for rule in &sorted {
            if rule_matches(rule, &fields) {
                let s = decision_strictness(&rule.decision.decision_type);

                // Global Deny → immediate return (cannot be overridden)
                if *layer == "global" && rule.decision.decision_type == "Deny" {
                    return EvalResponse {
                        decision: "Deny".to_string(),
                        delay_ms: None,
                        reason: rule.decision.reason.clone(),
                        matched_rule: Some(rule.id.clone()),
                        matched_layer: Some(layer.to_string()),
                        engine_version: engine_version(),
                    };
                }

                // Only accept if stricter than current best
                if s > best_strictness {
                    best_strictness = s;
                    best_decision = rule.decision.decision_type.clone();
                    matched_rule = Some(rule.id.clone());
                    matched_layer = Some(layer.to_string());
                    delay_ms = rule.decision.milliseconds;
                    reason = rule.decision.reason.clone();
                }

                break; // First match per layer wins (priority-sorted)
            }
        }
    }

    EvalResponse {
        decision: best_decision,
        delay_ms,
        reason,
        matched_rule,
        matched_layer,
        engine_version: engine_version(),
    }
}

/// Evaluate a JSON string and return a JSON string.
/// This is the Wasm-friendly entry point.
pub fn evaluate_json(input: &str) -> String {
    match serde_json::from_str::<EvalRequest>(input) {
        Ok(req) => {
            let resp = evaluate(&req);
            serde_json::to_string(&resp).unwrap_or_else(|e| {
                let error_msg = format!("serialization failed: {}", e);
                serde_json::json!({"error": error_msg}).to_string()
            })
        }
        Err(e) => {
            // Use serde_json to properly escape the error message
            let error_msg = format!("invalid input: {}", e);
            serde_json::json!({"error": error_msg}).to_string()
        }
    }
}

fn engine_version() -> String {
    "0.1.0-wasm".to_string()
}

fn decision_strictness(decision_type: &str) -> u8 {
    match decision_type {
        "Allow" => 0,
        "AuditOnly" => 1,
        "Throttle" => 2,
        "Delay" => 3,
        "RequireApproval" => 4,
        "Deny" => 5,
        // Fail-close: unknown decision types are treated as maximally strict
        _ => 5,
    }
}

// ─── Condition Matching ───

/// Build a flat field map from the request for condition matching.
///
/// Includes context attributes flattened with "context." prefix so that
/// Wasm policy rules can match on `context.amount`, `context.currency`, etc.
/// This mirrors the host-side policy engine's `resolve_field()` behavior.
fn build_field_map(req: &EvalRequest) -> HashMap<String, serde_json::Value> {
    let mut m = HashMap::new();
    m.insert("operation".to_string(), serde_json::Value::String(req.operation.clone()));
    m.insert("resource.service".to_string(), serde_json::Value::String(req.resource.service.clone()));
    m.insert("resource.tier".to_string(), serde_json::Value::String(req.resource.tier.clone()));
    m.insert("resource.sensitivity".to_string(), serde_json::Value::String(req.resource.sensitivity.clone()));
    m.insert("subject.agent_id".to_string(), serde_json::Value::String(req.subject.agent_id.clone()));
    if let Some(ref tid) = req.subject.tenant_id {
        m.insert("subject.tenant_id".to_string(), serde_json::Value::String(tid.clone()));
    }
    // Flatten context attributes with "context." prefix
    for (key, value) in &req.context.attributes {
        m.insert(format!("context.{}", key), value.clone());
    }
    m
}

fn rule_matches(rule: &Rule, fields: &HashMap<String, serde_json::Value>) -> bool {
    // Empty conditions = always matches
    if rule.conditions.is_empty() {
        return true;
    }
    // All conditions must match (AND)
    rule.conditions.iter().all(|c| condition_matches(c, fields))
}

fn condition_matches(cond: &Condition, fields: &HashMap<String, serde_json::Value>) -> bool {
    let field_val = match fields.get(&cond.field) {
        Some(v) => v,
        None => return false,
    };

    // Normalize operator to lowercase for case-insensitive matching.
    // The host policy.rs uses PascalCase ("Eq", "StartsWith") while the
    // canonical Wasm format is snake_case ("eq", "starts_with"). Accepting
    // both prevents silent Fail-Close when operators are passed without
    // case conversion.
    let op_lower = cond.operator.to_lowercase();
    match op_lower.as_str() {
        "eq" | "==" => field_val == &cond.value,
        "noteq" | "neq" | "!=" => field_val != &cond.value,
        "contains" => {
            if let (Some(haystack), Some(needle)) = (field_val.as_str(), cond.value.as_str()) {
                haystack.contains(needle)
            } else {
                false
            }
        }
        "startswith" | "starts_with" => {
            if let (Some(haystack), Some(needle)) = (field_val.as_str(), cond.value.as_str()) {
                haystack.starts_with(needle)
            } else {
                false
            }
        }
        "endswith" | "ends_with" => {
            if let (Some(haystack), Some(needle)) = (field_val.as_str(), cond.value.as_str()) {
                haystack.ends_with(needle)
            } else {
                false
            }
        }
        "in" => {
            if let Some(arr) = cond.value.as_array() {
                arr.contains(field_val)
            } else {
                false
            }
        }
        "notin" | "not_in" => {
            if let Some(arr) = cond.value.as_array() {
                !arr.contains(field_val)
            } else {
                true
            }
        }
        // Numeric comparisons (snake_case canonical, symbols accepted)
        "gt" | ">" => compare_numeric(field_val, &cond.value, |a, b| a > b),
        "gte" | ">=" => compare_numeric(field_val, &cond.value, |a, b| a >= b),
        "lt" | "<" => compare_numeric(field_val, &cond.value, |a, b| a < b),
        "lte" | "<=" => compare_numeric(field_val, &cond.value, |a, b| a <= b),
        // Fail-close: unknown operators never match (prevents accidental allow)
        _ => false,
    }
}

fn compare_numeric(a: &serde_json::Value, b: &serde_json::Value, cmp: fn(f64, f64) -> bool) -> bool {
    let av = a.as_f64().or_else(|| a.as_str().and_then(|s| s.parse().ok()));
    let bv = b.as_f64().or_else(|| b.as_str().and_then(|s| s.parse().ok()));
    match (av, bv) {
        (Some(a), Some(b)) => cmp(a, b),
        _ => false,
    }
}

// ─── Wasm FFI Exports ───

#[cfg(target_arch = "wasm32")]
mod wasm_ffi {
    use super::*;
    use std::alloc::{alloc, dealloc, Layout};

    /// Allocate memory for the host to write input.
    #[no_mangle]
    pub extern "C" fn engine_alloc(size: u32) -> *mut u8 {
        let layout = Layout::from_size_align(size as usize, 1).expect("layout with align=1 is always valid for non-zero size");
        unsafe { alloc(layout) }
    }

    /// Free memory.
    #[no_mangle]
    pub extern "C" fn engine_dealloc(ptr: *mut u8, size: u32) {
        let layout = Layout::from_size_align(size as usize, 1).expect("layout with align=1 is always valid for non-zero size");
        unsafe { dealloc(ptr, layout) }
    }

    /// Evaluate a policy request. Input: JSON at (ptr, len). Returns pointer
    /// to response (first 4 bytes = little-endian u32 JSON length, then JSON bytes).
    ///
    /// # Memory Contract
    /// The returned pointer is allocated via `engine_alloc`. The **host** is
    /// responsible for freeing it by calling:
    ///   `engine_dealloc(result_ptr, 4 + json_len)`
    /// where `json_len` is read from the first 4 bytes of the result.
    /// Failure to deallocate will leak Wasm linear memory.
    #[no_mangle]
    pub extern "C" fn engine_evaluate(ptr: *const u8, len: u32) -> *const u8 {
        let input = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
        let input_str = match std::str::from_utf8(input) {
            Ok(s) => s,
            Err(_) => {
                // Fail-close: invalid UTF-8 input → return explicit error, not "{}"
                let error_output = r#"{"error":"invalid UTF-8 input"}"#;
                let error_bytes = error_output.as_bytes();
                let total = 4 + error_bytes.len();
                let layout = Layout::from_size_align(total, 1).expect("error response layout with align=1 cannot fail");
                let err_ptr = unsafe { alloc(layout) };
                let len_bytes = (error_bytes.len() as u32).to_le_bytes();
                unsafe {
                    std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), err_ptr, 4);
                    std::ptr::copy_nonoverlapping(error_bytes.as_ptr(), err_ptr.add(4), error_bytes.len());
                }
                return err_ptr;
            }
        };

        let output = evaluate_json(input_str);
        let output_bytes = output.as_bytes();
        let total_len = 4 + output_bytes.len();

        let layout = Layout::from_size_align(total_len, 1).expect("response layout with align=1 cannot fail");
        let result_ptr = unsafe { alloc(layout) };

        // Write length prefix (little-endian u32)
        let len_bytes = (output_bytes.len() as u32).to_le_bytes();
        unsafe {
            std::ptr::copy_nonoverlapping(len_bytes.as_ptr(), result_ptr, 4);
            std::ptr::copy_nonoverlapping(output_bytes.as_ptr(), result_ptr.add(4), output_bytes.len());
        }

        result_ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(op: &str, sensitivity: &str, rules: Vec<Rule>) -> EvalRequest {
        EvalRequest {
            operation: op.to_string(),
            resource: ResourceAttrs {
                service: "gmail".to_string(),
                tier: "external".to_string(),
                sensitivity: sensitivity.to_string(),
            },
            subject: SubjectAttrs {
                agent_id: "test-agent".to_string(),
                tenant_id: None,
            },
            context: ContextAttrs::default(),
            rules,
        }
    }

    #[test]
    fn test_allow_when_no_rules() {
        let req = make_request("gvm.messaging.read", "low", vec![]);
        let resp = evaluate(&req);
        assert_eq!(resp.decision, "Allow");
    }

    #[test]
    fn test_deny_critical_delete() {
        let req = make_request("gvm.storage.delete", "critical", vec![
            Rule {
                id: "deny-critical-delete".to_string(),
                priority: 1,
                layer: "global".to_string(),
                conditions: vec![
                    Condition {
                        field: "resource.sensitivity".to_string(),
                        operator: "eq".to_string(),
                        value: serde_json::Value::String("critical".to_string()),
                    },
                    Condition {
                        field: "operation".to_string(),
                        operator: "starts_with".to_string(),
                        value: serde_json::Value::String("gvm.storage.delete".to_string()),
                    },
                ],
                decision: Decision {
                    decision_type: "Deny".to_string(),
                    milliseconds: None,
                    reason: Some("Critical data deletion forbidden".to_string()),
                },
            },
        ]);
        let resp = evaluate(&req);
        assert_eq!(resp.decision, "Deny");
        assert_eq!(resp.matched_rule.as_deref(), Some("deny-critical-delete"));
    }

    #[test]
    fn test_delay_medium_send() {
        let req = make_request("gvm.messaging.send", "medium", vec![
            Rule {
                id: "delay-send".to_string(),
                priority: 10,
                layer: "global".to_string(),
                conditions: vec![
                    Condition {
                        field: "operation".to_string(),
                        operator: "starts_with".to_string(),
                        value: serde_json::Value::String("gvm.messaging.send".to_string()),
                    },
                ],
                decision: Decision {
                    decision_type: "Delay".to_string(),
                    milliseconds: Some(300),
                    reason: None,
                },
            },
        ]);
        let resp = evaluate(&req);
        assert_eq!(resp.decision, "Delay");
        assert_eq!(resp.delay_ms, Some(300));
    }

    #[test]
    fn test_json_roundtrip() {
        let input = r#"{
            "operation": "gvm.messaging.read",
            "resource": {"service":"gmail","tier":"external","sensitivity":"low"},
            "subject": {"agent_id":"test"},
            "rules": []
        }"#;
        let output = evaluate_json(input);
        let resp: EvalResponse = serde_json::from_str(&output).expect("evaluate_json must return valid JSON");
        assert_eq!(resp.decision, "Allow");
        assert_eq!(resp.engine_version, "0.1.0-wasm");
    }

    #[test]
    fn test_pascal_case_operators_accepted() {
        // Host policy.rs sends PascalCase operators ("Eq", "StartsWith").
        // Wasm engine must accept them via case normalization.
        let req = make_request("gvm.messaging.send", "medium", vec![
            Rule {
                id: "pascal-delay".to_string(),
                priority: 10,
                layer: "global".to_string(),
                conditions: vec![
                    Condition {
                        field: "operation".to_string(),
                        operator: "StartsWith".to_string(),  // PascalCase
                        value: serde_json::Value::String("gvm.messaging".to_string()),
                    },
                    Condition {
                        field: "resource.sensitivity".to_string(),
                        operator: "Eq".to_string(),  // PascalCase
                        value: serde_json::Value::String("medium".to_string()),
                    },
                ],
                decision: Decision {
                    decision_type: "Delay".to_string(),
                    milliseconds: Some(300),
                    reason: None,
                },
            },
        ]);
        let resp = evaluate(&req);
        assert_eq!(resp.decision, "Delay");
        assert_eq!(resp.matched_rule.as_deref(), Some("pascal-delay"));
    }

    #[test]
    fn test_context_attribute_matching() {
        let mut ctx = ContextAttrs::default();
        ctx.attributes.insert("amount".to_string(), serde_json::json!(1500));
        ctx.attributes.insert("currency".to_string(), serde_json::json!("USD"));

        let req = EvalRequest {
            operation: "gvm.payment.charge".to_string(),
            resource: ResourceAttrs {
                service: "stripe".to_string(),
                tier: "external".to_string(),
                sensitivity: "high".to_string(),
            },
            subject: SubjectAttrs {
                agent_id: "test-agent".to_string(),
                tenant_id: None,
            },
            context: ctx,
            rules: vec![Rule {
                id: "deny-large-payment".to_string(),
                priority: 1,
                layer: "global".to_string(),
                conditions: vec![Condition {
                    field: "context.amount".to_string(),
                    operator: "gt".to_string(),
                    value: serde_json::json!(1000),
                }],
                decision: Decision {
                    decision_type: "Deny".to_string(),
                    milliseconds: None,
                    reason: Some("Payment exceeds limit".to_string()),
                },
            }],
        };
        let resp = evaluate(&req);
        assert_eq!(resp.decision, "Deny");
        assert_eq!(resp.matched_rule.as_deref(), Some("deny-large-payment"));
    }

    #[test]
    fn test_strictest_wins_across_layers() {
        let req = EvalRequest {
            operation: "gvm.messaging.send".to_string(),
            resource: ResourceAttrs {
                service: "gmail".to_string(),
                tier: "customer-facing".to_string(),
                sensitivity: "medium".to_string(),
            },
            subject: SubjectAttrs {
                agent_id: "test-agent".to_string(),
                tenant_id: Some("acme".to_string()),
            },
            context: ContextAttrs::default(),
            rules: vec![
                Rule {
                    id: "global-delay".to_string(),
                    priority: 10,
                    layer: "global".to_string(),
                    conditions: vec![],
                    decision: Decision {
                        decision_type: "Delay".to_string(),
                        milliseconds: Some(300),
                        reason: None,
                    },
                },
                Rule {
                    id: "tenant-deny".to_string(),
                    priority: 10,
                    layer: "tenant".to_string(),
                    conditions: vec![],
                    decision: Decision {
                        decision_type: "Deny".to_string(),
                        milliseconds: None,
                        reason: Some("Tenant policy blocks this".to_string()),
                    },
                },
            ],
        };
        let resp = evaluate(&req);
        assert_eq!(resp.decision, "Deny");
        assert_eq!(resp.matched_layer.as_deref(), Some("tenant"));
    }
}
