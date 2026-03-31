#![no_main]
//! Fuzz target for ABAC policy evaluation.
//!
//! Feeds arbitrary operation metadata to PolicyEngine::evaluate().
//! Goals:
//! - No panics on any attribute combination
//! - No unbounded memory from crafted attribute values
//! - Deterministic: same input always produces same decision

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::OnceLock;

static ENGINE: OnceLock<gvm_proxy::policy::PolicyEngine> = OnceLock::new();

fn get_engine() -> &'static gvm_proxy::policy::PolicyEngine {
    ENGINE.get_or_init(|| {
        let dir = tempfile::tempdir().expect("temp dir");
        let dir = Box::leak(Box::new(dir));
        let policy_dir = dir.path().join("policies");
        std::fs::create_dir_all(&policy_dir).expect("create policy dir");

        // Policy rules that exercise condition evaluation edge cases:
        // numeric comparisons, string matching, regex, nested attributes
        std::fs::write(policy_dir.join("global.toml"), r#"
            [[rules]]
            id = "deny-critical-delete"
            priority = 100
            layer = "Global"
            description = "Block critical deletes"
            [rules.match]
            operation = { starts_with = "gvm.data.delete" }
            [rules.match.context]
            sensitivity = { equals = "critical" }
            [rules.decision]
            type = "Deny"
            reason = "Critical delete blocked"

            [[rules]]
            id = "delay-large-payment"
            priority = 90
            layer = "Global"
            description = "Delay large payments"
            [rules.match]
            operation = { starts_with = "gvm.banking" }
            [rules.match.context]
            amount = { greater_than = 10000 }
            [rules.decision]
            type = "Delay"
            milliseconds = 500

            [[rules]]
            id = "audit-messaging"
            priority = 80
            layer = "Global"
            description = "Audit all messaging"
            [rules.match]
            operation = { starts_with = "gvm.messaging" }
            [rules.decision]
            type = "AuditOnly"
            alert_level = "Medium"

            [[rules]]
            id = "allow-read"
            priority = 50
            layer = "Global"
            description = "Allow reads"
            [rules.match]
            operation = { ends_with = ".read" }
            [rules.decision]
            type = "Allow"
        "#).expect("write policy");

        gvm_proxy::policy::PolicyEngine::load(dir.path().join("policies").as_path())
            .expect("load policy engine")
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 || data.len() > 4096 {
        return;
    }

    // Split fuzz data into operation name and context attributes
    let split_point = (data[0] as usize) % data.len().max(1);
    let (op_bytes, ctx_bytes) = data.split_at(split_point.min(data.len()));

    let operation = match std::str::from_utf8(op_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(op_bytes).to_string(),
    };

    // Build context attributes from remaining bytes
    let mut attributes = HashMap::new();

    // Try to parse context bytes as JSON for richer attribute fuzzing
    if let Ok(json_str) = std::str::from_utf8(ctx_bytes) {
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(json_str) {
            for (k, v) in map {
                attributes.insert(k, v);
            }
        } else {
            // Fallback: use raw bytes as a string attribute
            attributes.insert("value".to_string(), serde_json::Value::String(json_str.to_string()));
        }
    }

    // Add numeric attribute if we have enough bytes (for greater_than/less_than conditions)
    if ctx_bytes.len() >= 8 {
        let num = i64::from_le_bytes([
            ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3],
            ctx_bytes[4], ctx_bytes[5], ctx_bytes[6], ctx_bytes[7],
        ]);
        attributes.insert("amount".to_string(), serde_json::json!(num));
    }

    let op = gvm_types::OperationMetadata {
        operation,
        resource: gvm_types::ResourceDescriptor {
            service: "fuzz".to_string(),
            identifier: None,
            tier: gvm_types::ResourceTier::Internal,
            sensitivity: gvm_types::Sensitivity::Low,
        },
        subject: gvm_types::SubjectDescriptor {
            agent_id: "fuzz-agent".to_string(),
            tenant_id: None,
            session_id: "fuzz-session".to_string(),
        },
        context: gvm_types::OperationContext { attributes },
        payload: gvm_types::PayloadDescriptor::default(),
    };

    // This must never panic and must be deterministic
    let (decision1, rule1) = get_engine().evaluate(&op);
    let (decision2, rule2) = get_engine().evaluate(&op);

    // Determinism check: same input → same output
    assert_eq!(
        format!("{:?}", decision1),
        format!("{:?}", decision2),
        "Policy evaluation must be deterministic"
    );
    assert_eq!(rule1, rule2, "Matched rule must be deterministic");
});
