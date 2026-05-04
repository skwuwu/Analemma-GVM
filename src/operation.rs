//! Phase 1.B helpers — build `OperationDescriptor` instances at
//! production event-creation sites.
//!
//! Production code that previously set `operation: format!("POST {}", path)`
//! now also populates `operation_descriptor: Some(make_http(method, path))`.
//! The legacy `operation: String` field is kept for v1-hash backward
//! compat (existing WAL records continue to verify); v2 hash uses the
//! descriptor when present.
//!
//! Salt generation: 16 random bytes per descriptor with `detail.is_some()`,
//! drawn from `rand::thread_rng()`. Category-only descriptors leave the
//! salt empty (the digest is the canonical "no detail" marker).

use gvm_types::OperationDescriptor;
use rand::RngCore;

/// Generate 16 random bytes for the per-event salt.
/// Production-only entry point — tests construct salts deterministically.
fn fresh_salt() -> Vec<u8> {
    let mut s = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

/// Build a descriptor with caller-supplied detail. Salt is freshly
/// generated when `detail` is `Some`. Use this at sites where the
/// detail is sensitive (URL path, DNS subdomain, vault key id).
pub fn descriptor(category: impl Into<String>, detail: Option<String>) -> OperationDescriptor {
    let salt = if detail.is_some() {
        fresh_salt()
    } else {
        Vec::new()
    };
    OperationDescriptor::new(category, detail, salt)
}

/// Build a category-only descriptor (no sensitive detail). Salt is
/// always empty; digest is the canonical "no detail" marker.
/// Use for operations whose name is itself the full disclosure
/// (e.g. `gvm.system.config_load`).
pub fn category_only(category: impl Into<String>) -> OperationDescriptor {
    OperationDescriptor::category_only(category)
}

/// Convenience: HTTP-style descriptor for proxy paths.
/// Category is `format!("http.{}", method)` (e.g. `http.POST`),
/// detail is the path (e.g. `/api/v1/user/1234`).
pub fn http(method: &str, path: &str) -> OperationDescriptor {
    descriptor(format!("http.{}", method), Some(path.to_string()))
}

/// CONNECT-tunnel descriptor. Category is `http.CONNECT`, detail is
/// the host:port target.
pub fn connect(host: &str) -> OperationDescriptor {
    descriptor("http.CONNECT", Some(host.to_string()))
}

/// WebSocket UPGRADE descriptor. Category is `ws.upgrade`, detail
/// is `"{method} {path}"` (the WebSocket handshake request line).
pub fn ws_upgrade(method: &str, path: &str) -> OperationDescriptor {
    descriptor("ws.upgrade", Some(format!("{} {}", method, path)))
}

/// Vault descriptor. Category is `gvm.vault.{op}` (e.g.
/// `gvm.vault.vault_write`), detail is the vault key id.
pub fn vault(operation: &str, key: &str) -> OperationDescriptor {
    descriptor(format!("gvm.vault.{}", operation), Some(key.to_string()))
}

/// DNS query descriptor. Category is `gvm.dns.query`, detail is
/// the queried domain name (subdomain may be sensitive — e.g.
/// `customer-12345.attacker.example`).
pub fn dns_query(domain: &str) -> OperationDescriptor {
    descriptor("gvm.dns.query", Some(domain.to_string()))
}

/// Sandbox launch descriptor — category-only.
///
/// The sandbox_id and ca_pubkey_hash live in the event's `context`
/// map (plaintext — not PII, and the chain walker needs to read them
/// directly), not in the operation detail. Pairs with
/// [`build_sandbox_launch_event`] which assembles the full event.
pub fn sandbox_launch() -> OperationDescriptor {
    category_only("gvm.sandbox.launch")
}

/// Build a fully populated `gvm.sandbox.launch` audit event.
///
/// **Why this event exists**: the per-sandbox MITM CA model
/// (`gvm_sandbox::ca::SandboxCA` + `CARegistry`) needs every
/// enforcement decision made under a given sandbox to be traceable
/// back to a Merkle-anchored record of "which CA's pubkey governed
/// this sandbox's TLS inspection at launch". This event is that
/// record. Subsequent events in the same sandbox set their
/// `parent_event_id` to this event's `event_id`, so a chain walker
/// traversing backward from any enforcement decision can recover the
/// launch context (sandbox_id, agent_id, ca_pubkey_hash, lifetime)
/// and verify that the cryptographic root was the one the operator
/// expected. See the CA-2 design notes in `docs/internal/CHANGELOG.md`.
///
/// `parent_event_id` is always `None` — sandbox launches are chain
/// roots. `event_hash` is `None` because the [`Ledger`] computes it
/// on append (Phase 1 of the v3 audit architecture).
///
/// The caller (proxy-side sandbox launch orchestrator) must:
/// 1. Generate the per-sandbox CA via
///    `gvm_sandbox::ca::CARegistry::provision`.
/// 2. Call this builder with the resulting CA's `pubkey_hash_hex()`
///    and `not_after()`.
/// 3. Stamp `config_integrity_ref` from the proxy's current
///    `AppState::current_integrity_ref()` so the event is bound to
///    the active policy version.
/// 4. `Ledger::append_durable` (fail-close) — if WAL append fails,
///    the sandbox launch must fail too. There must not be a sandbox
///    operating with MITM whose launch is not in the audit chain.
///
/// [`Ledger`]: crate::ledger::Ledger
pub fn build_sandbox_launch_event(
    sandbox_id: &str,
    agent_id: &str,
    ca_pubkey_hash_hex: &str,
    ca_not_after: chrono::DateTime<chrono::Utc>,
) -> gvm_types::GVMEvent {
    use gvm_types::{
        EventStatus, GVMEvent, PayloadDescriptor, ResourceDescriptor, ResourceTier, Sensitivity,
    };
    use std::collections::HashMap;

    let mut context = HashMap::new();
    context.insert(
        "sandbox_id".to_string(),
        serde_json::Value::String(sandbox_id.to_string()),
    );
    context.insert(
        "ca_pubkey_hash".to_string(),
        serde_json::Value::String(ca_pubkey_hash_hex.to_string()),
    );
    context.insert(
        "ca_not_after".to_string(),
        serde_json::Value::String(ca_not_after.to_rfc3339()),
    );
    context.insert(
        "tls_inspection".to_string(),
        serde_json::Value::String("active".to_string()),
    );

    GVMEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        trace_id: uuid::Uuid::new_v4().to_string(),
        parent_event_id: None, // chain root for this sandbox
        agent_id: agent_id.to_string(),
        tenant_id: None,
        session_id: sandbox_id.to_string(),
        timestamp: chrono::Utc::now(),
        operation: "gvm.sandbox.launch".to_string(),
        resource: ResourceDescriptor {
            service: "gvm".to_string(),
            identifier: Some(sandbox_id.to_string()),
            tier: ResourceTier::Internal,
            sensitivity: Sensitivity::Low,
        },
        context,
        transport: None,
        decision: "Allow".to_string(),
        decision_source: "system".to_string(),
        matched_rule_id: None,
        enforcement_point: "sandbox-launcher".to_string(),
        status: EventStatus::Confirmed,
        payload: PayloadDescriptor::default(),
        nats_sequence: None,
        event_hash: None, // Ledger fills in on append
        llm_trace: None,
        default_caution: false,
        config_integrity_ref: None, // caller stamps from AppState
        operation_descriptor: Some(sandbox_launch()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_descriptor_uses_method_in_category() {
        let d = http("POST", "/api/v1/x");
        assert_eq!(d.category, "http.POST");
        assert_eq!(d.detail.as_deref(), Some("/api/v1/x"));
        assert_eq!(d.detail_salt.len(), 16);
        assert!(d.verify_digest());
    }

    #[test]
    fn category_only_helpers_have_empty_salt() {
        let d = category_only("gvm.system.config_load");
        assert_eq!(d.category, "gvm.system.config_load");
        assert!(d.detail.is_none());
        assert!(d.detail_salt.is_empty());
    }

    #[test]
    fn fresh_salt_is_unique_across_calls() {
        // Sanity: thread_rng produces different bytes per call.
        // (Equality possible at 2^-128, vanishing for practical purposes.)
        let d1 = http("GET", "/x");
        let d2 = http("GET", "/x");
        assert_ne!(
            d1.detail_salt, d2.detail_salt,
            "fresh salt must differ across descriptor builds"
        );
        assert_ne!(
            d1.detail_digest, d2.detail_digest,
            "different salts must produce different digests"
        );
    }

    #[test]
    fn vault_descriptor_includes_operation_in_category() {
        let d = vault("vault_write", "agent-1:checkpoint:0");
        assert_eq!(d.category, "gvm.vault.vault_write");
        assert_eq!(d.detail.as_deref(), Some("agent-1:checkpoint:0"));
    }

    #[test]
    fn dns_query_descriptor_treats_domain_as_detail() {
        let d = dns_query("customer-12345.attacker.example");
        assert_eq!(d.category, "gvm.dns.query");
        assert_eq!(d.detail.as_deref(), Some("customer-12345.attacker.example"));
    }

    #[test]
    fn ws_upgrade_descriptor_concatenates_method_path() {
        let d = ws_upgrade("GET", "/v1/messages?stream=1");
        assert_eq!(d.category, "ws.upgrade");
        assert_eq!(d.detail.as_deref(), Some("GET /v1/messages?stream=1"));
    }

    // ─── Sandbox launch event (CA-2) ───────────────────────────────────

    #[test]
    fn sandbox_launch_descriptor_is_category_only() {
        let d = sandbox_launch();
        assert_eq!(d.category, "gvm.sandbox.launch");
        assert!(
            d.detail.is_none(),
            "category-only — sandbox_id lives in event.context, not detail"
        );
        assert!(d.detail_salt.is_empty());
    }

    #[test]
    fn sandbox_launch_event_carries_ca_binding_in_context() {
        let now = chrono::Utc::now();
        let event = build_sandbox_launch_event(
            "sb-test-001",
            "agent-1",
            "a3b1c2d4e5f6deadbeef1234567890abcdef00112233445566778899aabbccdd",
            now,
        );

        // Operation name + descriptor wired correctly.
        assert_eq!(event.operation, "gvm.sandbox.launch");
        assert_eq!(
            event.operation_descriptor.as_ref().unwrap().category,
            "gvm.sandbox.launch"
        );

        // The four binding fields are in context as plaintext.
        assert_eq!(
            event.context.get("sandbox_id").and_then(|v| v.as_str()),
            Some("sb-test-001")
        );
        assert_eq!(
            event.context.get("ca_pubkey_hash").and_then(|v| v.as_str()),
            Some("a3b1c2d4e5f6deadbeef1234567890abcdef00112233445566778899aabbccdd")
        );
        assert!(event.context.contains_key("ca_not_after"));
        assert_eq!(
            event.context.get("tls_inspection").and_then(|v| v.as_str()),
            Some("active")
        );

        // Chain root for this sandbox.
        assert!(event.parent_event_id.is_none());
        assert_eq!(event.session_id, "sb-test-001");
        assert_eq!(event.agent_id, "agent-1");

        // Ledger-filled fields are left None as documented.
        assert!(event.event_hash.is_none());
        assert!(event.config_integrity_ref.is_none());
    }

    #[test]
    fn sandbox_launch_event_uses_internal_resource_tier() {
        // gvm.sandbox.launch is an internal control-plane event,
        // not external traffic. Tier must be Internal so audit
        // tooling does not classify it alongside outbound HTTP.
        let now = chrono::Utc::now();
        let event = build_sandbox_launch_event("sb-tier", "agent-x", &"00".repeat(32), now);
        assert!(matches!(
            event.resource.tier,
            gvm_types::ResourceTier::Internal
        ));
        assert!(matches!(
            event.resource.sensitivity,
            gvm_types::Sensitivity::Low
        ));
    }

    #[test]
    fn sandbox_launch_event_ids_are_unique_per_call() {
        let now = chrono::Utc::now();
        let e1 = build_sandbox_launch_event("sb-a", "agent", &"00".repeat(32), now);
        let e2 = build_sandbox_launch_event("sb-a", "agent", &"00".repeat(32), now);
        assert_ne!(e1.event_id, e2.event_id);
        assert_ne!(e1.trace_id, e2.trace_id);
    }
}
