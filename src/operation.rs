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
}
