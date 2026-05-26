//! SRR / classifier evasion regression suite — Phase 3 of the pentest plan.
//!
//! Targets the engine surface at `gvm_proxy::srr::NetworkSRR::check`. Each
//! test loads a tiny inline SRR config containing a single Deny rule, then
//! issues a request whose surface form has been adversarially transformed
//! to dodge that rule. The assertion is that the engine, after path/host
//! normalization, still matches and applies the Deny.
//!
//! These tests cover the *engine* layer; they complement (and do not
//! duplicate) the host-case / null-byte / unicode coverage in
//! `tests/hostile.rs` and the GraphQL-aliasing coverage in
//! `tests/graphql_alias_*.rs`.
//!
//! All tests are pure-Rust and run on every platform under `cargo test`.

use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::EnforcementDecision;

/// Build an in-memory SRR from inline TOML. Mirrors the helper pattern used
/// across `tests/hostile.rs` and `tests/srr_time_window.rs` (TOML → temp
/// file → `NetworkSRR::load`).
fn srr_from_toml(toml_str: &str) -> NetworkSRR {
    let dir = tempfile::tempdir().expect("temp dir creation must succeed");
    let path = dir.path().join("srr.toml");
    std::fs::write(&path, toml_str).expect("writing SRR config to temp file must succeed");
    NetworkSRR::load(&path).expect("inline SRR TOML must parse")
}

/// Assert the check decision is a Deny. Includes the matched rule (if any)
/// in the failure message so a regression points back at the rule that
/// SHOULD have fired but didn't.
fn assert_deny(srr: &NetworkSRR, method: &str, host: &str, path: &str, ctx: &str) {
    let result = srr.check(method, host, path, None);
    assert!(
        matches!(result.decision, EnforcementDecision::Deny { .. }),
        "{ctx}: expected Deny, got {:?} (matched: {:?})",
        result.decision,
        result.matched_description
    );
}

fn assert_deny_with_body(
    srr: &NetworkSRR,
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
    ctx: &str,
) {
    let result = srr.check(method, host, path, Some(body));
    assert!(
        matches!(result.decision, EnforcementDecision::Deny { .. }),
        "{ctx}: expected Deny, got {:?} (matched: {:?}, body_len={})",
        result.decision,
        result.matched_description,
        body.len()
    );
}

fn assert_not_deny(
    srr: &NetworkSRR,
    method: &str,
    host: &str,
    path: &str,
    body: Option<&[u8]>,
    ctx: &str,
) {
    let result = srr.check(method, host, path, body);
    assert!(
        !matches!(result.decision, EnforcementDecision::Deny { .. }),
        "{ctx}: expected non-Deny, got {:?}",
        result.decision
    );
}

/// Canonical SRR config used by most tests: deny POST anywhere under
/// `api.bank.com/admin*`. The trailing `*` makes this a prefix rule, so a
/// request whose canonical path is `/admin` (exact) or any path starting
/// with `/admin` (e.g. `/admin/secrets`, `/admin.txt`, `/admin/`) all
/// trigger the Deny. This is the realistic shape of a "block the admin
/// namespace" rule; an attacker who can mutate the surface form of the
/// request must still land inside this namespace after normalization.
const ADMIN_DENY_TOML: &str = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/admin*"
decision = { type = "Deny", reason = "Admin endpoint blocked" }
"#;

// ─── Case 1: URL-encoded path traversal normalized to canonical ────────────

#[test]
fn url_encoded_path_traversal_still_denied() {
    let srr = srr_from_toml(ADMIN_DENY_TOML);
    // Encoded dot-dots that resolve to `/admin`. Without percent decoding,
    // these would look like literal path components and never match a Deny
    // for `/admin`. The engine's normalize_path() must percent-decode and
    // then resolve dot segments before pattern matching.
    let evasions = [
        "/public/%2e%2e/admin",
        "/public/%2E%2E/admin",
        "/public/..%2f..%2fadmin",
    ];
    for path in evasions {
        assert_deny(&srr, "POST", "api.bank.com", path, &format!("path={path}"));
    }
}

// ─── Case 2: Double percent-encoding still resolved by 3-pass decoder ──────

#[test]
fn double_encoded_path_traversal_still_denied() {
    let srr = srr_from_toml(ADMIN_DENY_TOML);
    // First pass: `%252e` → `%2e`, `%252f` → `%2f`. Second pass: `%2e` → `.`,
    // `%2f` → `/`. Third pass would catch even deeper layers. The 3-pass
    // percent decoder in normalize.rs must collapse all encoding depths
    // before dot-segment resolution.
    let evasions = [
        "/public/%252e%252e/admin",     // 2x-encoded dot-dot
        "/public/%252E%252E%252Fadmin", // 2x-encoded with uppercase hex + encoded slash
    ];
    for path in evasions {
        assert_deny(&srr, "POST", "api.bank.com", path, &format!("path={path}"));
    }
}

// ─── Case 3: Null byte injection does not truncate match ───────────────────

#[test]
fn null_byte_in_path_does_not_truncate_match() {
    let srr = srr_from_toml(ADMIN_DENY_TOML);
    // `%00` decodes to a null byte; the engine then strips null bytes from
    // the path before matching, so `/admin%00.txt` becomes `/admin.txt`,
    // which matches the prefix rule `/admin`.
    // Also test the raw-null path: `/admin\0/bypass`. Both must Deny.
    assert_deny(
        &srr,
        "POST",
        "api.bank.com",
        "/admin%00.txt",
        "null in encoded form",
    );
    assert_deny(
        &srr,
        "POST",
        "api.bank.com",
        "/admin\0/bypass",
        "raw null byte",
    );
}

// ─── Case 4: Lowercase method matches uppercase rule ───────────────────────

#[test]
fn lowercase_method_matches_uppercase_rule() {
    let srr = srr_from_toml(ADMIN_DENY_TOML);
    // SRR storage is uppercase; check() uppercases the incoming method.
    // A lowercase method must NOT be treated as a different method.
    for method in ["post", "Post", "pOsT"] {
        assert_deny(
            &srr,
            method,
            "api.bank.com",
            "/admin",
            &format!("method={method}"),
        );
    }
}

// ─── Case 5: Consecutive slashes collapse to single ────────────────────────

#[test]
fn consecutive_slashes_in_path_collapsed_to_single() {
    let srr = srr_from_toml(ADMIN_DENY_TOML);
    // Double/triple slashes are a classic CDN-bypass vector — origin servers
    // often treat `/admin` and `///admin` as the same resource, while edge
    // matchers do not. The engine must collapse them before matching.
    assert_deny(&srr, "POST", "api.bank.com", "//admin", "double slash");
    assert_deny(&srr, "POST", "api.bank.com", "///admin", "triple slash");
    assert_deny(
        &srr,
        "POST",
        "api.bank.com",
        "/admin//",
        "trailing double slash",
    );
}

// ─── Case 6: Trailing dot segment resolves before match ────────────────────

#[test]
fn trailing_dot_segment_resolved_before_match() {
    let srr = srr_from_toml(ADMIN_DENY_TOML);
    // `/admin/.` and `/admin/` must both reduce to the canonical path the
    // rule expects. RFC 3986 §5.2.4 specifies that `/.`, `/./`, `/..`, and
    // `/../` are removed during normalization.
    assert_deny(&srr, "POST", "api.bank.com", "/admin/.", "trailing /.");
    assert_deny(&srr, "POST", "api.bank.com", "/admin/./", "trailing /./");
    assert_deny(
        &srr,
        "POST",
        "api.bank.com",
        "/foo/../admin",
        "back-up via /..",
    );
}

// ─── Case 7: Body at exactly max_body_bytes is inspected ───────────────────

#[test]
fn body_at_exact_max_size_inspected() {
    // Rule with a small explicit `max_body_bytes` so we can construct a body
    // at exactly the boundary without allocating MB of memory.
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.example.com/graphql"
payload_field = "op"
payload_match = ["drop_table"]
max_body_bytes = 1024
decision = { type = "Deny", reason = "Drop denied" }
"#;
    let srr = srr_from_toml(toml);

    // Build a JSON body whose total length is exactly 1024 bytes and which
    // contains the matching `op` field. The engine inspects bodies whose
    // size is <= max_body_bytes (strict `>` in src/srr/mod.rs:804).
    let prefix = r#"{"op":"drop_table","pad":""#;
    let suffix = r#""}"#;
    let pad_len = 1024 - prefix.len() - suffix.len();
    let pad = "x".repeat(pad_len);
    let body = format!("{prefix}{pad}{suffix}");
    assert_eq!(body.len(), 1024, "test fixture must be exactly 1024 bytes");

    assert_deny_with_body(
        &srr,
        "POST",
        "api.example.com",
        "/graphql",
        body.as_bytes(),
        "body at exact max_body_bytes",
    );
}

// ─── Case 8: Body one byte over max_body_bytes is NOT inspected ────────────

#[test]
fn body_one_byte_over_max_size_skipped() {
    // Same rule shape as Case 7, but body length = max_body_bytes + 1. The
    // engine skips payload inspection for this rule (per the explicit
    // `>` check at src/srr/mod.rs:804) and falls through. With no other
    // matching rule, the engine returns Default-to-Caution (not Deny).
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.example.com/graphql"
payload_field = "op"
payload_match = ["drop_table"]
max_body_bytes = 1024
decision = { type = "Deny", reason = "Drop denied" }
"#;
    let srr = srr_from_toml(toml);

    let prefix = r#"{"op":"drop_table","pad":""#;
    let suffix = r#""}"#;
    let pad_len = 1024 - prefix.len() - suffix.len() + 1;
    let pad = "x".repeat(pad_len);
    let body = format!("{prefix}{pad}{suffix}");
    assert_eq!(
        body.len(),
        1025,
        "test fixture must be exactly max_body_bytes + 1"
    );

    // The Deny rule must NOT fire — the body exceeds its inspection limit.
    // This documents the size-bypass surface: an attacker who can grow
    // their body past max_body_bytes evades payload inspection for that
    // rule. (URL-only rules covering the same endpoint still apply.)
    assert_not_deny(
        &srr,
        "POST",
        "api.example.com",
        "/graphql",
        Some(body.as_bytes()),
        "body one byte over max_body_bytes",
    );
}

// ─── Case 9: Base64-encoded JSON body still triggers payload rule ──────────

#[test]
fn base64_encoded_body_still_inspected() {
    // The engine tries plain JSON parse first, then falls back to
    // base64-decoding the body and parsing that as JSON (src/srr/mod.rs:820).
    // An attacker who base64-wraps a hostile JSON envelope must still be
    // caught.
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.example.com/graphql"
payload_field = "op"
payload_match = ["drop_table"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Drop denied" }
"#;
    let srr = srr_from_toml(toml);

    use base64::Engine;
    let inner = br#"{"op":"drop_table"}"#;
    let wrapped = base64::engine::general_purpose::STANDARD.encode(inner);
    assert_deny_with_body(
        &srr,
        "POST",
        "api.example.com",
        "/graphql",
        wrapped.as_bytes(),
        "base64-wrapped JSON body",
    );
}

// ─── Case 10: Base64-encoded field value still triggers payload rule ──────

#[test]
fn base64_encoded_field_value_still_inspected() {
    // Second base64 defense layer (src/srr/mod.rs:856): even when the body
    // parses as plain JSON, the engine ALSO tries to base64-decode the
    // target field's string value and look for the match inside. So an
    // attacker who base64-encodes the SENSITIVE token but leaves the
    // envelope plaintext is still caught.
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.example.com/cmd"
payload_field = "cmd"
payload_match = ["exfiltrate"]
max_body_bytes = 65536
decision = { type = "Deny", reason = "Exfiltration blocked" }
"#;
    let srr = srr_from_toml(toml);

    use base64::Engine;
    let secret = b"exfiltrate";
    let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
    let body = format!("{{\"cmd\":\"{encoded}\"}}");
    assert_deny_with_body(
        &srr,
        "POST",
        "api.example.com",
        "/cmd",
        body.as_bytes(),
        "base64-wrapped field value",
    );
}

// ─── Documented structural gaps (asserted, but #[ignore]'d) ────────────────
//
// The two tests below assert that a STRUCTURAL bypass currently SUCCEEDS.
// They're marked `#[ignore]` so CI doesn't fail on them, but they're
// runnable on demand with `cargo test --test srr_evasion_adversarial --
// --ignored`. If the engine ever adds case-insensitive JSON key lookup or
// recursive payload-field search, these tests will start failing — that's
// the signal to flip them into positive-defense tests.
//
// **Exploitability caveat.** Both bypasses require the upstream API to
// also accept the non-canonical envelope. A real GraphQL server rejects
// `{"OperationName":...}` (case-sensitive per spec) and `{"data":{...}}`
// wrappers (schema mismatch), so the bypass only matters for permissive
// internal APIs. Operators relying on SRR as defense-in-depth on such
// APIs should know about this.

/// PROBE: SRR payload_field is case-sensitive. `OperationName` evades a
/// rule written for `operationName`. The engine falls through to
/// Default-to-Caution (Delay 300ms) instead of Deny.
#[test]
#[ignore = "documents structural bypass — payload_field key match is case-sensitive"]
fn structural_bypass_case_variant_envelope_key_evades_payload_rule() {
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/graphql"
payload_field = "operationName"
payload_match = ["TransferFunds"]
decision = { type = "Deny", reason = "Transfer denied" }
"#;
    let srr = srr_from_toml(toml);

    // Sanity: canonical key DOES trigger Deny.
    let canon = srr.check(
        "POST",
        "api.bank.com",
        "/graphql",
        Some(br#"{"operationName":"TransferFunds"}"#),
    );
    assert!(
        matches!(canon.decision, EnforcementDecision::Deny { .. }),
        "Canonical envelope key must Deny (sanity); got {:?}",
        canon.decision
    );

    // Bypass: capitalise the key.
    let result = srr.check(
        "POST",
        "api.bank.com",
        "/graphql",
        Some(br#"{"OperationName":"TransferFunds"}"#),
    );
    assert!(
        !matches!(result.decision, EnforcementDecision::Deny { .. }),
        "structural bypass should currently succeed (engine has no case-folding \
         on JSON keys); if this test starts failing, the engine has been \
         hardened — flip the assertion to assert Deny."
    );
}

/// PROBE: SRR payload_field only looks at top-level JSON keys. Burying the
/// matched field one level deep in a wrapper object evades the rule.
#[test]
#[ignore = "documents structural bypass — payload_field lookup is top-level only"]
fn structural_bypass_nested_payload_field_evades_payload_rule() {
    let toml = r#"
[[rules]]
method = "POST"
pattern = "api.bank.com/cmd"
payload_field = "op"
payload_match = ["drop_table"]
decision = { type = "Deny", reason = "Drop denied" }
"#;
    let srr = srr_from_toml(toml);

    // Sanity: top-level field DOES trigger Deny.
    let canon = srr.check(
        "POST",
        "api.bank.com",
        "/cmd",
        Some(br#"{"op":"drop_table"}"#),
    );
    assert!(
        matches!(canon.decision, EnforcementDecision::Deny { .. }),
        "Top-level field must Deny (sanity); got {:?}",
        canon.decision
    );

    // Bypass: wrap the field inside a parent object.
    let result = srr.check(
        "POST",
        "api.bank.com",
        "/cmd",
        Some(br#"{"data":{"op":"drop_table"}}"#),
    );
    assert!(
        !matches!(result.decision, EnforcementDecision::Deny { .. }),
        "structural bypass should currently succeed (engine doesn't recurse \
         into nested objects); if this test starts failing, the engine has \
         been hardened — flip the assertion to assert Deny."
    );
}
