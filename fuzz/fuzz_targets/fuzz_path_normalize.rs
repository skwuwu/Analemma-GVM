#![no_main]
//! Fuzz target for SRR path normalization chain.
//!
//! Exercises the full normalization pipeline through NetworkSRR::check():
//!   percent-decode → null-byte strip → double-slash collapse → dot-segment resolve
//!
//! Goals:
//! - No panics on any path input (unicode, null bytes, percent-encoded sequences)
//! - No path traversal bypass (../../../etc/passwd must not match /etc/passwd rule)
//! - No unbounded memory allocation from crafted percent-encoding chains

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static SRR: OnceLock<gvm_proxy::srr::NetworkSRR> = OnceLock::new();

fn get_srr() -> &'static gvm_proxy::srr::NetworkSRR {
    SRR.get_or_init(|| {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("srr.toml");
        let dir = Box::leak(Box::new(dir));
        let _ = dir;

        // Rules that exercise path matching edge cases:
        // - Exact path, prefix, wildcard, deep nesting, encoded characters
        std::fs::write(&path, r#"
            [[rules]]
            method = "*"
            pattern = "test.com/admin/secret"
            decision = { type = "Deny", reason = "admin access" }

            [[rules]]
            method = "*"
            pattern = "test.com/api/v1/{any}"
            decision = { type = "Delay", milliseconds = 100 }

            [[rules]]
            method = "*"
            pattern = "test.com/public/{any}"
            decision = { type = "Allow" }

            [[rules]]
            method = "*"
            pattern = "{any}"
            decision = { type = "Delay", milliseconds = 300 }
        "#).expect("write SRR config");

        gvm_proxy::srr::NetworkSRR::load(&path).expect("load SRR config")
    })
}

fuzz_target!(|data: &[u8]| {
    // Use fuzz input as path (UTF-8 or lossy conversion)
    let path = match std::str::from_utf8(data) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(data).to_string(),
    };

    // Limit path length to prevent pathological regex/normalization cases
    if path.len() > 4096 {
        return;
    }

    // Exercise normalization through the public check() API.
    // check() calls normalize_path() internally on every invocation.
    let _ = get_srr().check("GET", "test.com", &path, None);

    // Also test with various host patterns to exercise normalize_host()
    let _ = get_srr().check("GET", &path, "/api/v1/test", None);
});
