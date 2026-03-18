#![no_main]
//! Fuzz target for SRR (Static Request Rules) pattern matching.
//!
//! Feeds arbitrary method/host/path/body combinations into NetworkSRR::check().
//! Goals:
//! - No panics on any input
//! - No unbounded memory allocation
//! - No regex catastrophic backtracking (timeout = implicit failure)

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static SRR: OnceLock<gvm_proxy::srr::NetworkSRR> = OnceLock::new();

fn get_srr() -> &'static gvm_proxy::srr::NetworkSRR {
    SRR.get_or_init(|| {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("srr.toml");
        // Intentionally leak the tempdir so the file persists for the fuzzer's lifetime
        let dir = Box::leak(Box::new(dir));
        let _ = dir;

        std::fs::write(&path, r#"
            [[rules]]
            method = "POST"
            pattern = "api.bank.com/transfer/{any}"
            decision = { type = "Deny", reason = "Wire transfer blocked" }

            [[rules]]
            method = "POST"
            pattern = "api.bank.com/graphql"
            payload_field = "operationName"
            payload_match = ["TransferFunds", "DeleteAccount"]
            max_body_bytes = 65536
            decision = { type = "Deny", reason = "Dangerous GraphQL" }

            [[rules]]
            method = "DELETE"
            pattern = "{any}"
            decision = { type = "Deny", reason = "Delete blocked" }

            [[rules]]
            method = "*"
            pattern = "{any}"
            decision = { type = "Delay", milliseconds = 300 }
        "#).expect("write SRR config");

        gvm_proxy::srr::NetworkSRR::load(&path).expect("load SRR config")
    })
}

fuzz_target!(|data: &[u8]| {
    // Split fuzz input into method (first 8 bytes), host, path, and optional body.
    // Format: [method_len:1][method][host_len:2_le][host][path...]
    // If input is too short, use empty strings for missing fields.
    if data.is_empty() {
        return;
    }

    let method_len = (data[0] as usize) % 16; // max 15 bytes for method
    if data.len() < 1 + method_len {
        let _ = get_srr().check("GET", "", "", None);
        return;
    }

    let method = std::str::from_utf8(&data[1..1 + method_len]).unwrap_or("GET");
    let rest = &data[1 + method_len..];

    if rest.len() < 2 {
        let _ = get_srr().check(method, "", "", None);
        return;
    }

    let host_len = (u16::from_le_bytes([rest[0], rest[1]]) as usize) % 256;
    let rest = &rest[2..];

    if rest.len() < host_len {
        let _ = get_srr().check(method, "", "", None);
        return;
    }

    let host = std::str::from_utf8(&rest[..host_len]).unwrap_or("");
    let rest = &rest[host_len..];

    // Split remaining into path and body at the midpoint
    let mid = rest.len() / 2;
    let path = std::str::from_utf8(&rest[..mid]).unwrap_or("");
    let body = if mid < rest.len() {
        Some(&rest[mid..])
    } else {
        None
    };

    // This must never panic
    let _ = get_srr().check(method, host, path, body);
});
