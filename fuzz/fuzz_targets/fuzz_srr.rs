#![no_main]
//! Structure-aware SRR fuzzer.
//!
//! Feeds arbitrary (method, host, path, body) into NetworkSRR::check().
//! Inputs are structurally valid (Arbitrary derive) so the fuzzer reaches
//! SRR matching logic instead of failing at UTF-8 validation.
//!
//! Adversarial patterns via FuzzPath: ReDoS payloads, path traversal,
//! percent-encoding, null bytes, query/fragment stripping.

use gvm_fuzz::types::SrrInput;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

struct SrrFixture {
    srr: gvm_proxy::srr::NetworkSRR,
    _tempdir: tempfile::TempDir,
}

static SRR: OnceLock<SrrFixture> = OnceLock::new();

fn get_srr() -> &'static gvm_proxy::srr::NetworkSRR {
    &SRR.get_or_init(|| {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("srr.toml");
        std::fs::write(
            &path,
            r#"
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
        "#,
        )
        .expect("write SRR config");
        let srr = gvm_proxy::srr::NetworkSRR::load(&path).expect("load SRR config");
        SrrFixture {
            srr,
            _tempdir: dir,
        }
    })
    .srr
}

fuzz_target!(|input: SrrInput| {
    let body_ref = input.body.as_deref();
    let _ = get_srr().check(input.method.as_str(), &input.host.0, &input.path.0, body_ref);
});
