#![no_main]
//! Structure-aware path normalization fuzzer.
//!
//! Generates paths from adversarial segments (dot-segments, percent-encoding,
//! double-encoding, null bytes, ReDoS payloads, encoded slashes) and feeds
//! them through NetworkSRR::check() which internally calls normalize_path().
//!
//! More targeted than raw-byte fuzzing because every input is a valid path
//! string, so the normalizer always has work to do.

use gvm_fuzz::types::{HttpMethod, NormalizePath};
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
            method = "*"
            pattern = "example.com/api/{any}"
            decision = { type = "Allow" }

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

fuzz_target!(|input: (HttpMethod, NormalizePath)| {
    let (method, path) = input;
    let _ = get_srr().check(method.as_str(), "example.com", &path.0, None);
});
