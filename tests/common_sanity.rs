//! Sanity check that `tests/common/mod.rs` compiles and produces a
//! usable `AppState`. This file exists purely so `cargo test` exercises
//! the shared helper at build time — without at least one `mod common;`
//! somewhere, the helper sits un-compiled and a silent breakage on an
//! `AppState` field rename would only surface when a developer adds a
//! new test that uses it.

mod common;

#[tokio::test]
async fn common_test_state_builds() {
    let (state, _wal) = common::test_state().await;
    // Hit a handful of fields that integration tests actually touch;
    // regressions that rename or remove them will fail here first.
    assert!(!state.tls_ready.load(std::sync::atomic::Ordering::Relaxed) || true);
    assert_eq!(state.max_body_bytes, 65536);
    assert!(state.current_integrity_ref().is_none());
    assert!(state.srr.read().is_ok());
}
