//! Integration test for `gvm import openapi` — Tier-2 P2-b.
//!
//! Drives the CLI from end-to-end:
//!   1. Write a minimal OpenAPI 3.0 spec to a temp file.
//!   2. Run `gvm import openapi <spec>` and capture stdout.
//!   3. Save stdout into a `srr_network.toml`-shaped file.
//!   4. Load that file via the production `NetworkSRR::load` path.
//!   5. Drive a handful of canonical requests through `srr.check` and
//!      verify the right operation-id surfaces as `matched_description`,
//!      with the conservative deny-by-default decision.
//!
//! This is the load-bearing assertion for the importer: it must round-trip
//! through SRR's loader (catches regex errors, malformed TOML), and the
//! emitted action names must reach the audit-readable surface.

use gvm_proxy::srr::NetworkSRR;
use gvm_proxy::types::EnforcementDecision;
use std::process::Command;
use tempfile::tempdir;

fn gvm_bin() -> &'static str {
    env!("CARGO_BIN_EXE_gvm")
}

const SPEC_YAML: &str = r#"
openapi: 3.0.0
info:
  title: Test API
  version: "1.0"
servers:
  - url: https://api.example.com/v1
paths:
  /users:
    get:
      operationId: listUsers
      summary: list all users
    post:
      operationId: createUser
  /users/{id}:
    get:
      operationId: getUser
    delete:
      operationId: deleteUser
  /workflows/{wf_id}/runs:
    post:
      operationId: triggerWorkflow
      summary: dispatch a workflow run
"#;

#[test]
fn gvm_import_openapi_produces_loadable_srr_with_action_names() {
    let dir = tempdir().expect("tempdir");
    let spec_path = dir.path().join("spec.yaml");
    let out_path = dir.path().join("srr_network.toml");
    std::fs::write(&spec_path, SPEC_YAML).expect("write spec");

    // ── Run the CLI: capture stdout into out_path ──
    let output = Command::new(gvm_bin())
        .args(["import", "openapi"])
        .arg(&spec_path)
        .output()
        .expect("spawn gvm");
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "gvm import openapi failed (exit {:?}); stderr:\n{stderr}",
            output.status.code()
        );
    }
    std::fs::write(&out_path, &output.stdout).expect("write generated SRR");

    // ── Load the generated TOML through the production SRR loader ──
    let srr = NetworkSRR::load(&out_path).expect("generated SRR must load");

    // ── Each canonical request should match its declared operationId ──
    let cases: &[(&str, &str, &str)] = &[
        ("GET", "/v1/users", "listUsers"),
        ("POST", "/v1/users", "createUser"),
        ("GET", "/v1/users/42", "getUser"),
        ("DELETE", "/v1/users/42", "deleteUser"),
        ("POST", "/v1/workflows/release/runs", "triggerWorkflow"),
    ];
    for (method, path, expected_op) in cases {
        let r = srr.check(method, "api.example.com", path, None);
        let desc = r.matched_description.as_deref().unwrap_or("<none>");
        assert_eq!(
            desc, *expected_op,
            "{method} {path} should match operation '{expected_op}', got '{desc}'"
        );
        assert!(
            matches!(r.decision, EnforcementDecision::Deny { .. }),
            "imported baseline must be Deny-by-default; got {:?} for {method} {path}",
            r.decision
        );
    }
}

#[test]
fn gvm_import_openapi_handles_paths_with_no_base_path() {
    let dir = tempdir().expect("tempdir");
    let spec_path = dir.path().join("spec.yaml");
    let out_path = dir.path().join("srr_network.toml");
    std::fs::write(
        &spec_path,
        r#"
openapi: 3.0.0
info: { title: bare, version: "1" }
servers:
  - url: https://internal.corp
paths:
  /ping:
    get:
      operationId: ping
"#,
    )
    .expect("write spec");

    let output = Command::new(gvm_bin())
        .args(["import", "openapi"])
        .arg(&spec_path)
        .output()
        .expect("spawn gvm");
    assert!(
        output.status.success(),
        "gvm import openapi failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(&out_path, &output.stdout).expect("write generated SRR");

    let srr = NetworkSRR::load(&out_path).expect("generated SRR must load");
    let r = srr.check("GET", "internal.corp", "/ping", None);
    assert_eq!(r.matched_description.as_deref(), Some("ping"));
    assert!(matches!(r.decision, EnforcementDecision::Deny { .. }));
}

#[test]
fn gvm_import_openapi_writes_to_out_flag_path() {
    let dir = tempdir().expect("tempdir");
    let spec_path = dir.path().join("spec.yaml");
    let out_path = dir.path().join("written.toml");
    std::fs::write(
        &spec_path,
        r#"
openapi: 3.0.0
info: { title: x, version: "1" }
servers: [ { url: https://api.example.com } ]
paths:
  /foo:
    get: { operationId: getFoo }
"#,
    )
    .expect("write spec");

    let output = Command::new(gvm_bin())
        .args(["import", "openapi"])
        .arg(&spec_path)
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("spawn gvm");
    assert!(
        output.status.success(),
        "gvm import openapi --out failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(out_path.exists(), "--out path must be written");
    // stdout should be empty when --out is used; the file does the work.
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty when --out is set; got {} bytes",
        output.stdout.len()
    );

    let srr = NetworkSRR::load(&out_path).expect("written SRR loads");
    let r = srr.check("GET", "api.example.com", "/foo", None);
    assert_eq!(r.matched_description.as_deref(), Some("getFoo"));
}

#[test]
fn gvm_import_openapi_fails_loudly_on_missing_servers() {
    let dir = tempdir().expect("tempdir");
    let spec_path = dir.path().join("bad.yaml");
    // No `servers:` block — importer cannot infer host. Must fail with
    // a non-zero exit and a stderr message, not silently emit a
    // half-broken file.
    std::fs::write(
        &spec_path,
        r#"
openapi: 3.0.0
info: { title: x, version: "1" }
paths:
  /foo:
    get: { operationId: foo }
"#,
    )
    .expect("write spec");

    let output = Command::new(gvm_bin())
        .args(["import", "openapi"])
        .arg(&spec_path)
        .output()
        .expect("spawn gvm");
    assert!(
        !output.status.success(),
        "missing servers must fail; stdout was:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("servers"),
        "stderr should explain the missing-servers cause; got:\n{stderr}"
    );
}
