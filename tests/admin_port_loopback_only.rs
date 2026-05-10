//! Pre-flight tests for the admin-port loopback enforcement
//! (`docs/internal/COVERAGE_HARDENING_PLAN.md` △-8b).
//!
//! The admin port carries privileged endpoints (IC-3 approval, SRR
//! reload, sandbox launch). The security model assumes only
//! same-host operators reach it; binding to `0.0.0.0` exposes those
//! endpoints to anyone routable to the host. The proxy now refuses
//! to start with a non-loopback `admin_listen` unless the operator
//! explicitly sets `[server] allow_non_loopback_admin = true`.
//!
//! These tests pin the contract on the validation function rather
//! than spinning up the full proxy, which keeps them fast and
//! cross-platform. The actual `bail!` site in `src/main.rs`
//! consumes this same function.

use gvm_proxy::config::{AdminBindCheck, ServerConfig};

fn cfg(addr: &str, allow_non_loopback: bool) -> ServerConfig {
    ServerConfig {
        listen: "0.0.0.0:8080".to_string(),
        admin_listen: addr.to_string(),
        allow_non_loopback_admin: allow_non_loopback,
        drain_timeout_secs: 5,
    }
}

#[test]
fn ipv4_loopback_default_accepted() {
    let r = cfg("127.0.0.1:9090", false).admin_bind_acceptable();
    assert!(matches!(r, Ok(AdminBindCheck::Loopback)));
}

#[test]
fn ipv4_loopback_alternate_octets_accepted() {
    // The whole 127.0.0.0/8 is loopback by RFC 1122, not just
    // 127.0.0.1. is_loopback() honours the full range.
    for addr in ["127.0.0.2:9090", "127.255.255.254:9090"] {
        let r = cfg(addr, false).admin_bind_acceptable();
        assert!(
            matches!(r, Ok(AdminBindCheck::Loopback)),
            "expected {addr} accepted as loopback, got {r:?}"
        );
    }
}

#[test]
fn ipv6_loopback_accepted() {
    let r = cfg("[::1]:9090", false).admin_bind_acceptable();
    assert!(matches!(r, Ok(AdminBindCheck::Loopback)));
}

#[test]
fn ipv4_wildcard_refused_by_default() {
    let r = cfg("0.0.0.0:9090", false).admin_bind_acceptable();
    let err = r.expect_err("0.0.0.0 must be refused without allow_non_loopback_admin");
    assert!(
        err.contains("non-loopback") && err.contains("allow_non_loopback_admin"),
        "error message must explain the cause and the opt-in. Got: {err}"
    );
}

#[test]
fn ipv6_wildcard_refused_by_default() {
    let r = cfg("[::]:9090", false).admin_bind_acceptable();
    assert!(
        r.is_err(),
        "[::] (IPv6 wildcard) must be refused without opt-in, got {r:?}"
    );
}

#[test]
fn private_routable_address_refused_by_default() {
    // RFC 1918 private addresses are still "non-loopback" per
    // is_loopback(). They are routable on the LAN and the proxy
    // shouldn't expose admin endpoints to LAN peers without
    // explicit opt-in.
    for addr in ["192.168.1.5:9090", "10.0.0.1:9090", "172.16.5.5:9090"] {
        let r = cfg(addr, false).admin_bind_acceptable();
        assert!(
            r.is_err(),
            "RFC 1918 private address {addr} must be refused without opt-in, got {r:?}"
        );
    }
}

#[test]
fn non_loopback_with_explicit_opt_in_accepted_with_warning_payload() {
    let r = cfg("0.0.0.0:9090", true).admin_bind_acceptable();
    match r {
        Ok(AdminBindCheck::NonLoopbackAllowed { addr }) => {
            assert_eq!(addr, "0.0.0.0:9090");
        }
        other => panic!("expected NonLoopbackAllowed with addr, got {other:?}"),
    }
}

#[test]
fn malformed_admin_listen_returns_parse_error() {
    let r = cfg("not-a-real-address", false).admin_bind_acceptable();
    let err = r.expect_err("malformed listen string must error");
    assert!(
        err.contains("not a parseable") || err.contains("resolved to no"),
        "parse error must be specific. Got: {err}"
    );
}

#[test]
fn loopback_does_not_change_with_allow_flag() {
    // Sanity: setting allow_non_loopback_admin = true on a loopback
    // bind doesn't downgrade the result to NonLoopbackAllowed —
    // a loopback bind stays loopback regardless of the flag.
    let r = cfg("127.0.0.1:9090", true).admin_bind_acceptable();
    assert!(matches!(r, Ok(AdminBindCheck::Loopback)));
}
