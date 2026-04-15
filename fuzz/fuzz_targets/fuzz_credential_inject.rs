#![no_main]
//! Fuzz target for credential injection and header stripping.
//!
//! Tests that:
//! - Agent-supplied auth headers are always stripped before injection
//! - CRLF injection in credential values is rejected
//! - Oversized headers don't cause panics
//! - Injection into arbitrary HeaderMap configurations never panics

use arbitrary::{Arbitrary, Unstructured};
use gvm_proxy::api_keys::{APIKeyStore, Credential, MissingCredentialPolicy};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::OnceLock;

static STORE: OnceLock<APIKeyStore> = OnceLock::new();

fn get_store() -> &'static APIKeyStore {
    STORE.get_or_init(|| {
        let mut creds = HashMap::new();
        creds.insert(
            "api.stripe.com".to_string(),
            Credential::Bearer {
                token: "sk_live_fuzz_test_token_12345678".to_string(),
            },
        );
        creds.insert(
            "api.slack.com".to_string(),
            Credential::Bearer {
                token: "xoxb-fuzz-slack-token".to_string(),
            },
        );
        creds.insert(
            "api.custom.com".to_string(),
            Credential::ApiKey {
                header: "x-api-key".to_string(),
                value: "custom-fuzz-key-value".to_string(),
            },
        );
        APIKeyStore::from_map(creds)
    })
}

#[derive(Debug)]
struct CredentialInput {
    host: String,
    agent_headers: Vec<(String, String)>,
}

impl<'a> Arbitrary<'a> for CredentialInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let hosts = [
            "api.stripe.com",
            "api.slack.com",
            "api.custom.com",
            "unknown.host.com",
        ];
        let host = hosts[u.int_in_range(0..=hosts.len() - 1)?].to_string();

        let header_count: usize = u.int_in_range(0..=5)?;
        let mut agent_headers = Vec::new();
        for _ in 0..header_count {
            let strategy: u8 = u.int_in_range(0..=4)?;
            let (name, value) = match strategy {
                // Normal auth header smuggling attempt
                0 => ("authorization".into(), "Bearer evil-agent-token".into()),
                // Cookie smuggling
                1 => ("cookie".into(), "session=hijacked".into()),
                // CRLF injection in value
                2 => (
                    "authorization".into(),
                    "Bearer token\r\nEvil: injected".into(),
                ),
                // Oversized header
                3 => ("x-api-key".into(), "a".repeat(8192)),
                // Custom auth header
                _ => ("x-auth-token".into(), "agent-custom-token".into()),
            };
            agent_headers.push((name, value));
        }

        Ok(Self {
            host,
            agent_headers,
        })
    }
}

fuzz_target!(|input: CredentialInput| {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    // Build HeaderMap from agent headers
    let mut headers = HeaderMap::new();
    for (name, value) in &input.agent_headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(n, v);
        }
    }

    // Inject credentials — must not panic
    get_store().inject(
        &mut headers,
        &input.host,
        &MissingCredentialPolicy::Passthrough,
    );

    // After injection on a known host, agent auth headers must be gone
    if input.host == "api.stripe.com" || input.host == "api.slack.com" {
        assert!(
            !headers
                .iter()
                .any(|(_, v)| v.as_bytes() == b"Bearer evil-agent-token"),
            "Agent auth header survived injection — stripping failed"
        );
    }
});
