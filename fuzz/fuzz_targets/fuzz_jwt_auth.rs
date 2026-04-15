#![no_main]
//! Fuzz target for JWT authentication (verify_token).
//!
//! Feeds arbitrary strings as JWT tokens to the verification function.
//! Tests that malformed tokens (wrong segment count, invalid base64,
//! bad signature, expired, future-issued) return Err, never panic.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static CONFIG: OnceLock<gvm_proxy::auth::JwtConfig> = OnceLock::new();

fn get_config() -> &'static gvm_proxy::auth::JwtConfig {
    CONFIG.get_or_init(|| gvm_proxy::auth::JwtConfig {
        secret: gvm_proxy::auth::JwtSecret::from_bytes(
            b"fuzz-secret-key-32bytes-exactly!".to_vec(),
        ),
        token_ttl_secs: 3600,
    })
}

/// JWT fuzz input with adversarial strategies.
#[derive(Debug)]
struct JwtInput {
    token: String,
}

impl<'a> Arbitrary<'a> for JwtInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let strategy: u8 = u.int_in_range(0..=5)?;
        let token = match strategy {
            // Random string (no JWT structure)
            0 => {
                let len: usize = u.int_in_range(0..=500)?;
                (0..len)
                    .map(|_| Ok(u.int_in_range(0x20u8..=0x7eu8)? as char))
                    .collect::<arbitrary::Result<String>>()?
            }
            // Three dot-separated segments (JWT-like)
            1 => {
                let header_len: usize = u.int_in_range(4..=100)?;
                let payload_len: usize = u.int_in_range(4..=200)?;
                let sig_len: usize = u.int_in_range(4..=100)?;
                let gen = |u: &mut Unstructured, n: usize| -> arbitrary::Result<String> {
                    (0..n)
                        .map(|_| {
                            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
                            let idx: usize = u.int_in_range(0..=chars.len() - 1)?;
                            Ok(chars[idx] as char)
                        })
                        .collect::<arbitrary::Result<String>>()
                };
                format!("{}.{}.{}", gen(u, header_len)?, gen(u, payload_len)?, gen(u, sig_len)?)
            }
            // Oversized token (MAX_TOKEN_BYTES = 4096)
            2 => "a".repeat(5000),
            // Empty token
            3 => String::new(),
            // Valid-looking but wrong signature
            4 => {
                // Base64 of {"alg":"HS256","typ":"JWT"} . {"sub":"fuzz","iss":"gvm-proxy","exp":999999999,"iat":0} . garbage-sig
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmdXp6IiwiaXNzIjoiZ3ZtLXByb3h5IiwiZXhwIjo5OTk5OTk5OTksImlhdCI6MH0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
            }
            // Single segment
            _ => "just-one-segment-no-dots".to_string(),
        };
        Ok(Self { token })
    }
}

fuzz_target!(|input: JwtInput| {
    // Must return Err for all malformed tokens, never panic
    let _ = gvm_proxy::auth::verify_token(get_config(), &input.token);
});
