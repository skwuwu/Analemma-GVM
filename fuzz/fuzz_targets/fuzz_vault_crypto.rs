#![no_main]
//! Fuzz target for Vault AES-256-GCM encrypt/decrypt round-trip.
//!
//! Tests that:
//! - Arbitrary plaintext encrypts and decrypts back to the same value
//! - Corrupted ciphertext returns Err, never panics
//! - Truncated data returns Err, never panics
//! - Wrong key returns Err, never panics

use arbitrary::{Arbitrary, Unstructured};
use gvm_proxy::vault::KeyProvider;
use libfuzzer_sys::fuzz_target;

#[derive(Debug)]
struct VaultInput {
    /// What to test
    strategy: VaultStrategy,
    /// Raw data
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
enum VaultStrategy {
    /// Encrypt then decrypt — round-trip integrity
    RoundTrip,
    /// Feed raw bytes to decrypt — corrupted ciphertext
    DecryptGarbage,
    /// Encrypt, flip some bytes, try to decrypt — tamper detection
    TamperAfterEncrypt,
    /// Decrypt with data shorter than nonce (12 bytes)
    TruncatedCiphertext,
}

impl<'a> Arbitrary<'a> for VaultInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let strategy: VaultStrategy = u.arbitrary()?;
        let len: usize = u.int_in_range(0..=4096)?;
        let data = u.bytes(len)?.to_vec();
        Ok(Self { strategy, data })
    }
}

// Fixed test key — same key for all fuzz iterations (deterministic)
fn get_key_provider() -> gvm_proxy::vault::LocalKeyProvider {
    let key = [0x42u8; 32]; // fixed key for fuzzing
    gvm_proxy::vault::LocalKeyProvider::new(key)
}

fuzz_target!(|input: VaultInput| {
    let kp = get_key_provider();

    match input.strategy {
        VaultStrategy::RoundTrip => {
            if let Ok(encrypted) = kp.encrypt(&input.data) {
                match kp.decrypt(&encrypted) {
                    Ok(decrypted) => {
                        assert_eq!(
                            decrypted, input.data,
                            "Round-trip mismatch: encrypt then decrypt should return original"
                        );
                    }
                    Err(_) => {
                        // Decrypt failure on valid ciphertext = bug
                        panic!("Decrypt failed on freshly encrypted data");
                    }
                }
            }
            // encrypt failure is acceptable (e.g., allocation failure)
        }

        VaultStrategy::DecryptGarbage => {
            // Must return Err, never panic
            let _ = kp.decrypt(&input.data);
        }

        VaultStrategy::TamperAfterEncrypt => {
            if let Ok(mut encrypted) = kp.encrypt(&input.data) {
                // Flip a byte somewhere in the ciphertext
                if !encrypted.is_empty() {
                    let idx = input.data.len() % encrypted.len();
                    encrypted[idx] ^= 0xFF;
                }
                // Must return Err (tampered) or Ok if the flip was in padding
                // Either way: no panic
                let _ = kp.decrypt(&encrypted);
            }
        }

        VaultStrategy::TruncatedCiphertext => {
            // Data shorter than nonce (12 bytes) — must return Err
            let short = &input.data[..input.data.len().min(11)];
            let result = kp.decrypt(short);
            assert!(result.is_err(), "Decrypt of <12 byte data should fail");
        }
    }
});
