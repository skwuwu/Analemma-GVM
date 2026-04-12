//! Shared types for structure-aware fuzzing.
//!
//! Each type implements `arbitrary::Arbitrary` so libFuzzer's mutator
//! generates structurally valid inputs that reach deep code paths instead
//! of failing at the first parse step.

pub mod types;
