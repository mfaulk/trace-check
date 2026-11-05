//! The affected half of the M11.6 negative control: `ml-dsa` `=0.1.0-rc.2`,
//! which RUSTSEC-2025-0144 lists as vulnerable.
//!
//! The contracts live in `contracts.rs` and are included verbatim by
//! `examples/ml-dsa-control-patched` too, so the analyzed functions are
//! byte-identical and the two runs differ in the library version and in the
//! three-line shim below.

use ml_dsa::{EncodedSignature, MlDsa65, SigningKey};

/// FIPS 204 deterministic ML-DSA-65 signing, as 0.1.0-rc.2 spells it.
///
/// # Panics
///
/// If signing fails, which for a 32-byte message and an empty context would
/// mean the library's documented API has changed shape.
#[inline(always)]
pub fn sign_deterministically(seed: &[u8; 32], message: &[u8; 32]) -> EncodedSignature<MlDsa65> {
    SigningKey::<MlDsa65>::from_seed(&(*seed).into())
        .sign_deterministic(message, &[])
        .expect("a 32-byte message with an empty context signs")
        .encode()
}

include!("contracts.rs");
