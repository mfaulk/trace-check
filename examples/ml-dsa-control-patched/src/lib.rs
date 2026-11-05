//! The patched half of the M11.6 negative control: `ml-dsa` `=0.1.2`, in which
//! RUSTSEC-2025-0144's division has been replaced with Barrett reduction.
//!
//! The contracts are the affected half's, included rather than copied, so a
//! difference between the two analyses cannot come from a difference in the
//! analyzed function.

use ml_dsa::{EncodedSignature, MlDsa65, SigningKey};

/// FIPS 204 deterministic ML-DSA-65 signing, as 0.1.2 spells it: the method
/// moved from `SigningKey` to the `ExpandedSigningKey` that `expanded_key()`
/// returns. Same algorithm, same inputs.
///
/// # Panics
///
/// If signing fails, which for a 32-byte message and an empty context would
/// mean the library's documented API has changed shape.
#[inline(always)]
pub fn sign_deterministically(seed: &[u8; 32], message: &[u8; 32]) -> EncodedSignature<MlDsa65> {
    SigningKey::<MlDsa65>::from_seed(&(*seed).into())
        .expanded_key()
        .sign_deterministic(message, &[])
        .expect("a 32-byte message with an empty context signs")
        .encode()
}

include!("../../ml-dsa-control-vulnerable/src/contracts.rs");
