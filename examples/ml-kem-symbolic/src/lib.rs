//! One ML-KEM-768 decapsulation contract, with **no** dependency that pulls in
//! `std`.
//!
//! This crate exists for one measurement. The audit crate next door depends on
//! `trace-check-secret` to draw its classification boundary, and that crate
//! links `std`, so the freestanding artifact `verify` builds collides with it
//! on `panic_impl` — a failure about *this repository's* adapter rather than
//! about `ml-kem`. A symbolic result has to be attributable to the target, so
//! the symbolic attempt is made here instead: `no_std`, `ml-kem` with
//! `default-features = false`, the proc macro, and nothing else.
//!
//! The secret is the 64-byte key-generation seed, as in the audit crate, and
//! no declassification is possible without `trace-check-secret` — so this is
//! the seed-level encoding by construction. `docs/audits/ml-kem/symbolic-feasibility.md`
//! records what the backend did with it.
#![cfg_attr(not(test), no_std)]

use ml_kem::array::Array;
use ml_kem::{Ciphertext, Decapsulate, DecapsulationKey768, MlKem768};
use trace_check_macros::constant_time;

/// Folds a 32-byte shared key into one byte in fixed work.
///
/// Every byte must change the result, or the optimizer is licensed to compute
/// less than a decapsulation.
#[inline(never)]
fn consume_all_bytes(bytes: &[u8]) -> u8 {
    let mut acc: u8 = 1;
    let mut index = 0;
    while index < 32 {
        acc = acc.wrapping_mul(31).wrapping_add(bytes[index]);
        index += 1;
    }
    acc
}

/// Key generation from a secret seed, then decapsulation of a public ciphertext.
///
/// Total in both arguments: key generation is defined for every seed, and FIPS
/// 203 rejects implicitly, so no input-domain restriction applies.
#[constant_time(secret = "seed", dynamic = false)]
pub fn keygen_and_decaps(seed: &[u8; 64], ciphertext: &[u8; 1088]) -> u8 {
    let key = DecapsulationKey768::from_seed(Array(*seed));
    let encapsulated = Ciphertext::<MlKem768>::try_from(ciphertext.as_slice());
    match encapsulated {
        Ok(encapsulated) => consume_all_bytes(key.decapsulate(&encapsulated).as_slice()),
        // Unreachable for a 1088-byte array; the width is a property of the
        // caller's type, never of an input value.
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract decapsulates: a different seed gives a different shared key
    /// for one fixed ciphertext, so the secret reaches the result.
    #[test]
    fn the_seed_reaches_the_result() {
        let ciphertext = [0x5au8; 1088];
        assert_ne!(
            keygen_and_decaps(&[1u8; 64], &ciphertext),
            keygen_and_decaps(&[2u8; 64], &ciphertext)
        );
    }
}
