//! The audit targets: `kyberlib`'s ML-KEM-768 decapsulation, one contract per
//! path through the Fujisaki–Okamoto transform.

use crate::fixture::{self, CIPHERTEXT_LEN, SEED_LEN};
use crate::sink::consume_all_bytes;
use trace_check_macros::constant_time;

/// Per-contract discriminants, so two contracts that differ only in a
/// declaration do not compile to one folded symbol and defeat attribution.
pub const VALID_TAG: u8 = 0x51;
pub const CORRUPTED_TAG: u8 = 0x52;
pub const SUPPLIED_TAG: u8 = 0x53;

/// Decapsulates `ciphertext` under the key derived from `seed`, returning the
/// **whole** shared secret.
#[inline(always)]
pub fn decaps_bytes(seed: &[u8; SEED_LEN], ciphertext: &[u8; CIPHERTEXT_LEN]) -> [u8; 32] {
    let (decap, _) = fixture::public_keygen(seed);
    fixture::with_key_level_secret(&decap, |key, _| {
        *key.decapsulate(&fixture::ciphertext(ciphertext)).as_bytes()
    })
}

/// Target A — decapsulation of a **valid** ciphertext: the successful FO path.
#[constant_time(secret = "seed", dynamic = false)]
pub fn decaps_valid_ciphertext(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&encap, m);
    let shared = fixture::with_key_level_secret(&decap, |key, _| {
        *key.decapsulate(&fixture::ciphertext(&ciphertext)).as_bytes()
    });
    consume_all_bytes(&shared) ^ VALID_TAG
}

/// Target B — one public byte of a valid ciphertext flipped, so the
/// implicit-rejection path is the one taken.
#[constant_time(secret = "seed", dynamic = false)]
pub fn decaps_corrupted_ciphertext(
    seed: &[u8; 64],
    m: &[u8; 32],
    position: u16,
    delta: u8,
) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let ciphertext = fixture::corrupted_ciphertext(&encap, m, position, delta);
    let shared = fixture::with_key_level_secret(&decap, |key, _| {
        *key.decapsulate(&fixture::ciphertext(&ciphertext)).as_bytes()
    });
    consume_all_bytes(&shared) ^ CORRUPTED_TAG
}

/// Target C — an arbitrary supplied ciphertext, which is the attacker's
/// position. Decapsulation is total, so no input-domain restriction applies.
#[constant_time(secret = "seed", dynamic = false)]
pub fn decaps_supplied_ciphertext(seed: &[u8; 64], ciphertext: &[u8; 1088]) -> u8 {
    consume_all_bytes(&decaps_bytes(seed, ciphertext)) ^ SUPPLIED_TAG
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid ciphertext decapsulates to the shared secret encapsulation
    /// produced, so the successful FO path really is the one taken.
    #[test]
    fn a_valid_ciphertext_recovers_the_encapsulated_secret() {
        let seed = [3u8; SEED_LEN];
        let m = [9u8; 32];
        let (_, encap) = fixture::public_keygen(&seed);
        let (ciphertext, expected) = fixture::valid_ciphertext(&encap, &m);
        assert_eq!(decaps_bytes(&seed, &ciphertext), expected);
    }

    /// A one-byte corruption drives implicit rejection.
    #[test]
    fn a_corrupted_ciphertext_is_implicitly_rejected() {
        let seed = [3u8; SEED_LEN];
        let m = [9u8; 32];
        let (_, encap) = fixture::public_keygen(&seed);
        let (_, expected) = fixture::valid_ciphertext(&encap, &m);
        let corrupted = fixture::corrupted_ciphertext(&encap, &m, 17, 0x40);
        let rejected = decaps_bytes(&seed, &corrupted);
        assert_ne!(rejected, expected);
        assert_ne!(rejected, [0u8; 32]);
    }

    /// The discriminants are distinct, which is the only reason they exist.
    #[test]
    fn the_contract_discriminants_differ() {
        assert_ne!(VALID_TAG, CORRUPTED_TAG);
        assert_ne!(CORRUPTED_TAG, SUPPLIED_TAG);
        assert_ne!(VALID_TAG, SUPPLIED_TAG);
    }
}
