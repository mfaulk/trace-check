//! The audit targets: ML-KEM-768 decapsulation, with the key-level
//! classification boundary.
//!
//! Three contracts, one per execution path through the Fujisaki–Okamoto
//! transform, because a corpus that happens to reach only one of them would
//! report a clean result for an operation half of which never ran:
//!
//! * [`decaps_valid_ciphertext`] — the ciphertext is genuine, `c' == c`, and
//!   the true shared key is selected;
//! * [`decaps_corrupted_ciphertext`] — one public byte of a genuine ciphertext
//!   is flipped, so re-encryption disagrees and implicit rejection selects
//!   `K̄`;
//! * [`decaps_supplied_ciphertext`] — the ciphertext is whatever the generator
//!   produced, which is the attacker's position in the threat model.
//!
//! In all three the secret is a 64-byte key-generation seed, key generation
//! runs declassified, and only `dk_pke` and `z` are marked for the
//! decapsulation itself. `docs/audits/ml-kem/threat-model.md` justifies that
//! boundary; `controls::public_component_branch` and
//! `controls::secret_component_branch` are what keep it checkable.

use crate::fixture;
use crate::layout::{CIPHERTEXT_LEN, SEED_LEN};
use crate::sink::consume_all_bytes;
use ml_kem::Decapsulate;
use trace_check_macros::constant_time;

/// Per-contract discriminants.
///
/// Two contracts that differ only in a declaration compile to identical bodies,
/// get folded to one symbol, and then a finding cannot be attributed to either
/// — the failure M9 recorded as finding one. One `xor` with a compile-time
/// constant keeps the bodies distinct without adding a branch or an address
/// dependency.
pub const VALID_TAG: u8 = 0x11;
pub const CORRUPTED_TAG: u8 = 0x22;
pub const SUPPLIED_TAG: u8 = 0x33;

/// Decapsulates `ciphertext` under the key derived from `seed`, returning the
/// **whole** shared key.
///
/// Shared by the contracts below and by the functional tests, so the tests
/// validate the code the contracts analyze. They must compare the full 32
/// bytes: the sink is lossy.
#[inline(always)]
pub fn decaps_bytes(seed: &[u8; SEED_LEN], ciphertext: &[u8; CIPHERTEXT_LEN]) -> [u8; 32] {
    let expanded = fixture::public_keygen(seed);
    fixture::with_key_level_secret(&expanded, |key, _| {
        let shared = key.decapsulate(&fixture::ciphertext(ciphertext));
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_slice());
        out
    })
}

/// Target A — decapsulation of a **valid** ciphertext.
///
/// `m` is the encapsulation randomness: public, because the attacker produced
/// the ciphertext. The path exercised is the one where `c' == c`, so the
/// constant-time selection returns the true shared key.
#[constant_time(secret = "seed", dynamic = false)]
pub fn decaps_valid_ciphertext(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, _| {
        let shared = key.decapsulate(&fixture::ciphertext(&ciphertext));
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_slice());
        out
    });
    consume_all_bytes(&shared) ^ VALID_TAG
}

/// Target B — decapsulation of a ciphertext whose re-encryption **fails**.
///
/// One byte of a genuine ciphertext is flipped at a public position, so the
/// implicit-rejection branch of the FO transform is the one taken. This is the
/// path a decapsulation oracle would attack, and the one a non-constant-time
/// comparison or selection would expose.
#[constant_time(secret = "seed", dynamic = false)]
pub fn decaps_corrupted_ciphertext(
    seed: &[u8; 64],
    m: &[u8; 32],
    position: u16,
    delta: u8,
) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let ciphertext = fixture::corrupted_ciphertext(&expanded, m, position, delta);
    let shared = fixture::with_key_level_secret(&expanded, |key, _| {
        let shared = key.decapsulate(&fixture::ciphertext(&ciphertext));
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.as_slice());
        out
    });
    consume_all_bytes(&shared) ^ CORRUPTED_TAG
}

/// Target C — decapsulation of an **arbitrary** supplied ciphertext.
///
/// Decapsulation is total: FIPS 203 rejects implicitly, so a malformed
/// ciphertext is not an error path but a pseudorandom key. No input-domain
/// restriction is therefore needed on `ciphertext`, and a generated value is a
/// valid input in the only sense that matters.
#[constant_time(secret = "seed", dynamic = false)]
pub fn decaps_supplied_ciphertext(seed: &[u8; 64], ciphertext: &[u8; 1088]) -> u8 {
    consume_all_bytes(&decaps_bytes(seed, ciphertext)) ^ SUPPLIED_TAG
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid ciphertext decapsulates to the shared key encapsulation
    /// produced — the successful FO path really is the one taken.
    #[test]
    fn a_valid_ciphertext_recovers_the_encapsulated_key() {
        let seed = [3u8; SEED_LEN];
        let m = [9u8; 32];
        let expanded = fixture::public_keygen(&seed);
        let (ciphertext, expected) = fixture::valid_ciphertext(&expanded, &m);
        assert_eq!(decaps_bytes(&seed, &ciphertext), expected);
    }

    /// A one-byte corruption drives implicit rejection: the recovered key is
    /// neither the encapsulated one nor zero.
    #[test]
    fn a_corrupted_ciphertext_is_implicitly_rejected() {
        let seed = [3u8; SEED_LEN];
        let m = [9u8; 32];
        let expanded = fixture::public_keygen(&seed);
        let (_, expected) = fixture::valid_ciphertext(&expanded, &m);
        let corrupted = fixture::corrupted_ciphertext(&expanded, &m, 17, 0x40);
        let rejected = decaps_bytes(&seed, &corrupted);
        assert_ne!(rejected, expected, "rejection must not return the real key");
        assert_ne!(rejected, [0u8; 32]);
    }

    /// The contracts' discriminants are distinct, which is the only reason
    /// they exist.
    #[test]
    fn the_contract_discriminants_differ() {
        assert_ne!(VALID_TAG, CORRUPTED_TAG);
        assert_ne!(CORRUPTED_TAG, SUPPLIED_TAG);
        assert_ne!(VALID_TAG, SUPPLIED_TAG);
    }

    /// The valid-ciphertext contract is its helper plus the discriminant, so
    /// the contract analyzed and the function tested are the same code.
    #[test]
    fn the_contract_is_the_helper_plus_its_tag() {
        let seed = [5u8; SEED_LEN];
        let m = [1u8; 32];
        let expanded = fixture::public_keygen(&seed);
        let (ciphertext, _) = fixture::valid_ciphertext(&expanded, &m);
        assert_eq!(
            decaps_valid_ciphertext(&seed, &m),
            consume_all_bytes(&decaps_bytes(&seed, &ciphertext)) ^ VALID_TAG
        );
    }

    /// Two different seeds give different shared keys for the same public
    /// ciphertext, so the secret really does reach the result.
    #[test]
    fn the_seed_changes_the_shared_key() {
        let m = [2u8; 32];
        let first = fixture::public_keygen(&[1u8; SEED_LEN]);
        let (ciphertext, _) = fixture::valid_ciphertext(&first, &m);
        assert_ne!(
            decaps_bytes(&[1u8; SEED_LEN], &ciphertext),
            decaps_bytes(&[2u8; SEED_LEN], &ciphertext)
        );
    }
}
