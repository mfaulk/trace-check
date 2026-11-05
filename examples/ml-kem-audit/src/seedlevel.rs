//! The seed-level encoding: mark the 64-byte seed and declassify nothing.
//!
//! This is the strongest relational statement available here — *no* observation
//! may depend on the key-generation seed — and it is deliberately kept beside
//! the key-level contracts rather than replaced by them, because the difference
//! between the two is a measurement this audit owes its reader.
//!
//! The predicted difference is that key generation samples `Â` from `ρ` by
//! rejection, and `ρ` is derived from the secret `d` here while being public in
//! the protocol. A finding in that sampling is a property of the marking, not
//! of `ml-kem`. `docs/audits/ml-kem/findings.md` records which encoding each
//! finding belongs to.

use crate::fixture;
use crate::sink::consume_all_bytes;
use ml_kem::Decapsulate;
use trace_check_macros::constant_time;

pub const SEED_LEVEL_TAG: u8 = 0x44;

/// Key generation **and** decapsulation, with the seed marked throughout.
///
/// The whole derivation is inside the analyzed region: SHAKE, rejection
/// sampling, the NTT, and then decapsulation.
#[constant_time(secret = "seed", dynamic = false)]
pub fn keygen_and_decaps(seed: &[u8; 64], ciphertext: &[u8; 1088]) -> u8 {
    let key = fixture::seed_level(seed);
    let shared = key.decapsulate(&fixture::ciphertext(ciphertext));
    consume_all_bytes(shared.as_slice()) ^ SEED_LEVEL_TAG
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decaps::decaps_bytes;
    use crate::layout::{CIPHERTEXT_LEN, SEED_LEN};

    /// The two encodings compute the same function: the declassification
    /// boundary changes what is *claimed*, never what is computed.
    #[test]
    fn both_encodings_decapsulate_identically() {
        let seed = [11u8; SEED_LEN];
        let ciphertext = [0x5au8; CIPHERTEXT_LEN];
        let expected = decaps_bytes(&seed, &ciphertext);
        assert_eq!(
            keygen_and_decaps(&seed, &ciphertext),
            consume_all_bytes(&expected) ^ SEED_LEVEL_TAG
        );
    }
}
