//! The seed-level encoding, kept for one comparison.
//!
//! `ml-kem`'s seed-level contracts come back `INCONCLUSIVE` because Memcheck
//! cannot trace the undefined values driving its rejection sampler back to the
//! marked secret (finding A). `kyberlib` has its *own* Keccak and its own
//! sampler, so running the same encoding here answers a question the `ml-kem`
//! audit alone cannot: is the lost provenance a property of one implementation,
//! or of taint tracking through a sponge?

use crate::sink::consume_all_bytes;
use trace_check_macros::constant_time;

pub const SEED_LEVEL_TAG: u8 = 0x54;

/// Key generation **and** decapsulation, with the seed marked throughout and
/// nothing declassified.
#[constant_time(secret = "seed", dynamic = false)]
#[allow(deprecated)]
pub fn keygen_and_decaps(seed: &[u8; 64], ciphertext: &[u8; 1088]) -> u8 {
    let keys = kyberlib::derive(seed).expect("64 bytes is the documented seed length");
    let shared =
        kyberlib::decapsulate(ciphertext, keys.expose_secret()).expect("lengths are constants");
    consume_all_bytes(&shared) ^ SEED_LEVEL_TAG
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decaps::decaps_bytes;
    use crate::fixture::SEED_LEN;

    /// Both encodings compute the same function: the boundary changes what is
    /// claimed, never what is computed.
    #[test]
    fn both_encodings_decapsulate_identically() {
        let seed = [11u8; SEED_LEN];
        let ciphertext = [0x5au8; 1088];
        assert_eq!(
            keygen_and_decaps(&seed, &ciphertext),
            consume_all_bytes(&decaps_bytes(&seed, &ciphertext)) ^ SEED_LEVEL_TAG
        );
    }
}
