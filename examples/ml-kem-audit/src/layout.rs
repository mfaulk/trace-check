//! The ML-KEM-768 expanded decapsulation key's layout, which is what makes the
//! declassification boundary expressible at all.
//!
//! FIPS 203 serializes a decapsulation key as
//! `dk_pke ‖ ek ‖ H(ek) ‖ z`. Only `dk_pke` and `z` are secret: `ek` is the
//! public encapsulation key the attacker holds, and `H(ek)` is a hash of it.
//! The offsets below split that encoding, so the boundary is drawn on a
//! documented serialization rather than on `ml-kem`'s private struct fields.
//!
//! `offsets_match_the_librarys_own_split` keeps the constants honest against
//! the library's own accessors.

/// Secret: the K-PKE decryption key, 3 polynomials × 256 coefficients × 12 bits.
pub const DK_PKE_LEN: usize = 1152;

/// Public: the encapsulation key, `t̂ ‖ ρ`.
pub const EK_LEN: usize = 1184;

/// Public: `H(ek)`.
pub const H_LEN: usize = 32;

/// Secret: the implicit-rejection seed.
pub const Z_LEN: usize = 32;

/// The whole expanded encoding.
pub const EXPANDED_LEN: usize = DK_PKE_LEN + EK_LEN + H_LEN + Z_LEN;

pub const EK_OFFSET: usize = DK_PKE_LEN;
pub const H_OFFSET: usize = EK_OFFSET + EK_LEN;
pub const Z_OFFSET: usize = H_OFFSET + H_LEN;

/// An ML-KEM-768 ciphertext.
pub const CIPHERTEXT_LEN: usize = 1088;

/// The encapsulation randomness `m`, and the shared key.
pub const B32_LEN: usize = 32;

/// The 64-byte key-generation seed `d ‖ z`.
pub const SEED_LEN: usize = 64;

/// The public slice of an expanded key: `ek ‖ H(ek)`.
#[inline(always)]
pub fn public_range(expanded: &[u8; EXPANDED_LEN]) -> &[u8] {
    &expanded[EK_OFFSET..Z_OFFSET]
}

/// The encapsulation key alone.
#[inline(always)]
pub fn ek_range(expanded: &[u8; EXPANDED_LEN]) -> &[u8] {
    &expanded[EK_OFFSET..H_OFFSET]
}

/// The K-PKE decryption key: secret.
#[inline(always)]
pub fn dk_pke_range(expanded: &[u8; EXPANDED_LEN]) -> &[u8] {
    &expanded[..DK_PKE_LEN]
}

/// The implicit-rejection seed: secret.
#[inline(always)]
pub fn z_range(expanded: &[u8; EXPANDED_LEN]) -> &[u8] {
    &expanded[Z_OFFSET..]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(deprecated)]
    use ml_kem::ExpandedKeyEncoding;
    use ml_kem::{DecapsulationKey768, KeyExport};

    /// The offsets agree with `ml-kem`'s own accessors: the bytes this module
    /// calls `ek` are exactly what `encapsulation_key().to_bytes()` returns, so
    /// a future layout change breaks the test rather than silently
    /// declassifying secret key material.
    #[test]
    #[allow(deprecated)]
    fn offsets_match_the_librarys_own_split() {
        let key = DecapsulationKey768::from_seed(crate::fixture::seed_array(&[7u8; SEED_LEN]));
        let expanded = key.to_expanded_bytes();
        let expanded: [u8; EXPANDED_LEN] = expanded.as_slice().try_into().unwrap();

        assert_eq!(expanded.len(), 2400, "ML-KEM-768 expanded key width");
        assert_eq!(
            ek_range(&expanded),
            key.encapsulation_key().to_bytes().as_slice(),
            "EK_OFFSET..H_OFFSET must be the encapsulation key"
        );
        assert_eq!(dk_pke_range(&expanded).len(), DK_PKE_LEN);
        assert_eq!(z_range(&expanded).len(), Z_LEN);
    }

    /// The contract signatures spell these widths as literals, because the
    /// macro sees the token and refuses a named length rather than guessing it.
    /// This is the test that keeps the two spellings in agreement.
    #[test]
    fn the_contract_literals_match_the_named_widths() {
        assert_eq!(SEED_LEN, 64, "contracts write `&[u8; 64]`");
        assert_eq!(CIPHERTEXT_LEN, 1088, "contracts write `&[u8; 1088]`");
        assert_eq!(B32_LEN, 32, "contracts write `&[u8; 32]`");
        assert_eq!(EXPANDED_LEN, 2400);
    }

    /// The secret and public ranges partition the encoding with no overlap and
    /// no gap: a boundary that left bytes unaccounted for would be a boundary
    /// that silently declassified or silently marked them.
    #[test]
    fn the_ranges_partition_the_encoding() {
        assert_eq!(DK_PKE_LEN + EK_LEN + H_LEN + Z_LEN, EXPANDED_LEN);
        assert_eq!(EK_OFFSET, DK_PKE_LEN);
        assert_eq!(Z_OFFSET + Z_LEN, EXPANDED_LEN);
        let expanded = [0u8; EXPANDED_LEN];
        assert_eq!(
            dk_pke_range(&expanded).len()
                + public_range(&expanded).len()
                + z_range(&expanded).len(),
            EXPANDED_LEN
        );
    }
}
