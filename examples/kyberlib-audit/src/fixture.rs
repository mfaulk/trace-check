//! Key and ciphertext construction, and the classification boundary.
//!
//! The same two problems as the `ml-kem` audit, solved the same way: validity
//! by deriving every key deterministically from a 64-byte seed, and
//! classification by running that derivation on a *declassified* copy of the
//! seed and marking only the secret components afterwards.
//!
//! One thing is cleaner here than next door. `MlKem768DecapKey` has no
//! byte constructor, but it does lend out its storage through `as_bytes`, so
//! the boundary is drawn on **the buffer the library actually reads** during
//! decapsulation rather than on a copy that has to be decoded again.
//!
//! `the_two_key_generation_paths_agree` checks the deterministic typed keygen
//! against the library's own documented `derive`, and
//! `offsets_match_the_librarys_own_public_key` checks the offsets against the
//! public key it returns.

use kyberlib::{KemCore, MlKem768, MlKem768Ciphertext, MlKem768DecapKey, MlKem768EncapKey};
use rand_core::{CryptoRng, Error, RngCore};
use trace_check_secret::{declassify, Secret};

/// Secret: the K-PKE decryption key.
pub const SK_PKE_LEN: usize = 1152;
/// Public: the encapsulation key.
pub const PK_LEN: usize = 1184;
/// Public: `H(pk)`.
pub const H_LEN: usize = 32;
/// Secret: the implicit-rejection seed.
pub const Z_LEN: usize = 32;

pub const SECRET_KEY_LEN: usize = SK_PKE_LEN + PK_LEN + H_LEN + Z_LEN;
pub const PK_OFFSET: usize = SK_PKE_LEN;
pub const H_OFFSET: usize = PK_OFFSET + PK_LEN;
pub const Z_OFFSET: usize = H_OFFSET + H_LEN;

pub const CIPHERTEXT_LEN: usize = 1088;
pub const SEED_LEN: usize = 64;

/// An RNG that hands out a fixed prefix and then zeros.
///
/// `kyberlib` takes `R: RngCore + CryptoRng` for both key generation and
/// encapsulation rather than explicit randomness, and this audit needs both to
/// be deterministic: a corpus whose keys or ciphertexts vary for reasons the
/// harness does not control cannot be replayed, and a finding in it cannot be
/// reduced to an input. The `CryptoRng` implementation is false about this
/// type's security and true about its purpose, which is why it exists only in
/// a test fixture.
pub struct FixedRng {
    bytes: [u8; SEED_LEN],
    len: usize,
    position: usize,
}

impl FixedRng {
    /// Supplies a 64-byte key-generation seed, `d ‖ z`.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        FixedRng {
            bytes: *seed,
            len: SEED_LEN,
            position: 0,
        }
    }

    /// Supplies the 32-byte encapsulation randomness `m`.
    pub fn from_m(m: &[u8; 32]) -> Self {
        let mut bytes = [0u8; SEED_LEN];
        bytes[..32].copy_from_slice(m);
        FixedRng {
            bytes,
            len: 32,
            position: 0,
        }
    }
}

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        self.fill_bytes(&mut word);
        u32::from_le_bytes(word)
    }

    fn next_u64(&mut self) -> u64 {
        let mut word = [0u8; 8];
        self.fill_bytes(&mut word);
        u64::from_le_bytes(word)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for slot in dest.iter_mut() {
            *slot = if self.position < self.len {
                let byte = self.bytes[self.position];
                self.position += 1;
                byte
            } else {
                0
            };
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedRng {}

/// Derives a key pair from `seed`, with key generation **outside** the secret
/// marking.
///
/// The seed arrives marked, so it is copied and the copy declassified before
/// key generation sees it — which keeps `ρ` and the rejection sampling it
/// drives public, exactly as in the `ml-kem` audit.
///
/// # Panics
///
/// If the library's key generation fails, which for a fixed 64-byte seed would
/// mean its typed API has changed shape.
#[inline(always)]
pub fn public_keygen(seed: &[u8; SEED_LEN]) -> (MlKem768DecapKey, MlKem768EncapKey) {
    let public_seed = *seed;
    declassify(&public_seed);
    MlKem768::generate(&mut FixedRng::from_seed(&public_seed))
        .expect("deterministic key generation over a 64-byte seed")
}

/// Runs `body` with **only** `sk_pke` and `z` marked secret.
///
/// The marking is applied to the key's own storage, so it is live for exactly
/// the bytes the library reads, and the guards are held across `body` because
/// Memcheck propagates per byte.
#[inline(always)]
pub fn with_key_level_secret<R>(
    key: &MlKem768DecapKey,
    body: impl FnOnce(&MlKem768DecapKey, &[u8; SECRET_KEY_LEN]) -> R,
) -> R {
    let bytes = key.as_bytes();
    let sk_pke_guard = Secret::new(&bytes[..SK_PKE_LEN]);
    let z_guard = Secret::new(&bytes[Z_OFFSET..]);

    let out = body(key, bytes);

    drop(sk_pke_guard);
    drop(z_guard);
    out
}

/// A genuinely valid ciphertext under `encap`, with its shared secret.
///
/// Built through the library's own encapsulation over the public key, so no
/// secret component is read and the ciphertext is public by construction
/// rather than by declassification.
///
/// # Panics
///
/// If encapsulation fails, which for a key this module derived would mean the
/// public-key constant is wrong.
#[inline(always)]
pub fn valid_ciphertext(
    encap: &MlKem768EncapKey,
    m: &[u8; 32],
) -> ([u8; CIPHERTEXT_LEN], [u8; 32]) {
    let (ciphertext, shared) = encap
        .encapsulate(&mut FixedRng::from_m(m))
        .expect("a derived encapsulation key must encapsulate");
    (*ciphertext.as_bytes(), *shared.as_bytes())
}

/// A valid ciphertext with one byte changed at a public position, which drives
/// implicit rejection.
#[inline(always)]
pub fn corrupted_ciphertext(
    encap: &MlKem768EncapKey,
    m: &[u8; 32],
    position: u16,
    delta: u8,
) -> [u8; CIPHERTEXT_LEN] {
    let (mut bytes, _) = valid_ciphertext(encap, m);
    bytes[usize::from(position) % CIPHERTEXT_LEN] ^= delta | 1;
    bytes
}

/// A ciphertext in the library's own type.
#[inline(always)]
pub fn ciphertext(bytes: &[u8; CIPHERTEXT_LEN]) -> MlKem768Ciphertext {
    MlKem768Ciphertext::from_bytes(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offsets agree with the library's own public key: the bytes this
    /// module calls `pk` inside the secret key are exactly what key generation
    /// returned as public, so a layout change breaks the test instead of
    /// silently declassifying secret key material.
    #[test]
    fn offsets_match_the_librarys_own_public_key() {
        let (decap, encap) = public_keygen(&[7u8; SEED_LEN]);
        let bytes = decap.as_bytes();
        assert_eq!(bytes.len(), 2400, "ML-KEM-768 secret key width");
        assert_eq!(&bytes[PK_OFFSET..H_OFFSET], &encap.as_bytes()[..]);
        assert_eq!(SK_PKE_LEN + PK_LEN + H_LEN + Z_LEN, SECRET_KEY_LEN);
    }

    /// Deterministic key generation through the typed API agrees with the
    /// library's own documented `derive`, so using the non-deprecated path
    /// does not quietly audit a different key than the seed names.
    #[test]
    #[allow(deprecated)]
    fn the_two_key_generation_paths_agree() {
        let seed = [11u8; SEED_LEN];
        let (decap, encap) = public_keygen(&seed);
        let derived = kyberlib::derive(&seed).expect("64 bytes is the documented seed length");
        assert_eq!(decap.as_bytes()[..], derived.expose_secret()[..]);
        assert_eq!(encap.as_bytes()[..], derived.public[..]);
    }

    /// The fixed RNG is deterministic, so the same `m` produces the same
    /// ciphertext and a different `m` does not.
    #[test]
    fn the_fixed_rng_makes_encapsulation_deterministic() {
        let (_, encap) = public_keygen(&[9u8; SEED_LEN]);
        let first = valid_ciphertext(&encap, &[3u8; 32]);
        assert_eq!(first, valid_ciphertext(&encap, &[3u8; 32]));
        assert_ne!(first.0, valid_ciphertext(&encap, &[4u8; 32]).0);
    }
}
