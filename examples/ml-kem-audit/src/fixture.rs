//! Key and ciphertext construction, and the declassification boundary.
//!
//! Two problems are solved here, and they are the reason this crate exists in
//! the shape it does.
//!
//! **Validity.** A generated `[u8; 2400]` is not a decapsulation key: the
//! encoding contains `H(ek)`, so being a key is a hash preimage condition no
//! `assume` can express. Every secret this crate analyzes is therefore derived
//! from a 64-byte seed through the library's own `from_seed`, which is exactly
//! the input FIPS 203 defines for deterministic key generation.
//!
//! **Classification.** A decapsulation key is not uniformly secret. Marking the
//! seed and running key generation taints `ρ`, and `ρ` drives the rejection
//! sampling that builds `Â` — public data in the protocol, so a finding there
//! describes the marking, not the library. [`public_keygen`] therefore runs key
//! generation on a *declassified copy* of the seed and
//! [`with_key_level_secret`] re-marks only `dk_pke` and `z` afterwards.
//!
//! [`seed_level`] keeps the other encoding available on purpose: it marks the
//! seed and declassifies nothing, so the two can be compared on the same
//! operation.

use crate::layout::{
    CIPHERTEXT_LEN, DK_PKE_LEN, EXPANDED_LEN, EK_OFFSET, H_OFFSET, SEED_LEN, Z_OFFSET,
};
use ml_kem::array::Array;
use ml_kem::{Ciphertext, DecapsulationKey768, EncapsulationKey768, MlKem768, Seed};

// The expanded encoding is deprecated upstream in favour of the seed, and this
// crate agrees: the *secret input* is the seed. The expanded form is used only
// as the documented serialization that makes the public and secret components
// of a derived key addressable, which is what the declassification boundary
// needs and what no other public API offers.
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use trace_check_secret::{declassify, Secret};

/// A 64-byte seed in the library's own type.
#[inline(always)]
pub fn seed_array(seed: &[u8; SEED_LEN]) -> Seed {
    Array(*seed)
}

/// A ciphertext in the library's own type.
///
/// # Panics
///
/// Never for a `[u8; CIPHERTEXT_LEN]`: the width is a property of the caller's
/// type, not of any input value.
#[inline(always)]
pub fn ciphertext(bytes: &[u8; CIPHERTEXT_LEN]) -> Ciphertext<MlKem768> {
    Ciphertext::<MlKem768>::try_from(bytes.as_slice()).expect("1088 bytes is an ML-KEM-768 ciphertext")
}

/// Derives a genuine ML-KEM-768 key from `seed`, with key generation **outside**
/// the secret marking.
///
/// The seed arrives marked, so it is copied and the copy declassified before
/// `from_seed` sees it. Everything key generation computes is therefore public
/// as far as Memcheck is concerned, which is what keeps `ρ`-driven rejection
/// sampling out of the findings. The secret comes back in
/// [`with_key_level_secret`], on the components that are actually secret.
#[inline(always)]
pub fn public_keygen(seed: &[u8; SEED_LEN]) -> [u8; EXPANDED_LEN] {
    let public_seed = *seed;
    declassify(&public_seed);
    let key = DecapsulationKey768::from_seed(seed_array(&public_seed));
    #[allow(deprecated)]
    let expanded = key.to_expanded_bytes();
    let mut out = [0u8; EXPANDED_LEN];
    out.copy_from_slice(expanded.as_slice());
    out
}

/// Rebuilds the key with **only** `dk_pke` and `z` marked secret, and runs
/// `body` with it.
///
/// The guards are held across `body` because the marking has to be live while
/// the library decodes the bytes into its polynomial representation and while
/// it decapsulates — Memcheck propagates per byte, so a marking dropped before
/// the decode would leave the derived coefficients defined.
///
/// `body` also receives the expanded buffer, which is marked for its duration:
/// the controls branch on a byte of it to show which side of the boundary that
/// byte landed on.
///
/// # Panics
///
/// If the expanded encoding fails validation, which for a key this function
/// derived means the layout constants are wrong — not that an input was bad.
#[inline(always)]
pub fn with_key_level_secret<R>(
    expanded: &[u8; EXPANDED_LEN],
    body: impl FnOnce(&DecapsulationKey768, &[u8; EXPANDED_LEN]) -> R,
) -> R {
    let dk_pke_guard = Secret::new(&expanded[..DK_PKE_LEN]);
    let z_guard = Secret::new(&expanded[Z_OFFSET..]);

    #[allow(deprecated)]
    let encoded = Array::<u8, <DecapsulationKey768 as ExpandedKeyEncoding>::EncodedSize>::try_from(
        expanded.as_slice(),
    )
    .expect("the expanded width is a constant of the parameter set");
    #[allow(deprecated)]
    let key = DecapsulationKey768::from_expanded_bytes(&encoded)
        .expect("an expanded key this crate derived must validate");

    let out = body(&key, expanded);
    drop(dk_pke_guard);
    drop(z_guard);
    out
}

/// Marks the seed and derives the key with **nothing** declassified.
///
/// This is the seed-level encoding: the strongest relational statement
/// available — no observation may depend on the seed — and the one whose
/// findings include public data derived from the seed.
#[inline(always)]
pub fn seed_level(seed: &[u8; SEED_LEN]) -> DecapsulationKey768 {
    DecapsulationKey768::from_seed(seed_array(seed))
}

/// A genuinely valid ciphertext for the key in `expanded`, with its shared key.
///
/// Built with the library's own deterministic encapsulation from the public
/// `m`, through an encapsulation key reconstructed from the *public* bytes of
/// the expanded encoding. Nothing here reads a secret component, so the
/// ciphertext is public by construction rather than by declassification.
///
/// # Panics
///
/// If the public bytes do not decode as an encapsulation key, which again would
/// mean the layout constants are wrong.
#[inline(always)]
pub fn valid_ciphertext(
    expanded: &[u8; EXPANDED_LEN],
    m: &[u8; 32],
) -> ([u8; CIPHERTEXT_LEN], [u8; 32]) {
    let ek_bytes = Array::try_from(&expanded[EK_OFFSET..H_OFFSET])
        .expect("EK_LEN bytes is an ML-KEM-768 encapsulation key");
    let ek = EncapsulationKey768::new(&ek_bytes).expect("a derived encapsulation key must decode");
    let (encapsulated, shared) = ek.encapsulate_deterministic(&Array(*m));

    let mut ciphertext_bytes = [0u8; CIPHERTEXT_LEN];
    ciphertext_bytes.copy_from_slice(encapsulated.as_slice());
    let mut shared_bytes = [0u8; 32];
    shared_bytes.copy_from_slice(shared.as_slice());
    (ciphertext_bytes, shared_bytes)
}

/// A valid ciphertext with one byte changed, which drives implicit rejection.
///
/// `position` and `delta` are public: they are the attacker's choice of
/// corruption, not a property of the key. `delta | 1` keeps the corruption from
/// being a no-op, so the rejection path is reached for every generated input
/// rather than for most of them.
#[inline(always)]
pub fn corrupted_ciphertext(
    expanded: &[u8; EXPANDED_LEN],
    m: &[u8; 32],
    position: u16,
    delta: u8,
) -> [u8; CIPHERTEXT_LEN] {
    let (mut bytes, _) = valid_ciphertext(expanded, m);
    let index = usize::from(position) % CIPHERTEXT_LEN;
    bytes[index] ^= delta | 1;
    bytes
}
