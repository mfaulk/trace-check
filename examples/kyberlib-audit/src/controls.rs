//! Controls, mirroring the `ml-kem` audit's so the two targets' results are
//! comparable: one that shows the harness marked the seed, one that catches
//! over-declassification, one on a public component that must stay clean, **two**
//! sensitivity controls -- one per data path through the Fujisaki-Okamoto
//! transform -- and a negative control.
//!
//! The two sensitivity controls are not interchangeable. A valid ciphertext's
//! shared secret depends on `sk_pke` through decryption and re-encryption; a
//! rejected one is derived from the implicit-rejection seed `z` and the
//! ciphertext, and from nothing the decryption produced. The rejected path is
//! the one a decapsulation oracle attacks.

use crate::fixture::{self, PK_OFFSET};
use crate::sink::consume_all_bytes;
use trace_check_macros::constant_time;

static SBOX: [u8; 32] = [
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb, 0x16, 0x14,
    0x1c, 0x15, 0x10, 0x17, 0x12, 0x1e, 0x11, 0x1f, 0x13, 0x1d, 0x18, 0x1a, 0x19, 0x1b,
];

static mut SIDE_EFFECT: u8 = 0;

/// A side effect the optimizer may neither elide nor hoist, so a branch
/// guarding it survives `opt-level = 3`.
#[inline(never)]
fn record(value: u8) {
    // SAFETY: one case per process, single-threaded. The write exists only to
    // be an effect the compiler must keep.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SIDE_EFFECT), value) }
}

/// Control 1 — a branch on `seed[0]` before key generation. Shows the harness
/// marked the array, and nothing else.
#[constant_time(secret = "seed", dynamic = false)]
pub fn pre_keygen_seed_byte(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    if seed[0] & 1 == 1 {
        record(1);
    }
    let (decap, encap) = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&encap, m);
    let shared = fixture::with_key_level_secret(&decap, |key, _| {
        consume_all_bytes(
            key.decapsulate(&fixture::ciphertext(&ciphertext))
                .as_bytes(),
        )
    });
    shared ^ 0x01
}

/// Control 2 — a branch on a byte of `sk_pke` after the boundary is drawn. If
/// this reads as public, the boundary declassified genuine key material.
#[constant_time(secret = "seed", dynamic = false)]
pub fn secret_component_branch(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&encap, m);
    let shared = fixture::with_key_level_secret(&decap, |key, marked| {
        if marked[0] & 1 == 1 {
            record(2);
        }
        consume_all_bytes(
            key.decapsulate(&fixture::ciphertext(&ciphertext))
                .as_bytes(),
        )
    });
    shared ^ 0x02
}

/// Control 3 — a secret-derived load address, indexed by a byte of `sk_pke`.
#[constant_time(secret = "seed", dynamic = false)]
pub fn secret_component_address(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&encap, m);
    let shared = fixture::with_key_level_secret(&decap, |key, marked| {
        let substituted = SBOX[usize::from(marked[7] & 0x1f)];
        record(substituted);
        consume_all_bytes(
            key.decapsulate(&fixture::ciphertext(&ciphertext))
                .as_bytes(),
        ) ^ substituted
    });
    shared ^ 0x03
}

/// Control 4 — a branch on a byte of the public key, under the key-level
/// boundary. Expected clean: the attacker holds the public key.
#[constant_time(secret = "seed", dynamic = false)]
pub fn public_component_branch(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&encap, m);
    let shared = fixture::with_key_level_secret(&decap, |key, marked| {
        if marked[PK_OFFSET] & 1 == 1 {
            record(4);
        }
        consume_all_bytes(
            key.decapsulate(&fixture::ciphertext(&ciphertext))
                .as_bytes(),
        )
    });
    shared ^ 0x04
}

/// Control 5 — the sensitivity control for the **valid** path: a branch on a
/// byte of the shared secret a genuine ciphertext produces.
///
/// That value depends on `sk_pke` through decryption and re-encryption, and
/// **not** on `z`. [`rejected_shared_secret_branch`] covers the other path, and
/// neither stands in for the other.
#[constant_time(secret = "seed", dynamic = false)]
pub fn shared_secret_branch(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&encap, m);
    let shared = fixture::with_key_level_secret(&decap, |key, _| {
        let shared = key.decapsulate(&fixture::ciphertext(&ciphertext));
        if shared.as_bytes()[0] & 1 == 1 {
            record(5);
        }
        consume_all_bytes(shared.as_bytes())
    });
    shared ^ 0x05
}

/// Control 7 — the sensitivity control for the **implicit-rejection** secret: a
/// branch on the shared secret an *invalid* ciphertext produces.
///
/// For a corrupted ciphertext the re-encryption check fails and the selection
/// returns a value derived from `z` and the ciphertext. That is the data a
/// decapsulation oracle attacks, and it reaches the branch through a hash, so
/// it needs its own control rather than an argument from control 5.
///
/// `the_rejected_secret_depends_on_z` is the independent evidence that the
/// value branched on here really is `z`-derived.
#[constant_time(secret = "seed", dynamic = false)]
pub fn rejected_shared_secret_branch(
    seed: &[u8; 64],
    m: &[u8; 32],
    position: u16,
    delta: u8,
) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let ciphertext = fixture::corrupted_ciphertext(&encap, m, position, delta);
    let shared = fixture::with_key_level_secret(&decap, |key, _| {
        let shared = key.decapsulate(&fixture::ciphertext(&ciphertext));
        if shared.as_bytes()[0] & 1 == 1 {
            record(7);
        }
        consume_all_bytes(shared.as_bytes())
    });
    shared ^ 0x07
}

/// Control 6 — the negative control: the boundary with nothing planted.
#[constant_time(secret = "seed", dynamic = false)]
pub fn no_planted_leak(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let (decap, encap) = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&encap, m);
    let shared = fixture::with_key_level_secret(&decap, |key, _| {
        consume_all_bytes(
            key.decapsulate(&fixture::ciphertext(&ciphertext))
                .as_bytes(),
        )
    });
    shared ^ 0x06
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::SEED_LEN;

    /// The value [`rejected_shared_secret_branch`] branches on really is
    /// derived from `z`: changing `z` alone, with everything else and the
    /// ciphertext fixed, changes it -- and leaves the valid-ciphertext result
    /// untouched.
    ///
    /// Goes through the byte-oriented API because `MlKem768DecapKey` has no byte
    /// constructor, so a modified `z` cannot be handed to the typed one.
    /// `the_blob_and_typed_paths_agree` in `tests/functional.rs` is what ties
    /// the two together, on both ciphertext paths.
    #[test]
    #[allow(deprecated)]
    fn the_rejected_secret_depends_on_z() {
        use crate::fixture::{SECRET_KEY_LEN, Z_OFFSET};

        let seed = [23u8; SEED_LEN];
        let m = [7u8; 32];
        let (decap, encap) = fixture::public_keygen(&seed);
        let rejecting = fixture::corrupted_ciphertext(&encap, &m, 5, 0x20);
        let (valid, encapsulated) = fixture::valid_ciphertext(&encap, &m);

        let mut secret: [u8; SECRET_KEY_LEN] = *decap.as_bytes();
        let before = kyberlib::decapsulate(&rejecting, &secret).expect("lengths are constants");

        secret[Z_OFFSET] ^= 1;
        let after = kyberlib::decapsulate(&rejecting, &secret).expect("lengths are constants");

        assert_ne!(
            before, after,
            "the rejected shared secret must depend on z, or control 7 is not about z"
        );
        assert_eq!(
            kyberlib::decapsulate(&valid, &secret).expect("lengths are constants"),
            encapsulated,
            "the valid path must not depend on z"
        );
    }

    /// Every control still decapsulates correctly, so a detected control is
    /// evidence about observation rather than about a broken fixture.
    #[test]
    fn the_controls_preserve_the_shared_secret() {
        let seed = [13u8; SEED_LEN];
        let m = [4u8; 32];
        let (_, encap) = fixture::public_keygen(&seed);
        let (_, expected) = fixture::valid_ciphertext(&encap, &m);
        let folded = consume_all_bytes(&expected);

        assert_eq!(pre_keygen_seed_byte(&seed, &m), folded ^ 0x01);
        assert_eq!(secret_component_branch(&seed, &m), folded ^ 0x02);
        assert_eq!(public_component_branch(&seed, &m), folded ^ 0x04);
        assert_eq!(shared_secret_branch(&seed, &m), folded ^ 0x05);
        assert_eq!(no_planted_leak(&seed, &m), folded ^ 0x06);
    }
}
