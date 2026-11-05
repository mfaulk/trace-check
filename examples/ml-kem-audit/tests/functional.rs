//! The audit adapters against NIST ACVP vectors for ML-KEM-768.
//!
//! The adapters are what trace-check analyzes, so if one of them computes
//! something other than ML-KEM-768 then every security result in this audit
//! describes the wrong operation. These tests are the independent evidence that
//! it does not: the expected values are NIST's published data, which shares no
//! code with `ml-kem` and none with this repository, so an adapter mistake
//! cannot cancel against the implementation under audit.
//!
//! Three things are checked, one per stage of what a contract does:
//!
//! 1. key derivation — `(d, z)` produces the expected expanded key;
//! 2. ciphertext construction — `(ek, m)` produces the expected ciphertext and
//!    shared key;
//! 3. decapsulation through the classification boundary — `(dk, c)` produces
//!    the expected shared key, for **both** modified and unmodified
//!    ciphertexts.
//!
//! Stage 3 is the one that matters most. NIST's decapsulation group supplies
//! five unmodified and five modified ciphertexts under one key, which is
//! independent evidence that both paths through the Fujisaki–Okamoto transform
//! are exercised — not a corpus that happened to reach only one of them.

mod vectors {
    pub mod acvp;
}

use mlkemaudit::fixture;
use mlkemaudit::layout::{CIPHERTEXT_LEN, EK_OFFSET, EXPANDED_LEN, H_OFFSET, SEED_LEN};
use ml_kem::Decapsulate;
use vectors::acvp::{DECAPSULATION, ENCAPSULATION, KEY_GEN};

/// Decodes lowercase hex, panicking on anything that is not a vector.
fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex must be whole bytes");
    (0..hex.len() / 2)
        .map(|index| {
            u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("vector hex is valid")
        })
        .collect()
}

fn fixed<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = unhex(hex);
    assert_eq!(bytes.len(), N, "vector width");
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

/// Deriving a key from `d ‖ z` reproduces NIST's expanded decapsulation key and
/// its encapsulation key, so `public_keygen` really is FIPS 203 key generation
/// and the layout offsets really do locate `ek` inside the encoding.
#[test]
fn key_derivation_matches_the_acvp_vectors() {
    assert!(KEY_GEN.len() >= 25, "the fixture must not shrink silently");
    for &(tc, d, z, dk, ek) in KEY_GEN {
        let mut seed = [0u8; SEED_LEN];
        seed[..32].copy_from_slice(&unhex(d));
        seed[32..].copy_from_slice(&unhex(z));

        let derived = fixture::public_keygen(&seed);
        assert_eq!(
            derived.to_vec(),
            unhex(dk),
            "tcId {tc}: expanded decapsulation key"
        );
        assert_eq!(
            derived[EK_OFFSET..H_OFFSET].to_vec(),
            unhex(ek),
            "tcId {tc}: the encapsulation key inside the encoding"
        );
    }
}

/// Deterministic encapsulation under NIST's `ek` with NIST's `m` reproduces its
/// ciphertext and shared key, so the ciphertext a contract decapsulates is a
/// genuine ML-KEM-768 ciphertext rather than something merely well-formed.
#[test]
fn encapsulation_matches_the_acvp_vectors() {
    assert!(ENCAPSULATION.len() >= 25, "the fixture must not shrink silently");
    for &(tc, ek, m, c, k) in ENCAPSULATION {
        let (ciphertext, shared) = fixture::encapsulate_to(&unhex(ek), &fixed::<32>(m));
        assert_eq!(ciphertext.to_vec(), unhex(c), "tcId {tc}: ciphertext");
        assert_eq!(shared.to_vec(), unhex(k), "tcId {tc}: shared key");
    }
}

/// Decapsulation through the classification boundary reproduces NIST's shared
/// key for every vector, including the modified ciphertexts that drive implicit
/// rejection — so the boundary's declassify-and-re-mark sequence does not change
/// what the operation computes.
#[test]
fn decapsulation_matches_the_acvp_vectors_on_both_paths() {
    let mut unmodified = 0;
    let mut modified = 0;

    for &(tc, dk, c, k, reason) in DECAPSULATION {
        let expanded: [u8; EXPANDED_LEN] = fixed(dk);
        let ciphertext: [u8; CIPHERTEXT_LEN] = fixed(c);

        let shared = fixture::with_key_level_secret(&expanded, |key, _| {
            let shared = key.decapsulate(&fixture::ciphertext(&ciphertext));
            shared.as_slice().to_vec()
        });
        assert_eq!(shared, unhex(k), "tcId {tc} ({reason}): shared key");

        if reason == "no modification" {
            unmodified += 1;
        } else {
            modified += 1;
        }
    }

    // Both FO paths covered, by NIST's own classification rather than by
    // inference from the inputs.
    assert!(unmodified >= 5, "unmodified ciphertext vectors: {unmodified}");
    assert!(modified >= 5, "modified ciphertext vectors: {modified}");
}

/// A modified ciphertext's shared key differs from the one its unmodified
/// sibling produces, which is what makes the previous test evidence about two
/// paths rather than about one path run twice.
#[test]
fn the_two_paths_produce_different_shared_keys() {
    let unmodified: Vec<_> = DECAPSULATION
        .iter()
        .filter(|row| row.4 == "no modification")
        .collect();
    let modified: Vec<_> = DECAPSULATION
        .iter()
        .filter(|row| row.4 != "no modification")
        .collect();
    assert!(!unmodified.is_empty() && !modified.is_empty());

    // Same key across the group, so the shared keys are comparable.
    assert_eq!(unmodified[0].1, modified[0].1, "one key per ACVP VAL group");
    assert_ne!(
        unmodified[0].3, modified[0].3,
        "implicit rejection must not return the key a valid ciphertext does"
    );
}

/// The fixture's own widths match the parameter set, so a vector file swapped
/// for another parameter set's fails here rather than deep inside a decode.
#[test]
fn the_vectors_are_ml_kem_768() {
    for &(tc, d, z, dk, ek) in KEY_GEN {
        assert_eq!(unhex(d).len(), 32, "tcId {tc}");
        assert_eq!(unhex(z).len(), 32, "tcId {tc}");
        assert_eq!(unhex(dk).len(), EXPANDED_LEN, "tcId {tc}");
        assert_eq!(unhex(ek).len(), H_OFFSET - EK_OFFSET, "tcId {tc}");
    }
    for &(tc, dk, c, k, _) in DECAPSULATION {
        assert_eq!(unhex(dk).len(), EXPANDED_LEN, "tcId {tc}");
        assert_eq!(unhex(c).len(), CIPHERTEXT_LEN, "tcId {tc}");
        assert_eq!(unhex(k).len(), 32, "tcId {tc}");
    }
}
