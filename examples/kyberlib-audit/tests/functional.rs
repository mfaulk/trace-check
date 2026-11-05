//! `kyberlib`'s ML-KEM-768 against NIST ACVP vectors.
//!
//! The same fixture the `ml-kem` audit uses, read from its directory rather
//! than duplicated, because 372 kB of hex committed twice is 372 kB that can
//! drift. The point of running it against a second implementation is that NIST
//! vectors settle a question no amount of API reading does: whether this
//! library computes the same function.
//!
//! Three results, and the third is the interesting one — see
//! `docs/audits/kyberlib/findings.md`.

// The encapsulation group is unused here: `kyberlib` encapsulates through an
// RNG, so a vector supplying explicit randomness has no entry point to use.
// Allowed rather than trimmed, because the fixture belongs to the other audit
// and must stay byte-identical to what its generator produces.
#[allow(dead_code)]
#[path = "../../ml-kem-audit/tests/vectors/acvp.rs"]
mod acvp;

use acvp::{DECAPSULATION, KEY_GEN};
use kyberaudit::fixture::{self, PK_OFFSET, SECRET_KEY_LEN, SEED_LEN};

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("vector hex"))
        .collect()
}

/// Deterministic key generation from `d ‖ z` reproduces NIST's expanded secret
/// key and its public key, so `kyberlib`'s key generation is FIPS 203's.
#[test]
fn key_derivation_matches_the_acvp_vectors() {
    assert!(KEY_GEN.len() >= 25);
    for &(tc, d, z, dk, ek) in KEY_GEN {
        let mut seed = [0u8; SEED_LEN];
        seed[..32].copy_from_slice(&unhex(d));
        seed[32..].copy_from_slice(&unhex(z));

        let (decap, encap) = fixture::public_keygen(&seed);
        assert_eq!(
            decap.as_bytes().to_vec(),
            unhex(dk),
            "tcId {tc}: secret key"
        );
        assert_eq!(
            encap.as_bytes().to_vec(),
            unhex(ek),
            "tcId {tc}: public key"
        );
        assert_eq!(
            decap.as_bytes()[PK_OFFSET..PK_OFFSET + 1184].to_vec(),
            unhex(ek),
            "tcId {tc}: the public key inside the secret key"
        );
    }
}

/// Decapsulation reproduces NIST's shared secret for every vector, including
/// the modified ciphertexts that drive implicit rejection — so both paths
/// through the FO transform compute what the standard says.
#[test]
fn decapsulation_matches_the_acvp_vectors_on_both_paths() {
    let mut unmodified = 0;
    let mut modified = 0;

    for &(tc, dk, c, k, reason) in DECAPSULATION {
        let secret: [u8; SECRET_KEY_LEN] = unhex(dk).try_into().expect("2400 bytes");
        let ciphertext: [u8; 1088] = unhex(c).try_into().expect("1088 bytes");

        // ACVP supplies the key as bytes, and `MlKem768DecapKey` has no byte
        // constructor, so this vector test goes through the blob API the crate
        // soft-deprecated. It is the same `kem_dec_generic` the typed path
        // calls; `the_blob_and_typed_paths_agree` is what keeps that true.
        #[allow(deprecated)]
        let shared = kyberlib::decapsulate(&ciphertext, &secret).expect("lengths are constants");
        assert_eq!(shared.to_vec(), unhex(k), "tcId {tc} ({reason})");

        if reason == "no modification" {
            unmodified += 1;
        } else {
            modified += 1;
        }
    }

    assert!(unmodified >= 5, "unmodified vectors: {unmodified}");
    assert!(modified >= 5, "modified vectors: {modified}");
}

/// The blob API the vector test uses and the typed API the contracts use
/// compute the same shared secret, so the functional evidence transfers to the
/// code actually analyzed.
#[test]
fn the_blob_and_typed_paths_agree() {
    let seed = [21u8; SEED_LEN];
    let m = [5u8; 32];
    let (decap, encap) = fixture::public_keygen(&seed);
    let (ciphertext, expected) = fixture::valid_ciphertext(&encap, &m);

    let typed = *decap
        .decapsulate(&fixture::ciphertext(&ciphertext))
        .as_bytes();
    #[allow(deprecated)]
    let blob = kyberlib::decapsulate(&ciphertext, decap.as_bytes()).expect("lengths are constants");

    assert_eq!(typed, expected, "the typed path recovers the shared secret");
    assert_eq!(blob.to_vec(), typed.to_vec());
}
