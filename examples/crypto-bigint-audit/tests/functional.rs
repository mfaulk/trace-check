//! The adapters against an independent arithmetic oracle.
//!
//! A side-channel result describes whatever the artifact computed. If an
//! adapter decodes the wrong byte order, truncates an operand, builds a
//! Montgomery value incorrectly or consumes the wrong part of a result, the
//! checker reports confidently about an operation that is not the one the
//! contract names — and nothing in the security pipeline would notice.
//!
//! So these run first, and the expected values come from
//! `ci/gen-m9-vectors.py`, which computes them in Python's
//! arbitrary-precision integers. The reference shares no code with
//! `crypto-bigint`, so an adapter mistake cannot cancel against the
//! implementation under audit.
//!
//! # Why these compare 32 bytes and not the adapters' return value
//!
//! The output sink folds a 256-bit result into one byte, so it maps 2^256
//! results onto 256 values — and because the fold is linear mod 256, two byte
//! changes can cancel exactly (`sink::the_fold_is_lossy_and_must_not_be_used_for_correctness`
//! pins a concrete collision). Comparing through it would give randomized
//! confidence and nothing more, which is not enough for the mutation
//! experiments: those claim a mutation changed observable behavior **without**
//! changing the arithmetic.
//!
//! So each operation has a helper returning the complete 32-byte result, the
//! annotated adapter folds that helper's output, and these tests compare the
//! helper. One code path, two consumers — not a parallel implementation.

use cbaudit::{
    add::{self, wrapping_add_bytes},
    monty::{self, mul_bytes},
    select::{self, ct_select_bytes},
    sink::consume_all_bytes,
};

mod vectors {
    include!("vectors/generated.rs");
}

/// Decodes one 64-digit big-endian hex fixture.
fn bytes(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "a 256-bit fixture is 64 hex digits: {hex}");
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("not hex: {hex}"));
    }
    out
}

/// The hex decoder is correct, which everything below depends on.
#[test]
fn the_fixture_decoder_round_trips() {
    assert_eq!(bytes(&"00".repeat(32)), [0u8; 32]);
    assert_eq!(bytes(&"ff".repeat(32)), [0xffu8; 32]);
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(bytes(&format!("{}01", "00".repeat(31))), one);
    // Big-endian: the first digit pair is the most significant byte.
    let mut high = [0u8; 32];
    high[0] = 0x80;
    assert_eq!(bytes(&format!("80{}", "00".repeat(31))), high);
}

/// `U256::wrapping_add` agrees with `(left + right) mod 2^256` on every
/// fixture, byte for byte.
#[test]
fn wrapping_add_matches_the_oracle() {
    assert!(!vectors::ADD.is_empty(), "the fixture is empty");
    for (left, right, expected) in vectors::ADD {
        let (left, right, expected) = (bytes(left), bytes(right), bytes(expected));
        assert_eq!(
            wrapping_add_bytes(&left, &right),
            expected,
            "wrapping_add disagrees with the oracle"
        );
    }
}

/// Both `wrapping_add` contracts are that helper plus their own discriminant,
/// so validating the helper validates what the contracts analyze.
#[test]
fn the_wrapping_add_adapters_fold_the_validated_helper() {
    for (left, right, _) in vectors::ADD.iter().take(64) {
        let (left, right) = (bytes(left), bytes(right));
        let folded = consume_all_bytes(&wrapping_add_bytes(&left, &right));
        assert_eq!(
            add::wrapping_add_secret_left(&left, &right),
            folded ^ add::SECRET_LEFT_TAG
        );
        assert_eq!(
            add::wrapping_add_both_secret(&left, &right),
            folded ^ add::BOTH_SECRET_TAG
        );
    }
}

/// `CtSelect` selects by bit 0 of the choice byte, on every fixture, byte for
/// byte — and the fixture covers all 256 byte values, so no other reading of
/// the byte passes.
#[test]
fn ct_select_matches_the_oracle() {
    assert!(!vectors::SELECT.is_empty(), "the fixture is empty");
    for (first, second, choice, expected) in vectors::SELECT {
        let (first, second, expected) = (bytes(first), bytes(second), bytes(expected));
        assert_eq!(
            ct_select_bytes(&first, &second, *choice),
            expected,
            "ct_select disagrees with the oracle for choice {choice:#04x}"
        );
    }
}

/// The selection contract is that helper plus its discriminant.
#[test]
fn the_select_adapter_folds_the_validated_helper() {
    for (first, second, choice, _) in vectors::SELECT.iter().take(64) {
        let (first, second) = (bytes(first), bytes(second));
        assert_eq!(
            select::ct_select(&first, &second, *choice),
            consume_all_bytes(&ct_select_bytes(&first, &second, *choice)) ^ select::CT_SELECT_TAG
        );
    }
}

/// `ConstMontyForm::mul` agrees with `(left * right) mod p` on every fixture,
/// byte for byte. This is the test that would catch a Montgomery conversion
/// applied in the wrong direction, or a modulus that is not the one the oracle
/// used — neither of which a comparison through the lossy sink could be relied
/// on to catch.
#[test]
fn montgomery_multiplication_matches_the_oracle() {
    assert!(!vectors::MUL_MOD_P256.is_empty(), "the fixture is empty");
    for (left, right, expected) in vectors::MUL_MOD_P256 {
        let (left, right, expected) = (bytes(left), bytes(right), bytes(expected));
        assert_eq!(
            mul_bytes(&left, &right),
            expected,
            "mul disagrees with the oracle"
        );
    }
}

/// Both Montgomery contracts are that helper plus their own discriminant.
#[test]
fn the_montgomery_adapters_fold_the_validated_helper() {
    for (left, right, _) in vectors::MUL_MOD_P256.iter().take(64) {
        let (left, right) = (bytes(left), bytes(right));
        let folded = consume_all_bytes(&mul_bytes(&left, &right));
        assert_eq!(
            monty::mul_secret_left(&left, &right),
            folded ^ monty::MUL_SECRET_LEFT_TAG
        );
        assert_eq!(
            monty::mul_both_secret(&left, &right),
            folded ^ monty::MUL_BOTH_SECRET_TAG
        );
    }
}

/// The adapter's modulus is the one the oracle reduced by. Two independent
/// statements of the P-256 prime — a hex literal in `monty.rs` and an
/// arithmetic expression in the generator — and they have to agree, or every
/// product above is checked against the wrong field.
#[test]
fn the_adapter_and_the_oracle_share_a_modulus() {
    let expected = bytes(vectors::P256_PRIME);
    let mut one = [0u8; 32];
    one[31] = 1;
    // p is congruent to 0, so p * 1 == 0 in the adapter's field. Any other
    // modulus makes this product nonzero.
    assert_eq!(
        mul_bytes(&expected, &one),
        [0u8; 32],
        "the adapter's modulus is not the oracle's"
    );
}

/// Every contract's discriminant is distinct. Equal tags would restore the
/// bit-identical bodies that defeat per-contract attribution — see
/// `docs/audits/crypto-bigint/integration-report.md`.
#[test]
fn the_contract_discriminants_are_all_distinct() {
    let tags = [
        add::SECRET_LEFT_TAG,
        add::BOTH_SECRET_TAG,
        select::CT_SELECT_TAG,
        monty::MUL_SECRET_LEFT_TAG,
        monty::MUL_BOTH_SECRET_TAG,
    ];
    for (index, tag) in tags.iter().enumerate() {
        for other in &tags[index + 1..] {
            assert_ne!(tag, other, "two contracts share a discriminant");
        }
    }
}
