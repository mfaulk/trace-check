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

use cbaudit::{add, monty, select, sink::consume_all_bytes};

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
/// fixture, for both secret roles.
#[test]
fn wrapping_add_matches_the_oracle() {
    assert!(!vectors::ADD.is_empty(), "the fixture is empty");
    for (left, right, expected) in vectors::ADD {
        let (left, right, expected) = (bytes(left), bytes(right), bytes(expected));
        let folded = consume_all_bytes(&expected);
        assert_eq!(
            add::wrapping_add_secret_left(&left, &right) ^ add::SECRET_LEFT_TAG,
            folded,
            "wrapping_add_secret_left disagrees with the oracle"
        );
        assert_eq!(
            add::wrapping_add_both_secret(&left, &right) ^ add::BOTH_SECRET_TAG,
            folded,
            "wrapping_add_both_secret disagrees with the oracle"
        );
    }
}

/// `CtSelect` selects by bit 0 of the choice byte, on every fixture — and the
/// fixture covers all 256 byte values, so no other reading of the byte passes.
#[test]
fn ct_select_matches_the_oracle() {
    assert!(!vectors::SELECT.is_empty(), "the fixture is empty");
    for (first, second, choice, expected) in vectors::SELECT {
        let (first, second, expected) = (bytes(first), bytes(second), bytes(expected));
        assert_eq!(
            select::ct_select(&first, &second, *choice) ^ select::CT_SELECT_TAG,
            consume_all_bytes(&expected),
            "ct_select disagrees with the oracle for choice {choice:#04x}"
        );
    }
}

/// `ConstMontyForm::mul` agrees with `(left * right) mod p` on every fixture,
/// for both secret roles. This is the test that would catch a Montgomery
/// conversion applied in the wrong direction, or a modulus that is not the one
/// the oracle used.
#[test]
fn montgomery_multiplication_matches_the_oracle() {
    assert!(!vectors::MUL_MOD_P256.is_empty(), "the fixture is empty");
    for (left, right, expected) in vectors::MUL_MOD_P256 {
        let (left, right, expected) = (bytes(left), bytes(right), bytes(expected));
        let folded = consume_all_bytes(&expected);
        assert_eq!(
            monty::mul_secret_left(&left, &right) ^ monty::MUL_SECRET_LEFT_TAG,
            folded,
            "mul_secret_left disagrees with the oracle"
        );
        assert_eq!(
            monty::mul_both_secret(&left, &right) ^ monty::MUL_BOTH_SECRET_TAG,
            folded,
            "mul_both_secret disagrees with the oracle"
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
        monty::mul_secret_left(&expected, &one) ^ monty::MUL_SECRET_LEFT_TAG,
        consume_all_bytes(&[0u8; 32]),
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
