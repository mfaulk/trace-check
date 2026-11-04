//! Target C — Montgomery modular multiplication,
//! `crypto_bigint::modular::ConstMontyForm::mul`.
//!
//! The most realistic of the three: multi-limb multiplication, carry
//! propagation, Montgomery representation, modular reduction, and fixed
//! cryptographic parameters, all at once.
//!
//! # The modulus, and why no input is restricted
//!
//! The pinned modulus is the NIST P-256 field prime,
//! `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`. It is public, odd, and a constant —
//! which is the usual cryptographic situation, and the only one audited here.
//! An audit of a *secret* modulus is a different threat model.
//!
//! `ConstMontyForm::new` is a Montgomery multiplication by `R^2 mod p`, so it
//! reduces its argument. Any 256-bit value is therefore a valid input, the
//! adapter needs no reduction step of its own, and — importantly — it needs no
//! secret-dependent rejection branch. That was checked against the pinned
//! source rather than assumed; see
//! `docs/audits/crypto-bigint/target-selection.md`.

use crate::sink::{consume_all_bytes, result_array};
use crypto_bigint::modular::ConstMontyParams;
use crypto_bigint::{const_monty_form, const_monty_params, U256};
use trace_check_macros::constant_time;

const_monty_params!(
    P256Prime,
    U256,
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "The NIST P-256 field prime, 2^256 - 2^224 + 2^192 + 2^96 - 1."
);

const_monty_form!(Fp, P256Prime);

/// `left * right mod p`, as the **complete** 32-byte result.
///
/// Shared by both adapters below and by the functional tests; see
/// `add::wrapping_add_bytes` for why a correctness test cannot compare through
/// the sink. This is the helper that would catch a Montgomery conversion
/// applied in the wrong direction, which a lossy comparison might not.
#[inline(always)]
pub fn mul_bytes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let a = Fp::new(&U256::from_be_slice(left));
    let b = Fp::new(&U256::from_be_slice(right));
    result_array(a.mul(&b).retrieve().to_be_bytes().as_slice())
}

/// Per-contract discriminants; see `add::SECRET_LEFT_TAG` for why these exist.
pub const MUL_SECRET_LEFT_TAG: u8 = 0x1e;
pub const MUL_BOTH_SECRET_TAG: u8 = 0xe1;

/// `left * right mod p`, with `left` secret and `right` public.
///
/// The adapter decodes, converts both operands into Montgomery form with the
/// library's own `new`, calls the library's own `mul`, converts back with
/// `retrieve`, and folds the whole result.
#[constant_time(secret = "left", dynamic = false)]
pub fn mul_secret_left(left: &[u8; 32], right: &[u8; 32]) -> u8 {
    consume_all_bytes(&mul_bytes(left, right)) ^ MUL_SECRET_LEFT_TAG
}

/// The same operation with **both** operands secret.
#[constant_time(secret = "left", secret = "right", dynamic = false)]
pub fn mul_both_secret(left: &[u8; 32], right: &[u8; 32]) -> u8 {
    consume_all_bytes(&mul_bytes(left, right)) ^ MUL_BOTH_SECRET_TAG
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned modulus is the P-256 prime, and it is odd — which Montgomery
    /// arithmetic requires. A typo in the hex literal would otherwise be
    /// invisible until a result disagreed with the oracle.
    #[test]
    fn the_modulus_is_the_p256_prime_and_is_odd() {
        let modulus = Fp::MODULUS.get();
        assert_eq!(modulus.as_words()[0] & 1, 1, "the modulus must be odd");
        // 2^256 - 2^224 + 2^192 + 2^96 - 1, assembled independently of the
        // hex literal above.
        let expected = U256::ZERO
            .wrapping_sub(&U256::ONE.shl_vartime(224))
            .wrapping_add(&U256::ONE.shl_vartime(192))
            .wrapping_add(&U256::ONE.shl_vartime(96))
            .wrapping_sub(&U256::ONE);
        assert_eq!(modulus, expected);
    }

    /// Zero and one behave as the field's identities, which is the cheapest
    /// check that the Montgomery conversion in and out is not transposed.
    #[test]
    fn zero_and_one_are_the_field_identities() {
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[31] = 1;
        let value = [0x5au8; 32];

        assert_eq!(mul_bytes(&value, &zero), zero);
        assert_eq!(
            mul_bytes(&value, &one),
            value,
            "multiplying by one must be the identity"
        );
    }

    /// Multiplication is commutative in the field, so the two secret roles
    /// agree with each other once their discriminants are removed. This is
    /// also what catches an adapter that passed its operands in the wrong
    /// order to a non-commutative operation.
    #[test]
    fn the_two_secret_roles_compute_the_same_product() {
        let left = [0x5au8; 32];
        let right = [0xa5u8; 32];
        assert_eq!(mul_bytes(&left, &right), mul_bytes(&right, &left));
        assert_eq!(
            mul_secret_left(&left, &right) ^ MUL_SECRET_LEFT_TAG,
            mul_both_secret(&right, &left) ^ MUL_BOTH_SECRET_TAG
        );
    }

    /// An input at or above the modulus is reduced rather than rejected, which
    /// is the property that lets the adapter accept every 256-bit value and
    /// carry no validity branch.
    #[test]
    fn inputs_above_the_modulus_are_reduced() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let modulus = Fp::MODULUS.get().to_be_bytes();
        let reduced: [u8; 32] = modulus.as_slice().try_into().unwrap();
        // p mod p == 0, so p * 1 == 0 in the field.
        assert_eq!(mul_bytes(&reduced, &one), [0u8; 32]);
        // The all-ones value is 2^256 - 1, comfortably above p.
        let max = [0xffu8; 32];
        assert_ne!(mul_bytes(&max, &one), max);
    }
}
