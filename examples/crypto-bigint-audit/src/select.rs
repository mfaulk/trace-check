//! Target B — constant-time selection, `crypto_bigint`'s `CtSelect` for
//! `U256`.
//!
//! Conditional selection is the idiom constant-time cryptographic code is
//! built out of: scalar multiplication, modular reduction and point arithmetic
//! all reduce to choosing between candidates without branching. So this target
//! tests the idiom directly rather than an operation that merely happens to
//! use it.
//!
//! The adapter's one real obligation is to build the library's `Choice` from a
//! secret byte **without a branch**. `Choice::from_u8_lsb` is `value & 1`, so
//! there is nothing to erase and nothing to get wrong; the alternative — an
//! `if` on the secret, then picking a candidate — is
//! `controls::branch_selected`, which is expected to be detected.

use crate::sink::consume_all_bytes;
use crypto_bigint::{Choice, CtSelect, U256};
use trace_check_macros::constant_time;

/// Per-contract discriminant; see `add::SECRET_LEFT_TAG` for why these exist.
pub const CT_SELECT_TAG: u8 = 0x3c;

/// `if choice & 1 { second } else { first }`, through the library's own
/// `CtSelect` implementation.
///
/// All three inputs are secret. Selection between public candidates on a
/// public condition would not be a constant-time concern, and a secret
/// condition with public candidates still leaks which candidate was taken
/// through the result — the interesting claim is the one where everything is
/// secret.
#[constant_time(
    secret = "first",
    secret = "second",
    secret = "choice",
    dynamic = false
)]
pub fn ct_select(first: &[u8; 32], second: &[u8; 32], choice: u8) -> u8 {
    let a = U256::from_be_slice(first);
    let b = U256::from_be_slice(second);
    let selected = a.ct_select(&b, Choice::from_u8_lsb(choice));
    consume_all_bytes(selected.to_be_bytes().as_slice()) ^ CT_SELECT_TAG
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both outcomes are reachable and correct: bit 0 clear selects the first
    /// candidate, set selects the second.
    #[test]
    fn both_selection_outcomes_are_correct() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        assert_eq!(
            ct_select(&first, &second, 0) ^ CT_SELECT_TAG,
            consume_all_bytes(&first)
        );
        assert_eq!(
            ct_select(&first, &second, 1) ^ CT_SELECT_TAG,
            consume_all_bytes(&second)
        );
    }

    /// Only bit 0 of the selection byte matters, which is what
    /// `Choice::from_u8_lsb` promises. A generated corpus supplies all 256
    /// values, so a different reading of the byte would be a different
    /// function.
    #[test]
    fn only_the_low_bit_of_the_choice_matters() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        for byte in 0u8..=u8::MAX {
            let expected = if byte & 1 == 0 { &first } else { &second };
            assert_eq!(
                ct_select(&first, &second, byte) ^ CT_SELECT_TAG,
                consume_all_bytes(expected),
                "choice byte {byte:#04x}"
            );
        }
    }

    /// Identical candidates: the result cannot depend on the choice, which is
    /// the degenerate case an implementation that read the wrong operand would
    /// still pass — so it is here to pin the behavior, not to prove anything.
    #[test]
    fn identical_candidates_select_the_same_value() {
        let same = [0x7fu8; 32];
        assert_eq!(ct_select(&same, &same, 0), ct_select(&same, &same, 1));
    }

    /// Selection is per-limb, so a difference confined to the highest or the
    /// lowest limb must still be carried through. A per-limb mistake in the
    /// adapter or a partial select would show up here and nowhere else.
    #[test]
    fn selection_carries_the_highest_and_lowest_limbs() {
        for position in [0usize, 7, 8, 23, 24, 31] {
            let first = [0u8; 32];
            let mut second = [0u8; 32];
            second[position] = 0xff;
            assert_ne!(
                ct_select(&first, &second, 0),
                ct_select(&first, &second, 1),
                "a difference at byte {position} was not selected"
            );
            assert_eq!(
                ct_select(&first, &second, 1) ^ CT_SELECT_TAG,
                consume_all_bytes(&second)
            );
        }
    }
}
