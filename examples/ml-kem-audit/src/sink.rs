//! A fixed-work output sink for a 32-byte shared key.
//!
//! The generated checker hands back one scalar, and a shared key does not fit
//! in one. What reduces it decides what the compiler may discard: a sink that
//! reads four of the thirty-two bytes licenses the optimizer to compute less
//! than a decapsulation, and then the artifact no longer contains the operation
//! the contract names.
//!
//! The requirement is narrow and testable: **every** byte must materially
//! change the result, with no branch and no secret-derived address. It is not a
//! hash and carries no cryptographic property, and it is lossy — so no
//! correctness test may compare through it.

/// Width of a shared key, and of everything this module folds.
pub const SHARED_KEY_BYTES: usize = 32;

/// Folds all 32 bytes into one, in fixed work.
///
/// Multiplying by 31 is invertible mod 256, so no byte's contribution can be
/// cancelled by a later one. The loop bound is a constant and the accumulator
/// feeds nothing but arithmetic, so the fold has no secret-dependent branch or
/// address of its own.
///
/// # Panics
///
/// If `bytes` is not [`SHARED_KEY_BYTES`] long. The length is a property of the
/// caller's type, never of a secret.
#[inline(never)]
pub fn consume_all_bytes(bytes: &[u8]) -> u8 {
    assert!(
        bytes.len() == SHARED_KEY_BYTES,
        "the sink is defined over a 32-byte shared key"
    );
    let mut acc: u8 = 1;
    let mut index = 0;
    while index < SHARED_KEY_BYTES {
        acc = acc.wrapping_mul(31).wrapping_add(bytes[index]);
        index += 1;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flipping any one of the 32 bytes changes the fold, so no byte of the
    /// shared key can be optimized away as unobserved.
    #[test]
    fn every_byte_changes_the_result() {
        let base = [0u8; SHARED_KEY_BYTES];
        let folded = consume_all_bytes(&base);
        for position in 0..SHARED_KEY_BYTES {
            let mut mutated = base;
            mutated[position] ^= 0x80;
            assert_ne!(
                consume_all_bytes(&mutated),
                folded,
                "byte {position} does not reach the result"
            );
        }
    }

    /// The fold depends on byte order, not just on the multiset of bytes.
    #[test]
    fn the_fold_is_order_sensitive() {
        let mut first = [0u8; SHARED_KEY_BYTES];
        first[0] = 1;
        let mut second = [0u8; SHARED_KEY_BYTES];
        second[SHARED_KEY_BYTES - 1] = 1;
        assert_ne!(consume_all_bytes(&first), consume_all_bytes(&second));
    }

    /// A wrong-width slice is refused rather than silently folded short.
    #[test]
    #[should_panic(expected = "32-byte shared key")]
    fn a_short_slice_is_refused() {
        consume_all_bytes(&[0u8; 16]);
    }

    /// The fold is **not** injective, which is why the functional tests compare
    /// whole shared keys instead of folded ones.
    #[test]
    fn the_fold_is_lossy_and_must_not_be_used_for_correctness() {
        let zero = [0u8; SHARED_KEY_BYTES];
        let mut collides = [0u8; SHARED_KEY_BYTES];
        collides[0] = 1;
        collides[1] = 225;
        assert_ne!(zero, collides);
        assert_eq!(
            consume_all_bytes(&zero),
            consume_all_bytes(&collides),
            "if this ever stops colliding the comment above is wrong, not the test"
        );
    }
}
