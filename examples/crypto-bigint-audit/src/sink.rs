//! A fixed-work output sink.
//!
//! The generated checker hands back one scalar, and a 256-bit result does not
//! fit in one. Something has to reduce it, and that something decides what the
//! compiler is allowed to throw away: a sink that reads four of the thirty-two
//! bytes licenses the optimizer to compute only one limb, and then the artifact
//! no longer contains the operation the contract names.
//!
//! So the requirement is narrow and testable: **every** output byte must
//! materially change the result, with no branch and no secret-derived address.
//! It is not a hash and carries no cryptographic property.

/// Width of every result this crate reduces.
pub const RESULT_BYTES: usize = 32;

/// A 32-byte result as an array, so a caller can compare it **whole**.
///
/// The fold below is deliberately lossy — it maps 2^256 results onto 256
/// values — so it cannot be the thing a correctness test compares. The
/// operation helpers return this instead, and the annotated adapters fold it;
/// see `tests/functional.rs`.
///
/// # Panics
///
/// If `bytes` is not [`RESULT_BYTES`] long.
#[inline(always)]
pub fn result_array(bytes: &[u8]) -> [u8; RESULT_BYTES] {
    assert!(
        bytes.len() == RESULT_BYTES,
        "a 32-byte result is defined over 32 bytes"
    );
    let mut out = [0u8; RESULT_BYTES];
    out.copy_from_slice(bytes);
    out
}

/// Folds all 32 result bytes into one, in fixed work.
///
/// Multiplying by 31 is invertible mod 256, so no byte's contribution can be
/// cancelled by a later one — which is what
/// `every_byte_changes_the_result` checks. The loop bound is a constant and
/// the accumulator feeds nothing but arithmetic, so the fold itself has no
/// secret-dependent branch or address.
///
/// # Panics
///
/// If `bytes` is not [`RESULT_BYTES`] long. The length is a property of the
/// caller's type, never of a secret.
#[inline(never)]
pub fn consume_all_bytes(bytes: &[u8]) -> u8 {
    assert!(
        bytes.len() == RESULT_BYTES,
        "the sink is defined over a 32-byte result"
    );
    let mut acc: u8 = 1;
    let mut index = 0;
    while index < RESULT_BYTES {
        acc = acc.wrapping_mul(31).wrapping_add(bytes[index]);
        index += 1;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flipping any one of the 32 bytes changes the fold, so no byte of the
    /// operation's result can be optimized away as unobserved.
    #[test]
    fn every_byte_changes_the_result() {
        let base = [0u8; RESULT_BYTES];
        let folded = consume_all_bytes(&base);
        for position in 0..RESULT_BYTES {
            let mut mutated = base;
            mutated[position] ^= 0x80;
            assert_ne!(
                consume_all_bytes(&mutated),
                folded,
                "byte {position} does not reach the result"
            );
        }
    }

    /// The fold is a function of byte order, not just of the multiset of
    /// bytes: a swapped pair of limbs is a different result.
    #[test]
    fn the_fold_is_order_sensitive() {
        let mut first = [0u8; RESULT_BYTES];
        first[0] = 1;
        let mut second = [0u8; RESULT_BYTES];
        second[RESULT_BYTES - 1] = 1;
        assert_ne!(consume_all_bytes(&first), consume_all_bytes(&second));
    }

    /// A wrong-width slice is refused rather than silently folded short.
    #[test]
    #[should_panic(expected = "32-byte result")]
    fn a_short_slice_is_refused() {
        consume_all_bytes(&[0u8; 16]);
    }

    /// The fold is **not** injective, which is why no correctness test may
    /// compare through it.
    ///
    /// `acc * 31 + byte` is linear mod 256, so two byte changes can cancel
    /// exactly: 31 has order 8 mod 256, byte 0 carries weight 31^31 = 223 and
    /// byte 1 carries 31^30 = 65, and 223 + 225·65 ≡ 0. Every byte still
    /// *reaches* the result — that is what the sink is for — but 2^256 results
    /// map onto 256 values, so the functional tests compare
    /// [`result_array`]'s full 32 bytes instead.
    #[test]
    fn the_fold_is_lossy_and_must_not_be_used_for_correctness() {
        let zero = [0u8; RESULT_BYTES];
        let mut collides = [0u8; RESULT_BYTES];
        collides[0] = 1;
        collides[1] = 225;
        assert_ne!(zero, collides);
        assert_eq!(
            consume_all_bytes(&zero),
            consume_all_bytes(&collides),
            "if this ever stops colliding the comment above is wrong, not the test"
        );
    }

    /// `result_array` preserves order and width, so comparing its output is
    /// comparing the operation's whole result.
    #[test]
    fn the_result_array_is_the_bytes_verbatim() {
        let mut bytes = [0u8; RESULT_BYTES];
        bytes[0] = 0xde;
        bytes[31] = 0xad;
        assert_eq!(result_array(&bytes), bytes);
    }

    /// A wrong-width slice is refused there too.
    #[test]
    #[should_panic(expected = "32 bytes")]
    fn a_short_result_is_refused() {
        result_array(&[0u8; 31]);
    }
}
