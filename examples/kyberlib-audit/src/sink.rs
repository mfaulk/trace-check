//! The same fixed-work 32-byte fold as the `ml-kem` audit, for the same reason:
//! every output byte must materially change the result, or the optimizer is
//! licensed to compute less than a decapsulation.

pub const SHARED_SECRET_BYTES: usize = 32;

/// Folds all 32 bytes into one, in fixed work, with no branch and no
/// secret-derived address.
///
/// # Panics
///
/// If `bytes` is not [`SHARED_SECRET_BYTES`] long.
#[inline(never)]
pub fn consume_all_bytes(bytes: &[u8]) -> u8 {
    assert!(
        bytes.len() == SHARED_SECRET_BYTES,
        "the sink is defined over a 32-byte shared secret"
    );
    let mut acc: u8 = 1;
    let mut index = 0;
    while index < SHARED_SECRET_BYTES {
        acc = acc.wrapping_mul(31).wrapping_add(bytes[index]);
        index += 1;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Flipping any byte changes the fold, so none of the shared secret can be
    /// optimized away as unobserved.
    #[test]
    fn every_byte_changes_the_result() {
        let folded = consume_all_bytes(&[0u8; SHARED_SECRET_BYTES]);
        for position in 0..SHARED_SECRET_BYTES {
            let mut mutated = [0u8; SHARED_SECRET_BYTES];
            mutated[position] ^= 0x80;
            assert_ne!(consume_all_bytes(&mutated), folded, "byte {position}");
        }
    }
}
