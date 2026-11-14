//! An analyzer fixture for a first trace-check run, not a library to copy:
//! `tag_eq_insecure` leaks on purpose. Use `tag_eq_ct`'s approach in real code.

use subtle::ConstantTimeEq;
use trace_check_test::constant_time;

/// Insecure: returns at the first byte that differs, so the running time
/// reveals how long a prefix of `expected` an attacker has guessed.
///
/// The obvious version, `if expected[i] != supplied[i] { return false }` over
/// plain indexing, does **not** leak once compiled: at opt-level 3 the loop is
/// vectorized into a branchless compare-and-mask, and a demo built on it would
/// report nothing. The volatile load forces one byte to be read and compared
/// at a time, which keeps the early exit in the machine code.
#[constant_time(secret = "expected")]
pub fn tag_eq_insecure(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    let mut index = 0usize;
    while index < 16 {
        // SAFETY: `index < 16` and `expected` is exactly 16 bytes.
        let byte = unsafe { core::ptr::read_volatile(&expected[index]) };
        if byte != supplied[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Constant-time: compares all 16 bytes and folds the result without
/// branching on it.
#[constant_time(secret = "expected")]
pub fn tag_eq_ct(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: [u8; 16] = *b"0123456789abcdef";

    fn both(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
        let insecure = tag_eq_insecure(expected, supplied);
        assert_eq!(
            insecure,
            tag_eq_ct(expected, supplied),
            "the comparisons disagree"
        );
        insecure
    }

    // Both comparisons accept identical tags.
    #[test]
    fn equal_tags_match() {
        assert!(both(&TAG, &TAG));
    }

    // Both comparisons reject a tag whose first byte differs.
    #[test]
    fn first_byte_differs() {
        let mut supplied = TAG;
        supplied[0] ^= 1;
        assert!(!both(&TAG, &supplied));
    }

    // Both comparisons reject a tag whose last byte differs.
    #[test]
    fn last_byte_differs() {
        let mut supplied = TAG;
        supplied[15] ^= 0x80;
        assert!(!both(&TAG, &supplied));
    }

    // Both comparisons reject a tag in which every byte differs.
    #[test]
    fn all_bytes_differ() {
        let supplied = TAG.map(|byte| !byte);
        assert!(!both(&TAG, &supplied));
    }
}
