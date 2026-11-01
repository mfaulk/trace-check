//! Secret-indexed table lookup: the leak class that instruction-path
//! comparison cannot see.
//!
//! `lookup_secret_index` compiles to the same three instructions for every
//! secret value — only the effective address changes:
//!
//! ```asm
//! movzbl %sil, %eax            ; zero-extend the secret
//! movzbl (%rdi,%rax,1), %eax   ; load from a secret-dependent address
//! ret
//! ```
//!
//! M1's comparator reports `NO_DIFFERENCE_OBSERVED` for this and is correct:
//! the instruction path really is identical. The vulnerability lives in the
//! address, which is why M2 exists. This is the AES S-box leakage class.
//!
//! `lookup_constant_time_scan` reads the whole table and selects without
//! secret-dependent addressing or branching, using `subtle` for the mask so we
//! are not inventing a comparison primitive.

use subtle::{ConstantTimeEq, ConstantTimeGreater};

pub const TABLE_LEN: usize = 256;

/// A fixed synthetic substitution table. Deterministic and not derived from any
/// real cipher; the values are irrelevant to the property under test.
pub fn synthetic_table() -> [u8; TABLE_LEN] {
    let mut table = [0u8; TABLE_LEN];
    let mut i = 0;
    while i < TABLE_LEN {
        // An affine permutation over the byte range: cheap, bijective, and with
        // no secret-dependent construction cost.
        table[i] = ((i as u8).wrapping_mul(7)).wrapping_add(13);
        i += 1;
    }
    table
}

/// Vulnerable: the secret indexes the table directly, so the effective address
/// depends on the secret.
#[inline(never)]
pub fn lookup_secret_index(table: &[u8; TABLE_LEN], secret: u8) -> u8 {
    table[secret as usize]
}

/// Constant-time-oriented: every entry is read, and the selection is a mask
/// rather than an address or a branch.
#[inline(never)]
pub fn lookup_constant_time_scan(table: &[u8; TABLE_LEN], secret: u8) -> u8 {
    let mut selected = 0u8;
    let mut index = 0usize;
    while index < TABLE_LEN {
        // `ct_eq` yields 1 on a match; negating gives an all-ones mask.
        let hit = (index as u8).ct_eq(&secret).unwrap_u8();
        selected |= table[index] & hit.wrapping_neg();
        index += 1;
    }
    selected
}

/// Secret used only in arithmetic that never reaches a branch or an address.
/// Memcheck must stay quiet for this: propagating secrecy through computation
/// is expected and permitted.
#[inline(never)]
pub fn permitted_arithmetic(secret: u8, public: u8) -> u8 {
    secret.wrapping_mul(3).wrapping_add(public).rotate_left(2) ^ 0x5a
}

/// Bounds handling must also avoid branching, so the range check uses
/// `subtle`'s constant-time comparison rather than `<`.
#[inline(never)]
pub fn in_range_constant_time(secret: u8, limit: u8) -> bool {
    limit.ct_gt(&secret).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both lookups return the same value for every possible secret byte, so a
    /// finding can never be confounded with a functional difference.
    #[test]
    fn both_lookups_agree_for_every_secret() {
        let table = synthetic_table();
        for secret in 0..=u8::MAX {
            assert_eq!(
                lookup_secret_index(&table, secret),
                lookup_constant_time_scan(&table, secret),
                "lookups disagree at {secret}"
            );
        }
    }

    /// The synthetic table is a permutation, so no table entry is privileged.
    #[test]
    fn synthetic_table_is_a_permutation() {
        let table = synthetic_table();
        let mut seen = [false; TABLE_LEN];
        for byte in table {
            assert!(!seen[byte as usize], "value {byte} appears twice");
            seen[byte as usize] = true;
        }
    }

    /// The scan selects the entry at the secret index wherever it sits,
    /// including the first and last slots, and returns zero only when the
    /// selected entry is itself zero.
    #[test]
    fn scan_selects_the_entry_at_any_position() {
        let mut table = [0u8; TABLE_LEN];
        table[0] = 0xaa;
        table[TABLE_LEN - 1] = 0xbb;
        assert_eq!(lookup_constant_time_scan(&table, 0), 0xaa);
        assert_eq!(
            lookup_constant_time_scan(&table, (TABLE_LEN - 1) as u8),
            0xbb
        );
        assert_eq!(lookup_constant_time_scan(&table, 7), 0);
    }

    /// Permitted arithmetic is a pure function of its inputs.
    #[test]
    fn permitted_arithmetic_is_deterministic() {
        assert_eq!(permitted_arithmetic(7, 9), permitted_arithmetic(7, 9));
        assert_ne!(permitted_arithmetic(7, 9), permitted_arithmetic(8, 9));
    }
}
