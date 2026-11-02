//! Using `trace-check` from an ordinary Rust crate.
//!
//! This crate depends on `trace-check-test` as a **dev-dependency** only and
//! writes its constant-time checks as ordinary unit tests. There is no harness
//! binary and no JSON manifest. Run them with:
//!
//! ```sh
//! cargo trace-check test
//! ```
//!
//! Plain `cargo test` also works and passes, but prints that the constant-time
//! checks were skipped — the analysis needs Valgrind, and a skipped check must
//! never read as a success.
//!
//! The crate deliberately contains both safe and vulnerable implementations.
//! The `vulnerable_*` tests are **expected to be detected**, so a full run exits
//! nonzero by design. See `README.md` for which invocation demonstrates what.

use subtle::ConstantTimeEq;

pub const TAG_LEN: usize = 32;
pub const TABLE_LEN: usize = 256;

/// Constant-time-oriented tag comparison.
///
/// The contract says: with `supplied` held fixed, observable execution must not
/// depend on `expected`. The annotation does not change this function's
/// behavior in any way — it emits the function verbatim and adds test-only
/// metadata so the runner can tell whether the contract has coverage.
#[trace_check_test::constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; TAG_LEN], supplied: &[u8; TAG_LEN]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}

/// Vulnerable: stops at the first differing byte.
///
/// The volatile reads are what keep the loop from being vectorized into a
/// branchless comparison at `opt-level = 3`. Without them the compiled code has
/// no secret-dependent branch and there is nothing to detect — a lesson this
/// project has now learned in WASM, in native SIMD, and in its own calibration
/// probe.
#[inline(never)]
pub fn verify_tag_early_exit(expected: &[u8; TAG_LEN], supplied: &[u8; TAG_LEN]) -> bool {
    for index in 0..TAG_LEN {
        // SAFETY: `index < TAG_LEN` and both arrays are exactly `TAG_LEN` bytes.
        let (left, right) = unsafe {
            (
                core::ptr::read_volatile(&expected[index]),
                core::ptr::read_volatile(&supplied[index]),
            )
        };
        if left != right {
            return false;
        }
    }
    true
}

/// A fixed synthetic table. The values are irrelevant; only the access pattern
/// matters.
pub fn synthetic_table() -> [u8; TABLE_LEN] {
    let mut table = [0u8; TABLE_LEN];
    let mut index = 0;
    while index < TABLE_LEN {
        table[index] = ((index as u8).wrapping_mul(7)).wrapping_add(13);
        index += 1;
    }
    table
}

/// Vulnerable: the secret becomes part of a load address.
///
/// Every secret value executes the same three instructions, so comparing
/// instruction paths cannot see this. Memcheck can. This is the AES S-box
/// leakage class.
#[inline(never)]
pub fn lookup_secret_index(table: &[u8; TABLE_LEN], secret: u8) -> u8 {
    table[secret as usize]
}

/// Constant-time-oriented: reads the whole table and selects with a mask.
#[inline(never)]
pub fn lookup_scan(table: &[u8; TABLE_LEN], secret: u8) -> u8 {
    let mut selected = 0u8;
    let mut index = 0usize;
    while index < TABLE_LEN {
        let hit = (index as u8).ct_eq(&secret).unwrap_u8();
        selected |= table[index] & hit.wrapping_neg();
        index += 1;
    }
    selected
}

/// A secret used only in arithmetic. Propagating secrecy through computation is
/// expected and permitted; only branches and addresses are prohibited.
#[inline(never)]
pub fn mix(secret: u8, public: u8) -> u8 {
    secret.wrapping_mul(3).wrapping_add(public).rotate_left(2) ^ 0x5a
}

/// A helper that leaks, called from an outer function that looks innocent.
///
/// Demonstrates that a finding is attributed to where the secret-dependent
/// operation happens, not to the function the test called.
#[inline(never)]
fn leaky_helper(secret: u8, table: &[u8; TABLE_LEN]) -> u8 {
    table[secret as usize]
}

/// Calls a helper that performs a secret-dependent lookup.
#[inline(never)]
pub fn outer_calls_leaky_helper(table: &[u8; TABLE_LEN], secret: u8) -> u8 {
    leaky_helper(secret, table).wrapping_add(1)
}

/// A contract with no `ct_test` covering it, enabled by the
/// `untested-contract` feature so the coverage failure can be demonstrated in
/// isolation.
#[cfg(feature = "untested-contract")]
#[trace_check_test::constant_time(secret = "key")]
pub fn unverified_mix(key: &[u8; 16], public: u8) -> u8 {
    key.iter().fold(public, |acc, byte| acc ^ byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trace_check_test::{assert_constant_time, ct_test};

    /// A secret tag that differs from the public one at the last byte, so both
    /// comparisons reject and a finding cannot be confounded with a differing
    /// decision.
    fn secret_tag() -> [u8; TAG_LEN] {
        let mut tag = [0u8; TAG_LEN];
        tag[TAG_LEN - 1] = 1;
        tag
    }

    /// The `subtle`-based comparison: expected to observe no leak, and declared
    /// as covering the `verify_tag` contract.
    #[ct_test(target = "verify_tag")]
    fn verify_tag_is_constant_time() {
        let supplied = [0u8; TAG_LEN];

        // `verify_tag_ct` is the contract adapter generated by
        // `#[constant_time]`. It counts the call and delegates to the untouched
        // `verify_tag`, which is how the runner proves this test actually
        // exercised the contract rather than merely naming it.
        //
        // The secret is handed over by value and comes back as a reference the
        // compiler cannot see through, so it cannot be folded past the marked
        // storage.
        let accepted = assert_constant_time!(
            secret = secret_tag(),
            call = |expected| verify_tag_ct(expected, &supplied),
        );

        // The assertion evaluates to the call's value, so ordinary functional
        // checks still work alongside the security check.
        assert!(!accepted, "a mismatching tag must be rejected");
    }

    /// The early-exit comparison: expected to be detected as a
    /// secret-dependent branch.
    #[ct_test]
    fn vulnerable_tag_compare_leaks() {
        let supplied = [0u8; TAG_LEN];

        let accepted = assert_constant_time!(
            secret = secret_tag(),
            call = |expected| verify_tag_early_exit(expected, &supplied),
        );
        assert!(!accepted);
    }

    /// The secret-indexed lookup: expected to be detected as a
    /// secret-dependent address.
    #[ct_test]
    fn vulnerable_table_lookup_leaks() {
        let table = synthetic_table();

        let selected = assert_constant_time!(
            secret = 42u8,
            call = |index| lookup_secret_index(&table, *index),
        );
        assert_eq!(selected, table[42]);
    }

    /// The masked scan: expected to observe no leak.
    #[ct_test]
    fn table_scan_is_constant_time() {
        let table = synthetic_table();

        let selected =
            assert_constant_time!(secret = 42u8, call = |index| lookup_scan(&table, *index),);
        assert_eq!(selected, table[42]);
    }

    /// A secret used only in arithmetic: expected to observe no leak.
    #[ct_test]
    fn arithmetic_on_a_secret_is_permitted() {
        let mixed = assert_constant_time!(secret = 0x5eu8, call = |secret| mix(*secret, 0x11),);
        assert_eq!(mixed, mix(0x5e, 0x11));
    }

    /// A leak inside a helper is still detected, and attributed to the helper.
    #[ct_test]
    fn leak_in_a_helper_is_detected() {
        let table = synthetic_table();

        let value = assert_constant_time!(
            secret = 7u8,
            call = |index| outer_calls_leaky_helper(&table, *index),
        );
        assert_eq!(value, table[7].wrapping_add(1));
    }

    /// Secret bytes on the heap are marked through a slice. Marking the `Vec`
    /// itself would mark its pointer, length and capacity and none of the data,
    /// which is why `MarkSecret` is not implemented for `Vec`.
    #[ct_test]
    fn heap_secret_is_marked_through_a_slice() {
        let owned: Vec<u8> = (0..TAG_LEN as u8).collect();
        let supplied = [0u8; TAG_LEN];

        // `secret_bytes` takes a `&[u8]`, which is how heap-allocated secret
        // bytes are marked. Marking the `Vec` itself would mark its pointer,
        // length and capacity and none of the data, which is why `MarkSecret`
        // is not implemented for `Vec`.
        let accepted = assert_constant_time!(
            secret_bytes = owned.as_slice(),
            call = |bytes| {
                let mut expected = [0u8; TAG_LEN];
                expected.copy_from_slice(bytes);
                verify_tag_early_exit(&expected, &supplied)
            },
        );
        assert!(!accepted);
    }

    /// Ordinary unit tests are unaffected and need no instrumentation.
    #[test]
    fn both_lookups_agree_for_every_secret() {
        let table = synthetic_table();
        for secret in 0..=u8::MAX {
            assert_eq!(
                lookup_secret_index(&table, secret),
                lookup_scan(&table, secret)
            );
        }
    }
}
