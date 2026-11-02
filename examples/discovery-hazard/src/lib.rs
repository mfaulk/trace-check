//! Deliberate hazards for trace-check's discovery and coverage tests.
//!
//! Not a workspace member: its ordinary unit test fails by design, so
//! `cargo test --workspace` must never pick it up. The regression tests in
//! `crates/cargo-trace-check/tests/hazards.rs` drive it via `--manifest-path`.
//!
//! Three hazards, one per reviewed defect:
//!
//! 1. an ordinary `#[test]` that writes a sentinel and then fails — discovery
//!    must neither execute it nor be blocked by it;
//! 2. two modules each defining `verify` — qualified identity must keep both
//!    contracts distinct instead of one silently overwriting the other;
//! 3. a `ct_test` that names a target it never invokes — the claim must not be
//!    reported as coverage.

/// Where hazard 1's ordinary test records that it ran. Absence of this file
/// after discovery is the evidence that discovery did not execute it.
pub fn sentinel_path() -> std::path::PathBuf {
    std::env::temp_dir().join("trace-check-discovery-hazard-sentinel")
}

pub mod authentication {
    /// One of two same-named functions. Both contracts must survive discovery.
    #[trace_check_test::constant_time(secret = "key")]
    pub fn verify(key: &[u8; 16], supplied: &[u8; 16]) -> bool {
        use crate::subtle_lite::ct_eq;
        ct_eq(key, supplied)
    }
}

pub mod encryption {
    /// The other `verify`. Keyed on the bare name, this would overwrite the
    /// one in `authentication`.
    #[trace_check_test::constant_time(secret = "key")]
    pub fn verify(key: &[u8; 16], supplied: &[u8; 16]) -> bool {
        use crate::subtle_lite::ct_eq;
        ct_eq(supplied, key)
    }
}

/// A tiny constant-time comparison, so this crate needs no dependencies beyond
/// trace-check itself.
mod subtle_lite {
    #[inline(never)]
    pub fn ct_eq(left: &[u8; 16], right: &[u8; 16]) -> bool {
        let mut accumulator = 0u8;
        for index in 0..16 {
            accumulator |= left[index] ^ right[index];
        }
        accumulator == 0
    }
}

/// Vulnerable with respect to its declared secret: `index` becomes a load
/// address. A contract test must therefore report a violation, never coverage.
#[trace_check_test::constant_time(secret = "index")]
pub fn lookup_by_secret_index(index: u8, ignored: u8, table: &[u8; 256]) -> u8 {
    let _ = ignored;
    table[index as usize]
}

/// The same body, but the *second* parameter is declared secret while the
/// index stays public.
///
/// Paired with [`lookup_by_secret_index`] this pins down which parameter the
/// adapter marks. If marking followed position rather than the declaration,
/// this would report a leak and that one would not.
#[trace_check_test::constant_time(secret = "ignored")]
pub fn lookup_by_public_index(index: u8, ignored: u8, table: &[u8; 256]) -> u8 {
    let _ = ignored;
    table[index as usize]
}

/// A contract whose test will claim it without invoking it.
#[trace_check_test::constant_time(secret = "key")]
pub fn never_invoked(key: u8) -> u8 {
    key.wrapping_mul(3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trace_check_test::{assert_constant_time, ct_test};

    /// Hazard 1: an ordinary unit test with a side effect that then fails.
    ///
    /// Discovery must not execute this. If it does, the sentinel file appears
    /// and the whole discovery step fails on an unrelated test's failure.
    #[test]
    fn ordinary_test_with_a_side_effect_that_fails() {
        std::fs::write(sentinel_path(), b"executed").expect("write the sentinel");
        panic!("this ordinary test fails by design; discovery must not run it");
    }

    /// Hazard 2a: covers `authentication::verify` specifically.
    ///
    /// The adapter takes the declared secret by value, so the test cannot
    /// route a marked value anywhere else.
    #[ct_test(target = "authentication::verify")]
    fn authentication_verify_is_constant_time() {
        let supplied = [0u8; 16];
        let accepted = authentication::verify_ct([1u8; 16], &supplied);
        assert!(!accepted);
    }

    /// Hazard 4: invoking the contract "with public inputs" is not possible.
    ///
    /// Whatever reaches the declared slot is marked by the adapter, so a
    /// vulnerable function reports a violation rather than coverage. The
    /// separate unrelated assertion below cannot launder that away.
    #[ct_test(target = "lookup_by_secret_index")]
    fn a_vulnerable_contract_cannot_be_reported_covered() {
        let table = [7u8; 256];
        let _selected = lookup_by_secret_index_ct(42, 0, &table);
        // An unrelated clean assertion must not mask the finding above.
        let _unrelated = assert_constant_time!(secret = 9u8, call = |_secret| ());
    }

    /// Hazard 5: marking follows the declaration, not the parameter position.
    ///
    /// `ignored` is the declared secret here and the index is public, so this
    /// is clean — while the structurally identical
    /// `lookup_by_secret_index` above reports a violation.
    #[ct_test(target = "lookup_by_public_index")]
    fn marking_follows_the_declared_parameter() {
        let table = [7u8; 256];
        let selected = lookup_by_public_index_ct(42, 99, &table);
        assert_eq!(selected, 7);
    }

    /// Hazard 3: names a target but never invokes it.
    ///
    /// The generated code checks the contract's invocation counter, so this
    /// test fails rather than silently reporting the contract as covered.
    #[ct_test(target = "never_invoked")]
    fn claims_a_target_without_invoking_it() {
        let _unused = assert_constant_time!(
            secret = 42u8,
            call = |_key| 0u8,
        );
    }
}
