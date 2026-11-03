//! The vulnerable half of the attribution control.

use trace_check_macros::constant_time;

/// A secret-indexed load, and named identically to
/// [`crate::shadow::left::probe`].
///
/// A coverage or finding attribution that matched only the bare function name,
/// or only its length-prefixed mangled component, would count this as the
/// target when `left::probe` was the contract under study.
#[constant_time(secret = "key")]
pub fn probe(key: u8) -> u8 {
    crate::lookup::substitute_indexed(key)
}
