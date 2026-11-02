//! Fixed-size authentication-tag comparison.

use subtle::ConstantTimeEq;
use trace_check_macros::constant_time;

/// Tag length. A literal `16` appears in the signatures below rather than this
/// constant: a proc macro sees the token `TAG_LEN`, not its value, so a named
/// length cannot be turned into a symbolic width without guessing. The
/// constant is here for callers.
pub const TAG_LEN: usize = 16;

/// Constant-time tag comparison.
///
/// The contract is: with `supplied` held fixed, no modeled observation may
/// depend on `expected`. `#[constant_time]` emits this function verbatim; it
/// adds a test-only analysis adapter and an always-present contract
/// descriptor, and changes nothing about the compiled body.
#[constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}

/// The naive early exit, written the way a developer would write it — and
/// **not** a leak in the compiled code.
///
/// At `opt-level = 3` this vectorizes into the same branchless
/// `pcmpeqb` / `pmovmskb` sequence as [`verify_tag`], so the honest verdict for
/// the artifact is that it has no secret-dependent control flow. It is kept as
/// an educational case rather than rewritten into a manufactured finding: the
/// fifth time this project has recorded the compiler erasing a source-level
/// secret branch.
#[constant_time(secret = "expected")]
pub fn verify_tag_early_exit(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    let mut index = 0usize;
    while index < 16 {
        if expected[index] != supplied[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Vulnerable: an early exit the optimizer cannot vectorize away.
///
/// The volatile read is what keeps the per-byte branch in the compiled code.
/// Without it the loop becomes [`verify_tag_early_exit`] and there is nothing
/// to find — see that function.
#[constant_time(secret = "expected")]
pub fn verify_tag_volatile_early_exit(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
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
