//! Small fixed-width modular arithmetic.
//!
//! Correct arithmetic can still be implemented with a secret-dependent branch,
//! which makes conditional subtraction a useful case: it exercises a scalar
//! secret wider than a byte and a computation that is not byte-oriented.

use trace_check_macros::constant_time;

/// One conditional subtraction, written with a branch.
///
/// Whether the compiled code *keeps* the branch is a question about the
/// artifact, not about the source, and the verification case's declared
/// expectation records what was observed rather than what was intended.
#[constant_time(secret = "value")]
pub fn reduce_once(value: u32, modulus: u32) -> u32 {
    if value >= modulus {
        value - modulus
    } else {
        value
    }
}

/// The same reduction with the subtraction selected by a mask.
///
/// No branch to erase and no secret-dependent address: the borrow is computed
/// arithmetically and broadcast to a full-width mask.
#[constant_time(secret = "value")]
pub fn reduce_once_masked(value: u32, modulus: u32) -> u32 {
    let (difference, borrow) = value.overflowing_sub(modulus);
    // 0 when the subtraction underflowed, all ones otherwise.
    let keep = (borrow as u32).wrapping_sub(1);
    (difference & keep) | (value & !keep)
}
