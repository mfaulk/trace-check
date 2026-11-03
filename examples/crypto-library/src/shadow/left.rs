//! The safe half of the attribution control.

use trace_check_macros::constant_time;

/// Constant-time, and named identically to [`crate::shadow::right::probe`].
#[constant_time(secret = "key")]
pub fn probe(key: u8) -> u8 {
    crate::lookup::substitute(key)
}
