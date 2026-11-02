//! A library outside the trace-check workspace.
//!
//! It depends on nothing but the annotation macro, has its own lockfile, and is
//! verified through the installed CLI:
//!
//! ```sh
//! cargo trace-check verify --all-contracts \
//!   --manifest-path examples/external-library/Cargo.toml
//! ```
//!
//! `#![no_std]` unconditionally, and with no dev-dependency on
//! `trace-check-test`. The annotation's `#[cfg(test)]` adapter calls into that
//! crate and needs `std`, so a library wanting the M3 dynamic checks as well
//! must declare it and write `#![cfg_attr(not(test), no_std)]` -- which is what
//! `examples/crypto-library` does. This one carries no dynamic tests, so only
//! its library target compiles, and that is the target verification uses.
#![no_std]

use trace_check_macros::constant_time;

/// Constant-time selection between two secret words.
///
/// `choice` is public, so branching on it would be permitted; the mask is used
/// anyway, because a caller may later make it secret.
#[constant_time(secret = "first")]
pub fn select(first: u32, second: u32, choice: u8) -> u32 {
    // All ones when the low bit is clear, all zeros when it is set.
    let mask = ((choice & 1) as u32).wrapping_sub(1);
    (first & mask) | (second & !mask)
}

/// Vulnerable: the secret's low nibble selects a load address.
#[constant_time(secret = "word")]
pub fn digest_nibble(word: u32) -> u8 {
    static NIBBLES: [u8; 16] = [
        0x3, 0x9, 0x1, 0xe, 0x7, 0x0, 0xc, 0x5, 0xb, 0x2, 0xf, 0x8, 0x4, 0xd, 0x6, 0xa,
    ];
    // SAFETY: the mask keeps the index inside the 16-byte table.
    unsafe { core::ptr::read_volatile(&NIBBLES[(word & 15) as usize]) }
}
