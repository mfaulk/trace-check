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
//! `trace-check-test`. The contracts therefore say `dynamic = false`, which
//! drops the annotation's `#[cfg(test)]` analysis adapter — the part that calls
//! into that crate and needs `std`. Ordinary `cargo test` still compiles, which
//! is the point: adding a verification annotation must not make an otherwise
//! valid Rust library unable to build its own test suite.
//!
//! A library that wants the M3 dynamic checks as well keeps the default,
//! declares the dev-dependency, and writes `#![cfg_attr(not(test), no_std)]` —
//! which is what `examples/crypto-library` does.
#![no_std]

use trace_check_macros::constant_time;

/// Constant-time selection between two secret words.
///
/// `choice` is public, so branching on it would be permitted; the mask is used
/// anyway, because a caller may later make it secret.
#[constant_time(secret = "first", dynamic = false)]
pub fn select(first: u32, second: u32, choice: u8) -> u32 {
    // All ones when the low bit is clear, all zeros when it is set.
    let mask = ((choice & 1) as u32).wrapping_sub(1);
    (first & mask) | (second & !mask)
}

/// Vulnerable: the secret's low nibble selects a load address.
#[constant_time(secret = "word", dynamic = false)]
pub fn digest_nibble(word: u32) -> u8 {
    static NIBBLES: [u8; 16] = [
        0x3, 0x9, 0x1, 0xe, 0x7, 0x0, 0xc, 0x5, 0xb, 0x2, 0xf, 0x8, 0x4, 0xd, 0x6, 0xa,
    ];
    // SAFETY: the mask keeps the index inside the 16-byte table.
    unsafe { core::ptr::read_volatile(&NIBBLES[(word & 15) as usize]) }
}

/// Constant-time selection driven by a **public** `bool`.
///
/// `bool` is one byte with two valid values, and a symbolic byte has 256, so
/// the generated harness restricts this input's domain and the report says it
/// did. Without that, verification would reason about states this program can
/// never be in.
#[constant_time(secret = "secret", dynamic = false)]
pub fn mix_when(secret: u32, enabled: bool) -> u32 {
    if enabled {
        secret.rotate_left(7) ^ 0x5a5a_5a5a
    } else {
        secret
    }
}
