//! A minimal annotation-only library, for M8's contract-discovery test.
//!
//! Deliberately as small as a library can be while still being the thing M8
//! claims to handle:
//!
//! * `no_std`, so inventory discovery cannot depend on `std`;
//! * every contract `dynamic = false`, so there is no `#[ct_test]` and no M3
//!   metadata test to discover them through — the asymmetry M8 closes;
//! * **no `trace-check.toml` at all**, so nothing configures these contracts
//!   and the only way to find them is the compiler-derived inventory.
//!
//! The mutation test copies this library, appends a new annotated function,
//! and requires `cargo trace-check check --all-contracts --ci` to notice
//! without any configuration being edited.
#![no_std]

use trace_check_macros::constant_time;

static TABLE: [u8; 16] = [
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb,
];

/// Constant-time: reads every entry and selects with a mask.
#[constant_time(secret = "index", dynamic = false)]
pub fn masked(index: u8) -> u8 {
    let want = index & 15;
    let mut accumulator = 0u8;
    let mut position = 0u8;
    while position < 16 {
        let hit = ((((position ^ want) as i16) - 1) >> 15) as u8;
        // SAFETY: `position < 16` and `TABLE` is exactly 16 bytes. Volatile so
        // the full scan survives optimization.
        accumulator |= unsafe { core::ptr::read_volatile(&TABLE[position as usize]) } & hit;
        position += 1;
    }
    accumulator
}

/// Constant-time: the secret is consumed by arithmetic, and the branch is on a
/// public input that both compared executions share.
#[constant_time(secret = "secret", dynamic = false)]
pub fn mixed(secret: u8, rounds: u8) -> u8 {
    let mut out = secret;
    let mut index = 0u8;
    while index < (rounds & 3) {
        out = out.wrapping_mul(3).rotate_left(1);
        index += 1;
    }
    out
}
