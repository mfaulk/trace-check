//! Secret-indexed substitution, the AES S-box leakage class.

use trace_check_macros::constant_time;

/// A small substitution table. The values are irrelevant; only the access
/// pattern matters.
static SBOX: [u8; 16] = [
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb,
];

/// Constant-time substitution: reads every entry and selects with a mask.
#[constant_time(secret = "index")]
pub fn substitute(index: u8) -> u8 {
    let want = index & 15;
    let mut accumulator = 0u8;
    let mut position = 0u8;
    while position < 16 {
        // 0xff when position == want, 0x00 otherwise, computed without
        // branching.
        let hit = ((((position ^ want) as i16) - 1) >> 15) as u8;
        // SAFETY: `position < 16` and `SBOX` is exactly 16 bytes. Volatile so
        // the full scan survives optimization.
        accumulator |= unsafe { core::ptr::read_volatile(&SBOX[position as usize]) } & hit;
        position += 1;
    }
    accumulator
}

/// Vulnerable: the secret becomes part of a load address.
///
/// Every secret value executes the same instructions, so comparing instruction
/// paths cannot see this. Only an address-aware analysis can.
#[constant_time(secret = "index")]
pub fn substitute_indexed(index: u8) -> u8 {
    // SAFETY: the mask keeps the index inside the 16-byte table. Volatile so
    // the load is not folded away.
    unsafe { core::ptr::read_volatile(&SBOX[(index & 15) as usize]) }
}

/// A leak reachable only under one **public** mode.
///
/// A dynamic test that only ever passes `mode == 0` observes nothing, because
/// that path is the full scan. Finding the other path needs a search over the
/// public domain rather than a chosen input — the case M4 was built to answer
/// and the reason a declared contract is not the same as a tested one.
#[constant_time(secret = "index")]
pub fn substitute_mode(index: u8, mode: u8) -> u8 {
    if mode == 0 {
        substitute(index)
    } else {
        substitute_indexed(index)
    }
}
