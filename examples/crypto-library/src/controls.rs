//! Deliberate controls. These are not cryptographic operations; each one
//! exists to make a specific way of being wrong fail visibly.

use trace_check_macros::constant_time;

static SBOX: [u8; 16] = [
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb,
];

/// Per-byte control: **only the final byte** of the secret reaches a load
/// address.
///
/// The first fifteen bytes are folded into an accumulator, which is modeled as
/// safe. A harness that declared only the pointer secret, or only the leading
/// byte, or the wrong width, reports this function as secure. That is what
/// makes it the test which proves the array marking is complete rather than
/// nominal.
///
/// A control-flow formulation of the same idea was tried first — the final byte
/// as a loop trip count — and the optimizer solved the loop in closed form,
/// leaving no branch. A load index survives.
#[constant_time(secret = "expected")]
pub fn tail_byte_probe(expected: &[u8; 16], supplied: &[u8; 16]) -> u8 {
    let mut accumulator = 0u8;
    let mut index = 0usize;
    while index < 15 {
        accumulator |= expected[index] ^ supplied[index];
        index += 1;
    }
    // SAFETY: the mask keeps the index inside the 16-byte table.
    let selected = unsafe { core::ptr::read_volatile(&SBOX[(expected[15] & 15) as usize]) };
    accumulator | selected
}

/// Negative control: branches on a **public** parameter only, with the secret
/// consumed by arithmetic.
///
/// Both compared executions share their public inputs, so public-dependent
/// branching is not a leak. A checker that reported one here would be wrong in
/// the direction that makes the tool useless.
#[constant_time(secret = "secret")]
pub fn public_branch(secret: u8, mode: u8) -> u8 {
    let base = if (mode & 1) == 0 { 0usize } else { 8usize };
    let mixed = secret.wrapping_mul(3).rotate_left(2);
    // SAFETY: `base` is 0 or 8, both inside the 16-byte table.
    unsafe { core::ptr::read_volatile(&SBOX[base]) ^ mixed }
}
