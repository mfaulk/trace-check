//! Deliberate controls for the M9.1 feasibility gate.
//!
//! None of these is a cryptographic operation. Each exists to make one
//! specific way of being wrong fail visibly, and the one question they answer
//! together is:
//!
//! > does a secret declared as `&[u8; 32]` still *read* as secret after
//! > `crypto-bigint` has decoded it into a `Uint<4>` and done multi-limb
//! > arithmetic with it?
//!
//! A control that leaks before decoding proves only that the harness marked
//! the bytes. The controls that matter here are the ones whose observation is
//! driven by a limb of the decoded value, or by a carry the library itself
//! produced — if those read as public, then a clean result on a real operation
//! means nothing, and no amount of adapter polish fixes it.
//!
//! Each control names the byte of `secret` it depends on, and the gate
//! requires the first, an interior, and the last to be found independently: a
//! harness that marks only the pointer, only the leading byte, or the wrong
//! width passes some of these and fails others.

use crate::sink::consume_all_bytes;
use crypto_bigint::{Limb, U256};
use trace_check_macros::constant_time;

static SBOX: [u8; 16] = [
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb,
];

/// A side effect the optimizer may neither elide nor hoist, so a branch that
/// guards it must survive into the compiled code.
///
/// The repeated finding this project records is that a source-level `if` on a
/// secret usually becomes a `cmov` at `opt-level = 3`, leaving nothing to
/// detect. A control whose branch the compiler erases is not a control, so the
/// taken arm has to do something observable.
static mut SIDE_EFFECT: u8 = 0;

#[inline(never)]
fn record(value: u8) {
    // SAFETY: the checker runs one case per process, single-threaded. The
    // write exists only to be an effect the compiler must keep.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SIDE_EFFECT), value) }
}

/// Control B1 — the **necessary but insufficient** one: a branch on
/// `secret[0]` *before* any decoding.
///
/// It establishes that the generated harness marked the array at all. It
/// establishes nothing about `crypto-bigint`, because the secret never reaches
/// it. Listed first so a report cannot cite it as propagation evidence.
#[constant_time(secret = "secret", dynamic = false)]
pub fn pre_decode_first_byte(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    if secret[0] & 1 == 1 {
        record(1);
    }
    let a = U256::from_be_slice(secret);
    let b = U256::from_be_slice(public);
    consume_all_bytes(a.wrapping_add(&b).to_be_bytes().as_slice())
}

/// Control B2 — a branch on the **most significant limb** of the decoded
/// `U256`, which in big-endian decoding is `secret[0..8]`.
///
/// The first control that is genuinely about propagation: the observation is
/// driven by a `Word` the library produced from the secret bytes, not by the
/// bytes themselves.
#[constant_time(secret = "secret", dynamic = false)]
pub fn decoded_high_limb_branch(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    let a = U256::from_be_slice(secret);
    let b = U256::from_be_slice(public);
    if a.as_words()[3] & 1 == 1 {
        record(2);
    }
    consume_all_bytes(a.wrapping_add(&b).to_be_bytes().as_slice())
}

/// Control B3 — a branch on an **interior** limb, `secret[8..16]`.
///
/// Middle limbs are where a per-limb marking mistake hides: a harness that
/// marked the first and last eight bytes and nothing between them passes B2
/// and B4 and fails only here.
#[constant_time(secret = "secret", dynamic = false)]
pub fn decoded_interior_limb_branch(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    let a = U256::from_be_slice(secret);
    let b = U256::from_be_slice(public);
    if a.as_words()[2] & 1 == 1 {
        record(3);
    }
    consume_all_bytes(a.wrapping_add(&b).to_be_bytes().as_slice())
}

/// Control B4 — a branch on `secret[31]` alone, reached through the decoded
/// value's least significant limb.
///
/// Masking the low limb to eight bits isolates exactly the final byte, so a
/// harness that marked 31 of the 32 bytes, or that got the width wrong, reads
/// this as public.
#[constant_time(secret = "secret", dynamic = false)]
pub fn decoded_last_byte_branch(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    let a = U256::from_be_slice(secret);
    let b = U256::from_be_slice(public);
    if (a.as_words()[0] & 1) == 1 {
        record(4);
    }
    consume_all_bytes(a.wrapping_add(&b).to_be_bytes().as_slice())
}

/// Control B5 — a branch on the **carry the library itself produced**.
///
/// `carrying_add` is upstream code and the carry is its return value, so this
/// is the control that follows a secret through multi-limb propagation rather
/// than through decoding alone. Which input byte it depends on is not fixed:
/// the carry out of the top limb is a function of every byte of both operands.
#[constant_time(secret = "secret", dynamic = false)]
pub fn carry_branch(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    let a = U256::from_be_slice(secret);
    let b = U256::from_be_slice(public);
    let (sum, carry) = a.carrying_add(&b, Limb::ZERO);
    if carry.0 != 0 {
        record(5);
    }
    consume_all_bytes(sum.to_be_bytes().as_slice())
}

/// Control B6 — a secret-derived **load address** after decoding.
///
/// Every secret executes the same instruction sequence here, so an analysis
/// that only looks at control flow reports this clean. It is the gate's
/// evidence that the address half of the observation model also survives the
/// transition into the library's representation.
#[constant_time(secret = "secret", dynamic = false)]
pub fn decoded_address_probe(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    let a = U256::from_be_slice(secret);
    let b = U256::from_be_slice(public);
    let sum = a.wrapping_add(&b);
    let index = (sum.as_words()[0] & 15) as usize;
    // SAFETY: the mask keeps the index inside the 16-byte table.
    let selected = unsafe { core::ptr::read_volatile(&SBOX[index]) };
    selected ^ consume_all_bytes(sum.to_be_bytes().as_slice())
}

/// Negative control — a branch on the **public** operand only, with the secret
/// consumed by the library's arithmetic.
///
/// Both compared executions share their public inputs, so this is not a leak.
/// A finding here would be wrong in the direction that makes the tool useless,
/// and it is the control that distinguishes "the checker tracks the declared
/// secret" from "the checker complains about any branch".
#[constant_time(secret = "secret", dynamic = false)]
pub fn public_operand_branch(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    let a = U256::from_be_slice(secret);
    let b = U256::from_be_slice(public);
    if b.as_words()[3] & 1 == 1 {
        record(6);
    }
    consume_all_bytes(a.wrapping_add(&b).to_be_bytes().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every control returns the folded wrapping sum, so a control and the
    /// operation it is a control for differ in observable behavior only —
    /// never in the value they return.
    #[test]
    fn the_controls_preserve_the_arithmetic() {
        let secret = [0x5au8; 32];
        let public = [0xa5u8; 32];
        let sum = U256::from_be_slice(&secret).wrapping_add(&U256::from_be_slice(&public));
        let expected = consume_all_bytes(sum.to_be_bytes().as_slice());
        for produced in [
            pre_decode_first_byte(&secret, &public),
            decoded_high_limb_branch(&secret, &public),
            decoded_interior_limb_branch(&secret, &public),
            decoded_last_byte_branch(&secret, &public),
            carry_branch(&secret, &public),
            public_operand_branch(&secret, &public),
        ] {
            assert_eq!(produced, expected);
        }
    }

    /// B2 depends on `secret[0]`: the most significant limb of a big-endian
    /// decode is the first eight bytes, and its low bit is bit 0 of byte 7.
    #[test]
    fn the_high_limb_holds_the_leading_bytes() {
        let mut secret = [0u8; 32];
        secret[7] = 1;
        let decoded = U256::from_be_slice(&secret);
        assert_eq!(decoded.as_words()[3], 1);
    }

    /// B4 depends on `secret[31]`: the least significant limb's low bit is
    /// bit 0 of the final byte.
    #[test]
    fn the_low_limb_holds_the_final_byte() {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let decoded = U256::from_be_slice(&secret);
        assert_eq!(decoded.as_words()[0], 1);
    }

    /// B3's limb is the third eight-byte group, `secret[8..16]`.
    #[test]
    fn the_interior_limb_holds_the_second_group() {
        let mut secret = [0u8; 32];
        secret[15] = 1;
        let decoded = U256::from_be_slice(&secret);
        assert_eq!(decoded.as_words()[2], 1);
        assert_eq!(decoded.as_words()[3], 0);
    }

    /// B5's branch is reachable: the library's own carry is set exactly when
    /// the unbounded sum exceeds 2^256.
    #[test]
    fn the_carry_is_set_only_on_overflow() {
        let max = [0xffu8; 32];
        let mut one = [0u8; 32];
        one[31] = 1;
        let (_, carry) =
            U256::from_be_slice(&max).carrying_add(&U256::from_be_slice(&one), Limb::ZERO);
        assert_ne!(carry.0, 0);
        let (_, no_carry) =
            U256::from_be_slice(&one).carrying_add(&U256::from_be_slice(&one), Limb::ZERO);
        assert_eq!(no_carry.0, 0);
    }
}
