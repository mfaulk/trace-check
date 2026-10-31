//! Tag-comparison variants whose *compiled WASM* is the object under study.
//!
//! Three invariants matter here and are easy to break by accident:
//!
//! 1. Tags arrive as runtime arguments. Nothing secret may become a
//!    compile-time constant, or the interpreter would trace a specialized
//!    module instead of the real comparison.
//! 2. Every export performs identical setup before dispatching to its
//!    verifier, so a trace difference can only come from the comparison.
//! 3. `#[inline(never)]` keeps each verifier a distinct callee, which is what
//!    gives the trace stable call depths and instruction offsets.
//!
//! `verify_early_exit` is deliberately kept alongside `verify_early_exit_opaque`:
//! at `opt-level = 3` the former is vectorized into a branchless XOR/OR tree,
//! and demonstrating that erasure is part of the experiment.

#![cfg_attr(target_arch = "wasm32", no_std)]

use subtle::ConstantTimeEq;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

pub const TAG_LEN: usize = 32;
pub const TAG_WORDS: usize = TAG_LEN / 8;

/// Reassembles a 32-byte tag from four little-endian 64-bit words; word `k`
/// carries bytes `8k..8k+8`. The work is fixed-length and input-independent.
#[inline(never)]
pub fn words_to_tag(words: [i64; TAG_WORDS]) -> [u8; TAG_LEN] {
    let mut tag = [0u8; TAG_LEN];
    let mut w = 0;
    while w < TAG_WORDS {
        let bytes = (words[w] as u64).to_le_bytes();
        let mut b = 0;
        while b < 8 {
            tag[w * 8 + b] = bytes[b];
            b += 1;
        }
        w += 1;
    }
    tag
}

/// Naive early-exit comparison. Secret-dependent at the source level, but the
/// optimizer is free to erase the branch — which is exactly what it does here.
#[inline(never)]
pub fn verify_early_exit(expected: &[u8; TAG_LEN], supplied: &[u8; TAG_LEN]) -> bool {
    let mut i = 0;
    while i < TAG_LEN {
        if expected[i] != supplied[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Early-exit comparison whose per-byte loads are opaque to the vectorizer, so
/// the secret-dependent branch survives into the compiled module. This models
/// the common real-world case of a comparison the compiler cannot coalesce.
#[inline(never)]
pub fn verify_early_exit_opaque(expected: &[u8; TAG_LEN], supplied: &[u8; TAG_LEN]) -> bool {
    let mut i = 0;
    while i < TAG_LEN {
        // SAFETY: `i < TAG_LEN` and both arrays are exactly `TAG_LEN` bytes, so
        // each reference is valid, aligned and initialized.
        let e = unsafe { core::ptr::read_volatile(&expected[i]) };
        let s = unsafe { core::ptr::read_volatile(&supplied[i]) };
        if e != s {
            return false;
        }
        i += 1;
    }
    true
}

/// Constant-time-oriented comparison, used as the path-equivalence control.
#[inline(never)]
pub fn verify_constant_time(expected: &[u8; TAG_LEN], supplied: &[u8; TAG_LEN]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}

macro_rules! export_verifier {
    ($export:ident => $verifier:path) => {
        #[no_mangle]
        pub extern "C" fn $export(
            e0: i64,
            e1: i64,
            e2: i64,
            e3: i64,
            s0: i64,
            s1: i64,
            s2: i64,
            s3: i64,
        ) -> i32 {
            let expected = words_to_tag([e0, e1, e2, e3]);
            let supplied = words_to_tag([s0, s1, s2, s3]);
            $verifier(&expected, &supplied) as i32
        }
    };
}

export_verifier!(verify_early_exit_export => verify_early_exit);
export_verifier!(verify_early_exit_opaque_export => verify_early_exit_opaque);
export_verifier!(verify_constant_time_export => verify_constant_time);

#[cfg(test)]
mod tests {
    use super::*;

    type Verifier = fn(&[u8; TAG_LEN], &[u8; TAG_LEN]) -> bool;

    const VERIFIERS: [(&str, Verifier); 3] = [
        ("early_exit", verify_early_exit),
        ("early_exit_opaque", verify_early_exit_opaque),
        ("constant_time", verify_constant_time),
    ];

    /// Each 64-bit word maps to eight consecutive bytes in little-endian order.
    #[test]
    fn words_to_tag_uses_little_endian_words() {
        let tag = words_to_tag([1, 0, 0, 0x0100_0000_0000_0000]);
        assert_eq!(tag[0], 1);
        assert_eq!(tag[31], 1);
        assert_eq!(tag.iter().filter(|b| **b != 0).count(), 2);
    }

    /// Every verifier accepts when the supplied tag equals the expected tag.
    #[test]
    fn all_verifiers_accept_matching_tags() {
        let expected = [7u8; TAG_LEN];
        for (name, verify) in VERIFIERS {
            assert!(
                verify(&expected, &expected),
                "{name} rejected a matching tag"
            );
        }
    }

    /// Every verifier rejects a mismatch at any byte position, so trace
    /// differences cannot be confounded with differing decisions.
    #[test]
    fn all_verifiers_reject_mismatch_at_every_position() {
        let supplied = [0u8; TAG_LEN];
        for i in 0..TAG_LEN {
            let mut expected = [0u8; TAG_LEN];
            expected[i] = 1;
            for (name, verify) in VERIFIERS {
                assert!(
                    !verify(&expected, &supplied),
                    "{name} accepted a tag mismatching at byte {i}"
                );
            }
        }
    }

    /// All verifiers agree on the decision for multi-byte and full mismatches.
    #[test]
    fn all_verifiers_agree_on_multi_byte_mismatches() {
        let supplied = [0u8; TAG_LEN];
        for expected in [[0xffu8; TAG_LEN], [0x01u8; TAG_LEN]] {
            let decisions: Vec<bool> = VERIFIERS
                .iter()
                .map(|(_, verify)| verify(&expected, &supplied))
                .collect();
            assert_eq!(decisions, vec![false; VERIFIERS.len()]);
        }
    }
}
