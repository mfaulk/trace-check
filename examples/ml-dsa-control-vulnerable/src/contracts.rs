// M11.6 negative control — a documented defect the observation model cannot
// see.
//
// RUSTSEC-2025-0144 (reported 2025-12-12, issued 2026-01-27, CVE-2026-22705)
// records that `ml-dsa`'s `decompose` performed `r1.0 /= TwoGamma2::U32` — a
// variable-latency hardware division — on values derived from the secret `s2`
// and `t0` during signing. Patched in 0.1.0-rc.3 by replacing the division
// with Barrett reduction.
//
// Division latency is **not** in trace-check's observation model: the
// instruction path and the effective addresses are identical either way. So
// this control exists to demonstrate a limit rather than a capability, and the
// way it does that is by being compiled twice — against the affected
// `0.1.0-rc.2` and against the patched `0.1.2` — from this one source file.
//
// If trace-check's answer is the same for both, the advisory's defect is
// invisible to it, and that is the claim
// `docs/audits/controls.md` makes with the measurement beside it.
//
// The shared source is included by both crates, so the contracts themselves are
// byte-identical. One three-line shim per crate -- `sign_deterministically` --
// absorbs the only API difference between the two versions: 0.1.2 moved
// `sign_deterministic` from `SigningKey` to the `ExpandedSigningKey` that
// `expanded_key()` returns. Both shims compute FIPS 204's deterministic
// ML-DSA-65 signature over the same message under the same seed.

use trace_check_macros::constant_time;

/// Folds a signature into one byte in fixed work, so no part of it can be
/// discarded as unobserved.
#[inline(never)]
pub fn consume_all_bytes(bytes: &[u8]) -> u8 {
    let mut acc: u8 = 1;
    for &byte in bytes {
        acc = acc.wrapping_mul(31).wrapping_add(byte);
    }
    acc
}

/// Deterministic ML-DSA-65 signing, with the key-generation seed secret.
///
/// `sign_deterministic` is FIPS 204's deterministic variant, so the whole
/// computation is a function of the seed and the message — no RNG, and a
/// replayable corpus. The seed is marked and nothing is declassified, so
/// everything the signature computation derives from it is secret, including
/// the `s2` and `t0` the advisory names.
///
/// The shim this calls is the per-crate `sign_deterministically`.
#[constant_time(secret = "seed", dynamic = false)]
pub fn sign_secret_seed(seed: &[u8; 32], message: &[u8; 32]) -> u8 {
    consume_all_bytes(crate::sign_deterministically(seed, message).as_slice())
}

/// The same signing with the **message** secret and the key public.
///
/// Included because it is the other half of the question an auditor would ask,
/// and because it is a different claim: a signature scheme that leaks nothing
/// about its key may still leak about the message it signs.
#[constant_time(secret = "message", dynamic = false)]
pub fn sign_secret_message(seed: &[u8; 32], message: &[u8; 32]) -> u8 {
    consume_all_bytes(crate::sign_deterministically(seed, message).as_slice()) ^ 0x3c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signing is deterministic: the same seed and message give the same
    /// signature, which is what makes a corpus replayable.
    #[test]
    fn signing_is_deterministic() {
        assert_eq!(
            sign_secret_seed(&[1u8; 32], &[2u8; 32]),
            sign_secret_seed(&[1u8; 32], &[2u8; 32])
        );
    }

    /// The seed and the message both reach the signature, so neither contract
    /// is analyzing a value the computation ignores.
    #[test]
    fn both_inputs_reach_the_signature() {
        let base = sign_secret_seed(&[1u8; 32], &[2u8; 32]);
        assert_ne!(base, sign_secret_seed(&[9u8; 32], &[2u8; 32]));
        assert_ne!(base, sign_secret_seed(&[1u8; 32], &[9u8; 32]));
    }
}
