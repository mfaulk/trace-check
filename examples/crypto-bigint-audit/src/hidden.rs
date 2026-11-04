//! Leaks in real library operations, reachable only through **public** inputs.
//!
//! M9.7 asks whether coverage-guided exploration finds additional vulnerable
//! execution paths in an external integration, and that question cannot be
//! answered by the controls in [`crate::controls`]: those leak on essentially
//! every input, so the first generated case finds them and exploration has
//! nothing to add.
//!
//! These fixtures put the leak behind a public predicate instead. The *secret*
//! handling is the same as everywhere else in this crate — decode with
//! `U256::from_be_slice`, operate with the library's own function — and what
//! varies is how hard the vulnerable path is to reach.
//!
//! The spread is deliberate, and one of them is expected to be found by
//! **neither** strategy. A fixture set where coverage guidance wins every row
//! would be measuring the fixtures rather than the method:
//!
//! | Fixture | Gate | Reachable by |
//! | --- | --- | --- |
//! | [`boundary_gate`] | the public operand is all-ones | M6's boundary stage |
//! | [`nested_modes`] | three public predicates, conjunctively | coverage feedback only |
//! | [`nested_modes_wide`] | the same, beside a public 32-byte operand | neither |
//! | [`magic_gate`] | one exact 32-bit public equality | neither |
//! | [`nested_modes_clean`] | the same three predicates, safe body | nothing to find |
//!
//! Nothing here distorts `crypto-bigint`. A public mode selecting between a
//! table-driven path and a scan is an ordinary shape in cryptographic code,
//! and the vulnerable path is the same secret-indexed load `controls::B6`
//! uses.

use crate::sink::consume_all_bytes;
use crypto_bigint::U256;
use trace_check_macros::constant_time;

static SBOX: [u8; 16] = [
    0x7, 0x1, 0xd, 0x3, 0xf, 0x5, 0x9, 0xb, 0x0, 0x8, 0x4, 0xe, 0x2, 0xa, 0xc, 0x6,
];

/// The 32-bit token [`magic_gate`] requires.
pub const MAGIC: u32 = 0x5ca1_ab1e;

/// [`nested_modes_wide`]'s discriminant, and the second time this project paid
/// for the same lesson.
///
/// `nested_modes_wide` differs from [`nested_modes`] only in which parameter
/// is *declared* secret, which does not change codegen — so the two compiled
/// to one function with both symbols at one address, and `verify` refused the
/// contract outright:
///
/// ```text
/// error: `cbaudit::hidden::nested_modes` resolves to 2 symbols in the
/// verification artifact. trace-check refuses to choose: a verified result
/// must name one compiled function
/// ```
///
/// Worth recording because the symbolic backend's failure here is *better*
/// than the dynamic backend's: a flat refusal naming the cause, rather than an
/// `INCONCLUSIVE` with correctly located findings nobody can act on. One `xor`
/// with a compile-time constant separates them; see `docs/adapter-guide.md`.
pub const WIDE_TAG: u8 = 0x6b;

/// A secret-indexed load behind **three** public predicates, each its own
/// early return.
///
/// The shape matters, and the first attempt at this fixture got it wrong.
/// Written as one `if a == A && b == B && c == C`, the compiler merged the
/// three byte comparisons into a single test: there was no intermediate region
/// to reach, so coverage feedback had nothing to climb and reported
/// `NO_LEAK_OBSERVED` exactly like [`magic_gate`]. Separate early returns give
/// each conjunct its own region.
///
/// Each predicate is also individually *easy* — a nibble, not a whole byte —
/// so the difficulty is the conjunction rather than three separate
/// improbabilities. M6 spends its budget boundaries-first (one parameter away
/// from base), then pairwise (two away), so it cannot satisfy a
/// three-parameter conjunction at any budget; only its random stage can, at
/// roughly 2⁻¹² per case. Coverage feedback extends a retained seed one
/// predicate at a time.
#[constant_time(secret = "secret", secret = "other", dynamic = false)]
pub fn nested_modes(secret: &[u8; 32], other: &[u8; 32], stage: u8, gate: u8, trigger: u8) -> u8 {
    let sum = U256::from_be_slice(secret).wrapping_add(&U256::from_be_slice(other));
    let folded = consume_all_bytes(sum.to_be_bytes().as_slice());
    // Low nibble 0xa. No `u8` boundary value has it.
    if stage & 0x0f != 0x0a {
        return folded;
    }
    // High nibble 0x3, satisfied by the boundary value 0x3f — deliberately, so
    // this stays a test of conjunction rather than of three improbabilities.
    if gate & 0xf0 != 0x30 {
        return folded;
    }
    // An exact byte, again not a boundary value.
    if trigger != 0x5a {
        return folded;
    }
    let index = (sum.as_words()[0] & 15) as usize;
    // SAFETY: the mask keeps the index inside the 16-byte table.
    let selected = unsafe { core::ptr::read_volatile(&SBOX[index]) };
    selected ^ folded
}

/// The false-positive control: [`nested_modes`]' shape with a safe body.
///
/// Exploration reaches the guarded region and the security backend must still
/// observe nothing. A finding here would mean discovery had started
/// manufacturing evidence.
#[constant_time(secret = "secret", secret = "other", dynamic = false)]
pub fn nested_modes_clean(
    secret: &[u8; 32],
    other: &[u8; 32],
    stage: u8,
    gate: u8,
    trigger: u8,
) -> u8 {
    let sum = U256::from_be_slice(secret).wrapping_add(&U256::from_be_slice(other));
    let folded = consume_all_bytes(sum.to_be_bytes().as_slice());
    if stage & 0x0f != 0x0a {
        return folded;
    }
    if gate & 0xf0 != 0x30 {
        return folded;
    }
    if trigger != 0x5a {
        return folded;
    }
    // A full-table scan at secret-independent addresses, selected with a mask:
    // the constant-time way to do what `nested_modes` does.
    let want = (sum.as_words()[0] & 15) as u8;
    let mut selected = 0u8;
    let mut index = 0u8;
    while index < 16 {
        let mask = ((index ^ want) == 0) as u8;
        selected |= SBOX[index as usize] & mask.wrapping_neg();
        index += 1;
    }
    selected ^ folded
}

/// [`nested_modes`] again, with the second operand **public**.
///
/// The same three predicates, the same leak, the same budget — and
/// exploration does not find it. This fixture exists because that difference
/// was discovered by accident and is worth measuring rather than hiding.
///
/// The public surface here is 35 bytes (a 32-byte operand plus the three gate
/// bytes) instead of 3. The mutator spends its public budget across all of
/// them, almost all of it on array bytes that cannot open any gate, and
/// converges before climbing the third predicate: 1280 candidates, 2 seeds
/// retained, 6 new regions, `NO_LEAK_OBSERVED`. With the operand secret
/// instead, the same search retains 3 seeds, adds 14 regions and finds the
/// leak in 768 candidates.
///
/// So coverage-guided discovery is sensitive to how much of the signature is
/// public, not only to how deep the gate is — which matters for real
/// cryptographic APIs, where a wide public parameter beside a narrow mode byte
/// is an ordinary shape. See `docs/audits/crypto-bigint/exploration.md`.
#[constant_time(secret = "secret", dynamic = false)]
pub fn nested_modes_wide(
    secret: &[u8; 32],
    public: &[u8; 32],
    stage: u8,
    gate: u8,
    trigger: u8,
) -> u8 {
    let sum = U256::from_be_slice(secret).wrapping_add(&U256::from_be_slice(public));
    let folded = consume_all_bytes(sum.to_be_bytes().as_slice()) ^ WIDE_TAG;
    if stage & 0x0f != 0x0a {
        return folded;
    }
    if gate & 0xf0 != 0x30 {
        return folded;
    }
    if trigger != 0x5a {
        return folded;
    }
    let index = (sum.as_words()[0] & 15) as usize;
    // SAFETY: the mask keeps the index inside the 16-byte table.
    let selected = unsafe { core::ptr::read_volatile(&SBOX[index]) };
    selected ^ folded
}

/// A secret-indexed load behind an exact 32-bit public equality.
///
/// Region coverage gives no gradient toward one 32-bit constant, so
/// exploration is expected **not** to find this, and the configuration records
/// that rather than leaving the gap implicit. It is the honest limit of
/// coverage-guided discovery, kept as a fixture so the limit stays measured.
#[constant_time(secret = "secret", dynamic = false)]
pub fn magic_gate(secret: &[u8; 32], public: &[u8; 32], token: u32) -> u8 {
    let sum = U256::from_be_slice(secret).wrapping_add(&U256::from_be_slice(public));
    if token == MAGIC {
        let index = (sum.as_words()[0] & 15) as usize;
        // SAFETY: the mask keeps the index inside the 16-byte table.
        let selected = unsafe { core::ptr::read_volatile(&SBOX[index]) };
        return selected ^ consume_all_bytes(sum.to_be_bytes().as_slice());
    }
    consume_all_bytes(sum.to_be_bytes().as_slice())
}

/// A secret-indexed load behind the public operand's top limb being all-ones.
///
/// An all-ones byte array **is** a boundary value, so M6's boundary stage
/// supplies it among the first cases and finds this without exploration. The
/// fixture exists so a coverage-guided run that dropped the mandatory boundary
/// cases in favour of its own candidates would stop detecting it.
#[constant_time(secret = "secret", dynamic = false)]
pub fn boundary_gate(secret: &[u8; 32], public: &[u8; 32]) -> u8 {
    let decoded = U256::from_be_slice(public);
    let sum = U256::from_be_slice(secret).wrapping_add(&decoded);
    if decoded.as_words()[3] == u64::MAX {
        let index = (sum.as_words()[0] & 15) as usize;
        // SAFETY: the mask keeps the index inside the 16-byte table.
        let selected = unsafe { core::ptr::read_volatile(&SBOX[index]) };
        return selected ^ consume_all_bytes(sum.to_be_bytes().as_slice());
    }
    consume_all_bytes(sum.to_be_bytes().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guarded path is reachable, and off it every fixture returns the
    /// plain folded sum. A gate nobody can satisfy would make the benchmark
    /// measure nothing.
    #[test]
    fn the_guards_open_and_close() {
        let secret = [0x5au8; 32];
        let public = [0xa5u8; 32];
        let sum = U256::from_be_slice(&secret).wrapping_add(&U256::from_be_slice(&public));
        let folded = consume_all_bytes(sum.to_be_bytes().as_slice());

        assert_eq!(nested_modes(&secret, &public, 0, 0, 0), folded);
        assert_ne!(
            nested_modes(&secret, &public, 0x0a, 0x30, 0x5a),
            folded,
            "the guarded path must be reachable"
        );
        // Each predicate independently closes the gate.
        assert_eq!(nested_modes(&secret, &public, 0x0b, 0x30, 0x5a), folded);
        assert_eq!(nested_modes(&secret, &public, 0x0a, 0x40, 0x5a), folded);
        assert_eq!(nested_modes(&secret, &public, 0x0a, 0x30, 0x5b), folded);
        assert_eq!(magic_gate(&secret, &public, 0), folded);
        assert_ne!(magic_gate(&secret, &public, MAGIC), folded);
        assert_eq!(boundary_gate(&secret, &public), folded);
    }

    /// The diluted variant computes the same function as `nested_modes`,
    /// differing only by the documented discriminant that keeps their compiled
    /// bodies distinct.
    #[test]
    fn the_wide_variant_differs_only_by_its_discriminant() {
        let secret = [0x5au8; 32];
        let other = [0xa5u8; 32];
        for (stage, gate, trigger) in [(0u8, 0u8, 0u8), (0x0a, 0x30, 0x5a)] {
            assert_eq!(
                nested_modes_wide(&secret, &other, stage, gate, trigger) ^ WIDE_TAG,
                nested_modes(&secret, &other, stage, gate, trigger)
            );
        }
    }

    /// `boundary_gate` opens for an all-ones public operand, which is the
    /// boundary value the generator is required to supply.
    #[test]
    fn the_boundary_gate_opens_for_all_ones() {
        let secret = [0x11u8; 32];
        let public = [0xffu8; 32];
        let sum = U256::from_be_slice(&secret).wrapping_add(&U256::from_be_slice(&public));
        assert_ne!(
            boundary_gate(&secret, &public),
            consume_all_bytes(sum.to_be_bytes().as_slice())
        );
    }

    /// Both substitutions agree for every index, which is the functional
    /// property the constant-time rewrite in `nested_modes_clean` has to
    /// preserve. Without this the false-positive control could be clean
    /// because it computes something else.
    #[test]
    fn the_clean_control_computes_the_same_substitution() {
        for secret_byte in 0u8..=u8::MAX {
            let mut secret = [0u8; 32];
            secret[31] = secret_byte;
            let public = [0u8; 32];
            let leaky = nested_modes(&secret, &public, 0x0a, 0x30, 0x5a);
            let clean = nested_modes_clean(&secret, &public, 0x0a, 0x30, 0x5a);
            assert_eq!(leaky, clean, "secret byte {secret_byte:#04x}");
        }
    }
}
