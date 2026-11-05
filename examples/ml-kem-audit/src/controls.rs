//! Deliberate controls. Each one makes a specific way of being wrong fail
//! visibly, and together they answer three questions the audit's clean results
//! depend on:
//!
//! 1. did the harness mark the seed at all? ([`pre_keygen_seed_byte`])
//! 2. does the **re-marking** after key generation work, so a leak on a
//!    genuinely secret component is still found? ([`secret_component_branch`],
//!    [`secret_component_address`])
//! 3. did the declassification boundary move the line where it claims to, and
//!    only there? ([`public_component_branch`] against
//!    [`public_component_branch_seed_level`])
//!
//! The second pair is what makes over-declassification visible. A boundary that
//! quietly restored definedness for everything would make the whole audit read
//! clean, and nothing else in this crate would notice.
//!
//! The third pair is the only way to show the boundary is real: the *same*
//! branch on the *same* byte must be found under the seed-level encoding and
//! not found under the key-level one.

use crate::fixture;
use crate::layout::{CIPHERTEXT_LEN, EK_OFFSET, SEED_LEN};
use crate::sink::consume_all_bytes;
use ml_kem::{Decapsulate, KeyExport};
use trace_check_macros::constant_time;

static SBOX: [u8; 32] = [
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb, 0x16, 0x14,
    0x1c, 0x15, 0x10, 0x17, 0x12, 0x1e, 0x11, 0x1f, 0x13, 0x1d, 0x18, 0x1a, 0x19, 0x1b,
];

/// A side effect the optimizer may neither elide nor hoist.
///
/// This project has now recorded the compiler erasing a secret-dependent branch
/// seven times: at `opt-level = 3` a source-level `if` on a secret usually
/// becomes a `cmov`, leaving nothing to detect. A control whose branch the
/// compiler erases is not a control, so the taken arm writes through a volatile
/// pointer.
static mut SIDE_EFFECT: u8 = 0;

#[inline(never)]
fn record(value: u8) {
    // SAFETY: the checker runs one case per process, single-threaded. The write
    // exists only to be an effect the compiler must keep.
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(SIDE_EFFECT), value) }
}

/// Control 1 — the **necessary but insufficient** one: a branch on `seed[0]`
/// before key generation.
///
/// It shows the generated harness marked the array. It shows nothing about
/// `ml-kem`, and nothing about the boundary, because it reads the seed before
/// either is involved. Listed first so no report can cite it as propagation
/// evidence.
#[constant_time(secret = "seed", dynamic = false)]
pub fn pre_keygen_seed_byte(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    if seed[0] & 1 == 1 {
        record(1);
    }
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, _| {
        consume_all_bytes(key.decapsulate(&fixture::ciphertext(&ciphertext)).as_slice())
    });
    shared ^ 0x01
}

/// Control 2 — a branch on a byte of `dk_pke` **after** the boundary has been
/// drawn.
///
/// This is the control that catches over-declassification. `dk_pke` is the
/// K-PKE decryption key: if this reads as public, the boundary has declassified
/// genuine key material and every clean result in this audit is worthless.
#[constant_time(secret = "seed", dynamic = false)]
pub fn secret_component_branch(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, marked| {
        if marked[0] & 1 == 1 {
            record(2);
        }
        consume_all_bytes(key.decapsulate(&fixture::ciphertext(&ciphertext)).as_slice())
    });
    shared ^ 0x02
}

/// Control 3 — a **secret-derived address**: an `SBOX` load indexed by a byte of
/// `dk_pke`.
///
/// The address class is checked separately from the branch class because they
/// are separate observations, and an implementation can be free of one and not
/// the other.
#[constant_time(secret = "seed", dynamic = false)]
pub fn secret_component_address(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, marked| {
        let substituted = SBOX[usize::from(marked[7] & 0x1f)];
        record(substituted);
        consume_all_bytes(key.decapsulate(&fixture::ciphertext(&ciphertext)).as_slice())
            ^ substituted
    });
    shared ^ 0x03
}

/// Control 4 — a branch on a byte of the **encapsulation key**, under the
/// key-level boundary.
///
/// Expected to be **clean**. `ek` is public in the protocol — the attacker has
/// it — so a finding here would be a finding about the marking rather than
/// about the library. Read together with
/// [`public_component_branch_seed_level`], which is the same branch on the same
/// byte with nothing declassified.
#[constant_time(secret = "seed", dynamic = false)]
pub fn public_component_branch(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, marked| {
        if marked[EK_OFFSET] & 1 == 1 {
            record(4);
        }
        consume_all_bytes(key.decapsulate(&fixture::ciphertext(&ciphertext)).as_slice())
    });
    shared ^ 0x04
}

/// Control 5 — the same branch on the same byte of the encapsulation key, with
/// the **seed** marked and nothing declassified.
///
/// Expected to be **detected**. The pair (4, 5) is the evidence that the
/// boundary moved the classification line exactly where it says it does: one
/// byte, one branch, two encodings, two different answers.
#[constant_time(secret = "seed", dynamic = false)]
pub fn public_component_branch_seed_level(seed: &[u8; 64], ciphertext: &[u8; 1088]) -> u8 {
    let key = fixture::seed_level(seed);
    let ek_bytes = key.encapsulation_key().to_bytes();
    if ek_bytes[0] & 1 == 1 {
        record(5);
    }
    let shared = key.decapsulate(&fixture::ciphertext(ciphertext));
    consume_all_bytes(shared.as_slice()) ^ 0x05
}

/// Control 7 — a branch on a value derived from marked bytes by **shallow
/// arithmetic**: the sum of eight `dk_pke` bytes.
///
/// Control 2 branches on a byte Memcheck was told about directly. This one
/// branches on something the program computed from those bytes, which is the
/// first question to ask when a finding turns up unattributable: is provenance
/// lost by derivation as such, or only by derivation through something
/// specific?
#[constant_time(secret = "seed", dynamic = false)]
pub fn derived_arithmetic_branch(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, marked| {
        let mut accumulated: u8 = 0;
        let mut index = 0;
        while index < 8 {
            accumulated = accumulated.wrapping_add(marked[index]);
            index += 1;
        }
        if accumulated & 1 == 1 {
            record(7);
        }
        consume_all_bytes(key.decapsulate(&fixture::ciphertext(&ciphertext)).as_slice())
    });
    shared ^ 0x07
}

/// Control 8 — a branch on a byte of the **shared key**, which is derived from
/// marked key material through the whole FO transform.
///
/// This is the audit's sensitivity control, and the most important one here. A
/// genuine leak late in decapsulation would be driven by exactly this kind of
/// deeply derived value, so what this control produces bounds what a clean
/// result on the real contracts is worth: a `LEAK_DETECTED` here means a late
/// leak would be attributed, and anything else means it would only fail closed.
#[constant_time(secret = "seed", dynamic = false)]
pub fn shared_key_branch(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, _| {
        let shared = key.decapsulate(&fixture::ciphertext(&ciphertext));
        if shared[0] & 1 == 1 {
            record(8);
        }
        consume_all_bytes(shared.as_slice())
    });
    shared ^ 0x08
}

/// Control 6 — the negative control: the key-level boundary with **nothing**
/// planted.
///
/// Expected to be clean. If this ever reports a finding, the finding is in the
/// fixture or in the library, and the other controls are what tell those apart.
#[constant_time(secret = "seed", dynamic = false)]
pub fn no_planted_leak(seed: &[u8; 64], m: &[u8; 32]) -> u8 {
    let expanded = fixture::public_keygen(seed);
    let (ciphertext, _) = fixture::valid_ciphertext(&expanded, m);
    let shared = fixture::with_key_level_secret(&expanded, |key, _| {
        consume_all_bytes(key.decapsulate(&fixture::ciphertext(&ciphertext)).as_slice())
    });
    shared ^ 0x06
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every control still decapsulates correctly, so a detected control is
    /// evidence about observation and not about a broken fixture.
    #[test]
    fn the_controls_preserve_the_shared_key() {
        let seed = [13u8; SEED_LEN];
        let m = [4u8; 32];
        let expanded = fixture::public_keygen(&seed);
        let (ciphertext, expected) = fixture::valid_ciphertext(&expanded, &m);
        let folded = consume_all_bytes(&expected);

        assert_eq!(pre_keygen_seed_byte(&seed, &m), folded ^ 0x01);
        assert_eq!(secret_component_branch(&seed, &m), folded ^ 0x02);
        assert_eq!(public_component_branch(&seed, &m), folded ^ 0x04);
        assert_eq!(no_planted_leak(&seed, &m), folded ^ 0x06);
        // Control 3 mixes its substitution into the result on purpose, so it is
        // compared against its own definition rather than against the key.
        let substituted = SBOX[usize::from(expanded[7] & 0x1f)];
        assert_eq!(
            secret_component_address(&seed, &m),
            (folded ^ substituted) ^ 0x03
        );
    }

    /// Controls 4 and 5 read the same byte of the same encapsulation key, which
    /// is what makes the pair a statement about classification rather than
    /// about two different programs.
    #[test]
    fn the_boundary_pair_reads_the_same_byte() {
        let seed = [17u8; SEED_LEN];
        let expanded = fixture::public_keygen(&seed);
        let key = fixture::seed_level(&seed);
        assert_eq!(expanded[EK_OFFSET], key.encapsulation_key().to_bytes()[0]);
    }
}
