//! Leaks behind public-input conditions that M6's generator cannot construct.
//!
//! Every function here is a *benchmark* fixture: the vulnerability is planted,
//! and what is being measured is whether an input-discovery strategy reaches
//! it. They were written before the coverage-guided algorithm, so the algorithm
//! could not be tailored to them.
//!
//! # Why M6 cannot reach `nested_modes`, as a fact rather than a probability
//!
//! M6 spends its budget boundaries-first: one case per parameter boundary value
//! with every *other* parameter at its base value, then pairwise cases that
//! move exactly **two** parameters away from base, then seeded random fill.
//!
//! `nested_modes` guards its leak with a conjunction over **three** public
//! parameters, and two of the three required values are not boundary values of
//! a `u8` at all. So neither the boundary nor the pairwise stage can produce a
//! reaching input *at any budget* — raising `cases` buys more pairwise coverage,
//! not a third simultaneous parameter. Only the random stage can, with
//! probability about 2⁻¹⁶ per case.
//!
//! That is the gap coverage feedback closes: each conjunct is individually easy
//! to satisfy and executing it reaches a new region, so a retained seed can be
//! extended one predicate at a time instead of all three at once.

use trace_check_macros::constant_time;

use crate::lookup::{substitute, substitute_indexed};

/// Public threshold above which the public token must match exactly.
pub const THRESHOLD: u32 = 0x1000_0000;

/// Width of the window above [`THRESHOLD`] in which the leak is reachable.
pub const WINDOW: u32 = 64;

/// The magic token `magic_gate` demands. Chosen to have no structure a
/// boundary, a bit flip or a byte replacement would stumble onto.
pub const MAGIC: u32 = 0x5a17_c0de;

/// Vulnerable behind three public predicates that must hold at once.
///
/// The core coverage-guidance test. See the module documentation for why
/// boundary and pairwise generation cannot reach the final branch.
///
/// Each early return is the safe full-table scan, so the only secret-dependent
/// load in the function is the last line.
#[constant_time(secret = "index")]
pub fn nested_modes(index: u8, stage: u8, gate: u8, trigger: u8) -> u8 {
    // Low nibble 0xa. No `u8` boundary value has it: the boundary set is zero,
    // one, the maximum, and the powers of two with their neighbours.
    if stage & 0x0f != 0x0a {
        return substitute(index);
    }
    // High nibble 0x3. Satisfied by the boundary value 0x3f, deliberately: a
    // conjunct that *is* reachable keeps the fixture a test of conjunction
    // rather than of three separate improbabilities.
    if gate & 0xf0 != 0x30 {
        return substitute(index);
    }
    // An exact byte, again not a boundary value.
    if trigger != 0x5a {
        return substitute(index);
    }
    substitute_indexed(index)
}

/// Vulnerable behind an exact 32-bit public equality.
///
/// The comparison-guidance diagnostic. Region and branch coverage offer no
/// gradient toward a 32-bit constant: every token but one reaches the same two
/// regions, so there is nothing for a coverage-guided search to climb. This
/// fixture exists to measure that, not to be found.
#[constant_time(secret = "index")]
pub fn magic_gate(index: u8, token: u32) -> u8 {
    if token == MAGIC {
        substitute_indexed(index)
    } else {
        substitute(index)
    }
}

/// Vulnerable inside a narrow window above a public threshold.
///
/// Boundary generation *does* reach this, because [`THRESHOLD`] is a power of
/// two and so is a boundary value of a `u32`. It is here to check the
/// interaction rather than the discovery: a coverage-guided run that quietly
/// dropped M6's boundary cases in favour of its own candidates would stop
/// finding this, which is the regression the mandatory-baseline rule prevents.
#[constant_time(secret = "index")]
pub fn threshold_window(index: u8, level: u32) -> u8 {
    if level >= THRESHOLD && level - THRESHOLD < WINDOW {
        substitute_indexed(index)
    } else {
        substitute(index)
    }
}

/// Vulnerable only for some *secret* values, behind one public predicate.
///
/// Keeps secret-input exploration honest. The inner condition tests secret
/// bits, which is itself a disclosure — but reaching the region behind it
/// requires both an odd-ish public mode and a secret with its two high bits
/// set, so a discovery strategy that froze secrets at a fixed value would never
/// execute it and would report less coverage than it had.
#[constant_time(secret = "key")]
pub fn secret_gated(key: u8, mode: u8) -> u8 {
    if mode & 3 != 2 {
        return substitute(key);
    }
    if key & 0xc0 == 0xc0 {
        substitute_indexed(key)
    } else {
        substitute(key)
    }
}

/// Clean control sharing the shape of [`nested_modes`].
///
/// Three public predicates guard a region that does the *safe* thing. A
/// coverage-guided search should reach the guarded region and the security
/// backend should still observe no leak there. A finding here would mean
/// exploration had started manufacturing findings, which is the failure mode
/// that would make the whole milestone untrustworthy.
#[constant_time(secret = "index")]
pub fn nested_modes_clean(index: u8, stage: u8, gate: u8, trigger: u8) -> u8 {
    if stage & 0x0f != 0x0a {
        return substitute(index);
    }
    if gate & 0xf0 != 0x30 {
        return substitute(index);
    }
    if trigger != 0x5a {
        return substitute(index);
    }
    // Reached only by the same three-predicate conjunction, and still a
    // full-table scan.
    substitute(index ^ 0x0f)
}

/// Vulnerable behind a public **header** that must match in three fields.
///
/// The same class as [`nested_modes`] in a different representation, which is
/// why both are here: this one's conditions are fields of one `[u8; 8]`
/// parameter rather than three separate scalars, so reaching it exercises the
/// byte-array mutation operators and the per-position sweep instead of the
/// scalar ones.
///
/// It is also *harder* for M6 than `nested_modes` is, for a structural reason.
/// Boundary generation sets a byte array to whole patterns — all zeros, all
/// ones, the two alternating phases, one-hot in the first and last byte, and a
/// walking bit through the first — so a single pattern would have to satisfy
/// all three fields at once, and none does. The pairwise stage cannot help
/// either: it varies two *parameters*, and all three conditions live in one.
///
/// The shape is deliberately mundane — a version nibble, a flags nibble, and a
/// trailing marker — because that is what real parsing code checks, and the
/// point is that ordinary input validation is enough to hide a leak from
/// generated inputs.
#[constant_time(secret = "key")]
pub fn header_gate(key: u8, header: &[u8; 8]) -> u8 {
    // A version nibble.
    if header[0] >> 4 != 0x3 {
        return substitute(key);
    }
    // A flags nibble in a different byte.
    if header[1] & 0xf0 != 0xc0 {
        return substitute(key);
    }
    // A trailing marker, which is also what makes the *last* swept byte
    // position load-bearing rather than decorative.
    if header[7] != 0x7f {
        return substitute(key);
    }
    substitute_indexed(key)
}
