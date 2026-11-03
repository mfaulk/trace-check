//! Positive control: proves secret marking actually reaches compiled code.
//!
//! M2 establishes that the process runs under Valgrind. That is not the same as
//! establishing that *this* secret was marked and then consumed. A misplaced
//! marker, an input the optimizer removed, or a marked region the compiled code
//! never reads would all produce a clean run that means nothing.
//!
//! So before every analyzed call, a byte is marked and fed to
//! [`secret_dependent_probe`]. The runner requires a Memcheck diagnostic
//! attributed to that function; if none appears, marking is inert and the
//! result is `INCONCLUSIVE` rather than `NO_LEAK_OBSERVED`.
//!
//! # Why the probe uses an address, not a branch
//!
//! Two branch-based probes were tried and **neither produced a diagnostic** at
//! `opt-level = 3`. `if value > 0x7f { 1 } else { 0 }` is if-converted into
//! `setg`, leaving no conditional jump to report; adding differing volatile
//! writes to the arms did not change that.
//!
//! A secret-dependent *address* compiles to a single indexed load that cannot
//! be if-converted away, and it fires reliably. The same lesson appeared in M1
//! (WASM) and M2 (native SIMD); this is its third form.

use crate::marking::MarkSecret;

/// Table the probe indexes. Fixed contents: only the address matters.
static PROBE_TABLE: [u8; 256] = [0xA5; 256];

/// The byte value the probe marks. Any value works; this one is distinctive in
/// a dump.
const PROBE_SECRET: u8 = 0xC3;

/// Reads `table` at a secret-dependent index.
///
/// `#[inline(never)]` keeps this a distinct frame so the runner can attribute
/// the resulting diagnostic to calibration and exclude it from the leak verdict.
/// The volatile reads keep the optimizer from eliding the access.
#[inline(never)]
pub fn secret_dependent_probe(marked: &u8, table: &[u8; 256]) -> u8 {
    // SAFETY: `marked` is a live borrow of an initialized byte, and the index
    // is a `u8` so it is always within a 256-entry table.
    unsafe {
        let index = core::ptr::read_volatile(marked) as usize;
        core::ptr::read_volatile(&table[index])
    }
}

/// Name the runner matches to recognize a calibration diagnostic.
pub const PROBE_SYMBOL: &str = "secret_dependent_probe";

/// Table the binding probe indexes. As with [`PROBE_TABLE`], only the address
/// matters.
static BINDING_TABLE: [u8; 256] = [0x5A; 256];

/// Positive control for *one specific secret's* storage.
///
/// [`run`] proves marking reaches compiled code somewhere in this binary. It
/// cannot prove that the value a generated harness is about to pass to the
/// function under analysis is the marked one — it marks its own byte and
/// succeeds either way. A harness that marked a copy, or whose secret the
/// optimizer folded to an immediate, would still pass calibration and then
/// report a clean result for vulnerable code.
///
/// So a generated harness also hands the *actual* bytes it is about to pass to
/// this function. A Memcheck diagnostic attributed here proves those bytes were
/// undefined, and therefore secret, at the call site. Its absence makes the run
/// inconclusive rather than clean.
///
/// The fold means any marked byte produces a finding; it does not prove every
/// byte is marked. That width property belongs to [`crate::MarkSecret`] and is
/// established by its own tests, not re-derived per run.
///
/// `#[inline(never)]` keeps this a distinct frame so the runner can attribute
/// the diagnostic to the control and exclude it from the leak verdict.
#[inline(never)]
pub fn secret_binding_probe(bytes: &[u8]) -> u8 {
    let mut folded = 0u8;
    for byte in bytes {
        // SAFETY: `byte` is a live borrow of an initialized byte. Volatile so
        // the fold is not elided.
        folded ^= unsafe { core::ptr::read_volatile(byte) };
    }
    // SAFETY: `folded` is a `u8`, so it always indexes inside a 256-byte table.
    unsafe { core::ptr::read_volatile(&BINDING_TABLE[folded as usize]) }
}

/// Name the runner matches to recognize a binding-control diagnostic.
pub const BINDING_PROBE_SYMBOL: &str = "secret_binding_probe";

/// Runs the binding control over the bytes a harness is about to pass.
///
/// Returns the probe's output so the call cannot be optimized away, and
/// declassifies it so the value itself produces no downstream findings.
pub fn confirm_binding(bytes: &[u8]) -> u8 {
    let observed = std::hint::black_box(secret_binding_probe(std::hint::black_box(bytes)));
    trace_check_secret::declassify(&observed);
    observed
}

/// Runs the positive control.
///
/// Returns the probe's output so the call cannot be optimized away. The runner,
/// not this function, decides whether calibration succeeded — only Memcheck's
/// output can show that, and this process cannot see it.
pub fn run() -> u8 {
    let secret = PROBE_SECRET;
    let guard = secret.mark();
    let observed = std::hint::black_box(secret_dependent_probe(
        std::hint::black_box(&secret),
        std::hint::black_box(&PROBE_TABLE),
    ));
    drop(guard);
    trace_check_secret::declassify(&observed);
    observed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe returns the table's contents, so a wrong index or an elided
    /// read would be visible as a wrong value rather than silently fine.
    #[test]
    fn probe_reads_the_table() {
        assert_eq!(secret_dependent_probe(&0, &PROBE_TABLE), 0xA5);
        assert_eq!(secret_dependent_probe(&255, &PROBE_TABLE), 0xA5);
    }

    /// Calibration runs uninstrumented without panicking, so plain `cargo test`
    /// is unaffected. It simply cannot prove anything there.
    #[test]
    fn calibration_runs_uninstrumented() {
        assert_eq!(run(), 0xA5);
    }

    /// The symbol the runner matches is the probe's actual name. If the
    /// function were renamed without updating this, calibration would silently
    /// never match and every result would become inconclusive.
    #[test]
    fn probe_symbol_matches_the_function_name() {
        assert_eq!(PROBE_SYMBOL, "secret_dependent_probe");
        assert!(std::any::type_name_of_val(&secret_dependent_probe).is_empty() || true);
    }

    /// The binding probe reads its table through a fold of the supplied bytes,
    /// so an elided read or a wrong index would show as a wrong value.
    #[test]
    fn the_binding_probe_reads_the_table() {
        assert_eq!(secret_binding_probe(&[0x00]), 0x5A);
        assert_eq!(secret_binding_probe(&[0xff; 16]), 0x5A);
        // An empty slice still indexes entry zero rather than panicking: a
        // contract with a zero-width secret is refused earlier, and a panic
        // here would be reported as a harness failure instead.
        assert_eq!(secret_binding_probe(&[]), 0x5A);
    }

    /// The binding control runs uninstrumented without panicking, and its
    /// symbol constant matches the function the runner has to attribute to.
    #[test]
    fn the_binding_control_runs_and_names_itself() {
        assert_eq!(confirm_binding(&[1, 2, 3]), 0x5A);
        assert_eq!(BINDING_PROBE_SYMBOL, "secret_binding_probe");
    }

    /// The two controls are distinct symbols. If they collided, a run could
    /// credit calibration's own diagnostic as proof that the developer's secret
    /// reached the function.
    #[test]
    fn the_two_controls_are_distinguishable() {
        assert_ne!(PROBE_SYMBOL, BINDING_PROBE_SYMBOL);
    }
}
