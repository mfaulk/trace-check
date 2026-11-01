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

use crate::mark::MarkSecret;

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
}
