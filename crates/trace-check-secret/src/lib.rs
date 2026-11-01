//! Mark Rust data as secret for Valgrind Memcheck secret-dependency analysis.
//!
//! Memcheck tracks per-bit whether a value is *defined* and reports when an
//! undefined value influences a conditional branch, a memory address, or a
//! syscall argument. Marking a secret's shadow state as undefined turns that
//! machinery into a leak detector: "undefined" stands in for "secret", and
//! Memcheck's propagation through arithmetic, copies, registers and spills
//! comes for free.
//!
//! Nothing is erased. [`Secret::new`] changes Memcheck's bookkeeping only; the
//! real bytes stay readable and the program computes the same answers.
//!
//! # The two ways this goes wrong
//!
//! **Silent inactivity.** Outside Valgrind every client request is a no-op, so
//! an uninstrumented run finds nothing — which must never be read as a pass.
//! Call [`run_mode`] and refuse to interpret a clean result when it reports
//! [`RunMode::Native`]. The analysis backend enforces this.
//!
//! **Missing declassification.** A secret-derived result that reaches
//! `println!` or an assertion produces Memcheck findings inside `core::fmt`
//! that have nothing to do with the function under test. Declassify outputs
//! with [`declassify`] before ordinary use. The cost of forgetting is noise;
//! the cost of over-declassifying is suppressed findings, so keep the sites
//! few and explicit.

#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::marker::PhantomData;

#[cfg(not(trace_check_no_valgrind))]
mod sys {
    use std::ffi::c_void;

    extern "C" {
        pub fn trace_check_mark_undefined(addr: *mut c_void, len: usize);
        pub fn trace_check_mark_defined(addr: *mut c_void, len: usize);
        pub fn trace_check_running_on_valgrind() -> i32;
    }
}

// Unsupported platforms get no-ops, and `run_mode` reports Unsupported so a
// caller cannot mistake the absence of findings for a clean result.
#[cfg(trace_check_no_valgrind)]
mod sys {
    use std::ffi::c_void;

    pub unsafe fn trace_check_mark_undefined(_addr: *mut c_void, _len: usize) {}
    pub unsafe fn trace_check_mark_defined(_addr: *mut c_void, _len: usize) {}
    pub unsafe fn trace_check_running_on_valgrind() -> i32 {
        -1
    }
}

/// Whether instrumentation is actually active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Running under a Valgrind tool; marking takes effect.
    Valgrind,
    /// Running natively. Marking is a no-op, so no finding can be produced and
    /// a clean result means nothing.
    Native,
    /// Built for a platform without client-request support.
    Unsupported,
}

impl RunMode {
    /// True only when a clean result is meaningful evidence.
    pub fn is_instrumented(self) -> bool {
        matches!(self, RunMode::Valgrind)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RunMode::Valgrind => "valgrind",
            RunMode::Native => "native",
            RunMode::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn run_mode() -> RunMode {
    // SAFETY: the shim reads Valgrind's run-mode client request and has no
    // preconditions; outside Valgrind it returns 0.
    match unsafe { sys::trace_check_running_on_valgrind() } {
        0 => RunMode::Native,
        n if n > 0 => RunMode::Valgrind,
        _ => RunMode::Unsupported,
    }
}

/// Marks the bytes of `value` as secret for the guard's lifetime, restoring
/// definedness on drop.
///
/// The borrow is what makes this sound to use: the marked bytes must stay in
/// valid, stable storage for as long as Memcheck is told they are undefined,
/// and a reference held for the guard's lifetime guarantees exactly that.
///
/// Drop restores definedness so a secret living past the analysis window does
/// not poison later unrelated code. Use [`Secret::leak`] when the marking
/// should outlive the guard.
#[must_use = "dropping the guard immediately re-marks the data as public"]
pub struct Secret<'a, T: ?Sized> {
    addr: *mut u8,
    len: usize,
    declassified: bool,
    borrow: PhantomData<&'a T>,
}

impl<'a, T: ?Sized> Secret<'a, T> {
    /// Marks every byte of `value` as undefined in Memcheck's shadow state.
    pub fn new(value: &'a T) -> Self {
        let addr = value as *const T as *const u8 as *mut u8;
        let len = core::mem::size_of_val(value);
        // SAFETY: `addr`/`len` describe exactly the bytes of a live borrow, so
        // the range is valid and stays so for `'a`. The request mutates only
        // Memcheck's shadow state, never the bytes, so marking through a shared
        // reference does not alias-violate.
        unsafe { sys::trace_check_mark_undefined(addr.cast(), len) };
        Secret {
            addr,
            len,
            declassified: false,
            borrow: PhantomData,
        }
    }

    /// Number of bytes under marking.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Restores definedness now instead of on drop.
    pub fn declassify_now(mut self) {
        self.restore();
    }

    /// Leaves the data marked after the guard goes away. Only correct when the
    /// data is genuinely secret for the rest of the process.
    pub fn leak(mut self) {
        self.declassified = true;
    }

    fn restore(&mut self) {
        if !self.declassified {
            // SAFETY: same range as in `new`, still live because the borrow
            // outlives `self`.
            unsafe { sys::trace_check_mark_defined(self.addr.cast(), self.len) };
            self.declassified = true;
        }
    }
}

impl<T: ?Sized> Drop for Secret<'_, T> {
    fn drop(&mut self) {
        self.restore();
    }
}

impl<T: ?Sized> fmt::Debug for Secret<'_, T> {
    /// Never prints the bytes: they are the modeled secret, and formatting a
    /// marked value is also what produces spurious Memcheck findings.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Restores definedness for `value`, declassifying a secret-derived result so
/// it can be printed, asserted on, or returned without producing findings that
/// belong to the harness rather than the function under test.
pub fn declassify<T: ?Sized>(value: &T) {
    let addr = value as *const T as *const u8 as *mut u8;
    let len = core::mem::size_of_val(value);
    // SAFETY: `addr`/`len` describe the bytes of a live borrow; the request
    // touches only shadow state.
    unsafe { sys::trace_check_mark_defined(addr.cast(), len) };
}

/// Marks `value` as secret without a guard. Prefer [`Secret::new`]; this exists
/// for data whose marking must outlive any convenient scope.
pub fn classify<T: ?Sized>(value: &T) {
    Secret::new(value).leak();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Marking never alters the bytes, only Memcheck's shadow state.
    #[test]
    fn marking_does_not_change_values() {
        let data = [1u8, 2, 3, 4];
        {
            let _secret = Secret::new(&data);
            assert_eq!(data, [1, 2, 3, 4]);
        }
        assert_eq!(data, [1, 2, 3, 4]);
    }

    /// The guard reports the byte length it marked.
    #[test]
    fn guard_reports_marked_length() {
        let data = [0u8; 32];
        let secret = Secret::new(&data);
        assert_eq!(secret.len(), 32);
        assert!(!secret.is_empty());
    }

    /// Marking a slice covers its whole contents, not the reference.
    #[test]
    fn slice_marking_covers_contents() {
        let data = vec![7u8; 100];
        let secret = Secret::new(data.as_slice());
        assert_eq!(secret.len(), 100);
    }

    /// Declassifying early and then dropping must not double-restore.
    #[test]
    fn declassify_now_is_idempotent_with_drop() {
        let data = [9u8; 8];
        Secret::new(&data).declassify_now();
        assert_eq!(data, [9u8; 8]);
    }

    /// Debug output never includes the marked bytes.
    #[test]
    fn debug_does_not_leak_contents() {
        let data = [0xabu8; 4];
        let rendered = format!("{:?}", Secret::new(&data));
        assert!(rendered.contains("len"));
        assert!(!rendered.contains("ab"), "{rendered}");
    }

    /// Outside Valgrind the run mode is Native and is not instrumented, so a
    /// clean result cannot be mistaken for evidence.
    #[test]
    fn run_mode_outside_valgrind_is_not_instrumented() {
        let mode = run_mode();
        assert!(
            !mode.is_instrumented(),
            "the fast test suite does not run under Valgrind, got {mode}"
        );
        assert!(matches!(mode, RunMode::Native | RunMode::Unsupported));
    }

    /// `classify` and `declassify` accept unsized values without panicking.
    #[test]
    fn free_functions_accept_slices() {
        let data = [1u8, 2, 3];
        classify(data.as_slice());
        declassify(data.as_slice());
        assert_eq!(data, [1, 2, 3]);
    }
}
