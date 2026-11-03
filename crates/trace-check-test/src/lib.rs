//! Write constant-time assertions as ordinary Rust tests.
//!
//! ```no_run
//! use trace_check_test::{assert_constant_time, ct_test};
//!
//! # fn verify_tag(_: &[u8; 32], _: &[u8; 32]) -> bool { false }
//! #[ct_test]
//! fn verify_tag_is_constant_time() {
//!     let supplied = [0u8; 32];
//!
//!     // The secret is passed by value; the closure receives it back as a
//!     // reference the compiler cannot see through. See `analyze1` for why.
//!     let accepted = assert_constant_time!(
//!         secret = [0x42u8; 32],
//!         call = |expected| verify_tag(expected, &supplied),
//!     );
//!     assert!(!accepted, "these inputs must be rejected");
//! }
//! ```
//!
//! Run the checks with `cargo trace-check test`. Plain `cargo test` still works
//! and still passes, but prints that the constant-time check did **not** run —
//! the analysis needs Valgrind, and a skipped check must never read as success.
//!
//! # What a passing test means
//!
//! That no modeled secret-dependent behavior was observed **on the paths this
//! test exercised**, in one optimized binary, on one platform. It is not a
//! proof of constant-time behavior for all inputs. [`Outcome::NoLeakObserved`]
//! keeps that name deliberately.
//!
//! [`Outcome::NoLeakObserved`]: https://docs.rs/trace-check
//!
//! # Only some representations can be marked
//!
//! See [`MarkSecret`]. Marking a `Vec<u8>` would mark its pointer, length and
//! capacity and not one byte of its heap buffer, so `Vec` is deliberately not
//! supported; pass `vec.as_slice()`. A generic "mark anything" API would
//! compile, run, and silently report no leak for data it never marked.

pub use trace_check_macros::{constant_time, ct_test};
pub use trace_check_secret::RunMode;

pub mod calibration;
pub mod meta;

// Named `marking` rather than `mark` so it cannot shadow the `mark` function
// in path resolution.
mod marking;

pub use marking::{MarkSecret, SecretGuard};

/// Environment variable selecting the execution mode of a generated test.
pub const MODE_ENV: &str = "TRACE_CHECK_MODE";

/// Whether this process was started by the instrumented runner.
///
/// Generated checks are `#[ignore]`d, so plain `cargo test` never reaches them
/// and there is no "skip" path to get wrong. This only distinguishes a genuine
/// runner invocation from someone running the test directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Not started by the runner. A check must refuse to claim a result.
    Unmanaged,
    /// Started by `cargo trace-check test` to execute a check.
    Run,
}

impl Mode {
    /// Reads [`MODE_ENV`]. Anything unrecognized is [`Mode::Unmanaged`],
    /// because the safe default is to not claim a result.
    pub fn from_env() -> Mode {
        match std::env::var(MODE_ENV).unwrap_or_default().as_str() {
            "run" => Mode::Run,
            _ => Mode::Unmanaged,
        }
    }
}

/// The process's instrumentation mode.
///
/// Re-exported so a generated harness needs a dependency on this crate alone.
/// One fewer path dependency in a generated manifest is one fewer thing that
/// can fail to resolve on a machine that is not this repository.
pub fn run_mode() -> RunMode {
    trace_check_secret::run_mode()
}

/// Refuses to run a check outside the instrumented runner.
///
/// Generated tests are `#[ignore]`d, so reaching this function at all means
/// something explicitly selected the test. If that was not `cargo trace-check
/// test`, the check cannot produce a meaningful result and saying so loudly
/// beats returning quietly.
pub fn require_run_mode(test: &str) {
    assert_eq!(
        Mode::from_env(),
        Mode::Run,
        "trace-check: `{test}` is a constant-time check and was run directly. It needs the \
         instrumented runner: `cargo trace-check test`. Running it with `cargo test \
         --include-ignored` cannot produce a security result."
    );
    require_instrumentation(test);
}

/// Refuses to continue when a `run`-mode test is not actually instrumented.
///
/// Outside Valgrind every marking request is a no-op, so the assertion would
/// observe nothing and pass. Panicking here turns that into a visible failure.
pub fn require_instrumentation(test: &str) {
    let mode = trace_check_secret::run_mode();
    assert!(
        mode.is_instrumented(),
        "trace-check: `{test}` was asked to run its constant-time check but the process \
         is not under Valgrind (run mode: {mode}). Secret marking would be inert and a \
         clean result would be meaningless. Run `cargo trace-check test`."
    );
}

/// Starts an analyzed region: checks instrumentation, then runs the positive
/// control.
pub fn begin(test: &str) {
    require_instrumentation(test);
    calibration::run();
}

/// Starts the analyzed region inside a generated contract adapter.
///
/// Separate from [`begin`] only so the panic message can name the contract
/// rather than a file and line.
pub fn contract_begin(contract: &str) {
    require_instrumentation(contract);
    calibration::run();
}

/// Marks one secret for the lifetime of the returned guard.
///
/// Generic over `?Sized` rather than taking `&dyn MarkSecret`: a `&[u8]` is
/// already a fat pointer, so it cannot be coerced into a trait object.
pub fn mark<T: MarkSecret + ?Sized>(value: &T) -> SecretGuard<'_> {
    value.mark()
}

/// Returns `value` through an optimization barrier.
///
/// Load-bearing inside a contract adapter. `#[inline(never)]` stops the
/// adapter from being inlined, but it does not stop interprocedural constant
/// propagation from specializing it for a constant argument — and if the
/// optimizer knows the secret's value it will use an immediate and never read
/// the marked storage, producing a clean result for vulnerable code.
pub fn launder<T>(value: T) -> T {
    std::hint::black_box(value)
}

/// Ends an analyzed region by declassifying the produced value.
///
/// One well-defined boundary, after the instrumented call has returned, so the
/// caller can assert on and print the result without producing findings that
/// belong to the test rather than to the code under test.
///
/// Only the value's own bytes are restored. A heap-indirect return value may
/// still carry marked bytes; that is out of scope for M3 and documented rather
/// than silently handled.
pub fn finish<T>(value: T) -> T {
    trace_check_secret::declassify(&value);
    value
}

/// Analyzes a call that consumes one owned secret.
///
/// # Why the secret is passed by value
///
/// This was a correctness fix, not an ergonomic preference. An earlier design
/// let the test's closure capture its own binding:
///
/// ```ignore
/// let index: u8 = 42;
/// assert_constant_time!(secrets = [&index], call = || lookup(&table, index));
/// ```
///
/// The optimizer knows `index == 42`, so it passes the immediate and **never
/// reads the marked storage**. The analysis then observes nothing and reports
/// `NO_LEAK_OBSERVED` for code that is demonstrably vulnerable — verified
/// against a `lookup` that compiles to `movzbl (%rdi,%rax,1)`. The positive
/// control cannot catch this, because calibration marks its own byte and
/// succeeds either way.
///
/// Taking the secret by value removes the binding the optimizer was folding
/// from. `trace-check` owns the storage, marks it, and hands the closure a
/// reference laundered through `black_box`, so the only path to the value is
/// one the compiler cannot see through.
pub fn analyze1<S, T, F>(test: &str, secret: S, call: F) -> T
where
    S: MarkSecret,
    F: FnOnce(&S) -> T,
{
    begin(test);
    let storage = secret;
    let guard = storage.mark();
    let opaque = std::hint::black_box(&storage);
    let value = call(opaque);
    drop(guard);
    finish(value)
}

/// Analyzes a call that consumes two owned secrets.
pub fn analyze2<A, B, T, F>(test: &str, first: A, second: B, call: F) -> T
where
    A: MarkSecret,
    B: MarkSecret,
    F: FnOnce(&A, &B) -> T,
{
    begin(test);
    let (one, two) = (first, second);
    let guards = (one.mark(), two.mark());
    let value = call(std::hint::black_box(&one), std::hint::black_box(&two));
    drop(guards);
    finish(value)
}

/// Analyzes a call whose secret is a byte slice the caller owns.
///
/// Slices cannot be taken by value, so the caller keeps ownership and the
/// reference is laundered instead. Build the bytes at runtime where possible: a
/// slice whose full contents the compiler can see may still be constant-folded
/// past the marked storage, which is the hazard [`analyze1`] documents.
pub fn analyze_bytes<T, F>(test: &str, secret: &[u8], call: F) -> T
where
    F: FnOnce(&[u8]) -> T,
{
    begin(test);
    let guard = secret.mark();
    let opaque: &[u8] = std::hint::black_box(secret);
    let value = call(opaque);
    drop(guard);
    finish(value)
}

/// Marks secrets, runs the call, and returns its value.
///
/// Secrets are passed **by value** and handed back to the closure as
/// references, so the compiler cannot bypass the marked storage. See
/// [`analyze1`] for why that matters.
///
/// ```no_run
/// # use trace_check_test::assert_constant_time;
/// # fn verify(_: &[u8; 32], _: &[u8; 32]) -> bool { false }
/// # let expected = [0u8; 32]; let supplied = [0u8; 32];
/// let accepted = assert_constant_time!(
///     secret = expected,
///     call = |expected| verify(expected, &supplied),
/// );
/// ```
///
/// Forms:
///
/// * `secret = value, call = |value| …` — one owned secret
/// * `secrets = (a, b), call = |a, b| …` — two owned secrets
/// * `secret_bytes = slice, call = |bytes| …` — a borrowed `&[u8]`
#[macro_export]
macro_rules! assert_constant_time {
    (
        secret = $secret:expr,
        call = $call:expr $(,)?
    ) => {{
        $crate::analyze1(
            concat!(module_path!(), " @ ", file!(), ":", line!()),
            $secret,
            $call,
        )
    }};
    (
        secrets = ( $first:expr, $second:expr $(,)? ),
        call = $call:expr $(,)?
    ) => {{
        $crate::analyze2(
            concat!(module_path!(), " @ ", file!(), ":", line!()),
            $first,
            $second,
            $call,
        )
    }};
    (
        secret_bytes = $secret:expr,
        call = $call:expr $(,)?
    ) => {{
        $crate::analyze_bytes(
            concat!(module_path!(), " @ ", file!(), ":", line!()),
            $secret,
            $call,
        )
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unset or unrecognized mode is Unmanaged, so the default never
    /// claims a security result.
    #[test]
    fn unknown_mode_is_unmanaged() {
        // The variable is not set in the ordinary test environment.
        assert_eq!(Mode::from_env(), Mode::Unmanaged);
    }

    /// A check run outside the runner refuses, naming the right command.
    #[test]
    #[should_panic(expected = "cargo trace-check test")]
    fn running_a_check_directly_refuses() {
        require_run_mode("my_test");
    }

    /// Outside Valgrind, a run-mode test refuses rather than passing.
    #[test]
    #[should_panic(expected = "not under Valgrind")]
    fn uninstrumented_run_refuses() {
        require_instrumentation("my_test");
    }
}
