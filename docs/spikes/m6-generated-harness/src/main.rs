//! M6.1 feasibility spike: a generated-style dynamic harness around a real
//! Cargo library function.
//!
//! Hand-written to stand in for what M6.3 would generate. It contains no copy
//! of the library's algorithm: it decodes runtime inputs, marks the declared
//! secret, calls the real function, declassifies the result, and records a
//! completion marker.
//!
//! Usage: `tc-spike-m6 <target> <direct|reified> <index>:<mode> [...]`
//!
//! Inputs arrive through argv on purpose. A compile-time constant would let the
//! optimizer pass an immediate and never read the marked storage, which is the
//! false-negative `trace_check_test::analyze1` documents.

use trace_check_test::{calibration, finish, launder, mark, require_instrumentation};

/// Which real library function this run analyzes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    /// Leak reachable only under a public mode.
    SubstituteMode,
    /// Constant-time full-table scan.
    Substitute,
    /// Unconditional secret-indexed load.
    SubstituteIndexed,
}

impl Target {
    fn parse(name: &str) -> Option<Target> {
        match name {
            "substitute_mode" => Some(Target::SubstituteMode),
            "substitute" => Some(Target::Substitute),
            "substitute_indexed" => Some(Target::SubstituteIndexed),
            _ => None,
        }
    }
}

/// How the target is reached: a plain cross-crate call, or reified as a
/// function pointer and laundered so a distinct callable instance must exist.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CallForm {
    Direct,
    Reified,
    /// Target-binding negative control: marks a *decoy* byte and passes the
    /// real index unmarked. Calibration still fires, so a finding attributed to
    /// the library function under this form would prove the detector is seeing
    /// ambient marking rather than the declared secret.
    Decoy,
}

/// Invokes the target with the declared positional argument mapping.
///
/// `index` is the declared secret and is already marked by the caller; `mode`
/// is public.
fn invoke(target: Target, form: CallForm, index: u8, mode: u8) -> u8 {
    match (target, form) {
        (Target::SubstituteMode, CallForm::Direct) => crypto::lookup::substitute_mode(index, mode),
        (Target::Substitute, CallForm::Direct) => crypto::lookup::substitute(index),
        (Target::SubstituteIndexed, CallForm::Direct) => crypto::lookup::substitute_indexed(index),
        (Target::SubstituteMode, CallForm::Reified) => {
            let call: fn(u8, u8) -> u8 = crypto::lookup::substitute_mode;
            (std::hint::black_box(call))(index, mode)
        }
        (Target::Substitute, CallForm::Reified) => {
            let call: fn(u8) -> u8 = crypto::lookup::substitute;
            (std::hint::black_box(call))(index)
        }
        (Target::SubstituteIndexed, CallForm::Reified) => {
            let call: fn(u8) -> u8 = crypto::lookup::substitute_indexed;
            (std::hint::black_box(call))(index)
        }
        // The decoy form marks nothing the target can see; the caller has
        // already arranged that.
        (Target::SubstituteMode, CallForm::Decoy) => crypto::lookup::substitute_mode(index, mode),
        (Target::Substitute, CallForm::Decoy) => crypto::lookup::substitute(index),
        (Target::SubstituteIndexed, CallForm::Decoy) => crypto::lookup::substitute_indexed(index),
    }
}

/// Runs one generated case: mark, call, declassify.
///
/// Nothing is serialized, logged or compared while the secret is marked.
fn run_case(target: Target, form: CallForm, case_id: usize, index: u8, mode: u8) {
    // Laundered before marking, so interprocedural constant propagation cannot
    // specialize the call for a known value and bypass the marked storage.
    let index = launder(index);
    // Under the decoy form the marking is deliberately bound to storage the
    // target never receives, which is what makes a clean result here evidence
    // that the real run's finding came from the declared parameter.
    let decoy = launder(index ^ 0x5a);
    let guard = match form {
        CallForm::Decoy => mark(&decoy),
        _ => mark(&index),
    };
    let produced = invoke(target, form, index, mode);
    drop(guard);
    let produced = finish(produced);
    // Only after declassification: tool-controlled evidence the case completed.
    println!("tc-spike-case-done: {case_id} produced={produced}");
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let [_, target, form, cases @ ..] = argv.as_slice() else {
        eprintln!("usage: tc-spike-m6 <target> <direct|reified> <index>:<mode> [...]");
        std::process::exit(2);
    };
    let Some(target) = Target::parse(target) else {
        eprintln!("unknown target {target:?}");
        std::process::exit(2);
    };
    let form = match form.as_str() {
        "direct" => CallForm::Direct,
        "reified" => CallForm::Reified,
        "decoy" => CallForm::Decoy,
        other => {
            eprintln!("unknown call form {other:?}");
            std::process::exit(2);
        }
    };
    if cases.is_empty() {
        eprintln!("no cases given; a run that checks nothing is not a pass");
        std::process::exit(2);
    }

    // Structured run-mode line, in the shape the existing native backend
    // already requires, so a clean result from an uninstrumented run is
    // rejected rather than believed.
    println!(
        "trace-check-harness: run_mode={}",
        trace_check_secret::run_mode()
    );
    require_instrumentation("tc-spike-m6");

    // Positive control, once per process: proves marking reaches compiled code
    // in this binary.
    let control = calibration::run();
    println!("tc-spike-calibration: probe_returned={control}");

    for (case_id, case) in cases.iter().enumerate() {
        let Some((index, mode)) = case.split_once(':') else {
            eprintln!("case {case_id}: expected <index>:<mode>, got {case:?}");
            std::process::exit(2);
        };
        let (Ok(index), Ok(mode)) = (index.parse::<u8>(), mode.parse::<u8>()) else {
            eprintln!("case {case_id}: inputs must be u8");
            std::process::exit(2);
        };
        run_case(target, form, case_id, index, mode);
    }

    println!("tc-spike-run-complete: cases={}", cases.len());
}
