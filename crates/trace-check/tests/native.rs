//! Native Memcheck backend tests.
//!
//! These are the slow, instrumented tests: each case builds a harness and runs
//! it under Valgrind, which costs roughly an order of magnitude in runtime.
//! They skip when Valgrind is absent so the fast suite stays usable on a bare
//! machine, but `TRACE_CHECK_REQUIRE_BACKEND=1` — which CI sets — makes a
//! missing backend a failure, so a skip can never pass for a success.

use std::path::{Path, PathBuf};
use std::process::Command;

use trace_check::compare::{compare, Outcome as TraceOutcome};
use trace_check::memcheck::Classification;
use trace_check::native::{self, NativeManifest};
use trace_check::parser::{Decision, ExecutionEvent, ParsedTrace};
use trace_check::run_native_case;
use trace_check::security::Outcome;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn manifest() -> NativeManifest {
    NativeManifest::load(&workspace_root().join("examples/native-cases.json"))
        .expect("the bundled native manifest is valid")
}

/// Returns false (after reporting) when Valgrind is unavailable and the
/// environment has not demanded it.
fn valgrind_available() -> bool {
    let present = Command::new("valgrind")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !present {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
            "TRACE_CHECK_REQUIRE_BACKEND is set but valgrind is not on PATH"
        );
        eprintln!("skipping: valgrind is not on PATH");
    }
    present
}

/// Runs one manifest case end to end and returns its outcome plus the report.
fn analyze(case_id: &str) -> (Outcome, trace_check::native_report::NativeReport) {
    let root = workspace_root();
    let manifest = manifest();
    let case = manifest
        .cases
        .iter()
        .find(|case| case.id == case_id)
        .unwrap_or_else(|| panic!("no case {case_id}"));
    let report = run_native_case(&root.join("Cargo.toml"), case, native::Limits::default())
        .unwrap_or_else(|e| panic!("case {case_id} failed: {e}"));
    (report.cases[0].result.outcome, report)
}

/// The bundled manifest validates and declares the required demonstrations.
#[test]
fn bundled_manifest_is_valid() {
    let manifest = manifest();
    assert_eq!(manifest.schema_version, native::NATIVE_SCHEMA_VERSION);
    let ids: Vec<&str> = manifest.cases.iter().map(|c| c.id.as_str()).collect();
    for required in ["mac-early-exit-opaque", "table-secret-index"] {
        assert!(ids.contains(&required), "missing required case {required}");
    }
    // Every case must declare a recognized expectation.
    for case in &manifest.cases {
        assert!(
            Outcome::parse(&case.expected_outcome).is_some(),
            "{}",
            case.id
        );
    }
}

/// A secret-dependent branch in native code is detected, attributed to the
/// function under test, and carries a source location.
#[test]
fn secret_dependent_branch_is_detected() {
    if !valgrind_available() {
        return;
    }
    let (outcome, report) = analyze("mac-early-exit-opaque");
    assert_eq!(outcome, Outcome::LeakDetected);

    let result = &report.cases[0].result;
    assert!(
        result.instrumented,
        "instrumentation must be confirmed active"
    );
    assert!(!result.findings.is_empty());
    assert!(result.findings.iter().all(|f| f.attributed));
    assert!(result
        .findings
        .iter()
        .any(|f| f.classification == Classification::SecretDependentBranch));
    assert!(
        result.findings[0].location.is_some(),
        "a finding without a source location is not actionable"
    );
}

/// A secret-dependent **memory address** is detected. This is the capability
/// M1 does not have.
#[test]
fn secret_dependent_address_is_detected() {
    if !valgrind_available() {
        return;
    }
    let (outcome, report) = analyze("table-secret-index");
    assert_eq!(outcome, Outcome::LeakDetected);

    let result = &report.cases[0].result;
    assert!(result
        .findings
        .iter()
        .any(|f| f.classification == Classification::SecretDependentValue));
    let location = result.findings[0].location.as_deref().unwrap_or_default();
    assert!(
        location.contains("lib.rs"),
        "expected a source location, got {location:?}"
    );
}

/// The constant-time tag comparison and table scan are both accepted for the
/// tested cases.
#[test]
fn constant_time_implementations_are_accepted() {
    if !valgrind_available() {
        return;
    }
    for case in ["mac-constant-time", "table-constant-time-scan"] {
        let (outcome, report) = analyze(case);
        assert_eq!(outcome, Outcome::NoLeakObserved, "{case}");
        assert!(report.cases[0].result.findings.is_empty(), "{case}");
        assert!(report.cases[0].result.instrumented, "{case}");
    }
}

/// M1's finding reproduces natively: the naive early-exit comparison has no
/// secret-dependent branch left to detect, because the optimizer erased it.
#[test]
fn naive_early_exit_has_no_branch_left_to_detect() {
    if !valgrind_available() {
        return;
    }
    let (outcome, _) = analyze("mac-early-exit");
    assert_eq!(
        outcome,
        Outcome::NoLeakObserved,
        "LLVM vectorizes the loop, so there is no secret-dependent branch"
    );
}

/// A secret used only in arithmetic is permitted: propagating secrecy through
/// computation is expected, and only branches and addresses are prohibited.
#[test]
fn secret_in_arithmetic_only_is_permitted() {
    if !valgrind_available() {
        return;
    }
    assert_eq!(analyze("permitted-arithmetic").0, Outcome::NoLeakObserved);
}

/// A declassified secret-derived result can be branched on and printed without
/// producing a spurious finding, which is what proves declassification works.
#[test]
fn declassified_output_produces_no_spurious_finding() {
    if !valgrind_available() {
        return;
    }
    assert_eq!(analyze("declassified-output").0, Outcome::NoLeakObserved);
}

/// The instrumentation control: the same vulnerable lookup with the secret
/// left unmarked must be silent. If this produced findings, detection would be
/// caused by something other than the marking and every leak result would be
/// meaningless.
#[test]
fn unmarked_secret_control_is_silent() {
    if !valgrind_available() {
        return;
    }
    let (outcome, report) = analyze("control-unmarked-secret");
    assert_eq!(outcome, Outcome::NoLeakObserved);
    assert!(
        report.cases[0].result.findings.is_empty(),
        "the vulnerable function must only be flagged when its input is marked"
    );
}

/// A genuine memory error is reported as a memory error and makes the run
/// inconclusive, never classified as a timing leak.
#[test]
fn genuine_memory_error_is_not_a_timing_leak() {
    if !valgrind_available() {
        return;
    }
    let (outcome, report) = analyze("control-memory-error");
    assert_eq!(outcome, Outcome::Inconclusive);

    let result = &report.cases[0].result;
    assert!(
        result.findings.is_empty(),
        "a memory error must not appear as a secret-dependency finding"
    );
    assert!(!result.other_diagnostics.is_empty());
    assert!(result
        .other_diagnostics
        .iter()
        .any(|d| d.classification == Classification::MemoryError));
}

/// Every declared expectation in the manifest is reproduced, and the two
/// required detections are both present.
#[test]
fn all_declared_expectations_are_reproduced() {
    if !valgrind_available() {
        return;
    }
    let root = workspace_root();
    let report = trace_check::run_native(
        &root.join("Cargo.toml"),
        &manifest(),
        native::Limits::default(),
    )
    .expect("the full native suite runs");

    assert!(
        report.summary.expectations_reproduced,
        "unmet: {:?}",
        report.summary.unmet_expectations
    );
    assert_eq!(
        report.summary.leaks_detected, 2,
        "the early-exit comparison and the secret-indexed lookup must both be detected"
    );
    assert!(report.cases.iter().all(|case| {
        // Every case either confirmed instrumentation or is inconclusive.
        case.result.instrumented || case.result.outcome == Outcome::Inconclusive
    }));
}

/// The address leak is invisible to M1's instruction-path comparator.
///
/// `lookup_secret_index` compiles to `movzbl %sil,%eax; movzbl (%rdi,%rax,1),%eax;
/// ret` — the same three instructions for every secret, with only the effective
/// address differing. Feeding M1's real comparator the invariant path it would
/// observe shows it correctly reports no difference, while M2 reports a leak on
/// the same code. This is the gap that justifies the second backend.
#[test]
fn address_leak_is_invisible_to_instruction_path_comparison() {
    let invariant_path = |decision| ParsedTrace {
        export: "lookup_secret_index".to_string(),
        events: vec![
            ExecutionEvent {
                call_depth: 0,
                istream_offset: 0,
                opcode: "movzbl".into(),
            },
            ExecutionEvent {
                call_depth: 0,
                istream_offset: 4,
                opcode: "movzbl".into(),
            },
            ExecutionEvent {
                call_depth: 0,
                istream_offset: 8,
                opcode: "ret".into(),
            },
        ],
        decision,
        raw_return_value: 0,
    };

    // Two different secrets execute the identical instruction sequence.
    let result = compare(
        &invariant_path(Decision::Reject),
        &invariant_path(Decision::Reject),
        true,
    );
    assert_eq!(
        result.outcome,
        TraceOutcome::NoDifferenceObserved,
        "an instruction-path comparator cannot see an address-only difference"
    );

    if !valgrind_available() {
        return;
    }
    // The same function, analyzed by M2, is a leak.
    assert_eq!(
        analyze("table-secret-index").0,
        Outcome::LeakDetected,
        "M2 must detect what M1 structurally cannot"
    );
}
