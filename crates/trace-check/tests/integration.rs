//! Tests against real captured traces and, when the backend is present, a full
//! build-run-compare cycle.
//!
//! The end-to-end tests need WABT on `PATH`. They skip when it is absent so the
//! unit suite stays usable on a bare machine, but setting
//! `TRACE_CHECK_REQUIRE_BACKEND=1` — as CI does — turns a missing backend into a
//! failure, so a skipped backend can never be mistaken for a pass.

use std::path::{Path, PathBuf};
use std::process::Command;

use trace_check::compare::{compare, Outcome};
use trace_check::experiment::{Experiment, Variant};
use trace_check::parser::{parse_trace, Decision};
use trace_check::run_experiment;
use trace_check::runner::{Limits, Runner};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn cases_path() -> PathBuf {
    workspace_root().join("examples/mac-compare/cases.json")
}

/// Returns false (after reporting) when the pinned backend is unavailable and
/// the environment has not demanded it.
fn backend_available() -> bool {
    let present = Command::new("wasm-interp")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !present {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
            "TRACE_CHECK_REQUIRE_BACKEND is set but wasm-interp is not on PATH"
        );
        eprintln!("skipping: wasm-interp is not on PATH");
    }
    present
}

/// A real captured trace parses into the expected number of ordered events and
/// the expected authentication decision.
#[test]
fn real_trace_fixture_parses() {
    let parsed = parse_trace(&fixture("opaque-mismatch-byte0.trace")).expect("fixture parses");
    assert_eq!(parsed.export, "verify_early_exit_opaque_export");
    assert_eq!(parsed.decision, Decision::Reject);
    assert_eq!(parsed.events.len(), 104);
    assert_eq!(parsed.events[0].call_depth, 0);
}

/// The surviving early-exit branch produces a detectable path difference
/// between an early and a later mismatch in real captured traces.
#[test]
fn real_early_exit_divergence_is_detected() {
    let early = parse_trace(&fixture("opaque-mismatch-byte0.trace")).unwrap();
    let later = parse_trace(&fixture("opaque-mismatch-byte8.trace")).unwrap();
    let result = compare(&early, &later, true);
    assert_eq!(result.outcome, Outcome::DifferenceDetected);
    assert_eq!((result.events_a, result.events_b), (104, 152));
    let divergence = result
        .divergence
        .expect("a difference reports a divergence");
    assert_eq!(divergence.index, 92);
    // The divergence must land on a branch, not on a data instruction.
    assert!(
        divergence.side_a[0].contains("br")
            || divergence.common_context.last().unwrap().contains("br"),
        "expected the divergence to sit at a branch, got {divergence:?}"
    );
}

/// Real `subtle` traces whose raw text differs only in operand values compare
/// as equal control-flow paths.
#[test]
fn real_operand_differences_do_not_masquerade_as_path_differences() {
    let raw_a = fixture("constant-time-byte0.trace");
    let raw_b = fixture("constant-time-byte31.trace");
    assert_ne!(
        raw_a, raw_b,
        "fixtures must differ textually for this test to mean anything"
    );

    let a = parse_trace(&raw_a).unwrap();
    let b = parse_trace(&raw_b).unwrap();
    assert_eq!(a.decision, b.decision);
    let result = compare(&a, &b, true);
    assert_eq!(result.outcome, Outcome::NoDifferenceObserved);
    assert_eq!(result.events_a, result.events_b);
}

/// A truncated capture is an explicit parse error, never a short path.
#[test]
fn truncated_fixture_is_rejected() {
    let error = parse_trace(&fixture("truncated.trace")).expect_err("truncation must be rejected");
    assert!(error.to_string().contains("truncated"), "{error}");
}

/// Unrecognized interpreter output is an explicit parse error.
#[test]
fn malformed_fixture_is_rejected() {
    let error =
        parse_trace(&fixture("malformed.trace")).expect_err("malformed input must be rejected");
    assert!(error.to_string().contains("unrecognized"), "{error}");
}

/// The bundled experiment fixture validates against the supported schema.
#[test]
fn bundled_cases_fixture_is_valid() {
    let experiment = Experiment::load(&cases_path()).expect("bundled fixture is valid");
    assert_eq!(experiment.example, "mac-compare");
    assert_eq!(experiment.variants.len(), 3);
    assert!(!experiment.comparisons.is_empty());
    // Every mismatch case must reject so trace differences are not confounded.
    assert!(experiment
        .cases
        .iter()
        .any(|case| case.expected_decision == "accept"));
}

/// The full demonstration reproduces every expected control, with all runs
/// deterministic and all decisions matching the fixture.
#[test]
fn demo_reproduces_expected_controls() {
    if !backend_available() {
        return;
    }
    let root = workspace_root();
    let experiment = Experiment::load(&cases_path()).unwrap();
    let report = run_experiment(
        &root.join("Cargo.toml"),
        "mac-compare",
        &experiment,
        Limits::default(),
        false,
    )
    .expect("demo runs end to end");

    assert!(
        report.summary.controls_reproduced,
        "unmet expectations: {:?}",
        report.summary.unmet_expectations
    );
    assert!(report.runs.iter().all(|run| run.deterministic));
    assert!(report
        .runs
        .iter()
        .all(|run| run.decision == run.expected_decision));
    assert_eq!(report.summary.inconclusive, 0);
    assert!(report.summary.differences_detected > 0);
    assert!(report.summary.no_difference_observed > 0);
    assert!(!report.provenance.module_sha256.is_empty());
}

/// Executed work in the surviving early-exit comparator grows with the
/// mismatch position, which is the signature of an early exit rather than an
/// unexplained path difference.
#[test]
fn opaque_event_counts_increase_with_mismatch_position() {
    if !backend_available() {
        return;
    }
    let root = workspace_root();
    let experiment = Experiment::load(&cases_path()).unwrap();
    let report = run_experiment(
        &root.join("Cargo.toml"),
        "mac-compare",
        &experiment,
        Limits::default(),
        false,
    )
    .unwrap();

    let events = |case: &str| {
        report
            .runs
            .iter()
            .find(|run| run.variant == "early_exit_opaque" && run.case == case)
            .unwrap_or_else(|| panic!("missing run for case {case}"))
            .events
    };
    // Cases A, C, D, E, B mismatch at bytes 0, 8, 16, 24 and 31.
    let counts: Vec<usize> = ["A", "C", "D", "E", "B"]
        .iter()
        .map(|c| events(c))
        .collect();
    assert!(
        counts.windows(2).all(|pair| pair[0] < pair[1]),
        "expected monotonically increasing event counts, got {counts:?}"
    );

    // The constant-time control must not vary with mismatch position at all.
    let control: Vec<usize> = ["A", "C", "D", "E", "B"]
        .iter()
        .map(|case| {
            report
                .runs
                .iter()
                .find(|run| run.variant == "constant_time" && run.case == *case)
                .unwrap()
                .events
        })
        .collect();
    assert!(
        control.windows(2).all(|pair| pair[0] == pair[1]),
        "expected a flat control, got {control:?}"
    );
}

/// An export that does not exist in the module is an explicit failure rather
/// than an empty or equivalent trace.
#[test]
fn unknown_export_is_an_explicit_failure() {
    if !backend_available() {
        return;
    }
    let root = workspace_root();
    let experiment = Experiment::load(&cases_path()).unwrap();
    let runner = Runner::prepare(
        &root.join("Cargo.toml"),
        "mac-compare",
        Limits::default(),
        false,
    )
    .expect("toolchain is available");

    let missing = Variant {
        id: "missing".to_string(),
        export: "no_such_export".to_string(),
        description: String::new(),
    };
    let error = runner
        .capture_raw(
            &missing,
            experiment.case("A").unwrap(),
            experiment.supplied_words(),
        )
        .expect_err("an unknown export must fail");
    assert!(
        error.to_string().contains("no_such_export"),
        "error should name the export: {error}"
    );
}

/// Running against an unpinned WABT version is refused unless explicitly
/// overridden, because instruction offsets are version specific.
#[test]
fn wabt_version_is_pinned() {
    if !backend_available() {
        return;
    }
    let version = String::from_utf8(
        Command::new("wasm-interp")
            .arg("--version")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert_eq!(
        version.trim(),
        trace_check::runner::REQUIRED_WABT_VERSION,
        "the installed WABT does not match the pinned version"
    );
}
