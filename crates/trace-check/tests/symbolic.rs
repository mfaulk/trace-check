//! Symbolic backend tests, driven against the real analyzer.
//!
//! The whole bundled suite is verified once in a [`OnceLock`] and the
//! assertions read from that shared report: a case costs seconds of solver
//! time, and re-running the suite per assertion would make the file unusable.
//! Two tests that need a *different* artifact build their own.
//!
//! They skip when no container runtime or analyzer image is present, but
//! `TRACE_CHECK_REQUIRE_SYMBOLIC=1` — which CI sets — turns a missing backend
//! into a failure, so a skip can never be mistaken for a pass.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use trace_check::security::{Evidence, Outcome};
use trace_check::symbolic::{CaseFile, CheckFeature, SymbolicError, Verifier};
use trace_check::symbolic_report::SymbolicReport;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn case_dir() -> PathBuf {
    workspace_root().join("examples/symbolic")
}

fn cases() -> CaseFile {
    CaseFile::load(&case_dir().join("cases.json")).expect("the bundled case file is valid")
}

/// Returns false (after reporting) when the analyzer is unavailable and the
/// environment has not demanded it.
fn analyzer_available() -> bool {
    let reason = match Verifier::prepare() {
        Err(e) => Some(e.to_string()),
        Ok(mut verifier) => verifier.check_image().err().map(|e| e.to_string()),
    };
    match reason {
        None => true,
        Some(reason) => {
            assert!(
                std::env::var_os("TRACE_CHECK_REQUIRE_SYMBOLIC").is_none(),
                "TRACE_CHECK_REQUIRE_SYMBOLIC is set but the symbolic backend is unavailable: \
                 {reason}"
            );
            eprintln!("skipping: {reason}");
            false
        }
    }
}

/// The bundled suite, verified once per test binary.
fn suite() -> Option<&'static SymbolicReport> {
    static REPORT: OnceLock<Option<SymbolicReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            if !analyzer_available() {
                return None;
            }
            let file = cases();
            let out = std::env::temp_dir().join("trace-check-symbolic-it");
            Some(
                trace_check::run_symbolic(&file, &case_dir(), &file.cases, &out, None)
                    .expect("the bundled suite verifies"),
            )
        })
        .as_ref()
}

fn report_case<'a>(
    report: &'a SymbolicReport,
    id: &str,
) -> &'a trace_check::symbolic_report::CaseReport {
    report
        .cases
        .iter()
        .find(|entry| entry.case() == id)
        .unwrap_or_else(|| panic!("no case {id} in the report"))
}

/// Every bundled case reproduces the outcome it declares, and the run exits 0.
#[test]
fn every_bundled_case_meets_its_declared_expectation() {
    let Some(report) = suite() else { return };
    assert!(
        report.summary.unmet_expectations.is_empty(),
        "unmet: {:?}",
        report.summary.unmet_expectations
    );
    assert!(report.summary.expectations_reproduced);
    assert_eq!(report.executed, report.selected);
    assert_eq!(report.executed, cases().cases.len());
    assert_eq!(report.exit_code(), 0);
}

/// A secret-indexed load is found as a memory-access divergence, with no
/// enumeration of secret values.
#[test]
fn a_secret_indexed_load_is_reported_as_a_memory_divergence() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "table-lookup");
    assert_eq!(entry.result.outcome, Outcome::LeakDetected);
    assert!(
        entry
            .result
            .divergences
            .iter()
            .any(|d| d.kind == CheckFeature::MemoryAccess),
        "expected a memory-access divergence: {:?}",
        entry.result.divergences
    );
    // One path: the leak is in the address, not in the instruction sequence,
    // which is exactly what M1 cannot see.
    assert_eq!(entry.result.exploration.total_paths, Some(1));
}

/// A secret-dependent loop bound is found as control flow, and is the case that
/// survives the optimizer's branch erasure.
#[test]
fn a_secret_dependent_loop_bound_is_reported_as_control_flow() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "trip-count");
    assert_eq!(entry.result.outcome, Outcome::LeakDetected);
    assert!(
        entry
            .result
            .divergences
            .iter()
            .any(|d| d.kind == CheckFeature::ControlFlow),
        "expected a control-flow divergence: {:?}",
        entry.result.divergences
    );
}

/// Every reported divergence carries an analyzer-produced instruction address
/// and a source location resolved from the artifact's debug info.
#[test]
fn divergence_sites_name_an_address_and_a_source_location() {
    let Some(report) = suite() else { return };
    let divergences: Vec<_> = report
        .cases
        .iter()
        .flat_map(|entry| entry.result.divergences.iter())
        .collect();
    assert!(!divergences.is_empty(), "the suite should find leaks");
    for divergence in divergences {
        assert!(
            divergence.instruction.starts_with("0x"),
            "an address is expected: {divergence:?}"
        );
        let source = divergence
            .source
            .as_deref()
            .unwrap_or_else(|| panic!("no source location for {divergence:?}"));
        // The useful frame is the developer's own code, not the innermost
        // inlined core helper the address technically belongs to.
        assert!(
            source.contains("targets.rs"),
            "the outermost frame should name the analyzed source: {divergence:?}"
        );
    }
}

/// A nontrivial constant-time function is established as VERIFIED_BOUNDED, and
/// only on the two independent completeness signals.
#[test]
fn a_constant_time_scan_is_verified_over_the_declared_domain() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "masked-scan");
    assert_eq!(entry.result.outcome, Outcome::VerifiedBounded);
    assert!(entry.result.divergences.is_empty());
    assert_eq!(entry.evidence, Evidence::BoundedRelationalSymbolic);

    let exploration = &entry.result.exploration;
    assert!(exploration.is_complete(), "{exploration:?}");
    assert_eq!(exploration.unknown_queries, Some(0));
    assert!(
        exploration.performed_checks() > 0,
        "a clean verdict with zero discharged checks verifies nothing: {exploration:?}"
    );
}

/// Branching on a public input is not reported as a secret leak.
#[test]
fn a_public_branch_is_not_a_secret_leak() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "public-branch");
    assert_eq!(entry.result.outcome, Outcome::VerifiedBounded);
    assert!(entry.public_globals.contains(&"TC_PUBLIC".to_string()));
    assert!(entry.secret_globals.contains(&"TC_SECRET".to_string()));
}

/// The milestone's key demonstration: a leak reachable only under one public
/// mode is found, and the analyzer visited more than one path to find it.
#[test]
fn a_leak_behind_a_public_mode_is_found_where_sampling_misses_it() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "conditional-lookup");
    assert_eq!(entry.result.outcome, Outcome::LeakDetected);
    let paths = entry
        .result
        .exploration
        .total_paths
        .expect("path count is reported");
    assert!(
        paths > 1,
        "the public mode must be explored both ways, not sampled: {paths} path(s)"
    );
}

/// A source-level secret branch the compiler erased verifies, rather than being
/// reported as a leak that the binary does not contain.
#[test]
fn a_branch_the_compiler_erased_verifies() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "erased-branch");
    assert_eq!(entry.result.outcome, Outcome::VerifiedBounded);
    assert_eq!(
        entry.result.exploration.total_paths,
        Some(1),
        "an erased branch leaves a single path"
    );
}

/// Exploration that stops at its depth bound is INCONCLUSIVE, never verified.
#[test]
fn a_run_that_hits_the_depth_bound_is_inconclusive_not_verified() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "depth-bounded");
    assert_eq!(entry.result.outcome, Outcome::Inconclusive);
    assert_ne!(entry.result.outcome, Outcome::VerifiedBounded);
    assert!(
        !entry.result.exploration.is_complete(),
        "the case is declared inconclusive because exploration did not complete: {:?}",
        entry.result.exploration
    );
    assert!(
        entry.result.message.contains("depth") || entry.result.message.contains("path"),
        "the message should name the cause: {}",
        entry.result.message
    );
}

/// A control-flow leak reports the solver's own counterexample pair.
///
/// `-smt-dir` makes the analyzer cache each query with the model it got back,
/// and a query constraining both a secret and its `mirror_` copy is exactly
/// the relational one. The values are the solver's; nothing here constructs
/// them.
#[test]
fn a_control_flow_leak_reports_a_solver_counterexample() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "trip-count");
    assert_eq!(entry.result.outcome, Outcome::LeakDetected);
    assert_eq!(
        entry.result.witness,
        trace_check::symbolic::WitnessStatus::SolverCounterexample
    );

    let counterexample = entry
        .result
        .counterexamples
        .first()
        .unwrap_or_else(|| panic!("no counterexample for {}", entry.case()));
    assert_eq!(counterexample.global, "TC_SECRET");
    assert_ne!(
        counterexample.left, counterexample.right,
        "an identical pair witnesses nothing"
    );
    assert!(counterexample.query.ends_with(".smt2"));

    // The pair really does diverge: the target loops `secret & 7` times, so
    // the two low 3-bit values must differ.
    let parse = |value: &str| -> u8 {
        u8::from_str_radix(value.trim_start_matches("#x"), 16).expect("a hex byte")
    };
    assert_ne!(
        parse(&counterexample.left) & 7,
        parse(&counterexample.right) & 7,
        "{counterexample:?} would take the same number of iterations"
    );
}

/// A leak the analyzer settled without a solver query reports no witness, and
/// says why instead of inventing one.
#[test]
fn a_leak_without_a_solver_query_reports_no_witness() {
    let Some(report) = suite() else { return };
    let entry = report_case(report, "table-lookup");
    assert_eq!(entry.result.outcome, Outcome::LeakDetected);
    assert_eq!(
        entry.result.witness,
        trace_check::symbolic::WitnessStatus::UnavailableFromAnalyzer
    );
    assert!(entry.result.counterexamples.is_empty());
    let detail = entry
        .result
        .witness_detail
        .as_deref()
        .expect("the gap is explained");
    assert!(
        detail.contains("without issuing a relational satisfiability query"),
        "{detail}"
    );
}

/// A verified case has no counterexample, which is the point.
#[test]
fn a_verified_case_reports_no_counterexample() {
    let Some(report) = suite() else { return };
    for entry in &report.cases {
        if entry.result.outcome == Outcome::VerifiedBounded {
            assert!(entry.result.counterexamples.is_empty(), "{}", entry.case());
        }
    }
}

/// Provenance pins the analyzer and its bundled solver by image digest, not by
/// a mutable tag.
#[test]
fn provenance_pins_the_analyzer_by_digest() {
    let Some(report) = suite() else { return };
    assert!(
        report.provenance.analyzer_image.contains("@sha256:"),
        "{}",
        report.provenance.analyzer_image
    );
    assert!(report.provenance.analyzer.contains("binsec"));
    // The solver is linked into the analyzer, so the digest pins it too.
    assert!(
        report.provenance.solver.contains("bitwuzla"),
        "{}",
        report.provenance.solver
    );
    // The release tag and the build the binary self-reports are separate facts;
    // both are recorded.
    let build = report
        .provenance
        .analyzer_build
        .as_deref()
        .expect("the analyzer reports its own build");
    assert!(build.to_lowercase().contains("binsec"), "{build}");
}

/// Provenance records enough to rebuild and re-run: compiler, flags, target,
/// and the hash of the exact artifact analyzed.
#[test]
fn provenance_identifies_the_artifact_that_was_analyzed() {
    let Some(report) = suite() else { return };
    let provenance = &report.provenance;
    assert!(provenance.rustc_version.starts_with("rustc "));
    assert_eq!(provenance.target, "x86_64-unknown-linux-gnu");
    assert!(provenance.build_flags.contains("-O"), "optimized build");
    assert_eq!(provenance.artifact_sha256.len(), 64);
    assert!(provenance
        .artifact_sha256
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    // The recorded hash is the file's, not a label.
    let bytes = std::fs::read(&provenance.artifact_path).expect("the artifact is on disk");
    let digest = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(&bytes))
    };
    assert_eq!(digest, provenance.artifact_sha256);
}

/// Each case result names the artifact it describes, so a result stays
/// interpretable when separated from its report.
#[test]
fn each_case_result_names_its_artifact() {
    let Some(report) = suite() else { return };
    for entry in &report.cases {
        assert_eq!(
            entry.result.artifact_sha256,
            report.provenance.artifact_sha256
        );
    }
}

/// The report states the bounds its claim is scoped to, and does not present a
/// differing path as a measured timing signal.
#[test]
fn the_report_states_the_scope_of_its_claim() {
    let Some(report) = suite() else { return };
    let text = report.limitations.join(" ");
    assert!(text.contains("declared input domain"));
    assert!(text.contains("speculation"));
    assert!(text.contains("no hardware timing was observed"), "{text}");
    // The analysis script is kept so a result can be reproduced by hand.
    for entry in &report.cases {
        assert!(entry.result.script.contains("secret global"));
        assert!(entry.result.script.contains("explore all"));
    }
}

/// A case naming a symbol absent from the artifact is an explicit error, not a
/// clean result.
#[test]
fn a_case_naming_a_missing_symbol_is_an_error() {
    if !analyzer_available() {
        return;
    }
    let mut file = cases();
    file.cases.truncate(1);
    file.cases[0].entry_symbol = "tc_harness_does_not_exist".into();

    let staged = tempfile::tempdir().expect("temp dir");
    let out = staged.path().join("build");
    let error = trace_check::run_symbolic(&file, &case_dir(), &file.cases, &out, None)
        .expect_err("a missing entry symbol cannot be analyzed");
    match &error {
        SymbolicError::MissingSymbols { missing, .. } => {
            assert_eq!(missing, &vec!["tc_harness_does_not_exist".to_string()]);
        }
        other => panic!("expected MissingSymbols, got {other:?}"),
    }
    assert!(error.to_string().contains("tc_harness_does_not_exist"));
}

/// The verdict follows the analyzed artifact, not the case's name or declared
/// expectation.
///
/// `masked-scan` is the suite's verified case. Here its source is rewritten to
/// index by the secret and nothing else changes: same case id, same declared
/// `VERIFIED_BOUNDED`. The outcome must flip to `LEAK_DETECTED` and the run
/// must fail, which is only possible if classification comes from the analyzer.
#[test]
fn the_verdict_follows_the_artifact_not_the_declared_expectation() {
    if !analyzer_available() {
        return;
    }
    let staged = tempfile::tempdir().expect("temp dir");
    let src_dir = staged.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("src dir");
    let original = std::fs::read_to_string(case_dir().join("src/targets.rs")).expect("targets.rs");
    let leaking = original.replace(
        "acc |= unsafe { core::ptr::read_volatile(table.add(i as usize)) } & hit;",
        "acc |= unsafe { core::ptr::read_volatile(table.add((want & 15) as usize)) } & hit;",
    );
    assert_ne!(leaking, original, "the injection site must still exist");
    std::fs::write(src_dir.join("targets.rs"), leaking).expect("write targets.rs");

    let mut file = cases();
    file.cases.retain(|case| case.id == "masked-scan");
    assert_eq!(file.cases.len(), 1);
    assert_eq!(file.cases[0].expected_outcome, "VERIFIED_BOUNDED");

    let out = staged.path().join("build");
    let report = trace_check::run_symbolic(&file, staged.path(), &file.cases, &out, None)
        .expect("the mutated artifact analyzes");
    let entry = report_case(&report, "masked-scan");
    assert_eq!(
        entry.result.outcome,
        Outcome::LeakDetected,
        "a secret-indexed load must be found even though the case declares otherwise"
    );
    assert!(!entry.expectation.met);
    assert_eq!(report.exit_code(), 1);
    assert_ne!(report.provenance.artifact_sha256, suite_hash());
}

/// The bundled artifact's hash, for comparison against a rebuilt one.
fn suite_hash() -> String {
    suite()
        .map(|report| report.provenance.artifact_sha256.clone())
        .unwrap_or_default()
}

/// Rebuilding unchanged sources reproduces the same artifact, which is what
/// makes a recorded hash worth recording.
#[test]
fn an_unchanged_source_rebuilds_to_the_same_artifact() {
    if !analyzer_available() {
        return;
    }
    let verifier = Verifier::prepare().expect("a prepared verifier");
    let source = case_dir().join("src/targets.rs");
    let first = tempfile::tempdir().expect("temp dir");
    let second = tempfile::tempdir().expect("temp dir");
    let (_, left) = verifier.build(&source, first.path()).expect("first build");
    let (_, right) = verifier
        .build(&source, second.path())
        .expect("second build");
    assert_eq!(left, right, "the build is not reproducible");
}

/// Two builds aiming at the same artifact path do not corrupt each other.
///
/// rustc writes intermediate object files next to `-o`, so concurrent builds
/// into one output directory used to fail the link with a missing `.rcgu.o`.
/// Found by two tests sharing a directory, which is exactly how a developer
/// would hit it.
#[test]
fn concurrent_builds_into_one_directory_do_not_collide() {
    if !analyzer_available() {
        return;
    }
    let shared = tempfile::tempdir().expect("temp dir");
    let source = case_dir().join("src/targets.rs");
    let hashes: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let verifier = Verifier::prepare().expect("a prepared verifier");
                    verifier
                        .build(&source, shared.path())
                        .expect("a concurrent build succeeds")
                        .1
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("the build thread finishes"))
            .collect()
    });
    assert!(
        hashes.windows(2).all(|pair| pair[0] == pair[1]),
        "{hashes:?}"
    );
}

/// A vulnerable function paired with a safe harness must never be reported
/// VERIFIED_BOUNDED.
///
/// The reviewed hole: `function` and `entry_symbol` were independent and only
/// checked for existence, so this case analyzed the constant-time
/// `masked_scan` harness while the report named `secret_lookup` -- a function
/// with a known secret-dependent load that was never executed. The analyzer
/// is now asked whether it reached the declared function, and without that
/// evidence the outcome is INCONCLUSIVE.
#[test]
fn a_safe_harness_cannot_verify_a_vulnerable_declared_function() {
    if !analyzer_available() {
        return;
    }
    let mut file = cases();
    file.cases.retain(|case| case.id == "masked-scan");
    file.cases[0].function = "secret_lookup".into();
    assert_eq!(file.cases[0].entry_symbol, "tc_harness_masked_scan");
    assert_eq!(file.cases[0].expected_outcome, "VERIFIED_BOUNDED");

    let staged = tempfile::tempdir().expect("temp dir");
    let report = trace_check::run_symbolic(
        &file,
        &case_dir(),
        &file.cases,
        &staged.path().join("build"),
        None,
    )
    .expect("the mismatched case still analyzes");

    let entry = report_case(&report, "masked-scan");
    assert_eq!(
        entry.result.outcome,
        Outcome::Inconclusive,
        "a function the analyzer never reached cannot be verified"
    );
    assert_ne!(entry.result.outcome, Outcome::VerifiedBounded);
    assert!(!entry.result.target.reached);
    assert_eq!(entry.result.target.address, None);
    assert!(
        entry
            .result
            .message
            .contains("never reached `secret_lookup`"),
        "{}",
        entry.result.message
    );
    // The declared expectation is not met, so the run fails rather than
    // quietly producing a weaker result.
    assert!(!entry.expectation.met);
    assert_eq!(report.exit_code(), 2);
}

/// Every verified case carries analyzer-produced evidence that its function was
/// reached.
#[test]
fn a_verified_case_proves_its_function_was_reached() {
    let Some(report) = suite() else { return };
    for entry in &report.cases {
        if entry.result.outcome != Outcome::VerifiedBounded {
            continue;
        }
        assert!(
            entry.result.target.reached,
            "{} was verified without reaching {}",
            entry.case(),
            entry.function()
        );
        let address = entry
            .result
            .target
            .address
            .as_deref()
            .unwrap_or_else(|| panic!("{} has no reached address", entry.case()));
        assert!(address.starts_with("0x"), "{address}");
        assert!(entry.result.target.directive.contains(entry.function()));
    }
}

/// A control-flow-only analysis of the known secret-indexed lookup reports a
/// narrow result that cannot be mistaken for a full one.
///
/// Its instruction path really is secret-independent, so BINSEC reports
/// `secure` and the verdict is legitimate. What must not happen is a report
/// that reads like address noninterference was established.
#[test]
fn a_control_flow_only_result_cannot_be_mistaken_for_a_full_one() {
    if !analyzer_available() {
        return;
    }
    let mut file = cases();
    file.cases.retain(|case| case.id == "table-lookup");
    file.cases[0].features = vec![CheckFeature::ControlFlow];
    file.cases[0].expected_outcome = "VERIFIED_BOUNDED".into();

    let staged = tempfile::tempdir().expect("temp dir");
    let report = trace_check::run_symbolic(
        &file,
        &case_dir(),
        &file.cases,
        &staged.path().join("build"),
        None,
    )
    .expect("a narrow case analyzes");

    let entry = report_case(&report, "table-lookup");
    assert_eq!(entry.result.outcome, Outcome::VerifiedBounded);
    assert_eq!(
        entry.result.checked_features,
        vec![CheckFeature::ControlFlow]
    );
    assert_eq!(
        entry.result.unchecked_properties,
        vec!["memory-address noninterference"]
    );
    assert!(
        entry
            .result
            .message
            .contains("memory-address noninterference was NOT checked"),
        "{}",
        entry.result.message
    );

    let text = report.to_text();
    assert!(
        text.contains("NOT checked: memory-address noninterference"),
        "{text}"
    );

    // And the full model still finds the leak in the same function, which is
    // what makes the narrow result narrow rather than wrong.
    let full = report_case(suite().expect("the suite ran"), "table-lookup");
    assert_eq!(full.result.outcome, Outcome::LeakDetected);
}

/// Every bundled case states the observation model it was analyzed under.
#[test]
fn every_case_declares_its_observation_model() {
    let Some(report) = suite() else { return };
    for entry in &report.cases {
        assert!(
            !entry.result.checked_features.is_empty(),
            "{} declares no checks",
            entry.case()
        );
        // The bundled suite checks both classes, so nothing is left out.
        assert!(
            entry.result.unchecked_properties.is_empty(),
            "{} leaves {:?} unchecked",
            entry.case(),
            entry.result.unchecked_properties
        );
    }
    let text = report.limitations.join(" ");
    assert!(text.contains("only the observation classes the case declared"));
    assert!(text.contains("target.reached"));
}
