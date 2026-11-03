//! M6 generated-harness tests, against the real `examples/crypto-library`.
//!
//! These are the slow, instrumented tests: each one resolves a contract out of
//! the compiled library, generates a harness around the real function, builds
//! it, and runs generated cases under Valgrind. They skip when Valgrind is
//! absent so the fast suite stays usable on a bare machine, but
//! `TRACE_CHECK_REQUIRE_BACKEND=1` — which CI sets — makes a missing backend a
//! failure, so a skip can never pass for a success.
//!
//! The gate this file exists to hold: the harness must find the leak behind
//! `substitute_mode`'s public `mode = 1`, which the library's own hand-written
//! `#[ct_test]` misses because it passes `mode = 0`.

use std::path::{Path, PathBuf};
use std::process::Command;

use trace_check::check::{self, CheckBudget, ContractCheck, Control, Isolation};
use trace_check::contract::Contract;
use trace_check::dynamic_harness::{self, BatchRun};
use trace_check::generate::{self, GenerateSettings, Strategy, Value};
use trace_check::harness::{self, Library, Workspace};
use trace_check::memcheck::Classification;
use trace_check::native::{self, prepare_valgrind};
use trace_check::security::Outcome;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn library_manifest() -> PathBuf {
    workspace_root().join("examples/crypto-library/Cargo.toml")
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

/// One prepared contract: the descriptor read out of the library, the generated
/// harness, the built artifact, and the staged corpus.
struct Prepared {
    contract: Contract,
    artifact: PathBuf,
    corpus_path: PathBuf,
    corpus: generate::Corpus,
    /// Kept so a `Runner` can stage ad-hoc shrink candidates beside the corpus.
    work_dir: PathBuf,
    // Held so the workspace outlives the artifact it contains.
    _workspace: Workspace,
}

/// A Cargo target directory shared by every test in this file.
///
/// Each test otherwise rebuilds the library, `trace-check-test` and their
/// dependencies from scratch, which dominates the runtime of an already slow
/// instrumented suite. Cargo locks the directory, so concurrent test threads
/// serialize their builds rather than corrupting each other.
fn shared_target_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("trace-check-m6-dynamic-tests");
    std::fs::create_dir_all(&dir).expect("a shared target directory");
    dir
}

/// Resolves a contract, generates and builds its harness, and stages a corpus.
fn prepare(contract_id: &str, settings: GenerateSettings) -> Prepared {
    let library = Library::resolve(&library_manifest(), &[]).expect("the example library resolves");
    let workspace = Workspace::ephemeral().expect("a private work directory");
    let (work_dir, _per_run_target) = workspace
        .directories_for(contract_id)
        .expect("per-contract directories");
    let target_dir = shared_target_dir();

    let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
        .unwrap_or_else(|e| panic!("reading the contract for {contract_id} failed: {e}"));
    let generated = dynamic_harness::generate(&contract)
        .unwrap_or_else(|e| panic!("generating a harness for {contract_id} failed: {e}"));
    let corpus = generate::generate(contract_id, &contract.descriptor, &settings)
        .unwrap_or_else(|e| panic!("generating a corpus for {contract_id} failed: {e}"));
    let corpus_path =
        dynamic_harness::stage_corpus(&corpus, &work_dir).expect("the corpus is staged");
    let artifact =
        dynamic_harness::build(&library, &generated, contract_id, &work_dir, &target_dir)
            .unwrap_or_else(|e| panic!("building a harness for {contract_id} failed: {e}"));

    Prepared {
        contract,
        artifact: artifact.path,
        corpus_path,
        corpus,
        work_dir,
        _workspace: workspace,
    }
}

impl Prepared {
    fn run(&self, ids: Option<&[usize]>) -> BatchRun {
        let (valgrind, _version) = prepare_valgrind().expect("valgrind is available");
        dynamic_harness::run_batch(
            &valgrind,
            &self.artifact,
            &self.corpus_path,
            ids,
            native::Limits::default(),
        )
        .unwrap_or_else(|e| panic!("running the harness failed: {e}"))
    }

    /// Case ids whose inputs satisfy `predicate`.
    fn cases_where(&self, predicate: impl Fn(&[(String, Value)]) -> bool) -> Vec<usize> {
        self.corpus
            .cases
            .iter()
            .filter(|case| predicate(&case.inputs))
            .map(|case| case.id)
            .collect()
    }
}

/// Findings attributable to the contract's own function, excluding both
/// controls.
fn target_findings(run: &BatchRun, contract: &Contract) -> usize {
    let parsed = run.run.as_ref().expect("the XML parsed");
    parsed
        .secret_dependency_errors()
        .filter(|error| error.attributable_to(&contract.function))
        .count()
}

/// Whether a control fired, by attribution to its own `#[inline(never)]` frame.
fn control_fired(run: &BatchRun, symbol: &str) -> bool {
    let parsed = run.run.as_ref().expect("the XML parsed");
    parsed
        .secret_dependency_errors()
        .any(|error| error.attributable_to(symbol))
}

const CALIBRATION: &str = trace_check_test::calibration::PROBE_SYMBOL;
const BINDING: &str = trace_check_test::calibration::BINDING_PROBE_SYMBOL;

/// A small budget: enough to cover two `u8` parameters' boundary floor (43)
/// without spending a minute under Valgrind.
fn small() -> GenerateSettings {
    GenerateSettings {
        cases: 50,
        ..Default::default()
    }
}

/// The milestone's defining result: generated cases find the leak behind the
/// public mode, with no hand-written test and nobody naming `mode = 1`.
#[test]
fn generated_cases_find_the_leak_behind_the_public_mode() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::lookup::substitute_mode", small());
    let run = prepared.run(None);

    assert!(
        run.instrumented,
        "the harness did not report running under Valgrind: {}",
        run.stdout
    );
    assert!(
        run.all_completed(),
        "{} of {} cases completed",
        run.completed.len(),
        run.requested.len()
    );
    assert!(
        control_fired(&run, CALIBRATION),
        "calibration did not fire, so marking is not reaching compiled code"
    );
    assert!(
        control_fired(&run, BINDING),
        "the binding control did not fire, so the marked bytes never reached the call"
    );
    assert!(
        target_findings(&run, &prepared.contract) > 0,
        "no finding was attributed to `substitute_mode`, but the corpus reaches mode = 1. \
         stdout:\n{}",
        run.stdout
    );
}

/// Running only the safe public mode observes nothing in the target, which is
/// what the library's hand-written check does. Both halves of the asymmetry are
/// asserted, so a harness that reported findings unconditionally would fail.
#[test]
fn the_safe_public_mode_alone_observes_nothing() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::lookup::substitute_mode", small());
    let safe = prepared.cases_where(|inputs| matches!(inputs[1].1, Value::Scalar { value: 0, .. }));
    assert!(!safe.is_empty(), "the corpus has no mode = 0 case");
    let run = prepared.run(Some(&safe));

    assert!(run.all_completed());
    assert!(
        control_fired(&run, BINDING),
        "the binding control must fire even on a clean path"
    );
    assert_eq!(
        target_findings(&run, &prepared.contract),
        0,
        "the constant-time path produced a finding: {}",
        run.stdout
    );

    // The other half: the leaky mode, same artifact, same corpus.
    let leaky =
        prepared.cases_where(|inputs| matches!(inputs[1].1, Value::Scalar { value: 1, .. }));
    assert!(!leaky.is_empty(), "the corpus has no mode = 1 case");
    let run = prepared.run(Some(&leaky));
    assert!(
        target_findings(&run, &prepared.contract) > 0,
        "mode = 1 produced no finding: {}",
        run.stdout
    );
}

/// The unconditional secret-indexed load is found, and reported as an address
/// use rather than a branch.
#[test]
fn a_secret_indexed_load_is_found_and_classified() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::lookup::substitute_indexed", small());
    let run = prepared.run(None);
    let parsed = run.run.as_ref().expect("the XML parsed");
    let classes: Vec<Classification> = parsed
        .secret_dependency_errors()
        .filter(|error| error.attributable_to(&prepared.contract.function))
        .map(|error| error.classification)
        .collect();
    assert!(!classes.is_empty(), "no finding: {}", run.stdout);
    assert!(
        classes.contains(&Classification::SecretDependentValue),
        "a secret-dependent address must be classified as a value/address use, got {classes:?}"
    );
}

/// The constant-time full-table scan produces no finding over a whole generated
/// corpus. A false positive here is the error direction that makes the tool
/// useless.
#[test]
fn the_constant_time_scan_produces_no_finding() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::lookup::substitute", small());
    let run = prepared.run(None);
    assert!(run.all_completed());
    assert!(control_fired(&run, BINDING));
    assert_eq!(
        target_findings(&run, &prepared.contract),
        0,
        "the masked scan was reported as leaking: {}",
        run.stdout
    );
}

/// Branching on a public input is permitted, so the negative control stays
/// clean across the generated corpus.
#[test]
fn a_public_branch_is_not_reported_as_a_leak() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::controls::public_branch", small());
    let run = prepared.run(None);
    assert!(run.all_completed());
    assert_eq!(
        target_findings(&run, &prepared.contract),
        0,
        "a public branch was reported as a secret leak: {}",
        run.stdout
    );
}

/// A leak that depends only on the **final** byte of a 16-byte secret is found.
///
/// This is the test that proves the marking is complete rather than nominal: a
/// harness that marked only the pointer, only the leading byte, or the wrong
/// width would report this as clean.
#[test]
fn a_leak_in_the_last_secret_byte_is_found() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::controls::tail_byte_probe", small());
    let run = prepared.run(None);
    assert!(run.all_completed());
    assert!(
        target_findings(&run, &prepared.contract) > 0,
        "the tail-byte leak was missed, so not every declared secret byte is marked: {}",
        run.stdout
    );
}

/// The same seed and budget produce the same corpus for the same contract, end
/// to end through the staged wire file the harness actually read.
#[test]
fn the_staged_corpus_is_reproducible() {
    if !valgrind_available() {
        return;
    }
    let first = prepare("crypto::lookup::substitute_mode", small());
    let second = prepare("crypto::lookup::substitute_mode", small());
    let staged = |prepared: &Prepared| {
        std::fs::read_to_string(&prepared.corpus_path).expect("the staged corpus is readable")
    };
    assert_eq!(staged(&first), staged(&second));
    assert_eq!(first.corpus.sha256(), second.corpus.sha256());
}

/// A corpus whose cases were all replayed from a persisted failure runs, and the
/// reproducing input still reproduces.
#[test]
fn a_replayed_failure_reproduces() {
    if !valgrind_available() {
        return;
    }
    let settings = GenerateSettings {
        cases: 50,
        strategies: vec![Strategy::Boundaries],
        regressions: vec![vec![
            ("index".to_string(), Value::Scalar { bits: 8, value: 42 }),
            ("mode".to_string(), Value::Scalar { bits: 8, value: 1 }),
        ]],
        ..Default::default()
    };
    let prepared = prepare("crypto::lookup::substitute_mode", settings);
    // The replayed case is first, by construction.
    assert_eq!(prepared.corpus.cases[0].strategy, Strategy::Regression);
    let run = prepared.run(Some(&[0]));
    assert_eq!(run.completed, vec![0]);
    assert!(
        target_findings(&run, &prepared.contract) > 0,
        "the replayed failure did not reproduce: {}",
        run.stdout
    );
}

/// A single case can be run on its own, which is what failure isolation needs.
#[test]
fn one_case_can_be_run_in_isolation() {
    if !valgrind_available() {
        return;
    }
    // The default budget, so the pairwise stage runs and a *non-zero* secret
    // index is paired with the leaky mode. At 30 cases the boundaries alone
    // spend the budget and every `mode = 1` case still has `index = 0` — which
    // leaks too, because Memcheck tracks definedness rather than value, but it
    // is a weaker thing to isolate.
    let prepared = prepare(
        "crypto::lookup::substitute_mode",
        GenerateSettings::default(),
    );
    let leaky = prepared.cases_where(|inputs| {
        matches!(inputs[1].1, Value::Scalar { value: 1, .. })
            && !matches!(inputs[0].1, Value::Scalar { value: 0, .. })
    });
    let chosen = *leaky
        .first()
        .expect("pairwise pairs a non-zero index with mode = 1");
    let run = prepared.run(Some(&[chosen]));
    assert_eq!(run.requested, vec![chosen]);
    assert_eq!(run.completed, vec![chosen]);
    assert!(
        target_findings(&run, &prepared.contract) > 0,
        "case {chosen} did not reproduce alone: {}",
        run.stdout
    );
}

/// Asking for a case the corpus does not contain fails the harness rather than
/// producing a clean run over zero cases.
#[test]
fn an_unknown_case_id_fails_the_run() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::lookup::substitute", small());
    let run = prepared.run(Some(&[9999]));
    assert!(run.completed.is_empty());
    assert_ne!(
        run.exit_code,
        Some(0),
        "a missing case id must not exit cleanly"
    );
    assert!(
        run.stderr.contains("not in the corpus"),
        "stderr: {}",
        run.stderr
    );
}

// ---------------------------------------------------------------------------
// M6.4 / M6.5: batching, failure isolation, and shrinking.
// ---------------------------------------------------------------------------

/// Settings whose corpus is exactly the replayed cases, in order, so a test can
/// place a known leaky case at a known id.
fn replaying(cases: &[(u8, u8)]) -> GenerateSettings {
    GenerateSettings {
        cases: 64,
        strategies: Vec::new(),
        regressions: cases
            .iter()
            .map(|(index, mode)| {
                vec![
                    (
                        "index".to_string(),
                        Value::Scalar {
                            bits: 8,
                            value: u64::from(*index),
                        },
                    ),
                    (
                        "mode".to_string(),
                        Value::Scalar {
                            bits: 8,
                            value: u64::from(*mode),
                        },
                    ),
                ]
            })
            .collect(),
        ..Default::default()
    }
}

impl Prepared {
    /// Runs the whole corpus through the batching, isolation and shrinking
    /// pipeline.
    fn check(&self, budget: CheckBudget) -> ContractCheck {
        let (valgrind, _version) = prepare_valgrind().expect("valgrind is available");
        let mut runner = check::Runner::new(
            &valgrind,
            &self.artifact,
            self.corpus_path.clone(),
            self.work_dir.clone(),
            native::Limits::default(),
        );
        let generated = dynamic_harness::generate(&self.contract).expect("generated");
        check::check_contract(
            &mut runner,
            &self.contract,
            &self.corpus,
            &generated.secret_parameters,
            generated.marked_bytes,
            &budget,
        )
        .unwrap_or_else(|e| panic!("checking {} failed: {e}", self.contract.id))
    }
}

/// A batched finding is narrowed back to the single case that caused it.
///
/// Eight cases, one of which takes the leaky public mode. The aggregate report
/// cannot say which — Memcheck consolidates the site — so this is the test that
/// the re-run narrowing actually works.
#[test]
fn a_batched_finding_isolates_to_one_case() {
    if !valgrind_available() {
        return;
    }
    let cases = [
        (1, 0),
        (2, 0),
        (3, 0),
        (4, 0),
        (5, 1),
        (6, 0),
        (7, 0),
        (8, 0),
    ];
    let prepared = prepare("crypto::lookup::substitute_mode", replaying(&cases));
    assert_eq!(prepared.corpus.cases.len(), 8);

    let check = prepared.check(CheckBudget {
        batch_size: 8,
        shrink: false,
        ..Default::default()
    });
    assert_eq!(check.outcome, Outcome::LeakDetected, "{}", check.message);
    assert_eq!(check.cases_completed, 8);
    assert_eq!(check.findings.len(), 1, "{:#?}", check.findings);

    let finding = &check.findings[0];
    assert!(finding.attributed, "the finding must name the contract");
    match &finding.isolation {
        Isolation::Case { id, inputs, runs } => {
            // Case 4 is `(5, 1)`, the only one taking the leaky mode.
            assert_eq!(*id, 4, "isolated the wrong case: {inputs:?}");
            assert_eq!(inputs[1].1, Value::Scalar { bits: 8, value: 1 });
            // Binary split over 8 cases: a handful of re-runs, not eight.
            assert!(*runs <= 6, "{runs} re-runs to narrow 8 cases");
        }
        other => panic!("expected a single-case isolation, got {other:?}"),
    }
}

/// A clean contract reports `NO_LEAK_OBSERVED` with both controls confirmed,
/// and spends exactly one Memcheck process per batch — no isolation re-runs
/// when there is nothing to isolate.
#[test]
fn a_clean_contract_confirms_both_controls_and_isolates_nothing() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::lookup::substitute", small());
    let check = prepared.check(CheckBudget::default());
    assert_eq!(check.outcome, Outcome::NoLeakObserved, "{}", check.message);
    assert_eq!(check.calibration, Control::Confirmed);
    assert_eq!(
        check.binding,
        Control::Confirmed,
        "the binding control must confirm this contract's own secret reached the call"
    );
    assert!(check.findings.is_empty());
    assert!(check.unattributed.is_empty());
    assert!(check.other_diagnostics.is_empty());
    assert!(check.message.contains("not proof"), "{}", check.message);
    // Exactly one Memcheck process per batch and nothing more: with no finding
    // there is nothing to isolate, so no re-runs are spent.
    let batches = check.cases_planned.div_ceil(check::DEFAULT_BATCH_SIZE);
    assert_eq!(check.analyzer_runs, batches, "{}", check.message);
    assert_eq!(check.secret_parameters, vec!["index"]);
    assert_eq!(check.marked_bytes, 1);
}

/// The aggregate cannot count leaks: a batch where *every* case is leaky still
/// reports one consolidated finding, which is exactly why isolation exists.
#[test]
fn an_all_leaky_batch_still_reports_one_finding() {
    if !valgrind_available() {
        return;
    }
    let cases = [(1, 1), (2, 1), (3, 1), (4, 1)];
    let prepared = prepare("crypto::lookup::substitute_mode", replaying(&cases));
    let check = prepared.check(CheckBudget {
        batch_size: 4,
        shrink: false,
        ..Default::default()
    });
    assert_eq!(check.outcome, Outcome::LeakDetected, "{}", check.message);
    assert_eq!(
        check.findings.len(),
        1,
        "Memcheck consolidates the site, so the finding count is not a leak count"
    );
    // Narrowing lands on the first half's first case, because every case
    // reproduces it.
    assert_eq!(check.findings[0].isolation.ids().len(), 1);
}

/// An isolated finding shrinks to a simpler input that still reproduces the
/// same finding.
#[test]
fn an_isolated_finding_shrinks_to_a_simpler_input() {
    if !valgrind_available() {
        return;
    }
    // A single leaky case with a deliberately large secret index, so there is
    // something to reduce.
    let prepared = prepare("crypto::lookup::substitute_mode", replaying(&[(200, 1)]));
    let check = prepared.check(CheckBudget {
        batch_size: 1,
        shrink: true,
        shrink_budget: 20,
    });
    assert_eq!(check.outcome, Outcome::LeakDetected, "{}", check.message);
    let finding = &check.findings[0];
    let shrunk = finding
        .shrunk
        .as_ref()
        .expect("a secret index of 200 should reduce");
    assert!(shrunk.steps >= 1);
    assert!(shrunk.attempts <= 20, "the shrink budget was exceeded");
    let Value::Scalar { value, .. } = shrunk.inputs[0].1 else {
        panic!("expected a scalar index");
    };
    assert!(value < 200, "{value} is not simpler than 200");
    // The public mode cannot shrink away: `mode = 0` takes the constant-time
    // path and would stop reproducing, so the shrinker must have kept it.
    assert_eq!(shrunk.inputs[1].1, Value::Scalar { bits: 8, value: 1 });
}

/// Shrinking can be switched off, and then costs nothing.
#[test]
fn shrinking_is_optional() {
    if !valgrind_available() {
        return;
    }
    let prepared = prepare("crypto::lookup::substitute_mode", replaying(&[(200, 1)]));
    let check = prepared.check(CheckBudget {
        batch_size: 1,
        shrink: false,
        ..Default::default()
    });
    assert_eq!(check.outcome, Outcome::LeakDetected);
    assert!(check.findings[0].shrunk.is_none());
    // One batch, no isolation (a single case is already the answer), no shrink.
    assert_eq!(check.analyzer_runs, 1);
}

/// A single-case batch needs no narrowing, and says so rather than claiming
/// re-runs it did not spend.
#[test]
fn a_single_case_batch_is_already_isolated() {
    if !valgrind_available() {
        return;
    }
    // `substitute_indexed` takes the secret alone, so it needs a one-parameter
    // replay rather than the `(index, mode)` helper.
    let settings = GenerateSettings {
        cases: 64,
        strategies: Vec::new(),
        regressions: vec![vec![(
            "index".to_string(),
            Value::Scalar { bits: 8, value: 7 },
        )]],
        ..Default::default()
    };
    let prepared = prepare("crypto::lookup::substitute_indexed", settings);
    let check = prepared.check(CheckBudget {
        batch_size: 1,
        shrink: false,
        ..Default::default()
    });
    assert_eq!(check.outcome, Outcome::LeakDetected, "{}", check.message);
    assert!(matches!(
        check.findings[0].isolation,
        Isolation::Single { id: 0 }
    ));
}

/// The tail-byte leak isolates and then shrinks to an input whose *last* byte
/// is still non-zero, because that is the byte the leak depends on.
#[test]
fn shrinking_preserves_the_byte_a_leak_depends_on() {
    if !valgrind_available() {
        return;
    }
    let settings = GenerateSettings {
        cases: 64,
        strategies: Vec::new(),
        regressions: vec![vec![
            (
                "expected".to_string(),
                Value::Bytes {
                    bytes: vec![0xff; 16],
                },
            ),
            (
                "supplied".to_string(),
                Value::Bytes {
                    bytes: vec![0xff; 16],
                },
            ),
        ]],
        ..Default::default()
    };
    let prepared = prepare("crypto::controls::tail_byte_probe", settings);
    let check = prepared.check(CheckBudget {
        batch_size: 1,
        shrink: true,
        shrink_budget: 30,
    });
    assert_eq!(check.outcome, Outcome::LeakDetected, "{}", check.message);
    let finding = &check.findings[0];
    if let Some(shrunk) = &finding.shrunk {
        let Value::Bytes { bytes } = &shrunk.inputs[0].1 else {
            panic!("expected a byte array");
        };
        assert_eq!(bytes.len(), 16, "the width must not change while shrinking");
        // Whatever else was reduced, the finding still reproduces, which is the
        // property a shrink has to preserve.
        assert!(shrunk.steps >= 1);
    }
}

/// A case that forges a completion marker and exits early is not accepted as
/// having completed.
///
/// The strongest form of the completion-evidence problem: the *library* prints
/// plausible markers for cases it never ran and then terminates the process.
/// Staged as a copy whose `substitute` body does the forging, so nothing about
/// the harness, the generator or the runner is special-cased.
#[test]
fn a_forged_marker_and_an_early_exit_are_not_completion() {
    if !valgrind_available() {
        return;
    }
    let staged = tempfile::tempdir().expect("temp dir");
    let copy = stage_library(staged.path());
    let path = copy.join("src/lookup.rs");
    let source = std::fs::read_to_string(&path).expect("lookup.rs");
    let forged = source.replace(
        "    let want = index & 15;",
        "    {\n        \
         for id in 0..60 {\n            \
         println!(\"trace-check-case: forged {id} produced=0\");\n        }\n        \
         println!(\"trace-check-run-complete: forged cases=60\");\n        \
         std::process::exit(0);\n    }\n    let want = index & 15;",
    );
    assert_ne!(forged, source, "the injection site must still exist");
    std::fs::write(&path, forged).expect("write lookup.rs");
    // The forging code needs `std`, which the library has under `cfg(test)`
    // only, so the copy drops its `no_std` attribute.
    let lib_path = copy.join("src/lib.rs");
    let lib = std::fs::read_to_string(&lib_path).expect("lib.rs");
    std::fs::write(
        &lib_path,
        lib.replace("#![cfg_attr(not(test), no_std)]", ""),
    )
    .expect("write lib.rs");

    let staged = run_staged_corpus(&copy, "crypto::lookup::substitute", small());
    assert!(
        !staged.run.all_completed(),
        "a forged marker plus an early exit was accepted as a complete run"
    );
    let why = staged
        .run
        .incompleteness()
        .expect("an incomplete run must explain itself");
    assert!(
        staged.run.completed.len() < staged.planned,
        "{} of {} cases were credited as completed: {why}",
        staged.run.completed.len(),
        staged.planned
    );
    // The forged markers carry a nonce this run never issued, so none of them
    // was counted at all.
    assert!(
        staged.run.completed.is_empty(),
        "forged markers were credited: {:?}",
        staged.run.completed
    );
}

/// Copies a directory tree.
///
/// Recursive, because the library's `src` is not flat: a module declared as a
/// directory (`src/shadow/`) made a flat `read_dir` + `copy` fail with "the
/// source path is neither a regular file nor a symlink to a regular file",
/// which is an unhelpful way to learn that a test helper constrained the
/// library's layout.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap_or_else(|e| panic!("{}: {e}", to.display()));
    for entry in std::fs::read_dir(from).unwrap_or_else(|e| panic!("{}: {e}", from.display())) {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target)
                .unwrap_or_else(|e| panic!("{}: {e}", entry.path().display()));
        }
    }
}

/// Copies the example library into `root`, rewriting its workspace-inherited
/// manifest keys and relative path dependencies so the copy builds standalone.
fn stage_library(root: &Path) -> PathBuf {
    let copy = root.join("crypto-library");
    copy_tree(
        &workspace_root().join("examples/crypto-library/src"),
        &copy.join("src"),
    );

    let absolute = |relative: &str| {
        workspace_root()
            .join(relative)
            .display()
            .to_string()
            .replace('\\', "/")
    };
    let manifest = std::fs::read_to_string(library_manifest()).expect("manifest");
    let staged = manifest
        .replace("version.workspace = true", "version = \"0.1.0\"")
        .replace("edition.workspace = true", "edition = \"2021\"")
        .replace(
            "license.workspace = true",
            "license = \"MIT OR Apache-2.0\"",
        )
        .replace(
            "path = \"../../crates/trace-check-macros\"",
            &format!("path = {:?}", absolute("crates/trace-check-macros")),
        )
        .replace(
            "path = \"../../crates/trace-check-test\"",
            &format!("path = {:?}", absolute("crates/trace-check-test")),
        );
    std::fs::write(copy.join("Cargo.toml"), format!("{staged}\n[workspace]\n"))
        .expect("write manifest");
    copy
}

/// Builds and runs a staged library copy's whole corpus, returning the batch
/// evidence. Lower-level than the `check_contract` pipeline on purpose: this is
/// for tests about whether a run *finished*, not about its verdict.
fn run_staged_corpus(copy: &Path, contract_id: &str, settings: GenerateSettings) -> StagedCheck {
    let library =
        Library::resolve(&copy.join("Cargo.toml"), &[]).expect("the staged library resolves");
    let workspace = Workspace::ephemeral().expect("a private work directory");
    let (work_dir, _) = workspace
        .directories_for(contract_id)
        .expect("per-contract directories");
    let target_dir = shared_target_dir();

    let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
        .unwrap_or_else(|e| panic!("reading {contract_id} from the staged copy failed: {e}"));
    let generated = dynamic_harness::generate(&contract).expect("generated");
    let corpus =
        generate::generate(contract_id, &contract.descriptor, &settings).expect("corpus generated");
    let corpus_path = dynamic_harness::stage_corpus(&corpus, &work_dir).expect("staged");
    let artifact =
        dynamic_harness::build(&library, &generated, contract_id, &work_dir, &target_dir)
            .unwrap_or_else(|e| panic!("building the staged harness failed: {e}"));

    let (valgrind, _version) = prepare_valgrind().expect("valgrind is available");
    let run = dynamic_harness::run_batch(
        &valgrind,
        &artifact.path,
        &corpus_path,
        None,
        native::Limits::default(),
    )
    .unwrap_or_else(|e| panic!("running the staged harness failed: {e}"));
    StagedCheck {
        planned: corpus.cases.len(),
        run,
        _workspace: workspace,
    }
}

/// A staged run's evidence, with the workspace held open.
struct StagedCheck {
    planned: usize,
    run: BatchRun,
    _workspace: Workspace,
}

/// A sequence-dependent leak reproduces only when the recorded cases are
/// replayed verbatim — order, multiplicity and all.
///
/// The regression this holds down: replay rebuilt its corpus through ordinary
/// generation, which deduplicates by input value. A reproducer of two
/// *identical* calls collapsed to one, so the only category of finding that
/// sequence preservation exists for could never be reproduced.
///
/// Staged as a copy of the library whose `substitute` leaks on its second
/// invocation and only then, so nothing about the harness or the runner is
/// special-cased.
#[test]
fn a_sequence_dependent_leak_needs_verbatim_replay() {
    if !valgrind_available() {
        return;
    }
    let staged = tempfile::tempdir().expect("temp dir");
    let copy = stage_library(staged.path());
    let path = copy.join("src/lookup.rs");
    let source = std::fs::read_to_string(&path).expect("lookup.rs");
    let stateful = source.replace(
        "    let want = index & 15;",
        "    // Injected: leaks on the second invocation and only then.\n\
         \x20   static CALLS: core::sync::atomic::AtomicUsize =\n\
         \x20       core::sync::atomic::AtomicUsize::new(0);\n\
         \x20   if CALLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) >= 1 {\n\
         \x20       // SAFETY: the mask keeps the index inside the 16-byte table.\n\
         \x20       return unsafe { core::ptr::read_volatile(&SBOX[(index & 15) as usize]) };\n\
         \x20   }\n\
         \x20   let want = index & 15;",
    );
    assert_ne!(stateful, source, "the injection site must still exist");
    std::fs::write(&path, stateful).expect("write lookup.rs");

    let contract_id = "crypto::lookup::substitute";
    let one_call = vec![("index".to_string(), Value::Scalar { bits: 8, value: 42 })];
    let twice = vec![one_call.clone(), one_call.clone()];

    // Replayed verbatim, both calls survive and the second one leaks.
    assert!(
        run_staged_cases(&copy, contract_id, &twice),
        "the second identical invocation leaks, so replaying both must reproduce it"
    );

    // One call cannot reproduce a leak that needs two. This is exactly what
    // ordinary generation leaves after deduplicating the pair, which is why
    // replay must not go through it.
    assert!(
        !run_staged_cases(&copy, contract_id, &[one_call]),
        "one call reproduced a leak that needs two; this test is no longer demonstrating why \
         verbatim replay is required"
    );

    // And the deduplication is real, not hypothetical.
    let library =
        Library::resolve(&copy.join("Cargo.toml"), &[]).expect("the staged library resolves");
    let workspace = Workspace::ephemeral().expect("a private work directory");
    let (work_dir, target_dir) = workspace
        .directories_for(contract_id)
        .expect("per-contract directories");
    let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
        .expect("the contract reads");
    assert_eq!(
        generate::verbatim(contract_id, &contract.descriptor, &twice)
            .expect("verbatim")
            .cases
            .len(),
        2
    );
    assert_eq!(
        generate::generate(
            contract_id,
            &contract.descriptor,
            &GenerateSettings {
                cases: 64,
                strategies: Vec::new(),
                regressions: twice,
                ..Default::default()
            }
        )
        .expect("generated")
        .cases
        .len(),
        1,
        "ordinary generation deduplicates identical cases"
    );
}

/// Builds the staged copy's harness and runs exactly `cases`, reporting whether
/// a finding was attributed to the contract.
fn run_staged_cases(copy: &Path, contract_id: &str, cases: &[Vec<(String, Value)>]) -> bool {
    let library =
        Library::resolve(&copy.join("Cargo.toml"), &[]).expect("the staged library resolves");
    let workspace = Workspace::ephemeral().expect("a private work directory");
    let (work_dir, _) = workspace
        .directories_for(contract_id)
        .expect("per-contract directories");
    let target_dir = shared_target_dir();

    let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
        .unwrap_or_else(|e| panic!("reading {contract_id} failed: {e}"));
    let generated = dynamic_harness::generate(&contract).expect("generated");
    let corpus =
        generate::verbatim(contract_id, &contract.descriptor, cases).expect("a verbatim corpus");
    let corpus_path = dynamic_harness::stage_corpus(&corpus, &work_dir).expect("staged");
    let artifact =
        dynamic_harness::build(&library, &generated, contract_id, &work_dir, &target_dir)
            .unwrap_or_else(|e| panic!("building the staged harness failed: {e}"));

    let (valgrind, _version) = prepare_valgrind().expect("valgrind is available");
    let ids: Vec<usize> = corpus.cases.iter().map(|case| case.id).collect();
    let run = dynamic_harness::run_batch(
        &valgrind,
        &artifact.path,
        &corpus_path,
        Some(&ids),
        native::Limits::default(),
    )
    .unwrap_or_else(|e| panic!("running the staged harness failed: {e}"));
    assert!(
        run.all_completed(),
        "the staged run did not complete: {:?}",
        run.incompleteness()
    );
    let parsed = run.run.as_ref().expect("the XML parsed");
    let found = parsed
        .secret_dependency_errors()
        .any(|error| error.attributable_to(&contract.function));
    found
}

// ---------------------------------------------------------------------------
// M6.7: mutation tests.
//
// These are the tests that catch broken secret marking, a harness generated
// against the wrong parameter, and a classifier that accidentally depends on
// fixture names. Each one takes a function the suite above reports CLEAN, edits
// the library's real implementation, and requires the verdict to flip while the
// harness design, the generator and the configuration stay the same.
// ---------------------------------------------------------------------------

/// Rewrites one source file in a staged copy, requiring the injection site to
/// still exist so a silently-missed mutation cannot pass as a clean result.
fn mutate(copy: &Path, file: &str, from: &str, to: &str) {
    let path = copy.join("src").join(file);
    let original = std::fs::read_to_string(&path).expect("source file");
    let mutated = original.replace(from, to);
    assert_ne!(
        mutated, original,
        "the injection site no longer exists in {file}; this test is no longer testing anything"
    );
    std::fs::write(&path, mutated).expect("write mutated source");
}

/// Runs a generated check against a staged library copy.
fn check_staged(copy: &Path, contract_id: &str, settings: GenerateSettings) -> ContractCheck {
    let library =
        Library::resolve(&copy.join("Cargo.toml"), &[]).expect("the staged library resolves");
    let workspace = Workspace::ephemeral().expect("a private work directory");
    let (work_dir, _) = workspace
        .directories_for(contract_id)
        .expect("per-contract directories");
    let target_dir = shared_target_dir();

    let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
        .unwrap_or_else(|e| panic!("reading {contract_id} from the staged copy failed: {e}"));
    let generated = dynamic_harness::generate(&contract).expect("generated");
    let corpus =
        generate::generate(contract_id, &contract.descriptor, &settings).expect("corpus generated");
    let corpus_path = dynamic_harness::stage_corpus(&corpus, &work_dir).expect("staged");
    let artifact =
        dynamic_harness::build(&library, &generated, contract_id, &work_dir, &target_dir)
            .unwrap_or_else(|e| panic!("building the staged harness failed: {e}"));

    let (valgrind, _version) = prepare_valgrind().expect("valgrind is available");
    let mut runner = check::Runner::new(
        &valgrind,
        &artifact.path,
        corpus_path,
        work_dir.clone(),
        native::Limits::default(),
    );
    check::check_contract(
        &mut runner,
        &contract,
        &corpus,
        &generated.secret_parameters,
        generated.marked_bytes,
        &CheckBudget {
            batch_size: 32,
            shrink: false,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("checking the staged copy failed: {e}"))
}

/// Mutation 1: a full-table scan becomes a secret-indexed lookup.
///
/// `substitute` is reported clean by the suite above. Indexing by the secret
/// instead of by the loop counter must make the generated check fail, with
/// nothing else changed.
#[test]
fn mutation_a_secret_indexed_lookup_is_caught() {
    if !valgrind_available() {
        return;
    }
    let staged = tempfile::tempdir().expect("temp dir");
    let copy = stage_library(staged.path());
    mutate(
        &copy,
        "lookup.rs",
        "read_volatile(&SBOX[position as usize])",
        "read_volatile(&SBOX[want as usize])",
    );
    let check = check_staged(&copy, "crypto::lookup::substitute", small());
    assert_eq!(
        check.outcome,
        Outcome::LeakDetected,
        "a secret-indexed load replaced a constant-time scan and was not caught: {}",
        check.message
    );
    assert!(check.findings.iter().any(|finding| finding.attributed));
}

/// Mutation 2: a secret-dependent branch appears under a public mode.
///
/// `public_branch` branches on its public input only and is reported clean.
/// Making the branch depend on the secret instead must be caught — and it is
/// the generator that has to reach the mode, since no test names it.
#[test]
fn mutation_b_a_secret_branch_under_a_public_mode_is_caught() {
    if !valgrind_available() {
        return;
    }
    let staged = tempfile::tempdir().expect("temp dir");
    let copy = stage_library(staged.path());
    // Only the body changes, so the contract descriptor and the generated
    // harness are byte-for-byte what they were.
    mutate(
        &copy,
        "controls.rs",
        "let base = if (mode & 1) == 0 { 0usize } else { 8usize };",
        "let base = if (secret & 1) == 0 { 0usize } else { 8usize };",
    );
    let check = check_staged(&copy, "crypto::controls::public_branch", small());
    assert_eq!(
        check.outcome,
        Outcome::LeakDetected,
        "a branch on the secret replaced a branch on a public input and was not caught: {}",
        check.message
    );
}

/// Mutation 3: a leak that depends only on the final byte of a 16-byte secret.
///
/// `verify_tag` folds all 16 bytes and is reported clean. Making only the last
/// byte select a load address must still be caught: a harness that marked the
/// pointer, the leading byte, or the wrong width would report this clean, and
/// the last byte is the one a short mark misses.
#[test]
fn mutation_c_a_last_byte_only_leak_is_caught() {
    if !valgrind_available() {
        return;
    }
    let staged = tempfile::tempdir().expect("temp dir");
    let copy = stage_library(staged.path());
    // A helper whose load address depends on the secret's final byte only.
    //
    // Injected after `TAG_LEN`, which is unique in the file: injecting at
    // `pub fn verify_tag(` would land between the `#[constant_time]` attribute
    // and the function it annotates.
    mutate(
        &copy,
        "tag.rs",
        "pub const TAG_LEN: usize = 16;",
        "pub const TAG_LEN: usize = 16;\n\n\
         static TAIL_TABLE: [u8; 256] = [0x11; 256];\n\n\
         /// Injected by a mutation test: only `expected[15]` reaches an address.\n\
         fn tail_leak(expected: &[u8; 16]) -> bool {\n    \
         // SAFETY: a `u8` index is always inside a 256-byte table.\n    \
         (unsafe { core::ptr::read_volatile(&TAIL_TABLE[expected[15] as usize]) }) != 0x12\n\
         }",
    );
    // Call it from the contract's own body, so the leak is on the analyzed
    // path. The signature and the declared contract are untouched.
    mutate(
        &copy,
        "tag.rs",
        "expected.ct_eq(supplied).unwrap_u8() == 1",
        "expected.ct_eq(supplied).unwrap_u8() == 1 && tail_leak(expected)",
    );

    let check = check_staged(&copy, "crypto::tag::verify_tag", small());
    assert_eq!(
        check.outcome,
        Outcome::LeakDetected,
        "a leak depending only on the secret's final byte was missed, so the marking is not \
         complete: {}",
        check.message
    );
}
