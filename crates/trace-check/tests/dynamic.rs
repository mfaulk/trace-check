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

use trace_check::contract::Contract;
use trace_check::dynamic_harness::{self, BatchRun};
use trace_check::generate::{self, GenerateSettings, Strategy, Value};
use trace_check::harness::{self, Library, Workspace};
use trace_check::memcheck::Classification;
use trace_check::native::{self, prepare_valgrind};

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

    let staged = check_staged(&copy, "crypto::lookup::substitute", small());
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

/// Copies the example library into `root`, rewriting its workspace-inherited
/// manifest keys and relative path dependencies so the copy builds standalone.
fn stage_library(root: &Path) -> PathBuf {
    let copy = root.join("crypto-library");
    std::fs::create_dir_all(copy.join("src")).expect("src dir");
    let source_dir = workspace_root().join("examples/crypto-library/src");
    for entry in std::fs::read_dir(&source_dir).expect("read src") {
        let entry = entry.expect("dir entry");
        std::fs::copy(entry.path(), copy.join("src").join(entry.file_name())).expect("copy source");
    }

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

/// Builds and runs a generated check against a staged library copy, returning
/// the batch evidence for its whole corpus.
fn check_staged(copy: &Path, contract_id: &str, settings: GenerateSettings) -> StagedCheck {
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
