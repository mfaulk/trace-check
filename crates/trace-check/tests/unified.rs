//! M10.0: one contract, two backends, one invocation, one enforcement decision.
//!
//! The feasibility gate for unified verification. Every test here drives the
//! real `crypto-bigint` audit library from M9 through
//! [`trace_check::run_contract_coverage`], so the generated result comes from
//! Valgrind over a generated corpus and the symbolic result comes from BINSEC
//! over a bounded search — no mocked outcomes, because a mocked policy
//! evaluator would prove nothing about whether the two backends can be
//! scheduled and their evidence kept apart.
//!
//! The load-bearing assertion is not that the run passes. It is that the two
//! results are bound to **different executables** and that neither can
//! discharge the other's obligation.
//!
//! These tests skip when no container runtime or analyzer image is present, but
//! `TRACE_CHECK_REQUIRE_SYMBOLIC=1` — which CI sets — turns a missing backend
//! into a failure, so a skip can never be mistaken for a pass.

use std::path::{Path, PathBuf};

use trace_check::contract::{VerifyConfig, CONFIG_FILE};
use trace_check::coverage_report::CoverageReport;
use trace_check::enforcement::Analysis;
use trace_check::harness::{Library, Workspace};
use trace_check::security::Outcome;
use trace_check::symbolic::Verifier;
use trace_check::Selection;

const CONTRACT: &str = "cbaudit::monty::mul_both_secret";

/// A container runtime that cannot exist, so "the analyzer is unavailable" is
/// deterministic even on a machine that has the image.
const UNREACHABLE_RUNTIME: &str = "no-such-runtime";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn library_dir() -> PathBuf {
    workspace_root().join("examples/crypto-bigint-audit")
}

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

/// The audit library's own configuration with a policy appended.
///
/// The committed configuration carries no `[policy]` table, so the M8 default
/// applies and every declaration owes `generated` only. These tests supply the
/// policy that makes a contract owe both analyses, without editing the audit
/// configuration that the standalone M9 acceptance checks read.
fn config_with_policy(policy: &str) -> VerifyConfig {
    let base = std::fs::read_to_string(library_dir().join(CONFIG_FILE))
        .expect("the audit configuration is committed");
    write_config(&format!("{base}\n{policy}"))
}

/// Loads `text` as a configuration, through a file because that is the only
/// loader and validation is part of what is under test.
fn write_config(text: &str) -> VerifyConfig {
    let directory = tempfile::tempdir().expect("a temporary configuration directory");
    let path = directory.path().join(CONFIG_FILE);
    std::fs::write(&path, text).expect("write the configuration");
    VerifyConfig::load(&path).expect("the composed configuration is valid")
}

/// Requires both analyses of [`CONTRACT`] and leaves every other declaration on
/// the default.
fn both_required() -> VerifyConfig {
    config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{CONTRACT}\"]\nrequired = [\"generated\", \"symbolic\"]\n"
    ))
}

/// Runs the unified checker over `CONTRACT` alone.
///
/// A named selection rather than every contract: the inventory is still built
/// over the whole library, so the other seventeen declarations are reported
/// `NOT_SELECTED` and the run costs two backends on one contract instead of
/// thirty-six analyses.
fn unified(config: &VerifyConfig, runtime: Option<&str>) -> CoverageReport {
    let workspace = Workspace::ephemeral().expect("a private workspace");
    let library =
        Library::resolve(&library_dir().join("Cargo.toml"), &[]).expect("the audit library");
    trace_check::run_contract_coverage(
        &library,
        config,
        &workspace,
        &trace_check::CheckOverrides::default(),
        &Selection::Named(vec![CONTRACT.to_string()]),
        None,
        "2026-11-04",
        runtime,
    )
    .expect("the unified run reports rather than failing")
}

/// Asserts that nothing blocking this run is about `contract`.
///
/// A named selection leaves the library's other declarations `NOT_SELECTED`,
/// which blocks the *run* — M8's rule that a subset is not a successful
/// security check, and not something these tests are trying to change. So the
/// question a passing obligation answers is whether the contract appears among
/// the blocking reasons, not whether the process would exit zero.
fn assert_no_blocking_reason_names(report: &CoverageReport, contract: &str) {
    let about: Vec<&String> = report
        .summary
        .blocking_reasons
        .iter()
        .filter(|reason| reason.contains(contract))
        .collect();
    assert!(
        about.is_empty(),
        "nothing about `{contract}` should block: {about:?}"
    );
}

fn contract_of(report: &CoverageReport) -> &trace_check::enforcement::ContractCoverage {
    report
        .contracts
        .iter()
        .find(|entry| entry.id == CONTRACT)
        .expect("the audit library declares the contract")
}

/// One invocation runs both backends, each obligation is discharged by its own
/// backend's evidence, and the two results describe two different executables.
#[test]
fn one_invocation_discharges_a_generated_and_a_symbolic_obligation() {
    if !analyzer_available() {
        return;
    }
    let report = unified(&both_required(), None);
    let contract = contract_of(&report);

    assert_eq!(
        contract.required,
        vec![Analysis::Generated, Analysis::Symbolic],
        "the policy's requirements must reach the report"
    );

    let generated = contract
        .evidence_for(Analysis::Generated)
        .expect("generated evidence");
    let symbolic = contract
        .evidence_for(Analysis::Symbolic)
        .expect("symbolic evidence");

    assert_eq!(generated.outcome, Outcome::NoLeakObserved);
    assert_eq!(symbolic.outcome, Outcome::VerifiedBounded);

    // The milestone's central rule, as a value: two backends, two artifacts.
    // One hash for both results would mean one of them is describing an
    // executable it did not analyze.
    assert_ne!(
        generated.artifact_sha256, symbolic.artifact_sha256,
        "the generated and symbolic analyses build different executables, and each result is a \
         claim about the one it analyzed"
    );
    assert!(!generated.artifact_sha256.is_empty());
    assert!(!symbolic.artifact_sha256.is_empty());

    assert!(
        contract.satisfied() && !contract.violated(),
        "both obligations are discharged: {:?}",
        contract.status
    );
    assert_no_blocking_reason_names(&report, CONTRACT);
}

/// Symbolic evidence keeps the conditions its result was established under:
/// the artifact, the symbol it was attributed to, the reachability evidence,
/// the input domain, the observation classes and the depth bound.
#[test]
fn symbolic_evidence_retains_the_conditions_of_its_result() {
    if !analyzer_available() {
        return;
    }
    let report = unified(&both_required(), None);
    let contract = contract_of(&report);
    let evidence = contract
        .evidence_for(Analysis::Symbolic)
        .expect("symbolic evidence");
    let symbolic = evidence
        .symbolic
        .as_ref()
        .expect("symbolic evidence carries its whole record, not just an outcome");

    assert_eq!(symbolic.contract, CONTRACT);
    assert_eq!(symbolic.symbol.contract, CONTRACT);
    assert!(
        symbolic.symbol.reached,
        "a result is attributed to a function only when the analyzer reached it"
    );
    assert_eq!(symbolic.artifact.sha256, evidence.artifact_sha256);
    assert_eq!(symbolic.analysis.artifact_sha256, evidence.artifact_sha256);

    // Both declared observation classes, and the report says so rather than
    // leaving it to be inferred from whichever checks the backend ran.
    assert_eq!(symbolic.analysis.checked_features.len(), 2, "{symbolic:?}");
    assert!(symbolic.analysis.exploration.is_complete());
    assert!(symbolic.max_depth > 0);
    assert!(symbolic.solver_timeout_secs > 0);
    assert_eq!(symbolic.inputs.len(), 2, "two secret operands");

    // The generated evidence keeps its own structure alongside it.
    let generated = contract
        .evidence_for(Analysis::Generated)
        .expect("generated evidence");
    assert!(
        generated.check.is_some(),
        "generated evidence keeps its case counts, controls and findings"
    );
    assert!(generated.symbolic.is_none());
}

/// A generated result cannot discharge a symbolic requirement: with the
/// analyzer unreachable the generated analysis still completes and reports, the
/// symbolic requirement is BACKEND_UNAVAILABLE, and strict CI fails.
#[test]
fn a_missing_analyzer_leaves_the_symbolic_requirement_unmet() {
    let report = unified(&both_required(), Some(UNREACHABLE_RUNTIME));
    let contract = contract_of(&report);

    let generated = contract
        .evidence_for(Analysis::Generated)
        .expect("the generated analysis runs regardless of the symbolic backend");
    assert_eq!(
        generated.outcome,
        Outcome::NoLeakObserved,
        "an unavailable backend must not discard evidence another backend produced"
    );

    assert_eq!(
        contract
            .status
            .get(&Analysis::Generated)
            .map(|s| s.as_str()),
        Some("CHECKED")
    );
    assert_eq!(
        contract.status.get(&Analysis::Symbolic).map(|s| s.as_str()),
        Some("BACKEND_UNAVAILABLE"),
        "a missing analyzer is a missing analyzer, not a satisfied requirement: {:?}",
        contract.status
    );
    assert!(contract.evidence_for(Analysis::Symbolic).is_none());

    assert!(!contract.satisfied(), "{:?}", contract.status);
    assert_eq!(
        report.exit_code(),
        2,
        "an unmet required analysis fails strict CI: {}",
        report.to_text()
    );
}

/// A symbolic requirement with no `[verify]` entry is a configuration gap, not
/// a pass, and the generated evidence it coexists with is preserved.
///
/// A bounded search needs a declared depth and observation model, which cannot
/// be inferred from a signature. The gap is reported before any container is
/// started, so this test needs no analyzer.
#[test]
fn a_symbolic_requirement_without_declared_bounds_is_incomplete() {
    // Written from scratch rather than appended to the audit configuration,
    // precisely so there is no `[verify]` table to find.
    let config = write_config(&format!(
        "schema_version = 1\n\n[check.\"{CONTRACT}\"]\ncases = 64\n\n\
         [policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{CONTRACT}\"]\nrequired = [\"generated\", \"symbolic\"]\n"
    ));
    let report = unified(&config, None);
    let contract = contract_of(&report);

    assert_eq!(
        contract
            .evidence_for(Analysis::Generated)
            .map(|e| e.outcome),
        Some(Outcome::NoLeakObserved),
        "the generated analysis still runs and still reports: {:?} / {:?}",
        contract.status,
        contract
            .evidence
            .iter()
            .map(|e| (e.analysis, e.outcome))
            .collect::<Vec<_>>()
    );
    let symbolic = contract
        .status
        .get(&Analysis::Symbolic)
        .expect("a required analysis always has a status");
    assert_eq!(symbolic.as_str(), "INCONCLUSIVE", "{symbolic:?}");
    assert!(
        symbolic.describe().contains("[verify."),
        "the diagnostic must name the missing configuration: {}",
        symbolic.describe()
    );
    assert!(!contract.satisfied());
    assert_eq!(report.exit_code(), 2, "{}", report.to_text());
}

/// A declared leak cannot satisfy a security contract's symbolic obligation.
///
/// `cbaudit::controls::pre_decode_first_byte` branches on `secret[0]`. Declared
/// a **security contract** — which is what dropping the audit configuration's
/// `expectation = "analyzer-regression"` does — the leak both backends find
/// must fail the run, and the `[verify]` entry's `expected_outcome` must not
/// turn it into a pass.
#[test]
fn an_expected_leak_cannot_make_a_security_contract_pass() {
    if !analyzer_available() {
        return;
    }
    const LEAKY: &str = "cbaudit::controls::pre_decode_first_byte";
    let config = write_config(&format!(
        "schema_version = 1\n\n[check.\"{LEAKY}\"]\ncases = 64\n\n\
         [verify.\"{LEAKY}\"]\nmax_depth = 20000\n\
         checks = [\"control-flow\", \"memory-access\"]\n\
         expected_outcome = \"LEAK_DETECTED\"\n\n\
         [policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{LEAKY}\"]\nrequired = [\"generated\", \"symbolic\"]\n"
    ));
    let workspace = Workspace::ephemeral().expect("a private workspace");
    let library =
        Library::resolve(&library_dir().join("Cargo.toml"), &[]).expect("the audit library");
    let report = trace_check::run_contract_coverage(
        &library,
        &config,
        &workspace,
        &trace_check::CheckOverrides::default(),
        &Selection::Named(vec![LEAKY.to_string()]),
        None,
        "2026-11-04",
        None,
    )
    .expect("the unified run reports rather than failing");

    let contract = report
        .contracts
        .iter()
        .find(|entry| entry.id == LEAKY)
        .expect("declared");
    assert!(
        contract.regression_expectation.is_none(),
        "without an explicit analyzer-regression expectation this is a security contract"
    );
    assert!(
        contract.violated(),
        "a detected leak fails a security contract whatever `expected_outcome` says: {:?}",
        contract.status
    );
    assert!(!contract.satisfied());
    assert_eq!(
        report.exit_code(),
        1,
        "a leak outranks every other condition: {}",
        report.to_text()
    );
}

/// A fixture that declares different outcomes for the two backends cannot be
/// enforced by a model holding one expectation per contract, and says so.
///
/// `cbaudit::hidden::magic_gate` hides a leak behind an exact public-input
/// equality. Generated testing never guesses the gate and declares
/// `NO_LEAK_OBSERVED`; symbolic execution solves for it and declares
/// `LEAK_DETECTED`. Both are correct, and `regression_expectation` is a single
/// value read from `[check]` -- so folding the symbolic result against it would
/// report a fixture that is behaving exactly as declared as misbehaving.
///
/// Until expectations are modelled per analysis (M10.1) the obligation is
/// settled as a gap: strict CI fails, the diagnostic names the conflict, and no
/// result is judged against the wrong expectation. Settled before any backend
/// runs, so this test needs no analyzer.
#[test]
fn a_backend_disagreement_fixture_is_not_judged_against_the_wrong_expectation() {
    const DISAGREES: &str = "cbaudit::hidden::magic_gate";
    let config = config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{DISAGREES}\"]\nrequired = [\"symbolic\"]\n"
    ));
    let workspace = Workspace::ephemeral().expect("a private workspace");
    let library =
        Library::resolve(&library_dir().join("Cargo.toml"), &[]).expect("the audit library");
    let report = trace_check::run_contract_coverage(
        &library,
        &config,
        &workspace,
        &trace_check::CheckOverrides::default(),
        // Selected, so the gap cannot be mistaken for NOT_SELECTED.
        &Selection::Named(vec![DISAGREES.to_string()]),
        None,
        "2026-11-04",
        Some(UNREACHABLE_RUNTIME),
    )
    .expect("the unified run reports rather than failing");

    let contract = report
        .contracts
        .iter()
        .find(|entry| entry.id == DISAGREES)
        .expect("declared");
    let status = contract
        .status
        .get(&Analysis::Symbolic)
        .expect("a required analysis always has a status");
    assert_eq!(status.as_str(), "INCONCLUSIVE", "{status:?}");
    let detail = status.describe();
    assert!(
        detail.contains("NO_LEAK_OBSERVED") && detail.contains("LEAK_DETECTED"),
        "the diagnostic must name both declared outcomes: {detail}"
    );
    assert!(
        detail.contains("verify --contract"),
        "the diagnostic must name the command that can still verify it: {detail}"
    );
    assert!(!contract.satisfied(), "{:?}", contract.status);
    assert!(
        contract.evidence_for(Analysis::Symbolic).is_none(),
        "nothing ran, so there is no symbolic evidence to mis-attribute"
    );
}
