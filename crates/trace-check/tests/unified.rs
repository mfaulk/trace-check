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
    unified_for(config, CONTRACT, runtime)
}

/// The unified checker over one named contract of the audit library.
fn unified_for(config: &VerifyConfig, contract: &str, runtime: Option<&str>) -> CoverageReport {
    let workspace = Workspace::ephemeral().expect("a private workspace");
    let library =
        Library::resolve(&library_dir().join("Cargo.toml"), &[]).expect("the audit library");
    trace_check::run_contract_coverage(
        &library,
        config,
        &workspace,
        &trace_check::CheckOverrides::default(),
        &Selection::Named(vec![contract.to_string()]),
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
    named(report, CONTRACT)
}

fn named<'a>(
    report: &'a CoverageReport,
    contract: &str,
) -> &'a trace_check::enforcement::ContractCoverage {
    report
        .contracts
        .iter()
        .find(|entry| entry.id == contract)
        .unwrap_or_else(|| panic!("`{contract}` is not declared in this build"))
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

/// A security contract cannot declare that it leaks. The contradiction is
/// refused when the configuration loads, not resolved when a result arrives.
///
/// `[check]` has refused `expected_outcome` on a security contract since M6.
/// `[verify]` could still say `LEAK_DETECTED`, because M4 and M5 predate the
/// split and had no purpose to check it against — so the only thing standing
/// between a stray declaration and an excused leak was enforcement getting it
/// right every time.
#[test]
fn a_security_contract_declaring_a_leak_is_refused_at_load() {
    const LEAKY: &str = "cbaudit::controls::pre_decode_first_byte";
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join(CONFIG_FILE);
    std::fs::write(
        &path,
        format!(
            "schema_version = 1\n\n[verify.\"{LEAKY}\"]\nmax_depth = 20000\n\
             checks = [\"control-flow\", \"memory-access\"]\n\
             expected_outcome = \"LEAK_DETECTED\"\n"
        ),
    )
    .expect("write the configuration");
    let error = VerifyConfig::load(&path).expect_err("the contradiction must be refused");
    let message = error.to_string();
    assert!(message.contains("security contract"), "{message}");
    assert!(
        message.contains("analyzer-regression"),
        "the refusal must name the way to declare a deliberate fixture: {message}"
    );

    // The same entry is fine once it says what it is.
    std::fs::write(
        &path,
        format!(
            "schema_version = 1\n\n[verify.\"{LEAKY}\"]\nmax_depth = 20000\n\
             checks = [\"control-flow\", \"memory-access\"]\n\
             expectation = \"analyzer-regression\"\n\
             expected_outcome = \"LEAK_DETECTED\"\n"
        ),
    )
    .expect("write the configuration");
    VerifyConfig::load(&path).expect("a declared fixture is valid");
}

/// A leak fails a security contract that declared it would verify bounded.
///
/// The realistic shape of the rule the load-time check cannot cover: the
/// configuration asserts `VERIFIED_BOUNDED`, which is a legitimate tripwire on
/// the analyzer and the toolchain, and the function leaks anyway. The
/// declaration is not consulted — a security contract's obligation is
/// discharged by what the analysis established, and a leak is a violation.
#[test]
fn a_leak_fails_a_security_contract_that_declared_it_clean() {
    if !analyzer_available() {
        return;
    }
    const LEAKY: &str = "cbaudit::controls::pre_decode_first_byte";
    let config = write_config(&format!(
        "schema_version = 1\n\n[check.\"{LEAKY}\"]\ncases = 64\n\n\
         [verify.\"{LEAKY}\"]\nmax_depth = 20000\n\
         checks = [\"control-flow\", \"memory-access\"]\n\
         expected_outcome = \"VERIFIED_BOUNDED\"\n\n\
         [policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{LEAKY}\"]\nrequired = [\"generated\", \"symbolic\"]\n"
    ));
    let report = unified_for(&config, LEAKY, None);
    let contract = named(&report, LEAKY);

    assert!(
        contract.regression_expectations.is_empty(),
        "without an explicit analyzer-regression declaration this is a security contract"
    );
    assert!(
        contract.violated(),
        "a detected leak fails a security contract whatever it declared: {:?}",
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

/// A fixture may declare that generated inputs will not reach its gate while a
/// solver will, and both declarations are enforced independently.
///
/// `cbaudit::hidden::magic_gate` hides a leak behind an exact public-input
/// equality. `[check]` declares `NO_LEAK_OBSERVED` -- generated inputs never
/// guess the magic value -- and `[verify]` declares `LEAK_DETECTED`, because a
/// solver does. Both are correct, and this is the disagreement M10.0 could only
/// report as a gap: one expected outcome per contract had to judge the symbolic
/// result against the generated declaration.
#[test]
fn a_fixture_may_declare_a_different_outcome_per_backend() {
    if !analyzer_available() {
        return;
    }
    const DISAGREES: &str = "cbaudit::hidden::magic_gate";
    let config = config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{DISAGREES}\"]\nrequired = [\"generated\", \"symbolic\"]\n"
    ));
    let report = unified_for(&config, DISAGREES, None);
    let contract = named(&report, DISAGREES);

    assert_eq!(
        contract.regression_expectations.get(&Analysis::Generated),
        Some(&Outcome::NoLeakObserved)
    );
    assert_eq!(
        contract.regression_expectations.get(&Analysis::Symbolic),
        Some(&Outcome::LeakDetected)
    );

    // Each backend reproduced its own declaration.
    assert_eq!(
        contract
            .evidence_for(Analysis::Generated)
            .map(|e| e.outcome),
        Some(Outcome::NoLeakObserved)
    );
    assert_eq!(
        contract.evidence_for(Analysis::Symbolic).map(|e| e.outcome),
        Some(Outcome::LeakDetected)
    );
    for analysis in [Analysis::Generated, Analysis::Symbolic] {
        assert_eq!(
            contract.status.get(&analysis).map(|s| s.as_str()),
            Some("CHECKED"),
            "{analysis} must be judged against its own declaration: {:?}",
            contract.status
        );
    }

    // The declared leak is the fixture passing, not a violation -- and the
    // declaration excuses only the backend that predicted it.
    assert!(!contract.violated(), "{:?}", contract.status);
    assert!(contract.satisfied(), "{:?}", contract.status);
    assert_no_blocking_reason_names(&report, DISAGREES);
}

/// The same disagreement inverted: generated testing finds the leak and
/// symbolic verification does not.
///
/// `crypto::tag::verify_tag_early_exit` is written with a per-byte branch. The
/// symbolic backend's freestanding artifact vectorizes it away and verifies
/// bounded; the dynamic backend's artifact keeps the branch and finds it. Two
/// honest answers about two compilations, which is why the artifact hashes are
/// part of the evidence. A model that took the generated declaration as the
/// contract's would have failed the symbolic result here.
#[test]
fn the_inverse_disagreement_is_enforced_too() {
    if !analyzer_available() {
        return;
    }
    const INVERTED: &str = "crypto::tag::verify_tag_early_exit";
    let base = std::fs::read_to_string(
        workspace_root()
            .join("examples/crypto-library")
            .join(CONFIG_FILE),
    )
    .expect("the bundled configuration is committed");
    let config = write_config(&format!(
        "{base}\n[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{INVERTED}\"]\nrequired = [\"generated\", \"symbolic\"]\n"
    ));
    let workspace = Workspace::ephemeral().expect("a private workspace");
    let library = Library::resolve(
        &workspace_root().join("examples/crypto-library/Cargo.toml"),
        &[],
    )
    .expect("the bundled library");
    let report = trace_check::run_contract_coverage(
        &library,
        &config,
        &workspace,
        &trace_check::CheckOverrides::default(),
        &Selection::Named(vec![INVERTED.to_string()]),
        None,
        "2026-11-04",
        None,
    )
    .expect("the unified run reports rather than failing");
    let contract = named(&report, INVERTED);

    assert_eq!(
        contract
            .evidence_for(Analysis::Generated)
            .map(|e| e.outcome),
        Some(Outcome::LeakDetected),
        "the dynamic artifact keeps the per-byte branch"
    );
    assert_eq!(
        contract.evidence_for(Analysis::Symbolic).map(|e| e.outcome),
        Some(Outcome::VerifiedBounded),
        "the symbolic artifact vectorizes it away"
    );
    for analysis in [Analysis::Generated, Analysis::Symbolic] {
        assert_eq!(
            contract.status.get(&analysis).map(|s| s.as_str()),
            Some("CHECKED"),
            "{analysis}: {:?}",
            contract.status
        );
    }
    assert!(!contract.violated(), "{:?}", contract.status);
    assert!(contract.satisfied(), "{:?}", contract.status);

    // The two results describe two different executables, which is the whole
    // reason they are allowed to disagree.
    let generated = contract.evidence_for(Analysis::Generated).expect("present");
    let symbolic = contract.evidence_for(Analysis::Symbolic).expect("present");
    assert_ne!(generated.artifact_sha256, symbolic.artifact_sha256);
}
