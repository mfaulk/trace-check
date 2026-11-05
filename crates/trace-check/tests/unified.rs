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
        None,
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

/// Two tables declaring different purposes for one contract is refused when the
/// configuration loads, before any backend runs.
///
/// The dangerous direction is explicit: `[check]` saying `security-contract`
/// with `[verify]` saying `analyzer-regression` would make the contract a
/// fixture, so one section would override the other's stated security intent
/// and a declared leak would satisfy strict CI.
///
/// Distinct from the covered case of one table declaring a purpose while the
/// other is silent, which is a complete declaration and stays legal.
#[test]
fn contradictory_contract_purposes_are_refused_at_load() {
    const CONTESTED: &str = "crypto::operation";
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join(CONFIG_FILE);
    let write = |check_purpose: &str, verify_purpose: &str| {
        std::fs::write(
            &path,
            format!(
                "schema_version = 1\n\n[check.\"{CONTESTED}\"]\n{check_purpose}\n\n\
                 [verify.\"{CONTESTED}\"]\nmax_depth = 4000\n\
                 checks = [\"control-flow\", \"memory-access\"]\n\
                 expected_outcome = \"LEAK_DETECTED\"\n{verify_purpose}\n"
            ),
        )
        .expect("write the configuration");
    };

    // The contradiction.
    write(
        "expectation = \"security-contract\"",
        "expectation = \"analyzer-regression\"",
    );
    let error = VerifyConfig::load(&path).expect_err("a contradiction must be refused");
    let message = error.to_string();
    assert!(message.contains("security-contract"), "{message}");
    assert!(message.contains("analyzer-regression"), "{message}");
    assert!(
        message.contains("State the purpose once"),
        "the refusal must say what to do: {message}"
    );

    // The same contradiction the other way round.
    write(
        "expectation = \"analyzer-regression\"\nexpected_outcome = \"LEAK_DETECTED\"",
        "expectation = \"security-contract\"",
    );
    VerifyConfig::load(&path).expect_err("a contradiction must be refused either way round");

    // Agreement is fine.
    write(
        "expectation = \"analyzer-regression\"\nexpected_outcome = \"LEAK_DETECTED\"",
        "expectation = \"analyzer-regression\"",
    );
    let config = VerifyConfig::load(&path).expect("agreeing declarations are valid");
    assert_eq!(
        config.purpose(CONTESTED),
        trace_check::contract::Expectation::AnalyzerRegression
    );

    // And so is one table declaring it while the other stays silent, which is
    // the shape every fixture in this repository already uses.
    write(
        "expectation = \"analyzer-regression\"\nexpected_outcome = \"LEAK_DETECTED\"",
        "",
    );
    let config = VerifyConfig::load(&path).expect("a silent table does not contradict");
    assert_eq!(
        config.purpose(CONTESTED),
        trace_check::contract::Expectation::AnalyzerRegression
    );
}

/// Every result carries the identity of the executable it analyzed, and the two
/// identities for one contract differ in the inputs that explain why they are
/// two different executables.
///
/// A hash alone says two artifacts are different bytes. A developer looking at
/// a clean generated result beside a symbolic one needs to know *why* they are
/// different builds before deciding what either establishes.
#[test]
fn each_result_carries_the_identity_of_what_it_analyzed() {
    if !analyzer_available() {
        return;
    }
    let report = unified(&both_required(), None);
    let contract = contract_of(&report);
    let generated = contract
        .evidence_for(Analysis::Generated)
        .expect("generated evidence");
    let symbolic = contract
        .evidence_for(Analysis::Symbolic)
        .expect("symbolic evidence");

    // The convenience hash and the identity cannot disagree: both constructors
    // copy it out of the identity.
    for evidence in [generated, symbolic] {
        assert_eq!(evidence.artifact_sha256, evidence.artifact.artifact_sha256);
        assert_eq!(evidence.artifact.contract, CONTRACT);
        assert_eq!(evidence.artifact.library_package, "crypto-bigint-audit");
        assert_eq!(evidence.artifact.target, "x86_64-unknown-linux-gnu");
        assert_eq!(evidence.artifact.descriptor_sha256.len(), 64);
        assert_ne!(evidence.artifact.lockfile_sha256, "unavailable");
        assert!(!evidence.artifact.harness_sha256.is_empty());
        assert!(!evidence.artifact.backend_version.is_empty());
        // The compiler that actually built it, measured through the toolchain
        // the library's project pins.
        assert!(
            evidence
                .artifact
                .toolchain
                .rustc_version
                .starts_with("rustc "),
            "{:?}",
            evidence.artifact.toolchain
        );
    }

    // Only the symbolic result depends on an analyzer image, and it names it by
    // digest: the image is the analyzer and its solver.
    assert!(generated.artifact.analyzer_image.is_none());
    let image = symbolic
        .artifact
        .analyzer_image
        .as_deref()
        .expect("a symbolic result names its analyzer image");
    assert!(image.contains("@sha256:"), "{image}");

    // The two differ in named inputs, not only in the hash.
    let differences = generated.artifact.differences(&symbolic.artifact);
    let joined = differences.join("; ");
    for named in ["profile", "harness", "backend", "artifact"] {
        assert!(
            differences.iter().any(|line| line.starts_with(named)),
            "{named} must be named among the differences: {joined}"
        );
    }
    // And agree on everything that makes them comparable at all.
    for same in ["contract", "descriptor", "library", "compiler", "target"] {
        assert!(
            !differences.iter().any(|line| line.starts_with(same)),
            "{same} must not differ between two backends of one contract: {joined}"
        );
    }
}

/// No `DynamicRuns` to build a run from, for the cases that are about what the
/// enforcement model does with an absence.
fn no_dynamic_runs() -> trace_check::DynamicRuns {
    trace_check::DynamicRuns {
        runs: Vec::new(),
        profile: "release+debug".to_string(),
        lockfile_sha256: "lock".to_string(),
        valgrind_version: "valgrind 3.28.0".to_string(),
    }
}

/// Runs the unified checker over one contract with a dynamic contribution.
fn unified_with_dynamic(
    config: &VerifyConfig,
    contract: &str,
    runs: &trace_check::DynamicRuns,
) -> CoverageReport {
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
        None,
        Some(runs),
    )
    .expect("the unified run reports rather than failing")
}

/// A contract annotated `dynamic = false` has no test adapter, so an M3
/// dynamic requirement is unsupported rather than merely unmet.
///
/// Unsupported is the honest status: no amount of running tests will produce
/// adapter-backed evidence for a contract the macro emitted no adapter for.
/// Needs no backend at all -- it is settled before anything runs.
#[test]
fn a_dynamic_disabled_contract_cannot_satisfy_a_dynamic_requirement() {
    // `cbaudit::select::ct_select` is annotated `dynamic = false`.
    const DISABLED: &str = "cbaudit::select::ct_select";
    let config = config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{DISABLED}\"]\nrequired = [\"dynamic\"]\n"
    ));
    let report = unified_with_dynamic(&config, DISABLED, &no_dynamic_runs());
    let contract = named(&report, DISABLED);
    let status = contract
        .status
        .get(&Analysis::Dynamic)
        .expect("a required analysis always has a status");
    assert_eq!(status.as_str(), "UNSUPPORTED", "{status:?}");
    assert!(
        status.describe().contains("dynamic = false"),
        "the diagnostic must name the annotation: {}",
        status.describe()
    );
    assert!(!contract.satisfied());
    assert!(contract.evidence_for(Analysis::Dynamic).is_none());
}

/// A contract with a test adapter and no bound `#[ct_test]` run stays
/// NOT_ANALYZED.
///
/// The absence of evidence, which is the one thing a unified run must never
/// render as a clean result. `crypto::tag::verify_tag` has an adapter — it is
/// the acceptance subject precisely because it does — and this run supplies no
/// test results for it.
#[test]
fn a_contract_with_no_bound_test_is_not_analyzed() {
    const ADAPTED: &str = "crypto::tag::verify_tag";
    let base = std::fs::read_to_string(
        workspace_root()
            .join("examples/crypto-library")
            .join(CONFIG_FILE),
    )
    .expect("the bundled configuration is committed");
    let config = write_config(&format!(
        "{base}\n[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{ADAPTED}\"]\nrequired = [\"dynamic\"]\n"
    ));
    let workspace = Workspace::ephemeral().expect("a private workspace");
    let library = Library::resolve(
        &workspace_root().join("examples/crypto-library/Cargo.toml"),
        &[],
    )
    .expect("the bundled library");
    let runs = no_dynamic_runs();
    let report = trace_check::run_contract_coverage(
        &library,
        &config,
        &workspace,
        &trace_check::CheckOverrides::default(),
        &Selection::Named(vec![ADAPTED.to_string()]),
        None,
        "2026-11-04",
        None,
        Some(&runs),
    )
    .expect("the unified run reports rather than failing");
    let contract = named(&report, ADAPTED);
    let status = contract
        .status
        .get(&Analysis::Dynamic)
        .expect("a required analysis always has a status");
    assert_eq!(status.as_str(), "NOT_ANALYZED", "{status:?}");
    assert!(
        contract.evidence_for(Analysis::Dynamic).is_none(),
        "no bound test is no evidence, not clean evidence"
    );
    assert!(!contract.satisfied());
}

/// A `#[ct_test]` whose target names no contract in this build is reported,
/// not silently dropped.
///
/// Binding to nothing is already fail-closed: the obligation stays un-analyzed
/// and strict CI fails. But a run that fails without saying why is the shape of
/// problem this milestone exists to remove, so the unresolved target appears in
/// the report alongside configuration that matches no declaration.
#[test]
fn a_test_targeting_no_contract_is_reported() {
    let config = config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{CONTRACT}\"]\nrequired = [\"dynamic\"]\n"
    ));
    let mut runs = no_dynamic_runs();
    runs.runs.push(trace_check::dynamic::DynamicTestRun {
        test: "tests::covers_something_renamed".to_string(),
        declared_target: Some("monty::mul_renamed".to_string()),
        executable: "/t/tests-abc".to_string(),
        executable_sha256: "exec0".to_string(),
        outcome: Outcome::NoLeakObserved,
        calibrated: true,
        invoked_target: true,
        completed: true,
        message: "clean".to_string(),
        findings: Vec::new(),
    });
    let report = unified_with_dynamic(&config, CONTRACT, &runs);

    let reported: Vec<&trace_check::enforcement::StaleEntry> = report
        .stale
        .iter()
        .filter(|entry| entry.source == "ct_test")
        .collect();
    assert_eq!(reported.len(), 1, "{:?}", report.stale);
    assert!(
        reported[0].detail.contains("monty::mul_renamed"),
        "the diagnostic must name the target: {}",
        reported[0].detail
    );
    assert!(
        reported[0].detail.contains("declares no contract"),
        "{}",
        reported[0].detail
    );

    // And it discharged nothing: an unbound test is not evidence.
    let contract = contract_of(&report);
    assert_eq!(
        contract.status.get(&Analysis::Dynamic).map(|s| s.as_str()),
        Some("UNSUPPORTED"),
        "{:?}",
        contract.status
    );
    assert!(!contract.satisfied());
    assert!(
        report
            .summary
            .blocking_reasons
            .iter()
            .any(|reason| reason.contains("monty::mul_renamed")),
        "the unresolved target must block: {:?}",
        report.summary.blocking_reasons
    );
}

/// A leak found by a test that ran is never discarded, even when its contract
/// required nothing dynamic.
///
/// `dynamic` is a whole test suite rather than a per-contract job: a policy
/// requiring it of contract B makes the run execute every targeted
/// `#[ct_test]`, including one bound to contract A. If A's test finds a
/// secret-dependent branch, dropping it because A required only `generated`
/// would erase positive leakage evidence — which no arrangement of obligations
/// may do.
///
/// Needs no backend: the test results are supplied, and what is under test is
/// what enforcement does with them.
#[test]
fn a_leak_from_an_unrequired_test_still_fails_the_contract() {
    // A requires only `generated`; B requires `dynamic`. Running B's
    // requirement is what causes A's test to be executed at all.
    const A: &str = "cbaudit::monty::mul_both_secret";
    const B: &str = "cbaudit::monty::mul_secret_left";
    let config = config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{A}\"]\nrequired = [\"generated\"]\n\n\
         [policy.contracts.\"{B}\"]\nrequired = [\"dynamic\"]\n"
    ));
    let mut runs = no_dynamic_runs();
    // A's hand-written test reached a secret-dependent branch.
    runs.runs.push(trace_check::dynamic::DynamicTestRun {
        test: "tests::a_leaks".to_string(),
        declared_target: Some("monty::mul_both_secret".to_string()),
        executable: "/t/tests-abc".to_string(),
        executable_sha256: "exec0".to_string(),
        outcome: Outcome::LeakDetected,
        calibrated: true,
        invoked_target: true,
        completed: true,
        message: "secret-dependent branch at monty.rs:41".to_string(),
        findings: vec!["Secret-dependent branch: mul_both_secret at monty.rs:41".to_string()],
    });

    let workspace = Workspace::ephemeral().expect("a private workspace");
    let library =
        Library::resolve(&library_dir().join("Cargo.toml"), &[]).expect("the audit library");
    let report = trace_check::run_contract_coverage(
        &library,
        &config,
        &workspace,
        &trace_check::CheckOverrides::default(),
        // Only A is selected for analysis, so no backend runs for B.
        &Selection::Named(vec![A.to_string()]),
        None,
        "2026-11-04",
        Some(UNREACHABLE_RUNTIME),
        Some(&runs),
    )
    .expect("the unified run reports rather than failing");

    let contract = named(&report, A);
    let dynamic = contract
        .evidence_for(Analysis::Dynamic)
        .expect("the executed test's result must be retained");
    assert_eq!(dynamic.outcome, Outcome::LeakDetected);
    assert!(
        dynamic.detail.contains("monty.rs:41"),
        "the finding must survive: {}",
        dynamic.detail
    );

    // No `dynamic` *status*, because A never owed one -- recording CHECKED
    // would claim it was held to something it was not.
    assert!(
        !contract.status.contains_key(&Analysis::Dynamic),
        "an unrequired analysis must not acquire a status: {:?}",
        contract.status
    );
    assert_eq!(contract.required, vec![Analysis::Generated]);

    // But the leak fails the contract and the run.
    assert!(
        contract.violated(),
        "a leak observed by a test that ran must fail the contract: {:?}",
        contract.status
    );
    assert!(!contract.satisfied());
    assert!(
        report
            .summary
            .blocking_reasons
            .iter()
            .any(|reason| reason.contains(A)),
        "{:?}",
        report.summary.blocking_reasons
    );
    assert_eq!(
        report.exit_code(),
        1,
        "a leak outranks every other condition: {}",
        report.to_text()
    );
}

/// Requiring `generated` and `explore` runs **one** Memcheck workflow, and the
/// report says the two requirements shared it.
///
/// `explore` is not a separate proof level. Coverage feedback chooses which
/// inputs to analyze; every security conclusion still comes from the same
/// uninstrumented artifact, and an explored run already contains the boundary
/// cases a baseline run would have used. Two executions would double the most
/// expensive backend in the tool for no additional evidence.
///
/// Needs Valgrind and the LLVM tools, not the analyzer.
#[test]
fn generated_and_explore_share_one_memcheck_workflow() {
    let config = config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{CONTRACT}\"]\nrequired = [\"generated\", \"explore\"]\n"
    ));
    let report = unified(&config, None);

    // The plan committed to one workflow before anything was built.
    let execution = report
        .execution
        .as_ref()
        .expect("an executing run reports what it executed");
    assert_eq!(
        execution.memcheck_jobs(),
        1,
        "requiring both must plan one Memcheck workflow, not two:\n{}",
        execution.to_text()
    );
    let jobs = execution.jobs_for(CONTRACT);
    assert_eq!(jobs.len(), 1, "{}", execution.to_text());
    assert_eq!(
        jobs[0].work,
        trace_check::orchestration::Work::Generated { explore: true }
    );
    assert_eq!(
        jobs[0].discharges,
        vec![Analysis::Generated, Analysis::Explore],
        "the one execution answers both obligations"
    );

    // And the run bears that out: two requirements, two records, one
    // observation.
    let contract = contract_of(&report);
    let generated = contract
        .evidence_for(Analysis::Generated)
        .expect("generated evidence");
    let explore = contract
        .evidence_for(Analysis::Explore)
        .expect("explore evidence");
    for analysis in [Analysis::Generated, Analysis::Explore] {
        assert_eq!(
            contract.status.get(&analysis).map(|s| s.as_str()),
            Some("CHECKED"),
            "{analysis}: {:?}",
            contract.status
        );
    }
    assert_eq!(
        generated.artifact_sha256, explore.artifact_sha256,
        "one execution means one analyzed executable"
    );
    assert_eq!(
        generated.shared_with,
        vec![Analysis::Explore],
        "the generated record must say the explore requirement shared its execution"
    );
    assert_eq!(explore.shared_with, vec![Analysis::Generated]);

    // The case counts are the same object's, not two runs' -- so a reader
    // cannot add them up into twice the coverage.
    let left = generated.check.as_ref().expect("a check record");
    let right = explore.check.as_ref().expect("a check record");
    assert_eq!(left.cases_completed, right.cases_completed);
    assert_eq!(
        left.analyzer_runs, right.analyzer_runs,
        "two independent Memcheck workflows would not report identical process counts"
    );
    assert!(
        generated.discovery.is_some(),
        "the explored corpus's provenance must be retained"
    );
}

/// Requiring only `generated` plans no discovery, so the deduplication test
/// above is not passing because exploration is always on.
#[test]
fn requiring_only_generated_plans_no_discovery() {
    let config = config_with_policy(&format!(
        "[policy]\nmode = \"strict\"\ndefault_required = [\"generated\"]\n\n\
         [policy.contracts.\"{CONTRACT}\"]\nrequired = [\"generated\"]\n"
    ));
    let report = unified(&config, None);
    let execution = report.execution.as_ref().expect("an execution plan");
    let jobs = execution.jobs_for(CONTRACT);
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].work,
        trace_check::orchestration::Work::Generated { explore: false },
        "{}",
        execution.to_text()
    );
    assert_eq!(jobs[0].discharges, vec![Analysis::Generated]);
    let contract = contract_of(&report);
    assert!(
        contract
            .evidence_for(Analysis::Generated)
            .expect("generated evidence")
            .shared_with
            .is_empty(),
        "a lone requirement shares its execution with nothing"
    );
}
