//! The report `cargo trace-check check` produces, and the CI policy it applies.
//!
//! # Three kinds of coverage, never conflated
//!
//! *Contract coverage* is which required contracts received a completed check.
//! *Input-strategy coverage* is which planned input categories were actually
//! generated. *Execution coverage* — which code paths ran — is **not** measured
//! here, and is named as absent rather than left to be assumed.
//!
//! The one sentence this module exists to avoid printing: the fraction of
//! generated inputs executed is not a fraction of secret values proven safe.
//! `NO_LEAK_OBSERVED` keeps its name for that reason.
//!
//! # The policy split
//!
//! A `security-contract` entry fails on a detected leak. An
//! `analyzer-regression` entry asserts that *trace-check* produces a stated
//! result on a deliberately vulnerable example, so detecting the planted leak is
//! that entry passing. The two are separated in the configuration
//! ([`crate::contract::Expectation`]) so a stray expectation can never turn a
//! real leak into a green build.

use serde::Serialize;

use crate::check::{ContractCheck, Control};
use crate::contract::Expectation;
use crate::generate::{Corpus, StrategyCoverage};
use crate::security::Outcome;

/// Report schema this build emits.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Backend identity recorded with every result.
pub const BACKEND: &str = "generated-memcheck";

pub const EXIT_OK: u8 = 0;
pub const EXIT_LEAK: u8 = 1;
pub const EXIT_INCOMPLETE: u8 = 2;

/// Limits restated in every report, because a stored result outlives the
/// conversation that produced it.
pub const LIMITATIONS: [&str; 6] = [
    "A clean result is NO_LEAK_OBSERVED over the inputs that were generated and the paths they took. It is not a proof, and it says nothing about inputs that were not generated.",
    "The analyzed artifact is not the production binary. Its profile, dependency versions and hash are recorded because the result describes that build.",
    "Memcheck models secret-dependent branches and secret-dependent addresses. It does not model caches, execution ports, speculation, or data-dependent instruction timing.",
    "A batched run cannot attribute a finding to a case without re-running it, and a sequence-dependent finding may not reduce to a single case at all.",
    "Execution coverage -- which branches or regions the generated inputs reached -- is not measured. Input-strategy coverage is not a substitute for it.",
    "The contract inventory is what the configuration names, not every #[constant_time] annotation in the source tree.",
];

/// Toolchain and library provenance for a whole run.
#[derive(Debug, Clone, Serialize)]
pub struct CheckProvenance {
    pub rustc_version: String,
    pub cargo_version: String,
    /// The analyzer, e.g. `valgrind 3.28.0`.
    pub analyzer: String,
    pub target: String,
    /// Compilation settings of the generated harness.
    pub profile: String,
    pub library_package: String,
    pub library_version: String,
    pub library_manifest: String,
}

/// One declared secret, and how many bytes were marked for it.
#[derive(Debug, Clone, Serialize)]
pub struct SecretSummary {
    pub parameter: String,
    pub rust_type: String,
    pub bytes: u64,
}

/// The corpus a contract was checked with.
#[derive(Debug, Clone, Serialize)]
pub struct CorpusSummary {
    pub seed: u64,
    pub budget: usize,
    pub cases: usize,
    pub sha256: String,
    /// Input-strategy coverage: what each strategy planned and contributed.
    pub strategy_coverage: Vec<StrategyCoverage>,
    /// Strategies that could not be completed within the budget, named rather
    /// than implied by a case total.
    pub truncated: Vec<String>,
}

impl CorpusSummary {
    pub fn of(corpus: &Corpus) -> CorpusSummary {
        CorpusSummary {
            seed: corpus.seed,
            budget: corpus.budget,
            cases: corpus.cases.len(),
            sha256: corpus.sha256(),
            strategy_coverage: corpus.coverage.clone(),
            truncated: corpus
                .truncated()
                .into_iter()
                .map(|entry| {
                    format!(
                        "{}: {} of {} planned case(s) dropped for budget ({} emitted, {} \
                         already covered by another strategy)",
                        entry.strategy,
                        entry.dropped_for_budget(),
                        entry.planned,
                        entry.emitted,
                        entry.duplicates
                    )
                })
                .collect(),
        }
    }
}

/// Whether this entry satisfied what it was asserting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// The requirement was met.
    Satisfied,
    /// A leak was detected against a security contract.
    LeakDetected,
    /// The analysis did not complete well enough to conclude anything.
    Incomplete,
    /// An analyzer-regression fixture produced a different outcome than
    /// declared.
    ExpectationUnmet,
}

impl Policy {
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Satisfied => "satisfied",
            Policy::LeakDetected => "leak-detected",
            Policy::Incomplete => "incomplete",
            Policy::ExpectationUnmet => "expectation-unmet",
        }
    }

    pub fn satisfied(self) -> bool {
        self == Policy::Satisfied
    }
}

/// One contract's whole result.
#[derive(Debug, Clone, Serialize)]
pub struct ContractEntry {
    pub contract: String,
    pub function: String,
    /// `file:line` of the annotation, from the developer's own source.
    pub site: String,
    pub secrets: Vec<SecretSummary>,
    pub corpus: CorpusSummary,
    pub harness_sha256: String,
    pub artifact_sha256: String,
    pub lockfile_sha256: String,
    /// What this entry asserts.
    pub expectation: Expectation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_outcome: Option<String>,
    pub policy: Policy,
    /// Why the policy came out as it did, in one sentence.
    pub policy_detail: String,
    pub check: ContractCheck,
    /// Paths of reproducers written for this contract's findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reproducers: Vec<String>,
}

impl ContractEntry {
    /// Applies the CI policy to a completed check.
    ///
    /// An `analyzer-regression` entry is held to its declared outcome; a
    /// `security-contract` entry is held to the property. A leak against a
    /// security contract is never anything but a failure, whatever the
    /// configuration says, because a security contract cannot declare an
    /// expected outcome in the first place.
    pub fn evaluate(
        expectation: Expectation,
        expected_outcome: Option<&str>,
        check: &ContractCheck,
    ) -> (Policy, String) {
        match expectation {
            Expectation::AnalyzerRegression => {
                let declared = expected_outcome.unwrap_or("(none)");
                if check.outcome.as_str() == declared {
                    (
                        Policy::Satisfied,
                        format!(
                            "analyzer regression: produced {declared} as declared. This is a \
                             statement about trace-check on a fixture, not about the function \
                             being secure"
                        ),
                    )
                } else {
                    (
                        Policy::ExpectationUnmet,
                        format!(
                            "analyzer regression: declared {declared} but produced {}",
                            check.outcome.as_str()
                        ),
                    )
                }
            }
            Expectation::SecurityContract => match check.outcome {
                Outcome::LeakDetected => (
                    Policy::LeakDetected,
                    "a secret-dependent branch or address was found in a function declared \
                     constant-time"
                        .to_string(),
                ),
                Outcome::NoLeakObserved => {
                    if check.cases_completed == 0 {
                        (
                            Policy::Incomplete,
                            "no generated case completed, so nothing was checked".to_string(),
                        )
                    } else if check.cases_completed < check.cases_planned {
                        (
                            Policy::Incomplete,
                            format!(
                                "{} of {} planned case(s) completed",
                                check.cases_completed, check.cases_planned
                            ),
                        )
                    } else if check.calibration != Control::Confirmed
                        || check.binding != Control::Confirmed
                    {
                        (
                            Policy::Incomplete,
                            "a positive control did not confirm, so a clean result proves \
                             nothing"
                                .to_string(),
                        )
                    } else {
                        (
                            Policy::Satisfied,
                            "the dynamic gate passed: no leak observed over the generated \
                             inputs. This is not a proof of constant-time behavior"
                                .to_string(),
                        )
                    }
                }
                // The symbolic backend's vocabulary never reaches here, but an
                // explicit arm beats a catch-all that could silently pass it.
                Outcome::VerifiedBounded => (
                    Policy::Incomplete,
                    "the generated backend cannot produce VERIFIED_BOUNDED; this result is \
                     malformed"
                        .to_string(),
                ),
                Outcome::Inconclusive => (Policy::Incomplete, check.message.clone()),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Contracts that received a completed check.
    pub contracts_checked: usize,
    pub leaks_detected: usize,
    pub incomplete: usize,
    pub expectations_unmet: usize,
    /// Reasons this run must not be reported as a success.
    pub blocking_reasons: Vec<String>,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub schema_version: u32,
    pub backend: &'static str,
    pub provenance: CheckProvenance,
    /// Contracts selected for this run, named so a reader never has to infer
    /// what was covered.
    pub selected: Vec<String>,
    /// Configured contracts that were **not** selected, for the same reason.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_selected: Vec<String>,
    pub contracts: Vec<ContractEntry>,
    pub summary: Summary,
    pub limitations: Vec<String>,
}

/// Assembles the report and decides whether the run may be called a success.
///
/// `require_all_configured` is what `--ci` sets: a CI run that silently checked
/// a subset of the configured contracts would report success for coverage it
/// never had.
pub fn build(
    provenance: CheckProvenance,
    selected: Vec<String>,
    not_selected: Vec<String>,
    contracts: Vec<ContractEntry>,
    require_all_configured: bool,
) -> CheckReport {
    let leaks = contracts
        .iter()
        .filter(|entry| entry.policy == Policy::LeakDetected)
        .count();
    let incomplete = contracts
        .iter()
        .filter(|entry| entry.policy == Policy::Incomplete)
        .count();
    let unmet = contracts
        .iter()
        .filter(|entry| entry.policy == Policy::ExpectationUnmet)
        .count();
    let checked = contracts
        .iter()
        .filter(|entry| entry.check.cases_completed > 0)
        .count();

    let mut blocking = Vec::new();
    if selected.is_empty() {
        blocking.push(
            "no contracts were selected, and a run that checks nothing is not a pass".to_string(),
        );
    }
    if contracts.is_empty() && !selected.is_empty() {
        blocking.push("no selected contract produced a result".to_string());
    }
    for entry in &contracts {
        if !entry.policy.satisfied() {
            blocking.push(format!(
                "`{}` is {}: {}",
                entry.contract,
                entry.policy.as_str(),
                entry.policy_detail
            ));
        }
    }
    if require_all_configured && !not_selected.is_empty() {
        blocking.push(format!(
            "{} configured contract(s) were not checked, so this run does not cover the \
             configuration: {}",
            not_selected.len(),
            not_selected.join(", ")
        ));
    }

    let ok = blocking.is_empty();
    CheckReport {
        schema_version: REPORT_SCHEMA_VERSION,
        backend: BACKEND,
        provenance,
        selected,
        not_selected,
        contracts,
        summary: Summary {
            contracts_checked: checked,
            leaks_detected: leaks,
            incomplete,
            expectations_unmet: unmet,
            blocking_reasons: blocking,
            ok,
        },
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    }
}

impl CheckReport {
    /// A detected leak outranks an incomplete analysis, so the code names the
    /// most serious outcome while the report keeps everything.
    pub fn exit_code(&self) -> u8 {
        if self.summary.leaks_detected > 0 {
            EXIT_LEAK
        } else if !self.summary.ok {
            EXIT_INCOMPLETE
        } else {
            EXIT_OK
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("the report is serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        macro_rules! line {
            ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
        }

        line!("Generated constant-time checks");
        line!("");
        line!("Backend:  {} / {}", self.backend, self.provenance.analyzer);
        line!(
            "Library:  {} {} ({})",
            self.provenance.library_package,
            self.provenance.library_version,
            self.provenance.library_manifest
        );
        line!("Build:    {}", self.provenance.profile);
        line!("");

        for entry in &self.contracts {
            line!("{}", entry.contract);
            line!("  declared at {}", entry.site);
            let secrets: Vec<String> = entry
                .secrets
                .iter()
                .map(|secret| {
                    format!(
                        "{}: {} ({} byte(s) marked)",
                        secret.parameter, secret.rust_type, secret.bytes
                    )
                })
                .collect();
            line!("  secret:   {}", secrets.join(", "));
            line!(
                "  corpus:   {} case(s), seed {}, strategies {}",
                entry.corpus.cases,
                entry.corpus.seed,
                entry
                    .corpus
                    .strategy_coverage
                    .iter()
                    .map(|coverage| format!(
                        "{} {}/{}",
                        coverage.strategy, coverage.emitted, coverage.planned
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            for dropped in &entry.corpus.truncated {
                line!("  TRUNCATED: {dropped}");
            }
            line!(
                "  executed: {}/{} case(s) completed in {} analyzer run(s)",
                entry.check.cases_completed,
                entry.check.cases_planned,
                entry.check.analyzer_runs
            );
            line!(
                "  controls: calibration {}, secret binding {}",
                entry.check.calibration.as_str(),
                entry.check.binding.as_str()
            );
            line!("  {}", entry.check.outcome);
            line!("  {}", entry.check.message);

            for finding in &entry.check.findings {
                line!("");
                line!("  {}", finding.description);
                if let Some(site) = &finding.site {
                    line!("    in {} at {site}", entry.function);
                }
                for frame in finding.stack.iter().take(3) {
                    line!("    at {frame}");
                }
                line!("    origin: {}", finding.origin);
                match &finding.isolation {
                    crate::check::Isolation::Case { id, inputs, runs } => {
                        line!(
                            "    isolated to case {id} in {runs} re-run(s): {}",
                            render_inputs(inputs)
                        );
                    }
                    crate::check::Isolation::Single { id } => {
                        line!("    case {id} was the whole batch, so no narrowing was needed");
                    }
                    crate::check::Isolation::Sequence { ids, detail, .. } => {
                        line!("    SEQUENCE-DEPENDENT over case(s) {ids:?}: {detail}");
                    }
                }
                if let Some(shrunk) = &finding.shrunk {
                    line!(
                        "    shrunk in {} step(s) of {} attempt(s): {}",
                        shrunk.steps,
                        shrunk.attempts,
                        render_inputs(&shrunk.inputs)
                    );
                }
            }
            for finding in &entry.check.unattributed {
                line!("");
                line!("  UNATTRIBUTED: {}", finding.description);
                for frame in finding.stack.iter().take(3) {
                    line!("    at {frame}");
                }
            }
            for finding in &entry.check.other_diagnostics {
                line!("");
                line!("  OTHER DIAGNOSTIC: {}", finding.description);
                line!("    {}", finding.what);
            }
            for path in &entry.reproducers {
                line!("  reproducer: {path}");
            }
            line!(
                "  policy:   {} ({}) -- {}",
                entry.policy.as_str(),
                entry.expectation.as_str(),
                entry.policy_detail
            );
            line!("");
        }

        line!("Summary:");
        line!("  Contracts selected: {}", self.selected.len());
        line!("  Contracts checked:  {}", self.summary.contracts_checked);
        line!("  Leaks detected:     {}", self.summary.leaks_detected);
        line!("  Incomplete:         {}", self.summary.incomplete);
        if self.summary.expectations_unmet > 0 {
            line!("  Expectations unmet: {}", self.summary.expectations_unmet);
        }
        if !self.not_selected.is_empty() {
            line!("  Not selected:       {}", self.not_selected.join(", "));
        }
        if !self.summary.blocking_reasons.is_empty() {
            line!("");
            line!("Blocking:");
            for reason in &self.summary.blocking_reasons {
                line!("  - {reason}");
            }
        }
        line!("");
        line!("What this does and does not show:");
        for limitation in &self.limitations {
            line!("  - {limitation}");
        }
        line!("");
        line!("Result: {}", if self.summary.ok { "PASS" } else { "FAIL" });
        out
    }
}

fn render_inputs(inputs: &[(String, crate::generate::Value)]) -> String {
    inputs
        .iter()
        .map(|(name, value)| format!("{name}={}", value.describe()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{Control, Finding, Fingerprint, Isolation};
    use crate::generate::{Strategy, Value};
    use crate::memcheck::Classification;

    fn provenance() -> CheckProvenance {
        CheckProvenance {
            rustc_version: "rustc 1.97.0".into(),
            cargo_version: "cargo 1.97.0".into(),
            analyzer: "valgrind 3.28.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            profile: crate::dynamic_harness::PROFILE.into(),
            library_package: "crypto-library".into(),
            library_version: "0.1.0".into(),
            library_manifest: "/w/examples/crypto-library/Cargo.toml".into(),
        }
    }

    fn check(outcome: Outcome, planned: usize, completed: usize) -> ContractCheck {
        ContractCheck {
            contract: "crypto::lookup::substitute".into(),
            function: "substitute".into(),
            secret_parameters: vec!["index".into()],
            marked_bytes: 1,
            outcome,
            message: "a message".into(),
            calibration: Control::Confirmed,
            binding: Control::Confirmed,
            cases_planned: planned,
            cases_executed: completed,
            cases_completed: completed,
            analyzer_runs: 1,
            findings: Vec::new(),
            unattributed: Vec::new(),
            other_diagnostics: Vec::new(),
        }
    }

    fn entry(
        expectation: Expectation,
        expected: Option<&str>,
        check: ContractCheck,
    ) -> ContractEntry {
        let (policy, detail) = ContractEntry::evaluate(expectation, expected, &check);
        ContractEntry {
            contract: check.contract.clone(),
            function: check.function.clone(),
            site: "src/lookup.rs:12".into(),
            secrets: vec![SecretSummary {
                parameter: "index".into(),
                rust_type: "u8".into(),
                bytes: 1,
            }],
            corpus: CorpusSummary {
                seed: 7,
                budget: 64,
                cases: 30,
                sha256: "abc".into(),
                strategy_coverage: vec![StrategyCoverage {
                    strategy: Strategy::Boundaries,
                    planned: 22,
                    emitted: 22,
                    duplicates: 0,
                }],
                truncated: Vec::new(),
            },
            harness_sha256: "h".into(),
            artifact_sha256: "a".into(),
            lockfile_sha256: "l".into(),
            expectation,
            expected_outcome: expected.map(str::to_string),
            policy,
            policy_detail: detail,
            check,
            reproducers: Vec::new(),
        }
    }

    /// A clean security contract passes and exits 0, while saying it is not a
    /// proof.
    #[test]
    fn a_clean_security_contract_passes() {
        let entry = entry(
            Expectation::SecurityContract,
            None,
            check(Outcome::NoLeakObserved, 30, 30),
        );
        assert_eq!(entry.policy, Policy::Satisfied);
        assert!(entry.policy_detail.contains("not a proof"));
        let report = build(
            provenance(),
            vec!["crypto::lookup::substitute".into()],
            Vec::new(),
            vec![entry],
            false,
        );
        assert!(report.summary.ok);
        assert_eq!(report.exit_code(), EXIT_OK);
        assert!(report.to_text().contains("Result: PASS"));
    }

    /// A leak against a security contract fails with exit 1.
    #[test]
    fn a_leak_against_a_security_contract_fails() {
        let entry = entry(
            Expectation::SecurityContract,
            None,
            check(Outcome::LeakDetected, 30, 30),
        );
        assert_eq!(entry.policy, Policy::LeakDetected);
        let report = build(
            provenance(),
            vec!["crypto::lookup::substitute".into()],
            Vec::new(),
            vec![entry],
            false,
        );
        assert!(!report.summary.ok);
        assert_eq!(report.exit_code(), EXIT_LEAK);
        assert_eq!(report.summary.leaks_detected, 1);
        assert!(report.to_text().contains("Result: FAIL"));
    }

    /// The milestone's policy requirement: an analyzer-regression fixture that
    /// detects its planted leak passes, and the report says plainly that this is
    /// not a statement about the function being secure.
    #[test]
    fn an_analyzer_regression_passes_by_detecting_its_leak() {
        let entry = entry(
            Expectation::AnalyzerRegression,
            Some("LEAK_DETECTED"),
            check(Outcome::LeakDetected, 30, 30),
        );
        assert_eq!(entry.policy, Policy::Satisfied);
        assert!(
            entry.policy_detail.contains("not about the function"),
            "{}",
            entry.policy_detail
        );
        let report = build(
            provenance(),
            vec!["crypto::lookup::substitute".into()],
            Vec::new(),
            vec![entry],
            false,
        );
        assert_eq!(
            report.summary.leaks_detected, 0,
            "a regression fixture's planted leak is not a security failure"
        );
        assert_eq!(report.exit_code(), EXIT_OK);
    }

    /// An analyzer-regression fixture that stops reproducing its leak fails, so
    /// a compiler change that invalidates the fixture surfaces.
    #[test]
    fn an_analyzer_regression_that_stops_leaking_fails() {
        let entry = entry(
            Expectation::AnalyzerRegression,
            Some("LEAK_DETECTED"),
            check(Outcome::NoLeakObserved, 30, 30),
        );
        assert_eq!(entry.policy, Policy::ExpectationUnmet);
        let report = build(
            provenance(),
            vec!["c::f".into()],
            Vec::new(),
            vec![entry],
            false,
        );
        assert!(!report.summary.ok);
        assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
        assert_eq!(report.summary.expectations_unmet, 1);
    }

    /// A clean outcome over zero completed cases is incomplete, not a pass.
    #[test]
    fn a_clean_outcome_with_no_completed_cases_is_incomplete() {
        let entry = entry(
            Expectation::SecurityContract,
            None,
            check(Outcome::NoLeakObserved, 30, 0),
        );
        assert_eq!(entry.policy, Policy::Incomplete);
        assert!(entry.policy_detail.contains("nothing was checked"));
    }

    /// A clean outcome over a partial corpus is incomplete, naming the counts.
    #[test]
    fn a_partially_executed_corpus_is_incomplete() {
        let entry = entry(
            Expectation::SecurityContract,
            None,
            check(Outcome::NoLeakObserved, 30, 12),
        );
        assert_eq!(entry.policy, Policy::Incomplete);
        assert!(entry.policy_detail.contains("12 of 30"));
    }

    /// A clean outcome whose positive control did not confirm is incomplete.
    #[test]
    fn a_clean_outcome_without_a_confirmed_control_is_incomplete() {
        let mut inert = check(Outcome::NoLeakObserved, 30, 30);
        inert.binding = Control::Failed;
        let entry = entry(Expectation::SecurityContract, None, inert);
        assert_eq!(entry.policy, Policy::Incomplete);
        assert!(entry.policy_detail.contains("proves nothing"));
    }

    /// The generated backend cannot produce the symbolic outcome, and a result
    /// claiming it is treated as malformed rather than passed through.
    #[test]
    fn a_symbolic_outcome_from_this_backend_is_malformed() {
        let entry = entry(
            Expectation::SecurityContract,
            None,
            check(Outcome::VerifiedBounded, 30, 30),
        );
        assert_eq!(entry.policy, Policy::Incomplete);
        assert!(entry.policy_detail.contains("malformed"));
    }

    /// An empty selection is a failure, so a misconfigured CI job cannot report
    /// success for checking nothing.
    #[test]
    fn an_empty_selection_cannot_pass() {
        let report = build(provenance(), Vec::new(), Vec::new(), Vec::new(), false);
        assert!(!report.summary.ok);
        assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
        assert!(report.summary.blocking_reasons[0].contains("not a pass"));
    }

    /// `--ci` refuses a run that covered only part of the configuration, and
    /// names what it missed.
    #[test]
    fn strict_mode_refuses_a_partial_selection() {
        let entry = entry(
            Expectation::SecurityContract,
            None,
            check(Outcome::NoLeakObserved, 30, 30),
        );
        let lenient = build(
            provenance(),
            vec!["c::checked".into()],
            vec!["c::skipped".into()],
            vec![entry.clone()],
            false,
        );
        assert!(lenient.summary.ok, "a scoped run is allowed by default");

        let strict = build(
            provenance(),
            vec!["c::checked".into()],
            vec!["c::skipped".into()],
            vec![entry],
            true,
        );
        assert!(!strict.summary.ok);
        assert_eq!(strict.exit_code(), EXIT_INCOMPLETE);
        assert!(
            strict.summary.blocking_reasons[0].contains("c::skipped"),
            "{:?}",
            strict.summary.blocking_reasons
        );
    }

    /// Input-strategy truncation reaches the text report, so a dropped strategy
    /// is visible rather than implied by a case total.
    #[test]
    fn truncation_is_visible_in_the_report() {
        let mut subject = entry(
            Expectation::SecurityContract,
            None,
            check(Outcome::NoLeakObserved, 30, 30),
        );
        subject.corpus.truncated = vec!["pairwise: 8 of 484 planned case(s)".into()];
        let report = build(
            provenance(),
            vec!["c::f".into()],
            Vec::new(),
            vec![subject],
            false,
        );
        let text = report.to_text();
        assert!(text.contains("TRUNCATED: pairwise"), "{text}");
    }

    /// The report never presents generated inputs as proof, and names execution
    /// coverage as unmeasured.
    #[test]
    fn the_report_states_what_it_does_not_show() {
        let report = build(
            provenance(),
            vec!["c::f".into()],
            Vec::new(),
            Vec::new(),
            false,
        );
        let text = report.to_text();
        assert!(text.contains("not a proof"), "{text}");
        assert!(text.contains("Execution coverage"), "{text}");
        assert!(
            text.contains("not every #[constant_time] annotation"),
            "{text}"
        );
        // And the JSON carries the same statements.
        let json = report.to_json();
        assert!(json.contains("not a proof"));
        assert!(json.contains("\"schema_version\": 1"));
    }

    /// A finding's isolation and shrink reach the text report, including the
    /// sequence-dependent form.
    #[test]
    fn findings_render_their_isolation() {
        let finding = Finding {
            fingerprint: Fingerprint {
                classification: Classification::SecretDependentValue,
                function: Some("substitute_indexed".into()),
                location: Some("lookup.rs:37".into()),
            },
            classification: Classification::SecretDependentValue,
            description: "Secret-dependent memory address or value use".into(),
            what: "Use of uninitialised value of size 8".into(),
            origin: "created by a client request (the marked secret)".into(),
            stack: vec!["substitute_indexed (lookup.rs:37)".into()],
            attributed: true,
            site: Some("src/lookup.rs:37".into()),
            isolation: Isolation::Case {
                id: 4,
                inputs: vec![("index".into(), Value::Scalar { bits: 8, value: 5 })],
                runs: 3,
            },
            shrunk: None,
        };
        let mut leaking = check(Outcome::LeakDetected, 8, 8);
        leaking.findings = vec![finding.clone()];
        let text = build(
            provenance(),
            vec!["c::f".into()],
            Vec::new(),
            vec![entry(Expectation::SecurityContract, None, leaking)],
            false,
        )
        .to_text();
        assert!(text.contains("isolated to case 4 in 3 re-run(s)"), "{text}");
        // The developer-facing line, not the inlined `core` frame.
        assert!(text.contains("in substitute at src/lookup.rs:37"), "{text}");
        assert!(text.contains("index=5"), "{text}");

        let mut sequence = finding;
        sequence.isolation = Isolation::Sequence {
            ids: vec![1, 2],
            runs: 2,
            detail: "no single case reproduces this finding".into(),
        };
        let mut leaking = check(Outcome::LeakDetected, 8, 8);
        leaking.findings = vec![sequence];
        let text = build(
            provenance(),
            vec!["c::f".into()],
            Vec::new(),
            vec![entry(Expectation::SecurityContract, None, leaking)],
            false,
        )
        .to_text();
        assert!(text.contains("SEQUENCE-DEPENDENT"), "{text}");
    }
}
