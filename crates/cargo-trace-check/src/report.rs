//! Aggregation, contract coverage, and the text and JSON reports.
//!
//! Coverage is the part that stops an annotation from implying verification it
//! does not have.
//!
//! A contract is `covered` only when a test ran clean **and proved it invoked
//! the contract's function**. A test that merely names a target in a string is
//! `claimed-not-invoked`, which fails the run: otherwise this would pass,
//!
//! ```ignore
//! #[ct_test(target = "vulnerable")]
//! fn purported_test() {
//!     assert_constant_time!(secret = 42u8, call = |_key| 0u8);  // never calls it
//! }
//! ```
//!
//! reporting a vulnerable function as a covered contract. The generated test
//! checks an invocation counter, so this is proven per run rather than assumed.

use serde::Serialize;

use trace_check::security::{Outcome, Provenance};

use crate::discover::{ContractRecord, Discovery};
use crate::run::{Calibration, TestOutcome};

/// JSON report schema version.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Exit codes, matching the documented CLI contract.
pub const EXIT_OK: u8 = 0;
pub const EXIT_LEAK: u8 = 1;
pub const EXIT_INCOMPLETE: u8 = 2;

const LIMITATIONS: [&str; 5] = [
    "A passing test means no modeled secret-dependent behavior was observed on the paths that test exercised; it is not a proof of constant-time behavior.",
    "Memcheck models definedness influence, not time: operand latency, cache and branch-predictor effects, and speculation are outside this analysis.",
    "The analyzed binary is an optimized test executable, not the eventual production artifact.",
    "Only the secret representations implemented by MarkSecret are marked; nothing else compiles.",
    "Linux x86-64 only, and leak diagnostics are suppressed, so this is not a substitute for running Memcheck normally.",
];

/// How well a declared contract is covered by executed tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Coverage {
    /// A test ran clean **and** proved it invoked the contract's function.
    Covered,
    /// A test named this contract but did not invoke its function. Never a
    /// pass: the claim is unsupported.
    ClaimedNotInvoked,
    /// A test detected a violation of this contract.
    Violated,
    /// Tests ran but could not produce a trustworthy answer.
    Inconclusive,
    /// No test declares this contract. Never a pass.
    Untested,
    /// Tests were discovered but none executed, e.g. filtered out.
    NotExecuted,
}

impl Coverage {
    pub fn as_str(self) -> &'static str {
        match self {
            Coverage::Covered => "covered",
            Coverage::ClaimedNotInvoked => "claimed-not-invoked",
            Coverage::Violated => "violated",
            Coverage::Inconclusive => "inconclusive",
            Coverage::Untested => "untested",
            Coverage::NotExecuted => "not-executed",
        }
    }

    /// Whether this state is acceptable for a passing run.
    pub fn is_satisfied(self) -> bool {
        self == Coverage::Covered
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractReport {
    /// Module-qualified identity, unique across modules and crates.
    pub id: String,
    /// Bare name, for display.
    pub function: String,
    pub secrets: Vec<String>,
    pub file: String,
    pub line: u32,
    pub coverage: Coverage,
    /// Tests that declared this contract as their target.
    pub tests: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub backend: &'static str,
    pub provenance: Provenance,
    /// Tests discovered before filtering.
    pub discovered: usize,
    /// Tests the filter selected.
    pub selected: usize,
    /// Tests actually executed.
    pub executed: usize,
    pub tests: Vec<TestOutcome>,
    pub contracts: Vec<ContractReport>,
    pub summary: Summary,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub passed: usize,
    pub leaks_detected: usize,
    pub inconclusive: usize,
    pub contracts_unsatisfied: usize,
    /// Reasons the run cannot be considered complete.
    pub blocking_reasons: Vec<String>,
    pub ok: bool,
}

/// Builds the aggregated report.
///
/// `filtered` records whether the user narrowed the run. It changes how a
/// contract whose test was *not executed* is treated: deliberately excluding a
/// test should not be reported as a defect, while a contract with no test at
/// all always is.
pub fn build(
    discovery: &Discovery,
    selected: usize,
    outcomes: Vec<TestOutcome>,
    provenance: Provenance,
    filtered: bool,
) -> Report {
    let contracts = coverage(&discovery.contracts, &outcomes, &discovery.tests);

    let passed = outcomes.iter().filter(|t| t.passed()).count();
    let leaks = outcomes
        .iter()
        .filter(|t| t.outcome == Outcome::LeakDetected)
        .count();
    let inconclusive = outcomes
        .iter()
        .filter(|t| t.outcome == Outcome::Inconclusive)
        .count();
    let unsatisfied = contracts
        .iter()
        .filter(|c| {
            !c.coverage.is_satisfied() && !(filtered && c.coverage == Coverage::NotExecuted)
        })
        .count();

    let mut blocking = Vec::new();
    if discovery.tests.is_empty() {
        blocking.push(
            "no constant-time tests were discovered; a run that checks nothing is not a pass"
                .to_string(),
        );
    } else if selected == 0 {
        blocking
            .push("the filter selected no constant-time tests, so nothing was checked".to_string());
    } else if outcomes.is_empty() {
        blocking.push("no selected test was executed".to_string());
    }
    for contract in &contracts {
        // A narrowed run should not fail for the tests the user excluded, but a
        // contract with no test at all is a defect however the run was scoped.
        let excused = filtered && contract.coverage == Coverage::NotExecuted;
        if !contract.coverage.is_satisfied() && !excused {
            blocking.push(format!(
                "contract `{}` is {}",
                contract.id,
                contract.coverage.as_str()
            ));
        }
    }
    if inconclusive > 0 {
        blocking.push(format!("{inconclusive} test(s) were inconclusive"));
    }

    let ok = blocking.is_empty() && leaks == 0;

    Report {
        schema_version: REPORT_SCHEMA_VERSION,
        backend: trace_check::native::BACKEND,
        provenance,
        discovered: discovery.tests.len(),
        selected,
        executed: outcomes.len(),
        summary: Summary {
            passed,
            leaks_detected: leaks,
            inconclusive,
            contracts_unsatisfied: unsatisfied,
            blocking_reasons: blocking,
            ok,
        },
        tests: outcomes,
        contracts,
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    }
}

/// Whether a test's declared target names this contract.
///
/// Accepts the bare function name or any suffix of the qualified identity, so
/// `target = "verify"` matches `my_crate::auth::verify`. Ambiguity is rejected
/// before this point, in [`resolve_targets`].
fn targets(target: Option<&str>, contract: &ContractRecord) -> bool {
    let Some(target) = target else { return false };
    // Either the full identity, or a suffix of it ending at a path boundary,
    // so `verify` matches `my_crate::auth::verify` but `rify` does not.
    contract
        .id
        .strip_suffix(target)
        .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with("::"))
}

/// Rejects tests whose declared target names no contract, or more than one.
///
/// Both are errors rather than silent mismatches: an unknown target means the
/// test claims coverage of nothing, and an ambiguous one means trace-check
/// would have to guess which `verify` was meant.
pub fn resolve_targets(
    tests: &[crate::discover::TestRecord],
    contracts: &[ContractRecord],
) -> Result<(), String> {
    for test in tests {
        let Some(target) = test.target.as_deref() else {
            continue;
        };
        let matches: Vec<&ContractRecord> = contracts
            .iter()
            .filter(|contract| targets(Some(target), contract))
            .collect();
        match matches.len() {
            1 => {}
            0 => {
                return Err(format!(
                    "test `{}` declares `target = \"{target}\"` but no `#[constant_time]` \
                     contract with that name was discovered",
                    test.id
                ))
            }
            _ => {
                let names: Vec<&str> = matches.iter().map(|c| c.id.as_str()).collect();
                return Err(format!(
                    "test `{}` declares `target = \"{target}\"`, which is ambiguous between \
                     {}; use a longer path to disambiguate",
                    test.id,
                    names.join(" and ")
                ));
            }
        }
    }
    Ok(())
}

/// Maps each declared contract to its coverage state.
fn coverage(
    contracts: &[ContractRecord],
    outcomes: &[TestOutcome],
    discovered: &[crate::discover::TestRecord],
) -> Vec<ContractReport> {
    contracts
        .iter()
        .map(|contract| {
            // A test names its target by bare name; contracts are keyed by
            // module-qualified identity. `targets` resolves one to the other
            // and has already rejected an ambiguous name, so a test can never
            // be credited to the wrong `verify`.
            let executed: Vec<&TestOutcome> = outcomes
                .iter()
                .filter(|outcome| targets(outcome.target.as_deref(), contract))
                .collect();
            let declared = discovered
                .iter()
                .any(|test| targets(test.target.as_deref(), contract));

            let coverage = if executed.iter().any(|o| o.outcome == Outcome::LeakDetected) {
                Coverage::Violated
            } else if executed.iter().any(|o| o.outcome == Outcome::Inconclusive) {
                Coverage::Inconclusive
            } else if executed.iter().any(|o| o.invoked_target) {
                // Clean *and* proven to have exercised the function.
                Coverage::Covered
            } else if !executed.is_empty() {
                // A test named this contract but never invoked it, so the
                // clean result says nothing about this function.
                Coverage::ClaimedNotInvoked
            } else if declared {
                // A test exists but did not run, e.g. it was filtered out.
                Coverage::NotExecuted
            } else {
                Coverage::Untested
            };

            ContractReport {
                id: contract.id.clone(),
                function: contract.function.clone(),
                secrets: contract.secrets.clone(),
                file: contract.file.clone(),
                line: contract.line,
                coverage,
                tests: executed.iter().map(|o| o.test.clone()).collect(),
            }
        })
        .collect()
}

impl Report {
    /// Exit status: a detected leak outranks an incomplete analysis, so the
    /// code names the most serious outcome while the report keeps everything.
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
        serde_json::to_string_pretty(self).expect("report is serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        macro_rules! line {
            ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
        }

        line!("Backend: {}", self.backend);
        line!("Target:  {}", self.provenance.target);
        line!(
            "Build:   {} / {}",
            self.provenance.profile,
            self.provenance.analyzer
        );
        line!("");

        if self.tests.is_empty() {
            line!("No constant-time tests were executed.");
        } else {
            line!(
                "Running {} constant-time test{}",
                self.tests.len(),
                if self.tests.len() == 1 { "" } else { "s" }
            );
            line!("");
        }

        for test in &self.tests {
            let label = match test.outcome {
                Outcome::NoLeakObserved => "PASS",
                Outcome::LeakDetected => "FAIL",
                Outcome::Inconclusive => "INCONCLUSIVE",
            };
            line!("  {:<44} {label}", short_name(&test.test));
            line!("    {}", test.outcome);
            if test.calibration != Calibration::Confirmed {
                line!("    positive control: {}", test.calibration.as_str());
            }
            // An unrolled loop yields one diagnostic per unrolled branch, all
            // mapping to the same source line. Collapse them for the terminal;
            // the JSON report keeps every finding.
            for (label, count) in group(&test.findings) {
                line!("    {label}{}", occurrences(count));
            }
            for (label, count) in group(&test.other_diagnostics) {
                line!("    other: {label}{}", occurrences(count));
            }
            if test.outcome != Outcome::NoLeakObserved {
                line!("    {}", test.message);
            }
            line!("");
        }

        if !self.contracts.is_empty() {
            line!("Contracts");
            for contract in &self.contracts {
                let mark = if contract.coverage.is_satisfied() {
                    " "
                } else {
                    "!"
                };
                line!(
                    "  {mark} {:<42} {}",
                    contract.id,
                    contract.coverage.as_str()
                );
                if !contract.coverage.is_satisfied() {
                    line!(
                        "      declared at {}:{} with secret(s) {}",
                        contract.file,
                        contract.line,
                        contract.secrets.join(", ")
                    );
                }
            }
            line!("");
        }

        line!("Summary:");
        line!("  {} passed", self.summary.passed);
        line!("  {} leak detected", self.summary.leaks_detected);
        line!("  {} inconclusive", self.summary.inconclusive);
        if self.summary.contracts_unsatisfied > 0 {
            line!(
                "  {} contract(s) unsatisfied",
                self.summary.contracts_unsatisfied
            );
        }
        line!(
            "  {} discovered / {} selected / {} executed",
            self.discovered,
            self.selected,
            self.executed
        );

        if !self.summary.blocking_reasons.is_empty() {
            line!("");
            line!("Not a passing run:");
            for reason in &self.summary.blocking_reasons {
                line!("  - {reason}");
            }
        }

        line!("");
        line!("What this does and does not establish");
        for limitation in &self.limitations {
            line!("  - {limitation}");
        }
        out
    }
}

/// Groups findings by description and location, preserving first-seen order,
/// and counts how many collapsed into each entry.
fn group(findings: &[crate::run::Finding]) -> Vec<(String, usize)> {
    let mut order: Vec<String> = Vec::new();
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for finding in findings {
        let label = match &finding.location {
            Some(location) => format!("{}\n      {location}", finding.description),
            None => finding.description.clone(),
        };
        if !counts.contains_key(&label) {
            order.push(label.clone());
        }
        *counts.entry(label).or_default() += 1;
    }
    order
        .into_iter()
        .map(|label| {
            let count = counts[&label];
            (label, count)
        })
        .collect()
}

fn occurrences(count: usize) -> String {
    if count > 1 {
        format!("  ({count} occurrences)")
    } else {
        String::new()
    }
}

/// Trims the long module path so the table stays readable.
fn short_name(name: &str) -> String {
    name.rsplit("::").next().unwrap_or(name).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::TestRecord;

    fn provenance() -> Provenance {
        Provenance {
            rustc_version: "rustc 1.97.0".to_string(),
            cargo_version: "cargo 1.97.0".to_string(),
            analyzer: "valgrind 3.28.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            profile: "memcheck".to_string(),
            artifact_path: "/tmp/t".to_string(),
            artifact_sha256: "abc123".to_string(),
        }
    }

    fn outcome(test: &str, target: Option<&str>, outcome: Outcome) -> TestOutcome {
        TestOutcome {
            test: test.to_string(),
            target: target.map(str::to_string),
            executable: "/tmp/t".to_string(),
            executable_sha256: "abc123".to_string(),
            outcome,
            calibration: Calibration::Confirmed,
            invoked_target: true,
            message: "m".to_string(),
            findings: Vec::new(),
            other_diagnostics: Vec::new(),
        }
    }

    fn record(name: &str, target: Option<&str>) -> TestRecord {
        TestRecord {
            name: name.to_string(),
            id: format!("c::{name}"),
            target: target.map(str::to_string),
            executable: "/tmp/t".to_string(),
            executable_sha256: "abc123".to_string(),
        }
    }

    fn contract(function: &str) -> ContractRecord {
        ContractRecord {
            id: format!("c::{function}"),
            function: function.to_string(),
            secrets: vec!["expected".to_string()],
            file: "src/lib.rs".to_string(),
            line: 10,
        }
    }

    fn discovery(tests: Vec<TestRecord>, contracts: Vec<ContractRecord>) -> Discovery {
        Discovery {
            tests,
            contracts,
            profile: "memcheck".to_string(),
        }
    }

    /// A clean run with a covered contract exits 0.
    #[test]
    fn clean_covered_run_exits_zero() {
        let d = discovery(
            vec![record("m::t", Some("verify"))],
            vec![contract("verify")],
        );
        let report = build(
            &d,
            1,
            vec![outcome("m::t", Some("verify"), Outcome::NoLeakObserved)],
            provenance(),
            false,
        );
        assert!(report.summary.ok);
        assert_eq!(report.exit_code(), EXIT_OK);
        assert_eq!(report.contracts[0].coverage, Coverage::Covered);
    }

    /// A detected leak exits 1.
    #[test]
    fn detected_leak_exits_one() {
        let d = discovery(vec![record("m::t", None)], vec![]);
        let report = build(
            &d,
            1,
            vec![outcome("m::t", None, Outcome::LeakDetected)],
            provenance(),
            false,
        );
        assert_eq!(report.exit_code(), EXIT_LEAK);
        assert!(!report.summary.ok);
    }

    /// An inconclusive test exits 2, and is not mislabeled as a leak.
    #[test]
    fn inconclusive_exits_two_and_is_not_a_leak() {
        let d = discovery(vec![record("m::t", None)], vec![]);
        let report = build(
            &d,
            1,
            vec![outcome("m::t", None, Outcome::Inconclusive)],
            provenance(),
            false,
        );
        assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
        assert_eq!(report.summary.leaks_detected, 0);
        assert_eq!(report.summary.inconclusive, 1);
    }

    /// A leak outranks an inconclusive result in the exit code, while both stay
    /// in the report.
    #[test]
    fn a_leak_outranks_an_inconclusive_result() {
        let d = discovery(vec![record("a", None), record("b", None)], vec![]);
        let report = build(
            &d,
            2,
            vec![
                outcome("a", None, Outcome::LeakDetected),
                outcome("b", None, Outcome::Inconclusive),
            ],
            provenance(),
            false,
        );
        assert_eq!(report.exit_code(), EXIT_LEAK);
        assert_eq!(report.summary.inconclusive, 1);
        assert_eq!(report.summary.leaks_detected, 1);
    }

    /// A contract with no test is `untested` and blocks the run. An annotation
    /// must never imply verification it does not have.
    #[test]
    fn a_contract_with_no_test_is_untested_and_blocks() {
        let d = discovery(vec![], vec![contract("verify")]);
        let report = build(&d, 0, vec![], provenance(), false);
        assert_eq!(report.contracts[0].coverage, Coverage::Untested);
        assert!(!report.summary.ok);
        assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
        assert!(report
            .summary
            .blocking_reasons
            .iter()
            .any(|r| r.contains("untested")));
    }

    /// A contract whose test exists but did not execute is distinguished from
    /// one with no test at all.
    #[test]
    fn a_registered_but_unexecuted_test_is_not_executed() {
        let d = discovery(
            vec![record("m::t", Some("verify"))],
            vec![contract("verify")],
        );
        let report = build(&d, 0, vec![], provenance(), false);
        assert_eq!(report.contracts[0].coverage, Coverage::NotExecuted);
        assert!(!report.summary.ok);
    }

    /// A target naming no discovered contract is rejected before anything
    /// runs, so a test cannot silently claim coverage of nothing.
    #[test]
    fn an_unknown_target_is_rejected() {
        let tests = vec![record("m::t", Some("ghost"))];
        let error = resolve_targets(&tests, &[contract("verify")])
            .expect_err("an unknown target must be rejected");
        assert!(error.contains("no `#[constant_time]` contract"), "{error}");
        assert!(error.contains("ghost"), "{error}");
    }

    /// An ambiguous bare target is rejected rather than credited to whichever
    /// contract happened to be found first.
    #[test]
    fn an_ambiguous_target_is_rejected() {
        let tests = vec![record("m::t", Some("verify"))];
        let contracts = vec![
            ContractRecord {
                id: "c::authentication::verify".to_string(),
                function: "verify".to_string(),
                secrets: vec!["key".to_string()],
                file: "a.rs".to_string(),
                line: 1,
            },
            ContractRecord {
                id: "c::encryption::verify".to_string(),
                function: "verify".to_string(),
                secrets: vec!["key".to_string()],
                file: "b.rs".to_string(),
                line: 2,
            },
        ];
        let error = resolve_targets(&tests, &contracts).expect_err("ambiguity must be rejected");
        assert!(error.contains("ambiguous"), "{error}");
        assert!(
            error.contains("authentication") && error.contains("encryption"),
            "{error}"
        );
    }

    /// A qualified target disambiguates between same-named contracts.
    #[test]
    fn a_qualified_target_disambiguates() {
        let tests = vec![record("m::t", Some("authentication::verify"))];
        let contracts = vec![
            ContractRecord {
                id: "c::authentication::verify".to_string(),
                function: "verify".to_string(),
                secrets: vec![],
                file: "a.rs".to_string(),
                line: 1,
            },
            ContractRecord {
                id: "c::encryption::verify".to_string(),
                function: "verify".to_string(),
                secrets: vec![],
                file: "b.rs".to_string(),
                line: 2,
            },
        ];
        assert!(resolve_targets(&tests, &contracts).is_ok());
        assert!(targets(Some("authentication::verify"), &contracts[0]));
        assert!(!targets(Some("authentication::verify"), &contracts[1]));
    }

    /// A target must match a whole path segment, so `rify` does not match
    /// `verify`.
    #[test]
    fn a_target_matches_whole_segments_only() {
        let contract = ContractRecord {
            id: "c::auth::verify".to_string(),
            function: "verify".to_string(),
            secrets: vec![],
            file: "a.rs".to_string(),
            line: 1,
        };
        assert!(targets(Some("verify"), &contract));
        assert!(targets(Some("auth::verify"), &contract));
        assert!(targets(Some("c::auth::verify"), &contract));
        assert!(!targets(Some("rify"), &contract));
        assert!(!targets(Some("other"), &contract));
        assert!(!targets(None, &contract));
    }

    /// A contract is covered only when a test both ran clean and proved it
    /// invoked the function. A clean test that merely named the target is
    /// `claimed-not-invoked`, which blocks the run.
    #[test]
    fn coverage_requires_a_verified_invocation() {
        let d = discovery(
            vec![record("m::t", Some("verify"))],
            vec![contract("verify")],
        );

        let mut claimed = outcome("m::t", Some("verify"), Outcome::NoLeakObserved);
        claimed.invoked_target = false;
        let unsupported = build(&d, 1, vec![claimed], provenance(), false);
        assert_eq!(
            unsupported.contracts[0].coverage,
            Coverage::ClaimedNotInvoked
        );
        assert!(!unsupported.summary.ok);
        assert_eq!(unsupported.exit_code(), EXIT_INCOMPLETE);

        let mut verified = outcome("m::t", Some("verify"), Outcome::NoLeakObserved);
        verified.invoked_target = true;
        let supported = build(&d, 1, vec![verified], provenance(), false);
        assert_eq!(supported.contracts[0].coverage, Coverage::Covered);
        assert!(supported.summary.ok);
    }

    /// A narrowed run is not failed by the contracts whose tests the filter
    /// excluded, but an entirely untested contract still blocks.
    #[test]
    fn a_filtered_run_excuses_unexecuted_but_not_untested_contracts() {
        let d = discovery(
            vec![record("m::t", Some("covered"))],
            vec![contract("covered")],
        );
        let excused = build(&d, 0, vec![], provenance(), true);
        assert_eq!(excused.contracts[0].coverage, Coverage::NotExecuted);
        assert_eq!(excused.summary.contracts_unsatisfied, 0);

        let untested = discovery(vec![], vec![contract("orphan")]);
        let blocked = build(&untested, 0, vec![], provenance(), true);
        assert_eq!(blocked.contracts[0].coverage, Coverage::Untested);
        assert!(
            !blocked.summary.ok,
            "an untested contract blocks even a filtered run"
        );
    }

    /// A violated contract is reported as violated, not merely as a failing
    /// test.
    #[test]
    fn a_violated_contract_is_reported() {
        let d = discovery(
            vec![record("m::t", Some("verify"))],
            vec![contract("verify")],
        );
        let report = build(
            &d,
            1,
            vec![outcome("m::t", Some("verify"), Outcome::LeakDetected)],
            provenance(),
            false,
        );
        assert_eq!(report.contracts[0].coverage, Coverage::Violated);
    }

    /// An inconclusive test leaves its contract inconclusive rather than
    /// covered.
    #[test]
    fn an_inconclusive_test_leaves_its_contract_inconclusive() {
        let d = discovery(
            vec![record("m::t", Some("verify"))],
            vec![contract("verify")],
        );
        let report = build(
            &d,
            1,
            vec![outcome("m::t", Some("verify"), Outcome::Inconclusive)],
            provenance(),
            false,
        );
        assert_eq!(report.contracts[0].coverage, Coverage::Inconclusive);
    }

    /// Discovering nothing is an error, not a vacuous pass.
    #[test]
    fn discovering_no_tests_blocks_the_run() {
        let report = build(&discovery(vec![], vec![]), 0, vec![], provenance(), false);
        assert!(!report.summary.ok);
        assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
        assert!(report
            .summary
            .blocking_reasons
            .iter()
            .any(|r| r.contains("checks nothing")));
    }

    /// A filter that selects nothing is an error too.
    #[test]
    fn selecting_no_tests_blocks_the_run() {
        let d = discovery(vec![record("m::t", None)], vec![]);
        let report = build(&d, 0, vec![], provenance(), false);
        assert!(!report.summary.ok);
        assert!(report
            .summary
            .blocking_reasons
            .iter()
            .any(|r| r.contains("selected no constant-time tests")));
    }

    /// Repeated findings at one source location are collapsed with a count,
    /// because an unrolled loop produces one diagnostic per unrolled branch.
    #[test]
    fn repeated_findings_are_collapsed_with_a_count() {
        let d = discovery(vec![record("m::t", None)], vec![]);
        let mut leak = outcome("m::t", None, Outcome::LeakDetected);
        for _ in 0..31 {
            leak.findings.push(crate::run::Finding {
                classification: trace_check::memcheck::Classification::SecretDependentBranch,
                description: "Secret-dependent branch".to_string(),
                what: "Conditional jump".to_string(),
                location: Some("src/lib.rs:52".to_string()),
                function: Some("verify".to_string()),
                origin: "created by a client request (the marked secret)".to_string(),
                stack: vec![],
            });
        }
        let report = build(&d, 1, vec![leak], provenance(), false);
        let text = report.to_text();
        assert!(
            text.contains("(31 occurrences)"),
            "missing the count in:\n{text}"
        );
        assert_eq!(
            text.matches("Secret-dependent branch").count(),
            1,
            "the finding should appear once, not 31 times"
        );
        // The JSON report keeps every finding.
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["tests"][0]["findings"].as_array().unwrap().len(), 31);
    }

    /// Distinct locations are listed separately rather than merged.
    #[test]
    fn distinct_locations_are_not_merged() {
        let findings: Vec<crate::run::Finding> = ["a.rs:1", "b.rs:2", "a.rs:1"]
            .iter()
            .map(|location| crate::run::Finding {
                classification: trace_check::memcheck::Classification::SecretDependentBranch,
                description: "Secret-dependent branch".to_string(),
                what: String::new(),
                location: Some(location.to_string()),
                function: None,
                origin: String::new(),
                stack: vec![],
            })
            .collect();
        let grouped = group(&findings);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].1, 2);
        assert_eq!(grouped[1].1, 1);
    }

    /// Text output names the outcome and the source location of a finding.
    #[test]
    fn text_output_is_actionable() {
        let d = discovery(vec![record("m::unsafe_lookup", None)], vec![]);
        let mut leak = outcome("m::unsafe_lookup", None, Outcome::LeakDetected);
        leak.findings.push(crate::run::Finding {
            classification: trace_check::memcheck::Classification::SecretDependentValue,
            description: "Secret-dependent memory address or value use".to_string(),
            what: "Use of uninitialised value of size 8".to_string(),
            location: Some("src/crypto.rs:47".to_string()),
            function: Some("lookup".to_string()),
            origin: "created by a client request (the marked secret)".to_string(),
            stack: vec![],
        });
        let text = build(&d, 1, vec![leak], provenance(), false).to_text();
        for expected in [
            "Backend: native-memcheck",
            "unsafe_lookup",
            "FAIL",
            "LEAK_DETECTED",
            "Secret-dependent memory address",
            "src/crypto.rs:47",
            "1 leak detected",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    /// The report always states what the analysis does not establish.
    #[test]
    fn text_output_states_its_limits() {
        let d = discovery(vec![record("m::t", None)], vec![]);
        let text = build(
            &d,
            1,
            vec![outcome("m::t", None, Outcome::NoLeakObserved)],
            provenance(),
            false,
        )
        .to_text();
        assert!(text.contains("not a proof of constant-time behavior"));
    }

    /// A failed positive control is surfaced in the text output.
    #[test]
    fn failed_calibration_is_surfaced() {
        let d = discovery(vec![record("m::t", None)], vec![]);
        let mut broken = outcome("m::t", None, Outcome::Inconclusive);
        broken.calibration = Calibration::Failed;
        let text = build(&d, 1, vec![broken], provenance(), false).to_text();
        assert!(text.contains("positive control: failed"));
    }

    /// The JSON report carries schema, provenance, counts and calibration, and
    /// nests per-test results so keys cannot collide.
    #[test]
    fn json_report_is_complete_and_unambiguous() {
        let d = discovery(
            vec![record("m::t", Some("verify"))],
            vec![contract("verify")],
        );
        let report = build(
            &d,
            1,
            vec![outcome("m::t", Some("verify"), Outcome::NoLeakObserved)],
            provenance(),
            false,
        );
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(value["backend"], "native-memcheck");
        assert_eq!(value["provenance"]["analyzer"], "valgrind 3.28.0");
        assert_eq!(value["provenance"]["artifact_sha256"], "abc123");
        assert_eq!(value["discovered"], 1);
        assert_eq!(value["selected"], 1);
        assert_eq!(value["executed"], 1);
        assert_eq!(value["tests"][0]["outcome"], "NO_LEAK_OBSERVED");
        assert_eq!(value["tests"][0]["calibration"], "confirmed");
        assert_eq!(value["tests"][0]["target"], "verify");
        assert_eq!(value["contracts"][0]["coverage"], "covered");
        assert_eq!(value["contracts"][0]["secrets"][0], "expected");
        assert!(value["limitations"].as_array().unwrap().len() >= 5);
    }

    /// Long module paths are shortened for the table but the JSON keeps the
    /// full name, which is what `--exact` needs.
    #[test]
    fn display_shortens_names_but_json_keeps_them() {
        assert_eq!(short_name("a::b::c"), "c");
        assert_eq!(short_name("bare"), "bare");
        let d = discovery(vec![record("deep::module::t", None)], vec![]);
        let report = build(
            &d,
            1,
            vec![outcome("deep::module::t", None, Outcome::NoLeakObserved)],
            provenance(),
            false,
        );
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["tests"][0]["test"], "deep::module::t");
    }
}
