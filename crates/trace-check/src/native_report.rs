//! Reporting for the native Memcheck backend.
//!
//! Kept separate from [`crate::report`] rather than squeezing Memcheck
//! diagnostics into M1's `ExecutionEvent` shape. The two backends share the
//! outcome vocabulary, provenance and expectation handling from
//! [`crate::security`]; their evidence is genuinely different and forcing it
//! into one structure would lose the source locations and stacks that make a
//! native finding actionable.

use serde::Serialize;

use crate::native::{NativeCase, NativeResult, BACKEND};
use crate::security::{Expectation, Outcome, Provenance};

/// JSON report schema version for native analyses.
pub const NATIVE_REPORT_SCHEMA_VERSION: u32 = 1;

const LIMITATIONS: [&str; 6] = [
    "Memcheck models definedness influence, not time: secret-dependent operand latency, cache and branch-predictor effects, and speculation are outside this analysis.",
    "Findings exist only for the paths the test inputs executed; NO_LEAK_OBSERVED is not proof of constant-time behavior.",
    "A secret-dependent address finding reports that the address depended on a secret, not how much entropy leaks.",
    "Results describe one binary built for one target with one compiler; they do not transfer to other targets or flags.",
    "Declassification is manual and trusted: a misplaced restore silently suppresses real findings.",
    "Attribution matches stack frames by function name, so aggressive inlining can blur which function owns a finding.",
];

/// One analyzed case.
///
/// `result` is nested rather than flattened. Flattening duplicated `case`,
/// `function` and `secret_source`, which `NativeResult` also defines, and
/// serde emits duplicate JSON object keys without complaint. Parsers handle
/// those inconsistently, and this report is meant for CI and the eventual
/// assertion API, so the schema has to be unambiguous. Nesting makes the
/// collision impossible rather than merely fixing today's instance.
#[derive(Debug, Clone, Serialize)]
pub struct NativeCaseReport {
    pub description: String,
    pub package: String,
    pub rationale: String,
    pub provenance: Provenance,
    pub result: NativeResult,
    pub expectation: Expectation,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeReport {
    pub schema_version: u32,
    pub backend: &'static str,
    pub cases: Vec<NativeCaseReport>,
    pub summary: NativeSummary,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NativeSummary {
    pub analyzed: usize,
    pub leaks_detected: usize,
    pub no_leak_observed: usize,
    pub inconclusive: usize,
    pub unmet_expectations: Vec<String>,
    /// True when every declared expectation was reproduced. This reports that
    /// the analyzer behaved as predicted, not that any code is secure.
    pub expectations_reproduced: bool,
}

pub fn build(entries: Vec<(NativeCase, NativeResult, Provenance)>) -> NativeReport {
    let cases: Vec<NativeCaseReport> = entries
        .into_iter()
        .map(|(case, result, provenance)| {
            let expected =
                Outcome::parse(&case.expected_outcome).expect("the manifest was validated on load");
            NativeCaseReport {
                description: case.description,
                package: case.package,
                rationale: case.rationale,
                expectation: Expectation::new(expected, result.outcome),
                provenance,
                result,
            }
        })
        .collect();

    let count = |outcome: Outcome| {
        cases
            .iter()
            .filter(|entry| entry.result.outcome == outcome)
            .count()
    };
    let unmet: Vec<String> = cases
        .iter()
        .filter(|entry| !entry.expectation.met)
        .map(|entry| {
            format!(
                "{}: expected {} but observed {}",
                entry.result.case, entry.expectation.expected, entry.expectation.observed
            )
        })
        .collect();

    NativeReport {
        schema_version: NATIVE_REPORT_SCHEMA_VERSION,
        backend: BACKEND,
        summary: NativeSummary {
            analyzed: cases.len(),
            leaks_detected: count(Outcome::LeakDetected),
            no_leak_observed: count(Outcome::NoLeakObserved),
            inconclusive: count(Outcome::Inconclusive),
            expectations_reproduced: unmet.is_empty() && !cases.is_empty(),
            unmet_expectations: unmet,
        },
        cases,
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    }
}

impl NativeReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("native report is serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        macro_rules! line {
            ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
        }

        if let Some(first) = self.cases.first() {
            line!("trace-check native secret-dependency analysis");
            line!(
                "  {} / {} / {} / {}",
                first.provenance.rustc_version,
                first.provenance.target,
                first.provenance.profile,
                first.provenance.analyzer
            );
        }

        for entry in &self.cases {
            let verdict = if entry.expectation.met {
                "ok"
            } else {
                "UNEXPECTED"
            };
            line!("");
            // Three labels, because displaying INCONCLUSIVE as PASS would be
            // actively misleading in a security CLI. Whether the regression
            // test behaved as predicted is the separate [ok]/[UNEXPECTED] mark
            // on the Result line.
            let label = match entry.result.outcome {
                Outcome::LeakDetected => "LEAK",
                Outcome::NoLeakObserved => "NO LEAK OBSERVED",
                Outcome::Inconclusive => "INCONCLUSIVE",
            };
            line!("{label}: {}", entry.result.case);
            line!("");
            line!("Backend: {}", entry.result.backend);
            line!("Target:  {}", entry.provenance.target);
            line!(
                "Binary:  sha256 {}",
                short(&entry.provenance.artifact_sha256)
            );
            if !entry.result.instrumented {
                line!("Warning: the harness did not report running under Valgrind");
            }

            if entry.result.findings.is_empty() && entry.result.other_diagnostics.is_empty() {
                line!("");
                line!("Finding:");
                line!("  none");
            }
            for finding in &entry.result.findings {
                line!("");
                line!("Finding:");
                line!(
                    "  {}{}",
                    finding.description,
                    if finding.attributed {
                        ""
                    } else {
                        " (unattributed)"
                    }
                );
                if let Some(location) = &finding.location {
                    line!("");
                    line!("Location:");
                    line!("  {location}");
                }
                if !entry.result.secret_source.is_empty() {
                    line!("");
                    line!("Secret source:");
                    line!("  {}", entry.result.secret_source);
                }
                if !finding.origin.is_empty() {
                    line!("");
                    line!("Origin:");
                    line!("  {}", finding.origin);
                    for frame in &finding.origin_stack {
                        line!("    {frame}");
                    }
                }
                if !finding.stack.is_empty() {
                    line!("");
                    line!("Stack:");
                    for frame in &finding.stack {
                        line!("  {frame}");
                    }
                }
            }
            for diagnostic in &entry.result.other_diagnostics {
                line!("");
                line!("Other diagnostic (not a timing leak):");
                line!("  {} - {}", diagnostic.description, diagnostic.what);
                if let Some(location) = &diagnostic.location {
                    line!("  at {location}");
                }
            }

            line!("");
            line!("Result:");
            line!("  {}", entry.result.outcome);
            line!("  {}", entry.result.message);
            line!(
                "  [{verdict}] fixture expected {}",
                entry.expectation.expected
            );
        }

        line!("");
        line!(
            "Summary: {} analyzed - {} leak detected, {} no leak observed, {} inconclusive",
            self.summary.analyzed,
            self.summary.leaks_detected,
            self.summary.no_leak_observed,
            self.summary.inconclusive
        );
        if self.summary.expectations_reproduced {
            line!("Every declared expectation was reproduced.");
        } else {
            line!("Declared expectations were NOT reproduced:");
            for unmet in &self.summary.unmet_expectations {
                line!("  - {unmet}");
            }
        }

        line!("");
        line!("Limitations");
        for limitation in &self.limitations {
            line!("  - {limitation}");
        }
        out
    }
}

fn short(hash: &str) -> String {
    hash.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::NativeFinding;
    use crate::security::Evidence;

    fn provenance() -> Provenance {
        Provenance {
            rustc_version: "rustc 1.97.0".to_string(),
            cargo_version: "cargo 1.97.0".to_string(),
            analyzer: "valgrind 3.28.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            profile: "memcheck".to_string(),
            artifact_path: "/tmp/b".to_string(),
            artifact_sha256: "abcdef0123456789".to_string(),
        }
    }

    fn case(id: &str, expected: &str) -> NativeCase {
        NativeCase {
            id: id.to_string(),
            description: "d".to_string(),
            package: "p".to_string(),
            binary: "b".to_string(),
            features: vec![],
            case: id.to_string(),
            function: "f".to_string(),
            secret_source: "index".to_string(),
            expected_outcome: expected.to_string(),
            rationale: "r".to_string(),
        }
    }

    fn result_named(id: &str, outcome: Outcome, findings: Vec<NativeFinding>) -> NativeResult {
        NativeResult {
            case: id.to_string(),
            function: "f".to_string(),
            secret_source: "index".to_string(),
            backend: BACKEND,
            evidence: Evidence::DynamicSecretDependency,
            outcome,
            message: "m".to_string(),
            instrumented: true,
            findings,
            other_diagnostics: Vec::new(),
        }
    }

    fn result(outcome: Outcome, findings: Vec<NativeFinding>) -> NativeResult {
        result_named("c", outcome, findings)
    }

    fn finding() -> NativeFinding {
        NativeFinding {
            classification: crate::memcheck::Classification::SecretDependentValue,
            description: "Secret-dependent memory address or value use".to_string(),
            what: "Use of uninitialised value of size 8".to_string(),
            location: Some("examples/table-lookup/src/lib.rs:27".to_string()),
            function: Some("lookup_secret_index".to_string()),
            origin: "created by a client request (the marked secret)".to_string(),
            stack: vec!["lookup_secret_index (lib.rs:27)".to_string()],
            origin_stack: vec!["Secret::new (lib.rs:126)".to_string()],
            attributed: true,
        }
    }

    /// A detected leak that the fixture predicted counts as a met expectation,
    /// so the regression test passes when the analyzer works.
    #[test]
    fn detected_leak_meets_a_leak_expectation() {
        let report = build(vec![(
            case("secret_table_lookup", "LEAK_DETECTED"),
            result(Outcome::LeakDetected, vec![finding()]),
            provenance(),
        )]);
        assert!(report.summary.expectations_reproduced);
        assert_eq!(report.summary.leaks_detected, 1);
        assert!(report.cases[0].expectation.met);
    }

    /// An unmet expectation is named in the summary.
    #[test]
    fn unmet_expectation_is_reported() {
        let report = build(vec![(
            case("x", "LEAK_DETECTED"),
            result(Outcome::NoLeakObserved, vec![]),
            provenance(),
        )]);
        assert!(!report.summary.expectations_reproduced);
        assert_eq!(report.summary.unmet_expectations.len(), 1);
        assert!(report.summary.unmet_expectations[0].contains("expected LEAK_DETECTED"));
    }

    /// Text output carries the actionable fields: backend, target, finding,
    /// location, secret source and result.
    #[test]
    fn text_output_is_actionable() {
        let report = build(vec![(
            case("secret_table_lookup", "LEAK_DETECTED"),
            result_named(
                "secret_table_lookup",
                Outcome::LeakDetected,
                vec![finding()],
            ),
            provenance(),
        )]);
        let text = report.to_text();
        for expected in [
            "LEAK: secret_table_lookup",
            "Backend: native-memcheck",
            "Target:  x86_64-unknown-linux-gnu",
            "Secret-dependent memory address",
            "examples/table-lookup/src/lib.rs:27",
            "Secret source:",
            "LEAK_DETECTED",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    /// A clean case renders as PASS with an explicit "none" finding.
    #[test]
    fn clean_case_renders_as_pass() {
        let report = build(vec![(
            case("control", "NO_LEAK_OBSERVED"),
            result_named("control", Outcome::NoLeakObserved, vec![]),
            provenance(),
        )]);
        let text = report.to_text();
        assert!(text.contains("NO LEAK OBSERVED: control"));
        assert!(text.contains("none"));
    }

    /// Reports always carry the limitations, including that Memcheck does not
    /// model timing and that a clean result is not proof.
    #[test]
    fn report_always_states_its_limits() {
        let report = build(vec![(
            case("c", "NO_LEAK_OBSERVED"),
            result(Outcome::NoLeakObserved, vec![]),
            provenance(),
        )]);
        let text = report.to_text();
        assert!(text.contains("not proof of constant-time behavior"));
        assert!(text.contains("not time"));
        assert_eq!(report.limitations.len(), 6);
    }

    /// An uninstrumented run is flagged in the text output.
    #[test]
    fn uninstrumented_run_is_flagged_in_text() {
        let mut uninstrumented = result(Outcome::Inconclusive, vec![]);
        uninstrumented.instrumented = false;
        let report = build(vec![(
            case("c", "NO_LEAK_OBSERVED"),
            uninstrumented,
            provenance(),
        )]);
        assert!(report
            .to_text()
            .contains("did not report running under Valgrind"));
    }

    /// `NativeResult`'s field names must not also appear at the case object's
    /// top level, or serde would emit duplicate JSON object keys. Nesting
    /// `result` makes this structural, and this test fails if someone
    /// reintroduces `#[serde(flatten)]` plus an overlapping field.
    #[test]
    fn case_report_and_result_keys_do_not_collide() {
        let report = build(vec![(
            case("c", "LEAK_DETECTED"),
            result(Outcome::LeakDetected, vec![finding()]),
            provenance(),
        )]);
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        let case_object = value["cases"][0].as_object().expect("a case object");

        let result_json = serde_json::to_value(result(Outcome::LeakDetected, vec![])).unwrap();
        let result_keys: Vec<&String> = result_json
            .as_object()
            .expect("a result object")
            .keys()
            .collect();
        assert!(!result_keys.is_empty());

        for key in result_keys {
            assert!(
                !case_object.contains_key(key.as_str()),
                "key {key:?} appears both on the case object and inside `result`, which \
                 would serialize as a duplicate JSON key"
            );
        }
        assert!(case_object.contains_key("result"));
    }

    /// Each outcome renders as its own label. Displaying INCONCLUSIVE as PASS
    /// would be actively misleading in a security CLI.
    #[test]
    fn each_outcome_has_a_distinct_label() {
        for (outcome, expected) in [
            (Outcome::LeakDetected, "LEAK: c"),
            (Outcome::NoLeakObserved, "NO LEAK OBSERVED: c"),
            (Outcome::Inconclusive, "INCONCLUSIVE: c"),
        ] {
            let report = build(vec![(
                case("c", outcome.as_str()),
                result(outcome, vec![]),
                provenance(),
            )]);
            let text = report.to_text();
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
            assert!(!text.contains("PASS: c"), "PASS must not be used");
        }
    }

    /// The JSON report is valid and carries its schema version and provenance.
    #[test]
    fn json_report_carries_schema_and_provenance() {
        let report = build(vec![(
            case("c", "LEAK_DETECTED"),
            result(Outcome::LeakDetected, vec![finding()]),
            provenance(),
        )]);
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["schema_version"], NATIVE_REPORT_SCHEMA_VERSION);
        assert_eq!(value["backend"], BACKEND);
        assert_eq!(
            value["cases"][0]["provenance"]["analyzer"],
            "valgrind 3.28.0"
        );
        assert_eq!(value["cases"][0]["result"]["outcome"], "LEAK_DETECTED");
        assert_eq!(
            value["cases"][0]["result"]["evidence"],
            "dynamic_secret_dependency"
        );
        assert_eq!(value["cases"][0]["result"]["case"], "c");
    }
}
