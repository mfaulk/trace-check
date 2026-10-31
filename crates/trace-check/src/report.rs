//! Report assembly and rendering.
//!
//! Reports carry their own schema version and the provenance needed to
//! reinterpret them later: toolchain versions, build target and profile, the
//! compiled module's SHA-256, and the trace-parser version.
//!
//! Secret bytes are never included. Case identifiers and mismatch descriptions
//! come from the fixture, so a report says *which* case ran without restating
//! the modeled secret.

use serde::Serialize;

use crate::compare::{Comparison, Outcome};
use crate::experiment::{ComparisonSpec, Experiment};
use crate::runner::{CaseRun, Provenance};

/// JSON report schema version. Bump on any incompatible field change.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

const LIMITATIONS: [&str; 4] = [
    "Findings describe one compiled WASM module executed by one pinned WABT interpreter version.",
    "Only instruction-path equivalence is analyzed: not effective memory addresses, cache behavior, instruction latency, or physical timing.",
    "Matching paths cover the tested inputs only and are not proof of constant-time behavior.",
    "Results do not transfer to a separately compiled native binary or to real hardware.",
];

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub example: String,
    pub provenance: ProvenanceJson,
    pub runs: Vec<RunJson>,
    pub comparisons: Vec<ComparisonJson>,
    pub summary: Summary,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceJson {
    pub rustc_version: String,
    pub cargo_version: String,
    pub wabt_version: String,
    pub target: String,
    pub profile: String,
    pub module_path: String,
    pub module_sha256: String,
    pub trace_parser_version: u32,
    pub cases_schema_version: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunJson {
    pub variant: String,
    pub case: String,
    pub export: String,
    pub events: usize,
    pub decision: String,
    pub expected_decision: String,
    pub deterministic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instability: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonJson {
    pub id: String,
    pub variant: String,
    pub case_a: String,
    pub case_b: String,
    pub expected_outcome: String,
    pub rationale: String,
    #[serde(flatten)]
    pub result: Comparison,
    /// Whether the observed outcome matched the fixture's prediction. A `false`
    /// here is a finding about the fixture or the compiler, not a pass/fail of
    /// the code under test.
    pub matched_expectation: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub comparisons: usize,
    pub differences_detected: usize,
    pub no_difference_observed: usize,
    pub inconclusive: usize,
    pub unmet_expectations: Vec<String>,
    /// True only when every declared expectation was reproduced. This reports
    /// whether the experimental controls held, not that any code is secure.
    pub controls_reproduced: bool,
}

pub fn build(
    experiment: &Experiment,
    provenance: &Provenance,
    runs: &[CaseRun],
    results: &[(ComparisonSpec, Comparison)],
) -> Report {
    let run_entries = runs
        .iter()
        .map(|run| RunJson {
            variant: run.variant.clone(),
            case: run.case.clone(),
            export: run.export.clone(),
            events: run.trace.events.len(),
            decision: run.trace.decision.as_str().to_string(),
            expected_decision: experiment
                .case(&run.case)
                .map(|case| case.expected_decision.clone())
                .unwrap_or_default(),
            deterministic: run.stable,
            instability: run.instability.clone(),
        })
        .collect();

    let comparisons: Vec<ComparisonJson> = results
        .iter()
        .map(|(spec, result)| ComparisonJson {
            id: spec.id.clone(),
            variant: spec.variant.clone(),
            case_a: spec.case_a.clone(),
            case_b: spec.case_b.clone(),
            expected_outcome: spec.expected_outcome.clone(),
            rationale: spec.rationale.clone(),
            matched_expectation: result.outcome.as_str() == spec.expected_outcome,
            result: result.clone(),
        })
        .collect();

    let count = |outcome: Outcome| {
        comparisons
            .iter()
            .filter(|entry| entry.result.outcome == outcome)
            .count()
    };
    let unmet: Vec<String> = comparisons
        .iter()
        .filter(|entry| !entry.matched_expectation)
        .map(|entry| {
            format!(
                "{}: expected {} but observed {}",
                entry.id,
                entry.expected_outcome,
                entry.result.outcome.as_str()
            )
        })
        .collect();

    Report {
        schema_version: REPORT_SCHEMA_VERSION,
        example: experiment.example.clone(),
        provenance: ProvenanceJson {
            rustc_version: provenance.rustc_version.clone(),
            cargo_version: provenance.cargo_version.clone(),
            wabt_version: provenance.wabt_version.clone(),
            target: provenance.target.clone(),
            profile: provenance.profile.clone(),
            module_path: provenance.module_path.display().to_string(),
            module_sha256: provenance.module_sha256.clone(),
            trace_parser_version: provenance.trace_parser_version,
            cases_schema_version: experiment.schema_version,
        },
        summary: Summary {
            comparisons: comparisons.len(),
            differences_detected: count(Outcome::DifferenceDetected),
            no_difference_observed: count(Outcome::NoDifferenceObserved),
            inconclusive: count(Outcome::Inconclusive),
            controls_reproduced: unmet.is_empty()
                && runs.iter().all(|run| run.stable)
                && !comparisons.is_empty(),
            unmet_expectations: unmet,
        },
        runs: run_entries,
        comparisons,
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    }
}

impl Report {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report is serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let line = |out: &mut String, text: &str| {
            out.push_str(text);
            out.push('\n');
        };

        line(
            &mut out,
            &format!(
                "trace-check: {} (instruction-path equivalence)",
                self.example
            ),
        );
        line(
            &mut out,
            &format!(
                "  module {} sha256 {}",
                self.provenance.module_path, self.provenance.module_sha256
            ),
        );
        line(
            &mut out,
            &format!(
                "  {} / {} / {} / wabt {} / parser v{}",
                self.provenance.rustc_version,
                self.provenance.target,
                self.provenance.profile,
                self.provenance.wabt_version,
                self.provenance.trace_parser_version
            ),
        );

        line(&mut out, "");
        line(&mut out, "Runs");
        for run in &self.runs {
            let determinism = if run.deterministic {
                "stable"
            } else {
                "UNSTABLE"
            };
            line(
                &mut out,
                &format!(
                    "  {:<18} case {:<6} {:>6} events  {:<7} {}",
                    run.variant, run.case, run.events, run.decision, determinism
                ),
            );
            if let Some(detail) = &run.instability {
                line(&mut out, &format!("      {detail}"));
            }
        }

        line(&mut out, "");
        line(&mut out, "Comparisons");
        for entry in &self.comparisons {
            let mark = if entry.matched_expectation {
                "ok"
            } else {
                "UNEXPECTED"
            };
            line(
                &mut out,
                &format!(
                    "  [{mark}] {} ({} {} vs {}) -> {}",
                    entry.id,
                    entry.variant,
                    entry.case_a,
                    entry.case_b,
                    entry.result.outcome.as_str()
                ),
            );
            line(&mut out, &format!("      {}", entry.result.message));
            if !entry.matched_expectation {
                line(
                    &mut out,
                    &format!("      fixture expected {}", entry.expected_outcome),
                );
            }
            if let Some(divergence) = &entry.result.divergence {
                for event in &divergence.common_context {
                    line(&mut out, &format!("        common  {event}"));
                }
                for event in divergence.side_a.iter().take(2) {
                    line(&mut out, &format!("        {:<7} {event}", entry.case_a));
                }
                for event in divergence.side_b.iter().take(2) {
                    line(&mut out, &format!("        {:<7} {event}", entry.case_b));
                }
            }
        }

        line(&mut out, "");
        line(
            &mut out,
            &format!(
                "Summary: {} comparisons - {} difference detected, {} no difference observed, {} inconclusive",
                self.summary.comparisons,
                self.summary.differences_detected,
                self.summary.no_difference_observed,
                self.summary.inconclusive
            ),
        );
        if self.summary.controls_reproduced {
            line(&mut out, "Expected experimental controls were reproduced.");
        } else {
            line(
                &mut out,
                "Expected experimental controls were NOT reproduced:",
            );
            for unmet in &self.summary.unmet_expectations {
                line(&mut out, &format!("  - {unmet}"));
            }
            if self.runs.iter().any(|run| !run.deterministic) {
                line(&mut out, "  - at least one case was not deterministic");
            }
        }

        line(&mut out, "");
        line(&mut out, "Limitations");
        for limitation in &self.limitations {
            line(&mut out, &format!("  - {limitation}"));
        }
        out
    }
}
