//! Reporting for the symbolic verification backend.
//!
//! Kept separate from the dynamic backends' reports. The outcome vocabulary and
//! provenance are shared via [`crate::security`]; the evidence is not. A
//! Memcheck diagnostic names a stack and an origin, while a symbolic result
//! names a divergence site, an explored state space, and the bounds the claim
//! is scoped to. Flattening them would lose exactly the information that makes
//! each one interpretable.

use serde::Serialize;

use crate::security::{Evidence, Expectation, Outcome};
use crate::symbolic::{CaseResult, SymbolicProvenance, VerificationCase};

/// JSON report schema version for symbolic analyses.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

const LIMITATIONS: [&str; 7] = [
    "VERIFIED_BOUNDED is scoped to the declared input domain, the exploration bound, and the modeled observations; it claims nothing outside them.",
    "Only control flow and effective memory addresses are modeled. Cache behavior, speculation, operand latency, power and all hardware timing are excluded.",
    "A result describes one artifact built by one compiler at one set of flags; a different build must be re-verified.",
    "The analyzed artifact is a freestanding no_std harness whose inputs are globals. The function under test is ordinary optimized Rust, but its surroundings are not.",
    "The analyzer reports the leaking instruction, not the satisfying model, so concrete secret values are not available as a witness.",
    "A differing execution path is not a measured timing signal; no hardware timing was observed.",
    "Linux x86-64 only. An instruction the analyzer does not model yields INCONCLUSIVE, by design.",
];

#[derive(Debug, Clone, Serialize)]
pub struct CaseReport {
    pub case: String,
    pub description: String,
    pub function: String,
    pub rationale: String,
    /// The declared security lattice, so a reader can see what was treated as
    /// secret rather than inferring it.
    pub secret_globals: Vec<String>,
    pub public_globals: Vec<String>,
    /// `assume` constraints restricting the input domain.
    pub input_domain: Vec<String>,
    pub entry_symbol: String,
    pub halt_symbol: String,
    pub max_depth: u32,
    pub solver_timeout_secs: u32,
    pub evidence: Evidence,
    #[serde(flatten)]
    pub result: CaseResult,
    pub expectation: Expectation,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolicReport {
    pub schema_version: u32,
    pub backend: &'static str,
    pub provenance: SymbolicProvenance,
    pub selected: usize,
    pub executed: usize,
    pub cases: Vec<CaseReport>,
    pub summary: Summary,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub verified_bounded: usize,
    pub leaks_detected: usize,
    pub inconclusive: usize,
    pub unmet_expectations: Vec<String>,
    /// True when every declared expectation was reproduced. Reports that the
    /// analyzer behaved as predicted, not that any code is secure.
    pub expectations_reproduced: bool,
}

pub const BACKEND: &str = "binsec-relational-symbolic";

pub fn build(
    entries: Vec<(VerificationCase, CaseResult)>,
    provenance: SymbolicProvenance,
    selected: usize,
) -> SymbolicReport {
    let cases: Vec<CaseReport> = entries
        .into_iter()
        .map(|(case, result)| {
            let expected = Outcome::parse(&case.expected_outcome)
                .expect("the case file was validated on load");
            CaseReport {
                case: case.id,
                description: case.description,
                function: case.function,
                rationale: case.rationale,
                secret_globals: case.secret_globals,
                public_globals: case.public_globals,
                input_domain: case.assumptions,
                entry_symbol: case.entry_symbol,
                halt_symbol: case.halt_symbol,
                max_depth: case.max_depth,
                solver_timeout_secs: case.solver_timeout_secs,
                evidence: Evidence::BoundedRelationalSymbolic,
                expectation: Expectation::new(expected, result.outcome),
                result,
            }
        })
        .collect();

    let count = |outcome: Outcome| cases.iter().filter(|c| c.result.outcome == outcome).count();
    let unmet: Vec<String> = cases
        .iter()
        .filter(|entry| !entry.expectation.met)
        .map(|entry| {
            format!(
                "{}: expected {} but observed {}",
                entry.case, entry.expectation.expected, entry.expectation.observed
            )
        })
        .collect();

    SymbolicReport {
        schema_version: REPORT_SCHEMA_VERSION,
        backend: BACKEND,
        provenance,
        selected,
        executed: cases.len(),
        summary: Summary {
            verified_bounded: count(Outcome::VerifiedBounded),
            leaks_detected: count(Outcome::LeakDetected),
            inconclusive: count(Outcome::Inconclusive),
            expectations_reproduced: unmet.is_empty() && !cases.is_empty(),
            unmet_expectations: unmet,
        },
        cases,
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    }
}

impl SymbolicReport {
    /// A leak outranks an incomplete analysis, so the code names the most
    /// serious outcome while the report keeps everything.
    pub fn exit_code(&self) -> u8 {
        if !self.summary.expectations_reproduced {
            if self
                .cases
                .iter()
                .any(|case| case.result.outcome == Outcome::LeakDetected && !case.expectation.met)
            {
                return 1;
            }
            return 2;
        }
        0
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("symbolic report is serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        macro_rules! line {
            ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
        }

        line!("Backend:  {}", self.backend);
        line!("Analyzer: {}", self.provenance.analyzer);
        if let Some(build) = &self.provenance.analyzer_build {
            line!("Build:    {build}");
        }
        line!("Image:    {}", self.provenance.analyzer_image);
        line!("Solver:   {}", self.provenance.solver);
        line!("Target:   {}", self.provenance.target);
        line!("Compiler: {}", self.provenance.rustc_version);
        line!(
            "Artifact: {} sha256 {}",
            self.provenance.artifact_path,
            self.provenance.artifact_sha256
        );
        line!("");
        line!(
            "Verifying {} case{}",
            self.cases.len(),
            if self.cases.len() == 1 { "" } else { "s" }
        );

        for entry in &self.cases {
            let mark = if entry.expectation.met {
                "ok"
            } else {
                "UNEXPECTED"
            };
            line!("");
            line!("Case: {}", entry.case);
            if !entry.description.is_empty() {
                line!("  {}", entry.description);
            }
            line!("");
            line!("Function:");
            line!("  {}", entry.function);
            line!("");
            line!("Declared inputs:");
            line!("  secret: {}", entry.secret_globals.join(", "));
            line!(
                "  public: {}",
                if entry.public_globals.is_empty() {
                    "(none)".to_string()
                } else {
                    entry.public_globals.join(", ")
                }
            );
            if !entry.input_domain.is_empty() {
                line!("  domain: {}", entry.input_domain.join(" and "));
            }

            line!("");
            line!("Result:");
            line!("  {}", entry.result.outcome);
            line!("  {}", entry.result.message);

            if !entry.result.divergences.is_empty() {
                line!("");
                line!("Divergence:");
                for divergence in &entry.result.divergences {
                    line!("  {} at {}", divergence.description, divergence.instruction);
                    if let Some(source) = &divergence.source {
                        line!("    {source}");
                    }
                    // The innermost frame is what an objdump of the artifact
                    // agrees with, so the chain is shown when it is not
                    // trivial.
                    if divergence.inline_frames.len() > 1 {
                        line!(
                            "    inlined through: {}",
                            divergence.inline_frames.join(" <- ")
                        );
                    }
                }
                line!("");
                line!("Witness:");
                line!("  concrete inputs: {}", entry.result.witness.as_str());
                if let Some(detail) = &entry.result.witness_detail {
                    line!("    {detail}");
                }
            }

            let stats = &entry.result.exploration;
            line!("");
            line!("Analysis:");
            line!(
                "  paths {} of {} explored, {} pending",
                render(stats.completed_paths),
                render(stats.total_paths),
                render(stats.pending_paths)
            );
            line!(
                "  checks: {} / {} control flow, {} / {} memory access",
                render(stats.control_flow_checks_passed),
                render(stats.control_flow_checks_total),
                render(stats.memory_checks_passed),
                render(stats.memory_checks_total)
            );
            line!(
                "  unknown solver answers {}, depth bound {}, max depth reached {}",
                render(stats.unknown_queries),
                entry.max_depth,
                render(stats.max_path_depth)
            );
            line!("  exploration complete: {}", stats.is_complete());
            line!("  [{mark}] case expected {}", entry.expectation.expected);
        }

        line!("");
        line!(
            "Summary: {} verified bounded, {} leak detected, {} inconclusive",
            self.summary.verified_bounded,
            self.summary.leaks_detected,
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
        line!("What this does and does not establish");
        for limitation in &self.limitations {
            line!("  - {limitation}");
        }
        out
    }
}

fn render(value: Option<u64>) -> String {
    value.map_or_else(|| "?".to_string(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::{CheckFeature, Divergence, Exploration, WitnessStatus};

    fn provenance() -> SymbolicProvenance {
        SymbolicProvenance {
            rustc_version: "rustc 1.97.0".into(),
            analyzer: crate::symbolic::ANALYZER_NAME.into(),
            analyzer_build: Some("Binsec version dfe4739".into()),
            analyzer_image: crate::symbolic::ANALYZER_IMAGE.into(),
            solver: crate::symbolic::ANALYZER_SOLVER.into(),
            container_tool: "podman".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            build_flags: "-O -g".into(),
            artifact_path: "/tmp/targets".into(),
            artifact_sha256: "abc123".into(),
        }
    }

    fn case(id: &str, expected: &str) -> VerificationCase {
        VerificationCase {
            id: id.into(),
            description: "d".into(),
            function: "f".into(),
            entry_symbol: "tc_harness_f".into(),
            halt_symbol: "tc_halt".into(),
            secret_globals: vec!["TC_SECRET".into()],
            public_globals: vec!["TC_TABLE".into()],
            assumptions: vec!["TC_PUBLIC < 4".into()],
            features: vec![],
            max_depth: 2000,
            solver_timeout_secs: 30,
            wall_timeout_secs: 900,
            expected_outcome: expected.into(),
            rationale: "r".into(),
        }
    }

    fn complete_stats() -> Exploration {
        Exploration {
            total_paths: Some(2),
            completed_paths: Some(2),
            pending_paths: Some(0),
            unknown_queries: Some(0),
            max_path_depth: Some(80),
            control_flow_checks_passed: Some(3),
            control_flow_checks_total: Some(3),
            memory_checks_passed: Some(33),
            memory_checks_total: Some(34),
            analyzer_status: Some("insecure".into()),
        }
    }

    fn result(id: &str, outcome: Outcome, divergences: Vec<Divergence>) -> CaseResult {
        CaseResult {
            case: id.into(),
            function: "f".into(),
            artifact_sha256: "a".repeat(64),
            outcome,
            message: "m".into(),
            divergences,
            witness: WitnessStatus::UnavailableFromAnalyzer,
            witness_detail: Some("the analyzer does not expose the model".into()),
            exploration: complete_stats(),
            script: "starting from <tc_harness_f>\n".into(),
        }
    }

    fn divergence() -> Divergence {
        Divergence {
            kind: CheckFeature::MemoryAccess,
            description: "Secret-dependent memory access".into(),
            instruction: "0x2016b3".into(),
            source: Some("secret_lookup (targets.rs:47)".into()),
            inline_frames: vec![
                "core::ptr::read_volatile::<u8> (mod.rs:2107)".into(),
                "secret_lookup (targets.rs:47)".into(),
            ],
        }
    }

    /// A reproduced leak expectation exits 0: the fixture asserts the analyzer
    /// found the vulnerability, which it did.
    #[test]
    fn a_reproduced_leak_expectation_exits_zero() {
        let report = build(
            vec![(
                case("table-lookup", "LEAK_DETECTED"),
                result("table-lookup", Outcome::LeakDetected, vec![divergence()]),
            )],
            provenance(),
            1,
        );
        assert!(report.summary.expectations_reproduced);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.summary.leaks_detected, 1);
    }

    /// An unexpected leak exits 1.
    #[test]
    fn an_unexpected_leak_exits_one() {
        let report = build(
            vec![(
                case("masked-scan", "VERIFIED_BOUNDED"),
                result("masked-scan", Outcome::LeakDetected, vec![divergence()]),
            )],
            provenance(),
            1,
        );
        assert_eq!(report.exit_code(), 1);
        assert!(!report.summary.expectations_reproduced);
    }

    /// An unexpected inconclusive result exits 2 and is not called a leak.
    #[test]
    fn an_unexpected_inconclusive_exits_two() {
        let report = build(
            vec![(
                case("masked-scan", "VERIFIED_BOUNDED"),
                result("masked-scan", Outcome::Inconclusive, vec![]),
            )],
            provenance(),
            1,
        );
        assert_eq!(report.exit_code(), 2);
        assert_eq!(report.summary.leaks_detected, 0);
        assert_eq!(report.summary.inconclusive, 1);
    }

    /// A case that declares INCONCLUSIVE passes when that is what happens, so
    /// the fail-closed path has a green regression test.
    #[test]
    fn a_declared_inconclusive_case_passes() {
        let report = build(
            vec![(
                case("depth-bounded", "INCONCLUSIVE"),
                result("depth-bounded", Outcome::Inconclusive, vec![]),
            )],
            provenance(),
            1,
        );
        assert!(report.summary.expectations_reproduced);
        assert_eq!(report.exit_code(), 0);
    }

    /// Verifying nothing is not a pass.
    #[test]
    fn verifying_nothing_is_not_a_pass() {
        let report = build(vec![], provenance(), 0);
        assert!(!report.summary.expectations_reproduced);
        assert_eq!(report.exit_code(), 2);
    }

    /// Text output carries the divergence site, its source location, and the
    /// witness status — the fields that make a finding actionable.
    #[test]
    fn text_output_is_actionable() {
        let report = build(
            vec![(
                case("table-lookup", "LEAK_DETECTED"),
                result("table-lookup", Outcome::LeakDetected, vec![divergence()]),
            )],
            provenance(),
            1,
        );
        let text = report.to_text();
        for expected in [
            "Backend:  binsec-relational-symbolic",
            "Case: table-lookup",
            "LEAK_DETECTED",
            "Secret-dependent memory access at 0x2016b3",
            "secret_lookup (targets.rs:47)",
            // The outermost frame leads; the chain back to the artifact
            // follows, because that is what an objdump agrees with.
            "inlined through: core::ptr::read_volatile::<u8> (mod.rs:2107)",
            "concrete inputs: unavailable_from_analyzer",
            "sha256 abc123",
            "secret: TC_SECRET",
            "domain: TC_PUBLIC < 4",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    /// The report states the proof scope and never implies hardware timing was
    /// measured.
    #[test]
    fn the_report_states_its_proof_scope() {
        let report = build(
            vec![(
                case("masked-scan", "VERIFIED_BOUNDED"),
                result("masked-scan", Outcome::VerifiedBounded, vec![]),
            )],
            provenance(),
            1,
        );
        let text = report.to_text();
        assert!(text.contains("scoped to the declared input domain"));
        assert!(text.contains("not a measured timing signal"));
        assert!(text.contains("exploration complete: true"));
    }

    /// The JSON report carries schema, provenance, bounds, declared inputs and
    /// exploration statistics, so a result can be reproduced and audited.
    #[test]
    fn json_report_is_complete() {
        let report = build(
            vec![(
                case("conditional-lookup", "LEAK_DETECTED"),
                result(
                    "conditional-lookup",
                    Outcome::LeakDetected,
                    vec![divergence()],
                ),
            )],
            provenance(),
            1,
        );
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(value["backend"], BACKEND);
        assert!(value["provenance"]["analyzer_image"]
            .as_str()
            .unwrap()
            .contains("@sha256:"));
        assert_eq!(value["provenance"]["artifact_sha256"], "abc123");
        let entry = &value["cases"][0];
        assert_eq!(entry["outcome"], "LEAK_DETECTED");
        assert_eq!(entry["evidence"], "bounded_relational_symbolic");
        assert_eq!(entry["secret_globals"][0], "TC_SECRET");
        assert_eq!(entry["input_domain"][0], "TC_PUBLIC < 4");
        assert_eq!(entry["max_depth"], 2000);
        assert_eq!(entry["witness"], "unavailable_from_analyzer");
        assert_eq!(entry["divergences"][0]["instruction"], "0x2016b3");
        assert_eq!(entry["exploration"]["total_paths"], 2);
        assert!(!entry["script"].as_str().unwrap().is_empty());
        assert!(value["limitations"].as_array().unwrap().len() >= 7);
    }
}
