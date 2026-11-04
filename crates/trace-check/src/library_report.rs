//! Reporting for contract verification against a real library.
//!
//! Separate from [`crate::symbolic_report`] because the evidence is different.
//! An M4 case report names a hand-written target source; a contract report
//! names a package, a lockfile fingerprint, a feature set, the mangled symbol
//! the contract resolved to, and a generated harness — and it has to say, in
//! words and in a field, that the analyzed executable is **not** the
//! production binary.
//!
//! The analysis result is nested under `analysis` rather than flattened. M4
//! learned that `#[serde(flatten)]` over a struct repeating an outer field
//! emits duplicate JSON keys that most parsers silently resolve to the last
//! occurrence; nesting makes the collision impossible instead of testing for
//! it.
//!
//! # Report-level provenance says who analyzed, never what
//!
//! A run builds one executable per contract, so there is no single artifact a
//! report can describe. [`LibraryReport::analyzer`] therefore carries only the
//! analyzer, its solver, the container runtime and the platform; the artifact
//! hash, the build flags, the lockfile fingerprint and the resolved symbol are
//! per contract. An earlier revision put M4's `SymbolicProvenance` at report
//! level, which advertised the **last** contract's executable — and M4's
//! direct-`rustc` build flags, which M5 does not use — as though they described
//! the whole run.

use serde::Serialize;

use crate::contract::Contract;
use crate::harness::{Harness, Library, ResolvedSymbol, SymbolicInput};
use crate::security::{Evidence, Expectation, Outcome};
use crate::symbolic::{AnalyzerIdentity, CaseResult, VerificationCase};
use crate::symbolic_report::Summary;

pub const REPORT_SCHEMA_VERSION: u32 = 1;

pub const BACKEND: &str = "binsec-relational-symbolic";

/// What the analyzed executable is, stated rather than left to inference.
pub const PRODUCTION_ARTIFACT: &str =
    "not analyzed: this result describes the generated verification executable below, not any \
     production binary built from the same library";

const LIMITATIONS: [&str; 12] = [
    "VERIFIED_BOUNDED is scoped to the declared input domain, the exploration bound, and the modeled observations; it claims nothing outside them.",
    "The analyzed function is the library's own, compiled from the single definition in its source. It is not the machine code of a production binary: see the three artifact-boundary limitations below.",
    "The target is called through a laundered function pointer, so the verified instance is an out-of-line copy. A production caller that inlines the function gets code this run did not analyze. Without this the function would be dissolved by cross-crate inlining and nothing could be attributed to it.",
    "The surroundings are a freestanding no_std executable whose inputs are named globals. The function under test is ordinary optimized Rust; its callers and its memory layout are not.",
    "The verification build uses no LTO, panic=abort and static relocation. A production profile with lto = true is a different artifact and must be re-verified.",
    "A result covers only the observation classes the contract's configuration declared. Read `checked_features` and `unchecked_properties`: control-flow noninterference alone says nothing about secret-dependent addresses.",
    "A result is attributed to a function only when the contract resolved to exactly one symbol and the analyzer reported reaching it.",
    "Only control flow and effective memory addresses are modeled. Cache behavior, speculation, operand latency, power and all hardware timing are excluded.",
    "A concrete counterexample is reported only when the analyzer issued a relational satisfiability query and recorded its model.",
    "A reported counterexample contains the declared secret's values. Verify synthetic inputs; never point verification at a real key.",
    "A differing execution path is not a measured timing signal; no hardware timing was observed.",
    "Linux x86-64 only. An instruction the analyzer does not model yields INCONCLUSIVE, by design.",
];

/// The build a result describes.
#[derive(Debug, Clone, Serialize)]
pub struct Compilation {
    pub rustc: String,
    pub target: String,
    pub profile: String,
    pub panic: String,
    pub rustflags: String,
    pub lto: bool,
}

/// The generated wrapper, kept verbatim so a result can be reproduced without
/// this tool.
#[derive(Debug, Clone, Serialize)]
pub struct HarnessProvenance {
    pub entry_symbol: String,
    pub halt_symbol: String,
    pub output_global: String,
    pub sha256: String,
    pub call_shape: &'static str,
    pub source: String,
}

/// The verification executable, and what it is not.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactProvenance {
    pub path: String,
    pub sha256: String,
    /// Fingerprint of the harness's resolved dependency graph.
    pub lockfile_sha256: String,
    /// Whether [`ArtifactProvenance::path`] still exists after the run. The
    /// default workspace is a private directory that is removed, so the hash
    /// is the durable identity and a reader is told which they have.
    pub path_retained: bool,
    pub production_artifact: &'static str,
}

/// The contract-to-instruction binding, with the analyzer's own arrival
/// evidence.
#[derive(Debug, Clone, Serialize)]
pub struct SymbolBinding {
    pub contract: String,
    pub mangled: String,
    pub address: String,
    /// Whether the analyzer reported reaching it.
    pub reached: bool,
    /// Where it reported reaching it, which may differ from the symbol's own
    /// address if the analyzer arrived mid-function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reached_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContractReport {
    pub contract: String,
    pub module: String,
    pub function: String,
    /// `file:line` of the annotation in the developer's own source.
    pub declared_at: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rationale: String,
    pub library: Library,
    pub compilation: Compilation,
    pub symbol: SymbolBinding,
    pub harness: HarnessProvenance,
    pub artifact: ArtifactProvenance,
    /// Roles and widths as transferred from the annotation into the analysis.
    pub inputs: Vec<SymbolicInput>,
    /// The developer's own `assume` constraints, verbatim.
    pub input_domain: Vec<String>,
    /// Restrictions the generator had to add for the analyzed domain to match
    /// Rust's valid values — a `bool` parameter is one byte with two valid
    /// values, and a symbolic byte has 256. Listed separately so the
    /// developer's own constraints stay verbatim.
    pub generated_domain: Vec<String>,
    pub max_depth: u32,
    pub solver_timeout_secs: u32,
    pub evidence: Evidence,
    /// The symbolic analysis, from the engine M4 built.
    pub analysis: CaseResult,
    pub expectation: Expectation,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibraryReport {
    pub schema_version: u32,
    pub backend: &'static str,
    /// Who did the analyzing. Carries no artifact identity: a run builds one
    /// executable per contract, and those live on each contract.
    pub analyzer: AnalyzerIdentity,
    pub selected: usize,
    pub executed: usize,
    pub contracts: Vec<ContractReport>,
    pub summary: Summary,
    pub limitations: Vec<String>,
}

/// Everything one verified contract contributes to a report.
pub struct Verified {
    pub contract: Contract,
    pub case: VerificationCase,
    pub library: Library,
    pub symbol: ResolvedSymbol,
    pub harness: Harness,
    pub artifact: crate::harness::Artifact,
    pub result: CaseResult,
}

/// One verified contract's whole record, with its provenance intact.
///
/// Extracted from [`build`] so a unified run can hold a single contract's
/// symbolic evidence without assembling a standalone report around it. A
/// symbolic requirement is discharged by this value, not by the string
/// `VERIFIED_BOUNDED`: it carries the artifact the result describes, the symbol
/// it was attributed to, the evidence that the analyzer reached it, the declared
/// and generated input domain, the observation classes checked, and the depth
/// bound the search held to.
pub fn contract_report(
    entry: Verified,
    analyzer: &AnalyzerIdentity,
    path_retained: bool,
) -> ContractReport {
    let expected = Outcome::parse(&entry.case.expected_outcome)
        .expect("the configuration was validated on load");
    ContractReport {
        contract: entry.contract.id.clone(),
        module: entry.contract.module.clone(),
        function: entry.contract.function.clone(),
        declared_at: entry.contract.site.clone(),
        description: entry.case.description.clone(),
        rationale: entry.case.rationale.clone(),
        library: entry.library,
        compilation: Compilation {
            rustc: analyzer.rustc_version.clone(),
            target: crate::symbolic::SUPPORTED_TARGET.to_string(),
            profile: crate::harness::PROFILE.to_string(),
            panic: crate::harness::PANIC_STRATEGY.to_string(),
            rustflags: crate::harness::RUSTFLAGS.join(" "),
            lto: false,
        },
        symbol: SymbolBinding {
            contract: entry.symbol.contract.clone(),
            mangled: entry.symbol.mangled.clone(),
            address: entry.symbol.address.clone(),
            reached: entry.result.target.reached,
            reached_at: entry.result.target.address.clone(),
        },
        harness: HarnessProvenance {
            entry_symbol: entry.case.entry_symbol.clone(),
            halt_symbol: entry.case.halt_symbol.clone(),
            output_global: crate::harness::OUTPUT_GLOBAL.to_string(),
            sha256: entry.harness.source_sha256.clone(),
            call_shape: "laundered function pointer (out-of-line instance)",
            source: entry.harness.source.clone(),
        },
        artifact: ArtifactProvenance {
            path: entry.artifact.path.display().to_string(),
            sha256: entry.artifact.sha256.clone(),
            lockfile_sha256: entry.artifact.lockfile_sha256.clone(),
            path_retained,
            production_artifact: PRODUCTION_ARTIFACT,
        },
        generated_domain: entry.harness.generated_assumptions.clone(),
        inputs: entry.harness.inputs.clone(),
        input_domain: entry
            .case
            .assumptions
            .iter()
            .filter(|assumption| !entry.harness.generated_assumptions.contains(assumption))
            .cloned()
            .collect(),
        max_depth: entry.case.max_depth,
        solver_timeout_secs: entry.case.solver_timeout_secs,
        evidence: Evidence::BoundedRelationalSymbolic,
        expectation: Expectation::new(expected, entry.result.outcome),
        analysis: entry.result,
    }
}

pub fn build(
    entries: Vec<Verified>,
    analyzer: AnalyzerIdentity,
    selected: usize,
    path_retained: bool,
) -> LibraryReport {
    let contracts: Vec<ContractReport> = entries
        .into_iter()
        .map(|entry| contract_report(entry, &analyzer, path_retained))
        .collect();

    let count = |outcome: Outcome| {
        contracts
            .iter()
            .filter(|entry| entry.analysis.outcome == outcome)
            .count()
    };
    let unmet: Vec<String> = contracts
        .iter()
        .filter(|entry| !entry.expectation.met)
        .map(|entry| {
            format!(
                "{}: expected {} but observed {}",
                entry.contract, entry.expectation.expected, entry.expectation.observed
            )
        })
        .collect();

    LibraryReport {
        schema_version: REPORT_SCHEMA_VERSION,
        backend: BACKEND,
        analyzer,
        selected,
        executed: contracts.len(),
        summary: Summary {
            verified_bounded: count(Outcome::VerifiedBounded),
            leaks_detected: count(Outcome::LeakDetected),
            inconclusive: count(Outcome::Inconclusive),
            expectations_reproduced: unmet.is_empty() && !contracts.is_empty(),
            unmet_expectations: unmet,
        },
        contracts,
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    }
}

impl LibraryReport {
    /// A leak outranks an incomplete analysis, so the exit code names the most
    /// serious outcome while the report keeps everything.
    pub fn exit_code(&self) -> u8 {
        if !self.summary.expectations_reproduced {
            if self.contracts.iter().any(|entry| {
                entry.analysis.outcome == Outcome::LeakDetected && !entry.expectation.met
            }) {
                return 1;
            }
            return 2;
        }
        0
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("library report is serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        macro_rules! line {
            ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
        }

        line!("Backend:  {}", self.backend);
        line!("Analyzer: {}", self.analyzer.analyzer);
        if let Some(build) = &self.analyzer.analyzer_build {
            line!("Build:    {build}");
        }
        line!("Image:    {}", self.analyzer.analyzer_image);
        line!("Solver:   {}", self.analyzer.solver);
        line!("Runtime:  {}", self.analyzer.container_tool);
        // Deliberately no artifact here: there is one per contract below.

        for entry in &self.contracts {
            let mark = if entry.expectation.met {
                "ok"
            } else {
                "UNEXPECTED"
            };
            line!("");
            line!("Verifying {}", entry.contract);
            if !entry.description.is_empty() {
                line!("  {}", entry.description);
            }
            line!("");
            line!("Library:");
            line!(
                "  Package:        {} {}",
                entry.library.package,
                entry.library.version
            );
            line!(
                "  Contract:       {}  ({})",
                entry.contract,
                entry.declared_at
            );
            line!(
                "  Cargo features: {}",
                if entry.library.features.is_empty() {
                    "(default)".to_string()
                } else {
                    entry.library.features.join(", ")
                }
            );
            line!(
                "  Lockfile:       sha256 {}",
                entry.artifact.lockfile_sha256
            );
            line!("");
            line!("Compilation:");
            line!("  rustc:          {}", entry.compilation.rustc);
            line!("  Target:         {}", entry.compilation.target);
            line!("  Profile:        {}", entry.compilation.profile);
            line!("  Panic strategy: {}", entry.compilation.panic);
            line!("  Link:           {}", entry.compilation.rustflags);
            line!("");
            line!("Analyzed function:");
            line!("  Contract:        {}", entry.symbol.contract);
            line!("  Resolved symbol: {}", entry.symbol.mangled);
            line!("  Address:         {}", entry.symbol.address);
            // From the analyzer, not from the declaration.
            match (&entry.symbol.reached, &entry.symbol.reached_at) {
                (true, Some(address)) => line!(
                    "  Target reached:  yes, at {address} from {} (analyzer-reported)",
                    entry.harness.entry_symbol
                ),
                (true, None) => line!("  Target reached:  yes (analyzer-reported)"),
                (false, _) => line!("  Target reached:  NO -- nothing here is attributed to it"),
            }
            line!("  Call shape:      {}", entry.harness.call_shape);
            line!("");
            line!("Verification executable:");
            line!("  Harness sha256:    {}", entry.harness.sha256);
            line!("  Artifact sha256:   {}", entry.artifact.sha256);
            // Whether the recorded path still exists. The default workspace is
            // a private directory that is removed, so the hash is the durable
            // identity and a reader is told which they have.
            line!(
                "  Artifact path:     {} ({})",
                entry.artifact.path,
                if entry.artifact.path_retained {
                    "retained"
                } else {
                    "removed after the run; the hash is the durable identity"
                }
            );
            line!(
                "  Production binary: {}",
                entry.artifact.production_artifact
            );
            line!("");
            line!("Input domain:");
            for input in &entry.inputs {
                line!(
                    "  {:<10} {:<7} {:<12} {} bits, {}",
                    input.parameter,
                    input.role.as_str(),
                    input.repr,
                    input.bits,
                    if input.role == crate::contract::Role::Secret {
                        "all symbolic"
                    } else {
                        "symbolic and held equal"
                    }
                );
            }
            if !entry.input_domain.is_empty() {
                line!("  assumed:   {}", entry.input_domain.join(" and "));
            }
            if !entry.generated_domain.is_empty() {
                line!(
                    "  generated: {}  (so the analyzed domain is Rust's valid values)",
                    entry.generated_domain.join(" and ")
                );
            }
            line!("");
            line!("Observation model:");
            line!(
                "  checked:     {}",
                if entry.analysis.checked_features.is_empty() {
                    "(none)".to_string()
                } else {
                    entry
                        .analysis
                        .checked_features
                        .iter()
                        .map(|feature| feature.property())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            line!(
                "  NOT checked: {}",
                if entry.analysis.unchecked_properties.is_empty() {
                    "(nothing -- every modeled property was checked)".to_string()
                } else {
                    entry.analysis.unchecked_properties.join(", ")
                }
            );
            line!("");
            line!("Result: {}", entry.analysis.outcome);
            line!("  {}", entry.analysis.message);

            if !entry.analysis.divergences.is_empty() {
                line!("");
                line!("Divergence:");
                for divergence in &entry.analysis.divergences {
                    line!("  {} at {}", divergence.description, divergence.instruction);
                    if let Some(source) = &divergence.source {
                        line!("    {source}");
                    }
                    if divergence.inline_frames.len() > 1 {
                        line!(
                            "    inlined through: {}",
                            divergence.inline_frames.join(" <- ")
                        );
                    }
                }
                line!("");
                line!("Witness:");
                line!("  concrete inputs: {}", entry.analysis.witness.as_str());
                if let Some(detail) = &entry.analysis.witness_detail {
                    line!("    {detail}");
                }
                for counterexample in &entry.analysis.counterexamples {
                    line!(
                        "  {} = {} vs {}  (from {})",
                        counterexample.global,
                        counterexample.left,
                        counterexample.right,
                        counterexample.query
                    );
                }
            }

            let stats = &entry.analysis.exploration;
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
            line!(
                "  [{mark}] contract expected {}",
                entry.expectation.expected
            );
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

/// A clean symbolic record for the enforcement tests, built through the real
/// mapping so a field that stops being carried breaks them too.
#[cfg(test)]
pub(crate) fn sample_contract_report() -> ContractReport {
    contract_report(
        tests::verified(Outcome::VerifiedBounded, "VERIFIED_BOUNDED", Vec::new()),
        &tests::analyzer(),
        false,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::contract::{Descriptor, Role};
    use crate::harness::Artifact;
    use crate::symbolic::{CheckFeature, Divergence, Exploration, TargetEvidence, WitnessStatus};
    use std::path::PathBuf;

    const VERIFY_TAG: &str = r#"{"schema_version":1,"function":"verify_tag","parameters":[{"name":"expected","position":0,"role":"secret","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"},{"name":"supplied","position":1,"role":"public","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"}],"returns":{"repr":"bool","rust_type":"bool"}}"#;

    pub(crate) fn analyzer() -> AnalyzerIdentity {
        AnalyzerIdentity {
            rustc_version: "rustc 1.97.0".into(),
            analyzer: crate::symbolic::ANALYZER_NAME.into(),
            analyzer_build: Some("Binsec version dfe4739".into()),
            analyzer_image: crate::symbolic::ANALYZER_IMAGE.into(),
            solver: crate::symbolic::ANALYZER_SOLVER.into(),
            container_tool: "podman".into(),
            target: crate::symbolic::SUPPORTED_TARGET.into(),
        }
    }

    pub(crate) fn verified(
        outcome: Outcome,
        expected: &str,
        divergences: Vec<Divergence>,
    ) -> Verified {
        let contract = Contract {
            id: "crypto::tag::verify_tag".into(),
            module: "crypto::tag".into(),
            function: "verify_tag".into(),
            site: "src/tag.rs:21".into(),
            descriptor: Descriptor::parse(VERIFY_TAG).expect("parses"),
            descriptor_json: VERIFY_TAG.into(),
        };
        let library = Library {
            package: "crypto-library".into(),
            version: "0.1.0".into(),
            lib_name: "crypto".into(),
            manifest_path: "/w/examples/crypto-library/Cargo.toml".into(),
            features: Vec::new(),
        };
        let harness = crate::harness::generate(&library, &contract).expect("generated");
        let symbol = ResolvedSymbol {
            contract: contract.id.clone(),
            mangled: "_RNvCs1_6crypto3tag10verify_tag".into(),
            address: "0x2012b0".into(),
        };
        let settings = crate::contract::ContractSettings {
            description: "constant-time tag comparison".into(),
            rationale: "folds every byte".into(),
            max_depth: 4000,
            solver_timeout_secs: 30,
            wall_timeout_secs: 900,
            checks: vec![CheckFeature::ControlFlow, CheckFeature::MemoryAccess],
            assumptions: Vec::new(),
            expected_outcome: expected.into(),
            inputs: Default::default(),
        };
        let case = crate::harness::verification_case(&contract, &symbol, &harness, &settings);
        let result = CaseResult {
            case: contract.id.clone(),
            function: symbol.mangled.clone(),
            target: TargetEvidence {
                function: symbol.mangled.clone(),
                entry_symbol: crate::harness::ENTRY_SYMBOL.into(),
                reached: true,
                address: Some("0x2012b0".into()),
                directive: format!("reach <{}>", symbol.mangled),
            },
            checked_features: vec![CheckFeature::ControlFlow, CheckFeature::MemoryAccess],
            unchecked_properties: Vec::new(),
            artifact_sha256: "7d41".into(),
            outcome,
            message: "established".into(),
            divergences,
            witness: WitnessStatus::UnavailableFromAnalyzer,
            witness_detail: Some("no relational query was issued".into()),
            counterexamples: Vec::new(),
            exploration: Exploration {
                total_paths: Some(1),
                completed_paths: Some(1),
                pending_paths: Some(0),
                unknown_queries: Some(0),
                max_path_depth: Some(294),
                control_flow_checks_passed: Some(18),
                control_flow_checks_total: Some(18),
                memory_checks_passed: Some(221),
                memory_checks_total: Some(221),
                analyzer_status: Some("secure".into()),
            },
            script: "starting from <tc_verify_entry>\n".into(),
        };
        Verified {
            contract,
            case,
            library,
            symbol,
            harness,
            artifact: Artifact {
                path: PathBuf::from("/tmp/tc-verify-harness"),
                sha256: "7d41".into(),
                lockfile_sha256: "3f0a".into(),
            },
            result,
        }
    }

    fn divergence() -> Divergence {
        Divergence {
            kind: CheckFeature::ControlFlow,
            description: "Secret-dependent control flow".into(),
            instruction: "0x2016f5".into(),
            source: Some("crypto::tag::verify_tag_volatile_early_exit (tag.rs:55)".into()),
            inline_frames: Vec::new(),
        }
    }

    /// A reproduced expectation exits 0, and the summary counts the outcome.
    #[test]
    fn a_reproduced_expectation_exits_zero() {
        let report = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.summary.verified_bounded, 1);
        assert!(report.summary.expectations_reproduced);
    }

    /// An unexpected leak exits 1; an unexpected inconclusive exits 2.
    #[test]
    fn unexpected_outcomes_choose_the_right_exit_code() {
        let leaked = build(
            vec![verified(
                Outcome::LeakDetected,
                "VERIFIED_BOUNDED",
                vec![divergence()],
            )],
            analyzer(),
            1,
            false,
        );
        assert_eq!(leaked.exit_code(), 1);
        let inconclusive = build(
            vec![verified(Outcome::Inconclusive, "VERIFIED_BOUNDED", vec![])],
            analyzer(),
            1,
            false,
        );
        assert_eq!(inconclusive.exit_code(), 2);
    }

    /// Verifying nothing is not a pass.
    #[test]
    fn verifying_nothing_is_not_a_pass() {
        let report = build(vec![], analyzer(), 0, false);
        assert_eq!(report.exit_code(), 2);
        assert!(!report.summary.expectations_reproduced);
    }

    /// The text report names the library, the contract's own declaration site,
    /// the resolved symbol, both hashes, and the roles and widths of the
    /// symbolic inputs.
    #[test]
    fn the_text_report_connects_source_to_artifact() {
        let report = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        let text = report.to_text();
        for expected in [
            "Verifying crypto::tag::verify_tag",
            "Package:        crypto-library 0.1.0",
            "src/tag.rs:21",
            "Resolved symbol: _RNvCs1_6crypto3tag10verify_tag",
            "Target reached:  yes, at 0x2012b0 from tc_verify_entry (analyzer-reported)",
            "Call shape:      laundered function pointer (out-of-line instance)",
            "Harness sha256:",
            "Artifact sha256:   7d41",
            "Lockfile:       sha256 3f0a",
            "expected   secret  &[u8; 16]    128 bits, all symbolic",
            "supplied   public  &[u8; 16]    128 bits, symbolic and held equal",
            "Result: VERIFIED_BOUNDED",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
        }
    }

    /// The report never implies the production binary was analyzed, and says so
    /// where a reader will see it.
    #[test]
    fn the_report_disclaims_the_production_binary() {
        let report = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        let text = report.to_text();
        assert!(text.contains("Production binary: not analyzed"), "{text}");
        assert!(text.contains("out-of-line copy"), "{text}");
        assert!(text.contains("not a measured timing signal"), "{text}");
    }

    /// A contract the analyzer never reached is visible as such, so a reader
    /// cannot mistake the run for an attributed one.
    #[test]
    fn an_unreached_target_is_visible() {
        let mut entry = verified(Outcome::Inconclusive, "VERIFIED_BOUNDED", vec![]);
        entry.result.target.reached = false;
        entry.result.target.address = None;
        let report = build(vec![entry], analyzer(), 1, false);
        let text = report.to_text();
        assert!(text.contains("Target reached:  NO"), "{text}");
        assert!(text.contains("nothing here is attributed to it"), "{text}");
        assert!(!report.contracts[0].symbol.reached);
    }

    /// The JSON report carries the whole chain from the developer's source to
    /// the analyzed executable, plus the roles and widths that were marked.
    #[test]
    fn the_json_report_carries_the_whole_chain() {
        let report = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        assert_eq!(value["schema_version"], REPORT_SCHEMA_VERSION);
        assert_eq!(value["backend"], BACKEND);
        let entry = &value["contracts"][0];
        assert_eq!(entry["contract"], "crypto::tag::verify_tag");
        assert_eq!(entry["declared_at"], "src/tag.rs:21");
        assert_eq!(entry["library"]["package"], "crypto-library");
        assert_eq!(entry["compilation"]["lto"], false);
        assert_eq!(entry["compilation"]["panic"], "abort");
        assert_eq!(entry["symbol"]["reached"], true);
        assert_eq!(entry["inputs"][0]["role"], "secret");
        assert_eq!(entry["inputs"][0]["bits"], 128);
        assert_eq!(entry["inputs"][1]["role"], "public");
        assert_eq!(entry["analysis"]["outcome"], "VERIFIED_BOUNDED");
        assert_eq!(entry["evidence"], "bounded_relational_symbolic");
        assert!(entry["artifact"]["production_artifact"]
            .as_str()
            .unwrap()
            .contains("not analyzed"));
        // The generated harness is kept verbatim, which is what makes the
        // evidence bundle reproducible without this tool.
        assert!(entry["harness"]["source"]
            .as_str()
            .unwrap()
            .contains("crypto::tag::verify_tag"));
        assert!(value["limitations"].as_array().unwrap().len() >= 10);
    }

    /// A serialized contract object carries each key once. The analysis is
    /// nested rather than flattened for exactly this reason, and the check is
    /// kept because the M4 defect was invisible to parsers that collapse
    /// duplicates.
    #[test]
    fn a_serialized_contract_has_no_duplicate_keys() {
        let report = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        let text = serde_json::to_string(&report.contracts[0]).expect("serializable");
        let keys: Keys = serde_json::from_str(&text).expect("an object");
        let mut seen: Vec<&str> = Vec::new();
        for key in &keys.0 {
            assert!(!seen.contains(&key.as_str()), "duplicate key {key:?}");
            seen.push(key);
        }
        assert!(seen.contains(&"contract"));
        assert!(seen.contains(&"analysis"));
    }

    /// Every key of a JSON object in source order, duplicates kept.
    struct Keys(Vec<String>);

    impl<'de> serde::Deserialize<'de> for Keys {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Keys;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a JSON object")
                }

                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Keys, A::Error> {
                    let mut keys = Vec::new();
                    while let Some((key, _)) = map.next_entry::<String, serde_json::Value>()? {
                        keys.push(key);
                    }
                    Ok(Keys(keys))
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }

    /// A report covering two contracts must not advertise either executable as
    /// the artifact for both.
    ///
    /// Report-level provenance used to be M4's `SymbolicProvenance`, which
    /// carries an artifact path, its hash and direct-`rustc` build flags. In a
    /// multi-contract run it described the **last** contract's executable and a
    /// set of flags M5 does not use, while reading as though it described the
    /// whole report.
    #[test]
    fn a_multi_contract_report_claims_no_shared_artifact() {
        let mut second = verified(Outcome::VerifiedBounded, "VERIFIED_BOUNDED", vec![]);
        second.contract.id = "crypto::lookup::substitute".into();
        second.contract.module = "crypto::lookup".into();
        second.contract.function = "substitute".into();
        second.artifact.sha256 = "b19e".into();
        second.artifact.path = PathBuf::from("/tmp/tc-verify-substitute");
        second.result.case = second.contract.id.clone();

        let report = build(
            vec![
                verified(Outcome::VerifiedBounded, "VERIFIED_BOUNDED", vec![]),
                second,
            ],
            analyzer(),
            2,
            false,
        );
        assert_eq!(report.contracts.len(), 2);
        // Distinct artifacts, each named on its own contract.
        assert_ne!(
            report.contracts[0].artifact.sha256,
            report.contracts[1].artifact.sha256
        );

        // The report level carries the analyzer and nothing that identifies an
        // artifact. Checked over the serialized form so a future field cannot
        // reintroduce one unnoticed.
        let value: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        let shared = value["analyzer"].as_object().expect("an object");
        for forbidden in ["artifact_path", "artifact_sha256", "build_flags"] {
            assert!(
                !shared.contains_key(forbidden),
                "report-level provenance must not carry {forbidden}: {shared:?}"
            );
        }
        assert!(value.get("provenance").is_none(), "{value}");
        assert_eq!(shared["container_tool"], "podman");
        assert!(shared["analyzer_image"]
            .as_str()
            .unwrap()
            .contains("@sha256:"));

        // And the text report names no artifact before the per-contract
        // sections begin. (The analyzer *image* digest is there, and is a
        // property of the analyzer, not of anything it analyzed.)
        let text = report.to_text();
        let header = text.split("Verifying ").next().expect("a header");
        for forbidden in ["Artifact sha256", "Harness sha256", "Artifact path"] {
            assert!(!header.contains(forbidden), "{header}");
        }
    }

    /// Compilation provenance describes the build M5 actually performs, not
    /// M4's direct-`rustc` invocation.
    #[test]
    fn compilation_provenance_describes_the_cargo_build() {
        let report = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        let compilation = &report.contracts[0].compilation;
        assert!(!compilation.lto);
        assert_eq!(compilation.panic, "abort");
        assert!(compilation.profile.contains("lto=off"), "{compilation:?}");
        assert!(
            compilation.rustflags.contains("link-arg=-nostdlib"),
            "{compilation:?}"
        );
    }

    /// An artifact in the default workspace does not outlive the run, and the
    /// report says so rather than leaving a dangling path to be trusted.
    #[test]
    fn a_removed_artifact_path_is_marked_as_such() {
        let ephemeral = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        assert!(!ephemeral.contracts[0].artifact.path_retained);
        assert!(
            ephemeral.to_text().contains("removed after the run"),
            "{}",
            ephemeral.to_text()
        );
        let kept = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            true,
        );
        assert!(kept.contracts[0].artifact.path_retained);
        assert!(kept.to_text().contains("(retained)"), "{}", kept.to_text());
    }

    /// A generated domain restriction is reported apart from the developer's
    /// own assumptions, which stay verbatim.
    #[test]
    fn a_generated_domain_restriction_is_reported_separately() {
        let mut entry = verified(Outcome::VerifiedBounded, "VERIFIED_BOUNDED", vec![]);
        entry.harness.generated_assumptions = vec!["TC_PUBLIC_ENABLED <= 1".into()];
        entry.case.assumptions = vec![
            "TC_PUBLIC_ENABLED <= 1".into(),
            "TC_SECRET_EXPECTED < 1024".into(),
        ];
        let report = build(vec![entry], analyzer(), 1, false);
        let contract = &report.contracts[0];
        assert_eq!(contract.generated_domain, vec!["TC_PUBLIC_ENABLED <= 1"]);
        assert_eq!(contract.input_domain, vec!["TC_SECRET_EXPECTED < 1024"]);
        let text = report.to_text();
        assert!(
            text.contains("assumed:   TC_SECRET_EXPECTED < 1024"),
            "{text}"
        );
        assert!(text.contains("generated: TC_PUBLIC_ENABLED <= 1"), "{text}");
    }

    /// A secret input is described as fully symbolic and a public one as held
    /// equal, which is the property that makes a relational result meaningful.
    #[test]
    fn roles_are_described_in_relational_terms() {
        let report = build(
            vec![verified(
                Outcome::VerifiedBounded,
                "VERIFIED_BOUNDED",
                vec![],
            )],
            analyzer(),
            1,
            false,
        );
        let inputs = &report.contracts[0].inputs;
        assert_eq!(inputs[0].role, Role::Secret);
        assert!(inputs[0].passing.contains("pointer is public"));
        assert_eq!(inputs[1].role, Role::Public);
    }
}
