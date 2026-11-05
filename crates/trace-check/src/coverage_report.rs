//! The contract-coverage report: what was declared, what was required, what
//! happened, and whether CI may call it a success.
//!
//! Three things are easy to confuse and are kept visibly apart:
//!
//! * **Inventory completeness** — were all the declarations found?
//! * **Enforcement** — did each declaration's required analyses happen?
//! * **Evidence** — what did the analyses observe?
//!
//! A single "coverage: 87 %" would blur all three. The matrix shows each
//! contract's required analyses and their statuses; the summary counts
//! declarations and requirements separately; and the rate, when printed,
//! carries what it is not.

use serde::Serialize;

use crate::enforcement::{Analysis, Coverage, Enforcement, Status};
use crate::inventory::ContractInventory;

/// Report schema this build emits.
///
/// Two, not one: M6's generated-check report is schema 1, and this is a
/// different document with a different shape. A consumer that keyed on
/// `schema_version` keeps working.
pub const SCHEMA_VERSION: u32 = 2;

pub const EXIT_OK: u8 = 0;
pub const EXIT_LEAK: u8 = 1;
pub const EXIT_INCOMPLETE: u8 = 2;

/// Limits restated in every report, because a stored result outlives the
/// conversation that produced it.
pub const LIMITATIONS: [&str; 7] = [
    "This report covers the `#[constant_time]` declarations compiled into one library target under one feature selection. Another feature combination may declare different contracts.",
    "It enforces declared requirements. It does not discover functions that ought to carry a declaration, and a function with no annotation is not accounted for here at all.",
    "An enforcement status says whether a required analysis happened. It is not a security outcome: see each contract's evidence for what was actually observed.",
    "A satisfied requirement is as strong as the analysis that satisfied it. A generated dynamic check is NO_LEAK_OBSERVED over the inputs it ran, never a proof.",
    "An exemption records that an obligation was waived. It establishes nothing about the contract, and never suppresses a detected leak.",
    "Each analysis built and analyzed its own executable, and each result describes only that one. Two requirements satisfied for one contract are two results about two binaries, not one result about the function in general -- compare their `artifact_sha256` values. Neither is the production binary.",
    "A symbolic VERIFIED_BOUNDED is scoped to the declared input domain, the exploration bound and the observation classes the contract's `[verify]` entry listed. Read the symbolic evidence's `input_domain`, `max_depth` and `checked_features`: it claims nothing outside them.",
];

/// Toolchain and library provenance for the run.
#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub rustc_version: String,
    pub cargo_version: String,
    pub target: String,
    pub library_package: String,
    pub library_version: String,
    pub library_manifest: String,
    /// Features this run's inventory and analyses were built with.
    pub features: Vec<String>,
}

/// What the inventory established, separately from what enforcement did.
#[derive(Debug, Clone, Serialize)]
pub struct InventorySummary {
    pub complete: bool,
    pub schema_version: u32,
    pub id: String,
    pub variant: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
    pub profile: String,
    pub contracts_declared: usize,
    pub objects_inspected: usize,
    pub objects_read: usize,
    /// What a complete inventory does and does not mean.
    pub limitations: Vec<String>,
}

impl InventorySummary {
    pub fn of(inventory: &ContractInventory) -> InventorySummary {
        InventorySummary {
            complete: inventory.complete(),
            schema_version: inventory.schema_version,
            id: inventory.id.clone(),
            variant: inventory.build.variant(),
            artifact_path: inventory.build.artifact_path.clone(),
            artifact_sha256: inventory.build.artifact_sha256.clone(),
            profile: inventory.build.profile.clone(),
            contracts_declared: inventory.contracts.len(),
            objects_inspected: inventory.objects_inspected,
            objects_read: inventory.objects_read,
            limitations: inventory.limitations(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub mode: &'static str,
    #[serde(flatten)]
    pub counts: Enforcement,
    /// Requirements met over requirements owed, excluding waived ones.
    /// Absent when nothing was owed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_rate: Option<f64>,
    pub enforcement_caveat: &'static str,
    pub blocking_reasons: Vec<String>,
    pub ok: bool,
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    pub schema_version: u32,
    pub provenance: Provenance,
    pub inventory: InventorySummary,
    /// Contracts selected for this run, named so a reader never has to infer
    /// what was covered.
    pub selected: Vec<String>,
    /// How the selection was made, because `--all-contracts` and
    /// `--all-configured` cover different things.
    pub selection: &'static str,
    pub contracts: Vec<crate::enforcement::ContractCoverage>,
    pub stale: Vec<crate::enforcement::StaleEntry>,
    /// What this run actually executed, as decided before anything was built.
    ///
    /// Separate from the requirements on purpose: four named analyses are not
    /// four invocations. A reader comparing the obligations to this sees which
    /// requirements shared an execution, and a CI job can assert that
    /// requiring `generated` and `explore` produced one Memcheck workflow
    /// rather than two.
    ///
    /// Absent from a read-only `coverage` report, which runs nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<crate::orchestration::ExecutionPlan>,
    pub summary: Summary,
    pub limitations: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn build(
    provenance: Provenance,
    inventory: &ContractInventory,
    coverage: &Coverage,
    policy: &crate::enforcement::PolicyConfig,
    selected: Vec<String>,
    selection: &'static str,
    execution: Option<crate::orchestration::ExecutionPlan>,
) -> CoverageReport {
    let blocking = coverage.blocking(inventory, policy);
    let counts = coverage.enforcement();
    CoverageReport {
        schema_version: SCHEMA_VERSION,
        provenance,
        inventory: InventorySummary::of(inventory),
        selected,
        selection,
        contracts: coverage.contracts.clone(),
        stale: coverage.stale.clone(),
        execution,
        summary: Summary {
            mode: coverage.mode.as_str(),
            enforcement_rate: counts.rate(),
            enforcement_caveat: Enforcement::caveat(),
            counts,
            ok: blocking.is_empty(),
            blocking_reasons: blocking,
        },
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    }
}

impl CoverageReport {
    /// A detected violation outranks an incomplete analysis, so the code names
    /// the most serious outcome while the report keeps everything.
    pub fn exit_code(&self) -> u8 {
        if self.summary.counts.violations > 0 {
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

        line!("Contract coverage");
        line!("");
        line!(
            "Library:   {} {} ({})",
            self.provenance.library_package,
            self.provenance.library_version,
            self.provenance.library_manifest
        );
        line!(
            "Variant:   {} for {}",
            self.inventory.variant,
            self.provenance.target
        );
        line!("Policy:    {} mode", self.summary.mode);
        line!("Selection: {}", self.selection);
        line!("");

        // Section one: the inventory. Printed first, because every count below
        // is only meaningful if this was complete.
        line!("-- inventory (compiler-derived) --");
        line!(
            "  artifact: {} [{}]",
            short(&self.inventory.artifact_sha256),
            self.inventory.profile
        );
        line!("  identity: {}", short(&self.inventory.id));
        line!(
            "  objects:  {} of {} read",
            self.inventory.objects_read,
            self.inventory.objects_inspected
        );
        line!(
            "  declared: {} contract(s){}",
            self.inventory.contracts_declared,
            if self.inventory.complete {
                ""
            } else {
                " -- INCOMPLETE, so declarations may be missing entirely"
            }
        );
        line!("");

        // Section two: the matrix. One row per declaration, one column per
        // analysis that anything required.
        let columns: Vec<Analysis> = Analysis::all()
            .into_iter()
            .filter(|analysis| {
                self.contracts
                    .iter()
                    .any(|contract| contract.required.contains(analysis))
            })
            .collect();
        line!("-- enforcement --");
        if self.contracts.is_empty() {
            line!("  (no contract declarations)");
        } else {
            let width = self
                .contracts
                .iter()
                .map(|contract| contract.id.len())
                .max()
                .unwrap_or(8)
                .max(8);
            let mut header = format!("  {:<width$}", "contract", width = width);
            for analysis in &columns {
                header.push_str(&format!("  {:<20}", analysis.as_str()));
            }
            line!("{header}");
            for contract in &self.contracts {
                let mut row = format!("  {:<width$}", contract.id, width = width);
                for analysis in &columns {
                    let cell = match contract.status.get(analysis) {
                        Some(status) => status.as_str(),
                        // Not required of this contract, which is different
                        // from required and not done.
                        None => "-",
                    };
                    row.push_str(&format!("  {cell:<20}"));
                }
                line!("{row}");
            }
        }
        line!("");

        // Per-contract detail, for anything the matrix cannot convey on its
        // own. `NOT_ANALYZED` and `NOT_SELECTED` say everything there is to
        // say in one word, and repeating them per contract buries the statuses
        // that carry a reason.
        for contract in &self.contracts {
            let needs_detail = contract.status.values().any(|status| {
                matches!(
                    status,
                    Status::LeakDetected
                        | Status::Unsupported { .. }
                        | Status::Inconclusive { .. }
                        | Status::BackendUnavailable { .. }
                        | Status::Exempted { .. }
                        | Status::InventoryError { .. }
                        | Status::Inactive { .. }
                )
            });
            if !needs_detail {
                continue;
            }
            line!("{}", contract.id);
            line!("  declared at {}", contract.site);
            for analysis in &contract.required {
                let Some(status) = contract.status.get(analysis) else {
                    continue;
                };
                line!(
                    "  {:<10} {:<20} {}",
                    analysis.as_str(),
                    status.as_str(),
                    status.describe()
                );
            }
            for evidence in &contract.evidence {
                line!(
                    "  evidence:  {} produced {} in {} -- {}",
                    evidence.analysis,
                    evidence.outcome,
                    short(&evidence.artifact_sha256),
                    evidence.detail
                );
            }
            line!("");
        }

        for entry in &self.stale {
            line!("STALE [{}.\"{}\"]", entry.source, entry.contract);
            line!("  {}", entry.detail);
            line!("");
        }

        // Section three: the decision.
        let counts = &self.summary.counts;
        line!("CI decision:");
        line!("  Declared:          {}", counts.declared);
        line!("  Fully checked:     {}", counts.checked);
        line!("  Violations:        {}", counts.violations);
        line!("  Lacking evidence:  {}", counts.lacking_evidence);
        line!("  Exempted:          {}", counts.exempted);
        line!(
            "  Requirements:      {} owed, {} met, {} waived",
            counts.requirements,
            counts.requirements_checked,
            counts.requirements_exempted
        );
        match self.summary.enforcement_rate {
            Some(rate) => line!("  Enforcement:       {:.0}%", rate * 100.0),
            None => line!("  Enforcement:       n/a (no unwaived requirements)"),
        }
        line!("  Note:              {}", self.summary.enforcement_caveat);
        if !self.summary.blocking_reasons.is_empty() {
            line!("");
            line!("Blocking:");
            for reason in &self.summary.blocking_reasons {
                line!("  - {reason}");
            }
        }
        // What actually ran, so a reader can see that two requirements met by
        // one Memcheck workflow were one observation rather than two.
        if let Some(execution) = &self.execution {
            line!("");
            out.push_str(&execution.to_text());
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

/// First twelve characters of a hash, for human-readable output.
fn short(hash: &str) -> String {
    hash.chars().take(12).collect()
}

/// Renders an inventory on its own, for `list --contracts`.
pub fn inventory_to_text(inventory: &ContractInventory) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} contract declaration(s) in {}\n",
        inventory.contracts.len(),
        inventory.build.variant()
    ));
    out.push_str(&format!(
        "  artifact: {} [{}]\n",
        short(&inventory.build.artifact_sha256),
        inventory.build.profile
    ));
    out.push_str(&format!("  identity: {}\n", short(&inventory.id)));
    if !inventory.complete() {
        out.push_str(&format!(
            "  INCOMPLETE: {} of {} object member(s) read, so declarations may be missing\n",
            inventory.objects_read, inventory.objects_inspected
        ));
    }
    out.push('\n');
    for declaration in &inventory.contracts {
        let secrets: Vec<&str> = declaration
            .secrets()
            .map(|parameter| parameter.name.as_str())
            .collect();
        out.push_str(&format!(
            "  {}\n    at {}\n    secret(s): {}\n    adapter:   {}\n",
            declaration.id,
            declaration.site(),
            secrets.join(", "),
            if declaration.dynamic_adapter_enabled {
                "dynamic (an M3 #[ct_test] can cover it)"
            } else {
                "none (declared dynamic = false)"
            }
        ));
    }
    out.push('\n');
    for limitation in inventory.limitations() {
        out.push_str(&format!("  - {limitation}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enforcement::{AnalysisEvidence, Available, Plan, PolicyConfig};
    use crate::security::Outcome;

    fn provenance() -> Provenance {
        Provenance {
            rustc_version: "rustc 1.97.0".to_string(),
            cargo_version: "cargo 1.97.0".to_string(),
            target: "x86_64-unknown-linux-gnu".to_string(),
            library_package: "crypto-library".to_string(),
            library_version: "0.1.0".to_string(),
            library_manifest: "/x/Cargo.toml".to_string(),
            features: Vec::new(),
        }
    }

    fn report_for(
        ids: &[&str],
        policy: &PolicyConfig,
        evidence: &[(&str, Analysis, Outcome)],
    ) -> CoverageReport {
        let inventory = crate::enforcement::test_support::inventory(ids);
        let selected: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let plan = Plan::resolve(
            &inventory,
            &crate::contract::VerifyConfig::empty(),
            policy,
            &selected,
            &Available::all(),
            "2026-11-03",
        );
        let mut coverage = Coverage::from_plan(&plan, &inventory);
        for (id, analysis, outcome) in evidence {
            coverage.fold(
                id,
                AnalysisEvidence::summary(
                    *analysis,
                    *outcome,
                    crate::evidence::sample_identity(id, "artifact0000"),
                    "detail",
                ),
            );
        }
        build(
            provenance(),
            &inventory,
            &coverage,
            policy,
            selected,
            "--all-contracts",
            None,
        )
    }

    /// A clean run exits 0 and says so.
    #[test]
    fn a_satisfied_run_passes() {
        let report = report_for(
            &["crypto::a::probe"],
            &PolicyConfig::default(),
            &[(
                "crypto::a::probe",
                Analysis::Generated,
                Outcome::NoLeakObserved,
            )],
        );
        assert_eq!(report.exit_code(), EXIT_OK);
        assert!(report.summary.ok);
        let text = report.to_text();
        assert!(text.contains("Result: PASS"));
        assert!(text.contains("CHECKED"));
        assert!(text.contains("Enforcement:       100%"));
    }

    /// A detected leak exits 1, whatever else is wrong.
    #[test]
    fn a_violation_exits_one() {
        let report = report_for(
            &["crypto::a::probe", "crypto::b::probe"],
            &PolicyConfig::default(),
            &[(
                "crypto::a::probe",
                Analysis::Generated,
                Outcome::LeakDetected,
            )],
        );
        // `b` is also unmet, so both kinds of problem are present and the
        // more serious one names the exit code.
        assert_eq!(report.summary.counts.violations, 1);
        assert!(report.summary.counts.lacking_evidence >= 1);
        assert_eq!(report.exit_code(), EXIT_LEAK);
        let text = report.to_text();
        assert!(text.contains("LEAK_DETECTED"));
        assert!(text.contains("NOT_ANALYZED"), "{text}");
    }

    /// An unmet requirement with no violation exits 2.
    #[test]
    fn an_unmet_requirement_exits_two() {
        let report = report_for(&["crypto::a::probe"], &PolicyConfig::default(), &[]);
        assert_eq!(report.summary.counts.violations, 0);
        assert_eq!(report.exit_code(), EXIT_INCOMPLETE);
        assert!(report.to_text().contains("Result: FAIL"));
    }

    /// The matrix has a row per declaration and a column per required
    /// analysis, and a cell for a non-required analysis is distinguishable
    /// from one that was required and not done.
    #[test]
    fn the_matrix_shows_every_declaration() {
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            "crypto::b::probe".to_string(),
            crate::enforcement::ContractPolicy {
                required: Some(vec![Analysis::Generated, Analysis::Symbolic]),
            },
        );
        let report = report_for(
            &["crypto::a::probe", "crypto::b::probe"],
            &policy,
            &[
                (
                    "crypto::a::probe",
                    Analysis::Generated,
                    Outcome::NoLeakObserved,
                ),
                (
                    "crypto::b::probe",
                    Analysis::Generated,
                    Outcome::NoLeakObserved,
                ),
            ],
        );
        let text = report.to_text();
        assert!(text.contains("crypto::a::probe"));
        assert!(text.contains("crypto::b::probe"));
        // Both columns appear, because something required each.
        assert!(text.contains("generated"));
        assert!(text.contains("symbolic"));
        // `a` does not require symbolic, so its cell is a dash rather than a
        // status that could be read as a gap.
        let row = text
            .lines()
            .find(|line| line.contains("crypto::a::probe") && line.contains("CHECKED"))
            .expect("a row for a");
        assert!(row.contains('-'), "{row:?}");
    }

    /// The JSON report keeps inventory, enforcement and evidence in separate
    /// places, and carries its limitations.
    #[test]
    fn the_json_report_separates_the_three_questions() {
        let report = report_for(
            &["crypto::a::probe"],
            &PolicyConfig::default(),
            &[(
                "crypto::a::probe",
                Analysis::Generated,
                Outcome::NoLeakObserved,
            )],
        );
        let value: serde_json::Value =
            serde_json::from_str(&report.to_json()).expect("the report is JSON");
        assert_eq!(value["schema_version"], 2);
        // Inventory completeness is its own object.
        assert_eq!(value["inventory"]["complete"], true);
        assert_eq!(value["inventory"]["contracts_declared"], 1);
        // Enforcement counts are in the summary.
        assert_eq!(value["summary"]["checked"], 1);
        assert_eq!(value["summary"]["violations"], 0);
        // And evidence is per contract, with the outcome vocabulary intact.
        assert_eq!(
            value["contracts"][0]["evidence"][0]["outcome"],
            "NO_LEAK_OBSERVED"
        );
        assert_eq!(
            value["contracts"][0]["status"]["generated"]["state"],
            "checked"
        );
        assert!(value["limitations"]
            .as_array()
            .expect("limitations")
            .iter()
            .any(|limit| limit
                .as_str()
                .expect("a string")
                .contains("does not discover functions")));
    }

    /// The rate is absent rather than 100 % when nothing was owed.
    #[test]
    fn a_rate_over_no_obligations_is_not_a_number() {
        let policy = PolicyConfig {
            allow_empty_inventory: true,
            ..PolicyConfig::default()
        };
        let report = report_for(&[], &policy, &[]);
        assert_eq!(report.summary.enforcement_rate, None);
        assert!(report.to_text().contains("n/a (no unwaived requirements)"));
        assert_eq!(report.exit_code(), EXIT_OK);
    }
}
