//! Which analyses each declared contract owes, and whether it paid them.
//!
//! The inventory ([`crate::inventory`]) answers *which contracts exist*. This
//! module answers *what is required of each one, and what actually happened* —
//! and keeps those two questions apart, because collapsing them is how a tool
//! ends up reporting a contract as covered when all that happened was that
//! nobody asked about it.
//!
//! # Two dimensions, never one boolean
//!
//! Every contract carries both:
//!
//! * an **enforcement status** per required analysis — was it selected, could
//!   it be run, was it waived, did it complete; and
//! * **evidence** — what a backend actually observed.
//!
//! `NO_LEAK_OBSERVED` from generated testing and `VERIFIED_BOUNDED` from
//! symbolic verification are different claims about different things, so they
//! are separate evidence records and a requirement for one is never discharged
//! by the other.
//!
//! # The inventory decides what exists; configuration decides how it is checked
//!
//! That inversion is the milestone. Before M8, `--all-configured` selected
//! configuration keys, so a contract with no entry was not merely unchecked —
//! it was invisible. Now a declaration is required by default, and a
//! configuration entry can only change *how* it is analyzed.
//!
//! # Backend independence
//!
//! Nothing here names Valgrind or BINSEC. [`Analysis`] names requirements and
//! [`Evidence`] records results, so a future backend participates by producing
//! evidence for an analysis rather than by another redesign of discovery and
//! enforcement.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::contract::{Descriptor, Repr, Role, VerifyConfig};
use crate::inventory::{ContractDeclaration, ContractInventory};
use crate::security::Outcome;

/// An analysis a policy can require of a contract.
///
/// Named after what it establishes rather than after the tool that runs it, so
/// a requirement outlives a backend choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Analysis {
    /// A completed generated dynamic check with no detected leak (M6).
    Generated,
    /// Completed coverage-guided discovery, and the dynamic checking of what
    /// it selected (M7). Strictly more than `generated`, never a substitute
    /// for it: it is the same security backend over better-chosen inputs.
    Explore,
    /// A `VERIFIED_BOUNDED` result under its declared domain and observation
    /// model (M5).
    Symbolic,
    /// A developer-written `#[ct_test]` covering the contract (M3). A separate
    /// evidence source, required only when asked for explicitly.
    Dynamic,
}

impl Analysis {
    pub fn as_str(self) -> &'static str {
        match self {
            Analysis::Generated => "generated",
            Analysis::Explore => "explore",
            Analysis::Symbolic => "symbolic",
            Analysis::Dynamic => "dynamic",
        }
    }

    pub fn all() -> [Analysis; 4] {
        [
            Analysis::Generated,
            Analysis::Explore,
            Analysis::Symbolic,
            Analysis::Dynamic,
        ]
    }

    /// The outcome that discharges this requirement.
    ///
    /// The one place the vocabulary is mapped, so "a generated run completed"
    /// can never be read as satisfying a symbolic requirement: the two want
    /// different outcomes, and no backend produces both.
    pub fn discharged_by(self) -> Outcome {
        match self {
            Analysis::Generated | Analysis::Explore | Analysis::Dynamic => Outcome::NoLeakObserved,
            Analysis::Symbolic => Outcome::VerifiedBounded,
        }
    }

    /// Which backend has to be present to run it, for an up-front report.
    pub fn backend(self) -> &'static str {
        match self {
            Analysis::Generated | Analysis::Explore | Analysis::Dynamic => "valgrind",
            Analysis::Symbolic => "the symbolic analyzer image",
        }
    }
}

impl fmt::Display for Analysis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where one required analysis of one contract stands.
///
/// An enforcement state, not a security outcome. [`Status::LeakDetected`] is
/// the one place the two touch, and it exists because a detected leak has to be
/// visible in the enforcement dimension too — no arrangement of statuses may
/// let it read as satisfied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum Status {
    /// The analysis completed and discharged the requirement.
    Checked,
    /// The required security property was violated.
    LeakDetected,
    /// The analysis ran but did not establish the required outcome.
    Inconclusive { detail: String },
    /// The declared function cannot be analyzed by this backend.
    Unsupported { reason: String },
    /// A known applicable contract was left out of the requested run.
    NotSelected,
    /// Required, and no analysis reported a result for it.
    ///
    /// Every required analysis is given this status up front, so the status map
    /// is **total** over the requirements. An earlier revision left an
    /// un-analyzed requirement with no entry at all, and `gaps()` only looked
    /// at entries that existed -- so a contract requiring both `generated` and
    /// `symbolic`, given only a generated run, reported no gaps and passed.
    /// A requirement that is silently absent from the accounting is the exact
    /// failure this milestone exists to prevent.
    ///
    /// `detail` distinguishes *nothing ran* from *this command does not run
    /// it*. Reporting the second as [`Status::BackendUnavailable`] would be a
    /// claim about the machine rather than about the command, and would send a
    /// developer to install an analyzer they may already have.
    NotAnalyzed { detail: String },
    /// The analyzer or instrumentation this analysis needs is absent.
    BackendUnavailable { backend: String },
    /// An explicit, policy-approved waiver of the *obligation*.
    Exempted {
        reason: String,
        tracking: Option<String>,
        expires: Option<String>,
    },
    /// The declaration or configuration belongs to another build variant.
    Inactive { detail: String },
    /// Inventory completeness or integrity could not be established.
    InventoryError { detail: String },
}

impl Status {
    /// The default un-analyzed status: required, and nothing reported.
    pub fn not_analyzed() -> Status {
        Status::NotAnalyzed {
            detail: "this analysis was required and no backend reported a result for it"
                .to_string(),
        }
    }

    /// Required, but not something this command performs.
    pub fn not_performed(analysis: Analysis, command: &str) -> Status {
        Status::NotAnalyzed {
            detail: format!(
                "`{analysis}` is required and this command does not run it; its evidence comes \
                 from `{command}`. That is not the same as the analyzer being absent, which \
                 would be reported as BACKEND_UNAVAILABLE"
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Checked => "CHECKED",
            Status::LeakDetected => "LEAK_DETECTED",
            Status::Inconclusive { .. } => "INCONCLUSIVE",
            Status::Unsupported { .. } => "UNSUPPORTED",
            Status::NotSelected => "NOT_SELECTED",
            Status::NotAnalyzed { .. } => "NOT_ANALYZED",
            Status::BackendUnavailable { .. } => "BACKEND_UNAVAILABLE",
            Status::Exempted { .. } => "EXEMPTED",
            Status::Inactive { .. } => "INACTIVE",
            Status::InventoryError { .. } => "INVENTORY_ERROR",
        }
    }

    /// Whether this status discharges the obligation.
    ///
    /// An exemption does: that is what a waiver is for. It does **not** make a
    /// leak acceptable, because a leak is recorded as
    /// [`Status::LeakDetected`] and an exemption is never applied over one —
    /// see [`Plan::resolve`].
    pub fn satisfied(&self) -> bool {
        matches!(self, Status::Checked | Status::Exempted { .. })
    }

    /// Whether this status is a detected violation rather than a gap.
    pub fn violation(&self) -> bool {
        matches!(self, Status::LeakDetected)
    }

    pub fn describe(&self) -> String {
        match self {
            Status::Checked => "the required analysis completed and passed".to_string(),
            Status::LeakDetected => "a secret-dependent branch or address was found".to_string(),
            Status::Inconclusive { detail } => detail.clone(),
            Status::Unsupported { reason } => reason.clone(),
            Status::NotSelected => {
                "this contract is applicable but was not part of the requested run".to_string()
            }
            Status::NotAnalyzed { detail } => detail.clone(),
            Status::BackendUnavailable { backend } => {
                format!("{backend} is required for this analysis and was not available")
            }
            Status::Exempted {
                reason,
                tracking,
                expires,
            } => {
                let mut out = format!("waived: {reason}");
                if let Some(tracking) = tracking {
                    out.push_str(&format!(" (tracking {tracking})"));
                }
                if let Some(expires) = expires {
                    out.push_str(&format!(" (expires {expires})"));
                }
                out
            }
            Status::Inactive { detail } => detail.clone(),
            Status::InventoryError { detail } => detail.clone(),
        }
    }
}

/// What one backend actually observed, kept separate from the obligation.
///
/// # Generic where the policy reads it, specific where a developer does
///
/// The policy layer only ever consults `outcome`, which is what keeps
/// enforcement backend-independent. But a report that reduced a dynamic result
/// to one sentence would lose the finding stacks, the leak site, the isolated
/// input, the shrunk reproducer, the calibration controls, the case counts and
/// the discovery provenance -- everything a developer needs to act on a
/// failure. `check --all-contracts` is meant to become the standard CI
/// interface, so the backend-specific evidence rides along in its own fields
/// rather than being summarized away.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisEvidence {
    pub analysis: Analysis,
    pub outcome: Outcome,
    /// The artifact the observation describes, because a result is about one
    /// build rather than about the library in general.
    pub artifact_sha256: String,
    pub detail: String,
    /// The generated check's whole result, when a generated analysis produced
    /// this evidence: findings, isolation, shrinking, controls, case counts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<crate::check::ContractCheck>,
    /// Exploration evidence, when coverage-guided discovery ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<crate::check_report::DiscoveryEvidence>,
    /// Reproducers written for this contract's findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub reproducers: Vec<String>,
}

impl AnalysisEvidence {
    /// Evidence carrying only an outcome and a sentence, for a backend that
    /// has nothing more structured to offer.
    pub fn summary(
        analysis: Analysis,
        outcome: Outcome,
        artifact_sha256: &str,
        detail: &str,
    ) -> AnalysisEvidence {
        AnalysisEvidence {
            analysis,
            outcome,
            artifact_sha256: artifact_sha256.to_string(),
            detail: detail.to_string(),
            check: None,
            discovery: None,
            reproducers: Vec::new(),
        }
    }
}

/// Enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Required analyses must be satisfied; a gap fails. The default, because
    /// it is the answer that is safe when nobody thought about it.
    #[default]
    Strict,
    /// Gaps are reported but do not fail. For adopting the tool on an existing
    /// codebase without blocking every build on day one.
    Advisory,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Strict => "strict",
            Mode::Advisory => "advisory",
        }
    }
}

/// An explicit waiver of an obligation.
///
/// Exists because the alternative is worse. Without waivers a developer facing
/// an unsupported signature has one way to make CI pass: delete the annotation,
/// which removes the security requirement along with the complaint. A waiver
/// keeps the declaration, keeps it in the report, and records who decided and
/// why.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exemption {
    pub contract: String,
    /// Which analyses are waived. An empty list is refused rather than read as
    /// "all": a blanket waiver has to be written out.
    pub analyses: Vec<Analysis>,
    /// Why. Required and non-empty — a waiver without a reason is just a gap.
    pub reason: String,
    #[serde(default)]
    pub tracking: Option<String>,
    /// `YYYY-MM-DD`. Required in strict mode unless `never_expires` is set.
    #[serde(default)]
    pub expires: Option<String>,
    /// Deliberate, reviewed decision that this waiver has no end date.
    #[serde(default)]
    pub never_expires: bool,
}

impl Exemption {
    /// Rejects a waiver that could weaken the policy without saying so.
    pub fn validate(&self, mode: Mode) -> Result<(), String> {
        if self.contract.trim().is_empty() {
            return Err("an exemption has no `contract`".to_string());
        }
        if self.analyses.is_empty() {
            return Err(format!(
                "the exemption for `{}` lists no `analyses`. An empty list is refused rather \
                 than read as waiving everything: a blanket waiver has to be written out",
                self.contract
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(format!(
                "the exemption for `{}` has no `reason`. A waiver without one is \
                 indistinguishable from an unenforced contract",
                self.contract
            ));
        }
        match (&self.expires, self.never_expires) {
            (Some(_), true) => Err(format!(
                "the exemption for `{}` sets both `expires` and `never_expires = true`",
                self.contract
            )),
            (Some(date), false) => parse_date(date)
                .map(|_| ())
                .map_err(|e| format!("the exemption for `{}`: {e}", self.contract)),
            (None, true) => Ok(()),
            (None, false) if mode == Mode::Strict => Err(format!(
                "the exemption for `{}` has no `expires` date. Strict mode requires one, or \
                 `never_expires = true` as a deliberate decision, so a temporary waiver cannot \
                 quietly become permanent",
                self.contract
            )),
            (None, false) => Ok(()),
        }
    }

    /// Whether this waiver has lapsed as of `today` (`YYYY-MM-DD`).
    pub fn expired(&self, today: &str) -> bool {
        match &self.expires {
            // Lexicographic comparison is exact for zero-padded ISO dates, and
            // avoids a date library for the one comparison this needs.
            Some(date) => date.as_str() < today,
            None => false,
        }
    }
}

/// `YYYY-MM-DD`, validated strictly enough that a typo is a configuration
/// error rather than a waiver that never expires.
fn parse_date(text: &str) -> Result<(u32, u32, u32), String> {
    let parts: Vec<&str> = text.split('-').collect();
    let [year, month, day] = parts.as_slice() else {
        return Err(format!("`expires = {text:?}` is not a YYYY-MM-DD date"));
    };
    if year.len() != 4 || month.len() != 2 || day.len() != 2 {
        return Err(format!(
            "`expires = {text:?}` is not a YYYY-MM-DD date; the parts must be zero-padded so \
             dates compare correctly"
        ));
    }
    let number = |text: &str, what: &str| -> Result<u32, String> {
        text.parse::<u32>()
            .map_err(|_| format!("`expires = {text:?}` has a non-numeric {what}"))
    };
    let (year, month, day) = (
        number(year, "year")?,
        number(month, "month")?,
        number(day, "day")?,
    );
    if !(1..=12).contains(&month) {
        return Err(format!("`expires` names month {month}: {text:?}"));
    }
    // Real month lengths, not 1..=31 independently: `2027-02-31` passed the
    // looser check, and an exemption with an impossible expiry is one whose
    // lapse nobody will notice.
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let longest = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        _ => 28,
    };
    if !(1..=longest).contains(&day) {
        return Err(format!(
            "`expires` names day {day} of a month with {longest}: {text:?}"
        ));
    }
    Ok((year, month, day))
}

/// Per-contract policy overrides.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractPolicy {
    /// Analyses required of this contract, replacing the default.
    #[serde(default)]
    pub required: Option<Vec<Analysis>>,
}

/// The assurance policy.
///
/// Absent from a configuration entirely, the defaults apply: strict mode, a
/// generated dynamic check required of every declaration, and no waivers. An
/// existing `trace-check.toml` therefore keeps loading and gains enforcement
/// without being edited.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub mode: Mode,
    /// Analyses required of a declaration with no entry of its own.
    ///
    /// `generated` only, by default. Requiring symbolic verification of
    /// everything would make a container image a prerequisite for annotating a
    /// function, which is a good way to make developers stop annotating.
    #[serde(default = "default_required")]
    pub default_required: Vec<Analysis>,
    /// Whether a run that discovers no contracts may pass in strict mode.
    ///
    /// False by default. A library with no declarations is legitimate, but so
    /// is a broken selection that found none, and the two must not look alike.
    #[serde(default)]
    pub allow_empty_inventory: bool,
    /// Whether configuration naming no active declaration may be tolerated.
    ///
    /// False by default, because a typo, a renamed function and a removed one
    /// all look identical from the configuration's side and only a developer
    /// can tell which it is.
    ///
    /// Set it when **one** configuration file deliberately serves several
    /// build variants: entries for feature-gated contracts are then reported
    /// as `inactive` for the variants that do not compile them, rather than
    /// blocking. It is a statement that the unmatched entries are expected,
    /// which is why it has to be written down rather than inferred.
    #[serde(default)]
    pub allow_inactive_config: bool,
    #[serde(default)]
    pub contracts: BTreeMap<String, ContractPolicy>,
    #[serde(default)]
    pub exemptions: Vec<Exemption>,
}

fn default_required() -> Vec<Analysis> {
    vec![Analysis::Generated]
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            mode: Mode::default(),
            default_required: default_required(),
            allow_empty_inventory: false,
            allow_inactive_config: false,
            contracts: BTreeMap::new(),
            exemptions: Vec::new(),
        }
    }
}

impl PolicyConfig {
    /// Rejects a policy that could not be enforced as written.
    pub fn validate(&self) -> Result<(), String> {
        if self.default_required.is_empty() && self.mode == Mode::Strict {
            return Err(
                "`policy.default_required` is empty in strict mode, so no declaration would \
                 require anything and a passing run would establish nothing. List the analyses \
                 explicitly, e.g. default_required = [\"generated\"]"
                    .to_string(),
            );
        }
        if let Some(duplicate) = duplicate(&self.default_required) {
            return Err(format!("`policy.default_required` lists {duplicate} twice"));
        }
        for (contract, entry) in &self.contracts {
            if let Some(required) = &entry.required {
                if let Some(duplicate) = duplicate(required) {
                    return Err(format!(
                        "[policy.contracts.\"{contract}\"]: `required` lists {duplicate} twice"
                    ));
                }
                if required.is_empty() && self.mode == Mode::Strict {
                    return Err(format!(
                        "[policy.contracts.\"{contract}\"]: `required` is empty in strict mode. \
                         To waive an obligation deliberately, write an exemption with a reason \
                         rather than an empty requirement"
                    ));
                }
            }
        }
        for exemption in &self.exemptions {
            exemption.validate(self.mode)?;
        }
        let mut seen: BTreeSet<(&str, Analysis)> = BTreeSet::new();
        for exemption in &self.exemptions {
            for analysis in &exemption.analyses {
                if !seen.insert((exemption.contract.as_str(), *analysis)) {
                    return Err(format!(
                        "`{}` is exempted from `{analysis}` twice",
                        exemption.contract
                    ));
                }
            }
        }
        Ok(())
    }

    /// The analyses required of one contract.
    pub fn required_for(&self, contract: &str) -> Vec<Analysis> {
        let mut required = self
            .contracts
            .get(contract)
            .and_then(|entry| entry.required.clone())
            .unwrap_or_else(|| self.default_required.clone());
        required.sort_unstable();
        required.dedup();
        required
    }

    /// The waiver covering this contract and analysis, if any.
    pub fn exemption(&self, contract: &str, analysis: Analysis) -> Option<&Exemption> {
        self.exemptions
            .iter()
            .find(|entry| entry.contract == contract && entry.analyses.contains(&analysis))
    }
}

fn duplicate(analyses: &[Analysis]) -> Option<Analysis> {
    analyses
        .iter()
        .enumerate()
        .find(|(index, analysis)| analyses[..*index].contains(analysis))
        .map(|(_, analysis)| *analysis)
}

/// Why the generated backend cannot analyze a signature, if it cannot.
///
/// The same conditions [`crate::dynamic_harness::generate`] enforces, asked
/// *before* anything is built. That ordering is the point: the milestone
/// requires unsupported requirements to be reported up front rather than
/// discovered after a backend has been started.
pub fn generated_support(descriptor: &Descriptor) -> Result<(), String> {
    if descriptor.secrets().next().is_none() {
        return Err(
            "the contract declares no secret parameter, so there is nothing to mark".to_string(),
        );
    }
    for parameter in &descriptor.parameters {
        if parameter.repr.bytes().is_none() {
            return Err(format!(
                "parameter `{}` has type `{}`, for which no concrete value can be generated \
                 or marked",
                parameter.name, parameter.rust_type
            ));
        }
        if parameter.repr == Repr::Bool && parameter.role == Role::Secret {
            return Err(format!(
                "parameter `{}` is a secret `bool`; a one-bit secret is disclosed by any \
                 branch on it",
                parameter.name
            ));
        }
    }
    Ok(())
}

/// What each analysis of each contract will be held to, decided before any
/// backend runs.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub mode: Mode,
    /// Contracts in canonical order, with their requirements and any status
    /// already settled.
    pub entries: Vec<PlanEntry>,
    /// Configuration that named no active declaration.
    pub stale: Vec<StaleEntry>,
}

/// One contract's requirements, and anything already decided about them.
#[derive(Debug, Clone, Serialize)]
pub struct PlanEntry {
    pub id: String,
    pub site: String,
    pub required: Vec<Analysis>,
    /// Statuses settled without running anything: unsupported signatures,
    /// waivers, contracts not selected for this run.
    pub settled: BTreeMap<Analysis, Status>,
    /// The outcome an *analyzer-regression* fixture is declared to produce.
    ///
    /// `None` for a security contract, which is the default and the policy a
    /// developer's own function gets. M6's split is preserved rather than
    /// reinterpreted: for a security contract a leak fails, and for a fixture
    /// that exists to hold trace-check to detecting a planted leak, finding it
    /// is the fixture passing.
    ///
    /// It can only arrive from an explicit `expectation =
    /// "analyzer-regression"`, because `CheckSettings::validate` refuses an
    /// `expected_outcome` on a security contract.
    pub regression_expectation: Option<Outcome>,
    /// Whether this contract was selected for the requested run.
    pub selected: bool,
}

impl PlanEntry {
    /// Requirements still needing a backend to run.
    pub fn outstanding(&self) -> Vec<Analysis> {
        self.required
            .iter()
            .copied()
            .filter(|analysis| !self.settled.contains_key(analysis))
            .collect()
    }
}

/// A configuration or policy entry that matches no active declaration.
///
/// Reported rather than ignored: a typo, a renamed function and a
/// feature-gated contract that is simply not in this build all look the same
/// from the configuration's side, and only the developer can tell which it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaleEntry {
    pub contract: String,
    /// Which table it came from, so the diagnostic can name the line to fix.
    pub source: &'static str,
    pub detail: String,
}

impl Plan {
    /// Resolves the policy against an inventory and a selection.
    ///
    /// Deterministic and backend-free: its inputs are the inventory, the
    /// configuration, the selection and the set of available backends, and it
    /// runs before anything heavyweight so unsupported or unavailable
    /// requirements are reported up front.
    ///
    /// # Exemptions waive obligations, never evidence
    ///
    /// A waiver is applied here, where no analysis has run and so no leak can
    /// yet be known. [`Coverage::fold`] applies evidence afterwards and lets a
    /// detected leak overwrite a waived status — never the reverse. So a
    /// waiver can excuse *not looking*, and cannot excuse what was found by
    /// looking.
    pub fn resolve(
        inventory: &ContractInventory,
        config: &VerifyConfig,
        policy: &PolicyConfig,
        selected: &[String],
        available: &Available,
        today: &str,
    ) -> Plan {
        let chosen: BTreeSet<&str> = selected.iter().map(String::as_str).collect();
        let mut entries = Vec::new();
        for declaration in &inventory.contracts {
            let required = policy.required_for(&declaration.id);
            let is_selected = chosen.contains(declaration.id.as_str());
            let mut settled: BTreeMap<Analysis, Status> = BTreeMap::new();
            for analysis in &required {
                if let Some(status) = settle(
                    declaration,
                    *analysis,
                    policy,
                    is_selected,
                    available,
                    today,
                    config.settings(&declaration.id).is_some(),
                ) {
                    settled.insert(*analysis, status);
                }
            }
            entries.push(PlanEntry {
                id: declaration.id.clone(),
                site: declaration.site(),
                required,
                settled,
                regression_expectation: regression_expectation(config, &declaration.id),
                selected: is_selected,
            });
        }
        Plan {
            mode: policy.mode,
            entries,
            stale: stale(inventory, config, policy),
        }
    }

    pub fn entry(&self, id: &str) -> Option<&PlanEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }
}

/// The declared outcome of an analyzer-regression fixture, if the
/// configuration makes it one.
fn regression_expectation(config: &VerifyConfig, contract: &str) -> Option<Outcome> {
    let settings = config.check.get(contract)?;
    if settings.expectation != crate::contract::Expectation::AnalyzerRegression {
        return None;
    }
    Outcome::parse(settings.expected_outcome.as_deref()?)
}

/// What one requirement's status is before any backend runs, if it is already
/// decided.
fn settle(
    declaration: &ContractDeclaration,
    analysis: Analysis,
    policy: &PolicyConfig,
    selected: bool,
    available: &Available,
    today: &str,
    configured_for_symbolic: bool,
) -> Option<Status> {
    // An expired waiver is not a waiver. It is reported as the gap it always
    // was, with its reason, so the lapse is visible rather than silent.
    if let Some(exemption) = policy.exemption(&declaration.id, analysis) {
        if exemption.expired(today) {
            return Some(Status::Inconclusive {
                detail: format!(
                    "the exemption from `{analysis}` expired on {} ({}). An expired waiver is \
                     the gap it always was",
                    exemption.expires.clone().unwrap_or_default(),
                    exemption.reason
                ),
            });
        }
        return Some(Status::Exempted {
            reason: exemption.reason.clone(),
            tracking: exemption.tracking.clone(),
            expires: exemption.expires.clone(),
        });
    }
    // An unsupported signature is settled without a backend: no amount of
    // analysis will make a harness constructible for it.
    if matches!(analysis, Analysis::Generated | Analysis::Explore) {
        if let Err(reason) = generated_support(&declaration.descriptor) {
            return Some(Status::Unsupported { reason });
        }
        // A function that is not `pub` cannot be named by the external probe
        // harness the generated backend builds. Settled here so the read-only
        // `coverage` command reports it too, and so the declaration gets a
        // status rather than the run getting an error. `pub` is necessary and
        // not sufficient -- a `pub fn` in a private module is unreachable as
        // well -- so the probe remains the authority and reports that case
        // per contract.
        if !declaration.externally_nameable {
            return Some(Status::Unsupported {
                reason: format!(
                    "`{}` is not `pub`, so the generated harness -- which is a separate crate \
                     that calls the real function -- cannot name it. Make it `pub`, or exempt \
                     the obligation with a reason",
                    declaration.id
                ),
            });
        }
    }
    // Symbolic verification needs declared bounds -- an exploration depth and
    // an observation model -- which cannot be inferred from a signature. A
    // requirement with no `[verify]` entry is a configuration gap, and saying
    // so here means the developer hears it before a container is started.
    if analysis == Analysis::Symbolic && !configured_for_symbolic {
        return Some(Status::Inconclusive {
            detail: format!(
                "`symbolic` is required but there is no [verify.\"{}\"] entry. A bounded \
                 symbolic search needs a declared depth and observation model, which cannot be \
                 inferred from the signature",
                declaration.id
            ),
        });
    }
    // A `dynamic` requirement is evidence from a developer-written
    // `#[ct_test]`, which `cargo trace-check test` produces and this command
    // does not run.
    if analysis == Analysis::Dynamic && !declaration.dynamic_adapter_enabled {
        return Some(Status::Unsupported {
            reason: format!(
                "`dynamic` is required but `{}` is declared `dynamic = false`, so no test \
                 adapter exists to cover it",
                declaration.id
            ),
        });
    }
    if !selected {
        return Some(Status::NotSelected);
    }
    // Not something this command runs. Distinguished from an absent analyzer
    // on purpose; see `Available::performs`.
    if !available.performs(analysis) {
        let command = available
            .elsewhere
            .get(&analysis)
            .cloned()
            .unwrap_or_else(|| "another trace-check command".to_string());
        return Some(Status::not_performed(analysis, &command));
    }
    if !available.has(analysis) {
        return Some(Status::BackendUnavailable {
            backend: analysis.backend().to_string(),
        });
    }
    None
}

/// Configuration and policy entries that match no active declaration.
fn stale(
    inventory: &ContractInventory,
    config: &VerifyConfig,
    policy: &PolicyConfig,
) -> Vec<StaleEntry> {
    let active: BTreeSet<&str> = inventory.contracts.iter().map(|c| c.id.as_str()).collect();
    let detail = |name: &str| {
        format!(
            "no active declaration matches `{name}` in this build ({}). It may be a typo, a \
             renamed or removed function, or a contract behind a feature this build did not \
             enable",
            inventory.build.variant()
        )
    };
    let mut out = Vec::new();
    for name in config.check.keys() {
        if !active.contains(name.as_str()) {
            out.push(StaleEntry {
                contract: name.clone(),
                source: "check",
                detail: detail(name),
            });
        }
    }
    for name in config.verify.keys() {
        if !active.contains(name.as_str()) {
            out.push(StaleEntry {
                contract: name.clone(),
                source: "verify",
                detail: detail(name),
            });
        }
    }
    for name in policy.contracts.keys() {
        if !active.contains(name.as_str()) {
            out.push(StaleEntry {
                contract: name.clone(),
                source: "policy.contracts",
                detail: detail(name),
            });
        }
    }
    for exemption in &policy.exemptions {
        if !active.contains(exemption.contract.as_str()) {
            out.push(StaleEntry {
                contract: exemption.contract.clone(),
                source: "policy.exemptions",
                detail: format!(
                    "{} A waiver for a contract that is not here waives nothing",
                    detail(&exemption.contract)
                ),
            });
        }
    }
    out.sort_by(|left, right| (left.source, &left.contract).cmp(&(right.source, &right.contract)));
    out
}

/// Which backends this run can actually use.
///
/// Passed in rather than probed here, so the resolver stays a pure function and
/// a test can describe any combination of missing backends.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Available {
    pub generated: bool,
    pub explore: bool,
    pub symbolic: bool,
    pub dynamic: bool,
    /// Analyses the *command* performs, as distinct from backends present.
    ///
    /// `check` runs the generated family; `symbolic` evidence comes from
    /// `verify` and `dynamic` from `test`. Conflating the two would report
    /// BACKEND_UNAVAILABLE for an analyzer that is installed and simply not
    /// invoked here, sending a developer to fix their machine instead of
    /// running the other command.
    pub performs: Vec<Analysis>,
    /// The command that would run an analysis this one does not, named in the
    /// status so the report is actionable.
    pub elsewhere: BTreeMap<Analysis, String>,
}

impl Available {
    /// Everything present, and every analysis performed. The shape a test
    /// uses when the question is not about availability.
    pub fn all() -> Available {
        Available {
            generated: true,
            explore: true,
            symbolic: true,
            dynamic: true,
            performs: Analysis::all().to_vec(),
            elsewhere: BTreeMap::new(),
        }
    }

    /// Whether this command runs `analysis` at all.
    pub fn performs(&self, analysis: Analysis) -> bool {
        self.performs.contains(&analysis)
    }

    pub fn has(&self, analysis: Analysis) -> bool {
        match analysis {
            Analysis::Generated => self.generated,
            Analysis::Explore => self.explore,
            Analysis::Symbolic => self.symbolic,
            Analysis::Dynamic => self.dynamic,
        }
    }
}

/// One contract's enforcement status and evidence.
#[derive(Debug, Clone, Serialize)]
pub struct ContractCoverage {
    pub id: String,
    pub site: String,
    /// See [`PlanEntry::regression_expectation`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regression_expectation: Option<Outcome>,
    /// Whether the macro emitted M3's test adapter for it, recorded because a
    /// `dynamic` requirement cannot be met without one.
    pub dynamic_adapter_enabled: bool,
    pub required: Vec<Analysis>,
    pub status: BTreeMap<Analysis, Status>,
    /// What backends observed, in the order they were folded in.
    pub evidence: Vec<AnalysisEvidence>,
}

impl ContractCoverage {
    /// Whether every requirement is discharged.
    pub fn satisfied(&self) -> bool {
        !self.violated()
            && self
                .required
                .iter()
                .all(|analysis| self.status.get(analysis).is_some_and(Status::satisfied))
    }

    /// Whether any analysis found a violation.
    ///
    /// Checked ahead of satisfaction, deliberately: a waiver may excuse a
    /// missing analysis, and nothing excuses a leak that was found.
    pub fn violated(&self) -> bool {
        if self.status.values().any(Status::violation) {
            return true;
        }
        // Evidence of a leak is a violation *unless* this contract is a
        // declared analyzer-regression fixture whose whole purpose is to be
        // detected. That split is M6's and is preserved exactly: only an
        // explicit `expectation = "analyzer-regression"` with a matching
        // `expected_outcome` reaches here, and a security contract cannot
        // declare one.
        self.evidence.iter().any(|evidence| {
            evidence.outcome == Outcome::LeakDetected
                && self.regression_expectation != Some(Outcome::LeakDetected)
        })
    }

    /// Requirements that are neither satisfied nor violated.
    ///
    /// A requirement with no status at all is a gap, not an absence: see
    /// [`Status::NotAnalyzed`]. `Coverage::from_plan` fills the map so this
    /// cannot arise, and the fallback is here so a hand-built coverage value
    /// cannot reintroduce it.
    pub fn gaps(&self) -> Vec<(Analysis, Status)> {
        self.required
            .iter()
            .filter_map(|analysis| {
                let status = self
                    .status
                    .get(analysis)
                    .cloned()
                    .unwrap_or_else(Status::not_analyzed);
                (!status.satisfied() && !status.violation()).then_some((*analysis, status))
            })
            .collect()
    }

    pub fn evidence_for(&self, analysis: Analysis) -> Option<&AnalysisEvidence> {
        self.evidence
            .iter()
            .find(|evidence| evidence.analysis == analysis)
    }
}

/// Enforcement across every declared contract.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub mode: Mode,
    pub contracts: Vec<ContractCoverage>,
    pub stale: Vec<StaleEntry>,
}

impl Coverage {
    /// Starts from a resolved plan, before any evidence.
    pub fn from_plan(plan: &Plan, inventory: &ContractInventory) -> Coverage {
        Coverage {
            mode: plan.mode,
            contracts: plan
                .entries
                .iter()
                .map(|entry| ContractCoverage {
                    id: entry.id.clone(),
                    site: entry.site.clone(),
                    regression_expectation: entry.regression_expectation,
                    dynamic_adapter_enabled: inventory
                        .contract(&entry.id)
                        .is_some_and(|d| d.dynamic_adapter_enabled),
                    required: entry.required.clone(),
                    // Total over the requirements: anything a backend has yet
                    // to report starts as `NotAnalyzed` rather than as a
                    // missing entry, so no requirement can escape the
                    // accounting by simply not being there.
                    status: entry
                        .required
                        .iter()
                        .map(|analysis| {
                            let status = entry
                                .settled
                                .get(analysis)
                                .cloned()
                                .unwrap_or_else(Status::not_analyzed);
                            (*analysis, status)
                        })
                        .collect(),
                    evidence: Vec::new(),
                })
                .collect(),
            stale: plan.stale.clone(),
        }
    }

    /// Folds one backend's observation into a contract's coverage.
    ///
    /// # A leak always wins
    ///
    /// Evidence of a detected leak sets [`Status::LeakDetected`] whatever the
    /// status was — including over a waiver. That is the rule the milestone is
    /// explicit about: an exemption waives the obligation to *perform* an
    /// analysis, and cannot waive or erase what an analysis found. A run that
    /// waived the generated check and then ran it anyway, finding a leak,
    /// reports the leak.
    pub fn fold(&mut self, id: &str, evidence: AnalysisEvidence) {
        let Some(contract) = self.contracts.iter_mut().find(|entry| entry.id == id) else {
            return;
        };
        let analysis = evidence.analysis;
        let status = match contract.regression_expectation {
            // An analyzer-regression fixture is held to the outcome it
            // declares, which is a statement about trace-check rather than
            // about the function being secure. A planted leak that was found
            // is the fixture passing; a declared outcome that did not arrive
            // is the fixture failing.
            Some(declared) if evidence.outcome == declared => Status::Checked,
            Some(declared) => Status::Inconclusive {
                detail: format!(
                    "analyzer regression: declared {declared} but {analysis} produced {}: {}",
                    evidence.outcome, evidence.detail
                ),
            },
            // A security contract. A leak fails, whatever else is configured.
            None if evidence.outcome == Outcome::LeakDetected => Status::LeakDetected,
            None if evidence.outcome == analysis.discharged_by() => Status::Checked,
            None => Status::Inconclusive {
                detail: format!(
                    "{analysis} requires {} and the analysis produced {}: {}",
                    analysis.discharged_by(),
                    evidence.outcome,
                    evidence.detail
                ),
            },
        };
        // A leak overwrites anything, including an exemption. Nothing else
        // overwrites a leak.
        let existing = contract.status.get(&analysis);
        if !existing.is_some_and(Status::violation) {
            contract.status.insert(analysis, status);
        }
        contract.evidence.push(evidence);
    }

    /// Records a status for one requirement without any backend evidence.
    ///
    /// For a failure that *is* the answer: a contract whose harness cannot be
    /// built has no outcome to fold, and its status is the reason why. A
    /// recorded leak is still never overwritten.
    pub fn note(&mut self, id: &str, analysis: Analysis, status: Status) {
        let Some(contract) = self.contracts.iter_mut().find(|entry| entry.id == id) else {
            return;
        };
        if contract
            .status
            .get(&analysis)
            .is_some_and(Status::violation)
        {
            return;
        }
        contract.status.insert(analysis, status);
    }

    pub fn contract(&self, id: &str) -> Option<&ContractCoverage> {
        self.contracts.iter().find(|entry| entry.id == id)
    }

    /// Enforcement coverage: requirements satisfied over requirements owed.
    ///
    /// Exemptions are reported separately and **excluded from the numerator**,
    /// so a waived contract cannot inflate the proportion actually checked.
    /// The denominator excludes them too, because an obligation that was
    /// deliberately waived is not an obligation this run failed to meet.
    pub fn enforcement(&self) -> Enforcement {
        let mut counts = Enforcement::default();
        for contract in &self.contracts {
            counts.declared += 1;
            if contract.violated() {
                counts.violations += 1;
            }
            let mut any_exempt = false;
            let mut all_checked = true;
            for analysis in &contract.required {
                match contract.status.get(analysis) {
                    Some(Status::Checked) => counts.requirements_checked += 1,
                    Some(Status::Exempted { .. }) => {
                        any_exempt = true;
                        counts.requirements_exempted += 1;
                        all_checked = false;
                    }
                    _ => all_checked = false,
                }
                counts.requirements += 1;
            }
            if contract.violated() {
                // Counted as a violation, not as a gap.
            } else if all_checked {
                counts.checked += 1;
            } else if any_exempt && contract.satisfied() {
                counts.exempted += 1;
            } else {
                counts.lacking_evidence += 1;
            }
        }
        counts
    }

    /// Reasons this run must not be reported as a success.
    ///
    /// In advisory mode only violations and inventory problems block; gaps are
    /// reported but tolerated. In strict mode a gap blocks too.
    pub fn blocking(&self, inventory: &ContractInventory, policy: &PolicyConfig) -> Vec<String> {
        let mut blocking = Vec::new();
        if !inventory.complete() {
            blocking.push(format!(
                "the contract inventory is not complete: {} of {} object member(s) of {} could \
                 be read, so some declarations may be missing entirely",
                inventory.objects_read, inventory.objects_inspected, inventory.build.artifact_path
            ));
        }
        if self.contracts.is_empty() && !policy.allow_empty_inventory {
            blocking.push(format!(
                "no contract declarations were found in {}. A library with none is legitimate, \
                 but so is a selection that found none by mistake, and this run cannot tell \
                 them apart. Set `policy.allow_empty_inventory = true` to declare the empty \
                 inventory intentional",
                inventory.build.variant()
            ));
        }
        for contract in &self.contracts {
            if contract.violated() {
                blocking.push(format!(
                    "`{}` ({}): a required security property was violated",
                    contract.id, contract.site
                ));
                continue;
            }
            if self.mode == Mode::Advisory {
                continue;
            }
            for (analysis, status) in contract.gaps() {
                blocking.push(format!(
                    "`{}` ({}): {} is {} -- {}",
                    contract.id,
                    contract.site,
                    analysis,
                    status.as_str(),
                    status.describe()
                ));
            }
        }
        if !policy.allow_inactive_config {
            for entry in &self.stale {
                blocking.push(format!(
                    "[{}.\"{}\"]: {}",
                    entry.source, entry.contract, entry.detail
                ));
            }
        }
        blocking
    }
}

/// Counted enforcement, with exemptions kept out of the checked total.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Enforcement {
    /// Declarations in the inventory.
    pub declared: usize,
    /// Declarations whose every requirement completed and passed.
    pub checked: usize,
    /// Declarations with a detected violation.
    pub violations: usize,
    /// Declarations satisfied only because something was waived.
    pub exempted: usize,
    /// Declarations with an unmet requirement that was not waived.
    pub lacking_evidence: usize,
    /// Individual requirements owed, across all declarations.
    pub requirements: usize,
    pub requirements_checked: usize,
    pub requirements_exempted: usize,
}

impl Enforcement {
    /// Requirements satisfied over requirements owed, excluding waived ones
    /// from both.
    ///
    /// `None` when nothing was owed — a rate over zero obligations is not 100 %
    /// and should not be printed as one.
    pub fn rate(&self) -> Option<f64> {
        let owed = self.requirements.saturating_sub(self.requirements_exempted);
        if owed == 0 {
            return None;
        }
        Some(self.requirements_checked as f64 / owed as f64)
    }

    /// What the rate is and is not, for a report that prints it.
    pub fn caveat() -> &'static str {
        "Enforcement coverage is the proportion of declared requirements that were met. It is \
         not the proportion of secret inputs proven safe, and it says nothing about functions \
         that carry no declaration."
    }
}

/// Inventory fixtures for tests in this crate.
#[cfg(test)]
pub mod test_support {
    use crate::inventory::{ArchiveRead, BuildIdentity, ContractDeclaration, ContractInventory};

    /// A declaration with one `u8` secret parameter.
    pub fn declaration(id: &str) -> ContractDeclaration {
        let json = r#"{"schema_version":1,"function":"probe","parameters":[{"name":"key","position":0,"role":"secret","repr":"u8","rust_type":"u8"}],"returns":{"repr":"u8","rust_type":"u8"}}"#;
        ContractDeclaration {
            id: id.to_string(),
            module: id.rsplit_once("::").expect("a qualified id").0.to_string(),
            function: "probe".to_string(),
            source_file: "src/lib.rs".to_string(),
            source_line: 7,
            dynamic_adapter_enabled: true,
            externally_nameable: true,
            descriptor: crate::contract::Descriptor::parse(json).expect("parses"),
            descriptor_json: json.to_string(),
            descriptor_sha256: "sha".to_string(),
        }
    }

    pub fn identity() -> BuildIdentity {
        BuildIdentity {
            package: "crypto-library".to_string(),
            version: "0.1.0".to_string(),
            lib_target: "crypto".to_string(),
            manifest_path: "/x/Cargo.toml".to_string(),
            features: Vec::new(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            rustc_version: "rustc 1.97.0".to_string(),
            profile: crate::inventory::PROFILE.to_string(),
            artifact_path: "/x/libcrypto.rlib".to_string(),
            artifact_sha256: "deadbeef".to_string(),
        }
    }

    pub fn inventory(ids: &[&str]) -> ContractInventory {
        crate::inventory::assemble_for_test(
            identity(),
            ArchiveRead {
                contracts: ids.iter().map(|id| declaration(id)).collect(),
                objects_inspected: 1,
                objects_read: 1,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{ArchiveRead, BuildIdentity};

    const TODAY: &str = "2026-11-03";

    fn descriptor(secret_bool: bool) -> Descriptor {
        let repr = if secret_bool { "bool" } else { "u8" };
        let json = format!(
            r#"{{"schema_version":1,"function":"probe","parameters":[{{"name":"key","position":0,"role":"secret","repr":"{repr}","rust_type":"{repr}"}}],"returns":{{"repr":"u8","rust_type":"u8"}}}}"#
        );
        Descriptor::parse(&json).expect("the fixture descriptor parses")
    }

    fn declaration(id: &str, secret_bool: bool) -> ContractDeclaration {
        ContractDeclaration {
            id: id.to_string(),
            module: id.rsplit_once("::").expect("a qualified id").0.to_string(),
            function: "probe".to_string(),
            source_file: "src/lib.rs".to_string(),
            source_line: 7,
            dynamic_adapter_enabled: true,
            externally_nameable: true,
            descriptor: descriptor(secret_bool),
            descriptor_json: "{}".to_string(),
            descriptor_sha256: "sha".to_string(),
        }
    }

    fn inventory(ids: &[&str]) -> ContractInventory {
        inventory_with(ids.iter().map(|id| declaration(id, false)).collect())
    }

    fn inventory_with(contracts: Vec<ContractDeclaration>) -> ContractInventory {
        let read = ArchiveRead {
            contracts,
            objects_inspected: 1,
            objects_read: 1,
        };
        let build = BuildIdentity {
            package: "crypto-library".to_string(),
            version: "0.1.0".to_string(),
            lib_target: "crypto".to_string(),
            manifest_path: "/x/Cargo.toml".to_string(),
            features: Vec::new(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            rustc_version: "rustc 1.97.0".to_string(),
            profile: crate::inventory::PROFILE.to_string(),
            artifact_path: "/x/libcrypto.rlib".to_string(),
            artifact_sha256: "deadbeef".to_string(),
        };
        crate::inventory::assemble_for_test(build, read)
    }

    fn evidence(analysis: Analysis, outcome: Outcome) -> AnalysisEvidence {
        AnalysisEvidence::summary(analysis, outcome, "artifact", "detail")
    }

    fn resolved(
        ids: &[&str],
        policy: &PolicyConfig,
        selected: &[&str],
        available: &Available,
    ) -> (ContractInventory, Coverage) {
        let found = inventory(ids);
        let chosen: Vec<String> = selected.iter().map(|s| s.to_string()).collect();
        let plan = Plan::resolve(
            &found,
            &VerifyConfig::empty(),
            policy,
            &chosen,
            available,
            TODAY,
        );
        let coverage = Coverage::from_plan(&plan, &found);
        (found, coverage)
    }

    /// A declaration with no configuration requires a generated check, which is
    /// the default that makes a new annotation enforceable without edits.
    #[test]
    fn a_declaration_requires_a_generated_check_by_default() {
        let policy = PolicyConfig::default();
        assert_eq!(
            policy.required_for("crypto::a::probe"),
            vec![Analysis::Generated]
        );
        assert_eq!(policy.mode, Mode::Strict);
        // Symbolic verification is deliberately not required of everything: a
        // container image must not become a prerequisite for annotating.
        assert!(!policy
            .required_for("crypto::a::probe")
            .contains(&Analysis::Symbolic));
    }

    /// A clean generated run satisfies a generated requirement and nothing
    /// more.
    #[test]
    fn a_generated_run_does_not_satisfy_a_symbolic_requirement() {
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            "crypto::a::probe".to_string(),
            ContractPolicy {
                required: Some(vec![Analysis::Generated, Analysis::Symbolic]),
            },
        );
        let (found, mut coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::NoLeakObserved),
        );

        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert_eq!(contract.status[&Analysis::Generated], Status::Checked);
        assert!(
            !contract.satisfied(),
            "a generated run must not discharge a symbolic requirement"
        );
        let gaps = contract.gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].0, Analysis::Symbolic);
        assert!(!coverage.blocking(&found, &policy).is_empty());
    }

    /// A `VERIFIED_BOUNDED` result satisfies a symbolic requirement.
    #[test]
    fn verified_bounded_satisfies_a_symbolic_requirement() {
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            "crypto::a::probe".to_string(),
            ContractPolicy {
                required: Some(vec![Analysis::Symbolic]),
            },
        );
        let (found, mut coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Symbolic, Outcome::VerifiedBounded),
        );
        assert!(coverage
            .contract("crypto::a::probe")
            .expect("the contract")
            .satisfied());
        assert!(coverage.blocking(&found, &policy).is_empty());
    }

    /// An inconclusive symbolic result does not satisfy the requirement, and
    /// the gap says what was wanted and what arrived.
    #[test]
    fn an_inconclusive_result_does_not_satisfy_a_requirement() {
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            "crypto::a::probe".to_string(),
            ContractPolicy {
                required: Some(vec![Analysis::Symbolic]),
            },
        );
        let (_, mut coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Symbolic, Outcome::Inconclusive),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert!(!contract.satisfied());
        match &contract.status[&Analysis::Symbolic] {
            Status::Inconclusive { detail } => {
                assert!(detail.contains("VERIFIED_BOUNDED"), "{detail}");
                assert!(detail.contains("INCONCLUSIVE"), "{detail}");
            }
            other => panic!("unexpected status: {other:?}"),
        }
    }

    /// An unsupported signature is settled before any backend runs, and fails
    /// strict enforcement.
    #[test]
    fn an_unsupported_signature_is_settled_up_front_and_fails() {
        let policy = PolicyConfig::default();
        let found = inventory_with(vec![declaration("crypto::a::probe", true)]);
        let plan = Plan::resolve(
            &found,
            &VerifyConfig::empty(),
            &policy,
            &["crypto::a::probe".to_string()],
            &Available::all(),
            TODAY,
        );
        let entry = plan.entry("crypto::a::probe").expect("the entry");
        // Nothing is left for a backend to decide.
        assert!(entry.outstanding().is_empty());
        match &entry.settled[&Analysis::Generated] {
            Status::Unsupported { reason } => assert!(reason.contains("secret `bool`"), "{reason}"),
            other => panic!("unexpected status: {other:?}"),
        }
        let coverage = Coverage::from_plan(&plan, &found);
        assert!(!coverage
            .contract("crypto::a::probe")
            .expect("c")
            .satisfied());
        assert!(coverage
            .blocking(&found, &policy)
            .iter()
            .any(|reason| reason.contains("UNSUPPORTED")));
    }

    /// A missing backend is a gap, reported up front and named.
    #[test]
    fn a_missing_backend_is_reported_before_anything_runs() {
        let policy = PolicyConfig::default();
        let (found, coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available {
                generated: false,
                ..Available::all()
            },
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        match &contract.status[&Analysis::Generated] {
            Status::BackendUnavailable { backend } => assert_eq!(backend, "valgrind"),
            other => panic!("unexpected status: {other:?}"),
        }
        assert!(coverage
            .blocking(&found, &policy)
            .iter()
            .any(|reason| reason.contains("BACKEND_UNAVAILABLE")));
    }

    /// A known applicable contract left out of the run is reported, not
    /// omitted. This is the asymmetry M8 exists to close.
    #[test]
    fn an_unselected_contract_is_accounted_for() {
        let policy = PolicyConfig::default();
        let (found, coverage) = resolved(
            &["crypto::a::probe", "crypto::b::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        let skipped = coverage.contract("crypto::b::probe").expect("the contract");
        assert_eq!(skipped.status[&Analysis::Generated], Status::NotSelected);
        assert!(!skipped.satisfied());
        let blocking = coverage.blocking(&found, &policy);
        assert!(
            blocking
                .iter()
                .any(|reason| reason.contains("crypto::b::probe")),
            "{blocking:?}"
        );
    }

    /// A valid exemption satisfies the obligation, is visible, and carries its
    /// reason.
    #[test]
    fn a_valid_exemption_satisfies_and_stays_visible() {
        let policy = PolicyConfig {
            exemptions: vec![Exemption {
                contract: "crypto::a::probe".to_string(),
                analyses: vec![Analysis::Generated],
                reason: "unsupported field-element parameter".to_string(),
                tracking: Some("https://example/42".to_string()),
                expires: Some("2027-03-01".to_string()),
                never_expires: false,
            }],
            ..PolicyConfig::default()
        };
        policy.validate().expect("the policy is valid");
        let (found, coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert!(contract.satisfied());
        match &contract.status[&Analysis::Generated] {
            Status::Exempted {
                reason, tracking, ..
            } => {
                assert!(reason.contains("field-element"));
                assert!(tracking.is_some());
            }
            other => panic!("unexpected status: {other:?}"),
        }
        assert!(coverage.blocking(&found, &policy).is_empty());
        // And it does not inflate the checked count.
        let counts = coverage.enforcement();
        assert_eq!(counts.declared, 1);
        assert_eq!(counts.checked, 0);
        assert_eq!(counts.exempted, 1);
        assert_eq!(counts.requirements_checked, 0);
        assert_eq!(counts.requirements_exempted, 1);
        // Nothing was owed after the waiver, so there is no rate to report.
        assert_eq!(counts.rate(), None);
    }

    /// An expired exemption is the gap it always was, and fails.
    #[test]
    fn an_expired_exemption_fails() {
        let policy = PolicyConfig {
            exemptions: vec![Exemption {
                contract: "crypto::a::probe".to_string(),
                analyses: vec![Analysis::Generated],
                reason: "waiting on a parameter type".to_string(),
                tracking: None,
                expires: Some("2020-01-01".to_string()),
                never_expires: false,
            }],
            ..PolicyConfig::default()
        };
        let (found, coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert!(!contract.satisfied());
        match &contract.status[&Analysis::Generated] {
            Status::Inconclusive { detail } => {
                assert!(detail.contains("expired on 2020-01-01"), "{detail}");
                assert!(detail.contains("parameter type"), "{detail}");
            }
            other => panic!("unexpected status: {other:?}"),
        }
        assert!(!coverage.blocking(&found, &policy).is_empty());
    }

    /// An exemption cannot erase a detected leak. The milestone's rule, and the
    /// single most important property in this module.
    #[test]
    fn an_exemption_cannot_erase_a_detected_leak() {
        let policy = PolicyConfig {
            exemptions: vec![Exemption {
                contract: "crypto::a::probe".to_string(),
                analyses: vec![Analysis::Generated],
                reason: "we do not have time to fix this".to_string(),
                tracking: None,
                never_expires: true,
                expires: None,
            }],
            ..PolicyConfig::default()
        };
        let (found, mut coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        // Waived up front...
        assert!(matches!(
            coverage.contract("crypto::a::probe").expect("c").status[&Analysis::Generated],
            Status::Exempted { .. }
        ));
        // ...and then the analysis ran anyway and found a leak.
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::LeakDetected),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert_eq!(contract.status[&Analysis::Generated], Status::LeakDetected);
        assert!(contract.violated());
        assert!(!contract.satisfied());
        let blocking = coverage.blocking(&found, &policy);
        assert!(
            blocking.iter().any(|reason| reason.contains("violated")),
            "{blocking:?}"
        );
        assert_eq!(coverage.enforcement().violations, 1);
    }

    /// Nothing overwrites a recorded leak, whatever arrives afterwards.
    #[test]
    fn nothing_overwrites_a_recorded_leak() {
        let policy = PolicyConfig::default();
        let (_, mut coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::LeakDetected),
        );
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::NoLeakObserved),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert_eq!(contract.status[&Analysis::Generated], Status::LeakDetected);
        assert!(contract.violated());
        // Both observations are kept: the report shows what happened.
        assert_eq!(contract.evidence.len(), 2);
    }

    /// An exemption with no reason, no analyses, or no expiry in strict mode is
    /// refused.
    #[test]
    fn a_weak_exemption_is_refused() {
        let base = Exemption {
            contract: "crypto::a::probe".to_string(),
            analyses: vec![Analysis::Generated],
            reason: "a reason".to_string(),
            tracking: None,
            expires: Some("2027-01-01".to_string()),
            never_expires: false,
        };
        base.validate(Mode::Strict).expect("the baseline is valid");

        let no_reason = Exemption {
            reason: "   ".to_string(),
            ..base.clone()
        };
        assert!(no_reason
            .validate(Mode::Strict)
            .expect_err("a reasonless waiver is refused")
            .contains("indistinguishable"));

        let no_analyses = Exemption {
            analyses: Vec::new(),
            ..base.clone()
        };
        assert!(no_analyses
            .validate(Mode::Strict)
            .expect_err("an empty analyses list is refused")
            .contains("written out"));

        let no_expiry = Exemption {
            expires: None,
            ..base.clone()
        };
        assert!(no_expiry
            .validate(Mode::Strict)
            .expect_err("strict mode requires an expiry")
            .contains("never_expires"));
        // Advisory mode tolerates it.
        no_expiry
            .validate(Mode::Advisory)
            .expect("advisory mode does not require an expiry");
        // And a deliberate non-expiring waiver is accepted in strict mode.
        Exemption {
            expires: None,
            never_expires: true,
            ..base.clone()
        }
        .validate(Mode::Strict)
        .expect("a deliberate non-expiring waiver is allowed");
        // But not both at once.
        assert!(Exemption {
            never_expires: true,
            ..base.clone()
        }
        .validate(Mode::Strict)
        .is_err());
    }

    /// A malformed expiry is a configuration error, not a waiver that never
    /// expires.
    #[test]
    fn a_malformed_expiry_is_refused() {
        for bad in ["2027-3-1", "March 2027", "2027-13-01", "2027-01-99", "2027"] {
            let exemption = Exemption {
                contract: "crypto::a::probe".to_string(),
                analyses: vec![Analysis::Generated],
                reason: "a reason".to_string(),
                tracking: None,
                expires: Some(bad.to_string()),
                never_expires: false,
            };
            assert!(
                exemption.validate(Mode::Strict).is_err(),
                "{bad:?} was accepted as a date"
            );
        }
    }

    /// Configuration naming no active declaration is reported, with the table
    /// it came from.
    #[test]
    fn stale_configuration_is_diagnosed() {
        let mut config = VerifyConfig::empty();
        config
            .check
            .insert("crypto::gone::probe".to_string(), Default::default());
        let policy = PolicyConfig {
            exemptions: vec![Exemption {
                contract: "crypto::also_gone::probe".to_string(),
                analyses: vec![Analysis::Generated],
                reason: "a reason".to_string(),
                tracking: None,
                never_expires: true,
                expires: None,
            }],
            ..PolicyConfig::default()
        };
        let found = inventory(&["crypto::a::probe"]);
        let plan = Plan::resolve(
            &found,
            &config,
            &policy,
            &["crypto::a::probe".to_string()],
            &Available::all(),
            TODAY,
        );
        let sources: Vec<&str> = plan.stale.iter().map(|entry| entry.source).collect();
        assert_eq!(sources, vec!["check", "policy.exemptions"]);
        assert!(plan.stale[0].detail.contains("typo"));
        assert!(plan.stale[1].detail.contains("waives nothing"));
        // Stale configuration blocks: only the developer can say whether it is
        // a typo or a feature-gated contract.
        let coverage = Coverage::from_plan(&plan, &found);
        let blocking = coverage.blocking(&found, &policy);
        assert_eq!(
            blocking
                .iter()
                .filter(|reason| reason.starts_with('['))
                .count(),
            2,
            "{blocking:?}"
        );
        // And the live contract, which nothing analyzed, blocks as a gap
        // rather than vanishing from the accounting.
        assert!(
            blocking.iter().any(
                |reason| reason.contains("crypto::a::probe") && reason.contains("NOT_ANALYZED")
            ),
            "{blocking:?}"
        );
    }

    /// A contract on a function that is not `pub` is reported UNSUPPORTED for
    /// its generated requirement, and the other contracts are still checked.
    #[test]
    fn a_private_contract_is_unsupported_rather_than_fatal() {
        let private = ContractDeclaration {
            externally_nameable: false,
            ..declaration("crypto::inner::probe", false)
        };
        let found = inventory_with(vec![declaration("crypto::a::probe", false), private]);
        let policy = PolicyConfig::default();
        let plan = Plan::resolve(
            &found,
            &VerifyConfig::empty(),
            &policy,
            &[
                "crypto::a::probe".to_string(),
                "crypto::inner::probe".to_string(),
            ],
            &Available::all(),
            TODAY,
        );
        let inner = plan
            .entries
            .iter()
            .find(|entry| entry.id == "crypto::inner::probe")
            .expect("the private declaration is in the plan");
        match inner.settled.get(&Analysis::Generated) {
            Some(Status::Unsupported { reason }) => {
                assert!(reason.contains("not `pub`"), "{reason}")
            }
            other => panic!("expected UNSUPPORTED, got {other:?}"),
        }
        // The public one is still asked for, so one unanalyzable declaration
        // does not stop the run.
        let outer = plan
            .entries
            .iter()
            .find(|entry| entry.id == "crypto::a::probe")
            .expect("the public declaration is in the plan");
        assert!(!outer.settled.contains_key(&Analysis::Generated));
        assert!(outer.required.contains(&Analysis::Generated));
    }

    /// A date that passes a digit-range check but does not exist is rejected.
    #[test]
    fn an_impossible_calendar_date_is_rejected() {
        for bad in [
            "2027-02-31",
            "2027-02-29",
            "2027-04-31",
            "2027-06-31",
            "2027-09-31",
            "2027-11-31",
        ] {
            let exemption = Exemption {
                contract: "crypto::a::probe".to_string(),
                analyses: vec![Analysis::Generated],
                reason: "a reason".to_string(),
                tracking: None,
                never_expires: false,
                expires: Some(bad.to_string()),
            };
            assert!(
                exemption.validate(Mode::Strict).is_err(),
                "{bad:?} was accepted as a date"
            );
        }
        // A leap day that does exist is accepted.
        let leap = Exemption {
            contract: "crypto::a::probe".to_string(),
            analyses: vec![Analysis::Generated],
            reason: "a reason".to_string(),
            tracking: None,
            never_expires: false,
            expires: Some("2028-02-29".to_string()),
        };
        assert!(leap.validate(Mode::Strict).is_ok());
    }

    /// Configuration naming no active declaration blocks by default, and is
    /// tolerated only when the policy says one file serves several variants.
    #[test]
    fn inactive_configuration_is_tolerated_only_when_declared() {
        let mut config = VerifyConfig::empty();
        config
            .check
            .insert("crypto::gated::probe".to_string(), Default::default());
        let found = inventory(&["crypto::a::probe"]);
        let resolve = |policy: &PolicyConfig| {
            let plan = Plan::resolve(
                &found,
                &config,
                policy,
                &["crypto::a::probe".to_string()],
                &Available::all(),
                TODAY,
            );
            let mut coverage = Coverage::from_plan(&plan, &found);
            coverage.fold(
                "crypto::a::probe",
                evidence(Analysis::Generated, Outcome::NoLeakObserved),
            );
            coverage.blocking(&found, policy)
        };
        let strict = PolicyConfig::default();
        assert!(
            resolve(&strict)
                .iter()
                .any(|reason| reason.contains("crypto::gated::probe")),
            "unmatched configuration must block by default"
        );
        let permissive = PolicyConfig {
            allow_inactive_config: true,
            ..PolicyConfig::default()
        };
        assert!(
            resolve(&permissive).is_empty(),
            "{:?}",
            resolve(&permissive)
        );
    }

    /// An empty inventory does not pass strict enforcement unless the policy
    /// says the emptiness is intentional.
    #[test]
    fn an_empty_inventory_needs_explicit_permission() {
        let found = inventory(&[]);
        let policy = PolicyConfig::default();
        let plan = Plan::resolve(
            &found,
            &VerifyConfig::empty(),
            &policy,
            &[],
            &Available::all(),
            TODAY,
        );
        let coverage = Coverage::from_plan(&plan, &found);
        let blocking = coverage.blocking(&found, &policy);
        assert_eq!(blocking.len(), 1);
        assert!(
            blocking[0].contains("allow_empty_inventory"),
            "{blocking:?}"
        );

        let permissive = PolicyConfig {
            allow_empty_inventory: true,
            ..PolicyConfig::default()
        };
        assert!(coverage.blocking(&found, &permissive).is_empty());
    }

    /// An incomplete inventory blocks regardless of mode: declarations may be
    /// missing entirely, so nothing about the run can be trusted.
    #[test]
    fn an_incomplete_inventory_always_blocks() {
        let read = ArchiveRead {
            contracts: vec![declaration("crypto::a::probe", false)],
            objects_inspected: 4,
            objects_read: 2,
        };
        let found = inventory_with_read(read);
        assert!(!found.complete());
        for mode in [Mode::Strict, Mode::Advisory] {
            let policy = PolicyConfig {
                mode,
                ..PolicyConfig::default()
            };
            let plan = Plan::resolve(
                &found,
                &VerifyConfig::empty(),
                &policy,
                &["crypto::a::probe".to_string()],
                &Available::all(),
                TODAY,
            );
            let mut coverage = Coverage::from_plan(&plan, &found);
            coverage.fold(
                "crypto::a::probe",
                evidence(Analysis::Generated, Outcome::NoLeakObserved),
            );
            let blocking = coverage.blocking(&found, &policy);
            assert!(
                blocking
                    .iter()
                    .any(|reason| reason.contains("not complete")),
                "{mode:?}: {blocking:?}"
            );
        }
    }

    fn inventory_with_read(read: ArchiveRead) -> ContractInventory {
        let build = BuildIdentity {
            package: "crypto-library".to_string(),
            version: "0.1.0".to_string(),
            lib_target: "crypto".to_string(),
            manifest_path: "/x/Cargo.toml".to_string(),
            features: Vec::new(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            rustc_version: "rustc 1.97.0".to_string(),
            profile: crate::inventory::PROFILE.to_string(),
            artifact_path: "/x/libcrypto.rlib".to_string(),
            artifact_sha256: "deadbeef".to_string(),
        };
        crate::inventory::assemble_for_test(build, read)
    }

    /// Advisory mode reports gaps without blocking, and still blocks a leak.
    #[test]
    fn advisory_mode_reports_gaps_but_blocks_violations() {
        let policy = PolicyConfig {
            mode: Mode::Advisory,
            ..PolicyConfig::default()
        };
        let (found, mut coverage) = resolved(
            &["crypto::a::probe", "crypto::b::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        // `b` was not selected: a gap, tolerated in advisory mode.
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::NoLeakObserved),
        );
        assert!(coverage.blocking(&found, &policy).is_empty());
        assert_eq!(coverage.enforcement().lacking_evidence, 1);

        // A leak blocks even here.
        coverage.fold(
            "crypto::b::probe",
            evidence(Analysis::Generated, Outcome::LeakDetected),
        );
        assert!(!coverage.blocking(&found, &policy).is_empty());
    }

    /// The enforcement rate counts requirements met over requirements owed,
    /// and refuses to be a number when nothing was owed.
    #[test]
    fn the_enforcement_rate_excludes_waived_obligations() {
        let policy = PolicyConfig {
            exemptions: vec![Exemption {
                contract: "crypto::c::probe".to_string(),
                analyses: vec![Analysis::Generated],
                reason: "a reason".to_string(),
                tracking: None,
                never_expires: true,
                expires: None,
            }],
            ..PolicyConfig::default()
        };
        let (_, mut coverage) = resolved(
            &["crypto::a::probe", "crypto::b::probe", "crypto::c::probe"],
            &policy,
            &["crypto::a::probe", "crypto::b::probe", "crypto::c::probe"],
            &Available::all(),
        );
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::NoLeakObserved),
        );
        let counts = coverage.enforcement();
        assert_eq!(counts.declared, 3);
        assert_eq!(counts.requirements, 3);
        assert_eq!(counts.requirements_checked, 1);
        assert_eq!(counts.requirements_exempted, 1);
        // One of the two unwaived obligations was met.
        assert_eq!(counts.rate(), Some(0.5));
        assert!(Enforcement::caveat().contains("not the proportion of secret inputs"));
    }

    /// A policy that would require nothing in strict mode is refused.
    #[test]
    fn a_policy_requiring_nothing_is_refused() {
        let empty = PolicyConfig {
            default_required: Vec::new(),
            ..PolicyConfig::default()
        };
        assert!(empty
            .validate()
            .expect_err("an empty default is refused in strict mode")
            .contains("establish nothing"));
        // Advisory mode is allowed to require nothing: it blocks nothing
        // either, so it cannot be mistaken for enforcement.
        PolicyConfig {
            default_required: Vec::new(),
            mode: Mode::Advisory,
            ..PolicyConfig::default()
        }
        .validate()
        .expect("advisory mode may require nothing");

        let mut per_contract = PolicyConfig::default();
        per_contract.contracts.insert(
            "crypto::a::probe".to_string(),
            ContractPolicy {
                required: Some(Vec::new()),
            },
        );
        assert!(per_contract
            .validate()
            .expect_err("an empty per-contract requirement is refused")
            .contains("exemption with a reason"));
    }

    /// Every required analysis has a status from the moment the plan is
    /// resolved, so none can escape the accounting by being absent.
    ///
    /// The regression this pins: an un-analyzed requirement used to have no
    /// map entry, `gaps()` only inspected entries that existed, and a contract
    /// requiring both `generated` and `symbolic` passed after a generated run
    /// alone.
    #[test]
    fn every_requirement_has_a_status_before_anything_runs() {
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            "crypto::a::probe".to_string(),
            ContractPolicy {
                required: Some(vec![
                    Analysis::Generated,
                    Analysis::Symbolic,
                    Analysis::Dynamic,
                ]),
            },
        );
        let (found, coverage) = resolved(
            &["crypto::a::probe"],
            &policy,
            &["crypto::a::probe"],
            &Available::all(),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        // Total over the requirements: every one has *a* status.
        assert_eq!(contract.status.len(), contract.required.len());
        // `generated` and `dynamic` await a backend; `symbolic` was already
        // settled, because it needs declared bounds this configuration has
        // none of. Either way, none of them is absent.
        assert!(matches!(
            contract.status[&Analysis::Generated],
            Status::NotAnalyzed { .. }
        ));
        assert!(matches!(
            contract.status[&Analysis::Dynamic],
            Status::NotAnalyzed { .. }
        ));
        assert!(matches!(
            contract.status[&Analysis::Symbolic],
            Status::Inconclusive { .. }
        ));
        // All three appear as gaps, and all three block.
        assert_eq!(contract.gaps().len(), 3);
        let blocking = coverage.blocking(&found, &policy);
        for analysis in Analysis::all() {
            if analysis == Analysis::Explore {
                continue;
            }
            assert!(
                blocking
                    .iter()
                    .any(|reason| reason.contains(analysis.as_str())),
                "{analysis} was not named in {blocking:?}"
            );
        }
    }

    /// M6's expectation split survives: a declared analyzer-regression fixture
    /// passes by being detected, and a security contract fails by it.
    ///
    /// The two meanings must not be reinterpreted by M8, so this test asserts
    /// both directions over the *same* evidence.
    #[test]
    fn an_analyzer_regression_fixture_passes_by_being_detected() {
        use crate::contract::{CheckSettings, Expectation};

        let found = inventory(&["crypto::a::probe"]);
        let policy = PolicyConfig::default();
        let selected = vec!["crypto::a::probe".to_string()];

        // As a declared regression fixture: the planted leak is the point.
        let mut regression = VerifyConfig::empty();
        regression.check.insert(
            "crypto::a::probe".to_string(),
            CheckSettings {
                expectation: Expectation::AnalyzerRegression,
                expected_outcome: Some("LEAK_DETECTED".to_string()),
                ..CheckSettings::default()
            },
        );
        let plan = Plan::resolve(
            &found,
            &regression,
            &policy,
            &selected,
            &Available::all(),
            TODAY,
        );
        let mut coverage = Coverage::from_plan(&plan, &found);
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::LeakDetected),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert_eq!(contract.status[&Analysis::Generated], Status::Checked);
        assert!(
            !contract.violated(),
            "a declared regression is not a violation"
        );
        assert!(contract.satisfied());
        assert!(coverage.blocking(&found, &policy).is_empty());

        // The same evidence, as a security contract: a failure.
        let plan = Plan::resolve(
            &found,
            &VerifyConfig::empty(),
            &policy,
            &selected,
            &Available::all(),
            TODAY,
        );
        let mut coverage = Coverage::from_plan(&plan, &found);
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::LeakDetected),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert_eq!(contract.status[&Analysis::Generated], Status::LeakDetected);
        assert!(contract.violated());
        assert_eq!(coverage.enforcement().violations, 1);
    }

    /// A regression fixture that does **not** produce its declared outcome
    /// fails, naming both what was declared and what arrived.
    #[test]
    fn an_unmet_regression_expectation_fails() {
        use crate::contract::{CheckSettings, Expectation};

        let found = inventory(&["crypto::a::probe"]);
        let policy = PolicyConfig::default();
        let mut config = VerifyConfig::empty();
        config.check.insert(
            "crypto::a::probe".to_string(),
            CheckSettings {
                expectation: Expectation::AnalyzerRegression,
                expected_outcome: Some("LEAK_DETECTED".to_string()),
                ..CheckSettings::default()
            },
        );
        let plan = Plan::resolve(
            &found,
            &config,
            &policy,
            &["crypto::a::probe".to_string()],
            &Available::all(),
            TODAY,
        );
        let mut coverage = Coverage::from_plan(&plan, &found);
        // The planted leak was not found: the fixture is broken, or the
        // analyzer regressed.
        coverage.fold(
            "crypto::a::probe",
            evidence(Analysis::Generated, Outcome::NoLeakObserved),
        );
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        assert!(!contract.satisfied());
        assert!(!contract.violated());
        match &contract.status[&Analysis::Generated] {
            Status::Inconclusive { detail } => {
                assert!(detail.contains("declared LEAK_DETECTED"), "{detail}");
                assert!(detail.contains("NO_LEAK_OBSERVED"), "{detail}");
            }
            other => panic!("unexpected status: {other:?}"),
        }
        assert!(!coverage.blocking(&found, &policy).is_empty());
    }

    /// An analysis this command does not run is NOT_ANALYZED and says where to
    /// get it, rather than BACKEND_UNAVAILABLE.
    ///
    /// The two are different claims: the first is about the command, the
    /// second about the machine. An earlier revision hard-coded `symbolic` as
    /// unavailable, which sent a developer to install an analyzer they may
    /// already have had.
    #[test]
    fn an_analysis_this_command_does_not_run_says_where_to_get_it() {
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            "crypto::a::probe".to_string(),
            ContractPolicy {
                required: Some(vec![Analysis::Generated, Analysis::Symbolic]),
            },
        );
        // What `check` can do: the generated family, with symbolic evidence
        // coming from `verify`.
        let mut elsewhere = BTreeMap::new();
        elsewhere.insert(Analysis::Symbolic, "cargo trace-check verify".to_string());
        let capabilities = Available {
            generated: true,
            explore: true,
            symbolic: false,
            dynamic: true,
            performs: vec![Analysis::Generated, Analysis::Explore],
            elsewhere,
        };
        // A `[verify]` entry exists, so the requirement is not settled for
        // want of declared bounds.
        let mut config = VerifyConfig::empty();
        // Deserialized rather than constructed: `CheckFeature` is private to
        // the contract module, and a settings value built field-by-field here
        // would drift from what a real configuration means.
        config.verify.insert(
            "crypto::a::probe".to_string(),
            toml::from_str(
                "max_depth = 4000\nchecks = [\"control-flow\"]\n\
                 expected_outcome = \"VERIFIED_BOUNDED\"\n",
            )
            .expect("the fixture settings parse"),
        );

        let found = inventory(&["crypto::a::probe"]);
        let plan = Plan::resolve(
            &found,
            &config,
            &policy,
            &["crypto::a::probe".to_string()],
            &capabilities,
            TODAY,
        );
        let coverage = Coverage::from_plan(&plan, &found);
        let contract = coverage.contract("crypto::a::probe").expect("the contract");
        match &contract.status[&Analysis::Symbolic] {
            Status::NotAnalyzed { detail } => {
                assert!(detail.contains("cargo trace-check verify"), "{detail}");
                assert!(
                    detail.contains("not the same as the analyzer being absent"),
                    "{detail}"
                );
            }
            other => panic!("expected NOT_ANALYZED with a pointer, got {other:?}"),
        }
        // And a genuinely absent backend still reports as absent.
        let absent = Available {
            generated: false,
            performs: vec![Analysis::Generated],
            ..capabilities.clone()
        };
        let plan = Plan::resolve(
            &found,
            &config,
            &policy,
            &["crypto::a::probe".to_string()],
            &absent,
            TODAY,
        );
        let coverage = Coverage::from_plan(&plan, &found);
        assert!(matches!(
            coverage.contract("crypto::a::probe").expect("c").status[&Analysis::Generated],
            Status::BackendUnavailable { .. }
        ));
    }

    /// Every analysis name round-trips, so a configuration cannot silently
    /// mean something else.
    #[test]
    fn analysis_names_round_trip() {
        for analysis in Analysis::all() {
            let text = format!("\"{}\"", analysis.as_str());
            let parsed: Analysis = serde_json::from_str(&text).expect("round-trips");
            assert_eq!(parsed, analysis);
        }
        assert!(serde_json::from_str::<Analysis>("\"nonsense\"").is_err());
    }
}
