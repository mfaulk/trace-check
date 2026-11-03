//! Constant-time contracts as the symbolic backend sees them.
//!
//! A contract's identity, its parameter roles, and the width of every symbolic
//! input come from the **declaration** — `#[constant_time]` emits a JSON
//! descriptor built from the parsed signature — not from a second description
//! that could drift from it. This module models that descriptor, reads it out
//! of a compiled library, and layers the per-contract analysis settings from
//! `trace-check.toml` on top.
//!
//! # Roles come from the annotation, never from configuration
//!
//! [`ContractSettings::inputs`] can restate the default for a public
//! parameter and cannot assign a role. A configuration able to promote or
//! demote a secret would be exactly the second, drifting description this
//! design exists to avoid, so an attempt is an error rather than an override.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::generate::{self, Relationship, Strategy};
use crate::security::Outcome;
use crate::symbolic::CheckFeature;

/// Descriptor schema this build understands. Emitted by
/// `trace_check_macros::constant_time`; a mismatch is refused rather than
/// parsed on the assumption that the fields held.
pub const DESCRIPTOR_SCHEMA_VERSION: u32 = 1;

/// `trace-check.toml` schema this build understands.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// The only `inputs` value a configuration may state.
pub const PUBLIC_SYMBOLIC: &str = "public-symbolic";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Secret,
    Public,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Secret => "secret",
            Role::Public => "public",
        }
    }
}

/// How a parameter is represented as symbolic input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Repr {
    /// An unsigned integer of this many bits.
    Scalar(u32),
    /// `bool`, one byte constrained to 0 or 1.
    Bool,
    /// `[u8; N]` by value.
    ByteArray(u64),
    /// `&[u8; N]`: the bytes are the input, the pointer is public.
    RefByteArray(u64),
    /// No value.
    Unit,
    /// A shape the symbolic backend cannot represent. Carried rather than
    /// rejected at expansion time, so an existing M3 contract keeps compiling
    /// and the *verifier* is what refuses, naming the parameter and its type.
    Unsupported,
}

impl Repr {
    /// Width of the symbolic storage in bytes, or `None` when there is nothing
    /// to make symbolic.
    pub fn bytes(&self) -> Option<u64> {
        match self {
            Repr::Scalar(bits) => Some(u64::from(bits / 8)),
            Repr::Bool => Some(1),
            Repr::ByteArray(length) | Repr::RefByteArray(length) => Some(*length),
            Repr::Unit | Repr::Unsupported => None,
        }
    }

    /// The owned Rust type a generated harness declares storage with.
    pub fn owned_rust_type(&self) -> Option<String> {
        match self {
            Repr::Scalar(bits) => Some(format!("u{bits}")),
            Repr::Bool => Some("bool".to_string()),
            Repr::ByteArray(length) | Repr::RefByteArray(length) => Some(format!("[u8; {length}]")),
            Repr::Unit | Repr::Unsupported => None,
        }
    }

    /// Whether the call site must take a reference to the storage.
    pub fn passed_by_reference(&self) -> bool {
        matches!(self, Repr::RefByteArray(_))
    }

    pub fn describe(&self) -> String {
        match self {
            Repr::Scalar(bits) => format!("u{bits}"),
            Repr::Bool => "bool".to_string(),
            Repr::ByteArray(length) => format!("[u8; {length}]"),
            Repr::RefByteArray(length) => format!("&[u8; {length}]"),
            Repr::Unit => "()".to_string(),
            Repr::Unsupported => "unsupported".to_string(),
        }
    }
}

/// One parameter of a contract, as the annotation described it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Parameter {
    pub name: String,
    pub position: usize,
    pub role: Role,
    pub repr: Repr,
    /// The parameter's type as written, for error messages.
    pub rust_type: String,
}

/// The descriptor a `#[constant_time]` annotation emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Descriptor {
    pub function: String,
    pub parameters: Vec<Parameter>,
    pub returns: Repr,
    pub return_rust_type: String,
}

/// Wire form of the descriptor. Separate from [`Descriptor`] so the
/// representation names stay a stable protocol between the macro and this
/// crate while the in-memory model is free to change.
#[derive(Debug, Deserialize)]
struct RawDescriptor {
    schema_version: u32,
    function: String,
    parameters: Vec<RawParameter>,
    returns: RawRepr,
}

#[derive(Debug, Deserialize)]
struct RawParameter {
    name: String,
    position: usize,
    role: Role,
    #[serde(flatten)]
    repr: RawRepr,
}

#[derive(Debug, Deserialize)]
struct RawRepr {
    repr: String,
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    rust_type: String,
}

impl RawRepr {
    fn resolve(&self) -> Repr {
        match (self.repr.as_str(), self.length) {
            ("u8", _) => Repr::Scalar(8),
            ("u16", _) => Repr::Scalar(16),
            ("u32", _) => Repr::Scalar(32),
            ("u64", _) => Repr::Scalar(64),
            ("bool", _) => Repr::Bool,
            ("byte-array", Some(length)) => Repr::ByteArray(length),
            ("ref-byte-array", Some(length)) => Repr::RefByteArray(length),
            ("unit", _) => Repr::Unit,
            // Includes `byte-array` with no length, which the macro does not
            // emit; treating it as unsupported keeps a malformed descriptor
            // from becoming a zero-width symbolic input.
            _ => Repr::Unsupported,
        }
    }
}

impl Descriptor {
    /// Parses a descriptor emitted by the annotation.
    pub fn parse(json: &str) -> Result<Descriptor, ContractError> {
        let raw: RawDescriptor = serde_json::from_str(json)
            .map_err(|e| ContractError::Descriptor(format!("{e}; descriptor was {json:?}")))?;
        if raw.schema_version != DESCRIPTOR_SCHEMA_VERSION {
            return Err(ContractError::DescriptorSchema {
                found: raw.schema_version,
                supported: DESCRIPTOR_SCHEMA_VERSION,
            });
        }
        let mut parameters: Vec<Parameter> = raw
            .parameters
            .iter()
            .map(|parameter| Parameter {
                name: parameter.name.clone(),
                position: parameter.position,
                role: parameter.role,
                repr: parameter.repr.resolve(),
                rust_type: parameter.repr.rust_type.clone(),
            })
            .collect();
        parameters.sort_by_key(|parameter| parameter.position);
        Ok(Descriptor {
            function: raw.function,
            parameters,
            returns: raw.returns.resolve(),
            return_rust_type: raw.returns.rust_type,
        })
    }

    pub fn secrets(&self) -> impl Iterator<Item = &Parameter> {
        self.parameters
            .iter()
            .filter(|parameter| parameter.role == Role::Secret)
    }

    pub fn parameter(&self, name: &str) -> Option<&Parameter> {
        self.parameters
            .iter()
            .find(|parameter| parameter.name == name)
    }

    /// Rejects a contract the symbolic backend cannot represent faithfully.
    ///
    /// Every refusal names the parameter and the type as written, because the
    /// alternative — marking a guessed width into the analysis — would make a
    /// verified result mean nothing.
    pub fn validate(&self, contract: &str) -> Result<(), ContractError> {
        if self.secrets().next().is_none() {
            return Err(ContractError::Unsupported {
                contract: contract.to_string(),
                detail: "the contract declares no secret parameter, so there is no relational \
                         property to check"
                    .to_string(),
            });
        }
        for parameter in &self.parameters {
            if parameter.repr == Repr::Unsupported {
                return Err(ContractError::Unsupported {
                    contract: contract.to_string(),
                    detail: format!(
                        "parameter `{}` has type `{}`, which the symbolic backend cannot \
                         represent. Supported: u8/u16/u32/u64, `[u8; N]` and `&[u8; N]` with a \
                         literal N, and `bool` for a public parameter. A named length such as \
                         `&[u8; TAG_LEN]` is refused rather than guessed: the macro sees the \
                         token, not its value",
                        parameter.name, parameter.rust_type
                    ),
                });
            }
            if parameter.repr == Repr::Bool && parameter.role == Role::Secret {
                return Err(ContractError::Unsupported {
                    contract: contract.to_string(),
                    detail: format!(
                        "parameter `{}` is a secret `bool`. A one-bit secret is disclosed by \
                         any branch on it, so the property is not expressible; pass the value \
                         as a `u8` if the comparison itself must be constant-time",
                        parameter.name
                    ),
                });
            }
        }
        if matches!(self.returns, Repr::Unsupported) {
            return Err(ContractError::Unsupported {
                contract: contract.to_string(),
                detail: format!(
                    "the return type `{}` is not a scalar or `bool`, so the generated harness \
                     cannot consume the value and the call would be optimized away",
                    self.return_rust_type
                ),
            });
        }
        Ok(())
    }
}

/// A contract resolved against a real library: identity, declaration site, and
/// the descriptor read out of the compiled crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Contract {
    /// Fully qualified identity, e.g. `crypto::tag::verify_tag`.
    pub id: String,
    /// Module path the annotation expanded in.
    pub module: String,
    /// Bare function name.
    pub function: String,
    /// `file:line` of the annotation, from the library's own source.
    pub site: String,
    pub descriptor: Descriptor,
    /// The descriptor exactly as the library's constant holds it. A generated
    /// harness embeds these bytes and compares them against that constant at
    /// compile time, so the comparison is against the macro's own output rather
    /// than against a reserialization that could normalize a difference away.
    pub descriptor_json: String,
}

impl Contract {
    /// The path a generated harness calls, relative to the library crate root.
    ///
    /// The module constant is crate-qualified (`crypto::tag`), and a harness
    /// refers to the library by its crate name, so the whole path is already
    /// what the call site needs.
    pub fn call_path(&self) -> String {
        format!("{}::{}", self.module, self.function)
    }

    /// Name of the descriptor constant the annotation emitted.
    pub fn descriptor_const(&self) -> String {
        format!("{}::__TRACE_CHECK_CONTRACT_{}", self.module, self.function)
    }

    /// Name of the module constant.
    pub fn module_const(&self) -> String {
        format!("{}::__TRACE_CHECK_MODULE_{}", self.module, self.function)
    }

    /// Name of the declaration-site constant.
    pub fn site_const(&self) -> String {
        format!("{}::__TRACE_CHECK_SITE_{}", self.module, self.function)
    }
}

/// Per-contract analysis settings from `trace-check.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSettings {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rationale: String,
    pub max_depth: u32,
    #[serde(default = "default_solver_timeout")]
    pub solver_timeout_secs: u32,
    #[serde(default = "default_wall_timeout")]
    pub wall_timeout_secs: u64,
    /// Observation classes to check. Required: a result is only as strong as
    /// this list, and a default would make it depend on the analyzer version
    /// rather than on the contract.
    pub checks: Vec<CheckFeature>,
    /// BINSEC `assume` constraints restricting the input domain, reproduced
    /// verbatim in the report.
    #[serde(default)]
    pub assumptions: Vec<String>,
    /// Outcome this contract is declared to produce, so a compiler change that
    /// invalidates it surfaces as an unmet expectation. Never used to decide
    /// the outcome.
    pub expected_outcome: String,
    /// Explicit restatements of the default for public parameters. Cannot
    /// assign a role; see the module documentation.
    #[serde(default)]
    pub inputs: BTreeMap<String, String>,
}

fn default_solver_timeout() -> u32 {
    30
}

fn default_wall_timeout() -> u64 {
    900
}

/// What a `[check."…"]` entry is asserting.
///
/// This distinction is the whole of M6's CI policy. M4/M5 let a known-vulnerable
/// fixture declare `expected_outcome = "LEAK_DETECTED"`, which is correct for
/// testing trace-check against an example whose leak is the point — and exactly
/// wrong as the default for a developer declaring their own function
/// constant-time. Conflating the two would let a stray expectation turn a real
/// leak into a passing build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expectation {
    /// The function must satisfy the property. A detected leak fails. The
    /// default, because it is the answer that is safe when nobody thought about
    /// it.
    #[default]
    SecurityContract,
    /// The *analyzer* must produce a stated result on a stated example. Used by
    /// this project's own fixtures, where detecting the planted leak is the
    /// test passing.
    AnalyzerRegression,
}

impl Expectation {
    pub fn as_str(self) -> &'static str {
        match self {
            Expectation::SecurityContract => "security-contract",
            Expectation::AnalyzerRegression => "analyzer-regression",
        }
    }
}

/// Per-contract generated-testing settings from `trace-check.toml`.
///
/// Every field has a default: a minimally supported contract needs no `[check]`
/// entry at all, because the annotation already says which parameters are
/// secret and the signature supplies their types.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckSettings {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rationale: String,
    /// Case budget. A hard cap, spent boundaries-first.
    #[serde(default = "default_cases")]
    pub cases: usize,
    #[serde(default = "default_seed")]
    pub seed: u64,
    /// Generation strategies, in the order they are spent.
    #[serde(default = "Strategy::defaults")]
    pub strategies: Vec<Strategy>,
    /// Declared relationships between equal-length byte-array parameters.
    #[serde(default)]
    pub relationships: Vec<Relationship>,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Whether to reduce a reproducing input after isolating it.
    #[serde(default = "default_true")]
    pub shrink: bool,
    #[serde(default = "default_shrink_budget")]
    pub shrink_budget: usize,
    /// What this entry asserts; see [`Expectation`].
    #[serde(default)]
    pub expectation: Expectation,
    /// The outcome an *analyzer regression* fixture is declared to produce.
    ///
    /// Refused for a security contract: a contract that declares its own
    /// expected outcome could declare a leak acceptable, which is the failure
    /// this split exists to prevent.
    #[serde(default)]
    pub expected_outcome: Option<String>,
}

fn default_cases() -> usize {
    generate::DEFAULT_CASES
}

fn default_seed() -> u64 {
    generate::DEFAULT_SEED
}

fn default_batch_size() -> usize {
    crate::check::DEFAULT_BATCH_SIZE
}

fn default_shrink_budget() -> usize {
    crate::check::DEFAULT_SHRINK_BUDGET
}

fn default_true() -> bool {
    true
}

impl Default for CheckSettings {
    fn default() -> Self {
        CheckSettings {
            description: String::new(),
            rationale: String::new(),
            cases: default_cases(),
            seed: default_seed(),
            strategies: Strategy::defaults(),
            relationships: Vec::new(),
            batch_size: default_batch_size(),
            shrink: true,
            shrink_budget: default_shrink_budget(),
            expectation: Expectation::default(),
            expected_outcome: None,
        }
    }
}

impl CheckSettings {
    /// Rejects settings that could not be run, or that would weaken the policy.
    pub fn validate(&self, contract: &str) -> Result<(), ContractError> {
        let reject = |detail: String| {
            Err(ContractError::Config(format!(
                "[check.\"{contract}\"]: {detail}"
            )))
        };
        if self.cases == 0 {
            return reject("`cases` is 0, and a run that checks nothing is not a pass".to_string());
        }
        if self.batch_size == 0 {
            return reject("`batch_size` is 0, so no case would ever run".to_string());
        }
        if self.strategies.is_empty() && self.expectation == Expectation::SecurityContract {
            return reject(
                "`strategies` is empty, so no inputs would be generated; list them \
                 explicitly, e.g. strategies = [\"boundaries\", \"pairwise\", \"random\"]"
                    .to_string(),
            );
        }
        if let Some(duplicate) = self
            .strategies
            .iter()
            .enumerate()
            .find(|(index, strategy)| self.strategies[..*index].contains(strategy))
            .map(|(_, strategy)| *strategy)
        {
            return reject(format!("`strategies` lists {duplicate} twice"));
        }
        match (&self.expectation, &self.expected_outcome) {
            (Expectation::SecurityContract, Some(declared)) => reject(format!(
                "`expected_outcome = {declared:?}` is set on a security contract. A declared \
                 outcome cannot decide whether a leak is acceptable -- that is what the \
                 analyzer is for. If this entry exists to pin trace-check's own behavior on a \
                 deliberately vulnerable example, set \
                 `expectation = \"analyzer-regression\"`"
            )),
            (Expectation::AnalyzerRegression, None) => reject(
                "`expectation = \"analyzer-regression\"` needs an `expected_outcome`, \
                 otherwise it states nothing for the analyzer to be held to"
                    .to_string(),
            ),
            (Expectation::AnalyzerRegression, Some(declared)) => {
                if Outcome::parse(declared).is_none() {
                    return reject(format!(
                        "`expected_outcome` is {declared:?}; use LEAK_DETECTED, \
                         NO_LEAK_OBSERVED or INCONCLUSIVE"
                    ));
                }
                if declared == "VERIFIED_BOUNDED" {
                    return reject(
                        "`expected_outcome` is VERIFIED_BOUNDED, which only the symbolic \
                         backend produces; a completed generated run is NO_LEAK_OBSERVED"
                            .to_string(),
                    );
                }
                Ok(())
            }
            (Expectation::SecurityContract, None) => Ok(()),
        }
    }

    /// The generation settings this entry describes.
    pub fn generation(&self) -> generate::GenerateSettings {
        generate::GenerateSettings {
            cases: self.cases,
            seed: self.seed,
            strategies: self.strategies.clone(),
            relationships: self.relationships.clone(),
            regressions: Vec::new(),
        }
    }

    /// The execution budget this entry describes.
    pub fn budget(&self) -> crate::check::CheckBudget {
        crate::check::CheckBudget {
            batch_size: self.batch_size,
            shrink_budget: self.shrink_budget,
            shrink: self.shrink,
        }
    }
}

/// A library's verification configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyConfig {
    pub schema_version: u32,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub verify: BTreeMap<String, ContractSettings>,
    /// Generated-testing settings, keyed by qualified contract identity.
    ///
    /// Optional and additive: a configuration written for M5 has no `[check]`
    /// table and keeps working unchanged.
    #[serde(default)]
    pub check: BTreeMap<String, CheckSettings>,
}

/// Default configuration file name, looked for beside the library's manifest.
pub const CONFIG_FILE: &str = "trace-check.toml";

impl VerifyConfig {
    pub fn load(path: &Path) -> Result<VerifyConfig, ContractError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ContractError::Io(format!("{}: {e}", path.display())))?;
        let config: VerifyConfig = toml::from_str(&text)
            .map_err(|e| ContractError::Config(format!("{}: {e}", path.display())))?;
        if config.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ContractError::ConfigSchema {
                found: config.schema_version,
                supported: CONFIG_SCHEMA_VERSION,
            });
        }
        for (contract, settings) in &config.verify {
            settings.validate(contract)?;
        }
        for (contract, settings) in &config.check {
            settings.validate(contract)?;
        }
        Ok(config)
    }

    /// An empty configuration, for a library that has no `trace-check.toml`.
    ///
    /// Generated checking does not require one: the annotation already names
    /// the secret and the signature supplies the types, so a file only ever
    /// adds budgets, strategies and policy. Symbolic verification *does*
    /// require one, which is why this is not a `Default` impl.
    pub fn empty() -> VerifyConfig {
        VerifyConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            description: String::new(),
            verify: BTreeMap::new(),
            check: BTreeMap::new(),
        }
    }

    pub fn settings(&self, contract: &str) -> Option<&ContractSettings> {
        self.verify.get(contract)
    }

    /// Rejects a selection this configuration cannot describe.
    ///
    /// Deliberately decidable from the configuration and the command line
    /// alone — no Cargo, no compiler, no analyzer. A selection error used to
    /// surface *after* the container backend was prepared, so on a machine
    /// without the analyzer image an unknown contract name reported a missing
    /// image instead of the typo. Argument validation must not depend on a
    /// heavyweight backend.
    pub fn require_configured(&self, contracts: &[String]) -> Result<(), ContractError> {
        if contracts.is_empty() {
            return Err(ContractError::NothingSelected {
                available: self.contracts().iter().map(|c| c.to_string()).collect(),
            });
        }
        for contract in contracts {
            if !self.verify.contains_key(contract) {
                return Err(ContractError::NotConfigured {
                    contract: contract.clone(),
                    available: self.contracts().iter().map(|c| c.to_string()).collect(),
                });
            }
        }
        Ok(())
    }

    /// Every configured contract, in a stable order.
    pub fn contracts(&self) -> Vec<&str> {
        self.verify.keys().map(String::as_str).collect()
    }

    /// Generated-testing settings for a contract, or the defaults.
    ///
    /// A contract with no `[check]` entry is still checkable: the annotation
    /// already names the secret and the signature supplies the types, so an
    /// entry only ever adds budgets, strategies and policy.
    pub fn check_settings(&self, contract: &str) -> CheckSettings {
        self.check.get(contract).cloned().unwrap_or_default()
    }

    /// Whether a contract has an explicit `[check]` entry.
    pub fn is_check_configured(&self, contract: &str) -> bool {
        self.check.contains_key(contract)
    }

    /// Contracts with a `[check]` entry, in a stable order.
    ///
    /// This is what `--all-configured` enumerates, and it is deliberately not
    /// called "all contracts": it covers what the configuration names, not
    /// every `#[constant_time]` annotation in the source tree. Claiming the
    /// latter would be claiming coverage nothing has established.
    pub fn checked_contracts(&self) -> Vec<&str> {
        self.check.keys().map(String::as_str).collect()
    }
}

impl ContractSettings {
    /// Rejects settings that could not be analyzed as written.
    fn validate(&self, contract: &str) -> Result<(), ContractError> {
        let reject = |detail: String| {
            Err(ContractError::Config(format!(
                "[verify.\"{contract}\"]: {detail}"
            )))
        };
        if self.checks.is_empty() {
            return reject(
                "`checks` is empty, so the observation model is unstated; list the classes \
                 explicitly, e.g. checks = [\"control-flow\", \"memory-access\"]"
                    .to_string(),
            );
        }
        if let Some(duplicate) = self
            .checks
            .iter()
            .enumerate()
            .find(|(index, check)| self.checks[..*index].contains(check))
            .map(|(_, check)| *check)
        {
            return reject(format!("`checks` lists {} twice", duplicate.property()));
        }
        if self.max_depth == 0 {
            return reject("`max_depth` is 0, which would explore nothing".to_string());
        }
        if Outcome::parse(&self.expected_outcome).is_none() {
            return reject(format!(
                "`expected_outcome` is {:?}; use LEAK_DETECTED, VERIFIED_BOUNDED or \
                 INCONCLUSIVE",
                self.expected_outcome
            ));
        }
        if self.expected_outcome == "NO_LEAK_OBSERVED" {
            return reject(
                "`expected_outcome` is NO_LEAK_OBSERVED, which only the dynamic backend \
                 produces; a completed symbolic exploration is VERIFIED_BOUNDED"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Checks the `inputs` table against the contract the annotation declared.
    ///
    /// Two refusals, both of which would otherwise produce a verified result
    /// about the wrong lattice: naming a parameter that does not exist, and
    /// trying to set a role.
    pub fn validate_inputs(
        &self,
        contract: &str,
        descriptor: &Descriptor,
    ) -> Result<(), ContractError> {
        for (name, value) in &self.inputs {
            let Some(parameter) = descriptor.parameter(name) else {
                return Err(ContractError::Config(format!(
                    "[verify.\"{contract}\".inputs] names `{name}`, which is not a parameter \
                     of `{}`. Declared parameters: {}",
                    descriptor.function,
                    descriptor
                        .parameters
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            };
            if value != PUBLIC_SYMBOLIC {
                return Err(ContractError::RoleOverride {
                    contract: contract.to_string(),
                    parameter: name.clone(),
                    value: value.clone(),
                    declared: descriptor
                        .secrets()
                        .map(|p| p.name.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
            if parameter.role == Role::Secret {
                return Err(ContractError::RoleOverride {
                    contract: contract.to_string(),
                    parameter: name.clone(),
                    value: value.clone(),
                    declared: descriptor
                        .secrets()
                        .map(|p| p.name.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ContractError {
    Io(String),
    /// The descriptor could not be parsed.
    Descriptor(String),
    DescriptorSchema {
        found: u32,
        supported: u32,
    },
    Config(String),
    ConfigSchema {
        found: u32,
        supported: u32,
    },
    /// The contract exists but the backend cannot represent it.
    Unsupported {
        contract: String,
        detail: String,
    },
    /// A configuration tried to assign a parameter's role.
    RoleOverride {
        contract: String,
        parameter: String,
        value: String,
        declared: String,
    },
    /// No `[verify."…"]` entry for a selected contract.
    NotConfigured {
        contract: String,
        available: Vec<String>,
    },
    /// No contract was selected at all.
    NothingSelected {
        available: Vec<String>,
    },
    /// The library has no such contract, or it is not reachable from outside.
    NotAnnotated {
        contract: String,
        detail: String,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContractError::Io(message) => write!(f, "{message}"),
            ContractError::Descriptor(message) => {
                write!(f, "the contract descriptor is malformed: {message}")
            }
            ContractError::DescriptorSchema { found, supported } => write!(
                f,
                "contract descriptor schema_version {found} is not supported (this build \
                 understands {supported}); rebuild the library against a matching \
                 trace-check-macros"
            ),
            ContractError::Config(message) => write!(f, "invalid {CONFIG_FILE}: {message}"),
            ContractError::ConfigSchema { found, supported } => write!(
                f,
                "{CONFIG_FILE} schema_version {found} is not supported (this build understands \
                 {supported})"
            ),
            ContractError::Unsupported { contract, detail } => {
                write!(f, "`{contract}` cannot be verified symbolically: {detail}")
            }
            ContractError::RoleOverride {
                contract,
                parameter,
                value,
                declared,
            } => write!(
                f,
                "{CONFIG_FILE} maps `{parameter}` to {value:?} for `{contract}`, but parameter \
                 roles come from #[constant_time(secret = …)] on the function, not from \
                 configuration. Declared secret(s): {declared}. Remove the override; the only \
                 accepted value is {PUBLIC_SYMBOLIC:?}, which restates the default"
            ),
            ContractError::NotConfigured {
                contract,
                available,
            } => write!(
                f,
                "no [verify.\"{contract}\"] section in {CONFIG_FILE}; configured contracts: {}",
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            ),
            ContractError::NothingSelected { available } => write!(
                f,
                "no contracts selected; pass --contract <identity> or --all-contracts. \
                 {CONFIG_FILE} configures: {}",
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            ),
            ContractError::NotAnnotated { contract, detail } => write!(
                f,
                "`{contract}` has no usable #[constant_time] contract: {detail}"
            ),
        }
    }
}

impl std::error::Error for ContractError {}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFY_TAG: &str = r#"{"schema_version":1,"function":"verify_tag","parameters":[
        {"name":"expected","position":0,"role":"secret","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"},
        {"name":"supplied","position":1,"role":"public","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"}],
        "returns":{"repr":"bool","rust_type":"bool"}}"#;

    fn settings(expected: &str) -> ContractSettings {
        ContractSettings {
            description: String::new(),
            rationale: String::new(),
            max_depth: 4000,
            solver_timeout_secs: 30,
            wall_timeout_secs: 900,
            checks: vec![CheckFeature::ControlFlow, CheckFeature::MemoryAccess],
            assumptions: Vec::new(),
            expected_outcome: expected.to_string(),
            inputs: BTreeMap::new(),
        }
    }

    /// A descriptor round-trips into roles, widths and positions.
    #[test]
    fn a_descriptor_carries_roles_widths_and_positions() {
        let descriptor = Descriptor::parse(VERIFY_TAG).expect("parses");
        assert_eq!(descriptor.function, "verify_tag");
        assert_eq!(descriptor.parameters[0].name, "expected");
        assert_eq!(descriptor.parameters[0].role, Role::Secret);
        assert_eq!(descriptor.parameters[0].repr, Repr::RefByteArray(16));
        assert_eq!(descriptor.parameters[0].repr.bytes(), Some(16));
        assert_eq!(descriptor.parameters[1].role, Role::Public);
        assert_eq!(descriptor.returns, Repr::Bool);
        assert_eq!(
            descriptor
                .secrets()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            vec!["expected"]
        );
        descriptor
            .validate("crypto::tag::verify_tag")
            .expect("supported");
    }

    /// Parameters are ordered by declared position, not by the order they
    /// happen to appear in the descriptor: the generated call is positional.
    #[test]
    fn parameters_are_ordered_by_position() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"second","position":1,"role":"public","repr":"u8","rust_type":"u8"},
            {"name":"first","position":0,"role":"secret","repr":"u8","rust_type":"u8"}],
            "returns":{"repr":"u8","rust_type":"u8"}}"#;
        let descriptor = Descriptor::parse(json).expect("parses");
        assert_eq!(descriptor.parameters[0].name, "first");
        assert_eq!(descriptor.parameters[1].name, "second");
    }

    /// A descriptor from a future macro version is refused, not parsed on the
    /// assumption that its fields held.
    #[test]
    fn a_future_descriptor_schema_is_refused() {
        let json = VERIFY_TAG.replace("\"schema_version\":1", "\"schema_version\":2");
        let error = Descriptor::parse(&json).expect_err("refused");
        assert!(
            matches!(error, ContractError::DescriptorSchema { found: 2, .. }),
            "{error}"
        );
    }

    /// An unsupported parameter shape is refused by name and by type, so the
    /// message says what to change.
    #[test]
    fn an_unsupported_parameter_is_refused_with_its_type() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"key","position":0,"role":"secret","repr":"unsupported","rust_type":"&[u8; TAG_LEN]"}],
            "returns":{"repr":"bool","rust_type":"bool"}}"#;
        let descriptor = Descriptor::parse(json).expect("parses");
        let error = descriptor.validate("crypto::f").expect_err("refused");
        let message = error.to_string();
        assert!(message.contains("`key`"), "{message}");
        assert!(message.contains("&[u8; TAG_LEN]"), "{message}");
        assert!(message.contains("literal N"), "{message}");
    }

    /// A byte array with no length is unsupported rather than zero-width: a
    /// malformed descriptor must not become an empty symbolic input.
    #[test]
    fn a_length_less_byte_array_is_unsupported() {
        let raw = RawRepr {
            repr: "ref-byte-array".to_string(),
            length: None,
            rust_type: "&[u8; N]".to_string(),
        };
        assert_eq!(raw.resolve(), Repr::Unsupported);
    }

    /// A contract with no declared secret has no relational property, so it is
    /// refused rather than verified vacuously.
    #[test]
    fn a_contract_with_no_secret_is_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"a","position":0,"role":"public","repr":"u8","rust_type":"u8"}],
            "returns":{"repr":"u8","rust_type":"u8"}}"#;
        let descriptor = Descriptor::parse(json).expect("parses");
        let error = descriptor.validate("crypto::f").expect_err("refused");
        assert!(error.to_string().contains("no secret parameter"), "{error}");
    }

    /// A secret `bool` is refused: the property is not expressible for a
    /// one-bit secret.
    #[test]
    fn a_secret_bool_is_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"flag","position":0,"role":"secret","repr":"bool","rust_type":"bool"}],
            "returns":{"repr":"u8","rust_type":"u8"}}"#;
        let descriptor = Descriptor::parse(json).expect("parses");
        let error = descriptor.validate("crypto::f").expect_err("refused");
        assert!(error.to_string().contains("one-bit secret"), "{error}");
    }

    /// A return type the harness cannot consume is refused, because the call
    /// would otherwise be optimized away.
    #[test]
    fn an_unconsumable_return_type_is_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"s","position":0,"role":"secret","repr":"u8","rust_type":"u8"}],
            "returns":{"repr":"unsupported","rust_type":"Vec<u8>"}}"#;
        let descriptor = Descriptor::parse(json).expect("parses");
        let error = descriptor.validate("crypto::f").expect_err("refused");
        assert!(error.to_string().contains("Vec<u8>"), "{error}");
    }

    /// Restating the default for a public parameter is accepted.
    #[test]
    fn restating_the_public_default_is_accepted() {
        let descriptor = Descriptor::parse(VERIFY_TAG).expect("parses");
        let mut config = settings("VERIFIED_BOUNDED");
        config
            .inputs
            .insert("supplied".to_string(), PUBLIC_SYMBOLIC.to_string());
        config
            .validate_inputs("crypto::tag::verify_tag", &descriptor)
            .expect("accepted");
    }

    /// Declaring a secret public in configuration is rejected, naming the
    /// annotation as the source of truth.
    #[test]
    fn mapping_a_secret_as_public_is_rejected() {
        let descriptor = Descriptor::parse(VERIFY_TAG).expect("parses");
        let mut config = settings("VERIFIED_BOUNDED");
        config
            .inputs
            .insert("expected".to_string(), PUBLIC_SYMBOLIC.to_string());
        let error = config
            .validate_inputs("crypto::tag::verify_tag", &descriptor)
            .expect_err("rejected");
        let message = error.to_string();
        assert!(message.contains("#[constant_time(secret"), "{message}");
        assert!(
            message.contains("Declared secret(s): expected"),
            "{message}"
        );
    }

    /// Promoting a public parameter to secret is rejected for the same reason.
    #[test]
    fn mapping_a_public_as_secret_is_rejected() {
        let descriptor = Descriptor::parse(VERIFY_TAG).expect("parses");
        let mut config = settings("VERIFIED_BOUNDED");
        config
            .inputs
            .insert("supplied".to_string(), "secret-symbolic".to_string());
        let error = config
            .validate_inputs("crypto::tag::verify_tag", &descriptor)
            .expect_err("rejected");
        assert!(error.to_string().contains("roles come from"), "{error}");
    }

    /// Naming a parameter that does not exist is an error, not a silent no-op.
    #[test]
    fn an_unknown_parameter_name_is_rejected() {
        let descriptor = Descriptor::parse(VERIFY_TAG).expect("parses");
        let mut config = settings("VERIFIED_BOUNDED");
        config
            .inputs
            .insert("expceted".to_string(), PUBLIC_SYMBOLIC.to_string());
        let error = config
            .validate_inputs("crypto::tag::verify_tag", &descriptor)
            .expect_err("rejected");
        assert!(error.to_string().contains("Declared parameters"), "{error}");
    }

    /// Settings with no declared observation classes are refused: a result is
    /// only as strong as that list.
    #[test]
    fn settings_without_checks_are_refused() {
        let mut config = settings("VERIFIED_BOUNDED");
        config.checks.clear();
        let error = config.validate("c").expect_err("refused");
        assert!(error.to_string().contains("observation model"), "{error}");
    }

    /// `NO_LEAK_OBSERVED` is the dynamic backend's vocabulary and is refused
    /// here, so the two claims cannot be confused.
    #[test]
    fn the_dynamic_outcome_is_refused_as_an_expectation() {
        let mut config = settings("NO_LEAK_OBSERVED");
        let error = config.validate("c").expect_err("refused");
        assert!(error.to_string().contains("VERIFIED_BOUNDED"), "{error}");
        config.expected_outcome = "SOMETHING".to_string();
        assert!(config.validate("c").is_err());
    }

    /// A zero depth bound would explore nothing.
    #[test]
    fn a_zero_depth_bound_is_refused() {
        let mut config = settings("VERIFIED_BOUNDED");
        config.max_depth = 0;
        assert!(config.validate("c").is_err());
    }

    /// A duplicate observation class is refused rather than deduplicated
    /// silently.
    #[test]
    fn a_duplicate_check_is_refused() {
        let mut config = settings("VERIFIED_BOUNDED");
        config.checks = vec![
            CheckFeature::ControlFlow,
            CheckFeature::MemoryAccess,
            CheckFeature::ControlFlow,
        ];
        assert!(config.validate("c").is_err());
    }

    /// A configuration file parses, validates, and keys contracts by qualified
    /// identity.
    #[test]
    fn a_configuration_file_parses_and_validates() {
        let text = r#"
schema_version = 1
description = "the library's verification configuration"

[verify."crypto::tag::verify_tag"]
description = "constant-time tag comparison"
max_depth = 4000
checks = ["control-flow", "memory-access"]
expected_outcome = "VERIFIED_BOUNDED"

[verify."crypto::tag::verify_tag".inputs]
supplied = "public-symbolic"
"#;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, text).expect("written");
        let config = VerifyConfig::load(&path).expect("valid");
        assert_eq!(config.contracts(), vec!["crypto::tag::verify_tag"]);
        let entry = config.settings("crypto::tag::verify_tag").expect("present");
        assert_eq!(entry.max_depth, 4000);
        // Defaults that are not stated are still explicit in the model.
        assert_eq!(entry.solver_timeout_secs, 30);
        assert_eq!(entry.wall_timeout_secs, 900);
        assert_eq!(entry.inputs["supplied"], PUBLIC_SYMBOLIC);
    }

    /// An unknown key is refused rather than ignored: a typo in a bound or an
    /// observation class would otherwise silently take the default.
    #[test]
    fn an_unknown_configuration_key_is_refused() {
        let text = r#"
schema_version = 1

[verify."crypto::f"]
max_depth = 10
checks = ["control-flow"]
expected_outcome = "VERIFIED_BOUNDED"
max_dpeth = 2000
"#;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, text).expect("written");
        assert!(VerifyConfig::load(&path).is_err());
    }

    /// A configuration from a future schema is refused.
    #[test]
    fn a_future_configuration_schema_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, "schema_version = 99\n").expect("written");
        let error = VerifyConfig::load(&path).expect_err("refused");
        assert!(matches!(
            error,
            ContractError::ConfigSchema { found: 99, .. }
        ));
    }

    /// A selection is checked against the configuration alone: no Cargo, no
    /// compiler, no container runtime.
    ///
    /// This is the ordering regression. Selection used to be validated inside
    /// the per-contract loop, *after* the analyzer backend was prepared, so on
    /// a machine without the analyzer image a misspelled contract name reported
    /// a missing image instead of the typo — and the CLI test covering the typo
    /// failed in the CI job that has no image.
    #[test]
    fn a_selection_is_validated_without_any_backend() {
        let text = r#"
schema_version = 1

[verify."crypto::tag::verify_tag"]
max_depth = 10
checks = ["control-flow"]
expected_outcome = "VERIFIED_BOUNDED"
"#;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, text).expect("written");
        let config = VerifyConfig::load(&path).expect("valid");

        config
            .require_configured(&["crypto::tag::verify_tag".to_string()])
            .expect("a configured contract is accepted");

        let error = config
            .require_configured(&["crypto::tag::verify_tga".to_string()])
            .expect_err("a typo is refused");
        let message = error.to_string();
        assert!(message.contains("verify_tga"), "{message}");
        assert!(
            message.contains("crypto::tag::verify_tag"),
            "the message must list what is configured: {message}"
        );
        // Nothing in the message mentions a backend, because none was touched.
        assert!(!message.contains("analyzer"), "{message}");
        assert!(!message.contains("image"), "{message}");

        let error = config
            .require_configured(&[])
            .expect_err("an empty selection is refused");
        assert!(error.to_string().contains("--all-contracts"), "{error}");
    }

    /// A contract's generated item paths are derived from its module, so a
    /// harness can name them without a second source of truth.
    #[test]
    fn generated_item_paths_follow_the_module() {
        let contract = Contract {
            id: "crypto::tag::verify_tag".to_string(),
            module: "crypto::tag".to_string(),
            function: "verify_tag".to_string(),
            site: "src/tag.rs:21".to_string(),
            descriptor: Descriptor::parse(VERIFY_TAG).expect("parses"),
            descriptor_json: VERIFY_TAG.to_string(),
        };
        assert_eq!(contract.call_path(), "crypto::tag::verify_tag");
        assert_eq!(
            contract.descriptor_const(),
            "crypto::tag::__TRACE_CHECK_CONTRACT_verify_tag"
        );
        assert_eq!(
            contract.module_const(),
            "crypto::tag::__TRACE_CHECK_MODULE_verify_tag"
        );
    }

    /// Representations map to the owned Rust types a harness declares storage
    /// with, and say whether the call takes a reference.
    #[test]
    fn representations_map_to_owned_storage_types() {
        assert_eq!(Repr::Scalar(32).owned_rust_type().unwrap(), "u32");
        assert_eq!(
            Repr::RefByteArray(16).owned_rust_type().unwrap(),
            "[u8; 16]"
        );
        assert!(Repr::RefByteArray(16).passed_by_reference());
        assert!(!Repr::ByteArray(16).passed_by_reference());
        assert_eq!(Repr::Scalar(64).bytes(), Some(8));
        assert_eq!(Repr::Unsupported.bytes(), None);
    }
}

#[cfg(test)]
mod check_config_tests {
    use super::*;

    fn settings() -> CheckSettings {
        CheckSettings::default()
    }

    /// A contract with no `[check]` entry is still checkable, on defaults.
    #[test]
    fn an_unconfigured_contract_uses_defaults() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, "schema_version = 1\n").expect("written");
        let config = VerifyConfig::load(&path).expect("valid");
        let defaults = config.check_settings("crypto::tag::verify_tag");
        assert_eq!(defaults.cases, crate::generate::DEFAULT_CASES);
        assert_eq!(defaults.seed, crate::generate::DEFAULT_SEED);
        assert_eq!(defaults.strategies, Strategy::defaults());
        assert_eq!(defaults.expectation, Expectation::SecurityContract);
        assert!(defaults.expected_outcome.is_none());
        assert!(defaults.shrink);
        assert!(!config.is_check_configured("crypto::tag::verify_tag"));
        assert!(config.checked_contracts().is_empty());
    }

    /// An M5 configuration with no `[check]` table keeps working, so adding
    /// generated testing does not invalidate an existing file.
    #[test]
    fn a_configuration_without_a_check_table_still_loads() {
        let text = r#"
schema_version = 1

[verify."crypto::tag::verify_tag"]
max_depth = 4000
checks = ["control-flow"]
expected_outcome = "VERIFIED_BOUNDED"
"#;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, text).expect("written");
        let config = VerifyConfig::load(&path).expect("valid");
        assert_eq!(config.contracts(), vec!["crypto::tag::verify_tag"]);
        assert!(config.check.is_empty());
    }

    /// A `[check]` table parses, and `--all-configured` enumerates exactly its
    /// keys.
    #[test]
    fn a_check_table_parses_and_is_enumerable() {
        let text = r#"
schema_version = 1

[check."crypto::lookup::substitute"]
description = "the masked scan"
cases = 128
seed = 99
strategies = ["boundaries", "random"]
batch_size = 16

[check."crypto::lookup::substitute_mode"]
expectation = "analyzer-regression"
expected_outcome = "LEAK_DETECTED"
rationale = "the leak behind a public mode is the point of this fixture"
"#;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, text).expect("written");
        let config = VerifyConfig::load(&path).expect("valid");
        assert_eq!(
            config.checked_contracts(),
            vec![
                "crypto::lookup::substitute",
                "crypto::lookup::substitute_mode"
            ]
        );
        let scan = config.check_settings("crypto::lookup::substitute");
        assert_eq!(scan.cases, 128);
        assert_eq!(scan.seed, 99);
        assert_eq!(
            scan.strategies,
            vec![Strategy::Boundaries, Strategy::Random]
        );
        assert_eq!(scan.batch_size, 16);
        assert_eq!(scan.expectation, Expectation::SecurityContract);
        let fixture = config.check_settings("crypto::lookup::substitute_mode");
        assert_eq!(fixture.expectation, Expectation::AnalyzerRegression);
        assert_eq!(fixture.expected_outcome.as_deref(), Some("LEAK_DETECTED"));
    }

    /// The policy split: a security contract may not declare its own expected
    /// outcome, because that would let a configuration call a leak acceptable.
    #[test]
    fn a_security_contract_cannot_declare_an_expected_outcome() {
        let mut config = settings();
        config.expected_outcome = Some("LEAK_DETECTED".to_string());
        let error = config.validate("crypto::f").expect_err("refused");
        let message = error.to_string();
        assert!(message.contains("security contract"), "{message}");
        assert!(message.contains("analyzer-regression"), "{message}");
    }

    /// An analyzer-regression entry without an expected outcome states nothing.
    #[test]
    fn an_analyzer_regression_needs_an_expected_outcome() {
        let mut config = settings();
        config.expectation = Expectation::AnalyzerRegression;
        let error = config.validate("crypto::f").expect_err("refused");
        assert!(error.to_string().contains("states nothing"), "{error}");
    }

    /// `VERIFIED_BOUNDED` is the symbolic backend's vocabulary and is refused
    /// here, so the two claims cannot be confused.
    #[test]
    fn the_symbolic_outcome_is_refused_as_a_generated_expectation() {
        let mut config = settings();
        config.expectation = Expectation::AnalyzerRegression;
        config.expected_outcome = Some("VERIFIED_BOUNDED".to_string());
        let error = config.validate("crypto::f").expect_err("refused");
        assert!(error.to_string().contains("NO_LEAK_OBSERVED"), "{error}");

        config.expected_outcome = Some("SOMETHING".to_string());
        assert!(config.validate("crypto::f").is_err());
    }

    /// A zero budget or a zero batch size would check nothing.
    #[test]
    fn empty_budgets_are_refused() {
        let mut config = settings();
        config.cases = 0;
        assert!(config.validate("c").is_err());

        let mut config = settings();
        config.batch_size = 0;
        assert!(config.validate("c").is_err());
    }

    /// A security contract with no strategies would generate no inputs.
    #[test]
    fn a_security_contract_needs_at_least_one_strategy() {
        let mut config = settings();
        config.strategies.clear();
        let error = config.validate("c").expect_err("refused");
        assert!(error.to_string().contains("no inputs"), "{error}");
    }

    /// A duplicated strategy is refused rather than silently deduplicated.
    #[test]
    fn a_duplicate_strategy_is_refused() {
        let mut config = settings();
        config.strategies = vec![Strategy::Boundaries, Strategy::Random, Strategy::Boundaries];
        let error = config.validate("c").expect_err("refused");
        assert!(error.to_string().contains("twice"), "{error}");
    }

    /// Settings convert to the generation and execution budgets they describe.
    #[test]
    fn settings_become_generation_and_execution_budgets() {
        let mut config = settings();
        config.cases = 12;
        config.seed = 7;
        config.batch_size = 4;
        config.shrink = false;
        config.shrink_budget = 3;
        let generation = config.generation();
        assert_eq!(generation.cases, 12);
        assert_eq!(generation.seed, 7);
        assert!(generation.regressions.is_empty());
        let budget = config.budget();
        assert_eq!(budget.batch_size, 4);
        assert!(!budget.shrink);
        assert_eq!(budget.shrink_budget, 3);
    }

    /// An unknown key in a `[check]` entry is refused, so a typo in a budget
    /// does not silently take the default.
    #[test]
    fn an_unknown_check_key_is_refused() {
        let text = r#"
schema_version = 1

[check."crypto::f"]
cases = 10
csaes = 20
"#;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, text).expect("written");
        assert!(VerifyConfig::load(&path).is_err());
    }

    /// An invalid `[check]` entry is caught when the file loads, not when the
    /// contract is reached.
    #[test]
    fn an_invalid_check_entry_fails_the_load() {
        let text = r#"
schema_version = 1

[check."crypto::f"]
cases = 0
"#;
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join(CONFIG_FILE);
        std::fs::write(&path, text).expect("written");
        let error = VerifyConfig::load(&path).expect_err("refused");
        assert!(error.to_string().contains("not a pass"), "{error}");
    }
}
