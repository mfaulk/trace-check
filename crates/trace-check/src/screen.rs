//! Screening orchestration: runs Tier 0 and Tier 1 over a module and renders
//! the result.
//!
//! The screen configuration declares which functions to analyze, which of
//! their parameters are secret, and how secrets reach them. That declaration is
//! required rather than inferred: nothing in a compiled module says which bytes
//! are a key, and a screener that guesses would quietly analyze the wrong
//! thing.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::census::{self, Baseline, BaselineComparison, Census};
use crate::taint::{self, FunctionVerdict, LoadPolicy, TaintConfig, TAINT_ANALYSIS_VERSION};
use crate::wasm::{self, Module};

/// Screen configuration schema version.
pub const SCREEN_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct ScreenConfig {
    pub schema_version: u32,
    #[serde(default)]
    pub description: String,
    pub targets: Vec<ScreenTarget>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScreenTarget {
    /// Function name as it appears in the module's name section.
    pub function: String,
    #[serde(default)]
    pub description: String,
    pub secret_params: Vec<u32>,
    pub load_policy: LoadPolicy,
    /// Whether this function is expected to be free of secret-dependent
    /// control flow. Declared per target so an unexpected result is a finding
    /// rather than something the tool decides for itself.
    pub expect_clean: bool,
}

impl ScreenTarget {
    fn taint_config(&self) -> TaintConfig {
        TaintConfig {
            secret_params: self.secret_params.clone(),
            load_policy: self.load_policy,
        }
    }
}

#[derive(Debug)]
pub enum ScreenError {
    Io(String),
    Parse(String),
    UnsupportedSchema {
        found: u32,
        supported: u32,
    },
    UnknownFunction {
        function: String,
        available: Vec<String>,
    },
    Wasm(String),
    Baseline(String),
}

impl fmt::Display for ScreenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScreenError::Io(message) => write!(f, "cannot read the screen config: {message}"),
            ScreenError::Parse(message) => write!(f, "cannot parse the screen config: {message}"),
            ScreenError::UnsupportedSchema { found, supported } => write!(
                f,
                "screen config schema_version {found} is not supported (this build understands {supported})"
            ),
            ScreenError::UnknownFunction { function, available } => write!(
                f,
                "module has no function named {function:?}; it exports {}",
                available.join(", ")
            ),
            ScreenError::Wasm(message) => write!(f, "{message}"),
            ScreenError::Baseline(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ScreenError {}

impl ScreenConfig {
    pub fn load(path: &Path) -> Result<Self, ScreenError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ScreenError::Io(format!("{}: {e}", path.display())))?;
        let config: ScreenConfig = serde_json::from_str(&text)
            .map_err(|e| ScreenError::Parse(format!("{}: {e}", path.display())))?;
        if config.schema_version != SCREEN_SCHEMA_VERSION {
            return Err(ScreenError::UnsupportedSchema {
                found: config.schema_version,
                supported: SCREEN_SCHEMA_VERSION,
            });
        }
        Ok(config)
    }

    pub fn function_names(&self) -> Vec<String> {
        self.targets.iter().map(|t| t.function.clone()).collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub function: String,
    pub description: String,
    pub secret_params: Vec<u32>,
    pub load_policy: LoadPolicy,
    pub expect_clean: bool,
    pub census: Census,
    pub verdict: FunctionVerdict,
    /// Whether the observed cleanliness matched the declaration.
    pub matched_expectation: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScreenReport {
    pub schema_version: u32,
    pub taint_analysis_version: u32,
    pub module_path: String,
    pub module_sha256: String,
    pub rustc_version: String,
    pub target: String,
    pub profile: String,
    pub targets: Vec<TargetReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineComparison>,
    pub summary: ScreenSummary,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScreenSummary {
    pub screened: usize,
    pub leaks: usize,
    pub inconclusive: usize,
    pub unmet_expectations: Vec<String>,
    /// True when every declaration held, every function was analyzable, and the
    /// baseline (if checked) did not drift.
    pub passed: bool,
}

const LIMITATIONS: [&str; 5] = [
    "Static screening is intraprocedural and does not track taint through linear memory; secrets are declared at the function boundary.",
    "Control flow is over-approximated: loop-carried taint is treated as reaching the whole function, so a finding is a candidate to confirm.",
    "Absence of findings is only as strong as the declared load policy and secret parameters.",
    "A secret-dependent address finding describes the access pattern, not an observed timing difference.",
    "Results describe one compiled module; they do not transfer to a native build or to real hardware.",
];

pub struct ScreenInputs<'a> {
    pub module_path: &'a Path,
    pub rustc_version: &'a str,
    pub target: &'a str,
    pub profile: &'a str,
}

/// Runs both tiers. `baseline` is compared when supplied.
pub fn run(
    config: &ScreenConfig,
    inputs: &ScreenInputs<'_>,
    baseline: Option<&Baseline>,
) -> Result<ScreenReport, ScreenError> {
    let module = wasm::load(inputs.module_path).map_err(|e| ScreenError::Wasm(e.to_string()))?;
    let available: Vec<String> = module.functions.iter().map(|f| f.display_name()).collect();

    let mut targets = Vec::new();
    for target in &config.targets {
        let function =
            module
                .function(&target.function)
                .ok_or_else(|| ScreenError::UnknownFunction {
                    function: target.function.clone(),
                    available: available.clone(),
                })?;
        let verdict = taint::analyze(function, &target.taint_config());
        let matched_expectation = verdict.analyzed && verdict.is_clean() == target.expect_clean;
        targets.push(TargetReport {
            function: target.function.clone(),
            description: target.description.clone(),
            secret_params: target.secret_params.clone(),
            load_policy: target.load_policy,
            expect_clean: target.expect_clean,
            census: census::census(function),
            verdict,
            matched_expectation,
        });
    }

    let current = current_baseline(&module, config, inputs);
    let comparison = baseline.map(|recorded| census::compare_baseline(recorded, &current));

    let leaks = targets.iter().map(|t| t.verdict.leaks().count()).sum();
    let inconclusive = targets.iter().filter(|t| !t.verdict.analyzed).count();
    let unmet: Vec<String> = targets
        .iter()
        .filter(|t| !t.matched_expectation)
        .map(|t| {
            if !t.verdict.analyzed {
                format!("{}: not analyzable", t.function)
            } else if t.expect_clean {
                format!(
                    "{}: declared free of secret-dependent control flow, but {} finding(s) were reported",
                    t.function,
                    t.verdict.leaks().count()
                )
            } else {
                format!(
                    "{}: declared to have secret-dependent control flow, but none was found",
                    t.function
                )
            }
        })
        .collect();

    let passed = unmet.is_empty()
        && inconclusive == 0
        && !targets.is_empty()
        && comparison.as_ref().is_none_or(|c| !c.is_regression());

    Ok(ScreenReport {
        schema_version: SCREEN_SCHEMA_VERSION,
        taint_analysis_version: TAINT_ANALYSIS_VERSION,
        module_path: inputs.module_path.display().to_string(),
        module_sha256: module.sha256.clone(),
        rustc_version: inputs.rustc_version.to_string(),
        target: inputs.target.to_string(),
        profile: inputs.profile.to_string(),
        summary: ScreenSummary {
            screened: targets.len(),
            leaks,
            inconclusive,
            unmet_expectations: unmet,
            passed,
        },
        targets,
        baseline: comparison,
        limitations: LIMITATIONS.iter().map(|s| s.to_string()).collect(),
    })
}

/// Captures a baseline for the configured targets, for `--update-baseline`.
pub fn capture_baseline(
    config: &ScreenConfig,
    inputs: &ScreenInputs<'_>,
) -> Result<Baseline, ScreenError> {
    let module = wasm::load(inputs.module_path).map_err(|e| ScreenError::Wasm(e.to_string()))?;
    Ok(current_baseline(&module, config, inputs))
}

fn current_baseline(module: &Module, config: &ScreenConfig, inputs: &ScreenInputs<'_>) -> Baseline {
    let names: Vec<String> = module
        .functions
        .iter()
        .filter(|f| {
            config.targets.iter().any(|t| {
                t.function == f.display_name() || Some(t.function.as_str()) == f.name.as_deref()
            })
        })
        .map(|f| f.display_name())
        .collect();
    Baseline::capture(
        module,
        &names,
        inputs.rustc_version,
        inputs.target,
        inputs.profile,
    )
}

impl ScreenReport {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("screen report is serializable")
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        macro_rules! line {
            ($($arg:tt)*) => {{ out.push_str(&format!($($arg)*)); out.push('\n'); }};
        }

        line!("trace-check screen: {}", self.module_path);
        line!("  sha256 {}", self.module_sha256);
        line!(
            "  {} / {} / {} / taint v{}",
            self.rustc_version,
            self.target,
            self.profile,
            self.taint_analysis_version
        );

        line!("");
        line!("Tier 0 - structural census");
        line!(
            "  {:<28} {:>5} {:>7} {:>6} {:>7} {:>6} {:>7}",
            "function",
            "instr",
            "branch",
            "loop",
            "select",
            "load",
            "store"
        );
        for target in &self.targets {
            let c = &target.census;
            line!(
                "  {:<28} {:>5} {:>7} {:>6} {:>7} {:>6} {:>7}",
                truncate(&target.function, 28),
                c.instructions,
                c.branches(),
                c.loops,
                c.select,
                c.loads,
                c.stores
            );
        }

        if let Some(comparison) = &self.baseline {
            line!("");
            if comparison.is_regression() {
                line!("  BASELINE DRIFT");
                for drift in &comparison.drift {
                    line!(
                        "    {} {}: {} -> {}",
                        drift.function,
                        drift.field,
                        drift.baseline,
                        drift.current
                    );
                }
                for added in &comparison.added {
                    line!("    {added}: newly screened, not in the baseline");
                }
                for removed in &comparison.removed {
                    line!("    {removed}: in the baseline but no longer present");
                }
            } else {
                line!("  baseline: census unchanged");
            }
            if comparison.module_changed {
                line!(
                    "    note: module hash changed ({} -> {}); expected after a toolchain change",
                    short(&comparison.baseline_module_sha256),
                    short(&comparison.current_module_sha256)
                );
            }
        }

        line!("");
        line!("Tier 1 - secret-dependent control flow");
        for target in &self.targets {
            let status = if !target.verdict.analyzed {
                "INCONCLUSIVE"
            } else if target.verdict.is_clean() {
                "clean"
            } else {
                "FINDINGS"
            };
            let mark = if target.matched_expectation {
                "ok"
            } else {
                "UNEXPECTED"
            };
            line!(
                "  [{mark}] {} -> {status}  (secret params {:?}, policy {:?})",
                target.function,
                target.secret_params,
                target.load_policy
            );
            if let Some(reason) = &target.verdict.inconclusive_reason {
                line!("      {reason}");
            }
            for finding in &target.verdict.findings {
                let label = if finding.kind.is_leak() {
                    "leak"
                } else {
                    "info"
                };
                line!(
                    "      {label} {} at instruction {}: {}",
                    finding.kind.as_str(),
                    finding.instruction_index,
                    finding.instruction
                );
            }
            if target.verdict.analyzed && target.verdict.findings.is_empty() {
                line!("      no secret value reaches a branch, address or call target");
            }
        }

        line!("");
        line!(
            "Summary: {} screened - {} leak finding(s), {} inconclusive",
            self.summary.screened,
            self.summary.leaks,
            self.summary.inconclusive
        );
        if self.summary.passed {
            line!("Screen passed: every declaration held and the census did not drift.");
        } else {
            line!("Screen FAILED:");
            for unmet in &self.summary.unmet_expectations {
                line!("  - {unmet}");
            }
            if self.baseline.as_ref().is_some_and(|c| c.is_regression()) {
                line!("  - the structural census drifted from the baseline");
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

fn truncate(text: &str, width: usize) -> String {
    if text.len() <= width {
        text.to_string()
    } else {
        format!("{}...", &text[..width.saturating_sub(3)])
    }
}

fn short(hash: &str) -> String {
    hash.chars().take(12).collect()
}
