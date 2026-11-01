//! Tier 0: a per-function structural census and a baseline regression gate.
//!
//! The census is deliberately shallow — it counts instruction shapes and does
//! not decide whether anything is secret-dependent. Its value is as a tripwire:
//! a toolchain upgrade that if-converts a `select` back into a branch, or that
//! starts emitting a loop where there was straight-line code, changes these
//! counts. That class of regression is invisible to source review and is the
//! realistic way constant-time code decays.
//!
//! The module hash is recorded but compared separately: it changes on every
//! compiler bump, so treating it as a gate would make the gate noise. Census
//! drift is the failure; a hash change alone is a note.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::wasm::{Function, Instr, Module};

/// Baseline file schema version.
pub const BASELINE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Census {
    pub instructions: usize,
    pub br_if: usize,
    pub br_table: usize,
    pub r#if: usize,
    pub loops: usize,
    pub select: usize,
    pub loads: usize,
    pub stores: usize,
    pub calls: usize,
    pub call_indirect: usize,
    /// Count of operators outside the modeled subset. Non-zero means the static
    /// analyses cannot give this function a verdict.
    pub unsupported: usize,
}

impl Census {
    /// Total conditional control-flow constructs. Zero is the strong, input
    /// independent property worth gating on for a comparison primitive.
    pub fn branches(&self) -> usize {
        self.br_if + self.br_table + self.r#if
    }
}

pub fn census(function: &Function) -> Census {
    let mut census = Census {
        instructions: function.body.len(),
        ..Census::default()
    };
    for instr in &function.body {
        match instr {
            Instr::BrIf { .. } => census.br_if += 1,
            Instr::BrTable { .. } => census.br_table += 1,
            Instr::If { .. } => census.r#if += 1,
            Instr::Loop { .. } => census.loops += 1,
            Instr::Select => census.select += 1,
            Instr::Load => census.loads += 1,
            Instr::Store => census.stores += 1,
            Instr::Call { .. } => census.calls += 1,
            Instr::CallIndirect { .. } => census.call_indirect += 1,
            Instr::Unsupported(_) => census.unsupported += 1,
            _ => {}
        }
    }
    census
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Baseline {
    pub schema_version: u32,
    /// Informational: expected to change on any toolchain bump.
    pub module_sha256: String,
    pub rustc_version: String,
    pub target: String,
    pub profile: String,
    /// Census per function display name, ordered for a stable diff.
    pub functions: BTreeMap<String, Census>,
}

impl Baseline {
    pub fn capture(
        module: &Module,
        screened: &[String],
        rustc_version: &str,
        target: &str,
        profile: &str,
    ) -> Baseline {
        let mut functions = BTreeMap::new();
        for function in &module.functions {
            let name = function.display_name();
            if screened.contains(&name) {
                functions.insert(name, census(function));
            }
        }
        Baseline {
            schema_version: BASELINE_SCHEMA_VERSION,
            module_sha256: module.sha256.clone(),
            rustc_version: rustc_version.to_string(),
            target: target.to_string(),
            profile: profile.to_string(),
            functions,
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Baseline, BaselineError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| BaselineError::Io(format!("{}: {e}", path.display())))?;
        let baseline: Baseline = serde_json::from_str(&text)
            .map_err(|e| BaselineError::Parse(format!("{}: {e}", path.display())))?;
        if baseline.schema_version != BASELINE_SCHEMA_VERSION {
            return Err(BaselineError::UnsupportedSchema {
                found: baseline.schema_version,
                supported: BASELINE_SCHEMA_VERSION,
            });
        }
        Ok(baseline)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("baseline is serializable")
    }
}

#[derive(Debug)]
pub enum BaselineError {
    Io(String),
    Parse(String),
    UnsupportedSchema { found: u32, supported: u32 },
}

impl fmt::Display for BaselineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaselineError::Io(message) => write!(
                f,
                "cannot read the baseline ({message}); create it with `screen --update-baseline`"
            ),
            BaselineError::Parse(message) => write!(f, "cannot parse the baseline: {message}"),
            BaselineError::UnsupportedSchema { found, supported } => write!(
                f,
                "baseline schema_version {found} is not supported (this build understands {supported})"
            ),
        }
    }
}

impl std::error::Error for BaselineError {}

#[derive(Debug, Clone, Serialize)]
pub struct Drift {
    pub function: String,
    pub field: String,
    pub baseline: i64,
    pub current: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineComparison {
    pub drift: Vec<Drift>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// True when the recorded and current module hashes differ. Informational.
    pub module_changed: bool,
    pub baseline_module_sha256: String,
    pub current_module_sha256: String,
}

impl BaselineComparison {
    /// Census drift, additions and removals are regressions. A hash change on
    /// its own is expected whenever the toolchain moves.
    pub fn is_regression(&self) -> bool {
        !self.drift.is_empty() || !self.added.is_empty() || !self.removed.is_empty()
    }
}

pub fn compare_baseline(baseline: &Baseline, current: &Baseline) -> BaselineComparison {
    let mut drift = Vec::new();
    let mut removed = Vec::new();

    for (name, old) in &baseline.functions {
        let Some(new) = current.functions.get(name) else {
            removed.push(name.clone());
            continue;
        };
        let fields: [(&str, usize, usize); 11] = [
            ("instructions", old.instructions, new.instructions),
            ("br_if", old.br_if, new.br_if),
            ("br_table", old.br_table, new.br_table),
            ("if", old.r#if, new.r#if),
            ("loops", old.loops, new.loops),
            ("select", old.select, new.select),
            ("loads", old.loads, new.loads),
            ("stores", old.stores, new.stores),
            ("calls", old.calls, new.calls),
            ("call_indirect", old.call_indirect, new.call_indirect),
            ("unsupported", old.unsupported, new.unsupported),
        ];
        for (field, before, after) in fields {
            if before != after {
                drift.push(Drift {
                    function: name.clone(),
                    field: field.to_string(),
                    baseline: before as i64,
                    current: after as i64,
                });
            }
        }
    }

    let added = current
        .functions
        .keys()
        .filter(|name| !baseline.functions.contains_key(*name))
        .cloned()
        .collect();

    BaselineComparison {
        drift,
        added,
        removed,
        module_changed: baseline.module_sha256 != current.module_sha256,
        baseline_module_sha256: baseline.module_sha256.clone(),
        current_module_sha256: current.module_sha256.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(body: Vec<Instr>) -> Function {
        Function {
            index: 0,
            name: Some("f".to_string()),
            param_count: 0,
            result_count: 0,
            local_count: 0,
            body,
        }
    }

    /// The census counts each instruction shape it tracks.
    #[test]
    fn census_counts_instruction_shapes() {
        let c = census(&function(vec![
            Instr::BrIf { depth: 0 },
            Instr::BrIf { depth: 1 },
            Instr::Loop { results: 0 },
            Instr::Select,
            Instr::Load,
            Instr::Store,
            Instr::Const,
        ]));
        assert_eq!(c.instructions, 7);
        assert_eq!(c.br_if, 2);
        assert_eq!(c.loops, 1);
        assert_eq!(c.select, 1);
        assert_eq!(c.loads, 1);
        assert_eq!(c.stores, 1);
        assert_eq!(c.branches(), 2);
    }

    /// A branchless body reports zero branches, the property worth gating on.
    #[test]
    fn branchless_body_reports_zero_branches() {
        let c = census(&function(vec![Instr::Load, Instr::Load, Instr::Binop]));
        assert_eq!(c.branches(), 0);
    }

    /// Unsupported operators are counted so a clean census cannot hide them.
    #[test]
    fn census_counts_unsupported_operators() {
        let c = census(&function(vec![Instr::Unsupported("MemoryFill".into())]));
        assert_eq!(c.unsupported, 1);
    }

    fn baseline(br_if: usize) -> Baseline {
        let mut functions = BTreeMap::new();
        functions.insert(
            "f".to_string(),
            Census {
                br_if,
                ..Census::default()
            },
        );
        Baseline {
            schema_version: BASELINE_SCHEMA_VERSION,
            module_sha256: "aaa".to_string(),
            rustc_version: "x".to_string(),
            target: "t".to_string(),
            profile: "release".to_string(),
            functions,
        }
    }

    /// An identical census is not a regression.
    #[test]
    fn identical_census_is_not_a_regression() {
        let comparison = compare_baseline(&baseline(0), &baseline(0));
        assert!(!comparison.is_regression());
        assert!(comparison.drift.is_empty());
    }

    /// A branch appearing where there was none is a regression, naming the field.
    #[test]
    fn new_branch_is_a_regression() {
        let comparison = compare_baseline(&baseline(0), &baseline(1));
        assert!(comparison.is_regression());
        assert_eq!(comparison.drift.len(), 1);
        assert_eq!(comparison.drift[0].field, "br_if");
        assert_eq!(
            (comparison.drift[0].baseline, comparison.drift[0].current),
            (0, 1)
        );
    }

    /// A module hash change alone is reported but is not a regression, so a
    /// toolchain bump does not fail the gate on its own.
    #[test]
    fn module_hash_change_alone_is_not_a_regression() {
        let mut current = baseline(0);
        current.module_sha256 = "bbb".to_string();
        let comparison = compare_baseline(&baseline(0), &current);
        assert!(comparison.module_changed);
        assert!(!comparison.is_regression());
    }

    /// A screened function disappearing is a regression, not a silent pass.
    #[test]
    fn removed_function_is_a_regression() {
        let mut current = baseline(0);
        current.functions.clear();
        let comparison = compare_baseline(&baseline(0), &current);
        assert_eq!(comparison.removed, vec!["f".to_string()]);
        assert!(comparison.is_regression());
    }

    /// A newly screened function is surfaced so the baseline gets refreshed.
    #[test]
    fn added_function_is_reported() {
        let mut current = baseline(0);
        current.functions.insert("g".to_string(), Census::default());
        let comparison = compare_baseline(&baseline(0), &current);
        assert_eq!(comparison.added, vec!["g".to_string()]);
        assert!(comparison.is_regression());
    }

    /// An unsupported baseline schema version is refused rather than guessed at.
    #[test]
    fn unsupported_baseline_schema_is_refused() {
        let json = r#"{"schema_version":99,"module_sha256":"","rustc_version":"","target":"","profile":"","functions":{}}"#;
        let path = std::env::temp_dir().join("trace-check-bad-baseline.json");
        std::fs::write(&path, json).unwrap();
        let error = Baseline::load(&path).unwrap_err();
        assert!(matches!(
            error,
            BaselineError::UnsupportedSchema { found: 99, .. }
        ));
    }
}
