//! Running a generated corpus under Memcheck: batching, failure isolation, and
//! shrinking.
//!
//! # Two questions, two mechanisms
//!
//! A multi-case run answers *did any invocation leak?* from the aggregate
//! Memcheck report. It cannot answer *which input?* — Memcheck consolidates
//! repeated diagnostic sites, so the M6.1 spike measured a 1-of-16 leaky batch
//! and a 16-of-16 leaky batch as the same single error. The error count is not a
//! leak count and is never used as one.
//!
//! So the second question is answered by re-running. Valgrind startup dominates
//! (~0.64 s measured, against unmeasurable per-case cost), which is what makes
//! batching worth ~100x at 64 cases and makes the ⌈log₂ n⌉ extra runs that
//! isolate a failure almost free.
//!
//! # A finding that will not isolate is kept
//!
//! Binary splitting assumes the finding depends on one case. A leak that needs
//! prior process state does not, and narrowing it produces two clean halves. The
//! original finding is **not** discarded in that case: it is reported as
//! sequence-dependent with its batch preserved for replay. Dropping a finding
//! because it resisted attribution is the one outcome a security tool cannot
//! have.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::contract::Contract;
use crate::dynamic_harness::{self, BatchRun, DynamicError};
use crate::generate::{Corpus, GeneratedCase, Strategy, Value};
use crate::memcheck::{Classification, MemcheckError};
use crate::native::Limits;
use crate::security::Outcome;

/// Cases per Memcheck process by default.
///
/// Modest on purpose. Valgrind startup dominates either way, and a smaller
/// batch means fewer re-runs to isolate a failure and a shorter sequence to
/// preserve when one will not isolate.
pub const DEFAULT_BATCH_SIZE: usize = 32;

/// Attempts a shrink is allowed before the original reproducer is kept.
///
/// Budgeted separately from the check itself: a reproducible original failure is
/// worth more than a smaller but untrustworthy one.
pub const DEFAULT_SHRINK_BUDGET: usize = 40;

/// Whether the positive control fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Control {
    /// The probe produced its expected diagnostic.
    Confirmed,
    /// The probe produced nothing, so marking is inert here.
    Failed,
    /// The run did not get far enough to tell.
    NotRun,
}

impl Control {
    pub fn as_str(self) -> &'static str {
        match self {
            Control::Confirmed => "confirmed",
            Control::Failed => "failed",
            Control::NotRun => "not_run",
        }
    }

    fn from_fired(fired: bool) -> Control {
        if fired {
            Control::Confirmed
        } else {
            Control::Failed
        }
    }
}

/// A finding's identity across runs of **one** artifact.
///
/// Deliberately not an absolute instruction address: the same source defect
/// lands at a different address in a differently compiled artifact, and a
/// fingerprint that changed with the linker would make every reproducer
/// single-use. Classification plus the attributed function plus the source
/// location is stable across re-runs of one build, which is what isolation and
/// shrinking compare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fingerprint {
    pub classification: Classification,
    /// The frame the finding is attributed to.
    pub function: Option<String>,
    /// `file:line` of that frame, when debug info supplied one.
    pub location: Option<String>,
}

impl Fingerprint {
    fn of(error: &MemcheckError) -> Fingerprint {
        let frame = error.primary_frame();
        Fingerprint {
            classification: error.classification,
            function: frame.and_then(|frame| frame.function.clone()),
            location: frame.and_then(|frame| {
                frame.file.as_ref().map(|file| match frame.line {
                    Some(line) => format!("{file}:{line}"),
                    None => file.clone(),
                })
            }),
        }
    }

    pub fn describe(&self) -> String {
        let where_ = match (&self.function, &self.location) {
            (Some(function), Some(location)) => format!("{function} ({location})"),
            (Some(function), None) => function.clone(),
            (None, Some(location)) => location.clone(),
            (None, None) => "<unknown location>".to_string(),
        };
        format!("{} at {where_}", self.classification.as_str())
    }
}

/// How far a finding was narrowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Isolation {
    /// One case reproduces the finding on its own.
    Case {
        id: usize,
        inputs: Vec<(String, Value)>,
        /// Re-runs spent narrowing.
        runs: usize,
    },
    /// No single case reproduces it, so it depends on the sequence. The batch is
    /// preserved rather than the finding discarded.
    Sequence {
        ids: Vec<usize>,
        runs: usize,
        detail: String,
    },
    /// Isolation was not attempted, because the batch was already one case.
    Single { id: usize },
}

impl Isolation {
    /// The case ids that reproduce the finding, for replay.
    pub fn ids(&self) -> Vec<usize> {
        match self {
            Isolation::Case { id, .. } | Isolation::Single { id } => vec![*id],
            Isolation::Sequence { ids, .. } => ids.clone(),
        }
    }
}

/// One finding, with everything needed to act on it.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub fingerprint: Fingerprint,
    pub classification: Classification,
    pub description: String,
    pub what: String,
    pub origin: String,
    /// Frames of the primary stack, shallowest first.
    pub stack: Vec<String>,
    /// Whether a frame naming the contract's function appears in the
    /// attribution window.
    pub attributed: bool,
    pub isolation: Isolation,
    /// The reproducing inputs after shrinking, when shrinking improved on the
    /// isolated case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shrunk: Option<Shrunk>,
}

/// A smaller input that still reproduces the same finding.
#[derive(Debug, Clone, Serialize)]
pub struct Shrunk {
    pub inputs: Vec<(String, Value)>,
    /// Candidates tried, so a reader can see the budget that was spent.
    pub attempts: usize,
    /// Simplification steps that were accepted.
    pub steps: usize,
}

impl Finding {
    fn from_error(error: &MemcheckError, function: &str, isolation: Isolation) -> Finding {
        Finding {
            fingerprint: Fingerprint::of(error),
            classification: error.classification,
            description: error.classification.describe().to_string(),
            what: error.what.clone(),
            origin: error.origin.describe(),
            stack: error
                .primary_stack
                .iter()
                .take(6)
                .map(ToString::to_string)
                .collect(),
            attributed: error.attributable_to(function),
            isolation,
            shrunk: None,
        }
    }
}

/// Evidence from one contract's whole check.
#[derive(Debug, Clone, Serialize)]
pub struct ContractCheck {
    pub contract: String,
    pub function: String,
    /// Declared secrets and the bytes marked for them.
    pub secret_parameters: Vec<String>,
    pub marked_bytes: u64,
    pub outcome: Outcome,
    pub message: String,
    pub calibration: Control,
    /// The binding control: whether *this* contract's secret storage was
    /// confirmed marked at the call site.
    pub binding: Control,
    pub cases_planned: usize,
    pub cases_executed: usize,
    pub cases_completed: usize,
    /// Memcheck processes spent, including isolation and shrinking re-runs.
    pub analyzer_runs: usize,
    pub findings: Vec<Finding>,
    /// Secret-dependency findings that could not be attributed to the
    /// contract's function. Retained, never dropped.
    pub unattributed: Vec<Finding>,
    /// Diagnostics that are not secret dependency. Retained, never dropped.
    pub other_diagnostics: Vec<Finding>,
}

impl ContractCheck {
    /// Whether this check met its contract as a security requirement.
    pub fn clean(&self) -> bool {
        self.outcome == Outcome::NoLeakObserved
    }
}

/// Executes batches of a staged corpus for one contract.
pub struct Runner<'a> {
    pub valgrind: &'a Path,
    pub artifact: &'a Path,
    /// Where the generated corpus was staged.
    pub corpus_path: PathBuf,
    /// Directory ad-hoc corpora (shrink candidates) are written to.
    pub work_dir: PathBuf,
    pub limits: Limits,
    /// Memcheck processes spent so far.
    runs: usize,
}

impl<'a> Runner<'a> {
    pub fn new(
        valgrind: &'a Path,
        artifact: &'a Path,
        corpus_path: PathBuf,
        work_dir: PathBuf,
        limits: Limits,
    ) -> Runner<'a> {
        Runner {
            valgrind,
            artifact,
            corpus_path,
            work_dir,
            limits,
            runs: 0,
        }
    }

    pub fn runs(&self) -> usize {
        self.runs
    }

    /// Runs the named cases from the staged corpus.
    fn run_ids(&mut self, ids: &[usize]) -> Result<BatchRun, DynamicError> {
        self.runs += 1;
        dynamic_harness::run_batch(
            self.valgrind,
            self.artifact,
            &self.corpus_path,
            Some(ids),
            self.limits,
        )
    }

    /// Runs one ad-hoc input assignment that is not in the staged corpus.
    ///
    /// Shrinking needs this: a candidate is a value the generator never
    /// produced, and the harness reads a corpus file rather than taking inputs
    /// on the command line.
    fn run_inputs(
        &mut self,
        contract: &str,
        inputs: &[(String, Value)],
    ) -> Result<BatchRun, DynamicError> {
        let corpus = Corpus {
            schema_version: crate::generate::CORPUS_SCHEMA_VERSION,
            contract: contract.to_string(),
            seed: 0,
            budget: 1,
            strategies_requested: vec![Strategy::Regression],
            coverage: Vec::new(),
            cases: vec![GeneratedCase {
                id: 0,
                strategy: Strategy::Regression,
                inputs: inputs.to_vec(),
            }],
        };
        let path = self.work_dir.join("shrink-candidate.tcc");
        std::fs::write(&path, corpus.to_wire())
            .map_err(|e| DynamicError::Io(format!("{}: {e}", path.display())))?;
        self.runs += 1;
        dynamic_harness::run_batch(self.valgrind, self.artifact, &path, Some(&[0]), self.limits)
    }
}

/// Secret-dependency findings attributable to `function`, with the controls
/// excluded.
fn target_errors<'r>(run: &'r BatchRun, function: &str) -> Vec<&'r MemcheckError> {
    let Some(parsed) = run.run.as_ref() else {
        return Vec::new();
    };
    parsed
        .secret_dependency_errors()
        .filter(|error| !is_control(error))
        .filter(|error| error.attributable_to(function))
        .collect()
}

/// Whether a diagnostic belongs to one of the two positive controls.
///
/// Both are `#[inline(never)]` so this split is possible; without it the
/// controls' own findings would be reported as leaks in the function under
/// analysis.
fn is_control(error: &MemcheckError) -> bool {
    error.attributable_to(trace_check_control::PROBE)
        || error.attributable_to(trace_check_control::BINDING)
}

/// The control symbols, restated here rather than taken as a dependency.
///
/// `trace-check-test` is a dev-dependency of this crate and a dependency of the
/// *generated* harness, not of this library, so the names cross the boundary as
/// constants. The unit test
/// [`tests::the_control_symbols_match_the_test_crate`] fails if they drift.
mod trace_check_control {
    pub const PROBE: &str = "secret_dependent_probe";
    pub const BINDING: &str = "secret_binding_probe";
}

/// Whether a batch shows a finding matching `fingerprint` in `function`.
fn reproduces(run: &BatchRun, function: &str, fingerprint: &Fingerprint) -> bool {
    target_errors(run, function)
        .into_iter()
        .any(|error| Fingerprint::of(error) == *fingerprint)
}

/// Narrows a batch to the smallest set that still shows the finding.
///
/// Binary split, which the M6.1 spike measured at ⌈log₂ n⌉ re-runs. Returns
/// `None` when neither half reproduces it alone, which means the finding depends
/// on the sequence rather than on one case.
fn narrow(
    runner: &mut Runner<'_>,
    function: &str,
    fingerprint: &Fingerprint,
    ids: &[usize],
) -> Result<Option<usize>, DynamicError> {
    if ids.len() == 1 {
        return Ok(Some(ids[0]));
    }
    let (left, right) = ids.split_at(ids.len() / 2);
    for half in [left, right] {
        if half.is_empty() {
            continue;
        }
        let run = runner.run_ids(half)?;
        // A half that fails to execute cleanly proves nothing either way, so it
        // is not treated as evidence of absence.
        if !run.all_completed() {
            continue;
        }
        if reproduces(&run, function, fingerprint) {
            return narrow(runner, function, fingerprint, half);
        }
    }
    Ok(None)
}

/// Isolates one finding within the batch that produced it.
fn isolate(
    runner: &mut Runner<'_>,
    corpus: &Corpus,
    function: &str,
    fingerprint: &Fingerprint,
    batch: &[usize],
) -> Result<Isolation, DynamicError> {
    if let [only] = batch {
        return Ok(Isolation::Single { id: *only });
    }
    let before = runner.runs();
    match narrow(runner, function, fingerprint, batch)? {
        Some(id) => {
            let inputs = corpus
                .case(id)
                .map(|case| case.inputs.clone())
                .unwrap_or_default();
            Ok(Isolation::Case {
                id,
                inputs,
                runs: runner.runs() - before,
            })
        }
        None => Ok(Isolation::Sequence {
            ids: batch.to_vec(),
            runs: runner.runs() - before,
            detail: "no single case reproduces this finding, so it depends on earlier cases in \
                     the batch; the whole batch is preserved for replay"
                .to_string(),
        }),
    }
}

/// Simplification candidates for one value, most aggressive first.
///
/// Every candidate is strictly simpler than its input — smaller for a scalar,
/// fewer non-zero bytes for an array, `false` for a `bool`. That is what makes
/// the shrink loop terminate: each accepted step strictly decreases a measure
/// that is bounded below, so no sequence of accepted candidates can cycle.
fn simplifications(value: &Value) -> Vec<Value> {
    match value {
        Value::Scalar { bits, value: v } => {
            let mut candidates = Vec::new();
            for target in [0u64, 1, v / 2, v.saturating_sub(1)] {
                // Strictly smaller only: 0 is already minimal, and offering it
                // `1` would let the loop walk away from the simplest value.
                if target < *v && !candidates.iter().any(|existing| {
                    matches!(existing, Value::Scalar { value, .. } if *value == target)
                }) {
                    candidates.push(Value::Scalar {
                        bits: *bits,
                        value: target,
                    });
                }
            }
            candidates
        }
        Value::Bool { value } => {
            if *value {
                vec![Value::Bool { value: false }]
            } else {
                Vec::new()
            }
        }
        Value::Bytes { bytes } => {
            let mut candidates = Vec::new();
            if bytes.iter().any(|byte| *byte != 0) {
                candidates.push(Value::Bytes {
                    bytes: vec![0; bytes.len()],
                });
            }
            // Zero the trailing half, then individual non-zero bytes from the
            // end: a leak that depends on the last byte survives the first and
            // is pinned down by the second.
            if bytes.len() > 1 {
                let mut half = bytes.clone();
                for byte in half.iter_mut().skip(bytes.len() / 2) {
                    *byte = 0;
                }
                if half != *bytes {
                    candidates.push(Value::Bytes { bytes: half });
                }
            }
            for index in (0..bytes.len()).rev() {
                if bytes[index] != 0 {
                    let mut single = bytes.clone();
                    single[index] = 0;
                    candidates.push(Value::Bytes { bytes: single });
                }
            }
            candidates
        }
    }
}

/// Reduces a reproducing input while the *same* finding still appears.
///
/// A candidate is accepted only when it reproduces the recorded fingerprint. A
/// panic, a different diagnostic class, or a finding somewhere else is not a
/// successful shrink — it is a different bug, and treating it as progress would
/// hand the developer a reproducer for something they were not looking at.
pub fn shrink(
    runner: &mut Runner<'_>,
    contract: &str,
    function: &str,
    fingerprint: &Fingerprint,
    inputs: &[(String, Value)],
    budget: usize,
) -> Result<Option<Shrunk>, DynamicError> {
    let mut current = inputs.to_vec();
    let mut attempts = 0;
    let mut steps = 0;
    let mut improved = true;
    while improved && attempts < budget {
        improved = false;
        for position in 0..current.len() {
            for candidate in simplifications(&current[position].1) {
                if attempts >= budget {
                    break;
                }
                attempts += 1;
                let mut trial = current.clone();
                trial[position].1 = candidate;
                let run = runner.run_inputs(contract, &trial)?;
                if run.all_completed() && reproduces(&run, function, fingerprint) {
                    current = trial;
                    steps += 1;
                    improved = true;
                    break;
                }
            }
        }
    }
    if steps == 0 {
        return Ok(None);
    }
    Ok(Some(Shrunk {
        inputs: current,
        attempts,
        steps,
    }))
}

/// What a check is allowed to spend.
#[derive(Debug, Clone)]
pub struct CheckBudget {
    pub batch_size: usize,
    pub shrink_budget: usize,
    /// Whether to attempt shrinking at all.
    pub shrink: bool,
}

impl Default for CheckBudget {
    fn default() -> Self {
        CheckBudget {
            batch_size: DEFAULT_BATCH_SIZE,
            shrink_budget: DEFAULT_SHRINK_BUDGET,
            shrink: true,
        }
    }
}

/// Runs a whole corpus for one contract and classifies the result.
///
/// Classification order is fail-closed and mirrors the existing dynamic
/// backend: a harness that did not run, then instrumentation, then the positive
/// controls, then unattributable diagnostics, and only then is a clean run
/// allowed to mean anything.
pub fn check_contract(
    runner: &mut Runner<'_>,
    contract: &Contract,
    corpus: &Corpus,
    secret_parameters: &[String],
    marked_bytes: u64,
    budget: &CheckBudget,
) -> Result<ContractCheck, DynamicError> {
    let function = &contract.function;
    let mut report = ContractCheck {
        contract: contract.id.clone(),
        function: function.clone(),
        secret_parameters: secret_parameters.to_vec(),
        marked_bytes,
        outcome: Outcome::Inconclusive,
        message: String::new(),
        calibration: Control::NotRun,
        binding: Control::NotRun,
        cases_planned: corpus.cases.len(),
        cases_executed: 0,
        cases_completed: 0,
        analyzer_runs: 0,
        findings: Vec::new(),
        unattributed: Vec::new(),
        other_diagnostics: Vec::new(),
    };

    if corpus.cases.is_empty() {
        report.message =
            "the corpus contains no cases, and a run that checks nothing is not a pass".to_string();
        report.analyzer_runs = runner.runs();
        return Ok(report);
    }

    let all: Vec<usize> = corpus.cases.iter().map(|case| case.id).collect();
    let mut calibration_fired = false;
    let mut binding_fired = false;
    let mut pending: Vec<(Fingerprint, Vec<usize>, MemcheckError)> = Vec::new();

    for batch in all.chunks(budget.batch_size.max(1)) {
        let run = runner.run_ids(batch)?;
        report.cases_executed += batch.len();
        report.cases_completed += run.completed.len();

        if !run.instrumented {
            report.message = "the harness did not report running under Valgrind, so secret \
                              marking was inert and a clean result would prove nothing"
                .to_string();
            report.analyzer_runs = runner.runs();
            return Ok(report);
        }
        if let Some(detail) = &run.parse_error {
            report.message = format!("Memcheck output could not be parsed: {detail}");
            report.analyzer_runs = runner.runs();
            return Ok(report);
        }
        if !run.all_completed() {
            report.message = format!(
                "{} of {} cases in a batch completed; the harness stopped early, so no \
                 security conclusion can be drawn. stderr: {}",
                run.completed.len(),
                batch.len(),
                first_lines(&run.stderr, 4)
            );
            report.analyzer_runs = runner.runs();
            return Ok(report);
        }

        let parsed = run.run.as_ref().expect("checked above");
        calibration_fired |= parsed
            .secret_dependency_errors()
            .any(|error| error.attributable_to(trace_check_control::PROBE));
        binding_fired |= parsed
            .secret_dependency_errors()
            .any(|error| error.attributable_to(trace_check_control::BINDING));

        for error in parsed.secret_dependency_errors() {
            if is_control(error) {
                continue;
            }
            let fingerprint = Fingerprint::of(error);
            if error.attributable_to(function) {
                if !pending.iter().any(|(known, _, _)| *known == fingerprint) {
                    pending.push((fingerprint, batch.to_vec(), error.clone()));
                }
            } else {
                report.unattributed.push(Finding::from_error(
                    error,
                    function,
                    Isolation::Sequence {
                        ids: batch.to_vec(),
                        runs: 0,
                        detail: "not attributable to the contract's function, so it was not \
                                 narrowed"
                            .to_string(),
                    },
                ));
            }
        }
        for error in parsed.non_secret_errors() {
            report.other_diagnostics.push(Finding::from_error(
                error,
                function,
                Isolation::Sequence {
                    ids: batch.to_vec(),
                    runs: 0,
                    detail: "not secret dependency, so it was not narrowed".to_string(),
                },
            ));
        }
    }

    report.calibration = Control::from_fired(calibration_fired);
    report.binding = Control::from_fired(binding_fired);

    // The controls gate everything downstream.
    if report.calibration == Control::Failed {
        report.message = format!(
            "the positive control produced no diagnostic, so secret marking is not reaching \
             compiled code in this binary (probe `{}`). A clean result here would be \
             meaningless",
            trace_check_control::PROBE
        );
        report.analyzer_runs = runner.runs();
        return Ok(report);
    }
    if report.binding == Control::Failed {
        report.message = format!(
            "the binding control produced no diagnostic, so the bytes this harness marked never \
             reached `{function}` as undefined. Calibration passing only shows marking works \
             somewhere in this binary, not that this contract's secret was analyzed"
        );
        report.analyzer_runs = runner.runs();
        return Ok(report);
    }

    // Isolate each distinct finding, then try to shrink it.
    for (fingerprint, batch, error) in pending {
        let isolation = isolate(runner, corpus, function, &fingerprint, &batch)?;
        let mut finding = Finding::from_error(&error, function, isolation);
        // Only a finding pinned to one case has an input to reduce. A
        // sequence-dependent one is preserved as it is.
        let reproducer: Vec<(String, Value)> = match &finding.isolation {
            Isolation::Case { inputs, .. } => inputs.clone(),
            Isolation::Single { id } => corpus
                .case(*id)
                .map(|case| case.inputs.clone())
                .unwrap_or_default(),
            Isolation::Sequence { .. } => Vec::new(),
        };
        if budget.shrink && !reproducer.is_empty() {
            finding.shrunk = shrink(
                runner,
                &contract.id,
                function,
                &fingerprint,
                &reproducer,
                budget.shrink_budget,
            )?;
        }
        report.findings.push(finding);
    }

    if !report.other_diagnostics.is_empty() {
        let memory = report
            .other_diagnostics
            .iter()
            .filter(|finding| finding.classification == Classification::MemoryError)
            .count();
        let unrelated = report.other_diagnostics.len() - memory;
        report.message = format!(
            "Memcheck reported {} diagnostic(s) that are not secret dependency ({memory} memory \
             error(s), {unrelated} undefined value(s) not traceable to the marked secret); \
             resolve these before trusting a security conclusion",
            report.other_diagnostics.len()
        );
        report.analyzer_runs = runner.runs();
        return Ok(report);
    }

    if !report.findings.is_empty() {
        let branches = report
            .findings
            .iter()
            .filter(|finding| finding.classification == Classification::SecretDependentBranch)
            .count();
        let addresses = report.findings.len() - branches;
        report.outcome = Outcome::LeakDetected;
        report.message = format!(
            "{} finding(s) in `{function}` over {} generated case(s): {branches} \
             secret-dependent branch(es), {addresses} secret-dependent address/value use(s)",
            report.findings.len(),
            report.cases_completed
        );
        report.analyzer_runs = runner.runs();
        return Ok(report);
    }

    if !report.unattributed.is_empty() {
        report.message = format!(
            "{} secret-dependency finding(s) were observed but none is attributable to \
             `{function}`; they are retained for inspection. The usual causes are a missing \
             declassification in the harness and a target the compiler inlined away",
            report.unattributed.len()
        );
        report.analyzer_runs = runner.runs();
        return Ok(report);
    }

    report.outcome = Outcome::NoLeakObserved;
    report.message = format!(
        "no secret-derived value reached a branch or an address in `{function}` on the paths {} \
         generated case(s) executed; this is not proof of constant-time behavior",
        report.cases_completed
    );
    report.analyzer_runs = runner.runs();
    Ok(report)
}

fn first_lines(text: &str, count: usize) -> String {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .take(count)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Errors specific to orchestrating a check.
#[derive(Debug)]
pub enum CheckError {
    Dynamic(DynamicError),
}

impl From<DynamicError> for CheckError {
    fn from(error: DynamicError) -> Self {
        CheckError::Dynamic(error)
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckError::Dynamic(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CheckError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memcheck::{self, Origin};

    /// The control symbols this module matches on are the ones
    /// `trace-check-test` actually defines. If they drifted, the controls'
    /// diagnostics would be reported as leaks in the function under analysis and
    /// every clean contract would fail.
    #[test]
    fn the_control_symbols_match_the_test_crate() {
        assert_eq!(
            trace_check_control::PROBE,
            trace_check_test::calibration::PROBE_SYMBOL
        );
        assert_eq!(
            trace_check_control::BINDING,
            trace_check_test::calibration::BINDING_PROBE_SYMBOL
        );
    }

    fn error_with(function: &str, file: &str, line: u32, kind: &str) -> MemcheckError {
        let xml = format!(
            "<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>\
             <error><unique>0x0</unique><kind>{kind}</kind>\
             <what>Use of uninitialised value of size 8</what>\
             <stack><frame><ip>0x1</ip><fn>{function}</fn><file>{file}</file>\
             <line>{line}</line></frame></stack>\
             <auxwhat>Uninitialised value was created by a client request</auxwhat>\
             <stack><frame><ip>0x9</ip><fn>harness</fn></frame></stack></error>\
             <status><state>FINISHED</state></status></valgrindoutput>"
        );
        memcheck::parse(&xml)
            .expect("fixture parses")
            .errors
            .remove(0)
    }

    /// A fingerprint is classification plus the attributed frame and its source
    /// location, and does not include an absolute address.
    #[test]
    fn a_fingerprint_identifies_a_finding_without_an_address() {
        let error = error_with(
            "crypto::lookup::substitute_indexed",
            "lookup.rs",
            37,
            "UninitValue",
        );
        let fingerprint = Fingerprint::of(&error);
        assert_eq!(
            fingerprint.classification,
            Classification::SecretDependentValue
        );
        assert_eq!(
            fingerprint.function.as_deref(),
            Some("crypto::lookup::substitute_indexed")
        );
        assert_eq!(fingerprint.location.as_deref(), Some("lookup.rs:37"));
        let rendered = fingerprint.describe();
        assert!(rendered.contains("lookup.rs:37"), "{rendered}");
        assert!(
            !rendered.contains("0x"),
            "an address must not identify a finding: {rendered}"
        );
    }

    /// Two findings at different lines are different findings; the same line is
    /// the same finding.
    #[test]
    fn fingerprints_distinguish_sites() {
        let first = Fingerprint::of(&error_with("f", "a.rs", 10, "UninitValue"));
        let same = Fingerprint::of(&error_with("f", "a.rs", 10, "UninitValue"));
        let other_line = Fingerprint::of(&error_with("f", "a.rs", 11, "UninitValue"));
        let other_kind = Fingerprint::of(&error_with("f", "a.rs", 10, "UninitCondition"));
        assert_eq!(first, same);
        assert_ne!(first, other_line);
        assert_ne!(first, other_kind);
    }

    /// Both controls are recognized, so their own diagnostics are never
    /// reported as findings in the function under analysis.
    #[test]
    fn control_diagnostics_are_recognized() {
        let calibration = error_with(
            "trace_check_test::calibration::secret_dependent_probe",
            "calibration.rs",
            44,
            "UninitValue",
        );
        let binding = error_with(
            "trace_check_test::calibration::secret_binding_probe",
            "calibration.rs",
            70,
            "UninitValue",
        );
        let target = error_with(
            "crypto::lookup::substitute_indexed",
            "lookup.rs",
            37,
            "UninitValue",
        );
        assert!(is_control(&calibration));
        assert!(is_control(&binding));
        assert!(!is_control(&target));
    }

    /// A client-request origin is what makes a diagnostic secret dependency
    /// rather than an ordinary uninitialized-memory bug.
    #[test]
    fn only_a_client_request_origin_counts_as_secret_dependency() {
        let error = error_with("f", "a.rs", 1, "UninitValue");
        assert_eq!(error.origin, Origin::ClientRequest);
        assert!(error.classification.is_secret_dependency());
    }

    /// Scalars shrink toward zero, never away from it, and every candidate is
    /// strictly smaller — which is what makes the loop terminate.
    #[test]
    fn scalars_shrink_toward_zero() {
        let candidates = simplifications(&Value::Scalar { bits: 8, value: 42 });
        assert!(candidates.contains(&Value::Scalar { bits: 8, value: 0 }));
        assert!(candidates.contains(&Value::Scalar { bits: 8, value: 1 }));
        for candidate in &candidates {
            let Value::Scalar { value, .. } = candidate else {
                panic!("expected a scalar, got {candidate:?}");
            };
            assert!(*value < 42, "{value} is not simpler than 42");
        }
        // Already minimal: nothing to try, and in particular not `1`.
        assert!(simplifications(&Value::Scalar { bits: 8, value: 0 }).is_empty());
        assert_eq!(
            simplifications(&Value::Scalar { bits: 8, value: 1 }),
            vec![Value::Scalar { bits: 8, value: 0 }]
        );
    }

    /// A byte array shrinks toward all-zero, then by zeroing its trailing half,
    /// then one byte at a time from the end — which is what pins down a leak
    /// that depends only on the last byte.
    #[test]
    fn byte_arrays_shrink_toward_zero_and_then_per_byte() {
        let candidates = simplifications(&Value::Bytes {
            bytes: vec![0xff, 0xff, 0xff, 0xff],
        });
        assert_eq!(
            candidates[0],
            Value::Bytes {
                bytes: vec![0, 0, 0, 0]
            }
        );
        assert_eq!(
            candidates[1],
            Value::Bytes {
                bytes: vec![0xff, 0xff, 0, 0]
            }
        );
        // Then individual bytes, from the end.
        assert!(candidates.contains(&Value::Bytes {
            bytes: vec![0xff, 0xff, 0xff, 0x00]
        }));
        assert!(simplifications(&Value::Bytes { bytes: vec![0; 4] }).is_empty());
    }

    /// `true` shrinks to `false`; `false` has nothing simpler.
    #[test]
    fn bools_shrink_to_false() {
        assert_eq!(
            simplifications(&Value::Bool { value: true }),
            vec![Value::Bool { value: false }]
        );
        assert!(simplifications(&Value::Bool { value: false }).is_empty());
    }

    /// An isolation names the case ids that reproduce the finding, whichever
    /// form it took.
    #[test]
    fn an_isolation_names_its_reproducing_cases() {
        assert_eq!(Isolation::Single { id: 7 }.ids(), vec![7]);
        assert_eq!(
            Isolation::Case {
                id: 3,
                inputs: Vec::new(),
                runs: 4
            }
            .ids(),
            vec![3]
        );
        assert_eq!(
            Isolation::Sequence {
                ids: vec![1, 2, 3],
                runs: 2,
                detail: String::new()
            }
            .ids(),
            vec![1, 2, 3]
        );
    }

    /// A sequence-dependent finding keeps its whole batch and says why, rather
    /// than being dropped for resisting attribution.
    #[test]
    fn a_sequence_dependent_finding_is_preserved() {
        let isolation = Isolation::Sequence {
            ids: vec![4, 5, 6],
            runs: 2,
            detail: "no single case reproduces this finding".to_string(),
        };
        assert_eq!(isolation.ids().len(), 3);
        let json = serde_json::to_string(&isolation).expect("serializes");
        assert!(json.contains("\"kind\":\"sequence\""), "{json}");
        assert!(json.contains("no single case"), "{json}");
    }

    /// The default batch size is modest, and the shrink budget is separate from
    /// the check's own.
    #[test]
    fn budgets_are_separate_and_bounded() {
        let budget = CheckBudget::default();
        assert_eq!(budget.batch_size, DEFAULT_BATCH_SIZE);
        assert_eq!(budget.shrink_budget, DEFAULT_SHRINK_BUDGET);
        assert!(budget.shrink);
        // A zero batch size would run nothing; the runner also clamps it.
        const _: () = assert!(DEFAULT_BATCH_SIZE >= 1);
    }
}
