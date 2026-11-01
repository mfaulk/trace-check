//! Executing one constant-time test under Memcheck and classifying the result.
//!
//! Each test runs in its own process via `--exact`, so a diagnostic belongs
//! unambiguously to one test and tests cannot interfere with one another.
//!
//! Classification order matters, and every step is fail-closed:
//!
//! 1. the test process must not have failed for its own reasons,
//! 2. the XML must parse completely (M2's four completeness checks),
//! 3. the **positive control must have fired**,
//! 4. no non-secret diagnostic may remain,
//! 5. only then may a clean run mean anything.
//!
//! Step 3 is the one M3 adds. M2 proves Valgrind is running; it does not prove
//! that *this* secret was marked and consumed. Without the control, a
//! misplaced marker or an optimized-away input would produce a confident
//! `NO_LEAK_OBSERVED`.

use serde::Serialize;

use trace_check::memcheck::{self, Classification, MemcheckError};
use trace_check::native::{self, Limits, NativeError};
use trace_check::security::Outcome;

use crate::discover::TestRecord;

/// Function name a calibration diagnostic is attributed to. Must match
/// `trace_check_test::calibration::PROBE_SYMBOL`.
pub const PROBE_SYMBOL: &str = "secret_dependent_probe";

/// Whether the positive control fired in a given run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Calibration {
    /// The probe produced its expected diagnostic: marking reaches compiled
    /// code in this binary.
    Confirmed,
    /// The probe produced nothing. Marking is inert, so no clean result from
    /// this process can be trusted.
    Failed,
    /// The run did not get far enough to tell.
    NotRun,
}

impl Calibration {
    pub fn as_str(self) -> &'static str {
        match self {
            Calibration::Confirmed => "confirmed",
            Calibration::Failed => "failed",
            Calibration::NotRun => "not_run",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub classification: Classification,
    pub description: String,
    pub what: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    pub origin: String,
    pub stack: Vec<String>,
}

impl Finding {
    fn from_error(error: &MemcheckError) -> Self {
        let primary = error.primary_frame();
        Finding {
            classification: error.classification,
            description: error.classification.describe().to_string(),
            what: error.what.clone(),
            location: primary.and_then(|frame| {
                frame.file.as_ref().map(|file| match frame.line {
                    Some(line) => format!("{file}:{line}"),
                    None => file.clone(),
                })
            }),
            function: primary.and_then(|frame| frame.function.clone()),
            origin: error.origin.describe(),
            stack: error
                .primary_stack
                .iter()
                .take(6)
                .map(ToString::to_string)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TestOutcome {
    pub test: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub executable: String,
    pub executable_sha256: String,
    pub outcome: Outcome,
    pub calibration: Calibration,
    pub message: String,
    pub findings: Vec<Finding>,
    /// Diagnostics that are not secret dependency. Retained, never dropped.
    pub other_diagnostics: Vec<Finding>,
}

impl TestOutcome {
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::NoLeakObserved
    }
}

/// Runs one test under Memcheck and classifies what came back.
pub fn run_test(
    valgrind: &std::path::Path,
    record: &TestRecord,
    limits: Limits,
) -> Result<TestOutcome, NativeError> {
    let args = vec![
        "--exact".to_string(),
        record.name.clone(),
        "--nocapture".to_string(),
        // One test per process; the harness would otherwise spawn a thread and
        // blur which code a diagnostic belongs to.
        "--test-threads=1".to_string(),
    ];
    let env = vec![("TRACE_CHECK_MODE".to_string(), "run".to_string())];
    let output = native::run_under_memcheck(
        valgrind,
        std::path::Path::new(&record.executable),
        &args,
        &env,
        limits,
    )?;

    let base = |outcome: Outcome, calibration: Calibration, message: String| TestOutcome {
        test: record.name.clone(),
        target: record.target.clone(),
        executable: record.executable.clone(),
        executable_sha256: record.executable_sha256.clone(),
        outcome,
        calibration,
        message,
        findings: Vec::new(),
        other_diagnostics: Vec::new(),
    };

    // The test harness exits 101 when a test fails or panics. That is a test
    // failure, not a security result, and must not be reported as either a
    // leak or a clean run.
    let findings_code = output.exited_with_findings();
    match output.exit_code {
        Some(code) if code == 0 || findings_code => {}
        Some(code) => {
            let detail = if output.stderr.trim().is_empty() {
                output.stdout.clone()
            } else {
                output.stderr.clone()
            };
            return Ok(base(
                Outcome::Inconclusive,
                Calibration::NotRun,
                format!(
                    "the test process failed with exit code {code}, so no security conclusion \
                     can be drawn: {}",
                    first_lines(&detail, 6)
                ),
            ));
        }
        None => {
            return Ok(base(
                Outcome::Inconclusive,
                Calibration::NotRun,
                format!(
                    "the test process was killed by a signal: {}",
                    first_lines(&output.stderr, 4)
                ),
            ))
        }
    }

    // Did the test actually execute? `--exact` on a name that no longer exists
    // runs zero tests and still exits 0, which must not read as a pass.
    // libtest prints `test result: ok. 1 passed; …` for a single match.
    if !output.stdout.contains("1 passed") {
        return Ok(base(
            Outcome::Inconclusive,
            Calibration::NotRun,
            format!(
                "the harness reported no executed test for `{}`; it may have been renamed \
                 or filtered out",
                record.name
            ),
        ));
    }

    let run = match memcheck::parse(&output.xml) {
        Ok(run) => run,
        Err(error) => {
            return Ok(base(
                Outcome::Inconclusive,
                Calibration::NotRun,
                format!("Memcheck output could not be parsed: {error}"),
            ))
        }
    };

    // Split calibration from everything else by attribution. The probe is
    // `#[inline(never)]` precisely so this split is possible.
    let (calibration_errors, rest): (Vec<_>, Vec<_>) = run
        .errors
        .iter()
        .partition(|error| error.attributable_to(PROBE_SYMBOL));

    let calibration = if calibration_errors
        .iter()
        .any(|error| error.classification.is_secret_dependency())
    {
        Calibration::Confirmed
    } else {
        Calibration::Failed
    };

    let secret_findings: Vec<Finding> = rest
        .iter()
        .filter(|error| error.classification.is_secret_dependency())
        .map(|error| Finding::from_error(error))
        .collect();
    let other: Vec<Finding> = rest
        .iter()
        .filter(|error| !error.classification.is_secret_dependency())
        .map(|error| Finding::from_error(error))
        .collect();

    let mut result = base(Outcome::Inconclusive, calibration, String::new());
    result.findings = secret_findings;
    result.other_diagnostics = other;

    // The positive control gates everything downstream.
    if calibration == Calibration::Failed {
        result.outcome = Outcome::Inconclusive;
        result.message = format!(
            "the positive control produced no diagnostic, so secret marking is not reaching \
             compiled code in this binary (probe `{PROBE_SYMBOL}`). A clean result here would \
             be meaningless"
        );
        return Ok(result);
    }

    if !result.other_diagnostics.is_empty() {
        let memory = result
            .other_diagnostics
            .iter()
            .filter(|f| f.classification == Classification::MemoryError)
            .count();
        let unrelated = result.other_diagnostics.len() - memory;
        result.outcome = Outcome::Inconclusive;
        result.message = format!(
            "Memcheck reported {} diagnostic(s) that are not secret dependency ({memory} \
             memory error(s), {unrelated} undefined value(s) not traceable to the marked \
             secret); resolve these before trusting a security conclusion",
            result.other_diagnostics.len()
        );
        return Ok(result);
    }

    if !result.findings.is_empty() {
        // When the test declares a contract target, require the finding to be
        // attributable to it; otherwise we would blame the wrong function.
        if let Some(target) = &record.target {
            let attributed = rest
                .iter()
                .filter(|error| error.classification.is_secret_dependency())
                .any(|error| error.attributable_to(target));
            if !attributed {
                result.outcome = Outcome::Inconclusive;
                result.message = format!(
                    "{} secret-dependency finding(s) were observed but none is attributable to \
                     the declared target `{target}`; they are retained for inspection",
                    result.findings.len()
                );
                return Ok(result);
            }
        }
        let branches = result
            .findings
            .iter()
            .filter(|f| f.classification == Classification::SecretDependentBranch)
            .count();
        let addresses = result.findings.len() - branches;
        result.outcome = Outcome::LeakDetected;
        result.message = format!(
            "{} finding(s): {branches} secret-dependent branch(es), {addresses} \
             secret-dependent address/value use(s)",
            result.findings.len()
        );
        return Ok(result);
    }

    result.outcome = Outcome::NoLeakObserved;
    result.message = "no secret-derived value reached a branch or an address on the path this \
                      test exercised; this is not proof of constant-time behavior"
        .to_string();
    Ok(result)
}

fn first_lines(text: &str, count: usize) -> String {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .take(count)
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: &str = r#"<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>
<status><state>FINISHED</state></status></valgrindoutput>"#;

    fn with_errors(body: &str) -> String {
        format!(
            "<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>{body}\
             <status><state>FINISHED</state></status></valgrindoutput>"
        )
    }

    fn calibration_error() -> String {
        "<error><kind>UninitValue</kind><what>Use of uninitialised value of size 8</what><stack>\
         <frame><fn>read_volatile&lt;u8&gt;</fn></frame>\
         <frame><fn>trace_check_test::calibration::secret_dependent_probe</fn>\
         <file>calibration.rs</file><line>50</line></frame></stack>\
         <auxwhat>Uninitialised value was created by a client request</auxwhat>\
         <stack><frame><fn>mark</fn></frame></stack></error>"
            .to_string()
    }

    fn leak_error(function: &str) -> String {
        format!(
            "<error><kind>UninitCondition</kind><what>Conditional jump</what><stack>\
             <frame><fn>{function}</fn><file>lib.rs</file><line>17</line></frame></stack>\
             <auxwhat>Uninitialised value was created by a client request</auxwhat>\
             <stack><frame><fn>mark</fn></frame></stack></error>"
        )
    }

    /// The calibration finding is recognized by attribution to the probe.
    #[test]
    fn calibration_is_recognized() {
        let run = memcheck::parse(&with_errors(&calibration_error())).unwrap();
        assert!(run.errors[0].attributable_to(PROBE_SYMBOL));
        assert!(run.errors[0].classification.is_secret_dependency());
    }

    /// A real finding is not mistaken for calibration, which is what keeps the
    /// control from masking an actual leak.
    #[test]
    fn a_real_finding_is_not_calibration() {
        let run = memcheck::parse(&with_errors(&leak_error("crate::verify"))).unwrap();
        assert!(!run.errors[0].attributable_to(PROBE_SYMBOL));
    }

    /// With calibration plus a real finding, the two are separated and only the
    /// real one counts toward the verdict.
    #[test]
    fn calibration_and_leak_are_separated() {
        let xml = with_errors(&format!(
            "{}{}",
            calibration_error(),
            leak_error("crate::verify")
        ));
        let run = memcheck::parse(&xml).unwrap();
        let (calib, rest): (Vec<_>, Vec<_>) = run
            .errors
            .iter()
            .partition(|e| e.attributable_to(PROBE_SYMBOL));
        assert_eq!(calib.len(), 1);
        assert_eq!(rest.len(), 1);
        assert_eq!(
            rest[0].primary_frame().unwrap().function.as_deref(),
            Some("crate::verify")
        );
    }

    /// A clean run with no calibration diagnostic has a failed control: there
    /// is nothing proving marking worked.
    #[test]
    fn clean_run_without_calibration_has_failed_control() {
        let run = memcheck::parse(CLEAN).unwrap();
        let fired = run
            .errors
            .iter()
            .any(|e| e.attributable_to(PROBE_SYMBOL) && e.classification.is_secret_dependency());
        assert!(!fired, "an empty run cannot confirm calibration");
    }

    /// Calibration labels round-trip for the JSON report.
    #[test]
    fn calibration_labels_are_stable() {
        assert_eq!(Calibration::Confirmed.as_str(), "confirmed");
        assert_eq!(Calibration::Failed.as_str(), "failed");
        assert_eq!(Calibration::NotRun.as_str(), "not_run");
    }

    /// The probe symbol matches the one the test library exports. If these
    /// drifted, calibration would never fire and every result would be
    /// inconclusive.
    #[test]
    fn probe_symbol_matches_the_test_library() {
        assert_eq!(PROBE_SYMBOL, "secret_dependent_probe");
    }

    /// Diagnostic text is truncated to a few lines so a panicking test does not
    /// flood the report.
    #[test]
    fn diagnostic_text_is_truncated() {
        let text = (0..50)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let rendered = first_lines(&text, 3);
        assert_eq!(rendered, "line 0 | line 1 | line 2");
    }
}
