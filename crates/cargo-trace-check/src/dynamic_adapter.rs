//! Discovering and running developer-written `#[ct_test]`s for a unified run.
//!
//! The execution half of M10.4. Building Cargo test binaries and running them
//! under Valgrind belongs here, where the `test` subcommand's machinery already
//! lives; binding the results to the compiler-derived inventory and deciding
//! whether a `dynamic` requirement is discharged belongs to
//! [`trace_check::dynamic`], because that is a security decision.
//!
//! Nothing here is reimplemented. `discover::build_test_binaries`,
//! `discover::discover`, `report::resolve_targets` and `run::run_test` are the
//! same functions `cargo trace-check test` uses, so a unified run and a
//! standalone one cannot disagree about what a test established.

use std::path::Path;

use sha2::{Digest, Sha256};
use trace_check::dynamic::DynamicTestRun;
use trace_check::enforcement::{Analysis, PolicyConfig};
use trace_check::native::{self, Limits};
use trace_check::DynamicRuns;

use crate::{discover, report, run};

/// Whether any policy in this configuration asks for the `dynamic` analysis.
///
/// Checked from the configuration alone, before the inventory exists: building
/// test binaries is expensive, and a project requiring nothing dynamic must not
/// pay for it. The policy's default counts as well as its per-contract
/// entries — `default_required = ["dynamic"]` applies to every declaration.
pub fn wanted(policy: &PolicyConfig) -> bool {
    policy.default_required.contains(&Analysis::Dynamic)
        || policy
            .contracts
            .values()
            .filter_map(|entry| entry.required.as_ref())
            .any(|required| required.contains(&Analysis::Dynamic))
}

/// Builds the test binaries, discovers the `#[ct_test]`s, and runs those that
/// declare a target.
///
/// # Only tests that claim a contract are run
///
/// A `#[ct_test]` with no `target` cannot discharge a contract-specific
/// obligation, so running it here would spend a Valgrind process to produce
/// evidence nothing can use. `cargo trace-check test` still runs them.
///
/// Ordinary unit tests are never executed: `discover` enumerates the
/// generated metadata tests only, which is M3's existing guarantee and the
/// reason discovery does not run the developer's suite.
pub fn collect(
    manifest_path: &Path,
    profile: Option<&str>,
    features: &[String],
    limits: Limits,
) -> Result<DynamicRuns, String> {
    let (valgrind, valgrind_version) = native::prepare_valgrind().map_err(|e| e.to_string())?;
    let (binaries, used_profile) =
        discover::build_test_binaries(Some(manifest_path), profile, features)
            .map_err(|e| e.to_string())?;
    let discovery = discover::discover(&binaries, &used_profile).map_err(|e| e.to_string())?;

    // An unknown or ambiguous target is an error before anything runs, exactly
    // as it is for `test`: a test naming a contract that does not exist claims
    // coverage of nothing, and a developer should hear about the typo rather
    // than about a requirement that stayed un-analyzed.
    report::resolve_targets(&discovery.tests, &discovery.contracts)?;

    let mut runs = Vec::new();
    for record in &discovery.tests {
        if record.target.is_none() {
            continue;
        }
        let outcome = run::run_test(&valgrind, record, limits).map_err(|e| e.to_string())?;
        runs.push(DynamicTestRun {
            test: outcome.test.clone(),
            declared_target: outcome.target.clone(),
            executable: outcome.executable.clone(),
            executable_sha256: outcome.executable_sha256.clone(),
            outcome: outcome.outcome,
            calibrated: outcome.calibration == run::Calibration::Confirmed,
            invoked_target: outcome.invoked_target,
            // `Calibration::NotRun` is M3's marker for a test that did not get
            // as far as its constant-time check: it failed, timed out, was
            // killed, or produced output that could not be parsed. Deriving
            // `completed` from it rather than assuming it is load-bearing --
            // hard-coding `true` reported a test that never ran its check as a
            // completed one whose positive control merely failed, which named
            // the wrong cause.
            completed: outcome.calibration != run::Calibration::NotRun,
            message: outcome.message.clone(),
            findings: outcome
                .findings
                .iter()
                .map(|finding| match (&finding.location, &finding.function) {
                    (Some(at), Some(function)) => {
                        format!("{}: {function} at {at}", finding.description)
                    }
                    (Some(at), None) => format!("{}: {at}", finding.description),
                    (None, Some(function)) => format!("{}: {function}", finding.description),
                    (None, None) => finding.description.clone(),
                })
                .collect(),
        });
    }

    Ok(DynamicRuns {
        runs,
        profile: used_profile,
        lockfile_sha256: lockfile_fingerprint(manifest_path),
        valgrind_version,
    })
}

/// `sha256` of the library's dependency lockfile, which decides the code
/// compiled into the test binaries.
///
/// Unavailable rather than fatal: a library with no lockfile is legitimate, and
/// recording that fact is more useful than refusing to analyze it.
fn lockfile_fingerprint(manifest_path: &Path) -> String {
    let lockfile = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("Cargo.lock");
    std::fs::read(&lockfile)
        .map(|bytes| format!("{:x}", Sha256::digest(&bytes)))
        .unwrap_or_else(|_| "unavailable".to_string())
}
