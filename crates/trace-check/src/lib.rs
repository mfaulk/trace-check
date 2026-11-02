//! Differential execution-trace analysis for secret-dependent control flow.
//!
//! The pipeline is: build a pinned WASM artifact, execute paired inputs under
//! WABT's interpreter ([`runner`]), reduce raw trace text to ordered
//! instruction locations ([`parser`]), compare those sequences ([`compare`]),
//! and render the result with its provenance and limits ([`report`]).
//!
//! Alongside that dynamic pipeline, [`screen`] runs two static analyses over
//! the compiled artifact: a structural census with a baseline regression gate
//! ([`census`]) and a taint analysis for secret-dependent control flow
//! ([`taint`]), both over the lowered module from [`wasm`].
//!
//! A second, independent backend analyzes **native** code: [`native`] builds a
//! harness, runs it under Valgrind Memcheck, and [`memcheck`] classifies the
//! diagnostics into secret-dependent branches and addresses. The two backends
//! share only the outcome vocabulary and provenance in [`security`] — their
//! evidence is of different kinds and is reported separately.
//!
//! A third backend reasons *symbolically*: [`symbolic`] drives BINSEC's
//! relational symbolic execution over an optimized native artifact, searching
//! for a secret assignment that leaks rather than sampling chosen inputs. When
//! the search completes it reports `VERIFIED_BOUNDED` — bounded noninterference
//! over a declared domain, which is a different and stronger claim than the
//! dynamic backend's `NO_LEAK_OBSERVED`.

pub mod census;
pub mod compare;
pub mod experiment;
pub mod memcheck;
pub mod native;
pub mod native_report;
pub mod parser;
pub mod report;
pub mod runner;
pub mod screen;
pub mod security;
pub mod symbolic;
pub mod symbolic_report;
pub mod taint;
pub mod wasm;

#[cfg(test)]
mod testwat;

use std::path::Path;

use compare::Comparison;
use experiment::{ComparisonSpec, Experiment};
use report::Report;
use runner::{CaseRun, Limits, RunError, Runner};

/// Executes an experiment end to end and assembles its report.
pub fn run_experiment(
    workspace_manifest: &Path,
    package: &str,
    experiment: &Experiment,
    limits: Limits,
    allow_version_mismatch: bool,
) -> Result<Report, RunError> {
    let runner = Runner::prepare(workspace_manifest, package, limits, allow_version_mismatch)?;
    let runs = runner.run_all(experiment)?;

    let mut results: Vec<(ComparisonSpec, Comparison)> = Vec::new();
    for spec in &experiment.comparisons {
        let a = &runs[&(spec.variant.clone(), spec.case_a.clone())];
        let b = &runs[&(spec.variant.clone(), spec.case_b.clone())];
        results.push((
            spec.clone(),
            compare::compare(&a.trace, &b.trace, a.stable && b.stable),
        ));
    }

    // Report runs in fixture order rather than hash order so output is stable.
    let ordered: Vec<CaseRun> = experiment
        .variants
        .iter()
        .flat_map(|variant| {
            experiment
                .cases
                .iter()
                .map(move |case| (variant.id.clone(), case.id.clone()))
        })
        .map(|key| runs[&key].clone())
        .collect();

    Ok(report::build(
        experiment,
        &runner.provenance,
        &ordered,
        &results,
    ))
}

use native::{NativeCase, NativeError, NativeManifest, NativeRunner};
use native_report::NativeReport;

/// Runs every case in a native manifest and assembles its report.
///
/// A build or execution failure for one case aborts the run rather than being
/// folded into the report: a harness failure is not a security result, and
/// continuing would risk presenting a partial analysis as a complete one.
pub fn run_native(
    workspace_manifest: &Path,
    manifest: &NativeManifest,
    limits: native::Limits,
) -> Result<NativeReport, NativeError> {
    let runner = NativeRunner::prepare(workspace_manifest, limits)?;
    let mut entries = Vec::new();
    for case in &manifest.cases {
        let (result, provenance) = runner.analyze(case)?;
        entries.push((case.clone(), result, provenance));
    }
    Ok(native_report::build(entries))
}

/// Runs a single named case, for a future assertion macro or focused debugging.
pub fn run_native_case(
    workspace_manifest: &Path,
    case: &NativeCase,
    limits: native::Limits,
) -> Result<NativeReport, NativeError> {
    let runner = NativeRunner::prepare(workspace_manifest, limits)?;
    let (result, provenance) = runner.analyze(case)?;
    Ok(native_report::build(vec![(
        case.clone(),
        result,
        provenance,
    )]))
}

use symbolic::{CaseFile, SymbolicError, VerificationCase, Verifier};
use symbolic_report::SymbolicReport;

/// Runs symbolic verification for the selected cases and assembles the report.
///
/// The artifact is built once and shared: every case analyzes the *same* binary,
/// so a reported hash describes all of them and a compiler change is visible as
/// one hash change rather than several.
pub fn run_symbolic(
    case_file: &CaseFile,
    case_dir: &Path,
    selected: &[VerificationCase],
    out_dir: &Path,
    runtime: Option<&str>,
) -> Result<SymbolicReport, SymbolicError> {
    let mut verifier = Verifier::prepare_with(runtime)?;
    verifier.check_image()?;

    let source = case_dir.join(&case_file.target_source);
    let (artifact, hash) = verifier.build(&source, out_dir)?;

    let mut entries = Vec::new();
    for case in selected {
        let result = verifier.verify(case, &artifact, &hash)?;
        entries.push((case.clone(), result));
    }

    Ok(symbolic_report::build(
        entries,
        verifier.provenance(&artifact, &hash),
        selected.len(),
    ))
}
