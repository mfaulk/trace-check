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

pub mod census;
pub mod compare;
pub mod experiment;
pub mod parser;
pub mod report;
pub mod runner;
pub mod screen;
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
