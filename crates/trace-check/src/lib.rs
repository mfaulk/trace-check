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
//! The symbolic backend has two artifact sources. M4's compiles one
//! hand-written `no_std` file; M5's [`harness`] generates a `no_std` harness
//! package around a developer's real Cargo library, so the function analyzed is
//! the one they ship. Both feed the same engine.
//!
//! A third backend reasons *symbolically*: [`symbolic`] drives BINSEC's
//! relational symbolic execution over an optimized native artifact, searching
//! for a secret assignment that leaks rather than sampling chosen inputs. When
//! the search completes it reports `VERIFIED_BOUNDED` — bounded noninterference
//! over a declared domain, which is a different and stronger claim than the
//! dynamic backend's `NO_LEAK_OBSERVED`.

pub mod census;
pub mod compare;
pub mod contract;
pub mod dynamic_harness;
pub mod experiment;
pub mod generate;
pub mod harness;
pub mod library_report;
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

use contract::VerifyConfig;
use harness::{Artifact, Harness, HarnessError, Library, ResolvedSymbol, Workspace};
use library_report::{LibraryReport, Verified};

/// Verifies declared contracts against the real functions in a Cargo library.
///
/// One artifact per contract, deliberately. A shared artifact would need one
/// entry symbol per contract, and anything `_start` does not reach is dropped
/// as dead code — a multi-entry harness silently lost two entry symbols during
/// the feasibility spike. Per-contract packages make that unrepresentable, and
/// let each report name the exact executable its result describes.
///
/// # Order of operations
///
/// The analyzer backend is prepared **lazily**, immediately before the first
/// query it is needed for. Everything else is checked first, in the order it
/// becomes decidable: the selection from the configuration alone, then each
/// contract's annotation, parameter roles, signature and compiled symbol.
///
/// This ordering is the whole point. An earlier revision prepared the container
/// backend up front, so on a machine without the analyzer image a misspelled
/// contract name reported a missing image rather than the typo. Moving the
/// selection check ahead of it fixed that case and left two more behind: a
/// contract that is *configured* but carries no `#[constant_time]` annotation
/// also reported a missing image, because reaching that diagnosis needs the
/// library compiled and compilation came after the backend check. A problem
/// with the contract must be reported as a problem with the contract.
///
/// The cost is that a developer without the analyzer waits for one probe and
/// one harness build before being told to install it. That is the right trade:
/// being told the truth about the contract matters more than being told about
/// the backend sooner.
pub fn run_contract_verification(
    library: &Library,
    config: &VerifyConfig,
    contracts: &[String],
    workspace: &Workspace,
    runtime: Option<&str>,
) -> Result<LibraryReport, HarnessError> {
    config.require_configured(contracts)?;

    let mut verifier: Option<symbolic::Verifier> = None;
    let mut entries = Vec::new();
    for contract_id in contracts {
        let settings = config
            .settings(contract_id)
            .expect("the selection was validated above");
        let (work_dir, target_dir) = workspace.directories_for(contract_id)?;

        let contract = harness::probe_contract(library, contract_id, &work_dir, &target_dir)?;
        // Checked after the descriptor is known, so the message can name the
        // declared secrets rather than guess at them.
        settings.validate_inputs(contract_id, &contract.descriptor)?;

        let generated: Harness = harness::generate(library, &contract)?;
        let artifact: Artifact =
            harness::build(library, &generated, contract_id, &work_dir, &target_dir)?;
        let symbol: ResolvedSymbol = harness::resolve_symbol(&artifact.path, contract_id)?;

        let case = harness::verification_case(&contract, &symbol, &generated, settings);

        // Prepared here, not earlier: everything above is a question about the
        // contract and the library, and a missing analyzer must not answer any
        // of them.
        if verifier.is_none() {
            let mut prepared = symbolic::Verifier::prepare_with(runtime)?;
            prepared.check_image()?;
            verifier = Some(prepared);
        }
        let verifier = verifier.as_ref().expect("prepared just above");
        let result = verifier.verify(&case, &artifact.path, &artifact.sha256)?;

        entries.push(Verified {
            contract,
            case,
            library: library.clone(),
            symbol,
            harness: generated,
            artifact,
            result,
        });
    }

    // A non-empty selection always reaches the analyzer, because
    // `require_configured` rejects an empty one and any earlier failure
    // returns.
    let verifier = verifier.expect("a verified contract implies a prepared analyzer");
    Ok(library_report::build(
        entries,
        verifier.identity(),
        contracts.len(),
        workspace.is_kept(),
    ))
}
