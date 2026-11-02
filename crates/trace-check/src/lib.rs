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
pub mod experiment;
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

use contract::{ContractError, VerifyConfig};
use harness::{Artifact, Harness, HarnessError, Library, ResolvedSymbol};
use library_report::{LibraryReport, Verified};

/// Verifies declared contracts against the real functions in a Cargo library.
///
/// One artifact per contract, deliberately. A shared artifact would need one
/// entry symbol per contract, and anything `_start` does not reach is dropped
/// as dead code — a multi-entry harness silently lost two entry symbols during
/// the feasibility spike. Per-contract packages make that unrepresentable, and
/// let each report name the exact executable its result describes.
pub fn run_contract_verification(
    library: &Library,
    config: &VerifyConfig,
    contracts: &[String],
    work_root: &Path,
    runtime: Option<&str>,
) -> Result<LibraryReport, HarnessError> {
    let mut verifier = symbolic::Verifier::prepare_with(runtime)?;
    verifier.check_image()?;

    let mut entries = Vec::new();
    let mut provenance = None;
    for contract_id in contracts {
        let settings =
            config
                .settings(contract_id)
                .ok_or_else(|| ContractError::NotConfigured {
                    contract: contract_id.clone(),
                    available: config.contracts().iter().map(|c| c.to_string()).collect(),
                })?;
        // A generated package per contract, sharing one target directory.
        // Per-contract target directories rebuilt `core`, `subtle` and the
        // library itself for every contract and left hundreds of megabytes
        // behind; sharing is safe because each generated package has its own
        // name, so their binaries do not collide.
        let work_dir = work_root.join("contracts").join(sanitize(contract_id));
        let target_dir = work_root.join("target");
        for directory in [&work_dir, &target_dir] {
            std::fs::create_dir_all(directory)
                .map_err(|e| HarnessError::Io(format!("{}: {e}", directory.display())))?;
        }

        let contract = harness::probe_contract(library, contract_id, &work_dir, &target_dir)?;
        // Checked after the descriptor is known, so the message can name the
        // declared secrets rather than guess at them.
        settings.validate_inputs(contract_id, &contract.descriptor)?;

        let generated: Harness = harness::generate(library, &contract)?;
        let artifact: Artifact =
            harness::build(library, &generated, contract_id, &work_dir, &target_dir)?;
        let symbol: ResolvedSymbol = harness::resolve_symbol(&artifact.path, contract_id)?;

        let case = harness::verification_case(&contract, &symbol, &generated, settings);
        let result = verifier.verify(&case, &artifact.path, &artifact.sha256)?;
        provenance = Some(verifier.provenance(&artifact.path, &artifact.sha256));

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

    let provenance = provenance.unwrap_or_else(|| verifier.provenance(Path::new("<none>"), ""));
    Ok(library_report::build(entries, provenance, contracts.len()))
}

/// A contract identity as a directory name. Identities are Rust paths, already
/// validated by `harness::split_contract`, so this only replaces separators.
fn sanitize(contract: &str) -> String {
    contract.replace("::", "-")
}
