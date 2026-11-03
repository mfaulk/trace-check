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
pub mod check;
pub mod check_report;
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
pub mod reproducer;
pub mod runner;
pub mod screen;
pub mod security;
pub mod symbolic;
pub mod symbolic_report;
pub mod taint;
pub mod wasm;

#[cfg(test)]
mod testwat;

use std::path::{Path, PathBuf};

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

use check::{CheckBudget, Runner as CheckRunner};
use check_report::{CheckProvenance, CheckReport, ContractEntry, CorpusSummary, SecretSummary};
use dynamic_harness::DynamicError;
use generate::GenerateError;
use reproducer::{Reproducer, ReproducerError};

/// Command-line overrides for a contract's configured generation settings.
///
/// Each is `None` when the flag was absent, so a configured value is only ever
/// replaced deliberately rather than by a default that looks like a choice.
#[derive(Debug, Clone, Default)]
pub struct CheckOverrides {
    pub cases: Option<usize>,
    pub seed: Option<u64>,
    pub batch_size: Option<usize>,
    pub shrink: Option<bool>,
}

#[derive(Debug)]
pub enum CheckRunError {
    Harness(HarnessError),
    Dynamic(DynamicError),
    Generate(GenerateError),
    Native(NativeError),
    Reproducer(ReproducerError),
    /// No contract was selected at all.
    NothingSelected {
        available: Vec<String>,
    },
}

impl std::fmt::Display for CheckRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckRunError::Harness(error) => write!(f, "{error}"),
            CheckRunError::Dynamic(error) => write!(f, "{error}"),
            CheckRunError::Generate(error) => write!(f, "{error}"),
            CheckRunError::Native(error) => write!(f, "{error}"),
            CheckRunError::Reproducer(error) => write!(f, "{error}"),
            CheckRunError::NothingSelected { available } => write!(
                f,
                "no contracts selected; pass --contract <identity> or --all-configured. \
                 {} configures: {}",
                contract::CONFIG_FILE,
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            ),
        }
    }
}

impl std::error::Error for CheckRunError {}

impl From<HarnessError> for CheckRunError {
    fn from(error: HarnessError) -> Self {
        CheckRunError::Harness(error)
    }
}
impl From<DynamicError> for CheckRunError {
    fn from(error: DynamicError) -> Self {
        CheckRunError::Dynamic(error)
    }
}
impl From<GenerateError> for CheckRunError {
    fn from(error: GenerateError) -> Self {
        CheckRunError::Generate(error)
    }
}
impl From<NativeError> for CheckRunError {
    fn from(error: NativeError) -> Self {
        CheckRunError::Native(error)
    }
}
impl From<ReproducerError> for CheckRunError {
    fn from(error: ReproducerError) -> Self {
        CheckRunError::Reproducer(error)
    }
}

/// Runs generated constant-time testing for the selected contracts.
///
/// # Order of operations
///
/// Valgrind is located **lazily**, immediately before the first run that needs
/// it. Everything decidable without it is decided first: the selection, then
/// each contract's annotation, parameter shapes, generated corpus and compiled
/// harness. This is the same ordering M5 settled on, for the same reason — a
/// developer with a misspelled contract name or an unsupported parameter type
/// should be told about *that*, not about a missing analyzer.
pub fn run_generated_checks(
    library: &Library,
    config: &VerifyConfig,
    contracts: &[String],
    workspace: &Workspace,
    overrides: &CheckOverrides,
    reproducer_dir: Option<&Path>,
    require_all_configured: bool,
) -> Result<CheckReport, CheckRunError> {
    if contracts.is_empty() {
        return Err(CheckRunError::NothingSelected {
            available: config
                .checked_contracts()
                .iter()
                .map(|c| c.to_string())
                .collect(),
        });
    }

    let mut valgrind: Option<(PathBuf, String)> = None;
    let mut entries = Vec::new();

    for contract_id in contracts {
        let mut settings = config.check_settings(contract_id);
        if let Some(cases) = overrides.cases {
            settings.cases = cases;
        }
        if let Some(seed) = overrides.seed {
            settings.seed = seed;
        }
        if let Some(batch_size) = overrides.batch_size {
            settings.batch_size = batch_size;
        }
        if let Some(shrink) = overrides.shrink {
            settings.shrink = shrink;
        }
        // An override can make a configured entry invalid, so the result is
        // re-validated rather than trusted because the file was valid.
        settings
            .validate(contract_id)
            .map_err(HarnessError::Contract)?;

        let (work_dir, target_dir) = workspace.directories_for(contract_id)?;
        let contract = harness::probe_contract(library, contract_id, &work_dir, &target_dir)?;
        let generated = dynamic_harness::generate(&contract)?;
        let corpus = generate::generate(contract_id, &contract.descriptor, &settings.generation())?;
        let corpus_path = dynamic_harness::stage_corpus(&corpus, &work_dir)?;
        let artifact =
            dynamic_harness::build(library, &generated, contract_id, &work_dir, &target_dir)?;

        // Located here, not earlier: everything above is a question about the
        // contract and the library, and a missing analyzer must not answer any
        // of them.
        if valgrind.is_none() {
            valgrind = Some(native::prepare_valgrind()?);
        }
        let (valgrind_path, _) = valgrind.as_ref().expect("located just above");

        let mut runner = CheckRunner::new(
            valgrind_path,
            &artifact.path,
            corpus_path,
            work_dir.clone(),
            native::Limits::default(),
        );
        let budget: CheckBudget = settings.budget();
        let outcome = check::check_contract(
            &mut runner,
            &contract,
            &corpus,
            &generated.secret_parameters,
            generated.marked_bytes,
            &budget,
        )?;

        // Reproducers, one per finding, written only when a directory was named.
        let mut reproducers = Vec::new();
        if let Some(directory) = reproducer_dir {
            for (index, finding) in outcome.findings.iter().enumerate() {
                let record = Reproducer::from_finding(
                    contract_id,
                    &corpus,
                    finding,
                    library,
                    &artifact.sha256,
                    dynamic_harness::PROFILE,
                );
                let path =
                    directory.join(format!("{}-{index}.json", contract_id.replace("::", "-")));
                record.save(&path)?;
                reproducers.push(path.display().to_string());
            }
        }

        let secrets: Vec<SecretSummary> = contract
            .descriptor
            .secrets()
            .map(|parameter| SecretSummary {
                parameter: parameter.name.clone(),
                rust_type: parameter.rust_type.clone(),
                bytes: parameter.repr.bytes().unwrap_or(0),
            })
            .collect();
        let (policy, policy_detail) = ContractEntry::evaluate(
            settings.expectation,
            settings.expected_outcome.as_deref(),
            &outcome,
        );
        entries.push(ContractEntry {
            contract: contract_id.clone(),
            function: contract.function.clone(),
            site: contract.site.clone(),
            secrets,
            corpus: CorpusSummary::of(&corpus),
            harness_sha256: generated.source_sha256.clone(),
            artifact_sha256: artifact.sha256.clone(),
            lockfile_sha256: artifact.lockfile_sha256.clone(),
            expectation: settings.expectation,
            expected_outcome: settings.expected_outcome.clone(),
            policy,
            policy_detail,
            check: outcome,
            reproducers,
        });
    }

    let analyzer = match &valgrind {
        Some((_, version)) => format!("valgrind {version}"),
        None => "valgrind (not located)".to_string(),
    };
    let provenance = CheckProvenance {
        rustc_version: native::tool_version(Path::new("rustc"), &["--version"])
            .unwrap_or_else(|_| "rustc (version unavailable)".to_string()),
        cargo_version: native::tool_version(Path::new("cargo"), &["--version"])
            .unwrap_or_else(|_| "cargo (version unavailable)".to_string()),
        analyzer,
        target: symbolic::SUPPORTED_TARGET.to_string(),
        profile: dynamic_harness::PROFILE.to_string(),
        library_package: library.package.clone(),
        library_version: library.version.clone(),
        library_manifest: library.manifest_path.clone(),
    };

    let selected: Vec<String> = contracts.to_vec();
    let not_selected: Vec<String> = config
        .checked_contracts()
        .into_iter()
        .filter(|configured| !contracts.iter().any(|chosen| chosen == configured))
        .map(|configured| configured.to_string())
        .collect();

    Ok(check_report::build(
        provenance,
        selected,
        not_selected,
        entries,
        require_all_configured,
    ))
}

/// Replays a persisted reproducer against a freshly built artifact.
///
/// The artifact hash is compared with the recorded one and the difference is
/// reported rather than hidden: replaying after a change answers whether the
/// leak survived it, which is a different question from whether the original
/// observation still holds.
///
/// # Fail-closed
///
/// `NOT_REPRODUCED` is only ever returned when a complete, instrumented,
/// calibrated run establishes the recorded finding's absence. An earlier
/// revision derived "did not reproduce" from the mere absence of a matching
/// diagnostic, so malformed analyzer output, an inert harness or a failed
/// control all looked like a fixed vulnerability — and with a rebuilt artifact
/// that exited 0. Everything that is not positive evidence either way is
/// `INCONCLUSIVE`.
pub fn replay_reproducer(
    library: &Library,
    record: &Reproducer,
    workspace: &Workspace,
) -> Result<reproducer::ReplayResult, CheckRunError> {
    use reproducer::Verdict;

    let contract_id = &record.contract;
    let (work_dir, target_dir) = workspace.directories_for(contract_id)?;
    let contract = harness::probe_contract(library, contract_id, &work_dir, &target_dir)?;
    let generated = dynamic_harness::generate(&contract)?;

    // Verbatim, not generated: ordinary generation deduplicates by input value,
    // which collapses a sequence-dependent reproducer's repeated calls into one
    // and makes it unreproducible by construction. Per-case validation against
    // the contract still happens, so a recorded value cannot be bound to the
    // wrong width.
    let corpus = generate::verbatim(contract_id, &contract.descriptor, &record.as_regressions())?;
    let corpus_path = dynamic_harness::stage_corpus(&corpus, &work_dir)?;
    let artifact =
        dynamic_harness::build(library, &generated, contract_id, &work_dir, &target_dir)?;

    let (valgrind_path, _version) = native::prepare_valgrind()?;
    let ids: Vec<usize> = corpus.cases.iter().map(|case| case.id).collect();
    let run = dynamic_harness::run_batch(
        &valgrind_path,
        &artifact.path,
        &corpus_path,
        Some(&ids),
        native::Limits::default(),
    )?;

    let wanted = record.finding.to_fingerprint();
    let found = check::run_reproduces(&run, &contract.function, &wanted);

    // The same gates `check_contract` applies, in the same order. A replay that
    // skipped them would be a second, weaker definition of a trustworthy run.
    let invalid = if !run.instrumented {
        Some(
            "the harness did not report running under Valgrind, so secret marking was inert"
                .to_string(),
        )
    } else if let Some(detail) = &run.parse_error {
        Some(format!("Memcheck output could not be parsed: {detail}"))
    } else if let Some(detail) = run.incompleteness() {
        Some(detail)
    } else {
        let parsed = run.run.as_ref().expect("parse_error was checked above");
        if !check::control_fired(parsed, check::ControlKind::Calibration) {
            Some(
                "the positive control produced no diagnostic, so secret marking is not reaching \
                 compiled code in this binary"
                    .to_string(),
            )
        } else if !check::control_fired(parsed, check::ControlKind::SecretBinding) {
            Some(
                "the binding control produced no diagnostic, so the marked bytes never reached \
                 the function as undefined"
                    .to_string(),
            )
        } else if parsed.non_secret_errors().next().is_some() {
            Some(
                "Memcheck reported diagnostics that are not secret dependency; resolve those \
                 before trusting a replay"
                    .to_string(),
            )
        } else {
            None
        }
    };

    // A finding that *did* appear is positive evidence and stands even when
    // something else about the run is unsatisfying -- a leak cannot be
    // un-observed. Its absence is only meaningful if the run was sound.
    let (verdict, detail) = match (found, invalid) {
        (true, _) => (Verdict::Reproduced, None),
        (false, None) => (Verdict::NotReproduced, None),
        (false, Some(detail)) => (Verdict::Inconclusive, Some(detail)),
    };
    Ok(reproducer::ReplayResult::new(
        record,
        &artifact.sha256,
        verdict,
        detail,
    ))
}
