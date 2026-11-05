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
pub mod coverage;
pub mod coverage_report;
pub mod dynamic;
pub mod dynamic_harness;
pub mod enforcement;
pub mod evidence;
pub mod experiment;
pub mod explore;
pub mod generate;
pub mod harness;
pub mod inventory;
pub mod library_report;
pub mod memcheck;
pub mod native;
pub mod native_report;
pub mod orchestration;
pub mod parser;
pub mod report;
pub mod reproducer;
pub mod runner;
pub mod schedule;
pub mod screen;
pub mod security;
pub mod symbolic;
pub mod symbolic_report;
pub mod taint;
pub mod toolchain;
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
use harness::{Artifact, Backend, Harness, HarnessError, Library, ResolvedSymbol, Workspace};
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
        // Everything decidable about the contract is decided before the
        // analyzer is touched, so a problem with the contract is reported as a
        // problem with the contract. See this function's own notes.
        let staged = stage_symbolic(
            library,
            contract_id,
            settings,
            workspace,
            Backend::Standalone,
        )?;

        // Prepared here, not earlier: everything above is a question about the
        // contract and the library, and a missing analyzer must not answer any
        // of them.
        if verifier.is_none() {
            let mut prepared = symbolic::Verifier::prepare_with(runtime)?;
            prepared.check_image()?;
            verifier = Some(prepared);
        }
        let verifier = verifier.as_ref().expect("prepared just above");
        entries.push(verify_staged(staged, verifier, library)?);
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

/// Everything one contract's symbolic verification needs, assembled before the
/// analyzer is involved.
///
/// Split out so a unified run can tell a *per-contract* failure -- an
/// unsupported signature, a harness that will not compile, a symbol that does
/// not resolve -- from a *shared infrastructure* failure, which is the missing
/// analyzer image. The first becomes one contract's status; the second applies
/// to every symbolic requirement in the run. Before the split both arrived as
/// the same `HarnessError` from the same call.
pub struct StagedSymbolic {
    contract: contract::Contract,
    case: VerificationCase,
    symbol: ResolvedSymbol,
    harness: Harness,
    artifact: Artifact,
}

impl StagedSymbolic {
    /// The executable this staging built, which is the artifact any result
    /// drawn from it describes.
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact.sha256
    }
}

/// Builds one contract's symbolic verification artifact, touching no analyzer.
///
/// The per-contract execution seam M10 needs: `verify` and the unified run
/// reach the symbolic backend through this and [`verify_staged`], so there is
/// one implementation of what symbolic verification *is* and the two commands
/// cannot drift apart.
fn stage_symbolic(
    library: &Library,
    contract_id: &str,
    settings: &contract::ContractSettings,
    workspace: &Workspace,
    backend: Backend,
) -> Result<StagedSymbolic, HarnessError> {
    let (work_dir, target_dir) = workspace.directories_for_backend(contract_id, backend)?;

    let contract = harness::probe_contract(library, contract_id, &work_dir, &target_dir)?;
    // Checked after the descriptor is known, so the message can name the
    // declared secrets rather than guess at them.
    settings.validate_inputs(contract_id, &contract.descriptor)?;

    let harness: Harness = harness::generate(library, &contract)?;
    let artifact: Artifact =
        harness::build(library, &harness, contract_id, &work_dir, &target_dir)?;
    let symbol: ResolvedSymbol = harness::resolve_symbol(&artifact.path, contract_id)?;
    let case = harness::verification_case(&contract, &symbol, &harness, settings);

    Ok(StagedSymbolic {
        contract,
        case,
        symbol,
        harness,
        artifact,
    })
}

/// Runs the analyzer over a staged contract.
fn verify_staged(
    staged: StagedSymbolic,
    verifier: &symbolic::Verifier,
    library: &Library,
) -> Result<Verified, HarnessError> {
    let StagedSymbolic {
        contract,
        case,
        symbol,
        harness,
        artifact,
    } = staged;
    let result = verifier.verify(&case, &artifact.path, &artifact.sha256)?;
    Ok(Verified {
        contract,
        case,
        library: library.clone(),
        symbol,
        harness,
        artifact,
        result,
    })
}

use check::{CheckBudget, Runner as CheckRunner};
use check_report::{
    CheckProvenance, CheckReport, ContractEntry, CorpusSummary, DiscoveryEvidence, SecretSummary,
};
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
    /// Turn M7 coverage-guided exploration on or off for every selected
    /// contract.
    pub explore: Option<bool>,
    /// Mutation candidates per contract.
    pub explore_cases: Option<usize>,
    /// Cap on cases handed to the security backend.
    pub security_cases: Option<usize>,
}

#[derive(Debug)]
pub enum CheckRunError {
    Harness(HarnessError),
    Dynamic(DynamicError),
    Generate(GenerateError),
    Native(NativeError),
    Reproducer(ReproducerError),
    Coverage(coverage::CoverageError),
    Explore(explore::ExploreError),
    Inventory(InventoryError),
    /// A contract was asked for that the inventory does not declare.
    NotDeclared {
        requested: Vec<String>,
        available: Vec<String>,
        variant: String,
    },
    /// The inventory's descriptor and the probed one disagree.
    DescriptorDrift {
        contract: String,
    },
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
            CheckRunError::Coverage(error) => write!(f, "{error}"),
            CheckRunError::Explore(error) => write!(f, "{error}"),
            CheckRunError::Inventory(error) => write!(f, "{error}"),
            CheckRunError::NotDeclared {
                requested,
                available,
                variant,
            } => write!(
                f,
                "{} is not declared in {variant}. The compiler-derived inventory of this build \
                 declares: {}",
                requested
                    .iter()
                    .map(|name| format!("`{name}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
                if available.is_empty() {
                    "(none)".to_string()
                } else {
                    available.join(", ")
                }
            ),
            CheckRunError::DescriptorDrift { contract } => write!(
                f,
                "`{contract}`'s inventory record and its compiled descriptor disagree, so the \
                 artifact the inventory describes is not the artifact about to be analyzed. \
                 Rebuild and retry"
            ),
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
impl From<coverage::CoverageError> for CheckRunError {
    fn from(error: coverage::CoverageError) -> Self {
        CheckRunError::Coverage(error)
    }
}
impl From<explore::ExploreError> for CheckRunError {
    fn from(error: explore::ExploreError) -> Self {
        CheckRunError::Explore(error)
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
///
/// The LLVM coverage tools are located the same way and for the same reason,
/// one step earlier than Valgrind: a contract that cannot be explored usually
/// cannot be analyzed either, and the annotation is what a developer should
/// hear about.
///
/// # Where exploration fits
///
/// When a contract enables it, exploration runs **between** corpus generation
/// and analysis. It builds its own instrumented artifact, searches for inputs,
/// selects a bounded corpus, and hands that corpus back. Everything downstream
/// — secret marking, calibration, the binding control, batching, isolation,
/// shrinking, classification, the CI policy — is M6's, unchanged, and cannot
/// tell an explored case from a boundary case.
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
    let mut tools: Option<coverage::LlvmTools> = None;
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
        if let Some(explore) = overrides.explore {
            settings.explore.enabled = explore;
        }
        if let Some(candidates) = overrides.explore_cases {
            settings.explore.candidate_budget = candidates;
            // Naming a candidate budget is asking for exploration. Requiring
            // both flags would make `--explore-cases 2000` silently do nothing.
            if overrides.explore.is_none() {
                settings.explore.enabled = true;
            }
        }
        if let Some(cases) = overrides.security_cases {
            settings.explore.security_case_budget = cases;
        }
        // An override can make a configured entry invalid, so the result is
        // re-validated rather than trusted because the file was valid.
        settings
            .validate(contract_id)
            .map_err(HarnessError::Contract)?;

        let (work_dir, target_dir) = workspace.directories_for(contract_id)?;
        let contract = harness::probe_contract(library, contract_id, &work_dir, &target_dir)?;
        let generated = dynamic_harness::generate(&contract)?;
        let baseline =
            generate::generate(contract_id, &contract.descriptor, &settings.generation())?;

        // Exploration, when the contract asks for it. It may only *replace the
        // corpus*: the artifact built below, the controls, and every downstream
        // stage are the same whether it ran or not.
        let (corpus, discovery) = if settings.explore.enabled {
            if tools.is_none() {
                tools = Some(coverage::LlvmTools::locate(Some(&library.toolchain))?);
            }
            let tools = tools.as_ref().expect("located just above");
            let (corpus, evidence) = explore_contract(
                library,
                &contract,
                &baseline,
                tools,
                &settings,
                &work_dir,
                &target_dir,
            )?;
            (corpus, Some(evidence))
        } else {
            (baseline, None)
        };

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
            settings.expectation(),
            settings.expected_outcome.as_deref(),
            &outcome,
            discovery.as_ref(),
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
            expectation: settings.expectation(),
            expected_outcome: settings.expected_outcome.clone(),
            policy,
            policy_detail,
            check: outcome,
            reproducers,
            discovery,
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

/// Explores one contract and returns the corpus the security backend should run.
///
/// # The architectural boundary
///
/// This function owns the instrumented artifact and everything coverage means.
/// What it returns is a [`generate::Corpus`] — M6's own type, carrying inputs
/// and nothing else — plus evidence *about the search*, which the report keeps
/// in its own section. The caller cannot accidentally let a region count
/// influence a security conclusion, because no region count crosses back.
///
/// # Why the discovery artifact is built per contract
///
/// For the reason M5 builds one symbolic artifact per contract: the generated
/// harness calls one function, and anything its `main` does not reach is dead
/// code the compiler is free to drop. A shared multi-contract discovery binary
/// would have a coverage map whose records depend on which other contracts were
/// selected, which would make a region identity depend on the command line.
fn explore_contract(
    library: &Library,
    contract: &contract::Contract,
    baseline: &generate::Corpus,
    tools: &coverage::LlvmTools,
    settings: &contract::CheckSettings,
    work_dir: &Path,
    target_dir: &Path,
) -> Result<(generate::Corpus, DiscoveryEvidence), CheckRunError> {
    let harness = dynamic_harness::generate_discovery(contract)?;
    let artifact = dynamic_harness::build(library, &harness, &contract.id, work_dir, target_dir)?;
    let collector = coverage::Collector::new(
        tools,
        &artifact.path,
        &artifact.sha256,
        Path::new(&library.manifest_path),
        &contract.module,
        &contract.function,
        native::Limits::default(),
    );
    let explore_settings = settings.explore.settings(settings.seed);
    let exploration = explore::explore(
        &contract.id,
        &contract.descriptor,
        baseline,
        &collector,
        &explore_settings,
        work_dir,
    )?;
    let selection = explore::select(&exploration, explore_settings.security_case_budget);
    let corpus =
        explore::security_corpus(&contract.id, &contract.descriptor, &exploration, &selection)?;

    let evidence = DiscoveryEvidence {
        artifact_sha256: artifact.sha256.clone(),
        profile: dynamic_harness::HarnessKind::Discovery
            .profile()
            .to_string(),
        instrumentation: dynamic_harness::INSTRUMENT_FLAG.to_string(),
        harness_sha256: harness.source_sha256.clone(),
        marked_bytes: harness.marked_bytes,
        llvm_tools: tools.version.clone(),
        feedback: exploration.feedback.clone(),
        granularity: exploration.granularity.clone(),
        coverage_map_id: exploration.coverage_map.id.clone(),
        scope: exploration.scope.clone(),
        seed: exploration.seed,
        candidate_budget: exploration.candidate_budget,
        baseline_cases: exploration.baseline_cases,
        candidates_attempted: exploration.candidates_attempted,
        candidates_observed: exploration.candidates_observed,
        baseline_observed: exploration.baseline_observed,
        candidates_retained: exploration.candidates_retained,
        rounds: exploration.rounds,
        baseline_regions: exploration.baseline_regions,
        regions_reached: exploration.regions_reached,
        regions_added: exploration.regions_added(),
        mutation_mix: exploration.mutation_mix.clone(),
        termination: exploration.termination.as_str().to_string(),
        termination_detail: exploration
            .incompleteness()
            .unwrap_or_else(|| exploration.termination.describe()),
        elapsed_ms: exploration.elapsed_ms,
        time_limit_ms: exploration.time_limit_ms,
        overran_time_limit: exploration.overran_time_limit,
        failures: exploration
            .failures
            .iter()
            .map(|failure| format!("case {}: {}", failure.case_id, failure.status))
            .collect(),
        selected_provenance: explore::provenance(&exploration, &selection),
        selection,
    };
    Ok((corpus, evidence))
}

use coverage_report::CoverageReport;
use enforcement::{Analysis, AnalysisEvidence, Available, Coverage, Plan, Status};
use inventory::{ContractInventory, InventoryError};

/// How `check` chose its contracts.
///
/// The two `--all-*` forms cover different things and are kept apart on
/// purpose: `--all-configured` means every explicitly configured generated
/// check, and `--all-contracts` means every declaration the compiler put in the
/// inventory. Reinterpreting the first as the second would silently change what
/// an existing CI job enforces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Every declaration in the inventory.
    AllContracts,
    /// Every contract with a `[check."..."]` entry. M6's meaning, unchanged.
    AllConfigured,
    /// Exactly these.
    Named(Vec<String>),
}

impl Selection {
    pub fn describe(&self) -> &'static str {
        match self {
            Selection::AllContracts => "--all-contracts (every declaration in the inventory)",
            Selection::AllConfigured => "--all-configured (every configured generated check)",
            Selection::Named(_) => "--contract (named explicitly)",
        }
    }
}

impl From<InventoryError> for CheckRunError {
    fn from(error: InventoryError) -> Self {
        CheckRunError::Inventory(error)
    }
}

/// Enforces every applicable contract and reports the coverage matrix.
///
/// # Order of operations
///
/// 1. Build the **inventory**, which decides what exists. Nothing else can be
///    decided first: a selection, a policy and a backend probe are all about
///    contracts, and the set of contracts is what the inventory establishes.
/// 2. Resolve the **plan**, before any heavyweight backend runs, so an
///    unsupported signature, a missing analyzer, an unconfigured symbolic
///    requirement and an unselected contract are all reported up front.
/// 3. Run the analyses the plan still leaves outstanding.
/// 4. Fold the evidence in, where a detected leak overrides anything.
///
/// Valgrind is located lazily, after the inventory and the plan, for the same
/// reason M5 and M6 settled on: a developer whose contract cannot be analyzed
/// should be told about the contract, not about a missing analyzer.
/// Everything a unified enforcement run was asked for.
///
/// Grouped rather than passed positionally. Ten parameters, three of them
/// `Option`, is a signature a caller gets subtly wrong -- and the next
/// milestone package adds more. The CLI's own `CheckRequest` groups its options
/// for the same reason.
pub struct CoverageRequest<'a> {
    pub library: &'a Library,
    pub config: &'a VerifyConfig,
    pub workspace: &'a Workspace,
    pub overrides: &'a CheckOverrides,
    pub selection: &'a Selection,
    pub reproducer_dir: Option<&'a Path>,
    /// Today, for expiring waivers. Passed in so a run is reproducible and a
    /// test can describe any date.
    pub today: &'a str,
    /// Container runtime for the analyzer. `None` selects whichever holds the
    /// pinned image.
    pub runtime: Option<&'a str>,
    /// Developer-written `#[ct_test]` results, when the caller collected them.
    pub dynamic_runs: Option<&'a DynamicRuns>,
    /// How many jobs of each backend may run at once.
    pub limits: schedule::Limits,
}

pub fn run_contract_coverage(
    request: CoverageRequest<'_>,
) -> Result<CoverageReport, CheckRunError> {
    let CoverageRequest {
        library,
        config,
        workspace,
        overrides,
        selection,
        reproducer_dir,
        today,
        runtime,
        dynamic_runs,
        limits,
    } = request;
    let policy = &config.policy;
    let inventory_dir = workspace.inventory_target_dir()?;
    let found = inventory::build_and_read(library, &inventory_dir)?;

    let selected: Vec<String> = match selection {
        Selection::AllContracts => found.contracts.iter().map(|c| c.id.clone()).collect(),
        Selection::AllConfigured => config
            .checked_contracts()
            .iter()
            .map(|c| c.to_string())
            .collect(),
        Selection::Named(names) => names.clone(),
    };

    // A named selection may contain something the inventory does not have.
    // Reported as its own failure rather than quietly dropped, because "that
    // contract does not exist in this build" is exactly what a developer with
    // a typo needs to hear.
    let unknown: Vec<String> = selected
        .iter()
        .filter(|id| found.contract(id).is_none())
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(CheckRunError::NotDeclared {
            requested: unknown,
            available: found.ids().iter().map(|id| id.to_string()).collect(),
            variant: found.build.variant(),
        });
    }

    // Which backends this run can use. Probed once, before the plan, so the
    // plan can settle a missing one rather than failing halfway through.
    let valgrind = native::prepare_valgrind().ok();
    // Exploration can be asked for two ways, and both have to be counted.
    // An earlier revision looked only at the *policy*, so a contract whose
    // `[check."...".explore] enabled = true` asked for coverage-guided
    // discovery had its tools left unlocated and fell back to the baseline
    // corpus -- silently, which turned a configured search into no search and
    // reported NO_LEAK_OBSERVED on the two fixtures that need one.
    let needs_explore = found.contracts.iter().any(|declaration| {
        policy
            .required_for(&declaration.id)
            .contains(&Analysis::Explore)
            || {
                let mut settings = config.check_settings(&declaration.id);
                apply_overrides(&mut settings, overrides);
                settings.explore.enabled
            }
    });
    let tools = if needs_explore {
        // A hard error, as in `run_generated_checks`: a run asked to explore
        // that cannot explore must fail rather than quietly analyze a
        // different corpus.
        Some(coverage::LlvmTools::locate(Some(&library.toolchain))?)
    } else {
        None
    };
    // The analyzer, prepared once for the whole run and only if some policy
    // asks for it. A failure is carried rather than returned: it settles every
    // symbolic requirement as BACKEND_UNAVAILABLE, which is a status, while the
    // generated analyses still run and still report. A missing backend must
    // never abort the analyses that do work, and must never be substituted for.
    let symbolic_backend =
        needs_symbolic(&found, policy).then(|| prepare_symbolic_backend(runtime));
    let available = check_capabilities(
        valgrind.is_some(),
        tools.is_some(),
        symbolic_backend.as_ref().is_some_and(Result::is_ok),
        dynamic_runs.is_some(),
    );

    let plan = Plan::resolve(&found, config, policy, &selected, &available, today);
    let mut coverage = Coverage::from_plan(&plan, &found);

    // What will actually run, decided before any artifact is compiled. Four
    // named analyses are not four invocations: `generated` and `explore` share
    // one Memcheck workflow, and `dynamic` is one pass over a test suite
    // rather than a per-contract job. Deciding it here, as a value, is what
    // makes "requiring both must not run two Memcheck analyses" a property
    // something can check.
    let execution = orchestration::ExecutionPlan::resolve(&plan, &|contract| {
        let mut settings = config.check_settings(contract);
        apply_overrides(&mut settings, overrides);
        settings.explore.enabled
    });

    // Stage two: run what the plan left outstanding. The generated family is
    // executed here and symbolic verification in stage three; `dynamic`
    // evidence is a developer-written `#[ct_test]` that
    // `cargo trace-check test` produces, and a requirement for it is reported
    // as outstanding rather than silently satisfied.
    let generated_jobs: Vec<&orchestration::Job> = execution
        .jobs
        .iter()
        .filter(|job| matches!(job.work, orchestration::Work::Generated { .. }))
        .collect();
    // Run concurrently, fold sequentially. Each job writes into a fixed slot
    // and the slots are drained in plan order, so the report is identical
    // whatever the worker count and whatever order the backends finished in.
    let analysed_jobs = schedule::in_order(&generated_jobs, limits.generated, |_, job| {
        let orchestration::Work::Generated { explore } = job.work else {
            unreachable!("filtered to the generated family above");
        };
        let Some((valgrind_path, valgrind_version)) = &valgrind else {
            return None;
        };
        let declaration = found
            .contract(&job.contract)
            .expect("planned from the inventory");

        let mut settings = config.check_settings(&job.contract);
        apply_overrides(&mut settings, overrides);
        // The plan already decided this, from the policy and the
        // configuration together. Taking it from the plan rather than
        // re-deriving it here is the point: one place decides what runs.
        settings.explore.enabled = explore;
        if let Err(error) = settings.validate(&job.contract) {
            return Some(Err(CheckRunError::Harness(HarnessError::Contract(error))));
        }

        // A failure analysing one contract becomes that contract's status, not
        // the end of the run. An earlier revision propagated it, so a single
        // private annotated function -- inventoried correctly, but not
        // reachable from an external probe harness -- abandoned the whole
        // enforcement run: no report, no status for the contract that caused
        // it, and every other declaration left unchecked. M8's whole claim is
        // that every declaration gets an explicit status, which an aborted run
        // cannot deliver.
        //
        // Errors that are not about *this contract* -- a missing analyzer, a
        // broken inventory -- are still propagated, because they would recur
        // identically for every contract and reporting them 18 times is not
        // more useful than reporting them once.
        Some(analyse_one(
            library,
            workspace,
            declaration,
            &settings,
            valgrind_path,
            valgrind_version,
            tools.as_ref(),
            reproducer_dir,
        ))
    });

    for (job, outcome) in generated_jobs.iter().zip(analysed_jobs) {
        let Some(outcome) = outcome else {
            // No Valgrind: the plan's requirements were already settled as
            // BACKEND_UNAVAILABLE, and nothing ran.
            continue;
        };
        let analysed = match outcome {
            Ok(analysed) => analysed,
            Err(error) if per_contract(&error) => {
                for analysis in &job.discharges {
                    coverage.note(
                        &job.contract,
                        *analysis,
                        Status::Unsupported {
                            reason: error.to_string(),
                        },
                    );
                }
                continue;
            }
            Err(error) => return Err(error),
        };
        // One execution, folded against every obligation it discharges. Each
        // record names the others, so two requirements met by one Memcheck
        // workflow cannot be read as two independent observations.
        for analysis in &job.discharges {
            coverage.fold(
                &job.contract,
                fold_analysis(*analysis, &analysed, &job.discharges),
            );
        }
    }

    // Stage three: symbolic verification, through the same per-contract
    // implementation `verify` uses. A separate stage rather than a branch
    // inside stage two, because it builds a different executable from a
    // different generated harness with different flags -- the artifact
    // identities must stay apart, and nothing here may read the generated
    // result.
    if let Some(Ok(verifier)) = &symbolic_backend {
        let identity = verifier.identity();
        let symbolic_jobs: Vec<&orchestration::Job> = execution
            .jobs
            .iter()
            .filter(|job| job.work == orchestration::Work::Symbolic)
            .collect();
        // Concurrent, then folded in plan order, for the same reason stage two
        // is. The analyzer is prepared once and shared: it is immutable after
        // preparation, and its identity describes the analyzer rather than any
        // one artifact.
        let verified_jobs = schedule::in_order(&symbolic_jobs, limits.symbolic, |_, job| {
            // Outstanding implies configured: `settle` reports a symbolic
            // requirement with no `[verify]` entry as a configuration gap,
            // which is settled and so never reaches here.
            let settings = config
                .settings(&job.contract)
                .expect("an outstanding symbolic requirement implies a [verify] entry");

            // Staging is per contract and touches no analyzer, so most of its
            // failures are facts about this declaration -- an unsupported
            // signature, a harness that will not compile, a symbol that does
            // not resolve -- and become this contract's status rather than the
            // end of the run.
            //
            // Anything else is recorded as INCONCLUSIVE rather than propagated.
            // Stage two aborts the run on a failure that is not about one
            // contract, which is defensible when nothing has been established
            // yet; by here the generated evidence is already in hand, and
            // throwing it away to report an error that is also in the report
            // would lose more than it tells anyone. Neither status can pass.
            let staged = match stage_symbolic(
                library,
                &job.contract,
                settings,
                workspace,
                Backend::Symbolic,
            ) {
                Ok(staged) => staged,
                Err(error) => {
                    let reason = format!(
                        "the symbolic verification artifact for `{}` could not be prepared: \
                         {error}",
                        job.contract
                    );
                    return Err(if per_contract(&CheckRunError::Harness(error)) {
                        Status::Unsupported { reason }
                    } else {
                        Status::Inconclusive { detail: reason }
                    });
                }
            };
            // Recorded before the analyzer runs. The obligation is about the
            // executable this run built, and the evidence is checked against
            // that rather than against whatever the result claims.
            let built = evidence::ArtifactIdentity::symbolic(
                &job.contract,
                &staged.contract.descriptor_json,
                library,
                &staged.artifact,
                &staged.harness.source_sha256,
                &identity,
            );
            match verify_staged(staged, verifier, library) {
                Ok(verified) => {
                    let report = library_report::contract_report(verified, workspace.is_kept());
                    Ok(AnalysisEvidence::from_symbolic(
                        &settings.checks,
                        built,
                        Box::new(report),
                    ))
                }
                Err(error) => Err(Status::Inconclusive {
                    detail: format!(
                        "the analyzer did not produce a usable result for `{}`: {error}",
                        job.contract
                    ),
                }),
            }
        });

        for (job, outcome) in symbolic_jobs.iter().zip(verified_jobs) {
            match outcome {
                Ok(evidence) => coverage.fold(&job.contract, evidence),
                Err(status) => coverage.note(&job.contract, Analysis::Symbolic, status),
            }
        }
    }

    // Stage four: developer-written `#[ct_test]` evidence, discovered and
    // executed by the caller and bound to the inventory here. The binding is
    // where the security decision is: a test that ran is not evidence about a
    // contract unless it provably invoked it.
    if let Some(runs) = dynamic_runs {
        let binding = dynamic::bind(&runs.runs, &found);
        // Reported whenever runs were supplied, *not* only when some contract
        // still owes a `dynamic` answer. A test naming a contract this build
        // does not declare is a mistake about the test suite rather than about
        // any one obligation -- gating it on an outstanding requirement hid it
        // whenever the only contract asking for `dynamic` was already settled.
        report_unresolved_targets(&mut coverage, &binding);
        // Folded whenever runs were supplied, for the same reason: the tests
        // have already executed, and whether some contract still *owes* a
        // dynamic answer decides which results get a status -- never which
        // get kept. Gating this on the job existing discarded a leak found by
        // a test whose own contract required nothing dynamic.
        fold_dynamic(
            &mut coverage,
            execution.dynamic.as_ref(),
            &found,
            library,
            runs,
            &binding,
        );
    }

    let provenance = coverage_report::Provenance {
        rustc_version: library.toolchain.rustc_version.clone(),
        cargo_version: library.toolchain.cargo_version.clone(),
        target: symbolic::SUPPORTED_TARGET.to_string(),
        library_package: library.package.clone(),
        library_version: library.version.clone(),
        library_manifest: library.manifest_path.clone(),
        features: found.build.features.clone(),
    };
    Ok(coverage_report::build(
        provenance,
        &found,
        &coverage,
        policy,
        selected,
        selection.describe(),
        Some(execution),
    ))
}

/// Everything the caller discovered and executed for the `dynamic` analysis.
///
/// Passed in rather than produced here: discovering `#[ct_test]`s means
/// building Cargo test binaries and running them under Valgrind, which lives in
/// the CLI. What this crate owns is the part a security decision depends on —
/// binding them to the compiler-derived inventory, and refusing to count one
/// that establishes nothing.
pub struct DynamicRuns {
    pub runs: Vec<dynamic::DynamicTestRun>,
    /// Compilation settings of the test binaries, for the artifact identity.
    pub profile: String,
    /// `sha256` of the library's dependency lockfile, which decides the code
    /// compiled into those binaries.
    pub lockfile_sha256: String,
    /// What Valgrind reports about itself.
    pub valgrind_version: String,
}

/// Reports a `#[ct_test]` whose target names no contract in this build, or
/// more than one.
///
/// Such a test binds to nothing, which is already fail-closed -- the obligation
/// stays un-analyzed and strict CI fails -- but silently so, and "failed
/// without saying why" is the shape of problem this milestone exists to remove.
///
/// Reported where configuration that matches no declaration is reported,
/// because it is the same class of mistake: something names a contract this
/// build does not have. The CLI's `resolve_targets` rejects these up front, so
/// reaching here means the inventory and the test binaries' own metadata
/// disagree -- which a developer must hear about.
fn report_unresolved_targets(coverage: &mut Coverage, binding: &dynamic::Binding) {
    for detail in &binding.unresolved {
        coverage.stale.push(enforcement::StaleEntry {
            contract: detail.split('`').nth(1).unwrap_or_default().to_string(),
            source: "ct_test",
            detail: detail.clone(),
        });
    }
}

/// Folds one aggregate per contract that has a bound test.
///
/// `job` names the contracts that *owe* a dynamic answer, and is `None` when
/// none does. Either way that is not the same set as the contracts which
/// *have* an answer: `dynamic` is a whole test
/// suite rather than a per-contract job, so a policy requiring it of one
/// contract makes the run execute every targeted `#[ct_test]`, including tests
/// bound to contracts that require nothing dynamic.
///
/// Those tests have *already run*. Discarding a leak one of them found, because
/// nobody asked for the analysis, would erase positive leakage evidence -- and
/// no arrangement of obligations may do that.
fn fold_dynamic(
    coverage: &mut Coverage,
    job: Option<&orchestration::DynamicJob>,
    found: &ContractInventory,
    library: &Library,
    runs: &DynamicRuns,
    binding: &dynamic::Binding,
) {
    // Empty when no contract owes a dynamic answer, which is a reason for
    // every result to be supplemental -- not a reason to drop them.
    let required: std::collections::BTreeSet<&str> = job
        .map(|job| job.contracts.iter().map(String::as_str).collect())
        .unwrap_or_default();
    for (contract, tests) in &binding.per_contract {
        let Some(declaration) = found.contract(contract) else {
            continue;
        };
        // A contract with no bound test keeps the `NOT_ANALYZED` status it
        // already has: saying so here would be the same thing twice, and
        // silently folding a clean result would be the failure this milestone
        // exists to prevent. Such a contract is simply absent from `binding`.
        let Some(aggregate) = dynamic::aggregate(tests) else {
            continue;
        };
        let identity = evidence::ArtifactIdentity::developer_test(
            contract,
            &declaration.descriptor_json,
            library,
            &dynamic::artifact_sha256(&aggregate.executables),
            &runs.lockfile_sha256,
            &runs.profile,
            &runs.valgrind_version,
        );
        let evidence = AnalysisEvidence::from_dynamic(identity, aggregate);
        if required.contains(contract.as_str()) {
            coverage.fold(contract, evidence);
        } else {
            // No obligation to discharge, so no status is written: recording
            // CHECKED would claim the contract was held to something it never
            // was. The evidence is kept, and `violated()` reads evidence as
            // well as statuses, so a leak still fails the contract.
            coverage.fold_supplemental(contract, evidence);
        }
    }
}

/// Resolves the policy and reports the matrix **without running anything**.
///
/// The read-only half of `run_contract_coverage`, for `cargo trace-check
/// coverage`. It answers "what is required, and what is outstanding?" — which
/// is a different question from "enforce it now", and the one a developer
/// adopting the tool asks first.
///
/// Every requirement comes back as `NOT_ANALYZED` unless the plan already
/// settled it, so an exemption, an unsupported signature and a missing backend
/// are all visible here at no analysis cost.
pub fn report_contract_coverage(
    library: &Library,
    config: &VerifyConfig,
    workspace: &Workspace,
    selection: &Selection,
    today: &str,
    runtime: Option<&str>,
) -> Result<CoverageReport, CheckRunError> {
    let policy = &config.policy;
    let found = read_contract_inventory(library, workspace)?;
    let selected: Vec<String> = match selection {
        Selection::AllContracts => found.contracts.iter().map(|c| c.id.clone()).collect(),
        Selection::AllConfigured => config
            .checked_contracts()
            .iter()
            .map(|c| c.to_string())
            .collect(),
        Selection::Named(names) => names.clone(),
    };
    // Backends are probed, because "the analyzer is missing" is part of the
    // answer to "what is outstanding".
    let valgrind = native::prepare_valgrind().is_ok();
    let available = check_capabilities(
        valgrind,
        coverage::LlvmTools::locate(Some(&library.toolchain)).is_ok(),
        needs_symbolic(&found, policy) && prepare_symbolic_backend(runtime).is_ok(),
        // `coverage` runs nothing, so it never performs the dynamic analysis.
        false,
    );
    let plan = Plan::resolve(&found, config, policy, &selected, &available, today);
    let coverage = Coverage::from_plan(&plan, &found);
    let provenance = coverage_report::Provenance {
        rustc_version: native::tool_version(Path::new("rustc"), &["--version"])
            .unwrap_or_else(|_| "rustc (version unavailable)".to_string()),
        cargo_version: native::tool_version(Path::new("cargo"), &["--version"])
            .unwrap_or_else(|_| "cargo (version unavailable)".to_string()),
        target: symbolic::SUPPORTED_TARGET.to_string(),
        library_package: library.package.clone(),
        library_version: library.version.clone(),
        library_manifest: library.manifest_path.clone(),
        features: found.build.features.clone(),
    };
    Ok(coverage_report::build(
        provenance,
        &found,
        &coverage,
        policy,
        selected,
        selection.describe(),
        // `coverage` runs nothing, so there is no execution to report.
        None,
    ))
}

/// Builds the inventory alone, for `list --contracts`.
pub fn read_contract_inventory(
    library: &Library,
    workspace: &Workspace,
) -> Result<ContractInventory, CheckRunError> {
    let target = workspace.inventory_target_dir()?;
    Ok(inventory::build_and_read(library, &target)?)
}

/// What the unified `check --all-contracts` can do, as distinct from what this
/// machine has.
///
/// It performs the generated family *and* symbolic verification. `dynamic`
/// evidence is a developer-written `#[ct_test]`, which `cargo trace-check test`
/// produces, so a requirement for it is reported as un-analyzed *and told where
/// to get it* rather than as a missing analyzer -- a claim about the command,
/// not about the machine.
///
/// `symbolic` used to be in that same category. It is not any more: this
/// command runs it, so a missing analyzer image is now honestly
/// BACKEND_UNAVAILABLE, and nothing else is allowed to stand in for it.
fn check_capabilities(valgrind: bool, tools: bool, symbolic: bool, dynamic: bool) -> Available {
    let mut elsewhere = std::collections::BTreeMap::new();
    let mut performs = vec![Analysis::Generated, Analysis::Explore, Analysis::Symbolic];
    if dynamic {
        performs.push(Analysis::Dynamic);
    } else {
        // Not something this invocation does, which is a claim about the
        // command and not about the machine. See `Available::performs`.
        elsewhere.insert(Analysis::Dynamic, "cargo trace-check test".to_string());
    }
    Available {
        generated: valgrind,
        explore: valgrind && tools,
        symbolic,
        dynamic: valgrind && dynamic,
        performs,
        elsewhere,
    }
}

/// Whether any declaration's policy asks for symbolic verification.
///
/// The analyzer is prepared only when the answer is yes. A project requiring
/// nothing symbolic must not need a container runtime to run `check`, and
/// probing for one it will never use would make a missing image visible in a
/// report that has no symbolic obligation to report it against.
fn needs_symbolic(found: &ContractInventory, policy: &enforcement::PolicyConfig) -> bool {
    found.contracts.iter().any(|declaration| {
        policy
            .required_for(&declaration.id)
            .contains(&Analysis::Symbolic)
    })
}

/// Prepares the one analyzer the whole run shares, or says why it cannot.
///
/// One prepared verifier per run, reused across contracts: its identity is the
/// analyzer's, which is shared, while the artifact identities are per contract
/// and stay on each result. Preparing it once also means a missing image is
/// diagnosed once rather than per contract.
fn prepare_symbolic_backend(runtime: Option<&str>) -> Result<symbolic::Verifier, String> {
    let mut verifier = symbolic::Verifier::prepare_with(runtime).map_err(|e| e.to_string())?;
    verifier.check_image().map_err(|e| e.to_string())?;
    Ok(verifier)
}

/// What analysing one contract produced.
struct Analysed {
    outcome: security::Outcome,
    message: String,
    /// What decides which executable this result describes, including its
    /// hash. Nothing carries the hash separately: two fields for one value is
    /// two chances for them to disagree.
    artifact: evidence::ArtifactIdentity,
    /// Why requested exploration did not complete, when it did not.
    ///
    /// `Some` downgrades an otherwise-clean outcome for **every** requirement,
    /// not just an `explore` one. See `fold_analysis`.
    explore_incomplete: Option<String>,
    /// The generated check's whole result, kept so the report can show finding
    /// stacks, isolation, shrinking, controls and case counts rather than one
    /// sentence about them.
    check: check::ContractCheck,
    /// Exploration evidence, when exploration ran.
    discovery: Option<DiscoveryEvidence>,
    /// Reproducers written for this contract's findings.
    reproducers: Vec<String>,
}

/// Whether a failure is about one contract rather than about the run.
///
/// A contract whose descriptor cannot be read, whose harness cannot be
/// generated, or whose harness will not compile is a fact about that
/// declaration: the usual cause is a signature the generator cannot model or a
/// function an external probe cannot reach. Those become that contract's
/// status. A missing analyzer or an unreadable inventory is a fact about the
/// run and would recur identically for every contract, so it still aborts.
fn per_contract(error: &CheckRunError) -> bool {
    matches!(
        error,
        CheckRunError::Harness(harness::HarnessError::Contract(_))
            | CheckRunError::Harness(harness::HarnessError::Build { .. })
            | CheckRunError::Harness(harness::HarnessError::SymbolMissing { .. })
            | CheckRunError::Harness(harness::HarnessError::SymbolAmbiguous { .. })
            | CheckRunError::Dynamic(dynamic_harness::DynamicError::Contract(_))
            | CheckRunError::Dynamic(dynamic_harness::DynamicError::Build { .. })
            | CheckRunError::Generate(_)
            | CheckRunError::DescriptorDrift { .. }
    )
}

/// One analysis's evidence from a completed run of one contract.
///
/// # Incomplete exploration downgrades every requirement
///
/// If exploration was requested and did not finish, a clean outcome becomes
/// `INCONCLUSIVE` for whatever requirement it was about -- not only for an
/// `explore` obligation. An earlier revision checked that flag solely when
/// folding `Analysis::Explore`, so a contract whose policy required only
/// `generated` while its configuration enabled exploration could have its
/// search die early, fold a clean generated outcome, and pass strict CI. That
/// is a regression from M7, where an incomplete required exploration turned
/// satisfied into incomplete.
///
/// A detected leak is never downgraded. A finding from the security artifact
/// does not depend on how its input was chosen, so it stands whatever the
/// search did.
fn fold_analysis(
    analysis: Analysis,
    analysed: &Analysed,
    discharges: &[Analysis],
) -> AnalysisEvidence {
    let leaked = analysed.outcome == security::Outcome::LeakDetected;
    let (outcome, detail) = match &analysed.explore_incomplete {
        _ if leaked => (analysed.outcome, analysed.message.clone()),
        Some(reason) => (
            security::Outcome::Inconclusive,
            format!(
                "coverage-guided exploration was requested and did not complete, so the inputs \
                 this result describes are not the inputs the run was configured to search \
                 for: {reason}. The security analysis itself was: {}",
                analysed.message
            ),
        ),
        None => (analysed.outcome, analysed.message.clone()),
    };
    AnalysisEvidence::from_generated(
        analysis,
        outcome,
        analysed.artifact.clone(),
        &detail,
        analysed.check.clone(),
        analysed.discovery.clone(),
        analysed.reproducers.clone(),
        // The other obligations this same Memcheck workflow answered, so the
        // two records cannot be read as two independent observations.
        discharges
            .iter()
            .copied()
            .filter(|other| *other != analysis)
            .collect(),
    )
}

fn apply_overrides(settings: &mut contract::CheckSettings, overrides: &CheckOverrides) {
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
    if let Some(explore) = overrides.explore {
        settings.explore.enabled = explore;
    }
    if let Some(candidates) = overrides.explore_cases {
        settings.explore.candidate_budget = candidates;
        if overrides.explore.is_none() {
            settings.explore.enabled = true;
        }
    }
    if let Some(cases) = overrides.security_cases {
        settings.explore.security_case_budget = cases;
    }
}

/// Runs the generated (and optionally coverage-guided) check for one contract.
///
/// Deliberately the same pipeline `run_generated_checks` uses, reached through
/// the same functions: M8 changes which contracts are analyzed, not how.
#[allow(clippy::too_many_arguments)]
fn analyse_one(
    library: &Library,
    workspace: &Workspace,
    declaration: &inventory::ContractDeclaration,
    settings: &contract::CheckSettings,
    valgrind: &Path,
    // What Valgrind reports about itself, for the artifact identity: the
    // backend is part of what a result depends on.
    valgrind_version: &str,
    tools: Option<&coverage::LlvmTools>,
    reproducer_dir: Option<&Path>,
) -> Result<Analysed, CheckRunError> {
    let (work_dir, target_dir) = workspace.directories_for(&declaration.id)?;
    let contract = harness::probe_contract(library, &declaration.id, &work_dir, &target_dir)?;
    // The inventory record and the probed descriptor must agree. They come
    // from the same macro expansion, so a difference means the artifact the
    // inventory was read from is not the artifact about to be analyzed.
    if contract.descriptor != declaration.descriptor {
        return Err(CheckRunError::DescriptorDrift {
            contract: declaration.id.clone(),
        });
    }
    let generated = dynamic_harness::generate(&contract)?;
    let baseline = generate::generate(
        &declaration.id,
        &contract.descriptor,
        &settings.generation(),
    )?;

    let mut explore_incomplete = None;
    let mut discovery = None;
    let corpus = if settings.explore.enabled {
        // Unreachable by construction -- the caller locates the tools when any
        // contract asks for exploration -- and an error rather than a silent
        // fallback, because falling back analyzes a corpus nobody asked for.
        let tools = tools.ok_or_else(|| {
            CheckRunError::Explore(explore::ExploreError::Io(format!(
                "`{}` is configured to explore but the LLVM coverage tools were not located",
                declaration.id
            )))
        })?;
        let (corpus, evidence) = explore_contract(
            library,
            &contract,
            &baseline,
            tools,
            settings,
            &work_dir,
            &target_dir,
        )?;
        if !evidence.complete() {
            explore_incomplete = Some(evidence.termination_detail.clone());
        }
        discovery = Some(evidence);
        corpus
    } else {
        baseline
    };

    let corpus_path = dynamic_harness::stage_corpus(&corpus, &work_dir)?;
    let artifact =
        dynamic_harness::build(library, &generated, &declaration.id, &work_dir, &target_dir)?;
    let mut runner = CheckRunner::new(
        valgrind,
        &artifact.path,
        corpus_path,
        work_dir.clone(),
        native::Limits::default(),
    );
    let outcome = check::check_contract(
        &mut runner,
        &contract,
        &corpus,
        &generated.secret_parameters,
        generated.marked_bytes,
        &settings.budget(),
    )?;
    let mut reproducers = Vec::new();
    if let Some(directory) = reproducer_dir {
        for (index, finding) in outcome.findings.iter().enumerate() {
            let record = Reproducer::from_finding(
                &declaration.id,
                &corpus,
                finding,
                library,
                &artifact.sha256,
                dynamic_harness::PROFILE,
            );
            let path = directory.join(format!(
                "{}-{index}.json",
                declaration.id.replace("::", "-")
            ));
            record.save(&path)?;
            reproducers.push(path.display().to_string());
        }
    }
    Ok(Analysed {
        outcome: outcome.outcome,
        message: outcome.message.clone(),
        artifact: evidence::ArtifactIdentity::generated(
            &declaration.id,
            &contract.descriptor_json,
            library,
            &artifact,
            &generated.source_sha256,
            valgrind_version,
        ),
        explore_incomplete,
        check: outcome,
        discovery,
        reproducers,
    })
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

#[cfg(test)]
mod fold_tests {
    use super::*;

    fn analysed(outcome: security::Outcome, explore_incomplete: Option<&str>) -> Analysed {
        Analysed {
            outcome,
            message: "the security analysis said this".to_string(),
            artifact: evidence::sample_identity("crypto::a::probe", "artifact"),
            explore_incomplete: explore_incomplete.map(str::to_string),
            check: check::ContractCheck {
                contract: "crypto::a::probe".to_string(),
                function: "probe".to_string(),
                secret_parameters: vec!["key".to_string()],
                marked_bytes: 1,
                outcome,
                message: "the security analysis said this".to_string(),
                calibration: check::Control::Confirmed,
                binding: check::Control::Confirmed,
                cases_planned: 64,
                cases_executed: 64,
                cases_completed: 64,
                analyzer_runs: 2,
                findings: Vec::new(),
                unattributed: Vec::new(),
                other_diagnostics: Vec::new(),
            },
            discovery: None,
            reproducers: vec!["/tmp/a-0.json".to_string()],
        }
    }

    /// An incomplete exploration downgrades a clean result for **every**
    /// requirement, not only an `explore` one.
    ///
    /// The regression this pins: with `default_required = ["generated"]` and
    /// exploration enabled in `[check]`, a search that died early folded a
    /// clean generated outcome and passed strict CI. M7 downgraded a satisfied
    /// result when required exploration was incomplete, and M8 must not undo
    /// that.
    #[test]
    fn an_incomplete_exploration_downgrades_a_clean_generated_result() {
        let evidence = fold_analysis(
            Analysis::Generated,
            &analysed(
                security::Outcome::NoLeakObserved,
                Some("the wall-clock limit was reached"),
            ),
            &[Analysis::Generated],
        );
        assert_eq!(evidence.outcome, security::Outcome::Inconclusive);
        assert!(
            evidence.detail.contains("did not complete"),
            "{}",
            evidence.detail
        );
        assert!(
            evidence.detail.contains("wall-clock"),
            "{}",
            evidence.detail
        );
        // The security analysis's own words are kept, so the report says what
        // was observed as well as why it is not enough.
        assert!(
            evidence.detail.contains("the security analysis said this"),
            "{}",
            evidence.detail
        );
    }

    /// A detected leak is never downgraded by an incomplete search: a finding
    /// does not depend on how its input was chosen.
    #[test]
    fn an_incomplete_exploration_never_downgrades_a_leak() {
        let evidence = fold_analysis(
            Analysis::Generated,
            &analysed(security::Outcome::LeakDetected, Some("it died early")),
            &[Analysis::Generated],
        );
        assert_eq!(evidence.outcome, security::Outcome::LeakDetected);
        assert_eq!(evidence.detail, "the security analysis said this");
    }

    /// A complete exploration leaves the outcome alone.
    #[test]
    fn a_complete_exploration_does_not_downgrade_anything() {
        for analysis in [Analysis::Generated, Analysis::Explore] {
            let evidence = fold_analysis(
                analysis,
                &analysed(security::Outcome::NoLeakObserved, None),
                &[Analysis::Generated, Analysis::Explore],
            );
            assert_eq!(evidence.outcome, security::Outcome::NoLeakObserved);
            assert_eq!(evidence.detail, "the security analysis said this");
        }
    }

    /// The backend's own evidence rides along, so a report can show findings,
    /// controls, case counts and reproducers rather than a sentence about them.
    #[test]
    fn the_backends_evidence_is_preserved() {
        let evidence = fold_analysis(
            Analysis::Generated,
            &analysed(security::Outcome::NoLeakObserved, None),
            &[Analysis::Generated],
        );
        let check = evidence.check.expect("the generated result is attached");
        assert_eq!(check.cases_completed, 64);
        assert_eq!(check.analyzer_runs, 2);
        assert_eq!(check.calibration, check::Control::Confirmed);
        assert_eq!(check.binding, check::Control::Confirmed);
        assert_eq!(evidence.reproducers, vec!["/tmp/a-0.json".to_string()]);
    }
}
