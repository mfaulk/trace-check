//! `cargo trace-check test` — run constant-time checks under Valgrind Memcheck.
//!
//! Cargo invokes an external subcommand as `cargo-trace-check trace-check …`,
//! so the first argument is the subcommand name and has to be dropped. Running
//! the binary directly also works, which is what the integration tests do.

mod discover;
mod report;
mod run;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};

use trace_check::contract::{self, VerifyConfig};
use trace_check::harness::{Library, Workspace};
use trace_check::native::{self, Limits};
use trace_check::security::Provenance;
use trace_check::symbolic::CaseFile;

#[derive(Parser)]
#[command(
    name = "cargo-trace-check",
    about = "Run constant-time checks as ordinary Rust tests",
    long_about = "Builds this package's tests with optimization and debug symbols, discovers \
                  #[ct_test] functions and #[constant_time] contracts, and runs each check in \
                  its own process under Valgrind Memcheck.\n\n\
                  A passing check means no modeled secret-dependent behavior was observed on \
                  the paths the test exercised. It is not a proof of constant-time behavior."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build, discover and run the constant-time checks.
    Test {
        /// Run only tests whose name contains this substring.
        #[arg(long)]
        filter: Option<String>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        /// Package manifest to build, if not the one in the current directory.
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Build profile. Defaults to `memcheck`, falling back to optimized
        /// release with debug symbols when the package does not define it.
        #[arg(long)]
        profile: Option<String>,
        /// Cargo features to enable, passed through to the build.
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        /// Per-test wall-clock limit. Memcheck costs roughly an order of
        /// magnitude in runtime.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_output_bytes: usize,
    },
    /// Search for a secret assignment that leaks, using bounded relational
    /// symbolic execution over an optimized native artifact.
    ///
    /// Unlike `test`, this does not run inputs you chose: it searches a declared
    /// domain. When exploration completes it reports VERIFIED_BOUNDED, which is
    /// a different and stronger claim than the dynamic backend's
    /// NO_LEAK_OBSERVED.
    Verify {
        /// Verify a declared `#[constant_time]` contract in a real library, by
        /// its qualified identity, e.g. `crypto::tag::verify_tag`. Repeatable.
        #[arg(long, conflicts_with_all = ["case", "cases"])]
        contract: Vec<String>,
        /// Verify every contract configured in trace-check.toml.
        #[arg(long, conflicts_with_all = ["case", "cases"])]
        all_contracts: bool,
        /// Library manifest to verify contracts from. Defaults to
        /// ./Cargo.toml.
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Verification configuration. Defaults to trace-check.toml beside the
        /// manifest.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Cargo features to enable for the library's verification build.
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        /// Keep the generated harnesses and analyzed executables under this
        /// directory instead of a private one that is removed after the run.
        ///
        /// Each run still gets a freshly created directory inside it, so
        /// nothing pre-existing is written through and two runs never share
        /// one.
        #[arg(long)]
        artifact_dir: Option<PathBuf>,
        /// Run only this bundled standalone case (M4).
        #[arg(long)]
        case: Option<String>,
        /// Bundled case file. Defaults to examples/symbolic/cases.json.
        #[arg(long)]
        cases: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        #[arg(long)]
        workspace_root: Option<PathBuf>,
        /// Container runtime to run the analyzer in. Defaults to whichever of
        /// podman or docker holds the pinned image.
        #[arg(long, value_parser = ["podman", "docker"])]
        container_runtime: Option<String>,
    },
    /// Generate inputs for declared contracts and check them for
    /// secret-dependent control flow and memory addressing.
    ///
    /// Unlike `test`, this needs no hand-written `#[ct_test]`: the annotation
    /// already says which parameters are secret and the signature supplies
    /// their types. Unlike `verify`, it needs no container -- it reuses the
    /// Valgrind backend and so reaches `std` libraries.
    ///
    /// A clean result is NO_LEAK_OBSERVED over the inputs that were generated.
    /// It is not a proof.
    Check {
        /// Check a declared `#[constant_time]` contract by its qualified
        /// identity, e.g. `crypto::lookup::substitute_mode`. Repeatable.
        #[arg(long, conflicts_with = "replay")]
        contract: Vec<String>,
        /// Check every contract with a [check."..."] entry in trace-check.toml.
        ///
        /// Deliberately not called --all-contracts: it covers what the
        /// configuration names, not every annotation in the source tree.
        #[arg(long, conflicts_with = "replay")]
        all_configured: bool,
        /// Library manifest to check contracts from. Defaults to ./Cargo.toml.
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        /// Configuration file. Defaults to trace-check.toml beside the
        /// manifest. Optional: a contract with no entry is checked on defaults.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Cargo features to enable for the library build.
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        /// Case budget per contract, overriding the configuration.
        #[arg(long)]
        cases: Option<usize>,
        /// Generation seed, overriding the configuration. The same seed and
        /// budget reproduce the same corpus.
        #[arg(long)]
        seed: Option<u64>,
        /// Cases per Valgrind process, overriding the configuration.
        #[arg(long)]
        batch_size: Option<usize>,
        /// Search for inputs with coverage feedback before analyzing.
        ///
        /// Builds a second, instrumented artifact and uses the regions each
        /// candidate reaches to decide which inputs are worth analyzing. Needs
        /// the toolchain's LLVM tools: `rustup component add llvm-tools`.
        ///
        /// Coverage guides the search. It establishes nothing: every security
        /// conclusion still comes from the uninstrumented Memcheck artifact.
        #[arg(long, conflicts_with = "replay")]
        explore: bool,
        /// Mutation candidates per contract. Implies --explore.
        #[arg(long, conflicts_with = "replay")]
        explore_cases: Option<usize>,
        /// Cap on cases handed to Memcheck. Separate from --explore-cases
        /// because exploring is cheap and analyzing is not.
        #[arg(long, conflicts_with = "replay")]
        security_cases: Option<usize>,
        /// Skip input reduction after a finding is isolated.
        #[arg(long)]
        no_shrink: bool,
        /// Write a replayable reproducer per finding into this directory.
        #[arg(long)]
        reproducer_dir: Option<PathBuf>,
        /// Replay a saved reproducer instead of generating inputs.
        #[arg(long)]
        replay: Option<PathBuf>,
        /// Require that every configured contract was checked, so a CI job
        /// cannot report success for a subset it happened to select.
        #[arg(long)]
        ci: bool,
        /// Keep the generated harnesses and analyzed executables under this
        /// directory instead of a private one removed after the run.
        #[arg(long)]
        artifact_dir: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// List the discovered checks and contracts without running them.
    List {
        #[arg(long)]
        manifest_path: Option<PathBuf>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    // Drop the subcommand name Cargo inserts.
    let args: Vec<String> = std::env::args()
        .enumerate()
        .filter(|(index, arg)| !(*index == 1 && arg == "trace-check"))
        .map(|(_, arg)| arg)
        .collect();

    match execute(Cli::parse_from(args)) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(report::EXIT_INCOMPLETE)
        }
    }
}

fn execute(cli: Cli) -> Result<u8, String> {
    match cli.command {
        Command::Test {
            filter,
            format,
            manifest_path,
            profile,
            features,
            timeout_secs,
            max_output_bytes,
        } => test(
            filter.as_deref(),
            format,
            manifest_path.as_deref(),
            profile.as_deref(),
            &features,
            Limits {
                timeout: Duration::from_secs(timeout_secs),
                max_output_bytes,
            },
        ),
        Command::List {
            manifest_path,
            profile,
            features,
            format,
        } => list(
            manifest_path.as_deref(),
            profile.as_deref(),
            &features,
            format,
        ),
        Command::Check {
            contract,
            all_configured,
            manifest_path,
            config,
            features,
            cases,
            seed,
            batch_size,
            no_shrink,
            explore,
            explore_cases,
            security_cases,
            reproducer_dir,
            replay,
            ci,
            artifact_dir,
            format,
        } => check(CheckRequest {
            selected: contract,
            all_configured,
            manifest_path,
            config_path: config,
            features,
            overrides: trace_check::CheckOverrides {
                cases,
                seed,
                batch_size,
                // Absent unless the flag was passed, so a configured `shrink`
                // is only ever overridden deliberately.
                shrink: if no_shrink { Some(false) } else { None },
                // `--explore` turns exploration on; its absence leaves the
                // configuration alone rather than turning it off, so a
                // contract that enabled it in trace-check.toml keeps it.
                explore: if explore { Some(true) } else { None },
                explore_cases,
                security_cases,
            },
            reproducer_dir,
            replay,
            ci,
            artifact_dir,
            format,
        }),
        Command::Verify {
            contract,
            all_contracts,
            manifest_path,
            config,
            features,
            artifact_dir,
            case,
            cases,
            format,
            workspace_root,
            container_runtime,
        } => {
            if !contract.is_empty() || all_contracts {
                verify_contracts(
                    &contract,
                    all_contracts,
                    manifest_path.as_deref(),
                    config.as_deref(),
                    &features,
                    artifact_dir.as_deref(),
                    format,
                    container_runtime.as_deref(),
                )
            } else {
                // `--manifest-path`, `--config`, `--features` and
                // `--artifact-dir` select or describe a library, which only
                // contract verification uses. Accepting them silently here
                // would look like they had an effect.
                if manifest_path.is_some()
                    || config.is_some()
                    || !features.is_empty()
                    || artifact_dir.is_some()
                {
                    return Err(
                        "--manifest-path, --config, --features and --artifact-dir apply to \
                         contract verification; pass --contract <identity> or --all-contracts"
                            .to_string(),
                    );
                }
                verify(
                    case.as_deref(),
                    cases.as_deref(),
                    format,
                    workspace_root.as_deref(),
                    container_runtime.as_deref(),
                )
            }
        }
    }
}

/// Everything `check` was asked for, grouped so the subcommand's options travel
/// as one value rather than eleven positional arguments.
struct CheckRequest {
    selected: Vec<String>,
    all_configured: bool,
    manifest_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    features: Vec<String>,
    overrides: trace_check::CheckOverrides,
    reproducer_dir: Option<PathBuf>,
    replay: Option<PathBuf>,
    ci: bool,
    artifact_dir: Option<PathBuf>,
    format: Format,
}

/// Generated constant-time checking, and replay.
fn check(request: CheckRequest) -> Result<u8, String> {
    let CheckRequest {
        selected,
        all_configured,
        manifest_path,
        config_path,
        features,
        overrides,
        reproducer_dir,
        replay,
        ci,
        artifact_dir,
        format,
    } = request;
    let manifest = manifest_path.unwrap_or_else(|| PathBuf::from("Cargo.toml"));
    if !manifest.is_file() {
        return Err(format!(
            "{} is not a file; pass --manifest-path to name the library to check",
            manifest.display()
        ));
    }
    let library = Library::resolve(&manifest, &features).map_err(|e| e.to_string())?;
    let workspace = match &artifact_dir {
        Some(directory) => Workspace::kept_in(directory),
        None => Workspace::ephemeral(),
    }
    .map_err(|e| e.to_string())?;

    // Replay answers a different question and needs no configuration: the
    // reproducer carries the contract, the inputs and the artifact it was found
    // against.
    if let Some(path) = &replay {
        let record = trace_check::reproducer::Reproducer::load(path).map_err(|e| e.to_string())?;
        let result = trace_check::replay_reproducer(&library, &record, &workspace)
            .map_err(|e| e.to_string())?;
        match format {
            Format::Json => println!(
                "{}",
                serde_json::to_string_pretty(&result).expect("a replay result is serializable")
            ),
            Format::Text => {
                println!("Replaying {}", record.contract);
                println!("  inputs:   {}", record.describe());
                println!("  finding:  {:?}", record.finding.classification);
                println!(
                    "  artifact: recorded {}, replayed {}",
                    short(&result.recorded_artifact_sha256),
                    short(&result.replayed_artifact_sha256)
                );
                println!("  {}", result.verdict.as_str());
                println!("  {}", result.message);
            }
        }
        // A finding that is still there fails; a run that established nothing
        // is incomplete, never a pass.
        return Ok(match result.verdict {
            trace_check::reproducer::Verdict::Reproduced => report::EXIT_LEAK,
            trace_check::reproducer::Verdict::NotReproduced if result.same_artifact => {
                report::EXIT_INCOMPLETE
            }
            trace_check::reproducer::Verdict::NotReproduced => report::EXIT_OK,
            trace_check::reproducer::Verdict::Inconclusive => report::EXIT_INCOMPLETE,
        });
    }

    // The configuration is optional: a contract with no entry is checked on
    // defaults. It is only required to resolve --all-configured.
    let config_path = config_path.unwrap_or_else(|| {
        manifest
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(contract::CONFIG_FILE)
    });
    let config = if config_path.is_file() {
        VerifyConfig::load(&config_path).map_err(|e| e.to_string())?
    } else if all_configured {
        return Err(format!(
            "{} does not exist, so there is no configuration to enumerate; pass --contract \
             <identity> instead",
            config_path.display()
        ));
    } else {
        VerifyConfig::empty()
    };

    let contracts: Vec<String> = if all_configured {
        config
            .checked_contracts()
            .iter()
            .map(|c| c.to_string())
            .collect()
    } else {
        selected
    };

    let report = trace_check::run_generated_checks(
        &library,
        &config,
        &contracts,
        &workspace,
        &overrides,
        reproducer_dir.as_deref(),
        ci,
    )
    .map_err(|e| e.to_string())?;

    match format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", report.to_json()),
    }
    Ok(report.exit_code())
}

/// First twelve characters of a hash, for human-readable output.
fn short(hash: &str) -> String {
    hash.chars().take(12).collect()
}

fn test(
    filter: Option<&str>,
    format: Format,
    manifest_path: Option<&std::path::Path>,
    profile: Option<&str>,
    features: &[String],
    limits: Limits,
) -> Result<u8, String> {
    // Validate the platform and the backend before building anything, so a
    // missing Valgrind is an immediate, clear failure.
    let (valgrind, valgrind_version) = native::prepare_valgrind().map_err(|e| e.to_string())?;

    let (binaries, used_profile) = discover::build_test_binaries(manifest_path, profile, features)
        .map_err(|e| e.to_string())?;
    let discovery = discover::discover(&binaries, &used_profile).map_err(|e| e.to_string())?;

    // An unknown or ambiguous target is an error before anything runs: a test
    // that names a contract which does not exist claims coverage of nothing.
    report::resolve_targets(&discovery.tests, &discovery.contracts)?;

    let selected: Vec<_> = discovery
        .tests
        .iter()
        .filter(|test| filter.is_none_or(|needle| test.name.contains(needle)))
        .cloned()
        .collect();

    let mut outcomes = Vec::new();
    for record in &selected {
        let outcome = run::run_test(&valgrind, record, limits).map_err(|e| e.to_string())?;
        outcomes.push(outcome);
    }

    let provenance = provenance(&discovery, &used_profile, &valgrind_version, &selected);
    let report = report::build(
        &discovery,
        selected.len(),
        outcomes,
        provenance,
        filter.is_some(),
    );

    match format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", report.to_json()),
    }
    Ok(report.exit_code())
}

/// Resolves the repository root, preferring an explicit flag.
///
/// The compile-time manifest directory is the fallback so `cargo trace-check
/// verify` works from anywhere inside the repository.
fn resolve_workspace_root(override_path: Option<&Path>) -> Result<PathBuf, String> {
    let root = match override_path {
        Some(path) => path.to_path_buf(),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .ok_or("cannot derive the repository root; pass --workspace-root")?
            .to_path_buf(),
    };
    if !root.join("Cargo.toml").is_file() {
        return Err(format!(
            "{} does not look like the repository root (no Cargo.toml); pass --workspace-root",
            root.display()
        ));
    }
    Ok(root)
}

/// Searches for a secret assignment that leaks, rather than running chosen
/// inputs.
fn verify(
    case_filter: Option<&str>,
    cases_override: Option<&Path>,
    format: Format,
    workspace_root_override: Option<&Path>,
    container_runtime: Option<&str>,
) -> Result<u8, String> {
    let root = resolve_workspace_root(workspace_root_override)?;
    let cases_path = cases_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("examples/symbolic/cases.json"));
    let case_dir = cases_path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", cases_path.display()))?
        .to_path_buf();

    let case_file = CaseFile::load(&cases_path).map_err(|e| e.to_string())?;
    let selected: Vec<_> = match case_filter {
        None => case_file.cases.clone(),
        Some(wanted) => vec![case_file
            .case(wanted)
            .ok_or_else(|| {
                format!(
                    "no verification case {wanted:?} in {}; available: {}",
                    cases_path.display(),
                    case_file
                        .cases
                        .iter()
                        .map(|case| case.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?
            .clone()],
    };

    // A private directory created atomically, not a path derived from the
    // process id: a guessable name under a world-writable /tmp can be
    // pre-created or symlinked, and the build writes an executable into it.
    // The artifact's hash, not its path, is what a report is pinned to, so
    // removing the directory afterwards costs nothing.
    let out_dir = tempfile::Builder::new()
        .prefix("trace-check-symbolic-build-")
        .tempdir()
        .map_err(|e| format!("cannot create a private build directory: {e}"))?;
    let report = trace_check::run_symbolic(
        &case_file,
        &case_dir,
        &selected,
        out_dir.path(),
        container_runtime,
    )
    .map_err(|e| e.to_string())?;

    match format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", report.to_json()),
    }
    Ok(report.exit_code())
}

/// Verifies declared contracts against the real functions in a Cargo library.
///
/// This is M5's path: the analyzed function is compiled from the developer's
/// own source, not from a verification-specific copy of the algorithm.
///
/// Validation is ordered so that everything decidable from the command line and
/// the configuration happens **before** the container backend is touched: a
/// misspelled contract name must report the typo, not a missing analyzer image.
#[allow(clippy::too_many_arguments)]
fn verify_contracts(
    selected: &[String],
    all_contracts: bool,
    manifest_path: Option<&Path>,
    config_path: Option<&Path>,
    features: &[String],
    artifact_dir: Option<&Path>,
    format: Format,
    container_runtime: Option<&str>,
) -> Result<u8, String> {
    let manifest = manifest_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("Cargo.toml"));
    if !manifest.is_file() {
        return Err(format!(
            "{} is not a file; pass --manifest-path to name the library to verify",
            manifest.display()
        ));
    }

    // Derived from the manifest's directory rather than from resolved package
    // metadata, so locating and validating the configuration needs neither
    // Cargo nor the analyzer.
    let config_path = config_path.map(Path::to_path_buf).unwrap_or_else(|| {
        manifest
            .parent()
            .unwrap_or(Path::new("."))
            .join(contract::CONFIG_FILE)
    });
    if !config_path.is_file() {
        return Err(format!(
            "{} does not exist. Contract verification needs per-contract bounds and an \
             observation model, which cannot be inferred from the annotation; create it or \
             pass --config",
            config_path.display()
        ));
    }
    let config = VerifyConfig::load(&config_path).map_err(|e| e.to_string())?;

    let contracts: Vec<String> = if all_contracts {
        config.contracts().iter().map(|c| c.to_string()).collect()
    } else {
        selected.to_vec()
    };
    config
        .require_configured(&contracts)
        .map_err(|e| e.to_string())?;

    let library = Library::resolve(&manifest, features).map_err(|e| e.to_string())?;
    let workspace = match artifact_dir {
        Some(directory) => Workspace::kept_in(directory),
        None => Workspace::ephemeral(),
    }
    .map_err(|e| e.to_string())?;

    let report = trace_check::run_contract_verification(
        &library,
        &config,
        &contracts,
        &workspace,
        container_runtime,
    )
    .map_err(|e| e.to_string())?;

    match format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", report.to_json()),
    }
    Ok(report.exit_code())
}

fn list(
    manifest_path: Option<&std::path::Path>,
    profile: Option<&str>,
    features: &[String],
    format: Format,
) -> Result<u8, String> {
    let (binaries, used_profile) = discover::build_test_binaries(manifest_path, profile, features)
        .map_err(|e| e.to_string())?;
    let discovery = discover::discover(&binaries, &used_profile).map_err(|e| e.to_string())?;

    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&discovery).expect("discovery is serializable")
        ),
        Format::Text => {
            println!("{} constant-time test(s)", discovery.tests.len());
            for test in &discovery.tests {
                let target = test.target.as_deref().unwrap_or("-");
                println!("  {}  (target: {target})", test.name);
            }
            println!("{} declared contract(s)", discovery.contracts.len());
            for contract in &discovery.contracts {
                println!(
                    "  {}  secret(s): {}  at {}:{}",
                    contract.function,
                    contract.secrets.join(", "),
                    contract.file,
                    contract.line
                );
            }
        }
    }

    // Listing nothing is not a failure of the list command itself, but it is
    // worth saying so explicitly.
    if discovery.tests.is_empty() && discovery.contracts.is_empty() {
        eprintln!("trace-check: nothing discovered; are there #[ct_test] functions in scope?");
    }
    Ok(report::EXIT_OK)
}

fn provenance(
    discovery: &discover::Discovery,
    profile: &str,
    valgrind_version: &str,
    selected: &[discover::TestRecord],
) -> Provenance {
    // The artifact is the test executable actually analyzed. With several test
    // binaries the first selected one is recorded, and each test outcome
    // carries its own executable and hash.
    let (artifact_path, artifact_sha256) = selected
        .first()
        .or(discovery.tests.first())
        .map(|test| (test.executable.clone(), test.executable_sha256.clone()))
        .unwrap_or_else(|| ("<none>".to_string(), String::new()));

    Provenance {
        rustc_version: tool_version("rustc"),
        cargo_version: tool_version("cargo"),
        analyzer: format!("valgrind {valgrind_version}"),
        target: native::SUPPORTED_TARGET.to_string(),
        profile: profile.to_string(),
        artifact_path,
        artifact_sha256,
    }
}

fn tool_version(program: &str) -> String {
    std::process::Command::new(program)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| format!("{program} (version unavailable)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The subcommand name Cargo inserts is dropped, so both `cargo
    /// trace-check test` and a direct invocation parse.
    #[test]
    fn cargo_subcommand_name_is_dropped() {
        let via_cargo = [
            "cargo-trace-check".to_string(),
            "trace-check".to_string(),
            "test".to_string(),
        ];
        let filtered: Vec<String> = via_cargo
            .iter()
            .enumerate()
            .filter(|(index, arg)| !(*index == 1 && *arg == "trace-check"))
            .map(|(_, arg)| arg.clone())
            .collect();
        assert_eq!(filtered, vec!["cargo-trace-check", "test"]);
        assert!(Cli::try_parse_from(filtered).is_ok());
    }

    /// A direct invocation without the inserted name also parses.
    #[test]
    fn direct_invocation_parses() {
        assert!(Cli::try_parse_from(["cargo-trace-check", "test"]).is_ok());
        assert!(Cli::try_parse_from(["cargo-trace-check", "list"]).is_ok());
    }

    /// A literal `trace-check` later in the arguments is not stripped, so a
    /// filter can legitimately contain that text.
    #[test]
    fn only_the_first_argument_is_stripped() {
        let args = [
            "cargo-trace-check".to_string(),
            "test".to_string(),
            "--filter".to_string(),
            "trace-check".to_string(),
        ];
        let filtered: Vec<String> = args
            .iter()
            .enumerate()
            .filter(|(index, arg)| !(*index == 1 && *arg == "trace-check"))
            .map(|(_, arg)| arg.clone())
            .collect();
        assert_eq!(filtered.len(), 4);
    }

    /// Unknown subcommands are rejected rather than silently doing nothing.
    #[test]
    fn unknown_subcommand_is_rejected() {
        assert!(Cli::try_parse_from(["cargo-trace-check", "frobnicate"]).is_err());
    }

    /// The documented flags exist and parse.
    #[test]
    fn documented_flags_parse() {
        let cli = Cli::try_parse_from([
            "cargo-trace-check",
            "test",
            "--filter",
            "verify_tag",
            "--format",
            "json",
            "--timeout-secs",
            "30",
        ])
        .expect("flags parse");
        match cli.command {
            Command::Test {
                filter,
                timeout_secs,
                ..
            } => {
                assert_eq!(filter.as_deref(), Some("verify_tag"));
                assert_eq!(timeout_secs, 30);
            }
            _ => panic!("expected the test subcommand"),
        }
    }
}
