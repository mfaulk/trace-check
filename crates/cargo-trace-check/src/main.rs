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
        /// Run only this case.
        #[arg(long)]
        case: Option<String>,
        /// Case file. Defaults to examples/symbolic/cases.json.
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
        Command::Verify {
            case,
            cases,
            format,
            workspace_root,
            container_runtime,
        } => verify(
            case.as_deref(),
            cases.as_deref(),
            format,
            workspace_root.as_deref(),
            container_runtime.as_deref(),
        ),
    }
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

    // Keyed on the process so two concurrent invocations cannot overwrite each
    // other's artifact while the other is being analyzed. The artifact's hash,
    // not its path, is what a report is pinned to.
    let out_dir =
        std::env::temp_dir().join(format!("trace-check-symbolic-build-{}", std::process::id()));
    let report = trace_check::run_symbolic(
        &case_file,
        &case_dir,
        &selected,
        &out_dir,
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
