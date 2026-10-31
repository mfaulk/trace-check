use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use trace_check::compare::{compare, Outcome};
use trace_check::experiment::Experiment;
use trace_check::parser::parse_trace;
use trace_check::run_experiment;
use trace_check::runner::{Limits, Runner};

/// Exit codes are part of the CLI contract: a tool that cannot tell a
/// difference from a failure is unusable in CI.
const EXIT_OK: u8 = 0;
const EXIT_FINDING: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "trace-check",
    about = "Detect secret-dependent execution paths by comparing WASM instruction traces",
    long_about = "Compares the ordered instruction paths of a compiled WASM module across paired \
                  inputs that differ only in a modeled secret. Reports instruction-path \
                  equivalence only; it does not measure timing and cannot certify constant-time \
                  behavior."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build, run and compare a bundled example end to end.
    Demo {
        #[arg(value_enum)]
        example: ExampleName,
        #[command(flatten)]
        options: DemoOptions,
    },
    /// Compare two previously captured raw traces without rerunning anything.
    Compare {
        trace_a: PathBuf,
        trace_b: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Write a raw interpreter trace for one case. Raw traces contain the input
    /// values, including the modeled secret, so this is opt-in.
    Capture {
        #[arg(value_enum)]
        example: ExampleName,
        /// Variant id from the example's cases.json.
        #[arg(long)]
        variant: String,
        /// Case id from the example's cases.json.
        #[arg(long)]
        case: String,
        #[arg(long)]
        out: PathBuf,
        #[command(flatten)]
        options: DemoOptions,
    },
}

#[derive(Args)]
struct DemoOptions {
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Workspace root containing Cargo.toml and examples/.
    #[arg(long)]
    workspace_root: Option<PathBuf>,
    /// Per-invocation wall-clock limit for the interpreter, in seconds.
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
    /// Per-invocation cap on captured trace bytes.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_output_bytes: usize,
    /// Run against a WABT version other than the pinned one. Instruction
    /// offsets and trace format are version specific, so results may not be
    /// comparable to recorded ones.
    #[arg(long)]
    allow_wabt_version_mismatch: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum ExampleName {
    MacCompare,
}

impl ExampleName {
    fn package(self) -> &'static str {
        match self {
            ExampleName::MacCompare => "mac-compare",
        }
    }

    fn cases_path(self, workspace_root: &Path) -> PathBuf {
        match self {
            ExampleName::MacCompare => workspace_root.join("examples/mac-compare/cases.json"),
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run() -> Result<u8, String> {
    match Cli::parse().command {
        Command::Demo { example, options } => demo(example, &options),
        Command::Compare {
            trace_a,
            trace_b,
            format,
        } => compare_files(&trace_a, &trace_b, format),
        Command::Capture {
            example,
            variant,
            case,
            out,
            options,
        } => capture(example, &variant, &case, &out, &options),
    }
}

fn demo(example: ExampleName, options: &DemoOptions) -> Result<u8, String> {
    let root = workspace_root(options)?;
    let experiment = Experiment::load(&example.cases_path(&root)).map_err(|e| e.to_string())?;
    let report = run_experiment(
        &root.join("Cargo.toml"),
        example.package(),
        &experiment,
        limits(options),
        options.allow_wabt_version_mismatch,
    )
    .map_err(|e| e.to_string())?;

    match options.format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", report.to_json()),
    }

    Ok(if report.summary.controls_reproduced {
        EXIT_OK
    } else {
        EXIT_FINDING
    })
}

fn capture(
    example: ExampleName,
    variant_id: &str,
    case_id: &str,
    out: &Path,
    options: &DemoOptions,
) -> Result<u8, String> {
    let root = workspace_root(options)?;
    let experiment = Experiment::load(&example.cases_path(&root)).map_err(|e| e.to_string())?;
    let variant = experiment
        .variant(variant_id)
        .ok_or_else(|| format!("unknown variant {variant_id:?}"))?;
    let case = experiment
        .case(case_id)
        .ok_or_else(|| format!("unknown case {case_id:?}"))?;

    let runner = Runner::prepare(
        &root.join("Cargo.toml"),
        example.package(),
        limits(options),
        options.allow_wabt_version_mismatch,
    )
    .map_err(|e| e.to_string())?;
    let raw = runner
        .capture_raw(variant, case, experiment.supplied_words())
        .map_err(|e| e.to_string())?;
    std::fs::write(out, &raw).map_err(|e| format!("{}: {e}", out.display()))?;

    eprintln!(
        "wrote {} bytes to {}; this file contains the case input values",
        raw.len(),
        out.display()
    );
    Ok(EXIT_OK)
}

fn compare_files(trace_a: &Path, trace_b: &Path, format: Format) -> Result<u8, String> {
    let read = |path: &Path| {
        std::fs::read_to_string(path)
            .map_err(|e| format!("{}: {e}", path.display()))
            .and_then(|text| parse_trace(&text).map_err(|e| format!("{}: {e}", path.display())))
    };
    let (a, b) = (read(trace_a)?, read(trace_b)?);

    // Determinism cannot be established from stored files, so it is asserted
    // here and disclosed in the output rather than silently assumed.
    let result = compare(&a, &b, true);
    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": trace_check::report::REPORT_SCHEMA_VERSION,
                "trace_parser_version": trace_check::parser::TRACE_PARSER_VERSION,
                "trace_a": trace_a.display().to_string(),
                "trace_b": trace_b.display().to_string(),
                "determinism_verified": false,
                "result": result,
            }))
            .expect("comparison is serializable")
        ),
        Format::Text => {
            println!("{} vs {}", trace_a.display(), trace_b.display());
            println!("  exports: {} / {}", a.export, b.export);
            println!("  outcome: {}", result.outcome.as_str());
            println!("  {}", result.message);
            if let Some(divergence) = &result.divergence {
                for event in &divergence.common_context {
                    println!("    common {event}");
                }
                for event in divergence.side_a.iter().take(2) {
                    println!("    a      {event}");
                }
                for event in divergence.side_b.iter().take(2) {
                    println!("    b      {event}");
                }
            }
            println!("  note: determinism was not verified; stored traces are compared as given");
        }
    }

    Ok(match result.outcome {
        Outcome::NoDifferenceObserved => EXIT_OK,
        Outcome::DifferenceDetected => EXIT_FINDING,
        Outcome::Inconclusive => EXIT_ERROR,
    })
}

fn limits(options: &DemoOptions) -> Limits {
    Limits {
        timeout: Duration::from_secs(options.timeout_secs),
        max_output_bytes: options.max_output_bytes,
    }
}

/// Resolves the workspace root, preferring an explicit flag. The compile-time
/// manifest directory is the fallback so `cargo run` works from anywhere.
fn workspace_root(options: &DemoOptions) -> Result<PathBuf, String> {
    let root = match &options.workspace_root {
        Some(path) => path.clone(),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .ok_or("cannot derive the workspace root; pass --workspace-root")?
            .to_path_buf(),
    };
    if !root.join("Cargo.toml").is_file() {
        return Err(format!(
            "{} does not look like the workspace root (no Cargo.toml); pass --workspace-root",
            root.display()
        ));
    }
    Ok(root)
}
