use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use trace_check::census::Baseline;
use trace_check::compare::{compare, Outcome};
use trace_check::experiment::Experiment;
use trace_check::native::{self, NativeManifest};
use trace_check::parser::parse_trace;
use trace_check::run_experiment;
use trace_check::run_native;
use trace_check::runner::{self, Limits, Runner, CARGO_PROFILE, WASM_TARGET};
use trace_check::screen::{self, ScreenConfig, ScreenInputs};

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
    /// Analyze native Rust code for secret-dependent branches and memory
    /// addresses, using Valgrind Memcheck undefined-value tracking.
    Native {
        /// Run only the case with this id.
        #[arg(long)]
        case: Option<String>,
        /// Case manifest; defaults to examples/native-cases.json.
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
        #[arg(long)]
        workspace_root: Option<PathBuf>,
        /// Per-case wall-clock limit in seconds. Memcheck is roughly an order
        /// of magnitude slower than native execution.
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_output_bytes: usize,
    },
    /// Statically screen the compiled artifact for secret-dependent control
    /// flow, and gate its structural census against a recorded baseline.
    Screen {
        #[arg(value_enum)]
        example: ExampleName,
        /// Screen a prebuilt module instead of building the example.
        #[arg(long)]
        module: Option<PathBuf>,
        /// Baseline file; defaults to the example's artifact-baseline.json.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Overwrite the baseline with the current census.
        #[arg(long)]
        update_baseline: bool,
        /// Skip the baseline comparison even when a baseline file exists.
        #[arg(long)]
        no_baseline: bool,
        #[command(flatten)]
        options: DemoOptions,
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
        self.example_dir(workspace_root).join("cases.json")
    }

    fn screen_path(self, workspace_root: &Path) -> PathBuf {
        self.example_dir(workspace_root).join("screen.json")
    }

    fn baseline_path(self, workspace_root: &Path) -> PathBuf {
        self.example_dir(workspace_root)
            .join("artifact-baseline.json")
    }

    fn example_dir(self, workspace_root: &Path) -> PathBuf {
        match self {
            ExampleName::MacCompare => workspace_root.join("examples/mac-compare"),
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
        Command::Native {
            case,
            manifest,
            format,
            workspace_root,
            timeout_secs,
            max_output_bytes,
        } => native_analysis(
            case.as_deref(),
            manifest.as_deref(),
            format,
            workspace_root.as_deref(),
            native::Limits {
                timeout: Duration::from_secs(timeout_secs),
                max_output_bytes,
            },
        ),
        Command::Screen {
            example,
            module,
            baseline,
            update_baseline,
            no_baseline,
            options,
        } => screen_example(
            example,
            module.as_deref(),
            baseline.as_deref(),
            update_baseline,
            no_baseline,
            &options,
        ),
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

fn native_analysis(
    case_filter: Option<&str>,
    manifest_path: Option<&Path>,
    format: Format,
    workspace_root_override: Option<&Path>,
    limits: native::Limits,
) -> Result<u8, String> {
    let root = resolve_workspace_root(workspace_root_override)?;
    let manifest_path = manifest_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| root.join("examples/native-cases.json"));
    let mut manifest = NativeManifest::load(&manifest_path).map_err(|e| e.to_string())?;

    if let Some(wanted) = case_filter {
        manifest.cases.retain(|case| case.id == wanted);
        if manifest.cases.is_empty() {
            return Err(format!(
                "no native case with id {wanted:?} in {}",
                manifest_path.display()
            ));
        }
    }

    let report =
        run_native(&root.join("Cargo.toml"), &manifest, limits).map_err(|e| e.to_string())?;
    match format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", report.to_json()),
    }
    Ok(if report.summary.expectations_reproduced {
        EXIT_OK
    } else {
        EXIT_FINDING
    })
}

fn screen_example(
    example: ExampleName,
    module: Option<&Path>,
    baseline_override: Option<&Path>,
    update_baseline: bool,
    no_baseline: bool,
    options: &DemoOptions,
) -> Result<u8, String> {
    let root = workspace_root(options)?;
    let config = ScreenConfig::load(&example.screen_path(&root)).map_err(|e| e.to_string())?;

    let module_path = match module {
        Some(path) => path.to_path_buf(),
        None => runner::build_wasm(&root.join("Cargo.toml"), example.package())
            .map_err(|e| e.to_string())?,
    };
    let rustc_version =
        runner::tool_version(Path::new("rustc"), &["--version"]).map_err(|e| e.to_string())?;
    let inputs = ScreenInputs {
        module_path: &module_path,
        rustc_version: &rustc_version,
        target: WASM_TARGET,
        profile: CARGO_PROFILE,
    };

    let baseline_path = baseline_override
        .map(Path::to_path_buf)
        .unwrap_or_else(|| example.baseline_path(&root));

    if update_baseline {
        let captured = screen::capture_baseline(&config, &inputs).map_err(|e| e.to_string())?;
        std::fs::write(&baseline_path, captured.to_json() + "\n")
            .map_err(|e| format!("{}: {e}", baseline_path.display()))?;
        eprintln!("wrote baseline to {}", baseline_path.display());
        return Ok(EXIT_OK);
    }

    // The gate is on whenever a baseline exists, so CI needs no extra flag.
    let recorded = if no_baseline || !baseline_path.is_file() {
        None
    } else {
        Some(Baseline::load(&baseline_path).map_err(|e| e.to_string())?)
    };
    if recorded.is_none() && !no_baseline {
        eprintln!(
            "note: no baseline at {}; run `screen --update-baseline` to create one",
            baseline_path.display()
        );
    }

    let report = screen::run(&config, &inputs, recorded.as_ref()).map_err(|e| e.to_string())?;
    match options.format {
        Format::Text => print!("{}", report.to_text()),
        Format::Json => println!("{}", report.to_json()),
    }
    Ok(if report.summary.passed {
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
    resolve_workspace_root(options.workspace_root.as_deref())
}

fn resolve_workspace_root(override_path: Option<&Path>) -> Result<PathBuf, String> {
    let root = match override_path {
        Some(path) => path.to_path_buf(),
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
