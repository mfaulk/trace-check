//! Build and execution host: produces the WASM artifact and drives
//! `wasm-interp` under explicit bounds.
//!
//! Every process is spawned with an argument array — never a shell string —
//! because case data flows into the command line. Output is read on dedicated
//! threads so a bounded read cannot deadlock against a full pipe, and both a
//! wall-clock timeout and a maximum capture size are enforced; a run that hits
//! either is a failure, never an equivalent trace.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::experiment::{Case, Experiment, Variant, TAG_WORDS};
use crate::parser::{parse_trace, ParsedTrace, TRACE_PARSER_VERSION};

/// WABT release the trace grammar was verified against. A different version may
/// emit a different trace format or different instruction offsets, so results
/// are not comparable across versions.
pub const REQUIRED_WABT_VERSION: &str = "1.0.42";

/// Build target and profile are part of the claim being made, so they are fixed.
pub const WASM_TARGET: &str = "wasm32-unknown-unknown";
pub const CARGO_PROFILE: &str = "release";

#[derive(Debug)]
pub enum RunError {
    MissingTool {
        tool: String,
        source: String,
    },
    WabtVersionMismatch {
        found: String,
        required: String,
    },
    Build {
        stderr: String,
    },
    ArtifactNotFound {
        package: String,
    },
    Spawn {
        command: String,
        source: String,
    },
    Timeout {
        command: String,
        limit: Duration,
    },
    OutputTooLarge {
        command: String,
        limit: usize,
    },
    Trap {
        command: String,
        status: String,
        stderr: String,
    },
    /// The interpreter succeeded but emitted nothing. WABT 1.0.42 does this for
    /// an unknown export and for a wrong argument arity, so an empty capture
    /// must be an error — otherwise a typo would read as an equivalent trace.
    EmptyOutput {
        command: String,
    },
    Parse {
        command: String,
        source: String,
    },
    DecisionMismatch {
        variant: String,
        case: String,
        expected: String,
        found: String,
    },
    Io(String),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::MissingTool { tool, source } => write!(
                f,
                "cannot run {tool:?} ({source}); install WABT {REQUIRED_WABT_VERSION} and put its bin directory on PATH"
            ),
            RunError::WabtVersionMismatch { found, required } => write!(
                f,
                "found WABT {found} but this experiment is pinned to {required}; instruction \
                 offsets and trace format are version specific (pass --allow-wabt-version-mismatch to override)"
            ),
            RunError::Build { stderr } => write!(f, "building the example failed:\n{stderr}"),
            RunError::ArtifactNotFound { package } => write!(
                f,
                "cargo reported no .wasm artifact for package {package:?}"
            ),
            RunError::Spawn { command, source } => {
                write!(f, "cannot spawn `{command}`: {source}")
            }
            RunError::Timeout { command, limit } => write!(
                f,
                "`{command}` exceeded the {limit:?} timeout and was killed"
            ),
            RunError::OutputTooLarge { command, limit } => write!(
                f,
                "`{command}` produced more than {limit} bytes of trace output"
            ),
            RunError::Trap { command, status, stderr } => write!(
                f,
                "`{command}` failed with {status}: {stderr}"
            ),
            RunError::EmptyOutput { command } => write!(
                f,
                "`{command}` exited successfully but produced no trace; the export name or the \
                 argument arity is probably wrong"
            ),
            RunError::Parse { command, source } => {
                write!(f, "cannot parse the trace from `{command}`: {source}")
            }
            RunError::DecisionMismatch { variant, case, expected, found } => write!(
                f,
                "variant {variant:?} case {case:?} returned {found} but the fixture expects {expected}; \
                 trace comparisons are meaningless if the decision is wrong"
            ),
            RunError::Io(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Bounds applied to every interpreter invocation.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // The pinned example traces are ~100-1200 instructions; these bounds are
        // orders of magnitude above that, so hitting one means something broke.
        Limits {
            timeout: Duration::from_secs(60),
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Reproducibility metadata recorded alongside every report.
#[derive(Debug, Clone)]
pub struct Provenance {
    pub rustc_version: String,
    pub cargo_version: String,
    pub wabt_version: String,
    pub target: String,
    pub profile: String,
    pub module_path: PathBuf,
    pub module_sha256: String,
    pub trace_parser_version: u32,
}

/// A single executed case: its parsed path plus whether a repeat run of the
/// same input reproduced it.
#[derive(Debug, Clone)]
pub struct CaseRun {
    pub variant: String,
    pub case: String,
    pub export: String,
    pub trace: ParsedTrace,
    pub stable: bool,
    pub instability: Option<String>,
}

pub struct Runner {
    wasm_interp: PathBuf,
    limits: Limits,
    pub provenance: Provenance,
}

impl Runner {
    /// Validates the toolchain, builds the example and hashes the artifact.
    pub fn prepare(
        manifest: &Path,
        package: &str,
        limits: Limits,
        allow_version_mismatch: bool,
    ) -> Result<Self, RunError> {
        let wasm_interp = PathBuf::from("wasm-interp");
        let wabt_version = tool_version(&wasm_interp, &["--version"])?;
        if wabt_version != REQUIRED_WABT_VERSION && !allow_version_mismatch {
            return Err(RunError::WabtVersionMismatch {
                found: wabt_version,
                required: REQUIRED_WABT_VERSION.to_string(),
            });
        }

        let module_path = build_wasm(manifest, package)?;
        let bytes = std::fs::read(&module_path)
            .map_err(|e| RunError::Io(format!("{}: {e}", module_path.display())))?;
        let module_sha256 = format!("{:x}", Sha256::digest(&bytes));

        Ok(Runner {
            wasm_interp,
            limits,
            provenance: Provenance {
                rustc_version: tool_version(Path::new("rustc"), &["--version"])?,
                cargo_version: tool_version(Path::new("cargo"), &["--version"])?,
                wabt_version,
                target: WASM_TARGET.to_string(),
                profile: CARGO_PROFILE.to_string(),
                module_path,
                module_sha256,
                trace_parser_version: TRACE_PARSER_VERSION,
            },
        })
    }

    /// Runs every (variant, case) pair twice: once for the trace and once to
    /// prove the normalized trace is reproducible for identical input.
    pub fn run_all(
        &self,
        experiment: &Experiment,
    ) -> Result<HashMap<(String, String), CaseRun>, RunError> {
        let supplied = experiment.supplied_words();
        let mut runs = HashMap::new();
        for variant in &experiment.variants {
            for case in &experiment.cases {
                let run = self.run_case(variant, case, supplied)?;
                runs.insert((variant.id.clone(), case.id.clone()), run);
            }
        }
        Ok(runs)
    }

    fn run_case(
        &self,
        variant: &Variant,
        case: &Case,
        supplied: [i64; TAG_WORDS],
    ) -> Result<CaseRun, RunError> {
        let args = interp_args(
            &self.provenance.module_path,
            &variant.export,
            case.expected_words(),
            supplied,
        );
        let first = self.invoke(&args)?;
        let second = self.invoke(&args)?;

        let expected = case.decision().map_err(|e| RunError::Io(e.to_string()))?;
        if first.decision != expected {
            return Err(RunError::DecisionMismatch {
                variant: variant.id.clone(),
                case: case.id.clone(),
                expected: expected.as_str().to_string(),
                found: first.decision.as_str().to_string(),
            });
        }

        let instability = if first.events != second.events {
            Some(format!(
                "repeated run produced {} events instead of {}",
                second.events.len(),
                first.events.len()
            ))
        } else if first.decision != second.decision {
            Some("repeated run returned a different decision".to_string())
        } else {
            None
        };

        Ok(CaseRun {
            variant: variant.id.clone(),
            case: case.id.clone(),
            export: variant.export.clone(),
            trace: first,
            stable: instability.is_none(),
            instability,
        })
    }

    fn invoke(&self, args: &[String]) -> Result<ParsedTrace, RunError> {
        let rendered = render(&self.wasm_interp, args);
        let captured = run_bounded(&self.wasm_interp, args, self.limits, &rendered)?;
        parse_trace(&captured).map_err(|e| RunError::Parse {
            command: rendered,
            source: e.to_string(),
        })
    }

    /// Captures raw interpreter output for a case. Opt-in debugging only: raw
    /// traces embed the input values, including the modeled secret.
    pub fn capture_raw(
        &self,
        variant: &Variant,
        case: &Case,
        supplied: [i64; TAG_WORDS],
    ) -> Result<String, RunError> {
        let args = interp_args(
            &self.provenance.module_path,
            &variant.export,
            case.expected_words(),
            supplied,
        );
        let rendered = render(&self.wasm_interp, &args);
        run_bounded(&self.wasm_interp, &args, self.limits, &rendered)
    }
}

fn interp_args(
    module: &Path,
    export: &str,
    expected: [i64; TAG_WORDS],
    supplied: [i64; TAG_WORDS],
) -> Vec<String> {
    let mut args = vec![
        module.display().to_string(),
        format!("--run-export={export}"),
        "--trace".to_string(),
    ];
    // Argument order mirrors the export signature: expected words then supplied.
    for word in expected.iter().chain(supplied.iter()) {
        args.push(format!("--argument=i64:{word}"));
    }
    args
}

fn render(program: &Path, args: &[String]) -> String {
    let mut rendered = program.display().to_string();
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    rendered
}

/// Spawns a process, captures bounded output and enforces a wall-clock limit.
fn run_bounded(
    program: &Path,
    args: &[String],
    limits: Limits,
    rendered: &str,
) -> Result<String, RunError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| RunError::Spawn {
            command: rendered.to_string(),
            source: e.to_string(),
        })?;

    // Drain both pipes concurrently: a bounded read on a single pipe would
    // otherwise deadlock once the other pipe's buffer fills.
    let (tx, rx) = mpsc::channel();
    let mut readers = Vec::new();
    let pipes: [(&'static str, Option<Box<dyn Read + Send>>); 2] = [
        (
            "stdout",
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
        (
            "stderr",
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
    ];
    for (name, pipe) in pipes {
        let Some(mut pipe) = pipe else { continue };
        let tx = tx.clone();
        readers.push(std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            let mut overflow = false;
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        if buffer.len() + count > limits.max_output_bytes {
                            overflow = true;
                            break;
                        }
                        buffer.extend_from_slice(&chunk[..count]);
                    }
                }
            }
            let _ = tx.send((
                name,
                String::from_utf8_lossy(&buffer).into_owned(),
                overflow,
            ));
        }));
    }
    drop(tx);

    let deadline = Instant::now() + limits.timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::Timeout {
                        command: rendered.to_string(),
                        limit: limits.timeout,
                    });
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => {
                return Err(RunError::Spawn {
                    command: rendered.to_string(),
                    source: e.to_string(),
                })
            }
        }
    };

    let mut streams = HashMap::new();
    let mut overflowed = false;
    for (name, text, overflow) in rx.iter() {
        overflowed |= overflow;
        streams.insert(name, text);
    }
    for reader in readers {
        let _ = reader.join();
    }
    if overflowed {
        return Err(RunError::OutputTooLarge {
            command: rendered.to_string(),
            limit: limits.max_output_bytes,
        });
    }

    let stdout = streams.remove("stdout").unwrap_or_default();
    let stderr = streams.remove("stderr").unwrap_or_default();
    if !status.success() {
        return Err(RunError::Trap {
            command: rendered.to_string(),
            status: status
                .code()
                .map_or_else(|| "a signal".to_string(), |c| format!("exit code {c}")),
            stderr: if stderr.trim().is_empty() {
                stdout
            } else {
                stderr
            },
        });
    }
    if stdout.trim().is_empty() {
        return Err(RunError::EmptyOutput {
            command: rendered.to_string(),
        });
    }
    Ok(stdout)
}

pub fn tool_version(program: &Path, args: &[&str]) -> Result<String, RunError> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| RunError::MissingTool {
            tool: program.display().to_string(),
            source: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(RunError::MissingTool {
            tool: program.display().to_string(),
            source: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Builds the example for WASM and returns the artifact path reported by cargo.
/// Public so the static screen can analyze the same artifact the dynamic
/// experiment traces.
/// The path is read from cargo's JSON output rather than guessed, so a custom
/// `CARGO_TARGET_DIR` does not silently trace a stale module.
pub fn build_wasm(manifest: &Path, package: &str) -> Result<PathBuf, RunError> {
    let output = Command::new("cargo")
        .args([
            "build",
            "--locked",
            "--profile",
            CARGO_PROFILE,
            "--target",
            WASM_TARGET,
            "--package",
            package,
            "--manifest-path",
        ])
        .arg(manifest)
        .arg("--message-format=json-render-diagnostics")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| RunError::MissingTool {
            tool: "cargo".to_string(),
            source: e.to_string(),
        })?;

    if !output.status.success() {
        return Err(RunError::Build {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let artifact = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .filter_map(|message| {
            message["filenames"]
                .as_array()?
                .iter()
                .filter_map(|name| name.as_str())
                .find(|name| name.ends_with(".wasm"))
                .map(PathBuf::from)
        })
        .next_back();

    artifact.ok_or_else(|| RunError::ArtifactNotFound {
        package: package.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Interpreter arguments are an argv array with expected words before
    /// supplied words, matching the export signature.
    #[test]
    fn interp_args_order_matches_the_export_signature() {
        let args = interp_args(Path::new("m.wasm"), "f", [1, 2, 3, 4], [5, 6, 7, 8]);
        assert_eq!(args[0], "m.wasm");
        assert_eq!(args[1], "--run-export=f");
        assert_eq!(args[2], "--trace");
        let words: Vec<&str> = args[3..].iter().map(String::as_str).collect();
        assert_eq!(
            words,
            [
                "--argument=i64:1",
                "--argument=i64:2",
                "--argument=i64:3",
                "--argument=i64:4",
                "--argument=i64:5",
                "--argument=i64:6",
                "--argument=i64:7",
                "--argument=i64:8"
            ]
        );
    }

    /// Negative words (tag bytes above 0x7f) are passed through unmangled.
    #[test]
    fn interp_args_pass_negative_words_verbatim() {
        let args = interp_args(Path::new("m.wasm"), "f", [-1, 0, 0, 0], [0, 0, 0, 0]);
        assert!(args.contains(&"--argument=i64:-1".to_string()));
    }

    /// A process exceeding the timeout is killed and reported as a timeout.
    #[test]
    fn timeout_is_enforced() {
        let limits = Limits {
            timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let args = vec!["5".to_string()];
        let error = run_bounded(Path::new("sleep"), &args, limits, "sleep 5").unwrap_err();
        assert!(matches!(error, RunError::Timeout { .. }));
    }

    /// Output beyond the size limit is an error, not a truncated trace.
    #[test]
    fn output_size_limit_is_enforced() {
        let limits = Limits {
            max_output_bytes: 16,
            ..Limits::default()
        };
        let args = vec!["-c".to_string(), "head -c 100000 /dev/zero".to_string()];
        let error = run_bounded(Path::new("sh"), &args, limits, "sh -c ...").unwrap_err();
        assert!(matches!(error, RunError::OutputTooLarge { .. }));
    }

    /// A nonzero exit is surfaced as a failure rather than an empty trace.
    #[test]
    fn nonzero_exit_is_reported_as_failure() {
        let args = vec!["-c".to_string(), "echo boom >&2; exit 3".to_string()];
        let error =
            run_bounded(Path::new("sh"), &args, Limits::default(), "sh -c ...").unwrap_err();
        match error {
            RunError::Trap { status, stderr, .. } => {
                assert_eq!(status, "exit code 3");
                assert!(stderr.contains("boom"));
            }
            other => panic!("expected Trap, got {other:?}"),
        }
    }

    /// A successful process that emits nothing is an error, not an empty trace.
    #[test]
    fn empty_output_is_reported_as_failure() {
        let args = vec!["-c".to_string(), "exit 0".to_string()];
        let error =
            run_bounded(Path::new("sh"), &args, Limits::default(), "sh -c ...").unwrap_err();
        assert!(matches!(error, RunError::EmptyOutput { .. }));
    }

    /// A missing backend binary produces an actionable install message.
    #[test]
    fn missing_tool_is_reported_with_guidance() {
        let error =
            tool_version(Path::new("definitely-not-a-real-tool"), &["--version"]).unwrap_err();
        assert!(error.to_string().contains("install WABT"));
    }
}
