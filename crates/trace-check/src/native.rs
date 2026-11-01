//! Native Memcheck backend: builds a harness, runs it under Valgrind, and
//! classifies the result.
//!
//! The bounded-subprocess discipline mirrors [`crate::runner`]: argument
//! arrays rather than shell strings, concurrent pipe drainage, a wall-clock
//! timeout and an output cap, and every failure mode explicit.
//!
//! Two rules are specific to this backend and are the difference between a
//! trustworthy result and a rubber stamp:
//!
//! * **Instrumentation must be confirmed active.** The harness reports its run
//!   mode; if marking was inert, a clean run is [`Outcome::Inconclusive`], never
//!   [`Outcome::NoLeakObserved`]. Outside Valgrind every client request is a
//!   no-op, so this is the difference between evidence and nothing.
//! * **Not every Memcheck error is a leak.** Genuine memory errors and
//!   unattributable findings make the run inconclusive rather than being
//!   counted as secret dependency.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::memcheck::{self, Classification, MemcheckError, MemcheckRun};
use crate::security::{Evidence, Outcome, Provenance};

/// Valgrind release the XML grammar and classification were verified against.
pub const REQUIRED_VALGRIND_MAJOR_MINOR: &str = "3.";

/// Build profile for native harnesses: production-like optimization plus debug
/// symbols, because a finding without a source location is not actionable.
pub const NATIVE_PROFILE: &str = "memcheck";

/// The only target this backend supports today.
pub const SUPPORTED_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Exit code the harness is run with so Memcheck findings are distinguishable
/// from the harness's own exit status. Chosen outside the range a Rust binary
/// or a signal would produce naturally.
const MEMCHECK_ERROR_EXITCODE: i32 = 42;

/// Distinguishes concurrent analyses within one process. Keying the scratch
/// directory on the case id alone let two parallel runs of the same case
/// delete each other's XML before it was read.
static INVOCATION: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // Memcheck costs roughly an order of magnitude in runtime, and the
        // table scan touches 256 entries, so the budget is generous.
        Limits {
            timeout: Duration::from_secs(300),
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}

/// One native case: a harness binary, the case it should run, and the function
/// whose findings count.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NativeCase {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// Cargo package providing the harness binary.
    pub package: String,
    /// Harness binary name.
    pub binary: String,
    /// Feature enabling the harness binary.
    #[serde(default)]
    pub features: Vec<String>,
    /// Argument passed to the harness selecting the case.
    pub case: String,
    /// Function under test; findings are attributed to it.
    pub function: String,
    /// Which parameter is the modeled secret, for reporting only.
    #[serde(default)]
    pub secret_source: String,
    pub expected_outcome: String,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NativeManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub description: String,
    pub cases: Vec<NativeCase>,
}

/// Manifest schema version this build understands.
pub const NATIVE_SCHEMA_VERSION: u32 = 1;

impl NativeManifest {
    pub fn load(path: &Path) -> Result<Self, NativeError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| NativeError::Io(format!("{}: {e}", path.display())))?;
        let manifest: NativeManifest = serde_json::from_str(&text)
            .map_err(|e| NativeError::Manifest(format!("{}: {e}", path.display())))?;
        if manifest.schema_version != NATIVE_SCHEMA_VERSION {
            return Err(NativeError::UnsupportedSchema {
                found: manifest.schema_version,
                supported: NATIVE_SCHEMA_VERSION,
            });
        }
        for case in &manifest.cases {
            if Outcome::parse(&case.expected_outcome).is_none() {
                return Err(NativeError::UnknownExpectedOutcome {
                    case: case.id.clone(),
                    value: case.expected_outcome.clone(),
                });
            }
        }
        Ok(manifest)
    }
}

#[derive(Debug)]
pub enum NativeError {
    Io(String),
    Manifest(String),
    UnsupportedSchema {
        found: u32,
        supported: u32,
    },
    UnknownExpectedOutcome {
        case: String,
        value: String,
    },
    MissingValgrind {
        source: String,
    },
    UnsupportedValgrind {
        found: String,
    },
    UnsupportedTarget {
        found: String,
    },
    Build {
        package: String,
        stderr: String,
    },
    ArtifactNotFound {
        package: String,
        binary: String,
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
    /// The harness itself failed, as opposed to Memcheck reporting findings.
    HarnessFailed {
        command: String,
        status: String,
        stderr: String,
    },
    XmlUnreadable {
        path: String,
        source: String,
    },
}

impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NativeError::Io(message) => write!(f, "{message}"),
            NativeError::Manifest(message) => {
                write!(f, "cannot parse the native case manifest: {message}")
            }
            NativeError::UnsupportedSchema { found, supported } => write!(
                f,
                "native manifest schema_version {found} is not supported (this build understands {supported})"
            ),
            NativeError::UnknownExpectedOutcome { case, value } => write!(
                f,
                "case {case:?} expects unknown outcome {value:?}; use LEAK_DETECTED, \
                 NO_LEAK_OBSERVED or INCONCLUSIVE"
            ),
            NativeError::MissingValgrind { source } => write!(
                f,
                "cannot run valgrind ({source}); install it and put it on PATH \
                 (Debian/Ubuntu: apt-get install valgrind, Fedora: dnf install valgrind)"
            ),
            NativeError::UnsupportedValgrind { found } => write!(
                f,
                "Valgrind {found} is not supported; this backend was verified against {REQUIRED_VALGRIND_MAJOR_MINOR}x"
            ),
            NativeError::UnsupportedTarget { found } => write!(
                f,
                "the native Memcheck backend supports {SUPPORTED_TARGET}, not {found}"
            ),
            NativeError::Build { package, stderr } => {
                write!(f, "building the native harness for {package:?} failed:\n{stderr}")
            }
            NativeError::ArtifactNotFound { package, binary } => write!(
                f,
                "cargo reported no binary {binary:?} for package {package:?}"
            ),
            NativeError::Spawn { command, source } => {
                write!(f, "cannot spawn `{command}`: {source}")
            }
            NativeError::Timeout { command, limit } => {
                write!(f, "`{command}` exceeded the {limit:?} timeout and was killed")
            }
            NativeError::OutputTooLarge { command, limit } => {
                write!(f, "`{command}` produced more than {limit} bytes of output")
            }
            NativeError::HarnessFailed { command, status, stderr } => write!(
                f,
                "the harness `{command}` failed with {status} (this is a harness failure, not a \
                 security finding): {stderr}"
            ),
            NativeError::XmlUnreadable { path, source } => {
                write!(f, "cannot read Memcheck XML at {path}: {source}")
            }
        }
    }
}

impl std::error::Error for NativeError {}

/// A finding reported against the function under test.
#[derive(Debug, Clone, Serialize)]
pub struct NativeFinding {
    pub classification: Classification,
    pub description: String,
    pub what: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Shallow stack context, rendered for readability.
    pub stack: Vec<String>,
    /// Whether a frame naming the function under test was found.
    pub attributed: bool,
}

impl NativeFinding {
    fn from_error(error: &MemcheckError, function: &str) -> Self {
        let primary = error.primary_frame();
        NativeFinding {
            classification: error.classification,
            description: error.classification.describe().to_string(),
            what: error.what.clone(),
            location: primary.and_then(|frame| {
                frame.file.as_ref().map(|file| match frame.line {
                    Some(line) => format!("{file}:{line}"),
                    None => file.clone(),
                })
            }),
            function: primary.and_then(|frame| frame.function.clone()),
            origin: error.origin.clone(),
            stack: error
                .stack
                .iter()
                .take(6)
                .map(ToString::to_string)
                .collect(),
            attributed: error.attributable_to(function),
        }
    }
}

/// The analysis result for one native case.
#[derive(Debug, Clone, Serialize)]
pub struct NativeResult {
    pub case: String,
    pub function: String,
    pub secret_source: String,
    pub backend: &'static str,
    pub evidence: Evidence,
    pub outcome: Outcome,
    pub message: String,
    /// Whether the harness confirmed that marking was active.
    pub instrumented: bool,
    pub findings: Vec<NativeFinding>,
    /// Retained diagnostics that are not secret-dependency findings.
    pub other_diagnostics: Vec<NativeFinding>,
}

pub struct NativeRunner {
    valgrind: PathBuf,
    valgrind_version: String,
    limits: Limits,
    workspace_manifest: PathBuf,
    rustc_version: String,
    cargo_version: String,
}

impl NativeRunner {
    /// Validates the toolchain and target before anything is built.
    pub fn prepare(workspace_manifest: &Path, limits: Limits) -> Result<Self, NativeError> {
        if std::env::consts::ARCH != "x86_64" || std::env::consts::OS != "linux" {
            return Err(NativeError::UnsupportedTarget {
                found: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            });
        }

        let valgrind = PathBuf::from("valgrind");
        let banner = tool_version(&valgrind, &["--version"])
            .map_err(|source| NativeError::MissingValgrind { source })?;
        // `valgrind --version` prints e.g. `valgrind-3.28.0`.
        let version = banner.trim().trim_start_matches("valgrind-").to_string();
        if !version.starts_with(REQUIRED_VALGRIND_MAJOR_MINOR) {
            return Err(NativeError::UnsupportedValgrind { found: version });
        }

        Ok(NativeRunner {
            valgrind,
            valgrind_version: version,
            limits,
            workspace_manifest: workspace_manifest.to_path_buf(),
            rustc_version: tool_version(Path::new("rustc"), &["--version"])
                .map_err(NativeError::Io)?,
            cargo_version: tool_version(Path::new("cargo"), &["--version"])
                .map_err(NativeError::Io)?,
        })
    }

    pub fn valgrind_version(&self) -> &str {
        &self.valgrind_version
    }

    /// Builds the harness binary for a case and returns its path and hash.
    pub fn build(&self, case: &NativeCase) -> Result<(PathBuf, String), NativeError> {
        let mut args = vec![
            "build".to_string(),
            "--locked".to_string(),
            "--profile".to_string(),
            NATIVE_PROFILE.to_string(),
            "--package".to_string(),
            case.package.clone(),
            "--bin".to_string(),
            case.binary.clone(),
        ];
        if !case.features.is_empty() {
            args.push("--features".to_string());
            args.push(case.features.join(","));
        }
        args.push("--manifest-path".to_string());
        args.push(self.workspace_manifest.display().to_string());
        args.push("--message-format=json-render-diagnostics".to_string());

        let output = Command::new("cargo")
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| NativeError::Io(format!("cannot run cargo: {e}")))?;
        if !output.status.success() {
            return Err(NativeError::Build {
                package: case.package.clone(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        // Read the artifact path from cargo rather than guessing, so a custom
        // CARGO_TARGET_DIR cannot leave us analyzing a stale binary.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|message| message["reason"] == "compiler-artifact")
            .filter_map(|message| {
                message["executable"]
                    .as_str()
                    .filter(|path| path.ends_with(&case.binary))
                    .map(PathBuf::from)
            })
            .next_back()
            .ok_or_else(|| NativeError::ArtifactNotFound {
                package: case.package.clone(),
                binary: case.binary.clone(),
            })?;

        let bytes = std::fs::read(&path)
            .map_err(|e| NativeError::Io(format!("{}: {e}", path.display())))?;
        Ok((path, format!("{:x}", Sha256::digest(&bytes))))
    }

    /// Runs one case under Memcheck and classifies the result.
    pub fn analyze(&self, case: &NativeCase) -> Result<(NativeResult, Provenance), NativeError> {
        let (binary, hash) = self.build(case)?;

        let xml_dir = std::env::temp_dir().join(format!(
            "trace-check-memcheck-{}-{}-{}",
            std::process::id(),
            INVOCATION.fetch_add(1, Ordering::Relaxed),
            case.id
        ));
        std::fs::create_dir_all(&xml_dir)
            .map_err(|e| NativeError::Io(format!("{}: {e}", xml_dir.display())))?;
        let xml_path = xml_dir.join("memcheck.xml");

        let args = vec![
            "--tool=memcheck".to_string(),
            "--track-origins=yes".to_string(),
            "--num-callers=24".to_string(),
            // Leak checking would report allocations that are irrelevant here
            // and would muddy the memory-error classification.
            "--leak-check=no".to_string(),
            format!("--error-exitcode={MEMCHECK_ERROR_EXITCODE}"),
            "--xml=yes".to_string(),
            format!("--xml-file={}", xml_path.display()),
            binary.display().to_string(),
            case.case.clone(),
        ];
        let rendered = render(&self.valgrind, &args);
        let captured = run_bounded(&self.valgrind, &args, self.limits, &rendered)?;

        // A nonzero status that is not the Memcheck error code means the
        // harness itself failed, which is not a security result.
        if let Some(code) = captured.exit_code {
            if code != 0 && code != MEMCHECK_ERROR_EXITCODE {
                return Err(NativeError::HarnessFailed {
                    command: rendered,
                    status: format!("exit code {code}"),
                    stderr: if captured.stderr.trim().is_empty() {
                        captured.stdout.clone()
                    } else {
                        captured.stderr.clone()
                    },
                });
            }
        } else {
            return Err(NativeError::HarnessFailed {
                command: rendered,
                status: "a signal".to_string(),
                stderr: captured.stderr.clone(),
            });
        }

        let xml = std::fs::read_to_string(&xml_path).map_err(|e| NativeError::XmlUnreadable {
            path: xml_path.display().to_string(),
            source: e.to_string(),
        })?;
        let _ = std::fs::remove_dir_all(&xml_dir);

        let instrumented = harness_was_instrumented(&captured.stdout);
        let result = match memcheck::parse(&xml) {
            Ok(run) => classify(case, &run, instrumented),
            Err(error) => NativeResult {
                case: case.id.clone(),
                function: case.function.clone(),
                secret_source: case.secret_source.clone(),
                backend: BACKEND,
                evidence: Evidence::DynamicSecretDependency,
                outcome: Outcome::Inconclusive,
                message: format!("Memcheck output could not be parsed: {error}"),
                instrumented,
                findings: Vec::new(),
                other_diagnostics: Vec::new(),
            },
        };

        let provenance = Provenance {
            rustc_version: self.rustc_version.clone(),
            cargo_version: self.cargo_version.clone(),
            analyzer: format!("valgrind {}", self.valgrind_version),
            target: SUPPORTED_TARGET.to_string(),
            profile: NATIVE_PROFILE.to_string(),
            artifact_path: binary.display().to_string(),
            artifact_sha256: hash,
        };
        Ok((result, provenance))
    }
}

pub const BACKEND: &str = "native-memcheck";

/// Reads the harness's structured run-mode line. Absent or non-Valgrind means
/// marking was inert, so no conclusion can be drawn from a clean run.
fn harness_was_instrumented(stdout: &str) -> bool {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("trace-check-harness:"))
        .filter_map(|rest| {
            rest.split_whitespace()
                .find_map(|field| field.strip_prefix("run_mode="))
        })
        .any(|mode| mode == "valgrind")
}

/// Turns a parsed Memcheck run into a security outcome.
///
/// Order matters: inactive instrumentation invalidates everything, then real
/// memory errors, then unattributable diagnostics, and only then is a clean run
/// allowed to mean anything.
fn classify(case: &NativeCase, run: &MemcheckRun, instrumented: bool) -> NativeResult {
    let findings: Vec<NativeFinding> = run
        .secret_dependency_errors()
        .map(|error| NativeFinding::from_error(error, &case.function))
        .collect();
    let other: Vec<NativeFinding> = run
        .memory_errors()
        .chain(run.unclassified_errors())
        .map(|error| NativeFinding::from_error(error, &case.function))
        .collect();

    let attributed: Vec<&NativeFinding> = findings.iter().filter(|f| f.attributed).collect();
    let unattributed = findings.len() - attributed.len();

    let (outcome, message) = if !instrumented {
        (
            Outcome::Inconclusive,
            "the harness did not report running under Valgrind, so secret marking was inert; \
             a clean result would prove nothing"
                .to_string(),
        )
    } else if !other.is_empty() {
        (
            Outcome::Inconclusive,
            format!(
                "Memcheck reported {} diagnostic(s) that are not secret dependency (e.g. a \
                 genuine memory error); these are retained but must be resolved before a \
                 security conclusion is meaningful",
                other.len()
            ),
        )
    } else if !attributed.is_empty() {
        let branches = attributed
            .iter()
            .filter(|f| f.classification == Classification::SecretDependentBranch)
            .count();
        let values = attributed.len() - branches;
        (
            Outcome::LeakDetected,
            format!(
                "{} finding(s) in {}: {branches} secret-dependent branch(es), {values} \
                 secret-dependent address/value use(s)",
                attributed.len(),
                case.function
            ),
        )
    } else if unattributed > 0 {
        (
            Outcome::Inconclusive,
            format!(
                "{unattributed} secret-dependency finding(s) could not be attributed to {}; \
                 they are retained for inspection (a missing declassification in the harness \
                 is the usual cause)",
                case.function
            ),
        )
    } else {
        (
            Outcome::NoLeakObserved,
            format!(
                "no secret-derived value reached a branch or an address in {} on the path these \
                 inputs executed; this is not proof of constant-time behavior",
                case.function
            ),
        )
    };

    NativeResult {
        case: case.id.clone(),
        function: case.function.clone(),
        secret_source: case.secret_source.clone(),
        backend: BACKEND,
        evidence: Evidence::DynamicSecretDependency,
        outcome,
        message,
        instrumented,
        findings,
        other_diagnostics: other,
    }
}

#[derive(Debug)]
struct Captured {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
}

fn render(program: &Path, args: &[String]) -> String {
    let mut rendered = program.display().to_string();
    for arg in args {
        rendered.push(' ');
        rendered.push_str(arg);
    }
    rendered
}

/// Spawns a process with bounded output and a wall-clock limit. Mirrors
/// [`crate::runner`]'s discipline; both pipes are drained concurrently so a
/// bounded read cannot deadlock against a full pipe.
fn run_bounded(
    program: &Path,
    args: &[String],
    limits: Limits,
    rendered: &str,
) -> Result<Captured, NativeError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| NativeError::Spawn {
            command: rendered.to_string(),
            source: e.to_string(),
        })?;

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
                    return Err(NativeError::Timeout {
                        command: rendered.to_string(),
                        limit: limits.timeout,
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(NativeError::Spawn {
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
        return Err(NativeError::OutputTooLarge {
            command: rendered.to_string(),
            limit: limits.max_output_bytes,
        });
    }

    Ok(Captured {
        stdout: streams.remove("stdout").unwrap_or_default(),
        stderr: streams.remove("stderr").unwrap_or_default(),
        exit_code: status.code(),
    })
}

fn tool_version(program: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> NativeCase {
        NativeCase {
            id: "c".to_string(),
            description: String::new(),
            package: "p".to_string(),
            binary: "b".to_string(),
            features: Vec::new(),
            case: "k".to_string(),
            function: "verify_early_exit_opaque".to_string(),
            secret_source: "expected".to_string(),
            expected_outcome: "LEAK_DETECTED".to_string(),
            rationale: String::new(),
        }
    }

    fn run_from(xml: &str) -> MemcheckRun {
        memcheck::parse(xml).expect("fixture parses")
    }

    const BRANCH_XML: &str = r#"<?xml version="1.0"?><valgrindoutput>
<protocolversion>6</protocolversion><error><kind>UninitCondition</kind>
<what>Conditional jump or move depends on uninitialised value(s)</what><stack>
<frame><fn>mac_compare::verify_early_exit_opaque</fn><file>lib.rs</file><line>70</line></frame>
</stack></error></valgrindoutput>"#;

    const CLEAN_XML: &str = r#"<?xml version="1.0"?><valgrindoutput>
<protocolversion>6</protocolversion></valgrindoutput>"#;

    /// An attributed secret-dependent branch yields LEAK_DETECTED.
    #[test]
    fn attributed_branch_finding_is_a_leak() {
        let result = classify(&case(), &run_from(BRANCH_XML), true);
        assert_eq!(result.outcome, Outcome::LeakDetected);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].attributed);
        assert_eq!(result.findings[0].location.as_deref(), Some("lib.rs:70"));
    }

    /// A clean instrumented run is NO_LEAK_OBSERVED, with bounded wording.
    #[test]
    fn clean_instrumented_run_observes_no_leak() {
        let result = classify(&case(), &run_from(CLEAN_XML), true);
        assert_eq!(result.outcome, Outcome::NoLeakObserved);
        assert!(result
            .message
            .contains("not proof of constant-time behavior"));
    }

    /// A clean run with inactive instrumentation is INCONCLUSIVE: this is the
    /// single most important rule in the backend.
    #[test]
    fn clean_uninstrumented_run_is_inconclusive() {
        let result = classify(&case(), &run_from(CLEAN_XML), false);
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(result.message.contains("inert"));
    }

    /// Even a real finding cannot be trusted when instrumentation was inactive.
    #[test]
    fn uninstrumented_run_is_inconclusive_despite_findings() {
        let result = classify(&case(), &run_from(BRANCH_XML), false);
        assert_eq!(result.outcome, Outcome::Inconclusive);
    }

    /// A genuine memory error is retained, reported as not-a-leak, and makes
    /// the run inconclusive rather than being labelled a timing leak.
    #[test]
    fn genuine_memory_error_is_not_a_timing_leak() {
        let xml = r#"<?xml version="1.0"?><valgrindoutput><protocolversion>6</protocolversion>
<error><kind>InvalidRead</kind><what>Invalid read of size 1</what><stack>
<frame><fn>table_lookup::genuine_memory_error</fn><file>h.rs</file><line>9</line></frame>
</stack></error></valgrindoutput>"#;
        let result = classify(&case(), &run_from(xml), true);
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(
            result.findings.is_empty(),
            "must not be a secret-dependency finding"
        );
        assert_eq!(result.other_diagnostics.len(), 1);
        assert_eq!(
            result.other_diagnostics[0].classification,
            Classification::MemoryError
        );
        assert!(result.message.contains("not secret dependency"));
    }

    /// A finding only in formatting code is unattributable, so the run is
    /// inconclusive and the diagnostic is retained rather than counted.
    #[test]
    fn unattributable_finding_is_inconclusive_and_retained() {
        let xml = BRANCH_XML.replace(
            "mac_compare::verify_early_exit_opaque",
            "core::fmt::num::_fmt_inner",
        );
        let result = classify(&case(), &run_from(&xml), true);
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert_eq!(result.findings.len(), 1);
        assert!(!result.findings[0].attributed);
        assert!(result.message.contains("could not be attributed"));
    }

    /// A secret-dependent address is classified as a value use and counted.
    #[test]
    fn secret_dependent_address_is_detected() {
        let xml = r#"<?xml version="1.0"?><valgrindoutput><protocolversion>6</protocolversion>
<error><kind>UninitValue</kind><what>Use of uninitialised value of size 8</what><stack>
<frame><fn>table_lookup::lookup_secret_index</fn><file>lib.rs</file><line>44</line></frame>
</stack></error></valgrindoutput>"#;
        let mut target = case();
        target.function = "lookup_secret_index".to_string();
        let result = classify(&target, &run_from(xml), true);
        assert_eq!(result.outcome, Outcome::LeakDetected);
        assert_eq!(
            result.findings[0].classification,
            Classification::SecretDependentValue
        );
        assert!(result.message.contains("1 secret-dependent address"));
    }

    /// The harness run-mode line is parsed from stdout.
    #[test]
    fn harness_run_mode_is_detected() {
        assert!(harness_was_instrumented(
            "trace-check-harness: run_mode=valgrind case=x\nselected=5\n"
        ));
        assert!(!harness_was_instrumented(
            "trace-check-harness: run_mode=native case=x\n"
        ));
        assert!(!harness_was_instrumented(
            "trace-check-harness: run_mode=unsupported case=x\n"
        ));
        assert!(!harness_was_instrumented("selected=5\n"));
    }

    /// Unparseable Memcheck output is inconclusive, never a silent pass.
    #[test]
    fn malformed_xml_is_inconclusive() {
        // Exercised through the same path `analyze` uses.
        let error = memcheck::parse("not xml at all").unwrap_err();
        let result = NativeResult {
            case: "c".into(),
            function: "f".into(),
            secret_source: String::new(),
            backend: BACKEND,
            evidence: Evidence::DynamicSecretDependency,
            outcome: Outcome::Inconclusive,
            message: format!("Memcheck output could not be parsed: {error}"),
            instrumented: true,
            findings: Vec::new(),
            other_diagnostics: Vec::new(),
        };
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(result.message.contains("could not be parsed"));
    }

    /// A manifest with an unknown expected outcome is rejected up front.
    #[test]
    fn manifest_rejects_unknown_expected_outcome() {
        let path = std::env::temp_dir().join("trace-check-bad-native-manifest.json");
        std::fs::write(
            &path,
            r#"{"schema_version":1,"cases":[{"id":"a","package":"p","binary":"b","case":"c","function":"f","expected_outcome":"SECURE"}]}"#,
        )
        .unwrap();
        let error = NativeManifest::load(&path).unwrap_err();
        assert!(matches!(error, NativeError::UnknownExpectedOutcome { .. }));
    }

    /// An unsupported manifest schema version is refused.
    #[test]
    fn manifest_rejects_unsupported_schema() {
        let path = std::env::temp_dir().join("trace-check-bad-native-schema.json");
        std::fs::write(&path, r#"{"schema_version":99,"cases":[]}"#).unwrap();
        let error = NativeManifest::load(&path).unwrap_err();
        assert!(matches!(
            error,
            NativeError::UnsupportedSchema { found: 99, .. }
        ));
    }

    /// A process exceeding the timeout is killed and reported as a timeout.
    #[test]
    fn timeout_is_enforced() {
        let limits = Limits {
            timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let error =
            run_bounded(Path::new("sleep"), &["5".to_string()], limits, "sleep 5").unwrap_err();
        assert!(matches!(error, NativeError::Timeout { .. }));
    }

    /// Output beyond the cap is an error rather than a truncated capture.
    #[test]
    fn output_cap_is_enforced() {
        let limits = Limits {
            max_output_bytes: 16,
            ..Limits::default()
        };
        let error = run_bounded(
            Path::new("sh"),
            &["-c".to_string(), "head -c 100000 /dev/zero".to_string()],
            limits,
            "sh -c ...",
        )
        .unwrap_err();
        assert!(matches!(error, NativeError::OutputTooLarge { .. }));
    }

    /// A missing Valgrind binary produces an actionable install message.
    #[test]
    fn missing_valgrind_message_is_actionable() {
        let error = NativeError::MissingValgrind {
            source: "No such file".to_string(),
        };
        let rendered = error.to_string();
        assert!(rendered.contains("apt-get install valgrind"), "{rendered}");
        assert!(rendered.contains("dnf install valgrind"), "{rendered}");
    }
}
