//! Bounded relational verification via BINSEC symbolic execution.
//!
//! Where M2 observes one execution per input, this backend searches for a
//! secret assignment that leaks. When the search completes it reports
//! [`Outcome::VerifiedBounded`] — noninterference over a *declared* input
//! domain, under a stated model, for one compiled artifact.
//!
//! BINSEC runs in a digest-pinned container through its supported CLI. No
//! symbolic engine is implemented here.
//!
//! # Classification is fail-closed, and "no findings" is not enough
//!
//! A `secure` verdict is accepted only when the run *also* shows complete
//! exploration, zero unknown solver answers, and a non-zero number of completed
//! checks. During the feasibility spike a small depth bound produced
//! `total paths 10` against `completed/cut paths 7`; a verdict drawn from 7 of
//! 10 paths is not a verification result, so both signals are checked
//! independently of the reported status.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security::Outcome;

/// Case-file schema version this build understands.
pub const CASES_SCHEMA_VERSION: u32 = 1;

/// Analyzer image, pinned by **digest** rather than tag so the analyzer and its
/// bundled solver are reproducible as one artifact.
pub const ANALYZER_IMAGE: &str =
    "docker.io/binsec/binsec@sha256:19a0ff4b0278906bd6f00a5752cab19e8cad7153715cecf32d4f885826f62967";

/// Human-readable analyzer identity, recorded in reports. The release is the
/// image tag the digest above was published under; the build the binary
/// self-reports is read at run time and recorded alongside it, because the two
/// are independent facts.
pub const ANALYZER_NAME: &str = "binsec 0.11.2 (-checkct relational symbolic execution)";

/// The solver that discharges the relational queries.
///
/// It is linked into the analyzer binary through BINSEC's OCaml bindings rather
/// than invoked as a subprocess — the pinned image contains no `z3`,
/// `bitwuzla` or `cvc5` executable — so pinning the image digest pins the
/// solver with it. Read out of the pinned image: `bitwuzla-c.1.0.6` with a
/// vendored bitwuzla over CaDiCaL 2.1.2.
pub const ANALYZER_SOLVER: &str =
    "bitwuzla (linked via bitwuzla-c 1.0.6, SAT backend CaDiCaL 2.1.2)";

/// The only supported target.
pub const SUPPORTED_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Hard cap on captured analyzer output.
const MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckFeature {
    ControlFlow,
    MemoryAccess,
}

impl CheckFeature {
    fn as_binsec(self) -> &'static str {
        match self {
            CheckFeature::ControlFlow => "control-flow",
            CheckFeature::MemoryAccess => "memory-access",
        }
    }

    /// The noninterference property this class of check establishes, named so a
    /// report can state what was and was not covered.
    pub fn property(self) -> &'static str {
        match self {
            CheckFeature::ControlFlow => "control-flow noninterference",
            CheckFeature::MemoryAccess => "memory-address noninterference",
        }
    }

    /// Every class, so a report can list what a case left unchecked.
    pub fn all() -> [CheckFeature; 2] {
        [CheckFeature::ControlFlow, CheckFeature::MemoryAccess]
    }
}

/// One verification case.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerificationCase {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// Function whose constant-time behavior is under analysis.
    pub function: String,
    /// Symbol analysis starts at. A harness, so program startup is not
    /// explored.
    pub entry_symbol: String,
    /// Symbol analysis halts at.
    pub halt_symbol: String,
    /// Globals treated as secret (high).
    pub secret_globals: Vec<String>,
    /// Globals treated as public (low but symbolic).
    pub public_globals: Vec<String>,
    /// BINSEC `assume` constraints restricting the input domain.
    #[serde(default)]
    pub assumptions: Vec<String>,
    /// Observations to check, declared explicitly rather than left to the
    /// analyzer's default. A result is only as strong as this list: a case that
    /// checks `control-flow` alone establishes nothing about addresses, and a
    /// reader cannot tell the difference unless the case says so.
    pub features: Vec<CheckFeature>,
    /// Exploration depth bound. A case that deliberately exceeds it must be
    /// declared `INCONCLUSIVE`.
    pub max_depth: u32,
    /// Per-query solver timeout, seconds.
    #[serde(default = "default_solver_timeout")]
    pub solver_timeout_secs: u32,
    /// Wall-clock limit for the whole analysis, seconds.
    #[serde(default = "default_wall_timeout")]
    pub wall_timeout_secs: u64,
    pub expected_outcome: String,
    #[serde(default)]
    pub rationale: String,
}

fn default_solver_timeout() -> u32 {
    30
}

fn default_wall_timeout() -> u64 {
    900
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaseFile {
    pub schema_version: u32,
    #[serde(default)]
    pub description: String,
    /// Rust source built into the analyzed artifact, relative to the case file.
    pub target_source: String,
    pub cases: Vec<VerificationCase>,
}

impl CaseFile {
    pub fn load(path: &Path) -> Result<Self, SymbolicError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", path.display())))?;
        let file: CaseFile = serde_json::from_str(&text)
            .map_err(|e| SymbolicError::Schema(format!("{}: {e}", path.display())))?;
        if file.schema_version != CASES_SCHEMA_VERSION {
            return Err(SymbolicError::UnsupportedSchema {
                found: file.schema_version,
                supported: CASES_SCHEMA_VERSION,
            });
        }
        file.validate()?;
        Ok(file)
    }

    /// Rejects a case that could not be analyzed as written. Validating up
    /// front keeps a typo from surfacing as a mysterious inconclusive result.
    fn validate(&self) -> Result<(), SymbolicError> {
        let mut seen: Vec<&str> = Vec::new();
        for case in &self.cases {
            if seen.contains(&case.id.as_str()) {
                return Err(SymbolicError::Schema(format!(
                    "duplicate case id {:?}",
                    case.id
                )));
            }
            seen.push(&case.id);

            if Outcome::parse(&case.expected_outcome).is_none() {
                return Err(SymbolicError::Schema(format!(
                    "case {:?} expects unknown outcome {:?}; use LEAK_DETECTED, \
                     VERIFIED_BOUNDED or INCONCLUSIVE",
                    case.id, case.expected_outcome
                )));
            }
            if case.expected_outcome == "NO_LEAK_OBSERVED" {
                return Err(SymbolicError::Schema(format!(
                    "case {:?} expects NO_LEAK_OBSERVED, which only the dynamic backend \
                     produces; a completed symbolic exploration is VERIFIED_BOUNDED",
                    case.id
                )));
            }
            if case.features.is_empty() {
                return Err(SymbolicError::Schema(format!(
                    "case {:?} declares no features, so its observation model is \
                     unstated; list the checks explicitly, e.g. \
                     [\"control-flow\", \"memory-access\"]",
                    case.id
                )));
            }
            if let Some(duplicate) = case
                .features
                .iter()
                .enumerate()
                .find(|(index, feature)| case.features[..*index].contains(feature))
                .map(|(_, feature)| *feature)
            {
                return Err(SymbolicError::Schema(format!(
                    "case {:?} lists {:?} twice",
                    case.id,
                    duplicate.as_binsec()
                )));
            }
            if case.secret_globals.is_empty() {
                return Err(SymbolicError::Schema(format!(
                    "case {:?} declares no secret globals, so there is no relational \
                     property to check",
                    case.id
                )));
            }
            for symbol in case
                .secret_globals
                .iter()
                .chain(&case.public_globals)
                .chain(std::iter::once(&case.entry_symbol))
                .chain(std::iter::once(&case.halt_symbol))
                .chain(std::iter::once(&case.function))
            {
                if !is_symbol_name(symbol) {
                    return Err(SymbolicError::Schema(format!(
                        "case {:?} names {symbol:?}, which is not a plain symbol name",
                        case.id
                    )));
                }
            }
            // A global cannot be both high and low.
            if let Some(both) = case
                .secret_globals
                .iter()
                .find(|secret| case.public_globals.contains(secret))
            {
                return Err(SymbolicError::Schema(format!(
                    "case {:?} declares {both:?} as both secret and public",
                    case.id
                )));
            }
            if case.max_depth == 0 {
                return Err(SymbolicError::Schema(format!(
                    "case {:?} has max_depth 0, which would explore nothing",
                    case.id
                )));
            }
        }
        Ok(())
    }

    pub fn case(&self, id: &str) -> Option<&VerificationCase> {
        self.cases.iter().find(|case| case.id == id)
    }
}

/// Symbol names reach a generated script and a symbol-table lookup, so they are
/// restricted rather than trusted.
fn is_symbol_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$')
}

#[derive(Debug)]
pub enum SymbolicError {
    Io(String),
    Schema(String),
    UnsupportedSchema {
        found: u32,
        supported: u32,
    },
    UnsupportedTarget {
        found: String,
    },
    MissingContainerTool,
    MissingImage {
        image: String,
        /// The runtime that was selected, so the suggested pull command names
        /// the store the analyzer will actually read from.
        tool: String,
        detail: String,
    },
    Build {
        stderr: String,
    },
    MissingSymbols {
        artifact: String,
        missing: Vec<String>,
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
}

impl fmt::Display for SymbolicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolicError::Io(message) => write!(f, "{message}"),
            SymbolicError::Schema(message) => write!(f, "invalid verification case: {message}"),
            SymbolicError::UnsupportedSchema { found, supported } => write!(
                f,
                "case file schema_version {found} is not supported (this build understands {supported})"
            ),
            SymbolicError::UnsupportedTarget { found } => write!(
                f,
                "symbolic verification supports {SUPPORTED_TARGET}, not {found}"
            ),
            SymbolicError::MissingContainerTool => write!(
                f,
                "neither `podman` nor `docker` is available; the analyzer runs in a \
                 digest-pinned container. Install one, or run BINSEC yourself with the \
                 generated script"
            ),
            SymbolicError::MissingImage { image, tool, detail } => write!(
                f,
                "cannot obtain the analyzer image {image}: {detail}. Pull it into that \
                 store with `{tool} pull {image}`"
            ),
            SymbolicError::Build { stderr } => {
                write!(f, "building the verification target failed:\n{stderr}")
            }
            SymbolicError::MissingSymbols { artifact, missing } => write!(
                f,
                "{artifact} does not define {}; the case names a symbol the artifact does \
                 not contain, so nothing would be analyzed",
                missing.join(", ")
            ),
            SymbolicError::Spawn { command, source } => {
                write!(f, "cannot run `{command}`: {source}")
            }
            SymbolicError::Timeout { command, limit } => write!(
                f,
                "`{command}` exceeded its {limit:?} wall-clock limit and was killed"
            ),
            SymbolicError::OutputTooLarge { command, limit } => {
                write!(f, "`{command}` produced more than {limit} bytes of output")
            }
        }
    }
}

impl std::error::Error for SymbolicError {}

/// A site where the analyzer found differing modeled observations.
#[derive(Debug, Clone, Serialize)]
pub struct Divergence {
    pub kind: CheckFeature,
    pub description: String,
    /// Instruction address, as reported by the analyzer.
    pub instruction: String,
    /// Source location resolved from the artifact's debug info, when available.
    ///
    /// The **outermost** frame of the inline chain, which is the analyzed
    /// function rather than whatever `core` helper the address technically
    /// lands in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The whole inline chain, innermost first, when the address was inlined
    /// through more than one frame. Kept because the innermost frame is what
    /// an objdump of the artifact will agree with.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub inline_frames: Vec<String>,
}

/// What is known about concrete inputs reproducing a divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessStatus {
    /// The solver produced a satisfying model for the relational query, giving
    /// two concrete secret values whose executions diverge.
    SolverCounterexample,
    /// No model exists to report. The analyzer settles some leaks by taint
    /// analysis or formula preprocessing without ever issuing a satisfiability
    /// query, and there is then nothing to extract.
    UnavailableFromAnalyzer,
}

impl WitnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WitnessStatus::SolverCounterexample => "solver_counterexample",
            WitnessStatus::UnavailableFromAnalyzer => "unavailable_from_analyzer",
        }
    }
}

/// A solver-produced pair of secret values whose executions diverge.
///
/// Read back from the analyzer's own cached solver interaction: BINSEC records
/// the model alongside each query it issued. The values are the solver's, not
/// this tool's -- nothing here constructs or guesses them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Counterexample {
    /// The declared secret global the pair is for.
    pub global: String,
    /// The two values, as the solver reported them.
    pub left: String,
    pub right: String,
    /// The query file the model came from, so it can be re-solved by hand.
    pub query: String,
}

/// Exploration and proof-obligation statistics parsed from the analyzer.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Exploration {
    pub total_paths: Option<u64>,
    pub completed_paths: Option<u64>,
    pub pending_paths: Option<u64>,
    pub unknown_queries: Option<u64>,
    pub max_path_depth: Option<u64>,
    pub control_flow_checks_passed: Option<u64>,
    pub control_flow_checks_total: Option<u64>,
    pub memory_checks_passed: Option<u64>,
    pub memory_checks_total: Option<u64>,
    /// The analyzer's own verdict string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzer_status: Option<String>,
}

impl Exploration {
    /// Whether exploration demonstrably covered every path it discovered.
    ///
    /// Two independent signals, because a `secure` verdict drawn from a partial
    /// exploration is not a verification result.
    pub fn is_complete(&self) -> bool {
        matches!((self.total_paths, self.completed_paths), (Some(t), Some(c)) if t == c)
            && self.pending_paths == Some(0)
    }

    /// Discharged and total obligations for one class of check, as the
    /// analyzer reported them.
    ///
    /// `None` means the analyzer said nothing about that class. For a class the
    /// case asked for, that is missing evidence rather than zero obligations,
    /// and the classifier treats it as such.
    pub fn checks(&self, feature: CheckFeature) -> (Option<u64>, Option<u64>) {
        match feature {
            CheckFeature::ControlFlow => (
                self.control_flow_checks_passed,
                self.control_flow_checks_total,
            ),
            CheckFeature::MemoryAccess => (self.memory_checks_passed, self.memory_checks_total),
        }
    }

    /// Whether any relational obligation was actually discharged. Zero checks
    /// means nothing was verified, however clean the verdict looks.
    pub fn performed_checks(&self) -> u64 {
        self.control_flow_checks_total.unwrap_or(0) + self.memory_checks_total.unwrap_or(0)
    }
}

/// Analyzer-produced evidence about the function a case claims to be about.
///
/// The generated script carries a `reach <function>` directive, and BINSEC
/// reports `Path N reached address 0x... (<function>)` when exploration
/// actually arrives there. Without that line nothing can be attributed to the
/// function: the entry symbol decides what is explored, and a case naming a
/// function the harness never calls would otherwise inherit the harness's
/// clean verdict. This is the M3 invocation-counter problem in a new place,
/// and it is settled the same way — with evidence rather than with a
/// declaration.
#[derive(Debug, Clone, Serialize)]
pub struct TargetEvidence {
    pub function: String,
    pub entry_symbol: String,
    /// Whether the analyzer reported reaching the function.
    pub reached: bool,
    /// Where it reported reaching it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The directive that asked for this evidence.
    pub directive: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub case: String,
    pub function: String,
    /// Evidence that the analysis actually covered [`CaseResult::function`].
    pub target: TargetEvidence,
    /// The observation classes this result covers. Anything absent here was
    /// not checked, and the result says nothing about it.
    pub checked_features: Vec<CheckFeature>,
    /// Properties the result does **not** cover, named rather than left to
    /// inference.
    pub unchecked_properties: Vec<&'static str>,
    /// The artifact this result describes. Carried per case so a result stays
    /// interpretable after being split out of its report.
    pub artifact_sha256: String,
    pub outcome: Outcome,
    pub message: String,
    pub divergences: Vec<Divergence>,
    pub witness: WitnessStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_detail: Option<String>,
    /// Solver-produced secret pairs that diverge, when the analyzer issued a
    /// relational query and recorded its model.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub counterexamples: Vec<Counterexample>,
    pub exploration: Exploration,
    /// The script handed to the analyzer, so a result can be reproduced by hand.
    pub script: String,
}

/// Who did the analyzing, with no claim about *what* was analyzed.
///
/// Split out from [`SymbolicProvenance`] because a run can analyze more than
/// one artifact. The analyzer, its solver and the platform are shared by every
/// result in a report; an artifact path, its hash and the flags that built it
/// are not, and a report-level field carrying one artifact's identity invites a
/// reader to associate it with all of them.
#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerIdentity {
    pub rustc_version: String,
    pub analyzer: String,
    /// What the analyzer binary reports about itself. Absent if it could not be
    /// queried, which is recorded rather than guessed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzer_build: Option<String>,
    pub analyzer_image: String,
    pub solver: String,
    pub container_tool: String,
    pub target: String,
}

/// Toolchain and artifact provenance for a symbolic run.
#[derive(Debug, Clone, Serialize)]
pub struct SymbolicProvenance {
    pub rustc_version: String,
    pub analyzer: String,
    /// What the analyzer binary reports about itself. Absent if it could not be
    /// queried, which is recorded rather than guessed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analyzer_build: Option<String>,
    pub analyzer_image: String,
    pub solver: String,
    pub container_tool: String,
    pub target: String,
    pub build_flags: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
}

/// Build flags for the analyzed artifact.
///
/// Freestanding and static: there is no runtime to symbolically execute, which
/// is what keeps analysis on the primitive rather than on program startup.
pub const BUILD_FLAGS: [&str; 8] = [
    "--edition",
    "2021",
    "-O",
    "-g",
    "-C",
    "panic=abort",
    "-C",
    "relocation-model=static",
];

const LINK_FLAGS: [&str; 4] = ["-C", "link-arg=-nostdlib", "-C", "link-arg=-static"];

/// Container runtimes probed, in preference order when more than one holds the
/// image.
pub const CONTAINER_RUNTIMES: [&str; 2] = ["podman", "docker"];

/// Environment override for the container runtime, equivalent to
/// `--container-runtime`.
pub const RUNTIME_ENV: &str = "TRACE_CHECK_CONTAINER_RUNTIME";

/// Picks the runtime that actually holds the image.
///
/// Selecting the first runtime on `PATH` instead is a real failure mode, not a
/// hypothetical one: a CI runner with both installed pulled the image with
/// Docker, the tool picked Podman, and every case failed with "not present
/// locally" before any analysis ran. `probe` reports, per runtime, whether it
/// is usable and whether it has the image.
///
/// Returns the chosen runtime, or the list of usable runtimes when none has the
/// image — that list is what makes the error message name the right command.
fn select_runtime(
    candidates: &[String],
    probe: impl Fn(&str) -> RuntimeState,
) -> Result<String, Vec<String>> {
    let mut usable = Vec::new();
    for candidate in candidates {
        match probe(candidate) {
            RuntimeState::Absent => {}
            RuntimeState::WithoutImage => usable.push(candidate.clone()),
            RuntimeState::WithImage => return Ok(candidate.clone()),
        }
    }
    Err(usable)
}

/// What a probe of one container runtime found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    /// Not installed, or not usable.
    Absent,
    /// Usable, but the analyzer image is not in its store.
    WithoutImage,
    /// Usable and holding the analyzer image.
    WithImage,
}

fn probe_runtime(tool: &str) -> RuntimeState {
    let usable = Command::new(tool)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !usable {
        return RuntimeState::Absent;
    }
    // `image inspect` rather than podman's `image exists`, which Docker does
    // not have. Both runtimes have to work.
    let present = Command::new(tool)
        .args(["image", "inspect", ANALYZER_IMAGE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if present {
        RuntimeState::WithImage
    } else {
        RuntimeState::WithoutImage
    }
}

pub struct Verifier {
    container_tool: String,
    rustc_version: String,
    /// What the analyzer binary reports about itself, filled in by
    /// [`Verifier::check_image`].
    analyzer_build: Option<String>,
}

impl Verifier {
    /// Validates the platform and locates a container runtime holding the
    /// analyzer image, honoring [`RUNTIME_ENV`].
    pub fn prepare() -> Result<Self, SymbolicError> {
        let requested = std::env::var(RUNTIME_ENV).ok().filter(|v| !v.is_empty());
        Self::prepare_with(requested.as_deref())
    }

    /// As [`Verifier::prepare`], with an explicit runtime choice that overrides
    /// both the probe order and the environment.
    pub fn prepare_with(requested: Option<&str>) -> Result<Self, SymbolicError> {
        if std::env::consts::ARCH != "x86_64" || std::env::consts::OS != "linux" {
            return Err(SymbolicError::UnsupportedTarget {
                found: format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            });
        }
        let candidates: Vec<String> = match requested {
            Some(tool) => {
                if !CONTAINER_RUNTIMES.contains(&tool) {
                    return Err(SymbolicError::Schema(format!(
                        "unknown container runtime {tool:?}; expected one of {}",
                        CONTAINER_RUNTIMES.join(", ")
                    )));
                }
                vec![tool.to_string()]
            }
            None => CONTAINER_RUNTIMES.iter().map(|t| t.to_string()).collect(),
        };

        let container_tool = match select_runtime(&candidates, probe_runtime) {
            Ok(tool) => tool,
            // No runtime has the image. Keep the first usable one so the error
            // names a command the caller can actually run; an empty list means
            // nothing is installed at all.
            Err(usable) => usable
                .first()
                .cloned()
                .ok_or(SymbolicError::MissingContainerTool)?,
        };

        Ok(Verifier {
            container_tool,
            rustc_version: tool_version("rustc"),
            analyzer_build: None,
        })
    }

    pub fn container_tool(&self) -> &str {
        &self.container_tool
    }

    /// Confirms the analyzer image is present in the selected runtime's store,
    /// so a missing image is an explicit dependency error rather than a mid-run
    /// surprise.
    pub fn check_image(&mut self) -> Result<(), SymbolicError> {
        if probe_runtime(&self.container_tool) != RuntimeState::WithImage {
            return Err(SymbolicError::MissingImage {
                image: ANALYZER_IMAGE.to_string(),
                tool: self.container_tool.clone(),
                detail: format!("not in {}'s image store", self.container_tool),
            });
        }
        self.analyzer_build = Command::new(&self.container_tool)
            .args(["run", "--rm", ANALYZER_IMAGE, "binsec", "-version"])
            .stdin(Stdio::null())
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .filter(|line| !line.is_empty());
        Ok(())
    }

    /// Builds the freestanding artifact and returns its path and hash.
    ///
    /// rustc drops its intermediate object files next to `-o`, so two builds
    /// aiming at the same output path corrupt each other. The link happens in a
    /// private directory and the result is renamed into place, which keeps the
    /// artifact path stable while making concurrent builds safe.
    pub fn build(&self, source: &Path, out_dir: &Path) -> Result<(PathBuf, String), SymbolicError> {
        std::fs::create_dir_all(out_dir)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", out_dir.display())))?;
        let artifact = out_dir.join("targets");
        let scratch = tempfile::Builder::new()
            .prefix("trace-check-link-")
            .tempdir_in(out_dir)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", out_dir.display())))?;
        let linked = scratch.path().join("targets");

        let output = Command::new("rustc")
            .args(BUILD_FLAGS)
            .args(LINK_FLAGS)
            .args(["--crate-type", "bin", "-o"])
            .arg(&linked)
            .arg(source)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| SymbolicError::Io(format!("cannot run rustc: {e}")))?;
        if !output.status.success() {
            return Err(SymbolicError::Build {
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        std::fs::rename(&linked, &artifact)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", artifact.display())))?;

        let bytes = std::fs::read(&artifact)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", artifact.display())))?;
        Ok((artifact, format!("{:x}", Sha256::digest(&bytes))))
    }

    /// Reads the artifact's symbol table.
    pub fn symbols(&self, artifact: &Path) -> Result<BTreeMap<String, u64>, SymbolicError> {
        let output = Command::new("nm")
            .arg(artifact)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| SymbolicError::Io(format!("cannot run nm: {e}")))?;
        if !output.status.success() {
            return Err(SymbolicError::Io(format!(
                "nm failed on {}: {}",
                artifact.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let mut symbols = BTreeMap::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut fields = line.split_whitespace();
            let (Some(address), Some(_kind), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if let Ok(address) = u64::from_str_radix(address, 16) {
                symbols.insert(name.to_string(), address);
            }
        }
        Ok(symbols)
    }

    /// Generates the BINSEC script for a case.
    ///
    /// The syntax is BINSEC's own: `secret global` / `public global` declare the
    /// security lattice, `assume` restricts the input domain, and `explore all`
    /// asks for exhaustive exploration.
    pub fn script(&self, case: &VerificationCase) -> String {
        let mut script = String::new();
        script.push_str(&format!("starting from <{}>\n\n", case.entry_symbol));
        script.push_str("with concrete stack pointer\n\n");
        if !case.secret_globals.is_empty() {
            script.push_str(&format!(
                "secret global {}\n",
                case.secret_globals.join(", ")
            ));
        }
        if !case.public_globals.is_empty() {
            script.push_str(&format!(
                "public global {}\n",
                case.public_globals.join(", ")
            ));
        }
        script.push('\n');
        for assumption in &case.assumptions {
            script.push_str(&format!("assume {assumption}\n"));
        }
        if !case.assumptions.is_empty() {
            script.push('\n');
        }
        // Asks the analyzer to report whether exploration reaches the function
        // the case is about. Verified against the real analyzer to leave path
        // counts, check counts and the verdict unchanged.
        script.push_str(&format!("{}\n\n", reach_directive(&case.function)));
        script.push_str(&format!("halt at <{}>\n", case.halt_symbol));
        script.push_str("explore all\n");
        script
    }

    /// Runs one case and classifies the result.
    pub fn verify(
        &self,
        case: &VerificationCase,
        artifact: &Path,
        artifact_sha256: &str,
    ) -> Result<CaseResult, SymbolicError> {
        let symbols = self.symbols(artifact)?;
        let missing: Vec<String> = [&case.entry_symbol, &case.halt_symbol, &case.function]
            .into_iter()
            .chain(case.secret_globals.iter())
            .chain(case.public_globals.iter())
            .filter(|symbol| !symbols.contains_key(symbol.as_str()))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(SymbolicError::MissingSymbols {
                artifact: artifact.display().to_string(),
                missing,
            });
        }

        let script = self.script(case);
        // A world-readable staging directory: the analyzer image runs as a
        // non-root user, and a rootless container cannot traverse the
        // restrictive temp directories the rest of the tool uses.
        let stage = stage_dir(&case.id)?;
        let script_path = stage.path().join("case.cfg");
        std::fs::write(&script_path, &script)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", script_path.display())))?;
        let staged_artifact = stage.path().join("targets");
        std::fs::copy(artifact, &staged_artifact)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", staged_artifact.display())))?;
        // The analyzer writes its solver queries here, models included. That
        // is where a counterexample comes from, so the container's non-root
        // user needs to be able to write into it.
        let smt_dir = stage.path().join("smt");
        std::fs::create_dir_all(&smt_dir)
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", smt_dir.display())))?;
        make_readable(stage.path())?;
        make_writable(&smt_dir)?;

        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "-v".to_string(),
            format!("{}:/work:z", stage.path().display()),
            "-w".to_string(),
            "/work".to_string(),
            ANALYZER_IMAGE.to_string(),
            "binsec".to_string(),
            "-sse".to_string(),
            "-checkct".to_string(),
            "-sse-script".to_string(),
            "case.cfg".to_string(),
            "-sse-depth".to_string(),
            case.max_depth.to_string(),
            "-fml-solver-timeout".to_string(),
            case.solver_timeout_secs.to_string(),
            // Caches every query with the solver's answer and model, which is
            // the only interface that exposes a satisfying assignment.
            "-smt-dir".to_string(),
            "/work/smt".to_string(),
        ];
        // Always explicit. Relying on the analyzer's default would make the
        // observation model of a result depend on the analyzer version rather
        // than on the case, and the case file requires it for that reason.
        args.push("-checkct-features".to_string());
        args.push(
            case.features
                .iter()
                .map(|feature| feature.as_binsec())
                .collect::<Vec<_>>()
                .join(","),
        );
        args.push("targets".to_string());

        let limits = Duration::from_secs(case.wall_timeout_secs);
        let captured = run_bounded(&self.container_tool, &args, limits)?;
        let combined = format!("{}\n{}", captured.stdout, captured.stderr);

        let exploration = parse_exploration(&combined);
        let divergences = parse_divergences(&combined, artifact, &symbols);
        let reached = parse_reached(&combined, &case.function);
        let target = TargetEvidence {
            function: case.function.clone(),
            entry_symbol: case.entry_symbol.clone(),
            reached: reached.is_some(),
            address: reached,
            directive: reach_directive(&case.function),
        };
        let (outcome, message) = classify(case, &exploration, &divergences, &captured, &target);

        // Only a leak has a counterexample to report, and only when the
        // analyzer actually issued a relational query.
        let counterexamples = if outcome == Outcome::LeakDetected {
            parse_counterexamples(&smt_dir, &case.secret_globals)
        } else {
            Vec::new()
        };
        let (witness, witness_detail) = if counterexamples.is_empty() {
            (
                WitnessStatus::UnavailableFromAnalyzer,
                Some(
                    "no satisfying model is available: the analyzer settled this without \
                     issuing a relational satisfiability query, so there is no assignment \
                     to extract"
                        .to_string(),
                ),
            )
        } else {
            (
                WitnessStatus::SolverCounterexample,
                Some(
                    "the values below are the solver's own model, read back from the \
                     analyzer's cached query"
                        .to_string(),
                ),
            )
        };

        Ok(CaseResult {
            case: case.id.clone(),
            function: case.function.clone(),
            target,
            checked_features: case.features.clone(),
            unchecked_properties: unchecked_properties(&case.features),
            artifact_sha256: artifact_sha256.to_string(),
            outcome,
            message,
            divergences,
            witness,
            witness_detail,
            counterexamples,
            exploration,
            script,
        })
    }

    /// The analyzer's identity, without an artifact. Use this where a report
    /// covers several artifacts.
    pub fn identity(&self) -> AnalyzerIdentity {
        AnalyzerIdentity {
            rustc_version: self.rustc_version.clone(),
            analyzer: ANALYZER_NAME.to_string(),
            analyzer_build: self.analyzer_build.clone(),
            analyzer_image: ANALYZER_IMAGE.to_string(),
            solver: ANALYZER_SOLVER.to_string(),
            container_tool: self.container_tool.clone(),
            target: SUPPORTED_TARGET.to_string(),
        }
    }

    pub fn provenance(&self, artifact: &Path, artifact_sha256: &str) -> SymbolicProvenance {
        SymbolicProvenance {
            rustc_version: self.rustc_version.clone(),
            analyzer: ANALYZER_NAME.to_string(),
            analyzer_build: self.analyzer_build.clone(),
            analyzer_image: ANALYZER_IMAGE.to_string(),
            solver: ANALYZER_SOLVER.to_string(),
            container_tool: self.container_tool.clone(),
            target: SUPPORTED_TARGET.to_string(),
            build_flags: BUILD_FLAGS
                .iter()
                .chain(LINK_FLAGS.iter())
                .copied()
                .collect::<Vec<_>>()
                .join(" "),
            artifact_path: artifact.display().to_string(),
            artifact_sha256: artifact_sha256.to_string(),
        }
    }
}

/// Decides the outcome, rejecting a clean verdict unless the run earned it.
pub fn classify(
    case: &VerificationCase,
    exploration: &Exploration,
    divergences: &[Divergence],
    captured: &Captured,
    target: &TargetEvidence,
) -> (Outcome, String) {
    if captured.exit_code != Some(0) {
        return (
            Outcome::Inconclusive,
            format!(
                "the analyzer exited with {}, so its output cannot be trusted",
                captured
                    .exit_code
                    .map_or_else(|| "a signal".to_string(), |code| format!("code {code}"))
            ),
        );
    }

    let status = exploration.analyzer_status.as_deref();
    if status.is_none() {
        return (
            Outcome::Inconclusive,
            "the analyzer produced no verdict; its output is missing or malformed".to_string(),
        );
    }

    // Nothing is attributed to a function the analyzer never reached. The entry
    // symbol decides what gets explored, so a case naming an unrelated function
    // would otherwise inherit the harness's verdict -- including a clean one.
    if !target.reached {
        let found_anything = status == Some("insecure") || !divergences.is_empty();
        return (
            Outcome::Inconclusive,
            if found_anything {
                format!(
                    "the analyzer found {} divergence site(s) but never reached `{}` from \
                     `{}`, so no result can be attributed to it; the sites are reported \
                     below and belong to other code on the explored paths",
                    divergences.len(),
                    target.function,
                    target.entry_symbol
                )
            } else {
                format!(
                    "the analyzer never reached `{}` from `{}`, so this run establishes \
                     nothing about it; check that the entry symbol is the harness that \
                     calls it",
                    target.function, target.entry_symbol
                )
            },
        );
    }

    // A reported leak is a leak regardless of completeness: a satisfiable
    // relational query is positive evidence, and stopping early cannot
    // un-discover it.
    if status == Some("insecure") || !divergences.is_empty() {
        let control = divergences
            .iter()
            .filter(|d| d.kind == CheckFeature::ControlFlow)
            .count();
        let memory = divergences.len() - control;
        return (
            Outcome::LeakDetected,
            format!(
                "{} divergence site(s): {control} secret-dependent branch(es), {memory} \
                 secret-dependent memory access(es)",
                divergences.len()
            ),
        );
    }

    if status == Some("unknown") {
        return (
            Outcome::Inconclusive,
            format!(
                "the analyzer reported `unknown`: exploration or a solver query did not \
                 complete ({} of {} paths finished)",
                exploration
                    .completed_paths
                    .map_or_else(|| "?".to_string(), |c| c.to_string()),
                exploration
                    .total_paths
                    .map_or_else(|| "?".to_string(), |t| t.to_string())
            ),
        );
    }

    // From here the analyzer said `secure`. That is necessary but not
    // sufficient.
    if !exploration.is_complete() {
        return (
            Outcome::Inconclusive,
            format!(
                "the analyzer reported `secure` but exploration was incomplete ({} of {} \
                 paths finished, {} pending); a verdict drawn from part of the state space \
                 is not a verification result",
                exploration
                    .completed_paths
                    .map_or_else(|| "?".to_string(), |c| c.to_string()),
                exploration
                    .total_paths
                    .map_or_else(|| "?".to_string(), |t| t.to_string()),
                exploration
                    .pending_paths
                    .map_or_else(|| "?".to_string(), |p| p.to_string())
            ),
        );
    }
    if exploration.unknown_queries.unwrap_or(1) != 0 {
        return (
            Outcome::Inconclusive,
            format!(
                "{} solver query/queries returned unknown, so the relational obligations \
                 were not all discharged",
                exploration
                    .unknown_queries
                    .map_or_else(|| "?".to_string(), |u| u.to_string())
            ),
        );
    }
    // Every obligation the case asked for has to be accounted for, class by
    // class. A `secure` verdict alongside `0 / 1 memory access checks pass`
    // contradicts itself, and a class the analyzer said nothing about is
    // missing evidence rather than zero work.
    for feature in &case.features {
        match exploration.checks(*feature) {
            (Some(passed), Some(total)) if total > 0 && passed == total => {}
            (Some(passed), Some(total)) if total > 0 => {
                return (
                    Outcome::Inconclusive,
                    format!(
                        "the analyzer reported `secure` but only {passed} of {total} {} \
                         check(s) passed; the counts contradict the verdict",
                        feature.as_binsec()
                    ),
                );
            }
            (_, Some(0)) => {
                return (
                    Outcome::Inconclusive,
                    format!(
                        "no {} check was performed, so {} was not established however \
                         clean the verdict looks",
                        feature.as_binsec(),
                        feature.property()
                    ),
                );
            }
            _ => {
                return (
                    Outcome::Inconclusive,
                    format!(
                        "the case asked for {} checks but the analyzer reported no count \
                         for them; its output is missing or malformed",
                        feature.as_binsec()
                    ),
                );
            }
        }
    }

    // Depth evidence is required, not assumed. Treating a missing maximum as
    // zero would let malformed output pass the bound check.
    let Some(max_depth_reached) = exploration.max_path_depth else {
        return (
            Outcome::Inconclusive,
            "the analyzer reported no maximum path depth, so the exploration bound cannot \
             be shown to have held"
                .to_string(),
        );
    };
    if max_depth_reached >= u64::from(case.max_depth) {
        return (
            Outcome::Inconclusive,
            format!(
                "exploration reached the depth bound ({}), so paths beyond it were not \
                 examined",
                case.max_depth
            ),
        );
    }

    let verified: Vec<&str> = case.features.iter().map(|f| f.property()).collect();
    let unchecked = unchecked_properties(&case.features);
    let mut message = format!(
        "{} established over {} fully explored path(s) ({} relational check(s) discharged), \
         within the declared input domain and bounds",
        verified.join(" and "),
        exploration
            .total_paths
            .map_or_else(|| "?".to_string(), |t| t.to_string()),
        exploration.performed_checks()
    );
    if !unchecked.is_empty() {
        message.push_str(&format!("; {} was NOT checked", unchecked.join(" and ")));
    }
    message.push_str(
        "; this is not a claim about untested domains, other artifacts, or unmodeled \
         observations",
    );
    (Outcome::VerifiedBounded, message)
}

/// Properties no selected check covers, so a report can name them instead of
/// leaving a reader to infer the gap.
pub fn unchecked_properties(selected: &[CheckFeature]) -> Vec<&'static str> {
    CheckFeature::all()
        .into_iter()
        .filter(|feature| !selected.contains(feature))
        .map(CheckFeature::property)
        .collect()
}

/// Extracts solver-produced counterexamples from the analyzer's cached SMT
/// queries.
///
/// `-smt-dir` makes BINSEC write every query it issued, with the solver's
/// answer and model recorded as trailing comments:
///
/// ```text
/// (declare-fun mirror_TC_SECRET!1 () (_ BitVec 8))
/// (declare-fun TC_SECRET!1 () (_ BitVec 8))
/// ...
/// ; sat
/// (get-value (mirror_TC_SECRET!1))
/// ; ((mirror_TC_SECRET!1 #xff))
/// (get-value (TC_SECRET!1))
/// ; ((TC_SECRET!1 #xfe))
/// ```
///
/// A query is *relational* when it constrains both a secret and its `mirror_`
/// copy; that pair is the counterexample. Queries over a single copy are
/// path-feasibility questions and are ignored, because one value is not a
/// counterexample to noninterference.
///
/// Returns at most one pair per declared secret global, the first found, so a
/// report names a witness rather than a list of equivalent ones.
fn parse_counterexamples(smt_dir: &Path, secrets: &[String]) -> Vec<Counterexample> {
    let Ok(entries) = std::fs::read_dir(smt_dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "smt2"))
        .collect();
    // Deterministic order, so the reported witness does not depend on how the
    // directory happens to be laid out.
    files.sort();

    let mut found: Vec<Counterexample> = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        // Only a satisfiable query has a model.
        if !text.lines().any(|line| line.trim() == "; sat") {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        for secret in secrets {
            if found.iter().any(|c| &c.global == secret) {
                continue;
            }
            let plain = model_value(&text, secret, false);
            let mirror = model_value(&text, secret, true);
            // Both copies, and genuinely different: equal values would make the
            // "counterexample" vacuous.
            if let (Some(left), Some(right)) = (plain, mirror) {
                if left != right {
                    found.push(Counterexample {
                        global: secret.clone(),
                        left,
                        right,
                        query: name.clone(),
                    });
                }
            }
        }
    }
    found
}

/// Reads one recorded model value for `global`, or its `mirror_` copy.
///
/// Matches `; ((TC_SECRET!1 #xfe))`. The `!n` suffix is BINSEC's SSA index and
/// is not part of the global's name, so the prefix is matched and the index
/// skipped.
fn model_value(text: &str, global: &str, mirror: bool) -> Option<String> {
    let prefix = if mirror {
        format!("mirror_{global}!")
    } else {
        format!("{global}!")
    };
    text.lines().find_map(|line| {
        let line = line.trim();
        let body = line.strip_prefix("; ((")?.strip_suffix("))")?;
        let (name, value) = body.split_once(' ')?;
        if !name.starts_with(&prefix) {
            return None;
        }
        // `TC_SECRET!1` must not match the prefix of `mirror_TC_SECRET!1`, and
        // the plain form must not match the mirror.
        if !mirror && name.starts_with("mirror_") {
            return None;
        }
        Some(value.trim().to_string())
    })
}

/// The directive that asks the analyzer to report reaching `function`.
fn reach_directive(function: &str) -> String {
    format!("reach <{function}>")
}

/// Reads back the analyzer's own statement that it reached `function`.
///
/// The line looks like
/// `[sse:result] Path 0 reached address 0x2014c0 (<masked_scan>) (0 to go)`.
/// Matching on the symbol in parentheses rather than on an address keeps this
/// independent of where the linker put the function.
fn parse_reached(output: &str, function: &str) -> Option<String> {
    let marker = format!("(<{function}>)");
    output.lines().find_map(|line| {
        if !line.contains("reached address") || !line.contains(&marker) {
            return None;
        }
        line.split("reached address")
            .nth(1)?
            .split_whitespace()
            .next()
            .map(str::to_string)
    })
}

/// Pulls exploration statistics out of the analyzer's report.
pub fn parse_exploration(output: &str) -> Exploration {
    let mut exploration = Exploration::default();
    let number_after = |needle: &str| -> Option<u64> {
        output.lines().find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix(needle)?;
            rest.split_whitespace().next()?.parse().ok()
        })
    };

    exploration.total_paths = number_after("total paths");
    exploration.completed_paths = number_after("completed/cut paths");
    exploration.pending_paths = number_after("pending paths");
    exploration.max_path_depth = number_after("max path depth");

    // `unknown` appears inside the satisfiability-query block. Take the first,
    // which is that block's own count.
    exploration.unknown_queries = output.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("unknown")?;
        rest.split_whitespace().next()?.parse().ok()
    });

    exploration.analyzer_status = output.lines().find_map(|line| {
        let rest = line.split("Program status is :").nth(1)?;
        rest.split_whitespace().next().map(str::to_string)
    });

    let checks = |kind: &str| -> (Option<u64>, Option<u64>) {
        for line in output.lines() {
            if !line.contains(kind) || !line.contains("checks pass") {
                continue;
            }
            // `[checkct:info] 7 / 8 memory access checks pass`
            let Some(index) = line.find(" / ") else {
                continue;
            };
            let left = line[..index]
                .split_whitespace()
                .next_back()
                .and_then(|value| value.parse().ok());
            let right = line[index + 3..]
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok());
            return (left, right);
        }
        (None, None)
    };
    let (cf_pass, cf_total) = checks("control flow");
    exploration.control_flow_checks_passed = cf_pass;
    exploration.control_flow_checks_total = cf_total;
    let (mem_pass, mem_total) = checks("memory access");
    exploration.memory_checks_passed = mem_pass;
    exploration.memory_checks_total = mem_total;

    exploration
}

/// Extracts the divergence sites the analyzer localized.
pub fn parse_divergences(
    output: &str,
    artifact: &Path,
    symbols: &BTreeMap<String, u64>,
) -> Vec<Divergence> {
    let mut divergences = Vec::new();
    for line in output.lines() {
        let Some(rest) = line.split("Instruction ").nth(1) else {
            continue;
        };
        let Some(address) = rest.split_whitespace().next() else {
            continue;
        };
        let kind = if rest.contains("control flow leak") {
            CheckFeature::ControlFlow
        } else if rest.contains("memory access leak") {
            CheckFeature::MemoryAccess
        } else {
            continue;
        };
        let description = match kind {
            CheckFeature::ControlFlow => "Secret-dependent control flow",
            CheckFeature::MemoryAccess => "Secret-dependent memory access",
        };
        let frames = resolve_source(artifact, address);
        divergences.push(Divergence {
            kind,
            description: description.to_string(),
            instruction: address.to_string(),
            source: frames
                .last()
                .cloned()
                .or_else(|| enclosing_symbol(symbols, address).map(|name| format!("in {name}"))),
            inline_frames: if frames.len() > 1 { frames } else { Vec::new() },
        });
    }
    divergences
}

/// Resolves an instruction address to its inline chain via the artifact's debug
/// info, innermost frame first. Best effort: a finding without a location is
/// still reported.
///
/// `-i` matters. At `-O` a leaking load sits inside an inlined
/// `core::ptr::read_volatile`, so without the inline chain every finding in
/// this example resolves to `mod.rs` in the standard library and names no code
/// the developer wrote.
fn resolve_source(artifact: &Path, address: &str) -> Vec<String> {
    let Ok(output) = Command::new("addr2line")
        .args(["-e"])
        .arg(artifact)
        .args(["-f", "-i", "-C", "-s", address])
        .stdin(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // addr2line emits alternating function and location lines, one pair per
    // inlined frame.
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    lines
        .chunks(2)
        .filter_map(|pair| match pair {
            [function, location] if !location.starts_with("??") => {
                Some(if function.starts_with("??") {
                    location.to_string()
                } else {
                    format!("{function} ({location})")
                })
            }
            _ => None,
        })
        .collect()
}

/// Falls back to naming the function containing an address.
fn enclosing_symbol(symbols: &BTreeMap<String, u64>, address: &str) -> Option<String> {
    let address = u64::from_str_radix(address.trim_start_matches("0x"), 16).ok()?;
    symbols
        .iter()
        .filter(|(_, start)| **start <= address)
        .max_by_key(|(_, start)| **start)
        .map(|(name, _)| name.clone())
}

#[derive(Debug)]
pub struct Captured {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

/// A staging directory the analyzer container can read.
fn stage_dir(case_id: &str) -> Result<tempfile::TempDir, SymbolicError> {
    // The case id is validated to a conservative charset, but the prefix is
    // fixed and the random component comes from tempfile regardless.
    let _ = case_id;
    tempfile::Builder::new()
        .prefix("trace-check-symbolic-")
        .tempdir_in("/tmp")
        .map_err(|e| SymbolicError::Io(format!("cannot create a staging directory: {e}")))
}

/// Makes the staging directory traversable by the container's non-root user.
/// Lets the container's non-root user write into a staged directory.
fn make_writable(dir: &Path) -> Result<(), SymbolicError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o777))
        .map_err(|e| SymbolicError::Io(format!("{}: {e}", dir.display())))
}

fn make_readable(dir: &Path) -> Result<(), SymbolicError> {
    use std::os::unix::fs::PermissionsExt;
    let apply = |path: &Path, mode: u32| -> Result<(), SymbolicError> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| SymbolicError::Io(format!("{}: {e}", path.display())))
    };
    apply(dir, 0o755)?;
    for entry in
        std::fs::read_dir(dir).map_err(|e| SymbolicError::Io(format!("{}: {e}", dir.display())))?
    {
        let entry = entry.map_err(|e| SymbolicError::Io(e.to_string()))?;
        apply(&entry.path(), 0o755)?;
    }
    Ok(())
}

/// Runs the analyzer with bounded output and a wall-clock limit.
///
/// Both pipes are drained concurrently, the same discipline M2's runner uses: a
/// bounded read on one pipe deadlocks against a full buffer on the other.
fn run_bounded(program: &str, args: &[String], limit: Duration) -> Result<Captured, SymbolicError> {
    let rendered = format!("{program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SymbolicError::Spawn {
            command: rendered.clone(),
            source: e.to_string(),
        })?;

    let (sender, receiver) = std::sync::mpsc::channel();
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
        let sender = sender.clone();
        readers.push(std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 64 * 1024];
            let mut overflow = false;
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        if buffer.len() + count > MAX_OUTPUT_BYTES {
                            overflow = true;
                            break;
                        }
                        buffer.extend_from_slice(&chunk[..count]);
                    }
                }
            }
            let _ = sender.send((
                name,
                String::from_utf8_lossy(&buffer).into_owned(),
                overflow,
            ));
        }));
    }
    drop(sender);

    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SymbolicError::Timeout {
                        command: rendered,
                        limit,
                    });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return Err(SymbolicError::Spawn {
                    command: rendered,
                    source: e.to_string(),
                })
            }
        }
    };

    let mut streams = BTreeMap::new();
    let mut overflowed = false;
    for (name, text, overflow) in receiver.iter() {
        overflowed |= overflow;
        streams.insert(name, text);
    }
    for reader in readers {
        let _ = reader.join();
    }
    if overflowed {
        return Err(SymbolicError::OutputTooLarge {
            command: rendered,
            limit: MAX_OUTPUT_BYTES,
        });
    }

    Ok(Captured {
        stdout: streams.remove("stdout").unwrap_or_default(),
        stderr: streams.remove("stderr").unwrap_or_default(),
        exit_code: status.code(),
    })
}

fn tool_version(program: &str) -> String {
    Command::new(program)
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

    /// Real BINSEC output for the secret-indexed lookup, captured during the
    /// feasibility spike.
    const LEAKY: &str = "\
[checkct:result] Instruction 0x2016b3 has memory access leak (0.029s)
[sse:info] SMT queries
             Satisfiability queries
               total          0
               sat            0
               unsat          0
               unknown        0
           Exploration
             total paths                      1
             completed/cut paths              1
             pending paths                    0
             max path depth                   10
[checkct:result] Program status is : insecure (0.029)
[checkct:info] 1 / 1 control flow checks pass
[checkct:info] 7 / 8 memory access checks pass
";

    /// Real output for the masked scan.
    const SECURE: &str = "\
[sse:info] SMT queries
             Satisfiability queries
               total          2
               sat            1
               unsat          1
               unknown        0
           Exploration
             total paths                      1
             completed/cut paths              1
             pending paths                    0
             max path depth                   120
[checkct:result] Program status is : secure (0.052)
[checkct:info] 1 / 1 control flow checks pass
[checkct:info] 30 / 30 memory access checks pass
";

    /// Real output for exploration cut short by a depth bound.
    const INCOMPLETE: &str = "\
[sse:info] SMT queries
             Satisfiability queries
               total          4
               sat            2
               unsat          2
               unknown        0
           Exploration
             total paths                      10
             completed/cut paths              7
             pending paths                    0
             max path depth                   44
[checkct:result] Program status is : unknown (0.047)
[checkct:info] 20 / 20 control flow checks pass
[checkct:info] 43 / 43 memory access checks pass
";

    fn case(expected: &str, max_depth: u32) -> VerificationCase {
        VerificationCase {
            id: "c".into(),
            description: String::new(),
            function: "f".into(),
            entry_symbol: "tc_harness_f".into(),
            halt_symbol: "tc_halt".into(),
            secret_globals: vec!["TC_SECRET".into()],
            public_globals: vec!["TC_TABLE".into()],
            assumptions: vec![],
            features: vec![CheckFeature::ControlFlow, CheckFeature::MemoryAccess],
            max_depth,
            solver_timeout_secs: 30,
            wall_timeout_secs: 900,
            expected_outcome: expected.into(),
            rationale: String::new(),
        }
    }

    /// The analyzer reported reaching the declared function.
    fn reached() -> TargetEvidence {
        TargetEvidence {
            function: "f".into(),
            entry_symbol: "tc_harness_f".into(),
            reached: true,
            address: Some("0x2014c0".into()),
            directive: "reach <f>".into(),
        }
    }

    /// The analyzer never reported reaching it.
    fn unreached() -> TargetEvidence {
        TargetEvidence {
            reached: false,
            address: None,
            ..reached()
        }
    }

    fn ok() -> Captured {
        Captured {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
        }
    }

    /// Statistics are parsed out of the analyzer's real report format.
    #[test]
    fn parses_real_analyzer_output() {
        let stats = parse_exploration(LEAKY);
        assert_eq!(stats.analyzer_status.as_deref(), Some("insecure"));
        assert_eq!(stats.total_paths, Some(1));
        assert_eq!(stats.completed_paths, Some(1));
        assert_eq!(stats.pending_paths, Some(0));
        assert_eq!(stats.unknown_queries, Some(0));
        assert_eq!(stats.memory_checks_passed, Some(7));
        assert_eq!(stats.memory_checks_total, Some(8));
        assert_eq!(stats.control_flow_checks_total, Some(1));
        assert!(stats.is_complete());
        assert_eq!(stats.performed_checks(), 9);
    }

    /// A localized memory-access leak becomes a divergence with its address.
    #[test]
    fn parses_a_memory_divergence() {
        let divergences = parse_divergences(LEAKY, Path::new("/nonexistent"), &BTreeMap::new());
        assert_eq!(divergences.len(), 1);
        assert_eq!(divergences[0].kind, CheckFeature::MemoryAccess);
        assert_eq!(divergences[0].instruction, "0x2016b3");
    }

    /// Control-flow leaks are distinguished from memory ones, and all sites are
    /// retained rather than collapsed.
    #[test]
    fn parses_multiple_control_flow_divergences() {
        let output = "\
[checkct:result] Instruction 0x2015f4 has control flow leak (0.037s)
[checkct:result] Instruction 0x2015fd has control flow leak (0.038s)
[checkct:result] Program status is : insecure (0.04)
";
        let divergences = parse_divergences(output, Path::new("/nonexistent"), &BTreeMap::new());
        assert_eq!(divergences.len(), 2);
        assert!(divergences
            .iter()
            .all(|d| d.kind == CheckFeature::ControlFlow));
    }

    /// A reported leak classifies as LEAK_DETECTED with both kinds counted.
    #[test]
    fn a_reported_leak_is_detected() {
        let stats = parse_exploration(LEAKY);
        let divergences = parse_divergences(LEAKY, Path::new("/nonexistent"), &BTreeMap::new());
        let (outcome, message) = classify(
            &case("LEAK_DETECTED", 1000),
            &stats,
            &divergences,
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::LeakDetected);
        assert!(message.contains("1 secret-dependent memory access"));
    }

    /// A complete, clean, check-performing run is VERIFIED_BOUNDED, and the
    /// message scopes the claim.
    #[test]
    fn a_complete_clean_run_is_verified_bounded() {
        let stats = parse_exploration(SECURE);
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::VerifiedBounded);
        assert!(message.contains("within the declared input domain"));
        assert!(message.contains("not a claim about untested domains"));
    }

    /// The analyzer's own `unknown` is inconclusive.
    #[test]
    fn an_unknown_verdict_is_inconclusive() {
        let stats = parse_exploration(INCOMPLETE);
        let (outcome, message) =
            classify(&case("INCONCLUSIVE", 40), &stats, &[], &ok(), &reached());
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("7 of 10 paths"));
    }

    /// A `secure` verdict over incomplete exploration is still inconclusive.
    /// This is the check that stops a partial state-space sweep from being
    /// reported as a verification result.
    #[test]
    fn secure_but_incomplete_is_inconclusive() {
        let output = SECURE.replace(
            "completed/cut paths              1",
            "completed/cut paths              0",
        );
        let stats = parse_exploration(&output);
        assert_eq!(stats.analyzer_status.as_deref(), Some("secure"));
        assert!(!stats.is_complete());
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("exploration was incomplete"));
    }

    /// A `secure` verdict with pending paths is inconclusive.
    #[test]
    fn secure_with_pending_paths_is_inconclusive() {
        let output = SECURE.replace(
            "pending paths                    0",
            "pending paths                    3",
        );
        let stats = parse_exploration(&output);
        let (outcome, _) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
    }

    /// A `secure` verdict with an unknown solver answer is inconclusive.
    #[test]
    fn secure_with_unknown_queries_is_inconclusive() {
        let output = SECURE.replace("unknown        0", "unknown        1");
        let stats = parse_exploration(&output);
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("returned unknown"));
    }

    /// A `secure` verdict that discharged no checks verified nothing.
    #[test]
    fn secure_with_zero_checks_is_inconclusive() {
        let output = SECURE
            .replace(
                "1 / 1 control flow checks pass",
                "0 / 0 control flow checks pass",
            )
            .replace(
                "30 / 30 memory access checks pass",
                "0 / 0 memory access checks pass",
            );
        let stats = parse_exploration(&output);
        assert_eq!(stats.performed_checks(), 0);
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(
            message.contains("no control-flow check was performed"),
            "{message}"
        );
        assert!(
            message.contains("control-flow noninterference was not established"),
            "{message}"
        );
    }

    /// Reaching the depth bound is inconclusive even with a clean verdict.
    #[test]
    fn reaching_the_depth_bound_is_inconclusive() {
        let stats = parse_exploration(SECURE);
        // The spike's masked scan reached depth 120.
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 120),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("depth bound"));
    }

    /// Output with no verdict at all is inconclusive, never a pass.
    #[test]
    fn missing_verdict_is_inconclusive() {
        let stats = parse_exploration("some unrelated text");
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("no verdict"));
    }

    /// A non-zero analyzer exit is inconclusive regardless of what it printed.
    #[test]
    fn a_failed_analyzer_run_is_inconclusive() {
        let stats = parse_exploration(SECURE);
        let failed = Captured {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(2),
        };
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &failed,
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("exited with code 2"));
    }

    /// Truncated output cannot yield a clean verdict.
    #[test]
    fn truncated_output_is_inconclusive() {
        let truncated = &SECURE[..SECURE.len() / 2];
        let stats = parse_exploration(truncated);
        let (outcome, _) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
    }

    /// A clean, complete run establishes nothing when the analyzer never
    /// reported reaching the declared function.
    ///
    /// The reviewed hole: `function` and `entry_symbol` were independent, both
    /// only checked for existence, so pairing a vulnerable function with a safe
    /// harness reported VERIFIED_BOUNDED for code that was never analyzed.
    #[test]
    fn a_clean_run_that_never_reached_the_target_is_inconclusive() {
        let stats = parse_exploration(SECURE);
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &unreached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert_ne!(outcome, Outcome::VerifiedBounded);
        assert!(message.contains("never reached `f`"), "{message}");
        assert!(message.contains("tc_harness_f"), "{message}");
    }

    /// A leak found while the declared function was never reached is not
    /// attributed to it, and is not swallowed either.
    #[test]
    fn a_leak_without_target_evidence_is_not_attributed() {
        let divergences = parse_divergences(LEAKY, Path::new("/nonexistent"), &BTreeMap::new());
        let stats = parse_exploration(LEAKY);
        let (outcome, message) = classify(
            &case("LEAK_DETECTED", 1000),
            &stats,
            &divergences,
            &ok(),
            &unreached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("never reached `f`"), "{message}");
        assert!(
            message.contains("divergence site(s)"),
            "the finding must not be hidden: {message}"
        );
    }

    /// The script asks the analyzer for that evidence.
    #[test]
    fn the_script_asks_whether_the_target_was_reached() {
        let verifier = Verifier {
            container_tool: "podman".into(),
            rustc_version: "rustc 1.97.0".into(),
            analyzer_build: None,
        };
        let script = verifier.script(&case("LEAK_DETECTED", 1000));
        assert!(script.contains("reach <f>"), "{script}");
    }

    /// The analyzer's own "reached address" line is read back, matched on the
    /// symbol rather than an address so the linker's layout does not matter.
    #[test]
    fn a_reached_target_is_parsed_from_the_analyzer_output() {
        let output = "[sse:result] Path 0 reached address 0x2014c0 (<masked_scan>) (0 to go)";
        assert_eq!(
            parse_reached(output, "masked_scan").as_deref(),
            Some("0x2014c0")
        );
        // A different function in the same run is not evidence for this one.
        assert_eq!(parse_reached(output, "secret_lookup"), None);
        assert_eq!(parse_reached("", "masked_scan"), None);
    }

    /// A `secure` verdict alongside counts that do not add up is contradictory,
    /// and the counts win.
    #[test]
    fn secure_with_unaccounted_obligations_is_inconclusive() {
        let output = SECURE.replace(
            "30 / 30 memory access checks pass",
            "0 / 1 memory access checks pass",
        );
        let stats = parse_exploration(&output);
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(
            message.contains("only 0 of 1 memory-access check(s) passed"),
            "{message}"
        );
        assert!(message.contains("contradict"), "{message}");
    }

    /// A class the case asked for but the analyzer said nothing about is
    /// missing evidence, not zero work.
    #[test]
    fn a_requested_check_class_with_no_reported_count_is_inconclusive() {
        let output = SECURE.replace("[checkct:info] 30 / 30 memory access checks pass\n", "");
        let stats = parse_exploration(&output);
        assert_eq!(stats.checks(CheckFeature::MemoryAccess), (None, None));
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("reported no count"), "{message}");
    }

    /// Checking control flow alone cannot be mistaken for a full result.
    ///
    /// This is the reviewed case: the known secret-indexed lookup reports
    /// `secure` under control-flow-only checks, because its instruction path
    /// really is secret-independent. The verdict is legitimate and narrow, and
    /// the message has to say which property was left out.
    #[test]
    fn a_control_flow_only_result_names_what_it_did_not_check() {
        let output = SECURE.replace("[checkct:info] 30 / 30 memory access checks pass\n", "");
        let stats = parse_exploration(&output);
        let mut narrow = case("VERIFIED_BOUNDED", 1000);
        narrow.features = vec![CheckFeature::ControlFlow];
        let (outcome, message) = classify(&narrow, &stats, &[], &ok(), &reached());
        assert_eq!(outcome, Outcome::VerifiedBounded);
        assert!(
            message.contains("control-flow noninterference established"),
            "{message}"
        );
        assert!(
            message.contains("memory-address noninterference was NOT checked"),
            "{message}"
        );
        assert_eq!(
            unchecked_properties(&narrow.features),
            vec!["memory-address noninterference"]
        );
    }

    /// A full result reports nothing as unchecked.
    #[test]
    fn a_full_result_leaves_no_modeled_property_unchecked() {
        assert!(unchecked_properties(&CheckFeature::all()).is_empty());
    }

    /// Missing depth evidence is not treated as depth zero.
    #[test]
    fn a_missing_max_depth_is_inconclusive() {
        let output = SECURE.replace("             max path depth                   120\n", "");
        let stats = parse_exploration(&output);
        assert_eq!(stats.max_path_depth, None);
        let (outcome, message) = classify(
            &case("VERIFIED_BOUNDED", 1000),
            &stats,
            &[],
            &ok(),
            &reached(),
        );
        assert_eq!(outcome, Outcome::Inconclusive);
        assert!(message.contains("no maximum path depth"), "{message}");
    }

    /// A case must declare its observation model rather than inheriting the
    /// analyzer's default.
    #[test]
    fn a_case_with_no_declared_features_is_rejected() {
        let error = case_file(|value| {
            value["cases"][0]["features"] = serde_json::json!([]);
        })
        .expect_err("an unstated observation model is refused");
        assert!(error.to_string().contains("observation model"), "{error}");
    }

    /// Omitting the field entirely is refused too, so the requirement cannot be
    /// sidestepped.
    #[test]
    fn a_case_missing_the_features_field_is_rejected() {
        let error = case_file(|value| {
            value["cases"][0]
                .as_object_mut()
                .expect("a case object")
                .remove("features");
        })
        .expect_err("features is required");
        assert!(error.to_string().contains("features"), "{error}");
    }

    /// A duplicated feature is a case-file mistake, not a silently deduplicated
    /// list.
    #[test]
    fn a_duplicated_feature_is_rejected() {
        let error = case_file(|value| {
            value["cases"][0]["features"] = serde_json::json!(["control-flow", "control-flow"]);
        })
        .expect_err("a duplicate is refused");
        assert!(error.to_string().contains("twice"), "{error}");
    }

    /// Real relational query as the analyzer cached it, model included.
    const RELATIONAL_QUERY: &str = "\
(set-logic QF_ABV)
(declare-fun mirror_TC_SECRET!1 () (_ BitVec 8))
(declare-fun TC_SECRET!1 () (_ BitVec 8))
(assert !2) (check-sat)
; sat
(get-value (mirror_TC_SECRET!1))
; ((mirror_TC_SECRET!1 #xff))
(get-value (TC_SECRET!1))
; ((TC_SECRET!1 #xfe))
";

    /// Real path-feasibility query: one copy only, so not a counterexample.
    const PATH_QUERY: &str = "\
(set-logic QF_ABV)
(declare-fun TC_SECRET!1 () (_ BitVec 8))
(assert !0) (check-sat)
; sat
(get-value (TC_SECRET!1))
; ((TC_SECRET!1 #x06))
";

    fn smt_dir(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        for (name, body) in files {
            std::fs::write(dir.path().join(name), body).expect("write query");
        }
        dir
    }

    /// A relational model is read back as the counterexample pair.
    #[test]
    fn a_relational_model_yields_a_counterexample_pair() {
        let dir = smt_dir(&[("query_10.smt2", RELATIONAL_QUERY)]);
        let found = parse_counterexamples(dir.path(), &["TC_SECRET".to_string()]);
        assert_eq!(
            found,
            vec![Counterexample {
                global: "TC_SECRET".into(),
                left: "#xfe".into(),
                right: "#xff".into(),
                query: "query_10.smt2".into(),
            }]
        );
    }

    /// A single-copy query is a path-feasibility question, not a
    /// counterexample: one value cannot witness a difference.
    #[test]
    fn a_single_copy_model_is_not_a_counterexample() {
        let dir = smt_dir(&[("query_11.smt2", PATH_QUERY)]);
        assert!(parse_counterexamples(dir.path(), &["TC_SECRET".to_string()]).is_empty());
    }

    /// An unsatisfiable query has no model to report.
    #[test]
    fn an_unsat_query_yields_no_counterexample() {
        let unsat = RELATIONAL_QUERY.replace("; sat", "; unsat");
        let dir = smt_dir(&[("query_10.smt2", &unsat)]);
        assert!(parse_counterexamples(dir.path(), &["TC_SECRET".to_string()]).is_empty());
    }

    /// Equal values are not a counterexample, however the model is recorded.
    #[test]
    fn an_identical_pair_is_refused_as_a_witness() {
        let vacuous = RELATIONAL_QUERY.replace("#xff", "#xfe");
        let dir = smt_dir(&[("query_10.smt2", &vacuous)]);
        assert!(parse_counterexamples(dir.path(), &["TC_SECRET".to_string()]).is_empty());
    }

    /// Selection is deterministic: the lowest-sorting query wins, so a report
    /// does not depend on directory order.
    #[test]
    fn the_reported_witness_is_deterministic() {
        let other = RELATIONAL_QUERY.replace("#xfe", "#xfb");
        let dir = smt_dir(&[
            ("query_4.smt2", &other),
            ("query_10.smt2", RELATIONAL_QUERY),
        ]);
        let found = parse_counterexamples(dir.path(), &["TC_SECRET".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].query, "query_10.smt2");
        assert_eq!(found[0].left, "#xfe");
    }

    /// A missing cache directory is not a failure: many leaks are settled
    /// without a solver call, and that is reported rather than erroring.
    #[test]
    fn a_missing_query_cache_yields_no_counterexample() {
        let found =
            parse_counterexamples(Path::new("/nonexistent/smt"), &["TC_SECRET".to_string()]);
        assert!(found.is_empty());
    }

    /// `mirror_` and plain copies are never confused for one another.
    #[test]
    fn mirror_and_plain_model_values_are_distinguished() {
        assert_eq!(
            model_value(RELATIONAL_QUERY, "TC_SECRET", false).as_deref(),
            Some("#xfe")
        );
        assert_eq!(
            model_value(RELATIONAL_QUERY, "TC_SECRET", true).as_deref(),
            Some("#xff")
        );
        assert_eq!(model_value(PATH_QUERY, "TC_SECRET", true), None);
    }

    /// The generated script uses BINSEC's syntax and carries the declared
    /// lattice, assumptions and boundaries.
    #[test]
    fn script_declares_the_security_lattice() {
        let verifier = Verifier {
            container_tool: "podman".into(),
            rustc_version: "rustc 1.97.0".into(),
            analyzer_build: None,
        };
        let mut target = case("LEAK_DETECTED", 1000);
        target.assumptions = vec!["TC_PUBLIC < 4".into()];
        let script = verifier.script(&target);
        assert!(script.contains("starting from <tc_harness_f>"));
        assert!(script.contains("secret global TC_SECRET"));
        assert!(script.contains("public global TC_TABLE"));
        assert!(script.contains("assume TC_PUBLIC < 4"));
        assert!(script.contains("halt at <tc_halt>"));
        assert!(script.contains("explore all"));
    }

    fn case_file(patch: impl Fn(&mut serde_json::Value)) -> Result<CaseFile, SymbolicError> {
        let mut value = serde_json::json!({
            "schema_version": 1,
            "target_source": "src/targets.rs",
            "cases": [{
                "id": "a",
                "function": "f",
                "entry_symbol": "tc_harness_f",
                "halt_symbol": "tc_halt",
                "secret_globals": ["TC_SECRET"],
                "public_globals": ["TC_TABLE"],
                "features": ["control-flow", "memory-access"],
                "max_depth": 1000,
                "expected_outcome": "LEAK_DETECTED"
            }]
        });
        patch(&mut value);
        let file: CaseFile =
            serde_json::from_value(value).map_err(|e| SymbolicError::Schema(e.to_string()))?;
        file.validate()?;
        Ok(file)
    }

    /// A well-formed case file validates.
    #[test]
    fn valid_case_file_is_accepted() {
        assert!(case_file(|_| {}).is_ok());
    }

    /// A case declaring no secret has no relational property to check.
    #[test]
    fn a_case_with_no_secret_is_rejected() {
        let error =
            case_file(|v| v["cases"][0]["secret_globals"] = serde_json::json!([])).unwrap_err();
        assert!(error.to_string().contains("no secret globals"));
    }

    /// A global cannot be both secret and public.
    #[test]
    fn a_global_cannot_be_both_secret_and_public() {
        let error = case_file(|v| {
            v["cases"][0]["public_globals"] = serde_json::json!(["TC_SECRET"]);
        })
        .unwrap_err();
        assert!(error.to_string().contains("both secret and public"));
    }

    /// NO_LEAK_OBSERVED belongs to the dynamic backend and is refused here, so
    /// the two kinds of evidence keep distinct names.
    #[test]
    fn no_leak_observed_is_refused_for_symbolic_cases() {
        let error = case_file(|v| {
            v["cases"][0]["expected_outcome"] = serde_json::json!("NO_LEAK_OBSERVED");
        })
        .unwrap_err();
        assert!(error.to_string().contains("only the dynamic backend"));
    }

    /// An unknown expected outcome is rejected up front.
    #[test]
    fn an_unknown_expected_outcome_is_rejected() {
        let error = case_file(|v| {
            v["cases"][0]["expected_outcome"] = serde_json::json!("SECURE");
        })
        .unwrap_err();
        assert!(error.to_string().contains("unknown outcome"));
    }

    /// A symbol name outside the permitted charset is rejected before it can
    /// reach a generated script.
    #[test]
    fn an_injected_symbol_name_is_rejected() {
        for bad in ["TC; halt at <x>", "a b", "", "x\ny"] {
            let error = case_file(|v| {
                v["cases"][0]["secret_globals"] = serde_json::json!([bad]);
            })
            .unwrap_err();
            assert!(
                error.to_string().contains("not a plain symbol name")
                    || error.to_string().contains("no secret globals"),
                "{bad:?} should be rejected: {error}"
            );
        }
    }

    /// A zero depth bound would explore nothing.
    #[test]
    fn a_zero_depth_bound_is_rejected() {
        let error = case_file(|v| v["cases"][0]["max_depth"] = serde_json::json!(0)).unwrap_err();
        assert!(error.to_string().contains("max_depth 0"));
    }

    /// Duplicate case ids are rejected so lookups stay unambiguous.
    #[test]
    fn duplicate_case_ids_are_rejected() {
        let error = case_file(|v| {
            let first = v["cases"][0].clone();
            v["cases"] = serde_json::json!([first.clone(), first]);
        })
        .unwrap_err();
        assert!(error.to_string().contains("duplicate case id"));
    }

    /// An unsupported schema version is refused rather than guessed at.
    #[test]
    fn an_unsupported_schema_version_is_refused() {
        let path = std::env::temp_dir().join("trace-check-bad-symbolic-cases.json");
        std::fs::write(
            &path,
            r#"{"schema_version":99,"target_source":"x","cases":[]}"#,
        )
        .unwrap();
        let error = CaseFile::load(&path).unwrap_err();
        assert!(matches!(
            error,
            SymbolicError::UnsupportedSchema { found: 99, .. }
        ));
    }

    /// A missing container tool is an explicit dependency error naming the fix.
    #[test]
    fn a_missing_container_tool_is_actionable() {
        let rendered = SymbolicError::MissingContainerTool.to_string();
        assert!(rendered.contains("podman"));
        assert!(rendered.contains("docker"));
    }

    /// A missing analyzer image names the pull command.
    #[test]
    fn a_missing_image_names_the_pull_command_for_the_selected_runtime() {
        let rendered = SymbolicError::MissingImage {
            image: ANALYZER_IMAGE.to_string(),
            tool: "docker".to_string(),
            detail: "not in docker's image store".to_string(),
        }
        .to_string();
        assert!(rendered.contains("docker pull"), "{rendered}");
        assert!(!rendered.contains("podman pull"), "{rendered}");
    }

    fn runtimes() -> Vec<String> {
        CONTAINER_RUNTIMES.iter().map(|t| t.to_string()).collect()
    }

    /// The runtime holding the image is selected even when another one comes
    /// first on PATH.
    ///
    /// This is the CI failure that made the M4 job red: the image was pulled
    /// with Docker, Podman was picked because it probes first, and every case
    /// failed with "not present locally" before any analysis ran.
    #[test]
    fn the_runtime_holding_the_image_is_selected_over_the_first_on_path() {
        let chosen = select_runtime(&runtimes(), |tool| match tool {
            "podman" => RuntimeState::WithoutImage,
            "docker" => RuntimeState::WithImage,
            _ => RuntimeState::Absent,
        });
        assert_eq!(chosen.as_deref(), Ok("docker"));
    }

    /// Preference order still decides when more than one runtime has the image.
    #[test]
    fn the_preferred_runtime_wins_when_both_have_the_image() {
        let chosen = select_runtime(&runtimes(), |_| RuntimeState::WithImage);
        assert_eq!(chosen.as_deref(), Ok("podman"));
    }

    /// When no runtime has the image, the usable ones are reported so the error
    /// can name a command that works.
    #[test]
    fn with_no_image_anywhere_the_usable_runtimes_are_reported() {
        let chosen = select_runtime(&runtimes(), |tool| match tool {
            "docker" => RuntimeState::WithoutImage,
            _ => RuntimeState::Absent,
        });
        assert_eq!(chosen, Err(vec!["docker".to_string()]));
    }

    /// Nothing installed is distinguishable from installed-but-empty.
    #[test]
    fn no_runtime_at_all_is_distinguishable_from_a_missing_image() {
        let chosen = select_runtime(&runtimes(), |_| RuntimeState::Absent);
        assert_eq!(chosen, Err(Vec::new()));
    }

    /// An explicit runtime choice is restricted to the runtimes actually
    /// supported, so a typo cannot turn into a command that is run.
    #[test]
    fn an_unknown_explicit_runtime_is_rejected() {
        let error = match Verifier::prepare_with(Some("containerd")) {
            Err(error) => error,
            Ok(_) => panic!("an unsupported runtime name must be rejected"),
        };
        assert!(error.to_string().contains("containerd"), "{error}");
        assert!(error.to_string().contains("podman, docker"), "{error}");
    }

    /// The analyzer image is pinned by digest, not by a mutable tag.
    #[test]
    fn the_analyzer_image_is_pinned_by_digest() {
        assert!(
            ANALYZER_IMAGE.contains("@sha256:"),
            "a tag would let the analyzer change underneath a recorded result"
        );
    }

    /// An address resolves to its enclosing symbol when debug info is absent.
    #[test]
    fn addresses_fall_back_to_the_enclosing_symbol() {
        let mut symbols = BTreeMap::new();
        symbols.insert("secret_lookup".to_string(), 0x2016a0);
        symbols.insert("tc_halt".to_string(), 0x201700);
        assert_eq!(
            enclosing_symbol(&symbols, "0x2016b3").as_deref(),
            Some("secret_lookup")
        );
        assert_eq!(enclosing_symbol(&symbols, "0x100").as_deref(), None);
    }
}
