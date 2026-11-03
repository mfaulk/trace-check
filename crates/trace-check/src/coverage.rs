//! Per-case LLVM source coverage from an instrumented discovery artifact.
//!
//! This module produces **no security evidence**. It executes candidate inputs
//! in a separately compiled, instrumented binary and reports which regions of
//! the developer's library each input reached. Nothing here can establish that
//! a function is constant-time, and a clean result from this artifact means
//! precisely nothing: see [`crate::check`] for the only thing that does.
//!
//! # Why `llvm-cov`, and not the cheaper thing
//!
//! A `.profraw` can be read with `llvm-profdata show --counts`, which skips the
//! coverage map and is three times faster. The M7.1 spike measured it on
//! `crypto::hidden::nested_modes` and found the input that reaches the planted
//! vulnerability sets **no physical counter at all** — every region it covers
//! is a counter *expression*, a subtraction over sibling counters, which only
//! `llvm-cov` evaluates. A counter-only fingerprint scored the leak-reaching
//! candidate as the least interesting in its batch. So the expensive decode is
//! load-bearing, and it is parallelized rather than avoided.
//!
//! # Granularity is reported, not implied
//!
//! Branch coverage needs `-Z coverage-options=branch` and comparison tracing
//! needs SanitizerCoverage; both are nightly-only and this project pins a
//! stable toolchain. What is available is **source region** coverage, and
//! [`FEEDBACK`] and [`GRANULARITY`] say so. Region coverage and edge coverage
//! are not interchangeable and a report that used one word for the other would
//! be claiming a finer search than it ran.
//!
//! # Absent evidence is never zero coverage
//!
//! Every failure mode — a missing profile, a corrupt one, a profile carrying a
//! duplicate record, a decode error, a case that never completed — becomes an
//! [`ExecutionStatus`] other than [`ExecutionStatus::Observed`], and such an
//! observation contributes no coverage and is not eligible to be a mutation
//! seed. The alternative is worse than it sounds: an empty region set reads as
//! "this input reached nothing new", so a silently failing decode would make
//! every candidate look uninteresting and exploration would quietly do nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::dynamic_harness::{
    self, DynamicError, BASELINE_PROFILE, DISCOVERY_MODE_MARKER, DRAIN_PROFILE,
};
use crate::native::{self, Limits};

/// The feedback mechanism this build implements.
pub const FEEDBACK: &str = "llvm-regions";

/// What one unit of that feedback is, in words a report can print verbatim.
pub const GRANULARITY: &str = "LLVM source regions (code regions only; branch, edge and \
                               comparison feedback are unavailable on a stable toolchain)";

/// Environment override for the directory holding `llvm-profdata` and
/// `llvm-cov`.
pub const LLVM_TOOLS_ENV: &str = "TRACE_CHECK_LLVM_TOOLS";

/// Candidates decoded per round before results are folded back in.
///
/// Decoding is ~13 ms per case and embarrassingly parallel, while execution is
/// ~0.02 ms. Rounds exist to recover that parallelism without giving up
/// determinism: a round's membership is a pure function of the queue state, and
/// its results are folded in a fixed order.
pub const DEFAULT_ROUND_SIZE: usize = 64;

/// One source region in the discovery artifact's coverage map.
///
/// Identity is a source coordinate rather than an instruction address, and it
/// is scoped to **one** discovery artifact. It is stable across re-runs of that
/// artifact, which is what per-case comparison needs, and is deliberately not
/// assumed stable across compiler versions or source edits — a report records
/// the coverage-map identity alongside it so a changed map is visible rather
/// than silently reinterpreted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Region {
    /// Source file, as the coverage map records it.
    pub file: String,
    pub line_start: u32,
    pub column_start: u32,
    pub line_end: u32,
    pub column_end: u32,
}

impl Region {
    /// `file:line:col-line:col`, with the file shortened to its name.
    pub fn describe(&self) -> String {
        let name = self
            .file
            .rsplit('/')
            .next()
            .unwrap_or(self.file.as_str())
            .to_string();
        format!(
            "{name}:{}:{}-{}:{}",
            self.line_start, self.column_start, self.line_end, self.column_end
        )
    }
}

/// A set of regions. Ordered, so every derived report is deterministic.
pub type RegionSet = BTreeSet<Region>;

/// The discovery artifact's coverage map, read once.
///
/// `id` is a hash over every region the map declares — covered or not — so a
/// recompilation that moved a region changes it. Two observations may only be
/// compared when they carry the same `id`.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageMap {
    pub id: String,
    /// Regions the map declares, over every file.
    pub total_regions: usize,
    /// Regions declared in files inside the library's scope.
    pub in_scope_regions: usize,
    /// In-scope source files, for the report to name what was measured.
    pub files: Vec<String>,
    /// Coverage records whose function matched the contract's target.
    pub target_records: usize,
}

/// Why an observation does or does not carry usable coverage.
///
/// Only [`ExecutionStatus::Observed`] does. Everything else is retained and
/// reported rather than dropped, because a run that failed to measure half its
/// candidates is a different thing from a run that measured them and found
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum ExecutionStatus {
    /// The case completed and its profile decoded.
    Observed,
    /// The case never printed its completion marker.
    DidNotComplete,
    /// No profile was written for the case.
    ProfileMissing,
    /// A profile was written but cannot be trusted.
    ProfileInvalid { detail: String },
    /// `llvm-profdata` or `llvm-cov` rejected the profile or failed.
    DecodeFailed { detail: String },
}

impl ExecutionStatus {
    /// Whether this observation's coverage may be used as feedback.
    pub fn usable(&self) -> bool {
        matches!(self, ExecutionStatus::Observed)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ExecutionStatus::Observed => "observed",
            ExecutionStatus::DidNotComplete => "did-not-complete",
            ExecutionStatus::ProfileMissing => "profile-missing",
            ExecutionStatus::ProfileInvalid { .. } => "profile-invalid",
            ExecutionStatus::DecodeFailed { .. } => "decode-failed",
        }
    }
}

impl fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionStatus::ProfileInvalid { detail }
            | ExecutionStatus::DecodeFailed { detail } => {
                write!(f, "{}: {detail}", self.as_str())
            }
            other => f.write_str(other.as_str()),
        }
    }
}

/// What executing one candidate in the discovery artifact revealed.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageObservation {
    pub case_id: usize,
    /// The discovery artifact this was measured in. Never the security one.
    pub artifact_sha256: String,
    /// The coverage map the regions below are coordinates in.
    pub coverage_map_id: String,
    /// In-scope regions this case covered. Empty unless `status` is `Observed`.
    pub covered_regions: RegionSet,
    /// In-scope coverage records this case entered, by their mangled name.
    ///
    /// A coarser signal than the region set and a more useful priority: a
    /// candidate that entered a function nothing had entered opened a larger
    /// unexplored area than one that reached another region inside a function
    /// already being explored.
    pub covered_functions: BTreeSet<String>,
    /// Whether a coverage record for the contract's own function was executed.
    pub target_invoked: bool,
    pub status: ExecutionStatus,
}

impl CoverageObservation {
    /// Regions in this observation that are not in `seen`.
    ///
    /// Set difference, never a count comparison. An input that takes a deeper
    /// path covers *fewer* total regions than one that returns early — the
    /// M7.1 spike measured exactly that on the nested-predicate fixture — so
    /// "covered more" and "covered something new" are different questions and
    /// only the second one matters.
    pub fn novel(&self, seen: &RegionSet) -> RegionSet {
        if !self.status.usable() {
            return RegionSet::new();
        }
        self.covered_regions.difference(seen).cloned().collect()
    }
}

/// One execution of the discovery artifact over a batch of cases.
#[derive(Debug, Clone)]
pub struct DiscoveryRun {
    /// Case ids this run was asked to execute, from the corpus or the caller.
    pub requested: Vec<usize>,
    /// Ids that printed their completion marker with this run's nonce.
    pub completed: Vec<usize>,
    /// Case count from the run-completion marker, when it was printed.
    pub run_complete: Option<usize>,
    /// Whether the harness reported writing its baseline profile.
    pub baseline_written: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// One observation per requested id, in requested order.
    pub observations: Vec<CoverageObservation>,
}

impl DiscoveryRun {
    /// Observations whose coverage may be used.
    pub fn usable(&self) -> impl Iterator<Item = &CoverageObservation> {
        self.observations
            .iter()
            .filter(|observation| observation.status.usable())
    }

    /// Whether every requested case produced usable coverage.
    pub fn complete(&self) -> bool {
        self.run_complete == Some(self.requested.len())
            && self.baseline_written
            && self.observations.iter().all(|o| o.status.usable())
    }

    /// Why this run was not complete, when it was not.
    pub fn incompleteness(&self) -> Option<String> {
        if !self.baseline_written {
            return Some(
                "the discovery harness did not report writing its baseline profile, so there is \
                 no reference length to validate the per-case profiles against"
                    .to_string(),
            );
        }
        match self.run_complete {
            None => {
                return Some(format!(
                    "the discovery harness never printed its run-completion marker; {} of {} \
                     case(s) reported completing",
                    self.completed.len(),
                    self.requested.len()
                ))
            }
            Some(count) if count != self.requested.len() => {
                return Some(format!(
                    "the discovery harness reported {count} completed case(s) for a batch of {}",
                    self.requested.len()
                ))
            }
            Some(_) => {}
        }
        let failed: Vec<String> = self
            .observations
            .iter()
            .filter(|observation| !observation.status.usable())
            .map(|observation| format!("case {}: {}", observation.case_id, observation.status))
            .collect();
        if failed.is_empty() {
            None
        } else {
            Some(format!(
                "{} of {} candidate(s) produced no usable coverage: {}",
                failed.len(),
                self.requested.len(),
                failed
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        }
    }
}

/// The LLVM tools that read this compiler's profiles.
///
/// Taken from the active toolchain's sysroot, never from `PATH`. A system LLVM
/// of a different version cannot read these profiles, and the failure is not
/// always loud — reading the wrong thing quietly is the outcome this avoids.
#[derive(Debug, Clone, Serialize)]
pub struct LlvmTools {
    pub profdata: PathBuf,
    pub cov: PathBuf,
    /// `llvm-cov`'s self-reported version, which embeds the rustc version.
    pub version: String,
}

impl LlvmTools {
    pub fn locate() -> Result<LlvmTools, CoverageError> {
        let directory = match std::env::var_os(LLVM_TOOLS_ENV) {
            Some(from_env) => PathBuf::from(from_env),
            None => sysroot_tools_dir()?,
        };
        let profdata = directory.join("llvm-profdata");
        let cov = directory.join("llvm-cov");
        for tool in [&profdata, &cov] {
            if !tool.is_file() {
                return Err(CoverageError::ToolsMissing {
                    tried: tool.display().to_string(),
                    from_env: std::env::var_os(LLVM_TOOLS_ENV).is_some(),
                });
            }
        }
        let version = native::tool_version(&cov, &["--version"])
            .unwrap_or_else(|_| "llvm-cov (version unavailable)".to_string());
        Ok(LlvmTools {
            profdata,
            cov,
            version,
        })
    }
}

/// `<sysroot>/lib/rustlib/<target>/bin`, where `rustup component add
/// llvm-tools` installs them.
fn sysroot_tools_dir() -> Result<PathBuf, CoverageError> {
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .map_err(|e| CoverageError::Io(format!("cannot run rustc: {e}")))?;
    if !output.status.success() {
        return Err(CoverageError::Io(
            "`rustc --print sysroot` failed, so the toolchain's LLVM tools cannot be located"
                .to_string(),
        ));
    }
    let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(Path::new(&sysroot)
        .join("lib/rustlib")
        .join(crate::symbolic::SUPPORTED_TARGET)
        .join("bin"))
}

/// Collects per-case coverage from one discovery artifact.
pub struct Collector<'a> {
    tools: &'a LlvmTools,
    artifact: PathBuf,
    artifact_sha256: String,
    /// Directory whose files count as the library. Everything else — the
    /// generated harness, `std`, third-party dependencies — is excluded from
    /// target feedback.
    scope: PathBuf,
    /// The contract's bare function name, for `target_invoked`.
    function: String,
    /// Concurrent decode workers.
    workers: usize,
    limits: Limits,
}

impl<'a> Collector<'a> {
    pub fn new(
        tools: &'a LlvmTools,
        artifact: &Path,
        artifact_sha256: &str,
        library_manifest: &Path,
        function: &str,
        limits: Limits,
    ) -> Collector<'a> {
        // The library's package root, which is what a coverage map records
        // source paths relative to.
        let scope = library_manifest
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        Collector {
            tools,
            artifact: artifact.to_path_buf(),
            artifact_sha256: artifact_sha256.to_string(),
            scope,
            function: function.to_string(),
            workers: decode_workers(),
            limits,
        }
    }

    /// Overrides the decode concurrency. Used by tests to pin it.
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.workers = workers.max(1);
        self
    }

    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    pub fn scope(&self) -> &Path {
        &self.scope
    }

    /// Reads the artifact's coverage map from one profile.
    ///
    /// Fails when the map declares no record for the contract's function. That
    /// is not pedantry: without such a record nothing can be attributed to the
    /// target, and reporting coverage of *something* while the function under
    /// study is invisible would be the most misleading result available.
    pub fn map(&self, profile: &Path) -> Result<CoverageMap, CoverageError> {
        let export = self.export(profile)?;
        let mut declared: RegionSet = RegionSet::new();
        let mut in_scope = RegionSet::new();
        let mut files: BTreeSet<String> = BTreeSet::new();
        let mut target_records = 0usize;
        for function in &export.functions {
            if self.matches_target(&function.name) {
                target_records += 1;
            }
            for region in &function.regions {
                declared.insert(region.region.clone());
                if self.in_scope(&region.region.file) {
                    files.insert(region.region.file.clone());
                    in_scope.insert(region.region.clone());
                }
            }
        }
        if target_records == 0 {
            return Err(CoverageError::TargetNotInMap {
                function: self.function.clone(),
                artifact: self.artifact.display().to_string(),
            });
        }
        if in_scope.is_empty() {
            return Err(CoverageError::ScopeEmpty {
                scope: self.scope.display().to_string(),
            });
        }
        let mut hasher = Sha256::new();
        for region in &declared {
            hasher.update(region.file.as_bytes());
            hasher.update(
                [
                    region.line_start,
                    region.column_start,
                    region.line_end,
                    region.column_end,
                ]
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<u8>>(),
            );
        }
        Ok(CoverageMap {
            id: format!("{:x}", hasher.finalize()),
            total_regions: declared.len(),
            in_scope_regions: in_scope.len(),
            files: files.into_iter().collect(),
            target_records,
        })
    }

    /// Runs one case, then reads the artifact's coverage map from the baseline
    /// profile.
    ///
    /// This is the first thing an exploration does, and it is a gate rather
    /// than a formality. It establishes that the artifact is instrumented, that
    /// the harness writes profiles the tools accept, that the map has a record
    /// for the function under study, and that the library is in scope — before
    /// a single candidate is generated. Every one of those failing later would
    /// look like "no candidate covered anything new".
    ///
    /// The baseline profile is written after a counter reset and before any
    /// case, so its counts are all zero. That is exactly right for reading a
    /// map: the map is which regions *exist*, not which ran.
    pub fn probe_map(
        &self,
        corpus_path: &Path,
        id: usize,
        profile_dir: &Path,
    ) -> Result<(CoverageMap, DiscoveryRun), CoverageError> {
        // A placeholder map id for this one run: the map is what the run is
        // being performed to learn, so the observations it yields are discarded
        // rather than compared against anything.
        let run = self.observe(corpus_path, &[id], profile_dir, "probe")?;
        if !run.baseline_written {
            return Err(CoverageError::NoBaseline {
                detail: run
                    .incompleteness()
                    .unwrap_or_else(|| "no detail".to_string()),
                stderr: first_line(&run.stderr),
            });
        }
        let baseline = profile_dir.join(BASELINE_PROFILE);
        let indexed = profile_dir.join("baseline.profdata");
        self.merge(&baseline, &indexed)?;
        let map = self.map(&indexed)?;
        Ok((map, run))
    }

    /// Executes `ids` in the discovery artifact and decodes their coverage.
    ///
    /// One process for the whole batch, with the profiling counters reset
    /// between cases, so per-case attribution costs no process startup. The
    /// per-case profile lengths are validated against the baseline profile the
    /// harness writes before any case runs; see [`BASELINE_PROFILE`].
    pub fn observe(
        &self,
        corpus_path: &Path,
        ids: &[usize],
        profile_dir: &Path,
        coverage_map_id: &str,
    ) -> Result<DiscoveryRun, CoverageError> {
        if ids.is_empty() {
            return Err(CoverageError::NothingSelected);
        }
        std::fs::create_dir_all(profile_dir)
            .map_err(|e| CoverageError::Io(format!("{}: {e}", profile_dir.display())))?;
        // Stale profiles from an earlier round would be read as this round's
        // coverage, so the directory is cleared rather than written over.
        for id in ids {
            let _ = std::fs::remove_file(profile_dir.join(format!("case-{id}.profraw")));
        }
        let _ = std::fs::remove_file(profile_dir.join(BASELINE_PROFILE));
        let _ = std::fs::remove_file(profile_dir.join(DRAIN_PROFILE));

        let nonce = dynamic_harness::run_nonce();
        let args = vec![
            corpus_path.display().to_string(),
            ids.iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(","),
            nonce.clone(),
            profile_dir.display().to_string(),
        ];
        let run = native::run_process(&self.artifact, &args, self.limits)
            .map_err(|e| CoverageError::Run(e.to_string()))?;

        let completed = dynamic_harness::completed_cases(&run.stdout, &nonce);
        let run_complete = dynamic_harness::run_complete_count(&run.stdout, &nonce);
        let baseline_written = baseline_ok(&run.stdout, &nonce);
        // Only a baseline the harness said it wrote *and* that is on disk can
        // serve as the reference length.
        let expected_len = if baseline_written {
            std::fs::metadata(profile_dir.join(BASELINE_PROFILE))
                .ok()
                .map(|meta| meta.len())
        } else {
            None
        };

        let observations =
            self.decode_all(ids, &completed, profile_dir, expected_len, coverage_map_id);
        Ok(DiscoveryRun {
            requested: ids.to_vec(),
            completed,
            run_complete,
            baseline_written,
            exit_code: run.exit_code,
            stdout: run.stdout,
            stderr: run.stderr,
            observations,
        })
    }

    /// Decodes already-written profiles without re-running the artifact.
    ///
    /// Separate from [`Collector::observe`] so the decode half can be tested
    /// against deliberately damaged profiles — a profile that was truncated,
    /// removed, or grew a duplicate record — which is not something a correctly
    /// behaving harness produces on demand.
    ///
    /// `expected_len` is the baseline profile's length; `None` means there was
    /// no baseline, which makes every profile unvalidatable rather than fine.
    pub fn decode(
        &self,
        ids: &[usize],
        completed: &[usize],
        profile_dir: &Path,
        expected_len: Option<u64>,
        coverage_map_id: &str,
    ) -> Vec<CoverageObservation> {
        self.decode_all(ids, completed, profile_dir, expected_len, coverage_map_id)
    }

    /// Decodes every case's profile, `workers` at a time.
    ///
    /// Results are written into a fixed slot per case, so the output order is
    /// the requested order no matter which worker finished first. Scheduling
    /// cannot affect the result.
    fn decode_all(
        &self,
        ids: &[usize],
        completed: &[usize],
        profile_dir: &Path,
        expected_len: Option<u64>,
        coverage_map_id: &str,
    ) -> Vec<CoverageObservation> {
        let next = AtomicUsize::new(0);
        let slots: Vec<std::sync::Mutex<Option<CoverageObservation>>> =
            ids.iter().map(|_| std::sync::Mutex::new(None)).collect();
        let workers = self.workers.min(ids.len()).max(1);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= ids.len() {
                        return;
                    }
                    let id = ids[index];
                    let observation = self.decode_one(
                        id,
                        completed.contains(&id),
                        profile_dir,
                        expected_len,
                        coverage_map_id,
                    );
                    *slots[index].lock().expect("no panic holds this lock") = Some(observation);
                });
            }
        });
        slots
            .into_iter()
            .map(|slot| {
                slot.into_inner()
                    .expect("no panic holds this lock")
                    .expect("every slot is filled before the scope ends")
            })
            .collect()
    }

    fn decode_one(
        &self,
        id: usize,
        completed: bool,
        profile_dir: &Path,
        expected_len: Option<u64>,
        coverage_map_id: &str,
    ) -> CoverageObservation {
        let empty = |status: ExecutionStatus| CoverageObservation {
            case_id: id,
            artifact_sha256: self.artifact_sha256.clone(),
            coverage_map_id: coverage_map_id.to_string(),
            covered_regions: RegionSet::new(),
            covered_functions: BTreeSet::new(),
            target_invoked: false,
            status,
        };
        if !completed {
            return empty(ExecutionStatus::DidNotComplete);
        }
        let raw = profile_dir.join(format!("case-{id}.profraw"));
        let Ok(meta) = std::fs::metadata(&raw) else {
            return empty(ExecutionStatus::ProfileMissing);
        };
        // The append hazard: the profiling runtime's writes grow a file by one
        // whole record each time, and a doubled profile decodes to doubled
        // counts rather than to an error. A length that is not the baseline's
        // length is the cheap, exact signal for it.
        match expected_len {
            None => {
                return empty(ExecutionStatus::ProfileInvalid {
                    detail: "no baseline profile was written, so this profile's length cannot be \
                             validated"
                        .to_string(),
                })
            }
            Some(expected) if meta.len() != expected => {
                return empty(ExecutionStatus::ProfileInvalid {
                    detail: format!(
                        "profile is {} bytes where this artifact's profiles are {expected}; a \
                         profile holding more than one record decodes to multiplied counts \
                         rather than to an error",
                        meta.len()
                    ),
                })
            }
            Some(_) => {}
        }
        let indexed = profile_dir.join(format!("case-{id}.profdata"));
        if let Err(error) = self.merge(&raw, &indexed) {
            return empty(ExecutionStatus::DecodeFailed {
                detail: error.to_string(),
            });
        }
        let export = match self.export(&indexed) {
            Ok(export) => export,
            Err(error) => {
                return empty(ExecutionStatus::DecodeFailed {
                    detail: error.to_string(),
                })
            }
        };
        let mut covered = RegionSet::new();
        let mut functions = BTreeSet::new();
        let mut target_invoked = false;
        for function in &export.functions {
            if self.matches_target(&function.name) && function.count > 0 {
                target_invoked = true;
            }
            let mut in_scope = false;
            for region in &function.regions {
                if !self.in_scope(&region.region.file) {
                    continue;
                }
                in_scope = true;
                if region.count > 0 {
                    covered.insert(region.region.clone());
                }
            }
            if in_scope && function.count > 0 {
                functions.insert(function.name.clone());
            }
        }
        CoverageObservation {
            case_id: id,
            artifact_sha256: self.artifact_sha256.clone(),
            coverage_map_id: coverage_map_id.to_string(),
            covered_regions: covered,
            covered_functions: functions,
            target_invoked,
            status: ExecutionStatus::Observed,
        }
    }

    fn merge(&self, raw: &Path, out: &Path) -> Result<(), CoverageError> {
        let output = Command::new(&self.tools.profdata)
            .arg("merge")
            .arg("-sparse")
            .arg("--failure-mode=all")
            .arg("-o")
            .arg(out)
            .arg(raw)
            .output()
            .map_err(|e| CoverageError::Io(format!("cannot run llvm-profdata: {e}")))?;
        if !output.status.success() {
            return Err(CoverageError::Profdata {
                detail: first_line(&String::from_utf8_lossy(&output.stderr)),
            });
        }
        Ok(())
    }

    /// Runs `llvm-cov export` and parses what this module needs out of it.
    fn export(&self, profile: &Path) -> Result<Export, CoverageError> {
        let output = Command::new(&self.tools.cov)
            .arg("export")
            // Expansion records duplicate a macro's regions at each call site,
            // which inflates the fingerprint without distinguishing paths.
            .arg("--skip-expansions")
            .arg("--instr-profile")
            .arg(profile)
            .arg(&self.artifact)
            .output()
            .map_err(|e| CoverageError::Io(format!("cannot run llvm-cov: {e}")))?;
        if !output.status.success() {
            return Err(CoverageError::Cov {
                detail: first_line(&String::from_utf8_lossy(&output.stderr)),
            });
        }
        parse_export(&output.stdout)
    }

    /// Whether a source path is inside the library being measured.
    fn in_scope(&self, file: &str) -> bool {
        Path::new(file).starts_with(&self.scope)
    }

    /// Whether a coverage record belongs to the contract's function.
    ///
    /// Both Rust manglings length-prefix each path component — `_ZN…12nested_
    /// modesE` and `_RNvNt…12nested_modes` alike — so the prefixed component is
    /// an exact test in either. A bare substring test is **not**: for the
    /// contract `crypto::lookup::substitute` it would also match
    /// `substitute_indexed`, and `target_invoked` would report that the
    /// function under study ran when a different one did.
    ///
    /// When no record matches, [`Collector::map`] refuses the artifact rather
    /// than falling back to something looser.
    fn matches_target(&self, record: &str) -> bool {
        record.contains(&format!("{}{}", self.function.len(), self.function))
            // A demangled name, should a future llvm-cov emit one. Still an
            // exact component test, not a substring.
            || record.ends_with(&format!("::{}", self.function))
    }
}

/// How many decode workers to use.
///
/// Decoding is the dominant cost and is independent per case. Two cores are
/// left for the rest of the run, and the count never affects the result —
/// see [`Collector::decode_all`].
fn decode_workers() -> usize {
    std::thread::available_parallelism()
        .map(|cores| cores.get().saturating_sub(2).max(1))
        .unwrap_or(1)
        .min(16)
}

/// Whether the harness reported writing its baseline profile successfully.
fn baseline_ok(stdout: &str, nonce: &str) -> bool {
    let prefix = format!("{DISCOVERY_MODE_MARKER} {nonce} ");
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .filter_map(|rest| rest.trim().strip_prefix("baseline="))
        .filter_map(|status| status.trim().parse::<i32>().ok())
        .any(|status| status == 0)
}

/// A region with its execution count, as exported.
#[derive(Debug)]
struct CountedRegion {
    region: Region,
    count: u64,
}

/// One coverage record: a function, its count, and its regions.
#[derive(Debug)]
struct FunctionRecord {
    name: String,
    count: u64,
    regions: Vec<CountedRegion>,
}

#[derive(Debug)]
struct Export {
    functions: Vec<FunctionRecord>,
}

/// Region kind meaning "ordinary code", the only kind a stable toolchain emits.
///
/// Skipped (2) and gap (3) regions describe source that was not instrumented
/// rather than code that ran, and treating them as coverage would make two
/// inputs look different for reasons that have nothing to do with their paths.
const REGION_KIND_CODE: u64 = 0;

/// Parses `llvm-cov export`'s JSON into [`Export`].
///
/// The region arrays are positional — `[line_start, column_start, line_end,
/// column_end, count, file_id, expanded_file_id, kind]` — so each entry's
/// length is checked rather than assumed. A schema change should be a parse
/// error, not a silently misread coordinate.
fn parse_export(bytes: &[u8]) -> Result<Export, CoverageError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| CoverageError::Export(format!("llvm-cov export is not JSON: {e}")))?;
    let data = value["data"]
        .as_array()
        .ok_or_else(|| CoverageError::Export("llvm-cov export has no `data` array".to_string()))?;
    let mut functions = Vec::new();
    for export in data {
        let Some(records) = export["functions"].as_array() else {
            continue;
        };
        for record in records {
            let name = record["name"].as_str().unwrap_or_default().to_string();
            let count = record["count"].as_u64().unwrap_or(0);
            let filenames: Vec<String> = record["filenames"]
                .as_array()
                .map(|names| {
                    names
                        .iter()
                        .map(|name| name.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default();
            let mut regions = Vec::new();
            for entry in record["regions"].as_array().into_iter().flatten() {
                let fields = entry.as_array().ok_or_else(|| {
                    CoverageError::Export("a region entry is not an array".to_string())
                })?;
                if fields.len() < 8 {
                    return Err(CoverageError::Export(format!(
                        "a region entry has {} field(s), not the expected 8; llvm-cov's export \
                         schema has changed and the coordinates cannot be read safely",
                        fields.len()
                    )));
                }
                let number = |index: usize| fields[index].as_u64().unwrap_or(0);
                if number(7) != REGION_KIND_CODE {
                    continue;
                }
                let file = filenames
                    .get(number(5) as usize)
                    .cloned()
                    .unwrap_or_default();
                regions.push(CountedRegion {
                    region: Region {
                        file,
                        line_start: number(0) as u32,
                        column_start: number(1) as u32,
                        line_end: number(2) as u32,
                        column_end: number(3) as u32,
                    },
                    count: number(4),
                });
            }
            functions.push(FunctionRecord {
                name,
                count,
                regions,
            });
        }
    }
    if functions.is_empty() {
        return Err(CoverageError::Export(
            "llvm-cov export contained no coverage records, so this profile does not describe \
             this executable"
                .to_string(),
        ));
    }
    Ok(Export { functions })
}

/// Summary of what a set of observations covered, for reporting.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CoverageSummary {
    pub regions_covered: usize,
    /// Regions covered, grouped by source file name.
    pub by_file: BTreeMap<String, usize>,
}

impl CoverageSummary {
    pub fn of(regions: &RegionSet) -> CoverageSummary {
        let mut by_file: BTreeMap<String, usize> = BTreeMap::new();
        for region in regions {
            let name = region
                .file
                .rsplit('/')
                .next()
                .unwrap_or(region.file.as_str())
                .to_string();
            *by_file.entry(name).or_default() += 1;
        }
        CoverageSummary {
            regions_covered: regions.len(),
            by_file,
        }
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("no detail")
        .to_string()
}

#[derive(Debug)]
pub enum CoverageError {
    Io(String),
    Dynamic(DynamicError),
    ToolsMissing { tried: String, from_env: bool },
    Run(String),
    Profdata { detail: String },
    Cov { detail: String },
    Export(String),
    NothingSelected,
    NoBaseline { detail: String, stderr: String },
    TargetNotInMap { function: String, artifact: String },
    ScopeEmpty { scope: String },
}

impl From<DynamicError> for CoverageError {
    fn from(error: DynamicError) -> Self {
        CoverageError::Dynamic(error)
    }
}

impl fmt::Display for CoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoverageError::Io(message) => write!(f, "{message}"),
            CoverageError::Dynamic(error) => write!(f, "{error}"),
            CoverageError::ToolsMissing { tried, from_env } => write!(
                f,
                "coverage-guided exploration needs this toolchain's `llvm-profdata` and \
                 `llvm-cov`, which were not found at {tried}. {}",
                if *from_env {
                    format!("{LLVM_TOOLS_ENV} names a directory without them")
                } else {
                    "Install them with `rustup component add llvm-tools`. They must come from \
                     the active toolchain: a system LLVM of another version cannot read this \
                     compiler's profiles"
                        .to_string()
                }
            ),
            CoverageError::Run(message) => {
                write!(f, "running the discovery artifact failed: {message}")
            }
            CoverageError::Profdata { detail } => {
                write!(f, "llvm-profdata rejected a coverage profile: {detail}")
            }
            CoverageError::Cov { detail } => {
                write!(f, "llvm-cov could not export coverage: {detail}")
            }
            CoverageError::Export(message) => write!(f, "{message}"),
            CoverageError::NothingSelected => write!(
                f,
                "no candidates were selected for this discovery batch, and a batch that \
                 measures nothing cannot be reported as exploration"
            ),
            CoverageError::NoBaseline { detail, stderr } => write!(
                f,
                "the discovery artifact did not produce a baseline coverage profile, so nothing \
                 it reports can be validated: {detail}. stderr: {stderr}"
            ),
            CoverageError::TargetNotInMap { function, artifact } => write!(
                f,
                "the discovery artifact's coverage map has no record for `{function}`, so no \
                 coverage could be attributed to the function under study. {artifact} was built \
                 with instrumentation, so the usual cause is a contract whose function is not \
                 reachable from the generated harness"
            ),
            CoverageError::ScopeEmpty { scope } => write!(
                f,
                "the discovery artifact's coverage map declares no regions under {scope}, so \
                 nothing in the library would ever be measured. Exploration is refused rather \
                 than reporting that every candidate covered nothing new"
            ),
        }
    }
}

impl std::error::Error for CoverageError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(file: &str, line: u32) -> Region {
        Region {
            file: file.to_string(),
            line_start: line,
            column_start: 1,
            line_end: line,
            column_end: 9,
        }
    }

    /// A region's identity includes its file and all four coordinates, so two
    /// regions on the same line in different files are distinct.
    #[test]
    fn region_identity_includes_the_file() {
        assert_ne!(region("a.rs", 7), region("b.rs", 7));
        assert_eq!(region("a.rs", 7), region("a.rs", 7));
    }

    /// New coverage is a set difference, so an input covering fewer total
    /// regions than a predecessor can still be novel.
    #[test]
    fn novelty_is_set_difference_not_a_count() {
        let seen: RegionSet = [region("a.rs", 1), region("a.rs", 2), region("a.rs", 3)]
            .into_iter()
            .collect();
        let observation = CoverageObservation {
            case_id: 0,
            artifact_sha256: "deadbeef".to_string(),
            coverage_map_id: "map".to_string(),
            covered_regions: [region("a.rs", 9)].into_iter().collect(),
            covered_functions: BTreeSet::new(),
            target_invoked: true,
            status: ExecutionStatus::Observed,
        };
        let novel = observation.novel(&seen);
        assert_eq!(novel.len(), 1);
        assert!(novel.contains(&region("a.rs", 9)));
    }

    /// An observation that did not complete contributes no coverage, whatever
    /// regions happen to be attached to it.
    #[test]
    fn an_unusable_observation_contributes_nothing() {
        let observation = CoverageObservation {
            case_id: 3,
            artifact_sha256: "deadbeef".to_string(),
            coverage_map_id: "map".to_string(),
            covered_regions: [region("a.rs", 1), region("a.rs", 2)].into_iter().collect(),
            covered_functions: BTreeSet::new(),
            target_invoked: false,
            status: ExecutionStatus::ProfileInvalid {
                detail: "doubled".to_string(),
            },
        };
        assert!(observation.novel(&RegionSet::new()).is_empty());
        assert!(!observation.status.usable());
    }

    /// A malformed region entry is a parse error rather than a misread
    /// coordinate.
    #[test]
    fn a_short_region_entry_is_rejected() {
        let json = br#"{"data":[{"functions":[
            {"name":"f","count":1,"filenames":["/lib/a.rs"],"regions":[[1,2,3,4]]}]}]}"#;
        let error = parse_export(json).expect_err("a four-field region must be refused");
        assert!(
            error.to_string().contains("schema has changed"),
            "unexpected message: {error}"
        );
    }

    /// An export with no coverage records is rejected, because that is what a
    /// profile from a different executable looks like.
    #[test]
    fn an_export_with_no_records_is_rejected() {
        let error = parse_export(br#"{"data":[{"functions":[]}]}"#)
            .expect_err("an empty export must be refused");
        assert!(error
            .to_string()
            .contains("does not describe this executable"));
    }

    /// Only code regions are counted; skipped and gap regions describe
    /// uninstrumented source rather than execution.
    #[test]
    fn only_code_regions_are_counted() {
        let json = br#"{"data":[{"functions":[{"name":"f","count":1,
            "filenames":["/lib/a.rs"],"regions":[
              [1,1,1,9,5,0,0,0],
              [2,1,2,9,7,0,0,2],
              [3,1,3,9,9,0,0,3]]}]}]}"#;
        let export = parse_export(json).expect("the export parses");
        assert_eq!(export.functions[0].regions.len(), 1);
        assert_eq!(export.functions[0].regions[0].region.line_start, 1);
    }

    /// v0 mangling length-prefixes path components, so a target name cannot be
    /// matched by a longer function whose name contains it.
    #[test]
    fn target_matching_uses_the_mangled_component() {
        let tools = LlvmTools {
            profdata: PathBuf::from("/nonexistent"),
            cov: PathBuf::from("/nonexistent"),
            version: "test".to_string(),
        };
        let collector = Collector::new(
            &tools,
            Path::new("/nonexistent/artifact"),
            "sha",
            Path::new("/lib/Cargo.toml"),
            "substitute",
            Limits::default(),
        );
        // v0 and legacy mangling both length-prefix the component.
        assert!(collector.matches_target("_RNvNtCs123_6crypto6lookup10substitute"));
        assert!(collector.matches_target("_ZN6crypto6lookup10substitute17h0123456789abcdefE"));
        // `substitute_indexed` *contains* `substitute`, and must not match: its
        // component is prefixed 18, not 10.
        assert!(!collector.matches_target("_RNvNtCs123_6crypto6lookup18substitute_indexed"));
        assert!(!collector.matches_target("_RNvNtCs123_6crypto6lookup19substitute_unrelated"));
    }

    /// Scope is a path prefix test against the library's package directory.
    #[test]
    fn only_library_files_are_in_scope() {
        let tools = LlvmTools {
            profdata: PathBuf::from("/nonexistent"),
            cov: PathBuf::from("/nonexistent"),
            version: "test".to_string(),
        };
        let collector = Collector::new(
            &tools,
            Path::new("/nonexistent/artifact"),
            "sha",
            Path::new("/work/examples/crypto-library/Cargo.toml"),
            "substitute",
            Limits::default(),
        );
        assert!(collector.in_scope("/work/examples/crypto-library/src/lookup.rs"));
        // The generated harness, at its remapped path.
        assert!(!collector.in_scope("/trace-check/generated/src/main.rs"));
        // A third-party dependency.
        assert!(!collector.in_scope("/home/x/.cargo/registry/src/subtle-2.6.1/src/lib.rs"));
    }

    /// The baseline marker is only accepted with this run's nonce and a
    /// successful status.
    #[test]
    fn the_baseline_marker_is_nonce_bound() {
        let good = format!("{DISCOVERY_MODE_MARKER} abc123 baseline=0");
        assert!(baseline_ok(&good, "abc123"));
        assert!(!baseline_ok(&good, "other"));
        let failed = format!("{DISCOVERY_MODE_MARKER} abc123 baseline=-1");
        assert!(!baseline_ok(&failed, "abc123"));
    }

    /// A run missing its baseline is incomplete, and says why.
    #[test]
    fn a_run_without_a_baseline_is_incomplete() {
        let run = DiscoveryRun {
            requested: vec![0],
            completed: vec![0],
            run_complete: Some(1),
            baseline_written: false,
            exit_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            observations: Vec::new(),
        };
        assert!(!run.complete());
        assert!(run
            .incompleteness()
            .expect("an incomplete run explains itself")
            .contains("baseline profile"));
    }
}
