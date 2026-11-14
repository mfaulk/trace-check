//! Header discovery here replicates `trace-check-secret/build.rs` rather than
//! sharing code with it, because a build script cannot depend on a published
//! sibling. A test pins the two search orders together.

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;

use trace_check::memcheck::{self, Classification};
use trace_check::symbolic::{RuntimeState, ANALYZER_IMAGE, CONTAINER_RUNTIMES};

/// Version of the `--format json` document. Bump on any incompatible change.
pub const DOCTOR_SCHEMA_VERSION: u32 = 1;

/// Lowest Valgrind accepted. CI's Ubuntu 24.04 runner ships 3.22; #34 decides
/// the supported range, and this is the one place to change it.
pub const MIN_VALGRIND_VERSION: (u32, u32, u32) = (3, 22, 0);

/// The declared `rust-version` of this workspace.
pub const MIN_RUST_VERSION: &str = env!("CARGO_PKG_RUST_VERSION");

/// Every required check passed.
pub const EXIT_HEALTHY: u8 = 0;
/// At least one required check failed.
pub const EXIT_UNHEALTHY: u8 = 1;

/// Function in the self-test harness with a planted secret-dependent branch.
pub const PLANTED_SYMBOL: &str = "doctor_planted_branch";
/// Function in the self-test harness that handles the secret in constant time.
pub const CONTROL_SYMBOL: &str = "doctor_constant_time_control";

/// Must match `trace_check_test::calibration::BINDING_PROBE_SYMBOL`.
const BINDING_PROBE_SYMBOL: &str = "secret_binding_probe";

const RUN_MODE_MARKER: &str = "trace-check-doctor: run_mode=";
const COMPLETE_MARKER: &str = "trace-check-doctor: complete";

const VALGRIND_INSTALL: &str = "Debian/Ubuntu: `sudo apt-get install valgrind`; \
     Fedora: `sudo dnf install valgrind valgrind-devel`";
const HEADERS_INSTALL: &str = "Debian/Ubuntu: `sudo apt-get install valgrind` (ships the \
     headers); Fedora: `sudo dnf install valgrind-devel`; or set VALGRIND_INCLUDE to the \
     directory that contains valgrind/memcheck.h";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    Required,
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Missing,
    Incompatible,
    Skipped,
}

/// What a reader acts on: a required check that is not `ok` fails, an
/// optional one only warns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    Warn,
    Skip,
}

impl Verdict {
    fn of(requirement: Requirement, status: Status) -> Verdict {
        match (requirement, status) {
            (_, Status::Ok) => Verdict::Pass,
            (Requirement::Required, Status::Skipped) => Verdict::Fail,
            (Requirement::Optional, Status::Skipped) => Verdict::Skip,
            (Requirement::Required, _) => Verdict::Fail,
            (Requirement::Optional, _) => Verdict::Warn,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Warn => "WARN",
            Verdict::Skip => "SKIP",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub requirement: Requirement,
    pub status: Status,
    pub verdict: Verdict,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub required_ok: bool,
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    pub fn exit_code(&self) -> u8 {
        if self.required_ok {
            EXIT_HEALTHY
        } else {
            EXIT_UNHEALTHY
        }
    }

    #[cfg(test)]
    pub fn check(&self, id: &str) -> Option<&CheckResult> {
        self.checks.iter().find(|check| check.id == id)
    }
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// What the self-test produced, before it is judged.
#[derive(Debug, Clone)]
pub enum SelfTestRun {
    /// The harness could not be prepared or run at all.
    SetupFailed { reason: String },
    /// Cargo could not build the harness; `diagnostics` is the relevant output.
    BuildFailed { diagnostics: String },
    Ran {
        stdout: String,
        stderr: String,
        exit_code: Option<i32>,
        /// Whether the exit code is Memcheck's findings code.
        exited_with_findings: bool,
        xml: String,
    },
}

/// Everything doctor observes about the machine, so the checks can be tested
/// without Valgrind.
pub trait Environment {
    /// `(arch, os)`, as in `std::env::consts`.
    fn platform(&self) -> (String, String);
    fn var(&self, name: &str) -> Option<String>;
    /// `None` when the program could not be started at all.
    fn run(&self, program: &str, args: &[&str]) -> Option<CommandOutput>;
    fn is_file(&self, path: &Path) -> bool;
    /// The canonical path of `program` as found on `PATH`.
    fn find_on_path(&self, program: &str) -> Option<PathBuf>;
    /// `rustc --version` and `cargo --version` through the active toolchain.
    fn rust_versions(&self) -> (String, String);
    /// The `llvm-cov` version line, or why the tools were not found.
    fn llvm_tools(&self) -> Result<String, String>;
    fn container_runtime(&self, tool: &str) -> RuntimeState;
    fn self_test(&self) -> SelfTestRun;
}

/// Where `memcheck.h` is looked for, in `build.rs`'s order.
pub const HEADER_SEARCH_ORDER: [&str; 4] = [
    "VALGRIND_INCLUDE",
    "pkg-config",
    "the prefix of `valgrind` on PATH",
    "/usr/include",
];

const GENERIC_SELF_TEST_FIX: &str = "Re-run `cargo trace-check doctor`; if it still fails, \
     report it at https://github.com/mfaulk/trace-check/issues with this output";

type Outcome = (Status, String, Option<String>);

fn ok(detail: impl Into<String>) -> Outcome {
    (Status::Ok, detail.into(), None)
}

fn not_ok(status: Status, detail: impl Into<String>, fix: impl Into<String>) -> Outcome {
    (status, detail.into(), Some(fix.into()))
}

/// Runs every check against `env`, in a fixed order.
pub fn diagnose(env: &dyn Environment) -> DoctorReport {
    let mut checks = Vec::new();
    let mut record =
        |id: &'static str, requirement: Requirement, probe: &mut dyn FnMut() -> Outcome| {
            let start = Instant::now();
            let (status, detail, remediation) = probe();
            checks.push(CheckResult {
                id,
                requirement,
                status,
                verdict: Verdict::of(requirement, status),
                detail,
                remediation,
                duration_ms: start.elapsed().as_millis() as u64,
            });
            status
        };

    use Requirement::{Optional, Required};
    let platform = record("platform", Required, &mut || check_platform(env));
    let rust = record("rust", Required, &mut || check_rust(env));
    let valgrind = record("valgrind", Required, &mut || check_valgrind(env));
    record("valgrind-headers", Required, &mut || check_headers(env));
    let compiler = record("c-compiler", Required, &mut || check_c_compiler(env));

    // Headers are deliberately not a prerequisite: the self-test is the ground
    // truth for them, and it is what names an inert shim.
    let blocking: Vec<&str> = [
        ("platform", platform),
        ("rust", rust),
        ("valgrind", valgrind),
        ("c-compiler", compiler),
    ]
    .into_iter()
    .filter(|(_, status)| *status != Status::Ok)
    .map(|(id, _)| id)
    .collect();
    record("self-test", Required, &mut || {
        if blocking.is_empty() {
            evaluate_self_test(&env.self_test())
        } else {
            not_ok(
                Status::Skipped,
                format!(
                    "not run: the self-test needs {}, which did not pass",
                    blocking.join(", ")
                ),
                "Fix the failing checks above, then re-run `cargo trace-check doctor`",
            )
        }
    });

    record("llvm-tools", Optional, &mut || match env.llvm_tools() {
        Ok(version) => ok(version),
        Err(reason) => not_ok(
            Status::Missing,
            reason,
            "`rustup component add llvm-tools` (needed only for `check --explore`)",
        ),
    });

    let runtimes: Vec<(&str, RuntimeState)> = CONTAINER_RUNTIMES
        .iter()
        .map(|tool| (*tool, env.container_runtime(tool)))
        .collect();
    let usable: Vec<&str> = runtimes
        .iter()
        .filter(|(_, state)| *state != RuntimeState::Absent)
        .map(|(tool, _)| *tool)
        .collect();
    record("container-runtime", Optional, &mut || {
        if usable.is_empty() {
            not_ok(
                Status::Missing,
                "neither podman nor docker is usable",
                "Install podman (`sudo apt-get install podman` / `sudo dnf install podman`) \
                 or Docker (needed only for `verify`)",
            )
        } else {
            ok(usable.join(", "))
        }
    });
    record("analyzer-image", Optional, &mut || {
        let holding = runtimes
            .iter()
            .find(|(_, state)| *state == RuntimeState::WithImage);
        match (holding, usable.first()) {
            (Some((tool, _)), _) => ok(format!("{tool} holds {ANALYZER_IMAGE}")),
            (None, Some(tool)) => not_ok(
                Status::Missing,
                format!("{} does not hold {ANALYZER_IMAGE}", usable.join(", ")),
                format!("`{tool} pull {ANALYZER_IMAGE}` (needed only for `verify`)"),
            ),
            (None, None) => not_ok(
                Status::Skipped,
                "no container runtime to hold the image",
                "Install a container runtime first (see container-runtime)",
            ),
        }
    });

    let required_ok = checks
        .iter()
        .filter(|check| check.requirement == Required)
        .all(|check| check.status == Status::Ok);
    DoctorReport {
        schema_version: DOCTOR_SCHEMA_VERSION,
        tool: env!("CARGO_PKG_NAME"),
        tool_version: env!("CARGO_PKG_VERSION"),
        required_ok,
        checks,
    }
}

fn check_platform(env: &dyn Environment) -> Outcome {
    let (arch, os) = env.platform();
    let found = format!("{arch}-{os}");
    if arch == "x86_64" && os == "linux" {
        ok(found)
    } else {
        not_ok(
            Status::Incompatible,
            format!("{found} is not supported; native checking needs x86_64-linux"),
            "Native checking needs Linux on x86-64; run trace-check in a Linux x86-64 VM, \
             container, or CI runner",
        )
    }
}

type Version = (u32, u32, u32);

/// Parses the first `major.minor[.patch]` in `text` after `prefix`.
fn parse_version(text: &str, prefix: &str) -> Option<Version> {
    let rest = text.trim().strip_prefix(prefix)?;
    let token = rest.split_whitespace().next()?;
    let mut parts = token.split(['.', '-']).map(|part| {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().ok()
    });
    let major = parts.next()??;
    let minor = parts.next()??;
    let patch = parts.next().flatten().unwrap_or(0);
    Some((major, minor, patch))
}

fn show((major, minor, patch): Version) -> String {
    format!("{major}.{minor}.{patch}")
}

fn check_rust(env: &dyn Environment) -> Outcome {
    let floor = parse_version(MIN_RUST_VERSION, "").expect("rust-version is a version");
    let (rustc, cargo) = env.rust_versions();
    let install = "Install Rust with rustup (https://rustup.rs), then run `cargo trace-check \
                   doctor` again";
    let (Some(rustc_version), Some(cargo_version)) = (
        parse_version(&rustc, "rustc "),
        parse_version(&cargo, "cargo "),
    ) else {
        return not_ok(
            Status::Missing,
            format!("could not read the toolchain version ({rustc}; {cargo})"),
            install,
        );
    };
    let detail = format!(
        "rustc {}, cargo {} (floor {MIN_RUST_VERSION})",
        show(rustc_version),
        show(cargo_version)
    );
    if rustc_version < floor || cargo_version < floor {
        not_ok(
            Status::Incompatible,
            format!("{detail}: older than the declared rust-version"),
            format!("`rustup update`, or `rustup toolchain install {MIN_RUST_VERSION}`"),
        )
    } else {
        ok(detail)
    }
}

fn check_valgrind(env: &dyn Environment) -> Outcome {
    let Some(output) = env.run("valgrind", &["--version"]) else {
        return not_ok(
            Status::Missing,
            "`valgrind` is not on PATH",
            VALGRIND_INSTALL,
        );
    };
    let banner = output.stdout.trim().to_string();
    let floor = show(MIN_VALGRIND_VERSION);
    let range = format!(">= {floor}, < {}.0.0", MIN_VALGRIND_VERSION.0 + 1);
    match parse_version(&banner, "valgrind-") {
        Some(version)
            if output.success
                && version >= MIN_VALGRIND_VERSION
                && version.0 == MIN_VALGRIND_VERSION.0 =>
        {
            ok(format!("{} (supported range {range})", show(version)))
        }
        Some(version) => not_ok(
            Status::Incompatible,
            format!(
                "Valgrind {} is outside the supported range {range}; the minimum is {floor}",
                show(version)
            ),
            format!("{VALGRIND_INSTALL}; or build Valgrind {floor} or newer from https://valgrind.org/downloads/"),
        ),
        None => not_ok(
            Status::Incompatible,
            format!("`valgrind --version` printed {banner:?}, which is not a Valgrind version banner"),
            VALGRIND_INSTALL,
        ),
    }
}

fn check_headers(env: &dyn Environment) -> Outcome {
    let header = |dir: &Path| env.is_file(&dir.join("valgrind/memcheck.h"));

    if let Some(dir) = env.var("VALGRIND_INCLUDE") {
        let dir = PathBuf::from(dir);
        return if header(&dir) {
            ok(format!("{} (from VALGRIND_INCLUDE)", dir.display()))
        } else {
            not_ok(
                Status::Incompatible,
                format!(
                    "VALGRIND_INCLUDE={} does not contain valgrind/memcheck.h, so the \
                     trace-check-secret build script will abort",
                    dir.display()
                ),
                "Unset VALGRIND_INCLUDE, or point it at the directory that contains \
                 valgrind/memcheck.h",
            )
        };
    }

    if let Some(output) = env.run("pkg-config", &["--variable=includedir", "valgrind"]) {
        let dir = PathBuf::from(output.stdout.trim());
        if output.success && header(&dir) {
            return ok(format!("{} (from pkg-config)", dir.display()));
        }
    }

    if let Some(prefix) = env
        .find_on_path("valgrind")
        .and_then(|binary| binary.parent()?.parent().map(Path::to_path_buf))
    {
        let dir = prefix.join("include");
        if header(&dir) {
            return ok(format!(
                "{} (from the prefix of `valgrind` on PATH)",
                dir.display()
            ));
        }
    }

    let system = Path::new("/usr/include");
    if header(system) {
        return ok(format!("{} (system)", system.display()));
    }

    not_ok(
        Status::Missing,
        format!(
            "valgrind/memcheck.h not found (searched {}); trace-check-secret would build an \
             inert shim",
            HEADER_SEARCH_ORDER.join(", ")
        ),
        HEADERS_INSTALL,
    )
}

fn check_c_compiler(env: &dyn Environment) -> Outcome {
    let configured = env
        .var("CC")
        .and_then(|cc| cc.split_whitespace().next().map(str::to_string));
    let program = configured.as_deref().unwrap_or("cc");
    let fix = "Debian/Ubuntu: `sudo apt-get install build-essential`; Fedora: `sudo dnf \
               install gcc`; or set CC to a working C compiler";
    match env.run(program, &["--version"]) {
        None => not_ok(Status::Missing, format!("`{program}` is not on PATH"), fix),
        Some(output) if !output.success => not_ok(
            Status::Incompatible,
            format!(
                "`{program} --version` failed: {}",
                first_line(&output.stderr)
            ),
            fix,
        ),
        Some(output) => ok(format!("{program}: {}", first_line(&output.stdout))),
    }
}

fn first_line(text: &str) -> &str {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("")
}

fn excerpt(text: &str, count: usize) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(count)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Judges a self-test run. Passing needs all four: the planted branch
/// detected, the control clean, and both positive controls confirmed.
pub fn evaluate_self_test(run: &SelfTestRun) -> Outcome {
    let headers_fix = format!("{HEADERS_INSTALL}; then re-run `cargo trace-check doctor`");
    let (stdout, stderr, exit_code, exited_with_findings, xml) = match run {
        SelfTestRun::SetupFailed { reason } => {
            let fix = if reason.contains(trace_check::dynamic_harness::TEST_CRATE_ENV) {
                format!(
                    "Set {} to a trace-check-test package directory",
                    trace_check::dynamic_harness::TEST_CRATE_ENV
                )
            } else {
                GENERIC_SELF_TEST_FIX.to_string()
            };
            return not_ok(
                Status::Incompatible,
                format!("the self-test could not run: {reason}"),
                fix,
            );
        }
        SelfTestRun::BuildFailed { diagnostics } => {
            if diagnostics.contains("does not contain valgrind/memcheck.h") {
                return not_ok(
                    Status::Incompatible,
                    "the self-test harness did not build: VALGRIND_INCLUDE names a directory \
                     without valgrind/memcheck.h, so the trace-check-secret build script aborted",
                    "Unset VALGRIND_INCLUDE, or point it at the directory that contains \
                     valgrind/memcheck.h",
                );
            }
            return not_ok(
                Status::Incompatible,
                format!(
                    "the self-test harness did not build: {}",
                    excerpt(diagnostics, 8)
                ),
                GENERIC_SELF_TEST_FIX,
            );
        }
        SelfTestRun::Ran {
            stdout,
            stderr,
            exit_code,
            exited_with_findings,
            xml,
        } => (stdout, stderr, *exit_code, *exited_with_findings, xml),
    };

    let run_mode = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix(RUN_MODE_MARKER));
    match run_mode {
        Some("valgrind") => {}
        Some("unsupported") => {
            return not_ok(
                Status::Incompatible,
                "trace-check-secret was built without Valgrind's headers (an inert shim), so \
                 secret marking does nothing and no result could be trusted",
                headers_fix,
            )
        }
        Some(other) => {
            return not_ok(
                Status::Incompatible,
                format!("the self-test reported run mode `{other}` instead of `valgrind`"),
                GENERIC_SELF_TEST_FIX,
            )
        }
        None => {
            return not_ok(
                Status::Incompatible,
                format!(
                    "the self-test exited with {} before reporting its run mode: {}",
                    exit_code.map_or("a signal".to_string(), |code| format!("code {code}")),
                    excerpt(stderr, 6)
                ),
                GENERIC_SELF_TEST_FIX,
            )
        }
    }

    if !(exit_code == Some(0) || exited_with_findings) {
        return not_ok(
            Status::Incompatible,
            format!(
                "the self-test exited with {}: {}",
                exit_code.map_or("a signal".to_string(), |code| format!("code {code}")),
                excerpt(stderr, 6)
            ),
            GENERIC_SELF_TEST_FIX,
        );
    }
    if !stdout.lines().any(|line| line.trim() == COMPLETE_MARKER) {
        return not_ok(
            Status::Incompatible,
            "the self-test did not print its completion marker, so it did not complete",
            GENERIC_SELF_TEST_FIX,
        );
    }

    let parsed = match memcheck::parse(xml) {
        Ok(parsed) => parsed,
        Err(error) => {
            return not_ok(
                Status::Incompatible,
                format!("Memcheck's XML output could not be parsed: {error}"),
                GENERIC_SELF_TEST_FIX,
            )
        }
    };

    let mut calibration = 0;
    let mut binding = 0;
    let mut planted = 0;
    let mut control = 0;
    let mut unexpected = Vec::new();
    for error in &parsed.errors {
        let secret = error.classification.is_secret_dependency();
        if secret && error.attributable_to(crate::run::PROBE_SYMBOL) {
            calibration += 1;
        } else if secret && error.attributable_to(BINDING_PROBE_SYMBOL) {
            binding += 1;
        } else if error.attributable_to(PLANTED_SYMBOL)
            && error.classification == Classification::SecretDependentBranch
        {
            planted += 1;
        } else if error.attributable_to(CONTROL_SYMBOL) {
            control += 1;
        } else {
            unexpected.push(error.what.clone());
        }
    }

    if calibration == 0 {
        return not_ok(
            Status::Incompatible,
            "the calibration control produced no diagnostic, so secret marking does not reach \
             compiled code",
            GENERIC_SELF_TEST_FIX,
        );
    }
    if binding == 0 {
        return not_ok(
            Status::Incompatible,
            "the secret-binding control produced no diagnostic, so the analyzed secret's own \
             storage was not shown to be marked",
            GENERIC_SELF_TEST_FIX,
        );
    }
    if planted == 0 {
        return not_ok(
            Status::Incompatible,
            format!(
                "Memcheck did not report the planted secret-dependent branch in \
                 `{PLANTED_SYMBOL}`, so a real leak would be missed"
            ),
            GENERIC_SELF_TEST_FIX,
        );
    }
    if control > 0 {
        return not_ok(
            Status::Incompatible,
            format!(
                "the constant-time control `{CONTROL_SYMBOL}` produced {control} finding(s), a \
                 false positive"
            ),
            GENERIC_SELF_TEST_FIX,
        );
    }
    if !unexpected.is_empty() {
        return not_ok(
            Status::Incompatible,
            format!(
                "{} unexpected diagnostic(s), first: {}",
                unexpected.len(),
                unexpected[0]
            ),
            GENERIC_SELF_TEST_FIX,
        );
    }
    ok(
        "planted secret-dependent branch detected; constant-time control clean; \
        calibration and secret binding confirmed",
    )
}

pub fn render_text(report: &DoctorReport) -> String {
    let mut out = format!(
        "cargo trace-check doctor ({} {})\n\n",
        report.tool, report.tool_version
    );
    for check in &report.checks {
        out.push_str(&format!(
            "{}  {:<18} {}\n",
            check.verdict.label(),
            check.id,
            check.detail
        ));
        if check.verdict != Verdict::Pass {
            if let Some(fix) = &check.remediation {
                out.push_str(&format!("      fix: {fix}\n"));
            }
        }
    }
    let failed: Vec<&str> = report
        .checks
        .iter()
        .filter(|check| check.verdict == Verdict::Fail)
        .map(|check| check.id)
        .collect();
    out.push('\n');
    if report.required_ok {
        out.push_str("Result: ready. Every required check passed (exit 0).\n");
    } else {
        out.push_str(&format!(
            "Result: not ready. Required check(s) failed: {} (exit {EXIT_UNHEALTHY}).\n",
            failed.join(", ")
        ));
    }
    out
}

pub fn render_json(report: &DoctorReport) -> String {
    let mut text = serde_json::to_string_pretty(report).expect("the report serializes");
    text.push('\n');
    text
}

/// Runs doctor against this machine, prints the report, and returns the exit
/// code.
pub fn run(json: bool) -> u8 {
    let env = SystemEnv::new(!json);
    let report = diagnose(&env);
    if json {
        print!("{}", render_json(&report));
    } else {
        print!("{}", render_text(&report));
    }
    report.exit_code()
}

/// The self-test harness. The planted function's early exit uses volatile
/// loads, because a plain early-exit byte loop is if-converted into branchless
/// code at opt-level 3 and would leave nothing to detect.
const HARNESS_SOURCE: &str = r#"use std::hint::black_box;

#[inline(never)]
fn doctor_planted_branch(secret: &[u8; 16], guess: &[u8; 16]) -> bool {
    for i in 0..16 {
        // SAFETY: `i` is in bounds and the reference is live.
        let byte = unsafe { core::ptr::read_volatile(&secret[i]) };
        if byte != guess[i] {
            return false;
        }
    }
    true
}

#[inline(never)]
fn doctor_constant_time_control(secret: &[u8; 16], guess: &[u8; 16]) -> u8 {
    let mut difference = 0u8;
    for i in 0..16 {
        // SAFETY: `i` is in bounds and the reference is live.
        difference |= unsafe { core::ptr::read_volatile(&secret[i]) } ^ guess[i];
    }
    difference
}

fn main() {
    println!("trace-check-doctor: run_mode={}", trace_check_test::run_mode());
    trace_check_test::calibration::run();
    let guess = black_box([0x5au8; 16]);

    let secret: [u8; 16] = trace_check_test::launder([0x5a; 16]);
    let guard = trace_check_test::mark(&secret);
    trace_check_test::calibration::confirm_binding(&secret);
    let equal = doctor_planted_branch(black_box(&secret), &guess);
    drop(guard);
    let equal = trace_check_test::finish(equal);

    let secret: [u8; 16] = trace_check_test::launder([0x5a; 16]);
    let guard = trace_check_test::mark(&secret);
    trace_check_test::calibration::confirm_binding(&secret);
    let difference = doctor_constant_time_control(black_box(&secret), &guess);
    drop(guard);
    let difference = trace_check_test::finish(difference);

    println!("trace-check-doctor: planted={equal} control={difference}");
    println!("trace-check-doctor: complete");
}
"#;

struct SystemEnv {
    toolchain: trace_check::toolchain::Toolchain,
    announce: bool,
}

impl SystemEnv {
    fn new(announce: bool) -> SystemEnv {
        let directory = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        SystemEnv {
            toolchain: trace_check::toolchain::Toolchain::resolve(&directory),
            announce,
        }
    }
}

impl Environment for SystemEnv {
    fn platform(&self) -> (String, String) {
        (
            std::env::consts::ARCH.to_string(),
            std::env::consts::OS.to_string(),
        )
    }

    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn run(&self, program: &str, args: &[&str]) -> Option<CommandOutput> {
        let output = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        Some(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn is_file(&self, path: &Path) -> bool {
        path.is_file()
    }

    fn find_on_path(&self, program: &str) -> Option<PathBuf> {
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
            .and_then(|found| std::fs::canonicalize(found).ok())
    }

    fn rust_versions(&self) -> (String, String) {
        (
            self.toolchain.rustc_version.clone(),
            self.toolchain.cargo_version.clone(),
        )
    }

    fn llvm_tools(&self) -> Result<String, String> {
        trace_check::coverage::LlvmTools::locate(Some(&self.toolchain))
            .map(|tools| tools.version)
            .map_err(|error| error.to_string())
    }

    fn container_runtime(&self, tool: &str) -> RuntimeState {
        trace_check::symbolic::probe_runtime(tool)
    }

    fn self_test(&self) -> SelfTestRun {
        if self.announce {
            eprintln!("doctor: building and running the self-test under Memcheck...");
        }
        run_self_test(&self.toolchain)
    }
}

/// Builds the harness with the same `trace-check-test` resolution and release
/// profile a generated security harness uses, then runs it under Memcheck.
fn run_self_test(toolchain: &trace_check::toolchain::Toolchain) -> SelfTestRun {
    use std::process::{Command, Stdio};

    let setup = |reason: String| SelfTestRun::SetupFailed { reason };
    let dependency = match trace_check::dynamic_harness::test_crate_dependency() {
        Ok(stanza) => stanza,
        Err(error) => return setup(error.to_string()),
    };
    let work = match tempfile::Builder::new()
        .prefix("trace-check-doctor-")
        .tempdir()
    {
        Ok(dir) => dir,
        Err(error) => return setup(format!("cannot create a scratch directory: {error}")),
    };
    let crate_dir = work.path().join("probe");
    let manifest = format!(
        "[package]\nname = \"trace-check-doctor-probe\"\nversion = \"0.0.0\"\n\
         edition = \"2021\"\npublish = false\n\n{dependency}\
         [profile.release]\nopt-level = 3\ndebug = true\npanic = \"unwind\"\n\
         codegen-units = 1\nlto = false\nincremental = false\nstrip = false\n\n\
         [workspace]\n"
    );
    let written = std::fs::create_dir_all(crate_dir.join("src"))
        .and_then(|()| std::fs::write(crate_dir.join("Cargo.toml"), manifest))
        .and_then(|()| std::fs::write(crate_dir.join("src/main.rs"), HARNESS_SOURCE));
    if let Err(error) = written {
        return setup(format!("cannot write the self-test harness: {error}"));
    }

    let mut build = Command::new("cargo");
    toolchain.apply(&mut build);
    let output = build
        .args([
            "build",
            "--release",
            "--message-format=json-render-diagnostics",
            "--color=never",
        ])
        .arg("--target-dir")
        .arg(work.path().join("target"))
        .current_dir(&crate_dir)
        .stdin(Stdio::null())
        .output();
    let output = match output {
        Ok(output) => output,
        Err(error) => return setup(format!("cannot run cargo: {error}")),
    };
    if !output.status.success() {
        return SelfTestRun::BuildFailed {
            diagnostics: trace_check::native::compiler_diagnostics(
                &String::from_utf8_lossy(&output.stderr),
                24,
            ),
        };
    }
    let executable = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|message| message["reason"] == "compiler-artifact")
        .filter_map(|message| message["executable"].as_str().map(PathBuf::from))
        .next_back();
    let Some(executable) = executable else {
        return SelfTestRun::BuildFailed {
            diagnostics: "cargo reported no executable for the self-test harness".to_string(),
        };
    };

    let limits = trace_check::native::Limits {
        timeout: std::time::Duration::from_secs(120),
        max_output_bytes: 16 * 1024 * 1024,
    };
    match trace_check::native::run_under_memcheck(
        Path::new("valgrind"),
        &executable,
        &[],
        &[],
        limits,
    ) {
        Ok(output) => SelfTestRun::Ran {
            exited_with_findings: output.exited_with_findings(),
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            xml: output.xml,
        },
        Err(error) => setup(format!("Memcheck could not run the harness: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::{HashMap, HashSet};

    struct FakeEnv {
        platform: (String, String),
        vars: HashMap<String, String>,
        commands: HashMap<String, CommandOutput>,
        files: HashSet<PathBuf>,
        on_path: HashMap<String, PathBuf>,
        rust: (String, String),
        llvm: Result<String, String>,
        runtimes: HashMap<String, RuntimeState>,
        self_test: SelfTestRun,
        self_test_ran: Cell<bool>,
    }

    fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn xml(body: &str) -> String {
        format!(
            "<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>{body}\
             <status><state>FINISHED</state></status></valgrindoutput>"
        )
    }

    fn error(kind: &str, function: &str) -> String {
        format!(
            "<error><kind>{kind}</kind><what>diagnostic</what><stack>\
             <frame><fn>{function}</fn><file>main.rs</file><line>9</line></frame></stack>\
             <auxwhat>Uninitialised value was created by a client request</auxwhat>\
             <stack><frame><fn>mark</fn></frame></stack></error>"
        )
    }

    fn calibration() -> String {
        error(
            "UninitValue",
            "trace_check_test::calibration::secret_dependent_probe",
        )
    }

    fn binding() -> String {
        error(
            "UninitValue",
            "trace_check_test::calibration::secret_binding_probe",
        )
    }

    fn planted() -> String {
        error(
            "UninitCondition",
            "trace_check_doctor_probe::doctor_planted_branch",
        )
    }

    fn ran(stdout: &str, body: &str) -> SelfTestRun {
        SelfTestRun::Ran {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(42),
            exited_with_findings: true,
            xml: xml(body),
        }
    }

    const HEALTHY_STDOUT: &str = "trace-check-doctor: run_mode=valgrind\n\
                                  trace-check-doctor: complete\n";

    fn healthy_run() -> SelfTestRun {
        ran(
            HEALTHY_STDOUT,
            &format!("{}{}{}{}", calibration(), binding(), binding(), planted()),
        )
    }

    impl FakeEnv {
        fn healthy() -> FakeEnv {
            let mut commands = HashMap::new();
            commands.insert("valgrind".to_string(), ok("valgrind-3.28.0\n"));
            commands.insert("cc".to_string(), ok("cc (GCC) 14.2.1\n"));
            commands.insert(
                "pkg-config".to_string(),
                CommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "Package valgrind was not found".to_string(),
                },
            );
            let mut runtimes = HashMap::new();
            runtimes.insert("podman".to_string(), RuntimeState::WithImage);
            runtimes.insert("docker".to_string(), RuntimeState::Absent);
            FakeEnv {
                platform: ("x86_64".to_string(), "linux".to_string()),
                vars: HashMap::new(),
                commands,
                files: [PathBuf::from("/usr/include/valgrind/memcheck.h")]
                    .into_iter()
                    .collect(),
                on_path: [("valgrind".to_string(), PathBuf::from("/usr/bin/valgrind"))]
                    .into_iter()
                    .collect(),
                rust: (
                    "rustc 1.97.0 (0123abcd 2026-01-01)".to_string(),
                    "cargo 1.97.0 (0123abcd 2026-01-01)".to_string(),
                ),
                llvm: Ok("LLVM version 20.1.8-rust-1.97.0-stable".to_string()),
                runtimes,
                self_test: healthy_run(),
                self_test_ran: Cell::new(false),
            }
        }

        fn without_command(mut self, program: &str) -> FakeEnv {
            self.commands.remove(program);
            self.on_path.remove(program);
            self
        }
    }

    impl Environment for FakeEnv {
        fn platform(&self) -> (String, String) {
            self.platform.clone()
        }
        fn var(&self, name: &str) -> Option<String> {
            self.vars.get(name).cloned()
        }
        fn run(&self, program: &str, _args: &[&str]) -> Option<CommandOutput> {
            self.commands.get(program).cloned()
        }
        fn is_file(&self, path: &Path) -> bool {
            self.files.contains(path) || path.is_file()
        }
        fn find_on_path(&self, program: &str) -> Option<PathBuf> {
            self.on_path.get(program).cloned()
        }
        fn rust_versions(&self) -> (String, String) {
            self.rust.clone()
        }
        fn llvm_tools(&self) -> Result<String, String> {
            self.llvm.clone()
        }
        fn container_runtime(&self, tool: &str) -> RuntimeState {
            self.runtimes
                .get(tool)
                .copied()
                .unwrap_or(RuntimeState::Absent)
        }
        fn self_test(&self) -> SelfTestRun {
            self.self_test_ran.set(true);
            self.self_test.clone()
        }
    }

    fn check<'a>(report: &'a DoctorReport, id: &str) -> &'a CheckResult {
        report
            .check(id)
            .unwrap_or_else(|| panic!("no `{id}` check in {report:?}"))
    }

    fn remediation(report: &DoctorReport, id: &str) -> String {
        check(report, id)
            .remediation
            .clone()
            .unwrap_or_else(|| panic!("`{id}` has no remediation"))
    }

    /// A healthy machine passes every required check and exits 0.
    #[test]
    fn healthy_environment_passes_every_required_check() {
        let env = FakeEnv::healthy();
        let report = diagnose(&env);
        assert!(report.required_ok, "{report:#?}");
        assert_eq!(report.exit_code(), EXIT_HEALTHY);
        for check in &report.checks {
            assert_eq!(check.verdict, Verdict::Pass, "{check:?}");
        }
        assert!(env.self_test_ran.get());
    }

    /// The checks appear in a fixed order with fixed ids, which the JSON schema promises.
    #[test]
    fn check_ids_are_fixed_and_ordered() {
        let report = diagnose(&FakeEnv::healthy());
        let ids: Vec<&str> = report.checks.iter().map(|c| c.id).collect();
        assert_eq!(
            ids,
            [
                "platform",
                "rust",
                "valgrind",
                "valgrind-headers",
                "c-compiler",
                "self-test",
                "llvm-tools",
                "container-runtime",
                "analyzer-image",
            ]
        );
    }

    /// A non-Linux or non-x86-64 host fails the platform check as unsupported.
    #[test]
    fn unsupported_platform_fails() {
        let mut env = FakeEnv::healthy();
        env.platform = ("aarch64".to_string(), "macos".to_string());
        let report = diagnose(&env);
        let platform = check(&report, "platform");
        assert_eq!(platform.status, Status::Incompatible);
        assert_eq!(platform.verdict, Verdict::Fail);
        assert!(platform.detail.contains("aarch64-macos"));
        assert!(remediation(&report, "platform").contains("Linux on x86-64"));
        assert_eq!(report.exit_code(), EXIT_UNHEALTHY);
    }

    /// No `valgrind` on PATH is a missing required check with distro install lines.
    #[test]
    fn missing_valgrind_fails_with_install_remediation() {
        let report = diagnose(&FakeEnv::healthy().without_command("valgrind"));
        assert_eq!(check(&report, "valgrind").status, Status::Missing);
        let fix = remediation(&report, "valgrind");
        assert!(fix.contains("apt-get install valgrind"), "{fix}");
        assert!(fix.contains("dnf install valgrind valgrind-devel"), "{fix}");
        assert!(!report.required_ok);
    }

    /// A version banner below the floor is incompatible and names the floor.
    #[test]
    fn old_valgrind_banner_is_incompatible() {
        let mut env = FakeEnv::healthy();
        env.commands
            .insert("valgrind".to_string(), ok("valgrind-3.10.1\n"));
        let report = diagnose(&env);
        let valgrind = check(&report, "valgrind");
        assert_eq!(valgrind.status, Status::Incompatible);
        assert!(valgrind.detail.contains("3.10.1"), "{}", valgrind.detail);
        assert!(valgrind.detail.contains("3.22.0"), "{}", valgrind.detail);
        assert!(remediation(&report, "valgrind").contains("apt-get install valgrind"));
    }

    /// CI's Ubuntu 24.04 Valgrind 3.22 is accepted rather than hard-failed.
    #[test]
    fn valgrind_3_22_is_accepted() {
        let mut env = FakeEnv::healthy();
        env.commands
            .insert("valgrind".to_string(), ok("valgrind-3.22.0\n"));
        assert_eq!(check(&diagnose(&env), "valgrind").status, Status::Ok);
    }

    /// A different major version is outside the range the XML grammar was verified on.
    #[test]
    fn valgrind_major_4_is_incompatible() {
        let mut env = FakeEnv::healthy();
        env.commands
            .insert("valgrind".to_string(), ok("valgrind-4.0.0\n"));
        assert_eq!(
            check(&diagnose(&env), "valgrind").status,
            Status::Incompatible
        );
    }

    /// An unparseable banner is incompatible rather than assumed fine.
    #[test]
    fn unparseable_valgrind_banner_is_incompatible() {
        let mut env = FakeEnv::healthy();
        env.commands
            .insert("valgrind".to_string(), ok("something else\n"));
        assert_eq!(
            check(&diagnose(&env), "valgrind").status,
            Status::Incompatible
        );
    }

    /// A rustc below the declared floor is incompatible with an update remediation.
    #[test]
    fn rust_below_floor_is_incompatible() {
        let mut env = FakeEnv::healthy();
        env.rust.0 = "rustc 1.80.0 (abc 2024-07-21)".to_string();
        let report = diagnose(&env);
        let rust = check(&report, "rust");
        assert_eq!(rust.status, Status::Incompatible);
        assert!(rust.detail.contains("1.80.0"), "{}", rust.detail);
        assert!(remediation(&report, "rust").contains("rustup update"));
    }

    /// A missing cargo is a missing required check pointing at rustup.
    #[test]
    fn missing_cargo_is_missing() {
        let mut env = FakeEnv::healthy();
        env.rust.1 = "cargo (version unavailable)".to_string();
        let report = diagnose(&env);
        assert_eq!(check(&report, "rust").status, Status::Missing);
        assert!(remediation(&report, "rust").contains("rustup.rs"));
    }

    /// The Rust floor is the workspace's declared rust-version.
    #[test]
    fn rust_floor_is_the_declared_rust_version() {
        assert_eq!(MIN_RUST_VERSION, "1.97");
    }

    /// VALGRIND_INCLUDE wins over every other location, as in build.rs.
    #[test]
    fn valgrind_include_is_searched_first() {
        let include = tempfile::tempdir().unwrap();
        std::fs::create_dir(include.path().join("valgrind")).unwrap();
        std::fs::write(include.path().join("valgrind/memcheck.h"), "").unwrap();
        let mut env = FakeEnv::healthy();
        env.vars.insert(
            "VALGRIND_INCLUDE".to_string(),
            include.path().display().to_string(),
        );
        let report = diagnose(&env);
        let headers = check(&report, "valgrind-headers");
        assert_eq!(headers.status, Status::Ok);
        assert!(
            headers.detail.contains("VALGRIND_INCLUDE"),
            "{}",
            headers.detail
        );
    }

    /// VALGRIND_INCLUDE naming an empty directory is incompatible, because build.rs aborts.
    #[test]
    fn empty_valgrind_include_dir_is_incompatible() {
        let include = tempfile::tempdir().unwrap();
        let mut env = FakeEnv::healthy();
        env.vars.insert(
            "VALGRIND_INCLUDE".to_string(),
            include.path().display().to_string(),
        );
        let report = diagnose(&env);
        let headers = check(&report, "valgrind-headers");
        assert_eq!(headers.status, Status::Incompatible);
        assert_eq!(headers.verdict, Verdict::Fail);
        assert!(remediation(&report, "valgrind-headers").contains("VALGRIND_INCLUDE"));
        assert!(!report.required_ok);
    }

    /// pkg-config's includedir is used before the valgrind prefix and /usr/include.
    #[test]
    fn pkg_config_is_searched_before_the_prefix() {
        let mut env = FakeEnv::healthy();
        env.commands
            .insert("pkg-config".to_string(), ok("/opt/vg/include\n"));
        env.files
            .insert(PathBuf::from("/opt/vg/include/valgrind/memcheck.h"));
        let headers = diagnose(&env).check("valgrind-headers").unwrap().clone();
        assert!(
            headers.detail.contains("/opt/vg/include"),
            "{}",
            headers.detail
        );
        assert!(headers.detail.contains("pkg-config"), "{}", headers.detail);
    }

    /// The prefix of the `valgrind` on PATH is searched for a local source install.
    #[test]
    fn valgrind_prefix_is_searched_before_usr_include() {
        let mut env = FakeEnv::healthy();
        env.on_path.insert(
            "valgrind".to_string(),
            PathBuf::from("/home/u/.local/share/valgrind-3.28.0/bin/valgrind"),
        );
        env.files.insert(PathBuf::from(
            "/home/u/.local/share/valgrind-3.28.0/include/valgrind/memcheck.h",
        ));
        let headers = diagnose(&env).check("valgrind-headers").unwrap().clone();
        assert!(
            headers.detail.contains("valgrind-3.28.0/include"),
            "{}",
            headers.detail
        );
    }

    /// No headers anywhere is a missing required check with distro install lines.
    #[test]
    fn missing_headers_fail_with_install_remediation() {
        let mut env = FakeEnv::healthy();
        env.files.clear();
        let report = diagnose(&env);
        assert_eq!(check(&report, "valgrind-headers").status, Status::Missing);
        let fix = remediation(&report, "valgrind-headers");
        assert!(fix.contains("dnf install valgrind-devel"), "{fix}");
        assert!(fix.contains("VALGRIND_INCLUDE"), "{fix}");
    }

    /// Missing headers still run the self-test, which is what names an inert shim.
    #[test]
    fn self_test_runs_when_headers_are_missing() {
        let mut env = FakeEnv::healthy();
        env.files.clear();
        diagnose(&env);
        assert!(env.self_test_ran.get());
    }

    /// The search order mirrors trace-check-secret's build script.
    #[test]
    fn header_search_order_agrees_with_build_script() {
        let build_rs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../trace-check-secret/build.rs");
        let Ok(source) = std::fs::read_to_string(&build_rs) else {
            eprintln!(
                "skipping: {} is not in this source tree",
                build_rs.display()
            );
            return;
        };
        let body = &source[source.find("fn discover()").expect("discover() exists")..];
        let positions: Vec<usize> = [
            "VALGRIND_INCLUDE",
            "pkg_config()",
            "command -v valgrind",
            "/usr/include",
        ]
        .iter()
        .map(|needle| {
            body.find(needle)
                .unwrap_or_else(|| panic!("build.rs no longer mentions {needle}"))
        })
        .collect();
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        assert_eq!(positions, sorted, "build.rs changed its search order");
        assert_eq!(HEADER_SEARCH_ORDER.len(), 4);
    }

    /// No C compiler is a missing required check with distro install lines.
    #[test]
    fn missing_c_compiler_fails() {
        let report = diagnose(&FakeEnv::healthy().without_command("cc"));
        assert_eq!(check(&report, "c-compiler").status, Status::Missing);
        let fix = remediation(&report, "c-compiler");
        assert!(fix.contains("build-essential"), "{fix}");
        assert!(fix.contains("dnf install gcc"), "{fix}");
    }

    /// `CC` names the compiler the cc crate will use, so it is the one probed.
    #[test]
    fn cc_env_selects_the_compiler() {
        let mut env = FakeEnv::healthy().without_command("cc");
        env.vars.insert("CC".to_string(), "clang".to_string());
        env.commands
            .insert("clang".to_string(), ok("clang version 20\n"));
        let report = diagnose(&env);
        let compiler = check(&report, "c-compiler");
        assert_eq!(compiler.status, Status::Ok);
        assert!(compiler.detail.contains("clang"), "{}", compiler.detail);
    }

    /// Without Valgrind the self-test cannot run, so it is skipped and still fails.
    #[test]
    fn self_test_is_skipped_without_valgrind() {
        let env = FakeEnv::healthy().without_command("valgrind");
        let report = diagnose(&env);
        let self_test = check(&report, "self-test");
        assert_eq!(self_test.status, Status::Skipped);
        assert_eq!(self_test.verdict, Verdict::Fail);
        assert!(
            self_test.detail.contains("valgrind"),
            "{}",
            self_test.detail
        );
        assert!(!env.self_test_ran.get());
    }

    /// A shim built without headers reports `unsupported` and is named as inert.
    #[test]
    fn inert_shim_fails_the_self_test_with_a_named_cause() {
        let run = ran(
            "trace-check-doctor: run_mode=unsupported\ntrace-check-doctor: complete\n",
            "",
        );
        let (status, detail, fix) = evaluate_self_test(&run);
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("inert"), "{detail}");
        assert!(fix.unwrap().contains("valgrind-devel"));
    }

    /// A build-script abort over VALGRIND_INCLUDE is named, not reported as a generic failure.
    #[test]
    fn valgrind_include_build_abort_is_named() {
        let run = SelfTestRun::BuildFailed {
            diagnostics: "error: failed to run custom build command for `trace-check-secret`\n\
                          thread 'main' panicked at build.rs:51:9:\n\
                          VALGRIND_INCLUDE=/tmp/empty does not contain valgrind/memcheck.h"
                .to_string(),
        };
        let (status, detail, fix) = evaluate_self_test(&run);
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("VALGRIND_INCLUDE"), "{detail}");
        assert!(fix.unwrap().contains("VALGRIND_INCLUDE"));
    }

    /// A planted branch Memcheck did not report fails the self-test.
    #[test]
    fn undetected_planted_branch_fails() {
        let run = ran(HEALTHY_STDOUT, &format!("{}{}", calibration(), binding()));
        let (status, detail, _) = evaluate_self_test(&run);
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("planted"), "{detail}");
    }

    /// A finding in the constant-time control is a false positive and fails the self-test.
    #[test]
    fn finding_in_control_fails() {
        let body = format!(
            "{}{}{}{}",
            calibration(),
            binding(),
            planted(),
            error(
                "UninitCondition",
                "trace_check_doctor_probe::doctor_constant_time_control"
            )
        );
        let (status, detail, _) = evaluate_self_test(&ran(HEALTHY_STDOUT, &body));
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("control"), "{detail}");
    }

    /// Without the calibration diagnostic, marking is unproven and the self-test fails.
    #[test]
    fn missing_calibration_fails() {
        let body = format!("{}{}", binding(), planted());
        let (status, detail, _) = evaluate_self_test(&ran(HEALTHY_STDOUT, &body));
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("calibration"), "{detail}");
    }

    /// Without the binding diagnostic, the secret's own storage is unproven.
    #[test]
    fn missing_binding_fails() {
        let body = format!("{}{}", calibration(), planted());
        let (status, detail, _) = evaluate_self_test(&ran(HEALTHY_STDOUT, &body));
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("binding"), "{detail}");
    }

    /// A harness that never printed its completion marker cannot pass.
    #[test]
    fn incomplete_run_fails() {
        let body = format!("{}{}{}", calibration(), binding(), planted());
        let run = ran("trace-check-doctor: run_mode=valgrind\n", &body);
        let (status, detail, _) = evaluate_self_test(&run);
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("complete"), "{detail}");
    }

    /// An unexpected non-secret diagnostic makes the self-test fail rather than pass.
    #[test]
    fn unexpected_diagnostic_fails() {
        let body = format!(
            "{}{}{}<error><kind>InvalidRead</kind><what>Invalid read of size 8</what>\
             <stack><frame><fn>somewhere</fn></frame></stack></error>",
            calibration(),
            binding(),
            planted()
        );
        let (status, detail, _) = evaluate_self_test(&ran(HEALTHY_STDOUT, &body));
        assert_eq!(status, Status::Incompatible);
        assert!(detail.contains("unexpected"), "{detail}");
    }

    /// A healthy run passes and says what it confirmed.
    #[test]
    fn healthy_self_test_passes() {
        let (status, detail, fix) = evaluate_self_test(&healthy_run());
        assert_eq!(status, Status::Ok, "{detail}");
        assert!(detail.contains("planted"), "{detail}");
        assert!(detail.contains("calibration"), "{detail}");
        assert!(fix.is_none());
    }

    /// Missing llvm-tools warns, names the rustup component, and still exits 0.
    #[test]
    fn missing_llvm_tools_is_optional() {
        let mut env = FakeEnv::healthy();
        env.llvm = Err("llvm-cov not found".to_string());
        let report = diagnose(&env);
        let llvm = check(&report, "llvm-tools");
        assert_eq!(llvm.status, Status::Missing);
        assert_eq!(llvm.verdict, Verdict::Warn);
        assert!(remediation(&report, "llvm-tools").contains("rustup component add llvm-tools"));
        assert_eq!(report.exit_code(), EXIT_HEALTHY);
    }

    /// No container runtime warns, skips the image check, and still exits 0.
    #[test]
    fn missing_container_runtime_is_optional() {
        let mut env = FakeEnv::healthy();
        env.runtimes.clear();
        let report = diagnose(&env);
        assert_eq!(check(&report, "container-runtime").verdict, Verdict::Warn);
        assert_eq!(check(&report, "analyzer-image").status, Status::Skipped);
        assert_eq!(check(&report, "analyzer-image").verdict, Verdict::Skip);
        assert!(remediation(&report, "container-runtime").contains("podman"));
        assert_eq!(report.exit_code(), EXIT_HEALTHY);
    }

    /// A runtime without the pinned image warns with the exact pull command.
    #[test]
    fn missing_analyzer_image_names_the_pull() {
        let mut env = FakeEnv::healthy();
        env.runtimes
            .insert("podman".to_string(), RuntimeState::Absent);
        env.runtimes
            .insert("docker".to_string(), RuntimeState::WithoutImage);
        let report = diagnose(&env);
        assert_eq!(check(&report, "container-runtime").status, Status::Ok);
        assert_eq!(check(&report, "analyzer-image").verdict, Verdict::Warn);
        assert_eq!(
            remediation(&report, "analyzer-image"),
            format!("`docker pull {ANALYZER_IMAGE}` (needed only for `verify`)")
        );
        assert_eq!(report.exit_code(), EXIT_HEALTHY);
    }

    /// Text output labels each check and puts a fix line under every non-passing one.
    #[test]
    fn text_output_has_verdicts_and_fixes() {
        let mut env = FakeEnv::healthy().without_command("cc");
        env.llvm = Err("missing".to_string());
        let text = render_text(&diagnose(&env));
        assert!(text.contains("PASS  platform"), "{text}");
        assert!(text.contains("FAIL  c-compiler"), "{text}");
        assert!(text.contains("WARN  llvm-tools"), "{text}");
        assert!(text.contains("fix: Debian/Ubuntu: `sudo apt-get install build-essential`"));
        assert!(text.contains("not ready"), "{text}");
    }

    /// The JSON document matches the committed fixture byte for byte once durations are zeroed.
    #[test]
    fn json_matches_the_committed_fixture() {
        let mut env = FakeEnv::healthy();
        env.runtimes.clear();
        let mut report = diagnose(&env);
        for check in &mut report.checks {
            check.duration_ms = 0;
        }
        let rendered = render_json(&report);
        if std::env::var_os("DOCTOR_BLESS").is_some() {
            let path =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/doctor-sample.json");
            std::fs::write(path, &rendered).unwrap();
        }
        let expected = include_str!("../tests/fixtures/doctor-sample.json");
        assert_eq!(rendered, expected, "regenerate with DOCTOR_BLESS=1");
    }
}
