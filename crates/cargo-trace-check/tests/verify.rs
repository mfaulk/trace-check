//! `cargo trace-check verify` end to end.
//!
//! Drives the real binary so argument handling, report rendering, and exit
//! codes are exercised as a developer sees them. Skips without a container
//! runtime and analyzer image, unless `TRACE_CHECK_REQUIRE_SYMBOLIC=1` demands
//! them.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cargo-trace-check"))
}

/// The analyzer image is checked through the CLI itself: a dry `verify` of one
/// case fails fast with a dependency error when the backend is absent.
fn analyzer_available() -> bool {
    let tool = ["podman", "docker"].into_iter().find(|tool| {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    });
    let present = match tool {
        None => false,
        Some(tool) => Command::new(tool)
            .args(["image", "inspect", trace_check::symbolic::ANALYZER_IMAGE])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false),
    };
    if !present {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_SYMBOLIC").is_none(),
            "TRACE_CHECK_REQUIRE_SYMBOLIC is set but the symbolic analyzer image is unavailable"
        );
        eprintln!("skipping: no container runtime with the pinned analyzer image");
    }
    present
}

/// The first probed runtime whose store holds the analyzer image.
fn runtime_with_image() -> Option<String> {
    ["podman", "docker"].into_iter().find_map(|tool| {
        Command::new(tool)
            .args(["image", "inspect", trace_check::symbolic::ANALYZER_IMAGE])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|_| tool.to_string())
    })
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn verify(args: &[&str]) -> Run {
    let output = Command::new(cli())
        .arg("verify")
        .arg("--workspace-root")
        .arg(workspace_root())
        .args(args)
        .output()
        .expect("the CLI runs");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A single case verifies, prints an interpretable report, and exits 0.
#[test]
fn verifying_one_case_reports_it_and_exits_zero() {
    if !analyzer_available() {
        return;
    }
    let run = verify(&["--case", "masked-scan"]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains("VERIFIED_BOUNDED"), "{}", run.stdout);
    assert!(run.stdout.contains("masked_scan"));
    // The claim's scope travels with the claim.
    assert!(
        run.stdout.contains("declared input domain"),
        "{}",
        run.stdout
    );
    assert!(
        run.stdout.contains("@sha256:"),
        "the analyzer digest should be shown: {}",
        run.stdout
    );
}

/// A case declaring a leak passes when the analyzer reproduces the finding, and
/// the report distinguishes the function's security from the fixture's result.
#[test]
fn a_declared_leak_is_reproduced_and_exits_zero() {
    if !analyzer_available() {
        return;
    }
    let run = verify(&["--case", "table-lookup"]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains("LEAK_DETECTED"));
    assert!(
        run.stdout.contains("Secret-dependent memory access"),
        "{}",
        run.stdout
    );
}

/// JSON output is machine readable and carries provenance, outcomes, and the
/// generated analysis script.
#[test]
fn json_output_is_machine_readable() {
    if !analyzer_available() {
        return;
    }
    let run = verify(&["--case", "conditional-lookup", "--format", "json"]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout)
        .unwrap_or_else(|e| panic!("expected JSON: {e}\n{}", run.stdout));

    assert_eq!(value["backend"], "binsec-relational-symbolic");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["cases"][0]["outcome"], "LEAK_DETECTED");
    assert_eq!(value["cases"][0]["expectation"]["met"], true);
    assert_eq!(value["cases"][0]["evidence"], "bounded_relational_symbolic");
    assert!(value["cases"][0]["script"]
        .as_str()
        .expect("the script is recorded")
        .contains("secret global"));
    assert!(value["provenance"]["artifact_sha256"]
        .as_str()
        .is_some_and(|hash| hash.len() == 64));
    assert!(!value["limitations"]
        .as_array()
        .expect("limitations")
        .is_empty());
}

/// An unknown case name is an error that lists what is available, rather than a
/// run that verifies nothing and succeeds.
#[test]
fn an_unknown_case_name_is_an_error() {
    let run = verify(&["--case", "no-such-case"]);
    assert_eq!(run.code, 2, "stdout:\n{}", run.stdout);
    assert!(
        run.stderr.contains("no verification case"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("table-lookup"),
        "the available cases should be listed: {}",
        run.stderr
    );
}

/// A missing case file is an error, not an empty pass.
#[test]
fn a_missing_case_file_is_an_error() {
    let run = verify(&["--cases", "/nonexistent/cases.json"]);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("cases.json"), "{}", run.stderr);
}

/// A case file whose secret specification is invalid is refused before any
/// analysis runs, so a typo cannot surface as a mysterious clean result.
#[test]
fn an_invalid_secret_specification_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("cases.json");
    std::fs::write(
        &path,
        r#"{
          "schema_version": 1,
          "target_source": "src/targets.rs",
          "cases": [{
            "id": "bad",
            "function": "masked_scan",
            "entry_symbol": "tc_harness_masked_scan",
            "halt_symbol": "tc_halt",
            "secret_globals": [],
            "public_globals": ["TC_TABLE"],
            "features": ["control-flow", "memory-access"],
            "max_depth": 100,
            "expected_outcome": "VERIFIED_BOUNDED"
          }]
        }"#,
    )
    .expect("write cases");

    let run = verify(&["--cases", path.to_str().expect("utf-8 path")]);
    assert_eq!(run.code, 2, "stdout:\n{}", run.stdout);
    assert!(
        run.stderr.contains("no secret globals"),
        "the cause should be named: {}",
        run.stderr
    );
}

/// A symbol name that is not a plain identifier is rejected before it can reach
/// the generated analysis script.
#[test]
fn an_injected_symbol_name_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("cases.json");
    std::fs::write(
        &path,
        r#"{
          "schema_version": 1,
          "target_source": "src/targets.rs",
          "cases": [{
            "id": "injected",
            "function": "masked_scan",
            "entry_symbol": "tc_harness_masked_scan",
            "halt_symbol": "tc_halt",
            "secret_globals": ["TC_SECRET\nexplore all"],
            "public_globals": [],
            "features": ["control-flow", "memory-access"],
            "max_depth": 100,
            "expected_outcome": "VERIFIED_BOUNDED"
          }]
        }"#,
    )
    .expect("write cases");

    let run = verify(&["--cases", path.to_str().expect("utf-8 path")]);
    assert_eq!(run.code, 2);
    assert!(
        run.stderr.contains("not a plain symbol name"),
        "{}",
        run.stderr
    );
}

/// An explicit `--container-runtime` is honored, and an unsupported one is
/// rejected by argument parsing rather than attempted.
#[test]
fn an_explicit_container_runtime_is_honored() {
    let run = verify(&["--case", "masked-scan", "--container-runtime", "containerd"]);
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("containerd"),
        "the rejected value should be named: {}",
        run.stderr
    );

    if !analyzer_available() {
        return;
    }
    // The runtime that holds the image is what CI pulls into; naming it
    // explicitly must produce the same result as automatic selection.
    let tool = runtime_with_image().expect("a runtime holds the image");
    let run = verify(&[
        "--case",
        "masked-scan",
        "--container-runtime",
        &tool,
        "--format",
        "json",
    ]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON");
    assert_eq!(value["provenance"]["container_tool"], tool);
}

/// Automatic selection picks a runtime that actually holds the image, not
/// whichever appears first.
///
/// The CI failure this covers: the image was pulled with Docker, Podman probed
/// first and was chosen, and every case failed with "not present locally"
/// before any analysis ran.
#[test]
fn automatic_selection_picks_a_runtime_holding_the_image() {
    if !analyzer_available() {
        return;
    }
    let run = verify(&["--case", "masked-scan", "--format", "json"]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON");
    let used = value["provenance"]["container_tool"]
        .as_str()
        .expect("the runtime is recorded");
    let holds = Command::new(used)
        .args(["image", "inspect", trace_check::symbolic::ANALYZER_IMAGE])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    assert!(holds, "{used} was selected but does not hold the image");

    // CI pulls into one runtime only; when it says which, the selection must
    // agree.
    if let Ok(expected) = std::env::var("EXPECTED_CONTAINER_RUNTIME") {
        assert_eq!(used, expected);
    }
}

/// `verify` does not change `test`: the M3 backend stays independent of the
/// symbolic one.
#[test]
fn the_dynamic_subcommands_are_still_available() {
    let output = Command::new(cli())
        .args(["list", "--help"])
        .output()
        .expect("the CLI runs");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("--manifest-path"));

    let output = Command::new(cli())
        .arg("--help")
        .output()
        .expect("the CLI runs");
    let help = String::from_utf8_lossy(&output.stdout);
    for subcommand in ["test", "list", "verify"] {
        assert!(
            help.contains(subcommand),
            "{subcommand} missing from {help}"
        );
    }
}

/// A case file that does not state its observation model is refused before any
/// analysis runs.
#[test]
fn a_case_without_a_declared_observation_model_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("cases.json");
    std::fs::write(
        &path,
        r#"{
          "schema_version": 1,
          "target_source": "src/targets.rs",
          "cases": [{
            "id": "unstated",
            "function": "masked_scan",
            "entry_symbol": "tc_harness_masked_scan",
            "halt_symbol": "tc_halt",
            "secret_globals": ["TC_SECRET"],
            "public_globals": ["TC_TABLE"],
            "features": [],
            "max_depth": 100,
            "expected_outcome": "VERIFIED_BOUNDED"
          }]
        }"#,
    )
    .expect("write cases");

    let run = verify(&["--cases", path.to_str().expect("utf-8 path")]);
    assert_eq!(run.code, 2, "stdout:\n{}", run.stdout);
    assert!(
        run.stderr.contains("observation model"),
        "the cause should be named: {}",
        run.stderr
    );
}
