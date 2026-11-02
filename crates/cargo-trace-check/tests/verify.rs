//! `cargo trace-check verify` end to end.
//!
//! Drives the real binary so argument handling, report rendering, and exit
//! codes are exercised as a developer sees them. Skips without a container
//! runtime and analyzer image, unless `TRACE_CHECK_REQUIRE_SYMBOLIC=1` demands
//! them.

use std::path::{Path, PathBuf};
use std::process::Command;

use trace_check::symbolic::Verifier;

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

/// Asks the library the same question the CLI asks, rather than probing for a
/// runtime here.
///
/// An earlier version of this helper reimplemented the probe and reproduced the
/// defect under review: it took the first runtime on `PATH` and looked for the
/// image only there, so on a machine with Podman installed and the image in
/// Docker every test "skipped" -- and failed outright under
/// `TRACE_CHECK_REQUIRE_SYMBOLIC`. Duplicating the logic is what made that
/// possible, so it is not duplicated.
fn analyzer_available() -> bool {
    let reason = match Verifier::prepare() {
        Err(e) => Some(e.to_string()),
        Ok(mut verifier) => verifier.check_image().err().map(|e| e.to_string()),
    };
    match reason {
        None => true,
        Some(reason) => {
            assert!(
                std::env::var_os("TRACE_CHECK_REQUIRE_SYMBOLIC").is_none(),
                "TRACE_CHECK_REQUIRE_SYMBOLIC is set but the symbolic backend is unavailable: \
                 {reason}"
            );
            eprintln!("skipping: {reason}");
            false
        }
    }
}

/// The runtime the library would select, which is the one holding the image.
fn runtime_with_image() -> Option<String> {
    let mut verifier = Verifier::prepare().ok()?;
    verifier.check_image().ok()?;
    Some(verifier.container_tool().to_string())
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

// ---------------------------------------------------------------------------
// M5: verifying declared contracts in a real library
// ---------------------------------------------------------------------------

/// Runs the CLI without `--workspace-root`, which contract verification does
/// not use: it locates the library through `--manifest-path` instead.
fn verify_contracts(args: &[&str]) -> Run {
    let output = Command::new(cli())
        .arg("verify")
        .args(args)
        .output()
        .expect("the CLI runs");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn crypto_manifest() -> String {
    workspace_root()
        .join("examples/crypto-library/Cargo.toml")
        .display()
        .to_string()
}

/// `--contract` verifies a declared contract in a real library and reports the
/// whole chain from the developer's source to the analyzed executable.
#[test]
fn verifying_a_library_contract_reports_the_whole_chain() {
    if !analyzer_available() {
        return;
    }
    let run = verify_contracts(&[
        "--contract",
        "crypto::tag::verify_tag",
        "--manifest-path",
        &crypto_manifest(),
    ]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    for expected in [
        "Verifying crypto::tag::verify_tag",
        "Package:        crypto-library",
        "tag.rs:",
        "Resolved symbol:",
        "Target reached:  yes",
        "expected   secret  &[u8; 16]",
        "supplied   public  &[u8; 16]",
        "Result: VERIFIED_BOUNDED",
        "Production binary: not analyzed",
    ] {
        assert!(
            run.stdout.contains(expected),
            "missing {expected:?} in:\n{}",
            run.stdout
        );
    }
}

/// A vulnerable library function is detected and localized to the developer's
/// own source line.
#[test]
fn a_vulnerable_library_contract_is_detected() {
    if !analyzer_available() {
        return;
    }
    let run = verify_contracts(&[
        "--contract",
        "crypto::lookup::substitute_indexed",
        "--manifest-path",
        &crypto_manifest(),
    ]);
    // The contract declares LEAK_DETECTED, so reproducing it is a pass.
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains("LEAK_DETECTED"), "{}", run.stdout);
    assert!(
        run.stdout.contains("Secret-dependent memory access"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("lookup.rs"), "{}", run.stdout);
}

/// `--all-contracts` verifies everything the configuration declares, in one
/// run, and the JSON report carries each contract's own artifact.
#[test]
fn all_contracts_verify_and_emit_json() {
    if !analyzer_available() {
        return;
    }
    let run = verify_contracts(&[
        "--all-contracts",
        "--manifest-path",
        &crypto_manifest(),
        "--format",
        "json",
    ]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("valid JSON");
    let contracts = report["contracts"].as_array().expect("contracts");
    assert!(contracts.len() >= 8, "only {} contracts", contracts.len());
    assert_eq!(report["summary"]["expectations_reproduced"], true);
    for entry in contracts {
        assert!(entry["symbol"]["reached"].as_bool().unwrap_or(false));
        assert_eq!(entry["artifact"]["sha256"].as_str().unwrap().len(), 64);
        assert!(entry["artifact"]["production_artifact"]
            .as_str()
            .unwrap()
            .contains("not analyzed"));
    }
}

/// The CLI works for a library outside the trace-check workspace: its own
/// manifest, its own lockfile, and no knowledge of this repository's layout.
#[test]
fn the_cli_verifies_a_library_outside_the_workspace() {
    if !analyzer_available() {
        return;
    }
    let manifest = workspace_root()
        .join("examples/external-library/Cargo.toml")
        .display()
        .to_string();
    let run = verify_contracts(&["--all-contracts", "--manifest-path", &manifest]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    assert!(
        run.stdout.contains("Verifying external_library::select"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("VERIFIED_BOUNDED"), "{}", run.stdout);
    assert!(run.stdout.contains("LEAK_DETECTED"), "{}", run.stdout);
    assert!(run
        .stdout
        .contains("Every declared expectation was reproduced."));
}

/// A contract name that is not configured is refused with the list of
/// configured ones, rather than analyzed with invented bounds. The
/// *configured-but-undeclared* case — where the library has no such annotation
/// — is covered in `trace-check`'s `tests/library.rs`, which can build a
/// configuration for a name the library does not define.
#[test]
fn an_unknown_contract_name_lists_the_configured_ones() {
    let run = verify_contracts(&[
        "--contract",
        "crypto::tag::no_such_function",
        "--manifest-path",
        &crypto_manifest(),
    ]);
    assert_eq!(run.code, 2, "stdout:\n{}", run.stdout);
    assert!(
        run.stderr
            .contains("no [verify.\"crypto::tag::no_such_function\"] section"),
        "stderr:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("crypto::tag::verify_tag"),
        "the message must list what is configured: {}",
        run.stderr
    );
    assert!(!run.stdout.contains("VERIFIED_BOUNDED"));
}

/// A contract with no configuration is refused before anything is analyzed: a
/// depth bound and an observation model cannot be inferred from an annotation.
#[test]
fn an_unconfigured_contract_fails_before_analysis() {
    let run = verify_contracts(&[
        "--contract",
        "crypto::tag::verify_tag",
        "--manifest-path",
        &crypto_manifest(),
        "--config",
        &workspace_root()
            .join("examples/crypto-library/does-not-exist.toml")
            .display()
            .to_string(),
    ]);
    assert_eq!(run.code, 2);
    assert!(
        run.stderr.contains("does not exist"),
        "stderr:\n{}",
        run.stderr
    );
}

/// `--contract` and `--case` select different artifact sources and cannot be
/// combined; clap rejects the combination rather than silently preferring one.
#[test]
fn contract_and_case_selection_are_mutually_exclusive() {
    let run = verify_contracts(&[
        "--contract",
        "crypto::tag::verify_tag",
        "--case",
        "masked-scan",
    ]);
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("cannot be used with"),
        "stderr:\n{}",
        run.stderr
    );
}

/// Library-selection flags are refused on an M4 run rather than accepted with
/// no effect.
#[test]
fn library_flags_without_a_contract_are_refused() {
    let run = verify_contracts(&["--manifest-path", &crypto_manifest()]);
    assert_eq!(run.code, 2);
    assert!(
        run.stderr.contains("--all-contracts"),
        "stderr:\n{}",
        run.stderr
    );
}

/// M4's standalone cases keep working beside contract verification: the two
/// artifact sources share one engine and neither displaces the other.
#[test]
fn the_standalone_cases_still_work() {
    if !analyzer_available() {
        return;
    }
    let run = verify(&["--case", "masked-scan"]);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    assert!(run.stdout.contains("Case: masked-scan"), "{}", run.stdout);
}
