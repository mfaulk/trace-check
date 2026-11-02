//! Regression tests for the defects found in review of PR #3.
//!
//! Each drives the real CLI against `examples/discovery-hazard`, a crate kept
//! outside the workspace because its ordinary unit test fails by design.
//!
//! | Finding | Hazard | Test |
//! | --- | --- | --- |
//! | discovery executed ordinary tests | a failing `#[test]` with a side effect | [`discovery_does_not_execute_ordinary_tests`] |
//! | a contract could be covered without invoking its function | a `ct_test` that names a target it never calls | [`a_claimed_but_uninvoked_target_is_not_coverage`] |
//! | same-named contracts overwrote each other | two modules each defining `verify` | [`same_named_contracts_in_different_modules_are_distinct`] |

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn hazard_manifest() -> PathBuf {
    workspace_root().join("examples/discovery-hazard/Cargo.toml")
}

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cargo-trace-check"))
}

/// Where the hazard crate's ordinary test records that it executed.
fn sentinel() -> PathBuf {
    std::env::temp_dir().join("trace-check-discovery-hazard-sentinel")
}

fn valgrind_available() -> bool {
    let present = Command::new("valgrind")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !present {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
            "TRACE_CHECK_REQUIRE_BACKEND is set but valgrind is not on PATH"
        );
        eprintln!("skipping: valgrind is not on PATH");
    }
    present
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(cli())
        .arg(args[0])
        .arg("--manifest-path")
        .arg(hazard_manifest())
        .args(&args[1..])
        .output()
        .expect("the CLI runs");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn json(run: &Run) -> serde_json::Value {
    serde_json::from_str(&run.stdout).unwrap_or_else(|e| {
        panic!(
            "expected JSON: {e}\nstdout:\n{}\nstderr:\n{}",
            run.stdout, run.stderr
        )
    })
}

/// Discovery must not execute ordinary unit tests.
///
/// The hazard crate's ordinary test writes a sentinel file and then fails. If
/// discovery executed it, the sentinel would appear and an unrelated failure
/// would block discovery entirely. Both are observable here.
#[test]
fn discovery_does_not_execute_ordinary_tests() {
    if !valgrind_available() {
        return;
    }
    let _ = std::fs::remove_file(sentinel());

    let listed = run(&["list", "--format", "json"]);
    assert_eq!(
        listed.code, 0,
        "a failing ordinary test must not block discovery.\nstderr:\n{}",
        listed.stderr
    );
    assert!(
        !sentinel().exists(),
        "discovery executed an ordinary unit test: its sentinel file appeared at {}",
        sentinel().display()
    );

    // Discovery still found the real checks and contracts.
    let value = json(&listed);
    assert!(!value["tests"].as_array().expect("tests").is_empty());
    assert!(!value["contracts"].as_array().expect("contracts").is_empty());
}

/// A `ct_test` that names a target without invoking it must not produce
/// coverage.
///
/// This is the reviewed counterexample: the test marks a secret and calibrates
/// but never calls the contract's function, so a clean Memcheck result says
/// nothing about that function. The generated code checks an invocation
/// counter, so the test fails and the contract stays uncovered.
#[test]
fn a_claimed_but_uninvoked_target_is_not_coverage() {
    if !valgrind_available() {
        return;
    }
    let result = run(&["test", "--format", "json"]);
    let value = json(&result);

    let claim = value["tests"]
        .as_array()
        .expect("tests")
        .iter()
        .find(|test| {
            test["test"]
                .as_str()
                .unwrap_or_default()
                .ends_with("claims_a_target_without_invoking_it")
        })
        .expect("the claiming test should have run");

    assert_eq!(claim["outcome"], "INCONCLUSIVE");
    assert_eq!(claim["invoked_target"], false);
    let message = claim["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("never invoked it"),
        "the message should name the cause: {message}"
    );

    // And the contract is not covered.
    let contract = value["contracts"]
        .as_array()
        .expect("contracts")
        .iter()
        .find(|contract| {
            contract["id"]
                .as_str()
                .unwrap_or_default()
                .ends_with("never_invoked")
        })
        .expect("the uninvoked contract");
    assert_ne!(
        contract["coverage"], "covered",
        "a contract must never be covered by a test that did not invoke it"
    );

    assert_ne!(result.code, 0, "the run must not succeed");
}

/// Two contracts with the same function name in different modules must both
/// survive discovery and be tracked independently.
///
/// Keyed on the bare name, one silently overwrote the other, and a test
/// targeting `verify` could mark the survivor covered while the other vanished.
#[test]
fn same_named_contracts_in_different_modules_are_distinct() {
    if !valgrind_available() {
        return;
    }
    let value = json(&run(&["test", "--format", "json"]));
    let contracts = value["contracts"].as_array().expect("contracts");

    let ids: Vec<&str> = contracts
        .iter()
        .filter_map(|contract| contract["id"].as_str())
        .collect();
    assert!(
        ids.iter().any(|id| id.ends_with("authentication::verify")),
        "the authentication contract should be present: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id.ends_with("encryption::verify")),
        "the encryption contract should be present: {ids:?}"
    );

    // One is covered by its specific test; the other has no test at all, and
    // the two states are reported separately rather than merged.
    let coverage = |suffix: &str| -> String {
        contracts
            .iter()
            .find(|contract| {
                contract["id"]
                    .as_str()
                    .unwrap_or_default()
                    .ends_with(suffix)
            })
            .and_then(|contract| contract["coverage"].as_str())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(coverage("authentication::verify"), "covered");
    assert_eq!(coverage("encryption::verify"), "untested");
}

/// Plain `cargo test` on the hazard crate reports the constant-time checks as
/// `ignored`, never as `ok`, so an unrun security check cannot look like a
/// passing one.
#[test]
fn plain_cargo_test_reports_checks_as_ignored() {
    let output = Command::new("cargo")
        .arg("test")
        .arg("--manifest-path")
        .arg(hazard_manifest())
        .arg("--")
        .arg("--skip")
        // The hazard crate's ordinary test fails by design; skip it so this
        // test observes only how the checks are reported.
        .arg("ordinary_test_with_a_side_effect_that_fails")
        .output()
        .expect("cargo test runs");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("ignored"),
        "constant-time checks should be reported as ignored:\n{stdout}"
    );
    assert!(
        stdout.contains("run `cargo trace-check test`"),
        "the ignore reason should name the real command:\n{stdout}"
    );
    assert!(
        !stdout.contains("NO_LEAK_OBSERVED"),
        "an unrun check must not report a security outcome:\n{stdout}"
    );
}
