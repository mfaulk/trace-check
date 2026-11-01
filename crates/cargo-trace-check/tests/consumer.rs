//! End-to-end tests driving the real CLI against `examples/consumer-crate`.
//!
//! These exercise the actual binary and its **exit codes**, not internal
//! return values, because the exit code is the contract CI depends on.
//!
//! They skip when Valgrind is absent so the fast suite runs on a bare machine,
//! but `TRACE_CHECK_REQUIRE_BACKEND=1` — which CI sets — makes a missing
//! backend a failure, so a skip can never pass for a success.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate lives two levels below the workspace root")
        .to_path_buf()
}

fn consumer_dir() -> PathBuf {
    workspace_root().join("examples/consumer-crate")
}

/// The binary under test, as cargo built it for this test run.
fn cli() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_cargo-trace-check"));
    if !path.exists() {
        path = workspace_root().join("target/debug/cargo-trace-check");
    }
    path
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

impl Run {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| {
            panic!(
                "expected JSON on stdout: {e}\nstdout:\n{}\nstderr:\n{}",
                self.stdout, self.stderr
            )
        })
    }

    /// Maps short test name to its outcome.
    fn outcomes(&self) -> BTreeMap<String, String> {
        self.json()["tests"]
            .as_array()
            .expect("tests array")
            .iter()
            .map(|test| {
                let name = test["test"].as_str().unwrap_or_default();
                let short = name.rsplit("::").next().unwrap_or(name).to_string();
                (
                    short,
                    test["outcome"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(cli())
        .current_dir(consumer_dir())
        .args(args)
        .output()
        .expect("the CLI runs");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Discovery finds the consumer's tests and its declared contract without any
/// manifest maintained by hand.
#[test]
fn discovery_finds_tests_and_contracts() {
    if !valgrind_available() {
        return;
    }
    let listed = run(&["list", "--format", "json"]);
    assert_eq!(listed.code, 0, "stderr:\n{}", listed.stderr);
    let value = listed.json();

    let tests = value["tests"].as_array().expect("tests");
    assert!(
        tests.len() >= 7,
        "expected the consumer's checks, got {}",
        tests.len()
    );
    let contracts = value["contracts"].as_array().expect("contracts");
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0]["function"], "verify_tag");
    assert_eq!(contracts[0]["secrets"][0], "expected");

    // The declared target links a test to its contract.
    assert!(
        tests.iter().any(|test| test["target"] == "verify_tag"),
        "a test should declare the contract it covers"
    );
}

/// The headline requirement: both a secret-dependent branch and a
/// secret-dependent address are detected, while the constant-time controls are
/// accepted for the paths exercised.
#[test]
fn branches_and_addresses_are_detected_and_controls_pass() {
    if !valgrind_available() {
        return;
    }
    let result = run(&["test", "--format", "json"]);
    let outcomes = result.outcomes();

    for (test, expected) in [
        ("verify_tag_is_constant_time", "NO_LEAK_OBSERVED"),
        ("table_scan_is_constant_time", "NO_LEAK_OBSERVED"),
        ("arithmetic_on_a_secret_is_permitted", "NO_LEAK_OBSERVED"),
        ("vulnerable_tag_compare_leaks", "LEAK_DETECTED"),
        ("vulnerable_table_lookup_leaks", "LEAK_DETECTED"),
        ("leak_in_a_helper_is_detected", "LEAK_DETECTED"),
        ("heap_secret_is_marked_through_a_slice", "LEAK_DETECTED"),
    ] {
        assert_eq!(
            outcomes.get(test).map(String::as_str),
            Some(expected),
            "{test}: wrong outcome. all outcomes: {outcomes:?}"
        );
    }

    // A detected leak exits 1.
    assert_eq!(result.code, 1, "a detected leak must exit 1");
}

/// The secret-dependent address finding carries a source location, which is
/// what makes it actionable, and is classified as a value use rather than a
/// branch.
#[test]
fn address_finding_is_classified_and_located() {
    if !valgrind_available() {
        return;
    }
    let result = run(&[
        "test",
        "--filter",
        "vulnerable_table_lookup",
        "--format",
        "json",
    ]);
    let value = result.json();
    let findings = value["tests"][0]["findings"]
        .as_array()
        .expect("findings array");
    assert!(!findings.is_empty(), "the address leak must be reported");
    assert_eq!(findings[0]["classification"], "secret_dependent_value");
    let location = findings[0]["location"].as_str().unwrap_or_default();
    assert!(
        location.contains("lib.rs"),
        "expected a source location, got {location:?}"
    );
    // Every finding must be traceable to our marking, not to unrelated
    // uninitialized memory.
    assert!(findings[0]["origin"]
        .as_str()
        .unwrap_or_default()
        .contains("client request"));
}

/// The positive control fires for every executed test. Without it a clean
/// result would prove nothing.
#[test]
fn every_test_confirms_its_positive_control() {
    if !valgrind_available() {
        return;
    }
    let value = run(&["test", "--format", "json"]).json();
    for test in value["tests"].as_array().expect("tests") {
        assert_eq!(
            test["calibration"], "confirmed",
            "test {} did not confirm secret marking",
            test["test"]
        );
    }
}

/// A clean, filtered run exits 0 and reports its contract as covered.
#[test]
fn a_passing_filtered_run_exits_zero() {
    if !valgrind_available() {
        return;
    }
    let result = run(&[
        "test",
        "--filter",
        "verify_tag_is_constant_time",
        "--format",
        "json",
    ]);
    assert_eq!(result.code, 0, "stdout:\n{}", result.stdout);
    let value = result.json();
    assert_eq!(value["summary"]["ok"], true);
    assert_eq!(value["summary"]["passed"], 1);
    assert_eq!(value["selected"], 1);
    assert_eq!(value["executed"], 1);
    let contract = &value["contracts"][0];
    assert_eq!(contract["coverage"], "covered");
}

/// A filter that matches nothing is an error, not a vacuous success. A run that
/// checks nothing must never report a pass.
#[test]
fn a_filter_matching_nothing_exits_with_an_error() {
    if !valgrind_available() {
        return;
    }
    let result = run(&[
        "test",
        "--filter",
        "no_such_test_anywhere",
        "--format",
        "json",
    ]);
    assert_eq!(result.code, 2, "zero selected tests must exit 2");
    let value = result.json();
    assert_eq!(value["selected"], 0);
    assert_eq!(value["summary"]["ok"], false);
    assert!(value["summary"]["blocking_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap_or_default().contains("selected no")));
}

/// Reports carry the provenance needed to reinterpret them later.
#[test]
fn report_carries_provenance() {
    if !valgrind_available() {
        return;
    }
    let value = run(&["test", "--filter", "table_scan", "--format", "json"]).json();
    let provenance = &value["provenance"];
    assert!(provenance["rustc_version"]
        .as_str()
        .unwrap_or_default()
        .contains("rustc"));
    assert!(provenance["analyzer"]
        .as_str()
        .unwrap_or_default()
        .contains("valgrind"));
    assert_eq!(provenance["target"], "x86_64-unknown-linux-gnu");
    assert!(!provenance["artifact_sha256"]
        .as_str()
        .unwrap_or_default()
        .is_empty());
    assert_eq!(value["schema_version"], 1);
}

/// Text output is readable and states what the analysis does not establish.
#[test]
fn text_output_is_readable_and_bounded() {
    if !valgrind_available() {
        return;
    }
    let result = run(&["test", "--filter", "table_scan"]);
    assert_eq!(result.code, 0);
    for expected in [
        "Backend: native-memcheck",
        "Target:  x86_64-unknown-linux-gnu",
        "table_scan_is_constant_time",
        "PASS",
        "NO_LEAK_OBSERVED",
        "not a proof of constant-time behavior",
    ] {
        assert!(
            result.stdout.contains(expected),
            "missing {expected:?} in:\n{}",
            result.stdout
        );
    }
}

/// Repeated findings from an unrolled loop are collapsed in the terminal, so a
/// single leak does not produce dozens of identical lines.
#[test]
fn repeated_findings_are_collapsed_in_text_output() {
    if !valgrind_available() {
        return;
    }
    let result = run(&["test", "--filter", "vulnerable_tag_compare"]);
    assert_eq!(result.code, 1);
    assert!(
        result.stdout.contains("occurrences"),
        "the unrolled branch findings should be collapsed:\n{}",
        result.stdout
    );
    assert_eq!(
        result.stdout.matches("Secret-dependent branch").count(),
        1,
        "the finding should be listed once:\n{}",
        result.stdout
    );
}

/// Plain `cargo test` works without Valgrind and never reports a successful
/// security check — it says the checks were skipped.
#[test]
fn plain_cargo_test_skips_without_claiming_success() {
    let output = Command::new("cargo")
        .current_dir(consumer_dir())
        .args(["test", "--", "--nocapture"])
        .output()
        .expect("cargo test runs");
    assert!(
        output.status.success(),
        "plain cargo test should pass:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("SKIPPED constant-time check"),
        "the skip notice must be visible:\n{stdout}"
    );
    assert!(
        stdout.contains("cargo trace-check test"),
        "the notice should name the real command"
    );
    assert!(
        !stdout.contains("NO_LEAK_OBSERVED"),
        "an uninstrumented run must not report a security outcome"
    );
}

/// A `#[constant_time]` function with no `ct_test` covering it is reported as
/// `untested` and fails the run.
///
/// This is the requirement that keeps an annotation from implying verification
/// it does not have. The consumer gates such a contract behind a feature so it
/// can be demonstrated without making every other run fail.
#[test]
fn an_untested_contract_fails_the_run() {
    if !valgrind_available() {
        return;
    }
    let result = run(&[
        "test",
        "--features",
        "untested-contract",
        "--filter",
        "verify_tag_is_constant_time",
        "--format",
        "json",
    ]);
    let value = result.json();

    let contracts = value["contracts"].as_array().expect("contracts");
    let orphan = contracts
        .iter()
        .find(|contract| contract["function"] == "unverified_mix")
        .unwrap_or_else(|| {
            panic!("the feature-gated contract should be discovered: {contracts:?}")
        });
    assert_eq!(orphan["coverage"], "untested");
    assert_eq!(orphan["secrets"][0], "key");

    // The covered contract is still reported as covered, so one orphan does not
    // taint the others.
    let covered = contracts
        .iter()
        .find(|contract| contract["function"] == "verify_tag")
        .expect("the covered contract");
    assert_eq!(covered["coverage"], "covered");

    assert_eq!(value["summary"]["ok"], false);
    assert!(value["summary"]["blocking_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap_or_default().contains("untested")));

    // No leak was selected, so the failure is an incomplete analysis: exit 2.
    assert_eq!(result.code, 2, "an untested contract must exit 2");
}
