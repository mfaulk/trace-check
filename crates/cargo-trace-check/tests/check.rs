//! `cargo trace-check check` end to end.
//!
//! Drives the real binary so argument handling, report rendering and exit codes
//! are exercised as a developer sees them. Tests that need Valgrind skip
//! without it, unless `TRACE_CHECK_REQUIRE_BACKEND=1` — which CI sets — demands
//! it; the argument-handling tests need no backend at all and never skip, which
//! is itself the property they assert.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

fn library_manifest() -> PathBuf {
    workspace_root().join("examples/crypto-library/Cargo.toml")
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

/// Runs `check` against the example library with the given extra arguments.
fn check(args: &[&str]) -> Output {
    Command::new(cli())
        .arg("check")
        .arg("--manifest-path")
        .arg(library_manifest())
        .args(args)
        // A shared target directory, so each test does not rebuild the library
        // and its dependencies from scratch.
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m6-cli-tests"),
        )
        .output()
        .expect("the CLI runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The milestone's developer-facing claim, through the CLI: a declared contract
/// is checked with no hand-written test, and the leak behind a public mode is
/// found.
#[test]
fn checking_a_contract_finds_the_leak_behind_a_public_mode() {
    if !valgrind_available() {
        return;
    }
    let output = check(&[
        "--contract",
        "crypto::lookup::substitute_mode",
        "--cases",
        "50",
    ]);
    let text = stdout(&output);
    assert!(text.contains("LEAK_DETECTED"), "{text}{}", stderr(&output));
    assert!(text.contains("Secret-dependent memory address"), "{text}");
    assert!(
        text.contains("mode=1"),
        "the reported input must name the mode: {text}"
    );
    // The library configures this one as an analyzer regression, so detecting
    // its planted leak is the fixture passing.
    assert!(text.contains("analyzer-regression"), "{text}");
    assert_eq!(output.status.code(), Some(0), "{text}");
}

/// A clean contract passes and says explicitly that it is not a proof.
#[test]
fn a_clean_contract_passes_without_claiming_a_proof() {
    if !valgrind_available() {
        return;
    }
    let output = check(&["--contract", "crypto::lookup::substitute", "--cases", "30"]);
    let text = stdout(&output);
    assert!(
        text.contains("NO_LEAK_OBSERVED"),
        "{text}{}",
        stderr(&output)
    );
    assert!(
        text.contains("not proof of constant-time behavior"),
        "{text}"
    );
    assert!(text.contains("Result: PASS"), "{text}");
    assert_eq!(output.status.code(), Some(0));
    // Both positive controls confirmed, or the clean result would mean nothing.
    assert!(
        text.contains("calibration confirmed, secret binding confirmed"),
        "{text}"
    );
}

/// A leak against a *security contract* fails the build with exit 1, even
/// though the same function passes as a configured analyzer-regression fixture.
///
/// This is the policy split end to end: the only difference between the two
/// runs is which configuration file is in force.
#[test]
fn a_leak_against_a_security_contract_exits_one() {
    if !valgrind_available() {
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("security.toml");
    // No expectation at all: the default is a security contract, and the schema
    // refuses to let one declare an expected outcome.
    std::fs::write(
        &config,
        "schema_version = 1\n\n[check.\"crypto::lookup::substitute_mode\"]\n\
         description = \"treated as a real contract\"\n",
    )
    .expect("written");

    let output = check(&[
        "--contract",
        "crypto::lookup::substitute_mode",
        "--cases",
        "50",
        "--config",
        config.to_str().expect("utf-8 path"),
    ]);
    let text = stdout(&output);
    assert!(text.contains("LEAK_DETECTED"), "{text}{}", stderr(&output));
    assert!(text.contains("leak-detected (security-contract)"), "{text}");
    assert!(text.contains("Result: FAIL"), "{text}");
    assert_eq!(
        output.status.code(),
        Some(1),
        "a leak in a function declared constant-time must fail the build: {text}"
    );
}

/// A security contract may not declare an expected outcome, so a stray
/// expectation cannot make a leak acceptable. Refused when the file loads,
/// before any analysis.
#[test]
fn a_security_contract_cannot_declare_a_leak_acceptable() {
    let directory = tempfile::tempdir().expect("temp dir");
    let config = directory.path().join("sneaky.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n[check.\"crypto::lookup::substitute_mode\"]\n\
         expected_outcome = \"LEAK_DETECTED\"\n",
    )
    .expect("written");

    let output = check(&[
        "--contract",
        "crypto::lookup::substitute_mode",
        "--config",
        config.to_str().expect("utf-8 path"),
    ]);
    let message = stderr(&output);
    assert!(message.contains("security contract"), "{message}");
    assert!(message.contains("analyzer-regression"), "{message}");
    assert_ne!(output.status.code(), Some(0));
}

/// Selecting nothing is an error, not a pass: the message names what the
/// configuration offers.
#[test]
fn selecting_no_contract_is_an_error() {
    let output = check(&[]);
    let message = stderr(&output);
    assert!(message.contains("--all-configured"), "{message}");
    assert!(
        message.contains("crypto::lookup::substitute_mode"),
        "the message must list what is configured: {message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// A contract the library does not declare is reported as a missing annotation,
/// naming the contract — not as an inconclusive analysis of something else.
///
/// Needs no Valgrind, which is the point: a question about the contract is
/// answered before any backend is touched.
#[test]
fn an_undeclared_contract_is_explained_without_a_backend() {
    let output = check(&["--contract", "crypto::lookup::substitute_mdoe"]);
    let message = stderr(&output);
    assert!(message.contains("substitute_mdoe"), "{message}");
    assert!(
        message.contains("#[constant_time]") || message.contains("could not be resolved"),
        "{message}"
    );
    assert!(
        !message.to_lowercase().contains("valgrind"),
        "a contract problem must not be reported as a backend problem: {message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// A budget too small to cover a contract's boundary values is refused, naming
/// the contract and the minimum rather than silently skipping them.
#[test]
fn a_budget_that_cannot_cover_the_boundaries_is_refused() {
    let output = check(&["--contract", "crypto::reduce::reduce_once", "--cases", "4"]);
    let message = stderr(&output);
    assert!(message.contains("reduce_once"), "{message}");
    assert!(message.contains("at least"), "{message}");
    assert_ne!(output.status.code(), Some(0));
}

/// A zero budget would check nothing, and a run that checks nothing is not a
/// pass.
#[test]
fn a_zero_budget_is_refused() {
    let output = check(&["--contract", "crypto::lookup::substitute", "--cases", "0"]);
    let message = stderr(&output);
    assert!(message.contains("not a pass"), "{message}");
    assert_ne!(output.status.code(), Some(0));
}

/// `--all-configured` needs a configuration to enumerate, and says so instead
/// of quietly checking nothing.
#[test]
fn all_configured_without_a_configuration_is_an_error() {
    let directory = tempfile::tempdir().expect("temp dir");
    let absent = directory.path().join("missing.toml");
    let output = check(&[
        "--all-configured",
        "--config",
        absent.to_str().expect("utf-8 path"),
    ]);
    let message = stderr(&output);
    assert!(message.contains("does not exist"), "{message}");
    assert!(message.contains("--contract"), "{message}");
    assert_ne!(output.status.code(), Some(0));
}

/// `--ci` refuses a run that covered only part of the configuration, naming
/// what it skipped. Without it, a scoped run is allowed.
#[test]
fn ci_mode_refuses_a_partial_selection() {
    if !valgrind_available() {
        return;
    }
    let scoped = check(&["--contract", "crypto::lookup::substitute", "--cases", "30"]);
    assert_eq!(
        scoped.status.code(),
        Some(0),
        "a scoped run is allowed by default: {}",
        stdout(&scoped)
    );

    let strict = check(&[
        "--contract",
        "crypto::lookup::substitute",
        "--cases",
        "50",
        "--ci",
    ]);
    let text = stdout(&strict);
    assert_eq!(
        strict.status.code(),
        Some(2),
        "--ci must refuse a subset of the configuration: {text}"
    );
    assert!(text.contains("were not checked"), "{text}");
    assert!(text.contains("crypto::tag::verify_tag"), "{text}");
}

/// The JSON report carries a versioned schema, the per-strategy coverage, and
/// the limitations — so a stored result cannot be read as stronger than it is.
#[test]
fn the_json_report_is_versioned_and_states_its_limits() {
    if !valgrind_available() {
        return;
    }
    let output = check(&[
        "--contract",
        "crypto::lookup::substitute",
        "--cases",
        "50",
        "--format",
        "json",
    ]);
    let text = stdout(&output);
    let report: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON: {e}\n{text}"));
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["backend"], "generated-memcheck");
    let entry = &report["contracts"][0];
    assert_eq!(entry["contract"], "crypto::lookup::substitute");
    assert_eq!(entry["check"]["outcome"], "NO_LEAK_OBSERVED");
    assert_eq!(entry["check"]["calibration"], "confirmed");
    assert_eq!(entry["check"]["binding"], "confirmed");
    assert!(entry["corpus"]["sha256"]
        .as_str()
        .is_some_and(|h| h.len() == 64));
    assert!(entry["corpus"]["strategy_coverage"]
        .as_array()
        .is_some_and(|coverage| !coverage.is_empty()));
    assert!(report["limitations"]
        .as_array()
        .expect("limitations")
        .iter()
        .any(|limit| limit.as_str().is_some_and(|s| s.contains("not a proof"))));
    // The artifact a result describes is recorded, because the result is about
    // that build.
    assert!(entry["artifact_sha256"]
        .as_str()
        .is_some_and(|h| h.len() == 64));
}

/// The same seed and budget reproduce the same corpus, so a recorded seed is a
/// reproduction instruction rather than a decoration.
#[test]
fn a_recorded_seed_reproduces_the_corpus() {
    if !valgrind_available() {
        return;
    }
    let run = || {
        let output = check(&[
            "--contract",
            "crypto::lookup::substitute",
            "--cases",
            "50",
            "--seed",
            "4242",
            "--format",
            "json",
        ]);
        let report: serde_json::Value =
            serde_json::from_str(&stdout(&output)).expect("JSON report");
        (
            report["contracts"][0]["corpus"]["sha256"]
                .as_str()
                .expect("corpus hash")
                .to_string(),
            report["contracts"][0]["artifact_sha256"]
                .as_str()
                .expect("artifact hash")
                .to_string(),
        )
    };
    let (first_corpus, first_artifact) = run();
    let (second_corpus, second_artifact) = run();
    assert_eq!(first_corpus, second_corpus);
    // And the artifact hash is stable too, or `--replay` could never report
    // that it ran against the same build.
    assert_eq!(first_artifact, second_artifact);
}

/// A reproducer is written, replays, and reports that it ran against the same
/// artifact. A still-reproducing finding exits 1.
#[test]
fn a_saved_reproducer_replays_against_the_same_artifact() {
    if !valgrind_available() {
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let found = check(&[
        "--contract",
        "crypto::lookup::substitute_indexed",
        "--cases",
        "50",
        "--reproducer-dir",
        directory.path().to_str().expect("utf-8 path"),
    ]);
    assert!(
        stdout(&found).contains("LEAK_DETECTED"),
        "{}{}",
        stdout(&found),
        stderr(&found)
    );

    let saved: Vec<PathBuf> = std::fs::read_dir(directory.path())
        .expect("reproducer directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    assert_eq!(saved.len(), 1, "{saved:?}");

    // The reproducer records the developer's own source line, not the inlined
    // `core` helper the address technically lands in.
    let record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&saved[0]).expect("readable"))
            .expect("JSON reproducer");
    assert_eq!(record["schema_version"], 1);
    assert_eq!(record["contract"], "crypto::lookup::substitute_indexed");
    assert!(
        record["finding"]["site"]
            .as_str()
            .is_some_and(|site| site.contains("lookup.rs")),
        "{record}"
    );

    let replayed = check(&["--replay", saved[0].to_str().expect("utf-8 path")]);
    let text = stdout(&replayed);
    assert!(text.contains("REPRODUCED"), "{text}{}", stderr(&replayed));
    assert!(
        text.contains("reproduced against the same artifact"),
        "{text}"
    );
    assert_eq!(
        replayed.status.code(),
        Some(1),
        "a finding that still reproduces must fail: {text}"
    );
}

/// A contract whose parameter the generator cannot represent is refused with
/// the type as written, rather than given a guessed value.
#[test]
fn an_unsupported_parameter_type_is_refused() {
    // `examples/consumer-crate` declares a contract over a slice, which has no
    // concrete width to generate or mark.
    let output = Command::new(cli())
        .arg("check")
        .arg("--manifest-path")
        .arg(workspace_root().join("examples/consumer-crate/Cargo.toml"))
        .arg("--contract")
        .arg("consumer_crate::nonexistent_contract")
        .output()
        .expect("the CLI runs");
    // Either the contract is absent or its shape is unsupported; both are
    // explicit refusals naming the contract, never an inconclusive pass.
    let message = stderr(&output);
    assert!(message.contains("nonexistent_contract"), "{message}");
    assert_ne!(output.status.code(), Some(0));
}

/// A replay whose analysis is unusable exits incomplete, never 0.
///
/// The review's second finding: "did not reproduce" used to be derived from the
/// absence of a matching diagnostic, with no requirement that the run was
/// instrumented, parseable, complete or calibrated — so an infrastructure
/// failure on a rebuilt artifact looked like a fixed vulnerability and exited 0.
///
/// Driven through the CLI by pointing a valid reproducer at a *different*
/// contract's finding, so the recorded fingerprint cannot match and the
/// not-reproduced path is the one under test.
#[test]
fn a_replay_that_establishes_nothing_does_not_pass() {
    if !valgrind_available() {
        return;
    }
    let directory = tempfile::tempdir().expect("temp dir");
    let found = check(&[
        "--contract",
        "crypto::lookup::substitute_indexed",
        "--cases",
        "50",
        "--reproducer-dir",
        directory.path().to_str().expect("utf-8 path"),
    ]);
    assert!(
        stdout(&found).contains("LEAK_DETECTED"),
        "{}{}",
        stdout(&found),
        stderr(&found)
    );
    let saved = std::fs::read_dir(directory.path())
        .expect("reproducer directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .next()
        .expect("one reproducer");

    // Replayed as recorded: the finding is still there, so exit 1.
    let honest = check(&["--replay", saved.to_str().expect("utf-8 path")]);
    assert_eq!(honest.status.code(), Some(1), "{}", stdout(&honest));
    assert!(stdout(&honest).contains("REPRODUCED"));

    // Now corrupt only the recorded *location*, so nothing can match it. The
    // run is otherwise sound, so this is the genuine NOT_REPRODUCED path --
    // and because the artifact is unchanged, losing a finding is a
    // contradiction rather than a pass.
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&saved).expect("readable"))
            .expect("JSON reproducer");
    record["finding"]["location"] = serde_json::Value::String("nowhere.rs:1".into());
    record["finding"]["site"] = serde_json::Value::String("nowhere.rs:1".into());
    let altered = directory.path().join("altered.json");
    std::fs::write(&altered, record.to_string()).expect("written");

    let vanished = check(&["--replay", altered.to_str().expect("utf-8 path")]);
    let text = stdout(&vanished);
    assert!(
        text.contains("NOT_REPRODUCED"),
        "{text}{}",
        stderr(&vanished)
    );
    assert_eq!(
        vanished.status.code(),
        Some(2),
        "losing a finding on an unchanged artifact is a contradiction, not a pass: {text}"
    );
    assert!(text.contains("contradiction"), "{text}");
}

/// A reproducer whose recorded inputs no longer fit the contract is refused
/// before any analysis, rather than replayed against the wrong widths.
#[test]
fn a_reproducer_that_does_not_fit_its_contract_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("mismatched.json");
    // A valid schema whose single input names a parameter the contract does not
    // have.
    std::fs::write(
        &path,
        r#"{"schema_version":1,"contract":"crypto::lookup::substitute_mode","seed":1,
            "corpus_sha256":"x","sequence_dependent":false,
            "cases":[{"id":0,"inputs":[["nonexistent",{"repr":"scalar","bits":8,"value":1}]]}],
            "finding":{"classification":"secret_dependent_value"},
            "artifact":{"sha256":"a","profile":"p","library_package":"crypto-library",
                        "library_version":"0.1.0"}}"#,
    )
    .expect("written");

    let output = check(&["--replay", path.to_str().expect("utf-8 path")]);
    let message = stderr(&output);
    assert!(
        message.contains("does not fit") || message.contains("no value for"),
        "{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// A budget below a contract's real boundary floor is refused, naming the
/// contract and the corrected minimum.
///
/// The review's fourth finding: the floor was the largest single parameter's
/// boundary count, which accepted a budget covering barely half of a
/// two-parameter sweep.
#[test]
fn the_boundary_floor_accounts_for_every_parameter() {
    // Two `u32` parameters: 94 boundary values each, 187 distinct cases.
    let output = check(&[
        "--contract",
        "crypto::reduce::reduce_once",
        "--cases",
        "100",
    ]);
    let message = stderr(&output);
    assert!(message.contains("reduce_once"), "{message}");
    assert!(
        message.contains("187"),
        "the message must name the real floor, not one parameter's count: {message}"
    );
    assert_ne!(output.status.code(), Some(0));
}
