//! `cargo trace-check check --explore` end to end, as a developer sees it.
//!
//! The milestone's acceptance gate. These drive the real binary so argument
//! handling, the three-section report, the CI policy and the exit codes are all
//! exercised together.
//!
//! The decisive one is
//! [`exploration_finds_a_leak_m6_generation_cannot_reach`]: the same contract,
//! the same budget, the same security backend, and the only difference is
//! whether `--explore` was passed.
//!
//! Tests needing a backend skip without it, unless `TRACE_CHECK_REQUIRE_BACKEND`
//! — which CI sets — demands it. The ordering and argument tests need no
//! backend at all and never skip, which is itself the property they assert.

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

fn external_manifest() -> PathBuf {
    workspace_root().join("examples/external-library/Cargo.toml")
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

fn llvm_tools_available() -> bool {
    let present = trace_check::coverage::LlvmTools::locate(None).is_ok();
    if !present {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
            "TRACE_CHECK_REQUIRE_BACKEND is set but the toolchain's llvm-tools are missing; \
             install them with `rustup component add llvm-tools`"
        );
        eprintln!("skipping: the toolchain's llvm-tools are not installed");
    }
    present
}

/// Whether both backends are present. Exploration needs the LLVM tools and the
/// analysis that follows it needs Valgrind.
fn backends_available() -> bool {
    llvm_tools_available() && valgrind_available()
}

fn run(manifest: &Path, args: &[&str]) -> Output {
    Command::new(cli())
        .arg("check")
        .arg("--manifest-path")
        .arg(manifest)
        .args(args)
        // A shared target directory, so each test does not rebuild the library
        // and its dependencies from scratch.
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m7-cli-tests"),
        )
        .output()
        .expect("the CLI runs")
}

fn check(args: &[&str]) -> Output {
    run(&library_manifest(), args)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The milestone's acceptance claim, through the CLI.
///
/// `crypto::hidden::nested_modes` guards its leak with a conjunction over three
/// public parameters. `tests/baseline.rs` in the library crate proves M6's
/// boundary and pairwise stages cannot construct a reaching input at any
/// budget. So the same command differs in one flag and in one outcome.
#[test]
fn exploration_finds_a_leak_m6_generation_cannot_reach() {
    if !backends_available() {
        return;
    }
    let config = workspace_root().join("examples/crypto-library/trace-check.toml");

    // Without exploration: the leak is there, on a path nothing generated
    // reaches, and the tool says so honestly rather than claiming safety.
    // `--no-explore` is what makes this a fair comparison -- the library's own
    // configuration is still read, so the only difference is the flag.
    let without = check(&[
        "--contract",
        "crypto::hidden::nested_modes",
        "--config",
        config.to_str().expect("a utf-8 path"),
        "--cases",
        "200",
        "--no-explore",
    ]);
    let text = stdout(&without);
    assert!(
        text.contains("NO_LEAK_OBSERVED"),
        "M6 generation unexpectedly found the hidden path:\n{text}\n{}",
        stderr(&without)
    );
    assert!(
        !text.contains("-- exploration"),
        "a run without --explore must not report an exploration section"
    );

    // With exploration: the same security backend finds it.
    let with = check(&[
        "--contract",
        "crypto::hidden::nested_modes",
        "--config",
        config.to_str().expect("a utf-8 path"),
        "--cases",
        "200",
        "--explore",
    ]);
    let text = stdout(&with);
    assert!(
        text.contains("LEAK_DETECTED"),
        "exploration did not find the hidden path:\n{text}\n{}",
        stderr(&with)
    );
    // The finding is attributed to the library's own source, in the function
    // the contract names.
    assert!(
        text.contains("hidden.rs:63"),
        "the finding was not attributed to the secret-indexed load:\n{text}"
    );
    // And the input is traceable back to the search that produced it.
    assert!(
        text.contains("input from:"),
        "a finding on an explored case must name where its input came from:\n{text}"
    );
    assert!(
        text.contains("explored "),
        "the corpus must label explored cases"
    );
}

/// The report keeps three sections apart, and the exploration section is
/// labelled as carrying no security evidence.
#[test]
fn the_report_separates_discovery_from_security_evidence() {
    if !backends_available() {
        return;
    }
    let config = workspace_root().join("examples/crypto-library/trace-check.toml");
    let output = check(&[
        "--contract",
        "crypto::hidden::nested_modes",
        "--config",
        config.to_str().expect("a utf-8 path"),
        "--cases",
        "200",
        "--explore",
        "--explore-cases",
        "512",
    ]);
    let text = stdout(&output);

    let discovery = text
        .find("-- exploration (discovery artifact; no security evidence) --")
        .expect("an exploration section");
    let security = text
        .find("-- security analysis (uninstrumented artifact) --")
        .expect("a security section");
    let decision = text.find("CI decision:").expect("a CI decision section");
    assert!(
        discovery < security && security < decision,
        "the sections are out of order: discovery {discovery}, security {security}, decision \
         {decision}"
    );

    // The discovery artifact marks nothing, and says so.
    assert!(text.contains("this artifact marks no secret and makes no claim"));
    // The granularity is stated, including what is unavailable.
    assert!(text.contains("llvm-regions"));
    assert!(text.contains("branch, edge and comparison feedback are unavailable"));
    // The two artifact hashes are both present and different: a report must
    // never advertise one artifact as representing both analyses.
    let discovery_hash = extract(&text, "  artifact: ", " [-Cinstrument-coverage]");
    let security_hash = extract(&text, "  artifact: ", " [no instrumentation]");
    assert_ne!(
        discovery_hash, security_hash,
        "the discovery and security artifacts reported the same hash"
    );
    // The CI decision restates no coverage number.
    let tail = &text[decision..];
    assert!(
        !tail.contains("regions"),
        "the CI decision section mentions regions, which conflates execution coverage with \
         verification coverage:\n{tail}"
    );
    assert!(tail.contains("exploration coverage is not verification coverage"));
    // And the limitation names where coverage was measured.
    assert!(text.contains("Coverage guided which inputs were analyzed; it verifies nothing."));
}

fn extract(text: &str, prefix: &str, suffix: &str) -> String {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            if let Some(value) = rest.strip_suffix(suffix) {
                return value.to_string();
            }
        }
    }
    panic!("no line matching {prefix:?}…{suffix:?} in:\n{text}");
}

/// A clean result never rests on the instrumented artifact: the selected corpus
/// is analyzed in the uninstrumented one, under the mandatory controls.
#[test]
fn a_clean_result_rests_on_the_uninstrumented_artifact() {
    if !backends_available() {
        return;
    }
    let config = workspace_root().join("examples/crypto-library/trace-check.toml");
    let output = check(&[
        "--contract",
        "crypto::hidden::nested_modes_clean",
        "--config",
        config.to_str().expect("a utf-8 path"),
        "--cases",
        "200",
        "--explore",
    ]);
    let text = stdout(&output);
    assert!(
        text.contains("NO_LEAK_OBSERVED"),
        "the clean control produced a finding:\n{text}\n{}",
        stderr(&output)
    );
    // Exploration reached the deeply guarded region -- so the clean result is
    // about code that actually ran, not about a path nothing visited.
    assert!(
        text.contains("added by exploration"),
        "the control did not record what exploration added:\n{text}"
    );
    let added = extract_number(&text, "regions:  ", "added by exploration");
    assert!(
        added > 0,
        "exploration reached nothing new, so this is not a false-positive control at all"
    );
    // The controls are still mandatory and still confirmed.
    assert!(text.contains("controls: calibration confirmed, secret binding confirmed"));
    // The analyzed artifact is the uninstrumented one.
    assert!(text.contains("[no instrumentation]"));
    assert_eq!(output.status.code(), Some(0), "the control must pass");
}

/// Pulls the trailing integer before `marker` out of the line starting with
/// `prefix`, e.g. `regions:  34 reached, 19 by …, 15 added by exploration`.
fn extract_number(text: &str, prefix: &str, marker: &str) -> usize {
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !line.contains(prefix.trim()) || !trimmed.contains(marker) {
            continue;
        }
        let before = &trimmed[..trimmed.find(marker).expect("checked above")];
        if let Some(number) = before
            .split_whitespace()
            .filter_map(|field| field.trim_end_matches(',').parse::<usize>().ok())
            .next_back()
        {
            return number;
        }
    }
    panic!("no number before {marker:?} on a {prefix:?} line in:\n{text}");
}

/// A leak against a *security contract* fails CI, whether or not exploration
/// found the input.
#[test]
fn a_leak_against_a_security_contract_fails_ci() {
    if !backends_available() {
        return;
    }
    // The library's own configuration declares its vulnerable fixtures as
    // analyzer regressions, where detecting the leak is the entry passing. This
    // test needs the other kind, so it writes a configuration that holds the
    // same function to the property instead.
    let dir = std::env::temp_dir().join("trace-check-m7-security-contract");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("trace-check.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n\
         [check.\"crypto::lookup::substitute_mode\"]\n\
         expectation = \"security-contract\"\n\n\
         [check.\"crypto::lookup::substitute_mode\".explore]\n\
         enabled = true\n\
         candidate_budget = 256\n",
    )
    .expect("the config is writable");

    let output = check(&[
        "--contract",
        "crypto::lookup::substitute_mode",
        "--config",
        config.to_str().expect("a utf-8 path"),
        "--cases",
        "64",
        "--ci",
    ]);
    let text = stdout(&output);
    assert!(text.contains("LEAK_DETECTED"), "{text}");
    assert!(
        text.contains("leak-detected"),
        "the policy must name the leak"
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "a leak must exit 1:\n{text}\n{}",
        stderr(&output)
    );
    assert!(text.contains("Result: FAIL"));
}

/// An invalid contract is diagnosed before the coverage tools or the analyzer
/// are required.
///
/// The same ordering M5 and M6 settled on, extended to a third backend. A
/// developer with a misspelled contract name must hear about the name — and the
/// test proves it by making both backends unreachable and still expecting the
/// right diagnosis.
#[test]
fn a_bad_contract_is_diagnosed_before_any_backend() {
    let output = Command::new(cli())
        .arg("check")
        .arg("--manifest-path")
        .arg(library_manifest())
        .args([
            "--contract",
            "crypto::hidden::no_such_function",
            "--explore",
        ])
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m7-cli-tests"),
        )
        // The coverage tools are pointed at nothing, so reaching them is a
        // failure of the ordering rather than of the environment. `PATH` is
        // left alone: `cargo` itself is on it, and a run that cannot invoke
        // Cargo tests nothing about ordering.
        .env("TRACE_CHECK_LLVM_TOOLS", "/nonexistent/llvm")
        .output()
        .expect("the CLI runs");
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        message.contains("no_such_function"),
        "the missing contract was not named:\n{message}"
    );
    assert!(
        !message.contains("llvm-tools") && !message.contains("llvm-profdata"),
        "a bad contract was reported as a missing coverage tool:\n{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// Missing coverage tools are refused, not worked around.
///
/// A run asked to explore that cannot explore must fail. Quietly falling back
/// to M6 generation would report a search it did not perform.
#[test]
fn missing_coverage_tools_fail_the_run() {
    let output = Command::new(cli())
        .arg("check")
        .arg("--manifest-path")
        .arg(library_manifest())
        .args([
            "--contract",
            "crypto::lookup::substitute",
            "--cases",
            "64",
            "--explore",
        ])
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m7-cli-tests"),
        )
        .env("TRACE_CHECK_LLVM_TOOLS", "/nonexistent/llvm")
        .output()
        .expect("the CLI runs");
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        message.contains("llvm-profdata") || message.contains("llvm-cov"),
        "the missing tool was not named:\n{message}"
    );
    assert!(
        message.contains("rustup component add llvm-tools")
            || message.contains("TRACE_CHECK_LLVM_TOOLS"),
        "the message does not say how to fix it:\n{message}"
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "a run that could not explore must not pass:\n{message}"
    );
    assert!(
        !message.contains("NO_LEAK_OBSERVED"),
        "a failed exploration produced a clean security claim:\n{message}"
    );
}

/// Exploration settings that would search nothing are refused by validation
/// rather than silently doing nothing.
#[test]
fn settings_that_would_search_nothing_are_refused() {
    let output = check(&[
        "--contract",
        "crypto::lookup::substitute",
        "--cases",
        "64",
        "--explore",
        "--explore-cases",
        "0",
    ]);
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        message.contains("candidate_budget"),
        "a zero candidate budget was not refused:\n{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// A configuration naming an unimplemented feedback mechanism is refused, and
/// the message says what this build supports.
#[test]
fn an_unimplemented_feedback_mechanism_is_refused() {
    let dir = std::env::temp_dir().join("trace-check-m7-feedback-config");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("trace-check.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n\
         [check.\"crypto::lookup::substitute\"]\n\n\
         [check.\"crypto::lookup::substitute\".explore]\n\
         enabled = true\n\
         feedback = \"edges\"\n",
    )
    .expect("the config is writable");

    let output = check(&[
        "--contract",
        "crypto::lookup::substitute",
        "--config",
        config.to_str().expect("a utf-8 path"),
    ]);
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        message.contains("edges") && message.contains("llvm-regions"),
        "the message must name both what was asked for and what exists:\n{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// Mutating neither role is refused: it would be a slower way to run the
/// baseline corpus while reporting a search.
#[test]
fn freezing_both_roles_is_refused() {
    let dir = std::env::temp_dir().join("trace-check-m7-frozen-config");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("trace-check.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n\
         [check.\"crypto::lookup::substitute\"]\n\n\
         [check.\"crypto::lookup::substitute\".explore]\n\
         enabled = true\n\
         mutate_public = false\n\
         mutate_secret = false\n",
    )
    .expect("the config is writable");

    let output = check(&[
        "--contract",
        "crypto::lookup::substitute",
        "--config",
        config.to_str().expect("a utf-8 path"),
    ]);
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        message.contains("mutate_public") && message.contains("mutate_secret"),
        "{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// `explored` is not a generation strategy a configuration may request, and the
/// refusal points at the table that does enable it.
#[test]
fn explored_is_not_a_requestable_strategy() {
    let dir = std::env::temp_dir().join("trace-check-m7-strategy-config");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let config = dir.join("trace-check.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n\
         [check.\"crypto::lookup::substitute\"]\n\
         strategies = [\"boundaries\", \"explored\"]\n",
    )
    .expect("the config is writable");

    let output = check(&[
        "--contract",
        "crypto::lookup::substitute",
        "--config",
        config.to_str().expect("a utf-8 path"),
    ]);
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(message.contains("explored"), "{message}");
    assert!(
        message.contains("explore") && message.contains("enabled = true"),
        "the refusal must point at the table that enables it:\n{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// A library outside this workspace explores through the Cargo CLI with no
/// special setup, which is the usability checkpoint.
///
/// `examples/external-library` is the right subject: it has its own lockfile,
/// is not a workspace member, and its contracts are declared
/// `dynamic = false`, so it does not depend on `trace-check-test` at all. If
/// exploration works there it works for a developer who only added the
/// annotation.
#[test]
fn an_external_library_explores_through_the_cli() {
    if !backends_available() {
        return;
    }
    let output = run(
        &external_manifest(),
        &[
            "--contract",
            "external_library::digest_nibble",
            // A `u32` has 94 boundary values, which is the floor for this
            // contract; a smaller budget is refused rather than silently
            // skipping them.
            "--cases",
            "96",
            "--explore",
            "--explore-cases",
            "256",
        ],
    );
    let text = stdout(&output);
    assert!(
        text.contains("-- exploration (discovery artifact; no security evidence) --"),
        "the external library did not explore:\n{text}\n{}",
        stderr(&output)
    );
    assert!(
        text.contains("llvm-regions"),
        "the feedback mechanism was not reported:\n{text}"
    );
    // The secret's low nibble selects a load address, and the finding comes
    // from the uninstrumented artifact under the mandatory controls.
    assert!(text.contains("LEAK_DETECTED"), "{text}");
    assert!(text.contains("[no instrumentation]"));
    assert!(text.contains("controls: calibration confirmed"));
    assert_eq!(output.status.code(), Some(1), "a leak must exit 1");
}

/// Exploration leaves nothing behind in the developer's directory.
///
/// `rustflags` reaches proc-macro crates, so `trace-check-macros` is itself
/// built instrumented and rustc *runs* it to expand the library's annotations —
/// at which point the profiling runtime writes a profile to its default path.
/// Before this was redirected, every `--explore` run scattered a
/// quarter-megabyte `default_*.profraw` per expansion into whichever directory
/// Cargo was invoked from. Twenty of them turned up in `git status`.
#[test]
fn exploration_leaves_no_profiles_in_the_working_directory() {
    if !backends_available() {
        return;
    }
    let dir = std::env::temp_dir().join("trace-check-m7-cwd");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch working directory");

    let output = Command::new(cli())
        .arg("check")
        .arg("--manifest-path")
        .arg(library_manifest())
        .args([
            "--contract",
            "crypto::lookup::substitute",
            "--cases",
            "64",
            "--explore",
            "--explore-cases",
            "128",
        ])
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m7-cli-tests"),
        )
        // An empty working directory, so anything found in it afterwards was
        // put there by this run.
        .current_dir(&dir)
        .output()
        .expect("the CLI runs");
    assert!(
        stdout(&output).contains("-- exploration"),
        "the run did not explore, so it cannot have been tested:\n{}",
        stderr(&output)
    );

    let left: Vec<String> = std::fs::read_dir(&dir)
        .expect("the directory exists")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        left.is_empty(),
        "exploration left {} file(s) in the working directory: {left:?}",
        left.len()
    );
}

/// Replay is unaffected by exploration: it answers a different question from a
/// recorded reproducer and builds no discovery artifact.
#[test]
fn replay_does_not_explore() {
    if !valgrind_available() {
        return;
    }
    let dir = std::env::temp_dir().join("trace-check-m7-replay");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    let found = check(&[
        "--contract",
        "crypto::lookup::substitute_indexed",
        "--cases",
        "32",
        "--reproducer-dir",
        dir.to_str().expect("a utf-8 path"),
    ]);
    assert!(
        stdout(&found).contains("LEAK_DETECTED"),
        "{}",
        stdout(&found)
    );

    let reproducer = std::fs::read_dir(&dir)
        .expect("the directory exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("a reproducer was written");

    let replayed = check(&["--replay", reproducer.to_str().expect("a utf-8 path")]);
    let text = stdout(&replayed);
    assert!(
        !text.contains("exploration"),
        "replay built a discovery artifact:\n{text}"
    );
    assert!(
        text.contains("REPRODUCED") || text.contains("Replaying"),
        "{text}\n{}",
        stderr(&replayed)
    );
}

/// `--explore` and `--replay` are mutually exclusive, so a replay can never be
/// read as a search.
#[test]
fn explore_and_replay_conflict() {
    let output = check(&["--replay", "/nonexistent.json", "--explore"]);
    let message = format!("{}{}", stdout(&output), stderr(&output));
    assert!(
        message.contains("cannot be used with") || message.contains("conflict"),
        "{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// The JSON report carries both artifacts' provenance under distinct keys, so a
/// machine consumer cannot confuse them either.
#[test]
fn the_json_report_distinguishes_the_two_artifacts() {
    if !backends_available() {
        return;
    }
    let config = workspace_root().join("examples/crypto-library/trace-check.toml");
    let output = check(&[
        "--contract",
        "crypto::hidden::threshold_window",
        "--config",
        config.to_str().expect("a utf-8 path"),
        "--cases",
        "200",
        "--explore",
        "--explore-cases",
        "256",
        "--format",
        "json",
    ]);
    let text = stdout(&output);
    let report: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("the report is JSON: {e}\n{text}"));
    let entry = &report["contracts"][0];

    let security = entry["artifact_sha256"]
        .as_str()
        .expect("a security artifact hash");
    let discovery = entry["discovery"]["artifact_sha256"]
        .as_str()
        .expect("a discovery artifact hash");
    assert_ne!(security, discovery);
    assert_eq!(
        entry["discovery"]["marked_bytes"].as_u64(),
        Some(0),
        "the discovery artifact must report marking nothing"
    );
    assert_eq!(
        entry["discovery"]["feedback"].as_str(),
        Some("llvm-regions")
    );
    assert!(entry["discovery"]["instrumentation"]
        .as_str()
        .expect("an instrumentation flag")
        .contains("instrument-coverage"));
    assert!(entry["discovery"]["coverage_map_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    // The selection is reported as discovery evidence, with its budget
    // accounting visible.
    let selection = &entry["discovery"]["selection"];
    assert!(selection["mandatory"].as_u64().expect("a count") > 0);
    assert!(selection["total"].as_u64().expect("a count") > 0);
    // And the security section holds no coverage at all.
    assert!(
        entry["check"]["regions_reached"].is_null(),
        "the security result carries a coverage number"
    );
}
