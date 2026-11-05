//! M10.4: `dynamic`, `generated` and `symbolic` evidence from one invocation.
//!
//! The acceptance test for integrating M3's developer-written `#[ct_test]`s
//! into the unified enforcement model. `crypto::tag::verify_tag` is the subject
//! because it is the one contract in this repository that all three analyses
//! can be configured for: it carries a `#[ct_test(target = "tag::verify_tag")]`,
//! a `[check]` entry and a `[verify]` entry.
//!
//! The load-bearing test is
//! [`breaking_the_dynamic_test_fails_only_the_dynamic_requirement`]. A test that
//! runs and passes without ever calling the function it names establishes
//! nothing about that function — and the only thing standing between that and a
//! green CI run is whether the invocation is checked rather than assumed.
//!
//! Skips without Valgrind or the analyzer image; `TRACE_CHECK_REQUIRE_BACKEND`
//! and `TRACE_CHECK_REQUIRE_SYMBOLIC` turn a skip into a failure, so a skip can
//! never be mistaken for a pass.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

const CONTRACT: &str = "crypto::tag::verify_tag";

/// The policy requiring all three analyses of the subject contract.
const POLICY: &str = r#"
[policy]
mode = "strict"
default_required = ["generated"]

[policy.contracts."crypto::tag::verify_tag"]
required = ["generated", "symbolic", "dynamic"]
"#;

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

fn backends_available() -> bool {
    let valgrind = Command::new("valgrind")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !valgrind {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
            "TRACE_CHECK_REQUIRE_BACKEND is set but valgrind is not on PATH"
        );
        eprintln!("skipping: valgrind is not on PATH");
        return false;
    }
    let analyzer = match trace_check::symbolic::Verifier::prepare() {
        Err(e) => Some(e.to_string()),
        Ok(mut verifier) => verifier.check_image().err().map(|e| e.to_string()),
    };
    if let Some(reason) = analyzer {
        assert!(
            std::env::var_os("TRACE_CHECK_REQUIRE_SYMBOLIC").is_none(),
            "TRACE_CHECK_REQUIRE_SYMBOLIC is set but the symbolic backend is unavailable: \
             {reason}"
        );
        eprintln!("skipping: {reason}");
        return false;
    }
    true
}

/// A private copy of `examples/crypto-library` whose source a test may rewrite.
struct Staged {
    root: PathBuf,
    _directory: tempfile::TempDir,
}

impl Staged {
    fn new() -> Staged {
        let directory = tempfile::tempdir().expect("a scratch directory");
        let root = directory.path().join("crypto-library");
        let source = workspace_root().join("examples/crypto-library");
        copy_tree(&source.join("src"), &root.join("src"));
        std::fs::create_dir_all(&root).expect("the staged root");

        // The manifest inherits workspace keys and uses relative dependency
        // paths, neither of which resolves outside the workspace.
        let absolute = |relative: &str| {
            workspace_root()
                .join(relative)
                .display()
                .to_string()
                .replace('\\', "/")
        };
        let manifest = std::fs::read_to_string(source.join("Cargo.toml"))
            .expect("the manifest is readable")
            .replace("version.workspace = true", "version = \"0.1.0\"")
            .replace("edition.workspace = true", "edition = \"2021\"")
            .replace(
                "license.workspace = true",
                "license = \"MIT OR Apache-2.0\"",
            )
            .replace(
                "path = \"../../crates/trace-check-macros\"",
                &format!("path = {:?}", absolute("crates/trace-check-macros")),
            )
            .replace(
                "path = \"../../crates/trace-check-test\"",
                &format!("path = {:?}", absolute("crates/trace-check-test")),
            );
        std::fs::write(
            root.join("Cargo.toml"),
            format!("{manifest}\n[workspace]\n"),
        )
        .expect("write the manifest");

        // The staged copy lives outside the repository, where the workspace's
        // `rust-toolchain.toml` no longer resolves -- so without this it is
        // analyzed with whatever toolchain the machine happens to default to.
        // Every build in a run uses the *library's* toolchain, including the
        // one whose `llvm-profdata` reads the coverage profiles, so a default
        // without the `llvm-tools` component breaks coverage-guided discovery.
        // CI found exactly that.
        //
        // Staging the pin makes the copy behave like the in-repo library it is
        // a copy of, and makes the test independent of the machine it runs on.
        std::fs::copy(
            workspace_root().join("rust-toolchain.toml"),
            root.join("rust-toolchain.toml"),
        )
        .expect("the workspace pins a toolchain");

        let config = std::fs::read_to_string(source.join("trace-check.toml"))
            .expect("the configuration is committed");
        std::fs::write(root.join("trace-check.toml"), format!("{config}\n{POLICY}"))
            .expect("write the configuration");

        Staged {
            root,
            _directory: directory,
        }
    }

    fn manifest(&self) -> PathBuf {
        self.root.join("Cargo.toml")
    }

    /// Rewrites the staged library's source.
    fn replace(&self, from: &str, to: &str) {
        self.rewrite("src/lib.rs", from, to);
    }

    fn rewrite(&self, relative: &str, from: &str, to: &str) {
        let path = self.root.join(relative);
        let source = std::fs::read_to_string(&path).expect("the staged source is readable");
        assert!(source.contains(from), "{from:?} is not in {relative}");
        std::fs::write(&path, source.replace(from, to)).expect("the staged file is writable");
    }

    fn check(&self) -> Output {
        Command::new(cli())
            .args(["check", "--all-contracts", "--ci", "--format", "json"])
            .arg("--manifest-path")
            .arg(self.manifest())
            .arg("--config")
            .arg(self.root.join("trace-check.toml"))
            // A shared target directory, so each run does not rebuild the
            // macro crate and its dependencies from scratch.
            .env(
                "CARGO_TARGET_DIR",
                std::env::temp_dir().join("trace-check-m10-unified-cli"),
            )
            .output()
            .expect("the CLI runs")
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a destination directory");
    for entry in std::fs::read_dir(from).expect("a readable source") {
        let entry = entry.expect("a readable entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy");
        }
    }
}

/// The subject contract's row, parsed out of the JSON report.
fn subject(output: &Output) -> Value {
    let text = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!(
            "the report must be JSON: {e}\nstdout: {}\nstderr: {}",
            text.chars().take(600).collect::<String>(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    report["contracts"]
        .as_array()
        .expect("contracts")
        .iter()
        .find(|row| row["id"] == CONTRACT)
        .cloned()
        .unwrap_or_else(|| panic!("`{CONTRACT}` is not in the report"))
}

fn evidence_for(row: &Value, analysis: &str) -> Option<Value> {
    row["evidence"]
        .as_array()?
        .iter()
        .find(|item| item["analysis"] == analysis)
        .cloned()
}

fn state(row: &Value, analysis: &str) -> String {
    row["status"][analysis]["state"]
        .as_str()
        .unwrap_or("(absent)")
        .to_string()
}

/// One command produces distinct, valid evidence for all three analyses, each
/// bound to its own executable.
#[test]
fn one_invocation_produces_dynamic_generated_and_symbolic_evidence() {
    if !backends_available() {
        return;
    }
    let staged = Staged::new();
    let output = staged.check();
    let row = subject(&output);

    for analysis in ["generated", "symbolic", "dynamic"] {
        assert_eq!(
            state(&row, analysis),
            "checked",
            "{analysis} must be checked:\n{}",
            serde_json::to_string_pretty(&row["status"]).unwrap_or_default()
        );
    }

    let generated = evidence_for(&row, "generated").expect("generated evidence");
    let symbolic = evidence_for(&row, "symbolic").expect("symbolic evidence");
    let dynamic = evidence_for(&row, "dynamic").expect("dynamic evidence");

    assert_eq!(generated["outcome"], "NO_LEAK_OBSERVED");
    assert_eq!(symbolic["outcome"], "VERIFIED_BOUNDED");
    assert_eq!(dynamic["outcome"], "NO_LEAK_OBSERVED");

    // Three analyses, three executables. A shared hash would mean one result
    // is describing a binary it never analyzed.
    let hashes: Vec<&str> = [&generated, &symbolic, &dynamic]
        .iter()
        .map(|item| item["artifact_sha256"].as_str().expect("a hash"))
        .collect();
    assert_eq!(
        hashes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3,
        "each analysis builds its own executable: {hashes:?}"
    );

    // The backends are named distinctly, including the two that are both
    // Valgrind over different input sources.
    assert_eq!(generated["artifact"]["backend"], "valgrind-memcheck");
    assert_eq!(dynamic["artifact"]["backend"], "valgrind-ct-test");
    assert_eq!(symbolic["artifact"]["backend"], "binsec-relational");

    // The dynamic evidence names the test it rests on, and records that the
    // test provably invoked the contract.
    let tests = dynamic["dynamic"]["tests"]
        .as_array()
        .expect("the dynamic evidence names its tests");
    assert!(!tests.is_empty());
    for test in tests {
        assert_eq!(test["invoked_target"], true, "{test}");
        assert_eq!(test["calibrated"], true, "{test}");
        // Verbatim from the annotation, which is module-relative: a developer
        // writes `tag::verify_tag`, not their own crate name. It resolved to
        // this contract, which is what binding it under this row records.
        let declared = test["declared_target"].as_str().expect("a declared target");
        assert!(
            CONTRACT.ends_with(declared),
            "{declared:?} must be a suffix of {CONTRACT:?}"
        );
    }
}

/// A `#[ct_test]` that stops calling the function it names stops being evidence
/// about it — and nothing else changes.
///
/// The test still compiles, still runs and still passes. What it no longer does
/// is invoke the contract through the instrumented adapter, so it establishes
/// nothing about it. The generated and symbolic analyses are untouched, which
/// is what makes this a test of the dynamic binding rather than of the run.
#[test]
fn breaking_the_dynamic_test_fails_only_the_dynamic_requirement() {
    if !backends_available() {
        return;
    }
    let staged = Staged::new();

    // Before: all three satisfied.
    let before = subject(&staged.check());
    assert_eq!(state(&before, "dynamic"), "checked");
    let generated_before = evidence_for(&before, "generated").expect("generated evidence");
    let symbolic_before = evidence_for(&before, "symbolic").expect("symbolic evidence");

    // Stop invoking *this* contract while still marking a secret, so the
    // positive control still fires and the only thing missing is the
    // invocation. Calling the real function directly would fail calibration
    // instead -- a correct refusal, but for the wrong reason, and it would
    // leave the invocation check untested.
    staged.replace(
        "let accepted = tag::verify_tag_ct(secret_tag(), &supplied);\n        \
         assert!(!accepted, \"a mismatching tag must be rejected\");",
        "let _ = supplied;\n        \
         let selected = lookup::substitute_ct(secret_index());\n        \
         assert_eq!(selected, lookup::substitute(secret_index()));",
    );

    let after = subject(&staged.check());
    assert_ne!(
        state(&after, "dynamic"),
        "checked",
        "a test that never invoked the contract must not discharge its obligation:\n{}",
        serde_json::to_string_pretty(&after["status"]).unwrap_or_default()
    );
    let dynamic = evidence_for(&after, "dynamic").expect("dynamic evidence is still reported");
    assert_eq!(dynamic["outcome"], "INCONCLUSIVE");
    // The diagnostic names the missing invocation. M3's own harness asserts it
    // and fails the test, so the aggregate reports a test that did not complete
    // *and* carries the reason it did not.
    let detail = dynamic["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("never invoked"),
        "the diagnostic must name the invocation as what is missing: {detail}"
    );
    let test = &dynamic["dynamic"]["tests"][0];
    assert_eq!(
        test["invoked_target"], false,
        "the run must record that the contract was not reached: {test}"
    );
    assert_eq!(
        test["completed"], false,
        "a test that failed its own invocation assertion did not complete its check: {test}"
    );

    // The other two analyses are unaffected, down to the artifact hashes: the
    // library's own code did not change, only the test's call.
    let generated_after = evidence_for(&after, "generated").expect("generated evidence");
    let symbolic_after = evidence_for(&after, "symbolic").expect("symbolic evidence");
    assert_eq!(state(&after, "generated"), "checked");
    assert_eq!(state(&after, "symbolic"), "checked");
    assert_eq!(
        generated_before["artifact_sha256"], generated_after["artifact_sha256"],
        "the generated artifact must not change when only a test body does"
    );
    assert_eq!(
        symbolic_before["artifact_sha256"], symbolic_after["artifact_sha256"],
        "the symbolic artifact must not change when only a test body does"
    );
}
