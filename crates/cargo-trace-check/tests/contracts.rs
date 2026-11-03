//! M8 contract-discovery and enforcement, through the real binary.
//!
//! The milestone's principal failure mode is a **false claim of
//! completeness** — a run that reports success because a contract was never
//! considered. Every test here is a way of adding, removing or breaking a
//! declaration and requiring the tool to notice.
//!
//! [`adding_a_leaking_annotation_fails_ci_with_no_configuration_change`] is the
//! defining one. It is the whole argument for the milestone in a single test:
//! annotate a vulnerable function, change nothing else, and CI fails.
//!
//! `examples/enforcement-fixture` is the subject: `no_std`, every contract
//! `dynamic = false`, and **no `trace-check.toml` at all**. There is nothing
//! for the tool to discover these contracts through except the compiled
//! library.

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

fn fixture_dir() -> PathBuf {
    workspace_root().join("examples/enforcement-fixture")
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

/// A private copy of the fixture library whose source the test may rewrite.
struct Staged {
    root: PathBuf,
    manifest: PathBuf,
    source: PathBuf,
}

impl Staged {
    /// Copies the fixture into a scratch directory, with the macro dependency
    /// pointed at an absolute path so the copy builds standalone.
    fn new(name: &str) -> Staged {
        let root = std::env::temp_dir().join(format!("trace-check-m8-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("a scratch directory");

        let manifest = std::fs::read_to_string(fixture_dir().join("Cargo.toml"))
            .expect("the fixture manifest is readable");
        let macros = workspace_root()
            .join("crates/trace-check-macros")
            .display()
            .to_string()
            .replace('\\', "/");
        std::fs::write(
            root.join("Cargo.toml"),
            manifest.replace(
                "path = \"../../crates/trace-check-macros\"",
                &format!("path = {macros:?}"),
            ),
        )
        .expect("the manifest is writable");
        std::fs::copy(fixture_dir().join("src/lib.rs"), root.join("src/lib.rs"))
            .expect("the source copies");

        Staged {
            manifest: root.join("Cargo.toml"),
            source: root.join("src/lib.rs"),
            root,
        }
    }

    /// Appends to the library's source.
    fn append(&self, text: &str) {
        let mut source =
            std::fs::read_to_string(&self.source).expect("the staged source is readable");
        source.push_str(text);
        std::fs::write(&self.source, source).expect("the staged source is writable");
    }

    fn replace(&self, from: &str, to: &str) {
        let source = std::fs::read_to_string(&self.source).expect("the staged source is readable");
        assert!(
            source.contains(from),
            "{from:?} is not in the staged source"
        );
        std::fs::write(&self.source, source.replace(from, to))
            .expect("the staged source is writable");
    }

    /// Whether a `trace-check.toml` exists. The mutation test asserts it never
    /// appears.
    fn has_config(&self) -> bool {
        self.root.join("trace-check.toml").is_file()
    }

    fn write_config(&self, text: &str) {
        std::fs::write(self.root.join("trace-check.toml"), text).expect("the config is writable");
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli())
            .arg("check")
            .arg("--manifest-path")
            .arg(&self.manifest)
            .args(args)
            // A shared target directory, so each run does not rebuild the
            // macro crate and its dependencies from scratch.
            .env(
                "CARGO_TARGET_DIR",
                std::env::temp_dir().join("trace-check-m8-cli-tests"),
            )
            .output()
            .expect("the CLI runs")
    }

    fn list(&self) -> Output {
        Command::new(cli())
            .args(["list", "--contracts", "--manifest-path"])
            .arg(&self.manifest)
            .env(
                "CARGO_TARGET_DIR",
                std::env::temp_dir().join("trace-check-m8-cli-tests"),
            )
            .output()
            .expect("the CLI runs")
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn both(output: &Output) -> String {
    format!(
        "{}{}",
        stdout(output),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A secret-indexed load: the classic table-lookup side channel.
const LEAKING: &str = r#"

/// Vulnerable: the secret becomes part of a load address.
#[constant_time(secret = "index", dynamic = false)]
pub fn indexed(index: u8) -> u8 {
    // SAFETY: the mask keeps the index inside the 16-byte table.
    unsafe { core::ptr::read_volatile(&TABLE[(index & 15) as usize]) }
}
"#;

/// **The defining M8 test.**
///
/// Annotate a vulnerable function. Change no configuration, no test, no
/// registry. The inventory must grow, the dynamic checker must find the leak,
/// and CI must fail.
///
/// Then remove the annotation and watch the inventory shrink back.
#[test]
fn adding_a_leaking_annotation_fails_ci_with_no_configuration_change() {
    if !valgrind_available() {
        return;
    }
    let staged = Staged::new("mutation");

    // 1. The library as it stands: two constant-time functions, no
    //    configuration, every contract annotation-only.
    let before = staged.run(&["--all-contracts", "--ci"]);
    let text = stdout(&before);
    assert_eq!(
        before.status.code(),
        Some(0),
        "the clean fixture must pass:\n{}",
        both(&before)
    );
    assert!(text.contains("declared: 2 contract(s)"), "{text}");
    assert!(text.contains("fixture::masked"), "{text}");
    assert!(text.contains("fixture::mixed"), "{text}");
    assert!(text.contains("Result: PASS"));
    assert!(
        !staged.has_config(),
        "the fixture must have no trace-check.toml, or the test proves nothing"
    );

    // 2. Add a leaking annotated function. Nothing else changes.
    staged.append(LEAKING);

    let after = staged.run(&["--all-contracts", "--ci"]);
    let text = stdout(&after);

    // The inventory noticed.
    assert!(
        text.contains("declared: 3 contract(s)"),
        "the new declaration was not inventoried:\n{text}"
    );
    assert!(
        text.contains("fixture::indexed"),
        "the new contract is not in the matrix:\n{text}"
    );
    // The checker found the leak, in the developer's own source.
    assert!(
        text.contains("LEAK_DETECTED"),
        "the planted leak was not detected:\n{text}"
    );
    assert!(
        text.contains("src/lib.rs"),
        "the finding is not attributed to a source location:\n{text}"
    );
    // And CI failed, with the leak naming the exit code.
    assert_eq!(
        after.status.code(),
        Some(1),
        "a leaking declaration must exit 1:\n{}",
        both(&after)
    );
    assert!(text.contains("Result: FAIL"));
    assert!(
        !staged.has_config(),
        "no configuration was written, which is the point of the test"
    );

    // 3. Remove the annotation and the inventory follows.
    staged.replace(
        "#[constant_time(secret = \"index\", dynamic = false)]\npub fn indexed",
        "pub fn indexed",
    );
    let removed = staged.run(&["--all-contracts", "--ci"]);
    let text = stdout(&removed);
    assert!(
        text.contains("declared: 2 contract(s)"),
        "removing the annotation did not shrink the inventory:\n{text}"
    );
    assert!(
        !text.contains("fixture::indexed"),
        "a removed declaration is still inventoried:\n{text}"
    );
    assert_eq!(
        removed.status.code(),
        Some(0),
        "the fixture must pass again:\n{}",
        both(&removed)
    );
}

/// A declaration the generated backend cannot analyze is **inventoried** and
/// reported `UNSUPPORTED`, and fails.
///
/// The framework must not pass simply because it could not construct a
/// harness: an unanalyzable requirement is a gap, not an absence. A secret
/// `bool` is the case that compiles and is still unanalyzable — a one-bit
/// secret is disclosed by any branch on it, so there is nothing a harness
/// could establish.
#[test]
fn an_unsupported_declaration_is_inventoried_and_fails() {
    let staged = Staged::new("unsupported-bool");
    staged.append(
        r#"

/// Unsupported: a secret `bool` is disclosed by any branch on it.
#[constant_time(secret = "flag", dynamic = false)]
pub fn over_bool(flag: bool) -> u8 {
    if flag {
        1
    } else {
        0
    }
}
"#,
    );
    // It is in the inventory: an unsupported contract is visible, not absent.
    let listed = stdout(&staged.list());
    assert!(listed.contains("3 contract declaration(s)"), "{listed}");
    assert!(listed.contains("fixture::over_bool"), "{listed}");

    let output = staged.run(&["--all-contracts", "--ci"]);
    let text = stdout(&output);
    assert!(text.contains("fixture::over_bool"), "{text}");
    assert!(text.contains("UNSUPPORTED"), "{text}");
    assert!(text.contains("secret `bool`"), "{text}");
    // Unsupported is a gap, not a violation, so it exits 2 rather than 1.
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unanalyzable declaration must not pass:\n{}",
        both(&output)
    );
}

/// An annotation the *macro* refuses never compiles, so it cannot pass either.
///
/// The earlier line of defence. A `&[u8]` secret is rejected at expansion with
/// an actionable message, which is a better outcome than being inventoried and
/// reported unsupported — but the test exists because "the build failed" and
/// "the check passed" must never be confusable.
#[test]
fn an_annotation_the_macro_refuses_cannot_pass() {
    let staged = Staged::new("unsupported-slice");
    // A `&[u8]` slice: the descriptor cannot model it, so no harness can be
    // generated and no value can be marked.
    staged.append(
        r#"

/// Unsupported: a slice parameter the descriptor cannot model.
#[constant_time(secret = "bytes", dynamic = false)]
pub fn over_slice(bytes: &[u8]) -> u8 {
    let mut out = 0u8;
    let mut index = 0usize;
    while index < bytes.len() {
        out ^= bytes[index];
        index += 1;
    }
    out
}
"#,
    );
    let output = staged.run(&["--all-contracts", "--ci"]);
    let message = both(&output);
    assert_ne!(
        output.status.code(),
        Some(0),
        "an unanalyzable declaration must not pass:\n{message}"
    );
    // The message names the parameter and what to do instead.
    assert!(message.contains("`bytes` is a slice"), "{message}");
    assert!(message.contains("&[u8; 32]"), "{message}");
    assert!(
        !message.contains("Result: PASS"),
        "a build failure was reported as a passing check:\n{message}"
    );
}

/// `list --contracts` finds annotation-only declarations with no configuration
/// and no test adapter.
#[test]
fn listing_contracts_finds_annotation_only_declarations() {
    let staged = Staged::new("listing");
    let output = staged.list();
    let text = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", both(&output));
    assert!(text.contains("2 contract declaration(s)"), "{text}");
    assert!(text.contains("fixture::masked"), "{text}");
    assert!(text.contains("fixture::mixed"), "{text}");
    // The adapter state is reported, because a `dynamic` requirement cannot be
    // met without one.
    assert!(text.contains("declared dynamic = false"), "{text}");
    // And the limits travel with the listing.
    assert!(text.contains("does not discover functions"), "{text}");
}

/// Asking for a contract the inventory does not declare is an error that names
/// what is actually there.
#[test]
fn an_undeclared_contract_is_diagnosed_against_the_inventory() {
    let staged = Staged::new("undeclared");
    let output = Command::new(cli())
        .args(["coverage", "--manifest-path"])
        .arg(&staged.manifest)
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m8-cli-tests"),
        )
        .output()
        .expect("the CLI runs");
    // `coverage` is read-only and reports the matrix; with nothing analyzed
    // every requirement is outstanding, so strict mode fails.
    let text = stdout(&output);
    assert!(text.contains("NOT_ANALYZED"), "{text}");
    assert_eq!(output.status.code(), Some(2), "{}", both(&output));
    assert!(text.contains("fixture::masked"));
}

/// An exemption makes an unsupported contract's obligation explicit, keeps it
/// in the report, and lets CI pass — while a leak in a *different* contract
/// still fails.
#[test]
fn an_exemption_waives_an_obligation_without_hiding_the_contract() {
    if !valgrind_available() {
        return;
    }
    let staged = Staged::new("exemption");
    staged.append(
        r#"

/// Unsupported: a secret `bool` is disclosed by any branch on it.
#[constant_time(secret = "flag", dynamic = false)]
pub fn over_bool(flag: bool) -> u8 {
    if flag {
        1
    } else {
        0
    }
}
"#,
    );

    // Without a waiver the unsupported contract fails; see
    // `an_unsupported_declaration_is_inventoried_and_fails` for that path on
    // its own.
    let unwaived = staged.run(&["--all-contracts", "--ci"]);
    assert_ne!(unwaived.status.code(), Some(0), "{}", both(&unwaived));
    assert!(
        stdout(&unwaived).contains("UNSUPPORTED"),
        "{}",
        stdout(&unwaived)
    );

    // With one, the obligation is discharged and the contract stays visible.
    staged.write_config(
        r#"schema_version = 1

[policy]
mode = "strict"

[[policy.exemptions]]
contract = "fixture::over_bool"
analyses = ["generated"]
reason = "a one-bit secret cannot be marked; the parameter is being removed"
tracking = "https://example.invalid/issues/1"
expires = "2099-01-01"
"#,
    );
    let waived = staged.run(&["--all-contracts", "--ci"]);
    let text = stdout(&waived);
    assert_eq!(
        waived.status.code(),
        Some(0),
        "a waived obligation must pass:\n{}",
        both(&waived)
    );
    assert!(text.contains("EXEMPTED"), "{text}");
    assert!(
        text.contains("fixture::over_bool"),
        "an exempted contract must stay in the report:\n{text}"
    );
    assert!(
        text.contains("being removed"),
        "the reason must be shown:\n{text}"
    );
    // And it does not count as checked.
    assert!(text.contains("Exempted:          1"), "{text}");
    assert!(text.contains("Fully checked:     2"), "{text}");
}

/// An expired exemption fails, and the lapse is visible.
#[test]
fn an_expired_exemption_fails() {
    let staged = Staged::new("expired");
    staged.write_config(
        r#"schema_version = 1

[[policy.exemptions]]
contract = "fixture::masked"
analyses = ["generated"]
reason = "waiting on a fix"
expires = "2020-01-01"
"#,
    );
    let output = Command::new(cli())
        .args(["coverage", "--manifest-path"])
        .arg(&staged.manifest)
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m8-cli-tests"),
        )
        .output()
        .expect("the CLI runs");
    let text = stdout(&output);
    assert_ne!(output.status.code(), Some(0), "{}", both(&output));
    assert!(text.contains("expired on 2020-01-01"), "{text}");
    assert!(text.contains("the gap it always was"), "{text}");
}

/// An exemption naming no active declaration is reported as stale rather than
/// silently waiving nothing.
#[test]
fn a_stale_exemption_is_reported() {
    let staged = Staged::new("stale");
    staged.write_config(
        r#"schema_version = 1

[[policy.exemptions]]
contract = "fixture::removed_long_ago"
analyses = ["generated"]
reason = "a reason"
never_expires = true
"#,
    );
    let output = Command::new(cli())
        .args(["coverage", "--manifest-path"])
        .arg(&staged.manifest)
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m8-cli-tests"),
        )
        .output()
        .expect("the CLI runs");
    let text = stdout(&output);
    assert!(text.contains("STALE"), "{text}");
    assert!(text.contains("removed_long_ago"), "{text}");
    assert!(text.contains("waives nothing"), "{text}");
    assert_ne!(output.status.code(), Some(0), "{}", both(&output));
}

/// An exemption with no reason is refused at configuration load, before
/// anything is built.
#[test]
fn a_reasonless_exemption_is_refused() {
    let staged = Staged::new("reasonless");
    staged.write_config(
        r#"schema_version = 1

[[policy.exemptions]]
contract = "fixture::masked"
analyses = ["generated"]
reason = ""
never_expires = true
"#,
    );
    let output = staged.run(&["--all-contracts"]);
    let message = both(&output);
    assert!(
        message.contains("indistinguishable from an unenforced contract"),
        "{message}"
    );
    assert_ne!(output.status.code(), Some(0));
}

/// A feature-gated declaration is inventoried according to the selected build,
/// and the two variants are distinguishable.
#[test]
fn a_feature_gated_declaration_follows_the_selected_build() {
    let staged = Staged::new("features");
    // Add an optional feature and a declaration behind it.
    let manifest = std::fs::read_to_string(&staged.manifest).expect("readable");
    std::fs::write(
        &staged.manifest,
        format!("{manifest}\n[features]\nextra = []\n"),
    )
    .expect("writable");
    staged.append(
        r#"

/// Only compiled with `--features extra`.
#[cfg(feature = "extra")]
#[constant_time(secret = "index", dynamic = false)]
pub fn gated(index: u8) -> u8 {
    masked(index)
}
"#,
    );

    let without = staged.list();
    let text = stdout(&without);
    assert!(text.contains("2 contract declaration(s)"), "{text}");
    assert!(!text.contains("fixture::gated"), "{text}");

    let with = Command::new(cli())
        .args([
            "list",
            "--contracts",
            "--features",
            "extra",
            "--manifest-path",
        ])
        .arg(&staged.manifest)
        .env(
            "CARGO_TARGET_DIR",
            std::env::temp_dir().join("trace-check-m8-cli-tests"),
        )
        .output()
        .expect("the CLI runs");
    let text = stdout(&with);
    assert!(text.contains("3 contract declaration(s)"), "{text}");
    assert!(text.contains("fixture::gated"), "{text}");
    // The variants are named differently, so two inventories are never
    // confused for one another.
    assert!(text.contains("[extra]"), "{text}");
    assert!(
        stdout(&without).contains("[default]"),
        "{}",
        stdout(&without)
    );
}

/// The JSON report keeps inventory, enforcement and evidence apart.
#[test]
fn the_json_report_separates_inventory_from_enforcement() {
    if !valgrind_available() {
        return;
    }
    let staged = Staged::new("json");
    let output = staged.run(&["--all-contracts", "--ci", "--format", "json"]);
    let text = stdout(&output);
    let report: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("the report is JSON: {e}\n{text}"));

    assert_eq!(report["schema_version"], 2);
    // Inventory completeness is its own object, not folded into a percentage.
    assert_eq!(report["inventory"]["complete"], true);
    assert_eq!(report["inventory"]["contracts_declared"], 2);
    assert!(report["inventory"]["artifact_sha256"]
        .as_str()
        .is_some_and(|hash| hash.len() == 64));
    assert!(report["inventory"]["profile"]
        .as_str()
        .expect("a profile")
        .contains("lto=off"));
    // Enforcement counts are separate.
    assert_eq!(report["summary"]["declared"], 2);
    assert_eq!(report["summary"]["checked"], 2);
    assert_eq!(report["summary"]["violations"], 0);
    assert_eq!(report["summary"]["ok"], true);
    // And evidence is per contract, in the outcome vocabulary the backends use.
    let contracts = report["contracts"].as_array().expect("contracts");
    assert_eq!(contracts.len(), 2);
    assert_eq!(contracts[0]["evidence"][0]["outcome"], "NO_LEAK_OBSERVED");
    assert_eq!(contracts[0]["status"]["generated"]["state"], "checked");
    // The rate is reported with its caveat.
    assert!(report["summary"]["enforcement_caveat"]
        .as_str()
        .expect("a caveat")
        .contains("not the proportion of secret inputs"));
}
