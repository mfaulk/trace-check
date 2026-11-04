//! Contract verification against a real Cargo library, driven against the real
//! analyzer.
//!
//! The whole configured suite is verified once in a [`OnceLock`] and the
//! assertions read from that shared report; tests that need a *different*
//! library or a *different* configuration stage their own copy.
//!
//! They skip when no container runtime or analyzer image is present, but
//! `TRACE_CHECK_REQUIRE_SYMBOLIC=1` — which CI sets — turns a missing backend
//! into a failure, so a skip can never be mistaken for a pass.
//!
//! The load-bearing test here is
//! [`the_verdict_follows_the_library_implementation`]. It rewrites one function
//! body in a copy of the library, leaves the configuration and the generated
//! harness design untouched, and requires the verdict to flip. Nothing keyed on
//! a contract name, a declared expectation, or a copy of the algorithm can pass
//! it — and there is no copy of the algorithm to key on, which is the whole
//! point of the milestone.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use trace_check::contract::{ContractError, VerifyConfig, CONFIG_FILE};
use trace_check::harness::{self, HarnessError, Library, Workspace};
use trace_check::library_report::LibraryReport;
use trace_check::security::Outcome;
use trace_check::symbolic::{CheckFeature, Verifier};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn library_dir() -> PathBuf {
    workspace_root().join("examples/crypto-library")
}

fn manifest() -> PathBuf {
    library_dir().join("Cargo.toml")
}

fn config() -> VerifyConfig {
    VerifyConfig::load(&library_dir().join(CONFIG_FILE))
        .expect("the bundled configuration is valid")
}

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

/// Verifies `contracts` from `manifest_path` with `config`, in a private
/// workspace that is removed when the call returns.
fn verify_with(
    manifest_path: &Path,
    config: &VerifyConfig,
    contracts: &[String],
) -> Result<LibraryReport, HarnessError> {
    verify_with_runtime(manifest_path, config, contracts, None)
}

/// A container runtime that cannot exist, so "the analyzer is unavailable" is
/// deterministic in every environment.
///
/// Setting `TRACE_CHECK_CONTAINER_RUNTIME` is **not** a reproduction: the
/// library entry point takes an explicit runtime and never reads the
/// environment, so on a machine where podman happens to hold the image the
/// backend is reachable regardless. That is precisely why two contract-level
/// error tests passed locally and failed in CI — the local run had a working
/// analyzer and never exercised the ordering at all.
const UNREACHABLE_RUNTIME: &str = "no-such-runtime";

fn verify_with_runtime(
    manifest_path: &Path,
    config: &VerifyConfig,
    contracts: &[String],
    runtime: Option<&str>,
) -> Result<LibraryReport, HarnessError> {
    let workspace = Workspace::ephemeral()?;
    let library = Library::resolve(manifest_path, &[])?;
    trace_check::run_contract_verification(&library, config, contracts, &workspace, runtime)
}

/// Every configured contract, verified once per test binary.
fn suite() -> Option<&'static LibraryReport> {
    static REPORT: OnceLock<Option<LibraryReport>> = OnceLock::new();
    REPORT
        .get_or_init(|| {
            if !analyzer_available() {
                return None;
            }
            let config = config();
            let contracts: Vec<String> = config.contracts().iter().map(|c| c.to_string()).collect();
            Some(
                verify_with(&manifest(), &config, &contracts)
                    .expect("the bundled contracts verify"),
            )
        })
        .as_ref()
}

/// Asserts an error is about the contract, not about a missing analyzer.
///
/// Every contract-level error test calls this. Two of them failed in CI for
/// exactly the reason it checks: the container backend was prepared before the
/// library was compiled, so "this function carries no `#[constant_time]`
/// annotation" came out as "cannot obtain the analyzer image" on any machine
/// without it. A problem with the contract must be reported as a problem with
/// the contract, and these tests must fail if that ever stops being true —
/// rather than being quietly gated on a backend they do not need.
fn assert_not_a_backend_error(error: &HarnessError) {
    let message = error.to_string();
    for masking in ["analyzer image", "podman", "docker", "container"] {
        assert!(
            !message.contains(masking),
            "a contract-level error was masked by the backend: {message}"
        );
    }
}

fn contract_report<'a>(
    report: &'a LibraryReport,
    id: &str,
) -> &'a trace_check::library_report::ContractReport {
    report
        .contracts
        .iter()
        .find(|entry| entry.contract == id)
        .unwrap_or_else(|| panic!("no contract {id} in the report"))
}

/// Every configured contract reproduces the outcome it declares, and the run
/// exits 0.
#[test]
fn every_configured_contract_meets_its_declared_expectation() {
    let Some(report) = suite() else { return };
    assert!(
        report.summary.unmet_expectations.is_empty(),
        "unmet: {:?}",
        report.summary.unmet_expectations
    );
    assert!(report.summary.expectations_reproduced);
    assert_eq!(report.executed, report.selected);
    assert_eq!(report.executed, config().contracts().len());
    assert_eq!(report.exit_code(), 0);
}

/// A real library function earns VERIFIED_BOUNDED: complete exploration, no
/// pending paths, no unknown answers, every requested obligation class
/// discharged, and the analyzer's own evidence that it reached the function.
#[test]
fn a_real_library_function_earns_verified_bounded() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::tag::verify_tag");
    assert_eq!(entry.analysis.outcome, Outcome::VerifiedBounded);
    assert!(entry.analysis.exploration.is_complete());
    assert_eq!(entry.analysis.exploration.pending_paths, Some(0));
    assert_eq!(entry.analysis.exploration.unknown_queries, Some(0));
    assert!(entry.analysis.exploration.performed_checks() > 0);
    assert!(entry.analysis.divergences.is_empty());
    assert!(entry.analysis.unchecked_properties.is_empty());
    // Attribution is evidence, not declaration.
    assert!(entry.symbol.reached);
    assert!(entry.symbol.reached_at.is_some());
    // And it is the library's own function, named by the contract.
    assert!(
        entry.symbol.mangled.contains("verify_tag"),
        "{}",
        entry.symbol.mangled
    );
    assert_eq!(entry.library.package, "crypto-library");
}

/// A secret-dependent branch in library code is found, and localized to the
/// developer's own source line rather than to a generated file.
#[test]
fn a_secret_dependent_branch_in_library_code_is_found() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::tag::verify_tag_volatile_early_exit");
    assert_eq!(entry.analysis.outcome, Outcome::LeakDetected);
    let control: Vec<_> = entry
        .analysis
        .divergences
        .iter()
        .filter(|divergence| divergence.kind == CheckFeature::ControlFlow)
        .collect();
    assert!(!control.is_empty(), "{:?}", entry.analysis.divergences);
    let source = control[0].source.as_deref().unwrap_or_default();
    assert!(
        source.contains("verify_tag_volatile_early_exit") && source.contains("tag.rs"),
        "a finding must name the library's own source, got {source:?}"
    );
}

/// A secret-dependent memory address in library code is found. The instruction
/// sequence is identical for every secret, so only an address-aware analysis
/// can see this.
#[test]
fn a_secret_dependent_address_in_library_code_is_found() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::lookup::substitute_indexed");
    assert_eq!(entry.analysis.outcome, Outcome::LeakDetected);
    assert!(entry
        .analysis
        .divergences
        .iter()
        .any(|divergence| divergence.kind == CheckFeature::MemoryAccess));
    // One path: the leak is in the address, not in the instruction sequence.
    assert_eq!(entry.analysis.exploration.total_paths, Some(1));
    let source = entry.analysis.divergences[0]
        .source
        .as_deref()
        .unwrap_or_default();
    assert!(source.contains("lookup.rs"), "got {source:?}");
}

/// Branching on a public input is not a leak: both compared executions share
/// their public inputs. A finding here would be wrong in the direction that
/// makes the tool useless.
#[test]
fn a_public_branch_is_not_reported_as_a_leak() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::controls::public_branch");
    assert_eq!(entry.analysis.outcome, Outcome::VerifiedBounded);
    assert!(entry.analysis.divergences.is_empty());
}

/// The milestone's key demonstration. The M3 dynamic test for this contract
/// exercises `mode = 0` and observes nothing; the symbolic search over the
/// public domain finds the vulnerable path.
#[test]
fn a_leak_behind_an_untested_public_mode_is_found() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::lookup::substitute_mode");
    assert_eq!(entry.analysis.outcome, Outcome::LeakDetected);
    // Both modes were explored; the dynamic test visited one of them.
    assert_eq!(entry.analysis.exploration.total_paths, Some(2));
    assert!(entry
        .analysis
        .divergences
        .iter()
        .any(|divergence| divergence.kind == CheckFeature::MemoryAccess));
}

/// The per-byte control: a leak that depends on **nothing but byte 15** of the
/// secret array is found. A harness that declared only the pointer secret, only
/// the leading byte, or the wrong width reports this as secure.
#[test]
fn a_leak_in_the_final_secret_byte_is_found() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::controls::tail_byte_probe");
    assert_eq!(entry.analysis.outcome, Outcome::LeakDetected);
    assert!(entry
        .analysis
        .divergences
        .iter()
        .any(|divergence| divergence.kind == CheckFeature::MemoryAccess));
    // The whole array is the secret, not its pointer: 16 bytes, one global.
    let secret = entry
        .inputs
        .iter()
        .find(|input| input.role == trace_check::contract::Role::Secret)
        .expect("a declared secret");
    assert_eq!(secret.bits, 128);
    assert!(secret.passing.contains("pointer is public"));
}

/// A counterexample for an array secret is a pair of whole-array values, which
/// is what shows the entire array was made symbolic rather than its first byte.
#[test]
fn a_counterexample_covers_the_whole_secret_array() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::tag::verify_tag_volatile_early_exit");
    let Some(counterexample) = entry.analysis.counterexamples.first() else {
        // Not every leak has a model: the analyzer settles some by taint
        // analysis without issuing a relational query, and that is reported
        // rather than fabricated.
        assert_eq!(
            entry.analysis.witness,
            trace_check::symbolic::WitnessStatus::UnavailableFromAnalyzer
        );
        return;
    };
    assert!(counterexample.global.starts_with("TC_SECRET_"));
    assert_ne!(
        counterexample.left, counterexample.right,
        "two equal values witness nothing"
    );
    // The solver's model is over the full 128-bit input.
    assert!(
        counterexample.left.contains("128"),
        "expected a 128-bit model, got {}",
        counterexample.left
    );
}

/// **The milestone's defining regression.** One function body is rewritten in a
/// copy of the library; the configuration, the contract identity and the
/// generated harness design are untouched. The verdict must flip.
#[test]
fn the_verdict_follows_the_library_implementation() {
    if !analyzer_available() {
        return;
    }
    let staged = tempfile::tempdir().expect("temp dir");
    let copy = stage_library(staged.path());

    // `substitute` is a branchless full-table scan and verifies. Make it index
    // by the secret instead. Nothing else changes -- not the harness, not the
    // configuration, not the declared expectation.
    let path = copy.join("src/lookup.rs");
    let original = std::fs::read_to_string(&path).expect("lookup.rs");
    let leaking = original.replace(
        "accumulator |= unsafe { core::ptr::read_volatile(&SBOX[position as usize]) } & hit;",
        "accumulator |= unsafe { core::ptr::read_volatile(&SBOX[want as usize]) } & hit;",
    );
    assert_ne!(leaking, original, "the injection site must still exist");
    std::fs::write(&path, leaking).expect("write lookup.rs");

    let config = config();
    let contracts = vec!["crypto::lookup::substitute".to_string()];
    assert_eq!(
        config
            .settings(&contracts[0])
            .expect("configured")
            .expected_outcome,
        "VERIFIED_BOUNDED",
        "the declared expectation must still say the function is safe"
    );

    let report = verify_with(&copy.join("Cargo.toml"), &config, &contracts)
        .expect("the mutated library analyzes");

    let entry = contract_report(&report, &contracts[0]);
    assert_eq!(
        entry.analysis.outcome,
        Outcome::LeakDetected,
        "changing only the library must change the verdict: {}",
        entry.analysis.message
    );
    assert!(!entry.expectation.met);
    assert_eq!(report.exit_code(), 1);
    // A different artifact, and the report says so.
    let baseline = suite().map(|report| {
        contract_report(report, &contracts[0])
            .artifact
            .sha256
            .clone()
    });
    if let Some(baseline) = baseline {
        assert_ne!(entry.artifact.sha256, baseline);
    }
}

/// A contract the library does not declare is an explicit error naming what is
/// missing, not an inconclusive analysis of something else.
#[test]
fn an_undeclared_contract_is_an_explicit_error() {
    let mut config = config();
    // Reuse a valid section under a name the library does not define.
    let settings = config
        .verify
        .remove("crypto::tag::verify_tag")
        .expect("configured");
    config
        .verify
        .insert("crypto::tag::no_such_function".to_string(), settings);

    let error = verify_with(
        &manifest(),
        &config,
        &["crypto::tag::no_such_function".to_string()],
    )
    .expect_err("an undeclared contract must be refused");
    let message = error.to_string();
    assert!(
        message.contains("no_such_function") && message.contains("#[constant_time]"),
        "{message}"
    );
    assert_not_a_backend_error(&error);
}

/// A function in the library that carries no annotation is refused for the same
/// reason: there is no declaration to read roles and widths from.
#[test]
fn an_unannotated_function_is_an_explicit_error() {
    let mut config = config();
    let settings = config
        .verify
        .remove("crypto::lookup::substitute")
        .expect("configured");
    // `synthetic_table`-style helpers are ordinary functions with no contract.
    config
        .verify
        .insert("crypto::tag::TAG_LEN".to_string(), settings);

    let error = verify_with(&manifest(), &config, &["crypto::tag::TAG_LEN".to_string()])
        .expect_err("an unannotated item must be refused");
    assert!(error.to_string().contains("#[constant_time]"), "{error}");
    assert_not_a_backend_error(&error);
}

/// An identity qualified by the wrong crate is refused before anything is
/// built, naming the crate the manifest actually describes.
#[test]
fn a_wrongly_qualified_identity_is_refused() {
    let library = Library::resolve(&manifest(), &[]).expect("resolves");
    let error = harness::split_contract(&library, "other::tag::verify_tag").expect_err("refused");
    assert!(error.to_string().contains("crate `crypto`"), "{error}");
    // A bare name says nothing about where the code lives.
    assert!(harness::split_contract(&library, "verify_tag").is_err());
}

/// A signature the symbolic backend cannot represent is an actionable error
/// naming the parameter and its type, not a guessed width.
///
/// `examples/consumer-crate` declares `verify_tag(expected: &[u8; TAG_LEN], …)`.
/// A proc macro sees the token `TAG_LEN`, not `32`, so the contract is recorded
/// as unsupported and refused here — while remaining fully usable under M3.
#[test]
fn an_unsupported_signature_is_an_actionable_error() {
    let consumer = workspace_root().join("examples/consumer-crate/Cargo.toml");
    let library = Library::resolve(&consumer, &[]).expect("resolves");
    let staged = tempfile::tempdir().expect("temp dir");
    let target = staged.path().join("target");
    std::fs::create_dir_all(&target).expect("target dir");

    let error = harness::probe_contract(
        &library,
        "consumer_crate::verify_tag",
        staged.path(),
        &target,
    )
    .expect_err("an unsupported signature must be refused");
    assert_not_a_backend_error(&error);
    let message = error.to_string();
    assert!(message.contains("`expected`"), "{message}");
    assert!(message.contains("TAG_LEN"), "{message}");
    assert!(message.contains("literal N"), "{message}");
}

/// Configuration cannot assign a parameter's role. The refusal happens after
/// the descriptor is read, so the message can name the declared secrets.
#[test]
fn configuration_cannot_reassign_a_role() {
    let mut config = config();
    config
        .verify
        .get_mut("crypto::tag::verify_tag")
        .expect("configured")
        .inputs
        .insert("expected".to_string(), "public-symbolic".to_string());

    let error = verify_with(
        &manifest(),
        &config,
        &["crypto::tag::verify_tag".to_string()],
    )
    .expect_err("a role override must be refused");
    let message = error.to_string();
    assert!(message.contains("#[constant_time(secret"), "{message}");
    assert!(
        message.contains("Declared secret(s): expected"),
        "{message}"
    );
}

/// A contract that is not configured is refused rather than verified with
/// invented bounds: a depth limit and an observation model cannot be inferred
/// from an annotation.
#[test]
fn an_unconfigured_contract_is_refused() {
    let mut config = config();
    config.verify.remove("crypto::tag::verify_tag");
    let error = verify_with(
        &manifest(),
        &config,
        &["crypto::tag::verify_tag".to_string()],
    )
    .expect_err("an unconfigured contract must be refused");
    assert!(
        matches!(
            error,
            HarnessError::Contract(ContractError::NotConfigured { .. })
        ),
        "{error}"
    );
    assert_not_a_backend_error(&error);
}

/// A symbol the artifact does not define is an explicit error, not a verdict.
/// This is the "inlined, removed, or misnamed" case: there is nothing to
/// analyze, and the message says so.
///
/// Uses a kept workspace on purpose. The default one is removed when the run
/// ends, which is correct but would leave this assertion with no artifact to
/// interrogate -- and an early return here would make the test vacuous.
#[test]
fn a_missing_symbol_is_an_explicit_error() {
    if !analyzer_available() {
        return;
    }
    let parent = tempfile::tempdir().expect("temp dir");
    let workspace = Workspace::kept_in(parent.path()).expect("created");
    let config = config();
    let contracts = vec!["crypto::tag::verify_tag".to_string()];
    let library = Library::resolve(&manifest(), &[]).expect("resolves");
    let report =
        trace_check::run_contract_verification(&library, &config, &contracts, &workspace, None)
            .expect("verifies");
    let artifact = PathBuf::from(&contract_report(&report, &contracts[0]).artifact.path);
    assert!(artifact.is_file(), "the kept artifact must still exist");

    // Present, by construction.
    harness::resolve_symbol(&artifact, "crypto::tag::verify_tag").expect("resolves");
    // Absent: inlined away, removed, or misnamed -- indistinguishable from
    // here, and all three mean there is nothing to analyze.
    let error = harness::resolve_symbol(&artifact, "crypto::tag::vanished").expect_err("refused");
    let message = error.to_string();
    assert!(message.contains("resolves to no symbol"), "{message}");
    assert!(message.contains("nothing to analyze"), "{message}");
}

/// Exploration cut short by a depth bound is INCONCLUSIVE, never a verdict —
/// the M4 fail-closed rule, reached through the M5 path.
#[test]
fn exceeding_the_depth_bound_is_inconclusive() {
    if !analyzer_available() {
        return;
    }
    let mut config = config();
    let settings = config
        .verify
        .get_mut("crypto::tag::verify_tag")
        .expect("configured");
    // The unbounded run reaches a maximum path depth in the hundreds.
    settings.max_depth = 40;
    let report = verify_with(
        &manifest(),
        &config,
        &["crypto::tag::verify_tag".to_string()],
    )
    .expect("the bounded run analyzes");
    let entry = contract_report(&report, "crypto::tag::verify_tag");
    assert_eq!(
        entry.analysis.outcome,
        Outcome::Inconclusive,
        "{}",
        entry.analysis.message
    );
    assert!(!entry.expectation.met);
    assert_eq!(report.exit_code(), 2);
}

/// A result covers only the observation classes the configuration asked for,
/// and says which it does not cover. A narrow run must not read like the
/// stronger one.
#[test]
fn a_narrow_observation_model_is_named_as_such() {
    if !analyzer_available() {
        return;
    }
    let mut config = config();
    let settings = config
        .verify
        .get_mut("crypto::lookup::substitute_indexed")
        .expect("configured");
    // The secret-indexed load's instruction path really is secret-independent:
    // only the address varies. Under control-flow checks alone the analyzer is
    // right to report `secure`, and the report has to name the gap.
    settings.checks = vec![CheckFeature::ControlFlow];
    settings.expected_outcome = "VERIFIED_BOUNDED".to_string();

    let report = verify_with(
        &manifest(),
        &config,
        &["crypto::lookup::substitute_indexed".to_string()],
    )
    .expect("the narrow run analyzes");
    let entry = contract_report(&report, "crypto::lookup::substitute_indexed");
    assert_eq!(entry.analysis.outcome, Outcome::VerifiedBounded);
    assert_eq!(
        entry.analysis.unchecked_properties,
        vec!["memory-address noninterference"]
    );
    let text = report.to_text();
    assert!(
        text.contains("NOT checked: memory-address noninterference"),
        "{text}"
    );
}

/// The report connects the developer's source to the analyzed executable, and
/// never claims the production binary was analyzed.
#[test]
fn the_report_connects_source_to_artifact() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::tag::verify_tag");
    assert!(
        entry.declared_at.contains("tag.rs"),
        "{}",
        entry.declared_at
    );
    assert_eq!(entry.library.lib_name, "crypto");
    assert_eq!(entry.compilation.panic, "abort");
    assert!(!entry.compilation.lto);
    assert_eq!(
        entry.compilation.target,
        trace_check::symbolic::SUPPORTED_TARGET
    );
    assert_eq!(entry.harness.sha256.len(), 64);
    assert_eq!(entry.artifact.sha256.len(), 64);
    assert_eq!(entry.artifact.lockfile_sha256.len(), 64);
    assert!(entry.artifact.production_artifact.contains("not analyzed"));
    // The generated harness is kept verbatim, and contains no algorithm.
    assert!(entry.harness.source.contains("crypto::tag::verify_tag"));
    assert!(!entry.harness.source.contains("ct_eq"));
}

/// Each contract is analyzed in its own executable, so a result names the exact
/// artifact it describes. A shared multi-entry artifact dropped entry symbols
/// as dead code during the feasibility spike.
#[test]
fn each_contract_has_its_own_artifact() {
    let Some(report) = suite() else { return };
    let mut hashes: Vec<&str> = report
        .contracts
        .iter()
        .map(|entry| entry.artifact.sha256.as_str())
        .collect();
    hashes.sort_unstable();
    let distinct = hashes.len();
    hashes.dedup();
    assert_eq!(hashes.len(), distinct, "two contracts share one artifact");
}

/// Copies a directory tree.
///
/// Recursive, because the library's `src` is not flat: a module declared as a
/// directory (`src/shadow/`) made a flat `read_dir` + `copy` fail with "the
/// source path is neither a regular file nor a symlink to a regular file",
/// which is an unhelpful way to learn that a test helper constrained the
/// library's layout.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap_or_else(|e| panic!("{}: {e}", to.display()));
    for entry in std::fs::read_dir(from).unwrap_or_else(|e| panic!("{}: {e}", from.display())) {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target)
                .unwrap_or_else(|e| panic!("{}: {e}", entry.path().display()));
        }
    }
}

/// Copies the library into `root`, with a self-contained manifest.
///
/// The bundled manifest inherits `version`, `edition` and `license` from the
/// trace-check workspace, which does not exist outside the repository, so the
/// copy pins them and declares itself a workspace root.
fn stage_library(root: &Path) -> PathBuf {
    let copy = root.join("crypto-library");
    copy_tree(&library_dir().join("src"), &copy.join("src"));
    std::fs::copy(library_dir().join(CONFIG_FILE), copy.join(CONFIG_FILE)).expect("copy config");

    let manifest = std::fs::read_to_string(manifest()).expect("manifest");
    let absolute = |relative: &str| {
        workspace_root()
            .join(relative)
            .display()
            .to_string()
            .replace('\\', "/")
    };
    let staged = manifest
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
    std::fs::write(copy.join("Cargo.toml"), format!("{staged}\n[workspace]\n"))
        .expect("write manifest");
    copy
}

/// A selection error is reported with no backend involved at all.
///
/// The ordering regression from review: selection used to be validated inside
/// the per-contract loop, after the container backend was prepared, so on a
/// machine without the analyzer image a misspelled contract reported a missing
/// image rather than the typo. Asserted here without touching a runtime —
/// `require_configured` is reachable from the configuration alone.
#[test]
fn a_selection_error_needs_no_backend() {
    let config = config();
    let error = config
        .require_configured(&["crypto::tag::verify_tga".to_string()])
        .expect_err("a typo is refused");
    let message = error.to_string();
    assert!(message.contains("verify_tga"), "{message}");
    assert!(message.contains("crypto::tag::verify_tag"), "{message}");
    assert!(!message.contains("analyzer image"), "{message}");
    config
        .require_configured(&["crypto::tag::verify_tag".to_string()])
        .expect("a configured contract is accepted");
}

/// A public `bool` reaches the analyzer with a generated domain restriction, so
/// the searched domain is Rust's valid values rather than all 256 bytes of a
/// symbolic byte. Verified end to end, including the generated BINSEC `assume`.
#[test]
fn a_public_bool_is_restricted_in_the_generated_script() {
    if !analyzer_available() {
        return;
    }
    let manifest = workspace_root().join("examples/external-library/Cargo.toml");
    let config = VerifyConfig::load(&manifest.parent().unwrap().join(CONFIG_FILE))
        .expect("the external configuration is valid");
    let contracts = vec!["external_library::mix_when".to_string()];
    let report = verify_with(&manifest, &config, &contracts).expect("verifies");
    let entry = contract_report(&report, &contracts[0]);

    assert_eq!(entry.analysis.outcome, Outcome::VerifiedBounded);
    assert_eq!(entry.generated_domain, vec!["TC_PUBLIC_ENABLED <= 1"]);
    // The developer declared none, and the generated one is not folded in with
    // theirs.
    assert!(entry.input_domain.is_empty());
    // It really reached the analyzer: the script carries the directive.
    assert!(
        entry
            .analysis
            .script
            .contains("assume TC_PUBLIC_ENABLED <= 1"),
        "{}",
        entry.analysis.script
    );
    let flag = entry
        .inputs
        .iter()
        .find(|input| input.parameter == "enabled")
        .expect("the bool input");
    assert_eq!(flag.bits, 8);
    assert_eq!(flag.role, trace_check::contract::Role::Public);
    assert_eq!(flag.domain.as_deref(), Some("TC_PUBLIC_ENABLED <= 1"));
    // Branching on a public input is not a leak.
    assert!(entry.analysis.divergences.is_empty());
}

/// A library whose only dependency is the annotation macro verifies, and its
/// contracts opt out of the dynamic adapter so its own `cargo test` compiles.
/// That compatibility is asserted in `cargo_test_compiles_for_an_annotated_library`.
#[test]
fn an_annotation_only_library_verifies() {
    if !analyzer_available() {
        return;
    }
    let manifest = workspace_root().join("examples/external-library/Cargo.toml");
    let config = VerifyConfig::load(&manifest.parent().unwrap().join(CONFIG_FILE))
        .expect("the external configuration is valid");
    let contracts: Vec<String> = config.contracts().iter().map(|c| c.to_string()).collect();
    let report = verify_with(&manifest, &config, &contracts).expect("verifies");
    assert!(report.summary.expectations_reproduced);
    assert_eq!(report.exit_code(), 0);
    assert!(report.contracts.iter().all(|entry| entry.symbol.reached));
}

/// Adding a verification annotation must not stop a library from building its
/// own test suite.
///
/// `#[constant_time]`'s dynamic machinery calls into `trace-check-test`, which
/// needs `std` and has to be a dev-dependency. A library that wants only the
/// contract verified says `dynamic = false`, and this is the test that keeps
/// that promise: an ordinary `cargo test` over the annotation-only example must
/// compile its library *and* its test targets.
#[test]
fn cargo_test_compiles_for_an_annotated_library() {
    let manifest = workspace_root().join("examples/external-library/Cargo.toml");
    let target = tempfile::tempdir().expect("temp dir");
    let output = std::process::Command::new("cargo")
        .args(["test", "--locked", "--all-targets", "--manifest-path"])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(target.path())
        .stdin(std::process::Stdio::null())
        .output()
        .expect("cargo runs");
    assert!(
        output.status.success(),
        "`cargo test` must compile for a library that only carries the annotation:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The default workspace is a private directory created atomically and removed
/// when the run ends, and the report says the recorded path is gone rather than
/// leaving a dangling one to be trusted.
#[test]
fn the_default_workspace_does_not_outlive_the_run() {
    let Some(report) = suite() else { return };
    let entry = contract_report(report, "crypto::tag::verify_tag");
    assert!(!entry.artifact.path_retained);
    assert!(!Path::new(&entry.artifact.path).exists());
    // The hash is what the result is pinned to.
    assert_eq!(entry.artifact.sha256.len(), 64);
    assert!(report.to_text().contains("removed after the run"));
}

/// `--artifact-dir`'s workspace keeps the evidence bundle, in a freshly created
/// directory inside the caller's rather than at a predictable path.
#[test]
fn a_kept_workspace_preserves_the_evidence_bundle() {
    if !analyzer_available() {
        return;
    }
    let parent = tempfile::tempdir().expect("temp dir");
    let workspace = Workspace::kept_in(parent.path()).expect("created");
    let root = workspace.root().to_path_buf();
    assert_ne!(root, parent.path());

    let config = config();
    let contracts = vec!["crypto::lookup::substitute_indexed".to_string()];
    let library = Library::resolve(&manifest(), &[]).expect("resolves");
    let report =
        trace_check::run_contract_verification(&library, &config, &contracts, &workspace, None)
            .expect("verifies");
    let entry = contract_report(&report, &contracts[0]);
    assert!(entry.artifact.path_retained);
    let artifact = Path::new(&entry.artifact.path);
    assert!(
        artifact.is_file(),
        "{} should still exist",
        entry.artifact.path
    );
    assert!(artifact.starts_with(&root));
}

/// A contract-level error is reported as itself with the analyzer unreachable
/// by construction.
///
/// The regression CI caught twice. Selection validation moved ahead of the
/// backend in the first pass, which fixed a misspelled *name*; a contract that
/// is configured but carries no `#[constant_time]` annotation still reported
/// "cannot obtain the analyzer image", because reaching that diagnosis needs
/// the library compiled and compilation came after the backend check. The
/// analyzer is now prepared lazily, immediately before the first query it is
/// needed for.
///
/// Unlike the environment-variable approach that hid this, `UNREACHABLE_RUNTIME`
/// makes the backend genuinely absent on any machine, so this test exercises
/// the ordering rather than the local analyzer install.
#[test]
fn contract_errors_survive_an_unreachable_analyzer() {
    let mut config = config();
    let settings = config
        .verify
        .remove("crypto::tag::verify_tag")
        .expect("configured");
    config
        .verify
        .insert("crypto::tag::no_such_function".to_string(), settings);

    let error = verify_with_runtime(
        &manifest(),
        &config,
        &["crypto::tag::no_such_function".to_string()],
        Some(UNREACHABLE_RUNTIME),
    )
    .expect_err("an undeclared contract must be refused");
    assert!(
        error.to_string().contains("#[constant_time]"),
        "the contract problem must be the one reported: {error}"
    );
    assert_not_a_backend_error(&error);
    assert!(!error.to_string().contains(UNREACHABLE_RUNTIME), "{error}");
}

/// And the companion that keeps the test above honest: with the same
/// unreachable analyzer, a contract with nothing wrong with it must fail *on
/// the analyzer*. Without this, the assertion above would also pass if the
/// runtime were somehow reachable after all.
#[test]
fn an_unreachable_analyzer_is_reported_when_it_is_the_problem() {
    let error = verify_with_runtime(
        &manifest(),
        &config(),
        &["crypto::tag::verify_tag".to_string()],
        Some(UNREACHABLE_RUNTIME),
    )
    .expect_err("an unreachable analyzer must be refused");
    let message = error.to_string();
    assert!(
        message.contains(UNREACHABLE_RUNTIME) || message.contains("container runtime"),
        "expected a backend failure, got: {message}"
    );
    assert!(!message.contains("#[constant_time]"), "{message}");
}

/// The verification artifact's hash is a function of its inputs, not of the
/// random directory it was built in.
///
/// `debug = true` bakes the generated harness's absolute path into the DWARF,
/// and the work directory is randomly named -- so without `--remap-path-prefix`
/// two runs of the same contract against the same library produce two different
/// hashes. That matters because the hash *is* the artifact's identity in every
/// report and in M8/M10 enforcement: evidence is accepted only when it names the
/// artifact its obligation is about, and an identity that changes every run
/// cannot be compared to anything.
///
/// M6's generated harness has remapped since it was written. This is the
/// symbolic harness, found unremapped by the M10.0 spike: two consecutive
/// `verify` runs reported different artifacts for identical inputs. No analyzer
/// is needed to show it, so this test is not gated on one.
#[test]
fn the_verification_artifact_hash_is_reproducible() {
    let contract_id = "crypto::tag::verify_tag";
    let library = Library::resolve(&manifest(), &[]).expect("the bundled library resolves");

    let build_once = || {
        let workspace = Workspace::ephemeral().expect("a private workspace");
        let (work_dir, target_dir) = workspace.directories_for(contract_id).expect("directories");
        let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
            .expect("the contract is declared");
        let generated = harness::generate(&library, &contract).expect("a harness");
        let artifact = harness::build(&library, &generated, contract_id, &work_dir, &target_dir)
            .expect("the harness builds");
        (generated.source_sha256.clone(), artifact.sha256.clone())
    };

    let (first_source, first) = build_once();
    let (second_source, second) = build_once();
    assert_eq!(
        first_source, second_source,
        "the generated source must be identical, or the artifacts are not comparable"
    );
    assert_eq!(
        first, second,
        "two builds of one contract from one library produced different artifacts; the \
         artifact hash is the identity every report and every enforcement decision uses"
    );
}
