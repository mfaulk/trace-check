//! M8 contract-inventory tests, against the real `examples/crypto-library`.
//!
//! These cross the boundary the milestone asks to be tested from both sides:
//! `#[constant_time]` *emits* a record, and `trace_check::inventory` *extracts*
//! it. A unit test of either half cannot catch a disagreement between them, so
//! these build the real library and read its real records.
//!
//! The property they exist for is completeness. Every one of these tests is a
//! way of asking "could a declaration have gone missing?", because the only
//! failure mode that matters here is an inventory that looks fine and is short.

use std::path::{Path, PathBuf};

use trace_check::harness::Library;
use trace_check::inventory::{self, InventoryError};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels below the workspace root")
        .to_path_buf()
}

fn library_manifest() -> PathBuf {
    workspace_root().join("examples/crypto-library/Cargo.toml")
}

/// A Cargo target directory shared by every test in this file, so the library
/// and its dependencies are not rebuilt per test.
fn shared_target_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("trace-check-m8-inventory-tests");
    std::fs::create_dir_all(&dir).expect("a shared target directory");
    dir
}

fn library() -> Library {
    Library::resolve(&library_manifest(), &[]).expect("the example library resolves")
}

fn inventory_of(library: &Library) -> inventory::ContractInventory {
    inventory::build_and_read(library, &shared_target_dir())
        .unwrap_or_else(|e| panic!("reading the contract inventory failed: {e}"))
}

/// Every declaration in the example library is discovered, with no
/// configuration file and no test execution involved.
#[test]
fn every_declaration_in_the_library_is_discovered() {
    let found = inventory_of(&library());
    assert!(found.complete(), "the inventory was not complete");
    assert_eq!(found.schema_version, inventory::SCHEMA_VERSION);

    // Named individually rather than counted, so a *replacement* -- one
    // declaration vanishing while another appears -- cannot pass.
    let expected = [
        "crypto::controls::public_branch",
        "crypto::controls::tail_byte_probe",
        "crypto::hidden::header_gate",
        "crypto::hidden::magic_gate",
        "crypto::hidden::nested_modes",
        "crypto::hidden::nested_modes_clean",
        "crypto::hidden::secret_gated",
        "crypto::hidden::threshold_window",
        "crypto::lookup::substitute",
        "crypto::lookup::substitute_indexed",
        "crypto::lookup::substitute_mode",
        "crypto::reduce::reduce_once",
        "crypto::reduce::reduce_once_masked",
        "crypto::shadow::left::probe",
        "crypto::shadow::right::probe",
        "crypto::tag::verify_tag",
        "crypto::tag::verify_tag_early_exit",
        "crypto::tag::verify_tag_volatile_early_exit",
    ];
    assert_eq!(
        found.ids(),
        expected,
        "the inventory does not match the library's declarations"
    );
}

/// Two functions named `probe` in sibling modules get two distinct records,
/// each with its own module path and its own descriptor.
#[test]
fn same_named_functions_in_sibling_modules_are_separate_records() {
    let found = inventory_of(&library());
    let left = found
        .contract("crypto::shadow::left::probe")
        .expect("the left declaration");
    let right = found
        .contract("crypto::shadow::right::probe")
        .expect("the right declaration");

    assert_eq!(left.function, "probe");
    assert_eq!(right.function, "probe");
    assert_eq!(left.module, "crypto::shadow::left");
    assert_eq!(right.module, "crypto::shadow::right");
    assert_ne!(left.id, right.id);
    assert!(
        left.source_file.ends_with("left.rs"),
        "{}",
        left.source_file
    );
    assert!(
        right.source_file.ends_with("right.rs"),
        "{}",
        right.source_file
    );
}

/// Each record carries the declaration site from the developer's own source.
#[test]
fn records_carry_their_declaration_site() {
    let found = inventory_of(&library());
    for declaration in &found.contracts {
        assert!(
            declaration.source_file.ends_with(".rs"),
            "{} has no source file",
            declaration.id
        );
        assert!(
            declaration.source_line > 0,
            "{} has no source line",
            declaration.id
        );
        assert!(declaration.site().contains(':'));
    }
    // Spot-checked against the source, so a plausible-looking but wrong line
    // cannot pass.
    let nested = found
        .contract("crypto::hidden::nested_modes")
        .expect("the nested declaration");
    assert!(nested.source_file.ends_with("hidden.rs"));
    let source =
        std::fs::read_to_string(workspace_root().join("examples/crypto-library/src/hidden.rs"))
            .expect("the fixture source is readable");
    // The recorded line is the **annotation**, not the `fn` beneath it, which
    // is both what `line!()` reports from inside an attribute macro and what a
    // developer wants to jump to. It matches the existing `site_const` the
    // other backends report, so the two cannot disagree.
    let lines: Vec<&str> = source.lines().collect();
    let declared = lines
        .get(nested.source_line as usize - 1)
        .expect("the recorded line exists");
    assert!(
        declared.contains("#[constant_time"),
        "line {} is {declared:?}, not the annotation",
        nested.source_line
    );
    assert!(
        lines
            .get(nested.source_line as usize)
            .is_some_and(|next| next.contains("pub fn nested_modes")),
        "the annotation at line {} is not on the declaration it names",
        nested.source_line
    );
}

/// Each record's embedded descriptor models the real signature, and matches
/// what the macro put in the descriptor constant.
#[test]
fn records_carry_a_usable_descriptor() {
    let found = inventory_of(&library());
    let tag = found
        .contract("crypto::tag::verify_tag")
        .expect("the tag declaration");
    assert_eq!(tag.descriptor.function, "verify_tag");
    assert_eq!(tag.descriptor.parameters.len(), 2);
    let secrets: Vec<&str> = tag
        .secrets()
        .map(|parameter| parameter.name.as_str())
        .collect();
    assert_eq!(secrets, vec!["expected"]);
    assert_eq!(tag.descriptor_sha256.len(), 64);

    // Every declaration's descriptor validates against its own identity, which
    // is what makes the record a declaration rather than just a name.
    for declaration in &found.contracts {
        declaration
            .descriptor
            .validate(&declaration.id)
            .unwrap_or_else(|e| panic!("{}: {e}", declaration.id));
        assert_eq!(declaration.descriptor.function, declaration.function);
    }
}

/// `dynamic = false` is recorded, and does not remove the declaration.
///
/// The asymmetry M8 exists to close: M3's discovery goes through a generated
/// `#[cfg(test)]` metadata test, so an annotation-only library was invisible to
/// it. `examples/external-library` declares every contract `dynamic = false`
/// and depends only on the macro crate.
#[test]
fn dynamic_false_declarations_are_still_inventoried() {
    let external = Library::resolve(
        &workspace_root().join("examples/external-library/Cargo.toml"),
        &[],
    )
    .expect("the external library resolves");
    let found = inventory_of(&external);

    assert!(found.complete());
    assert_eq!(
        found.ids(),
        vec![
            "external_library::digest_nibble",
            "external_library::mix_when",
            "external_library::select",
        ]
    );
    for declaration in &found.contracts {
        assert!(
            !declaration.dynamic_adapter_enabled,
            "{} should have no dynamic adapter",
            declaration.id
        );
    }
    // And the library's own declarations carry the flag the other way, so the
    // field is not simply always false.
    let crypto = inventory_of(&library());
    assert!(
        crypto
            .contracts
            .iter()
            .all(|declaration| declaration.dynamic_adapter_enabled),
        "the example library's contracts all use the dynamic adapter"
    );
}

/// The same artifact yields the same inventory, including its identity.
#[test]
fn the_inventory_is_deterministic() {
    let first = inventory_of(&library());
    let second = inventory_of(&library());
    assert_eq!(first.id, second.id);
    assert_eq!(first.ids(), second.ids());
    assert_eq!(
        first.build.artifact_sha256, second.build.artifact_sha256,
        "two builds of one source produced different artifacts"
    );
}

/// The inventory records which compilation it describes.
#[test]
fn the_inventory_records_its_build_identity() {
    let found = inventory_of(&library());
    let build = &found.build;
    assert_eq!(build.package, "crypto-library");
    assert_eq!(build.lib_target, "crypto");
    assert!(build.features.is_empty(), "no features were requested");
    assert_eq!(build.target_triple, "x86_64-unknown-linux-gnu");
    assert!(
        build.rustc_version.contains("rustc"),
        "{}",
        build.rustc_version
    );
    assert_eq!(build.artifact_sha256.len(), 64);
    assert!(build.artifact_path.ends_with(".rlib"));
    // The flag that makes the records readable at all is recorded, not
    // implied: an LTO rlib holds bitcode and has no ELF sections.
    assert!(build.profile.contains("lto=off"), "{}", build.profile);
    assert!(build.variant().contains("crypto-library"));

    // The limitations travel with the result.
    let limits = found.limitations().join(" ");
    assert!(limits.contains("one compilation"), "{limits}");
    assert!(limits.contains("does not discover functions"), "{limits}");
}

/// A feature-gated declaration follows the selected compilation: present when
/// the feature is on, absent when it is off, and the two inventories are
/// distinguishable.
#[test]
fn feature_gated_declarations_follow_the_selected_build() {
    let manifest = workspace_root().join("examples/consumer-crate/Cargo.toml");
    let plain = Library::resolve(&manifest, &[]).expect("the consumer resolves");
    let gated = Library::resolve(&manifest, &["untested-contract".to_string()])
        .expect("the consumer resolves with the feature");

    let without = inventory_of(&plain);
    let with = inventory_of(&gated);

    const GATED: &str = "consumer_crate::unverified_mix";
    assert!(
        without.contract(GATED).is_none(),
        "an inactive declaration was inventoried: {:?}",
        without.ids()
    );
    assert!(
        with.contract(GATED).is_some(),
        "an active declaration was not inventoried: {:?}",
        with.ids()
    );

    // Two variants of one package must never be confused for each other.
    assert_ne!(without.id, with.id);
    assert_ne!(without.build.variant(), with.build.variant());
    assert!(with.build.variant().contains("untested-contract"));
    // Everything the plain build declares is still declared by the gated one;
    // the feature adds rather than replaces.
    for id in without.ids() {
        assert!(
            with.contract(id).is_some(),
            "{id} disappeared when a feature was enabled"
        );
    }
}

/// A library with no declarations yields a valid empty inventory, not an error
/// and not a failure to read.
#[test]
fn a_library_with_no_declarations_yields_an_empty_inventory() {
    let manifest = workspace_root().join("examples/table-lookup/Cargo.toml");
    let plain = Library::resolve(&manifest, &[]).expect("the library resolves");
    let found = inventory_of(&plain);
    assert!(
        found.contracts.is_empty(),
        "unexpected declarations: {:?}",
        found.ids()
    );
    // The distinction that makes the empty result meaningful: objects were
    // read, there was simply nothing declared in them.
    assert!(found.complete());
    assert!(
        found.objects_read > 0,
        "no object was read, so `no contracts` is not an established result"
    );
}

/// An artifact that is not an archive is refused by name rather than read as
/// an empty inventory.
#[test]
fn a_non_archive_artifact_is_refused() {
    let scratch = std::env::temp_dir().join("trace-check-m8-bad-artifact");
    std::fs::create_dir_all(&scratch).expect("a scratch directory");
    let fake = scratch.join("libnothing.rlib");
    std::fs::write(&fake, b"this is not an ar archive").expect("the file is writable");

    let error =
        inventory::read_artifact(&library(), &fake).expect_err("a non-archive must be refused");
    assert!(matches!(error, InventoryError::NotAnArchive), "{error:?}");
}

/// The LTO case, end to end: the developer's own release profile enables fat
/// LTO, which fills the rlib with bitcode. That must be an explicit error.
///
/// This is the failure the M8.1 spike found in this very repository, and the
/// reason the inventory build pins `lto = off`. Reading it as an empty
/// inventory would have cleared all 18 of the library's contracts.
#[test]
fn an_lto_artifact_is_refused_rather_than_reported_empty() {
    let target = std::env::temp_dir().join("trace-check-m8-lto-artifact");
    let output = std::process::Command::new("cargo")
        .args(["build", "--release", "--lib", "--quiet"])
        .arg("--manifest-path")
        .arg(library_manifest())
        .arg("--target-dir")
        .arg(&target)
        // Exactly what the workspace's own release profile does.
        .env("CARGO_PROFILE_RELEASE_LTO", "true")
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("cargo runs");
    assert!(
        output.status.success(),
        "the LTO build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let artifact = target.join("release/libcrypto.rlib");

    let error = inventory::read_artifact(&library(), &artifact)
        .expect_err("a bitcode archive must be refused");
    match &error {
        InventoryError::NotObjects { objects, bitcode } => {
            assert!(*objects > 0);
            assert_eq!(objects, bitcode, "every object should be bitcode");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let message = error.to_string();
    assert!(message.contains("lto = off"), "{message}");
    assert!(message.contains("clean bill of health"), "{message}");
}

/// Nothing in the inventory path executes the library's tests.
///
/// `examples/discovery-hazard` has an ordinary unit test that writes a sentinel
/// file and then fails. M3's discovery had to be fixed not to run it; the
/// inventory must not run it either, and for a stronger reason: it reads
/// compiled data and should never need to execute anything at all.
#[test]
fn building_an_inventory_does_not_execute_tests() {
    const SENTINEL: &str = "/tmp/trace-check-discovery-hazard-sentinel";
    let _ = std::fs::remove_file(SENTINEL);

    let hazard = Library::resolve(
        &workspace_root().join("examples/discovery-hazard/Cargo.toml"),
        &[],
    )
    .expect("the hazard library resolves");
    let found = inventory::build_and_read(&hazard, &shared_target_dir())
        .expect("the hazard library's inventory is readable");

    assert!(
        !Path::new(SENTINEL).exists(),
        "building an inventory executed an ordinary unit test"
    );
    assert!(found.complete());
}
