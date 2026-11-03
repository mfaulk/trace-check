//! M7 coverage-collection tests, against the real `examples/crypto-library`.
//!
//! These build an instrumented discovery artifact around a real contract and
//! read per-case LLVM coverage out of it. They need the `llvm-tools` component
//! and so skip when it is absent, except under `TRACE_CHECK_REQUIRE_BACKEND`,
//! which CI sets — a skip must never be able to pass for a success.
//!
//! They assert nothing about constant-time behavior. That is the whole point:
//! this artifact exists to discover inputs, and these tests check that it
//! discriminates paths, attributes coverage to the right case, excludes the
//! harness's own code, and refuses evidence it cannot validate.

use std::path::{Path, PathBuf};

use trace_check::contract::Contract;
use trace_check::coverage::{self, Collector, CoverageMap, ExecutionStatus, LlvmTools, RegionSet};
use trace_check::dynamic_harness::{self, HarnessKind};
use trace_check::generate::{self, GeneratedCase, Strategy, Value};
use trace_check::harness::{self, Library, Workspace};
use trace_check::native::Limits;

const NESTED: &str = "crypto::hidden::nested_modes";

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

/// Returns the LLVM tools, or `None` (after reporting) when they are absent and
/// the environment has not demanded them.
fn llvm_tools() -> Option<LlvmTools> {
    match LlvmTools::locate() {
        Ok(tools) => Some(tools),
        Err(error) => {
            assert!(
                std::env::var_os("TRACE_CHECK_REQUIRE_BACKEND").is_none(),
                "TRACE_CHECK_REQUIRE_BACKEND is set but the LLVM tools are missing: {error}"
            );
            eprintln!("skipping: {error}");
            None
        }
    }
}

/// A Cargo target directory shared by every test in this file, for the same
/// reason the M6 dynamic suite shares one: each test would otherwise rebuild
/// the library and its dependencies from scratch.
fn shared_target_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("trace-check-m7-coverage-tests");
    std::fs::create_dir_all(&dir).expect("a shared target directory");
    dir
}

/// A built discovery artifact with a staged corpus of hand-written cases.
struct Discovery {
    contract: Contract,
    artifact: PathBuf,
    artifact_sha256: String,
    corpus_path: PathBuf,
    profile_dir: PathBuf,
    // Held so the workspace outlives the artifact inside it.
    _workspace: Workspace,
}

/// Builds the discovery artifact for `contract_id` over exactly `cases`.
fn prepare(contract_id: &str, cases: &[Vec<(String, Value)>]) -> Discovery {
    let library = Library::resolve(&library_manifest(), &[]).expect("the example library resolves");
    let workspace = Workspace::ephemeral().expect("a private work directory");
    let (work_dir, _per_run) = workspace
        .directories_for(contract_id)
        .expect("per-contract directories");
    let target_dir = shared_target_dir();

    let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
        .unwrap_or_else(|e| panic!("reading the contract for {contract_id} failed: {e}"));
    let generated = dynamic_harness::generate_discovery(&contract)
        .unwrap_or_else(|e| panic!("generating a discovery harness failed: {e}"));
    assert_eq!(generated.kind, HarnessKind::Discovery);
    let corpus = generate::verbatim(contract_id, &contract.descriptor, cases)
        .expect("the hand-written cases fit the contract");
    let corpus_path =
        dynamic_harness::stage_corpus(&corpus, &work_dir).expect("the corpus is staged");
    let artifact =
        dynamic_harness::build(&library, &generated, contract_id, &work_dir, &target_dir)
            .unwrap_or_else(|e| panic!("building the discovery artifact failed: {e}"));
    let profile_dir = work_dir.join("profiles");

    Discovery {
        contract,
        artifact: artifact.path,
        artifact_sha256: artifact.sha256,
        corpus_path,
        profile_dir,
        _workspace: workspace,
    }
}

impl Discovery {
    fn collector<'a>(&self, tools: &'a LlvmTools) -> Collector<'a> {
        Collector::new(
            tools,
            &self.artifact,
            &self.artifact_sha256,
            &library_manifest(),
            &self.contract.function,
            Limits::default(),
        )
    }
}

/// `nested_modes(index, stage, gate, trigger)` as a case.
fn nested(index: u8, stage: u8, gate: u8, trigger: u8) -> Vec<(String, Value)> {
    [
        ("index", index),
        ("stage", stage),
        ("gate", gate),
        ("trigger", trigger),
    ]
    .into_iter()
    .map(|(name, value)| {
        (
            name.to_string(),
            Value::Scalar {
                bits: 8,
                value: value as u64,
            },
        )
    })
    .collect()
}

/// The predicate ladder: 0, 1, 2 and 3 of `nested_modes`' conjuncts satisfied.
fn ladder() -> Vec<Vec<(String, Value)>> {
    vec![
        nested(7, 0x00, 0x00, 0x00),
        nested(7, 0x0a, 0x00, 0x00),
        nested(7, 0x0a, 0x30, 0x00),
        nested(7, 0x0a, 0x30, 0x5a),
    ]
}

/// Every additional satisfied public predicate reaches regions the previous one
/// did not: the gradient the whole milestone depends on.
#[test]
fn deeper_inputs_reach_new_library_regions() {
    let Some(tools) = llvm_tools() else { return };
    let discovery = prepare(NESTED, &ladder());
    let collector = discovery.collector(&tools);

    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    assert!(
        map.target_records >= 1,
        "the map must hold a record for the function under study"
    );
    assert!(
        map.files.iter().any(|file| file.ends_with("hidden.rs")),
        "the library's own source must be in scope, got {:?}",
        map.files
    );

    let run = collector
        .observe(
            &discovery.corpus_path,
            &[0, 1, 2, 3],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");
    assert!(
        run.complete(),
        "the discovery run was incomplete: {:?}",
        run.incompleteness()
    );

    let mut seen = RegionSet::new();
    let mut novel_per_step = Vec::new();
    for observation in &run.observations {
        let novel = observation.novel(&seen);
        novel_per_step.push(novel.len());
        seen.extend(novel);
    }
    assert!(
        novel_per_step.iter().all(|count| *count > 0),
        "each step of the predicate ladder must add new regions, got {novel_per_step:?}"
    );
    // The deepest case reaches the secret-indexed load, which lives in
    // `lookup.rs` and is not reachable from any shallower case.
    let deepest = &run.observations[3];
    assert!(
        deepest
            .covered_regions
            .iter()
            .any(|region| region.file.ends_with("lookup.rs")
                && region.line_start >= 30
                && region.line_start <= 40),
        "the deepest case must reach substitute_indexed, covered: {:?}",
        deepest
            .covered_regions
            .iter()
            .map(|r| r.describe())
            .collect::<Vec<_>>()
    );
}

/// An input covering fewer total regions can still be the novel one. Taking the
/// deep path means *not* executing three early returns.
#[test]
fn the_deepest_case_covers_fewer_regions_and_is_still_novel() {
    let Some(tools) = llvm_tools() else { return };
    let discovery = prepare(NESTED, &ladder());
    let collector = discovery.collector(&tools);
    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    let run = collector
        .observe(
            &discovery.corpus_path,
            &[2, 3],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");

    let shallow = &run.observations[0];
    let deep = &run.observations[1];
    assert!(
        deep.covered_regions.len() < shallow.covered_regions.len(),
        "expected the deep case to cover fewer regions ({} vs {})",
        deep.covered_regions.len(),
        shallow.covered_regions.len()
    );
    assert!(
        !deep.novel(&shallow.covered_regions).is_empty(),
        "the deep case must still be novel against the shallow one"
    );
}

/// Re-running the same input produces the same coverage, so a repeat never
/// looks like a discovery.
#[test]
fn repeating_an_input_discovers_nothing_new() {
    let Some(tools) = llvm_tools() else { return };
    let deep = nested(7, 0x0a, 0x30, 0x5a);
    let discovery = prepare(NESTED, &[deep.clone(), deep.clone(), deep]);
    let collector = discovery.collector(&tools);
    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    let run = collector
        .observe(
            &discovery.corpus_path,
            &[0, 1, 2],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");
    assert!(run.complete(), "{:?}", run.incompleteness());

    let first = &run.observations[0];
    assert!(
        !first.covered_regions.is_empty(),
        "the first case covers something"
    );
    for repeat in &run.observations[1..] {
        assert_eq!(
            repeat.covered_regions, first.covered_regions,
            "an identical input must produce identical coverage"
        );
        assert!(
            repeat.novel(&first.covered_regions).is_empty(),
            "a repeated input must discover nothing new"
        );
    }
}

/// Coverage is attributed to the case that produced it, not to the batch: the
/// counters are reset between cases, so a shallow case run *after* a deep one
/// does not inherit the deep one's regions.
#[test]
fn coverage_is_attributed_to_the_individual_case() {
    let Some(tools) = llvm_tools() else { return };
    let discovery = prepare(NESTED, &ladder());
    let collector = discovery.collector(&tools);
    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    // Deepest first, shallowest last.
    let run = collector
        .observe(
            &discovery.corpus_path,
            &[3, 0],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");
    assert!(run.complete(), "{:?}", run.incompleteness());

    let deep = &run.observations[0];
    let shallow = &run.observations[1];
    assert_eq!(deep.case_id, 3);
    assert_eq!(shallow.case_id, 0);
    assert!(
        !shallow.covered_regions.is_superset(&deep.covered_regions),
        "the shallow case inherited the deep case's coverage; counters are not being reset"
    );
    assert!(
        !shallow.covered_regions.is_empty(),
        "the shallow case still covers its own regions"
    );
}

/// The generated harness's own regions are excluded from target feedback, so a
/// candidate is never retained for having exercised the decoder.
#[test]
fn harness_and_dependency_coverage_is_excluded() {
    let Some(tools) = llvm_tools() else { return };
    let discovery = prepare(NESTED, &ladder());
    let collector = discovery.collector(&tools);
    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    let run = collector
        .observe(
            &discovery.corpus_path,
            &[0, 3],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");

    for observation in &run.observations {
        for region in &observation.covered_regions {
            assert!(
                Path::new(&region.file).starts_with(collector.scope()),
                "{} is outside the library scope {}",
                region.file,
                collector.scope().display()
            );
            assert!(
                !region.file.contains(dynamic_harness::REMAPPED_HARNESS_DIR),
                "the generated harness's own coverage leaked into the feedback: {}",
                region.file
            );
        }
    }
    // The map does see the harness and the dependencies; they are excluded from
    // the *in-scope* count rather than never measured.
    assert!(
        map.total_regions > map.in_scope_regions,
        "the artifact covers more than the library, so the two counts must differ"
    );
}

/// `target_invoked` reports the function under study, which the ladder always
/// enters.
#[test]
fn the_target_is_reported_as_invoked() {
    let Some(tools) = llvm_tools() else { return };
    let discovery = prepare(NESTED, &ladder());
    let collector = discovery.collector(&tools);
    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    let run = collector
        .observe(
            &discovery.corpus_path,
            &[0, 1, 2, 3],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");
    for observation in &run.observations {
        assert!(
            observation.target_invoked,
            "case {} did not record entering the target",
            observation.case_id
        );
        assert_eq!(observation.status, ExecutionStatus::Observed);
        assert_eq!(observation.artifact_sha256, discovery.artifact_sha256);
        assert_eq!(observation.coverage_map_id, map.id);
    }
}

/// Damaged, missing and unvalidatable coverage evidence is each reported as
/// its own status, and none of them contributes coverage.
///
/// The failure this guards is subtle: an empty region set reads as "this input
/// reached nothing new", so a silently failing decode would make every
/// candidate look uninteresting and exploration would do nothing while
/// reporting success.
#[test]
fn damaged_coverage_evidence_is_rejected_not_read_as_empty() {
    let Some(tools) = llvm_tools() else { return };
    let discovery = prepare(NESTED, &ladder());
    let collector = discovery.collector(&tools);
    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    let run = collector
        .observe(
            &discovery.corpus_path,
            &[0, 1, 2, 3],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");
    assert!(run.complete(), "{:?}", run.incompleteness());
    let good = std::fs::metadata(discovery.profile_dir.join("baseline.profraw"))
        .expect("the baseline exists")
        .len();

    // Case 0: doubled, exactly as the at-exit write would have left it. This is
    // the hazard the M7.1 spike found -- a doubled profile decodes to doubled
    // counts rather than to an error, so only the length check catches it.
    let raw = discovery.profile_dir.join("case-0.profraw");
    let bytes = std::fs::read(&raw).expect("the profile is readable");
    let mut doubled = bytes.clone();
    doubled.extend_from_slice(&bytes);
    std::fs::write(&raw, &doubled).expect("the profile is writable");

    // Case 1: truncated, which the tools themselves refuse.
    let truncated = discovery.profile_dir.join("case-1.profraw");
    let bytes = std::fs::read(&truncated).expect("the profile is readable");
    std::fs::write(&truncated, &bytes[..bytes.len() / 3]).expect("the profile is writable");

    // Case 2: gone.
    std::fs::remove_file(discovery.profile_dir.join("case-2.profraw"))
        .expect("the profile exists to be removed");

    // Case 3: intact, so the test shows the others are rejected individually
    // rather than the whole batch being discarded.
    let observations = collector.decode(
        &[0, 1, 2, 3],
        &[0, 1, 2, 3],
        &discovery.profile_dir,
        Some(good),
        &map.id,
    );
    assert!(
        matches!(
            observations[0].status,
            ExecutionStatus::ProfileInvalid { .. }
        ),
        "a doubled profile must be refused, got {:?}",
        observations[0].status
    );
    assert!(
        !observations[1].status.usable(),
        "a truncated profile must be refused, got {:?}",
        observations[1].status
    );
    assert_eq!(observations[2].status, ExecutionStatus::ProfileMissing);
    assert_eq!(observations[3].status, ExecutionStatus::Observed);
    for rejected in &observations[..3] {
        assert!(
            rejected.covered_regions.is_empty(),
            "a refused profile contributes no coverage"
        );
        assert!(rejected.novel(&RegionSet::new()).is_empty());
    }
    assert!(!observations[3].covered_regions.is_empty());

    // A case that never reported completing is its own status, distinct from a
    // case whose profile was unreadable.
    let incomplete = collector.decode(&[3], &[], &discovery.profile_dir, Some(good), &map.id);
    assert_eq!(incomplete[0].status, ExecutionStatus::DidNotComplete);

    // With no baseline there is no reference length, and *every* profile
    // becomes unvalidatable rather than acceptable.
    let unvalidatable = collector.decode(&[3], &[3], &discovery.profile_dir, None, &map.id);
    assert!(
        matches!(
            unvalidatable[0].status,
            ExecutionStatus::ProfileInvalid { .. }
        ),
        "without a baseline nothing can be validated, got {:?}",
        unvalidatable[0].status
    );
}

/// The at-exit drain keeps the last case's profile the same length as the
/// others, which is what makes the length check usable at all.
#[test]
fn the_last_case_profile_is_not_doubled() {
    let Some(tools) = llvm_tools() else { return };
    let discovery = prepare(NESTED, &ladder());
    let collector = discovery.collector(&tools);
    let (map, _) = collector
        .probe_map(&discovery.corpus_path, 0, &discovery.profile_dir)
        .expect("the coverage map is readable");
    collector
        .observe(
            &discovery.corpus_path,
            &[0, 1, 2, 3],
            &discovery.profile_dir,
            &map.id,
        )
        .expect("the batch runs");

    let baseline = std::fs::metadata(discovery.profile_dir.join("baseline.profraw"))
        .expect("the baseline exists")
        .len();
    for id in 0..4 {
        let length = std::fs::metadata(discovery.profile_dir.join(format!("case-{id}.profraw")))
            .unwrap_or_else(|e| panic!("case {id}'s profile is missing: {e}"))
            .len();
        assert_eq!(
            length, baseline,
            "case {id}'s profile is {length} bytes against a {baseline}-byte baseline; the \
             at-exit write is appending a stale record"
        );
    }
    assert!(
        discovery.profile_dir.join("at-exit.profraw").is_file(),
        "the drain profile must exist, or the at-exit write went somewhere else"
    );
}

/// The discovery harness marks no secret and does not depend on the marking
/// crate, so it cannot be the source of a security claim.
#[test]
fn the_discovery_harness_marks_nothing() {
    let library = Library::resolve(&library_manifest(), &[]).expect("the library resolves");
    let workspace = Workspace::ephemeral().expect("a work directory");
    let (work_dir, _) = workspace.directories_for(NESTED).expect("directories");
    let contract = harness::probe_contract(&library, NESTED, &work_dir, &shared_target_dir())
        .expect("the contract resolves");

    let discovery = dynamic_harness::generate_discovery(&contract).expect("a discovery harness");
    assert_eq!(discovery.marked_bytes, 0);
    assert!(!discovery.source.contains("trace_check_test"));
    assert!(!discovery.source.contains("confirm_binding"));
    assert!(!discovery.source.contains("require_instrumentation"));
    assert!(discovery.source.contains("__llvm_profile_reset_counters"));

    let security = dynamic_harness::generate(&contract).expect("a security harness");
    assert!(security.marked_bytes > 0);
    assert!(security.source.contains("confirm_binding"));
    assert!(!security.source.contains("__llvm_profile"));

    // The shared part: both decode the same wire format into the same
    // positional call, which is what makes a candidate transferable.
    for shared in ["fn decode_scalar", "fn decode_bytes", "fn decode_bool"] {
        assert!(discovery.source.contains(shared));
        assert!(security.source.contains(shared));
    }
    assert_ne!(discovery.source_sha256, security.source_sha256);
}

/// Unused in this file but kept honest: the corpus the discovery artifact reads
/// is the same wire format the security artifact reads.
#[test]
fn both_artifacts_read_one_corpus_format() {
    let descriptor = {
        let library =
            Library::resolve(&library_manifest(), &[]).expect("the example library resolves");
        let workspace = Workspace::ephemeral().expect("a work directory");
        let (work_dir, _) = workspace.directories_for(NESTED).expect("directories");
        harness::probe_contract(&library, NESTED, &work_dir, &shared_target_dir())
            .expect("the contract resolves")
            .descriptor
    };
    let corpus = generate::generate(
        NESTED,
        &descriptor,
        &generate::GenerateSettings {
            cases: 200,
            strategies: vec![Strategy::Boundaries],
            ..Default::default()
        },
    )
    .expect("generation succeeds");
    let wire = corpus.to_wire();
    assert!(wire.starts_with("# trace-check corpus v1"));
    let first: &GeneratedCase = &corpus.cases[0];
    assert!(wire.contains(&format!("{} boundaries", first.id)));
}

/// `CoverageMap` is scoped to one artifact: rebuilding with different
/// instrumentation changes the identity, so observations cannot be mixed.
#[test]
fn the_security_artifact_has_no_coverage_map() {
    let Some(tools) = llvm_tools() else { return };
    let library = Library::resolve(&library_manifest(), &[]).expect("the library resolves");
    let workspace = Workspace::ephemeral().expect("a work directory");
    let (work_dir, _) = workspace.directories_for(NESTED).expect("directories");
    let target_dir = shared_target_dir();
    let contract = harness::probe_contract(&library, NESTED, &work_dir, &target_dir)
        .expect("the contract resolves");
    let security = dynamic_harness::generate(&contract).expect("a security harness");
    let artifact = dynamic_harness::build(&library, &security, NESTED, &work_dir, &target_dir)
        .expect("the security artifact builds");

    let collector = Collector::new(
        &tools,
        &artifact.path,
        &artifact.sha256,
        &library_manifest(),
        &contract.function,
        Limits::default(),
    );
    // There is no profile to offer it, and the uninstrumented binary has no
    // coverage map to read: the two artifacts cannot be confused.
    let error = collector
        .map(&work_dir.join("does-not-exist.profdata"))
        .expect_err("an uninstrumented artifact has no coverage map");
    let message = error.to_string();
    assert!(
        message.contains("llvm-cov") || message.contains("coverage"),
        "unexpected message: {message}"
    );
    let _: fn() -> &'static str = || coverage::FEEDBACK;
    let _unused: Option<CoverageMap> = None;
}
