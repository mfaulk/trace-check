//! M7 exploration tests: does coverage feedback reach what M6 cannot?
//!
//! `tests/baseline.rs` establishes the premise — that boundary and pairwise
//! generation cannot satisfy `crypto::hidden::nested_modes`' three-parameter
//! conjunction at any budget, and that seeded random generation does not do it
//! reliably. These tests establish the consequence.
//!
//! They need the `llvm-tools` component and so skip when it is absent, except
//! under `TRACE_CHECK_REQUIRE_BACKEND`, which CI sets.
//!
//! Nothing here asserts anything about constant-time behavior. Exploration
//! selects inputs; `tests/dynamic.rs` and `crates/cargo-trace-check/tests/explore.rs`
//! are where a leak is actually established, in the uninstrumented security
//! artifact.

use std::path::{Path, PathBuf};
use std::time::Duration;

use trace_check::contract::Contract;
use trace_check::coverage::{Collector, LlvmTools};
use trace_check::dynamic_harness;
use trace_check::explore::{self, Exploration, ExploreSettings, Origin, Termination};
use trace_check::generate::{self, GenerateSettings, Strategy, Value};
use trace_check::harness::{self, Library, Workspace};
use trace_check::native::Limits;

const NESTED: &str = "crypto::hidden::nested_modes";
const MAGIC: &str = "crypto::hidden::magic_gate";
const HEADER: &str = "crypto::hidden::header_gate";
const TAG: &str = "crypto::tag::verify_tag";

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

fn shared_target_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("trace-check-m7-coverage-tests");
    std::fs::create_dir_all(&dir).expect("a shared target directory");
    dir
}

/// Builds the discovery artifact for a contract and runs exploration over it.
fn run(contract_id: &str, settings: &ExploreSettings, cases: usize) -> (Contract, Exploration) {
    let tools = llvm_tools().expect("the caller checked availability");
    let library = Library::resolve(&library_manifest(), &[]).expect("the example library resolves");
    let workspace = Workspace::ephemeral().expect("a private work directory");
    let (work_dir, _per_run) = workspace
        .directories_for(contract_id)
        .expect("per-contract directories");
    let target_dir = shared_target_dir();

    let contract = harness::probe_contract(&library, contract_id, &work_dir, &target_dir)
        .unwrap_or_else(|e| panic!("reading the contract for {contract_id} failed: {e}"));
    let harness = dynamic_harness::generate_discovery(&contract)
        .unwrap_or_else(|e| panic!("generating a discovery harness failed: {e}"));
    let artifact = dynamic_harness::build(&library, &harness, contract_id, &work_dir, &target_dir)
        .unwrap_or_else(|e| panic!("building the discovery artifact failed: {e}"));

    // The M6 corpus exploration starts from, generated exactly as M6 would.
    let baseline = generate::generate(
        contract_id,
        &contract.descriptor,
        &GenerateSettings {
            cases,
            ..GenerateSettings::default()
        },
    )
    .expect("the baseline corpus generates");

    let collector = Collector::new(
        &tools,
        &artifact.path,
        &artifact.sha256,
        &library_manifest(),
        &contract.module,
        &contract.function,
        Limits::default(),
    );
    let exploration = explore::explore(
        contract_id,
        &contract.descriptor,
        &baseline,
        &collector,
        settings,
        &work_dir,
    )
    .unwrap_or_else(|e| panic!("exploration failed: {e}"));
    // The workspace holds the artifact, so it must outlive the run above.
    drop(workspace);
    (contract, exploration)
}

fn scalar(inputs: &[(String, Value)], name: &str) -> u64 {
    match inputs
        .iter()
        .find(|(parameter, _)| parameter == name)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("`{name}` is a parameter"))
    {
        Value::Scalar { value, .. } => *value,
        other => panic!("`{name}` is a scalar, got {other:?}"),
    }
}

/// `header_gate`'s three header fields, which must hold together.
fn reaches_header_leak(inputs: &[(String, Value)]) -> bool {
    let bytes = match inputs
        .iter()
        .find(|(parameter, _)| parameter == "header")
        .map(|(_, value)| value)
        .expect("`header` is a parameter")
    {
        Value::Bytes { bytes } => bytes.clone(),
        other => panic!("`header` is a byte array, got {other:?}"),
    };
    bytes[0] >> 4 == 0x3 && bytes[1] & 0xf0 == 0xc0 && bytes[7] == 0x7f
}

/// `nested_modes`' three-predicate conjunction, the path M6 cannot construct.
fn reaches_nested_leak(inputs: &[(String, Value)]) -> bool {
    scalar(inputs, "stage") & 0x0f == 0x0a
        && scalar(inputs, "gate") & 0xf0 == 0x30
        && scalar(inputs, "trigger") == 0x5a
}

/// Coverage feedback reaches the leak behind three public predicates, which
/// `tests/baseline.rs` proves M6's boundary and pairwise stages cannot do at
/// any budget.
///
/// This is the milestone's central claim and the reason M7 exists.
#[test]
fn exploration_reaches_the_leak_m6_cannot_construct() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        candidate_budget: 2_000,
        seed: 12_345,
        ..ExploreSettings::default()
    };
    let (_, exploration) = run(NESTED, &settings, 200);

    let reaching: Vec<&explore::Candidate> = exploration
        .candidates
        .iter()
        .filter(|candidate| reaches_nested_leak(&candidate.inputs))
        .collect();
    assert!(
        !reaching.is_empty(),
        "exploration retained {} candidate(s) over {} attempt(s) in {} round(s) and none \
         satisfied the conjunction. Termination: {}. Regions: {} baseline, {} total",
        exploration.candidates.len(),
        exploration.candidates_attempted,
        exploration.rounds,
        exploration.termination.describe(),
        exploration.baseline_regions,
        exploration.regions_reached
    );
    // And it got there by mutation, not by accident in the baseline.
    assert!(
        reaching
            .iter()
            .any(|candidate| matches!(candidate.origin, Origin::Mutated { .. })),
        "the reaching candidate came from the baseline, which contradicts tests/baseline.rs"
    );
    assert!(
        exploration.regions_added() > 0,
        "exploration added no regions over the baseline"
    );
    assert!(
        exploration.complete(),
        "exploration was not complete: {:?}",
        exploration.incompleteness()
    );
}

/// The second hidden-path fixture, whose conditions are fields of one
/// byte-array parameter rather than separate scalars.
///
/// A different mutation path from `nested_modes`: the per-position sweep over a
/// `[u8; 8]` rather than the scalar operators. `tests/baseline.rs` proves no
/// byte-array boundary pattern satisfies even the first of its three fields, so
/// M6 cannot reach it at any budget.
#[test]
fn exploration_reaches_a_leak_behind_one_structured_parameter() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        candidate_budget: 1_500,
        seed: 2_024,
        ..ExploreSettings::default()
    };
    let (_, exploration) = run(HEADER, &settings, 64);

    let reaching: Vec<&explore::Candidate> = exploration
        .candidates
        .iter()
        .filter(|candidate| reaches_header_leak(&candidate.inputs))
        .collect();
    assert!(
        !reaching.is_empty(),
        "exploration attempted {} candidate(s) in {} round(s) and reached none of the three \
         header fields together. Termination: {}. Regions: {} baseline, {} total",
        exploration.candidates_attempted,
        exploration.rounds,
        exploration.termination.describe(),
        exploration.baseline_regions,
        exploration.regions_reached
    );
    assert!(
        reaching
            .iter()
            .any(|candidate| matches!(candidate.origin, Origin::Mutated { .. })),
        "the reaching candidate came from the baseline, which contradicts tests/baseline.rs"
    );
    // Every byte array still has its declared width.
    for candidate in &exploration.candidates {
        match &candidate.inputs[1].1 {
            Value::Bytes { bytes } => assert_eq!(bytes.len(), 8),
            other => panic!("`header` became {other:?}"),
        }
    }
    assert!(exploration.complete(), "{:?}", exploration.incompleteness());
}

/// The same seed, artifact and budget produce an identical retained corpus.
#[test]
fn exploration_is_reproducible() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        // Small, so the test is a reproducibility check rather than a second
        // run of the search above.
        candidate_budget: 192,
        seed: 777,
        ..ExploreSettings::default()
    };
    let keys = |exploration: &Exploration| -> Vec<String> {
        exploration
            .candidates
            .iter()
            .map(|candidate| format!("{}|{}", candidate.id, candidate.describe()))
            .collect()
    };

    let (_, first) = run(NESTED, &settings, 200);
    let (_, second) = run(NESTED, &settings, 200);
    assert_eq!(
        keys(&first),
        keys(&second),
        "the same seed and budget produced different corpora"
    );
    assert_eq!(first.candidates_attempted, second.candidates_attempted);
    assert_eq!(first.regions_reached, second.regions_reached);
    assert_eq!(
        first.coverage_map.id, second.coverage_map.id,
        "two builds of the same source produced different coverage maps"
    );

    let other = ExploreSettings {
        seed: 778,
        ..settings.clone()
    };
    let (_, different) = run(NESTED, &other, 200);
    assert_ne!(
        keys(&first),
        keys(&different),
        "a different seed explored identically"
    );
}

/// A changed seed cannot change which parameter is secret, only which values
/// are tried.
#[test]
fn a_seed_cannot_change_the_declared_roles() {
    if llvm_tools().is_none() {
        return;
    }
    for seed in [1u64, 999] {
        let settings = ExploreSettings {
            candidate_budget: 128,
            seed,
            ..ExploreSettings::default()
        };
        let (contract, exploration) = run(NESTED, &settings, 200);
        let secrets: Vec<&str> = contract
            .descriptor
            .secrets()
            .map(|parameter| parameter.name.as_str())
            .collect();
        assert_eq!(secrets, vec!["index"]);
        for candidate in &exploration.candidates {
            let names: Vec<&str> = candidate
                .inputs
                .iter()
                .map(|(name, _)| name.as_str())
                .collect();
            assert_eq!(
                names,
                vec!["index", "stage", "gate", "trigger"],
                "seed {seed} produced a candidate with different parameters"
            );
        }
    }
}

/// Every M6 case survives exploration as a mandatory candidate, so enabling
/// exploration can never reduce what the security backend is offered.
#[test]
fn the_baseline_corpus_is_preserved_in_full() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        candidate_budget: 128,
        ..ExploreSettings::default()
    };
    let (contract, exploration) = run(NESTED, &settings, 200);

    let baseline = generate::generate(
        NESTED,
        &contract.descriptor,
        &GenerateSettings {
            cases: 200,
            ..GenerateSettings::default()
        },
    )
    .expect("the baseline corpus generates");

    assert_eq!(exploration.baseline_cases, baseline.cases.len());
    let mandatory: Vec<&explore::Candidate> = exploration
        .candidates
        .iter()
        .filter(|candidate| candidate.mandatory)
        .collect();
    assert_eq!(
        mandatory.len(),
        baseline.cases.len(),
        "a baseline case was dropped by exploration"
    );
    for (case, candidate) in baseline.cases.iter().zip(&mandatory) {
        assert_eq!(case.id, candidate.id);
        assert_eq!(case.inputs, candidate.inputs);
        assert_eq!(
            candidate.origin,
            Origin::Baseline {
                strategy: case.strategy
            }
        );
    }
    // Explored candidates are labelled as such and never as a baseline
    // strategy, so a corpus report cannot misattribute them.
    for candidate in &exploration.candidates {
        if let Origin::Baseline { strategy } = candidate.origin {
            assert_ne!(strategy, Strategy::Explored);
        }
    }
}

/// The magic-constant fixture is *not* reached, and the run says so honestly
/// rather than reporting a successful search.
///
/// The M7.1 spike measured why: 16 random 32-bit tokens produce byte-identical
/// coverage, so region feedback has nothing to climb toward one exact value.
/// This is the recorded basis for deferring comparison-guided mutation.
#[test]
fn the_magic_constant_is_not_reached_and_the_run_admits_it() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        candidate_budget: 1_000,
        seed: 4_242,
        ..ExploreSettings::default()
    };
    let (_, exploration) = run(MAGIC, &settings, 200);
    let reached = exploration
        .candidates
        .iter()
        .any(|candidate| scalar(&candidate.inputs, "token") == 0x5a17_c0de);
    assert!(
        !reached,
        "region coverage reached a 32-bit constant; the comparison-guidance analysis in \
         docs/MILESTONE-07.md has to be revisited"
    );
    // The search converges rather than pretending to still be making progress.
    assert!(
        matches!(
            exploration.termination,
            Termination::Converged { .. } | Termination::BudgetExhausted | Termination::QueueEmpty
        ),
        "unexpected termination: {:?}",
        exploration.termination
    );
    assert!(exploration.complete());
}

/// Byte-array contracts explore too, and every mutated array keeps its declared
/// length.
#[test]
fn byte_array_contracts_explore_within_their_declared_widths() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        candidate_budget: 256,
        seed: 31,
        ..ExploreSettings::default()
    };
    let (contract, exploration) = run(TAG, &settings, 128);
    for candidate in &exploration.candidates {
        for (parameter, (name, value)) in
            contract.descriptor.parameters.iter().zip(&candidate.inputs)
        {
            assert_eq!(&parameter.name, name);
            assert!(
                value.fits(&parameter.repr),
                "candidate {} bound {value:?} to {}",
                candidate.id,
                parameter.repr.describe()
            );
        }
    }
    assert!(exploration.candidates_attempted > 0);
}

/// A wall-clock limit stops exploration and is reported as an incomplete run,
/// never as a converged one.
#[test]
fn a_time_limit_is_reported_as_incomplete() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        candidate_budget: 100_000,
        // Short enough that the first mutation round cannot finish inside it.
        time_limit: Duration::from_millis(1),
        ..ExploreSettings::default()
    };
    let (_, exploration) = run(NESTED, &settings, 200);
    assert!(
        matches!(exploration.termination, Termination::TimeLimit { .. }),
        "expected a time-limit termination, got {:?}",
        exploration.termination
    );
    assert!(!exploration.complete());
    assert!(exploration
        .incompleteness()
        .expect("a curtailed run explains itself")
        .contains("wall-clock"));
    // The budget is still reported, so the gap between asked and done is
    // visible rather than inferred.
    assert_eq!(exploration.candidate_budget, 100_000);
    assert!(exploration.candidates_attempted < 100_000);
}

/// Exploration records the feedback mechanism and granularity it actually used,
/// so a report cannot imply edge or comparison coverage.
#[test]
fn the_reported_granularity_is_regions() {
    if llvm_tools().is_none() {
        return;
    }
    let settings = ExploreSettings {
        candidate_budget: 64,
        ..ExploreSettings::default()
    };
    let (_, exploration) = run(NESTED, &settings, 200);
    assert_eq!(exploration.feedback, "llvm-regions");
    assert!(exploration.granularity.contains("region"));
    assert!(
        exploration.granularity.contains("branch")
            && exploration.granularity.contains("unavailable"),
        "the granularity must name what is NOT available: {}",
        exploration.granularity
    );
    assert!(!exploration.coverage_map.id.is_empty());
    assert!(exploration.coverage_map.target_records >= 1);
    assert!(exploration.scope.ends_with("crypto-library"));
}
