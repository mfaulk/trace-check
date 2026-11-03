//! What M6's generator can and cannot reach, measured rather than asserted.
//!
//! These tests pin the *premise* of M7: that the hidden-path fixtures in
//! `examples/crypto-library/src/hidden.rs` are out of reach of boundary and
//! pairwise generation at any budget, and effectively out of reach of seeded
//! random generation at a realistic one.
//!
//! They are deliberately pure generator tests — no Valgrind, no build — so the
//! baseline claim is cheap to re-check whenever the generator changes. If a
//! future generator improvement reaches these paths, these tests fail and the
//! M7 benchmark comparison has to be restated instead of silently becoming
//! false.

use trace_check::contract::Descriptor;
use trace_check::generate::{self, GenerateSettings, Strategy, Value};

/// `crypto::hidden::nested_modes(index: u8, stage: u8, gate: u8, trigger: u8)`.
const NESTED_MODES: &str = r#"{"schema_version":1,"function":"nested_modes","parameters":[
    {"name":"index","position":0,"role":"secret","repr":"u8","rust_type":"u8"},
    {"name":"stage","position":1,"role":"public","repr":"u8","rust_type":"u8"},
    {"name":"gate","position":2,"role":"public","repr":"u8","rust_type":"u8"},
    {"name":"trigger","position":3,"role":"public","repr":"u8","rust_type":"u8"}],
    "returns":{"repr":"u8","rust_type":"u8"}}"#;

/// `crypto::hidden::threshold_window(index: u8, level: u32)`.
const THRESHOLD_WINDOW: &str = r#"{"schema_version":1,"function":"threshold_window","parameters":[
    {"name":"index","position":0,"role":"secret","repr":"u8","rust_type":"u8"},
    {"name":"level","position":1,"role":"public","repr":"u32","rust_type":"u32"}],
    "returns":{"repr":"u8","rust_type":"u8"}}"#;

/// `crypto::hidden::magic_gate(index: u8, token: u32)`.
const MAGIC_GATE: &str = r#"{"schema_version":1,"function":"magic_gate","parameters":[
    {"name":"index","position":0,"role":"secret","repr":"u8","rust_type":"u8"},
    {"name":"token","position":1,"role":"public","repr":"u32","rust_type":"u32"}],
    "returns":{"repr":"u8","rust_type":"u8"}}"#;

fn descriptor(json: &str) -> Descriptor {
    Descriptor::parse(json).expect("the fixture descriptor parses")
}

fn scalar(case: &[(String, Value)], name: &str) -> u64 {
    match case
        .iter()
        .find(|(parameter, _)| parameter == name)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("`{name}` is a parameter of this fixture"))
    {
        Value::Scalar { value, .. } => *value,
        other => panic!("`{name}` is a scalar, got {other:?}"),
    }
}

/// The predicate guarding `nested_modes`' secret-indexed load.
fn reaches_nested_leak(case: &[(String, Value)]) -> bool {
    scalar(case, "stage") & 0x0f == 0x0a
        && scalar(case, "gate") & 0xf0 == 0x30
        && scalar(case, "trigger") == 0x5a
}

/// The predicate guarding `threshold_window`'s secret-indexed load.
fn reaches_threshold_leak(case: &[(String, Value)]) -> bool {
    let level = scalar(case, "level") as u32;
    level >= 0x1000_0000 && level - 0x1000_0000 < 64
}

fn settings(cases: usize, strategies: Vec<Strategy>) -> GenerateSettings {
    GenerateSettings {
        cases,
        strategies,
        ..GenerateSettings::default()
    }
}

/// Two of `nested_modes`' three required public values are not boundary values
/// of a `u8`, so no amount of boundary generation produces them.
#[test]
fn the_nested_fixture_needs_values_that_are_not_boundaries() {
    let corpus = generate::generate(
        "crypto::hidden::nested_modes",
        &descriptor(NESTED_MODES),
        &settings(4096, vec![Strategy::Boundaries]),
    )
    .expect("generation succeeds");

    let stages: Vec<u64> = corpus
        .cases
        .iter()
        .map(|case| scalar(&case.inputs, "stage"))
        .collect();
    assert!(
        !stages.iter().any(|stage| stage & 0x0f == 0x0a),
        "no u8 boundary value has low nibble 0xa; the fixture depends on that"
    );
    let triggers: Vec<u64> = corpus
        .cases
        .iter()
        .map(|case| scalar(&case.inputs, "trigger"))
        .collect();
    assert!(
        !triggers.contains(&0x5a),
        "0x5a is not a u8 boundary value; the fixture depends on that"
    );
}

/// Boundary and pairwise generation move at most two parameters away from base,
/// so they cannot satisfy a three-parameter conjunction at any budget.
#[test]
fn boundaries_and_pairwise_cannot_reach_the_nested_leak_at_any_budget() {
    // 85 is this fixture's boundary floor: four `u8`s with 22 boundary values
    // each. A smaller budget is refused rather than silently skipping them.
    for cases in [85, 200, 2_000, 8_192] {
        let corpus = generate::generate(
            "crypto::hidden::nested_modes",
            &descriptor(NESTED_MODES),
            &settings(cases, vec![Strategy::Boundaries, Strategy::Pairwise]),
        )
        .expect("generation succeeds");
        assert!(
            !corpus
                .cases
                .iter()
                .any(|case| reaches_nested_leak(&case.inputs)),
            "a boundaries+pairwise corpus of {cases} cases reached the nested leak; the M7 \
             benchmark premise no longer holds and has to be restated"
        );
    }
}

/// M6's default generation — boundaries, pairwise, then random fill — does not
/// reach the nested leak at a budget twenty times its default.
#[test]
fn m6_default_generation_does_not_reach_the_nested_leak() {
    for seed in [generate::DEFAULT_SEED, 1, 12_345, 0xdead_beef] {
        let corpus = generate::generate(
            "crypto::hidden::nested_modes",
            &descriptor(NESTED_MODES),
            &GenerateSettings {
                cases: 1_280,
                seed,
                ..GenerateSettings::default()
            },
        )
        .expect("generation succeeds");
        assert!(
            !corpus
                .cases
                .iter()
                .any(|case| reaches_nested_leak(&case.inputs)),
            "seed {seed} reached the nested leak under M6 default generation"
        );
    }
}

/// Even an all-random budget of 2000 cases misses the nested leak for every
/// seed tried: the conjunction has probability about 2⁻¹⁶ per case.
#[test]
fn a_large_random_budget_does_not_reliably_reach_the_nested_leak() {
    let mut reached = 0;
    let seeds = [generate::DEFAULT_SEED, 1, 2, 3, 12_345, 0xdead_beef];
    for seed in seeds {
        let corpus = generate::generate(
            "crypto::hidden::nested_modes",
            &descriptor(NESTED_MODES),
            &GenerateSettings {
                cases: 2_000,
                seed,
                strategies: vec![Strategy::Random],
                ..GenerateSettings::default()
            },
        )
        .expect("generation succeeds");
        if corpus
            .cases
            .iter()
            .any(|case| reaches_nested_leak(&case.inputs))
        {
            reached += 1;
        }
    }
    assert!(
        reached * 2 < seeds.len(),
        "{reached} of {} random seeds reached the nested leak, which is more reliable than the \
         benchmark premise allows",
        seeds.len()
    );
}

/// The magic-constant fixture is unreachable by every M6 strategy: an exact
/// 32-bit token is neither a boundary value nor a plausible random draw.
#[test]
fn no_m6_strategy_reaches_the_magic_token() {
    let corpus = generate::generate(
        "crypto::hidden::magic_gate",
        &descriptor(MAGIC_GATE),
        &settings(
            4_096,
            vec![Strategy::Boundaries, Strategy::Pairwise, Strategy::Random],
        ),
    )
    .expect("generation succeeds");
    assert!(
        !corpus
            .cases
            .iter()
            .any(|case| scalar(&case.inputs, "token") == 0x5a17_c0de),
        "the magic token was generated, so the comparison-guidance diagnostic is void"
    );
}

/// The threshold fixture *is* reached by boundary generation, because its
/// threshold is a power of two. M7 must not lose this.
#[test]
fn boundaries_do_reach_the_threshold_window() {
    let corpus = generate::generate(
        "crypto::hidden::threshold_window",
        &descriptor(THRESHOLD_WINDOW),
        &settings(512, vec![Strategy::Boundaries]),
    )
    .expect("generation succeeds");
    assert!(
        corpus
            .cases
            .iter()
            .any(|case| reaches_threshold_leak(&case.inputs)),
        "boundary generation is supposed to reach the threshold window; the fixture or the \
         generator changed"
    );
}
