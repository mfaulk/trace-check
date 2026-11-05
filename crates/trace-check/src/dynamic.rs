//! Developer-written `#[ct_test]`s as enforcement evidence.
//!
//! M3 already runs these tests under Memcheck and already proves, per test,
//! that the declared contract's function was invoked through the instrumented
//! adapter. What it did not do is bind them to the compiler-derived inventory
//! and aggregate them into one answer per contract, which is what a `dynamic`
//! policy requirement needs.
//!
//! Discovery and execution stay in the CLI, where the test binaries and the
//! Valgrind processes live. This module owns the part that decides whether a
//! requirement is discharged: binding, validation and aggregation.
//!
//! # A test that ran is not evidence about a contract
//!
//! A passing test proves nothing about `crypto::tag::verify_tag` unless it
//! actually called it with the declared secret marked. M3's `#[ct_test]`
//! harness already asserts this and *fails* a test that declared a target it
//! never invoked, so such a test arrives here as one that did not complete.
//!
//! [`DynamicTestRun::invoked_target`] is checked anyway, for the same reason
//! the other backends' completion evidence is re-checked at this boundary: the
//! policy layer reads an outcome, and a run whose own record says it never
//! reached the contract must not be able to discharge an obligation about it
//! however that came to be.
//!
//! # Aggregation is deterministic and fail-closed
//!
//! Several tests may cover one contract. The rules, in order:
//!
//! 1. a detected leak is preserved, whatever else passed;
//! 2. a test whose controls did not fire, that never reached its target, or
//!    that did not complete, prevents a clean aggregate;
//! 3. a clean aggregate requires **every** bound test to have completed with
//!    valid controls and a confirmed invocation;
//! 4. the same test executed twice counts once;
//! 5. a contract with no bound test is not analyzed — never clean.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::inventory::ContractInventory;
use crate::security::Outcome;

/// One `#[ct_test]` execution, as the enforcement layer needs it.
///
/// Deliberately a small value rather than M3's whole `TestOutcome`: this
/// crosses a crate boundary, and the fields here are the ones a decision
/// depends on. Everything else stays in the CLI's own report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DynamicTestRun {
    /// Harness path of the test, which is also what `--exact` accepts.
    pub test: String,
    /// The contract the test declares it covers, verbatim from the annotation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_target: Option<String>,
    pub executable: String,
    pub executable_sha256: String,
    pub outcome: Outcome,
    /// Whether the positive control fired, proving secret marking reaches
    /// compiled code in this binary.
    pub calibrated: bool,
    /// Whether the declared contract's function was proven to have been
    /// invoked through the instrumented adapter.
    pub invoked_target: bool,
    /// Whether the test process ran to completion, as opposed to being killed
    /// or timing out.
    pub completed: bool,
    pub message: String,
    /// Secret-dependency findings, retained rather than counted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
}

impl DynamicTestRun {
    /// Why this run is not usable evidence for its contract, if it is not.
    ///
    /// A detected leak is excluded from this: a finding is positive evidence
    /// and the questions here are all about whether a *clean* result was
    /// earned.
    fn unusable(&self) -> Option<String> {
        if !self.completed {
            // The test's own message is carried through: M3 diagnoses *why* it
            // did not complete -- a failed assertion, a timeout, a target it
            // declared and never invoked -- and that is the actionable part.
            return Some(format!(
                "`{}` did not run to completion, so its result describes a partial execution: {}",
                self.test, self.message
            ));
        }
        if !self.calibrated {
            return Some(format!(
                "`{}` produced no positive control, so secret marking is not reaching compiled \
                 code and a clean result would establish nothing",
                self.test
            ));
        }
        if !self.invoked_target {
            return Some(format!(
                "`{}` never invoked the contract through the instrumented adapter, so it \
                 establishes nothing about it however cleanly it passed",
                self.test
            ));
        }
        if self.outcome != Outcome::NoLeakObserved {
            return Some(format!(
                "`{}` produced {}: {}",
                self.test, self.outcome, self.message
            ));
        }
        None
    }
}

/// What a contract's `dynamic` obligation rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DynamicEvidence {
    /// Every bound test, de-duplicated, in a deterministic order.
    pub tests: Vec<DynamicTestRun>,
    /// The aggregate, and why it is what it is.
    pub outcome: Outcome,
    pub detail: String,
    /// Executables the bound tests live in, so a composite artifact hash can
    /// be read back to the binaries it covers.
    pub executables: Vec<String>,
}

/// How tests map onto the inventory's contracts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Binding {
    /// Contract identity to the tests bound to it.
    pub per_contract: BTreeMap<String, Vec<DynamicTestRun>>,
    /// Tests whose declared target names no contract in this build, or more
    /// than one.
    ///
    /// Reported rather than ignored, and bound to nothing: a test claiming
    /// coverage of a contract that does not exist claims coverage of nothing,
    /// and one that could mean either of two contracts cannot be resolved by
    /// guessing. The usual causes are a typo, a feature-gated contract, and a
    /// target shortened past the point of uniqueness.
    pub unresolved: Vec<String>,
    /// Tests declaring no target at all. They run under `test` and cannot
    /// discharge a contract-specific obligation.
    pub untargeted: Vec<String>,
}

/// Whether a test's declared target names this contract.
///
/// `#[ct_test(target = "...")]` is written module-relative — `tag::verify_tag`
/// for `crypto::tag::verify_tag` — because a developer should not have to spell
/// their own crate name. So a target matches when it is a suffix of the
/// qualified identity **ending at a path boundary**: `verify_tag` and
/// `tag::verify_tag` both match `crypto::tag::verify_tag`, and `ify_tag` does
/// not.
///
/// This is M3's rule, and the one implementation of it. Substring matching
/// would let `verify` claim `verify_tag`; requiring the full identity would
/// break every existing annotation. Shortening a target past the point of
/// uniqueness is handled by rejecting the ambiguity rather than by guessing —
/// see [`bind`].
pub fn matches_target(declared: &str, contract_id: &str) -> bool {
    contract_id
        .strip_suffix(declared)
        .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with("::"))
}

/// Binds runs to the contracts the **compiler-derived inventory** declares.
///
/// Resolved against the inventory rather than against the test binaries' own
/// metadata, because the inventory is the authoritative set of applicable
/// declarations. The two are built differently — one from the library's rlib,
/// one from the test executables — and a target that resolves in one and not
/// the other must not quietly bind.
///
/// A target matching no contract, or more than one, binds to nothing and is
/// reported. The same test appearing twice is bound once: running a test again
/// does not make its evidence stronger, and a duplicate would inflate the count
/// a clean aggregate is judged over.
pub fn bind(runs: &[DynamicTestRun], inventory: &ContractInventory) -> Binding {
    let mut binding = Binding::default();
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for run in runs {
        let Some(target) = run.declared_target.as_deref() else {
            binding.untargeted.push(run.test.clone());
            continue;
        };
        let matched: Vec<&str> = inventory
            .contracts
            .iter()
            .map(|contract| contract.id.as_str())
            .filter(|id| matches_target(target, id))
            .collect();
        let contract = match matched.as_slice() {
            [one] => *one,
            [] => {
                binding.unresolved.push(format!(
                    "`{}` targets `{target}`, which this build declares no contract for",
                    run.test
                ));
                continue;
            }
            many => {
                binding.unresolved.push(format!(
                    "`{}` targets `{target}`, which is ambiguous between {}; use a longer path",
                    run.test,
                    many.join(" and ")
                ));
                continue;
            }
        };
        // Keyed on the test *and* its executable: the same harness path in two
        // executables is two tests, while the same test run twice is one.
        if !seen.insert((run.test.as_str(), run.executable_sha256.as_str())) {
            continue;
        }
        binding
            .per_contract
            .entry(contract.to_string())
            .or_default()
            .push(run.clone());
    }
    for tests in binding.per_contract.values_mut() {
        tests.sort_by(|left, right| {
            (&left.test, &left.executable_sha256).cmp(&(&right.test, &right.executable_sha256))
        });
    }
    binding.untargeted.sort();
    binding.unresolved.sort();
    binding
}

/// Aggregates one contract's bound tests into a single outcome.
///
/// Returns `None` when no test is bound, which is *not analyzed* rather than
/// clean. An empty set of tests is the absence of evidence.
pub fn aggregate(tests: &[DynamicTestRun]) -> Option<DynamicEvidence> {
    if tests.is_empty() {
        return None;
    }
    let mut executables: Vec<String> = tests
        .iter()
        .map(|run| run.executable_sha256.clone())
        .collect();
    executables.sort();
    executables.dedup();

    let leaking: Vec<&DynamicTestRun> = tests
        .iter()
        .filter(|run| run.outcome == Outcome::LeakDetected)
        .collect();
    // A leak first and unconditionally. Another test passing does not
    // un-discover it, and nothing below may overwrite it.
    if !leaking.is_empty() {
        let detail = format!(
            "{} of {} bound test(s) detected a secret-dependent leak: {}",
            leaking.len(),
            tests.len(),
            leaking
                .iter()
                .map(|run| format!("`{}`: {}", run.test, run.message))
                .collect::<Vec<_>>()
                .join("; ")
        );
        return Some(DynamicEvidence {
            tests: tests.to_vec(),
            outcome: Outcome::LeakDetected,
            detail,
            executables,
        });
    }

    let unusable: Vec<String> = tests.iter().filter_map(|run| run.unusable()).collect();
    if !unusable.is_empty() {
        return Some(DynamicEvidence {
            tests: tests.to_vec(),
            outcome: Outcome::Inconclusive,
            detail: format!(
                "a clean aggregate requires every bound test to complete with valid controls and \
                 a confirmed invocation, and {} of {} did not: {}",
                unusable.len(),
                tests.len(),
                unusable.join("; ")
            ),
            executables,
        });
    }

    let detail = format!(
        "{} bound test(s) completed with calibration confirmed and the contract provably \
         invoked, and none observed a secret-dependent branch or address: {}. This is \
         NO_LEAK_OBSERVED over the inputs those tests chose, not a proof",
        tests.len(),
        tests
            .iter()
            .map(|run| format!("`{}`", run.test))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Some(DynamicEvidence {
        tests: tests.to_vec(),
        outcome: Outcome::NoLeakObserved,
        detail,
        executables,
    })
}

/// The artifact hash a dynamic result describes.
///
/// For one test executable, that executable. For several — two `#[ct_test]`s
/// for one contract in different integration test targets — a digest over
/// their sorted hashes, with each named in
/// [`DynamicEvidence::executables`] so the composite can be read back to the
/// binaries it covers.
///
/// Composite rather than "the first one": a result drawn from two executables
/// is about both, and naming one of them would be a claim about an artifact
/// that produced only part of the evidence.
pub fn artifact_sha256(executables: &[String]) -> String {
    match executables {
        [only] => only.clone(),
        many => format!("{:x}", Sha256::digest(many.join("\n").as_bytes())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(test: &str, target: Option<&str>, outcome: Outcome) -> DynamicTestRun {
        DynamicTestRun {
            test: test.to_string(),
            declared_target: target.map(str::to_string),
            executable: "/t/tests-abc".to_string(),
            executable_sha256: "exec0".to_string(),
            outcome,
            calibrated: true,
            invoked_target: true,
            completed: true,
            message: "message".to_string(),
            findings: Vec::new(),
        }
    }

    fn inventory() -> ContractInventory {
        crate::enforcement::test_support::inventory(&[
            "crypto::tag::verify_tag",
            "crypto::a::probe",
        ])
    }

    /// A target is a path-boundary suffix of the contract identity, so a
    /// module-relative declaration binds and a partial path component does not.
    #[test]
    fn a_target_matches_at_path_boundaries_only() {
        assert!(matches_target("verify_tag", "crypto::tag::verify_tag"));
        assert!(matches_target("tag::verify_tag", "crypto::tag::verify_tag"));
        assert!(matches_target(
            "crypto::tag::verify_tag",
            "crypto::tag::verify_tag"
        ));
        // Mid-component, so not a contract path.
        assert!(!matches_target("ify_tag", "crypto::tag::verify_tag"));
        // A different function whose name is a prefix of this one.
        assert!(!matches_target("verify", "crypto::tag::verify_tag"));
    }

    /// Binding resolves module-relative targets against the inventory, and a
    /// target naming no contract is reported rather than silently dropped.
    #[test]
    fn tests_bind_to_inventoried_contracts() {
        let runs = vec![
            run(
                "tag::clean",
                Some("tag::verify_tag"),
                Outcome::NoLeakObserved,
            ),
            // Names a function this build does not declare a contract for.
            run("tag::absent", Some("tag::verify"), Outcome::NoLeakObserved),
            run("no_target", None, Outcome::NoLeakObserved),
        ];
        let binding = bind(&runs, &inventory());
        assert_eq!(binding.per_contract.len(), 1);
        assert_eq!(
            binding.per_contract["crypto::tag::verify_tag"]
                .iter()
                .map(|r| r.test.as_str())
                .collect::<Vec<_>>(),
            vec!["tag::clean"]
        );
        assert_eq!(binding.untargeted, vec!["no_target".to_string()]);
        assert_eq!(binding.unresolved.len(), 1);
        assert!(
            binding.unresolved[0].contains("declares no contract"),
            "{:?}",
            binding.unresolved
        );
    }

    /// An ambiguous target binds to nothing. Two modules may each define
    /// `probe`, and guessing which was meant would attribute a test's evidence
    /// to a function it may never have called.
    #[test]
    fn an_ambiguous_target_binds_to_nothing() {
        let found = crate::enforcement::test_support::inventory(&[
            "crypto::left::probe",
            "crypto::right::probe",
        ]);
        let binding = bind(
            &[run("ambiguous", Some("probe"), Outcome::NoLeakObserved)],
            &found,
        );
        assert!(binding.per_contract.is_empty());
        assert_eq!(binding.unresolved.len(), 1);
        assert!(
            binding.unresolved[0].contains("ambiguous between"),
            "{:?}",
            binding.unresolved
        );
        // A longer path resolves it.
        let binding = bind(
            &[run(
                "explicit",
                Some("left::probe"),
                Outcome::NoLeakObserved,
            )],
            &found,
        );
        assert_eq!(binding.per_contract.len(), 1);
        assert!(binding.per_contract.contains_key("crypto::left::probe"));
    }

    /// The same test executed twice is bound once, so a duplicate cannot
    /// inflate the count a clean aggregate is judged over.
    #[test]
    fn a_duplicate_execution_counts_once() {
        let once = run(
            "tag::clean",
            Some("tag::verify_tag"),
            Outcome::NoLeakObserved,
        );
        let binding = bind(&[once.clone(), once.clone(), once], &inventory());
        assert_eq!(binding.per_contract["crypto::tag::verify_tag"].len(), 1);
    }

    /// A contract with no bound test has no evidence, which is not a clean
    /// result.
    #[test]
    fn no_bound_test_is_no_evidence() {
        assert_eq!(aggregate(&[]), None);
    }

    /// A clean aggregate needs every bound test to have completed with valid
    /// controls and a confirmed invocation.
    #[test]
    fn a_clean_aggregate_requires_every_test_to_qualify() {
        let clean = run("a", Some("c"), Outcome::NoLeakObserved);
        assert_eq!(
            aggregate(std::slice::from_ref(&clean))
                .expect("evidence")
                .outcome,
            Outcome::NoLeakObserved
        );

        // Never reached its target: it establishes nothing about the contract.
        let mut uninvoked = clean.clone();
        uninvoked.test = "b".to_string();
        uninvoked.invoked_target = false;
        let evidence = aggregate(&[clean.clone(), uninvoked]).expect("evidence");
        assert_eq!(evidence.outcome, Outcome::Inconclusive);
        assert!(
            evidence.detail.contains("never invoked"),
            "{}",
            evidence.detail
        );

        // Controls did not fire.
        let mut uncalibrated = clean.clone();
        uncalibrated.test = "c".to_string();
        uncalibrated.calibrated = false;
        let evidence = aggregate(&[clean.clone(), uncalibrated]).expect("evidence");
        assert_eq!(evidence.outcome, Outcome::Inconclusive);
        assert!(
            evidence.detail.contains("positive control"),
            "{}",
            evidence.detail
        );

        // Killed or timed out.
        let mut truncated = clean.clone();
        truncated.test = "d".to_string();
        truncated.completed = false;
        let evidence = aggregate(&[clean, truncated]).expect("evidence");
        assert_eq!(evidence.outcome, Outcome::Inconclusive);
        assert!(
            evidence.detail.contains("completion"),
            "{}",
            evidence.detail
        );
    }

    /// One test detecting a leak while another passes is a leak, and the
    /// finding is preserved in the detail.
    #[test]
    fn a_leak_from_one_test_outranks_another_passing() {
        let clean = run("clean", Some("c"), Outcome::NoLeakObserved);
        let mut leaking = run("leaking", Some("c"), Outcome::LeakDetected);
        leaking.message = "secret-dependent branch at tag.rs:55".to_string();
        let evidence = aggregate(&[clean, leaking]).expect("evidence");
        assert_eq!(evidence.outcome, Outcome::LeakDetected);
        assert!(evidence.detail.contains("tag.rs:55"), "{}", evidence.detail);
        assert_eq!(evidence.tests.len(), 2, "both tests are retained");
    }

    /// A leak outranks an unusable control too: nothing un-discovers a finding.
    #[test]
    fn a_leak_outranks_a_failed_control() {
        let mut leaking = run("leaking", Some("c"), Outcome::LeakDetected);
        leaking.calibrated = false;
        let evidence = aggregate(&[leaking]).expect("evidence");
        assert_eq!(evidence.outcome, Outcome::LeakDetected);
    }

    /// One executable is named directly; several become a composite digest
    /// whose parts are listed.
    #[test]
    fn the_artifact_hash_names_what_it_covers() {
        assert_eq!(artifact_sha256(&["exec0".to_string()]), "exec0");
        let composite = artifact_sha256(&["exec0".to_string(), "exec1".to_string()]);
        assert_eq!(composite.len(), 64);
        assert_ne!(composite, "exec0");
        // Deterministic, so two runs of the same tests compare equal.
        assert_eq!(
            composite,
            artifact_sha256(&["exec0".to_string(), "exec1".to_string()])
        );
    }
}
