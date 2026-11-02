//! Outcome vocabulary shared by every analysis backend.
//!
//! Backends observe different *kinds* of fact — a WASM instruction offset and a
//! Memcheck undefined-value diagnostic are not interchangeable — so evidence
//! types stay backend-specific. What is shared is the conclusion drawn, the
//! provenance recorded, and the mapping from outcome to a CI exit code.
//!
//! This is the seam an M3 `assert_constant_time!` macro would use: it needs the
//! verdict and the findings, not the backend's internal representation.

use std::fmt;

use serde::Serialize;

/// Strength of evidence a backend can produce. Recorded with every result so a
/// stored report cannot be read as stronger than it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Two specific inputs produced different observable behavior. Says nothing
    /// about untested inputs.
    DifferentialTrace,
    /// On the executed path, a secret-derived value reached a branch or an
    /// address. Finds violations from one run, but only on paths reached.
    DynamicSecretDependency,
    /// A property over all inputs, under an explicitly stated model.
    StaticAnalysis,
    /// A relational symbolic search over a declared input domain: either a
    /// counterexample, or completed coverage of that domain under the model.
    BoundedRelationalSymbolic,
}

impl Evidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Evidence::DifferentialTrace => "differential_trace",
            Evidence::DynamicSecretDependency => "dynamic_secret_dependency",
            Evidence::StaticAnalysis => "static_analysis",
            Evidence::BoundedRelationalSymbolic => "bounded_relational_symbolic",
        }
    }
}

/// The security conclusion for one analysis.
///
/// `NoLeakObserved` is named for what was observed rather than what might be
/// concluded; it is never proof of constant-time behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Outcome {
    #[serde(rename = "LEAK_DETECTED")]
    LeakDetected,
    /// A dynamic check observed no leak on the paths it executed. Produced by
    /// the Memcheck backend only.
    #[serde(rename = "NO_LEAK_OBSERVED")]
    NoLeakObserved,
    /// A symbolic exploration completed and discharged every relational
    /// obligation within a declared input domain and bounds.
    ///
    /// Deliberately a separate variant from [`Outcome::NoLeakObserved`]: a
    /// sampled dynamic run and a completed bounded search are different claims
    /// and must not share a name.
    #[serde(rename = "VERIFIED_BOUNDED")]
    VerifiedBounded,
    #[serde(rename = "INCONCLUSIVE")]
    Inconclusive,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::LeakDetected => "LEAK_DETECTED",
            Outcome::NoLeakObserved => "NO_LEAK_OBSERVED",
            Outcome::VerifiedBounded => "VERIFIED_BOUNDED",
            Outcome::Inconclusive => "INCONCLUSIVE",
        }
    }

    pub fn parse(text: &str) -> Option<Outcome> {
        match text {
            "LEAK_DETECTED" => Some(Outcome::LeakDetected),
            "NO_LEAK_OBSERVED" => Some(Outcome::NoLeakObserved),
            "VERIFIED_BOUNDED" => Some(Outcome::VerifiedBounded),
            "INCONCLUSIVE" => Some(Outcome::Inconclusive),
            _ => None,
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Toolchain and artifact provenance. A result is a claim about one specific
/// binary built one specific way, so reinterpreting a stored report later
/// requires all of this.
#[derive(Debug, Clone, Serialize)]
pub struct Provenance {
    pub rustc_version: String,
    pub cargo_version: String,
    /// Analysis tool and version, e.g. `valgrind 3.28.0` or `wabt 1.0.42`.
    pub analyzer: String,
    pub target: String,
    pub profile: String,
    pub artifact_path: String,
    pub artifact_sha256: String,
}

/// How an observed outcome relates to what a fixture declared.
///
/// This distinction matters for CI: a test asserting that a *vulnerable*
/// implementation is detected must pass when the analyzer correctly finds the
/// vulnerability. The security result of the example and the pass/fail of the
/// regression test are not the same thing.
#[derive(Debug, Clone, Serialize)]
pub struct Expectation {
    pub expected: Outcome,
    pub observed: Outcome,
    pub met: bool,
}

impl Expectation {
    pub fn new(expected: Outcome, observed: Outcome) -> Self {
        Expectation {
            expected,
            observed,
            met: expected == observed,
        }
    }
}

/// Exit codes shared across subcommands, so a difference is never confused
/// with a harness failure.
pub const EXIT_OK: u8 = 0;
pub const EXIT_FINDING: u8 = 1;
pub const EXIT_ERROR: u8 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    /// Outcome names round-trip, so stored reports stay readable.
    #[test]
    fn outcome_names_round_trip() {
        for outcome in [
            Outcome::LeakDetected,
            Outcome::NoLeakObserved,
            Outcome::VerifiedBounded,
            Outcome::Inconclusive,
        ] {
            assert_eq!(Outcome::parse(outcome.as_str()), Some(outcome));
        }
    }

    /// An unrecognized outcome name is rejected rather than defaulted.
    #[test]
    fn unknown_outcome_name_is_rejected() {
        assert_eq!(Outcome::parse("SECURE"), None);
        assert_eq!(Outcome::parse(""), None);
    }

    /// Outcomes serialize to the documented screaming-snake vocabulary.
    #[test]
    fn outcome_serializes_to_the_public_vocabulary() {
        let json = serde_json::to_string(&Outcome::NoLeakObserved).unwrap();
        assert_eq!(json, "\"NO_LEAK_OBSERVED\"");
    }

    /// An expectation is met only when observed equals expected, so detecting a
    /// known vulnerability counts as a passing regression test.
    #[test]
    fn detecting_a_declared_leak_meets_the_expectation() {
        let met = Expectation::new(Outcome::LeakDetected, Outcome::LeakDetected);
        assert!(met.met);
        let unmet = Expectation::new(Outcome::LeakDetected, Outcome::NoLeakObserved);
        assert!(!unmet.met);
    }

    /// A completed symbolic exploration keeps a name of its own: it must never
    /// be confused with a sampled dynamic result.
    #[test]
    fn verified_bounded_is_distinct_from_no_leak_observed() {
        assert_ne!(Outcome::VerifiedBounded, Outcome::NoLeakObserved);
        assert_eq!(
            serde_json::to_string(&Outcome::VerifiedBounded).unwrap(),
            "\"VERIFIED_BOUNDED\""
        );
        assert!(!Expectation::new(Outcome::VerifiedBounded, Outcome::NoLeakObserved).met);
        assert!(!Expectation::new(Outcome::NoLeakObserved, Outcome::VerifiedBounded).met);
    }

    /// Inconclusive never satisfies an expectation of either definite outcome.
    #[test]
    fn inconclusive_does_not_meet_a_definite_expectation() {
        assert!(!Expectation::new(Outcome::NoLeakObserved, Outcome::Inconclusive).met);
        assert!(!Expectation::new(Outcome::LeakDetected, Outcome::Inconclusive).met);
        assert!(!Expectation::new(Outcome::VerifiedBounded, Outcome::Inconclusive).met);
    }
}
