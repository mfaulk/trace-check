//! Persisted reproducers: the input that exposed a leak, written down so it can
//! be replayed.
//!
//! # Why a sequence and not a single case
//!
//! Most findings pin to one input, and the schema says so. Some do not: a leak
//! that depends on earlier cases in a batch is real, and refusing to record it
//! because it will not isolate would discard a true finding. So a reproducer
//! carries an ordered *list* of cases, usually of length one.
//!
//! # What a replay can and cannot promise
//!
//! A reproducer names the artifact hash it was found against. Replaying it
//! after any change to the library, its dependencies or the compiler builds a
//! *different* artifact, and whether the finding survives that is exactly the
//! question being asked — so the mismatch is recorded in the result rather than
//! treated as an error or hidden.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::check::{Finding, Fingerprint, Isolation};
use crate::generate::{Corpus, Value};
use crate::harness::Library;
use crate::memcheck::Classification;

/// Reproducer schema this build writes and understands.
pub const REPRODUCER_SCHEMA_VERSION: u32 = 1;

/// The finding a reproducer is for, in the fingerprint's terms.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecordedFinding {
    pub classification: Classification,
    /// The frame the finding was attributed to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// `file:line` of that frame, when debug info supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// `file:line` in the developer's own source, when the contract's frame
    /// carried one. The field to read; `location` is the matching identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

impl RecordedFinding {
    fn from_finding(finding: &Finding) -> RecordedFinding {
        RecordedFinding {
            classification: finding.fingerprint.classification,
            function: finding.fingerprint.function.clone(),
            location: finding.fingerprint.location.clone(),
            site: finding.site.clone(),
        }
    }

    pub fn to_fingerprint(&self) -> Fingerprint {
        Fingerprint {
            classification: self.classification,
            function: self.function.clone(),
            location: self.location.clone(),
        }
    }
}

/// The build a reproducer was found against.
///
/// Recorded because a dynamic result describes one artifact. A replay that
/// builds a different one is still useful — it answers whether the leak
/// survived the change — but it must not be presented as the same observation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecordedArtifact {
    pub sha256: String,
    pub profile: String,
    pub library_package: String,
    pub library_version: String,
}

/// One case of a reproducer: a value per declared parameter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecordedCase {
    /// Id in the corpus this was found in, for cross-referencing a report.
    pub id: usize,
    pub inputs: Vec<(String, Value)>,
}

/// A persisted failure.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reproducer {
    pub schema_version: u32,
    pub contract: String,
    /// Seed and corpus hash of the run that found it, so the whole run can be
    /// repeated rather than just the one case.
    pub seed: u64,
    pub corpus_sha256: String,
    /// Ordered cases that reproduce the finding. One for an isolated finding,
    /// the whole batch for a sequence-dependent one.
    pub cases: Vec<RecordedCase>,
    /// Whether the finding needed the whole sequence.
    pub sequence_dependent: bool,
    pub finding: RecordedFinding,
    pub artifact: RecordedArtifact,
}

impl Reproducer {
    /// Builds a reproducer from a finding, preferring the shrunk input.
    ///
    /// The shrunk input is the one a developer should see first; the original is
    /// recoverable from the seed and corpus hash, which are both recorded.
    pub fn from_finding(
        contract: &str,
        corpus: &Corpus,
        finding: &Finding,
        library: &Library,
        artifact_sha256: &str,
        profile: &str,
    ) -> Reproducer {
        let sequence_dependent = matches!(finding.isolation, Isolation::Sequence { .. });
        let cases: Vec<RecordedCase> = match (&finding.shrunk, &finding.isolation) {
            // A shrunk input replaces the isolated case's values, keeping its id
            // so a report can still be cross-referenced.
            (Some(shrunk), Isolation::Case { id, .. } | Isolation::Single { id }) => {
                vec![RecordedCase {
                    id: *id,
                    inputs: shrunk.inputs.clone(),
                }]
            }
            _ => finding
                .isolation
                .ids()
                .into_iter()
                .filter_map(|id| {
                    corpus.case(id).map(|case| RecordedCase {
                        id,
                        inputs: case.inputs.clone(),
                    })
                })
                .collect(),
        };
        Reproducer {
            schema_version: REPRODUCER_SCHEMA_VERSION,
            contract: contract.to_string(),
            seed: corpus.seed,
            corpus_sha256: corpus.sha256(),
            cases,
            sequence_dependent,
            finding: RecordedFinding::from_finding(finding),
            artifact: RecordedArtifact {
                sha256: artifact_sha256.to_string(),
                profile: profile.to_string(),
                library_package: library.package.clone(),
                library_version: library.version.clone(),
            },
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a reproducer is serializable")
    }

    pub fn load(path: &Path) -> Result<Reproducer, ReproducerError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ReproducerError::Io(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Reproducer, ReproducerError> {
        let reproducer: Reproducer =
            serde_json::from_str(text).map_err(|e| ReproducerError::Malformed(e.to_string()))?;
        if reproducer.schema_version != REPRODUCER_SCHEMA_VERSION {
            return Err(ReproducerError::UnsupportedSchema {
                found: reproducer.schema_version,
                supported: REPRODUCER_SCHEMA_VERSION,
            });
        }
        if reproducer.cases.is_empty() {
            return Err(ReproducerError::Malformed(
                "it records no cases, so there is nothing to replay".to_string(),
            ));
        }
        for case in &reproducer.cases {
            if case.inputs.is_empty() {
                return Err(ReproducerError::Malformed(format!(
                    "case {} records no inputs",
                    case.id
                )));
            }
        }
        Ok(reproducer)
    }

    pub fn save(&self, path: &Path) -> Result<(), ReproducerError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| ReproducerError::Io(format!("{}: {e}", parent.display())))?;
            }
        }
        std::fs::write(path, format!("{}\n", self.to_json()))
            .map_err(|e| ReproducerError::Io(format!("{}: {e}", path.display())))
    }

    /// The cases as the generator's replay input, so a replay goes through the
    /// same validation a generated case does.
    pub fn as_regressions(&self) -> Vec<Vec<(String, Value)>> {
        self.cases.iter().map(|case| case.inputs.clone()).collect()
    }

    /// A one-line summary for a report.
    pub fn describe(&self) -> String {
        let inputs = self
            .cases
            .iter()
            .map(|case| {
                case.inputs
                    .iter()
                    .map(|(name, value)| format!("{name}={}", value.describe()))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .collect::<Vec<_>>()
            .join(" then ");
        if self.sequence_dependent {
            format!("{} case sequence: {inputs}", self.cases.len())
        } else {
            inputs
        }
    }
}

/// What a replay established.
///
/// Three values, not two. "The finding did not appear" and "the analysis could
/// not tell" are different facts, and collapsing them means an infrastructure
/// failure reads as a fixed vulnerability. Replay exists so a developer can ask
/// whether a change resolved a leak, which is exactly the question where that
/// confusion is most expensive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The recorded finding appeared again.
    Reproduced,
    /// A complete, instrumented, calibrated run established that the recorded
    /// finding is absent.
    NotReproduced,
    /// The run did not establish either. Never a pass.
    Inconclusive,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Reproduced => "REPRODUCED",
            Verdict::NotReproduced => "NOT_REPRODUCED",
            Verdict::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// What a replay saw, and whether it was even the same build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayResult {
    pub contract: String,
    pub verdict: Verdict,
    /// Whether the artifact replayed against is the one recorded.
    pub same_artifact: bool,
    pub recorded_artifact_sha256: String,
    pub replayed_artifact_sha256: String,
    pub message: String,
}

impl ReplayResult {
    /// Builds the result from a verdict the caller established.
    ///
    /// The caller is responsible for only ever passing
    /// [`Verdict::NotReproduced`] when the run was complete, instrumented and
    /// calibrated; see `trace_check::replay_reproducer`.
    pub fn new(
        reproducer: &Reproducer,
        replayed_sha256: &str,
        verdict: Verdict,
        detail: Option<String>,
    ) -> ReplayResult {
        let same_artifact = reproducer.artifact.sha256 == replayed_sha256;
        let message = match (verdict, same_artifact) {
            (Verdict::Reproduced, true) => {
                "the recorded finding reproduced against the same artifact".to_string()
            }
            (Verdict::Reproduced, false) => {
                "the recorded finding reproduced, but against a different artifact than the one \
                 it was found on; the leak survived the change"
                    .to_string()
            }
            (Verdict::NotReproduced, true) => {
                "the recorded finding did not reproduce, against the same artifact. That is a \
                 contradiction worth investigating rather than a pass: a deterministic check \
                 should not lose a finding on an unchanged build"
                    .to_string()
            }
            (Verdict::NotReproduced, false) => {
                "the recorded finding did not reproduce, and the artifact changed. The leak is \
                 absent from this build on this input -- which is what a fix looks like, and is \
                 still not a claim about other inputs"
                    .to_string()
            }
            (Verdict::Inconclusive, _) => format!(
                "the replay established nothing: {}. An infrastructure failure is not evidence \
                 that a leak was fixed",
                detail.unwrap_or_else(|| "the analysis was not usable".to_string())
            ),
        };
        ReplayResult {
            contract: reproducer.contract.clone(),
            verdict,
            same_artifact,
            recorded_artifact_sha256: reproducer.artifact.sha256.clone(),
            replayed_artifact_sha256: replayed_sha256.to_string(),
            message,
        }
    }

    pub fn reproduced(&self) -> bool {
        self.verdict == Verdict::Reproduced
    }

    /// Whether this replay must fail the build.
    ///
    /// Everything except a clean disappearance on a *changed* artifact. A
    /// finding that is still there fails; a finding that vanished from an
    /// unchanged build is a contradiction, not a fix; and an inconclusive run
    /// has established nothing, so it cannot be a pass.
    pub fn failed(&self) -> bool {
        match self.verdict {
            Verdict::Reproduced | Verdict::Inconclusive => true,
            Verdict::NotReproduced => self.same_artifact,
        }
    }
}

#[derive(Debug)]
pub enum ReproducerError {
    Io(String),
    Malformed(String),
    UnsupportedSchema { found: u32, supported: u32 },
}

impl fmt::Display for ReproducerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReproducerError::Io(message) => write!(f, "{message}"),
            ReproducerError::Malformed(detail) => {
                write!(f, "the reproducer could not be read: {detail}")
            }
            ReproducerError::UnsupportedSchema { found, supported } => write!(
                f,
                "reproducer schema_version {found} is not supported (this build understands \
                 {supported})"
            ),
        }
    }
}

impl std::error::Error for ReproducerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::Shrunk;
    use crate::generate::{GeneratedCase, Strategy};

    fn library() -> Library {
        Library {
            package: "crypto-library".into(),
            version: "0.1.0".into(),
            lib_name: "crypto".into(),
            manifest_path: "/w/examples/crypto-library/Cargo.toml".into(),
            features: Vec::new(),
            toolchain: crate::toolchain::Toolchain::unresolved(),
        }
    }

    fn scalar(value: u64) -> Value {
        Value::Scalar { bits: 8, value }
    }

    fn corpus() -> Corpus {
        Corpus {
            schema_version: crate::generate::CORPUS_SCHEMA_VERSION,
            contract: "crypto::lookup::substitute_mode".into(),
            seed: 12345,
            budget: 64,
            strategies_requested: vec![Strategy::Boundaries],
            coverage: Vec::new(),
            cases: (0..3)
                .map(|id| GeneratedCase {
                    id,
                    strategy: Strategy::Boundaries,
                    inputs: vec![
                        ("index".to_string(), scalar(40 + id as u64)),
                        ("mode".to_string(), scalar(1)),
                    ],
                })
                .collect(),
        }
    }

    fn fingerprint() -> Fingerprint {
        Fingerprint {
            classification: Classification::SecretDependentValue,
            function: Some("crypto::lookup::substitute_indexed".into()),
            location: Some("lookup.rs:37".into()),
        }
    }

    fn finding(isolation: Isolation, shrunk: Option<Shrunk>) -> Finding {
        Finding {
            fingerprint: fingerprint(),
            classification: Classification::SecretDependentValue,
            description: "Secret-dependent memory address or value use".into(),
            what: "Use of uninitialised value of size 8".into(),
            origin: "created by a client request (the marked secret)".into(),
            stack: vec!["crypto::lookup::substitute_indexed (lookup.rs:37)".into()],
            attributed: true,
            site: Some("src/lookup.rs:37".into()),
            isolation,
            shrunk,
        }
    }

    /// An isolated finding records the one case that reproduces it, with the
    /// seed and corpus hash of the run that found it.
    #[test]
    fn an_isolated_finding_becomes_a_single_case_reproducer() {
        let corpus = corpus();
        let finding = finding(
            Isolation::Case {
                id: 1,
                inputs: corpus.cases[1].inputs.clone(),
                runs: 3,
            },
            None,
        );
        let reproducer = Reproducer::from_finding(
            "crypto::lookup::substitute_mode",
            &corpus,
            &finding,
            &library(),
            "deadbeef",
            "release",
        );
        assert_eq!(reproducer.schema_version, REPRODUCER_SCHEMA_VERSION);
        assert_eq!(reproducer.cases.len(), 1);
        assert_eq!(reproducer.cases[0].id, 1);
        assert_eq!(reproducer.cases[0].inputs[0].1, scalar(41));
        assert!(!reproducer.sequence_dependent);
        assert_eq!(reproducer.seed, 12345);
        assert_eq!(reproducer.corpus_sha256, corpus.sha256());
        assert_eq!(reproducer.artifact.sha256, "deadbeef");
        assert_eq!(reproducer.artifact.library_package, "crypto-library");
    }

    /// A shrunk input is what gets recorded, because it is what a developer
    /// should look at first. The original run stays recoverable from the seed.
    #[test]
    fn a_shrunk_input_is_preferred_and_keeps_its_case_id() {
        let corpus = corpus();
        let finding = finding(
            Isolation::Case {
                id: 2,
                inputs: corpus.cases[2].inputs.clone(),
                runs: 2,
            },
            Some(Shrunk {
                inputs: vec![
                    ("index".to_string(), scalar(1)),
                    ("mode".to_string(), scalar(1)),
                ],
                attempts: 7,
                steps: 2,
            }),
        );
        let reproducer = Reproducer::from_finding(
            "crypto::lookup::substitute_mode",
            &corpus,
            &finding,
            &library(),
            "feed",
            "release",
        );
        assert_eq!(reproducer.cases.len(), 1);
        assert_eq!(reproducer.cases[0].id, 2, "the case id is kept");
        assert_eq!(
            reproducer.cases[0].inputs[0].1,
            scalar(1),
            "the shrunk value is what gets recorded"
        );
    }

    /// A sequence-dependent finding records the whole batch, in order, rather
    /// than being discarded for refusing to isolate.
    #[test]
    fn a_sequence_dependent_finding_records_its_whole_batch() {
        let corpus = corpus();
        let finding = finding(
            Isolation::Sequence {
                ids: vec![0, 1, 2],
                runs: 2,
                detail: "no single case reproduces this finding".into(),
            },
            None,
        );
        let reproducer = Reproducer::from_finding(
            "crypto::lookup::substitute_mode",
            &corpus,
            &finding,
            &library(),
            "abc",
            "release",
        );
        assert!(reproducer.sequence_dependent);
        assert_eq!(
            reproducer
                .cases
                .iter()
                .map(|case| case.id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert!(
            reproducer.describe().contains("then"),
            "{}",
            reproducer.describe()
        );
    }

    /// A reproducer round-trips through JSON unchanged.
    #[test]
    fn a_reproducer_round_trips() {
        let corpus = corpus();
        let finding = finding(Isolation::Single { id: 0 }, None);
        let original = Reproducer::from_finding(
            "crypto::lookup::substitute_mode",
            &corpus,
            &finding,
            &library(),
            "abc123",
            "release: opt-level=3",
        );
        let parsed = Reproducer::parse(&original.to_json()).expect("parses");
        assert_eq!(parsed, original);
        assert_eq!(parsed.finding.to_fingerprint(), fingerprint());
        // The developer-facing site survives the round trip alongside it.
        assert_eq!(parsed.finding.site.as_deref(), Some("src/lookup.rs:37"));
    }

    /// A reproducer survives a save and load through a file.
    #[test]
    fn a_reproducer_saves_and_loads() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nested/failure.json");
        let corpus = corpus();
        let finding = finding(Isolation::Single { id: 0 }, None);
        let original = Reproducer::from_finding("c::f", &corpus, &finding, &library(), "a", "p");
        original.save(&path).expect("saved");
        assert_eq!(Reproducer::load(&path).expect("loaded"), original);
    }

    /// A reproducer from a future schema is refused rather than parsed on the
    /// assumption that its fields held.
    #[test]
    fn a_future_schema_is_refused() {
        let corpus = corpus();
        let finding = finding(Isolation::Single { id: 0 }, None);
        let json = Reproducer::from_finding("c::f", &corpus, &finding, &library(), "a", "p")
            .to_json()
            .replace("\"schema_version\": 1", "\"schema_version\": 2");
        let error = Reproducer::parse(&json).expect_err("refused");
        assert!(
            matches!(error, ReproducerError::UnsupportedSchema { found: 2, .. }),
            "{error}"
        );
    }

    /// A reproducer with no cases is refused: there would be nothing to replay.
    #[test]
    fn an_empty_reproducer_is_refused() {
        let json = r#"{"schema_version":1,"contract":"c::f","seed":1,"corpus_sha256":"x",
            "cases":[],"sequence_dependent":false,
            "finding":{"classification":"secret_dependent_value"},
            "artifact":{"sha256":"a","profile":"p","library_package":"l","library_version":"1"}}"#;
        let error = Reproducer::parse(json).expect_err("refused");
        assert!(error.to_string().contains("nothing to replay"), "{error}");
    }

    /// An unknown field is refused, so a reproducer written by a newer build is
    /// not silently read with half its meaning.
    #[test]
    fn an_unknown_field_is_refused() {
        let corpus = corpus();
        let finding = finding(Isolation::Single { id: 0 }, None);
        let json = Reproducer::from_finding("c::f", &corpus, &finding, &library(), "a", "p")
            .to_json()
            .replace("\"seed\":", "\"unexpected\": 1,\n  \"seed\":");
        assert!(Reproducer::parse(&json).is_err());
    }

    /// The replay verdict distinguishes a finding that is gone from a run that
    /// could not tell, and only one combination is a pass.
    ///
    /// The regression: `failed()` was `reproduced || same_artifact`, and
    /// "not reproduced" was derived from the mere absence of a matching
    /// diagnostic. Malformed analyzer output on a rebuilt artifact therefore
    /// exited 0 — an infrastructure failure reading as a fixed vulnerability.
    #[test]
    fn a_replay_verdict_never_turns_a_failed_analysis_into_a_pass() {
        let corpus = corpus();
        let finding = finding(Isolation::Single { id: 0 }, None);
        let reproducer =
            Reproducer::from_finding("c::f", &corpus, &finding, &library(), "same", "p");

        let still_there = ReplayResult::new(&reproducer, "same", Verdict::Reproduced, None);
        assert!(still_there.reproduced() && still_there.same_artifact);
        assert!(still_there.failed());

        let survived_change =
            ReplayResult::new(&reproducer, "different", Verdict::Reproduced, None);
        assert!(survived_change.failed());
        assert!(survived_change.message.contains("survived the change"));

        let gone_same_build = ReplayResult::new(&reproducer, "same", Verdict::NotReproduced, None);
        assert!(
            gone_same_build.failed(),
            "losing a finding on an unchanged build is a contradiction, not a pass"
        );
        assert!(gone_same_build.message.contains("contradiction"));

        // The one passing combination: gone, on a changed artifact.
        let fixed = ReplayResult::new(&reproducer, "different", Verdict::NotReproduced, None);
        assert!(!fixed.failed());
        assert!(
            fixed.message.contains("what a fix looks like"),
            "{}",
            fixed.message
        );

        // An unusable analysis is never a pass, whichever artifact it ran on.
        for artifact in ["same", "different"] {
            let unusable = ReplayResult::new(
                &reproducer,
                artifact,
                Verdict::Inconclusive,
                Some("Memcheck output could not be parsed".to_string()),
            );
            assert!(
                unusable.failed(),
                "an inconclusive replay against {artifact} must not pass"
            );
            assert!(!unusable.reproduced());
            assert!(
                unusable
                    .message
                    .contains("not evidence that a leak was fixed"),
                "{}",
                unusable.message
            );
            assert!(unusable.message.contains("could not be parsed"));
        }
    }

    /// The verdicts render as the three distinct words a report prints.
    #[test]
    fn verdicts_are_named_distinctly() {
        assert_eq!(Verdict::Reproduced.as_str(), "REPRODUCED");
        assert_eq!(Verdict::NotReproduced.as_str(), "NOT_REPRODUCED");
        assert_eq!(Verdict::Inconclusive.as_str(), "INCONCLUSIVE");
    }

    /// Replay input goes through the generator's own validation, so a recorded
    /// case cannot bind a value of the wrong width.
    #[test]
    fn replay_cases_are_offered_as_regressions() {
        let corpus = corpus();
        let finding = finding(
            Isolation::Sequence {
                ids: vec![0, 1],
                runs: 1,
                detail: String::new(),
            },
            None,
        );
        let reproducer = Reproducer::from_finding("c::f", &corpus, &finding, &library(), "a", "p");
        let regressions = reproducer.as_regressions();
        assert_eq!(regressions.len(), 2);
        assert_eq!(regressions[0][0].0, "index");
    }
}
