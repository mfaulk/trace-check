//! Experiment definition loaded from an example's `cases.json`.
//!
//! Expected outcomes live in the fixture, not in the comparator, so that a
//! prediction invalidated by a new compiler shows up as a fixture mismatch
//! instead of being silently special-cased in code.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::parser::Decision;

/// Fixture schema this binary understands.
pub const CASES_SCHEMA_VERSION: u32 = 1;

pub const TAG_LEN: usize = 32;
pub const TAG_WORDS: usize = TAG_LEN / 8;

#[derive(Debug, Clone, Deserialize)]
pub struct Experiment {
    pub schema_version: u32,
    pub example: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tag_encoding: String,
    pub public_supplied_tag: String,
    pub cases: Vec<Case>,
    pub variants: Vec<Variant>,
    pub comparisons: Vec<ComparisonSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub expected_tag: String,
    pub expected_decision: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Variant {
    pub id: String,
    pub export: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ComparisonSpec {
    pub id: String,
    pub variant: String,
    pub case_a: String,
    pub case_b: String,
    pub expected_outcome: String,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug)]
pub enum ExperimentError {
    Io(String),
    Json(String),
    UnsupportedSchema { found: u32, supported: u32 },
    BadTag { case: String, reason: String },
    BadDecision { case: String, value: String },
    UnknownCase { comparison: String, case: String },
    UnknownVariant { comparison: String, variant: String },
    UnknownOutcome { comparison: String, value: String },
    DuplicateId { kind: &'static str, id: String },
    SelfComparison { comparison: String },
}

impl fmt::Display for ExperimentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExperimentError::Io(message) => write!(f, "cannot read experiment fixture: {message}"),
            ExperimentError::Json(message) => write!(f, "cannot parse experiment fixture: {message}"),
            ExperimentError::UnsupportedSchema { found, supported } => write!(
                f,
                "fixture schema_version {found} is not supported (this build understands {supported})"
            ),
            ExperimentError::BadTag { case, reason } => {
                write!(f, "case {case:?} has an invalid expected_tag: {reason}")
            }
            ExperimentError::BadDecision { case, value } => write!(
                f,
                "case {case:?} has expected_decision {value:?}; expected \"accept\" or \"reject\""
            ),
            ExperimentError::UnknownCase { comparison, case } => {
                write!(f, "comparison {comparison:?} references unknown case {case:?}")
            }
            ExperimentError::UnknownVariant { comparison, variant } => {
                write!(f, "comparison {comparison:?} references unknown variant {variant:?}")
            }
            ExperimentError::UnknownOutcome { comparison, value } => write!(
                f,
                "comparison {comparison:?} expects unknown outcome {value:?}"
            ),
            ExperimentError::DuplicateId { kind, id } => {
                write!(f, "duplicate {kind} id {id:?}")
            }
            ExperimentError::SelfComparison { comparison } => write!(
                f,
                "comparison {comparison:?} compares a case against itself, which tests \
                 determinism rather than secret-dependence"
            ),
        }
    }
}

impl std::error::Error for ExperimentError {}

impl Experiment {
    pub fn load(path: &Path) -> Result<Self, ExperimentError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ExperimentError::Io(format!("{}: {e}", path.display())))?;
        let experiment: Experiment = serde_json::from_str(&text)
            .map_err(|e| ExperimentError::Json(format!("{}: {e}", path.display())))?;
        experiment.validate()?;
        Ok(experiment)
    }

    /// Rejects a fixture that could not be executed as written. Doing this up
    /// front keeps a typo from surfacing as a mysterious inconclusive result.
    fn validate(&self) -> Result<(), ExperimentError> {
        if self.schema_version != CASES_SCHEMA_VERSION {
            return Err(ExperimentError::UnsupportedSchema {
                found: self.schema_version,
                supported: CASES_SCHEMA_VERSION,
            });
        }
        parse_tag("public_supplied_tag", &self.public_supplied_tag)?;

        let mut seen_cases = Vec::new();
        for case in &self.cases {
            if seen_cases.contains(&case.id) {
                return Err(ExperimentError::DuplicateId {
                    kind: "case",
                    id: case.id.clone(),
                });
            }
            seen_cases.push(case.id.clone());
            parse_tag(&case.id, &case.expected_tag)?;
            case.decision()?;
        }

        let mut seen_variants = Vec::new();
        for variant in &self.variants {
            if seen_variants.contains(&variant.id) {
                return Err(ExperimentError::DuplicateId {
                    kind: "variant",
                    id: variant.id.clone(),
                });
            }
            seen_variants.push(variant.id.clone());
        }

        let mut seen_comparisons = Vec::new();
        for spec in &self.comparisons {
            if seen_comparisons.contains(&spec.id) {
                return Err(ExperimentError::DuplicateId {
                    kind: "comparison",
                    id: spec.id.clone(),
                });
            }
            seen_comparisons.push(spec.id.clone());
            if spec.case_a == spec.case_b {
                return Err(ExperimentError::SelfComparison {
                    comparison: spec.id.clone(),
                });
            }
            for case in [&spec.case_a, &spec.case_b] {
                if self.case(case).is_none() {
                    return Err(ExperimentError::UnknownCase {
                        comparison: spec.id.clone(),
                        case: case.clone(),
                    });
                }
            }
            if self.variant(&spec.variant).is_none() {
                return Err(ExperimentError::UnknownVariant {
                    comparison: spec.id.clone(),
                    variant: spec.variant.clone(),
                });
            }
            if !matches!(
                spec.expected_outcome.as_str(),
                "DIFFERENCE_DETECTED" | "NO_DIFFERENCE_OBSERVED" | "INCONCLUSIVE"
            ) {
                return Err(ExperimentError::UnknownOutcome {
                    comparison: spec.id.clone(),
                    value: spec.expected_outcome.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn case(&self, id: &str) -> Option<&Case> {
        self.cases.iter().find(|case| case.id == id)
    }

    pub fn variant(&self, id: &str) -> Option<&Variant> {
        self.variants.iter().find(|variant| variant.id == id)
    }

    /// Four little-endian words for the fixed public supplied tag.
    pub fn supplied_words(&self) -> [i64; TAG_WORDS] {
        tag_to_words(&parse_tag("public_supplied_tag", &self.public_supplied_tag).unwrap())
    }
}

impl Case {
    pub fn decision(&self) -> Result<Decision, ExperimentError> {
        match self.expected_decision.as_str() {
            "accept" => Ok(Decision::Accept),
            "reject" => Ok(Decision::Reject),
            other => Err(ExperimentError::BadDecision {
                case: self.id.clone(),
                value: other.to_string(),
            }),
        }
    }

    /// Four little-endian words for this case's secret expected tag.
    pub fn expected_words(&self) -> [i64; TAG_WORDS] {
        tag_to_words(&parse_tag(&self.id, &self.expected_tag).unwrap())
    }
}

fn parse_tag(case: &str, hex: &str) -> Result<[u8; TAG_LEN], ExperimentError> {
    if hex.len() != TAG_LEN * 2 {
        return Err(ExperimentError::BadTag {
            case: case.to_string(),
            reason: format!(
                "expected {} hex characters, found {}",
                TAG_LEN * 2,
                hex.len()
            ),
        });
    }
    let mut tag = [0u8; TAG_LEN];
    for (index, byte) in tag.iter_mut().enumerate() {
        let pair = &hex[index * 2..index * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| ExperimentError::BadTag {
            case: case.to_string(),
            reason: format!("{pair:?} is not a hex byte"),
        })?;
    }
    Ok(tag)
}

/// Packs a tag into four little-endian words; word `k` carries bytes `8k..8k+8`.
/// This must mirror `mac_compare::words_to_tag` exactly.
fn tag_to_words(tag: &[u8; TAG_LEN]) -> [i64; TAG_WORDS] {
    let mut words = [0i64; TAG_WORDS];
    for (index, word) in words.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&tag[index * 8..index * 8 + 8]);
        *word = u64::from_le_bytes(bytes) as i64;
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte 0 lands in the low byte of word 0 and byte 31 in the high byte of word 3.
    #[test]
    fn tag_packing_is_little_endian_per_word() {
        let mut tag = [0u8; TAG_LEN];
        tag[0] = 1;
        assert_eq!(tag_to_words(&tag), [1, 0, 0, 0]);

        let mut tag = [0u8; TAG_LEN];
        tag[31] = 1;
        assert_eq!(tag_to_words(&tag), [0, 0, 0, 0x0100_0000_0000_0000]);
    }

    /// Tag bytes above 0x7f round-trip through the signed word encoding.
    #[test]
    fn tag_packing_round_trips_high_bytes() {
        let tag = [0xffu8; TAG_LEN];
        assert_eq!(tag_to_words(&tag), [-1i64; TAG_WORDS]);
    }

    /// A tag of the wrong length is rejected with a length explanation.
    #[test]
    fn short_tag_is_rejected() {
        let error = parse_tag("A", "00").unwrap_err();
        assert!(error.to_string().contains("expected 64 hex characters"));
    }

    /// A tag containing non-hex characters is rejected.
    #[test]
    fn non_hex_tag_is_rejected() {
        let error = parse_tag("A", &"zz".repeat(32)).unwrap_err();
        assert!(error.to_string().contains("not a hex byte"));
    }

    fn fixture(patch: impl Fn(&mut serde_json::Value)) -> Result<Experiment, ExperimentError> {
        let mut value: serde_json::Value = serde_json::json!({
            "schema_version": 1,
            "example": "t",
            "public_supplied_tag": "00".repeat(32),
            "cases": [
                {"id": "A", "expected_tag": "01".to_string() + &"00".repeat(31), "expected_decision": "reject"},
                {"id": "B", "expected_tag": "00".repeat(31) + "01", "expected_decision": "reject"}
            ],
            "variants": [{"id": "v", "export": "e"}],
            "comparisons": [{"id": "c", "variant": "v", "case_a": "A", "case_b": "B",
                             "expected_outcome": "DIFFERENCE_DETECTED"}]
        });
        patch(&mut value);
        let experiment: Experiment =
            serde_json::from_value(value).map_err(|e| ExperimentError::Json(e.to_string()))?;
        experiment.validate()?;
        Ok(experiment)
    }

    /// A well-formed fixture validates.
    #[test]
    fn valid_fixture_is_accepted() {
        assert!(fixture(|_| {}).is_ok());
    }

    /// An unsupported schema version is rejected rather than guessed at.
    #[test]
    fn unsupported_schema_version_is_rejected() {
        let error = fixture(|v| v["schema_version"] = serde_json::json!(99)).unwrap_err();
        assert!(matches!(
            error,
            ExperimentError::UnsupportedSchema { found: 99, .. }
        ));
    }

    /// A comparison referencing a missing case is rejected before execution.
    #[test]
    fn unknown_case_reference_is_rejected() {
        let error =
            fixture(|v| v["comparisons"][0]["case_b"] = serde_json::json!("Z")).unwrap_err();
        assert!(matches!(error, ExperimentError::UnknownCase { .. }));
    }

    /// A comparison referencing a missing variant is rejected before execution.
    #[test]
    fn unknown_variant_reference_is_rejected() {
        let error =
            fixture(|v| v["comparisons"][0]["variant"] = serde_json::json!("z")).unwrap_err();
        assert!(matches!(error, ExperimentError::UnknownVariant { .. }));
    }

    /// An expected outcome outside the defined vocabulary is rejected.
    #[test]
    fn unknown_expected_outcome_is_rejected() {
        let error =
            fixture(|v| v["comparisons"][0]["expected_outcome"] = serde_json::json!("SECURE"))
                .unwrap_err();
        assert!(matches!(error, ExperimentError::UnknownOutcome { .. }));
    }

    /// Comparing a case against itself is rejected as a determinism test.
    #[test]
    fn self_comparison_is_rejected() {
        let error =
            fixture(|v| v["comparisons"][0]["case_b"] = serde_json::json!("A")).unwrap_err();
        assert!(matches!(error, ExperimentError::SelfComparison { .. }));
    }

    /// Duplicate case ids are rejected so case lookups stay unambiguous.
    #[test]
    fn duplicate_case_id_is_rejected() {
        let error = fixture(|v| v["cases"][1]["id"] = serde_json::json!("A")).unwrap_err();
        assert!(matches!(
            error,
            ExperimentError::DuplicateId { kind: "case", .. }
        ));
    }

    /// An unrecognized expected decision is rejected.
    #[test]
    fn bad_expected_decision_is_rejected() {
        let error = fixture(|v| v["cases"][0]["expected_decision"] = serde_json::json!("maybe"))
            .unwrap_err();
        assert!(matches!(error, ExperimentError::BadDecision { .. }));
    }
}
