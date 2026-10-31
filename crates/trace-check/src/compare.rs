//! Differential comparison of two normalized instruction paths.
//!
//! The only property decided here is **instruction-path equivalence**: do two
//! runs execute the same ordered sequence of instruction locations? Nothing
//! about memory addresses, latency, or physical timing is inferred.
//!
//! Two guards keep the answer honest. A comparison whose runs returned
//! different authentication decisions is [`Outcome::Inconclusive`], because an
//! accept-versus-reject difference would explain a path difference without any
//! secret-dependent comparison work. And a path difference is only reported
//! once the same-input runs of both sides have been shown to be deterministic;
//! that check lives in the runner and is surfaced here as a precondition.

use serde::Serialize;

use crate::parser::{ExecutionEvent, ParsedTrace};

/// Instructions of context reported either side of a divergence.
pub const CONTEXT_EVENTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Outcome {
    /// An instruction-path difference was observed for the tested input pair.
    #[serde(rename = "DIFFERENCE_DETECTED")]
    DifferenceDetected,
    /// Normalized paths matched *for the tested cases*. Not proof of security.
    #[serde(rename = "NO_DIFFERENCE_OBSERVED")]
    NoDifferenceObserved,
    /// Capture, parsing, nondeterminism or confounded decisions prevented a
    /// trustworthy answer.
    #[serde(rename = "INCONCLUSIVE")]
    Inconclusive,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::DifferenceDetected => "DIFFERENCE_DETECTED",
            Outcome::NoDifferenceObserved => "NO_DIFFERENCE_OBSERVED",
            Outcome::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// Where two instruction paths first disagree, with surrounding context.
#[derive(Debug, Clone, Serialize)]
pub struct Divergence {
    /// Index into both event sequences of the first differing position.
    pub index: usize,
    /// Events shared by both runs immediately before the divergence.
    pub common_context: Vec<String>,
    /// First events unique to each side, including `None` when a run ended.
    pub side_a: Vec<String>,
    pub side_b: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub outcome: Outcome,
    pub message: String,
    pub events_a: usize,
    pub events_b: usize,
    pub decision_a: String,
    pub decision_b: String,
    pub divergence: Option<Divergence>,
}

/// Compares two parsed traces that are already known to be individually stable.
///
/// `stable` reports whether each side reproduced its own normalized trace on a
/// repeated identical run. Comparing unstable traces cannot distinguish
/// secret-dependence from interpreter nondeterminism, so it is inconclusive.
pub fn compare(a: &ParsedTrace, b: &ParsedTrace, stable: bool) -> Comparison {
    let (events_a, events_b) = (a.events.len(), b.events.len());
    let decisions = (a.decision, b.decision);
    let base = |outcome: Outcome, message: String, divergence: Option<Divergence>| Comparison {
        outcome,
        message,
        events_a,
        events_b,
        decision_a: decisions.0.as_str().to_string(),
        decision_b: decisions.1.as_str().to_string(),
        divergence,
    };

    if !stable {
        return base(
            Outcome::Inconclusive,
            "a repeated identical run produced a different normalized trace, so no \
             difference can be attributed to the secret input"
                .to_string(),
            None,
        );
    }

    if decisions.0 != decisions.1 {
        return base(
            Outcome::Inconclusive,
            format!(
                "the two runs returned different authentication decisions ({} vs {}), which \
                 would confound an accept/reject difference with secret-dependent comparison work",
                decisions.0.as_str(),
                decisions.1.as_str()
            ),
            None,
        );
    }

    match first_divergence(&a.events, &b.events) {
        None => base(
            Outcome::NoDifferenceObserved,
            format!(
                "normalized instruction paths matched over {events_a} events for the tested \
                 inputs; this is not proof of constant-time behavior"
            ),
            None,
        ),
        Some(index) => {
            let divergence = describe_divergence(&a.events, &b.events, index);
            base(
                Outcome::DifferenceDetected,
                format!(
                    "instruction paths diverge at event {index} ({events_a} vs {events_b} events \
                     total) while public inputs were held fixed"
                ),
                Some(divergence),
            )
        }
    }
}

fn first_divergence(a: &[ExecutionEvent], b: &[ExecutionEvent]) -> Option<usize> {
    let shared = a.len().min(b.len());
    for index in 0..shared {
        if a[index] != b[index] {
            return Some(index);
        }
    }
    // A prefix relationship is still a divergence: one run executed more work.
    if a.len() == b.len() {
        None
    } else {
        Some(shared)
    }
}

fn describe_divergence(a: &[ExecutionEvent], b: &[ExecutionEvent], index: usize) -> Divergence {
    let render = |events: &[ExecutionEvent], from: usize, count: usize| -> Vec<String> {
        events
            .iter()
            .skip(from)
            .take(count)
            .map(ToString::to_string)
            .collect()
    };
    let context_start = index.saturating_sub(CONTEXT_EVENTS);
    Divergence {
        index,
        common_context: render(a, context_start, index - context_start),
        side_a: render(a, index, CONTEXT_EVENTS),
        side_b: render(b, index, CONTEXT_EVENTS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Decision;

    fn event(offset: u32, opcode: &str) -> ExecutionEvent {
        ExecutionEvent {
            call_depth: 0,
            istream_offset: offset,
            opcode: opcode.to_string(),
        }
    }

    fn trace(events: Vec<ExecutionEvent>, decision: Decision) -> ParsedTrace {
        ParsedTrace {
            export: "f".to_string(),
            events,
            decision,
            raw_return_value: match decision {
                Decision::Accept => 1,
                Decision::Reject => 0,
            },
        }
    }

    fn rejecting(offsets: &[u32]) -> ParsedTrace {
        trace(
            offsets.iter().map(|o| event(*o, "local.get")).collect(),
            Decision::Reject,
        )
    }

    /// Identical event sequences compare equal.
    #[test]
    fn identical_paths_report_no_difference() {
        let a = rejecting(&[0, 8, 16]);
        let result = compare(&a, &a, true);
        assert_eq!(result.outcome, Outcome::NoDifferenceObserved);
        assert!(result.divergence.is_none());
    }

    /// A shorter path that is a prefix of a longer one is still a difference.
    #[test]
    fn prefix_path_reports_difference_at_the_shorter_length() {
        let result = compare(&rejecting(&[0, 8]), &rejecting(&[0, 8, 16]), true);
        assert_eq!(result.outcome, Outcome::DifferenceDetected);
        assert_eq!(result.divergence.unwrap().index, 2);
        assert_eq!((result.events_a, result.events_b), (2, 3));
    }

    /// Divergence is reported at the first differing index, not the last.
    #[test]
    fn divergence_index_is_the_first_difference() {
        let result = compare(
            &rejecting(&[0, 8, 16, 24]),
            &rejecting(&[0, 8, 99, 24]),
            true,
        );
        assert_eq!(result.divergence.unwrap().index, 2);
    }

    /// Equal-length paths differing only in opcode at one site are a difference.
    #[test]
    fn same_offset_different_opcode_is_a_difference() {
        let a = trace(vec![event(0, "i32.load8_u")], Decision::Reject);
        let b = trace(vec![event(0, "i32.load")], Decision::Reject);
        assert_eq!(compare(&a, &b, true).outcome, Outcome::DifferenceDetected);
    }

    /// Divergence context includes shared events before the split and the
    /// first distinct events on each side.
    #[test]
    fn divergence_reports_context_on_both_sides() {
        let a = rejecting(&[0, 1, 2, 3, 4, 5, 6]);
        let b = rejecting(&[0, 1, 2, 3, 4, 5, 99]);
        let divergence = compare(&a, &b, true).divergence.unwrap();
        assert_eq!(divergence.index, 6);
        assert_eq!(divergence.common_context.len(), CONTEXT_EVENTS);
        assert!(divergence.side_a[0].ends_with("6: local.get"));
        assert!(divergence.side_b[0].ends_with("99: local.get"));
    }

    /// Runs returning different decisions are inconclusive, never a difference.
    #[test]
    fn differing_decisions_are_inconclusive() {
        let a = rejecting(&[0, 8]);
        let b = trace(vec![event(0, "local.get")], Decision::Accept);
        let result = compare(&a, &b, true);
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(result
            .message
            .contains("different authentication decisions"));
    }

    /// An unstable same-input baseline makes any comparison inconclusive.
    #[test]
    fn unstable_traces_are_inconclusive() {
        let result = compare(&rejecting(&[0]), &rejecting(&[0, 8]), false);
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(result.message.contains("repeated identical run"));
    }

    /// "No difference observed" messaging never claims constant-time security.
    #[test]
    fn no_difference_message_is_bounded() {
        let a = rejecting(&[0, 8]);
        let message = compare(&a, &a, true).message;
        assert!(message.contains("not proof of constant-time behavior"));
    }
}
