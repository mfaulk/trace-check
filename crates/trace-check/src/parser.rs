//! Parser for WABT `wasm-interp --trace` output.
//!
//! The parser separates raw interpreter text from the stable control-flow facts
//! we are willing to compare. Two rules drive the design:
//!
//! * Operand text and value-stack depth are **presentation**, not control flow,
//!   and are dropped from [`ExecutionEvent`] entirely — they encode input
//!   values, which would make every input difference look like a path
//!   difference.
//! * Call depth and instruction-stream offset are **identity**. They are kept
//!   verbatim and in order, including repetitions.
//!
//! Truncation is treated as a parse failure rather than a short trace: a trace
//! is only accepted if it ends with the interpreter's result line, which is
//! also where the authentication decision is read from.

use std::fmt;

/// Trace format this parser understands. Bump when the recognized grammar
/// changes; it is recorded in reports so stored results stay interpretable.
pub const TRACE_PARSER_VERSION: u32 = 1;

/// One executed instruction, reduced to the facts that identify a location in
/// the compiled module.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExecutionEvent {
    /// Interpreter call depth, i.e. which activation is executing.
    pub call_depth: u32,
    /// Offset into the interpreter's instruction stream. Stable for a fixed
    /// module and WABT version, and distinguishes sites sharing an opcode.
    pub istream_offset: u32,
    /// Opcode mnemonic. Diagnostic detail; never sufficient on its own.
    pub opcode: String,
}

impl fmt::Display for ExecutionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{}. {}: {}",
            self.call_depth, self.istream_offset, self.opcode
        )
    }
}

/// The authentication decision the interpreter reported for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Accept,
    Reject,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Accept => "accept",
            Decision::Reject => "reject",
        }
    }
}

/// A fully parsed trace: an ordered instruction path plus the run's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTrace {
    pub export: String,
    pub events: Vec<ExecutionEvent>,
    pub decision: Decision,
    pub raw_return_value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// No `>>> running export "NAME":` header, so we cannot tell what ran.
    MissingHeader,
    /// No trailing result line: the trace is truncated or the run never
    /// returned. Never treat this as an empty-but-valid path.
    MissingResultLine,
    /// A line matched neither the instruction grammar nor a known framing line.
    UnrecognizedLine { line_number: usize, line: String },
    /// The result line parsed, but its value is not a boolean decision.
    NonBooleanResult { value: String },
    /// The trace contained a result line but no instructions.
    NoEvents,
    /// Header and result line disagree about which export ran.
    ExportMismatch { header: String, result: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MissingHeader => {
                write!(f, "trace has no `>>> running export` header")
            }
            ParseError::MissingResultLine => write!(
                f,
                "trace has no `export(args) => value` result line; it is truncated or the run did not return"
            ),
            ParseError::UnrecognizedLine { line_number, line } => {
                write!(f, "unrecognized trace line {line_number}: {line:?}")
            }
            ParseError::NonBooleanResult { value } => {
                write!(f, "result {value:?} is not an i32 boolean decision")
            }
            ParseError::NoEvents => write!(f, "trace contains a result but no instructions"),
            ParseError::ExportMismatch { header, result } => write!(
                f,
                "trace header names export {header:?} but the result line names {result:?}"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses `wasm-interp --trace` output for a single exported function.
///
/// Instruction lines look like
/// `#0. 1368: V:8  | i64.store $0:1048480+$88, 0`
/// and the run ends with `export(i64:1, ...) => i32:0`.
pub fn parse_trace(raw: &str) -> Result<ParsedTrace, ParseError> {
    let mut header_export: Option<String> = None;
    let mut events = Vec::new();
    let mut result: Option<(String, i64)> = None;

    for (index, line) in raw.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }

        if let Some(export) = parse_header(trimmed) {
            header_export = Some(export);
            continue;
        }
        if let Some(event) = parse_event(trimmed) {
            // Instructions after the result line would mean we merged two runs.
            if result.is_some() {
                return Err(ParseError::UnrecognizedLine {
                    line_number,
                    line: trimmed.to_string(),
                });
            }
            events.push(event);
            continue;
        }
        if let Some(parsed) = parse_result(trimmed) {
            result = Some(parsed?);
            continue;
        }
        return Err(ParseError::UnrecognizedLine {
            line_number,
            line: trimmed.to_string(),
        });
    }

    let header_export = header_export.ok_or(ParseError::MissingHeader)?;
    let (result_export, raw_return_value) = result.ok_or(ParseError::MissingResultLine)?;
    if header_export != result_export {
        return Err(ParseError::ExportMismatch {
            header: header_export,
            result: result_export,
        });
    }
    if events.is_empty() {
        return Err(ParseError::NoEvents);
    }

    let decision = match raw_return_value {
        0 => Decision::Reject,
        1 => Decision::Accept,
        other => {
            return Err(ParseError::NonBooleanResult {
                value: other.to_string(),
            })
        }
    };

    Ok(ParsedTrace {
        export: header_export,
        events,
        decision,
        raw_return_value,
    })
}

fn parse_header(line: &str) -> Option<String> {
    let rest = line.strip_prefix(">>> running export ")?;
    let rest = rest.strip_suffix(':')?;
    Some(rest.trim_matches('"').to_string())
}

fn parse_event(line: &str) -> Option<ExecutionEvent> {
    let rest = line.strip_prefix('#')?;
    let (depth, rest) = rest.split_once(". ")?;
    let (offset, rest) = rest.split_once(':')?;
    // `V:<n>` is value-stack depth: presentation, deliberately discarded.
    let (_stack, rest) = rest.split_once('|')?;
    let opcode = rest.split_whitespace().next()?;
    Some(ExecutionEvent {
        call_depth: depth.trim().parse().ok()?,
        istream_offset: offset.trim().parse().ok()?,
        opcode: opcode.trim_end_matches(',').to_string(),
    })
}

/// Recognizes `export(args...) => i32:VALUE`. Returns `None` when the line is
/// not a result line at all, and `Some(Err(..))` when it is one we reject.
fn parse_result(line: &str) -> Option<Result<(String, i64), ParseError>> {
    let (call, value) = line.rsplit_once("=>")?;
    let export = call.split_once('(')?.0.trim().to_string();
    if export.is_empty() {
        return None;
    }
    let value = value.trim();
    let digits = value.strip_prefix("i32:").unwrap_or(value);
    match digits.parse::<i64>() {
        Ok(parsed) => Some(Ok((export, parsed))),
        Err(_) => Some(Err(ParseError::NonBooleanResult {
            value: value.to_string(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = concat!(
        ">>> running export \"verify_early_exit_opaque_export\":\n",
        "#0. 1368: V:8  | alloca 2\n",
        "#1.  112: V:12 | local.get $2\n",
        "verify_early_exit_opaque_export(i64:1, i64:0) => i32:0\n",
    );

    /// A well-formed trace yields ordered events, the export name and decision.
    #[test]
    fn parses_events_in_order_with_decision() {
        let parsed = parse_trace(TRACE).expect("trace should parse");
        assert_eq!(parsed.export, "verify_early_exit_opaque_export");
        assert_eq!(parsed.decision, Decision::Reject);
        assert_eq!(
            parsed.events,
            vec![
                ExecutionEvent {
                    call_depth: 0,
                    istream_offset: 1368,
                    opcode: "alloca".into()
                },
                ExecutionEvent {
                    call_depth: 1,
                    istream_offset: 112,
                    opcode: "local.get".into()
                },
            ]
        );
    }

    /// Operand values are discarded, so events differing only in operands are equal.
    #[test]
    fn operand_values_are_not_part_of_an_event() {
        let a = parse_event("#1.  144: V:14 | i64.store $0:1048480+$0, 1").unwrap();
        let b = parse_event("#1.  144: V:14 | i64.store $0:1048480+$0, 72057594037927936").unwrap();
        assert_eq!(a, b);
    }

    /// Value-stack depth is presentation and does not affect event identity.
    #[test]
    fn value_stack_depth_is_not_part_of_an_event() {
        let a = parse_event("#0. 1368: V:8  | alloca 2").unwrap();
        let b = parse_event("#0. 1368: V:99 | alloca 2").unwrap();
        assert_eq!(a, b);
    }

    /// The same opcode at a different instruction offset is a different event.
    #[test]
    fn same_opcode_at_different_offsets_differs() {
        let a = parse_event("#0. 1368: V:8 | local.get $2").unwrap();
        let b = parse_event("#0. 1376: V:8 | local.get $2").unwrap();
        assert_ne!(a, b);
    }

    /// The same offset at a different call depth is a different event.
    #[test]
    fn same_offset_at_different_call_depth_differs() {
        let a = parse_event("#0. 1368: V:8 | local.get $2").unwrap();
        let b = parse_event("#1. 1368: V:8 | local.get $2").unwrap();
        assert_ne!(a, b);
    }

    /// A trace cut off before the result line is rejected, not treated as short.
    #[test]
    fn truncated_trace_is_rejected() {
        let truncated = TRACE
            .rsplit_once('\n')
            .unwrap()
            .0
            .rsplit_once('\n')
            .unwrap()
            .0;
        assert_eq!(parse_trace(truncated), Err(ParseError::MissingResultLine));
    }

    /// A trace with no `running export` header is rejected.
    #[test]
    fn missing_header_is_rejected() {
        let body = TRACE.split_once('\n').unwrap().1;
        assert_eq!(parse_trace(body), Err(ParseError::MissingHeader));
    }

    /// Unrecognized interpreter output is an error rather than a skipped line.
    #[test]
    fn unrecognized_line_is_rejected() {
        let malformed = TRACE.replace("#1.  112: V:12 | local.get $2", "!! unexpected output");
        match parse_trace(&malformed) {
            Err(ParseError::UnrecognizedLine { line, .. }) => {
                assert_eq!(line, "!! unexpected output");
            }
            other => panic!("expected UnrecognizedLine, got {other:?}"),
        }
    }

    /// A result line with no instructions before it is rejected.
    #[test]
    fn result_without_events_is_rejected() {
        let only_result = concat!(">>> running export \"f\":\n", "f(i64:1) => i32:0\n");
        assert_eq!(parse_trace(only_result), Err(ParseError::NoEvents));
    }

    /// A non-boolean return value is rejected rather than coerced to a decision.
    #[test]
    fn non_boolean_result_is_rejected() {
        let odd = TRACE.replace("=> i32:0", "=> i32:7");
        assert_eq!(
            parse_trace(&odd),
            Err(ParseError::NonBooleanResult { value: "7".into() })
        );
    }

    /// A header and result line naming different exports is rejected.
    #[test]
    fn export_name_mismatch_is_rejected() {
        let mismatched = TRACE.replace(
            ">>> running export \"verify_early_exit_opaque_export\"",
            ">>> running export \"other\"",
        );
        match parse_trace(&mismatched) {
            Err(ParseError::ExportMismatch { header, result }) => {
                assert_eq!(header, "other");
                assert_eq!(result, "verify_early_exit_opaque_export");
            }
            other => panic!("expected ExportMismatch, got {other:?}"),
        }
    }

    /// Instructions appearing after the result line indicate concatenated runs.
    #[test]
    fn events_after_the_result_line_are_rejected() {
        let concatenated = format!("{TRACE}#0. 4540: V:1  | return\n");
        assert!(matches!(
            parse_trace(&concatenated),
            Err(ParseError::UnrecognizedLine { .. })
        ));
    }

    /// An accepting run is reported as `accept`.
    #[test]
    fn accepting_run_is_parsed_as_accept() {
        let accepted = TRACE.replace("=> i32:0", "=> i32:1");
        assert_eq!(parse_trace(&accepted).unwrap().decision, Decision::Accept);
    }
}
