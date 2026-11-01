//! Valgrind Memcheck XML parsing and classification.
//!
//! Parsing is structured rather than a stderr grep. Memcheck's XML carries an
//! error `<kind>`, a human `<what>`, a primary `<stack>`, and — under
//! `--track-origins=yes` — one or more `<auxwhat>`/`<stack>` pairs describing
//! where the undefined value came from.
//!
//! Completeness is checked before any content is trusted. A document that
//! ended early must never parse to "no errors found", because that converts
//! missing instrumentation evidence into a clean security result — the one
//! failure mode a security tool cannot have. See [`parse`] for the four
//! independent checks.
//!
//! Three classification rules carry the weight:
//!
//! * Only `UninitCondition` and `UninitValue` can be secret dependency.
//!   Memcheck also reports genuine memory bugs; labelling an `InvalidRead` as
//!   a timing leak would be worse than missing it.
//! * Those kinds are only secret dependency when the **origin** is a client
//!   request, i.e. our own marking. Memcheck reports the same kinds for
//!   genuinely uninitialized heap or stack data, which is an ordinary defect
//!   and not a leak. See [`Origin`].
//! * Attribution uses the **primary** stack only. The origin stack names where
//!   the value was created — for a marked secret, the harness — so matching
//!   against it would attribute findings to the wrong function.

use std::fmt;

use serde::Serialize;

/// Valgrind XML protocol versions this parser understands.
///
/// The subset actually consumed — error `kind`/`what`, `stack/frame` with
/// `fn`/`file`/`line`/`obj`, and `auxwhat` — has been stable across these
/// revisions. Valgrind 3.28 emits 6; older releases emit 4. An unlisted
/// version is refused rather than parsed on the assumption that the layout
/// held.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 3] = ["4", "5", "6"];

/// How far down the primary stack a frame may be and still attribute the
/// finding to the function under test. Inlining can insert a few frames;
/// beyond this the finding is more likely to belong to a caller.
pub const ATTRIBUTION_DEPTH: usize = 8;

/// One stack frame from a Memcheck error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Frame {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
}

impl fmt::Display for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let function = self.function.as_deref().unwrap_or("<unknown>");
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(f, "{function} ({file}:{line})"),
            (Some(file), None) => write!(f, "{function} ({file})"),
            _ => write!(f, "{function}"),
        }
    }
}

/// An auxiliary stack: an `<auxwhat>` description and the frames that follow
/// it. For an undefined-value error the first one is the origin stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuxiliaryStack {
    pub what: String,
    pub frames: Vec<Frame>,
}

/// Where Memcheck says an undefined value came from.
///
/// This is the discriminator between our secret marking and an ordinary bug.
/// `VALGRIND_MAKE_MEM_UNDEFINED` is a client request, so a value we marked
/// reports [`Origin::ClientRequest`]. Genuinely uninitialized memory reports a
/// heap or stack allocation, which is a real defect but not a secret leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Created by a client request — our `Secret` marking.
    ClientRequest,
    /// Genuinely uninitialized heap memory.
    HeapAllocation,
    /// Genuinely uninitialized stack memory.
    StackAllocation,
    /// An origin description we do not classify, or an `auxwhat` that is not
    /// an origin sentence at all.
    Other(String),
    /// No origin was reported. With `--track-origins=yes` this means we cannot
    /// tell our marking from a genuine uninitialized-memory bug.
    Unknown,
}

impl Origin {
    /// Parses Valgrind's origin sentence, e.g.
    /// "Uninitialised value was created by a client request".
    fn parse(auxwhat: &str) -> Origin {
        let lowered = auxwhat.to_ascii_lowercase();
        if !lowered.contains("was created by") {
            return Origin::Other(auxwhat.trim().to_string());
        }
        if lowered.contains("client request") {
            Origin::ClientRequest
        } else if lowered.contains("heap") {
            Origin::HeapAllocation
        } else if lowered.contains("stack") {
            Origin::StackAllocation
        } else {
            Origin::Other(auxwhat.trim().to_string())
        }
    }

    /// Whether this origin is our own secret marking.
    pub fn is_secret_marking(&self) -> bool {
        matches!(self, Origin::ClientRequest)
    }

    pub fn describe(&self) -> String {
        match self {
            Origin::ClientRequest => "created by a client request (the marked secret)".to_string(),
            Origin::HeapAllocation => {
                "created by a heap allocation (genuinely uninitialized memory)".to_string()
            }
            Origin::StackAllocation => {
                "created by a stack allocation (genuinely uninitialized memory)".to_string()
            }
            Origin::Other(detail) => detail.clone(),
            Origin::Unknown => "no origin reported".to_string(),
        }
    }
}

/// What a Memcheck error means for this analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// `UninitCondition` from a marked secret: a secret-derived value reached
    /// a conditional branch.
    SecretDependentBranch,
    /// `UninitValue` from a marked secret: used where it affects behaviour,
    /// typically a memory address or a syscall argument.
    SecretDependentValue,
    /// An undefined-value diagnostic whose origin is *not* our marking, so it
    /// reports genuinely uninitialized data rather than secret dependency.
    UnrelatedUndefinedValue,
    /// A real memory bug. Not a timing leak.
    MemoryError,
    /// A kind this build does not classify. Retained, never ignored.
    Unclassified,
}

impl Classification {
    /// Whether this classification describes secret dependency.
    pub fn is_secret_dependency(self) -> bool {
        matches!(
            self,
            Classification::SecretDependentBranch | Classification::SecretDependentValue
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Classification::SecretDependentBranch => "secret_dependent_branch",
            Classification::SecretDependentValue => "secret_dependent_value",
            Classification::UnrelatedUndefinedValue => "unrelated_undefined_value",
            Classification::MemoryError => "memory_error",
            Classification::Unclassified => "unclassified",
        }
    }

    /// Human-facing description used in reports.
    pub fn describe(self) -> &'static str {
        match self {
            Classification::SecretDependentBranch => "Secret-dependent branch",
            Classification::SecretDependentValue => "Secret-dependent memory address or value use",
            Classification::UnrelatedUndefinedValue => {
                "Undefined value unrelated to the marked secret (not a timing leak)"
            }
            Classification::MemoryError => "Memory error (not a timing leak)",
            Classification::Unclassified => "Unclassified Memcheck diagnostic",
        }
    }
}

fn is_undefined_value_kind(kind: &str) -> bool {
    matches!(kind, "UninitCondition" | "UninitValue")
}

/// Memcheck's memory-error kinds.
fn is_memory_error_kind(kind: &str) -> bool {
    matches!(
        kind,
        "InvalidRead"
            | "InvalidWrite"
            | "InvalidJump"
            | "InvalidFree"
            | "MismatchedFree"
            | "Overlap"
            | "SyscallParam"
            | "ClientCheck"
            | "InvalidMemPool"
    ) || kind.starts_with("Leak_")
}

#[derive(Debug, Clone, Serialize)]
pub struct MemcheckError {
    pub kind: String,
    pub classification: Classification,
    pub what: String,
    /// Where the problematic operation happened. Attribution uses this only.
    pub primary_stack: Vec<Frame>,
    /// `<auxwhat>`/`<stack>` pairs. For an undefined-value error the first is
    /// the origin stack, naming where the value was created.
    pub auxiliary_stacks: Vec<AuxiliaryStack>,
    pub origin: Origin,
}

impl MemcheckError {
    fn classify(kind: &str, origin: &Origin) -> Classification {
        if is_undefined_value_kind(kind) {
            // An undefined-value diagnostic is only secret dependency when the
            // value came from our marking. Heap and stack origins are ordinary
            // uninitialized-memory bugs, and an unreported origin leaves us
            // unable to tell the two apart — so neither is claimed as a leak.
            if !origin.is_secret_marking() {
                return Classification::UnrelatedUndefinedValue;
            }
            return match kind {
                "UninitCondition" => Classification::SecretDependentBranch,
                _ => Classification::SecretDependentValue,
            };
        }
        if is_memory_error_kind(kind) {
            return Classification::MemoryError;
        }
        Classification::Unclassified
    }

    /// The frame a report should point at: the shallowest primary frame with a
    /// source location, falling back to the shallowest primary frame.
    pub fn primary_frame(&self) -> Option<&Frame> {
        self.primary_stack
            .iter()
            .find(|frame| frame.file.is_some() && frame.line.is_some())
            .or_else(|| self.primary_stack.first())
    }

    /// Whether a frame naming `function` appears within the attribution window
    /// of the **primary** stack.
    ///
    /// Deliberately ignores origin and auxiliary stacks: those name where the
    /// value was created, which for a marked secret is the harness.
    pub fn attributable_to(&self, function: &str) -> bool {
        self.primary_stack
            .iter()
            .take(ATTRIBUTION_DEPTH)
            .filter_map(|frame| frame.function.as_deref())
            .any(|name| frame_names_function(name, function))
    }

    /// The origin stack frames, for diagnostics.
    pub fn origin_frames(&self) -> &[Frame] {
        self.auxiliary_stacks
            .first()
            .map(|aux| aux.frames.as_slice())
            .unwrap_or(&[])
    }
}

/// Matches a demangled frame name against a plain function name. Frames appear
/// as `crate::module::function` or with generic suffixes, so compare the path
/// tail rather than requiring equality.
fn frame_names_function(frame: &str, function: &str) -> bool {
    let without_generics = frame
        .split(['<', '('])
        .next()
        .unwrap_or(frame)
        .trim_end_matches("::");
    without_generics
        .rsplit("::")
        .next()
        .is_some_and(|tail| tail == function)
        || without_generics == function
}

#[derive(Debug, Clone, Serialize)]
pub struct MemcheckRun {
    pub protocol_version: String,
    pub errors: Vec<MemcheckError>,
}

impl MemcheckRun {
    /// Errors that are secret dependency: an undefined-value kind whose origin
    /// is our marking.
    pub fn secret_dependency_errors(&self) -> impl Iterator<Item = &MemcheckError> {
        self.errors
            .iter()
            .filter(|e| e.classification.is_secret_dependency())
    }

    /// Undefined-value diagnostics not attributable to our marking, so they
    /// report ordinary uninitialized data.
    pub fn unrelated_undefined_errors(&self) -> impl Iterator<Item = &MemcheckError> {
        self.errors
            .iter()
            .filter(|e| e.classification == Classification::UnrelatedUndefinedValue)
    }

    pub fn memory_errors(&self) -> impl Iterator<Item = &MemcheckError> {
        self.errors
            .iter()
            .filter(|e| e.classification == Classification::MemoryError)
    }

    pub fn unclassified_errors(&self) -> impl Iterator<Item = &MemcheckError> {
        self.errors
            .iter()
            .filter(|e| e.classification == Classification::Unclassified)
    }

    /// Everything that is not secret dependency, in document order. These must
    /// be resolved before a security conclusion is meaningful.
    pub fn non_secret_errors(&self) -> impl Iterator<Item = &MemcheckError> {
        self.errors
            .iter()
            .filter(|e| !e.classification.is_secret_dependency())
    }
}

#[derive(Debug)]
pub enum MemcheckParseError {
    /// Not Valgrind XML at all, or syntactically invalid.
    Malformed(String),
    /// The document ended with structure still open, so instrumentation
    /// evidence may be missing. Never treated as "no errors found".
    Truncated(String),
    /// Valgrind produced XML for a protocol version this build does not know.
    UnsupportedProtocol { found: String },
    /// No `<protocolversion>`, so the layout cannot be assumed.
    MissingProtocolVersion,
    /// The document parsed but contained no `<valgrindoutput>` root.
    MissingRoot,
    /// The XML came from a different Valgrind tool, whose error kinds this
    /// classifier does not model.
    WrongTool { found: String },
    /// Valgrind never reported `FINISHED`, so the run was killed, crashed, or
    /// the output was captured mid-write.
    NotFinished,
}

impl fmt::Display for MemcheckParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemcheckParseError::Malformed(detail) => {
                write!(f, "malformed Memcheck XML: {detail}")
            }
            MemcheckParseError::Truncated(detail) => write!(
                f,
                "truncated Memcheck XML ({detail}); instrumentation evidence may be \
                 incomplete, so no security conclusion can be drawn"
            ),
            MemcheckParseError::UnsupportedProtocol { found } => write!(
                f,
                "Memcheck XML protocol version {found:?} is not supported (this build \
                 understands {})",
                SUPPORTED_PROTOCOL_VERSIONS.join(", ")
            ),
            MemcheckParseError::MissingProtocolVersion => write!(
                f,
                "Memcheck XML has no <protocolversion>, so its layout cannot be assumed"
            ),
            MemcheckParseError::MissingRoot => {
                write!(f, "Memcheck XML has no <valgrindoutput> root element")
            }
            MemcheckParseError::WrongTool { found } => write!(
                f,
                "XML was produced by the Valgrind tool {found:?}, not memcheck; its error \
                 kinds are not modeled here"
            ),
            MemcheckParseError::NotFinished => write!(
                f,
                "Valgrind did not report FINISHED, so the run was killed, crashed, or its \
                 output was captured mid-write"
            ),
        }
    }
}

impl std::error::Error for MemcheckParseError {}

/// Parses Valgrind's XML output.
///
/// Completeness is enforced before any content is trusted. A document that
/// ended early — because Valgrind was killed, crashed, or its output was read
/// mid-write — must never parse to "no errors found": that would turn missing
/// instrumentation evidence into a clean security result. Four independent
/// checks have to pass:
///
/// * the document is syntactically valid and every element is closed,
/// * `<protocolversion>` is present and known,
/// * `<tool>` is `memcheck`, since other tools use different error kinds,
/// * a terminal `<status><state>FINISHED</state>` was seen.
///
/// The `FINISHED` marker is the strongest of these. Balanced tags only prove
/// the bytes we received were well-formed; `FINISHED` proves Valgrind ran to
/// completion and wrote its full report.
///
/// Within an `<error>`, the first `<stack>` is the primary stack and any later
/// `<stack>` belongs to the preceding `<auxwhat>`. They are kept separate
/// because the origin stack names where a value was created, not where the
/// problematic operation happened.
pub fn parse(xml: &str) -> Result<MemcheckRun, MemcheckParseError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    reader.config_mut().check_end_names = true;

    let mut protocol_version: Option<String> = None;
    let mut tool: Option<String> = None;
    let mut errors = Vec::new();
    let mut saw_root = false;
    let mut root_closed = false;
    let mut finished = false;
    let mut depth: usize = 0;
    let mut in_status = false;

    let mut current: Option<PartialError> = None;
    let mut frame: Option<Frame> = None;
    let mut frames: Vec<Frame> = Vec::new();
    let mut in_stack = false;
    let mut text = String::new();

    loop {
        match reader.read_event() {
            Err(error) => return Err(MemcheckParseError::Malformed(error.to_string())),
            Ok(Event::Eof) => break,
            Ok(Event::Start(start)) => {
                let name = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                depth += 1;
                match name.as_str() {
                    "valgrindoutput" => saw_root = true,
                    "status" => in_status = true,
                    "error" => current = Some(PartialError::default()),
                    "stack" => {
                        in_stack = true;
                        frames = Vec::new();
                    }
                    "frame" => {
                        frame = Some(Frame {
                            function: None,
                            file: None,
                            line: None,
                            object: None,
                        })
                    }
                    _ => {}
                }
                text.clear();
            }
            Ok(Event::Text(contents)) => {
                text = contents
                    .decode()
                    .map_err(|e| MemcheckParseError::Malformed(e.to_string()))?
                    .into_owned();
            }
            Ok(Event::End(end)) => {
                let name = String::from_utf8_lossy(end.name().as_ref()).into_owned();
                depth = depth.checked_sub(1).ok_or_else(|| {
                    MemcheckParseError::Malformed(format!("unbalanced </{name}>"))
                })?;
                let in_error = current.is_some();
                let in_frame = frame.is_some();

                match name.as_str() {
                    "valgrindoutput" if depth == 0 => root_closed = true,
                    "protocolversion" if !in_error => protocol_version = Some(text.clone()),
                    "tool" if !in_error => tool = Some(text.clone()),
                    "state" if in_status => {
                        if text.trim() == "FINISHED" {
                            finished = true;
                        }
                    }
                    "status" => in_status = false,
                    "fn" if in_frame => frame.as_mut().unwrap().function = Some(text.clone()),
                    "file" if in_frame => frame.as_mut().unwrap().file = Some(text.clone()),
                    "obj" if in_frame => frame.as_mut().unwrap().object = Some(text.clone()),
                    "line" if in_frame => frame.as_mut().unwrap().line = text.trim().parse().ok(),
                    "frame" => {
                        if let Some(complete) = frame.take() {
                            frames.push(complete);
                        }
                    }
                    "stack" => {
                        in_stack = false;
                        if let Some(error) = current.as_mut() {
                            error.push_stack(std::mem::take(&mut frames));
                        }
                    }
                    "kind" if in_error => current.as_mut().unwrap().kind = Some(text.clone()),
                    "what" if in_error => {
                        let error = current.as_mut().unwrap();
                        if error.what.is_none() {
                            error.what = Some(text.clone());
                        }
                    }
                    // Each `auxwhat` describes the stack that follows it.
                    "auxwhat" if in_error => {
                        current.as_mut().unwrap().pending_auxwhat = Some(text.clone())
                    }
                    "error" => {
                        if let Some(complete) = current.take() {
                            errors.push(complete.build());
                        }
                    }
                    _ => {}
                }
                text.clear();
            }
            Ok(_) => {}
        }
    }

    if !saw_root {
        return Err(MemcheckParseError::MissingRoot);
    }
    // Structural completeness first: anything still open means the bytes we
    // have are not the whole report.
    if let Some(partial) = &current {
        return Err(MemcheckParseError::Truncated(format!(
            "an <error> element of kind {:?} was never closed",
            partial.kind.as_deref().unwrap_or("<unknown>")
        )));
    }
    if frame.is_some() {
        return Err(MemcheckParseError::Truncated(
            "a <frame> element was never closed".to_string(),
        ));
    }
    if in_stack {
        return Err(MemcheckParseError::Truncated(
            "a <stack> element was never closed".to_string(),
        ));
    }
    if depth != 0 || !root_closed {
        return Err(MemcheckParseError::Truncated(format!(
            "{depth} element(s) left open and the <valgrindoutput> root was {}",
            if root_closed {
                "closed"
            } else {
                "never closed"
            }
        )));
    }

    let protocol_version = protocol_version.ok_or(MemcheckParseError::MissingProtocolVersion)?;
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&protocol_version.as_str()) {
        return Err(MemcheckParseError::UnsupportedProtocol {
            found: protocol_version,
        });
    }
    match tool.as_deref() {
        Some("memcheck") => {}
        Some(other) => {
            return Err(MemcheckParseError::WrongTool {
                found: other.to_string(),
            })
        }
        None => {
            return Err(MemcheckParseError::WrongTool {
                found: "<absent>".to_string(),
            })
        }
    }
    if !finished {
        return Err(MemcheckParseError::NotFinished);
    }

    Ok(MemcheckRun {
        protocol_version,
        errors,
    })
}

#[derive(Default)]
struct PartialError {
    kind: Option<String>,
    what: Option<String>,
    primary_stack: Option<Vec<Frame>>,
    auxiliary_stacks: Vec<AuxiliaryStack>,
    /// The most recent `<auxwhat>`, awaiting its stack.
    pending_auxwhat: Option<String>,
}

impl PartialError {
    /// The first `<stack>` in an error is the primary one; later stacks belong
    /// to the `<auxwhat>` that preceded them.
    fn push_stack(&mut self, frames: Vec<Frame>) {
        if self.primary_stack.is_none() {
            self.primary_stack = Some(frames);
            return;
        }
        let what = self
            .pending_auxwhat
            .take()
            .unwrap_or_else(|| "auxiliary stack".to_string());
        self.auxiliary_stacks.push(AuxiliaryStack { what, frames });
    }

    fn build(mut self) -> MemcheckError {
        let kind = self.kind.unwrap_or_else(|| "Unknown".to_string());
        // An `auxwhat` with no following stack still describes the origin.
        if let Some(trailing) = self.pending_auxwhat.take() {
            self.auxiliary_stacks.push(AuxiliaryStack {
                what: trailing,
                frames: Vec::new(),
            });
        }
        // Prefer the first auxwhat that actually parses as an origin sentence.
        let origin = self
            .auxiliary_stacks
            .iter()
            .map(|aux| Origin::parse(&aux.what))
            .find(|origin| !matches!(origin, Origin::Other(_)))
            .or_else(|| {
                self.auxiliary_stacks
                    .first()
                    .map(|aux| Origin::parse(&aux.what))
            })
            .unwrap_or(Origin::Unknown);
        MemcheckError {
            classification: MemcheckError::classify(&kind, &origin),
            what: self.what.unwrap_or_default(),
            primary_stack: self.primary_stack.unwrap_or_default(),
            auxiliary_stacks: self.auxiliary_stacks,
            origin,
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete document with a marked-secret origin stack, matching what
    /// Valgrind 3.28 emits under `--track-origins=yes`.
    const SECRET_BRANCH: &str = r#"<?xml version="1.0"?>
<valgrindoutput>
<protocolversion>6</protocolversion>
<tool>memcheck</tool>
<status><state>RUNNING</state></status>
<error>
  <unique>0x0</unique>
  <kind>UninitCondition</kind>
  <what>Conditional jump or move depends on uninitialised value(s)</what>
  <stack>
    <frame><ip>0x1</ip><obj>/bin/t</obj><fn>mac_compare::verify_early_exit_opaque</fn><file>lib.rs</file><line>70</line></frame>
    <frame><ip>0x2</ip><obj>/bin/t</obj><fn>main</fn><file>main.rs</file><line>10</line></frame>
  </stack>
  <auxwhat>Uninitialised value was created by a client request</auxwhat>
  <stack>
    <frame><ip>0x9</ip><obj>/bin/t</obj><fn>trace_check_secret::Secret::new</fn><file>lib.rs</file><line>126</line></frame>
    <frame><ip>0xa</ip><obj>/bin/t</obj><fn>harness_setup</fn><file>harness.rs</file><line>5</line></frame>
  </stack>
</error>
<status><state>FINISHED</state></status>
</valgrindoutput>"#;

    fn complete(body: &str) -> String {
        format!(
            "<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>{body}\
             <status><state>FINISHED</state></status></valgrindoutput>"
        )
    }

    /// The primary and origin stacks are kept separate, not merged.
    #[test]
    fn primary_and_origin_stacks_are_separate() {
        let run = parse(SECRET_BRANCH).expect("fixture parses");
        let error = &run.errors[0];
        assert_eq!(
            error.primary_stack.len(),
            2,
            "the primary stack must hold only its own frames"
        );
        assert_eq!(
            error.primary_stack[0].function.as_deref(),
            Some("mac_compare::verify_early_exit_opaque")
        );
        assert_eq!(error.auxiliary_stacks.len(), 1);
        assert_eq!(error.auxiliary_stacks[0].frames.len(), 2);
        assert_eq!(error.origin_frames().len(), 2);
    }

    /// Attribution ignores the origin stack. The origin names where the secret
    /// was *marked* — the harness — so matching it would blame the wrong
    /// function for the finding.
    #[test]
    fn attribution_ignores_the_origin_stack() {
        let run = parse(SECRET_BRANCH).unwrap();
        let error = &run.errors[0];
        assert!(error.attributable_to("verify_early_exit_opaque"));
        assert!(
            !error.attributable_to("harness_setup"),
            "a function appearing only in the origin stack must not be attributed"
        );
        assert!(
            !error.attributable_to("new"),
            "Secret::new appears only in the origin stack"
        );
    }

    /// A client-request origin marks the finding as secret dependency.
    #[test]
    fn client_request_origin_is_secret_dependency() {
        let run = parse(SECRET_BRANCH).unwrap();
        assert_eq!(run.errors[0].origin, Origin::ClientRequest);
        assert_eq!(
            run.errors[0].classification,
            Classification::SecretDependentBranch
        );
        assert_eq!(run.secret_dependency_errors().count(), 1);
    }

    /// The same error kind from genuinely uninitialized heap memory is **not**
    /// a secret leak. Memcheck reports UninitCondition for ordinary bugs too.
    #[test]
    fn heap_origin_is_not_secret_dependency() {
        let xml = SECRET_BRANCH.replace(
            "Uninitialised value was created by a client request",
            "Uninitialised value was created by a heap allocation",
        );
        let run = parse(&xml).unwrap();
        let error = &run.errors[0];
        assert_eq!(error.origin, Origin::HeapAllocation);
        assert_eq!(
            error.classification,
            Classification::UnrelatedUndefinedValue
        );
        assert!(!error.classification.is_secret_dependency());
        assert_eq!(run.secret_dependency_errors().count(), 0);
        assert_eq!(run.unrelated_undefined_errors().count(), 1);
    }

    /// A stack-allocation origin is likewise not a secret leak.
    #[test]
    fn stack_origin_is_not_secret_dependency() {
        let xml = SECRET_BRANCH.replace(
            "Uninitialised value was created by a client request",
            "Uninitialised value was created by a stack allocation",
        );
        let run = parse(&xml).unwrap();
        assert_eq!(run.errors[0].origin, Origin::StackAllocation);
        assert_eq!(run.secret_dependency_errors().count(), 0);
    }

    /// With no origin reported we cannot tell marking from a real bug, so the
    /// finding is not claimed as secret dependency.
    #[test]
    fn absent_origin_is_not_claimed_as_secret_dependency() {
        let body = "<error><kind>UninitCondition</kind><what>w</what>\
                    <stack><frame><fn>f</fn></frame></stack></error>";
        let run = parse(&complete(body)).unwrap();
        assert_eq!(run.errors[0].origin, Origin::Unknown);
        assert_eq!(
            run.errors[0].classification,
            Classification::UnrelatedUndefinedValue
        );
        assert_eq!(run.secret_dependency_errors().count(), 0);
    }

    /// `UninitValue` from a client request is a secret-dependent value use,
    /// which is how a secret-dependent address is reported.
    #[test]
    fn uninit_value_from_marking_is_a_secret_dependent_value() {
        let xml = SECRET_BRANCH.replace("UninitCondition", "UninitValue");
        let run = parse(&xml).unwrap();
        assert_eq!(
            run.errors[0].classification,
            Classification::SecretDependentValue
        );
        assert!(run.errors[0].classification.is_secret_dependency());
    }

    /// Genuine memory errors are never secret dependency, whatever the origin.
    #[test]
    fn memory_errors_are_not_secret_dependency() {
        for kind in [
            "InvalidRead",
            "InvalidWrite",
            "InvalidFree",
            "MismatchedFree",
            "SyscallParam",
            "Leak_DefinitelyLost",
            "Leak_StillReachable",
        ] {
            let body = format!(
                "<error><kind>{kind}</kind><what>w</what>\
                 <stack><frame><fn>f</fn></frame></stack>\
                 <auxwhat>Uninitialised value was created by a client request</auxwhat>\
                 <stack><frame><fn>g</fn></frame></stack></error>"
            );
            let run = parse(&complete(&body)).unwrap();
            assert_eq!(
                run.errors[0].classification,
                Classification::MemoryError,
                "{kind}"
            );
            assert!(
                !run.errors[0].classification.is_secret_dependency(),
                "{kind}"
            );
        }
    }

    /// An unrecognized kind is retained as unclassified, never dropped and
    /// never assumed benign.
    #[test]
    fn unknown_kind_is_retained_as_unclassified() {
        let body = "<error><kind>SomeFutureKind</kind><what>w</what>\
                    <stack><frame><fn>f</fn></frame></stack></error>";
        let run = parse(&complete(body)).unwrap();
        assert_eq!(run.errors[0].classification, Classification::Unclassified);
        assert_eq!(run.unclassified_errors().count(), 1);
        assert_eq!(run.non_secret_errors().count(), 1);
    }

    /// Origin sentences are parsed case-insensitively, and an `auxwhat` that
    /// is not an origin sentence does not become one.
    #[test]
    fn origin_sentences_are_parsed_robustly() {
        assert_eq!(
            Origin::parse("Uninitialised value was created by a client request"),
            Origin::ClientRequest
        );
        assert_eq!(
            Origin::parse("uninitialised value WAS CREATED BY a heap allocation"),
            Origin::HeapAllocation
        );
        assert_eq!(
            Origin::parse("Uninitialised value was created by a stack allocation"),
            Origin::StackAllocation
        );
        assert!(matches!(
            Origin::parse("Address 0x1 is 4 bytes inside a block"),
            Origin::Other(_)
        ));
    }

    /// An error carrying a non-origin auxwhat plus a real origin sentence
    /// picks the origin, not the first auxwhat.
    #[test]
    fn origin_is_chosen_over_an_unrelated_auxwhat() {
        let body = "<error><kind>UninitValue</kind><what>w</what>\
                    <stack><frame><fn>f</fn></frame></stack>\
                    <auxwhat>Address 0x1 is 4 bytes inside a block</auxwhat>\
                    <stack><frame><fn>a</fn></frame></stack>\
                    <auxwhat>Uninitialised value was created by a client request</auxwhat>\
                    <stack><frame><fn>b</fn></frame></stack></error>";
        let run = parse(&complete(body)).unwrap();
        assert_eq!(run.errors[0].origin, Origin::ClientRequest);
        assert_eq!(run.errors[0].auxiliary_stacks.len(), 2);
        assert!(run.errors[0].classification.is_secret_dependency());
    }

    /// The primary frame is the shallowest primary frame with a source
    /// location, never an origin frame.
    #[test]
    fn primary_frame_comes_from_the_primary_stack() {
        let run = parse(SECRET_BRANCH).unwrap();
        let frame = run.errors[0].primary_frame().unwrap();
        assert_eq!(frame.line, Some(70));
        assert_eq!(frame.file.as_deref(), Some("lib.rs"));
    }

    /// Generic suffixes in a frame name still match the plain function name.
    #[test]
    fn generic_frame_names_match() {
        assert!(frame_names_function("crate::module::f::<u8>", "f"));
        assert!(frame_names_function("f", "f"));
        assert!(!frame_names_function("crate::module::fg", "f"));
    }

    /// Frames beyond the attribution window do not attribute the finding.
    #[test]
    fn frames_past_the_attribution_window_do_not_attribute() {
        let mut body = String::from("<error><kind>UninitCondition</kind><what>w</what><stack>");
        for index in 0..ATTRIBUTION_DEPTH {
            body.push_str(&format!("<frame><fn>filler{index}</fn></frame>"));
        }
        body.push_str("<frame><fn>target_function</fn></frame></stack></error>");
        let run = parse(&complete(&body)).unwrap();
        assert!(!run.errors[0].attributable_to("target_function"));
    }

    /// Multiple errors are retained in document order, each with its own
    /// stacks and origin.
    #[test]
    fn parses_multiple_errors_independently() {
        let body = "<error><kind>UninitCondition</kind><what>a</what>\
                    <stack><frame><fn>f</fn></frame></stack>\
                    <auxwhat>Uninitialised value was created by a client request</auxwhat>\
                    <stack><frame><fn>mark</fn></frame></stack></error>\
                    <error><kind>InvalidRead</kind><what>b</what>\
                    <stack><frame><fn>g</fn></frame></stack></error>";
        let run = parse(&complete(body)).unwrap();
        assert_eq!(run.errors.len(), 2);
        assert_eq!(run.secret_dependency_errors().count(), 1);
        assert_eq!(run.memory_errors().count(), 1);
        assert_eq!(run.errors[0].origin, Origin::ClientRequest);
        assert_eq!(run.errors[1].origin, Origin::Unknown);
        assert!(run.errors[1].auxiliary_stacks.is_empty());
    }

    /// Every documented protocol version is accepted.
    #[test]
    fn documented_protocol_versions_are_accepted() {
        for version in SUPPORTED_PROTOCOL_VERSIONS {
            let xml = SECRET_BRANCH.replace(
                "<protocolversion>6</protocolversion>",
                &format!("<protocolversion>{version}</protocolversion>"),
            );
            assert!(parse(&xml).is_ok(), "version {version} should parse");
        }
    }

    /// An unsupported protocol version is refused rather than guessed at.
    #[test]
    fn unsupported_protocol_version_is_refused() {
        let xml = SECRET_BRANCH.replace(
            "<protocolversion>6</protocolversion>",
            "<protocolversion>99</protocolversion>",
        );
        assert!(matches!(
            parse(&xml),
            Err(MemcheckParseError::UnsupportedProtocol { .. })
        ));
    }

    /// A complete clean run parses to zero errors rather than failing.
    #[test]
    fn parses_a_clean_run() {
        assert!(parse(&complete("")).unwrap().errors.is_empty());
    }

    /// XML cut mid-tag is rejected.
    #[test]
    fn xml_cut_mid_tag_is_rejected() {
        assert!(parse(&SECRET_BRANCH[..SECRET_BRANCH.len() / 2]).is_err());
    }

    /// A document cut at a clean element boundary — well-formed as far as it
    /// goes — must still be rejected. This is the dangerous shape: it has a
    /// root and a protocol version, so a parser that only checks those would
    /// report zero errors and the backend would call it NO_LEAK_OBSERVED.
    #[test]
    fn xml_cut_at_an_element_boundary_is_rejected() {
        let truncated = "<valgrindoutput>\n  <protocolversion>6</protocolversion>\n";
        let error = parse(truncated).expect_err("an unclosed document must be rejected");
        assert!(
            matches!(error, MemcheckParseError::Truncated(_)),
            "expected Truncated, got {error}"
        );
    }

    /// A document truncated immediately before `</valgrindoutput>` is
    /// rejected, even though every inner element closed and an error parsed.
    #[test]
    fn xml_truncated_before_the_root_close_is_rejected() {
        let truncated = SECRET_BRANCH
            .rsplit_once("</valgrindoutput>")
            .expect("fixture closes its root")
            .0;
        let error = parse(truncated).expect_err("a missing root close must be rejected");
        assert!(
            matches!(
                error,
                MemcheckParseError::Truncated(_) | MemcheckParseError::NotFinished
            ),
            "expected Truncated or NotFinished, got {error}"
        );
    }

    /// An `<error>` element left open is reported as truncation, never as a
    /// shorter error list.
    #[test]
    fn unfinished_error_element_is_rejected() {
        let xml = "<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>\
                   <error><kind>UninitCondition</kind>";
        match parse(xml).expect_err("an unclosed <error> must be rejected") {
            MemcheckParseError::Truncated(detail) => {
                assert!(detail.contains("UninitCondition"), "{detail}");
            }
            other => panic!("expected Truncated, got {other}"),
        }
    }

    /// An unclosed `<frame>` is reported as truncation.
    #[test]
    fn unfinished_frame_element_is_rejected() {
        let xml = "<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>\
                   <error><kind>UninitCondition</kind><what>w</what><stack><frame><fn>f</fn>";
        assert!(matches!(parse(xml), Err(MemcheckParseError::Truncated(_))));
    }

    /// An unclosed `<stack>` is reported as truncation, so a partially read
    /// stack cannot silently shorten the attribution window.
    #[test]
    fn unfinished_stack_element_is_rejected() {
        let xml = "<valgrindoutput><protocolversion>6</protocolversion><tool>memcheck</tool>\
                   <error><kind>UninitCondition</kind><what>w</what><stack>\
                   <frame><fn>f</fn></frame>";
        assert!(matches!(parse(xml), Err(MemcheckParseError::Truncated(_))));
    }

    /// Valgrind never reporting FINISHED means the run was killed or crashed.
    #[test]
    fn missing_finished_status_is_rejected() {
        let xml = SECRET_BRANCH.replace("<status><state>FINISHED</state></status>", "");
        assert!(matches!(parse(&xml), Err(MemcheckParseError::NotFinished)));
    }

    /// A RUNNING status alone is not completion.
    #[test]
    fn running_status_alone_is_not_finished() {
        let xml = SECRET_BRANCH.replace(
            "<status><state>FINISHED</state></status>",
            "<status><state>RUNNING</state></status>",
        );
        assert!(matches!(parse(&xml), Err(MemcheckParseError::NotFinished)));
    }

    /// Output from another Valgrind tool is refused.
    #[test]
    fn other_valgrind_tools_are_refused() {
        let xml = SECRET_BRANCH.replace("<tool>memcheck</tool>", "<tool>helgrind</tool>");
        match parse(&xml) {
            Err(MemcheckParseError::WrongTool { found }) => assert_eq!(found, "helgrind"),
            other => panic!("expected WrongTool, got {other:?}"),
        }
    }

    /// A document with no <tool> element is refused rather than assumed.
    #[test]
    fn absent_tool_element_is_refused() {
        let xml = SECRET_BRANCH.replace("<tool>memcheck</tool>", "");
        assert!(matches!(
            parse(&xml),
            Err(MemcheckParseError::WrongTool { .. })
        ));
    }

    /// A missing protocol version is refused rather than defaulted.
    #[test]
    fn absent_protocol_version_is_refused() {
        let xml = SECRET_BRANCH.replace("<protocolversion>6</protocolversion>", "");
        assert!(matches!(
            parse(&xml),
            Err(MemcheckParseError::MissingProtocolVersion)
        ));
    }

    /// Output that is not Valgrind XML at all is rejected.
    #[test]
    fn non_valgrind_output_is_rejected() {
        assert!(matches!(
            parse("valgrind: command not found"),
            Err(MemcheckParseError::MissingRoot)
        ));
    }
}
