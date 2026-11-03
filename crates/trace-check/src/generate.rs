//! Deterministic typed input generation for a declared contract.
//!
//! The generator turns a [`Descriptor`] — the parameter names, roles and
//! representations `#[constant_time]` already emits — into an ordered corpus of
//! concrete cases. It knows nothing about Valgrind, Memcheck or BINSEC: the
//! corpus is a value, and the backend that consumes it is someone else's
//! problem.
//!
//! # Determinism is a reporting requirement, not a convenience
//!
//! A finding is only useful if the run that produced it can be repeated, so the
//! corpus is a pure function of (descriptor, seed, budget, strategies). The RNG
//! is a small splitmix64 implemented here rather than pulled from a crate,
//! because a dependency bump that changed a value sequence would silently
//! invalidate every recorded seed.
//!
//! # Budgets are spent in a deliberate order, and truncation is reported
//!
//! Boundary cases first, then pairwise combinations of parameters, then seeded
//! random fill. A strategy that does not fit the budget is recorded in
//! [`StrategyCoverage`] with its planned and emitted counts, so a report can
//! say what was dropped. Silently emitting fewer cases than asked for would
//! make "128 cases completed" mean nothing.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::contract::{Descriptor, Parameter, Repr};

/// Corpus schema this build emits and understands.
pub const CORPUS_SCHEMA_VERSION: u32 = 1;

/// Default number of cases when a contract names no budget.
pub const DEFAULT_CASES: usize = 64;

/// Default seed, so an unconfigured run is still reproducible.
pub const DEFAULT_SEED: u64 = 0x7472_6163_655f_636b;

/// How a case was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strategy {
    /// Zero, one, maxima, powers of two, and the values either side of them.
    Boundaries,
    /// Combinations of two parameters' boundary values, with the rest at their
    /// base value.
    Pairwise,
    /// Seeded pseudorandom values for every parameter.
    Random,
    /// Declared relationships between two equal-length byte arrays.
    Relationships,
    /// Replayed from a persisted failure.
    Regression,
}

impl Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Strategy::Boundaries => "boundaries",
            Strategy::Pairwise => "pairwise",
            Strategy::Random => "random",
            Strategy::Relationships => "relationships",
            Strategy::Regression => "regression",
        }
    }

    /// The strategies a run uses when a contract names none.
    pub fn defaults() -> Vec<Strategy> {
        vec![Strategy::Boundaries, Strategy::Pairwise, Strategy::Random]
    }
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One concrete parameter value.
///
/// Carries its own width so the wire form is self-describing and the generated
/// harness can refuse a value whose shape does not match the parameter it is
/// about to be bound to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(tag = "repr", rename_all = "kebab-case")]
pub enum Value {
    Scalar { bits: u32, value: u64 },
    Bool { value: bool },
    Bytes { bytes: Vec<u8> },
}

impl Value {
    /// The wire encoding the generated harness parses: a tag, a colon, and a
    /// payload with no whitespace.
    pub fn to_wire(&self) -> String {
        match self {
            Value::Scalar { value, .. } => format!("s:{value}"),
            Value::Bool { value } => format!("b:{}", u8::from(*value)),
            Value::Bytes { bytes } => {
                let mut out = String::with_capacity(2 + bytes.len() * 2);
                out.push_str("x:");
                for byte in bytes {
                    out.push_str(&format!("{byte:02x}"));
                }
                out
            }
        }
    }

    /// Whether this value can be bound to a parameter of `repr`.
    ///
    /// Checked at generation time *and* again in the harness. A width mismatch
    /// would otherwise mark a different number of bytes than the contract
    /// declares, which is the failure mode that makes a clean result a lie.
    pub fn fits(&self, repr: &Repr) -> bool {
        match (self, repr) {
            (Value::Scalar { bits, .. }, Repr::Scalar(width)) => bits == width,
            (Value::Bool { .. }, Repr::Bool) => true,
            (Value::Bytes { bytes }, Repr::ByteArray(length) | Repr::RefByteArray(length)) => {
                bytes.len() as u64 == *length
            }
            _ => false,
        }
    }

    /// Human rendering for reports and reproducers.
    pub fn describe(&self) -> String {
        match self {
            Value::Scalar { value, .. } => value.to_string(),
            Value::Bool { value } => value.to_string(),
            Value::Bytes { bytes } => {
                let mut out = String::from("0x");
                for byte in bytes {
                    out.push_str(&format!("{byte:02x}"));
                }
                out
            }
        }
    }
}

/// One generated case: a value per declared parameter, in declared order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct GeneratedCase {
    pub id: usize,
    pub strategy: Strategy,
    /// Parameter name and value, in the descriptor's positional order.
    pub inputs: Vec<(String, Value)>,
}

impl GeneratedCase {
    /// `<id> <strategy> <value>...`, positional, one line, no whitespace inside
    /// a field.
    fn to_wire(&self) -> String {
        let mut line = format!("{} {}", self.id, self.strategy.as_str());
        for (_, value) in &self.inputs {
            line.push(' ');
            line.push_str(&value.to_wire());
        }
        line
    }

    /// Identity used to deduplicate, which ignores the id and the strategy: two
    /// strategies that happen to produce the same inputs are one case.
    fn key(&self) -> String {
        self.inputs
            .iter()
            .map(|(_, value)| value.to_wire())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What one strategy was asked for and what it actually contributed.
///
/// Both numbers are reported. `emitted < planned` means the budget ran out or
/// the cases collided with ones already present, and a reader is entitled to
/// know which.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StrategyCoverage {
    pub strategy: Strategy,
    pub planned: usize,
    pub emitted: usize,
}

impl StrategyCoverage {
    pub fn complete(&self) -> bool {
        self.emitted >= self.planned
    }
}

/// A generated corpus, with everything needed to reproduce it.
#[derive(Debug, Clone, Serialize)]
pub struct Corpus {
    pub schema_version: u32,
    pub contract: String,
    pub seed: u64,
    /// Case budget this corpus was generated under.
    pub budget: usize,
    pub strategies_requested: Vec<Strategy>,
    pub coverage: Vec<StrategyCoverage>,
    pub cases: Vec<GeneratedCase>,
}

impl Corpus {
    /// The form the generated harness reads. Line-oriented and dependency-free
    /// on purpose: the harness parses it with a few lines of generated code
    /// rather than linking a deserializer.
    pub fn to_wire(&self) -> String {
        let mut out = format!(
            "# trace-check corpus v{} contract={} seed={} cases={}\n",
            self.schema_version,
            self.contract,
            self.seed,
            self.cases.len()
        );
        for case in &self.cases {
            out.push_str(&case.to_wire());
            out.push('\n');
        }
        out
    }

    /// Hash of the wire form, which is what the harness actually consumed.
    pub fn sha256(&self) -> String {
        format!("{:x}", Sha256::digest(self.to_wire().as_bytes()))
    }

    /// Strategies that contributed at least one case.
    pub fn strategies_exercised(&self) -> Vec<Strategy> {
        let mut seen: Vec<Strategy> = self
            .coverage
            .iter()
            .filter(|entry| entry.emitted > 0)
            .map(|entry| entry.strategy)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    }

    /// Strategies that were requested but could not be completed within the
    /// budget, so a report can name them instead of implying full coverage.
    pub fn truncated(&self) -> Vec<&StrategyCoverage> {
        self.coverage
            .iter()
            .filter(|entry| !entry.complete())
            .collect()
    }

    pub fn case(&self, id: usize) -> Option<&GeneratedCase> {
        self.cases.iter().find(|case| case.id == id)
    }
}

/// Settings a contract may state for generation.
#[derive(Debug, Clone)]
pub struct GenerateSettings {
    pub cases: usize,
    pub seed: u64,
    pub strategies: Vec<Strategy>,
    /// Declared relationships between byte-array parameters.
    pub relationships: Vec<Relationship>,
    /// Cases replayed ahead of generation, from persisted failures.
    pub regressions: Vec<Vec<(String, Value)>>,
}

impl Default for GenerateSettings {
    fn default() -> Self {
        GenerateSettings {
            cases: DEFAULT_CASES,
            seed: DEFAULT_SEED,
            strategies: Strategy::defaults(),
            relationships: Vec::new(),
            regressions: Vec::new(),
        }
    }
}

/// A declared relationship between two equal-length byte-array parameters.
///
/// Opt-in and narrow by design. Uniform random generation is close to useless
/// for a tag comparison — two random 16-byte arrays essentially never share a
/// prefix — so the interesting pairs have to be asked for. Nothing here infers
/// a relationship from a function's name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub left: String,
    pub right: String,
    pub kind: RelationshipKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationshipKind {
    /// Byte-for-byte equal.
    Equal,
    /// Equal but for the first byte.
    DifferFirstByte,
    /// Equal but for the last byte.
    DifferLastByte,
    /// Equal but for one bit of one byte.
    DifferOneBit,
    /// Equal for the first half, then divergent.
    SharePrefix,
}

impl RelationshipKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RelationshipKind::Equal => "equal",
            RelationshipKind::DifferFirstByte => "differ-first-byte",
            RelationshipKind::DifferLastByte => "differ-last-byte",
            RelationshipKind::DifferOneBit => "differ-one-bit",
            RelationshipKind::SharePrefix => "share-prefix",
        }
    }

    pub fn all() -> [RelationshipKind; 5] {
        [
            RelationshipKind::Equal,
            RelationshipKind::DifferFirstByte,
            RelationshipKind::DifferLastByte,
            RelationshipKind::DifferOneBit,
            RelationshipKind::SharePrefix,
        ]
    }
}

#[derive(Debug)]
pub enum GenerateError {
    /// A parameter the symbolic representation cannot describe concretely.
    UnsupportedParameter { parameter: String, repr: String },
    /// The budget cannot cover even one case per parameter boundary.
    BudgetTooSmall { requested: usize, minimum: usize },
    /// A relationship named a parameter that does not exist or is not a byte
    /// array of matching length.
    Relationship { detail: String },
    /// A replayed case does not match the contract it is replayed against.
    Regression { detail: String },
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerateError::UnsupportedParameter { parameter, repr } => write!(
                f,
                "parameter `{parameter}` has representation `{repr}`, for which no concrete \
                 values can be generated. Supported: u8/u16/u32/u64, `bool`, and `[u8; N]` or \
                 `&[u8; N]` with a literal N"
            ),
            GenerateError::BudgetTooSmall { requested, minimum } => write!(
                f,
                "a budget of {requested} case(s) cannot cover this contract's boundary values; \
                 it needs at least {minimum}. Raise `cases`, because a run that silently skips \
                 the boundaries is not the run that was asked for"
            ),
            GenerateError::Relationship { detail } => {
                write!(f, "invalid input relationship: {detail}")
            }
            GenerateError::Regression { detail } => {
                write!(f, "a replayed case does not fit this contract: {detail}")
            }
        }
    }
}

impl std::error::Error for GenerateError {}

/// splitmix64. Implemented here so a dependency bump cannot change what a
/// recorded seed means.
struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
}

/// Masks a value to a parameter's width, so a generated value is always a valid
/// inhabitant of its declared type.
fn mask(value: u64, bits: u32) -> u64 {
    if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    }
}

/// Boundary values for one parameter, most interesting first and deduplicated.
fn boundaries(parameter: &Parameter) -> Result<Vec<Value>, GenerateError> {
    // Reports the type *as written*, not the internal representation name: a
    // developer has to find `&[u8]` in their signature, not the word
    // "unsupported".
    let unsupported = || GenerateError::UnsupportedParameter {
        parameter: parameter.name.clone(),
        repr: if parameter.rust_type.is_empty() {
            parameter.repr.describe()
        } else {
            parameter.rust_type.clone()
        },
    };
    match &parameter.repr {
        Repr::Scalar(bits) => {
            let bits = *bits;
            let mut raw: Vec<u64> = vec![0, 1, mask(u64::MAX, bits)];
            // Powers of two and their neighbours: the shapes a comparison,
            // a shift or a carry changes behaviour around.
            let mut power = 1u64;
            while power.leading_zeros() + 1 > 64 - bits {
                raw.push(mask(power, bits));
                raw.push(mask(power.wrapping_sub(1), bits));
                raw.push(mask(power.wrapping_add(1), bits));
                let Some(next) = power.checked_mul(2) else {
                    break;
                };
                power = next;
            }
            // The high bit set alone, which is where a sign-dependent
            // implementation changes direction.
            raw.push(mask(1u64 << (bits - 1), bits));
            Ok(dedup_scalars(raw, bits))
        }
        Repr::Bool => Ok(vec![
            Value::Bool { value: false },
            Value::Bool { value: true },
        ]),
        Repr::ByteArray(length) | Repr::RefByteArray(length) => {
            let n = *length as usize;
            if n == 0 {
                return Err(unsupported());
            }
            let mut patterns: Vec<Vec<u8>> = vec![
                vec![0x00; n],
                vec![0xff; n],
                // Alternating, both phases: catches a half-word comparison
                // that only looks at one of them.
                (0..n)
                    .map(|i| if i % 2 == 0 { 0xaa } else { 0x55 })
                    .collect(),
                (0..n)
                    .map(|i| if i % 2 == 0 { 0x55 } else { 0xaa })
                    .collect(),
            ];
            // One-hot in the first and last byte. The last-byte pattern is the
            // one that catches a harness marking fewer bytes than the contract
            // declares.
            let mut first = vec![0x00; n];
            first[0] = 0x01;
            patterns.push(first);
            let mut last = vec![0x00; n];
            last[n - 1] = 0x01;
            patterns.push(last);
            // Walking bit through the first byte, bounded so a long array does
            // not spend the whole budget here.
            for bit in 1..8u32 {
                let mut walking = vec![0x00; n];
                walking[0] = 1u8 << bit;
                patterns.push(walking);
            }
            Ok(dedup_bytes(patterns))
        }
        Repr::Unit | Repr::Unsupported => Err(unsupported()),
    }
}

fn dedup_scalars(raw: Vec<u64>, bits: u32) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    raw.into_iter()
        .map(|value| mask(value, bits))
        .filter(|value| seen.insert(*value))
        .map(|value| Value::Scalar { bits, value })
        .collect()
}

fn dedup_bytes(raw: Vec<Vec<u8>>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    raw.into_iter()
        .filter(|bytes| seen.insert(bytes.clone()))
        .map(|bytes| Value::Bytes { bytes })
        .collect()
}

/// A seeded random value for one parameter.
fn random_value(parameter: &Parameter, rng: &mut Rng) -> Result<Value, GenerateError> {
    match &parameter.repr {
        Repr::Scalar(bits) => Ok(Value::Scalar {
            bits: *bits,
            value: mask(rng.next_u64(), *bits),
        }),
        Repr::Bool => Ok(Value::Bool {
            value: rng.next_u8() & 1 == 1,
        }),
        Repr::ByteArray(length) | Repr::RefByteArray(length) => Ok(Value::Bytes {
            bytes: (0..*length).map(|_| rng.next_u8()).collect(),
        }),
        Repr::Unit | Repr::Unsupported => Err(GenerateError::UnsupportedParameter {
            parameter: parameter.name.clone(),
            repr: if parameter.rust_type.is_empty() {
                parameter.repr.describe()
            } else {
                parameter.rust_type.clone()
            },
        }),
    }
}

/// Accumulates cases, enforcing the budget and deduplicating.
struct Builder<'a> {
    parameters: &'a [Parameter],
    budget: usize,
    cases: Vec<GeneratedCase>,
    seen: BTreeSet<String>,
    coverage: Vec<StrategyCoverage>,
}

impl<'a> Builder<'a> {
    fn new(parameters: &'a [Parameter], budget: usize) -> Builder<'a> {
        Builder {
            parameters,
            budget,
            cases: Vec::new(),
            seen: BTreeSet::new(),
            coverage: Vec::new(),
        }
    }

    fn full(&self) -> bool {
        self.cases.len() >= self.budget
    }

    /// Adds a case unless it duplicates one already present or the budget is
    /// spent. Returns whether it was added.
    fn push(&mut self, strategy: Strategy, values: Vec<Value>) -> bool {
        if self.full() {
            return false;
        }
        let inputs: Vec<(String, Value)> = self
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone())
            .zip(values)
            .collect();
        let case = GeneratedCase {
            id: self.cases.len(),
            strategy,
            inputs,
        };
        if !self.seen.insert(case.key()) {
            return false;
        }
        self.cases.push(case);
        true
    }

    fn record(&mut self, strategy: Strategy, planned: usize, emitted: usize) {
        self.coverage.push(StrategyCoverage {
            strategy,
            planned,
            emitted,
        });
    }
}

/// Generates the corpus for one contract.
///
/// The returned corpus is a pure function of its arguments; see the module
/// documentation for why that matters.
pub fn generate(
    contract: &str,
    descriptor: &Descriptor,
    settings: &GenerateSettings,
) -> Result<Corpus, GenerateError> {
    let parameters = &descriptor.parameters;
    let per_parameter: Vec<Vec<Value>> = parameters
        .iter()
        .map(boundaries)
        .collect::<Result<_, _>>()?;
    // The base case: every parameter at its first boundary value. One-at-a-time
    // coverage varies a single parameter away from this.
    let base: Vec<Value> = per_parameter
        .iter()
        .map(|values| values[0].clone())
        .collect();

    let minimum = per_parameter.iter().map(Vec::len).max().unwrap_or(1);
    if settings.cases < minimum {
        return Err(GenerateError::BudgetTooSmall {
            requested: settings.cases,
            minimum,
        });
    }

    let mut builder = Builder::new(parameters, settings.cases);
    let mut rng = Rng::new(settings.seed);

    // Stage 4 first: a known failure is worth more than a new guess, so
    // persisted regressions are replayed ahead of generation and can never be
    // crowded out by the budget.
    let planned = settings.regressions.len();
    let mut emitted = 0;
    for replayed in &settings.regressions {
        let values = align_regression(parameters, replayed)?;
        if builder.push(Strategy::Regression, values) {
            emitted += 1;
        }
    }
    if planned > 0 {
        builder.record(Strategy::Regression, planned, emitted);
    }

    for strategy in &settings.strategies {
        match strategy {
            Strategy::Boundaries => {
                let planned: usize = per_parameter.iter().map(Vec::len).sum();
                let mut emitted = 0;
                for (index, values) in per_parameter.iter().enumerate() {
                    for value in values {
                        let mut case = base.clone();
                        case[index] = value.clone();
                        if builder.push(Strategy::Boundaries, case) {
                            emitted += 1;
                        }
                    }
                }
                builder.record(Strategy::Boundaries, planned, emitted);
            }
            Strategy::Pairwise => {
                let mut planned = 0;
                let mut emitted = 0;
                for first in 0..parameters.len() {
                    for second in (first + 1)..parameters.len() {
                        for left in &per_parameter[first] {
                            for right in &per_parameter[second] {
                                planned += 1;
                                let mut case = base.clone();
                                case[first] = left.clone();
                                case[second] = right.clone();
                                if builder.push(Strategy::Pairwise, case) {
                                    emitted += 1;
                                }
                            }
                        }
                    }
                }
                builder.record(Strategy::Pairwise, planned, emitted);
            }
            Strategy::Relationships => {
                let planned = settings.relationships.len() * RelationshipKind::all().len();
                let mut emitted = 0;
                for relationship in &settings.relationships {
                    let (left, right) = relationship_positions(parameters, relationship)?;
                    let length = match &parameters[left].repr {
                        Repr::ByteArray(length) | Repr::RefByteArray(length) => *length as usize,
                        _ => unreachable!("validated by relationship_positions"),
                    };
                    for seed_pattern in &per_parameter[left] {
                        let Value::Bytes { bytes } = seed_pattern else {
                            continue;
                        };
                        let partner = related(relationship.kind, bytes, length);
                        let mut case = base.clone();
                        case[left] = Value::Bytes {
                            bytes: bytes.clone(),
                        };
                        case[right] = Value::Bytes { bytes: partner };
                        if builder.push(Strategy::Relationships, case) {
                            emitted += 1;
                        }
                    }
                }
                builder.record(Strategy::Relationships, planned, emitted);
            }
            Strategy::Random => {
                // Random fills whatever the budget has left, so it is the one
                // strategy whose plan is defined by the remainder.
                let planned = settings.cases.saturating_sub(builder.cases.len());
                let mut emitted = 0;
                // Bounded attempts: a tiny domain such as a single `bool`
                // exhausts its distinct values quickly, and retrying forever
                // would hang rather than report.
                let mut attempts = 0;
                let limit = planned.saturating_mul(8).max(16);
                while !builder.full() && attempts < limit {
                    attempts += 1;
                    let values: Vec<Value> = parameters
                        .iter()
                        .map(|parameter| random_value(parameter, &mut rng))
                        .collect::<Result<_, _>>()?;
                    if builder.push(Strategy::Random, values) {
                        emitted += 1;
                    }
                }
                builder.record(Strategy::Random, planned, emitted);
            }
            Strategy::Regression => {
                // Replayed above, ahead of every generated strategy.
            }
        }
    }

    Ok(Corpus {
        schema_version: CORPUS_SCHEMA_VERSION,
        contract: contract.to_string(),
        seed: settings.seed,
        budget: settings.cases,
        strategies_requested: settings.strategies.clone(),
        coverage: builder.coverage,
        cases: builder.cases,
    })
}

/// Derives the partner of a byte pattern under one relationship.
fn related(kind: RelationshipKind, bytes: &[u8], length: usize) -> Vec<u8> {
    let mut partner = bytes.to_vec();
    match kind {
        RelationshipKind::Equal => {}
        RelationshipKind::DifferFirstByte => partner[0] ^= 0xff,
        RelationshipKind::DifferLastByte => partner[length - 1] ^= 0xff,
        RelationshipKind::DifferOneBit => partner[0] ^= 0x01,
        RelationshipKind::SharePrefix => {
            for byte in partner.iter_mut().skip(length / 2) {
                *byte ^= 0xff;
            }
        }
    }
    partner
}

/// Resolves a relationship's two parameters, rejecting anything the derivation
/// could not be applied to.
fn relationship_positions(
    parameters: &[Parameter],
    relationship: &Relationship,
) -> Result<(usize, usize), GenerateError> {
    let find = |name: &str| {
        parameters
            .iter()
            .position(|parameter| parameter.name == name)
            .ok_or_else(|| GenerateError::Relationship {
                detail: format!(
                    "`{name}` is not a parameter of this contract. Declared: {}",
                    parameters
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            })
    };
    let left = find(&relationship.left)?;
    let right = find(&relationship.right)?;
    if left == right {
        return Err(GenerateError::Relationship {
            detail: format!(
                "`{}` is related to itself, which states nothing",
                relationship.left
            ),
        });
    }
    let width = |index: usize| match &parameters[index].repr {
        Repr::ByteArray(length) | Repr::RefByteArray(length) => Some(*length),
        _ => None,
    };
    let (Some(left_width), Some(right_width)) = (width(left), width(right)) else {
        return Err(GenerateError::Relationship {
            detail: format!(
                "`{}` and `{}` must both be fixed-size byte arrays; a relationship between \
                 other shapes is not modeled",
                relationship.left, relationship.right
            ),
        });
    };
    if left_width != right_width {
        return Err(GenerateError::Relationship {
            detail: format!(
                "`{}` is {left_width} bytes and `{}` is {right_width}; a relationship needs \
                 equal lengths",
                relationship.left, relationship.right
            ),
        });
    }
    if left_width == 0 {
        return Err(GenerateError::Relationship {
            detail: "a zero-length array has no bytes to relate".to_string(),
        });
    }
    Ok((left, right))
}

/// Checks a replayed case against the contract and puts its values back into
/// declared order.
fn align_regression(
    parameters: &[Parameter],
    replayed: &[(String, Value)],
) -> Result<Vec<Value>, GenerateError> {
    if replayed.len() != parameters.len() {
        return Err(GenerateError::Regression {
            detail: format!(
                "it names {} input(s) but the contract declares {}",
                replayed.len(),
                parameters.len()
            ),
        });
    }
    let mut values = Vec::with_capacity(parameters.len());
    for parameter in parameters {
        let Some((_, value)) = replayed.iter().find(|(name, _)| *name == parameter.name) else {
            return Err(GenerateError::Regression {
                detail: format!("it has no value for `{}`", parameter.name),
            });
        };
        if !value.fits(&parameter.repr) {
            return Err(GenerateError::Regression {
                detail: format!(
                    "its value for `{}` does not fit `{}`",
                    parameter.name,
                    parameter.repr.describe()
                ),
            });
        }
        values.push(value.clone());
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `substitute_mode(index: u8 secret, mode: u8 public)`, the contract whose
    /// leak hides behind a public mode.
    const SUBSTITUTE_MODE: &str = r#"{"schema_version":1,"function":"substitute_mode","parameters":[
        {"name":"index","position":0,"role":"secret","repr":"u8","rust_type":"u8"},
        {"name":"mode","position":1,"role":"public","repr":"u8","rust_type":"u8"}],
        "returns":{"repr":"u8","rust_type":"u8"}}"#;

    /// `verify_tag(expected: &[u8; 16] secret, supplied: &[u8; 16] public)`.
    const VERIFY_TAG: &str = r#"{"schema_version":1,"function":"verify_tag","parameters":[
        {"name":"expected","position":0,"role":"secret","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"},
        {"name":"supplied","position":1,"role":"public","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"}],
        "returns":{"repr":"bool","rust_type":"bool"}}"#;

    fn descriptor(json: &str) -> Descriptor {
        Descriptor::parse(json).expect("parses")
    }

    /// The same seed and settings produce a byte-identical corpus, which is
    /// what makes a recorded seed a reproduction instruction.
    #[test]
    fn the_same_seed_reproduces_the_corpus() {
        let descriptor = descriptor(SUBSTITUTE_MODE);
        let settings = GenerateSettings::default();
        let first = generate("c::substitute_mode", &descriptor, &settings).unwrap();
        let second = generate("c::substitute_mode", &descriptor, &settings).unwrap();
        assert_eq!(first.to_wire(), second.to_wire());
        assert_eq!(first.sha256(), second.sha256());
    }

    /// A different seed changes the random cases, so the seed is doing
    /// something.
    #[test]
    fn a_different_seed_changes_the_corpus() {
        let descriptor = descriptor(VERIFY_TAG);
        let mut settings = GenerateSettings::default();
        let first = generate("c::verify_tag", &descriptor, &settings).unwrap();
        settings.seed += 1;
        let second = generate("c::verify_tag", &descriptor, &settings).unwrap();
        assert_ne!(first.sha256(), second.sha256());
    }

    /// The milestone's headline requirement: generation reaches the public mode
    /// that hides the leak, without anyone naming it.
    #[test]
    fn generation_reaches_the_hidden_public_mode() {
        let corpus = generate(
            "c::substitute_mode",
            &descriptor(SUBSTITUTE_MODE),
            &GenerateSettings::default(),
        )
        .unwrap();
        let reaches_mode_one = corpus.cases.iter().any(|case| {
            matches!(case.inputs[1].1, Value::Scalar { value: 1, .. })
                && !matches!(case.inputs[0].1, Value::Scalar { value: 0, .. })
        });
        assert!(
            reaches_mode_one,
            "no case pairs a non-zero secret index with mode = 1: {:#?}",
            corpus.cases
        );
    }

    /// Every parameter's boundary values all appear somewhere in the corpus.
    #[test]
    fn every_boundary_value_of_every_parameter_is_covered() {
        let descriptor = descriptor(SUBSTITUTE_MODE);
        let corpus = generate(
            "c::substitute_mode",
            &descriptor,
            &GenerateSettings::default(),
        )
        .unwrap();
        for (position, parameter) in descriptor.parameters.iter().enumerate() {
            for expected in boundaries(parameter).unwrap() {
                assert!(
                    corpus
                        .cases
                        .iter()
                        .any(|case| case.inputs[position].1 == expected),
                    "`{}` never takes {}",
                    parameter.name,
                    expected.describe()
                );
            }
        }
    }

    /// Scalar boundaries include zero, one, the maximum and the lone high bit.
    #[test]
    fn scalar_boundaries_include_the_interesting_values() {
        let descriptor = descriptor(SUBSTITUTE_MODE);
        let values: Vec<u64> = boundaries(&descriptor.parameters[0])
            .unwrap()
            .into_iter()
            .map(|value| match value {
                Value::Scalar { value, .. } => value,
                other => panic!("expected a scalar, got {other:?}"),
            })
            .collect();
        for expected in [0, 1, 2, 3, 0x80, 0xff] {
            assert!(values.contains(&expected), "missing {expected}: {values:?}");
        }
        // Nothing wider than the declared type.
        assert!(values.iter().all(|value| *value <= 0xff));
    }

    /// A `u32` parameter gets values around its arithmetic boundaries, all
    /// within its width.
    #[test]
    fn wide_scalars_stay_inside_their_width() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"value","position":0,"role":"secret","repr":"u32","rust_type":"u32"}],
            "returns":{"repr":"u32","rust_type":"u32"}}"#;
        let descriptor = descriptor(json);
        let values: Vec<u64> = boundaries(&descriptor.parameters[0])
            .unwrap()
            .into_iter()
            .map(|value| match value {
                Value::Scalar { value, .. } => value,
                other => panic!("expected a scalar, got {other:?}"),
            })
            .collect();
        assert!(values.contains(&0x8000_0000), "the high bit: {values:?}");
        assert!(values.contains(&0xffff_ffff), "the maximum: {values:?}");
        assert!(values.iter().all(|value| *value <= 0xffff_ffff));
    }

    /// Byte-array boundaries include the all-zero, all-ones and last-byte-only
    /// patterns. The last of those is what catches a harness that marks fewer
    /// bytes than the contract declares.
    #[test]
    fn byte_array_boundaries_include_a_last_byte_pattern() {
        let descriptor = descriptor(VERIFY_TAG);
        let patterns: Vec<Vec<u8>> = boundaries(&descriptor.parameters[0])
            .unwrap()
            .into_iter()
            .map(|value| match value {
                Value::Bytes { bytes } => bytes,
                other => panic!("expected bytes, got {other:?}"),
            })
            .collect();
        assert!(patterns.contains(&vec![0x00; 16]));
        assert!(patterns.contains(&vec![0xff; 16]));
        let mut last = vec![0x00; 16];
        last[15] = 0x01;
        assert!(patterns.contains(&last), "{patterns:?}");
        // Every pattern is exactly the declared width.
        assert!(patterns.iter().all(|bytes| bytes.len() == 16));
    }

    /// A public `bool` gets both of its valid values and nothing else.
    #[test]
    fn a_bool_gets_both_values() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"secret","position":0,"role":"secret","repr":"u32","rust_type":"u32"},
            {"name":"enabled","position":1,"role":"public","repr":"bool","rust_type":"bool"}],
            "returns":{"repr":"u32","rust_type":"u32"}}"#;
        let descriptor = descriptor(json);
        let values = boundaries(&descriptor.parameters[1]).unwrap();
        assert_eq!(
            values,
            vec![Value::Bool { value: false }, Value::Bool { value: true }]
        );
    }

    /// Generated values always fit the parameter they will be bound to, so the
    /// harness cannot mark a different width than the contract declares.
    #[test]
    fn every_generated_value_fits_its_parameter() {
        let descriptor = descriptor(VERIFY_TAG);
        let corpus = generate("c::verify_tag", &descriptor, &GenerateSettings::default()).unwrap();
        for case in &corpus.cases {
            assert_eq!(case.inputs.len(), descriptor.parameters.len());
            for (parameter, (name, value)) in descriptor.parameters.iter().zip(&case.inputs) {
                assert_eq!(*name, parameter.name);
                assert!(
                    value.fits(&parameter.repr),
                    "{} does not fit {}",
                    value.describe(),
                    parameter.repr.describe()
                );
            }
        }
    }

    /// The budget is a hard cap, and cases are unique.
    #[test]
    fn the_budget_is_respected_and_cases_are_unique() {
        // 30 is above the boundary minimum for two `u8` parameters and below
        // what pairwise would want, so the cap is doing work.
        let settings = GenerateSettings {
            cases: 30,
            ..Default::default()
        };
        let corpus = generate(
            "c::substitute_mode",
            &descriptor(SUBSTITUTE_MODE),
            &settings,
        )
        .unwrap();
        assert!(corpus.cases.len() <= 30, "{}", corpus.cases.len());
        let mut keys: Vec<String> = corpus.cases.iter().map(|case| case.key()).collect();
        let before = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), before, "duplicate cases were emitted");
        // Ids are dense and ordered, which is what makes a reported case id
        // meaningful.
        for (index, case) in corpus.cases.iter().enumerate() {
            assert_eq!(case.id, index);
        }
    }

    /// A budget too small to cover the boundaries is refused rather than
    /// quietly skipping them.
    #[test]
    fn a_budget_that_cannot_cover_the_boundaries_is_refused() {
        let settings = GenerateSettings {
            cases: 2,
            ..Default::default()
        };
        let error =
            generate("c::verify_tag", &descriptor(VERIFY_TAG), &settings).expect_err("refused");
        assert!(
            matches!(error, GenerateError::BudgetTooSmall { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("at least"), "{error}");
    }

    /// Truncation is reported per strategy rather than hidden, so "64 cases
    /// completed" cannot imply coverage that was dropped.
    #[test]
    fn truncation_is_reported_per_strategy() {
        let descriptor = descriptor(VERIFY_TAG);
        let settings = GenerateSettings {
            cases: 15,
            ..Default::default()
        };
        let corpus = generate("c::verify_tag", &descriptor, &settings).unwrap();
        let truncated = corpus.truncated();
        assert!(
            !truncated.is_empty(),
            "pairwise cannot fit in 15 cases but nothing was reported truncated"
        );
        let pairwise = corpus
            .coverage
            .iter()
            .find(|entry| entry.strategy == Strategy::Pairwise)
            .expect("pairwise was requested, so it must be accounted for");
        assert!(pairwise.planned > pairwise.emitted);
        assert!(!pairwise.complete());
    }

    /// Every requested strategy is accounted for in the coverage report, even
    /// one that contributed nothing.
    #[test]
    fn every_requested_strategy_is_accounted_for() {
        let corpus = generate(
            "c::substitute_mode",
            &descriptor(SUBSTITUTE_MODE),
            &GenerateSettings::default(),
        )
        .unwrap();
        for strategy in &corpus.strategies_requested {
            assert!(
                corpus
                    .coverage
                    .iter()
                    .any(|entry| entry.strategy == *strategy),
                "{strategy} was requested but is missing from the coverage report"
            );
        }
    }

    /// A declared relationship produces the identical and the
    /// differ-in-one-place pairs that random generation never would.
    #[test]
    fn relationships_produce_matching_and_near_matching_pairs() {
        let descriptor = descriptor(VERIFY_TAG);
        let settings = GenerateSettings {
            strategies: vec![Strategy::Relationships],
            relationships: vec![
                Relationship {
                    left: "expected".into(),
                    right: "supplied".into(),
                    kind: RelationshipKind::Equal,
                },
                Relationship {
                    left: "expected".into(),
                    right: "supplied".into(),
                    kind: RelationshipKind::DifferLastByte,
                },
            ],
            ..Default::default()
        };
        let corpus = generate("c::verify_tag", &descriptor, &settings).unwrap();
        let pairs: Vec<(Vec<u8>, Vec<u8>)> = corpus
            .cases
            .iter()
            .map(|case| match (&case.inputs[0].1, &case.inputs[1].1) {
                (Value::Bytes { bytes: left }, Value::Bytes { bytes: right }) => {
                    (left.clone(), right.clone())
                }
                other => panic!("expected two byte arrays, got {other:?}"),
            })
            .collect();
        assert!(
            pairs.iter().any(|(left, right)| left == right),
            "no identical pair was generated"
        );
        assert!(
            pairs
                .iter()
                .any(|(left, right)| { left[..15] == right[..15] && left[15] != right[15] }),
            "no pair differing only in the last byte was generated"
        );
    }

    /// A relationship between parameters of different shapes is refused with a
    /// message naming both.
    #[test]
    fn a_relationship_between_mismatched_parameters_is_refused() {
        let descriptor = descriptor(SUBSTITUTE_MODE);
        let related = |left: &str, right: &str| GenerateSettings {
            strategies: vec![Strategy::Relationships],
            relationships: vec![Relationship {
                left: left.to_string(),
                right: right.to_string(),
                kind: RelationshipKind::Equal,
            }],
            ..Default::default()
        };
        // Both exist, but neither is a byte array.
        let error = generate("c::substitute_mode", &descriptor, &related("index", "mode"))
            .expect_err("refused");
        assert!(error.to_string().contains("byte arrays"), "{error}");

        let error = generate(
            "c::substitute_mode",
            &descriptor,
            &related("index", "absent"),
        )
        .expect_err("refused");
        assert!(error.to_string().contains("not a parameter"), "{error}");
    }

    /// A persisted failure is replayed first, so a known leak is re-checked
    /// before budget is spent guessing.
    #[test]
    fn regressions_are_replayed_before_generated_cases() {
        let descriptor = descriptor(SUBSTITUTE_MODE);
        let settings = GenerateSettings {
            regressions: vec![vec![
                ("index".to_string(), Value::Scalar { bits: 8, value: 42 }),
                ("mode".to_string(), Value::Scalar { bits: 8, value: 1 }),
            ]],
            ..Default::default()
        };
        let corpus = generate("c::substitute_mode", &descriptor, &settings).unwrap();
        assert_eq!(corpus.cases[0].strategy, Strategy::Regression);
        assert_eq!(corpus.cases[0].inputs[0].1.describe(), "42");
        assert_eq!(corpus.cases[0].inputs[1].1.describe(), "1");
    }

    /// A replayed case that does not fit the contract is refused rather than
    /// bound to the wrong width.
    #[test]
    fn a_replayed_case_that_does_not_fit_is_refused() {
        let descriptor = descriptor(SUBSTITUTE_MODE);
        let replaying = |case: Vec<(String, Value)>| GenerateSettings {
            regressions: vec![case],
            ..Default::default()
        };
        // Right names, wrong width for `index`.
        let wrong_width = replaying(vec![
            (
                "index".to_string(),
                Value::Scalar {
                    bits: 32,
                    value: 42,
                },
            ),
            ("mode".to_string(), Value::Scalar { bits: 8, value: 1 }),
        ]);
        let error = generate("c::substitute_mode", &descriptor, &wrong_width).expect_err("refused");
        assert!(error.to_string().contains("does not fit"), "{error}");

        let missing = replaying(vec![(
            "index".to_string(),
            Value::Scalar { bits: 8, value: 42 },
        )]);
        let error = generate("c::substitute_mode", &descriptor, &missing).expect_err("refused");
        assert!(error.to_string().contains("declares 2"), "{error}");
    }

    /// An unsupported parameter shape is refused by name, never given a guessed
    /// value.
    #[test]
    fn an_unsupported_parameter_is_refused() {
        let json = r#"{"schema_version":1,"function":"f","parameters":[
            {"name":"key","position":0,"role":"secret","repr":"unsupported","rust_type":"&[u8]"}],
            "returns":{"repr":"u8","rust_type":"u8"}}"#;
        let error =
            generate("c::f", &descriptor(json), &GenerateSettings::default()).expect_err("refused");
        assert!(error.to_string().contains("`key`"), "{error}");
        assert!(error.to_string().contains("&[u8]"), "{error}");
    }

    /// The wire form is one line per case, positional, and parses back to the
    /// values that produced it.
    #[test]
    fn the_wire_form_is_line_oriented_and_positional() {
        let descriptor = descriptor(SUBSTITUTE_MODE);
        let settings = GenerateSettings {
            cases: 25,
            strategies: vec![Strategy::Boundaries],
            ..Default::default()
        };
        let corpus = generate("c::substitute_mode", &descriptor, &settings).unwrap();
        let wire = corpus.to_wire();
        let lines: Vec<&str> = wire.lines().collect();
        assert!(lines[0].starts_with("# trace-check corpus v1"));
        assert_eq!(lines.len(), corpus.cases.len() + 1);
        for (case, line) in corpus.cases.iter().zip(&lines[1..]) {
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(fields[0], case.id.to_string());
            assert_eq!(fields[1], case.strategy.as_str());
            assert_eq!(fields.len(), 2 + case.inputs.len());
            for (field, (_, value)) in fields[2..].iter().zip(&case.inputs) {
                assert_eq!(*field, value.to_wire());
            }
        }
    }

    /// Byte arrays reach the wire as fixed-width hex, so a value cannot lose
    /// leading zeros on the way to the harness.
    #[test]
    fn byte_values_are_fixed_width_hex() {
        let value = Value::Bytes {
            bytes: vec![0x00, 0x0f, 0xff],
        };
        assert_eq!(value.to_wire(), "x:000fff");
        assert_eq!(value.describe(), "0x000fff");
    }

    /// A value only fits the representation it was generated for.
    #[test]
    fn values_are_checked_against_their_representation() {
        let scalar = Value::Scalar { bits: 8, value: 1 };
        assert!(scalar.fits(&Repr::Scalar(8)));
        assert!(!scalar.fits(&Repr::Scalar(32)));
        assert!(!scalar.fits(&Repr::Bool));
        let bytes = Value::Bytes { bytes: vec![0; 16] };
        assert!(bytes.fits(&Repr::RefByteArray(16)));
        assert!(bytes.fits(&Repr::ByteArray(16)));
        assert!(!bytes.fits(&Repr::RefByteArray(32)));
    }

    /// The corpus hash covers the wire form, which is what the harness read.
    #[test]
    fn the_corpus_hash_covers_what_the_harness_consumed() {
        let settings = GenerateSettings {
            cases: 30,
            ..Default::default()
        };
        let corpus = generate(
            "c::substitute_mode",
            &descriptor(SUBSTITUTE_MODE),
            &settings,
        )
        .unwrap();
        let expected = format!("{:x}", Sha256::digest(corpus.to_wire().as_bytes()));
        assert_eq!(corpus.sha256(), expected);
        assert_eq!(corpus.sha256().len(), 64);
    }
}
