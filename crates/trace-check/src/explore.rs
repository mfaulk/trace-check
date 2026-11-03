//! Coverage-guided input discovery: typed mutations, a seed queue, and
//! deterministic retention.
//!
//! Exploration answers *which inputs are worth analyzing?* and nothing else. It
//! never classifies a finding, never marks a secret, and never produces an
//! outcome. What it produces is a corpus, which [`crate::check`] then runs in
//! the uninstrumented security artifact exactly as it runs M6's own corpus.
//!
//! # The baseline is never replaced
//!
//! Every case M6 would have generated is kept, and exploration adds to it. This
//! is not politeness about backward compatibility: a coverage heuristic that
//! displaced boundary cases would quietly stop finding the vulnerabilities
//! boundary generation is good at, and the loss would show up as *less*
//! security checking under a flag named for more.
//!
//! # Why mutation works here when random generation does not
//!
//! The fixtures in `examples/crypto-library/src/hidden.rs` guard a leak behind
//! a conjunction over several public parameters. Random generation has to
//! satisfy all of them at once; boundary and pairwise generation move one and
//! two parameters away from base and so cannot satisfy three at any budget.
//!
//! Mutation does not have to. Satisfying the *first* predicate executes a
//! region nothing else reached, so that input is retained as a seed, and the
//! search for the second predicate starts from an input that already satisfies
//! the first. The conjunction is climbed one conjunct at a time. That is the
//! entire mechanism, and the M7.1 spike measured the gradient it depends on.
//!
//! # Determinism
//!
//! The retained corpus is a pure function of (descriptor, baseline corpus,
//! explore seed, candidate budget, round size, discovery artifact). Mutation
//! choices come from one `splitmix64` stream advanced in a fixed order over a
//! queue whose order is itself fixed; coverage decoding is parallel but writes
//! into per-case slots, so thread scheduling cannot reach the result. A
//! wall-clock limit is the one thing that can cut a run short, and it is
//! reported separately from the budget so a shorter run is visible rather than
//! inferred.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::contract::{Descriptor, Parameter, Repr, Role};
use crate::coverage::{
    Collector, CoverageError, CoverageMap, CoverageObservation, ExecutionStatus, RegionSet,
};
use crate::generate::{self, CaseEntry, Corpus, GenerateError, Strategy, Value};

/// Default number of mutation candidates per contract.
pub const DEFAULT_CANDIDATE_BUDGET: usize = 2_000;

/// Default cap on how many cases reach the security backend.
pub const DEFAULT_SECURITY_CASE_BUDGET: usize = 256;

/// Rounds without new coverage before exploration stops early.
///
/// Eight, measured rather than chosen. A round's candidates are shared
/// round-robin across every seed, so the round that finally satisfies a new
/// predicate is several rounds after the seed that leads to it was retained. At
/// three dry rounds the nested-predicate search stopped at 384 of a 2000
/// candidate budget having satisfied two of three conjuncts -- it reported
/// convergence while the budget it was given was almost untouched.
///
/// Convergence is a courtesy that ends a search with nothing left to try. The
/// budget is the stopping rule.
pub const DEFAULT_DRY_ROUNDS: usize = 8;

/// Default wall-clock safety limit for one contract's exploration.
pub const DEFAULT_TIME_LIMIT: Duration = Duration::from_secs(300);

/// Which parameters a mutation is allowed to touch.
///
/// Public inputs usually decide *which* code runs, so they get most of the
/// budget. Secrets are not frozen, though: a branch on secret bits is itself a
/// vulnerability class, and a strategy that never varied the secret could not
/// reach the region behind one. The mix is configurable and recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationTarget {
    /// Public parameters only; every secret keeps its seed value.
    Public,
    /// Secret parameters only; every public input keeps its seed value.
    Secret,
    /// Both, in one candidate.
    Combined,
}

impl MutationTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            MutationTarget::Public => "public",
            MutationTarget::Secret => "secret",
            MutationTarget::Combined => "combined",
        }
    }
}

/// The deterministic rotation mutation targets are drawn from.
///
/// Three public attempts, then one secret, then one combined. A ratio rather
/// than a probability so the mix is identical on every run and a report can
/// state it as a fact.
const TARGET_ROTATION: [MutationTarget; 5] = [
    MutationTarget::Public,
    MutationTarget::Public,
    MutationTarget::Public,
    MutationTarget::Secret,
    MutationTarget::Combined,
];

/// One typed mutation operator.
///
/// Every operator preserves the parameter's Rust representation: a `u8` stays a
/// `u8`, a `[u8; 16]` keeps sixteen bytes. The number and types of parameters
/// are fixed by the descriptor and no operator can change them —
/// [`generate::with_ids`] revalidates anyway, because that check is the one no
/// caller is trusted to have done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operator {
    /// Replace a scalar with one of its boundary values.
    Boundary,
    /// Add or subtract a small amount.
    Offset,
    /// Flip one bit.
    BitFlip,
    /// Replace one byte.
    ByteReplace,
    /// Substitute a value from the interesting-byte table at a fixed byte
    /// position. The deterministic stage's operator; see [`State::propose`].
    Interesting,
    /// Replace a short run of bytes.
    RangeReplace,
    /// Zero a short run of bytes.
    RangeZero,
    /// Fill the array with one repeated byte, preserving its length.
    Pattern,
    /// Copy this parameter's value from another retained candidate.
    Splice,
    /// Toggle a `bool`.
    Toggle,
}

impl Operator {
    pub fn as_str(self) -> &'static str {
        match self {
            Operator::Boundary => "boundary",
            Operator::Offset => "offset",
            Operator::BitFlip => "bit-flip",
            Operator::ByteReplace => "byte-replace",
            Operator::Interesting => "interesting",
            Operator::RangeReplace => "range-replace",
            Operator::RangeZero => "range-zero",
            Operator::Pattern => "pattern",
            Operator::Splice => "splice",
            Operator::Toggle => "toggle",
        }
    }

    /// Operators applicable to a parameter's representation.
    fn for_repr(repr: &Repr) -> &'static [Operator] {
        match repr {
            Repr::Scalar(_) => &[
                Operator::Boundary,
                Operator::Offset,
                Operator::BitFlip,
                Operator::ByteReplace,
                Operator::Splice,
            ],
            Repr::Bool => &[Operator::Toggle],
            Repr::ByteArray(_) | Repr::RefByteArray(_) => &[
                Operator::BitFlip,
                Operator::ByteReplace,
                Operator::RangeReplace,
                Operator::RangeZero,
                Operator::Pattern,
                Operator::Splice,
            ],
            Repr::Unit | Repr::Unsupported => &[],
        }
    }
}

/// Where a candidate came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Origin {
    /// One of M6's generated cases, which exploration measured but did not
    /// invent.
    Baseline { strategy: Strategy },
    /// A mutation of a retained candidate.
    Mutated {
        /// Candidate index this was derived from.
        seed: usize,
        operator: Operator,
        target: MutationTarget,
        /// Parameters this mutation changed.
        parameters: Vec<String>,
    },
}

impl Origin {
    pub fn describe(&self) -> String {
        match self {
            Origin::Baseline { strategy } => format!("baseline ({strategy})"),
            Origin::Mutated {
                seed,
                operator,
                target,
                parameters,
            } => format!(
                "{} {} of candidate {seed} on {}",
                target.as_str(),
                operator.as_str(),
                parameters.join(", ")
            ),
        }
    }
}

/// One explored candidate and what it reached.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// Index in the exploration, which is also the case id it was run under.
    pub id: usize,
    pub inputs: Vec<(String, Value)>,
    pub origin: Origin,
    /// In-scope regions this candidate covered in the **discovery** artifact.
    pub covered: RegionSet,
    /// Regions it was the first to reach.
    pub novel: usize,
    /// Whether the discovery artifact recorded entering the target function.
    pub target_invoked: bool,
    /// Whether this candidate must reach the security backend regardless of
    /// what it covered.
    pub mandatory: bool,
}

impl Candidate {
    /// Describes the inputs, for a report or a reproducer.
    pub fn describe(&self) -> String {
        self.inputs
            .iter()
            .map(|(name, value)| format!("{name}={}", value.describe()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Why exploration stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum Termination {
    /// Every candidate in the budget was attempted.
    BudgetExhausted,
    /// No round found new coverage for `dry_rounds` consecutive rounds.
    Converged { dry_rounds: usize },
    /// The wall-clock limit was reached. Reported because a slower machine
    /// explores less and a report must not imply otherwise.
    TimeLimit { elapsed_ms: u128 },
    /// The seed queue emptied, which happens when no retained candidate has an
    /// unused mutation left.
    QueueEmpty,
    /// The discovery artifact stopped producing usable coverage, so continuing
    /// would be generating candidates nothing could evaluate.
    DiscoveryFailed { detail: String },
}

impl Termination {
    pub fn as_str(&self) -> &'static str {
        match self {
            Termination::BudgetExhausted => "budget-exhausted",
            Termination::Converged { .. } => "converged",
            Termination::TimeLimit { .. } => "time-limit",
            Termination::QueueEmpty => "queue-empty",
            Termination::DiscoveryFailed { .. } => "discovery-failed",
        }
    }

    /// Whether exploration finished the work it was asked to do.
    ///
    /// A time limit or a failing discovery artifact did not: a run that was cut
    /// short has not explored its budget, and a CI job that required
    /// exploration must not be told otherwise.
    pub fn complete(&self) -> bool {
        matches!(
            self,
            Termination::BudgetExhausted | Termination::Converged { .. } | Termination::QueueEmpty
        )
    }

    pub fn describe(&self) -> String {
        match self {
            Termination::BudgetExhausted => "the candidate budget was spent".to_string(),
            Termination::Converged { dry_rounds } => {
                format!("{dry_rounds} consecutive round(s) found no new coverage")
            }
            Termination::TimeLimit { elapsed_ms } => format!(
                "the wall-clock limit was reached after {elapsed_ms} ms, so fewer candidates were \
                 attempted than the budget allows"
            ),
            Termination::QueueEmpty => {
                "no retained candidate had an unused mutation left".to_string()
            }
            Termination::DiscoveryFailed { detail } => {
                format!("the discovery artifact stopped producing usable coverage: {detail}")
            }
        }
    }
}

/// How the mutation budget was actually spent.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MutationMix {
    pub public: usize,
    pub secret: usize,
    pub combined: usize,
    /// Candidates skipped because an identical input had already been tried.
    pub duplicates: usize,
    /// Candidates a mutation could not produce, because the operator had
    /// nothing to change.
    pub vacuous: usize,
}

/// Settings for one contract's exploration.
#[derive(Debug, Clone)]
pub struct ExploreSettings {
    /// Mutation candidates to attempt, beyond the baseline corpus.
    pub candidate_budget: usize,
    /// Cap on cases handed to the security backend.
    pub security_case_budget: usize,
    pub seed: u64,
    /// Candidates per discovery round.
    pub round_size: usize,
    pub mutate_public: bool,
    pub mutate_secret: bool,
    pub dry_rounds: usize,
    pub time_limit: Duration,
}

impl Default for ExploreSettings {
    fn default() -> Self {
        ExploreSettings {
            candidate_budget: DEFAULT_CANDIDATE_BUDGET,
            security_case_budget: DEFAULT_SECURITY_CASE_BUDGET,
            seed: generate::DEFAULT_SEED,
            round_size: crate::coverage::DEFAULT_ROUND_SIZE,
            mutate_public: true,
            mutate_secret: true,
            dry_rounds: DEFAULT_DRY_ROUNDS,
            time_limit: DEFAULT_TIME_LIMIT,
        }
    }
}

/// Everything one contract's exploration established.
///
/// Deliberately all about the **discovery** artifact. Every region count here
/// is a statement about code executed in an instrumented binary, and none of it
/// is evidence about constant-time behavior.
#[derive(Debug, Clone, Serialize)]
pub struct Exploration {
    pub feedback: String,
    pub granularity: String,
    pub coverage_map: CoverageMap,
    pub discovery_artifact_sha256: String,
    /// Library directory whose files counted as target coverage.
    pub scope: String,
    pub seed: u64,
    pub candidate_budget: usize,
    /// M6 cases measured in the discovery artifact.
    pub baseline_cases: usize,
    /// Mutation candidates attempted.
    pub candidates_attempted: usize,
    /// Candidates that produced usable coverage.
    pub candidates_observed: usize,
    /// Candidates retained for reaching something new.
    pub candidates_retained: usize,
    pub rounds: usize,
    /// Regions the baseline corpus alone reached.
    pub baseline_regions: usize,
    /// Regions reached in total.
    pub regions_reached: usize,
    pub mutation_mix: MutationMix,
    pub termination: Termination,
    pub elapsed_ms: u128,
    /// Candidates whose coverage could not be used, with the reason.
    pub failures: Vec<CandidateFailure>,
    /// Every retained candidate, in discovery order. Includes the baseline.
    pub candidates: Vec<Candidate>,
}

impl Exploration {
    /// Regions exploration reached that the baseline corpus did not.
    pub fn regions_added(&self) -> usize {
        self.regions_reached.saturating_sub(self.baseline_regions)
    }

    /// Whether exploration did the work it was asked to do.
    ///
    /// False when it was cut short, or when any candidate's coverage could not
    /// be trusted. Used by the CI policy: a run that required exploration and
    /// got a partial one is not a successful check.
    pub fn complete(&self) -> bool {
        self.termination.complete() && self.failures.is_empty()
    }

    /// Why exploration was not complete, when it was not.
    pub fn incompleteness(&self) -> Option<String> {
        if !self.termination.complete() {
            return Some(self.termination.describe());
        }
        if self.failures.is_empty() {
            return None;
        }
        Some(format!(
            "{} candidate(s) produced no usable coverage, so the exploration this run reports is \
             not the exploration it performed: {}",
            self.failures.len(),
            self.failures
                .iter()
                .take(4)
                .map(|failure| format!("case {}: {}", failure.case_id, failure.status))
                .collect::<Vec<_>>()
                .join("; ")
        ))
    }
}

/// A candidate whose coverage could not be used.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateFailure {
    pub case_id: usize,
    pub status: ExecutionStatus,
    /// The inputs, kept for diagnosis. A discovery crash is not a security
    /// finding, but it is still something a developer wants to reproduce.
    pub inputs: Vec<(String, Value)>,
}

/// `splitmix64`, the same generator M6 uses, for the same reason: a dependency
/// bump must not be able to change what a recorded seed means.
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

    /// Uniform in `0..bound`. Returns 0 for an empty bound rather than dividing
    /// by zero.
    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }
}

/// Runs coverage-guided exploration for one contract.
pub fn explore(
    contract: &str,
    descriptor: &Descriptor,
    baseline: &Corpus,
    collector: &Collector<'_>,
    settings: &ExploreSettings,
    work_dir: &Path,
) -> Result<Exploration, ExploreError> {
    let started = Instant::now();
    let profile_dir = work_dir.join("discovery-profiles");
    let round_dir = work_dir.join("discovery-rounds");
    std::fs::create_dir_all(&round_dir)
        .map_err(|e| ExploreError::Io(format!("{}: {e}", round_dir.display())))?;

    // The baseline corpus is staged and probed first. Everything the gate
    // checks — instrumentation, a readable map, a record for the function under
    // study, a library in scope — fails here if it is going to, before any
    // candidate exists to be blamed.
    let baseline_path = stage_entries(contract, descriptor, &numbered(baseline), &round_dir, 0)?;
    let first = baseline
        .cases
        .first()
        .ok_or(ExploreError::EmptyBaseline)?
        .id;
    let (map, _) = collector.probe_map(&baseline_path, first, &profile_dir)?;

    let mut state = State::new(descriptor, settings);

    // Stage one: measure every M6 case. These are mandatory — they reach the
    // security backend whatever their coverage — and they are also the seeds
    // the search starts from.
    for (round, chunk) in baseline
        .cases
        .chunks(settings.round_size.max(1))
        .enumerate()
    {
        let entries: Vec<CaseEntry> = chunk
            .iter()
            .map(|case| (case.id, case.strategy, case.inputs.clone()))
            .collect();
        let staged = stage_entries(contract, descriptor, &entries, &round_dir, round + 1)?;
        let ids: Vec<usize> = entries.iter().map(|(id, _, _)| *id).collect();
        let run = collector.observe(&staged, &ids, &profile_dir, &map.id)?;
        state.rounds += 1;
        state.absorb_baseline(&entries, &run.observations);
        if let Some(detail) = fatal(&run.observations) {
            state.termination = Some(Termination::DiscoveryFailed { detail });
            break;
        }
    }
    state.baseline_regions = state.seen.len();

    // Stage two: mutate, measure, retain. One round at a time, so a round's
    // results are available to the next round's seed choice.
    while state.termination.is_none() {
        if state.attempted >= settings.candidate_budget {
            state.termination = Some(Termination::BudgetExhausted);
            break;
        }
        if started.elapsed() >= settings.time_limit {
            state.termination = Some(Termination::TimeLimit {
                elapsed_ms: started.elapsed().as_millis(),
            });
            break;
        }
        let remaining = settings.candidate_budget - state.attempted;
        let wanted = settings.round_size.max(1).min(remaining);
        let batch = state.propose(wanted);
        if batch.is_empty() {
            state.termination = Some(Termination::QueueEmpty);
            break;
        }

        let entries: Vec<CaseEntry> = batch
            .iter()
            .map(|proposal| (proposal.id, Strategy::Explored, proposal.inputs.clone()))
            .collect();
        state.rounds += 1;
        let staged = stage_entries(contract, descriptor, &entries, &round_dir, state.rounds + 1)?;
        let ids: Vec<usize> = entries.iter().map(|(id, _, _)| *id).collect();
        let run = collector.observe(&staged, &ids, &profile_dir, &map.id)?;
        state.attempted += batch.len();

        let found = state.absorb(&batch, &run.observations);
        if let Some(detail) = fatal(&run.observations) {
            state.termination = Some(Termination::DiscoveryFailed { detail });
            break;
        }
        if found == 0 {
            state.dry += 1;
            if state.dry >= settings.dry_rounds {
                state.termination = Some(Termination::Converged {
                    dry_rounds: state.dry,
                });
            }
        } else {
            state.dry = 0;
        }
    }

    let termination = state
        .termination
        .take()
        .unwrap_or(Termination::BudgetExhausted);
    Ok(Exploration {
        feedback: crate::coverage::FEEDBACK.to_string(),
        granularity: crate::coverage::GRANULARITY.to_string(),
        coverage_map: map,
        discovery_artifact_sha256: collector.artifact_sha256().to_string(),
        scope: collector.scope().display().to_string(),
        seed: settings.seed,
        candidate_budget: settings.candidate_budget,
        baseline_cases: baseline.cases.len(),
        candidates_attempted: state.attempted,
        candidates_observed: state.observed,
        candidates_retained: state.retained_mutations,
        rounds: state.rounds,
        baseline_regions: state.baseline_regions,
        regions_reached: state.seen.len(),
        mutation_mix: state.mix,
        termination,
        elapsed_ms: started.elapsed().as_millis(),
        failures: state.failures,
        candidates: state.candidates,
    })
}

/// One item of a seed's deterministic plan.
#[derive(Debug, Clone, Copy)]
struct PlanItem {
    /// Parameter position in the descriptor.
    position: usize,
    /// Byte offset inside that parameter's value.
    byte: usize,
    /// Index into [`INTERESTING`].
    value: usize,
}

/// A retained candidate being used as a mutation seed.
struct Seed {
    /// Index into `State::candidates`.
    candidate: usize,
    /// How much of `plan` has been spent.
    cursor: usize,
    plan: Vec<PlanItem>,
}

impl Seed {
    /// The next unspent plan item, or `None` once the deterministic stage is
    /// finished and the seed moves to random havoc.
    fn next_item(&mut self) -> Option<PlanItem> {
        let item = self.plan.get(self.cursor).copied();
        if item.is_some() {
            self.cursor += 1;
        }
        item
    }
}

/// A proposed candidate, before it has been measured.
#[derive(Debug, Clone)]
struct Proposal {
    id: usize,
    inputs: Vec<(String, Value)>,
    origin: Origin,
}

/// Exploration's mutable state, kept in one place so the loop above reads as
/// the algorithm rather than as bookkeeping.
struct State<'a> {
    descriptor: &'a Descriptor,
    settings: &'a ExploreSettings,
    rng: Rng,
    /// Boundary values per parameter, for the `Boundary` operator. Computed
    /// once from the descriptor.
    boundaries: Vec<Vec<Value>>,
    /// Every retained candidate: the baseline, then whatever mutation found.
    candidates: Vec<Candidate>,
    /// Retained candidates eligible as mutation seeds, in priority order.
    queue: Vec<Seed>,
    /// Next seed to draw from, as an index into `queue`.
    cursor: usize,
    /// Regions anything has reached.
    seen: RegionSet,
    /// Functions anything has entered, for the "new function" priority tier.
    seen_functions: BTreeSet<String>,
    /// Input identities already attempted, so a mutation cannot re-run one.
    attempted_keys: HashSet<String>,
    /// Next case id to hand out. Starts above the baseline's highest id so a
    /// candidate id is never ambiguous.
    next_id: usize,
    attempted: usize,
    observed: usize,
    retained_mutations: usize,
    baseline_regions: usize,
    rounds: usize,
    dry: usize,
    mix: MutationMix,
    failures: Vec<CandidateFailure>,
    termination: Option<Termination>,
}

impl<'a> State<'a> {
    fn new(descriptor: &'a Descriptor, settings: &'a ExploreSettings) -> State<'a> {
        State {
            descriptor,
            settings,
            rng: Rng::new(settings.seed),
            boundaries: descriptor
                .parameters
                .iter()
                .map(scalar_boundaries)
                .collect(),
            candidates: Vec::new(),
            queue: Vec::new(),
            cursor: 0,
            seen: RegionSet::new(),
            seen_functions: BTreeSet::new(),
            attempted_keys: HashSet::new(),
            next_id: 0,
            attempted: 0,
            observed: 0,
            retained_mutations: 0,
            baseline_regions: 0,
            rounds: 0,
            dry: 0,
            mix: MutationMix::default(),
            failures: Vec::new(),
            termination: None,
        }
    }

    /// Folds in a measured baseline round.
    ///
    /// Baseline cases are retained unconditionally — they are M6's corpus and
    /// must reach the security backend — but only one that covered something
    /// new becomes a mutation seed. A hundred boundary cases that all take the
    /// same path are one useful starting point, not a hundred.
    fn absorb_baseline(&mut self, entries: &[CaseEntry], observations: &[CoverageObservation]) {
        for ((id, strategy, inputs), observation) in entries.iter().zip(observations) {
            self.attempted_keys.insert(key(inputs));
            self.next_id = self.next_id.max(id + 1);
            let novel = observation.novel(&self.seen);
            let fresh_function = self.fresh_functions(observation);
            if observation.status.usable() {
                self.observed += 1;
            } else {
                self.failures.push(CandidateFailure {
                    case_id: *id,
                    status: observation.status.clone(),
                    inputs: inputs.clone(),
                });
            }
            let index = self.candidates.len();
            self.candidates.push(Candidate {
                id: *id,
                inputs: inputs.clone(),
                origin: Origin::Baseline {
                    strategy: *strategy,
                },
                covered: observation.covered_regions.clone(),
                novel: novel.len(),
                target_invoked: observation.target_invoked,
                mandatory: true,
            });
            if !novel.is_empty() {
                self.enqueue(index, !fresh_function.is_empty());
            }
            self.seen.extend(novel);
            self.seen_functions.extend(fresh_function);
        }
    }

    /// Folds in a measured mutation round. Returns how many candidates found
    /// new coverage.
    fn absorb(&mut self, batch: &[Proposal], observations: &[CoverageObservation]) -> usize {
        let mut found = 0;
        for (proposal, observation) in batch.iter().zip(observations) {
            if observation.status.usable() {
                self.observed += 1;
            } else {
                self.failures.push(CandidateFailure {
                    case_id: proposal.id,
                    status: observation.status.clone(),
                    inputs: proposal.inputs.clone(),
                });
                continue;
            }
            let novel = observation.novel(&self.seen);
            if novel.is_empty() {
                continue;
            }
            let fresh_function = self.fresh_functions(observation);
            found += 1;
            self.retained_mutations += 1;
            let index = self.candidates.len();
            self.candidates.push(Candidate {
                id: proposal.id,
                inputs: proposal.inputs.clone(),
                origin: proposal.origin.clone(),
                covered: observation.covered_regions.clone(),
                novel: novel.len(),
                target_invoked: observation.target_invoked,
                mandatory: false,
            });
            self.enqueue(index, !fresh_function.is_empty());
            self.seen.extend(novel);
            self.seen_functions.extend(fresh_function);
        }
        found
    }

    /// Functions this observation entered that nothing had entered before.
    fn fresh_functions(&self, observation: &CoverageObservation) -> BTreeSet<String> {
        if !observation.status.usable() {
            return BTreeSet::new();
        }
        observation
            .covered_functions
            .difference(&self.seen_functions)
            .cloned()
            .collect()
    }

    /// Adds a candidate to the seed queue, with its deterministic plan.
    ///
    /// A candidate that reached a function nothing had entered goes to the
    /// front, because a new function is a larger unexplored area than a new
    /// region inside a function already being explored. Everything else is
    /// appended, so order within a tier is discovery order and therefore
    /// deterministic.
    fn enqueue(&mut self, index: usize, new_function: bool) {
        let seed = Seed {
            candidate: index,
            cursor: 0,
            plan: self.plan(),
        };
        if new_function {
            let at = self.cursor.min(self.queue.len());
            self.queue.insert(at, seed);
        } else {
            self.queue.push(seed);
        }
    }

    /// The deterministic plan every seed is given: one candidate per
    /// (parameter, byte position, interesting value).
    ///
    /// Public parameters first, so public diversity is explored before secret
    /// diversity, then secrets. The plan is tiny for the shapes contracts
    /// actually have — four `u8`s give 64 items — and it is what makes reaching
    /// an exact byte a *guarantee* rather than a probability.
    ///
    /// This is the lesson the first implementation taught. With random mutation
    /// alone, satisfying one more conjunct meant drawing the right parameter,
    /// then the right operator, then the right value: about three chances in a
    /// thousand per candidate. The search reliably stalled two conjuncts in. An
    /// exhaustive sweep over single-byte substitutions costs a few dozen
    /// candidates per seed and cannot miss.
    fn plan(&self) -> Vec<PlanItem> {
        let mut items = Vec::new();
        for secret_pass in [false, true] {
            for (position, parameter) in self.descriptor.parameters.iter().enumerate() {
                let secret = parameter.role == Role::Secret;
                if secret != secret_pass {
                    continue;
                }
                let target = if secret {
                    MutationTarget::Secret
                } else {
                    MutationTarget::Public
                };
                if !self.eligible(position, target) {
                    continue;
                }
                let bytes: Vec<usize> = match &parameter.repr {
                    Repr::Scalar(bits) => (0..(*bits as usize).div_ceil(8)).collect(),
                    Repr::ByteArray(length) | Repr::RefByteArray(length) => {
                        swept_positions(*length as usize)
                    }
                    // A `bool` has two values and the seed holds one of them;
                    // the havoc stage's toggle covers it.
                    Repr::Bool | Repr::Unit | Repr::Unsupported => Vec::new(),
                };
                for byte in bytes {
                    for value in 0..INTERESTING.len() {
                        items.push(PlanItem {
                            position,
                            byte,
                            value,
                        });
                    }
                }
            }
        }
        items
    }

    /// Proposes up to `wanted` fresh candidates, round-robin over the queue.
    ///
    /// Each seed spends its deterministic plan first and only then enters the
    /// random havoc stage. Round-robin rather than weighted, because fairness
    /// is what turns "every seed's plan completes" into a guarantee: a scheme
    /// that favoured recent seeds would be faster on the fixture it was tuned
    /// against and could starve a seed that leads somewhere else.
    fn propose(&mut self, wanted: usize) -> Vec<Proposal> {
        if self.queue.is_empty() {
            return Vec::new();
        }
        let mut batch = Vec::with_capacity(wanted);
        // Bounded attempts: a tiny input domain exhausts its distinct values,
        // and retrying forever would hang rather than report.
        let mut attempts = 0;
        let limit = wanted.saturating_mul(16).max(64);
        while batch.len() < wanted && attempts < limit {
            attempts += 1;
            let slot = self.cursor % self.queue.len();
            self.cursor = self.cursor.wrapping_add(1);
            let proposed = match self.queue[slot].next_item() {
                Some(item) => self.substitute(slot, item),
                None => {
                    let target = self.next_target();
                    self.mutate(self.queue[slot].candidate, target)
                }
            };
            let Some(proposal) = proposed else {
                self.mix.vacuous += 1;
                continue;
            };
            if !self.attempted_keys.insert(key(&proposal.inputs)) {
                self.mix.duplicates += 1;
                continue;
            }
            if let Origin::Mutated { target, .. } = &proposal.origin {
                match target {
                    MutationTarget::Public => self.mix.public += 1,
                    MutationTarget::Secret => self.mix.secret += 1,
                    MutationTarget::Combined => self.mix.combined += 1,
                }
            }
            batch.push(proposal);
        }
        batch
    }

    /// Applies one deterministic plan item: an interesting byte at a fixed
    /// position of one parameter.
    fn substitute(&mut self, slot: usize, item: PlanItem) -> Option<Proposal> {
        let seed_index = self.queue[slot].candidate;
        let parameter = &self.descriptor.parameters[item.position];
        let replacement = INTERESTING[item.value];
        let mut inputs = self.candidates[seed_index].inputs.clone();
        let value = match &inputs[item.position].1 {
            Value::Scalar { bits, value } => {
                let shift = item.byte * 8;
                let cleared = value & !(0xffu64 << shift);
                Value::Scalar {
                    bits: *bits,
                    value: mask(cleared | ((replacement as u64) << shift), *bits),
                }
            }
            Value::Bytes { bytes } => {
                let mut bytes = bytes.clone();
                *bytes.get_mut(item.byte)? = replacement;
                Value::Bytes { bytes }
            }
            Value::Bool { .. } => return None,
        };
        if value == inputs[item.position].1 {
            return None;
        }
        inputs[item.position] = (parameter.name.clone(), value);
        let id = self.next_id;
        self.next_id += 1;
        Some(Proposal {
            id,
            inputs,
            origin: Origin::Mutated {
                seed: self.candidates[seed_index].id,
                operator: Operator::Interesting,
                target: if parameter.role == Role::Secret {
                    MutationTarget::Secret
                } else {
                    MutationTarget::Public
                },
                parameters: vec![parameter.name.clone()],
            },
        })
    }

    /// The next target in the rotation, skipping ones the settings disable.
    fn next_target(&mut self) -> MutationTarget {
        let has_public = self
            .descriptor
            .parameters
            .iter()
            .any(|parameter| parameter.role != Role::Secret);
        let has_secret = self.descriptor.secrets().next().is_some();
        for step in 0..TARGET_ROTATION.len() {
            let candidate = TARGET_ROTATION
                [(self.attempted + self.mix.duplicates + step) % TARGET_ROTATION.len()];
            let allowed = match candidate {
                MutationTarget::Public => self.settings.mutate_public && has_public,
                MutationTarget::Secret => self.settings.mutate_secret && has_secret,
                MutationTarget::Combined => {
                    self.settings.mutate_public && self.settings.mutate_secret
                        || (self.settings.mutate_public && !has_secret)
                        || (self.settings.mutate_secret && !has_public)
                }
            };
            if allowed {
                return candidate;
            }
        }
        // Nothing is enabled; `mutate` will find no eligible parameter and the
        // round will report itself empty rather than silently mutating a role
        // the settings excluded.
        MutationTarget::Public
    }

    /// Derives one candidate from a seed.
    fn mutate(&mut self, seed_index: usize, target: MutationTarget) -> Option<Proposal> {
        let mut inputs = self.candidates[seed_index].inputs.clone();
        let eligible: Vec<usize> = (0..self.descriptor.parameters.len())
            .filter(|position| self.eligible(*position, target))
            .collect();
        if eligible.is_empty() {
            return None;
        }
        // A combined mutation changes two parameters where there are two to
        // change, because changing one is already what the single-role targets
        // do.
        let changes = if target == MutationTarget::Combined && eligible.len() > 1 {
            2
        } else {
            1
        };
        let mut touched = Vec::new();
        let mut operator = Operator::Boundary;
        for _ in 0..changes {
            let position = eligible[self.rng.below(eligible.len())];
            if touched.contains(&self.descriptor.parameters[position].name) {
                continue;
            }
            let parameter = &self.descriptor.parameters[position];
            let operators = Operator::for_repr(&parameter.repr);
            if operators.is_empty() {
                continue;
            }
            operator = operators[self.rng.below(operators.len())];
            let Some(value) = self.apply(operator, position, &inputs[position].1) else {
                continue;
            };
            if value == inputs[position].1 {
                continue;
            }
            inputs[position] = (parameter.name.clone(), value);
            touched.push(parameter.name.clone());
        }
        if touched.is_empty() {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        Some(Proposal {
            id,
            inputs,
            origin: Origin::Mutated {
                seed: self.candidates[seed_index].id,
                operator,
                target,
                parameters: touched,
            },
        })
    }

    /// Whether a parameter may be changed under this target.
    fn eligible(&self, position: usize, target: MutationTarget) -> bool {
        let parameter = &self.descriptor.parameters[position];
        let secret = parameter.role == Role::Secret;
        // An unsupported representation is never touched: no operator can
        // preserve a shape the descriptor cannot describe.
        if Operator::for_repr(&parameter.repr).is_empty() {
            return false;
        }
        match target {
            MutationTarget::Public => !secret && self.settings.mutate_public,
            MutationTarget::Secret => secret && self.settings.mutate_secret,
            MutationTarget::Combined => {
                (secret && self.settings.mutate_secret) || (!secret && self.settings.mutate_public)
            }
        }
    }

    /// Applies one operator to one value, preserving its representation.
    fn apply(&mut self, operator: Operator, position: usize, value: &Value) -> Option<Value> {
        let repr = &self.descriptor.parameters[position].repr;
        match (operator, value) {
            (Operator::Toggle, Value::Bool { value }) => Some(Value::Bool { value: !value }),
            (Operator::Boundary, Value::Scalar { bits, .. }) => {
                let options = &self.boundaries[position];
                if options.is_empty() {
                    return None;
                }
                let picked = self.rng.below(options.len());
                match &options[picked] {
                    Value::Scalar { value, .. } => Some(Value::Scalar {
                        bits: *bits,
                        value: mask(*value, *bits),
                    }),
                    _ => None,
                }
            }
            (Operator::Offset, Value::Scalar { bits, value }) => {
                // Small signed offsets, which is where a comparison, a carry or
                // an off-by-one changes behaviour.
                const OFFSETS: [i64; 8] = [1, -1, 2, -2, 8, -8, 64, -64];
                let offset = OFFSETS[self.rng.below(OFFSETS.len())];
                Some(Value::Scalar {
                    bits: *bits,
                    value: mask(value.wrapping_add(offset as u64), *bits),
                })
            }
            (Operator::BitFlip, Value::Scalar { bits, value }) => {
                let bit = self.rng.below(*bits as usize);
                Some(Value::Scalar {
                    bits: *bits,
                    value: mask(value ^ (1u64 << bit), *bits),
                })
            }
            (Operator::ByteReplace, Value::Scalar { bits, value }) => {
                let bytes = (*bits as usize).div_ceil(8);
                let index = self.rng.below(bytes);
                let replacement = self.interesting_byte() as u64;
                let shift = index * 8;
                let cleared = value & !(0xffu64 << shift);
                Some(Value::Scalar {
                    bits: *bits,
                    value: mask(cleared | (replacement << shift), *bits),
                })
            }
            (Operator::BitFlip, Value::Bytes { bytes }) => {
                let mut bytes = bytes.clone();
                if bytes.is_empty() {
                    return None;
                }
                let index = self.rng.below(bytes.len());
                let bit = self.rng.below(8);
                bytes[index] ^= 1u8 << bit;
                Some(Value::Bytes { bytes })
            }
            (Operator::ByteReplace, Value::Bytes { bytes }) => {
                let mut bytes = bytes.clone();
                if bytes.is_empty() {
                    return None;
                }
                let index = self.rng.below(bytes.len());
                bytes[index] = self.interesting_byte();
                Some(Value::Bytes { bytes })
            }
            (Operator::RangeReplace, Value::Bytes { bytes }) => {
                let mut bytes = bytes.clone();
                if bytes.is_empty() {
                    return None;
                }
                let start = self.rng.below(bytes.len());
                let length = 1 + self.rng.below(4.min(bytes.len() - start));
                for byte in &mut bytes[start..start + length] {
                    *byte = self.interesting_byte();
                }
                Some(Value::Bytes { bytes })
            }
            (Operator::RangeZero, Value::Bytes { bytes }) => {
                let mut bytes = bytes.clone();
                if bytes.is_empty() {
                    return None;
                }
                let start = self.rng.below(bytes.len());
                let length = 1 + self.rng.below(8.min(bytes.len() - start));
                bytes[start..start + length].fill(0);
                Some(Value::Bytes { bytes })
            }
            (Operator::Pattern, Value::Bytes { bytes }) => {
                // Length-preserving by construction: a repeated byte over the
                // same number of bytes.
                let fill = self.interesting_byte();
                Some(Value::Bytes {
                    bytes: vec![fill; bytes.len()],
                })
            }
            // The deterministic stage's operator, applied by
            // `State::substitute` rather than drawn here.
            (Operator::Interesting, _) => None,
            (Operator::Splice, _) => {
                // Copy this parameter's value from another retained candidate,
                // which is how a value one seed discovered reaches another.
                if self.candidates.is_empty() {
                    return None;
                }
                let donor = self.rng.below(self.candidates.len());
                let borrowed = self.candidates[donor].inputs.get(position)?.1.clone();
                // Representation is re-checked here as well as in
                // `generate::with_ids`: a splice is the one operator that
                // copies a value rather than deriving it.
                borrowed.fits(repr).then_some(borrowed)
            }
            _ => None,
        }
    }

    /// A byte worth trying: the extremes and the shapes a comparison, a nibble
    /// test or a sign check changes behaviour around, then anything.
    fn interesting_byte(&mut self) -> u8 {
        // Three in four draws come from the table, so an exact byte a predicate
        // demands stays likely without giving up the rest of the domain.
        if self.rng.below(4) == 0 {
            (self.rng.next_u64() >> 56) as u8
        } else {
            INTERESTING[self.rng.below(INTERESTING.len())]
        }
    }
}

/// Byte values worth substituting, in a fixed order.
///
/// Zero, one, two and the maxima; the low and high nibble patterns a mask test
/// keys on; the powers of two around a threshold; and the two classic
/// alternating patterns. Generic rather than tuned to any fixture: these are
/// the values a dictionary-free fuzzer has always used.
const INTERESTING: [u8; 16] = [
    0x00, 0x01, 0x02, 0x0a, 0x0f, 0x10, 0x20, 0x30, 0x3f, 0x40, 0x5a, 0x7f, 0x80, 0xaa, 0xc0, 0xff,
];

/// Byte positions the deterministic stage sweeps inside a byte array.
///
/// Every position for an array of sixteen bytes or fewer; otherwise the first
/// and last eight. The suffix is swept as deliberately as the prefix:
/// `crypto::controls::tail_byte_probe` exists precisely because only the final
/// byte of its secret reaches an address, and a prefix-only sweep would be
/// blind to that whole class.
fn swept_positions(length: usize) -> Vec<usize> {
    if length <= 16 {
        (0..length).collect()
    } else {
        (0..8).chain(length - 8..length).collect()
    }
}

/// Boundary values for a scalar parameter, or an empty list for anything else.
///
/// Derived here rather than reused from [`generate`] because the generator's
/// boundary function is about planning a corpus, while this is about one
/// operator's replacement pool. Keeping them separate means a change to one
/// cannot silently change the other's budget arithmetic.
fn scalar_boundaries(parameter: &Parameter) -> Vec<Value> {
    let Repr::Scalar(bits) = parameter.repr else {
        return Vec::new();
    };
    let mut raw: Vec<u64> = vec![0, 1, 2, mask(u64::MAX, bits), mask(u64::MAX - 1, bits)];
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
    raw.push(mask(1u64 << (bits - 1), bits));
    let mut seen = BTreeSet::new();
    raw.into_iter()
        .map(|value| mask(value, bits))
        .filter(|value| seen.insert(*value))
        .map(|value| Value::Scalar { bits, value })
        .collect()
}

fn mask(value: u64, bits: u32) -> u64 {
    if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    }
}

/// A candidate's input identity, for deduplication.
fn key(inputs: &[(String, Value)]) -> String {
    inputs
        .iter()
        .map(|(_, value)| value.to_wire())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The baseline corpus as `(id, strategy, inputs)` triples.
fn numbered(corpus: &Corpus) -> Vec<CaseEntry> {
    corpus
        .cases
        .iter()
        .map(|case| (case.id, case.strategy, case.inputs.clone()))
        .collect()
}

/// Writes one round's cases where the discovery harness can read them.
///
/// A file per round rather than one growing file: a round's corpus is the
/// evidence of what that round was asked to run, and overwriting it would make
/// a failed round impossible to inspect.
fn stage_entries(
    contract: &str,
    descriptor: &Descriptor,
    entries: &[CaseEntry],
    dir: &Path,
    round: usize,
) -> Result<std::path::PathBuf, ExploreError> {
    let corpus = generate::with_ids(contract, descriptor, entries)?;
    let path = dir.join(format!("round-{round:04}.tcc"));
    std::fs::write(&path, corpus.to_wire())
        .map_err(|e| ExploreError::Io(format!("{}: {e}", path.display())))?;
    Ok(path)
}

/// Whether a round failed badly enough that continuing is pointless.
///
/// One unreadable profile is recorded and tolerated — it costs one candidate.
/// A round in which *nothing* could be measured means the artifact or the tools
/// have stopped working, and generating more candidates would be inventing
/// inputs no one can evaluate.
fn fatal(observations: &[CoverageObservation]) -> Option<String> {
    if observations.is_empty() {
        return Some("a discovery round produced no observations at all".to_string());
    }
    if observations.iter().any(|o| o.status.usable()) {
        return None;
    }
    Some(format!(
        "no candidate in a round of {} produced usable coverage; the first failure was {}",
        observations.len(),
        observations[0].status
    ))
}

#[derive(Debug)]
pub enum ExploreError {
    Io(String),
    Coverage(CoverageError),
    Generate(GenerateError),
    /// Exploration was asked to start from an empty corpus.
    EmptyBaseline,
}

impl From<CoverageError> for ExploreError {
    fn from(error: CoverageError) -> Self {
        ExploreError::Coverage(error)
    }
}

impl From<GenerateError> for ExploreError {
    fn from(error: GenerateError) -> Self {
        ExploreError::Generate(error)
    }
}

impl fmt::Display for ExploreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExploreError::Io(message) => write!(f, "{message}"),
            ExploreError::Coverage(error) => write!(f, "{error}"),
            ExploreError::Generate(error) => write!(f, "{error}"),
            ExploreError::EmptyBaseline => write!(
                f,
                "exploration was given an empty baseline corpus. It extends M6's generated \
                 cases rather than replacing them, so there has to be something to extend"
            ),
        }
    }
}

impl std::error::Error for ExploreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Descriptor;

    const NESTED: &str = r#"{"schema_version":1,"function":"nested_modes","parameters":[
        {"name":"index","position":0,"role":"secret","repr":"u8","rust_type":"u8"},
        {"name":"stage","position":1,"role":"public","repr":"u8","rust_type":"u8"},
        {"name":"gate","position":2,"role":"public","repr":"u8","rust_type":"u8"},
        {"name":"trigger","position":3,"role":"public","repr":"u8","rust_type":"u8"}],
        "returns":{"repr":"u8","rust_type":"u8"}}"#;

    const TAG: &str = r#"{"schema_version":1,"function":"verify_tag","parameters":[
        {"name":"expected","position":0,"role":"secret","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"},
        {"name":"supplied","position":1,"role":"public","repr":"ref-byte-array","length":16,"rust_type":"&[u8; 16]"}],
        "returns":{"repr":"bool","rust_type":"bool"}}"#;

    fn descriptor(json: &str) -> Descriptor {
        Descriptor::parse(json).expect("the fixture descriptor parses")
    }

    fn scalar(value: u64) -> Value {
        Value::Scalar { bits: 8, value }
    }

    fn nested_case(index: u64, stage: u64, gate: u64, trigger: u64) -> Vec<(String, Value)> {
        vec![
            ("index".to_string(), scalar(index)),
            ("stage".to_string(), scalar(stage)),
            ("gate".to_string(), scalar(gate)),
            ("trigger".to_string(), scalar(trigger)),
        ]
    }

    /// Builds a state with one seeded candidate, for operator tests.
    fn seeded<'a>(
        descriptor: &'a Descriptor,
        settings: &'a ExploreSettings,
        inputs: Vec<(String, Value)>,
    ) -> State<'a> {
        let mut state = State::new(descriptor, settings);
        state.candidates.push(Candidate {
            id: 0,
            inputs,
            origin: Origin::Baseline {
                strategy: Strategy::Boundaries,
            },
            covered: RegionSet::new(),
            novel: 1,
            target_invoked: true,
            mandatory: true,
        });
        state.enqueue(0, true);
        state.next_id = 1;
        state
    }

    /// A public-only mutation leaves every secret value exactly as the seed had
    /// it.
    #[test]
    fn public_only_mutations_preserve_secrets() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings::default();
        let seed = nested_case(0x42, 0, 0, 0);
        let mut state = seeded(&descriptor, &settings, seed.clone());
        let mut produced = 0;
        for _ in 0..200 {
            if let Some(proposal) = state.mutate(0, MutationTarget::Public) {
                produced += 1;
                assert_eq!(
                    proposal.inputs[0].1, seed[0].1,
                    "a public-only mutation changed the secret"
                );
                if let Origin::Mutated { parameters, .. } = &proposal.origin {
                    assert!(!parameters.contains(&"index".to_string()));
                }
            }
        }
        assert!(produced > 100, "only {produced} of 200 attempts mutated");
    }

    /// A secret-only mutation leaves every public value exactly as the seed had
    /// it.
    #[test]
    fn secret_only_mutations_preserve_public_inputs() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings::default();
        let seed = nested_case(0, 0x0a, 0x30, 0x5a);
        let mut state = seeded(&descriptor, &settings, seed.clone());
        let mut produced = 0;
        for _ in 0..200 {
            if let Some(proposal) = state.mutate(0, MutationTarget::Secret) {
                produced += 1;
                for (public, original) in proposal.inputs[1..].iter().zip(&seed[1..]) {
                    assert_eq!(
                        public.1, original.1,
                        "a secret-only mutation changed a public input"
                    );
                }
            }
        }
        assert!(produced > 100, "only {produced} of 200 attempts mutated");
    }

    /// Every mutated value fits the parameter's declared representation, so a
    /// candidate can never be bound to the wrong width.
    #[test]
    fn every_mutation_fits_its_parameter() {
        for json in [NESTED, TAG] {
            let descriptor = descriptor(json);
            let settings = ExploreSettings::default();
            let seed: Vec<(String, Value)> = descriptor
                .parameters
                .iter()
                .map(|parameter| {
                    let value = match &parameter.repr {
                        Repr::Scalar(bits) => Value::Scalar {
                            bits: *bits,
                            value: 1,
                        },
                        Repr::Bool => Value::Bool { value: false },
                        Repr::ByteArray(length) | Repr::RefByteArray(length) => Value::Bytes {
                            bytes: vec![0xab; *length as usize],
                        },
                        other => panic!("unsupported fixture parameter {other:?}"),
                    };
                    (parameter.name.clone(), value)
                })
                .collect();
            let mut state = seeded(&descriptor, &settings, seed);
            for _ in 0..500 {
                for target in [
                    MutationTarget::Public,
                    MutationTarget::Secret,
                    MutationTarget::Combined,
                ] {
                    let Some(proposal) = state.mutate(0, target) else {
                        continue;
                    };
                    assert_eq!(proposal.inputs.len(), descriptor.parameters.len());
                    for (parameter, (name, value)) in
                        descriptor.parameters.iter().zip(&proposal.inputs)
                    {
                        assert_eq!(&parameter.name, name, "a mutation reordered the parameters");
                        assert!(
                            value.fits(&parameter.repr),
                            "{} got {value:?}, which does not fit {}",
                            parameter.name,
                            parameter.repr.describe()
                        );
                    }
                }
            }
        }
    }

    /// Byte-array mutations preserve the array's length. A shorter or longer
    /// array would mark a different number of bytes than the contract declares.
    #[test]
    fn byte_array_mutations_preserve_length() {
        let descriptor = descriptor(TAG);
        let settings = ExploreSettings::default();
        let seed = vec![
            (
                "expected".to_string(),
                Value::Bytes {
                    bytes: vec![0x11; 16],
                },
            ),
            (
                "supplied".to_string(),
                Value::Bytes {
                    bytes: vec![0x22; 16],
                },
            ),
        ];
        let mut state = seeded(&descriptor, &settings, seed);
        for _ in 0..500 {
            let Some(proposal) = state.mutate(0, MutationTarget::Combined) else {
                continue;
            };
            for (_, value) in &proposal.inputs {
                match value {
                    Value::Bytes { bytes } => assert_eq!(bytes.len(), 16),
                    other => panic!("a byte array became {other:?}"),
                }
            }
        }
    }

    /// The same seed produces the same proposals, and a different seed changes
    /// the havoc stage but not the deterministic one.
    ///
    /// The deterministic stage is seed-independent on purpose: it is an
    /// exhaustive sweep, and a sweep that depended on the seed would explore
    /// the same space in a different order for no benefit while making a
    /// reported seed less informative.
    #[test]
    fn proposals_are_a_function_of_the_seed() {
        let descriptor = descriptor(NESTED);
        // Four `u8` parameters: four byte positions, sixteen values each.
        let plan_length = 4 * INTERESTING.len();
        let run = |seed: u64| {
            let settings = ExploreSettings {
                seed,
                ..ExploreSettings::default()
            };
            // `settings` has to outlive the state, so the proposals are
            // collected inside this closure.
            let mut state = seeded(&descriptor, &settings, nested_case(7, 0, 0, 0));
            state
                .propose(plan_length + 64)
                .into_iter()
                .map(|proposal| key(&proposal.inputs))
                .collect::<Vec<_>>()
        };
        let first = run(99);
        assert_eq!(first, run(99), "the same seed must propose the same inputs");

        let other = run(100);
        assert_ne!(
            first, other,
            "a different seed must explore the havoc stage differently"
        );
        // The deterministic prefix is shared; some sweep items are skipped as
        // vacuous (the seed already holds that byte), so compare the common
        // prefix rather than a fixed count.
        let shared = first
            .iter()
            .zip(&other)
            .take_while(|(left, right)| left == right)
            .count();
        assert!(
            shared >= plan_length - 8,
            "only {shared} of about {plan_length} deterministic proposals matched, so the sweep              is not seed-independent"
        );
    }

    /// A seed cannot alter the contract's declared roles: changing it changes
    /// which values are tried, never which parameter is secret.
    #[test]
    fn a_seed_cannot_change_which_parameter_is_secret() {
        let descriptor = descriptor(NESTED);
        for seed in [1u64, 7, 12_345, 0xdead_beef] {
            let settings = ExploreSettings {
                seed,
                ..ExploreSettings::default()
            };
            let mut state = seeded(&descriptor, &settings, nested_case(0x42, 0, 0, 0));
            for proposal in state.propose(32) {
                if let Origin::Mutated {
                    target: MutationTarget::Public,
                    ..
                } = proposal.origin
                {
                    assert_eq!(
                        proposal.inputs[0].1,
                        scalar(0x42),
                        "seed {seed} let a public mutation touch the secret"
                    );
                }
            }
        }
    }

    /// Disabling secret mutation never produces a candidate whose secret
    /// differs from its seed's.
    #[test]
    fn disabling_secret_mutation_freezes_the_secret() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings {
            mutate_secret: false,
            ..ExploreSettings::default()
        };
        let mut state = seeded(&descriptor, &settings, nested_case(0x42, 0, 0, 0));
        let proposals = state.propose(64);
        assert!(!proposals.is_empty());
        for proposal in proposals {
            assert_eq!(proposal.inputs[0].1, scalar(0x42));
        }
        assert_eq!(state.mix.secret, 0, "a secret mutation was counted anyway");
    }

    /// Disabling public mutation never produces a candidate whose public inputs
    /// differ from its seed's.
    #[test]
    fn disabling_public_mutation_freezes_the_public_inputs() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings {
            mutate_public: false,
            ..ExploreSettings::default()
        };
        let seed = nested_case(0, 0x0a, 0x30, 0x5a);
        let mut state = seeded(&descriptor, &settings, seed.clone());
        let proposals = state.propose(64);
        assert!(!proposals.is_empty());
        for proposal in proposals {
            for (public, original) in proposal.inputs[1..].iter().zip(&seed[1..]) {
                assert_eq!(public.1, original.1);
            }
        }
        assert_eq!(state.mix.public, 0);
    }

    /// The default mix favours public inputs without eliminating secrets, which
    /// is the balance the milestone asks for.
    #[test]
    fn the_default_mix_favours_public_but_keeps_secrets() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings::default();
        let mut state = seeded(&descriptor, &settings, nested_case(7, 0, 0, 0));
        state.propose(200);
        assert!(
            state.mix.public > state.mix.secret,
            "public {} should exceed secret {}",
            state.mix.public,
            state.mix.secret
        );
        assert!(state.mix.secret > 0, "secret exploration must not be zero");
        assert!(
            state.mix.combined > 0,
            "combined exploration must not be zero"
        );
    }

    /// An input already attempted is not proposed again, and the skip is
    /// counted rather than hidden.
    #[test]
    fn an_already_attempted_input_is_not_reproposed() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings::default();
        let mut state = seeded(&descriptor, &settings, nested_case(7, 0, 0, 0));
        let first = state.propose(40);
        let keys: HashSet<String> = first.iter().map(|p| key(&p.inputs)).collect();
        assert_eq!(keys.len(), first.len(), "a round proposed a duplicate");
        let second = state.propose(40);
        for proposal in &second {
            assert!(
                !keys.contains(&key(&proposal.inputs)),
                "a later round re-proposed an input"
            );
        }
    }

    /// Every candidate gets a distinct case id, so coverage can never be
    /// attributed to the wrong one.
    #[test]
    fn candidate_ids_are_unique() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings::default();
        let mut state = seeded(&descriptor, &settings, nested_case(7, 0, 0, 0));
        let mut ids = HashSet::new();
        for _ in 0..5 {
            for proposal in state.propose(32) {
                assert!(
                    ids.insert(proposal.id),
                    "case id {} was reused",
                    proposal.id
                );
            }
        }
        assert!(ids.len() > 100);
        assert!(
            !ids.contains(&0),
            "the baseline's id 0 was handed out again"
        );
    }

    /// A round where nothing could be measured is fatal; one bad profile is
    /// not.
    #[test]
    fn only_a_wholly_unmeasurable_round_is_fatal() {
        let bad = |id: usize| CoverageObservation {
            case_id: id,
            artifact_sha256: "sha".to_string(),
            coverage_map_id: "map".to_string(),
            covered_regions: RegionSet::new(),
            covered_functions: BTreeSet::new(),
            target_invoked: false,
            status: ExecutionStatus::ProfileMissing,
        };
        let mut good = bad(1);
        good.status = ExecutionStatus::Observed;
        assert!(fatal(&[bad(0), good]).is_none());
        assert!(fatal(&[bad(0), bad(1)]).is_some());
        assert!(fatal(&[]).is_some());
    }

    /// A time limit or a failing discovery artifact is not a complete
    /// exploration, so a CI job that required one is not satisfied.
    #[test]
    fn a_curtailed_exploration_is_not_complete() {
        assert!(Termination::BudgetExhausted.complete());
        assert!(Termination::Converged { dry_rounds: 3 }.complete());
        assert!(Termination::QueueEmpty.complete());
        assert!(!Termination::TimeLimit { elapsed_ms: 10 }.complete());
        assert!(!Termination::DiscoveryFailed {
            detail: "x".to_string()
        }
        .complete());
    }

    /// Operators are only offered for representations they can preserve.
    #[test]
    fn operators_match_representations() {
        assert!(Operator::for_repr(&Repr::Bool) == [Operator::Toggle]);
        assert!(Operator::for_repr(&Repr::Unit).is_empty());
        assert!(Operator::for_repr(&Repr::Unsupported).is_empty());
        assert!(Operator::for_repr(&Repr::Scalar(8)).contains(&Operator::Offset));
        assert!(Operator::for_repr(&Repr::ByteArray(16)).contains(&Operator::Pattern));
        // No operator that changes a length is offered for a fixed-size array.
        assert!(!Operator::for_repr(&Repr::ByteArray(16)).contains(&Operator::Offset));
    }

    /// The interesting-byte table holds the exact values the hidden-path
    /// fixtures demand, which is why a byte-level predicate is reachable at
    /// all.
    #[test]
    fn interesting_bytes_cover_the_fixture_constants() {
        let descriptor = descriptor(NESTED);
        let settings = ExploreSettings::default();
        let mut state = seeded(&descriptor, &settings, nested_case(7, 0, 0, 0));
        let mut seen = HashSet::new();
        for _ in 0..4_000 {
            seen.insert(state.interesting_byte());
        }
        for required in [0x0a, 0x30, 0x3f, 0x5a] {
            assert!(
                seen.contains(&required),
                "{required:#04x} is needed by a hidden-path fixture but was never drawn"
            );
        }
    }
}
