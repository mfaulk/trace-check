//! What a unified run will actually execute, decided before anything heavy
//! starts.
//!
//! The policy says what each contract *owes* ([`crate::enforcement::Plan`]).
//! This says what will *run*, which is not the same thing: four named analyses
//! do not mean four backend invocations, because two of them share a backend
//! and one of them is a property of a whole test suite rather than of a
//! contract.
//!
//! # `explore` is not a separate proof level
//!
//! M7 coverage-guided discovery chooses which inputs to analyze. Every security
//! conclusion still comes from the same uninstrumented Memcheck artifact M6
//! uses, and an M7 run already includes the mandatory M6 corpus. So requiring
//! both `generated` and `explore` is **one** execution discharging two
//! obligations — not a baseline run followed by an explored one.
//!
//! That matters twice over. Running the baseline separately would double the
//! most expensive backend in the tool for no additional evidence; and
//! reporting the two results as independent observations would imply the
//! contract had been checked twice when it was checked once, with better
//! inputs.
//!
//! # Why the plan is a value
//!
//! It is built before any artifact is compiled, so it can be printed, asserted
//! on, and counted. "Requiring `generated` and `explore` must never result in
//! two equivalent Memcheck analyses" is a property of this structure, which a
//! test can check without running Valgrind at all.

use std::fmt::Write as _;

use serde::Serialize;

use crate::enforcement::{Analysis, Plan};

/// What one job does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "backend")]
pub enum Work {
    /// Generated dynamic checking under Memcheck, optionally preceded by
    /// coverage-guided input discovery.
    ///
    /// One variant rather than two, because there is one workflow: discovery
    /// selects a corpus and hands it to the same analysis. `explore` is a
    /// property of this job, never a second job.
    Generated { explore: bool },
    /// Bounded relational symbolic verification.
    Symbolic,
}

impl Work {
    pub fn describe(&self) -> &'static str {
        match self {
            Work::Generated { explore: true } => "LLVM coverage discovery + Memcheck",
            Work::Generated { explore: false } => "generated corpus + Memcheck",
            Work::Symbolic => "BINSEC relational verification",
        }
    }
}

/// One backend invocation, and the requirements it discharges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Job {
    pub contract: String,
    /// Flattened, so a job reads as `{"contract": …, "backend": "generated",
    /// "explore": true, "discharges": […]}` rather than burying the backend a
    /// level down. A consumer asking "how many Memcheck workflows did this run
    /// plan?" should not have to know the shape of an inner struct.
    #[serde(flatten)]
    pub work: Work,
    /// Every requirement this one execution answers.
    ///
    /// More than one only for the generated family: an explored run discharges
    /// `generated` as well, because the corpus it analyzed contains the
    /// boundary cases a baseline run would have used.
    pub discharges: Vec<Analysis>,
}

/// Developer-written `#[ct_test]`s, which are one pass over the whole suite.
///
/// Not per contract, deliberately. Discovery builds the Cargo test binaries
/// once and each test executes once; a per-contract job would rebuild the suite
/// per contract and run a test that covers two contracts twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DynamicJob {
    /// Contracts whose `dynamic` requirement this pass is expected to answer.
    pub contracts: Vec<String>,
}

/// Everything a unified run will execute.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExecutionPlan {
    pub jobs: Vec<Job>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic: Option<DynamicJob>,
}

impl ExecutionPlan {
    /// Translates outstanding requirements into the minimal set of
    /// invocations.
    ///
    /// `explore_configured` answers whether a contract's own configuration
    /// enables discovery, which is separate from the policy requiring it: a
    /// `[check."…".explore] enabled = true` asks for a search even where no
    /// `explore` obligation exists. Taken as a closure so this stays a pure
    /// function of the plan — the configuration and the command-line overrides
    /// that feed it are the caller's business.
    ///
    /// Only *outstanding* requirements produce jobs. A requirement already
    /// settled — exempted, unsupported, not selected, backend unavailable —
    /// has its answer, and running a backend to re-derive it would spend the
    /// analysis and then discard the result.
    pub fn resolve(plan: &Plan, explore_configured: &dyn Fn(&str) -> bool) -> ExecutionPlan {
        let mut jobs = Vec::new();
        let mut dynamic_contracts = Vec::new();
        for entry in &plan.entries {
            let outstanding = entry.outstanding();
            let family: Vec<Analysis> = outstanding
                .iter()
                .copied()
                .filter(|analysis| matches!(analysis, Analysis::Generated | Analysis::Explore))
                .collect();
            if !family.is_empty() {
                jobs.push(Job {
                    contract: entry.id.clone(),
                    work: Work::Generated {
                        // Explored when the policy requires it *or* the
                        // contract's configuration asks for it. An earlier
                        // revision looked only at the policy, so a configured
                        // search was silently skipped and the corpus analyzed
                        // was not the one the run was set up to analyze.
                        explore: family.contains(&Analysis::Explore)
                            || explore_configured(&entry.id),
                    },
                    discharges: family,
                });
            }
            if outstanding.contains(&Analysis::Symbolic) {
                jobs.push(Job {
                    contract: entry.id.clone(),
                    work: Work::Symbolic,
                    discharges: vec![Analysis::Symbolic],
                });
            }
            if outstanding.contains(&Analysis::Dynamic) {
                dynamic_contracts.push(entry.id.clone());
            }
        }
        ExecutionPlan {
            jobs,
            dynamic: (!dynamic_contracts.is_empty()).then_some(DynamicJob {
                contracts: dynamic_contracts,
            }),
        }
    }

    /// Jobs for one contract, in execution order.
    pub fn jobs_for(&self, contract: &str) -> Vec<&Job> {
        self.jobs
            .iter()
            .filter(|job| job.contract == contract)
            .collect()
    }

    /// How many invocations of each backend this plan will make.
    ///
    /// The number a deduplication claim is actually about. Requiring
    /// `generated` and `explore` of one contract must count **one** Memcheck
    /// workflow, not two.
    pub fn memcheck_jobs(&self) -> usize {
        self.jobs
            .iter()
            .filter(|job| matches!(job.work, Work::Generated { .. }))
            .count()
    }

    pub fn symbolic_jobs(&self) -> usize {
        self.jobs
            .iter()
            .filter(|job| job.work == Work::Symbolic)
            .count()
    }

    /// The plan as a developer reads it, grouped by contract.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        if self.jobs.is_empty() && self.dynamic.is_none() {
            return "Execution plan: nothing outstanding to run\n".to_string();
        }
        let _ = writeln!(out, "Execution plan");
        let mut contracts: Vec<&str> = self.jobs.iter().map(|job| job.contract.as_str()).collect();
        contracts.dedup();
        for contract in contracts {
            let _ = writeln!(out, "\n  {contract}");
            for (index, job) in self.jobs_for(contract).iter().enumerate() {
                let _ = writeln!(out, "    J{}: {}", index + 1, job.work.describe());
                let _ = writeln!(
                    out,
                    "        discharges: {}",
                    job.discharges
                        .iter()
                        .map(|analysis| analysis.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        if let Some(dynamic) = &self.dynamic {
            let _ = writeln!(
                out,
                "\n  Developer-written #[ct_test]s, one pass over the suite\n    \
                 discharges `dynamic` for: {}",
                dynamic.contracts.join(", ")
            );
        }
        let _ = writeln!(
            out,
            "\n  {} Memcheck workflow(s), {} symbolic verification(s)",
            self.memcheck_jobs(),
            self.symbolic_jobs()
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::VerifyConfig;
    use crate::enforcement::{test_support, Available, ContractPolicy, PolicyConfig};

    const CONTRACT: &str = "crypto::tag::verify_tag";
    const TODAY: &str = "2026-11-04";

    /// A plan for one contract requiring exactly `required`, with discovery
    /// not configured.
    fn plan_for(required: &[Analysis]) -> ExecutionPlan {
        plan_with(required, false)
    }

    fn plan_with(required: &[Analysis], explore_configured: bool) -> ExecutionPlan {
        let inventory = test_support::inventory(&[CONTRACT]);
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            CONTRACT.to_string(),
            ContractPolicy {
                required: Some(required.to_vec()),
            },
        );
        // A `[verify]` entry, so a symbolic requirement is not settled as a
        // configuration gap before it can produce a job.
        let mut config = VerifyConfig::empty();
        config.verify.insert(
            CONTRACT.to_string(),
            crate::contract::ContractSettings {
                description: String::new(),
                rationale: String::new(),
                max_depth: 4000,
                solver_timeout_secs: 30,
                wall_timeout_secs: 900,
                checks: vec![crate::symbolic::CheckFeature::ControlFlow],
                assumptions: Vec::new(),
                expected_outcome: "VERIFIED_BOUNDED".to_string(),
                expectation: None,
                inputs: Default::default(),
            },
        );
        let resolved = Plan::resolve(
            &inventory,
            &config,
            &policy,
            &[CONTRACT.to_string()],
            &Available::all(),
            TODAY,
        );
        ExecutionPlan::resolve(&resolved, &|_| explore_configured)
    }

    /// The deduplication table from the milestone, as a test.
    ///
    /// The row that matters is `generated` + `explore`: one Memcheck workflow,
    /// discharging both. Two would double the most expensive backend in the
    /// tool and produce no additional evidence.
    #[test]
    fn requirements_translate_to_the_minimal_set_of_invocations() {
        use Analysis::*;

        let plan = plan_for(&[Generated]);
        assert_eq!(plan.memcheck_jobs(), 1);
        assert_eq!(plan.symbolic_jobs(), 0);
        assert!(plan.dynamic.is_none());
        assert_eq!(plan.jobs[0].work, Work::Generated { explore: false });
        assert_eq!(plan.jobs[0].discharges, vec![Generated]);

        let plan = plan_for(&[Explore]);
        assert_eq!(plan.memcheck_jobs(), 1);
        assert_eq!(plan.jobs[0].work, Work::Generated { explore: true });
        assert_eq!(plan.jobs[0].discharges, vec![Explore]);

        // The load-bearing row.
        let plan = plan_for(&[Generated, Explore]);
        assert_eq!(
            plan.memcheck_jobs(),
            1,
            "requiring both must not run two Memcheck analyses: {}",
            plan.to_text()
        );
        assert_eq!(plan.jobs[0].work, Work::Generated { explore: true });
        assert_eq!(
            plan.jobs[0].discharges,
            vec![Generated, Explore],
            "the one execution answers both obligations"
        );

        let plan = plan_for(&[Symbolic]);
        assert_eq!(plan.memcheck_jobs(), 0);
        assert_eq!(plan.symbolic_jobs(), 1);

        let plan = plan_for(&[Generated, Symbolic]);
        assert_eq!(plan.memcheck_jobs(), 1);
        assert_eq!(plan.symbolic_jobs(), 1);

        // All four: one explored Memcheck workflow, one symbolic
        // verification, and one pass over the test suite.
        let plan = plan_for(&[Generated, Explore, Symbolic, Dynamic]);
        assert_eq!(plan.memcheck_jobs(), 1, "{}", plan.to_text());
        assert_eq!(plan.symbolic_jobs(), 1);
        assert_eq!(
            plan.dynamic.as_ref().map(|job| job.contracts.as_slice()),
            Some([CONTRACT.to_string()].as_slice())
        );
        assert_eq!(plan.jobs.len(), 2, "{}", plan.to_text());
    }

    /// Configuration can ask for discovery where no `explore` obligation
    /// exists, and it is still one job.
    ///
    /// The regression this preserves is M7's: a contract whose
    /// `[check."…".explore] enabled = true` asked for a search had it silently
    /// skipped when the policy did not also require `explore`, so the corpus
    /// analyzed was not the one the run was configured to analyze.
    #[test]
    fn configured_discovery_explores_without_an_explore_obligation() {
        let plan = plan_with(&[Analysis::Generated], true);
        assert_eq!(plan.memcheck_jobs(), 1);
        assert_eq!(plan.jobs[0].work, Work::Generated { explore: true });
        assert_eq!(
            plan.jobs[0].discharges,
            vec![Analysis::Generated],
            "a configured search does not create an obligation it was not asked to meet"
        );
    }

    /// A settled requirement produces no job: its answer is already known, and
    /// running a backend would spend the analysis and discard the result.
    #[test]
    fn a_settled_requirement_produces_no_job() {
        let inventory = test_support::inventory(&[CONTRACT]);
        let mut policy = PolicyConfig::default();
        policy.contracts.insert(
            CONTRACT.to_string(),
            ContractPolicy {
                required: Some(vec![Analysis::Generated, Analysis::Symbolic]),
            },
        );
        // No `[verify]` entry, so `symbolic` is settled as a configuration gap.
        let config = VerifyConfig::empty();
        let resolved = Plan::resolve(
            &inventory,
            &config,
            &policy,
            &[CONTRACT.to_string()],
            &Available::all(),
            TODAY,
        );
        let plan = ExecutionPlan::resolve(&resolved, &|_| false);
        assert_eq!(plan.symbolic_jobs(), 0, "{}", plan.to_text());
        assert_eq!(plan.memcheck_jobs(), 1);

        // And a contract left out of the selection runs nothing at all.
        let resolved = Plan::resolve(&inventory, &config, &policy, &[], &Available::all(), TODAY);
        let plan = ExecutionPlan::resolve(&resolved, &|_| false);
        assert_eq!(plan.jobs.len(), 0, "{}", plan.to_text());
        assert!(plan.dynamic.is_none());
    }

    /// The rendered plan names each job and what it discharges, so a developer
    /// can see that one execution answered two requirements.
    #[test]
    fn the_plan_renders_what_each_job_discharges() {
        let text =
            plan_for(&[Analysis::Generated, Analysis::Explore, Analysis::Symbolic]).to_text();
        assert!(text.contains(CONTRACT), "{text}");
        assert!(
            text.contains("J1: LLVM coverage discovery + Memcheck"),
            "{text}"
        );
        assert!(text.contains("discharges: generated, explore"), "{text}");
        assert!(
            text.contains("J2: BINSEC relational verification"),
            "{text}"
        );
        assert!(
            text.contains("1 Memcheck workflow(s), 1 symbolic verification(s)"),
            "{text}"
        );
    }
}
