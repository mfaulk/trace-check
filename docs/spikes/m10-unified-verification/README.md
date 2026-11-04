# M10.0 — Unified verification feasibility gate

**Status:** complete
**Branch:** `feat/m10-unified-verification`
**Subject:** `cbaudit::monty::mul_both_secret` in `examples/crypto-bigint-audit`
**Question:** can one invocation run two backends over one contract and keep
their evidence from being confused?

The gate exists because the rest of M10 is a scheduler, and a scheduler built on
the wrong seams produces a tool that reports a single confident verdict over
evidence that does not support it. So this spike runs the real backends — real
Valgrind, real BINSEC, no mocked outcomes — and the load-bearing result is not
that the run passes. It is that the two results are bound to **different
executables** and that neither can discharge the other's obligation.

## Result

One invocation, two backends, two artifacts:

```
cargo trace-check check --all-contracts --ci --config <audit config + policy.toml>
```

See *Reproducing* below for the exact invocation — the policy is an overlay on
the audit library's own configuration, not a replacement for it.

| Obligation | Backend | Outcome | Artifact |
| --- | --- | --- | --- |
| `generated` | Valgrind Memcheck | `NO_LEAK_OBSERVED` | `2d9f25d02a272bed…` |
| `symbolic` | BINSEC relational | `VERIFIED_BOUNDED` | `31bb717a767d476a…` |

Both requirements `CHECKED`, each by its own backend's evidence. The artifact
hashes differ, which is the point: they are different executables built from
different generated harnesses with different flags, and a shared hash would mean
one result was describing a binary it never analyzed.

The whole run, over the audit library's eighteen declarations:

| | |
| --- | --- |
| Contracts declared / reported | 18 / 18 |
| Requirements owed / checked | 19 / 19 |
| Violations | 0 |
| Exit code | 0 |
| Wall clock | 3:45 (see caveat) |
| Peak RSS | 167 MB |

The wall clock is one measurement on a machine that was also compiling
something else, so treat it as an order of magnitude and not a benchmark. It is
recorded because it establishes that the run completes in minutes rather than
hours; M9's 317 s figure for generated checking alone is the number to compare
against once there is something worth comparing.

Nineteen requirements over eighteen contracts: seventeen owe `generated` alone
on the M8 default, and the spike contract owes both.

Baselines for comparison, both already working in `main`:

| Standalone command | Outcome | Time |
| --- | --- | --- |
| `check --contract cbaudit::monty::mul_both_secret` | `NO_LEAK_OBSERVED` | 7.1 s |
| `verify --contract cbaudit::monty::mul_both_secret` | `VERIFIED_BOUNDED` | 3.6 s |

The generated artifact hash is identical between the standalone and the unified
run (`2d9f25d02a27…` in both), which is the cheapest available evidence that
orchestration changed which analyses run and not how they run.

No orchestration overhead was measured against a standalone-plus-standalone
baseline: with one symbolic contract among eighteen the difference is inside the
noise of Cargo cache state, and the measurement M10 actually needs is the one
after the planner exists (M10.5). Deferred to M10.8 rather than reported
imprecisely.

## What the spike had to change, and why

### 1. Per-contract work directories collided between backends

`Workspace::contract_dir` creates a directory with `create_dir` and treats
`AlreadyExists` as a collision to report rather than write into. That is the
right rule — two contracts landing on one directory must be an error — but it
made a second backend analyzing the *same* contract indistinguishable from a
collision. The generated analysis would take `contracts/<id>`, and the symbolic
analysis of the same contract would fail before it started.

`Backend` is now a path component, so the generated and symbolic analyses own
separate work directories and separate Cargo target directories. The collision
check still fires within one backend.

Target directories are split per backend as well, for a second reason: the two
harnesses are built with different profiles and link flags, so a shared target
directory would have each run invalidating the other's fingerprints, and would
put two executables that must never be confused in one place.

### 2. M5's per-contract runner split cleanly, and the split is load-bearing

`run_contract_verification`'s loop body became `stage_symbolic` (build the
artifact, resolve the symbol, construct the case — touching no analyzer) and
`verify_staged` (run the analyzer). `verify` and the unified run now reach the
backend through the same two functions, so there is one implementation of what
symbolic verification *is*.

The split is not cosmetic. It is what lets the orchestrator tell a
**per-contract** failure from a **shared infrastructure** failure:

* staging fails on an unsupported signature, a harness that will not compile or
  a symbol that does not resolve → a fact about one declaration, and becomes
  that contract's `UNSUPPORTED` status.
* staging fails any other way → recorded as that contract's `INCONCLUSIVE`
  rather than propagated. The generated stage aborts the run on a failure that
  is not about one contract, which is defensible when nothing has been
  established yet; by the symbolic stage the generated evidence is already in
  hand, and discarding it to report an error that is also in the report would
  lose more than it tells anyone. Neither status can pass.
* the analyzer is unavailable → applies to every symbolic requirement in the
  run, is diagnosed once, and becomes `BACKEND_UNAVAILABLE`.

Before the split both arrived as the same `HarnessError` from the same call.

M5's error-ordering rule is preserved: the analyzer is prepared only after
everything decidable about the contract has been decided, so a problem with the
contract is still reported as a problem with the contract.

### 3. Symbolic evidence enters M8 as its whole record

`library_report::contract_report` was extracted from `library_report::build`, so
a unified run can hold one contract's symbolic record without assembling a
standalone report around it. `AnalysisEvidence` carries it in a new `symbolic`
field, which keeps the artifact, the symbol binding, the reachability evidence,
the input roles, the declared and generated input domain, the observation
classes checked, the depth bound, the solver timeout and the raw case result.

No new parallel evidence type was invented. `ContractReport` already carried
everything the milestone's symbolic-evidence list asks for, and a second type
would be a second thing to keep in sync.

### 4. Evidence is validated against the obligation, not trusted for its wording

`AnalysisEvidence::from_symbolic` refuses to promote a clean result that is not
about this obligation. The backend's own `classify` already decides whether the
*analysis* was sound — target reached, exploration complete, no unknown solver
answers, every requested observation class counted, depth bound held. The
enforcement boundary needs a different question answered: is this record about
*this contract* and *this artifact*, covering the observation classes the
*configuration* asked for?

Two questions, deliberately answered separately, because the right treatment of
a failing leak differs between them.

**Identity** — is this record about this obligation at all? Rejected
unconditionally, including a detected leak:

* a record about another contract, or whose symbol binding resolved another;
* a record describing an artifact that is not the one this run built;
* a record whose per-case artifact hash disagrees with its own report's.

A leak found in another contract's run is not weak evidence about this one; it
is evidence about something else. Folding it in here would attribute a real
finding to the wrong function — sending a developer to read code that is fine,
and leaving the contract the leak belongs to without it. Both outcomes fail
strict CI, so rejecting loses no safety and gains an accurate diagnosis.

**Coverage** — did it establish enough? Rejected unless the result is a leak:

* a result the analyzer never attributed to the contract's symbol;
* a result covering fewer observation classes than the configuration declared.

Here the record *is* about this contract's own artifact, so a satisfiable
relational query is positive evidence and a narrower observation model than the
configuration asked for cannot un-discover it. (The first case cannot arise from
the backend today — M5's `classify` already refuses to attribute anything to an
unreached target — and is checked because enforcement must not depend on that
staying true.)

The observation model comes from configuration, never from whichever checks the
backend happened to run — otherwise a result would define the requirement it
satisfies.

## Three defects found

### Advisory mode made `--ci` fail open

`Coverage::blocking` skips gaps in advisory mode, by design. But `--ci` was
accepted alongside it, so `check --all-contracts --ci` against a policy with
`mode = "advisory"` exited **0** over a report in which every requirement was
unmet. A project that set advisory mode once during adoption and forgot would
have had a permanently green CI job that established nothing.

`--ci` now refuses an advisory policy rather than resolving the contradiction in
either direction: silently enforcing would break the adoption workflow, and
silently tolerating is the fail-open.

### One expectation per contract cannot hold the M9 disagreement fixtures

> **Resolved in M10.1.** Expectations are now modelled per analysis and both
> fixtures are enforceable; the gap status described below no longer occurs.
> This section records what the gate found, and is left as written.

This is the problem M10.1 exists for, and the spike confirmed it is real in
`main` rather than hypothetical.

`PlanEntry::regression_expectation` is a single `Option<Outcome>` per contract,
read from the `[check]` table. Two of M9's fixtures declare different outcomes
per backend:

| Contract | `[check]` | `[verify]` |
| --- | --- | --- |
| `cbaudit::hidden::magic_gate` | `NO_LEAK_OBSERVED` | `LEAK_DETECTED` |
| `cbaudit::hidden::nested_modes_wide` | `NO_LEAK_OBSERVED` | `LEAK_DETECTED` |

Both columns are correct. A leak behind an exact public-input equality is not
reached by generated inputs and is solved for by symbolic execution. Folding the
symbolic result against the generated expectation would report these fixtures as
*misbehaving* when they are behaving exactly as declared.

Rather than mis-attribute the result, `Plan::resolve` now settles such a
contract's symbolic requirement as `INCONCLUSIVE`, naming the conflict and the
standalone command that can still verify it. Strict CI fails, which is correct —
the obligation genuinely cannot be enforced yet — and nothing is judged against
the wrong expectation.

Also confirmed: `[verify."…"]` requires `expected_outcome` and has no
`expectation` field, so the symbolic table cannot express the
security-contract/analyzer-regression split at all. M10.1 has to make it
optional for security contracts while preserving the existing fixtures.

### The symbolic artifact hash was not reproducible

Two consecutive standalone `verify` runs of the same contract against the same
library reported **different** artifacts:

```
run1: 31c332ab1e5e29fd8881…
run2: ccebdc4c371cc0ea7b90…
```

The symbolic harness is built in a randomly named work directory with
`debug = true`, so the generated source's absolute path was baked into the
DWARF and the hash was a function of the temporary directory rather than of the
inputs.

This is a pre-existing M5 property, not something the spike introduced — but it
is incompatible with the milestone's own evidence rules. The artifact hash *is*
the artifact's identity: M10 accepts symbolic evidence only when it names the
artifact its obligation is about, and an identity that changes every run cannot
be compared to anything. It is also the concrete reason the plan is right to
defer a cross-run evidence cache: there was no stable key to cache under.

M6's generated harness has carried `--remap-path-prefix` for exactly this reason
since it was written. The symbolic harness now does too, against the same
`REMAPPED_HARNESS_DIR`, and the hash is stable across runs:

```
run1: 31bb717a767d476aa66e…  VERIFIED_BOUNDED
run2: 31bb717a767d476aa66e…  VERIFIED_BOUNDED
```

Worth noting what this does *not* make reproducible. The hash is now a function
of the library, the dependency lockfile, the generated harness source, the
compiler and the build flags — all of which the report already records. It is
not a claim of bit-for-bit reproducibility across machines or toolchains, and
the recorded provenance remains the thing that says which build a result is
about.

## One open question, not a finding

The generated harness packages are built in the run's work directory, which for
an ephemeral workspace is under `/tmp` — outside the repository. `rustup`
resolves a toolchain by walking up from the working directory, so those builds
do not see the repository's `rust-toolchain.toml` and use the machine's
**default** toolchain. Neither harness generator writes a `rust-toolchain.toml`
or sets `RUSTUP_TOOLCHAIN`.

Meanwhile `rustc_version` in every report comes from running `rustc --version`
in trace-check's own working directory, which *does* see the pin.

So on a machine whose default toolchain differs from the pinned one, the
recorded compiler would not be the compiler that built the analyzed artifact —
and "compiler version" is on M10.2's list of things an artifact identity must
carry. The two toolchains happened to resolve to the same `rustc 1.97.0` on the
development machine, so **this was not observed and is not a measured defect.**
It is recorded here because it is cheap to check and expensive to discover from
a wrong report, and because M10.2 is the package that should either pin the
toolchain for generated builds or read the version from the build that actually
ran.

## What this settles for the rest of M10

* **Extraction is safe.** M5's verification semantics are unchanged. The
  standalone `verify` suite and the M4/M5 symbolic suites were not edited at all
  and still pass; `tests/library.rs` gained one test and changed none.
* **One analyzer per run.** The verifier is prepared once and reused; its
  identity is shared because it describes the analyzer, while artifact
  identities are per contract and stay on each result.
* **Lazy preparation works per policy.** The analyzer is prepared only when some
  declaration's policy requires symbolic analysis, so a project requiring
  nothing symbolic still needs no container runtime.
* **Failure isolation is per contract.** A contract whose symbolic harness will
  not build gets a status; unrelated contracts still produce results.
* **Evidence survives a backend failure.** With the analyzer unreachable, the
  generated analysis still completes and still reports, and the symbolic
  requirement is `BACKEND_UNAVAILABLE` — never substituted for.

## What the spike did *not* do

Deliberately out of scope, each belonging to a later package:

* No execution planner and no deduplication of `generated` against `explore`
  (M10.5). Requiring both still goes through the existing single Memcheck
  workflow, but there is no plan representation yet.
* No concurrency (M10.6). Backends run sequentially, in inventory order.
* No M3 dynamic-test integration (M10.4). A `dynamic` requirement is still
  reported as evidence this command does not produce, pointing at
  `cargo trace-check test`.
* No per-analysis expectations — M10.1, now done; see the defect above.
* No report schema change (M10.7). The unified report is still schema 2, with
  symbolic evidence added as a new field rather than a reinterpretation of an
  existing one. `--ci` is now honoured on the `--all-contracts` path, where it
  previously only affected `--all-configured`.

## Reproducing

```sh
# The gate, as tests. Skips without a container runtime or the analyzer image;
# TRACE_CHECK_REQUIRE_SYMBOLIC=1 turns a skip into a failure.
cargo test -p trace-check --test unified

# The gate, end to end through the real binary, checking the report rather
# than the exit code.
cat examples/crypto-bigint-audit/trace-check.toml \
    docs/spikes/m10-unified-verification/policy.toml > /tmp/unified.toml
cd examples/crypto-bigint-audit
cargo trace-check check --all-contracts --ci --config /tmp/unified.toml \
    --format json > /tmp/unified.json
python3 ../../ci/verify-m10-feasibility.py /tmp/unified.json
```
