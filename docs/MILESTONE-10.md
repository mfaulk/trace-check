# Milestone 10 — Unified Multi-Backend Verification and CI Enforcement

**Status:** Implemented. M10.0–M10.8 complete, with a review round recorded in
§11; the outstanding items are in §13.
**Branch:** `feat/m10-unified-verification`, then one branch per package
**Prerequisite:** Milestone 9, merged
**Primary platform:** Linux x86-64, pinned Rust toolchain

---

## 1. What M10 is for

M1–M9 built four analysis mechanisms and left a developer to coordinate them by
hand: `check` for generated testing, `check --explore` for coverage-guided
discovery, `verify` for bounded symbolic verification, `test` for
developer-written `#[ct_test]`s. M8 could *represent* all four as policy
obligations, but `check --all-contracts` executed only the generated family, so
a contract requiring symbolic verification was reported as not analyzed even on
a machine where the standalone command would have established it.

M10 makes one command execute the analyses a policy requires and produce one CI
decision from them.

The architectural rule the whole milestone exists to hold is that **evidence is
never promoted beyond what its backend established.** `NO_LEAK_OBSERVED` from
Memcheck does not satisfy a symbolic requirement. `VERIFIED_BOUNDED` for a
freestanding verification executable does not establish that a different
production binary is constant-time. Two requirements satisfied for one contract
are two results about two binaries, not one result about the function.

---

## 2. Packages

| Package | Scope | State |
| --- | --- | --- |
| M10.0 | Real two-backend feasibility gate and integration seams | complete |
| M10.1 | Per-analysis expectations and security-policy semantics | complete |
| M10.2 | Typed artifact-bound evidence model | complete |
| M10.3 | Refactor and integrate the M5 symbolic runner | complete |
| M10.4 | Integrate M3 developer-written dynamic tests | complete |
| M10.5 | Unified execution planner and backend deduplication | complete |
| M10.6 | Bounded scheduling, isolation and failure handling | complete |
| M10.7 | Unified CLI, reporting and schema migration | complete |
| M10.8 | Acceptance, mutation tests, benchmarks, CI and documentation | complete |

---

## 3. M10.0 — the feasibility gate

Recorded in full, with its measurements and the three defects it found, in
[`docs/spikes/m10-unified-verification/README.md`](spikes/m10-unified-verification/README.md).

In summary: one invocation of `check --all-contracts --ci` runs Valgrind and
BINSEC over `cbaudit::monty::mul_both_secret`, discharges both obligations with
each backend's own evidence, and binds the two results to two different
executables.

| Obligation | Backend | Outcome | Artifact |
| --- | --- | --- | --- |
| `generated` | Valgrind Memcheck | `NO_LEAK_OBSERVED` | `2d9f25d02a272b…` |
| `symbolic` | BINSEC relational | `VERIFIED_BOUNDED` | `31bb717a767d47…` |

The gate also found and fixed: `--ci` passing under an advisory policy, and a
symbolic artifact hash that was a function of its temporary directory rather
than of its inputs.

---

## 4. M10.1 — one purpose per contract, one declared outcome per backend

### The problem

M6 introduced the distinction M10 depends on: a **security contract** must not
accept a detected leak, while an **analyzer-regression fixture** may expect
trace-check to detect a planted one. M8 preserved it with a single
`regression_expectation` per contract, read from the `[check]` table.

One value per contract cannot describe the fixtures this project already has.
Two of them genuinely disagree by backend, in opposite directions:

| Fixture | `[check]` | `[verify]` | Why both are right |
| --- | --- | --- | --- |
| `cbaudit::hidden::magic_gate` | `NO_LEAK_OBSERVED` | `LEAK_DETECTED` | the leak sits behind an exact public-input equality; generated inputs never guess it, a solver solves for it |
| `cbaudit::hidden::nested_modes_wide` | `NO_LEAK_OBSERVED` | `LEAK_DETECTED` | the same, over a wider gate |
| `crypto::tag::verify_tag_early_exit` | `LEAK_DETECTED` | `VERIFIED_BOUNDED` | the dynamic backend's artifact keeps the per-byte branch; the symbolic backend's vectorizes it away |

These are not contradictory evidence. They are two honest answers about two
compilations, which is why every result carries the hash of the executable it
analyzed. Judging one backend's result against another's declaration reports a
fixture that is behaving exactly as declared as broken.

M10.0 settled such a requirement as an explicit gap — fail-closed, and
unenforceable.

### What changed

**Purpose stays single.** A contract is a security contract or an
analyzer-regression fixture, never one for one backend and the other for
another, because that is precisely how a declared leak would come to excuse a
real one. `VerifyConfig::purpose` resolves it: a fixture when *either* table
declares `expectation = "analyzer-regression"`, and a security contract
otherwise. Either table is enough rather than requiring agreement — the
declaration is an explicit opt-out of the security reading, nobody writes it by
accident, and an unstated `[check]` purpose is indistinguishable from an
explicitly stated default one.

**The declared outcome is per analysis.**
`enforcement::regression_expectations` maps each analysis to what the fixture
declares for it: `[check]` governs `generated` and `explore` — the same backend
over better-chosen inputs, which cannot be declared to disagree with itself —
and `[verify]` governs `symbolic`. Nothing governs `dynamic`, because M3 has no
expectation syntax; a `dynamic` requirement on a fixture is reported as the
configuration gap it is rather than guessed at.

`Coverage::fold` looks the expectation up by the analysis that produced the
evidence, and `ContractCoverage::violated` asks whether **the backend that found
the leak** predicted it. A leak from a backend the fixture declared clean is a
real surprise and still fails: a declaration excuses only the finding it
predicted.

**`[verify]` gained the `expectation` field.** M4 and M5 predate the split, so a
fixture configured only for symbolic verification — `external_library::
digest_nibble` is the one in this repository — had no way to say that detecting
its planted leak is the test passing.

**A security contract declaring a leak is refused at load.**
`CheckSettings::validate` has refused `expected_outcome` on a security contract
since M6. `[verify]` could still say `LEAK_DETECTED` on one, so the only thing
standing between a stray declaration and an excused leak was enforcement
getting it right every time. The contradiction is now a configuration error.
`VERIFIED_BOUNDED` and `INCONCLUSIVE` remain declarable there: those are
tripwires on the analyzer and the toolchain, and neither can excuse a leak.

### Migration

One committed configuration relied on the old implicit reading:
`examples/external-library/trace-check.toml` declares
`expected_outcome = "LEAK_DETECTED"` for `external_library::digest_nibble` with
no `[check]` table at all. It now says `expectation = "analyzer-regression"`
explicitly. Without that line the configuration is refused at load, which is
the intended migration — loud, not silent. No existing analyzer-regression
configuration was reinterpreted: every other fixture already declared its
purpose in `[check]`, and that declaration now reaches the symbolic expectation
as well.

### Measured evidence

`check --all-contracts --ci` over the eighteen `crypto-bigint` audit contracts,
with the policy overlay in
[`docs/spikes/m10-unified-verification/policy.toml`](spikes/m10-unified-verification/policy.toml)
requiring both backends of one security contract and both disagreement fixtures:

| Contract | `generated` | `symbolic` | Status |
| --- | --- | --- | --- |
| `cbaudit::monty::mul_both_secret` | `NO_LEAK_OBSERVED` | `VERIFIED_BOUNDED` | both `CHECKED` |
| `cbaudit::hidden::magic_gate` | `NO_LEAK_OBSERVED` | `LEAK_DETECTED` | both `CHECKED` |
| `cbaudit::hidden::nested_modes_wide` | `NO_LEAK_OBSERVED` | `LEAK_DETECTED` | both `CHECKED` |

21 of 21 requirements satisfied, 0 violations, exit 0, 3:57 wall clock, 169 MB
peak RSS. Each contract's two results carry different artifact hashes.

The inverse direction is covered against `examples/crypto-library` by
`the_inverse_disagreement_is_enforced_too`, which requires both backends of
`crypto::tag::verify_tag_early_exit` and asserts `LEAK_DETECTED` from generated
testing alongside `VERIFIED_BOUNDED` from symbolic verification, both `CHECKED`.

### Negative coverage

Each of the plan's required negative tests, and where it lives:

| Property | Test |
| --- | --- |
| A security contract cannot declare a leak acceptable | `a_security_contract_declaring_a_leak_is_refused_at_load` (load time) and `a_leak_fails_a_security_contract_that_declared_it_clean` (enforcement) |
| Per-backend declarations coexist and are evaluated independently | `a_fixture_may_declare_a_different_outcome_per_backend`, `the_inverse_disagreement_is_enforced_too`, `a_fixture_is_judged_per_analysis` |
| An unmet symbolic regression expectation fails the fixture | `a_fixture_is_judged_per_analysis` (swapped outcomes) |
| A generated result cannot satisfy a symbolic requirement, or vice versa | `neither_backend_can_discharge_the_other_requirement` |
| An inconclusive result cannot satisfy any requirement | `an_inconclusive_result_does_not_satisfy_a_requirement` |
| A waiver cannot erase observed leakage | `an_exemption_cannot_erase_a_detected_leak`, `nothing_overwrites_a_recorded_leak` |
| A fixture declaring nothing for a required analysis cannot pass it | `a_fixture_with_no_declaration_for_an_analysis_cannot_pass_it` |
| Either table may declare the purpose | `either_table_may_declare_an_analyzer_regression` |

`ci/verify-m10-feasibility.py` asserts the same properties against the report
rather than the exit code, and now **requires** the report to contain at least
one fixture whose declarations differ by backend — without one, nothing in CI
would notice if a backend's result were judged against another's declaration.

### Report shape

`ContractCoverage.regression_expectation` (a string) became
`regression_expectations` (an analysis-to-outcome object), omitted entirely for
a security contract. `ci/verify-m8-contracts.py` reads the new shape. The
unified report stays at schema 2: the field is a refinement of an M8 field that
no released consumer outside this repository reads, and M10.7 owns the
deliberate schema migration.

---

## 5. M10.2 — every result names the executable it describes

### The problem

A security result is a claim about one compiled artifact, never about a function
in general. M8's evidence carried a bare `artifact_sha256`, which is enough to
say two results are about different bytes and not enough to say *why* — and a
developer looking at a clean generated result beside a symbolic one needs that
before deciding what either establishes.

Worse, one of the fields that decides those bytes was **recorded wrong**.

### The provenance defect

`rustup` resolves a toolchain by walking up from the working directory.
trace-check runs in the developer's project and sees its `rust-toolchain.toml`;
the harnesses it generates are built in a private work directory, which for an
ephemeral workspace is under `/tmp` and sees no such file. So:

* `rustc --version` was measured where trace-check runs — the pinned toolchain
  — and recorded as the artifact's compiler;
* the artifact was built where the harness lives — the **default** toolchain.

Reproduced against a staged copy of `examples/crypto-library` pinning 1.88.0 on
a machine whose default was 1.97.0:

| run | recorded | artifact |
| --- | --- | --- |
| relying on the library's pin | `1.88.0` | `e3b4a92fb9786d5b…` |
| 1.88.0 forced everywhere | `1.88.0` | `4d71088ab29dddd0…` |
| 1.97.0 forced everywhere | `1.97.0` | `e3b4a92fb9786d5b…` |

The first row reports 1.88.0 and is byte-identical to the 1.97.0 build. The
recorded compiler was not the compiler that ran.

It is also wrong on its own terms, independently of reporting: a developer who
pins a toolchain pins the code their project compiles, and verifying a build by
a different compiler analyzes code they do not ship.

`crate::toolchain` now resolves the toolchain once from the **library's**
manifest directory and forces it on every generated build — the probe, the
inventory, the generated harness and the verification harness — through
`RUSTUP_TOOLCHAIN`. The version is then measured through that same toolchain,
so the recorded compiler is the one that ran. With the fix the first row
produces `4d71088ab29dddd0…`, matching the pinned build.

The ambient `RUSTUP_TOOLCHAIN` is **cleared** during resolution, which is a
deliberate choice with a cost. rustup's cargo shim sets that variable for every
child process, so `cargo trace-check` inherits the toolchain resolved from the
*invocation* directory — not the library's. `--manifest-path` pointing at a
differently-pinned project is exactly the shape this repository's own CI uses,
and the inherited value would silently win. The library's pin is the authority
because the library is the code being analyzed. The cost is that
`cargo +1.99 trace-check verify` no longer selects 1.99 for the analysis build;
`rustup override set` and `rust-toolchain.toml` both still work, because both
are directory resolution.

### The identity

`evidence::ArtifactIdentity` is one shape for every backend, carrying the
inputs that decide the artifact's bytes:

| Field | Why it is part of the identity |
| --- | --- |
| `contract` | which declaration the artifact was built to analyze |
| `descriptor_sha256` | the annotation's own output: a changed secret role or parameter width changes it, and a result recorded against one descriptor says nothing about a contract that now declares something else |
| `library_package`, `library_version` | the code under analysis |
| `features` | another feature combination is another library |
| `target` | another architecture is another artifact |
| `toolchain` | the compiler that built it, measured through itself |
| `profile` | the build settings, including the panic strategy and link flags |
| `artifact_sha256` | the analyzed executable |
| `lockfile_sha256` | the resolved dependency graph |
| `harness_sha256` | the generated surroundings |
| `backend`, `backend_version` | which analyzer, and what it reports about itself |
| `analyzer_image` | symbolic only, by digest: the image *is* the analyzer and its bundled solver |

`ArtifactIdentity::differences` reports how two identities for one contract
differ by **naming the inputs**, because "these are two different binaries" is
not actionable and "they were built with different profiles by different
compilers" is.

Writing the identity surfaced a smaller defect of its own: `harness::PROFILE`
and `dynamic_harness::PROFILE` are the *same string*, so the two backends'
build settings were described identically despite one being a freestanding
`panic=abort` `-nostdlib` build and the other a hosted unwinding one. The
identity spells out the difference; the test that compares two backends' inputs
is what caught it.

### Validation at the enforcement boundary

Both backends' evidence now goes through a constructor that refuses to promote
a clean outcome the record does not support, and neither can be bypassed —
there is no way to build evidence without passing through one.

* `from_symbolic` checks identity (contract, symbol binding, artifact)
  unconditionally, then coverage (target reached, observation classes). See §4.
* `from_generated` checks that the record is about this contract, that both
  positive controls fired, and that every planned case completed.

`check::run` already gates `NO_LEAK_OBSERVED` behind both controls and behind
every batch completing, so the generated states are unreachable from the
backend today. That is precisely why they are checked here: the policy layer
reads only an outcome, and a record whose own fields contradict it must not be
able to discharge a requirement. A detected leak is never downgraded by either.

The identity is also now the **authority** on what an obligation is about. It
is built from the executable this run produced, before the analyzer runs, and
the backend's report is checked against it rather than the reverse.

### Scope limitation, kept

Only evidence produced and validated in the current unified execution can
discharge a requirement. Nothing imports historical reports, and there is no
cross-run evidence cache — the identity is now rich enough to key one, which is
a reason to design it deliberately rather than a reason to add it here.

---

## 6. M10.4 — developer-written `#[ct_test]`s as enforcement evidence

M3 already ran these tests under Memcheck and already proved, per test, that
the declared contract's function was invoked through the instrumented adapter.
What it did not do was bind them to the compiler-derived inventory and
aggregate them into one answer per contract, which is what a `dynamic` policy
requirement needs.

### Where the split falls

Discovery and execution stay in the CLI (`dynamic_adapter`), where the Cargo
test binaries and the Valgrind processes already live; binding, validation and
aggregation are in the library (`trace_check::dynamic`), because those are the
security decisions. Nothing is reimplemented — `build_test_binaries`,
`discover`, `resolve_targets` and `run_test` are the same functions
`cargo trace-check test` uses, so a unified run and a standalone one cannot
disagree about what a test established.

Test binaries are built **only** when some policy asks for `dynamic`. A project
requiring nothing dynamic must not pay for a `cargo test --no-run`, nor have a
missing test suite reported against an obligation it does not have. Tests that
declare no `target` are not run at all: they cannot discharge a
contract-specific obligation, so spending a Valgrind process on them would
produce evidence nothing can use. `cargo trace-check test` still runs them.

### Binding

A `#[ct_test(target = "...")]` is written module-relative — `tag::verify_tag`
for `crypto::tag::verify_tag` — so matching is by **path-boundary suffix**:
`verify_tag` and `tag::verify_tag` both match, `ify_tag` does not, and `verify`
does not match `verify_tag`. A target matching more than one contract is
ambiguous and binds to **nothing** rather than being guessed at.

That is M3's existing rule, and there is now one implementation of it:
`report::targets` delegates to `dynamic::matches_target`. A rule that decided
coverage one way for `test` and another for `check --all-contracts` would make
the two commands disagree about the same test.

Binding resolves against the **inventory**, not the test binaries' own contract
metadata. The two are built differently — one from the library's rlib, one from
the test executables — and a target that resolves in one and not the other must
not quietly bind.

### Aggregation

Deterministic and fail-closed, in order:

1. a detected leak is preserved, whatever else passed, and the finding is kept
   in the detail;
2. a test that did not complete, whose controls did not fire, or that never
   reached its target prevents a clean aggregate;
3. a clean aggregate requires **every** bound test to have completed with valid
   controls and a confirmed invocation;
4. the same test executed twice counts once — keyed on the test *and* its
   executable, so one harness path in two executables is two tests while one
   test run twice is one;
5. a contract with no bound test is `NOT_ANALYZED`, never clean.

### Artifact identity

`Backend::DeveloperTest` is a third backend name: the same Valgrind Memcheck as
the generated family over a different *source of inputs*. A developer choosing
the inputs and a generator choosing them are different evidence about the same
property, and a reader comparing two results needs to know which they have.

For a developer-written test there is no separate generated harness to
fingerprint — the test code **is** the harness — so `harness_sha256` names the
same executable as `artifact_sha256`. When two test targets both cover a
contract, `artifact_sha256` is a digest over their sorted hashes with each named
in the evidence, because a result drawn from two executables is about both and
naming one would be a claim about an artifact that produced half the evidence.

### A defect in the adapter, found by the acceptance test

The first version of the adapter set `completed: true` unconditionally,
reasoning that `run_test` returns an error rather than an outcome when a process
cannot be run. That was wrong: M3 uses `Calibration::NotRun` to mark a test that
did not get as far as its constant-time check — it failed, timed out, was
killed, or produced unparseable output.

The acceptance test exposed it. Breaking the subject test's invocation produced
"produced no positive control", naming the wrong cause: M3's own `#[ct_test]`
harness asserts the invocation and *fails* the test, so the run had not
completed at all. `completed` is now derived from the calibration marker, and
the not-completed diagnostic carries M3's own message, which names the real
reason.

That also corrected the record on where the invocation guarantee comes from:
M3 enforces it, and `invoked_target` is re-checked at this boundary for the same
reason the other backends' completion evidence is — the policy layer reads an
outcome, and a run whose own record says it never reached the contract must not
discharge an obligation about it however that came to be.

### Measured evidence

`examples/crypto-library`'s `crypto::tag::verify_tag` is the acceptance subject:
the one contract here that all three analyses can be configured for. One
`check --all-contracts --ci` invocation with
`required = ["generated", "symbolic", "dynamic"]`:

| Obligation | Backend | Outcome |
| --- | --- | --- |
| `generated` | `valgrind-memcheck` | `NO_LEAK_OBSERVED` |
| `symbolic` | `binsec-relational` | `VERIFIED_BOUNDED` |
| `dynamic` | `valgrind-ct-test` | `NO_LEAK_OBSERVED` |

Three analyses, three distinct artifact hashes, all three `CHECKED`.

`breaking_the_dynamic_test_fails_only_the_dynamic_requirement` is the
load-bearing one. It rewrites the test body to mark a secret and exercise a
*different* contract's adapter — so the test still compiles, still passes, and
still declares its target. The `dynamic` requirement fails with a diagnostic
naming the missing invocation, and the generated and symbolic results are
unchanged **down to their artifact hashes**, because the library's own code did
not change. Calling the real function directly instead would also fail, but on
calibration rather than invocation: a correct refusal for the wrong reason, and
it would leave the invocation check untested.

---

## 7. M10.5 — one execution plan, and no redundant backend runs

### What was already true, and what was missing

The unified run already invoked the generated backend once per contract and
folded that one result against both a `generated` and an `explore` obligation,
so the expensive half of deduplication was never broken. Three things were
missing.

**Nothing said so.** The decision was spread across an inline loop and derived
per contract at execution time. "Requiring both must never run two Memcheck
analyses" was true by accident of control flow rather than by construction, and
nothing could assert it without running Valgrind.

**The report double-counted.** Two evidence records with the same artifact hash
and the same case counts read as two independent observations. A reader counting
evidence would conclude the contract had been checked twice, when it was checked
once with better inputs.

**`dynamic` was modelled per contract**, when it is one pass over a whole test
suite: a per-contract job would rebuild the suite per contract and run a test
covering two contracts twice.

### The plan is a value

`orchestration::ExecutionPlan` is resolved from the policy plan *before any
artifact is compiled*, and the run walks it. One place decides what executes.

```
Execution plan

  cbaudit::monty::mul_both_secret
    J1: generated corpus + Memcheck
        discharges: generated
    J2: BINSEC relational verification
        discharges: symbolic

  1 Memcheck workflow(s), 1 symbolic verification(s)
```

`Work::Generated { explore }` is one variant rather than two, because there is
one workflow: discovery selects a corpus and hands it to the same analysis.
`explore` is a property of the job, never a second job. The deduplication table
from the milestone plan is now a unit test needing no backend at all:

| Required | Plans |
| --- | --- |
| `generated` | 1 Memcheck (`explore: false`) |
| `explore` | 1 Memcheck (`explore: true`) |
| `generated`, `explore` | **1** Memcheck (`explore: true`), discharging both |
| `symbolic` | 1 BINSEC |
| `generated`, `symbolic` | 1 Memcheck + 1 BINSEC |
| all four | 1 Memcheck + 1 BINSEC + one pass over the test suite |

Only *outstanding* requirements produce jobs. A requirement already settled —
exempted, unsupported, not selected, backend unavailable — has its answer, and
running a backend to re-derive it would spend the analysis and then discard the
result. A configured `[check."…".explore] enabled = true` still explores where
no `explore` obligation exists, which preserves M7's regression: looking only at
the policy silently skipped a configured search, so the corpus analyzed was not
the one the run was set up to analyze.

### Evidence says when it was shared

`AnalysisEvidence::shared_with` names the other requirements the same execution
discharged. Two records are still reported — the status map is total over the
requirements, and both genuinely were met — but neither can be read as an
independent observation.

The acceptance test checks both halves: that the plan commits to one workflow,
and that the run bears it out with one artifact hash, identical case counts,
identical analyzer-process counts, and `shared_with` agreeing in both
directions. A second test requires that a lone `generated` requirement plans
*no* discovery, so the first is not passing merely because exploration is always
on.

`verify-m10-feasibility.py` refuses a report whose plan schedules more than one
Memcheck workflow for a contract, refuses a job that discharges nothing, and
refuses a one-sided `shared_with`. The CI policy overlay gains
`cbaudit::monty::mul_secret_left` requiring `generated` and `explore`, so the
claim is exercised against real work rather than only in the planner's unit
tests.

### The plan is in the report

`CoverageReport.execution` carries it, absent from a read-only `coverage` report
because that runs nothing. The report now answers three separable questions:
which contracts were declared, what each owed, and **what actually ran** — the
last being what makes "two requirements, one observation" checkable rather than
a claim.

---

## 8. M10.6 — bounded scheduling that cannot reach the answer

### Concurrency, with the result held fixed

`--jobs n` runs that many analysis jobs of each backend at once. The default is
**one**: deterministic, readable, and what a developer reading a finding wants.

The property that makes the flag offerable at all is that it changes nothing but
machine time. Each job writes into a fixed slot indexed by its position in the
execution plan, and the slots are drained **in plan order** once the scope ends
— so the statuses, the outcomes, the artifact hashes and the blocking reasons
are identical whatever the worker count and whatever order the backends
finished in. `schedule::in_order` is the same pattern M7's coverage decoder
already used, for the same reason.

`one_worker_and_two_workers_agree` is the acceptance test: three contracts and
two backends, run at one worker and at two, compared field by field — plan,
contract order, per-analysis statuses, per-evidence outcomes and artifact
hashes, blocking reasons and exit code. Field by field rather than as rendered
text, because the text carries paths and timings that legitimately differ.

### What concurrency actually buys

Not parallel compilation. Builds within a backend serialise on Cargo's
target-directory lock, and that is deliberate: per-job target directories would
rebuild `core`, the library and every dependency per job and leave hundreds of
megabytes behind, which is the trade M5 settled and this package does not
reopen.

What it buys is **overlap between phases** — one contract's Memcheck run
proceeding while another's harness compiles. The limits are per backend rather
than one global number for the same reason: a single `--jobs 8` would either
starve the build or oversubscribe the analyzer containers.

I expected that to be worth little, and wrote as much before measuring. It is
not: over the eighteen audit contracts and the twenty-one jobs the policy
overlay plans, on one machine,

| Workers | Wall clock | Peak RSS |
| --- | --- | --- |
| `--jobs 1` | 3:58 | 169 MB |
| `--jobs 2` | 2:25 | 171 MB |

1.6x for 2 MB, with both runs compared field by field and found identical. The
Cargo lock bounds build parallelism but most of the wall clock is Memcheck, and
that overlaps freely. A fuller sweep across worker counts belongs to M10.8;
what this records is that the conservative default is leaving real time on the
table for anyone who asks for more.

### Isolation

Each backend already owns a separate work directory and target directory per
contract (M10.0), so two backends analyzing one contract cannot collide and a
failed build cannot pick up another analysis's executable. The per-contract
collision check still fires within a backend.

`one_contract_failing_does_not_stop_the_others` covers the failure path at both
worker counts: one contract is given a corpus budget too small to cover its
boundary values — a failure *during* the job rather than one settled before it
— and the contracts either side of it in the plan still produce evidence, while
the refused one gets an `UNSUPPORTED` status naming the cause and the run does
not pass.

Failures that are not about one contract still abort, as they did before: they
would recur identically for every contract, and reporting them eighteen times
is not more useful than once.

### An API change

`run_contract_coverage` had grown to ten positional parameters, three of them
`Option`, and M10.7 would have added more. It now takes a `CoverageRequest`,
which is the convention the CLI's own `CheckRequest` already followed. Ten
positional arguments is a signature callers get subtly wrong.

---

## 9. M10.7 — reporting, the schema, and two diagnostics M9 asked for

### The schema moved to 3

M10 changed what a field *means*, which an added field would not have, so the
unified report's schema version is bumped and consumers assert it. A reader
written against schema 2 now fails loudly rather than misreading:

* `regression_expectation` (a string: one declared outcome per contract) became
  `regression_expectations` (an analysis-to-outcome object). A reader looking
  for the old key finds nothing where it previously found the generated
  backend's expectation — and the whole point of the change is that one value
  could not describe a fixture whose backends disagree;
* each evidence record gained `artifact`, the full identity of the executable
  analyzed, alongside the `artifact_sha256` that keyed it;
* `shared_with` says which other requirements one execution discharged;
* `execution` reports the jobs the run committed to before building anything;
* evidence gained `dynamic` and `symbolic` payloads next to `check`.

The standalone M3, M5 and M6 report schemas are untouched. Only this document
changed, and only `--all-contracts` emits it.

### The leaking instruction, separately from the declaration

`declared at src/controls.rs:53` is where the annotation is written. It is
rarely the line to read when something leaks, and before this a developer had
to open the JSON to find the other one. Both are now in the text report:

```
cbaudit::controls::pre_decode_first_byte
  declared at src/controls.rs:53
  generated  LEAK_DETECTED        a secret-dependent branch or address was found
  symbolic   LEAK_DETECTED        a secret-dependent branch or address was found
  evidence:  generated produced LEAK_DETECTED in 6a582e2f50fd -- 1 finding(s) …
  leaks at:  controls.rs:55 in `cbaudit::controls::pre_decode_first_byte` (Secret-dependent branch)
  evidence:  symbolic produced LEAK_DETECTED in c41bb4a43776 -- 1 divergence site(s) …
  leaks at:  cbaudit::controls::pre_decode_first_byte (controls.rs:55) at 0x2048c0 (Secret-dependent control flow)
```

Three things make the leak site a different thing from the declaration, not
just a second copy of it. A contract can leak in several places. The frame
worth printing is the contract's **own** frame rather than the shallowest
located one, which at `-O` is usually an inlined `core` helper — stable for
matching a finding across runs, useless for acting on it. And a symbolic
divergence carries an instruction address, which no source line can supply.

### Folded symbols are diagnosed, not disassembled

M9 hit a case where the linker folded two contracts with identical bodies onto
one address, so neither had an instruction of its own for a result to be
attributed to. The message said only `resolves to 2 symbols`, which left the
developer to work out what had happened by disassembling.

`SymbolAmbiguous` now distinguishes the two causes, because the remedies
differ, and names the evidence for each:

* **several names at one address** — folding. The message names the colliding
  contracts and the shared address, says the linker folded identical bodies,
  and points at the remedy this repository's own audit adapters already use: a
  per-contract discriminant byte that makes the bodies differ.
* **one name at several addresses** — more than one compiled copy, which is a
  different problem and reads differently.

### The observation model can be an obligation (M10.3's remainder)

`[verify."…"].checks` declares what a contract's symbolic analysis *will*
check. It could not state what the requirement *needs*, so a `[verify]` entry
quietly narrowed to `checks = ["control-flow"]` kept satisfying a policy that
wanted memory addressing too.

`[policy.contracts."…"].observations` states it as part of the obligation.
Omitted, it accepts whatever `[verify]` declared, which is M5's behaviour and
remains the default. Given, the evidence is checked against the policy's list
rather than the configuration's — so narrowing the configuration stops
discharging the requirement instead of silently weakening it.

Refused as configuration errors: an empty list (which would state no model at
all, and is not the same as omitting it), a repeated class, and a list
constraining a `symbolic` requirement the contract does not have — that last
because an inert model is how a reader comes to believe something was required
that never was.

This completes M10.3. The plan offered two options — require observations in
policy and validate the configuration against them, or define a conservative
default requiring both classes. The first is implemented; the second is not,
because defaulting to both classes would retroactively invalidate every
existing single-class `[verify]` entry, and the plan is explicit that existing
configurations must not be silently reinterpreted.

---

## 10. M10.8 — acceptance, the mutation experiment, and what it costs

### A real mutation through the unified command

`ci/mutate-m9.py --unified` runs M9's upstream-mutation machinery and then the
unified command rather than the standalone check. All of M9's validity checks
still apply — the patch must apply cleanly, the mutated tree must actually
differ, and the adapter's own tests including the 1012 independent-oracle
vectors must still pass, so a mutation that changed the *arithmetic* is
rejected rather than reported as a side channel.

Acceptance experiment C, measured. Both dependencies run through the **same**
unified policy, so what is demonstrated is a transition and not merely an
outcome:

```
[clean]   generated: NO_LEAK_OBSERVED in 7eb93e534e8f
[clean]   symbolic:  VERIFIED_BOUNDED in 5f23c0b6e6d6
[clean]   exit code:   0
[clean]   statuses:    {'generated': 'checked', 'symbolic': 'checked'}

[mutated] mutation:    mutation-a-carry-branch.patch
[mutated] functional:  inline tests and the 1012 oracle vectors pass
[mutated] generated: LEAK_DETECTED in 5a5a1247b3d5
[mutated] symbolic:  LEAK_DETECTED in ac9c274433aa
[mutated] exit code:   1
[mutated] statuses:    {'generated': 'leak-detected', 'symbolic': 'leak-detected'}

artifacts:    7eb93e534e8f != 5a5a1247b3d5
graphs:       identical
```

A clean dependency passes the policy and exits 0; the mutated one is found by
both backends, in two different executables, and exits 1. The dependency graphs
are identical and the artifacts are not, so the patch is the only variable.

The clean baseline is what makes this an experiment. Without it a leaking run
proves nothing about the mutation: the policy might have been unsatisfiable to
begin with — and in the first version of this script it was, because it
required `dynamic` of every other contract and every audit contract declares
`dynamic = false`.

The script also fails if either analysis is **missing** from either report. A
run stopping at the first failure would report one backend and leave the other
un-analyzed.

### What orchestration costs

`ci/benchmark-m10.py` runs four configurations over the same work — eighteen
generated checks and three symbolic verifications of the audit contracts — so
the comparison measures orchestration rather than selection:

| Configuration | Wall clock | Peak RSS | Invocations |
| --- | --- | --- | --- |
| standalone `check` + `verify` | 226.4 s | 164 MB | not reported |
| unified, `--jobs 1` | 237.1 s | 161 MB | 18 Memcheck, 3 symbolic, 21 artifacts |
| unified, `--jobs 2` | 147.7 s | 163 MB | 18 Memcheck, 3 symbolic, 21 artifacts |

**Orchestration overhead: +4.7%** against coordinating the two commands by
hand, inside the plan's 10% engineering target. **Two workers: 1.61x**, which
also makes the unified run 35% faster than the standalone pair it replaces.

Twenty-one distinct artifact hashes for twenty-one jobs: every result is bound
to its own executable, and none shares one with another.

The deduplication invariant is asserted from the plan rather than from a
stopwatch — eighteen contracts must schedule eighteen Memcheck workflows even
though one of them requires `generated` *and* `explore`. A timing threshold
would be the wrong test for it: a shared CI runner's wall clock is not a
regression signal, and the invariant is exact.

### What the benchmark does not measure

Per-phase timings — inventory build, harness build, Memcheck execution, solver
time — are **not** measured. They would need the tool to instrument and emit
them, and deriving them from the outside by diffing wall clocks across
configurations would produce numbers that look precise and are not. The
milestone plan asks for them; this records their absence rather than
estimating them.

Cold-cache rows are available (`benchmark-m10.py` without `--warm-only`) but
not run in CI, because a cold row is dominated by compiling the dependency
graph, which is not what this measures.

### The CI surface

| Check | Where |
| --- | --- |
| Three backends, one invocation, three artifacts | `cargo test -p cargo-trace-check --test unified` |
| Unified report shape, identity, plan, deduplication | `ci/verify-m10-feasibility.py` |
| `--jobs 2` agrees with `--jobs 1` | `ci/compare-m10-runs.py`, on two real runs |
| Artifact built by the library's pinned toolchain | `tests/library.rs`, with a contrasting toolchain installed |
| A mutation fails the unified command, both analyses intact | `ci/mutate-m9.py --unified` |
| Orchestration overhead and deduplication | `ci/benchmark-m10.py --warm-only` |

---

## 11. Review round: seven corrections

A review of the stacked implementation found seven defects. All are fixed, each
with a regression that fails when the fix is reverted. Two are worth recording
in full, because both are instances of the same mistake.

### Evidence gated on an obligation

Twice in this milestone, something was gated on a *requirement* when it existed
independently of one.

**A leak found by a test that ran could be discarded.** `dynamic` is a whole
test suite rather than a per-contract job, so a policy requiring it of one
contract makes the run execute *every* targeted `#[ct_test]` — including tests
bound to contracts that require nothing dynamic. Folding results only for
contracts with an outstanding dynamic obligation threw the rest away. A
hand-written test that reached a secret-dependent branch in a contract whose
generated corpus happened to be clean was silently dropped, and the run could
pass strict CI having executed a test that found a leak. That is the one thing
the milestone's central rule forbids outright.

Evidence is now folded for every contract with a bound test.
`Coverage::fold_supplemental` keeps it without writing a status, because an
unrequired analysis has no obligation to discharge and recording `CHECKED`
against one would claim the contract was held to something it never was.
`violated()` reads evidence as well as statuses, so the leak fails the contract
either way.

**And the same mistake again, one package later.** Driving the fold from the
execution plan re-gated it on a dynamic *job* existing — `execution.dynamic` is
`Some` only when some contract has an outstanding dynamic requirement — so a
run where the only such contract was already settled folded nothing at all. The
job now decides which results get a status, never which get kept. The
unresolved-target diagnostic had already been fixed for exactly this reason
during M10.5; the lesson did not generalise the first time.

### Provenance that described the wrong compiler, four times more

M10.2 fixed the generated and symbolic harnesses. It missed four others — two
found by review, two by CI.

**M3 test binaries** were built with the ambient toolchain while their evidence
recorded `library.toolchain` — so pointed at a library elsewhere with
`--manifest-path`, the test executables were compiled by a different compiler
from every other artifact and from the one their own identity claimed. The
toolchain is threaded through `build_test_binaries`; `cargo trace-check test`
passes `None`, because it runs in the project it is testing.

**The symbolic report's `compilation.rustc`** came from `AnalyzerIdentity`,
measured in trace-check's own environment. The artifact was built correctly and
the document disagreed with itself. It now comes from the library's toolchain.

### And twice more, in CI

Both of the following passed locally and failed on a runner, for one reason:
this machine's default toolchain equals the pin and the runner's does not.

**`LlvmTools::locate`** resolved `llvm-profdata` and `llvm-cov` by running
`rustc --print sysroot` in trace-check's own environment, while the harness it
reads profiles from was built by the library's toolchain. Unlike the reporting
cases this one cannot fail quietly — the raw profile format is a hard
compatibility boundary:

```
Profile uses raw profile format version = 11; expected version = 10
```

`locate` takes the toolchain. A library pinning a toolchain without
`llvm-tools` now fails early, naming that sysroot.

**Three staging sites** copied a library outside the repository and left its
`rust-toolchain.toml` behind — the M10.4 acceptance fixture, the mutation
experiments' staged adapter, and the two `stage_library` test helpers. `rustup`
answers by walking up from the directory, so each was analyzed with whatever
the machine defaulted to. The mutation experiments are the case that mattered:
`--unified` requires exploration, so on a runner with no `llvm-tools` in its
default toolchain there was no report at all — and the earlier, non-unified
experiments had been measuring the mutation against a different compiler from
the one it was written against, with nothing to say so.

Each site now stages the pin, and `mutate-m9.py` asserts it took effect rather
than assuming it: dropping the copy fails on any machine, not only on one whose
default disagrees.

The generalisation this family keeps demanding: **a toolchain is a property of
the code being analyzed, never of the process doing the analysis.** Every place
that reads the ambient environment for one is wrong, and most of them are wrong
silently.

### The remaining five

| Finding | Fix |
| --- | --- |
| `[check]` saying `security-contract` with `[verify]` saying `analyzer-regression` made the contract a fixture, so one section overrode the other's explicit security intent | `[check]`'s purpose is `Option`, so silence is distinguishable from an explicit default; contradictory declarations are refused at load |
| `allow_inactive_config` suppressed unresolved `#[ct_test]` bindings along with inactive configuration | the two are scoped separately; an unresolved test binding always blocks |
| the leak-site diagnostic paired `finding.site` with `fingerprint.function`, which are different frames — rendering an upstream mutation as the adapter's line beside the library's function | instruction and function come from one frame; the contract's frame is labelled as attribution and shown only when it differs |
| the unified mutation experiment never established a clean baseline, and its policy made strict enforcement incomplete regardless | both dependencies run through the same policy; the clean one must pass and exit 0 before the mutated one is required to fail |

---

## 12. Definition of done

The milestone plan's checklist, against what is built. Each line names where
the claim is checked, because a checklist that cannot be re-run is a claim and
not a check.

| Claim | Checked by |
| --- | --- |
| A real contract runs generated and symbolic analysis through one command | `tests/unified.rs`, `ci/verify-m10-feasibility.py` |
| The compiler-derived inventory stays authoritative | `ci/verify-m8-contracts.py` |
| Every required analysis is in the execution plan | `orchestration.rs` tests; the plan is in the report |
| Every runnable required analysis is executed | `verify-m10-feasibility.py` (a job discharging nothing fails) |
| Generated and exploration share one Memcheck run | planner tests, `benchmark-m10.py`, `verify-m10-feasibility.py` |
| M5 symbolic verification has a reusable per-contract interface | `stage_symbolic` / `verify_staged`, used by `verify` and the unified run |
| M3 dynamic tests can satisfy explicit dynamic requirements | `cargo-trace-check/tests/unified.rs` |
| Each backend's evidence keeps its provenance and diagnostics | `each_result_carries_the_identity_of_what_it_analyzed` |
| Symbolic evidence keeps domain, assumptions, observations, depth | `symbolic_evidence_retains_the_conditions_of_its_result` |
| `VERIFIED_BOUNDED` satisfies only a compatible symbolic obligation | `validate_identity` / `validate_coverage` tests |
| `NO_LEAK_OBSERVED` cannot satisfy a symbolic requirement | `neither_backend_can_discharge_the_other_requirement` |
| Backend-specific regression expectations are supported | `a_fixture_may_declare_a_different_outcome_per_backend` |
| Security contracts cannot declare a leak acceptable | refused at load; `a_leak_fails_a_security_contract_that_declared_it_clean` |
| M9's backend-disagreement fixtures are handled | both directions, against both real libraries |
| A detected leak from either backend fails a security contract | `ci/mutate-m9.py --unified` |
| Incomplete or unavailable analysis fails strict CI | `a_missing_analyzer_leaves_the_symbolic_requirement_unmet` |
| Existing evidence is preserved if another backend fails | same test; `one_contract_failing_does_not_stop_the_others` |
| Missing backends cannot trigger weaker analysis instead | `Available::performs`; no substitution path exists |
| Exemptions stay explicit and cannot erase a leak | `an_exemption_cannot_erase_a_detected_leak` |
| Artifact hashes cannot be confused between backends | distinct hashes asserted in every multi-backend test |
| Concurrent execution introduces no artifact races | per-backend directories; `one_worker_and_two_workers_agree` |
| Report ordering is deterministic | results folded in plan order; `compare-m10-runs.py` |
| Reports distinguish inventory, enforcement and evidence | `the_json_report_separates_the_three_questions` |
| Findings identify leaking instructions separately | `a_leak_names_its_instruction_and_not_only_the_declaration` |
| Standalone M3/M5/M6/M7 workflows keep their semantics | their own suites, unedited, still green |
| The five clean M9 contracts pass generated **and** symbolic | the CI overlay requires both of three of them |
| M9's mutation experiments fail unified enforcement | `ci/mutate-m9.py --unified --expect-exit 1` |
| CI covers policy, provenance, backend failures, incompleteness | §10's table |
| Runtime and memory costs are measured | `benchmark-m10.py`; §10 |
| M1–M9 tests remain green | 846 tests, 37 binaries, both backends required |

Two lines of the plan's checklist are **not** fully met, and are listed in §13
rather than ticked here: the five clean M9 contracts are exercised with both
backends for three of them rather than all five (the other two differ only in
which operand is secret, and the policy overlay is a CI cost), and cold/warm
runtime is measured warm in CI with cold available but not run.

---

## 13. What is not done

Every package is implemented. These are the limits that remain inside them,
and the non-goals the plan set that are still non-goals.

**Carried limits.**

* M3 expectations are not modelled, so an analyzer-regression fixture cannot
  declare an outcome for `dynamic`; such a requirement is reported as a
  configuration gap rather than guessed at.
* Per-phase timings are not instrumented — see §10.
* The observation-model default is unchanged: omitting
  `policy.contracts."…".observations` accepts whatever `[verify]` declared.
  The plan's alternative, defaulting to both classes, would retroactively
  invalidate every existing single-class entry.
* `--jobs` bounds jobs per backend, not Cargo compilation separately from
  Valgrind separately from solver containers. One number per backend was enough
  for the measured gain; a finer split has no evidence behind it yet.
* No persistent cross-run evidence cache, deliberately. The artifact identity
  is now rich enough to key one, which is a reason to design it on purpose
  rather than to add it here. Only evidence produced and validated in the
  current execution can discharge a requirement.

**Still non-goals**, as the plan set them: no new symbolic engine, no new
observation classes, no hardware timing, no generic/method/struct support, no
cross-architecture verification, no build-profile matrix, no verification of
deployed production binaries, and no automatic discovery of unannotated
security-sensitive functions.
