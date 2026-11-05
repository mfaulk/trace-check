# Milestone 10 — Unified Multi-Backend Verification and CI Enforcement

**Status:** In progress. M10.0 and M10.1 complete; M10.2–M10.8 outstanding.
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
| M10.3 | Refactor and integrate the M5 symbolic runner | partial — see §5 |
| M10.4 | Integrate M3 developer-written dynamic tests | complete |
| M10.5 | Unified execution planner and backend deduplication | not started |
| M10.6 | Bounded scheduling, isolation and failure handling | not started |
| M10.7 | Unified CLI, reporting and schema migration | partial — see §5 |
| M10.8 | Acceptance, mutation tests, benchmarks, CI and documentation | not started |

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

## 7. What is not done

* **M10.3** — the per-contract symbolic seam exists (`stage_symbolic` /
  `verify_staged`) and the standalone command uses it. Observation-model policy
  is validated against the `[verify]` configuration, not declarable in policy.
* **M10.4** — M3 expectations are not modelled, so an analyzer-regression
  fixture cannot declare an outcome for `dynamic`; such a requirement is
  reported as a configuration gap rather than guessed at. A `dynamic`
  requirement is still reported as produced elsewhere when no policy asks for
  it, which is what keeps `coverage` and a generated-only run honest.
* **M10.5** — no execution plan representation and no deduplication of
  `generated` against `explore`. Requiring both still goes through the existing
  single Memcheck workflow, but nothing yet *proves* there is only one run.
* **M10.6** — backends run sequentially, in inventory order. No `--jobs`.
* **M10.7** — `--ci` is now honoured on the `--all-contracts` path and refuses
  an advisory policy. No schema migration, and no leaking-instruction/folded-
  symbol diagnostics.
* **M10.8** — no benchmark comparing unified execution against
  standalone-plus-standalone, and no mutation experiment run through the unified
  command.
