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
| M10.2 | Typed artifact-bound evidence model | partial — see §5 |
| M10.3 | Refactor and integrate the M5 symbolic runner | partial — see §5 |
| M10.4 | Integrate M3 developer-written dynamic tests | not started |
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

## 5. What is not done

* **M10.2** — evidence is typed and artifact-bound, and symbolic evidence
  carries its full provenance, but the identity is not yet the complete list
  the plan specifies. In particular the recorded `rustc_version` is read from
  trace-check's own working directory while generated harnesses build under
  `/tmp`, where the repository's `rust-toolchain.toml` does not apply. The two
  resolved to the same compiler on the development machine, so no mismatch has
  been observed; it is a latent provenance risk, not a measured defect.
* **M10.3** — the per-contract symbolic seam exists (`stage_symbolic` /
  `verify_staged`) and the standalone command uses it. Observation-model policy
  is validated against the `[verify]` configuration, not declarable in policy.
* **M10.4** — no M3 integration. A `dynamic` requirement is reported as
  evidence this command does not produce, pointing at `cargo trace-check test`.
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
