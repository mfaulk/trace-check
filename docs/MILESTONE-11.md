# Milestone 11 — Independent Cryptographic Security Audit and Vulnerability Discovery

**Status:** Implemented. M11.0-M11.8 complete; the outcome is **baseline success** and §10 says why not more.
**Gate:** M11.1 passed - see [`audits/ml-kem/integration-report.md`](audits/ml-kem/integration-report.md)
**Branch:** `feat/m11-independent-audit`, then one branch per package
**Prerequisite:** Milestone 10, merged
**Primary target:** RustCrypto `ml-kem` `0.3.4` (FIPS 203 ML-KEM), parameter set ML-KEM-768
**Primary platform:** Linux x86-64, pinned Rust toolchain

---

## 1. What M11 is for

M9 established that trace-check can analyze cryptographic code somebody else
wrote. Every vulnerability it has detected in such code, however, was put there
on purpose — seven controls and three upstream mutations, all authored in this
repository for the tool's benefit. M10 then made one command produce one CI
decision from four backends.

The question that is left is the only one that an outside reader actually cares
about:

> Can trace-check find a security defect that the developers of another
> cryptographic implementation did not know was there?

M11 asks that question against pinned upstream source, with a fixed
investigation budget, independent confirmation of anything it turns up, and a
responsible-disclosure path for anything that turns out to be real. Stated as
the objective the milestone is judged against:

> Test whether trace-check can independently discover previously unknown
> secret-dependent execution behavior in real cryptographic code, while
> distinguishing genuine vulnerabilities from taint-model artifacts and from the
> limits of its own observation model.

The second clause is not a caveat on the first. A milestone that produced
findings without separating those three categories would be worse than one that
produced none.

**Discovery is the stretch goal, not the pass criterion.** A rigorous audit
that finds every analyzed operation clean is a useful result, provided it states
exactly which operations were covered, which were out of model, and what the
analysis cost. The failure mode M11 must avoid is not "no vulnerability found";
it is "no vulnerability found, and no way to tell whether that is a property of
the library or of the tool."

---

## 2. Targets

Facts below are checked against crates.io and the RustSec advisory database as
of 2026-11-05. Anything not yet checked is marked as an M11.0 item rather than
asserted.

| Target | Role | Why | Status |
| --- | --- | --- | --- |
| `ml-kem` 0.3.4 | **primary discovery target** | RustCrypto's FIPS 203 implementation; 14.2 M downloads; `no_std`; no RustSec advisory; its own README says "The implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!" | version confirmed, published 2026-10-31 |
| `kyberlib` 0.0.11 | **second discovery target** | an independent implementation of the same standard makes a clean result on either one informative; the only candidate with a documented deterministic key-generation entry point, and the only one stating an auditability goal | selected in M11.0 from four resolved candidates — see [`audits/ml-kem/target-selection.md`](audits/ml-kem/target-selection.md) |
| `rsa` (RUSTSEC-2023-0071) | **external positive control** | a real, publicly documented timing side channel in a real library, with **no patched version** — so the defect is present in current source | advisory confirmed, dated 2023-11-22, category `crypto-failure` |
| `ml-dsa` (RUSTSEC-2025-0144) | **external negative control** | the leak is variable-latency `UDIV` on secret-derived values in `decompose` — *outside* trace-check's observation model | advisory confirmed: reported 2025-12-12, issued 2026-01-27, CVE-2026-22705, fixed in `0.1.0-rc.3` |

Two corrections to the plan this milestone was proposed from:

* **`crypto-pq-ml-kem` does not exist.** `https://crates.io/api/v1/crates/crypto-pq-ml-kem`
  returns 404 and a crates.io search finds no such crate. It was proposed as the
  first investigation on the strength of a release date and a documented
  constant-time claim; neither is real. It is removed from the target list, and
  nothing in M11 may cite a target that has not been resolved to a crates.io
  version and a source checksum.
* **The ML-DSA advisory is RUSTSEC-2025-0144**, reported 2025-12-12 and issued
  2026-01-27. The two dates are both real and a report must not use one where it
  means the other; the ID is what matters for citation.

### The two controls are doing opposite jobs

`rsa` is the calibration that says the tool can still see a real leak it did not
author. It cannot count as a discovery and must not be reported as one.

`ml-dsa` is more important, and is the control this project has never had.
RUSTSEC-2025-0144 is a secret-dependent **division latency**: the instruction
path and the effective addresses are identical, so a correct trace-check run on
the vulnerable version reports no finding. M11 must *demonstrate that miss* on
the affected version — Memcheck clean, symbolic clean where it completes — and
record it as the standing example of what a clean result does not cover.
Extending the observation model to instruction latency is explicitly not part of
this milestone.

A negative control is only interpretable if the thing it fails to see is
confirmed present, so the order of work is fixed: **first establish from the
disassembly of the analyzed artifact that a secret-derived operand reaches a
hardware `div` instruction** on the affected revision, in a function the run
reaches. `r1.0 /= TwoGamma2::U32` divides by a compile-time constant, and a
compiler that strength-reduces it to a multiply-and-shift removes the
vulnerability from the artifact — at which point a clean trace-check result
proves nothing at all. Three conditions, all required:

1. a secret-derived operand reaches `div`/`idiv` in the analyzed machine code,
   shown by disassembly and by the operand's provenance;
2. no branch or address finding is reported for the selected execution — a
   finding from some *other* channel would make the control ambiguous rather
   than informative;
3. the report says the latency risk is unobserved **because it is out of model**,
   not because the code is clean.

If condition 1 fails under the pinned toolchain, the control is recorded as
unavailable with the disassembly that shows why, rather than being presented as
a successful demonstration of a limit.

---

## 3. The secret-input domain, which is the hard part

A KEM decapsulation is

```text
K = Decapsulate(dk, c)
```

with `dk` the secret decapsulation key and `c` an attacker-supplied ciphertext.
The contract to analyze is: holding `c` fixed and public, nothing in the
declared observation classes may depend on `dk`.

The obvious encoding of that is wrong. `dk` for ML-KEM-768 is 2400 bytes
encoding a polynomial vector, the encapsulation key, a hash of it, and the
implicit-rejection seed `z`. Generated inputs over `[u8; 2400]` are
overwhelmingly not decapsulation keys any key generation can produce, so a
finding over that domain may be unreachable in practice — and there is no
`assume` constraint that expresses "is a well-formed ML-KEM key", because the
constraint is a hash preimage condition.

**The secret parameter is therefore the key-generation seed, not the key.** The
adapter takes `[u8; 64]` — `d ‖ z` — marks it secret, derives `dk` through the
library's own deterministic constructor, and decapsulates:

```text
seed: [u8; 64]  (secret)                 ciphertext: [u8; 1088]  (public)
        |                                         |
        v                                         v
DecapsulationKey::from_seed  ---- dk ---->  decapsulate  ----> K --> 32-byte fold
```

The API this relies on exists in `ml-kem` 0.3.4 and is checked, not assumed:
`DecapsulationKey::from_seed(seed: Seed)` reconstructs a key from the 64-byte
seed, `to_seed` serializes it back, `encapsulation_key()` yields the public key,
and `EncapsulationKey::encapsulate_deterministic(m: &[B32])` encapsulates with
supplied randomness. FIPS 203 defines `d` and `z` as exactly the input to
deterministic key generation, so this is the standard's own notion of a key
seed and not a convenience of one implementation.

Three consequences, each of which the plan accepts deliberately:

* **Every secret value analyzed is a genuine key.** The domain is exactly the
  one key generation produces, so no input-domain restriction is needed and no
  finding is dismissible as unreachable.
* **Decapsulation is total over the public ciphertext.** FIPS 203 has implicit
  rejection, so a malformed `c` is not an error path — it returns a
  pseudorandom key. Like M9's three targets, the contract needs no `assume`,
  and the attacker-supplied-ciphertext threat model is the natural one.
* **Key generation's SHAKE is inside the traced region.** Marking the seed
  taints everything derived from it, which is correct — but it means one case
  traces Keccak permutations and an NTT under Memcheck, not just the
  decapsulation. Whether that is affordable is the gate in §5.

The Fujisaki–Okamoto re-encryption check is where this encoding earns its
keep. The comparison `c == c'` and the selection between the true shared secret
and the rejection value both operate on secret-derived data under this marking.
That is precisely the code a constant-time ML-KEM has to get right, and it is
only reachable as secret-dependent if the secret marking survives key
generation, hashing, and polynomial arithmetic.

### 3.1 The declassification boundary, which decides what a finding means

Seeding solves validity and introduces a classification problem in its place. A
decapsulation key is not uniformly secret. Under FIPS 203 it carries the PKE
decryption key, **the encapsulation key, and a hash of the encapsulation key**,
alongside the implicit-rejection value `z`. The encapsulation key is public —
the attacker has it — but it is derived from `d`, so marking the seed secret
taints it and everything computed from it.

A branch on `ek` or on `H(ek)` would then be reported as secret-dependent while
depending only on bytes the attacker already knows. That is a **taint-model
artifact**, and shipping one to a maintainer as a vulnerability is the single
most likely way for this milestone to discredit itself.

The mechanism to fix it already exists: `trace-check-secret` provides
`declassify` and `Secret::declassify_now`, and its own documentation records the
tradeoff — forgetting to declassify costs noise, over-declassifying suppresses
findings. What M11.1 has to settle is *where the boundary goes*, choosing
between three encodings and recording the one it picks with its cost:

| | Encoding | What it claims | The problem |
| --- | --- | --- | --- |
| **A** | Seed tainted, nothing declassified | Nothing observable depends on the seed. The strongest relational property available | Findings on `ek` / `H(ek)` are artifacts. Usable as a screen, never disclosable without a further argument that the leaking value is genuinely protected |
| **B** | Declassify the public derivates after key generation | Findings depend only on protected data | Declassification is over address ranges, and the public-but-tainted bytes live *inside* the library's own `DecapsulationKey`. Reaching them depends on internal layout, which is not stable API |
| **C** | Run key generation untainted, then mark only the secret components | Same as B, and keeps Keccak out of the trace, so it is much cheaper | Same internal-layout dependency as B |

B and C share one structural obstacle worth stating plainly: serializing
`encapsulation_key().to_bytes()` and declassifying *that* copy does not untaint
the copy inside `dk` that decapsulation actually reads, including the stored
`H(ek)`. A boundary drawn only on the external copy looks right and changes
nothing.

Two controls make the chosen boundary checkable rather than asserted:

* a planted branch on a genuinely secret component (the PKE decryption key, or
  `z`) must **still be detected** after declassification — this is what catches
  over-declassification, and without it a boundary that silently suppresses
  everything would read as a clean audit;
* a planted branch on `ek` must be detected under A and **not** under the
  chosen boundary — this is what shows the boundary actually moved the line
  where it claims to.

Any real finding that disappears when declassification is applied is reported as
a taint-model artifact, with both runs shown. M11.1 passes on this point only if
it produces a defensible boundary, or an explicit decision to claim the weaker
seed-level property under encoding A and classify its findings accordingly.

### 3.2 Both ciphertext paths, and the ciphertext must stay public

Generating seeds and ciphertexts independently makes almost every case an
implicit rejection: a random 1088-byte string essentially never survives the
re-encryption check. A contract set encoded that way could spend its entire
budget on the rejection path and never once execute a successful decapsulation
— and would report `NO_LEAK_OBSERVED` for an operation half of which never ran.

The input domain is therefore constructed, not sampled:

* **Valid pairs**, deterministically: `encapsulate_deterministic` on the
  encapsulation key derived from the case's seed, with a fixed `m`, giving a
  ciphertext that decapsulates to a known shared secret the functional oracle
  checks independently against the FIPS 203 vectors.
* **Invalid ciphertexts**, including targeted single-byte and single-coefficient
  corruptions of a valid ciphertext, not only random bytes — a corruption near
  the boundary is a different execution from noise.
* **Evidence both paths executed**, by coverage or by the adapter's own
  oracle-checked outcome, recorded per contract. "Both paths reached" is an
  asserted expectation, not a hoped-for side effect.

The subtlety is that constructing a valid ciphertext from the case's own seed
makes it *derived from* secret-marked data, so it would arrive at decapsulation
tainted. It must not. The ciphertext is public in the threat model — the
attacker chose it — so the adapter constructs the pair and declassifies the
ciphertext before the analyzed call, and the report states that it did.

This is also where the distinction between two different uses of "varying an
input" has to stay explicit. Varying the public ciphertext *across* cases is
test coverage: it selects which executions get analyzed. The noninterference
claim is always *within* a case, over the secret with the public input held
fixed. Conflating them would turn a coverage sweep into an apparent relational
result, and nothing in the report may read that way.

---

## 4. What this tool can and cannot be pointed at

Known from the existing implementation, not to be rediscovered:

* `#[constant_time]` takes **non-generic free functions** only. `ml-kem` is
  generic over its parameter set, so the adapter supplies a concrete
  monomorphization — ML-KEM-768 — and the contract covers that instantiation.
  Another parameter set is another contract, and the plan does not assume
  results transfer between them.
* **The dynamic Memcheck backend is the primary engine.** It has no signature
  subset beyond the harness's representable types, it handles `std`, and M9
  showed secret dependence surviving byte decoding and multi-limb arithmetic.
* **The symbolic backend is very likely infeasible on a whole
  decapsulation.** `verify` builds a freestanding `no_std` artifact and bounds
  exploration depth; Keccak plus an NTT over 256 coefficients is not a
  plausible fit. The plan therefore scopes symbolic verification to *leaf*
  operations where it can realistically settle — compression/decompression,
  modular reduction, the constant-time byte comparison, the conditional select
  — and treats `INCONCLUSIVE` on the full operation as the expected result to
  be recorded, not a failure to be engineered around.
* **Out of model, for every backend here:** instruction latency, cache and
  branch-predictor state, speculation, and anything about a production build of
  the library rather than the analyzed artifact. `docs/limitations.md` states
  these; M11 adds the `ml-dsa` control so that one of them is demonstrated
  rather than merely documented.

The portable pure-Rust paths are the target. SIMD-specialized code paths are
out of scope for M11, and which paths a given target actually compiles is an
M11.0 recon item, confirmed by disassembly in M11.1 — M9's rule that the
analyzed artifact must be shown to contain the library's operation applies
unchanged.

---

## 5. Work packages

| PR | Package | State |
| --- | --- | --- |
| M11.0 | Target reconnaissance | **done** — four candidates resolved, `crypto-pq-ml-kem` found not to exist, `kyberlib` selected |
| M11.1 | **Feasibility gate** | **done — passed.** 13 contracts, 90 s, 157 MB; boundary controls intact; `decapsulate` confirmed in the artifact |
| M11.2 | Audit integration | **done** — 60 NIST ACVP vectors, both FO paths, hermetic fixture |
| M11.3 | Systematic analysis | **done** — dynamic for both targets; symbolic reaches the target and settles nothing |
| M11.4 | Candidate triage | **done** — every finding classified; none reaches stage 2 |
| M11.5 | Independent confirmation | **done** — the second target reproduces finding A's classification and localizes its cause |
| M11.6 | Controls | **done** — `rsa` detected; the `ml-dsa` control recorded **unavailable** on its premise |
| M11.7 | Disclosure | **done, vacuously** — nothing reached stage 2, so there was nothing to disclose |
| M11.8 | Audit report | **done** — [`audits/adoption.md`](audits/adoption.md) |

Two packages did not go as planned, and both are recorded rather than
reshaped. The symbolic scope in M11.3 turned out to be empty because `ml-kem`
exposes no leaf operation at all, and M11.6's negative control failed its own
premise because the compiler removed the defect it was built around.

M11.1 is a gate in M9's sense: the remaining packages do not start until it
passes. Its abort criteria are explicit, because the cost risk here is real in a
way it was not for 256-bit arithmetic —

* secret dependence does not survive key generation into the decapsulation, or
* one Memcheck case exceeds a wall-clock budget that makes a contract set
  unusable in CI, or
* no declassification boundary from §3.1 is both defensible and reachable
  without depending on the library's internal layout — in which case the
  milestone continues under encoding A with its findings classified as
  seed-level, and says so everywhere, or retargets as below.

Either outcome retargets the milestone at a smaller secret-bearing operation
(decapsulation with `dk` supplied by a fixed key and only the implicit-rejection
path varied, or an individual arithmetic leaf) and is written up as a measured
limit rather than worked around silently.

### Layout

Following M9, so that nothing about where things live is a new decision:

```text
examples/ml-kem-audit/            out-of-workspace crate, own lockfile
  src/decaps.rs                   the seeded-keygen decapsulation contracts
  src/leaf.rs                     the symbolically tractable leaf operations
  src/controls.rs                 planted controls, each with an optimization barrier
  tests/functional.rs             FIPS 203 KATs through the adapter
  trace-check.toml                one entry per contract, with its expectation

ci/verify-m11-audit.py            asserts the audit report's own claims
ci/verify-m11-controls.py         the rsa positive and ml-dsa negative controls

docs/audits/ml-kem/               target-selection, threat-model,
                                  integration-report, findings, adoption
docs/audits/<second-target>/      the same five
```

A control whose branch the compiler erases is not a control: every planted
control uses an optimization barrier, for the reason recorded seven times in
this repository now.

---

## 6. What counts as a finding

Four stages, and a report may only claim the stage it reached:

1. **Analysis finding** — trace-check reports a secret-dependent branch or
   effective address.
2. **Confirmed side-channel defect** — reproduced in genuine upstream code,
   from a pinned source, over valid inputs, with the secret classification
   justified and the leaking instruction attributed to an upstream frame.
3. **Security vulnerability** — a credible attacker observing that behavior
   learns something they should not, or a documented security property of the
   library is violated.
4. **Disclosed and remediated** — maintainers have a private report, have
   confirmed it, and a fix is coordinated.

A secret-dependent branch in an operation documented as variable-time is not a
defect. A branch on public data is not a defect. A confirmed secret-dependent
address with no demonstrated exploit may still violate the library's own
constant-time design requirement, and is reported as exactly that.

A credible report carries the source revision, the artifact and its hash, the
input or symbolic witness, the observation and its class, the upstream frame,
the threat model, and a proposed correction.

**Nothing at stage 2 or beyond is committed to this public repository before
disclosure is coordinated.** Candidate details and reproducers live outside the
repo until then. This is the one procedural rule in M11 that a mistake cannot be
walked back.

---

## 7. Success levels and the budget

**Stretch — new vulnerability discovered.** An independently confirmed,
previously unknown side-channel defect in an external project, privately
reported, with a case study publishable after coordination.

**Strong — real defect confirmed.** A genuine leakage defect in upstream code,
reproducible and accurately characterized, even if already known, or a
previously undocumented violation of a stated constant-time property.

**Baseline — independent audit completed.** Two externally maintained
implementations evaluated, three or more substantial secret-bearing operations
analyzed in depth, both external controls behaving as predicted, and every
result or limitation documented.

The budget is fixed so the milestone cannot become an open-ended search: **four
candidate crates in reconnaissance, two integrations, and the operations named
in M11.2.** If neither target yields a defensible finding, M11 ends at baseline
with the audit report — and the report's most useful content is then the list of
places where the analysis was too weak to conclude anything, ranked.

A second workstream — an application misusing a deliberately variable-time
library API, which is a plausible place to find something real — is explicitly
deferred. It needs a different threat model and a different kind of target
selection, and splitting M11's attention across both is how neither gets done
properly.

---

## 8. Definition of done

- [x] Every target resolved to an exact crates.io version, a committed lockfile
      and a license check — `ml-kem` `=0.3.4`, `kyberlib` `=0.0.11`, `rsa`
      `=0.9.10`, `ml-dsa` `=0.1.0-rc.2` and `=0.1.2`.
- [x] No target cited that was not resolved this way — which is how
      `crypto-pq-ml-kem` was found not to exist.
- [x] M11.1 gate passed.
- [x] The library's operation confirmed present in the analyzed artifact by
      disassembly — `decapsulate` as 743 instructions, 7 `cmov`, 0 `div`.
- [x] Secret inputs drawn from a domain the library's own key generation
      produces: a 64-byte seed, with the reasoning in the threat model.
- [x] A declassification boundary chosen and recorded, with the
      over-declassification controls passing. **Partially as specified:** the
      planted branch on `ek` is clean under the key-level boundary and
      `INCONCLUSIVE` rather than `LEAK_DETECTED` under the seed-level one, for
      the provenance reason finding A records. The pair still distinguishes the
      two encodings — zero diagnostics against ten — and `kyberlib`'s
      seed-level contract supplies the attributed half.
- [x] Every finding that disappears under declassification reported as a
      taint-model artifact, with both runs shown, and never disclosed.
- [x] Valid key/ciphertext pairs constructed deterministically and checked
      against FIPS 203 vectors; invalid ciphertexts include targeted
      corruptions; both FO paths asserted to have executed — by NIST's own
      classification of five modified and five unmodified ciphertexts.
- [x] The public ciphertext arrives untainted at the analyzed call, by
      construction rather than by declassification, and the report says so.
- [x] Coverage-varying of public inputs never presented as a relational result.
- [x] Adapters invoke upstream implementations without modifying them; zero
      upstream changes in both audits.
- [x] Functional oracles independent of the adapter, at full output width — 60
      ACVP vectors, passing for both targets.
- [x] Planted controls detected, each with an optimization barrier, covering a
      branch and an address, including **one per data path** through the FO
      transform: a branch on the valid path's `Kp`, which depends on `dk_pke`,
      and one on the rejected path's `K̄ = J(z ‖ c)`, which depends on `z`. One
      of them alone would have left the other path's secret untested, which is
      review finding four.
- [x] A negative control reports no finding — `no_planted_leak`, both targets.
- [x] Every analysis finding classified; none left unclassified.
- [x] `rsa` RUSTSEC-2023-0071 detected on current unpatched source, in
      `monty_modpow`.
- [ ] `ml-dsa` RUSTSEC-2025-0144 demonstrated as out of model. **Not done, and
      recorded as unavailable rather than reshaped:** condition 1 fails because
      rustc strength-reduces the division, so neither half's artifact contains
      it and no clean result can demonstrate the gap. `docs/limitations.md` now
      says the latency exclusion is a scope statement with no measurement behind
      it, and `ci/verify-m11-controls.py` fails if a future toolchain emits the
      division.
- [x] Symbolic results reported, with `INCONCLUSIVE` where nothing settled,
      never promoted. The scope changed: there is no reachable leaf operation,
      so the attempt was made against a whole decapsulation.
- [x] Any stage-2 candidate disclosed before public mention — vacuous: none.
- [x] Cost measured: wall time and peak RSS per audit, adapter and control line
      counts, in [`audits/adoption.md`](audits/adoption.md).
- [x] The audit report documents coverage and limits without claiming either
      library is secure.
- [x] CI validates both audits' own claims, the positive control, and the
      negative control's premise — over `check --all-contracts`, so the
      inventory is the compiled library's and not the configuration's, with
      `--self-test` requiring the validator to reject reports whose
      load-bearing evidence has been deleted.
- [x] M1–M10 tests remain green, including every symbolic expectation after the
      `memcpy` harness fix: crypto-library 6/4, external-library 2/1,
      crypto-bigint-audit 7/11, zero `INCONCLUSIVE`.

---

## 9. Non-goals

No extension of the observation model to instruction latency, cache state or
speculation. No hardware timing measurement. No generic, method or struct
support in `#[constant_time]`. No whole-library verification. No SIMD code
paths. No cross-architecture or compiler-matrix work. No claim that any audited
library is secure. And no application-misuse workstream — deferred, per §7.

---

## 10. The outcome against §7's levels

**Baseline success, met in full.** Two externally maintained implementations
evaluated, four substantial secret-bearing operations analyzed in depth
(decapsulation on three ciphertext paths, plus key generation at the seed
level), functional and leakage-positive controls validated, and every result or
limitation documented.

**Strong success, not met.** No genuine leakage defect was confirmed in upstream
code. The one upstream finding — rejection sampling on `ρ` — is a taint-model
artifact, classified as such and reproduced independently in both targets, and
the libraries document the behaviour themselves.

**Stretch goal, not met.** No previously unknown vulnerability.

The budget held: four candidate crates in reconnaissance, two integrations, and
two advisories. The milestone did not become an open-ended search.

What M11 produced instead of a vulnerability is a better answer to *why not*,
and three things that outlast it:

* a reusable method for auditing a structured cryptographic key, where the
  classification boundary is drawn on a standard's own serialization and kept
  checkable by a control pair;
* **two tool defects nothing in this repository could have surfaced** — the
  `memcpy` link failure, now fixed, which had made bounded verification
  unavailable to any library that moves large values; and the provenance loss on
  the `shake` XOF path, which currently makes ML-DSA signing unanalyzable and is
  ranked first in [`audits/adoption.md`](audits/adoption.md);
* a demonstration that a *negative* control can fail on its premise, and that
  the discipline of checking the premise first is what stops an audit from
  claiming a demonstration it does not have.

### What review changed

Seven findings, all addressed, and two were load-bearing. The boundary pair's
seed-level half could have passed on the library's unrelated sampling
diagnostics even if its own planted branch had vanished — the validator now
requires that branch by frame, and `--self-test` deletes it to prove the
requirement bites. And the sensitivity control covered only the valid
ciphertext's `Kp`: the rejected path's `z`-derived `K̄` had no control at all,
and a doc sentence claimed a dependency through `J` that the valid path does not
have. Both audits gained a rejection-path control and a test that varies `z`
alone.

The rest tightened how the audit validates itself rather than what it found:
`--all-contracts` instead of `--all-configured`, so the inventory comes from the
compiled library; case budgets, completion counts, calibration and binding
asserted; a hermetic digest check on the committed ACVP fixture; the negative
control's premise read from the analyzed executable with every division in the
library's code accounted for; and the `--jobs 12` timings re-measured, because
that flag only affects the selection the audits were not using.
