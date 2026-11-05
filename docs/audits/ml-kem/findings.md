# M11.4 — Findings and their triage

Every finding the audit produced, classified. The categories are the ones M11
committed to in advance: public-data variation, **taint-model artifact**,
intentional variable time, adapter artifact, out-of-model, or a genuine secret
dependency. Nothing is left unclassified, and nothing is promoted beyond what
its evidence supports.

**No finding in this audit reaches stage 2** — a confirmed side-channel defect in
upstream code. Stage definitions are in
[`../../MILESTONE-11.md`](../../MILESTONE-11.md) §6. Consequently there is
nothing to disclose for `ml-kem` 0.3.4, and §6 of this file says what that does
and does not mean.

---

## 1. The analysis results, in full

| Contract | Encoding | Outcome | Cases |
| --- | --- | --- | --- |
| `decaps::decaps_valid_ciphertext` | key-level | `NO_LEAK_OBSERVED` | 48 |
| `decaps::decaps_corrupted_ciphertext` | key-level | `NO_LEAK_OBSERVED` | 96 |
| `decaps::decaps_supplied_ciphertext` | key-level | `NO_LEAK_OBSERVED` | 48 |
| `controls::no_planted_leak` | key-level | `NO_LEAK_OBSERVED` | 32 |
| `controls::public_component_branch` | key-level | `NO_LEAK_OBSERVED` | 32 |
| `controls::pre_keygen_seed_byte` | key-level | `LEAK_DETECTED`, branch | 32 |
| `controls::secret_component_branch` | key-level | `LEAK_DETECTED`, branch | 32 |
| `controls::secret_component_address` | key-level | `LEAK_DETECTED`, value | 32 |
| `controls::derived_arithmetic_branch` | key-level | `LEAK_DETECTED`, branch | 32 |
| `controls::shared_key_branch` | key-level | `LEAK_DETECTED`, branch | 32 |
| `controls::public_component_branch_seed_level` | seed-level | `INCONCLUSIVE` | 32 |
| `seedlevel::keygen_and_decaps` | seed-level | `INCONCLUSIVE` | 32 |
| `mlkemsym::keygen_and_decaps` (symbolic) | seed-level | `INCONCLUSIVE` | — |

Five detected results are planted controls. The two `INCONCLUSIVE` dynamic
results are finding **A**. The symbolic one is in
[`symbolic-feasibility.md`](symbolic-feasibility.md).

---

## 2. Finding A — `rej_uniform` branches on data the seed-level encoding marks secret

**Classification: taint-model artifact, compounded by a tool provenance
limitation. Not a defect in `ml-kem`.**

Under the seed-level encoding, `seedlevel::keygen_and_decaps` produces ten
`Conditional jump or move depends on uninitialised value(s)` diagnostics. Eight
are upstream:

```text
ml_kem::algebra::rej_uniform (algebra.rs:68)
  at sample_ntt<shake::ShakeReader<168>> (src/algebra.rs:46)
  at matrix_sample_ntt::{closure#0} (src/algebra.rs:87)
origin: created by a stack allocation (genuinely uninitialized memory)
```

`algebra.rs:68` and `:73` are `if n == coeffs.len()` and `if d1 < BaseField::Q`
— the ML-KEM rejection sampler's loop, driven by XOF output derived from `ρ`.

Why this is not a defect:

* **`ρ` is public.** It travels inside the encapsulation key, which the attacker
  holds. The seed-level encoding makes it secret only because it is derived from
  the secret `d`.
* **The library says so at the site.** `sample_ntt`'s doc comment reads: *"The
  XOF input is the public seed `rho`, so the data-dependent loop does not leak
  secrets."* That is correct.
* **The key-level boundary removes it.** All five key-level contracts run the
  same `from_seed` on a declassified seed and report zero diagnostics.

So this is the artifact [`threat-model.md`](threat-model.md) §3 predicted, found
where it predicted it. Reporting it to maintainers as a vulnerability would have
been wrong.

### The part that is a tool limitation

What was *not* predicted is that trace-check cannot attribute these at all.
Memcheck reports the undefined value's origin as a stack allocation rather than
as the client request, so the classifier files all ten as
`unrelated_undefined_value` and returns `INCONCLUSIVE` — it neither reports a
leak nor claims the function clean. Under
`controls::public_component_branch_seed_level` the audit's own planted branch at
`controls.rs:137` lands in the same bucket.

Bounded by three measurements:

| Control | Derivation of the branched-on value | Attributed? |
| --- | --- | --- |
| 2 `secret_component_branch` | marked bytes, read directly | yes |
| 7 `derived_arithmetic_branch` | sum of eight marked bytes | yes |
| 8 `shared_key_branch` | marked `dk_pke` through K-PKE decrypt, `G`, re-encryption, `J`, `ct_select` | **yes** |
| A (this finding) | marked seed through SHAKE128 into `sample_ntt` | no |

Provenance survives ordinary arithmetic and survives the entire decapsulation
path including two Keccak-based hashes. Only the key-generation XOF loses it.

**Open question, deliberately not resolved here.** Whether the loss is Memcheck's
origin tag being approximate through that particular mixing, or an over-read of a
partially initialized stack buffer inside the XOF reader, is not settled by these
runs. What *is* settled: the diagnostics appear only when `ρ` is undefined and
vanish when it is public, so the undefined value is `ρ`-derived and the
"genuinely uninitialized memory" label is about the origin tag, not about
`ml-kem` reading uninitialized memory. Settling it needs a reduced reproducer
against the `shake` crate alone, which is out of M11's budget and is recorded in
[`adoption.md`](adoption.md) as the follow-up it is.

**Direction of failure: safe.** The tool declined to conclude rather than
reporting a clean result for code whose branches depend on marked data. That is
M8's fail-closed accounting, on a case nobody designed for — the same way M9's
folded adapter symbols produced an honest `INCONCLUSIVE` rather than a false
pass.

---

## 3. Finding B — decapsulation's constant-time shape survives `opt-level = 3`

**Classification: positive structural evidence. Not a finding against the
library; recorded because it is the kind of thing a source review cannot
establish.**

From the analyzed artifact's disassembly (SHA-256 `c94d7fa79b46fc47…`):

| Symbol | Instructions | Conditional jumps | `cmov` | `div`/`idiv` |
| --- | --- | --- | --- | --- |
| `DecapsulationKey<MlKem768> as Decapsulate>::decapsulate` | 743 | 12 | **7** | 0 |
| `pke::EncryptionKey<MlKem768>>::encrypt` | 972 | 17 | 0 | 0 |
| `algebra::rej_uniform` | 60 | 6 | 0 | 0 |

The seven conditional moves are `cp.ct_eq(encapsulated_key)` and
`Kbar.ct_select(&Kp, …)` — the FO transform's comparison and selection compiled
to data-independent form. The twelve conditional jumps are loop structure over
public bounds. No division appears anywhere on the decapsulation path, which
matters because division latency is the one leak class
[RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html)
showed this project cannot see.

`rej_uniform`'s six jumps over 60 instructions are the documented sampling loop,
present and executed, on public data under the audited encoding.

---

## 4. Findings against the tooling, not the library

Recorded here because an audit that hides its own friction is not reproducible.

| # | What | Status |
| --- | --- | --- |
| C | The freestanding verification artifact did not link against any library that emits `memcpy` calls — which is any library moving values too large to copy inline. | **fixed** in `harness.rs`, with a regression test. [`symbolic-feasibility.md`](symbolic-feasibility.md) §2 |
| D | A `#![no_builtins]` fix for C changed how cross-crate-inlined code compiles and flipped M5's `verify_tag_early_exit` to `LEAK_DETECTED`. | rejected; the volatile-shim alternative shipped. Caught by an existing expectation from M5 |
| E | An adapter that needs `trace-check-secret` links `std`, so it cannot be symbolically verified at all (`duplicate lang item panic_impl`). | worked around with a second `no_std` crate; the cost is that the symbolic attempt cannot use the declassification boundary |
| F | A run that stops with `unknown` does not say why, and the analyzer's log is not retained even under `--artifact-dir`. | open; [`adoption.md`](adoption.md) |
| G | The declassification boundary depends on `ExpandedKeyEncoding`, which is **deprecated** upstream. No other public API makes a key's public and secret components addressable. | open, and a fragility the audit owns rather than the library |
| H | `site` names the contract's own frame, so an upstream finding read from `site` alone looks like an adapter finding. | known since M9 finding two, unchanged |

---

## 5. What the clean results are worth

The three decapsulation contracts are `NO_LEAK_OBSERVED` over 192 generated
cases. That is worth reading **only** because of the controls, and specifically:

* `secret_component_branch` and `secret_component_address` are detected, so the
  boundary did not declassify key material. The second is reported as a
  secret-dependent *value* use, which is how Memcheck sees a load whose address
  came from marked bytes;
* `shared_key_branch` is detected, so a leak late in the FO transform would be
  attributed rather than silently missed;
* `public_component_branch` is clean with zero diagnostics while the same branch
  seed-level is not, so the boundary moved the classification line where it
  claims to;
* the ACVP vectors pass on both FO paths, so the operation analyzed is
  ML-KEM-768 and both halves of it ran.

And it is bounded by:

* two observation classes — no latency, cache, predictor or speculation;
* 192 generated cases, not a quantification over inputs;
* one artifact, one parameter set, one toolchain, one feature selection;
* no `VERIFIED_BOUNDED` anywhere, so nothing here quantifies over the secret
  domain.

---

## 6. Disclosure status

**Nothing to disclose.** No finding reached stage 2, so there is no private
report to send and no embargo to respect; everything in this audit is publishable
as it stands, which is why it is in the repository.

Stated precisely, because the distance between this and "ML-KEM is secure" is
the whole point: the audit found no secret-dependent branch or address in
`ml-kem` 0.3.4's ML-KEM-768 decapsulation, over the inputs it generated, under
the classification boundary it documents, in the artifact it hashes. It did not
examine latency, it did not verify anything symbolically, and it analyzed one of
three parameter sets through one compiled build.
