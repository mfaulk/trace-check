# M11.1 — The feasibility gate, and what it measured

**Verdict: passed.** The remaining packages are unblocked.

M11.1 is a gate in M9's sense: the plan forbids proceeding until it passes, and
it has three jobs. Establish that a declared secret still reads as secret after
`ml-kem` has derived a key from it. Establish that the declassification boundary
the threat model describes is real and checkable. Measure what one
decapsulation costs under Memcheck, because the cost risk here was genuine in a
way it was not for 256-bit arithmetic.

Reproduce everything below with:

```sh
cargo trace-check check --all-contracts --ci --jobs 12 \
  --manifest-path examples/ml-kem-audit/Cargo.toml
```

---

## 1. The headline numbers

| | |
| --- | --- |
| Contracts declared and checked | **13** |
| Wall clock, all thirteen, `--jobs 12` | **90.4 s** |
| Peak RSS | **156.9 MB** |
| One contract alone, 25 cases | 11.3 s, 154.2 MB |
| Upstream source changes | **0** |
| Adapter code, outside tests and controls | 61 lines across `fixture.rs` and `decaps.rs` |
| `assume` constraints anywhere | **0** |
| CI decision | PASS, every declared expectation reproduced |

The cost risk did not materialize. A single case runs key generation (SHAKE,
rejection sampling, two NTTs), a deterministic encapsulation, and a
decapsulation with its re-encryption — and thirteen contracts of those fit in a
minute and a half. The abort criterion for wall-clock cost was never approached.

`--all-contracts` is deliberate and not interchangeable with
`--all-configured`: it enforces every declaration the *compiled library*
carries rather than every one the configuration names, and it is the only path
`--jobs` affects. The same thirteen contracts take 114 s when run
sequentially.

---

## 2. Secret propagation: the controls

| Control | What it reads | Outcome | Class |
| --- | --- | --- | --- |
| 1 `pre_keygen_seed_byte` | `seed[0]`, before key generation | `LEAK_DETECTED` | branch |
| 2 `secret_component_branch` | a byte of `dk_pke`, after re-marking | `LEAK_DETECTED` | branch |
| 3 `secret_component_address` | `SBOX[dk_pke[7] & 0x1f]` | `LEAK_DETECTED` | **address** |
| 7 `derived_arithmetic_branch` | the sum of eight `dk_pke` bytes | `LEAK_DETECTED` | branch |
| 8 `shared_key_branch` | a byte of the shared key a **valid** ciphertext yields | `LEAK_DETECTED` | branch |
| 9 `rejected_shared_key_branch` | a byte of the shared key a **rejected** ciphertext yields | `LEAK_DETECTED` | branch |
| 4 `public_component_branch` | a byte of `ek`, key-level boundary | `NO_LEAK_OBSERVED` | — |
| 5 `public_component_branch_seed_level` | the same byte of `ek`, seed-level | `INCONCLUSIVE` | §4 |
| 6 `no_planted_leak` | nothing planted | `NO_LEAK_OBSERVED` | — |

Control 1 establishes only that the harness marked the array, and is listed
first so nothing cites it as propagation evidence. Controls 2, 3 and 7 are the
ones that matter for the boundary, and control 8 is the one that matters for the
audit.

### Controls 8 and 9 are what make the clean findings worth reading

These are the audit's **sensitivity** controls, and there are two of them
because the Fujisaki–Okamoto transform has two secrets and two data paths.

`shared_key_branch` uses a genuine ciphertext, so `cp.ct_eq(c)` holds and the
selection returns `Kp = G(mp, H(ek))`: a value derived from the marked `dk_pke`
through K-PKE decryption, `G`, and a full re-encryption, then through the
constant-time selection. `J(z ‖ c)` is computed as well, but its result is the
branch the selection does *not* take, so this control says nothing about `z`.

`rejected_shared_key_branch` corrupts one public byte, so the check fails and
the selection returns `K̄ = J(z ‖ c)` instead — derived from the
implicit-rejection seed through SHAKE256, and from nothing the decryption
produced. That is the value a decapsulation oracle attacks, and it travels a
hash this project has already caught losing provenance elsewhere, so an argument
by analogy from control 8 would not do.

Both are `LEAK_DETECTED`. Together they say a late leak would be *attributed*
on either path rather than merely failing closed; separately, neither would.
`the_rejected_key_depends_on_z` is the independent evidence that control 9's
value really is `z`-derived: changing `z` alone, with `dk_pke`, `ek`, `H(ek)`
and the ciphertext fixed, changes it, and leaves the valid-path result
untouched.

### Controls 2 and 7, read together

Control 2 branches on a byte Memcheck was told about directly by a client
request. Control 7 branches on something the program computed from those bytes.
Both are detected, so ordinary arithmetic derivation does not lose provenance —
which is the fact that makes §4's measurement specific rather than vague.

---

## 3. The declassification boundary is real

Control 4 is clean with **zero** diagnostics: a branch on `ek[0]` under the
key-level boundary produces nothing at all. Control 5 plants the same branch on
the same byte of the same encapsulation key, seed-level, and does not come back
clean.

So the boundary moved the classification line exactly where
[`threat-model.md`](threat-model.md) says it does, and controls 2, 3 and 7 show
it did not move further: `dk_pke` is still secret on the other side of it. The
over-declassification failure — a boundary that quietly restores definedness for
everything and makes the whole audit read clean — is excluded by measurement
rather than by inspection.

The boundary is drawn on byte offsets of FIPS 203's expanded encoding, and
`layout.rs`'s `offsets_match_the_librarys_own_split` checks them against
`encapsulation_key().to_bytes()`. A layout change breaks that test instead of
silently declassifying key material.

One adapter cost worth recording: `ExpandedKeyEncoding` is **deprecated**
upstream in favour of the seed. The audit agrees with the deprecation — its
secret input *is* the seed — and uses the expanded form only as the documented
serialization that makes a key's public and secret components addressable. No
other public API offers that, so the boundary depends on a deprecated trait, and
a future release that removes it would require a different mechanism.

---

## 4. The finding the gate produced: provenance does not survive key generation

The two seed-level contracts return `INCONCLUSIVE`, not `LEAK_DETECTED`. The
cause is worth stating precisely, because it is a limitation of the tool rather
than of the library.

`seedlevel::keygen_and_decaps` reports:

```text
INCONCLUSIVE
Memcheck reported 10 diagnostic(s) that are not secret dependency
(0 memory error(s), 10 undefined value(s) not traceable to the marked secret)
```

All ten are `Conditional jump or move depends on uninitialised value(s)`, and
eight of them are in the library:

```text
ml_kem::algebra::rej_uniform (algebra.rs:68)
  at sample_ntt<shake::ShakeReader<168>> (src/algebra.rs:46)
  at matrix_sample_ntt::{closure#0} (src/algebra.rs:87)
origin: created by a stack allocation (genuinely uninitialized memory)
```

`rej_uniform` is the ML-KEM rejection sampler. Lines 68 and 73 are
`if n == coeffs.len()` and `if d1 < BaseField::Q` — branches on XOF output
derived from `ρ`, which the seed-level encoding makes secret and which the
protocol publishes. The library documents the intent at the site: *"The XOF
input is the public seed `rho`, so the data-dependent loop does not leak
secrets."* It is right, and a finding there would be the taint-model artifact
the threat model predicted.

What the gate did **not** predict is how that artifact presents. Memcheck
attributes the origin of the undefined value to a *stack allocation* rather than
to the client request, so trace-check's classifier cannot tie it to the declared
secret, files all ten as `unrelated_undefined_value`, and fails closed. Under
control 5 the planted branch at `controls.rs:137` lands in the same bucket — the
audit's own deliberate leak, unattributable for the same reason.

Three observations bound what this means:

* it is **specific to the key-generation path**. Control 8 derives through `G`
  and `J` — also Keccak — and stays attributed, and control 7 shows ordinary
  arithmetic keeps provenance. Only the SHAKE128 XOF feeding `sample_ntt` loses
  it.
* the diagnostics appear **only when `ρ` is undefined**. All five key-level
  contracts run the same `from_seed` on a declassified seed and report zero
  diagnostics, so the undefined value driving those branches is `ρ`-derived, and
  "genuinely uninitialized memory" is the origin tag being wrong rather than a
  report of uninitialized memory in `ml-kem`. Whether the lost provenance is a
  Keccak-mixing artifact or an over-read of a partially initialized stack buffer
  is **not** settled by these runs, and [`findings.md`](findings.md) keeps it
  open.
* the direction of the failure is the safe one. The tool did not report a clean
  result for a function whose branches depend on marked data; it declined to
  conclude. That is M8's fail-closed accounting, observed on a case nobody
  designed for — as in M9, where identical adapter bodies produced the same kind
  of honest refusal.

The practical consequence for the audit is that the seed-level encoding is
usable as a **screen** and not as a source of attributable results, and the
key-level boundary is what the real contracts use. Both outcomes are recorded as
`expected_outcome` in `trace-check.toml`, so a future toolchain that changes
either one surfaces as an unmet expectation rather than as a quiet improvement.

---

## 5. The library's operation is in the analyzed artifact

Confirmed by disassembly, not assumed. Artifact for
`decaps::decaps_valid_ciphertext`: `tc-check-mlkemaudit-decaps-decaps_valid_ciphertext`,
5,990,600 bytes, SHA-256 `c94d7fa79b46fc47…`, release profile
`opt-level=3, debug=true, lto=off, codegen-units=1`.

Seventeen `ml_kem` symbols survive into it. `decapsulate` is a distinct
out-of-line symbol at `0x1f0d0`:

| Symbol | Instructions | Conditional jumps | `cmov` | `div`/`idiv` |
| --- | --- | --- | --- | --- |
| `DecapsulationKey<MlKem768> as Decapsulate>::decapsulate` | 743 | 12 | **7** | 0 |
| `pke::EncryptionKey<MlKem768>>::encrypt` (re-encryption) | 972 | 17 | 0 | 0 |
| `algebra::rej_uniform` | 60 | 6 | 0 | 0 |
| `mlkemaudit::decaps::decaps_valid_ciphertext` (the adapter) | 184 | 2 | 0 | 0 |

The seven conditional moves in `decapsulate` are the shape a constant-time FO
transform is supposed to have: `cp.ct_eq(encapsulated_key)` and
`Kbar.ct_select(&Kp, …)` compiled to data-independent selection rather than to a
branch. That is not automatic — it is the same thing M9 found worth singling out
for `crypto-bigint`'s `ct_select` — and it is not something a source review
establishes. No `div` appears anywhere in the decapsulation path, which is the
instruction class the `ml-dsa` control exists for.

`rej_uniform`'s six conditional jumps over 60 instructions are the documented
data-dependent sampling loop, present and executed exactly as expected.

---

## 6. The real contracts

All three decapsulation contracts are `NO_LEAK_OBSERVED` over their generated
corpora: 48 cases for the valid-ciphertext path, 96 for the corrupted path
(four parameters, so a larger boundary set), 48 for the arbitrary-ciphertext
path.

Read with §2: the five detected controls and control 8 in particular are what
make those three results informative rather than vacuous. Read with
[`threat-model.md`](threat-model.md) §5: they are statements about two
observation classes over a finite corpus in one artifact, and they are not a
claim that `ml-kem` is secure.

The independent functional oracle lands in M11.2. Until then, correctness rests
on the crate's own tests — a valid ciphertext recovering the encapsulated key, a
corrupted one not recovering it, and both encodings computing the same function
— which is weaker than NIST vectors and is replaced, not supplemented, by them.
