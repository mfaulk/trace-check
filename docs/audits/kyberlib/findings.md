# M11.5 — `kyberlib` 0.0.11: integration, results and triage

The second discovery target. The threat model, the secret input domain and the
classification boundary are the ones in
[`../ml-kem/threat-model.md`](../ml-kem/threat-model.md) — deliberately
unchanged, because the point of a second target is to vary the *implementation*
and nothing else. This file records what differs: the integration, the results,
and the one cross-target conclusion that neither audit could reach alone.

```sh
cargo trace-check check --all-configured --ci --jobs 12 \
  --manifest-path examples/kyberlib-audit/Cargo.toml
```

| | |
| --- | --- |
| Target | `kyberlib` 0.0.11, pinned `=0.0.11`, features `kyber768` + `std`, `avx2` off |
| Contracts | 10 |
| Wall clock, `--jobs 12` | 136.7 s |
| Peak RSS | 158.3 MB |
| Upstream source changes | 0 |
| `assume` constraints | 0 |
| CI decision | PASS, every declared expectation reproduced |

---

## 1. Results

| Contract | Encoding | Outcome |
| --- | --- | --- |
| `decaps::decaps_valid_ciphertext` | key-level | `NO_LEAK_OBSERVED` |
| `decaps::decaps_corrupted_ciphertext` | key-level | `NO_LEAK_OBSERVED` |
| `decaps::decaps_supplied_ciphertext` | key-level | `NO_LEAK_OBSERVED` |
| `controls::no_planted_leak` | key-level | `NO_LEAK_OBSERVED` |
| `controls::public_component_branch` | key-level | `NO_LEAK_OBSERVED` |
| `controls::pre_keygen_seed_byte` | key-level | `LEAK_DETECTED`, branch |
| `controls::secret_component_branch` | key-level | `LEAK_DETECTED`, branch |
| `controls::secret_component_address` | key-level | `LEAK_DETECTED`, value |
| `controls::shared_secret_branch` | key-level | `LEAK_DETECTED`, branch |
| `seedlevel::keygen_and_decaps` | seed-level | `LEAK_DETECTED`, 2 branches |

Every control behaves as it does for `ml-kem`, including the sensitivity
control: a branch on a byte of the shared secret is detected, so a leak late in
the FO transform would be attributed here too.

The library makes an explicit claim at the site, which is what
`decaps_corrupted_ciphertext` tests: `MlKem768DecapKey::decapsulate`'s
documentation says it *"never panics, never branches on validity"*. Over 96
generated cases driving the implicit-rejection path, nothing contradicted it.

---

## 2. Finding A′ — the same artifact, in a second implementation, attributed

**Classification: taint-model artifact. Not a defect in `kyberlib`.**

The seed-level contract reports two secret-dependent branches, and both are
attributed to the marked secret:

```text
secret_dependent_branch, origin: created by a client request (the marked secret)
  at rej_uniform (indcpa.rs:119)
  at kyberlib::reference::indcpa::gen_matrix (indcpa.rs:172)
  at gen_a (indcpa.rs:132)
  at indcpa_keypair (indcpa.rs:237)
  at generate_key_pair (kem.rs:37)
  at kyberlib::api::derive (api.rs:381)
```

The second is the same function at `indcpa.rs:123`.

This is FIPS 203 Algorithm 7 — rejection sampling of the matrix `Â` from `ρ` —
which is exactly where `ml-kem` produces its own diagnostics. `ρ` is public: it
is transmitted inside the encapsulation key. The seed-level encoding makes it
secret only because it is derived from the secret `d`, so a finding here
describes the marking rather than the library, and the key-level boundary
removes it: all five key-level contracts report zero findings and zero
diagnostics.

### What the pair of targets establishes that neither could alone

`ml-kem`'s seed-level contracts come back `INCONCLUSIVE`, with the same
algorithmic step reported as undefined-value uses whose origin Memcheck
attributes to a stack allocation
([`../ml-kem/findings.md`](../ml-kem/findings.md) finding A). `kyberlib` has its
own Keccak and its own sampler, and here the same branches arrive **attributed
to the client request**.

So the provenance loss is not a property of sponge constructions, and not a
property of rejection sampling. It is specific to the XOF path `ml-kem` uses —
`shake`'s `ShakeReader` over `sponge-cursor` — and that narrows finding A from a
general caveat to a reproducible, locatable defect in the tool's provenance
tracking. The two audits together are what made the difference measurable; one
alone would have left the cause a guess.

It also confirms finding A's *classification* by independent reproduction: two
independently written implementations branch on `ρ` at the same step, because the
standard says to.

---

## 3. Integration notes

Two differences from the `ml-kem` adapters, both forced by the library, and both
costs the audit owns rather than defects:

**Deterministic key generation is RNG-shaped.** `kyberlib` takes
`R: RngCore + CryptoRng` for key generation and encapsulation rather than
explicit randomness, so `fixture::FixedRng` supplies the seed and the
encapsulation randomness. `the_fixed_rng_makes_encapsulation_deterministic`
pins that it is in fact deterministic. A fixture RNG that claims `CryptoRng` is
false about its security and true about its purpose; it exists in one file and
is used nowhere else.

**The boundary is cleaner here.** `MlKem768DecapKey` has no byte constructor but
lends out its storage through `as_bytes`, so the marking is applied to the buffer
the library actually reads during decapsulation — no rebuild, no second decode.
`ml-kem` needed a round trip through its (deprecated) expanded encoding for the
same effect.

**The vector test uses the soft-deprecated blob API.** ACVP supplies keys as
bytes and the typed `MlKem768DecapKey` cannot be constructed from them, so
`decapsulation_matches_the_acvp_vectors_on_both_paths` calls
`kyberlib::decapsulate`. `the_blob_and_typed_paths_agree` is what keeps the
functional evidence applicable to the typed path the contracts analyze.

---

## 4. Functional evidence: `kyberlib` is FIPS 203

The same NIST ACVP fixture as the `ml-kem` audit, read from that crate's
directory rather than duplicated:

* **key generation** — 25 vectors: `(d, z)` reproduces NIST's secret key and
  public key byte for byte, and the public key sits at the audit's offsets
  inside the secret key;
* **decapsulation** — 10 vectors: the shared secret matches on all of them, five
  unmodified and five modified, so both FO paths compute what the standard says;
* **cross-path** — the typed and blob APIs agree.

That is worth stating plainly because the crate's own `derive` documentation
cites *draft-schwabe-cfrg-kyber* rather than FIPS 203, and the crate carries a
separate `fips` feature. On the evidence of NIST's vectors, its default
`kyber768` build **is** ML-KEM-768: no `fips` feature was enabled for any run
here.

---

## 5. Disclosure status

**Nothing to disclose.** No finding reaches stage 2. The one upstream finding is
a taint-model artifact, classified as such, reproduced independently in the other
target, and explained by the standard's own algorithm.

Bounded the same way as the `ml-kem` audit: two observation classes, 352
generated cases across ten contracts, one parameter set, one portable
implementation path with `avx2` off, one compiled build. No `VERIFIED_BOUNDED`
anywhere — `kyberlib` was not put to the symbolic backend, because
[`../ml-kem/symbolic-feasibility.md`](../ml-kem/symbolic-feasibility.md) already
measured what it does with a whole ML-KEM decapsulation, and the answer does not
depend on which implementation it is.
