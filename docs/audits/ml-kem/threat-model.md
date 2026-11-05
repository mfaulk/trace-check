# M11 — Threat model and analysis boundary

What an `ml-kem` result in this audit is a statement about, and what it is not.
[`../../limitations.md`](../../limitations.md) holds the tool-wide limits; this
file holds the ones specific to auditing a KEM.

---

## 1. The attacker

An attacker who

* holds the public encapsulation key `ek`, as the protocol intends;
* chooses the ciphertext `c` submitted for decapsulation, including malformed
  ones, and may submit many;
* observes the execution of decapsulation through its **control flow** and its
  **effective memory addresses**;
* does **not** observe instruction latency, cache state, branch-predictor
  state, speculation, or power.

The last two lines are the observation model, and they are the reason a clean
result here is narrow. A secret-dependent division — the defect RUSTSEC-2025-0144
documents in `ml-dsa` — is invisible to every backend in this project, which is
why M11 carries that advisory as a negative control rather than as a target.

The secret is the decapsulation key. The security property is noninterference
over the modeled observations: nothing the attacker observes may depend on it.

---

## 2. The secret input domain, and why it is a seed

Decapsulation is `K = Decapsulate(dk, c)`, and the obvious encoding of "vary the
secret" is to generate `dk`. That encoding is wrong.

For ML-KEM-768, `dk` is 2400 bytes holding `dk_pke ‖ ek ‖ H(ek) ‖ z`. Being a
decapsulation key therefore includes `H(ek)` matching `ek` — a hash preimage
condition. No `assume` constraint expresses it, so generated `[u8; 2400]` values
are overwhelmingly not keys, and a finding over that domain could be unreachable
for every key the system can actually hold.

So **the secret parameter is the 64-byte key-generation seed** `d ‖ z`. FIPS 203
defines exactly that as the input to deterministic key generation, `ml-kem`
exposes it as `DecapsulationKey::from_seed`, and every secret value the audit
analyzes is consequently a genuine key. Two consequences:

* **No input-domain restriction is needed anywhere.** Key generation is total
  over the seed, and decapsulation is total over the ciphertext — FIPS 203
  rejects implicitly, so a malformed `c` returns a pseudorandom key rather than
  taking an error path. As in M9, the whole class of "was this input even valid"
  question does not arise, and no contract in `examples/ml-kem-audit` carries an
  `assume`.
* **Key generation lands inside the analyzed region**, which is what §3 is about.

---

## 3. Classification: a decapsulation key is not uniformly secret

`dk_pke` and `z` are secret. `ek` and `H(ek)` are public — the attacker holds
`ek`. But both halves are derived from `d`, so marking the seed taints the public
half too.

That matters concretely rather than theoretically. Key generation samples the
matrix `Â` from `ρ` by **rejection**, and `ρ` travels in `ek`. Under a seed-level
marking, the sampler's loop is driven by data Memcheck considers secret, so the
analysis reports behavior that depends on a value the protocol publishes. The
library says as much at the site — `sample_ntt`'s own comment reads "The XOF
input is the public seed `rho`, so the data-dependent loop does not leak
secrets" — and it is right.

A finding of that kind is a **taint-model artifact**. Reporting one to a
maintainer as a vulnerability is the fastest way for an audit to discredit
itself, so the boundary is drawn explicitly.

### Where the boundary is drawn

The expanded encoding `dk_pke ‖ ek ‖ H(ek) ‖ z` is a *documented serialization*,
not a private struct layout, and `ml-kem` exposes it through
`ExpandedKeyEncoding::to_expanded_bytes` / `from_expanded_bytes`. So the
classification can be expressed on byte ranges the standard defines:

```text
offset     0        1152           2336   2368   2400
           | dk_pke  |      ek      | H(ek) |  z  |
           |<-- secret -->|<-- public -->|<- secret ->|
```

[`examples/ml-kem-audit/src/layout.rs`](../../../examples/ml-kem-audit/src/layout.rs)
holds those offsets, with a test that checks them against the library's own
`encapsulation_key().to_bytes()` so a layout change breaks the test rather than
silently declassifying key material.

The sequence each key-level contract runs:

1. the harness marks the 64-byte seed;
2. the adapter **copies the seed and declassifies the copy**, then calls
   `from_seed` on it — so key generation, including the `ρ`-driven rejection
   sampling, executes entirely on public data;
3. the derived key is serialized to its expanded form, and `Secret::new`
   **re-marks only** `dk_pke` and `z`;
4. the key is rebuilt with `from_expanded_bytes` and decapsulates a ciphertext
   built from the *public* bytes of that same encoding;
5. the whole 32-byte shared key is folded so nothing is optimized away.

Step 2 is what keeps `ρ` public. Step 3 is what keeps the audit about protected
data. Step 4's ciphertext is public **by construction** rather than by
declassification: it is produced through an encapsulation key reconstructed from
the public byte range, so no secret component is read while building it.

### Why the boundary is checkable rather than asserted

Two control pairs, because a boundary that quietly restored definedness for
everything would make the entire audit read clean and nothing else would notice.

| Control | Reads | Expected |
| --- | --- | --- |
| 2 `secret_component_branch` | a byte of `dk_pke`, after re-marking | detected |
| 3 `secret_component_address` | an `SBOX` load indexed by a byte of `dk_pke` | detected |
| 4 `public_component_branch` | a byte of `ek`, under the key-level boundary | **clean** |
| 5 `public_component_branch_seed_level` | the same byte of the same `ek`, seed-level | not clean |

Controls 2 and 3 catch over-declassification. Controls 4 and 5 are the evidence
that the boundary moved the classification line where it claims to and only
there: one byte, one branch, two encodings, two different answers.

What control 5 actually produces is `INCONCLUSIVE` rather than `LEAK_DETECTED`,
for a reason that is itself a finding; [`findings.md`](findings.md) records it.

### Reading a relational claim from a taint-based backend

Memcheck's model is per-execution definedness, not a comparison of two runs. The
claim a clean dynamic result supports is therefore "no modeled observation in
this execution depended on the marked bytes", evaluated over the generated
corpus. Holding the public input fixed is automatic — there is only one
execution — so deriving a case's public ciphertext from that case's key is sound
as long as the ciphertext's bytes are untainted where they are used, which step 4
arranges.

Across cases the public input *varies*, and that is coverage, not a relational
statement. The two are never combined: no report here claims that varying public
inputs established anything about secret dependence.

---

## 4. The analysis boundary, in one picture

```text
generated harness --> audit adapter --> ml-kem 0.3.4 --> adapter --> harness
                      (seed, boundary,   (keygen,         (fold)
                       ciphertext)        decapsulate)
```

A contract covers that whole invocation, so a finding is a statement about one
of four stages. `site` names the contract's own frame, which means an upstream
finding read from `site` alone looks like an adapter finding; the stack is what
distinguishes them. That hazard is M9's finding two, unchanged.

---

## 5. Out of scope

* **Instruction latency, caches, speculation, power.** Not modeled by any
  backend here. The `ml-dsa` control exists to demonstrate the first of these
  rather than to leave it as a sentence.
* **Encapsulation and key generation as security targets.** Key generation is
  analyzed only at the seed level, as a measurement of the boundary; its secret
  is the seed, and the audit makes no constant-time claim about it.
* **Parameter sets other than ML-KEM-768.** `#[constant_time]` takes
  non-generic free functions, so each adapter pins one monomorphization. Results
  do not transfer across parameter sets.
* **SIMD paths.** The portable implementation is the target.
* **The production binary.** The analyzed artifact is built by the harness, with
  its own profile and hash, both recorded per contract.
* **Any claim that `ml-kem` is secure.** `NO_LEAK_OBSERVED` is a statement about
  the generated corpus under two observation classes, and nothing more.
