# M11.8 — What the audit cost, and what it could not do

The milestone's own report. Three questions: what did it take to audit two
cryptographic libraries nobody here wrote, what did the analysis establish, and
which tool changes does the friction justify.

---

## 1. Cost

| | `ml-kem` | `kyberlib` |
| --- | --- | --- |
| Contracts | 13 | 11 |
| Adapter code outside tests and controls | 61 lines | 74 lines |
| Control code | 182 lines | 118 lines |
| Committed vector fixture | 372 kB, shared | reuses the same file |
| Upstream source changes | 0 | 0 |
| `assume` constraints | 0 | 0 |
| `check --all-contracts --ci --jobs 12` | 90 s | 93 s |
| Peak RSS | 157 MB | 158 MB |

Plus the controls: `rsa` 116 s for two contracts, and the two `ml-dsa` halves
26–28 s each, all three sequential. The symbolic attempt on a whole ML-KEM-768
decapsulation is 8 s and 173 MB, and settles nothing.

`--all-contracts` is what the audits run, for two reasons that are easy to get
wrong: it enforces every declaration the *compiled library* carries rather than
the ones `trace-check.toml` happens to name, and it is the only selection
`--jobs` affects. The same thirteen `ml-kem` contracts take 114 s sequentially,
so the parallel figure above is a measurement of the command line printed with
it.

So **the whole milestone's analysis is about seven minutes of compute.** The
cost that mattered was not machine time. It was three things, in descending
order:

1. **Deciding what "secret" means for a structured key.** A decapsulation key
   packs public and secret components together, and getting that wrong produces
   confident findings about data the attacker already has. This is the part that
   needed the most thought and is the part a user of this tool will have to
   repeat for every new primitive.
2. **Establishing that the operation analyzed is the operation named.** Five
   steps in the adapter could each be subtly wrong, so the ACVP vectors are not
   optional extra rigour — they are what makes any security result mean
   anything.
3. **Clearing two link failures** before the symbolic backend ran at all.

## 2. What was established

**Two independently maintained implementations of FIPS 203, audited with zero
upstream changes.** ML-KEM-768 decapsulation is `NO_LEAK_OBSERVED` over 192
generated cases for `ml-kem` 0.3.4 and 192 for `kyberlib` 0.0.11, under two
observation classes, with the public and secret components of the key
distinguished. Both reproduce NIST's ACVP vectors on both paths through the FO
transform, so both compute ML-KEM-768 and both halves of it ran.

**The clean results are load-bearing only because the controls are.** Six
planted controls per target are detected, including **two** sensitivity
controls — one per data path through the FO transform, because a valid
ciphertext's shared key depends on the decryption key and a rejected one on the
implicit-rejection seed. Without both, a clean result would be compatible with
the analysis having gone blind on one of the two paths mid-transform.

**`decapsulate`'s constant-time shape survives `opt-level = 3`:** 743
instructions, 12 conditional jumps over public bounds, seven `cmov` where
`ct_eq` and `ct_select` are, no division. Not something a source review
establishes.

**One real leak detected that nobody here planted** — `rsa` 0.9.10's modular
exponentiation, which RUSTSEC-2023-0071 is about.

**No previously unknown vulnerability.** M11's stretch goal is not met, and §4
is about why that is a weak conclusion rather than a strong one.

## 3. What it could not do

Ranked by how much they limited the audit.

### 3.1 Provenance does not survive some XOF paths

The largest limitation, and new. Under a seed-level marking, `ml-kem`'s
rejection sampler produces ten undefined-value uses whose origin Memcheck
attributes to a stack allocation rather than to the client request, so the
classifier cannot tie them to the declared secret and fails closed to
`INCONCLUSIVE`. `ml-dsa` is worse: 147 such diagnostics and **zero** attributed
findings, which means ML-DSA signing is not analyzable to a verdict at all
today.

`kyberlib` is the control that localizes it: its own Keccak and its own sampler
report the same algorithmic step as *attributed* findings. So this is not a
property of sponges or of rejection sampling — it is specific to the
`shake`/`sponge-cursor` path that `ml-kem` and `ml-dsa` share.

**The fix is a reduced reproducer against `shake` alone**, which M11 did not
build: enough to tell an approximate origin tag apart from an over-read of a
partially initialized buffer, and then either a Memcheck invocation change or an
upstream report. Until then, any audit of a library on that XOF stack can
analyze only a declassified key-generation path, as these two did.

### 3.2 The symbolic backend cannot finish an ML-KEM path

It reaches the target, discharges 7340 noninterference checks without a
violation, completes **none** of its four paths, and answers `unknown`. And the
run does not say why: depth is three orders of magnitude below the bound, no
solver query came back unknown, no path is pending.

**The smallest useful change is to keep the analyzer's log beside the artifact.**
The tool does not retain it even under `--artifact-dir`, so "unmodeled
instruction" and "internal limit" cannot be told apart from the report. That is
one flag and one file, and it is the difference between a measurement and a
shrug.

### 3.3 A library with no reachable leaf cannot be verified at all

Every arithmetic module in `ml-kem` is private, so the smallest symbolic target
its API offers is a whole decapsulation. This is not a tool limitation and not a
defect — libraries are entitled to private internals — but it decides what
bounded verification can be pointed at, and it is worth knowing before planning
an audit around it.

### 3.4 The adapter depends on a deprecated trait

`ml-kem`'s classification boundary needs `ExpandedKeyEncoding`, deprecated
upstream in favour of the seed. No other public API makes a key's public and
secret components addressable. `kyberlib` happens to be better here —
`as_bytes` lends out the real storage — but that is luck, not design.

**What would help generally: a way to declare a *region* of a secret parameter
public.** Every audit of a structured key will otherwise re-derive this by hand
from whatever serialization the library happens to expose.

### 3.5 An adapter that needs the marking crate cannot be verified

`trace-check-secret` links `std`, so a crate using it collides with the
freestanding harness on `panic_impl`. M11 worked around it with a second
`no_std` crate, at the cost that the symbolic attempt could not use the
classification boundary. A `no_std` build of `trace-check-secret` would remove
the workaround.

### 3.6 Scope limits, unchanged

Two observation classes; no latency, cache, predictor or speculation. One
parameter set per contract, one portable implementation path, one toolchain, one
feature selection, one compiled build per result. No `VERIFIED_BOUNDED` anywhere
in this audit.

## 4. Why "no vulnerability found" is a weak conclusion here

M11 set out to avoid one failure mode: *"no vulnerability found, and no way to
tell whether that is a property of the library or of the tool."* On the evidence
above, the honest account is mixed.

For **decapsulation under the key-level boundary**, the conclusion is
reasonably strong. The operation is confirmed present in the artifact, the
secret is confirmed to propagate through the whole transform by a control that
would catch a late leak, both FO paths are confirmed to execute by NIST's own
vectors, and two independent implementations agree.

For **everything else**, it is weak, and the limitations above are why:

* key generation was analyzed only with its inputs declassified, so nothing was
  established about it;
* the seed-level encoding — the stronger property — cannot produce attributable
  results on this XOF stack;
* nothing was verified symbolically;
* the one leak class the audited code might plausibly still contain, operand
  latency, is outside the model, and M11.6 could not even demonstrate that
  blind spot because the compiler removed the example.

A reader should take from this that trace-check can now audit a real
post-quantum KEM end to end and say something defensible about its
decapsulation, and that the next milestone's most valuable work is §3.1 — not
another target.

## 5. Ranked tool changes the audit's friction justifies

1. **Close the provenance gap on the `shake` XOF path** (§3.1). It is the
   difference between "ML-DSA is not analyzable" and "ML-DSA is analyzable".
2. **Retain the analyzer's log** (§3.2). One flag; turns an `unknown` into a
   diagnosis.
3. **Declare public regions of a secret parameter** (§3.4). Every structured
   key needs it; every audit currently hand-rolls it.
4. **Build `trace-check-secret` without `std`** (§3.5). Removes a whole
   duplicated crate from any audit that draws a boundary.
5. **A per-finding "which stage" attribution**, so an upstream finding is
   distinguishable from an adapter finding without reading the stack by hand.
   Known since M9 and still true.
