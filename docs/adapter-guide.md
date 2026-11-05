# Writing an audit adapter

`#[constant_time]` takes scalars and fixed-size byte arrays. Real cryptographic
code takes field elements, points, scalars in Montgomery form and types
parameterized by const generics. An **audit adapter** is the thin function that
bridges the two: it accepts what the annotation supports, builds the library's
own types, calls the library's own function, and consumes the whole result.

Broadening the annotation's type system is deliberately not the answer. The
hard question is whether a declared secret still reads as secret after the
library has converted it — and accepting the library's type as a parameter
would not answer that, because the conversion still happens somewhere. See
[`docs/audits/crypto-bigint/integration-report.md`](audits/crypto-bigint/integration-report.md)
for the measurement that settled it for `crypto-bigint`.

Worked example: [`examples/crypto-bigint-audit`](../examples/crypto-bigint-audit/README.md).

## What an adapter guarantees

Exactly one thing: that the contract's declared secrets were marked and passed
to the real operation, and that the two modeled observations — a
secret-dependent branch and a secret-dependent address — were watched for
across the whole invocation.

## What it does not guarantee

* That a finding is in the library. A contract covers the **whole adapter
  invocation**: decoding, type construction, the operation, and the result
  consumption. Only the finding's stack says which of those it came from, and
  the report's one-line `site` field names the *contract's* frame, not the
  leaking instruction's.
* That the library is constant-time anywhere else. One operation, one artifact,
  one input corpus.
* That the analyzed artifact resembles a caller's optimized binary. Different
  inlining, different artifact, different question.

## The rules

**Invoke, never reimplement.** If the adapter contains arithmetic, the analysis
is about the adapter. Decode with the library's decoder, operate with the
library's operation, convert back with the library's converter.

**Consume the entire result, in fixed work.** Whatever reduces a wide result to
the checker's scalar decides what the compiler may discard. A sink reading four
of thirty-two bytes licenses the optimizer to compute one limb, and then the
artifact no longer contains the operation the contract names. Fold every byte,
with no branch and no data-dependent index, and **test that every byte changes
the result** — `sink::consume_all_bytes` and its
`every_byte_changes_the_result` test are the pattern.

**Never compare through the sink in a correctness test.** The same fold that
makes every byte reach the result is lossy: it maps 2^256 results onto 256
values, and if it is linear — `acc * 31 + byte` is — two byte changes can
cancel *exactly*. So "the functional tests still pass" proves much less than it
reads like, which matters most where it matters most: a mutation experiment
claiming to change observable behavior without changing the arithmetic. Give
each operation a helper returning the complete result, have the annotated
adapter fold **that helper's** output, and compare the helper. One code path,
two consumers — a parallel implementation in the test would validate the wrong
thing. `sink::the_fold_is_lossy_and_must_not_be_used_for_correctness` pins a
concrete collision so the point stays true rather than remembered.

**Respect the operation's preconditions, without a secret-dependent branch.**
Prefer operations that are total over the adapter's input type; then there is
nothing to restrict and nothing to reject. Where a precondition is real,
document the adapter's input domain and enforce it with constant-work
construction — never with an `if` on a secret, unless the validity check is
itself what you are auditing.

**Declare secret roles separately, not as a parameter.** "Secret left operand,
public right" and "both operands secret" are different security requirements,
and an implementation safe for the first is not thereby safe for the second.
Two contracts, two declarations, two results.

**Keep each adapter distinguishable in the compiled artifact.** This is the
rule that cost the most to learn. Two adapters whose bodies compile identically
are folded to one function with both symbols at one address; a finding in
either then names whichever symbol survived, and attribution refuses it —
reported `INCONCLUSIVE`, with correctly located findings nobody can act on.
Since a `secret = …` declaration does not change codegen, role variants over
the same operation hit this immediately. One `xor` with a distinct
compile-time constant per contract is enough; it has no branch and no address
dependency, so it cannot change what the contract observes.

**Test the arithmetic against something that is not the library.** An adapter
that mishandles byte order, truncates an operand or builds the wrong
representation leaves the checker reporting on the wrong function, and no part
of the security pipeline notices. Generate vectors from an independent
reference — Python's arbitrary-precision integers are enough — commit them, and
make the functional tests a prerequisite for interpreting any side-channel
result.

**Make the controls part of the deliverable.** A clean result is only as
meaningful as the evidence that a leak *would* have been found. Inject one
deliberately, after the conversion into the library's type, driven by a value
the library produced. Cover the first, an interior and the last secret byte
independently — partial marking passes some and fails others. Add a negative
control that branches on a public input only. Declare them all
`expected_outcome = "LEAK_DETECTED"` so a control that stops working fails the
run instead of inflating the clean count.

**A control the compiler erases is not a control.** A source-level `if` on a
secret usually becomes a `cmov` at `opt-level = 3`. Put something the optimizer
must keep in the taken arm — a volatile write, or `core::hint::black_box` —
and confirm from the disassembly that the branch is still there.

**A structured secret is not uniformly secret, and saying so is the adapter's
job.** M11's case is the general one: a FIPS 203 decapsulation key packs
`dk_pke ‖ ek ‖ H(ek) ‖ z`, and the attacker *holds* `ek`. Mark the whole thing
and the library's rejection sampling on the public `ρ` reads as a leak — a
taint-model artifact, and the fastest way to send a maintainer a report that
discredits the audit. So:

* derive the key from the **seed** the standard defines for deterministic key
  generation, not from generated key bytes. Being a key is usually a hash
  preimage condition, which no input constraint expresses, and generated key
  bytes are keys no key generation can produce;
* run that derivation on a **declassified copy** of the seed, so the public
  derivates stay public, and re-mark only the genuinely secret components
  afterwards with `Secret::new`;
* draw the boundary on a **documented serialization**, not on the library's
  private fields, and test the offsets against the library's own accessors so a
  layout change breaks a test instead of silently declassifying key material;
* build any public input the fixture needs — a valid ciphertext, say — through
  the *public* components, so it is public by construction rather than by
  declassification.

**Two controls make a boundary checkable, and a boundary nobody checks is
worthless.** One planted leak on a genuinely secret component, which must stay
detected — that is what catches a boundary that quietly declassified
everything and made the whole audit read clean. And the *same* planted leak on
a public component under both classifications, which must differ between them —
that is what shows the line moved where it claims to and no further.

**Add a sensitivity control on the operation's output.** A branch on a byte of
the final result — derived through every hash, reduction and selection the
operation performs — bounds what a clean result is worth. If it is detected, a
leak late in the operation would be attributed. If it is not, the clean results
are compatible with the analysis having gone blind halfway through, and M11
found a real library where exactly that happens: provenance does not survive
every hash implementation, so this control is the difference between an audit
and an assumption.

## Validating an adapter

Before any security result is worth reading:

1. `cargo test` — the functional oracle, the sink's all-bytes property, and the
   representation assumptions (limb layout, byte order, modulus).
2. `cargo trace-check check --all-contracts --ci` — every control detected,
   every negative control clean, and if the secret is structured, the boundary
   pair disagreeing and the sensitivity control detected.
3. `objdump -d -l` over the analyzed artifact — the library's own frames
   present, operands loaded rather than constant-folded, the result written out
   and read. An inlined operation with no distinct symbol is fine; describing
   an inlined operation as a located symbol is not.
4. A mutation in the **library's** source, with the adapter and its contract
   unchanged, must flip the verdict and name the patched line. `ci/mutate-m9.py`
   is the harness, and its validity controls are the point: a stale patch, a
   mutation in code that never runs, a mutation that breaks the *arithmetic*,
   a reused artifact and a drifting dependency graph all fail the experiment
   instead of being reported as a result.

## When an adapter is the wrong tool

If an operation cannot be reached without rewriting the library, say so and
record the blocker. Substituting an easier operation of comparable complexity
is a legitimate choice; quietly substituting a trivial one and declaring the
target covered is not.
