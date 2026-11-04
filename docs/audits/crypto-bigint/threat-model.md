# Threat model and analysis boundary

## What is observed

M9 adds no observation model. The backend is the same generated-input Memcheck
checker M6 and M8 use, and it models exactly two things:

* a secret-derived value reaching a **conditional branch**;
* a secret-derived value reaching an **effective memory address**.

It does not model cache state, execution ports, speculation, power, or
data-dependent instruction latency. A result here is not independence from
timing; it is the absence of two specific, well-defined dependencies in one
compiled artifact over the inputs that were executed.

## What the contract covers

The analyzed program is not the library. It is:

```text
generated harness
    |  marks a secret [u8; 32] and calls the adapter
    v
audit adapter                       <- examples/crypto-bigint-audit
    |  U256::from_be_slice
    v
crypto-bigint 0.7.10                <- the subject of the audit
    |  the operation's own multi-limb arithmetic
    v
audit adapter
    |  to_be_bytes, then a fixed-work fold over all 32 bytes
    v
generated harness
```

A `#[constant_time]` contract on the adapter covers that **entire
invocation** — the decoding, the construction of the library's types, the
library operation, and the consumption of the result. Four consequences follow,
and the audit reports are written to respect all four.

**A finding is not automatically about upstream arithmetic.** It is about one of
those four stages. Which one is a question the finding's own stack answers, and
only the stack answers it: the report's one-line `site` field names the
contract's own frame, because that is the frame the contract is attributed to.
The leaf frame is where the leaking instruction is. For an upstream finding
those differ, and
[`integration-report.md`](integration-report.md#experiment-d--telling-the-adapter-apart-from-the-library)
records a measured example of exactly that.

**A clean result on the adapter is worth nothing on its own.** It is
indistinguishable from a harness that marked nothing, an operation the compiler
deleted, or a secret that stopped being tracked at the first type conversion.
The invariant this example is built around:

> A clean adapter result is not upstream audit evidence until the integration
> has separately demonstrated that declared secret dependencies reach the
> target operation.

That demonstration is the six controls in `src/controls.rs`, which are
`expected_outcome = "LEAK_DETECTED"` in `trace-check.toml`. If one of them ever
stops being detected, the run fails on an unmet expectation rather than
reporting a clean sweep.

**The adapter is in scope, and it is code that can be wrong.** A byte-order
mistake, a truncating decode, a result that is only partly consumed — each
would leave trace-check analyzing something that is not the intended operation
while reporting on it confidently. So every adapter carries functional tests
against an independently written reference, and no side-channel result is
interpreted before they pass.

**The analyzed artifact is not a production build.** Its profile
(`opt-level = 3`, `debug = true`, `lto = off`, `codegen-units = 1`), its
dependency versions and its hash are recorded with every result, because the
result describes that build. A different inlining decision in a caller's
optimized binary is a different artifact and a different question.

## What is secret, and who decides

Nothing in the tool decides. The `secret = …` arguments on each adapter do, and
that is a cryptographic judgment made by whoever writes the adapter:

* **Target A** has two contracts — one secret operand, and both secret —
  because they are different requirements. An implementation that is safe with
  a public operand is not thereby safe with a secret one, and the declaration
  is what records which claim was checked.
* **Target B**'s selection value is secret; the two candidates are declared
  secret as well, since selection between public values would not be a
  constant-time concern.
* **Target C**'s modulus is a pinned public constant, which is the usual
  cryptographic situation. An audit of a *secret* modulus is a different
  threat model and is not attempted.

A public parameter is held equal between the two compared executions, so
branching on it is permitted by construction. `controls::public_operand_branch`
is the negative control for that: a finding there would be wrong in the
direction that makes the tool useless.

## Out of scope

* Any claim that `crypto-bigint` is secure, or insecure. Three operations under
  one observation model on one target is not an audit of a library.
* Operations the adapters do not reach. The compiled inventory covers the nine
  declarations in this example and nothing else; `crypto-bigint` has hundreds
  of public functions, and a function with no declaration is not accounted for
  here at all.
* Hardware timing measurement, other architectures, other toolchains, and
  other feature selections.
* Proof. A generated dynamic check is `NO_LEAK_OBSERVED` over the inputs it
  ran. The symbolic backend can say `VERIFIED_BOUNDED`, and that too is bounded
  by a depth limit, an input domain and one artifact — M9.6 evaluates whether
  it reaches this integration at all.
