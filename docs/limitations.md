# Limitations

The central claim of this project is narrow, and the distance between what is
observed and what is often inferred is the thing most worth being precise about.

## What a result is a statement about

A `trace-check` finding describes **one compiled WASM module**, executed by
**one pinned interpreter version**, over **one finite set of test vectors**. The
report records the module's SHA-256, the Rust and WABT versions, and the build
target and profile for exactly this reason: change any of them and the result
has to be re-established.

## `NO_DIFFERENCE_OBSERVED` is not proof of security

Matching instruction paths over the tested inputs do not establish constant-time
behavior. The outcome is named for what was observed rather than what might be
concluded.

Specifically, it does **not** rule out:

* a path difference at an untested input,
* secret-dependent **effective memory addresses** along an identical instruction
  path (the subject of Milestone 2),
* secret-dependent **instruction latency** — a variable-latency division or
  multiplication is invisible to this analysis,
* cache, branch-predictor, prefetcher, or speculative-execution effects,
* anything about the native code a different compilation would produce.

## `VERIFIED_BOUNDED` is the strongest result here, and still not a proof

The symbolic backend (`verify`) is the only one whose clean result quantifies
over inputs rather than sampling them. When it reports `VERIFIED_BOUNDED` it
has established: for the **declared** secret and public globals, within the
**declared** `assume` constraints and the exploration depth bound, no secret
assignment changes the executed instruction path or any effective memory
address, in **this one** compiled artifact.

Everything outside those words is unestablished. In particular it does **not**
rule out:

* a leak outside the declared input domain, or beyond the depth bound — a case
  that stops early is `INCONCLUSIVE`, never verified,
* secret-dependent **instruction latency**; BINSEC has experimental
  multiplication and division checks and they are deliberately off,
* cache, branch-predictor, prefetcher, or speculative-execution effects,
* anything about a different build. The artifact's SHA-256, the `rustc`
  version, and the exact flags are recorded because a recompilation
  invalidates the result,
* anything about the *surroundings* of the function. The analyzed artifact is a
  freestanding `no_std` harness whose inputs are globals; the function under
  test is ordinary optimized Rust, but its calling context is not.

A differing execution path is also not a measured timing signal. The solver
proves that two executions diverge; nothing in this project measures what that
divergence costs on real hardware. That is Milestone 5.

Finally, the analyzer localizes a leak without exposing the satisfying model,
so there is no concrete pair of secrets to replay. The report records
`unavailable_from_analyzer` rather than manufacturing a witness.

## `DIFFERENCE_DETECTED` does not quantify a vulnerability

An observed path difference is evidence of secret-dependent program behavior. It
is not a measurement. The analysis does not establish:

* how large the resulting timing difference is in wall-clock terms,
* whether that difference is observable across a network or by a co-located
  attacker,
* how many queries an attacker would need,
* whether the difference survives into a native build at all.

Instruction counts in this tool are counts of *interpreted* instructions. They
are not cycle counts and should not be read as a timing model.

## Interpreter findings do not transfer to native code

The experiment analyzes WASM executed by WABT's stack-based interpreter. A
native build of the same Rust source is a different compilation through a
different backend to a different instruction set, and it may branch where the
WASM does not or vectorize where the WASM does not.

The `early_exit` variant is the concrete demonstration available here: identical
Rust source yields a branchless XOR/OR tree in optimized WASM. The same source
compiled natively, at a different optimization level, or by a different compiler
version may retain the branch. A result for one artifact is not a result for
another.

## The "constant time" label

`verify_constant_time` uses the `subtle` crate, which is designed for
constant-time comparison and is a reasonable choice. "Constant time" there
describes an *intended property* that depends on the compiler, target and
platform cooperating — not a guarantee the crate can enforce. This project
treats `subtle` as a negative control whose actual compiled behavior is
measured, not assumed, and it does not certify the crate.

No part of this tool labels code "secure" or "verified constant-time", and
output deliberately avoids that vocabulary.

## Static screening adds its own limits

The `screen` command is a screen, not a proof. Three properties bound it:

* **Secrets are declared, not discovered.** The analysis knows which values are
  secret only because the config says so. A wrong declaration produces a
  confident wrong answer, in either direction.
* **Taint does not flow through memory.** A store of a secret value does not
  taint later loads, so analysis must target the function where secrets arrive
  at the boundary. Screening a wrapper that spills its arguments to memory
  reports a false clean.
* **Control flow is over-approximated.** Findings are candidates to confirm,
  not confirmed leaks. Loop-carried taint is attributed to the whole function.

A function containing an unmodeled operator yields no verdict, and that counts
as inconclusive — never as clean.

"Zero findings" therefore means: no *declared* secret reaches a branch, address
or indirect call target, in *this* compiled module, under the *modeled*
instruction subset. It does not mean the function is constant-time.

The Tier 0 baseline gate makes an even narrower claim. It asserts only that the
compiled shape of the screened functions has not changed since the baseline was
recorded. A passing gate is not a security property; a failing gate is a prompt
to go inspect the artifact.

## Scope boundaries by construction

Out of scope for the WASM backend (Milestone 1), by design rather than by
omission. Native instrumentation arrived in M2 and bounded symbolic
verification in M4; the rest remains out of scope for the project as a whole:

* native instrumentation and hardware-level measurement — *M2 added Valgrind
  Memcheck; hardware measurement is still absent*,
* memory-address analysis — *M2 and M4 both detect secret-dependent addresses;
  cache-line behavior is still unmodeled*,
* statistical timing measurement,
* secret-taint analysis or automatic discovery of which inputs are secret,
* instrumentation of arbitrary crates or full protocol integrations,
* general-purpose constant-time certification.

Out of scope for the symbolic backend (Milestone 4), by instruction: no custom
symbolic execution engine, no custom SMT solver, no heap modeling or dynamic
allocation, no concurrency, no unbounded loops or recursion, no automatic
verification of arbitrary crates, no automatic verification of every
`#[constant_time]` annotation, and no proof certification. Connecting M3
contracts to the symbolic backend is deferred until the native verification
model has proven reliable.

## Reading the fixture's expectations

`cases.json` declares an expected outcome per comparison, and the demo exits
non-zero when one is not reproduced. That gate asks "did the experimental
controls behave as predicted?" — it is not a security verdict. An unmet
expectation most often means the compiler changed, and the correct response is
to inspect the new artifact, not to adjust the expectation to match.
