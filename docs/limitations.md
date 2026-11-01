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

Out of scope for Milestone 1, by design rather than by omission:

* native instrumentation (Valgrind) and hardware-level measurement,
* memory-address and cache-line analysis *as an observed trace* — Tier 1 flags
  secret-dependent addresses structurally, but nothing measures them,
* statistical timing measurement,
* secret-taint analysis or automatic discovery of which inputs are secret,
* instrumentation of arbitrary crates or full protocol integrations,
* general-purpose constant-time certification.

## Reading the fixture's expectations

`cases.json` declares an expected outcome per comparison, and the demo exits
non-zero when one is not reproduced. That gate asks "did the experimental
controls behave as predicted?" — it is not a security verdict. An unmet
expectation most often means the compiler changed, and the correct response is
to inspect the new artifact, not to adjust the expectation to match.
