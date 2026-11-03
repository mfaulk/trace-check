# Methodology

## Threat model

An attacker can call a verification function repeatedly with tags of their
choosing and observe how much work each call performs. They cannot read memory
or inspect internal state. The question is whether the amount or kind of work
performed reveals anything about the secret.

* **Public input** — the supplied authentication tag. Attacker-chosen, held
  fixed across every compared pair.
* **Secret input** — the expected tag, modeling a value derived from a key.
  This is the only thing that varies within a comparison.
* **Observable** — the ordered sequence of instruction locations executed by the
  compiled module under the interpreter.

Holding the public input fixed is what makes a difference attributable. If both
inputs varied, a path difference would not distinguish "the secret changed the
work" from "the attacker's own input changed the work".

## Why a MAC tag comparison

A fixed-length comparison of an attacker-supplied tag against a key-derived
expected tag is the relevant cryptographic operation. Computing HMAC and
managing keys would add work without changing the property under study, so the
example implements only the comparison.

The experiment relies on two properties of the chosen inputs:

1. **Decisions are held constant.** Every mismatch case rejects, so a path
   difference cannot be explained by one run accepting and another rejecting.
   The runner aborts if any case returns the wrong decision, and the comparator
   returns `INCONCLUSIVE` if two compared runs disagree.
2. **Only the mismatch position varies.** Cases A, C, D, E and B place a single
   differing byte at positions 0, 8, 16, 24 and 31. An early-exit comparison
   does work proportional to the mismatch position; a comparison that touches
   every byte does not.

## Inspecting the compiled artifact

The analysis is a claim about a specific compiled module, so the module is
inspected rather than assumed. For `examples/mac-compare` built at
`opt-level = 3` for `wasm32-unknown-unknown`:

```sh
wasm2wat "$(cargo build --release --target wasm32-unknown-unknown -p mac-compare \
  --message-format=json | jq -r 'select(.reason=="compiler-artifact")|.filenames[]|select(endswith(".wasm"))')"
```

`verify_early_exit` compiles to four pairs of `i64.load` / `i64.xor` folded
together with `i64.or` and a final `i64.eqz` — **no branch at all**. The
source-level `if` was vectorized away. `verify_early_exit_opaque` retains a
per-byte `i32.load8_u` / `i32.ne` / `br_unless` sequence because
`read_volatile` blocks the coalescing.

This is why the naive variant is kept in the experiment: the tool must report
what the artifact does, and "the source has a secret-dependent `if`" is not
evidence that the compiled module does.

## Passing inputs at runtime

Secrets must not become compile-time constants, or the interpreter would trace a
module specialized to one input. Each export therefore takes eight `i64`
arguments — four words for the expected tag, four for the supplied tag — and
reassembles the byte arrays at runtime. Word `k` carries bytes `8k..8k+8` in
little-endian order.

The reassembly loop is fixed-length and input-independent, and every export
performs the identical setup before dispatching to its verifier, so the only
thing that can differ between two traces is the comparison itself.

The module is a freestanding `cdylib` with `extern "C"` exports: no WASI
`main`, no argument parsing, no I/O, no printing inside the traced function.
That keeps the execution window small and free of startup noise.

## Trace capture and normalization

Each case is executed as

```sh
wasm-interp MODULE.wasm --run-export=EXPORT --trace \
  --argument=i64:W0 ... --argument=i64:W7
```

spawned as an argument array — never a shell string — because case data flows
into the command line. WABT 1.0.42 emits one line per executed instruction:

```text
#0. 1368: V:8  | i64.store $0:1048480+$88, 0
 ^      ^    ^    ^
 |      |    |    opcode and operands
 |      |    value-stack depth
 |      instruction-stream offset
 call depth
```

Normalization keeps `(call_depth, istream_offset, opcode)` and discards
everything else:

* **Operand text is dropped.** It encodes the input values. Keeping it would
  make every input difference look like a path difference — the single most
  likely way to build an analyzer that reports nothing but false positives.
* **Value-stack depth is dropped.** It is presentation, derivable from the path.
* **Order and repetition are preserved.** Instruction locations are compared as
  an ordered sequence, never as a multiset or an instruction count. Two runs
  with the same instruction totals but different orders are different paths.
* **The offset, not the opcode, carries identity.** Two sites sharing an opcode
  are distinct events; this is what keeps "compared only opcode names" from
  being the analysis.

Instruction-stream offsets are internal to the interpreter and specific to a
module and WABT build, which is why the WABT version is pinned, checked at
startup, and recorded in every report.

## Run sequence

1. Validate the backend version, the fixture, and the build artifact.
2. Build the example as optimized WASM and record its SHA-256.
3. For every (variant, case): execute twice and require the normalized traces to
   be identical. Nondeterminism makes everything downstream meaningless, so it
   is checked before any comparison.
4. Check each run's authentication decision against the fixture; a mismatch
   aborts the experiment.
5. For every declared comparison: compare the two ordered event sequences,
   locating the first divergence, the event totals, and surrounding context.
6. Compare each observed outcome against the outcome the fixture predicted.
7. Emit a text and/or versioned JSON report carrying toolchain versions, build
   target and profile, module hash, and parser version.

## Interpreting an outcome

`DIFFERENCE_DETECTED` means the executed instruction sequence changed while the
public input was held fixed. That is evidence of secret-dependent program
behavior and may indicate a timing side channel. It says nothing about the
magnitude or exploitability of the resulting timing signal.

`NO_DIFFERENCE_OBSERVED` means the normalized paths matched for the inputs
tested. It is a negative result over a finite input set, not a proof.

`INCONCLUSIVE` means the experiment did not produce a trustworthy answer:
nondeterministic traces, confounded decisions, truncated or unrecognized output.
It is never collapsed into "no difference".

## Extending the analysis

The event model is deliberately minimal. Milestone 2 introduces secret-indexed
memory access, where the instruction path is identical but effective addresses
differ — that requires extending `ExecutionEvent` with address information, and
the normalization rules above would have to change accordingly. Milestone 3
moves to native machine code, where the relationship between interpreter-level
findings and hardware behavior becomes the question.

## Static screening

Tracing answers "did these two runs execute the same path?" for the inputs you
chose. Static screening answers a different question — "can a secret value
reach a branch condition at all?" — which is quantified over every input but
decided on an approximation. Both tiers run without executing the module.

### Tier 0: structural census

For each screened function, count instruction shapes: branches (`br_if`,
`br_table`, `if`), loops, `select`s, loads, stores, calls, and operators outside
the modeled subset. The census makes no security claim. Its value is as a
tripwire against change.

For a fixed-length comparison primitive, **zero branches** is a strong
input-independent property, and it is cheap to assert. More importantly, the
census is committed as `artifact-baseline.json` and compared on every CI run.
The failure mode this exists for is a toolchain upgrade that if-converts a
`select` back into a branch, or that stops vectorizing a loop — a regression
invisible to source review, because the source did not change. Census drift
fails the gate; the module hash is recorded but compared separately, since it
changes on every compiler bump and would otherwise make the gate pure noise.

### Tier 1: taint analysis

A forward abstract interpretation over WASM's operand stack, locals and globals.
Each abstract value carries three facts: whether it is secret, whether it
derives from a declared secret-pointer parameter, and how many loads deep its
derivation is. Findings are raised where a secret value reaches:

| Sink | Finding | Why it matters |
| --- | --- | --- |
| `br_if` / `br_table` / `if` condition | `secret_dependent_branch` | secret-dependent control flow |
| load or store address | `secret_dependent_address` | identical instruction path, varying access pattern |
| `call_indirect` target | `secret_dependent_call_target` | secret-dependent dispatch |
| `select` condition | `secret_select` (informational) | branchless, so not a leak of this kind |

The `secret_dependent_address` sink is worth noting: it covers the
secret-indexed-table class (AES S-boxes) that differential instruction tracing
cannot see at all, because the instruction path is unchanged. That is Milestone
2's subject, reachable statically today.

### Declaring where secrets enter

Nothing in a compiled module marks which bytes are a key, so the screen config
declares it per function: which parameters are secret, and how secrets reach
them. The load policy exists because the answer depends on the ABI:

* `params` — secrets arrive as scalars. A load is secret only if its *address*
  is secret. Declaring a pointer parameter secret under this policy marks the
  pointer value itself as secret, which correctly flags the load address but is
  usually not what you mean.
* `pointer-params` — a parameter points directly at secret bytes, as with
  `&[u8; 32]`. Loads through it are secret; the address is not.
* `pointer-params-indirect` — a parameter points at a descriptor holding a data
  pointer and a length, as with `&[u8]`. The first dereference reads public
  metadata; only a second-level dereference reaches the data.

That last policy exists for a concrete false positive. A hand-rolled
`acc |= a[i] ^ b[i]` loop over `&[u8]` compiles to five branches, two loops and
a `select` — every one of them testing the slice *length*, which is public. A
branch census alone calls that leaky. It is not, and distinguishing the two
requires knowing that the first dereference is metadata.

### What the model does not do

The analysis is **intraprocedural** and **does not track taint through linear
memory**: a store of a secret value does not taint later loads. This is why the
bundled config screens the verifier functions rather than the exported
wrappers — the wrappers store their `i64` argument words to memory before
calling a verifier, so screening an export would report a false clean.

Control flow is **over-approximated**. Loop-carried taint is propagated by
re-running the function to a fixpoint with locals seeded from the previous pass,
so a local that becomes secret inside a loop is treated as secret throughout the
function, including before the loop. Erring toward reporting too much is the
right direction for a screen, but it means a finding is a *candidate* to be
confirmed — by reading the artifact, or by differential tracing.

A function containing an operator outside the modeled subset gets **no verdict**
at all, and that counts as inconclusive rather than clean. A screener that
silently skipped instructions it did not model would report "no finding" for
code it never looked at.

## Screening workflow

The two tiers here are the cheap end of a longer ladder. For reference, in
increasing cost and power:

1. **Tier 0 regression gate** — census drift in CI. No analysis, catches
   compiler-induced decay.
2. **Tier 1 taint** — quantified over all inputs, over-approximating.
3. **Differential tracing** (`demo`) — exact for the inputs run; confirms that
   taint actually reaches control flow and prunes Tier 1 candidates.
4. **Memory-address tracing** — Milestone 2; needed to *observe* the
   secret-indexed-access class that Tier 1 can only flag structurally.
5. **Statistical timing on hardware** — e.g. `dudect`; the only method that
   catches variable-latency instructions, which no trace-based analysis sees.

Prior art worth knowing rather than reinventing: **ctgrind** marks secrets as
uninitialized and lets Valgrind's memcheck report when an undefined value
reaches a branch or an address, which is taint analysis for free;
**Microwalk** does dynamic taint with leakage quantification; **DFSan** is
LLVM's dataflow sanitizer; **ct-verif**, **Binsec/Rel** and **Jasmin** cover the
formal end.

One boundary applies to all of it here: WASM is a convenient, stable IR, but it
is not what runs on hardware. A clean WASM screen says nothing about a native
build — the same argument as the `early_exit` erasure, one level up.

## Bounded relational verification

The symbolic backend (`verify`) answers a different question from everything
above, so its methodology lives with it:
[docs/MILESTONE-04.md](MILESTONE-04.md) states the relational noninterference
property, the threat model, what the fail-closed classifier requires before it
will report `VERIFIED_BOUNDED`, and the bounds every such claim is scoped to.
[docs/MILESTONE-05.md](MILESTONE-05.md) covers the second artifact source —
generating a harness around a function in a real Cargo library, so the code
analyzed is compiled from the developer's single definition of it — and the
artifact boundary that creates.
The short version: instead of running inputs someone chose, it asks a solver
whether *any* secret assignment in a declared domain changes the executed path
or an effective address, and reports `INCONCLUSIVE` whenever the search cannot
be shown to have finished.

## Choosing the inputs: coverage-guided discovery

Generated testing (`check`) and coverage-guided discovery (`check --explore`)
answer the same security question as the dynamic backends above. What differs
is only *which inputs are tested*, so the methodology that matters is the
separation between choosing an input and judging it.

[docs/MILESTONE-06.md](MILESTONE-06.md) covers input generation from a declared
contract. [docs/MILESTONE-07.md](MILESTONE-07.md) covers the coverage-guided
stage and the measurements behind its design decisions.

The procedure, in the order a run performs it:

1. Generate M6's corpus — boundaries, pairwise, relationships, seeded random —
   from the contract descriptor alone.
2. Build a **discovery artifact** with `-C instrument-coverage`. It marks no
   secret and does not depend on the marking crate, so it cannot produce
   evidence about secret dependence. Because it calls the LLVM profiling
   runtime directly, it does not link without instrumentation.
3. Read the coverage map once, and refuse to continue if it holds no record for
   the function under study or no region inside the library — reporting coverage
   of *something* while the function under study is invisible would be the most
   misleading available result.
4. Execute every M6 case in that artifact, one profile per case, and record
   which library regions each reached.
5. Mutate retained inputs — an exhaustive single-byte sweep per seed first, then
   random havoc — and keep those reaching regions nothing has reached. A
   candidate whose profile cannot be validated contributes no coverage and is
   reported, because an empty region set reads as "reached nothing new" and a
   silent decode failure would make a search that did nothing look like a
   search that found nothing.
6. Select a bounded corpus: every M6 case, plus a greedy set cover over the
   explored candidates. Everything dropped is counted, and the two reasons are
   kept apart because only one of them costs coverage.
7. Analyze that corpus in the **uninstrumented** artifact, under the same two
   positive controls, with the same batching, isolation, shrinking and
   classification as M6.

Steps 2 to 6 produce no security evidence and cannot strengthen an outcome. The
one direction they can move a result is weaker: a run that was asked to explore
and did not finish reports `INCONCLUSIVE`, because the inputs its result
describes are not the inputs it was configured to search for.

The boundary to keep in mind is the same one the WASM screen has, one level
over: the instrumented artifact is not the artifact a result describes.
Instrumentation changes code generation, so a region reached during discovery
may be reached by different instructions, or not at all, in the optimized build.
A finding stands regardless of how its input was chosen; a clean result never
claims the discovery artifact's paths were verified.
