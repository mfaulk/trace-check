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
