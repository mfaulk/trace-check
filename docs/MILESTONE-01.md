# Milestone 01 — Reproducible side-channel trace comparison

**Status:** Implemented — see [Implementation status](#implementation-status)  
**Target branch:** `main`  
**Primary backend:** WebAssembly, using WABT `wasm-interp`  
**Primary example:** MAC authentication-tag comparison

## Goal

Turn the existing manual tracing proof of concept into a small, reproducible tool that detects **secret-dependent execution paths** in a plausible cryptographic operation. A reader should be able to run one command, compare an intentionally vulnerable implementation with a constant-time-oriented implementation, and see where the execution traces diverge.

This milestone is a **vertical slice**, not a general constant-time verification framework: one example, one tracing backend, a structured parser and comparator, useful diagnostic output, and automated tests.

### Success in one sentence

On a pinned Linux toolchain, `cargo run -p trace-check -- demo mac-compare` builds the WASM example, runs paired secret inputs, detects the expected control-flow difference in the vulnerable verifier, reports no control-flow difference for the chosen `subtle`-based comparison cases, and produces a reproducible report.

This command now exists and reproduces the controls; see
[Implementation status](#implementation-status) for where the observed results
differed from the predictions below.

## Baseline

The original repository contains a small Rust program with a secret-dependent conditional, README instructions for manual Valgrind Lackey and WABT tracing, and several committed trace logs. It does **not** have an automated runner, normalized trace representation, comparator, diagnostics, or CI coverage.

Keep the existing example available as historical context or adapt it into the new examples layout. Avoid committing additional multi-megabyte raw trace logs.

## Example: verifying a 32-byte MAC authentication tag

A verifier compares an attacker-supplied authentication tag with the expected tag computed using a secret key. An early-exit comparison can reveal how much of the supplied tag matches the correct tag. We do **not** need to implement HMAC or manage keys: the fixed-length comparison is the relevant cryptographic operation.

### Vulnerable implementation (expected to reveal a path difference)

```rust
pub fn verify_early_exit(expected: &[u8; 32], supplied: &[u8; 32]) -> bool {
    for i in 0..32 {
        if expected[i] != supplied[i] {
            return false;
        }
    }
    true
}
```

This is functionally correct, but it can stop after the first differing byte. Whether the **compiled** module actually retains a secret-dependent branch must be verified; the source-level `if` is not sufficient proof.

### Constant-time-oriented implementation (expected path-equivalence control)

Use the widely used `subtle` crate's `ConstantTimeEq` rather than inventing a second bitwise comparison algorithm:

```rust
use subtle::ConstantTimeEq;

pub fn verify_constant_time(expected: &[u8; 32], supplied: &[u8; 32]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}
```

“Constant time” describes an intended property, not a guarantee for every compiler version, WASM interpreter, or hardware platform. Verify the **actual compiled WASM** for the chosen test cases.

### Experimental inputs

Hold public data fixed and vary only the expected tag (the secret value in this model):

| Case | Public supplied tag | Secret expected tag | Correct result |
| --- | --- | --- | --- |
| A | 32 zero bytes | `01 00 ... 00` (mismatch at byte 0) | Reject |
| B | 32 zero bytes | `00 00 ... 01` (mismatch at byte 31) | Reject |
| C–E | 32 zero bytes | Single mismatch at bytes 8, 16, or 24 | Reject |

Both programs must return **the same authentication decision** for cases A and B. This avoids conflating accepted-versus-rejected behavior with secret-dependent comparison work.

**Expected observation:** the early-exit comparator executes different instruction paths for early and late mismatch; the `subtle` implementation has matching normalized paths for those cases. If the compiler invalidates either prediction, investigate the compiled WASM rather than hard-coding the expected result.

## Technical design

### Choose a single tracing backend for M1

Use `wasm32-unknown-unknown` and a freestanding Rust library with unmangled `extern "C"` exports. Invoke exports directly through WABT's `wasm-interp` with `--run-export`, typed `--argument` values, and `--trace`. WABT currently supports invocations of this general form:

```sh
wasm-interp path/to/module.wasm --run-export=FUNCTION \
  --argument=i32:VALUE --trace
```

The exact command, supported argument types, and trace format must be verified against a **pinned WABT version** in the first PR. Compile in release mode and inspect the generated module with `wasm2wat` or `wasm-objdump`.

Pass inputs **at runtime**, not as compile-time constants. A practical wrapper can accept four `i64` words for each 32-byte tag, reconstruct fixed-length byte arrays, and invoke either verifier. Document the byte-order and scalar-to-array mapping; avoid secret-dependent setup work. The exported wrapper's setup must be identical across compared cases.

Avoid a WASI `main`, command-line parsing, filesystem I/O, and printing inside the traced function. We want a small, stable execution window, not startup noise.

### Trace representation

Separate raw interpreter output from stable instruction-path facts. Proposed representation:

```text
ExecutionEvent {
    function_id,       // identifies a function within the compiled module
    instruction_site,  // module/function-relative executed location
    opcode             // diagnostic information, not sufficient alone
}
```

Adapt these fields to what the pinned WABT version reliably emits. Preserve the **ordered sequence of instruction locations**. Do not compare only opcode names or aggregate instruction counts. Remove incidental formatting and stack/operand values from the control-flow comparison key, but do not remove meaningful differences in executed locations or repetitions.

The analyzer's initial security property is **instruction-path equivalence**. It does not yet claim equivalence of effective memory addresses, native instruction latency, cache behavior, or physical timing.

### Run and comparison sequence

1. Validate the compiled artifact, target export, input fixture, and WABT version.
2. Execute an identical case twice and ensure normalized traces are stable.
3. Execute the vulnerable verifier under cases A and B with the public tag held fixed.
4. Repeat for the `subtle`-based verifier.
5. Parse all captured traces to typed, ordered execution events; reject partial or unrecognized output.
6. Compare event sequences; identify the first divergence, event counts, and short context before and after divergence.
7. Confirm both runs return the same correct reject decision.
8. Emit a human-readable and JSON report with reproducibility metadata.

Use subprocess argument arrays, not shell interpolation. Set timeouts and output-size limits. Treat traps, nonzero exits, malformed output, and parser failures as explicit errors, not as equivalent traces.

### Outcomes and interpretation

- `DIFFERENCE_DETECTED` — observed instruction-path difference under the tested input pair.
- `NO_DIFFERENCE_OBSERVED` — normalized instruction paths matched **for the tested cases**; not proof of constant-time security.
- `INCONCLUSIVE` — capture, parsing, nondeterminism, execution, or comparison failed to produce a trustworthy answer.

A demo-level result may indicate whether the expected **experimental controls** were reproduced. Do not label arbitrary code “secure” or “verified constant-time.”

### Reporting

Each comparison should include:

- Example, implementation variant, fixture case IDs, target export, and return values.
- Build target/profile, compiled WASM SHA-256, Rust toolchain and WABT versions.
- Number of normalized events in each run, first divergence index, and nearby instruction context.
- Classification, explanatory message, and limitations.
- Versioned JSON schema and trace-parser version.

Do not include secret bytes in normal reports. Raw traces may expose input values and should be explicitly opt-in, contain only synthetic examples, and never be committed by default.

Support terminal text and JSON. An optional `trace-check compare TRACE_A TRACE_B` command can analyze previously captured traces without rerunning the example, provided it does not jeopardize the end-to-end demo.

### Suggested repository structure

```text
Cargo.toml                     # workspace
rust-toolchain.toml
README.md
crates/trace-check/
  Cargo.toml
  src/
    main.rs
    experiment.rs
    runner.rs
    parser.rs
    compare.rs
    report.rs
examples/mac-compare/
  Cargo.toml
  src/lib.rs
  cases.json
tests/
  fixtures/
  integration.rs
docs/
  MILESTONE-01.md
  methodology.md
  limitations.md
.github/workflows/ci.yml
```

This is a target layout, not a mandate to add empty files or to introduce premature backend abstractions.

## Implementation work packages

### PR 1 — Example, build toolchain, and WABT feasibility

**Deliverables**

- Organize a Cargo workspace, retaining the original demonstration or clearly documenting its replacement.
- Implement `examples/mac-compare` with early-exit and `subtle` comparison functions plus thin WASM exports.
- Add fixtures for fixed public tag and several synthetic secret expected tags.
- Pin Rust and WABT versions, lock dependencies, and build the example as optimized WASM.
- Demonstrate typed runtime arguments and trace capture for a named export.
- Inspect optimized WASM to establish that the vulnerable example has the intended variable path and the comparator based on `subtle` is a meaningful negative control.

**Feasibility gate:** prove that the pinned WABT trace contains stable **executed instruction locations**. If not, document the blocker and select a trace mode or alternative backend before implementing the comparator.

**Acceptance:** both implementations agree on all functional results, and the target artifact produces a parseable execution trace for each fixture without compiling secret constants into the module.

### PR 2 — Bounded, repeatable execution and trace capture

**Deliverables**

- Implement host-side WABT process invocation and typed argument encoding.
- Capture output, return codes, version metadata, and execution failures.
- Enforce timeout and maximum trace-output size.
- Check deterministic normalized traces for repeated identical cases.
- Make saving raw trace files an explicit debugging option, not the default.

**Acceptance:** all fixtures can be executed repeatedly; missing tools, unknown exports, malformed inputs, traps, and incomplete output are reliably reported as failures.

### PR 3 — Typed parser, normalization, and differential analyzer

**Deliverables**

- Parse the pinned WABT format into ordered instruction events.
- Normalize away textual presentation and operand values but not instruction identity or ordering.
- Detect sequence divergence and report the first divergent event and contextual events.
- Return `INCONCLUSIVE` for unsupported/malformed/truncated/unstable traces.
- Add small, checked-in fixture traces and comprehensive parser/comparator unit tests.

**Acceptance:** early-versus-late mismatch is detected in the vulnerable comparator; same-case traces compare equal; operand differences do not masquerade as execution-path differences; different instruction sites with identical opcodes are not considered equal.

### PR 4 — CLI and diagnostic reporting

**Deliverables**

- Provide `trace-check demo mac-compare` as the main entry point.
- Print a short explanatory summary with control-flow classification and divergence context.
- Emit machine-readable, versioned JSON with module hash and toolchain metadata.
- Make demo-level success contingent on both comparison variants exhibiting the expected control behavior.

**Acceptance:** a reader can build, run, inspect, and understand the experiment with one documented command and no manual comparison of giant text logs.

### PR 5 — Tests, CI, and educational documentation

**Deliverables**

- Linux GitHub Actions job with pinned Rust and WABT versions.
- Unit tests for parser/comparator; verifier functional tests; end-to-end demonstration tests.
- README quickstart and walkthrough explaining the problem and observations.
- `docs/methodology.md` describing threat model, public/secret inputs, WASM code inspection, and execution-path equivalence.
- `docs/limitations.md` distinguishing observed traces from claims about native code or physical side channels.
- `.gitignore` rules for generated trace output and a policy to check in only compact synthetic fixtures.

**Acceptance:** a clean CI job reproduces the expected controls and all tests pass.

## Verification matrix

| Test | Expected outcome |
| --- | --- |
| Same export with identical input, run twice | Equivalent normalized traces |
| Early-exit implementation, mismatch at byte 0 vs 31 | `DIFFERENCE_DETECTED` |
| Early-exit, mismatches at bytes 8, 16, and 24 | Differences consistent with early exit |
| `subtle` implementation, mismatch at byte 0 vs 31 | `NO_DIFFERENCE_OBSERVED` |
| Both implementations, exactly matching tags | Accept |
| Both implementations, any mismatching tag | Reject |
| Same instruction sites, different operand text in raw trace | Equal **control-flow** paths |
| Different instruction sites sharing the same opcode names | Difference detected |
| Truncated, malformed, or unrecognized trace | `INCONCLUSIVE` / explicit error |
| Timeout, trap, missing backend, bad export | Explicit failure; never a false pass |
| Complete demonstration in pinned Linux CI | Expected controls reproduced |

Always assert the **return values** alongside trace behavior. In particular, the two vulnerability demonstration cases must both reject.

## Definition of done

- [ ] A clean, documented Linux environment runs the complete demonstration with one command.
- [ ] The example has runtime-provided inputs and a pinned, release-mode WASM build.
- [ ] The vulnerable comparator demonstrably produces different executed instruction paths for early versus late mismatch.
- [ ] The `subtle` comparator has no observed instruction-path difference for the chosen negative-control cases.
- [ ] The parser and normalization logic are typed, deterministic, and unit-tested.
- [ ] Diagnostics identify the first divergence and surrounding instructions.
- [ ] Results distinguish difference, no observed difference, and inconclusive cases.
- [ ] Reports record compiler/interpreter versions and compiled-artifact hash.
- [ ] CI reproduces the end-to-end experiment.
- [ ] The README, methodology, and limitations documents make appropriately bounded security claims.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Rust optimizes away the early-exit branch | Inspect optimized WASM in PR 1; do not claim a vulnerability without observed divergence |
| `subtle` compiles unexpectedly on the selected target | Investigate the artifact and report the actual result, never special-case the expected outcome |
| WABT output lacks stable locations or changes across versions | Conduct a feasibility spike; pin WABT and add parser fixtures |
| Analyzer detects input-value differences, not execution paths | Separate operand values from execution-event identity and preserve ordered instruction sites |
| Runtime/startup noise obscures comparisons | Invoke a named export directly and validate same-case determinism first |
| Raw traces are huge or reveal test inputs | Use synthetic secrets, bounds, opt-in capture, and ignore generated logs |
| Users confuse “no difference observed” with proof of security | Explicit outcome terminology and separate limitations documentation |

## Non-goals

Defer until later milestones:

- Native Valgrind and hardware-level instrumentation.
- Full analysis of secret-dependent effective memory addresses or cache-line accesses.
- Statistical timing measurement, speculative execution, cache/power/EM effects.
- Generic secret-taint analysis and automatic detection of secret input regions.
- Arbitrary Rust crate instrumentation and full cryptographic protocol integrations.
- A web interface or elaborate backend/plugin framework.
- General-purpose constant-time certification.

## Follow-on milestones

- **M2 — Memory-access side channels:** introduce a secret-indexed table lookup that preserves the same instruction path but varies effective memory addresses; extend the trace model accordingly.
- **M3 — Native machine-code analysis:** add native instrumentation, normalize native locations, and investigate the relationship between interpreter-level findings, optimizing compilers, and hardware behavior.

## Security interpretation

A reproducible difference in executed instruction sequences while varying a secret input and holding public inputs constant is evidence of secret-dependent program behavior. It may indicate a timing side channel, but trace differences do not establish the size or exploitability of a timing signal.

Conversely, identical observed instruction sequences for a finite set of inputs do **not** establish constant-time security. M1 analyzes the behavior of a particular **compiled WASM module**, interpreter, and set of test vectors. It cannot certify equivalent behavior in a separately compiled native executable or on physical hardware.

This boundary is central to the project and must be explicit in the CLI, JSON reports, and documentation.

## References

- [WebAssembly Binary Toolkit (WABT)](https://github.com/WebAssembly/wabt) — interpreter and tracing tools.
- [WABT interpreter CLI](https://github.com/WebAssembly/wabt/blob/main/src/tools/wasm-interp.cc) — `--trace`, `--run-export`, and `--argument` handling.
- [Rust `subtle` crate](https://docs.rs/subtle/latest/subtle/) — constant-time-oriented comparison primitives and their compiler/platform caveats.

## Implementation status

Delivered. `cargo run -p trace-check -- demo mac-compare` builds the example,
runs every variant and case, and reproduces all eight declared expectations.
Where the implementation differs from the plan above, this is what changed and
why.

### The feasibility gate passed, with one prediction invalidated

WABT 1.0.42's `--trace` emits stable executed instruction locations in the form
`#<call_depth>. <istream_offset>: V:<stack> | <opcode> <operands>`, followed by
a result line `export(args) => i32:V`. Call depth and instruction-stream offset
became the comparison key; operands and value-stack depth are discarded.

The plan's **expected observation** for the vulnerable comparator did not hold.
At `opt-level = 3`, `verify_early_exit` is vectorized into a branchless
`i64.xor`/`i64.or` tree with a final `i64.eqz` — no branch survives, and its
normalized path is identical for early and late mismatch. Per the plan's own
Risk 1 mitigation, the artifact was inspected and the actual result reported
rather than the expectation hard-coded.

A third variant, `early_exit_opaque`, was therefore added: the same loop with
per-byte `read_volatile` loads, which the vectorizer cannot coalesce. It retains
the secret-dependent branch and is what demonstrates the vulnerability, with
executed work growing 6 instructions per compared byte (104 / 152 / 200 / 248 /
289 events for mismatches at bytes 0 / 8 / 16 / 24 / 31). The naive variant is
kept deliberately: the fixture declares `NO_DIFFERENCE_OBSERVED` for it, which
records the compiler erasure as a finding.

`subtle::ConstantTimeEq` behaved as predicted — a flat 1138 events regardless of
mismatch position — and is a working negative control.

### Other deviations from the plan

* **Tests live in `crates/trace-check/tests/`**, not a workspace-root `tests/`,
  because integration tests belong to the crate under Cargo's layout.
* **Six cases, not five.** A `MATCH` case was added so the accept decision is
  exercised for every variant, per the verification matrix row "Both
  implementations, exactly matching tags".
* **An extra `capture` subcommand** writes a single raw trace. The plan called
  for opt-in raw capture; a subcommand was the simplest way to expose it, and it
  is also how the checked-in parser fixtures were produced.
* **`examples/mac-compare` is a dual-target crate** (`cdylib` + `rlib`). The
  `rlib` lets the host test suite verify that all three verifiers agree on every
  authentication decision without involving the interpreter.
* **An empty-output guard was added** beyond the planned failure modes. WABT
  1.0.42 exits 0 and prints nothing for an unknown export, which would otherwise
  have read as an equivalent trace — a false pass.

### Definition of done

All items are met, with one clarification: "the vulnerable comparator
demonstrably produces different executed instruction paths" is satisfied by
`early_exit_opaque`. The naive `early_exit` comparator provably does *not*, and
reporting that is part of the result.
