# Milestone 02 — Native Rust secret-dependency analysis

**Status:** Implemented — see [Implementation status](#implementation-status)
**Backend:** native x86-64, Valgrind Memcheck undefined-value tracking
**New capability:** detection of secret-dependent **memory addressing**, which
instruction-path comparison cannot see

## Long-term vision

`trace-check` is becoming a **Rust-native constant-time verification and
regression-testing framework**. The goal is that a developer can declare that a
function must execute in constant time with respect to designated secret
parameters, and have automated tests detect violations — an experience close to
`cargo test`, but for a security property rather than functional correctness.

### The property

For a function with public inputs `p` and secret inputs `s`, and an observable
execution trace `L(f, p, s)`, we want the noninterference property

```
∀ p, s₁, s₂ :  L(f, p, s₁) = L(f, p, s₂)
```

What belongs in `L` depends on the backend, and grows over the roadmap:

* control flow — conditional branches and iteration counts
* memory-access patterns — secret-dependent addresses and table lookups
* eventually, machine-specific timing effects where practical

### Testing is not proof

Three distinct strengths of evidence are in play, and the project should never
blur them:

| Technique | What it establishes |
| --- | --- |
| Differential execution tracing (M1) | Two *specific* inputs produced different observable behavior. Cannot generalize to untested inputs. |
| Dynamic secret-dependency tracking (M2) | On the *executed path*, a secret-derived value reached a branch or an address. Finds violations without needing a second input, but only on paths the test reaches. |
| Static analysis / symbolic execution (M4) | Properties over *all* inputs, under an explicitly stated model. |

The long-term architecture should let these techniques implement the same
security contract while reporting evidence of different kinds. Forcing them into
one low-level event structure would be a mistake: a WASM instruction offset and
a Memcheck undefined-value diagnostic are not the same kind of fact.

### Roadmap

| Milestone | Scope | State |
| --- | --- | --- |
| **M1** | Differential execution tracing (WASM, WABT) | Complete |
| **M2** | Native secret-dependency analysis (Valgrind Memcheck) | This milestone |
| **M3** | Rust developer API — annotations, assertions, discovery, CI | Next |
| **M4** | Symbolic verification — no concrete vectors, counterexamples | Future |
| **M5** | Hardware-oriented validation — statistical timing, µarch leakage | Future |

Directional, not binding. Revise it when implementation experience justifies it.

## Why M2: the gap M1 cannot close

M1 analyzes **instruction-path equivalence**. That is genuinely useful, and it
has a blind spot that matters for real cryptography:

```rust
fn lookup(secret: u8, table: &[u8; 256]) -> u8 {
    table[secret as usize]
}
```

Compiled at `-O3` for x86-64 this is:

```asm
movzbl %sil, %eax            ; zero-extend the secret
movzbl (%rdi,%rax,1), %eax   ; load from a secret-dependent address
ret
```

Every secret value executes **the same three instructions in the same order**.
The instruction path is identical; only the effective address differs. M1's
comparator correctly reports `NO_DIFFERENCE_OBSERVED`, and it is right to —
the property it checks does hold. The vulnerability is simply outside that
property. This is the AES S-box leakage class, and it is not a toy concern.

M1's static Tier 1 taint pass can flag such an address *structurally*, but
nothing in M1 observes it in a real execution of native code.

## Security model

### Threat model

Unchanged in shape from M1, moved to native code. An attacker calls the
function repeatedly with inputs of their choosing and observes how much work it
performs, or which memory it touches. They cannot read memory directly.

* **Public input** — attacker-chosen, held fixed within a comparison.
* **Secret input** — the value whose influence we are testing.
* **Observable** — on this backend: whether a secret-derived value reaches a
  conditional branch or a memory address, on the executed path.

### How Memcheck is repurposed

Memcheck tracks, per bit, whether a value is *defined*. It reports when an
undefined value influences program behaviour — specifically at conditional
jumps, memory addresses, and syscall arguments. That is almost exactly the
leakage question, with "undefined" standing in for "secret".

The technique (ctgrind, Timecop):

1. Initialize the secret normally — the real bytes stay in memory.
2. `VALGRIND_MAKE_MEM_UNDEFINED(ptr, len)` marks its **shadow state** as
   undefined. Nothing is erased; only Memcheck's bookkeeping changes.
3. Execute the function under test. Memcheck propagates undefinedness through
   arithmetic, copies, registers and spills for free.
4. Any `UninitCondition` or `UninitValue` diagnostic whose stack reaches the
   function under test is a secret-dependency finding.
5. `VALGRIND_MAKE_MEM_DEFINED(ptr, len)` declassifies outputs and retained
   buffers before ordinary assertions, printing or cleanup.

Step 5 is not optional hygiene — it is the difference between a usable tool and
a noise generator. See [Declassification](#declassification-is-load-bearing).

### What a result means

| Outcome | Meaning |
| --- | --- |
| `LEAK_DETECTED` | A secret-derived value reached a branch or an address on the executed path. |
| `NO_LEAK_OBSERVED` | No such diagnostic **on the paths these inputs executed**. Not proof. |
| `INCONCLUSIVE` | Instrumentation inactive, Valgrind missing, unparseable output, timeout, or findings that could not be attributed. |

Harness failure (build error, missing tool, crash) is reported distinctly from
a successful analysis that found nothing.

## Feasibility gate (required, passed)

Run before building any runner. Native binaries at `opt-level = 3` with debug
symbols, Valgrind 3.28.0, `x86_64-unknown-linux-gnu`:

| Case | Memcheck findings | Attribution | Verdict |
| --- | --- | --- | --- |
| naive early-exit comparison | **0** | — | correct: see below |
| early-exit with volatile loads | **31** `UninitCondition` | `verify_early_exit_opaque` | leak detected |
| `subtle::ConstantTimeEq` | 0 | — | clean |
| secret-indexed table lookup | **1** `UninitValue` | `lookup_secret_index` | leak detected |
| constant-time table scan | 0 | — | clean |
| vulnerable call, secret **not** marked | 0 | — | instrumentation control holds |

Two findings from the spike are load-bearing for the design.

### M1's compiler erasure reproduces natively

The naive early-exit loop at `-O3` on x86-64 is **fully branchless SIMD**:

```asm
movdqu (%rdi),%xmm0 ; movdqu 0x10(%rdi),%xmm1
movdqu (%rsi),%xmm2 ; pcmpeqb %xmm0,%xmm2
movdqu 0x10(%rsi),%xmm0 ; pcmpeqb %xmm1,%xmm0
pand %xmm2,%xmm0 ; pmovmskb %xmm0,%eax
cmp $0xffff,%eax ; sete %al ; ret
```

No `jne`, no early exit. LLVM vectorized the 32-byte comparison into two 16-byte
`pcmpeqb` compares and a single test. Memcheck reported nothing because **there
is no secret-dependent branch to report**. The same erasure M1 found in WASM
happens independently in native code, by a different mechanism (SIMD
vectorization rather than an XOR/OR tree).

So the native example set needs the same treatment as M1: a variant whose
per-byte loads are opaque to the vectorizer carries the demonstration, and the
naive variant is kept to record the erasure. Its 31 findings match M1's 31
`br_if` exactly — one per compared byte, the last needing no branch.

### Declassification is load-bearing

The first spike marked the secret but not the returned `bool`. Memcheck then
reported two findings — both inside `core::fmt` formatting the secret-derived
result for `println!`, attributed to `num.rs:236`. Entirely spurious, and they
would have been reported as leaks in the function under test by a naive
implementation.

This drives two requirements: results must be explicitly declassified before
ordinary use, and findings must be **attributed** to the function under test
rather than counted.

## Architecture

M2 extends the existing structure rather than paralleling it.

```text
crates/trace-check-secret/     NEW: runtime secret-marking library
  csrc/shim.c                  minimal C shim over Valgrind client requests
  build.rs                     Valgrind header discovery
  src/lib.rs                   Secret<T> RAII guard, declassify, run-mode query

crates/trace-check/src/
  security.rs                  NEW: outcome vocabulary shared by both backends
  memcheck.rs                  NEW: Valgrind XML parsing and classification
  native.rs                    NEW: native build + bounded Memcheck execution
  runner.rs                    M1: WASM build + bounded wasm-interp execution
  parser.rs compare.rs         M1: trace grammar and differential analysis
  taint.rs census.rs screen.rs M1: static screening
  report.rs                    extended: shared metadata, per-backend evidence

examples/mac-compare/          extended with a native harness binary
examples/table-lookup/         NEW: the address-leak example
```

### Why a C shim rather than Rust assembly

Valgrind's client-request protocol is a platform-specific inline-assembly
sequence. Hand-writing it in Rust per architecture would be the wrong kind of
unsafe code. `csrc/shim.c` includes `<valgrind/memcheck.h>` and lets Valgrind's
own header emit the protocol, so correctness is Valgrind's problem, not ours.

`crabgrind` was evaluated first, as the established maintained binding. Its only
functional mode requires `bindgen`, hence `libclang`, as a build dependency for
every consumer. For three tiny functions that is a poor trade, so M2 uses the
shim route the milestone brief sanctions as the alternative. If crabgrind gains
pregenerated bindings, switching is a contained change.

Header discovery order: `VALGRIND_INCLUDE` env var → `pkg-config valgrind` →
the prefix of the `valgrind` binary on `PATH` → `/usr/include`. A clear build
error when none is found, never a silent no-op build.

### Instrumentation must survive optimization

The marking must demonstrably affect the values the compiled code consumes.
Hazards, and how M2 addresses them:

| Hazard | Mitigation |
| --- | --- |
| Secret copied before marking takes effect | `Secret<T>` borrows stable storage and marks in place; the guard's lifetime covers the call |
| Secret promoted to a register and never re-read from memory | Memcheck shadows registers too, so propagation follows |
| Function inlined and specialized away | `#[inline(never)]` on functions under test; `black_box` on arguments and results |
| Constant folding of a known secret | secrets are read through `black_box` so the compiler cannot see their values |
| Instrumentation silently inactive | `running_under_memcheck()` is checked and reported; the backend treats inactive instrumentation as `INCONCLUSIVE`, never as a pass |
| Marking itself broken | an unmarked-secret control case must produce **no** findings, and a marked known-vulnerable case must produce findings; both are regression tests |

### Attribution

A Memcheck error carries a full stack. A finding is attributed to the function
under test when a frame naming it appears within a bounded prefix of the stack.
Findings that are `UninitCondition`/`UninitValue` but attributable only to
runtime or formatting frames are retained as diagnostics and make the result
`INCONCLUSIVE` rather than being silently dropped or counted as leaks.

Memcheck kinds map as:

| Kind | Classification |
| --- | --- |
| `UninitCondition` | secret-dependent **branch** |
| `UninitValue` | secret-dependent **value use** — typically an address |
| `InvalidRead`, `InvalidWrite`, `InvalidFree`, `Leak_*`, `SyscallParam`, … | genuine memory error — **not** a timing leak |

A genuine memory error is reported as a memory error and makes the run
`INCONCLUSIVE`. Mislabelling one as a timing leak would be worse than missing it.

## Example programs

| Example | Variant | Expected native outcome |
| --- | --- | --- |
| mac-compare | `early_exit` (naive) | `NO_LEAK_OBSERVED` — branch erased by vectorization |
| mac-compare | `early_exit_opaque` | `LEAK_DETECTED` — secret-dependent branch |
| mac-compare | `constant_time` (`subtle`) | `NO_LEAK_OBSERVED` |
| table-lookup | `secret_index` | `LEAK_DETECTED` — secret-dependent **address** |
| table-lookup | `constant_time_scan` | `NO_LEAK_OBSERVED` |
| arithmetic | `permitted_arithmetic` | `NO_LEAK_OBSERVED` — secret used only in arithmetic |
| declassify | `declassified_output` | `NO_LEAK_OBSERVED` — no spurious finding |
| controls | `unmarked_secret` | `NO_LEAK_OBSERVED` — instrumentation control |
| controls | `genuine_memory_error` | `INCONCLUSIVE` — memory error, not a leak |

As in M1, every expectation lives in a fixture, not in code, so a compiler
change that invalidates a prediction surfaces as an unmet expectation.

Both mac-compare comparisons must return the **same** authentication decision,
so a finding cannot be confounded with accept-versus-reject.

## Work packages

* **PR 1 — secret-marking library.** The shim, header discovery, `Secret<T>`
  guard, run-mode detection, unit tests. Feasibility gate recorded.
* **PR 2 — native backend.** Build, bounded Memcheck execution, XML parsing,
  classification, attribution, provenance capture.
* **PR 3 — examples and manifest.** The table-lookup example, native harnesses,
  the native case manifest with declared expectations.
* **PR 4 — CLI, reporting, CI, docs.** `trace-check native`, text and JSON
  output, CI with pinned Valgrind, documentation.

## Test strategy

Red-green throughout. Fast tests stay separate from instrumented tests, which
are slower and need Valgrind.

| Test | Expected |
| --- | --- |
| Secret-dependent early-exit comparison | leak detected |
| `subtle`-based comparison | no leak observed |
| Secret-indexed table lookup | leak detected |
| Constant-time table selection | no leak observed |
| Secret used only in permitted arithmetic | no leak observed |
| Secret-derived return, declassified after analysis | no spurious leak |
| Missing Valgrind | explicit failure / inconclusive |
| Broken secret marking | known-vulnerable control fails |
| Malformed Memcheck output | inconclusive / error |
| Genuine unrelated memory error | reported as a memory error, not a leak |

Backend-dependent tests skip when Valgrind is absent so the fast suite runs on
a bare machine, but `TRACE_CHECK_REQUIRE_BACKEND=1` — which CI sets — makes a
missing backend a failure. A skipped backend must never read as a pass.

Examples are compiled with production-like optimization (`opt-level = 3`) plus
debug symbols, because source locations are what make a finding actionable.

## Acceptance criteria and definition of done

- [ ] One command compiles a native example, marks its secrets, runs it under
      Memcheck, and reports secret-dependent control flow or addressing.
- [ ] The early-exit comparison **and** the secret-indexed lookup are both
      detected; the corresponding constant-time implementations are accepted for
      the tested cases.
- [ ] The address leak is detected by M2 and demonstrably invisible to M1's
      instruction-path comparison, documented side by side.
- [ ] Findings carry source location and stack context.
- [ ] Human-readable and machine-readable output, both versioned.
- [ ] Memcheck findings are distinguished from ordinary process failures and
      from genuine memory errors.
- [ ] Missing Valgrind, inactive instrumentation, malformed output and timeouts
      are explicit failures, never silent passes.
- [ ] Provenance recorded: compiler, profile, target triple, Valgrind version,
      binary hash.
- [ ] M1's WASM backend and static screen remain fully functional.
- [ ] Linux CI installs a pinned Valgrind and reproduces every expectation.
- [ ] Documentation states supported platforms, assumptions and limitations.

## Known limitations

* **Memcheck does not model timing.** It models *definedness influence*.
  Secret-dependent operand latency (variable-time multiply, division),
  cache-line and set-associativity effects, branch-predictor state, speculation
  and prefetching are all outside the guarantee.
* **Path-limited.** Findings exist only for paths the test inputs execute.
  `NO_LEAK_OBSERVED` is not proof of constant-time behavior, and never a claim
  about untested inputs.
* **Granularity.** Memcheck reports that an address *depended on* a secret, not
  which cache line or how much entropy leaks.
* **One platform, one artifact.** Linux x86-64 and the specific binary built
  here. Different compiler versions, targets or flags need re-establishing —
  the naive early-exit erasure is exactly that lesson.
* **Declassification is manual and trusted.** A wrongly placed
  `MAKE_MEM_DEFINED` silently suppresses real findings. Declassification sites
  are deliberately few and explicit.
* **Attribution is heuristic.** It matches stack frames by function name within
  a bounded prefix. Aggressive inlining can blur which function owns a finding.
* **Memcheck slows execution by roughly an order of magnitude**, which is why
  instrumented tests are separated from the fast suite.

## Output completeness

A truncated Memcheck report must never read as a clean result. Four
independent checks run before any parsed content is trusted:

1. the XML is syntactically valid and every element is closed, with the
   `<valgrindoutput>` root closed at depth zero,
2. `<protocolversion>` is present and known,
3. `<tool>` is `memcheck` — other Valgrind tools use error kinds this
   classifier does not model,
4. a terminal `<status><state>FINISHED</state>` was seen.

The `FINISHED` marker is the strongest of the four. Balanced tags only prove
the bytes received were well-formed; `FINISHED` proves Valgrind ran to
completion and wrote its whole report. A run killed by the timeout, a Valgrind
crash, or output read mid-write all fail this check and become `INCONCLUSIVE`.

Any failure is a parse error, which the backend maps to `INCONCLUSIVE` — never
to a shorter error list and never to `NO_LEAK_OBSERVED`. An end-to-end test
captures real Memcheck output and asserts that **no strict prefix of it
parses**.

## Implications for the eventual Rust annotation API

M2 deliberately builds the primitives an M3 macro would need, without building
the macro. The seams:

* **Declaring the target** — a case manifest names an executable, a case id and
  the function under test. A macro would generate the same description.
* **Identifying public and secret inputs** — `Secret<T>` marks a borrow of
  stable storage for a scope. `#[constant_time(secret = "key")]` would expand to
  exactly this guard around the call.
* **Selecting a backend** — the outcome vocabulary in `security.rs` is shared;
  evidence types stay backend-specific.
* **Running and returning structured findings** — the backend returns typed
  findings with attribution, not formatted text.
* **Converting to pass/fail** — the declared expectation lives in the fixture,
  and the CLI maps outcome-versus-expectation to an exit code. An
  `assert_constant_time!` macro would call the same comparison.

What M2 does **not** build, by instruction: procedural macros, automatic test
generation, annotation discovery, a general annotation language, SMT or symbolic
execution, native instruction-by-instruction tracing, key management.

## Implementation status

Delivered. `cargo run -p trace-check -- native` builds nine harness cases, runs
each under Memcheck, and reproduces every declared expectation. Both required
detections work: the early-exit comparison **and** the secret-indexed memory
access, with the constant-time implementations accepted for the tested cases.

### Observed results

| Case | Outcome | Evidence |
| --- | --- | --- |
| `mac-early-exit` | `NO_LEAK_OBSERVED` | branch erased by SIMD vectorization |
| `mac-early-exit-opaque` | `LEAK_DETECTED` | 31 `UninitCondition`, matching M1's 31 `br_if` |
| `mac-constant-time` | `NO_LEAK_OBSERVED` | — |
| `table-secret-index` | `LEAK_DETECTED` | 1 `UninitValue` at `lib.rs:47` |
| `table-constant-time-scan` | `NO_LEAK_OBSERVED` | — |
| `permitted-arithmetic` | `NO_LEAK_OBSERVED` | secrecy through arithmetic is permitted |
| `declassified-output` | `NO_LEAK_OBSERVED` | declassification verified, no spurious finding |
| `control-unmarked-secret` | `NO_LEAK_OBSERVED` | instrumentation control holds |
| `control-memory-error` | `INCONCLUSIVE` | `InvalidRead` classified as a memory error |

153 tests pass; M1's `demo` and `screen` both still exit 0, and the traced WASM
artifact's SHA-256 is unchanged.

### Deviations from the plan

* **`crabgrind` was not used.** Its only functional mode requires `bindgen`,
  hence `libclang`, as a build dependency for every consumer. For three
  functions that is a poor trade, so M2 uses the C shim the brief sanctions as
  the alternative. Valgrind's own header emits the client-request assembly.
* **Missing Valgrind headers degrade rather than fail the build.** The crate
  compiles without the shim and `run_mode()` reports `Unsupported`, which the
  backend treats as inconclusive. This keeps the fast suite buildable on a
  machine with no Valgrind while remaining incapable of a silent pass.
* **Harness binaries are feature-gated.** Without this, building `mac-compare`
  for `wasm32-unknown-unknown` would try to compile a `main` under `no_std` and
  break M1. The gating also keeps `cargo build --workspace` independent of
  Valgrind. M1's artifact hash is verified unchanged.
* **A `memcheck` build profile was added** rather than reusing `release`:
  symbols are required for actionable findings, and the native harnesses need
  `panic = "unwind"`.
* **Nine cases, not the eight listed above**, after splitting the
  declassification control from the permitted-arithmetic control.

### Correction after review (PR #2)

**Truncated XML could be accepted as a clean result.** The parser stopped at
`Event::Eof` without checking that the document was closed. A document cut at a
clean element boundary — `<valgrindoutput><protocolversion>6</protocolversion>`
— satisfied the root and protocol checks, parsed to zero errors, and would have
been classified `NO_LEAK_OBSERVED` by the backend. The existing truncation test
gave false confidence because it cut mid-tag, which quick-xml rejects for
unrelated syntactic reasons.

Fixed by the four completeness checks above. See
[Output completeness](#output-completeness).

### Corrections made during implementation

Three predictions in the plan were wrong and were corrected against observed
behavior rather than worked around.

* **Valgrind's XML protocol version is 6, not 4.** The parser initially pinned
  4 from older documentation, so every case came back `INCONCLUSIVE` with
  "protocol version 6 is not supported". The guard behaved exactly as intended
  — an unrecognized format produced no verdict instead of a silent pass — and
  the fix was to accept the versions whose consumed subset is stable (4, 5, 6)
  and refuse anything else.
* **The memory-error control needed two rewrites.** Reading past a small `Vec`
  landed inside another live allocation, so Memcheck reported nothing. A plain
  dereference after `drop` is undefined behaviour, so LLVM elided the load
  entirely and the access never happened. A `read_volatile` of an explicitly
  `dealloc`-ed block is deterministic: volatile cannot be elided, and Memcheck
  quarantines freed blocks.
* **A concurrency bug was found by the test suite.** The Memcheck XML scratch
  directory was keyed on `(pid, case id)`, so two parallel analyses of the same
  case deleted each other's output. Now keyed on an additional per-invocation
  counter. This mattered beyond the tests: a future parallel `cargo test`
  integration would have hit it.

### What M2 did not build, by instruction

Procedural macros, automatic test generation, annotation discovery, a general
annotation language, SMT or symbolic execution, native instruction-by-instruction
tracing, and key management are all out of scope and absent.
