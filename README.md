# trace-check — constant-time verification and regression testing for Rust

A timing side channel exists when the work a program does depends on a secret.
The classic example is an authentication-tag comparison that stops at the first
differing byte: how long it runs tells an attacker how much of their guess was
correct.

**Where this is going.** The goal is a framework where a Rust developer can
declare that a function must execute in constant time with respect to designated
secret parameters, and have automated tests detect violations — an experience
close to `cargo test`, but for a security property rather than functional
correctness. See [docs/MILESTONE-02.md](docs/MILESTONE-02.md) for the vision,
the formal noninterference property, and the roadmap.

| Milestone | Scope | State |
| --- | --- | --- |
| M1 | Differential execution tracing (WASM, WABT) | complete |
| M2 | Native secret-dependency analysis (Valgrind Memcheck) | complete |
| M3 | Rust developer API — annotations, assertions, CI | next |
| M4 | Symbolic verification — no concrete vectors | future |
| M5 | Hardware-oriented validation — statistical timing | future |

`trace-check` turns that idea into reproducible analysis, from three directions:

* **Native secret-dependency analysis** (`native`) — mark a secret's shadow
  state as undefined, run under Valgrind Memcheck, and let it report wherever a
  secret-derived value reaches a conditional branch **or a memory address**.
  This is the only backend that sees secret-dependent *addressing*.

* **Statically** (`screen`) — parse the compiled WASM, count the control-flow
  shapes of each screened function against a committed baseline, and track
  which values derive from the secret to see whether any of them reaches a
  branch, a memory address, or an indirect call target.
* **Dynamically** (`demo`) — run the module under WABT's interpreter with
  paired inputs that differ **only** in a modeled secret, reduce each raw trace
  to an ordered sequence of executed instruction locations, and report where the
  two paths diverge.

```sh
cargo run -p trace-check -- native               # native, under Memcheck
cargo run -p trace-check -- screen mac-compare   # static, no execution
cargo run -p trace-check -- demo mac-compare     # dynamic WASM tracing
```

These are deliberately complementary. The static screen quantifies over *all*
inputs but over-approximates, so it can report candidates that are not real.
Differential tracing is exact for the inputs it runs but says nothing about the
inputs it did not. The `subtle` control in the bundled example shows why you
want both: its census contains a branch and a loop, yet no branch condition
derives from the secret — a census alone would read that as a finding.

## What it actually shows — and what it does not

The property analyzed is **instruction-path equivalence**: whether two runs
execute the same ordered sequence of instruction locations. That is a real,
checkable property, and it is much narrower than "constant time".

Results are reported as one of three outcomes:

| Outcome | Meaning |
| --- | --- |
| `DIFFERENCE_DETECTED` | The instruction path changed when only the secret changed. Evidence of secret-dependent behavior. |
| `NO_DIFFERENCE_OBSERVED` | Paths matched **for the tested inputs**. Not proof of constant-time security. |
| `INCONCLUSIVE` | Capture, parsing, nondeterminism, or a confounded decision prevented a trustworthy answer. |

The static screen reports per-function findings instead, of three kinds:
`secret_dependent_branch`, `secret_dependent_address` (an identical
instruction path whose memory access pattern still varies), and
`secret_dependent_call_target`. A `select` with a secret condition is reported
as informational, not a leak: it is branchless, which is the point.

See [docs/limitations.md](docs/limitations.md) for the full boundary, and
[docs/methodology.md](docs/methodology.md) for the threat model and procedure.

## Why three backends: the gap each one closes

```rust
fn lookup(secret: u8, table: &[u8; 256]) -> u8 {
    table[secret as usize]
}
```

At `-O3` on x86-64 this is three instructions — `movzbl %sil,%eax;
movzbl (%rdi,%rax,1),%eax; ret` — and **every secret value executes the same
three in the same order**. Only the effective address differs.

M1's comparator reports `NO_DIFFERENCE_OBSERVED` and is correct: the property it
checks genuinely holds. The vulnerability is outside that property. This is the
AES S-box leakage class, and M2 catches it:

```text
FAIL: table-secret-index

Backend: native-memcheck
Target:  x86_64-unknown-linux-gnu

Finding:
  Secret-dependent memory address or value use

Location:
  examples/table-lookup/src/lib.rs:47

Secret source:
  secret (parameter 1)

Result:
  LEAK_DETECTED
```

| Leak | M1 differential tracing | M1 static screen | M2 native Memcheck |
| --- | --- | --- | --- |
| secret-dependent branch | detected | flagged structurally | detected, with source location |
| secret-dependent address | **invisible** | flagged structurally | **detected** |
| quantified over all inputs | no | yes | no (executed paths only) |
| analyzes native code | no (WASM) | no (WASM) | yes |

## The example and its result

`examples/mac-compare` exports three verifiers that compare a 32-byte expected
tag (the modeled secret) against a fixed public supplied tag. All three agree on
every authentication decision, so a trace difference cannot be explained by one
of them accepting where another rejects.

| Variant | Implementation | Observed result |
| --- | --- | --- |
| `early_exit` | naive per-byte loop with `return false` | **no path difference** — LLVM vectorizes it into a branchless XOR/OR tree at `opt-level = 3` |
| `early_exit_opaque` | same loop, per-byte `read_volatile` loads | **path difference** — the branch survives; executed work grows by 6 instructions per compared byte |
| `constant_time` | `subtle::ConstantTimeEq` | **no path difference** — flat at 1138 events regardless of mismatch position |

Both analyses reach all three of those conclusions independently, which is the
strongest validation available here: the static screen finds exactly 31
secret-dependent branches in `early_exit_opaque` — one per compared byte, the
last needing none — matching the 6-instructions-per-byte growth measured
dynamically.

The `early_exit` row is the point of keeping it. A secret-dependent `if` in
Rust source is *not* evidence of a secret-dependent branch in the compiled
module, and the tool reports what the artifact does rather than what the source
suggests. Each expectation is declared in
[`examples/mac-compare/cases.json`](examples/mac-compare/cases.json), so a
compiler change that invalidates a prediction surfaces as an unmet expectation
instead of being silently absorbed.

Observed event counts for `early_exit_opaque`, by mismatch position:

| Mismatch at byte | 0 | 8 | 16 | 24 | 31 |
| --- | --- | --- | --- | --- | --- |
| Instructions executed | 104 | 152 | 200 | 248 | 289 |

## Prerequisites

* **Rust** — pinned by [`rust-toolchain.toml`](rust-toolchain.toml) (1.97.0 plus
  the `wasm32-unknown-unknown` target). `rustup` installs both automatically.
* **WABT 1.0.42** — the trace grammar and instruction offsets are specific to
  this release, so the version is checked at startup:

  ```sh
  curl -fsSLO https://github.com/WebAssembly/wabt/releases/download/1.0.42/wabt-1.0.42-linux-x64.tar.gz
  echo "84895407a6bbb80e918f33b16b2fb2206021c150b6bc9ff6f761263a745ab131  wabt-1.0.42-linux-x64.tar.gz" | sha256sum --check
  tar -xzf wabt-1.0.42-linux-x64.tar.gz -C ~/.local/share
  export PATH="$HOME/.local/share/wabt-1.0.42/bin:$PATH"
  ```

  Pass `--allow-wabt-version-mismatch` to run against another version; results
  are then not comparable to recorded ones.

## Commands

### `native` — secret-dependency analysis of native code

```sh
cargo run -p trace-check -- native
cargo run -p trace-check -- native --case table-secret-index
cargo run -p trace-check -- native --format json
```

Builds each harness with production-like optimization plus debug symbols, marks
the declared secret's shadow state as undefined, runs under Memcheck, and
classifies the diagnostics.

| Outcome | Meaning |
| --- | --- |
| `LEAK_DETECTED` | A secret-derived value reached a branch or an address on the executed path. |
| `NO_LEAK_OBSERVED` | No such diagnostic **for the paths these inputs executed**. Not proof. |
| `INCONCLUSIVE` | Instrumentation inactive, unparseable output, a genuine memory error, or an unattributable finding. |

Two rules keep a result trustworthy, and both are enforced rather than assumed:

* **Instrumentation must be confirmed active.** Outside Valgrind every client
  request is a no-op, so the harness reports its run mode and a clean
  uninstrumented run is `INCONCLUSIVE`, never a pass.
* **Not every Memcheck error is a leak.** `UninitCondition` and `UninitValue`
  are secret dependency *only when their origin is the client request that
  marked the secret* — Memcheck emits the same kinds for genuinely
  uninitialized memory, which is an ordinary bug. An `InvalidRead` is a memory
  bug and is reported as one. Anything else is retained and makes the run
  `INCONCLUSIVE`.
* **Attribution uses the primary stack.** An error also carries an origin
  stack naming where the value was created, which for a marked secret is the
  harness. Matching against it would blame the wrong function.

Cases live in [`examples/native-cases.json`](examples/native-cases.json) with
their expected outcomes, so a compiler change that invalidates a prediction
surfaces as an unmet expectation.

Requires **Valgrind** on Linux x86-64 (`apt-get install valgrind` or
`dnf install valgrind valgrind-devel`). Ubuntu's `valgrind` package also ships
the client-request headers the instrumentation shim needs at build time.

### `screen` — static screening and the regression gate

```sh
cargo run -p trace-check -- screen mac-compare
cargo run -p trace-check -- screen mac-compare --format json
cargo run -p trace-check -- screen mac-compare --module path/to/other.wasm
```

Runs both static tiers and needs no interpreter:

* **Tier 0 — structural census.** Counts branches, loops, `select`s, loads,
  stores and calls per screened function and compares them to
  `examples/mac-compare/artifact-baseline.json`. Census drift fails the gate;
  this is what catches a toolchain upgrade that if-converts a `select` back into
  a branch, the realistic way constant-time code decays. A module-hash change on
  its own is reported as a note, not a failure, since it changes on every
  compiler bump.
* **Tier 1 — taint analysis.** A forward abstract interpretation over the
  operand stack, locals and globals, flagging where a secret-derived value
  reaches a branch condition, a memory address, or an indirect call target.

The gate is active whenever the baseline file exists, so CI needs no extra flag.

| Option | Effect |
| --- | --- |
| `--update-baseline` | overwrite the baseline with the current census |
| `--no-baseline` | skip the comparison even if a baseline exists |
| `--baseline PATH` | use a different baseline file |
| `--module PATH` | screen a prebuilt module instead of building the example |

Which parameters are secret, and how secrets reach each function, are declared
in [`examples/mac-compare/screen.json`](examples/mac-compare/screen.json) —
nothing in a compiled module says which bytes are a key, and a screener that
guessed would quietly analyze the wrong thing. Three load policies are
available:

| Policy | Use when |
| --- | --- |
| `params` | secrets arrive as scalar values |
| `pointer-params` | a parameter points directly at secret bytes (`&[u8; 32]`) |
| `pointer-params-indirect` | a parameter points at a descriptor holding a data pointer and length (`&[u8]`); the first dereference is treated as public metadata |

### `demo` — build, run and compare an example end to end

```sh
cargo run -p trace-check -- demo mac-compare
cargo run -p trace-check -- demo mac-compare --format json > report.json
```

Builds the example as optimized WASM, executes every variant and case **twice**
to confirm the normalized trace is reproducible, checks every authentication
decision against the fixture, then runs the declared comparisons.

Options: `--format text|json`, `--workspace-root PATH`, `--timeout-secs N`,
`--max-output-bytes N`, `--allow-wabt-version-mismatch`.

### `compare` — analyze two stored traces

```sh
cargo run -p trace-check -- compare a.trace b.trace
```

Compares previously captured raw traces without rebuilding or rerunning.
Determinism cannot be established from stored files, so the output says so.

### `capture` — write one raw trace

```sh
cargo run -p trace-check -- capture mac-compare \
  --variant early_exit_opaque --case A --out byte0.trace
```

Opt-in debugging aid. Raw traces embed the case input values, including the
modeled secret, and are git-ignored except for the compact fixtures under
`crates/trace-check/tests/fixtures/`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | `demo`: every declared expectation reproduced. `screen`: every declaration held and the census did not drift. `compare`: `NO_DIFFERENCE_OBSERVED`. |
| `1` | `demo`: an expectation was not reproduced. `screen`: a finding, an unmet declaration, or baseline drift. `compare`: `DIFFERENCE_DETECTED`. |
| `2` | Error or `INCONCLUSIVE`: missing backend, build failure, timeout, trap, unparseable trace. |

A missing tool, a trap, a timeout, an oversized capture, an unknown export, a
truncated trace, or a wrong authentication decision is always an explicit
failure — never a silent pass.

## Repository layout

```text
Cargo.toml                       workspace and the pinned release profile
rust-toolchain.toml              pinned Rust channel and wasm32 target
crates/trace-check/
  src/main.rs                    CLI: native, screen, demo, compare, capture
  src/lib.rs                     end-to-end pipeline
  src/experiment.rs              cases.json loading and validation
  src/runner.rs                  WASM build, bounded wasm-interp execution
  src/parser.rs                  wasm-interp --trace grammar -> ExecutionEvent
  src/compare.rs                 differential analysis and outcomes
  src/report.rs                  text and versioned JSON reporting
  src/wasm.rs                    WASM binary -> modeled instruction subset
  src/census.rs                  Tier 0 census and baseline regression gate
  src/taint.rs                   Tier 1 secret-dependence abstract interpreter
  src/screen.rs                  screening orchestration and reporting
  src/security.rs                outcome vocabulary shared by all backends
  src/memcheck.rs                Valgrind XML parsing and classification
  src/native.rs                  native build + bounded Memcheck execution
  src/native_report.rs           native text and JSON reporting
crates/trace-check-secret/       secret marking for Memcheck (C shim)
  tests/integration.rs           fixture and end-to-end tests
  tests/fixtures/                compact captured traces
examples/mac-compare/            the example, its cases.json, screen.json
                                 and committed artifact-baseline.json
examples/table-lookup/           the secret-indexed address-leak example
examples/native-cases.json       native case manifest with expectations
examples/legacy-branch-demo/     original proof of concept, kept for context
docs/                            milestone plan, methodology, limitations
.github/workflows/ci.yml         pinned Linux CI
```

## Development

```sh
cargo test --workspace --lib --bins       # fast suite, no backends needed
cargo test --workspace                    # 153 tests; backend tests skip without WABT/Valgrind
TRACE_CHECK_REQUIRE_BACKEND=1 cargo test --workspace   # a missing backend fails instead
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all
```

`TRACE_CHECK_REQUIRE_BACKEND=1` is what CI sets, so a skipped backend can never
be mistaken for a pass. Some unit tests assemble inline `.wat` and therefore
need `wat2wasm`; the native tests need Valgrind. All follow the same
skip-or-require contract.

Memcheck costs roughly an order of magnitude in runtime, so the instrumented
tests live in their own integration target (`--test native`) and CI runs the
fast suite first.

### When the baseline legitimately changes

A toolchain bump that changes a screened function's compiled shape fails the
Tier 0 gate by design. Inspect the new artifact first — the point of the gate is
that this is where a constant-time regression would appear — and only then
refresh it:

```sh
cargo run -p trace-check -- screen mac-compare --update-baseline
```

### Supported platforms

| Backend | Platform |
| --- | --- |
| WASM tracing and static screen | any host; needs WABT 1.0.42 |
| Native Memcheck | Linux x86-64 only; needs Valgrind 3.x |

The native backend refuses to run on any other target rather than producing
a result that does not apply.

### Adding a screen target or a case

For the static screen, add a target to `examples/mac-compare/screen.json`
(function name, secret parameter indices, load policy, and whether it is
expected to be clean) and refresh the baseline.

For the dynamic experiment, edit `examples/mac-compare/cases.json`: add a case
(32-byte hex tag plus its expected decision) or a comparison (variant, two case
ids, expected outcome, and the reasoning). The fixture is validated before
anything is executed — unknown references, duplicate ids, self-comparisons and
malformed tags are rejected up front.

In both files the *expectation* lives in the fixture rather than in code, so a
compiler change that invalidates a prediction surfaces as an unmet expectation
instead of being silently absorbed.

### The legacy example

`examples/legacy-branch-demo` is the original single-branch program, kept as
historical context. It has no automated runner and is not part of the demo; the
multi-megabyte trace logs that accompanied it were removed from the working tree
(they remain in history at commit `2171580`) and generated traces are now
git-ignored.
