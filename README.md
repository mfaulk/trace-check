# trace-check — detecting secret-dependent execution paths with execution traces

A timing side channel exists when the work a program does depends on a secret.
The classic example is an authentication-tag comparison that stops at the first
differing byte: how long it runs tells an attacker how much of their guess was
correct.

`trace-check` turns that idea into a reproducible experiment. It builds a small
WebAssembly module, runs it under WABT's interpreter with paired inputs that
differ **only** in a modeled secret, reduces each raw trace to an ordered
sequence of executed instruction locations, and reports where the two paths
diverge.

One command runs the whole thing:

```sh
cargo run -p trace-check -- demo mac-compare
```

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

See [docs/limitations.md](docs/limitations.md) for the full boundary, and
[docs/methodology.md](docs/methodology.md) for the threat model and procedure.

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
| `0` | `demo`: every declared expectation reproduced. `compare`: `NO_DIFFERENCE_OBSERVED`. |
| `1` | `demo`: an expectation was not reproduced. `compare`: `DIFFERENCE_DETECTED`. |
| `2` | Error or `INCONCLUSIVE`: missing backend, build failure, timeout, trap, unparseable trace. |

A missing tool, a trap, a timeout, an oversized capture, an unknown export, a
truncated trace, or a wrong authentication decision is always an explicit
failure — never a silent pass.

## Repository layout

```text
Cargo.toml                       workspace and the pinned release profile
rust-toolchain.toml              pinned Rust channel and wasm32 target
crates/trace-check/
  src/main.rs                    CLI: demo, compare, capture
  src/lib.rs                     end-to-end pipeline
  src/experiment.rs              cases.json loading and validation
  src/runner.rs                  WASM build, bounded wasm-interp execution
  src/parser.rs                  wasm-interp --trace grammar -> ExecutionEvent
  src/compare.rs                 differential analysis and outcomes
  src/report.rs                  text and versioned JSON reporting
  tests/integration.rs           fixture and end-to-end tests
  tests/fixtures/                compact captured traces
examples/mac-compare/            the traced example and its cases.json
examples/legacy-branch-demo/     original proof of concept, kept for context
docs/                            milestone plan, methodology, limitations
.github/workflows/ci.yml         pinned Linux CI
```

## Development

```sh
cargo test --workspace                    # 54 tests; end-to-end tests skip without WABT
TRACE_CHECK_REQUIRE_BACKEND=1 cargo test --workspace   # a missing backend fails instead
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all
```

`TRACE_CHECK_REQUIRE_BACKEND=1` is what CI sets, so a skipped backend can never
be mistaken for a pass.

### Adding a case or comparison

Edit `examples/mac-compare/cases.json`: add a case (32-byte hex tag plus its
expected decision) or a comparison (variant, two case ids, expected outcome, and
the reasoning). The fixture is validated before anything is executed — unknown
references, duplicate ids, self-comparisons and malformed tags are rejected up
front.

### The legacy example

`examples/legacy-branch-demo` is the original single-branch program, kept as
historical context. It has no automated runner and is not part of the demo; the
multi-megabyte trace logs that accompanied it were removed from the working tree
(they remain in history at commit `2171580`) and generated traces are now
git-ignored.
