# Milestone 03 — Constant-time contracts and Cargo test integration

**Status:** Implemented — see [Implementation status](#implementation-status)
**Deliverable:** a Rust testing API and `cargo trace-check test`, not another backend
**Backend:** reuses M2's native Valgrind Memcheck analysis unchanged

## Objective and relationship to the vision

M1 and M2 built analysis infrastructure. Both are driven by JSON manifests and
purpose-built harness binaries that live inside this repository. Neither is
usable by a developer with their own crate.

M3 closes that gap. The target experience is an ordinary Rust test:

```rust
#[ct_test]
fn verify_tag_is_constant_time() {
    let supplied = [0u8; 32];
    let accepted = assert_constant_time!(
        secret = [0x42u8; 32],
        call = |expected| verify_tag(expected, &supplied),
    );
    assert!(!accepted);
}
```

run with one command:

```sh
cargo trace-check test
```

The guiding principle: **make constant-time checks feel like ordinary unit
tests, without giving up the fail-closed behavior security tooling requires.**

### Still not a proof

A passing `ct_test` means *no modeled secret-dependent behavior was observed on
the paths that test exercised*, in one optimized binary, on one platform. It is
not a proof of constant-time behavior for all inputs, and the API, reports and
documentation all say so. `Outcome::NoLeakObserved` keeps its M2 name for
exactly this reason.

## Feasibility gate (required, passed)

Validated before any implementation, against Valgrind 3.28.0 on
`x86_64-unknown-linux-gnu` with `opt-level = 3` plus debug symbols. Five
answers shaped the design, and two of them changed it.

| Question | Answer |
| --- | --- |
| Can test executables be located structurally? | Yes — `cargo test --profile memcheck --no-run --message-format=json` emits `compiler-artifact` messages with `executable` set and `profile.test == true` |
| Can tests be enumerated? | Yes — `<exe> --list --format=terse` prints `path::to::test: test` |
| Can one test run per process? | Yes — `<exe> --exact <name> --nocapture` |
| Does marking work inside a `#[test]`? | Yes — a finding attributed to the function under test, with a client-request origin |
| Does a positive control fire? | **Only the address-based probe.** See below |

### The branch-based positive control does not work

Three probe shapes were tried. A probe that branches on a marked byte and
returns a constant:

```rust
if value > 0x7f { 1 } else { 0 }
```

produces **no diagnostic** at `-O3`: LLVM if-converts it into `setg`, so there
is no conditional jump for Memcheck to report. Adding differing volatile writes
to the two arms did not help either.

The probe that reliably fires is a **secret-dependent address**:

```rust
let index = read_volatile(marked) as usize;
read_volatile(&table[index])
```

which compiles to a single `movzbl (%base,%idx,1)` that cannot be if-converted
away. This is the third time the same lesson has appeared in this project — M1
found it in WASM, M2 found it in native SIMD, and M3 finds it in the calibration
probe itself. Calibration therefore uses the address probe.

### Attribution must look past frame 0

The calibration finding's primary stack is:

```text
read_volatile<u8>                                  <- frame 0, inlined intrinsic
trace_check_test::calibration::secret_dependent_probe
trace_check_test::...::calibrate
<the test function>
```

Frame 0 names an inlined generic, not the probe. M2's `ATTRIBUTION_DEPTH = 8`
window already searches deep enough; this confirms a single-frame check would
have failed.

### The Rust test harness leaks, and that mattered

A full `#[test]` binary allocates in ways Memcheck reports as
`Leak_PossiblyLost` — unlike M2's tiny purpose-built harnesses. M2's classifier
maps `Leak_*` to `MemoryError`, which forces `INCONCLUSIVE`, so **every M3 test
would have been inconclusive**.

Suppressed at the Valgrind level, since a memory leak cannot corrupt a
definedness analysis:

```text
--leak-check=no --errors-for-leak-kinds=none --show-leak-kinds=none
```

`--leak-check=no` alone is not sufficient; `--show-leak-kinds=none` is the flag
that actually removes the error. With all three, a clean test yields exactly one
diagnostic: the calibration probe. M2's rule — any *other* non-secret
diagnostic forces `INCONCLUSIVE` — is preserved unchanged.

## Developer-facing API

Two crates are published to developers; everything else stays internal.

```text
trace-check-test     the testing library: assert_constant_time!, ct_test,
                     constant_time, MarkSecret, calibration
cargo-trace-check    the Cargo subcommand that builds, discovers and runs
```

`trace-check-test` re-exports the macros, so a consumer needs one dependency.

### `assert_constant_time!`

```rust
let value = assert_constant_time!(
    secret = expected,
    call = |expected| verify_tag(expected, &supplied),
);
```

Expands to, in order: run the calibration probe; take ownership of the secret
and mark its storage; hand the closure a reference laundered through
`black_box`; drop the guard, restoring definedness; declassify the returned
value; return it. The macro **evaluates to the call's return value** so ordinary
functional assertions still work — a constant-time check that stopped you
asserting correctness would not get used.

Declassification happens only after the closure returns, at exactly one
boundary.

Three forms, matching the three supported representations:

| Form | Secret |
| --- | --- |
| `secret = value` | one owned `[u8; N]` or integer scalar |
| `secrets = (a, b)` | two owned secrets |
| `secret_bytes = slice` | a borrowed `&[u8]`, e.g. `vec.as_slice()` |

#### Secrets are passed by value, and that is a correctness requirement

The illustrative API in the milestone brief had the test's own closure capture
its binding:

```rust
let index: u8 = 42;
assert_constant_time!(secrets = [&index], call = || lookup(&table, index));
```

Implemented that way, **it silently reported `NO_LEAK_OBSERVED` for code that is
demonstrably vulnerable.** The optimizer knows `index == 42`, so it passes the
immediate and never reads the marked storage. Verified against a `lookup` whose
disassembly is exactly `movzbl %sil,%eax; movzbl (%rdi,%rax,1),%eax; ret` — the
secret-dependent address was right there and the analysis saw nothing.

Adding `black_box` to the marked pointer did not fix it. What fixes it is
removing the binding the optimizer folds from: `trace-check` takes the secret by
value, owns the storage, and the closure's only access is a reference it got
back through `black_box`.

This is worth dwelling on because **the positive control cannot catch it**.
Calibration marks its own byte and succeeds regardless, so the run reported
`calibration: confirmed` alongside a false clean result. The brief anticipated
exactly this ("a misplaced marker, optimized-away input … could make vulnerable
code appear clean"); what it did not anticipate is that the *illustrative API
itself* had the defect.

### `MarkSecret`: a deliberately narrow trait

The most dangerous possible API here is a generic one. Marking a `Vec<u8>`'s
storage marks its 24-byte header — pointer, length, capacity — and **not one
byte of the heap buffer**. A generic `impl<T> MarkSecret for T` would compile,
run, report `NO_LEAK_OBSERVED`, and be worthless.

So `MarkSecret` is implemented only for representations whose bytes are entirely
within the borrowed storage:

| Type | Marked | Notes |
| --- | --- | --- |
| `[u8; N]` | all `N` bytes | the common tag/key case |
| `[u8]` | all `len` bytes | pass `vec.as_slice()`, never the `Vec` |
| `u8 u16 u32 u64 u128 usize` and signed | the scalar's bytes | |

`Vec<u8>`, `String`, `Box<T>` and arbitrary structs are **not** implemented, and
a compile-fail test pins that. The error directs the user to `.as_slice()`.

### Function-level contracts

```rust
#[constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 32], supplied: &[u8; 32]) -> bool { … }

#[ct_test(target = "verify_tag")]
fn verify_tag_case() { … }
```

`#[constant_time]` emits the function **completely unchanged** — no wrapper, no
instrumentation, no behavior change in production. It additionally emits a
`#[cfg(test)]` metadata test that declares the contract. Parameter names are
validated against the signature at compile time, so `secret = "expceted"` is a
compile error rather than a silently uncovered contract.

Coverage states are distinguished, and an annotation with no tests is never
reported as verified:

| State | Reported as |
| --- | --- |
| contract with passing tests | `covered` |
| contract with a detected violation | `violated` |
| contract whose tests were inconclusive | `inconclusive` |
| contract with no registered tests | `untested` — fails the run |
| contract registered but not executed | `not-executed` — fails the run |

## Discovery and the three execution modes

No manual manifest, and no `inventory`/`linkme` dependency. The mechanism is the
standard test harness plus one environment variable.

`#[ct_test]` generates an ordinary `#[test]` function whose body dispatches on
`TRACE_CHECK_MODE`:

| Mode | Behavior |
| --- | --- |
| unset | Print a skip notice and return. Plain `cargo test` passes with no Valgrind, and prints that the check did **not** run |
| `list` | Print one `trace-check-meta:` JSON line describing this test, then return |
| `run` | Execute calibration and the assertion body under instrumentation |

`#[constant_time]` generates a `#[cfg(test)]` test that emits its contract
record in `list` mode and returns otherwise, so contracts are discovered even
when a function has no `ct_test` at all — which is exactly the `untested` case
that must be detectable.

The runner then:

1. builds test binaries and locates them from cargo's JSON output,
2. runs each binary once with `TRACE_CHECK_MODE=list --nocapture` to collect
   metadata,
3. runs each selected test as `<exe> --exact <name> --nocapture` under Memcheck
   with `TRACE_CHECK_MODE=run` — one process per test, for isolation and
   unambiguous attribution,
4. parses the XML with M2's parser, classifies with M2's rules,
5. enforces contracts and aggregates.

Plain `cargo test` keeps working without Valgrind, and a skipped check says so
rather than reporting success.

## Positive control

M2 established that the process runs under Valgrind. That does not establish
that *this* secret was marked and consumed: a misplaced marker, an optimized-away
input, or a marked region the compiled code never reads would all look clean.

Calibration runs **per test case**, inside the same process, immediately before
the assertion, using the same `MarkSecret` implementation the test uses. It marks
a byte and feeds it to `secret_dependent_probe`, whose secret-dependent address
must produce a diagnostic.

The runner requires at least one diagnostic attributed to
`trace_check_test::calibration::secret_dependent_probe`. If none appears,
marking is not reaching compiled code and the result is `INCONCLUSIVE` — never
`NO_LEAK_OBSERVED`. Calibration findings are excluded from the leak verdict by
the same attribution mechanism.

**Tradeoff.** Per-case calibration costs one extra probe per test and catches
per-case marking mistakes. Per-binary calibration would be cheaper but would
miss a test that marks the wrong thing. Per-representation calibration would be
more precise still but needs a probe per type. M3 chooses per-case: for this
milestone, resistance to false negatives outranks instrumentation overhead.

## Result semantics and exit codes

M2's `Outcome` is reused unchanged.

| Exit | Meaning |
| --- | --- |
| 0 | every required test executed and met its contract |
| 1 | one or more constant-time violations detected |
| 2 | incomplete or failed analysis — inconclusive, zero tests selected, missing Valgrind, untested contract |

When several classes of failure occur, all findings are kept in the report and
the status is nonzero, with a leak taking precedence over an inconclusive result
so the exit code names the most serious outcome.

A **security assertion** and a **framework regression test** are different
things. `cargo trace-check test` fails on a detected leak. This repository's own
test suite asserts that the analyzer *detects* its deliberately vulnerable
examples, so those regression tests pass when a leak is found. The consumer
example carries both, with the expectation declared per test.

## Work packages

* **A — feasibility** (done, above): optimized tests under Memcheck, discovery,
  probe viability, leak-noise suppression.
* **B — `trace-check-test`**: `MarkSecret`, calibration, mode dispatch, metadata
  emission, `assert_constant_time!`.
* **C — `trace-check-macros`**: `#[ct_test]`, `#[constant_time]`, compile-time
  parameter validation, compile-fail tests.
* **D — `cargo-trace-check`**: build, discover, run per test under Memcheck,
  enforce contracts, text and JSON reports, exit codes.
* **E — integration**: `examples/consumer-crate`, regression tests, CI, docs.

## Non-goals

Deferred by instruction: symbolic execution, SMT, hardware timing, speculative
execution, generalized taint over arbitrary Rust object graphs, cross-platform
instrumentation, and a custom test harness.

Deferred by scope: generic functions, methods and trait dispatch in
`#[constant_time]`; nested or heap-indirect secret representations beyond those
listed; `async` functions; multi-threaded tests.

## Known limitations

* **Linux x86-64 only**, inherited from M2. The runner refuses other targets.
* **The analyzed binary is not the production artifact.** Tests are built with
  the `memcheck` profile — optimized, but a different crate graph, and with
  `panic = "unwind"`. A result describes that binary.
* **Path-limited.** Findings exist only for paths the test inputs execute.
* **Memcheck does not model time.** Operand latency, cache and
  branch-predictor effects, and speculation are all outside this analysis.
* **Marking is representation-bound.** Only the types in the `MarkSecret` table
  are supported; nothing else compiles.
* **Leak diagnostics are suppressed**, deliberately. A memory leak cannot
  corrupt a definedness analysis, but this does mean `cargo trace-check test`
  is not a substitute for running Memcheck normally.
* **Calibration proves marking works, not that the secret reached the function
  under test.** A test that marks the right data but never passes it to the
  function would calibrate successfully and observe no leak. The by-value API
  removes the most common cause (constant folding past the marked storage) and
  contract coverage mitigates the rest, but neither eliminates it. If a check
  reports `NO_LEAK_OBSERVED` for code you believe is vulnerable, write the
  vulnerable variant as a test first and confirm the tool detects it.
* **Attribution is heuristic**, inherited from M2: stack-frame name matching
  within a bounded window.

## Acceptance criteria

- [ ] A developer adds one dev-dependency and writes a constant-time assertion
      with no harness binary and no JSON manifest.
- [ ] `cargo trace-check test` builds, discovers, and executes those assertions.
- [ ] `--filter` and `--format json` work.
- [ ] `#[constant_time]` validates parameter names at compile time and leaves
      production behavior untouched.
- [ ] An untested contract fails the run and is reported as `untested`.
- [ ] Zero tests selected or executed is an error, not a success.
- [ ] Secret-dependent branches **and** secret-dependent addresses are detected.
- [ ] Constant-time controls pass for the paths exercised.
- [ ] A failed positive control yields `INCONCLUSIVE`.
- [ ] Running without Valgrind never reports a successful security check.
- [ ] Unsupported secret representations are rejected at compile time.
- [ ] Reports carry source locations, provenance, and calibration status.
- [ ] `examples/consumer-crate` works end to end.
- [ ] CI runs the full M3 workflow and treats missing instrumentation as failure.
- [ ] All M1 and M2 functionality still passes.

## Implementation status

Delivered. A developer adds one dependency, writes `#[ct_test]` functions with
`assert_constant_time!`, and runs `cargo trace-check test`. No harness binary,
no JSON manifest.

### Observed results

`examples/consumer-crate`, Valgrind 3.28.0, `memcheck` profile:

| Check | Outcome | Evidence |
| --- | --- | --- |
| `verify_tag_is_constant_time` | `NO_LEAK_OBSERVED` | `subtle::ConstantTimeEq` |
| `table_scan_is_constant_time` | `NO_LEAK_OBSERVED` | masked full-table scan |
| `arithmetic_on_a_secret_is_permitted` | `NO_LEAK_OBSERVED` | arithmetic only |
| `vulnerable_tag_compare_leaks` | **`LEAK_DETECTED`** | 31 secret-dependent branches, `lib.rs:52` |
| `vulnerable_table_lookup_leaks` | **`LEAK_DETECTED`** | secret-dependent address, `lib.rs:78` |
| `leak_in_a_helper_is_detected` | **`LEAK_DETECTED`** | attributed to the helper, `lib.rs:107` |
| `heap_secret_is_marked_through_a_slice` | **`LEAK_DETECTED`** | heap secret via `secret_bytes` |

Every executed check reported `calibration: confirmed`. Exit codes verified
through the real CLI: `0` for `--filter constant_time`, `1` for the full run,
`2` for `--features untested-contract`, `2` for a filter matching nothing.

### Deviations from the plan

* **The assertion API takes secrets by value**, not as a list of references.
  This was a correctness fix, not a preference — see
  [above](#secrets-are-passed-by-value-and-that-is-a-correctness-requirement).
* **`#[constant_time]` needs a regular dependency, not a dev-dependency.** The
  attribute annotates items in `src/lib.rs`, so it must resolve when the library
  is compiled, not only when its tests are. It expands to the function verbatim
  plus `#[cfg(test)]` metadata, so a production build contains nothing from
  trace-check. Crates that only write `#[ct_test]` assertions can keep it as a
  dev-dependency.
* **Discovery reads records from anywhere in a line.** `--nocapture`
  interleaves a test's output with the harness's `test NAME ... ok` progress
  line, so the metadata is not at line start. The first implementation used
  `strip_prefix` and discovered nothing.
* **The emitted test name drops the crate root.** `module_path!()` is
  crate-qualified (`consumer_crate::tests`) but libtest's `--exact` expects
  `tests::…`. Emitting the qualified path selected zero tests.
* **A `--features` passthrough was added**, needed to reach the feature-gated
  untested-contract demonstration and generally useful.
* **Repeated findings are collapsed in the terminal.** An unrolled comparison
  loop produces one diagnostic per unrolled branch — 31 identical lines for one
  leak. The JSON report keeps them all.
* **`run_under_memcheck` was extracted from M2** rather than reimplemented, so
  both backends share the bounded execution, scratch-directory safety, XML size
  bound and completeness checks.

### Deferred annotation capability

Recorded as required. `#[constant_time]` rejects, at compile time, what it
cannot support: generic functions, `async` functions, methods with receivers,
and a contract with no declared secret. Also deferred: associating a contract
with trait implementations, `#[ct_test]` on async tests, and secret
representations beyond `[u8; N]`, `&[u8]` and integer scalars. Nothing is
accepted-but-ignored; each is an error with an explanation.
