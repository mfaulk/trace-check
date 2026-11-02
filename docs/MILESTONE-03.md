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

Coverage states are listed under
[Contract identity and verified invocation](#coverage-requires-proof-of-invocation).
An annotation with no tests, or with a test that never invoked it, is never
reported as verified.

## Discovery, isolation, and ignore semantics

No manual manifest, and no `inventory`/`linkme` dependency — the standard test
harness provides everything needed.

`#[ct_test]` generates **two** items:

* the check itself, as a `#[test]` carrying `#[ignore]`. Plain `cargo test`
  reports it as `ignored` with the reason attached, never as `ok`;
* a separate metadata test named `__trace_check_meta_<name>`, also `#[ignore]`,
  which only prints a `trace-check-meta:` record.

`#[constant_time]` likewise generates a `__trace_check_contract_<name>` metadata
test, so contracts are discovered even when a function has no `ct_test` at all —
exactly the `untested` case that must be detectable.

The runner then:

1. builds test binaries and locates them from cargo's JSON output,
2. **enumerates** each binary with `--list --format=terse --include-ignored`,
   which runs nothing,
3. executes **only** the `__trace_check_*` metadata tests, in one bounded
   subprocess per binary, to collect the records,
4. runs each selected check as
   `<exe> --include-ignored --exact <name> --nocapture` under Memcheck with
   `TRACE_CHECK_MODE=run` — one process per check, for isolation and
   unambiguous attribution,
5. parses the XML with M2's parser and classifies with M2's rules,
6. enforces contracts and aggregates.

### Why discovery enumerates before executing

An earlier design ran every test with `TRACE_CHECK_MODE=list`, relying on
generated tests to recognize the mode and return early. Ordinary `#[test]`
functions do not recognize it, so **discovery executed the consumer's entire
unit-test suite**: side effects fired, an unrelated failure blocked discovery,
and a slow or hanging test delayed or stalled it. `--filter` did not help,
because the damage was already done before filtering.

Enumerating first and executing only our own generated tests removes the class.
Both discovery subprocesses are also wall-clock bounded, so a pathological test
binary cannot stall the run.

### Why checks are `#[ignore]`d rather than self-skipping

The earlier design had the check print a skip notice and return successfully, so
plain `cargo test` showed:

```text
test tests::verify_tag_is_constant_time ... ok
```

with the notice hidden by libtest's output capture. A developer saw a green test
for a security assertion that never ran. `#[ignore]` makes libtest report the
truth:

```text
test tests::verify_tag_is_constant_time ... ignored, trace-check constant-time
    check; run `cargo trace-check test`
```

### Execution evidence is a marker, not a substring

A generated check prints `trace-check-executed: <identity>` as its last act, and
the runner requires that exact line. Counting on libtest's `"1 passed"` summary
would match arbitrary output from the test binary itself, and `--exact` on a
renamed test runs zero tests while still exiting 0 — which must never read as a
pass.

## Contract identity and verified invocation

### Identity is module-qualified

A contract is keyed on `module_path!()::function`, not on the bare name. Two
modules may each define `verify`:

```rust
mod authentication { #[constant_time(secret = "key")] fn verify(…) }
mod encryption     { #[constant_time(secret = "key")] fn verify(…) }
```

Keyed on `verify`, one silently overwrote the other, and a test targeting
`"verify"` could mark the survivor covered while the second contract vanished
from the report entirely. Both now appear with distinct identities. A test's
`target` may be a bare name or any path suffix; an **ambiguous** name is a hard
error rather than a guess, and an unknown one is rejected before anything runs.

### Coverage requires proof of invocation

`target` is not a label. Without evidence, this would have passed:

```rust
#[constant_time(secret = "key")]
fn vulnerable(key: u8) -> u8 { if key == 0 { 0 } else { 1 } }

#[ct_test(target = "vulnerable")]
fn purported_test() {
    assert_constant_time!(secret = 42u8, call = |_key| 0u8);   // never calls it
}
```

The test marks a secret, calibration confirms, no findings appear, and the
contract would have been reported `covered` with the command exiting 0 — for a
function that was never executed.

So `#[constant_time]` additionally emits, **under `#[cfg(test)]` only**:

* an invocation counter, and
* an `#[inline(never)]` adapter `<function>_ct` with the same signature, which
  increments the counter and delegates to the untouched function.

Tests call the adapter. `#[ct_test(target = …)]` snapshots the counter, and
fails with a message naming the adapter if it did not advance. The adapter is a
separate frame delegating to the original, so **the code being analyzed is
unchanged** — important, because this project's recurring lesson is that the
compiled artifact is what matters.

Coverage states are therefore:

| State | Meaning |
| --- | --- |
| `covered` | a test ran clean **and** proved it invoked the function |
| `claimed-not-invoked` | a test named the contract but did not invoke it — blocks the run |
| `violated` | a test detected a violation |
| `inconclusive` | tests ran but could not answer |
| `untested` | no test names this contract — blocks the run |
| `not-executed` | a test exists but did not run; excused only under `--filter` |

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

### Corrections after review (PR #3)

Five defects, three of them blockers. All shared one root cause: discovery and
contract association were built on weak signals — running every test in a mode
only some tests understand, and matching contracts by bare string name.

**Discovery executed every ordinary unit test.** Verified against a crate whose
ordinary test writes a sentinel file and then fails: the sentinel appeared and
the failure blocked discovery. Now `--list` enumerates and only
`__trace_check_*` tests execute, both subprocesses bounded by a timeout.
`examples/discovery-hazard` is a non-workspace crate carrying that hazard, and
the regression test asserts the sentinel stays absent and `list` still exits 0.

**A contract could be reported covered without its function ever running.** The
reviewer's counterexample reproduced exactly. Fixed with the `#[cfg(test)]`
counter and `_ct` adapter described above; the claiming test now fails with a
message naming the adapter, and the contract reports `inconclusive` rather than
`covered`.

**Same-named contracts overwrote each other.** Two modules each defining
`verify` left one contract in the report. Identities are now module-qualified,
duplicates are an explicit error rather than a silent overwrite, and an
ambiguous `target` is rejected.

**An unrun check looked like a passing test.** Replaced the self-skipping
passing test with `#[ignore]`, so libtest reports `ignored` with a reason.

**Execution was detected by substring.** Replaced `"1 passed"` with a marker the
generated check prints itself, compared against the full test identity.

Two bugs surfaced while fixing these, both found by running the real harness:
`--exact` is a boolean flag rather than a repeatable argument, so repeating
`--exact NAME` pairs silently selected only the first; and a `--list` line is
`path::to::test: test`, so splitting on `:` truncated the module path and
discovered nothing.

### Deferred annotation capability

Recorded as required. `#[constant_time]` rejects, at compile time, what it
cannot support: generic functions, `async` functions, methods with receivers,
and a contract with no declared secret. Also deferred: associating a contract
with trait implementations, `#[ct_test]` on async tests, and secret
representations beyond `[u8; N]`, `&[u8]` and integer scalars. Nothing is
accepted-but-ignored; each is an error with an explanation.
