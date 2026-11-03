# M7.1 feasibility spike — per-input LLVM source coverage

Recorded evidence for [`docs/MILESTONE-07.md`](../../MILESTONE-07.md). This is a
**spike**, not a maintained example: it is hand-written to stand in for what
M7.2 would generate, it is outside the workspace, and CI does not run it.

It answers the question the milestone's mandatory gate poses — *can useful
coverage-guided exploration be built economically from the pinned Rust and LLVM
toolchain?* — and records the measurements the answer rests on.

## Requirements

The pinned toolchain plus its matching LLVM tools:

```sh
rustup component add llvm-tools
```

`llvm-profdata` and `llvm-cov` are taken from
`$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin`, never from
`PATH`. A system LLVM of a different version cannot read this compiler's
profiles, and silently reading the wrong thing is worse than not reading it.

## Running it

```sh
./run.sh all              # or: experiment-a | experiment-b | experiment-c
```

Numbers below were measured on Linux x86-64, 128 cores, rustc 1.97.0 with
LLVM 22.1.6, with the library built at `opt-level = 3, debug = true, lto = off`.

---

## Experiment A — instrument and measure a real library function

The harness takes `examples/crypto-library` as an ordinary path dependency and
calls `crypto::hidden::nested_modes`, whose leak sits behind three public
predicates. Four inputs satisfy 0, 1, 2 and 3 of them.

| Requirement | Result |
|---|---|
| 1. Coverage collected from the original library function | **Yes** — regions in `hidden.rs` and `lookup.rs` |
| 2. Harness and startup coverage excludable | **Yes** — by source file identity; harness regions are in `main.rs`, library regions under the library's manifest directory |
| 3. Two inputs on different paths distinguishable | **Yes** — four inputs, four distinct region sets |
| 4. Coverage attributable to one input | **Yes** — one `.profraw` per input |
| 5. Profile tied to the right executable | **Yes, and enforced** — see below |
| 6. No modification to the library source | **Yes** |

```
  4 input(s) -> 4 distinct coverage set(s)
    case   0:  19 region(s),  19 new     stage predicate fails
    case   1:  21 region(s),   4 new     stage passes, gate fails
    case   2:  23 region(s),   4 new     stage and gate pass, trigger fails
    case   3:  14 region(s),   7 new     all three pass -- reaches the leak
```

**This ladder is the whole feasibility argument.** Each additional satisfied
conjunct yields new library regions, so a search that retains inputs producing
new coverage can climb a conjunction one predicate at a time. Boundary and
pairwise generation, which move at most two parameters away from base, cannot.

Case 3 covers *fewer* total regions than case 2 — it takes the early returns
no longer — which is why "new coverage" has to be set difference and never a
count comparison.

### Invalid evidence is rejected by the tools, not interpreted as zero

```
$ llvm-cov export --instr-profile=case-0.profdata /bin/true
error: failed to load coverage: '/bin/true': no coverage data found

$ llvm-profdata merge -sparse -o bad.profdata bad.profraw     # truncated
warning: bad.profraw: invalid instrumentation profile data (file header is corrupt)
error: no profile can be merged
```

Both fail with a non-zero status. A missing or malformed profile therefore
surfaces as an error rather than as an empty region set, which is the
distinction the milestone requires: an empty set would read as "this input
reached nothing new" and the candidate would be discarded as uninteresting.

### Instrumentation cannot be silently absent

The harness calls `__llvm_profile_reset_counters`, `__llvm_profile_set_filename`
and `__llvm_profile_write_file` directly. Without `-C instrument-coverage` the
profiling runtime is not linked and the build **fails at link time**:

```
mold: error: undefined symbol: __llvm_profile_write_file
mold: error: undefined symbol: __llvm_profile_set_filename
mold: error: undefined symbol: __llvm_profile_reset_counters
```

So "confirm coverage instrumentation is active" is a property of the artifact
existing at all, not a runtime check that could be bypassed.

### A hazard the persistent approach has, and its fix

The profiling runtime writes the profile once more at process exit, to whatever
filename is current. With a per-case filename that appends a **second, stale
record** to the last case's file — observed as exactly double the file size, and
as `Total functions: 14` where every other case reported 7. `llvm-profdata
merge` then sums two records and the last candidate's coverage is wrong.

The fix is to point the filename at a scratch path after the loop, so the
at-exit write lands somewhere harmless and every case file holds exactly one
record. The real implementation must do this *and* validate the record count,
because a silent doubling is invisible in the exported region set.

---

## Experiment B — per-input feedback cost

512 random inputs.

| Stage | Total | Per input |
|---|---|---|
| **Approach 1** — one process and one profile per input | 0.66 s | 1.3 ms |
| **Approach 2** — one persistent process, counters reset per input | 0.01 s | 0.02 ms |
| Decode: `llvm-profdata merge` + `llvm-cov export`, serial | 6.83 s | 13.3 ms |
| Decode: the same, 16-way parallel | 0.74 s | 1.4 ms |
| Cold instrumented build | 1.89 s | — |
| Warm instrumented build | 0.37 s | — |

**Approach 3 — SanitizerCoverage / libFuzzer — is not available.**

```
$ rustc -Zsanitizer-coverage-trace-pc-guard -O probe.rs
error: the option `Z` is only accepted on the nightly compiler
```

`-C instrument-coverage` is stable; comparison tracing and
`trace-pc-guard` edge coverage are nightly-only, and `cargo-fuzz` requires
nightly as well. The toolchain is pinned to stable 1.97.0 and CI portability is
a stated requirement, so an embedded fuzzing engine is out of scope for M7 — not
because it would be slower, but because it is not reachable from the toolchain
this project builds with.

### What the numbers mean for the design

Execution is **not** the cost; decoding is, by roughly three orders of
magnitude. That inverts the obvious conclusion:

* Approach 2 is ~65× faster than approach 1 at *executing*, but it optimizes a
  term worth 1.3 ms against a decode term worth 13.3 ms. On its own it buys
  about a 9 % end-to-end improvement.
* Decoding is embarrassingly parallel, and parallelizing it is worth 9.2×.

Both together put 2000 candidates at about **3 s** of exploration. One Valgrind
process costs ~0.64 s, so a full 2000-candidate exploration costs about what
five security-analysis runs do — against a class of vulnerability that boundary
and pairwise generation cannot reach at any budget.

Approach 1 is kept as the correctness baseline the implementation is tested
against, because it has no shared-process state to get wrong.

### The cheap shortcut does not work

`llvm-profdata show --all-functions --counts` reads a `.profraw` without needing
the binary's coverage map, and would skip the `llvm-cov` cost entirely. It was
measured on the same ladder and **must not be used**:

```
  raw counter fingerprint, cumulative new per ladder step
    L0: nonzero=  2 new=  2
    L1: nonzero=  2 new=  1
    L2: nonzero=  2 new=  1
    L3: nonzero=  0 new=  0      <-- the input that reaches the leak
```

The input that reaches the vulnerability sets **no** physical counter, because
every region it covers is expressed as a counter *expression* — a subtraction
over sibling counters — rather than as a counter of its own. Only `llvm-cov`,
which evaluates those expressions against the coverage map, sees it. A
counter-only fingerprint would score the leak-reaching input as the least
interesting candidate in the batch and discard it.

---

## Experiment C — feedback quality

| Fixture | Result |
|---|---|
| **C1** public-branch exploration (`substitute_mode`, modes 0,1,2,3,255) | **2 distinct coverage sets** — `mode == 0` separates from `mode != 0`, which is the M6 gap this reproduces |
| **C2** nested public predicates (`nested_modes`) | **4 distinct sets, monotone new coverage** — see Experiment A |
| **C3** magic 32-bit equality (`magic_gate`) | **No gradient.** 16 random tokens produce *byte-identical* coverage; only the magic token differs |

C3's output is the decisive one:

```
  17 input(s) -> 2 distinct coverage set(s)
    case   0:  19 region(s),  19 new
    case   1:  19 region(s),   0 new
    ...                                  every non-magic token: 0 new
    case  16:   9 region(s),   9 new     the magic token
```

There are exactly two reachable coverage states and no path between them that
coverage feedback can observe. Region and branch coverage offer nothing to
climb toward a 32-bit constant, confirming the milestone's own expectation.

---

## Go / no-go

**Go**, with two decisions recorded against the measurements:

1. **Feedback mechanism: LLVM source-based region coverage via `llvm-cov
   export`, from the pinned toolchain's own LLVM tools.** Not raw counters,
   which lose the leak-reaching input. Not SanitizerCoverage, which needs
   nightly. The reported granularity is *region*, and the implementation must
   say so rather than claim edge coverage.

2. **Execution: a persistent discovery process with per-input counter reset,
   with the at-exit drain and a record-count check; decode parallelized across
   cores in deterministic rounds.** Approach 1 is retained as the correctness
   baseline the per-case attribution is tested against.

**M7.5 (comparison-guided mutation) is deferred**, on two independent grounds
established here: the toolchain support is nightly-only, and C3 shows the
feature's motivating case has no coverage gradient to improve upon rather than a
weak one. Deferring it is recorded in the milestone document with these
measurements, not left as an open option.

### Limitations of this spike

* One library, one platform, one toolchain version. Region identities are
  stable within an artifact and are **not** assumed stable across compiler
  versions or source edits.
* The decode timings are wall-clock on an idle 128-core machine. A CI runner
  with 2–4 cores gets the serial number, not the parallel one, which is why the
  implementation reports elapsed time and candidate count separately.
* Nothing here measures or claims anything about constant-time behavior. The
  instrumented artifact is for input discovery only; every security conclusion
  comes from M6's uninstrumented Memcheck artifact.
