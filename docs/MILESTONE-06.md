# Milestone 06 — Generated constant-time testing and CI enforcement

**Status:** M6.1 complete (this document and the feasibility spike). M6.2–M6.7
planned — see [Work packages](#10-work-packages).
**Backend:** Valgrind Memcheck, reused unchanged from M2/M3
**New capability:** useful dynamic leakage testing from a contract annotation
alone, without a hand-written `#[ct_test]`

## Objective

M3 lets a developer *declare* a constant-time contract and *write* a dynamic
check for it. M5 lets them ask for a bounded symbolic proof. Neither does
anything about the gap between the two: a contract whose only dynamic test
exercises one chosen input.

That gap is not hypothetical, and this repository already contains the
demonstration. `examples/crypto-library` declares:

```rust
#[constant_time(secret = "index")]
pub fn substitute_mode(index: u8, mode: u8) -> u8 {
    if mode == 0 { substitute(index) } else { substitute_indexed(index) }
}
```

Its hand-written check passes `mode = 0`, takes the constant-time path, and
observes nothing — honestly, because the leak is on a path that test never
visits. Today only `cargo trace-check verify` finds it, and that needs a
container, a pinned analyzer image, and a contract the symbolic backend can
represent.

M6's job is to find that leak dynamically, automatically, from the annotation.

**This is not verification.** A clean generated run is
`NO_LEAK_OBSERVED` over the inputs that were generated, and the reporting must
keep saying so. The goal is better detection per unit of developer effort and CI
time, on code for which symbolic verification is impractical, unsupported, or
too expensive.

### Success criteria

1. Useful dynamic leakage testing from a contract annotation, with no separate
   harness written by hand.
2. Generated inputs reach cases that hand-written tests commonly miss.
3. The framework identifies *which* generated input exposed a leak.
4. Failures reproduce, and are retained as regression cases.
5. CI semantics are security-oriented: a detected leak fails the build.
6. A bounded, predictable execution budget.
7. A clean dynamic result is never presented as proof.

M1–M5 continue functioning unchanged.

## 1. What M6 reuses

M6 does **not** implement a new leakage detector. It improves the
input-selection and execution layers feeding the existing one.

| Component | Reuse |
| --- | --- |
| `trace-check-macros` | parameter names, roles and types, from the existing descriptor |
| `contract.rs` | contract identity and supported input representations |
| `harness.rs` | Cargo package resolution, generated-package layout, artifact provenance |
| `trace-check-test` | `launder`, `mark`, `finish`, calibration |
| `trace-check-secret` | Valgrind client requests |
| `native.rs` / `memcheck.rs` | bounded Memcheck invocation, XML parsing, classification |
| `cargo-trace-check` | the developer-facing CLI |
| `security.rs` | the existing outcome and evidence vocabulary |
| `examples/crypto-library` | fixtures, including the `substitute_mode` demonstration |

### How the M6 artifact differs from M5's

M5 builds a freestanding `no_std` static ELF with no libc, because BINSEC must
not explore program startup. M6 can build an **ordinary Rust executable** linked
against the real library, which is what lets it reuse the Valgrind runtime and
makes `std` libraries reachable.

It is still an analysis artifact, not the production binary. Its compiler
settings, dependency versions and hash must be recorded, exactly as M5 records
them.

## 2. Developer-facing workflow

A new security-enforcement command, alongside the existing three:

```sh
cargo trace-check check --contract crypto::lookup::substitute_mode
cargo trace-check check --all-configured --cases 128 --seed 12345 --ci
cargo trace-check check --replay path/to/failure.json
```

`test` (hand-written dynamic assertions), `verify` (symbolic) and `list`
(discovery) are unchanged.

A minimally supported contract requires **no** generation configuration: the
annotation already says which parameters are secret, and the signature supplies
the types. Optional per-contract settings carry budgets and strategies only, and
may never assign or override a role — the same rule `contract.rs` already
enforces for `[verify.*.inputs]`.

## 3. Phase A — the feasibility spike

Before building a generator, prove a generated dynamic harness can safely
analyze a real library function. The spike is recorded in
[`docs/spikes/m6-generated-harness/`](spikes/m6-generated-harness/README.md) and
is reproducible from a fresh clone.

It is hand-written to stand in for what M6.3 would generate: it declares no
algorithm, takes the library as a path dependency, decodes inputs from `argv`,
launders and marks the declared secret, calls the real function with the
declared positional mapping, drops the marking, declassifies the result, and
prints a completion marker.

### Provenance of the measurements below

| | |
| --- | --- |
| rustc | 1.97.0 (2d8144b78 2026-07-07) |
| Valgrind | 3.28.0 |
| Platform | Linux 7.2.10-200.fc44 x86_64 |
| CPU | AMD Ryzen Threadripper PRO 5995WX (64 cores) |
| Harness profile | `opt-level=3`, `debug=true`, `lto=false`, `codegen-units=1`, `panic=unwind` |
| Memcheck flags | as `trace_check::native::shared_valgrind_args` |

## 4. Phase A — feasibility spike results

### A1 — a generated harness runs the real function under Memcheck

Confirmed. The harness reports `run_mode=valgrind`, the positive control fires,
and the case completes:

```text
trace-check-harness: run_mode=valgrind
tc-spike-calibration: probe_returned=165
tc-spike-case-done: 0 produced=3
tc-spike-run-complete: cases=1
```

With `mode = 0` the **only** Memcheck error is the calibration probe, attributed
to `trace_check_test::calibration::secret_dependent_probe`. So the safe path
yields no finding, and the positive control still proves marking reaches
compiled code.

### A2 — the hidden public mode is detected

With `mode = 1`, a second error appears:

```text
[1] kind=UninitValue
    what=Use of uninitialised value of size 8
    origin=Uninitialised value was created by a client request
    at read_volatile<u8> (library/core/src/ptr/mod.rs:2107)
    at substitute_indexed (lookup.rs:37)
    at crypto::lookup::substitute_mode (lookup.rs:51)
    at invoke (main.rs:53)
```

Three things in that output decide the design:

**The origin is a client request**, so it is our marking rather than a genuine
uninitialized-memory bug — the discriminator `memcheck.rs` already relies on.

**Attribution survives a direct cross-crate call.** The primary stack names
`crypto::lookup::substitute_mode` at depth 2, inside the existing
`ATTRIBUTION_DEPTH` window. This was the spike's main risk: M5 found that rustc
marks small non-generic functions cross-crate-inlinable, which dissolved its
target and left no symbol, and M3 only avoids the problem because
`#[constant_time]` generates an `#[inline(never)]` adapter *inside* the library.
An external harness has no such adapter. Measured, the direct call is enough
here; a `reified` form — function pointer laundered through `black_box` — was
tested and produced an identical finding, so it is available as a fallback but
is not needed by default.

Note that `substitute_indexed` appears as a bare local name while
`substitute_mode` is fully qualified, in one stack. That mixed qualification is
exactly what `memcheck::frame_names_function` was built to match.

### A2 controls

| Invocation | Expected | Observed |
| --- | --- | --- |
| `substitute_mode direct 42:0` | calibration only | calibration only |
| `substitute_mode direct 42:1` | leak in the library | leak, attributed to `substitute_mode` |
| `substitute_mode reified 42:1` | leak in the library | identical finding |
| `substitute direct 42:0` | no finding (constant-time scan) | calibration only |
| `substitute_indexed direct 42:0` | leak | leak, attributed to `substitute_indexed` |

The constant-time full-table scan produces **no** false finding, which is the
error direction that would make the tool useless.

### A2 — target-binding control

§6 of the plan requires more than the calibration probe: calibration marks its
own byte and succeeds whether or not the declared secret ever reaches the
declared parameter. The spike therefore adds a `decoy` form that marks a
*different* byte and passes the real index **unmarked**:

| Invocation | Observed |
| --- | --- |
| `substitute_indexed decoy 42:0` | calibration fires; **no** finding in the library |
| `substitute_mode decoy 42:1` | calibration fires; **no** finding in the library |

Both known-leaky targets go quiet. That is what makes the findings in A2
evidence that the marked bytes reached the declared parameter, rather than
evidence of ambient marking somewhere in the process. M6.3 must keep an
equivalent end-to-end control.

### A3 — batching

Several cases per Valgrind process works, and the cost model is stark.

| Execution | Wall clock |
| --- | --- |
| 64 cases, no Valgrind | 0.00 s |
| 1 case, 1 process | 0.65 s |
| 16 cases, 1 process | 0.64 s |
| 64 cases, 1 process | 0.65 s |
| 256 cases, 1 process | 0.65 s |
| 16 cases, one process each | 10.35 s |
| 64 cases, one process each | 41.31 s |

Valgrind startup is ~0.64 s and dominates completely; case execution itself is
not measurable at this scale. Batching 256 cases costs the same as one case,
making it roughly **100× faster per case at 64 cases** and ~400× at 256.

**But the aggregate cannot attribute, and cannot count.** Memcheck consolidates
repeated diagnostic sites, so these two runs are indistinguishable in the XML —
one error, one site, nothing naming a case:

| Batch | Errors attributed to the library |
| --- | --- |
| 1 leaky case of 16 | 1 |
| 16 leaky cases of 16 | 1 |

This confirms the plan's warning directly: aggregate XML must never be read as
evidence that every input in a batch leaked, and the error count must never be
used as a leak count.

Binary-split isolation recovers the culprit cheaply. For the 1-of-16 batch,
re-running shrinking subsets found case 11 in **4 re-runs** (⌈log₂ 16⌉), about
2.6 s:

```text
isolated case index 11  (input 11:1)  after 4 re-runs
```

### Feasibility gate: passed

The generated harness detects the original function's vulnerability, retains
correct secret marking and calibration, demonstrates correct target binding, and
has an acceptable execution model.

### What the results settle for the implementation

* **Batch to detect, split to attribute.** Default to batches with
  binary-split isolation on failure. The isolation cost (~⌈log₂ N⌉ runs) is
  negligible against the per-case cost of isolating by default.
* **Default to the direct call**, keeping the reified form as a fallback for
  targets that do get inlined away. Detect that case by requiring attribution
  and reporting an unattributable finding rather than guessing.
* **Budget arithmetic for CI.** At 64 cases per contract, one batched run per
  contract costs ~0.65 s. The 11 contracts in `examples/crypto-library` are
  ~7 s plus isolation only where a leak exists. A 64-case default is affordable;
  per-case processes at the same budget would be ~470 s.
* **Keep the existing calibration *and* add a target-binding control.** The
  `decoy` result shows the two prove different things.

## 5. Phase B — typed input generation (planned)

Deterministic, seeded generation for the representations the contract descriptor
already models: `u8`/`u16`/`u32`/`u64`, public `bool`, `[u8; N]` and `&[u8; N]`.
Unsupported shapes are refused with the actionable message `contract.rs` already
produces — never silently treated as though a pointer or a `Vec` header held the
secret bytes.

Stages, in order: deterministic edge cases; pairwise combinations of public
inputs; seeded pseudorandom cases; then persisted regression cases, replayed
first.

Uniform random generation is close to useless for some cryptographic shapes — a
random 128-bit tag essentially never matches — so a narrow, opt-in relationship
mechanism for fixed-size byte arrays is needed: identical, differing in the
first or last byte, differing at a chosen position, sharing a prefix, differing
in one bit. Any derived public input is computed **before** marking.

The corpus must be canonical, seeded, budget-bounded, independent of the
analyzer backend, and must record which strategy produced each case.

## 6. Phase C — the generated harness (planned)

`crates/trace-check/src/dynamic_harness.rs`, generating the package shape the
spike validated. Per case: decode, validate representations and domains,
initialize storage, mark, invoke with the declared positional mapping, end the
marked region, declassify, record completion.

Nothing may be generated, serialized, logged or compared while a value is
marked, unless that operation belongs to the function under analysis.

## 7. Phase D — isolation, and E — reproduction (planned)

Batch, then binary-split on failure, then verify the isolated finding matches
the original's classification and location. An isolated case that does not
reproduce must **not** discard the original finding: it may be
sequence-dependent, and the batch is then preserved for replay.

Finding identity should be a fingerprint over classification, target identity,
source location and — within one artifact — instruction location. Not an
absolute address across artifacts.

Reproducers are versioned JSON, replayable with `--replay`. Shrinking is
type-aware and budgeted separately; a candidate is retained only if the *same*
leakage finding still reproduces. A panic, a different memory error, or an
unrelated failure is not a successful shrink.

## 8. Phase F — CI semantics (planned)

This phase resolves a real mismatch in the current design. M4/M5 configuration
lets a known-vulnerable fixture declare `expected_outcome = "LEAK_DETECTED"`,
and `examples/crypto-library` uses it for five contracts. That is correct for
testing trace-check itself. It must not be what happens when a developer
declares their own function constant-time.

So `check` separates the two concepts:

* **security contract** — the function must satisfy the property; a leak fails.
* **analyzer regression fixture** — the analyzer must produce a stated result on
  a stated example; detecting the expected leak passes.

| Observed | Default `check` enforcement |
| --- | --- |
| `LEAK_DETECTED` | fail |
| `NO_LEAK_OBSERVED`, required cases completed | pass the dynamic gate, with no proof claim |
| `INCONCLUSIVE` | fail under `--ci` |
| zero cases executed | fail |
| contract not analyzed, but required | fail |
| missing instrumentation | fail |
| unsupported contract | fail, with an explanation |

A CI run must never report success because nothing was selected, nothing
executed, Valgrind was absent, marking was inert, the target was never called,
the executor failed, a leak was suppressed by an expectation, or a batch finding
could not be attributed and was dropped.

### A known limitation to state, not paper over

`--all-contracts` enumerates *configured* contracts, not every annotation in the
source tree. `--all-configured` keeps that honest in the name. Until a reliable
contract inventory exists, the report must say the inventory is incomplete
rather than imply full annotation coverage.

## 9. Phase G — coverage terminology (planned)

Three distinct things, never conflated:

| Term | Meaning | M6 |
| --- | --- | --- |
| Contract coverage | which required contracts received completed checks | required |
| Input-strategy coverage | which planned input categories were exercised | required |
| Execution coverage | which code paths were reached | deferred |

The fraction of generated inputs executed must never be presented as a fraction
of secret values proven safe.

## 10. Work packages

| Package | Deliverable | Gate | State |
| --- | --- | --- | --- |
| M6.1 | This document and the feasibility spike | finds the `substitute_mode` leak across two public modes | **complete** |
| M6.2 | Deterministic typed generator and corpus format | same seed reproduces the corpus | planned |
| M6.3 | Generated Cargo harness and Memcheck execution | correct marking and invocation of the real function | planned |
| M6.4 | Batching and diagnostic isolation | an aggregate finding reproduces as an input or sequence | planned |
| M6.5 | Reproduction and minimal shrinking | a saved failure reproduces the same leak | planned |
| M6.6 | CI security policy and contract-coverage reporting | a leak cannot pass a security check | planned |
| M6.7 | Integration tests, benchmark, documentation | M1–M5 remain green | planned |

## 11. Limitations

* A clean generated run is evidence about the inputs generated and the paths
  they took. It is not a proof, and `NO_LEAK_OBSERVED` keeps that name.
* The analyzed artifact is not the production binary. Its profile, dependency
  versions and hash are recorded because the result describes that build.
* Memcheck models secret-dependent branches and addresses. It does not model
  caches, ports, speculation, or data-dependent instruction timing.
* Batched runs cannot attribute a finding to a case without re-running, and a
  sequence-dependent finding may not isolate to a single case at all.
* The contract inventory is incomplete: configured contracts, not all
  annotations.

## 12. Non-goals

No new symbolic engine; no coverage-guided fuzzing integration; no general heap
modeling; no arbitrary structs, traits, generics or async; no statistical timing
backend; no microarchitectural modeling; no synthesis of domain validity
constraints; no proof claims from random testing; no universal
execution-coverage percentage.

In particular, LLVM coverage-guided fuzzing is **not** a prerequisite. It is an
attractive M7, but it adds compilation artifacts and a second set of assumptions
about which paths the security analyzer actually executes.

## 13. Future direction

* **M7** — coverage-guided leakage discovery, keeping coverage instrumentation
  separate from security analysis.
* **M8** — compiler and build-profile regression analysis, with
  artifact-specific evidence.
* **M9** — hardware timing validation on controlled hardware.
* **M10+** — broader observation models, permitted disclosures, and selected
  microarchitectural requirements.
