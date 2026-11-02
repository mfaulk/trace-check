# Milestone 04 — Bounded relational verification of native Rust

**Status:** Implemented — see [Implementation status](#implementation-status)
**Backend:** BINSEC relational symbolic execution (`-checkct`) on optimized x86-64 ELF
**New capability:** answers *does there exist a secret assignment that leaks*, without enumerating secrets

## Objective and motivation

M1–M3 all answer the same shape of question: **did these particular executions
leak?** M1 compares two traces, M2 observes one execution per input, and M3 runs
whatever concrete values a developer wrote into a test. Every verdict is scoped
to the inputs that were tried.

That leaves a specific, dangerous gap. Consider:

```rust
fn conditional_lookup(table: &[u8; 256], secret: u8, public_mode: u8) -> u8 {
    if public_mode == 0 { constant_time_scan(table, secret) }
    else                { table[secret as usize] }
}
```

An M3 test exercising only `public_mode = 0` reports `NO_LEAK_OBSERVED`, and it
is not wrong — on that path there is nothing to find. The vulnerability lives on
a path no test visited.

M4 searches for a counterexample instead of sampling. When the search completes
without finding one, it reports what was actually established: noninterference
over a **declared input domain**, under a **stated model**, for **one compiled
artifact**.

### The question M4 adds

| Milestone | Question answered |
| --- | --- |
| M1 | Did these two traced executions differ? |
| M2 | On this execution, did a secret-derived value reach a branch or address? |
| M3 | Do the assertions a developer wrote pass? |
| **M4** | **Does there exist a secret assignment, in the declared domain, that causes a prohibited difference?** And if exploration completes: have all of them been checked? |

## The relational property

Let `f` be the compiled function, `p` public inputs, `s` secret inputs, and
`L(f, p, s)` the modeled observable behavior. The property is noninterference:

```
∀ p, s₁, s₂ :  L(f, p, s₁) = L(f, p, s₂)
```

The verifier searches for its negation:

```
∃ p, s₁, s₂ :  L(f, p, s₁) ≠ L(f, p, s₂)
```

The two executions share **identical public inputs** and may differ only in
secrets. This is what makes the result meaningful: a difference that follows
from differing public inputs is not a leak, and the relational encoding rules it
out by construction rather than by filtering afterwards.

### What `L` contains

| Observation | Modeled |
| --- | --- |
| Conditional branch decisions and control-flow paths | yes (`control-flow` check) |
| Effective memory read/write addresses | yes (`memory-access` check) |
| Multiplication / division operand timing | available, experimental, **off** by default |
| Indirect call targets | covered by the control-flow check where resolved |
| Return values | **excluded** — see below |
| Cache state, speculation, power, hardware timing | no, and out of scope |

Return values are deliberately not compared. An authentication verifier *must*
return its decision; requiring output equality would reject every correct
implementation. The property is that the **computation leading to** that
disclosure leaks nothing further through the modeled observations. The
disclosure boundary is therefore explicit: whatever the function returns is
permitted to depend on the secret; nothing else modeled may.

**Instruction-path equivalence alone is not constant-time security.** M4 narrows
the gap M1 left, it does not close it.

## Threat model

Unchanged in shape from M1–M3. An attacker calls the function with inputs of
their choosing and observes control flow and memory access patterns. They cannot
read memory directly. What changes is the *evidence*: instead of observing
chosen executions, a solver searches the declared domain.

## Feasibility spike (required gate, passed)

Run before any integration, against BINSEC 0.11.2 (`binsec -version` reports
commit `dfe4739`) from the official image pinned by digest
`sha256:19a0ff4b0278906bd6f00a5752cab19e8cad7153715cecf32d4f885826f62967`,
on `rustc 1.97.0` output for `x86_64-unknown-linux-gnu` at `-O`.

### Results

| Question | Answer |
| --- | --- |
| Does BINSEC's own example work here? | Yes — their naive `memcmp` is `insecure` (39/41 control-flow checks pass), their constant-time variant `secure` (21/21, 452/452) |
| Can it analyze **optimized x86-64 Rust**? | Yes |
| Secret-dependent **address** found? | Yes — `insecure`, 6/7 memory-access checks pass, leak localized to `0x201483` |
| Secret-dependent **branch** found? | Yes — 7 control-flow leaks, each with an instruction address |
| Constant-time control verified? | Yes — `secure`, 29/29 memory-access checks, 0 unknown, 0 pending |
| Incomplete exploration distinguishable? | Yes — `Program status is : unknown`, and `total paths` ≠ `completed/cut paths` |
| Concrete solver witness (the two secret values)? | **Not from the console output** — but recoverable via `-smt-dir`; see [Witness scope](#witness-scope) |
| Concrete replay as corroboration? | **No** — dropped as establishing less than it appears to; see [Witness scope](#witness-scope) |

### Four findings that shaped the design

**1. The compiler erased a source-level branch — again.** The first branch
example was:

```rust
if read_volatile(&secret) > 0x7f { write_volatile(sink, 1); 1 }
else                             { write_volatile(sink, 2); 0 }
```

Differing volatile writes in each arm were supposed to prevent if-conversion.
They did not. At `-O` this compiles to:

```asm
shr $0x7,%al ; mov $0x2,%cl ; sub %al,%cl ; mov %cl,(%rsi) ; ret
```

Zero conditional jumps, so **BINSEC correctly reported `secure`**. This is the
fourth time the same lesson has appeared in this project — M1 in WASM, M2 in
native SIMD, M3 in its own calibration probe, and now here. Per the milestone's
instruction not to manufacture an expected finding, the erased variant is kept
as an educational case with `secure` as its *declared* expectation, and the
real branch example uses a **secret-dependent loop trip count**, whose backward
conditional jump cannot be if-converted.

**2. A freestanding `no_std` artifact is the right target.** The milestone warns
against symbolically executing Rust's standard library. Rather than arrange for
analysis to skip `std`, the examples have no `std` and no libc: a static
`no_std` ELF of roughly 8 KB with `#[no_mangle]` statics and harness symbols.
There is no runtime to explore, and analysis starts at a harness symbol, so even
`_start` is never visited. (A static `std` build was also impossible here —
the host has no static glibc — which made the decision easy.)

**3. Secrets are declared as named globals.** BINSEC's script language takes
`secret global <symbol>` / `public global <symbol>`, so the examples expose
inputs as `#[no_mangle] pub static mut` with stable names. This maps cleanly
onto the milestone's requirement for explicit symbolic-input declarations, and
`assume` expresses input-domain restrictions.

**4. Exploration completeness is observable, and is not the same as "no
findings".** A small `-sse-depth` on a loop produced `Program status : unknown`
with `total paths 11` against `completed/cut paths 7`. Both signals are checked
independently, because a verdict of `secure` that came from exploring 7 of 11
paths is not a verification result.

## Architecture

M4 adds a backend beside M2's, sharing the outcome vocabulary and provenance and
nothing else. BINSEC runs in a digest-pinned container, invoked through its
supported CLI — no fork, no custom symbolic engine.

```text
crates/trace-check/
  src/symbolic.rs          BINSEC case schema, invocation, output parsing, classification
  src/symbolic_report.rs   text and JSON reporting for symbolic results
  src/security.rs          extended with VerifiedBounded
  src/lib.rs               run_symbolic: prepare, build once, verify each case
  tests/symbolic.rs        backend tests against the real analyzer
crates/cargo-trace-check/
  src/main.rs              `cargo trace-check verify`, beside `test` and `list`
  tests/verify.rs          CLI tests: reports, exit codes, rejected case files
examples/symbolic/
  src/targets.rs           the no_std verification targets and their harnesses
  cases.json               versioned, validated case definitions
ci/verify-m4-symbolic.py   asserts the report, not the exit code
```

Deviations from the sketch above: `verify` lives in `cargo-trace-check`'s
`main.rs` next to the existing subcommands rather than in its own `verify.rs`,
and the targets are in `src/targets.rs` rather than `src/lib.rs` because the
artifact is a `#![no_main]` binary. Generated scripts are not written to
`examples/symbolic/scripts/`: each is staged into a per-case temporary
directory and recorded verbatim in the report's `script` field, so a result
carries the exact script that produced it instead of pointing at a file that
may have changed since.

### Why a container

BINSEC is OCaml and needs a solver. Pinning the official image by **digest**
rather than tag makes the analyzer and its solver reproducible as one artifact,
which is what the milestone asks for. The runner refuses to proceed if the
container tool or the image is missing, rather than skipping.

The solver is *linked into* the analyzer binary rather than invoked as a
subprocess: the pinned image contains no `z3`, `bitwuzla`, `cvc5` or `yices`
executable, and the binary carries BINSEC's `bitwuzla-c 1.0.6` bindings over a
vendored bitwuzla with CaDiCaL 2.1.2 as its SAT backend. That is why pinning
one digest is sufficient to pin the solver, and the CI job asserts the absence
of an external solver so the claim stays true. BINSEC's `-fml-solver` default
names `z3`, which is not present — if a future image changed this, queries
would come back `unknown` and the fail-closed classifier would report
`INCONCLUSIVE` rather than a verdict.

## Build and input initialization

Each case names a target function, an entry symbol, a halt symbol, and the
secret and public globals. The runner:

1. builds the example with `rustc -O -g -C panic=abort -C link-arg=-nostdlib
   -C link-arg=-static -C relocation-model=static`,
2. reads the symbol table to confirm the entry, halt, and target symbols exist —
   a missing symbol is an explicit error, never an analysis attempt,
3. generates the BINSEC script from the case declaration,
4. runs BINSEC under a wall-clock timeout with bounded output,
5. parses the result and classifies it fail-closed.

Memory initialization is explicit: every input is a named global in `.bss`, and
`public global` tells BINSEC the bytes are low-but-symbolic rather than
uninitialized. Anything not declared is left as the ELF defines it.

## Outcomes

`security::Outcome` gains one variant. The others keep their existing meanings,
and M3's `NO_LEAK_OBSERVED` is untouched — a dynamic Memcheck result and a
completed symbolic exploration are different claims and must not share a name.

| Result | Meaning |
| --- | --- |
| `LEAK_DETECTED` | A satisfiable relational query showed differing modeled observations |
| `VERIFIED_BOUNDED` | Exploration **and** all relational checks completed within the declared model, domain, and bounds |
| `INCONCLUSIVE` | Neither could be established |
| `NO_LEAK_OBSERVED` | M2/M3 only. Not produced by this backend |

### Fail-closed conditions

`INCONCLUSIVE` is returned when any of these hold, checked before a clean
verdict is allowed:

* BINSEC reports `unknown`;
* `total paths` ≠ `completed/cut paths`, or `pending paths` > 0;
* any solver query returned `unknown`;
* the exploration depth bound was reached;
* output is missing, malformed, or truncated;
* the analyzer exits non-zero or on a signal, or times out;
* a declared symbol could not be resolved;
* the analyzer never reported reaching the declared `function` — see
  [Attributing a result to a function](#attributing-a-result-to-a-function);
* for **any** requested check class: no count was reported, the count was `0`,
  or fewer obligations passed than were raised. `0 / 1 memory access checks
  pass` next to a `secure` verdict is a contradiction, and the counts win;
* no maximum path depth was reported, so the bound cannot be shown to have
  held. A missing figure is missing evidence, not depth zero.

A `secure` verdict with no reported findings is **not sufficient** for
`VERIFIED_BOUNDED` on its own. The run must also show complete exploration,
zero unknown queries, every requested class of obligation fully discharged, and
analyzer-produced evidence that the declared function was reached.

## Witness scope

BINSEC's `checkct` reports the **instruction address** of each leaking
operation. The satisfying model is not in its console output, but it is
reachable: `-smt-dir` makes the analyzer cache every query it issued, with the
solver's answer and model recorded as trailing comments.

```text
(declare-fun mirror_TC_SECRET!1 () (_ BitVec 8))
(declare-fun TC_SECRET!1 () (_ BitVec 8))
...
; sat
(get-value (mirror_TC_SECRET!1))
; ((mirror_TC_SECRET!1 #xff))
(get-value (TC_SECRET!1))
; ((TC_SECRET!1 #xfe))
```

A query constraining both a secret **and** its `mirror_` copy is the relational
one, and that pair is the counterexample. Queries over a single copy are
path-feasibility questions and are ignored: one value cannot witness a
difference. The values are the solver's own; nothing in this tool constructs,
guesses, or hard-codes them.

For `trip-count` the pair is `TC_SECRET = 0xfe` against `0xff` — low three bits
`6` against `7`, so the loop runs a different number of times. That is checked
in the test suite rather than asserted here.

**Not every leak has a model.** The analyzer settles some findings by taint
analysis or formula preprocessing without ever issuing a satisfiability query.
`table-lookup` and `conditional-lookup` are both such cases: zero relational
queries, so there is no assignment to extract. Those report
`witness = unavailable_from_analyzer` together with the reason, rather than a
fabricated pair.

| Field | Meaning |
| --- | --- |
| `divergences[].instruction` | The leaking instruction address, from the analyzer |
| `divergences[].kind` | `control-flow` or `memory-access` |
| `divergences[].source` | The **outermost** frame of the inline chain — the analyzed function |
| `divergences[].inline_frames` | The whole chain, innermost first, when the address was inlined |
| `witness` | `solver_counterexample` or `unavailable_from_analyzer` |
| `witness_detail` | Which of the two, and why |
| `counterexamples[]` | `global`, `left`, `right`, and the `query` file the model came from |

A pair is refused as a witness when the two values are equal, which would
witness nothing, and when the query is `unsat`. Selection is deterministic —
the lowest-sorting query — so a report does not depend on directory order.

The inline chain is not cosmetic. At `-O` a leaking load sits inside an inlined
`core::ptr::read_volatile`, so a single-frame lookup resolves every finding in
this example to `mod.rs` in the standard library and names no code the
developer wrote. The outermost frame leads; the chain is kept because the
innermost frame is what an `objdump` of the artifact agrees with.

**A counterexample contains the declared secret globals' values**, by
construction — that is what makes it a counterexample. Case inputs must
therefore be synthetic. The bundled example's secrets are `static mut` globals
with no meaning outside the harness; never point a case at a real key.

**Concrete replay was considered and dropped.** An earlier sketch had a
`witness.replay` field that would run the artifact twice with two domain
secrets and compare observable outputs. That establishes only that the secret
affects the result, which is true of every target here *including the verified
ones*, and says nothing about addresses or branches. A field that cannot
distinguish `masked_scan` from `secret_lookup` reads like corroboration while
corroborating nothing, so it was left out in favor of the solver's own model.

## Attributing a result to a function

A case names both a `function` and an `entry_symbol`, and the analyzer starts
at the entry. Checking only that both symbols exist leaves a hole: pair a
vulnerable function with a safe harness and the report names the vulnerable
function while describing the safe one's analysis.

Every generated script therefore carries a `reach <function>` directive, and
the analyzer reports

```text
[sse:result] Path 0 reached address 0x2014c0 (<masked_scan>) (0 to go)
```

when exploration actually arrives there. Without that line the outcome is
`INCONCLUSIVE`: nothing is attributed to a function the analyzer never reached.
If a leak was found meanwhile it is still reported, with a message saying it
belongs to other code on the explored paths — hidden findings would be worse
than mis-attributed ones.

The directive was checked against the real analyzer to leave path counts, check
counts and the verdict unchanged, so asking for the evidence does not perturb
what is being measured. This is the M3 contract-coverage problem in a new
place, settled the same way: with evidence, not with a declaration.

## Observation model

A case must declare its checks explicitly; there is no default. The reason is
concrete. `secret_lookup`'s instruction path really is secret-independent — only
the address varies — so under `control-flow` checks alone BINSEC reports
`secure`, with complete exploration and zero unknown answers. That verdict is
legitimate and narrow, and a report that does not name the missing property
reads exactly like the stronger result.

Every result therefore carries `checked_features` and `unchecked_properties`,
and the text report prints both:

```text
Observation model:
  checked:     control-flow noninterference
  NOT checked: memory-address noninterference
```

`VERIFIED_BOUNDED` is qualified by that list in its own message. The bundled
suite checks both classes, so nothing is left unchecked there; the narrow case
exists as a regression test.

## CLI

```sh
cargo trace-check verify                        # every bundled case
cargo trace-check verify --case table-lookup    # one case
cargo trace-check verify --format json
cargo trace-check verify --cases path/to/cases.json
```

`--workspace-root` overrides where `examples/symbolic/cases.json` is looked
for, which is how the integration tests drive the installed binary.

`cargo trace-check test` keeps its M3 behavior exactly, and the symbolic backend
is not a dependency of it: a developer without a container runtime can still run
M3 checks.

| Exit | Meaning |
| --- | --- |
| 0 | every selected case met its declared expectation |
| 1 | a constant-time violation was found where none was expected |
| 2 | inconclusive analysis, or infrastructure failure |

As in M2 and M3, a bundled case that *declares* `LEAK_DETECTED` passes when the
analyzer correctly reproduces that finding. The security result of the analyzed
function and the pass/fail of the regression fixture are separate.

## Examples

| Case | Target | Declared outcome |
| --- | --- | --- |
| `table-lookup` | secret-indexed load | `LEAK_DETECTED` (memory access) |
| `trip-count` | secret-dependent loop bound | `LEAK_DETECTED` (control flow) |
| `masked-scan` | full-table scan with mask select | `VERIFIED_BOUNDED` |
| `public-branch` | branches on a public input only | `VERIFIED_BOUNDED` |
| `conditional-lookup` | leak behind a public mode | `LEAK_DETECTED` |
| `erased-branch` | source branch the compiler removed | `VERIFIED_BOUNDED`, educational |
| `depth-bounded` | exceeds a deliberately small bound | `INCONCLUSIVE` |

`conditional-lookup` is the milestone's key demonstration: an M3 test using only
the safe mode reports no leak, while M4 explores the public-mode domain and
finds the vulnerable path.

## Non-goals

By instruction: no custom SMT solver, no general-purpose symbolic executor, no
automatic verification of arbitrary crates, no symbolic execution of ordinary
Rust test binaries, no heap modeling or dynamic allocation, no concurrency, no
unbounded loops or recursion, no hardware timing measurement, no cache or
speculation modeling, no automatic verification of every `#[constant_time]`
annotation, no proof certification.

By scope: connecting M3 contracts to the symbolic backend is deferred until the
native verification model has proven reliable, as the milestone directs.

## Known limitations

* **One artifact, one toolchain.** A result describes the specific binary built
  by the recorded `rustc` at the recorded flags. The recurring branch-erasure
  finding is exactly why that matters.
* **The analyzed artifact is not a production library.** It is a freestanding
  `no_std` harness whose inputs are globals. The *function under test* is
  ordinary optimized Rust, but its surroundings are not.
* **Bounded, declared domains.** `VERIFIED_BOUNDED` is scoped to the `assume`
  constraints, the depth bound, and the **declared** observation classes.
  Outside those it claims nothing, and a case checking one class says nothing
  about the other.
* **Concrete witnesses are partial.** A counterexample is available only where
  the analyzer issued a relational satisfiability query; leaks it settles by
  taint analysis or preprocessing have no model. See
  [Witness scope](#witness-scope).
* **Attribution needs evidence, and that evidence is coarse.** A result is
  attributed to a function only when the analyzer reported reaching it. The
  directive proves arrival, not that the leak sits inside that function rather
  than in something it calls; the divergence's own source location is what
  localizes it.
* **The model excludes cache, speculation, operand latency, and all hardware
  timing.** Multiplication and division checks exist in BINSEC but are
  experimental and left off.
* **x86-64 Linux only**, and BINSEC may not model every instruction a future
  compiler emits — which is an `INCONCLUSIVE`, by design.

## Acceptance criteria

- [x] Demonstrated against optimized native Rust binaries.
- [x] Finds secret-dependent branches and addresses without enumerating secrets.
- [x] Reports analyzer-produced divergence sites with source locations.
- [x] Establishes `VERIFIED_BOUNDED` for at least one nontrivial constant-time
      example.
- [x] Distinguishes completed verification from exploration that stopped early.
- [x] Supports explicit public and secret input domains.
- [x] Reports carry enough provenance to reproduce the result.
- [x] `cargo trace-check verify` works end to end.
- [x] Examples and tests run in CI with pinned analyzer and solver.
- [x] M1–M3 remain fully functional.
- [x] Reports a solver-generated counterexample where the analyzer issued a
      relational query, and states the absence with its reason where it did
      not.

## Implementation status

All seven bundled cases reproduce their declared outcomes against the pinned
analyzer. `cargo trace-check verify` exits 0; the observed run:

| Case | Outcome | Paths | Checks (cf / mem) | Reached at | Witness |
| --- | --- | --- | --- | --- | --- |
| `table-lookup` | `LEAK_DETECTED` (1 memory access) | 1 / 1 | 1 / 1 · 7 / 8 | `0x2016b0` | none — no solver query |
| `trip-count` | `LEAK_DETECTED` (7 control flow) | 8 / 8 | 8 / 15 · 35 / 35 | `0x2016c0` | `0xfe` vs `0xff` |
| `conditional-lookup` | `LEAK_DETECTED` (1 memory access) | 2 / 2 | 3 / 3 · 33 / 34 | `0x201480` | none — no solver query |
| `masked-scan` | `VERIFIED_BOUNDED` | 1 / 1 | 1 / 1 · 30 / 30 | `0x2014c0` | n/a |
| `public-branch` | `VERIFIED_BOUNDED` | 1 / 1 | 1 / 1 · 8 / 8 | `0x201620` | n/a |
| `erased-branch` | `VERIFIED_BOUNDED` | 1 / 1 | 1 / 1 · 10 / 10 | `0x2014a0` | n/a |
| `depth-bounded` | `INCONCLUSIVE` | 10 total, 7 completed | — | `0x201640` | n/a |

The whole suite takes roughly 2.5 s, so there is no fast/slow split: CI runs
every case. Container startup (~160 ms) dominates per-case cost.

### Deviations from the plan

* **Provenance gained a `solver` field and an `analyzer_build` field.** The
  image tag reads `0.11.2` while the binary self-reports commit `dfe4739`;
  those are independent facts, so both are recorded and the build is read from
  the image at run time rather than hard-coded.
* **`check_image` uses `image inspect`, not podman's `image exists`.** The
  latter does not exist in Docker, which would have made the CI job fail on a
  runner that has only Docker.
* **Builds link in a private directory and rename into place.** rustc drops
  intermediate object files next to `-o`, so two builds aiming at the same
  artifact path corrupted each other's link. Found by two tests sharing an
  output directory — the same way a developer would hit it — and covered by
  `concurrent_builds_into_one_directory_do_not_collide`.
* **A separate CI gate, `TRACE_CHECK_REQUIRE_SYMBOLIC`.** Reusing
  `TRACE_CHECK_REQUIRE_BACKEND` would have forced the M1–M3 job to require a
  container analyzer it does not need, and coupling the two means one backend
  going missing could mask the other.
* **`CaseResult` carries the artifact hash.** A single case result stays
  interpretable after being split out of its report.
* **Concrete counterexamples are reported after all**, via `-smt-dir`, where a
  relational query exists. The plan had recorded them as unavailable; see
  [Witness scope](#witness-scope).

### Corrected after review

Six findings from review of the first revision, in the order they were fixed:

1. **The CI job selected Podman after the image was pulled into Docker.**
   Runtime selection probed `PATH` order and stopped at the first runtime that
   existed, so on a runner with both the analyzer image was invisible and all
   18 symbolic tests failed before any analysis. Selection now prefers a
   runtime that **holds the image**, `--container-runtime` and
   `TRACE_CHECK_CONTAINER_RUNTIME` override it, and CI deliberately pulls into
   Docker only while Podman probes first so the regression stays covered.
2. **`VERIFIED_BOUNDED` was not tied to the declared function.** Fixed with the
   `reach <function>` directive; see
   [Attributing a result to a function](#attributing-a-result-to-a-function).
   The regression test pairs the vulnerable `secret_lookup` with the safe
   `masked_scan` harness and requires `INCONCLUSIVE`.
3. **A result did not say which observations it checked.** Features are now
   required per case, and every result carries `checked_features` and
   `unchecked_properties`; see [Observation model](#observation-model).
4. **The classifier accepted contradictory obligation counts.** It now requires
   `passed == total` for every requested class, treats a missing count as
   missing evidence, and no longer reads an absent maximum path depth as zero.
5. **No concrete counterexample.** Now extracted from the analyzer's own cached
   solver models; see [Witness scope](#witness-scope).
6. **Duplicate `case` and `function` keys in the JSON.** `#[serde(flatten)]`
   over a struct repeating an outer field emitted each twice, and both
   `serde_json` and Python's `json` keep the last occurrence silently. The
   fields now live on one side only, with a test that walks the serialized
   object through `MapAccess` — which preserves duplicates — rather than
   through a map that collapses them.

### What validates the validator

`ci/verify-m4-symbolic.py` checks the report, not the exit code. A
`VERIFIED_BOUNDED` case must show a complete exploration, zero pending paths,
zero `unknown` answers, a non-zero number of discharged checks, no divergences,
no unchecked property, and evidence that its function was reached; a
`LEAK_DETECTED` case must name an address, and must carry a non-identical
counterexample pair where one is expected. The chosen container runtime must
match the one CI pulled into.

Each of those was confirmed by tampering with a passing report before relying
on it: marking a verified function unreached, narrowing its feature list,
collapsing a counterexample pair to identical values, and claiming a witness
where none exists all make the validator fail.

The strongest check in the suite is
`the_verdict_follows_the_artifact_not_the_declared_expectation`: it rewrites
`masked_scan` to index by the secret, leaves the case id and its declared
`VERIFIED_BOUNDED` untouched, and requires the outcome to flip to
`LEAK_DETECTED` with exit code 1. A classifier keyed on names or on declared
expectations cannot pass it.
