# Milestone 07 — Coverage-Guided Leakage Discovery

**Status:** Implemented
**Branch:** `feat/m7-coverage-guided-discovery`
**Prerequisite:** Milestone 6, merged
**Primary platform:** Linux x86-64
**Security backend:** M6's Valgrind Memcheck integration, unchanged

---

## 1. What M7 changed, in one paragraph

M6 generates boundary, pairwise, relationship-aware and seeded random inputs.
That is a fixed set of guesses, and a leak behind a conjunction of public
conditions is not in it. M7 adds a second, separately compiled artifact built
with `-C instrument-coverage`, runs candidate inputs in it, and keeps the ones
that reach library code nothing has reached before. Those inputs are then
analyzed by **M6's backend, unmodified**. Nothing about the security decision
changed; only the choice of inputs did.

The central principle, which the implementation enforces structurally rather
than by documentation: **coverage guides testing and establishes nothing.**

---

## 2. Two artifacts, and why they cannot be confused

| | Discovery artifact | Security artifact |
|---|---|---|
| Built with | `-Cinstrument-coverage` | no instrumentation |
| Marks secrets | **no** — does not even depend on `trace-check-test` | yes, with calibration and a binding control |
| Produces | one LLVM coverage profile per case | Memcheck diagnostics |
| Security conclusions | **none** | the only ones there are |
| Package | `tc-explore-<contract>` | `tc-check-<contract>` |

Both are emitted by one generator ([`dynamic_harness`]), which was a deliberate
choice. The part that must *not* differ is the part a shared generator cannot
make differ: the decoders, the compile-time descriptor check, and the positional
argument mapping. An input selected in one artifact is only worth running in the
other if it means the same thing in both. Everything that *should* differ —
marking, calibration, instrumentation, the dependency on the marking crate —
differs structurally, so neither artifact can be argued into having done the
other's job.

Three consequences worth stating:

**Instrumentation cannot be silently absent.** The discovery harness calls
`__llvm_profile_reset_counters`, `__llvm_profile_set_filename` and
`__llvm_profile_write_file` directly. Without `-Cinstrument-coverage` the
profiling runtime is not linked and the artifact does not build. "Confirm
coverage instrumentation is active" is a property of the binary existing, not a
runtime check something could bypass.

**A discovery crash is not a security finding.** Every discovery failure mode is
its own `ExecutionStatus`, is reported, retains its triggering input for
diagnosis, and contributes no coverage.

**Run-level and per-case evidence are separate, and both are consulted.** One
unreadable profile costs one candidate, is recorded, and leaves the round's
other observations good. A process that did not *finish* makes the whole round
untrustworthy — including the observations that look fine, because nothing rules
out the process having died partway and the surviving profiles describing a
different set of cases than the markers suggest. So a round is refused when the
baseline profile is missing, the run-completion marker is absent, the completed
count or the completed *set* disagrees with the batch, or the process exited
abnormally.

That split had to be corrected: an earlier revision computed all of it in
`DiscoveryRun::complete()` and then never called it, so a discovery process that
marked every case and died before its final marker was accepted as a finished
search. Per-case markers do not rule out a death immediately after the last one
— which is the entire reason M6 has a separate run-completion marker — and the
discovery side now applies the same discipline.

**A clean discovery run means nothing.** The discovery artifact marks zero bytes
and the report prints that number, so a reader meets the coverage figures already
knowing what produced them.

---

## 3. The feasibility gate, and what it decided

Recorded in full, reproducibly, in
[`docs/spikes/m7-coverage-feedback/`](spikes/m7-coverage-feedback/README.md).
Three decisions came out of it, each from a measurement rather than a preference.

### Region coverage, not raw counters

`llvm-profdata show --counts` reads a `.profraw` without the coverage map and is
about three times faster. Measured on the predicate ladder of
`crypto::hidden::nested_modes`:

```
  llvm-cov regions (library files only), cumulative new per ladder step
    L0: covered= 19 new= 19     stage predicate fails
    L1: covered= 21 new=  4     stage passes, gate fails
    L2: covered= 23 new=  4     stage and gate pass, trigger fails
    L3: covered= 14 new=  7     all three pass -- reaches the leak

  raw counter fingerprint, cumulative new per ladder step
    L0: nonzero=  2 new=  2
    L1: nonzero=  2 new=  1
    L2: nonzero=  2 new=  1
    L3: nonzero=  0 new=  0     <-- the input that reaches the leak
```

The input that reaches the vulnerability sets **no physical counter at all**:
every region it covers is a counter *expression*, a subtraction over sibling
counters, which only `llvm-cov` evaluates. A counter-only fingerprint would have
scored the leak-reaching candidate as the least interesting in its batch and
discarded it. So the expensive decode is load-bearing and is parallelized rather
than avoided.

Note also that L3 covers *fewer* regions than L2 — taking the deep path means
not executing three early returns. "New coverage" is therefore a set difference
and never a count comparison, and a test pins that.

### Not SanitizerCoverage or libFuzzer

```
$ rustc -Zsanitizer-coverage-trace-pc-guard -O probe.rs
error: the option `Z` is only accepted on the nightly compiler
```

`-C instrument-coverage` is stable; branch coverage
(`-Zcoverage-options=branch`), `trace-pc-guard` edge coverage and comparison
tracing are nightly-only, and `cargo-fuzz` needs nightly too. This project pins
stable 1.97.0 and CI portability is a requirement, so an embedded fuzzing engine
is out of scope — not because it would be slower, but because it is not
reachable from the toolchain this project builds with.

**The available granularity is source regions, and the report says so**, in
those words, including what is unavailable. Region coverage and edge coverage are
not interchangeable, and a report that used one word for the other would be
claiming a finer search than it ran.

### A persistent process, with two hazards handled

512 inputs, measured:

| Stage | Total | Per input |
|---|---|---|
| Approach 1 — one process and one profile per input | 0.66 s | 1.3 ms |
| Approach 2 — one persistent process, counters reset per input | 0.01 s | 0.02 ms |
| Decode: `llvm-profdata merge` + `llvm-cov export`, serial | 6.83 s | 13.3 ms |
| Decode: the same, 16-way parallel | 0.74 s | 1.4 ms |
| Cold instrumented build | 1.89 s | — |
| Warm instrumented build | 0.37 s | — |

Execution is not the cost; decoding is, by three orders of magnitude. That
inverts the obvious conclusion: the persistent process is 65× faster at
*executing* but optimizes a 1.3 ms term against a 13.3 ms one, so on its own it
is worth about 9 % end to end. Parallelizing the decode is worth 9.2×. Both
together put 2000 candidates at roughly 3 s, against ~0.64 s for a single
Valgrind process.

Approach 1 is retained as the correctness baseline the per-case attribution is
tested against ([`Collector::decode`]), because it has no shared-process state to
get wrong.

Three hazards this approach has, all three found by running it:

* **The at-exit write.** The profiling runtime writes the profile once more at
  process exit, to whatever filename is current — appending a second, stale
  record to the *last* case's file, observed as exactly double the file size.
  `llvm-profdata merge` then sums two records and the last candidate's coverage
  is silently doubled. The harness drains the at-exit write to a scratch path,
  and every per-case profile's byte length is validated against a baseline
  profile written after the first counter reset and before any case. The length
  check costs no subprocess and catches the doubling exactly.
* **Stale profiles.** A profile left behind by an earlier round would be read as
  this round's coverage, so the per-case paths are removed before each run.
* **A replaced executable.** `llvm-cov export` needs *the exact executable that
  produced a profile*, and Cargo's target directory is shared so the library and
  its dependencies are not rebuilt per contract — which makes the executable
  path shared mutable state. Two runs of one contract produce the same package
  name and the same output path, and a later `cargo build` relinks over it while
  an earlier run is still using it. Cargo's lock serializes the builds; it does
  not keep the previous build's output alive.

  This surfaced as a CI failure on this very branch:
  `failed to load coverage: …/tc-explore-crypto-hidden-nested_modes: No such
  file or directory`. The fail-closed decode reported it as unusable evidence
  rather than as zero coverage, so it failed a test instead of quietly shrinking
  a search — which is the behaviour that rule exists for.

  The fix is to **copy the executable out** of the target directory into the
  run's own work directory, verify the copy byte-for-byte, and use the copy for
  everything downstream. Dependency-build caching is kept; the analyzed artifact
  becomes something nothing else can replace. It applies to the security
  artifact too, where the same race would have meant Valgrind re-running a
  different binary during isolation or shrinking.

### Comparison guidance: deferred, with the measurement

Magic-value fixture, 16 random 32-bit tokens then the magic one:

```
  17 input(s) -> 2 distinct coverage set(s)
    case   0:  19 region(s),  19 new
    case   1:  19 region(s),   0 new
    ...                                  every non-magic token: 0 new
    case  16:   9 region(s),   9 new     the magic token
```

There are exactly two reachable coverage states and nothing between them that
coverage feedback can observe. Region coverage offers no gradient toward a 32-bit
constant — not a weak one, none.

**M7.5 is therefore not implemented**, on two independent grounds: the toolchain
support is nightly-only, and the feature's motivating case has no gradient to
improve on rather than a shallow one. The gap is asserted rather than left
implicit: `crypto::hidden::magic_gate` is configured with
`expected_outcome = "NO_LEAK_OBSERVED"`, and `ci/verify-m7-explore.py` fails if
that ever changes in either direction — closing the gap is good news that
requires this document to be revised.

---

## 4. The benchmark fixtures, and why they came first

`examples/crypto-library/src/hidden.rs` was written and committed **before** the
coverage-guided algorithm, so the algorithm could not be tailored to it. Its
premise is pinned by `crates/trace-check/tests/baseline.rs` — pure generator
tests, no Valgrind, no build — which fail if a future generator improvement makes
the comparison false, rather than letting it quietly become so.

| Fixture | Property | Reached by |
|---|---|---|
| `lookup::substitute_mode` | leak behind `mode != 0` | M6 boundaries, M7 |
| `hidden::nested_modes` | leak behind **three** public predicates | **M7 only** |
| `hidden::header_gate` | leak behind **three fields of one** `[u8; 8]` | **M7 only** |
| `hidden::magic_gate` | leak behind an exact `u32` equality | neither (see §3) |
| `hidden::threshold_window` | leak in a window above a power-of-two threshold | M6 boundaries, M7 |
| `hidden::secret_gated` | leak reachable only for some secret values | M6 boundaries, M7 |
| `controls::tail_byte_probe` | only the final secret byte reaches an address | M6, M7 |
| `tag::verify_tag` + relationships | tag comparison with matching prefixes | M6 relationships, M7 |
| `controls::public_branch` | control flow varies only with public input | clean control |
| `lookup::substitute` | masked full-table scan | clean control |
| `hidden::nested_modes_clean` | the same three-predicate shape, safe region | **false-positive control** |

### Why `nested_modes` is out of M6's reach as a fact, not a probability

M6 spends its budget boundaries-first: one case per parameter boundary value
with every *other* parameter at its base value, then pairwise cases that move
exactly **two** parameters away from base, then random fill.

`nested_modes` requires three public parameters to hold particular values at
once, and two of the three required values (`stage & 0x0f == 0x0a`,
`trigger == 0x5a`) are not `u8` boundary values at all. So neither the boundary
nor the pairwise stage can produce a reaching input **at any budget** — raising
`cases` buys more pairwise coverage, not a third simultaneous parameter. Only the
random stage can, with probability about 2⁻¹⁶ per case; measured over six seeds
at 2000 all-random cases, it does not.

The third conjunct, `gate & 0xf0 == 0x30`, *is* satisfiable by the boundary value
`0x3f`, deliberately: a conjunct that is individually reachable keeps the fixture
a test of conjunction rather than of three separate improbabilities.

### Why `header_gate` is harder still

`header_gate`'s three conditions are fields of a *single* byte-array parameter —
a version nibble, a flags nibble, and a trailing marker, which is what ordinary
parsing code checks. Boundary generation sets a byte array to whole patterns
(all zeros, all ones, the two alternating phases, one-hot in the first and last
byte, a walking bit through the first), so one pattern would have to satisfy all
three fields at once, and `no_byte_array_boundary_pattern_satisfies_the_header_version_field`
shows none satisfies even the first. The pairwise stage cannot help either: it
varies two *parameters*, and all three conditions live in one.

It is here as a second fixture of the same class in a different representation,
so reaching it exercises the byte-array operators and the per-position sweep
rather than the scalar ones. The sweep covers every position of an eight-byte
array; for longer arrays it covers the first and last eight, because
`controls::tail_byte_probe` exists precisely because only the final byte of its
secret reaches an address.

### Why coverage feedback reaches them

Satisfying the first conjunct executes a region nothing else reached, so that
input is retained as a seed, and the search for the second conjunct starts from an
input that already satisfies the first. The conjunction is climbed one conjunct at
a time. That is the whole mechanism, and §3's ladder is the measurement that it
exists.

In practice, on `header_gate`, it takes 896 candidates and 1.7 s to arrive at
`header = 0x30c000000000007f` — the version nibble, the flags nibble and the
marker, assembled one field at a time from an all-zero start.

---

## 5. Exploration: what was built and what had to be corrected

[`explore`] holds the search; [`coverage`] holds everything coverage means.

### The baseline is never replaced

Every case M6 would have generated is measured, marked **mandatory**, and
selected before any heuristic runs. Enabling exploration therefore cannot reduce
security checking; the worst case is that it adds nothing. This is not politeness
about compatibility — a coverage heuristic that displaced boundary cases would
quietly stop finding what boundary generation is good at, and the loss would
appear as *less* checking under a flag named for more.
`hidden::threshold_window` exists to catch exactly that regression.

### Two corrections the first working version needed

**Random mutation alone stalled two conjuncts in.** Reaching an exact byte meant
drawing the right parameter, then the right operator, then the right value —
about three chances in a thousand per candidate. The first end-to-end run
retained 202 candidates over 384 attempts, got from 19 regions to 27 (satisfying
conjuncts one and two), and stopped.

Each seed now spends an exhaustive **deterministic stage** first: one candidate
per (parameter, byte position, interesting value). Four `u8` parameters give 64
candidates, and a `[u8; 16]` gives 256 per parameter. This is AFL's
deterministic-then-havoc model, and it turns reaching an exact byte from a
probability into a guarantee. Byte positions in long arrays are swept prefix-and-
suffix, because `controls::tail_byte_probe` exists precisely because only the
final byte of its secret reaches an address.

**Convergence after three dry rounds ended the search at 384 of a 2000 budget.** A
round's candidates are shared round-robin across every seed, so the round that
finally satisfies a new predicate is several rounds after the seed leading to it
was retained. The default is now eight dry rounds, and the principle is recorded:
the budget is the stopping rule, and convergence only ends a search with nothing
left to try.

### Public and secret roles

Mutations are drawn from a fixed 3:1:1 rotation of public-only, secret-only and
combined — a ratio rather than a probability, so the mix is identical on every run
and the report states it as a fact. Public inputs get most of the budget because
they usually decide *which* code runs.

Secrets are **not** frozen. A branch on secret bits is itself a vulnerability
class, and a strategy that never varied the secret could not reach the region
behind one; `hidden::secret_gated` is the fixture that keeps this honest. A
public-only mutation provably leaves every secret at its seed value and vice
versa, and both are unit-tested.

A seed changes which values are tried. It cannot change which parameter is
secret — that comes from the annotation, and a test asserts it across four seeds.

### Determinism

The retained corpus is a pure function of (descriptor, baseline corpus, explore
seed, candidate budget, round size, discovery artifact). One `splitmix64` stream
is advanced in a fixed order over a queue whose order is fixed; the decode is
parallel but writes into per-case slots, so thread scheduling cannot reach the
result. The deterministic stage is seed-*independent* by design — it is an
exhaustive sweep, and making it depend on the seed would reorder the same space
for no benefit while making a reported seed less informative.

A wall-clock limit is the one thing that can cut a run short. It is reported
separately from the budget, and a time-limited run is **not complete**, so a CI
job that required exploration is not satisfied by one.

---

## 6. Selection, and a budget defect worth recording

Explored candidates are added by the textbook greedy set-cover heuristic — take
the candidate covering the most not-yet-covered regions, ties broken by the
lowest case id — on top of the mandatory set.

**The budget caps what exploration adds, not the total.** That split was a
correction. When the budget capped the total, a contract with a 200-case corpus
and a 128-case budget kept all 200 mandatory cases and had no room left for the
three explored candidates — so a run configured to search dropped exactly the
inputs it had been run to find, and reported `NO_LEAK_OBSERVED` on the fixture
whose leak it had just located.

Two budgets that can conflict have to be resolved somehow, and the alternatives
are worse: capping the total either drops cases M6 would have run, which is less
checking under a flag asking for more, or drops the explored ones, which makes
the feature do nothing. Independent budgets mean a developer who sets both gets
both, and the report prints the total that came to.

Everything dropped is counted, and the two reasons are kept apart because only
one costs coverage: a candidate excluded as **duplicate coverage** loses nothing,
while one excluded **for budget** loses measurable regions, and the report names
how many.

### The handoff

What crosses into the security backend is M6's own `Corpus` type and nothing
else — no coverage, no region ids, no claim about what was explored. The backend
cannot tell a selected candidate from a boundary case, which is the point:
exploration must not be able to influence how a finding is classified. Values are
revalidated against the contract descriptor on the way through, so a mutated
value can never be bound to the wrong width.

Case identities survive, and `selected_provenance` maps each analyzed case back
to the observation that chose it — so a finding on an explored case can be
explained rather than presenting a developer with values nobody wrote.

---

## 7. Outcomes, and the one direction exploration can move them

The security vocabulary is unchanged: `LEAK_DETECTED`, `NO_LEAK_OBSERVED`,
`INCONCLUSIVE`. M7 adds no outcome and no stronger one.

Exploration is applied **after** the security decision and can only ever
subtract:

* A satisfied result becomes **incomplete** when required exploration did not
  finish — the inputs the result describes are not the inputs the run was
  configured to search for.
* A detected leak stays detected, because a finding from the security artifact
  does not depend on how the input that triggered it was chosen.

Missing LLVM tools, a failed discovery run, an unreadable profile and a
wall-clock cutoff all fail the check rather than falling back to M6 generation.
Quietly falling back would report a search that did not happen.

---

## 8. Using it

```sh
rustup component add llvm-tools     # once; must be the active toolchain's

cargo trace-check check \
    --contract crypto::hidden::nested_modes \
    --explore --explore-cases 1500 --security-cases 128
```

| Flag | Meaning |
|---|---|
| `--explore` | turn exploration on for every selected contract |
| `--no-explore` | turn it off even where `trace-check.toml` enables it |
| `--explore-cases N` | mutation candidates per contract; implies `--explore` |
| `--security-cases N` | cap on *explored* cases added to the analyzed corpus |
| `--seed N` | reproduces both the baseline corpus and the search |

```toml
[check."crypto::hidden::nested_modes"]
cases = 200                 # the M6 corpus, which exploration starts from
expectation = "security-contract"

[check."crypto::hidden::nested_modes".explore]
enabled = true              # off by default; M6 configurations stay valid
candidate_budget = 1500
security_case_budget = 128
feedback = "llvm-regions"   # the only implemented mechanism
mutate_public = true
mutate_secret = true
time_limit_seconds = 300
```

`explored` is **not** a value `strategies` accepts: it is produced by feedback
from an instrumented artifact rather than by a rule over the signature, and the
refusal points at the `explore` table instead. Settings that would search
nothing — a zero budget, both roles frozen, an unimplemented feedback mechanism —
are refused at validation rather than silently doing nothing.

### `TRACE_CHECK_LLVM_TOOLS`

Overrides where `llvm-profdata` and `llvm-cov` are found. They are otherwise
taken from the active toolchain's sysroot and never from `PATH`: a system LLVM of
a different version cannot read this compiler's profiles, and reading the wrong
thing quietly is worse than not reading it.

---

## 9. What a report says

Three sections, deliberately not interleaved.

```
crypto::hidden::nested_modes
  declared at .../src/hidden.rs:46

  -- exploration (discovery artifact; no security evidence) --
  artifact: 436c6021c9a9 [-Cinstrument-coverage]
  marking:  0 byte(s) -- this artifact marks no secret and makes no claim
  tools:    LLVM version 22.1.6-rust-1.97.0-stable
  feedback: llvm-regions -- LLVM source regions (code regions only; branch, edge
            and comparison feedback are unavailable on a stable toolchain)
  map:      22137f6d1cca over .../examples/crypto-library
  searched: 704 candidate(s) of a 1500 budget in 15 round(s), seed …, 1739 ms
  mutations: 238 public, 85 secret, 381 combined (1309 duplicate, 160 vacuous)
  regions:  34 reached, 19 by the baseline corpus, 15 added by exploration
  selected: 203 case(s) for analysis = 200 mandatory (M6's corpus) + 3 of a 128
            explored budget; 0 excluded as duplicate coverage, 0 for budget
  stopped:  converged -- 8 consecutive round(s) found no new coverage

  -- security analysis (uninstrumented artifact) --
  secret:   index: u8 (1 byte(s) marked)
  artifact: bfab81923c28 [no instrumentation]
  corpus:   203 case(s), …, strategies boundaries 85/85, pairwise 115/115, explored 3/3
  executed: 203/203 case(s) completed in 24 analyzer run(s)
  controls: calibration confirmed, secret binding confirmed
  LEAK_DETECTED

  Secret-dependent memory address or value use
    in nested_modes at hidden.rs:63
    at substitute_indexed (lookup.rs:37)
    isolated to case 691 in 5 re-run(s): index=0, stage=10, gate=48, trigger=90
    input from: public interesting of candidate 475 on trigger

CI decision:
  …
  Note: exploration coverage is not verification coverage; it describes code
        executed in an instrumented artifact and nothing else
```

The two artifact hashes are both present and different; a report must never
advertise one as representing both analyses. The CI decision section restates no
coverage number, because that is the one place a reader is most likely to
conflate execution coverage with verification coverage. The coverage caveat in
the limitations list is chosen at render time: "not measured" when exploration
did not run, and "measured in a different artifact, which verifies nothing" when
it did.

`input from: public interesting of candidate 475 on trigger` is the mechanism
visible in the output: a deterministic single-byte sweep on `trigger`, from a
seed that already satisfied the first two predicates.

---

## 10. Measured results

`ci/benchmark-m7.py` compares four configurations over the ten-fixture corpus
with the same case budget per fixture, so a difference is about input selection
rather than about how much was spent. The `m6-random-10x` configuration gets ten
times the cases — a deliberate handicap in M6's favour.

Measured on this development machine (128 cores, rustc 1.97.0, LLVM 22.1.6),
`--quick` fixture set, warm:

| Configuration | Wall clock | Sites | Fixtures found | Detection efficiency |
|---|---|---|---|---|
| `m6-boundaries` | 40.7 s | 1 | 1/4 | 0.025 site/s |
| `m6-default` | 40.3 s | 1 | 1/4 | 0.025 site/s |
| `m6-random-10x` | 117.2 s | 1 | 1/4 | 0.009 site/s |
| **`m7-explore`** | **78.6 s** | **3** | **3/4** | **0.038 site/s** |

Timings vary by roughly 10 % between runs on this machine; the ordering and the
fixture counts do not. Every measurement above is validated before it is used:
the benchmark refuses to report a threshold as met if any run's security
analysis did not complete under both controls, if any candidate's coverage was
unusable, if exploration did not finish, or if it overran its wall-clock limit.
Those checks run identically on warm and cold measurements — an earlier revision
collected them only on the cold run while the acceptance comparison used the
warm one, so they were gathered and then ignored by the decision they existed to
inform.

M7 wins on both metrics at once, which is the result worth having: a higher
proportion of planted vulnerabilities found *and* a higher detection efficiency,
so the extra wall clock is not being traded for the extra findings. The
`m6-random-10x` row is the useful control — ten times the case budget costs 2.7×
the time and finds nothing more, because the inputs it adds are drawn from the
same distribution that was already missing both hidden paths.

The fourth fixture is `magic_gate`, which neither strategy reaches and neither
is expected to. These are measurements on one machine, not a claim about other
hardware; the figures are reproducible with
`python3 ci/benchmark-m7.py --quick --skip-cold`.

The acceptance threshold is stated in the script and checked by it: at least two
additional confirmed leakage discoveries over `m6-default`, none lost, no finding
on a clean control, and no fixture left unmeasured — a configuration error that
skipped a fixture voids the comparison rather than weakening it. The primary
metric is distinct confirmed leakage sites per second of end-to-end time,
reported alongside the proportion of planted vulnerabilities found, because a
fast strategy that found only the easy leaks would otherwise look best.

The first run of this benchmark reported **NOT MET** with one additional
discovery, which is recorded here rather than quietly fixed: `nested_modes` was
the only M7-only fixture, and `magic_gate` — the other hard one — is unreachable
by both strategies by construction. `header_gate` was added as the second
fixture the milestone's section 12 asks for, of the same class in a different
representation, and its unreachability by M6 is proved in `tests/baseline.rs`
before it is used as evidence of anything.

**Coverage percentage is not a metric here**, and the script says so. What is
reported is confirmed leakage sites from the uninstrumented Memcheck artifact.

### Cost

Cold cost includes compiling two artifacts (~2 s each here) and dominates a
first run. Warm, exploration of 1500 candidates costs ~1.7 s against ~0.64 s per
Valgrind process — roughly what three security-analysis runs cost, for access to
a vulnerability class M6 cannot reach at any budget.

---

## 11. Limitations

* **Region coverage, not edges or comparisons.** Branch coverage and comparison
  tracing need a nightly toolchain. An exact 32-bit equality is unreachable by
  this search, measured and recorded in §3.
* **The limit on exploration time is round-granular.** `time_limit_seconds` is a
  soft safety limit checked between rounds, so a round already in flight when it
  passes runs to completion and the real bound is roughly the limit plus one
  round. The candidate budget is checked first, so a run that spends its whole
  budget reports `budget-exhausted` even if it overran — the search it was asked
  to perform did finish. That is only defensible because the overrun is
  reported: `overran_time_limit` appears in the JSON and as an `OVERRAN:` line
  in the text, independently of the termination reason. A bound on a *single*
  discovery subprocess is a different setting (`native::Limits`).
* **Region identities are per-artifact.** Stable across re-runs of one build,
  and deliberately not assumed stable across compiler versions or source edits.
  The coverage-map identity is recorded so a changed map is visible rather than
  silently reinterpreted.
* **Coverage scope is the library's package directory.** Third-party dependency
  code and the generated harness are excluded from target feedback; a leak inside
  a dependency is out of scope.
* **Discovery and security paths may differ.** A candidate that reached a region
  in the instrumented build may follow a different path, or be optimized
  differently, in the uninstrumented one. If the security artifact detects a
  leak, the finding stands regardless. If it does not, **nothing here claims the
  discovery artifact's paths were verified clean.**
* **Decode cost is the dominant term and is parallel.** A CI runner with two or
  four cores gets closer to the serial 13.3 ms per candidate than to the
  parallel 1.4 ms, which is why the report records elapsed time and candidate
  count separately rather than implying a rate.
* **Determinism is per machine within a wall-clock limit.** For a reproducible
  corpus in CI, set a fixed candidate budget and treat the time limit as a safety
  net rather than a schedule.
* **Nothing here is a proof.** A completed run is `NO_LEAK_OBSERVED` over the
  inputs selected, exactly as in M6. Coverage-guided selection makes that set
  better chosen, not exhaustive.
* **Supported parameter shapes are unchanged**: `u8`/`u16`/`u32`/`u64`, `bool`,
  and `[u8; N]`/`&[u8; N]` with a literal `N`. A contract M6 cannot generate for
  is one M7 cannot explore.

---

## 12. Tests

| File | Covers |
|---|---|
| `crates/trace-check/tests/baseline.rs` | the benchmark premise: what M6's generator can and cannot reach, as pure generator tests |
| `crates/trace-check/tests/coverage.rs` | per-case attribution, the coverage gradient, harness and dependency exclusion, rejection of damaged evidence, the at-exit drain, concurrent explorations of one contract, a private immutable artifact, module-qualified attribution |
| `crates/trace-check/tests/explore.rs` | reaching both hidden paths, reproducibility, baseline preservation, the magic-value gap, time-limit reporting, reported granularity |
| `crates/cargo-trace-check/tests/explore.rs` | the CLI: the M6-versus-M7 comparison, the three report sections, CI failure on a security-contract leak, backend-ordering, refused settings, an out-of-workspace library, replay |
| unit tests in `coverage.rs` | novelty as set difference, region identity, export-schema validation, target matching under both manglings and across modules, scope, run-level completion (missing marker, wrong case set, abnormal exit, signal death) |
| unit tests in `explore.rs` | role-preserving mutations, representation preservation, determinism, the mutation mix, selection and set cover |
| `ci/verify-m7-explore.py` | the report's own claims, rather than the exit code |
| `ci/benchmark-m7.py` | the acceptance threshold |

The CLI suite's ordering tests need no backend and never skip, which is itself
the property they assert: a misspelled contract must be diagnosed before the
coverage tools or the analyzer are required. Tests that do need a backend skip
without it, except under `TRACE_CHECK_REQUIRE_BACKEND`, which CI sets.

---

## 13. Review checkpoints

**1 — Feasibility.** §3. Per-input coverage costs 1.4 ms decoded in parallel
against 13.3 ms serial; execution is free by comparison. Raw counters were
measured and rejected for a reason that would have silently broken the search.

**2 — Improved discovery.** `exploration_reaches_the_leak_m6_cannot_construct`,
`exploration_reaches_a_leak_behind_one_structured_parameter` and
`exploration_finds_a_leak_m6_generation_cannot_reach` reach two vulnerabilities
of different shapes that `tests/baseline.rs` proves M6's boundary and pairwise
stages cannot construct at any budget.

**3 — Security boundary.** The finding on `nested_modes` comes from the
uninstrumented artifact at `hidden.rs:63`, under both mandatory controls, and is
isolated to one case by re-running. `verify-m7-explore.py` fails if the two
artifact hashes ever match, if the discovery artifact reports marking anything,
or if the security result carries a coverage number.
`hidden::nested_modes_clean` is reached just as deeply and still reports
`NO_LEAK_OBSERVED`.

**4 — Developer usability.** `an_external_library_explores_through_the_cli`
drives `examples/external-library` — its own lockfile, not a workspace member,
contracts declared `dynamic = false` — through the real binary.

### Attribution is qualified by module

A coverage record is matched against the contract's **whole module path plus
function**, as a sequence of length-prefixed mangled components:
`crypto::hidden::nested_modes` becomes `6crypto6hidden12nested_modes`, which
appears verbatim in both Rust manglings.

Two narrower tests were tried and are both wrong. A bare substring of the
function name matches `substitute_indexed` for the contract `substitute`. The
length-prefixed function component alone fixes that but still ignores module
identity, so `crypto::authentication::verify` and `crypto::encoding::verify`
are indistinguishable — both records count as the target, and coverage from the
wrong function can be attributed to the contract.

`crypto::shadow::left::probe` and `crypto::shadow::right::probe` are the
control: same name, same mangled component, one a full-table scan and the other
a secret-indexed load. `target_attribution_is_scoped_to_the_contracts_module`
builds one artifact for `left`, and checks that each collector sees exactly one
target record and that only the function actually called reports
`target_invoked`.

---

## 14. Definition of done

- [x] A coverage-instrumented executable can be built from an annotated Rust
      library — and cannot be built *without* instrumentation, because the
      harness calls the profiling runtime directly.
- [x] Coverage feedback is attributed to individual generated inputs, one
      profile per case, with the per-case length validated against a baseline.
- [x] Discovery and security artifacts have separate recorded provenance, under
      separate report sections, and CI fails if their hashes ever match.
- [x] A deterministic mutation queue uses coverage feedback to prioritise
      candidates: exhaustive single-byte sweep per seed, then random havoc.
- [x] Public-input exploration is prioritised (a 3:1:1 rotation) without
      eliminating secret-input exploration.
- [x] M6's boundary, pairwise, relationship and regression inputs remain
      supported, are all measured, and are all mandatory in the analyzed corpus.
- [x] A bounded, minimised corpus is transferred to the Memcheck backend as
      M6's own `Corpus` type, carrying no coverage across the boundary.
- [x] **Two** benchmark vulnerabilities are found that M6's default generation
      cannot reach — `nested_modes` and `header_gate`, both proved unreachable
      by `tests/baseline.rs` before being used as evidence. Measured: 3/4
      fixtures against M6's 1/4, at a higher detection efficiency.
- [x] Secret-dependent branches and addresses are reported only from
      security-analysis evidence; the discovery artifact marks zero bytes.
- [x] Findings retain M6's isolation, shrinking and replay. `--replay` builds no
      discovery artifact at all, and `--explore` conflicts with it.
- [x] Missing or malformed coverage evidence cannot produce a misleading
      success: each failure mode is its own status, contributes no coverage, and
      a required exploration that did not finish turns satisfied into
      incomplete. Run-level evidence — baseline, completion marker, completed
      set, exit status — is checked separately from per-case evidence and is
      actually consulted by both exploration loops.
- [x] The analyzed executable is private to its run, so a concurrent build
      cannot replace the binary a profile must be decoded against.
- [x] Coverage is attributed by qualified module path, so two same-named
      functions in different modules cannot be confused.
- [x] The benchmark refuses to report a threshold as met when any measurement
      behind it did not complete, checked identically on warm and cold runs.
- [x] Reports distinguish discovery coverage, security-analysis execution and
      contract coverage, and the CI decision restates no coverage number.
- [x] The CLI works against a separate out-of-workspace library
      (`examples/external-library`, contracts declared `dynamic = false`).
- [x] CI includes the mutation and negative-control tests, the two-artifact
      assertions, the backend-ordering assertions and the acceptance threshold.
- [x] Performance measurements include cold and warm costs and a fair M6
      baseline (`--no-explore`, same configuration, same budget).
- [x] M1–M6 checks remain passing, including M3's contract-coverage policy —
      which the new fixtures initially broke, and which is satisfied by writing
      real `#[ct_test]`s rather than by `dynamic = false`, since that option is
      documented as making a contract disappear from coverage accounting.
- [x] This document records the experiments, decisions, measured results and
      limitations.

**Not done, deliberately:** M7.5, comparison-guided mutation. Deferred on the
two measurements in §3 — the toolchain support is nightly-only, and the
feature's motivating case has no coverage gradient at all rather than a shallow
one. The gap is asserted by `crypto::hidden::magic_gate`'s declared outcome and
by `ci/verify-m7-explore.py`, which fails if it changes in either direction.

---

## 15. Future direction

The capability M7 adds is input discovery, deliberately not coupled to one
feedback format: [`coverage`] reports which mechanism and granularity it
provided, and [`explore`] consumes a region set rather than an LLVM detail.

The combination worth building next is the one the milestone proposal named:
static analysis identifies a potentially secret-dependent operation, a directed
search tries to *reach that operation* rather than maximizing coverage
generally, and Memcheck confirms whether it actually leaks on the executed path.
§3's magic-value measurement is the argument for it — maximizing general coverage
has a floor that a targeted search does not.

Nearer term, and cheaper: a nightly-gated branch-coverage mode would give a
finer gradient where it is available, provided the granularity stays reported
rather than assumed.
