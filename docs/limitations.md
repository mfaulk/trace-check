# Limitations

The central claim of this project is narrow, and the distance between what is
observed and what is often inferred is the thing most worth being precise about.

## What a result is a statement about

A `trace-check` finding describes **one compiled WASM module**, executed by
**one pinned interpreter version**, over **one finite set of test vectors**. The
report records the module's SHA-256, the Rust and WABT versions, and the build
target and profile for exactly this reason: change any of them and the result
has to be re-established.

## `NO_DIFFERENCE_OBSERVED` is not proof of security

Matching instruction paths over the tested inputs do not establish constant-time
behavior. The outcome is named for what was observed rather than what might be
concluded.

Specifically, it does **not** rule out:

* a path difference at an untested input,
* secret-dependent **effective memory addresses** along an identical instruction
  path (the subject of Milestone 2),
* secret-dependent **instruction latency** — a variable-latency division or
  multiplication is invisible to this analysis,
* cache, branch-predictor, prefetcher, or speculative-execution effects,
* anything about the native code a different compilation would produce.

## `VERIFIED_BOUNDED` is the strongest result here, and still not a proof

The symbolic backend (`verify`) is the only one whose clean result quantifies
over inputs rather than sampling them. When it reports `VERIFIED_BOUNDED` it
has established: for the **declared** secret and public globals, within the
**declared** `assume` constraints and the exploration depth bound, and under
the **declared** observation classes, no secret assignment changes what those
classes observe, in **this one** compiled artifact, in a function the analyzer
reported reaching.

When the target is a contract in a real library (`verify --contract`), the
*function* is the library's own, compiled from the single definition in its
source — but three differences separate the analyzed executable from a
production build, and none of them is glossed:

* the target is called through a laundered function pointer, so the verified
  instance is an **out-of-line copy**. Without that, rustc's cross-crate
  inlining of small functions dissolves the target and leaves no symbol to
  attribute anything to; with it, a production caller that inlines the function
  gets code the run did not analyze,
* the surroundings are a freestanding `no_std` executable whose inputs are
  named globals,
* the build uses no LTO, `panic = "abort"` and static relocation.

Every contract report records all three, and records that no production binary
was analyzed. It also records the *build*, the artifact hash, the lockfile
fingerprint and the resolved symbol **per contract**, because a run builds one
executable per contract and no single artifact describes the whole report.

Where a Rust type uses fewer byte patterns than its machine representation
allows — `bool` is the supported case — the generated harness restricts the
input's domain and the report names the restriction separately from the
developer's own assumptions. Without that the analyzer would reason about
states the compiled program can never be in, and the reported input domain
would not be the domain that was searched.

Everything outside those words is unestablished. In particular it does **not**
rule out:

* a leak outside the declared input domain, or beyond the depth bound — a case
  that stops early is `INCONCLUSIVE`, never verified,
* secret-dependent **instruction latency**; BINSEC has experimental
  multiplication and division checks and they are deliberately off,
* cache, branch-predictor, prefetcher, or speculative-execution effects,
* anything about a different build. The artifact's SHA-256, the `rustc`
  version, and the exact flags are recorded because a recompilation
  invalidates the result,
* anything about the *surroundings* of the function. The analyzed artifact is a
  freestanding `no_std` harness whose inputs are globals; the function under
  test is ordinary optimized Rust, but its calling context is not.

A differing execution path is also not a measured timing signal. The solver
proves that two executions diverge; nothing in this project measures what that
divergence costs on real hardware. That is Milestone 5.

Two further scoping rules decide what a result may be read as saying.

**A result covers only the observation classes its case declared.** Each case
lists them explicitly and every report prints both `checked_features` and
`unchecked_properties`. This matters because the two are easy to confuse:
`secret_lookup`'s instruction path really is secret-independent, so under
control-flow checks alone the analyzer reports `secure`. That verdict is
correct and says nothing whatever about the secret-dependent address the same
function contains.

**A result is attributed to a function only on the analyzer's own evidence that
exploration reached it.** The entry symbol decides what gets explored, so a
case naming a function its harness never calls would otherwise inherit the
harness's verdict. Each generated script carries a `reach <function>`
directive, and without the matching report the outcome is `INCONCLUSIVE`.

Where a counterexample exists it is the solver's own model, read back from the
analyzer's cached query — never constructed here. Where the analyzer settled a
leak without issuing a satisfiability query there is no model, and the report
records `unavailable_from_analyzer` with that reason rather than manufacturing
a witness. A counterexample necessarily contains the declared secret globals'
values, which is why case inputs must be synthetic.

## `DIFFERENCE_DETECTED` does not quantify a vulnerability

An observed path difference is evidence of secret-dependent program behavior. It
is not a measurement. The analysis does not establish:

* how large the resulting timing difference is in wall-clock terms,
* whether that difference is observable across a network or by a co-located
  attacker,
* how many queries an attacker would need,
* whether the difference survives into a native build at all.

Instruction counts in this tool are counts of *interpreted* instructions. They
are not cycle counts and should not be read as a timing model.

## Interpreter findings do not transfer to native code

The experiment analyzes WASM executed by WABT's stack-based interpreter. A
native build of the same Rust source is a different compilation through a
different backend to a different instruction set, and it may branch where the
WASM does not or vectorize where the WASM does not.

The `early_exit` variant is the concrete demonstration available here: identical
Rust source yields a branchless XOR/OR tree in optimized WASM. The same source
compiled natively, at a different optimization level, or by a different compiler
version may retain the branch. A result for one artifact is not a result for
another.

## The "constant time" label

`verify_constant_time` uses the `subtle` crate, which is designed for
constant-time comparison and is a reasonable choice. "Constant time" there
describes an *intended property* that depends on the compiler, target and
platform cooperating — not a guarantee the crate can enforce. This project
treats `subtle` as a negative control whose actual compiled behavior is
measured, not assumed, and it does not certify the crate.

No part of this tool labels code "secure" or "verified constant-time", and
output deliberately avoids that vocabulary.

## Static screening adds its own limits

The `screen` command is a screen, not a proof. Three properties bound it:

* **Secrets are declared, not discovered.** The analysis knows which values are
  secret only because the config says so. A wrong declaration produces a
  confident wrong answer, in either direction.
* **Taint does not flow through memory.** A store of a secret value does not
  taint later loads, so analysis must target the function where secrets arrive
  at the boundary. Screening a wrapper that spills its arguments to memory
  reports a false clean.
* **Control flow is over-approximated.** Findings are candidates to confirm,
  not confirmed leaks. Loop-carried taint is attributed to the whole function.

A function containing an unmodeled operator yields no verdict, and that counts
as inconclusive — never as clean.

"Zero findings" therefore means: no *declared* secret reaches a branch, address
or indirect call target, in *this* compiled module, under the *modeled*
instruction subset. It does not mean the function is constant-time.

The Tier 0 baseline gate makes an even narrower claim. It asserts only that the
compiled shape of the screened functions has not changed since the baseline was
recorded. A passing gate is not a security property; a failing gate is a prompt
to go inspect the artifact.

## Scope boundaries by construction

Out of scope for the WASM backend (Milestone 1), by design rather than by
omission. Native instrumentation arrived in M2 and bounded symbolic
verification in M4; the rest remains out of scope for the project as a whole:

* native instrumentation and hardware-level measurement — *M2 added Valgrind
  Memcheck; hardware measurement is still absent*,
* memory-address analysis — *M2 and M4 both detect secret-dependent addresses;
  cache-line behavior is still unmodeled*,
* statistical timing measurement,
* secret-taint analysis or automatic discovery of which inputs are secret,
* exhaustive path coverage — *M7 searches for inputs that reach new code; it
  does not enumerate paths and does not bound what it missed*,
* automatic security classification of unannotated functions — *M8 enforces
  declared obligations and does not discover which functions should have one*,
* instrumentation of arbitrary crates or full protocol integrations,
* general-purpose constant-time certification.

Out of scope for the symbolic backend (Milestones 4 and 5), by instruction: no
custom symbolic execution engine, no custom SMT solver, no heap modeling or
dynamic allocation, no concurrency, no unbounded loops or recursion, no
automatic verification of arbitrary crates, no automatic verification of every
`#[constant_time]` annotation, and no proof certification.

M5 connected M3's contracts to that backend, within a deliberately narrow
subset of Rust signatures: `u8`/`u16`/`u32`/`u64`, `[u8; N]` and `&[u8; N]`
with a **literal** `N`, and `bool` for a public parameter; scalar or `bool`
returns. Slices, `Vec`, `String`, structs, references to structs, generics,
trait methods, `async` and methods are all refused with an actionable error. So
is `&[u8; TAG_LEN]`: a proc macro sees the token, not its value, and a guessed
width marked into the analysis would make a verified result meaningless. A
library that needs `std` cannot be linked into the freestanding artifact at
all.

## Execution coverage is not verification coverage

Milestone 7 added coverage-guided input discovery, which introduces a second
compiled artifact and a second kind of number, and the distance between those
numbers and a security claim is the thing most worth being precise about here.

The discovery artifact is built with `-C instrument-coverage`. Its machine code
differs from the artifact a security result describes: instrumentation changes
code generation, and the two builds may inline, vectorize and lay out
differently. So:

* **A region reached during exploration may not be reached in the security
  artifact at all**, or may be reached by different instructions.
* **A clean result from the discovery artifact means nothing.** It marks no
  secret and cannot observe secret dependence; it does not even depend on the
  marking crate.
* **A region count is not a fraction of anything verified.** "34 regions
  reached" says 34 regions of an instrumented build executed. It does not bound
  the secret values checked, the paths of the production binary, or the
  completeness of the search.
* A report therefore carries both artifacts' hashes, in separate sections, and
  the CI decision restates no coverage number.

The feedback available on a stable toolchain is **source regions**. Branch
coverage, edge coverage and comparison tracing are nightly-only, and reports say
so in those words: region coverage and edge coverage are not interchangeable,
and using one word for the other would claim a finer search than was run.

Region coverage also offers no gradient toward an exact wide comparison. The
feasibility spike measured sixteen random 32-bit tokens producing byte-identical
coverage against a `token == 0x5a17c0de` guard — two reachable states with
nothing observable between them. A leak behind such a guard is **not** reachable
by this search, and `crypto::hidden::magic_gate` records that as a declared
expectation rather than leaving the gap implicit.

What coverage guidance does change is which inputs get analyzed, and only that.
Every security conclusion still comes from the uninstrumented Memcheck artifact
under the same two positive controls, and a completed run is still
`NO_LEAK_OBSERVED` over the inputs selected — better chosen, not exhaustive.

## A complete contract inventory is not a security claim

Milestone 8 added contract discovery, and "complete coverage" is a phrase worth
being precise about, because it invites exactly the wrong reading.

A **complete inventory** means every `#[constant_time]` record was successfully
extracted from the selected compiled artifact. It does not mean:

* every source file in the repository was compiled,
* every Cargo feature combination was checked,
* every dependency was inventoried,
* every compiled function is constant-time,
* or that any secret value was tested.

**Enforcement coverage** is the proportion of *declared requirements* that were
met, excluding waived ones from both sides of the ratio. It is not the
proportion of secret inputs proven safe, and it says nothing about functions
that carry no declaration. It is reported as absent rather than as 100 % when
nothing was owed.

An **enforcement status** is not a security outcome. `CHECKED` says a required
analysis completed and passed; how strong that is depends entirely on which
analysis it was, and a generated dynamic check is `NO_LEAK_OBSERVED` over the
inputs it ran. Status and evidence are therefore separate fields in every
report, and a requirement for one analysis is never discharged by another.

Two scope limits are structural rather than incidental:

* **Declared obligations only.** M8 enforces what someone declared. It does not
  and cannot discover functions that *ought* to carry a declaration, so an
  unannotated function handling a secret is invisible to all of this. Automatic
  security classification of unannotated functions is an explicit non-goal.
* **One compilation.** An inventory describes one library target under one
  feature selection for one target triple. Another feature combination may
  declare different contracts and compile the same contract to different
  machine code, so inventories carry a build identity and nothing merges their
  evidence.

An **exemption** records that an obligation was waived. It establishes nothing
whatsoever about the contract. It cannot suppress a detected leak: waivers are
applied before any analysis runs, and evidence of a violation overwrites a
waived status rather than the reverse.

Finally, discovery is **ELF-specific**. The records are read from a `#[used]`
static in a named section of the library's own `rlib`; Mach-O and COFF would
each need their own section-table reading, and the supported platform is Linux
x86-64.

## Reading the fixture's expectations

`cases.json` declares an expected outcome per comparison, and the demo exits
non-zero when one is not reproduced. That gate asks "did the experimental
controls behave as predicted?" — it is not a security verdict. An unmet
expectation most often means the compiler changed, and the correct response is
to inspect the new artifact, not to adjust the expectation to match.
