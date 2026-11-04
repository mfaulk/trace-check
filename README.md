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
| M3 | Rust developer API — annotations, assertions, CI | complete |
| M4 | Bounded relational verification (BINSEC symbolic execution) | complete, experimental |
| M5 | Verifying the real functions in a Cargo library | complete, experimental |
| M6 | Generated constant-time testing and CI enforcement | complete, experimental |
| M7 | Coverage-guided leakage discovery | complete, experimental |
| M8 | Complete contract coverage and enforcement | complete, experimental |
| M9 | Real-world cryptography integration — auditing `crypto-bigint` | complete, experimental |
| M10 | Hardware-oriented validation — statistical timing | future |

`trace-check` turns that idea into reproducible analysis, from five directions:

* **Generated dynamic testing** (`check`, experimental) — generate inputs for a
  declared contract and run them under Memcheck, with no hand-written test and
  no container. The annotation already says which parameters are secret and the
  signature supplies their types, so `check --contract my_crate::verify_tag` is
  the whole input. Boundary values first, then pairwise combinations of
  parameters, then seeded random fill; a finding is narrowed back to the single
  input that caused it, reduced, and saved as a replayable reproducer. This is
  the backend that finds a leak hiding behind a *public* mode no hand-written
  test thought to pass. See [docs/MILESTONE-06.md](docs/MILESTONE-06.md).

* **Bounded relational verification** (`verify`, experimental) — compile an
  optimized native target and ask a relational symbolic executor whether *any*
  secret assignment in a declared domain changes the executed path or an
  effective address. When the search completes without finding one, the result
  is `VERIFIED_BOUNDED`: a claim quantified over the whole declared domain
  rather than over the inputs someone happened to test. The target can be a
  **function in your own library**: `verify --contract` generates a harness
  around the real function, so the same `#[constant_time]` annotation drives
  both the dynamic checks and the symbolic search, and you maintain one
  implementation rather than two.

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
cargo trace-check test                           # your own crate's checks (M3)
cargo trace-check check --contract my_crate::verify_tag    # generated inputs (M6)
cargo trace-check check --contract my_crate::verify_tag --explore  # coverage-guided (M7)
cargo trace-check check --all-contracts --ci     # every declaration, enforced (M8)
cargo trace-check coverage                       # which contracts owe what (M8)
cargo trace-check verify --contract my_crate::verify_tag   # your real function (M5)
cargo trace-check verify                         # bundled standalone cases (M4)
cargo run -p trace-check -- native               # native, under Memcheck
cargo run -p trace-check -- screen mac-compare   # static, no execution
cargo run -p trace-check -- demo mac-compare     # dynamic WASM tracing
```

## Using it in your own crate

Write constant-time checks as ordinary unit tests — no harness binary, no JSON
manifest:

```rust
use trace_check_test::{assert_constant_time, ct_test};

#[ct_test(target = "verify_tag")]
fn verify_tag_is_constant_time() {
    let supplied = [0u8; 32];

    let accepted = assert_constant_time!(
        secret = secret_tag(),
        call = |expected| verify_tag(expected, &supplied),
    );

    // The macro evaluates to the call's value, so functional assertions work too.
    assert!(!accepted);
}
```

```sh
cargo trace-check test                          # build, discover, run under Memcheck
cargo trace-check test --filter verify_tag      # one check
cargo trace-check test --format json            # machine-readable
cargo trace-check list                          # what would run
```

Each check runs in its own process, and each one first runs a **positive
control** that proves secret marking actually reaches compiled code — without
it, a clean result would mean nothing. Plain `cargo test` keeps working without
Valgrind: the checks are `#[ignore]`d, so libtest reports them as `ignored` with
the reason, never as passing tests.

Secrets are passed **by value** so the optimizer cannot fold past the marked
storage. Supported: `secret = value` for `[u8; N]` and integer scalars,
`secrets = (a, b)` for two, and `secret_bytes = slice` for a `&[u8]`. `Vec<u8>`
and `String` are rejected at compile time, because marking a `Vec` would mark
its pointer, length and capacity and none of the heap data.

`#[constant_time(secret = "expected")]` declares a contract on a function. It
emits the function verbatim — no production behavior change — plus, under
`#[cfg(test)]`, an invocation counter and a `<function>_ct` **analysis adapter**
that takes the declared secret by value, marks it, and calls the untouched
function with it in its declared slot. Tests call the adapter, so a contract is
`covered` only when a test ran clean *and* provably exercised the function with
its declared secret marked — a test cannot invoke the contract with public
inputs, nor route the marked value to a different parameter.
Contracts are identified by module-qualified path, so two modules may each
define `verify` without one shadowing the other.

Start from [`examples/consumer-crate`](examples/consumer-crate/README.md), which
demonstrates clean cases, detected branch and address leaks, and an untested
contract.

| Exit | Meaning |
| --- | --- |
| `0` | every required check executed and met its contract |
| `1` | one or more constant-time violations detected |
| `2` | incomplete analysis — inconclusive, zero checks selected, missing Valgrind, untested contract |

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

The native backends add `LEAK_DETECTED`, and the symbolic backend adds
`VERIFIED_BOUNDED`. The two clean results are deliberately different words:

| Outcome | Produced by | Claim |
| --- | --- | --- |
| `NO_LEAK_OBSERVED` | `native`, `test` | Nothing was seen on the paths these inputs took. Says nothing about any other input. |
| `VERIFIED_BOUNDED` | `verify` | No secret assignment **in the declared domain** changes the path or an address, for this artifact, under the modeled observations. |

Neither is a proof of constant-time security in general: `VERIFIED_BOUNDED` is
scoped to a declared input domain, an exploration bound, one compiled artifact,
and a model that excludes cache, speculation, operand latency, and every other
hardware effect.

The static screen reports per-function findings instead, of three kinds:
`secret_dependent_branch`, `secret_dependent_address` (an identical
instruction path whose memory access pattern still varies), and
`secret_dependent_call_target`. A `select` with a secret condition is reported
as informational, not a leak: it is branchless, which is the point.

**Execution coverage is not verification coverage.** `check --explore` measures
which regions of a library an input reached, in an **instrumented** artifact
built for that purpose. A region reached there may be reached by different
machine code, or not reached at all, in the optimized artifact a security result
describes. Coverage decides which inputs are worth analyzing and verifies
nothing; a report that confused the two would be claiming the stronger of two
very different things.

See [docs/limitations.md](docs/limitations.md) for the full boundary, and
[docs/methodology.md](docs/methodology.md) for the threat model and procedure.

## Why four backends: the gap each one closes

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

| Leak | M1 differential tracing | M1 static screen | M2 native Memcheck | M4/M5 symbolic |
| --- | --- | --- | --- | --- |
| secret-dependent branch | detected | flagged structurally | detected, with source location | detected, with address |
| secret-dependent address | **invisible** | flagged structurally | **detected** | **detected** |
| quantified over all inputs | no | yes | no (executed paths only) | yes, over a declared domain |
| analyzes native code | no (WASM) | no (WASM) | yes | yes |
| needs concrete secrets | yes | no | yes | **no** |
| analyzes your library's own function | yes | yes | yes | yes, since M5 |

M2 and M3 still miss a leak that sits on a path no test takes:

```rust
fn conditional_lookup(table: &[u8; 256], secret: u8, public_mode: u8) -> u8 {
    if public_mode == 0 { constant_time_scan(table, secret) }
    else                { table[secret as usize] }
}
```

A test exercising only `public_mode == 0` reports `NO_LEAK_OBSERVED` and is not
wrong — that path really is constant time. M4 searches the public domain and
finds the other one. That case is bundled as `conditional-lookup`, and
`examples/crypto-library`'s `substitute_mode` is the same asymmetry in a real
library: its M3 dynamic check passes while
`verify --contract crypto::lookup::substitute_mode` finds the leak.

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

* **Rust** — pinned by [`rust-toolchain.toml`](rust-toolchain.toml) (1.97.0,
  the `wasm32-unknown-unknown` target, and the `llvm-tools` component).
  `rustup` installs all three automatically.

  `llvm-tools` supplies the `llvm-profdata` and `llvm-cov` that
  `check --explore` reads. They must come from the active toolchain — a system
  LLVM of another version cannot read this compiler's profiles — so they are
  located from the sysroot and never from `PATH`.
  `TRACE_CHECK_LLVM_TOOLS` overrides the directory.
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

* **Valgrind 3.28.0 or newer** plus its client-request headers, for `native`
  and `cargo trace-check test`. On Debian/Ubuntu: `apt-get install valgrind`.

* **A container runtime and the pinned analyzer image**, for `verify` only.
  The analyzer is pinned by **digest**, not tag, so the solver linked inside it
  is pinned with it:

  ```sh
  podman pull docker.io/binsec/binsec@sha256:19a0ff4b0278906bd6f00a5752cab19e8cad7153715cecf32d4f885826f62967
  ```

  Docker works too; with both installed, the runtime that *holds* the image is
  the one used, and `--container-runtime` or
  `TRACE_CHECK_CONTAINER_RUNTIME` overrides the choice. `verify` refuses to run
  if no runtime has the image, rather than skipping and reporting success.
  Nothing else needs it: a developer without a container runtime can still run
  every other command.

## Commands

### `check` — generated constant-time testing

```sh
cargo trace-check check --contract crypto::lookup::substitute_mode
cargo trace-check check --all-configured --ci
cargo trace-check check --all-contracts --ci                        # M8
cargo trace-check check --contract my_crate::verify_tag --cases 128 --seed 12345
cargo trace-check check --contract my_crate::verify_tag --explore   # M7
cargo trace-check check --replay failure.json
```

Generates inputs for a declared `#[constant_time]` contract and runs them under
Memcheck. No hand-written `#[ct_test]` and no container: the annotation names
the secret and the signature supplies the types, so a minimally supported
contract needs no configuration at all.

Why it exists: a hand-written dynamic check exercises the inputs someone thought
of. `examples/crypto-library` has the demonstration — `substitute_mode` takes a
public `mode`, its leak is on the `mode = 1` path, and its hand-written check
passes `mode = 0` and honestly observes nothing. Generated inputs reach the other
path without anyone naming it.

**Generation.** Deterministic and seeded, spent in a fixed order: boundary
values per parameter (zero, one, maxima, powers of two and their neighbours,
and for byte arrays the all-zero, all-ones, alternating, one-hot and
last-byte-only patterns), then pairwise combinations of parameters, then seeded
random fill. Boundary coverage is a **hard** guarantee: a budget too small to
cover every parameter's boundary values is refused, naming the contract and the
minimum, because those are the cheap high-value cases. Pairwise is quadratic and
explicitly best-effort, and a report names what it dropped. Persisted regressions replay *first* and can never be crowded out
by the budget. Supported shapes are the ones the contract descriptor models:
`u8`/`u16`/`u32`/`u64`, `bool` for a public parameter, and `[u8; N]` or
`&[u8; N]` with a literal length. Anything else is refused with the type as
written, never given a guessed value.

Uniform random generation is close to useless for some shapes — two random
16-byte tags essentially never match — so relationships between equal-length
byte arrays are opt-in:

```toml
[[check."crypto::tag::verify_tag".relationships]]
left = "expected"
right = "supplied"
kind = "equal"          # or differ-first-byte, differ-last-byte,
                        # differ-one-bit, share-prefix
```

**Finding an input, not just a leak.** Cases run in batches, because Valgrind
startup dominates: 256 cases in one process cost about what one case costs.
But Memcheck consolidates repeated diagnostic sites, so a batch where one case
leaks and a batch where every case leaks are *indistinguishable* in its output —
the error count is not a leak count. A batch that reports a finding is therefore
re-run over shrinking subsets until one case reproduces it, which takes
⌈log₂ n⌉ extra processes. A finding that will not narrow is **kept**, reported
as sequence-dependent with its batch preserved, because dropping a finding for
resisting attribution is the one outcome a security tool cannot have.

An isolated input is then reduced, and a candidate is accepted only when the
*same* finding still reproduces — a panic or a different diagnostic is a
different bug, not progress. `--reproducer-dir` writes a versioned JSON
reproducer per finding; `--replay` runs one back, verbatim: order, multiplicity
and values are preserved, because a leak that needs two identical calls cannot
be reproduced by one.

A replay reports three outcomes, not two. `NOT_REPRODUCED` is only ever
returned when a complete, instrumented, calibrated run establishes the
finding's absence; anything else is `INCONCLUSIVE` and fails. An infrastructure
failure must never read as a fixed vulnerability. Only one combination passes:
the finding is gone **and** the artifact changed — losing a finding on an
unchanged build is a contradiction, not a fix.

**Completion is evidence, not a count.** Every marker the generated harness
prints carries a per-run nonce, so the function under analysis — which shares
the harness's stdout — cannot forge one, and a final run-completion marker is
required because nothing a per-case marker says rules out the process dying
immediately afterwards.

**Two positive controls, not one.** Calibration proves marking reaches compiled
code in this binary. It cannot prove that *this contract's* secret reached the
function, because it marks its own byte and passes either way — so each case
also hands the bytes it is about to pass to a second probe. A run where that
probe is silent is `INCONCLUSIVE`, never clean.

**CI policy.** A `[check."…"]` entry declares what it asserts:

| `expectation` | Meaning | A detected leak |
| --- | --- | --- |
| `security-contract` (default) | the function must satisfy the property | fails the build |
| `analyzer-regression` | trace-check must produce a stated result on a known-vulnerable example | is that fixture passing |

A security contract **cannot declare an `expected_outcome` at all** — the schema
refuses it. That is what stops a stray expectation from turning a real leak into
a green build, and it is why this project's own deliberately vulnerable fixtures
have to say `expectation = "analyzer-regression"` out loud.

| Exit | Meaning |
| --- | --- |
| `0` | every selected contract satisfied what it asserted |
| `1` | a leak was detected against a security contract |
| `2` | incomplete — inconclusive, zero cases, a control that did not confirm, an unmet regression expectation, or `--ci` with contracts skipped |

`--all-configured` is deliberately not called `--all-contracts`: it covers what
`trace-check.toml` names, **not** every annotation in the source tree, and the
report says so. `--ci` adds the guarantee that no configured contract was
skipped.

Reports distinguish three things that are easy to conflate: *contract coverage*
(which contracts were checked), *input-strategy coverage* (which planned input
categories were generated, with per-strategy planned/emitted counts), and
*execution coverage* (which code paths ran) — which is not measured unless
`--explore` is passed, and is named as absent either way. The fraction of
generated inputs executed is not a fraction of secret values proven safe.

#### `--explore` — coverage-guided input discovery (M7)

```sh
rustup component add llvm-tools     # once; must be the active toolchain's

cargo trace-check check --contract crypto::hidden::nested_modes \
    --explore --explore-cases 1500 --security-cases 128
```

Generated inputs are a fixed set of guesses, and a leak behind a *conjunction*
of public conditions is not in it. `examples/crypto-library` has that
demonstration too: `crypto::hidden::nested_modes` guards its secret-indexed load
behind three public predicates, and because boundary generation moves one
parameter away from base and pairwise moves two, **neither can construct a
reaching input at any budget**. `crates/trace-check/tests/baseline.rs` proves
that rather than asserting it.

`--explore` builds a *second* artifact with `-Cinstrument-coverage`, runs
candidate inputs in it, and keeps the ones that reach library regions nothing
has reached before. Satisfying the first predicate reaches a new region, so that
input becomes a seed, and the search for the second predicate starts from one
that already satisfies the first — a conjunction gets climbed one conjunct at a
time. The kept inputs are then analyzed by the **same Memcheck backend**, which
cannot tell them from boundary cases.

| Flag | Meaning |
| --- | --- |
| `--explore` | turn exploration on for every selected contract |
| `--no-explore` | turn it off even where `trace-check.toml` enables it |
| `--explore-cases N` | mutation candidates per contract; implies `--explore` |
| `--security-cases N` | cap on *explored* cases added to the analyzed corpus |

```toml
[check."crypto::hidden::nested_modes".explore]
enabled = true              # off by default; M6 configurations stay valid
candidate_budget = 1500
security_case_budget = 128
feedback = "llvm-regions"   # the only implemented mechanism
mutate_public = true        # public inputs get most of the budget...
mutate_secret = true        # ...but secrets are not frozen: see below
time_limit_seconds = 300
```

**Coverage guides testing and establishes nothing.** The two artifacts are kept
apart by construction, not by convention. The discovery artifact marks no secret
and does not even depend on the marking crate, so it *cannot* produce
secret-dependence evidence — and because it calls the LLVM profiling runtime
directly, it does not even link without instrumentation, which makes "coverage
is active" a property of the binary existing. Reports carry both artifacts'
hashes under separate sections, and the discovery section prints that it marked
zero bytes.

**Exploration can only ever weaken a result.** It is applied after the security
decision: a satisfied result becomes incomplete when required exploration did
not finish, because the inputs the result describes are not the inputs the run
was configured to search for. A detected leak stays detected, because a finding
does not depend on how its input was chosen. Missing LLVM tools, an unreadable
profile and a wall-clock cutoff all fail the check rather than falling back to
M6 generation — a silent fallback would report a search that did not happen.

**M6's corpus is never replaced.** Every case M6 would have generated is kept
and analyzed; exploration adds to it, and `--security-cases` caps what it adds
rather than the total. A coverage heuristic that displaced boundary cases would
quietly stop finding what boundary generation is good at —
`crypto::hidden::threshold_window` is the fixture that would catch it.

**Secrets are explored too.** Public inputs get most of the budget because they
usually decide which code runs, but a branch on secret bits is itself a
vulnerability class and a strategy that never varied the secret could not reach
the region behind one. A seed changes which values are tried; it can never
change which parameter is secret.

**Attribution is qualified.** A coverage record is matched against the
contract's whole module path plus function, as length-prefixed mangled
components. Matching the bare name would confuse `substitute` with
`substitute_indexed`; matching the function component alone still ignores module
identity, so two same-named functions in different modules would both count as
the target. `crypto::shadow::left::probe` and `crypto::shadow::right::probe`
are the control — same name, opposite verdicts.

**What it will not find.** The available feedback is LLVM *source regions* —
branch coverage, edge coverage and comparison tracing all need a nightly
toolchain, and the report says so in those words rather than implying a finer
search. Region coverage offers no gradient toward an exact 32-bit equality: the
feasibility spike measured sixteen random tokens producing byte-identical
coverage. `crypto::hidden::magic_gate` records that gap as a declared
`NO_LEAK_OBSERVED`, and CI fails if it ever changes in either direction.

See [docs/MILESTONE-07.md](docs/MILESTONE-07.md) for the measurements, and
[docs/spikes/m7-coverage-feedback/](docs/spikes/m7-coverage-feedback/README.md)
for the reproducible feasibility experiments.

#### `--all-contracts` — enforce every declaration (M8)

```sh
cargo trace-check check --all-contracts --ci
```

`--all-configured` selects **configuration keys**. A contract with no
`[check."…"]` entry was therefore not merely unchecked — it was *invisible*, and
a run that never considered it reported success.

`--all-contracts` selects **declarations**. `#[constant_time]` emits a record
into the compiled library, and the inventory reads every record back, so a new
annotation is enforced from the moment it compiles — no configuration entry, no
test, no registry to remember.

| Flag | Meaning |
| --- | --- |
| `--all-contracts` | every `#[constant_time]` declaration in the selected build |
| `--all-configured` | every explicitly configured generated check (M6's meaning, unchanged) |

The two stay distinct: reinterpreting the first would silently change what an
existing CI job enforces, so `--all-contracts` emits its own schema-2 report.

**Every contract is accounted for, even one the tool cannot analyze.** Each
declaration gets an explicit status per required analysis:

| Status | Meaning |
| --- | --- |
| `CHECKED` | the required analysis completed and passed |
| `LEAK_DETECTED` | the required security property was violated |
| `INCONCLUSIVE` | it ran and did not establish the required outcome |
| `UNSUPPORTED` | the declaration cannot be analyzed by that backend — an unmodellable signature, or a function that is not `pub` and so cannot be named by the generated harness |
| `NOT_SELECTED` | applicable, and left out of the run |
| `NOT_ANALYZED` | required, runnable, and no backend reported a result — carrying why, so "not requested" is distinguishable from "ran and said nothing" |
| `BACKEND_UNAVAILABLE` | the analyzer or instrumentation is absent |
| `INACTIVE` | configured, and not compiled into the selected build |
| `EXEMPTED` | an explicit, policy-approved waiver |

A status is *not* a security outcome. It says whether a required analysis
happened; what it observed is reported separately as evidence, in the backends'
own vocabulary, so `NO_LEAK_OBSERVED` and `VERIFIED_BOUNDED` are never
interchangeable and a generated run never discharges a symbolic requirement.

Two read-only commands, because inspecting obligations is a different activity
from enforcing them:

```sh
cargo trace-check list --contracts     # the compiler-derived inventory
cargo trace-check coverage             # the matrix, running no analysis
cargo trace-check coverage --format json
```

#### Assurance policy and waivers

```toml
[policy]
mode = "strict"                   # or "advisory"
default_required = ["generated"]  # symbolic is not required of everything
allow_empty_inventory = false   # an empty inventory is not silently a pass
allow_inactive_config = false   # one config file across feature variants

[policy.contracts."crypto::tag::verify_tag"]
required = ["generated", "symbolic"]

[[policy.exemptions]]
contract = "crypto::legacy::operation"
analyses = ["generated"]
reason = "unsupported field-element parameter type"
tracking = "https://github.com/example/project/issues/42"
expires = "2027-03-01"
```

Absent a `[policy]` table the defaults apply, so an existing `trace-check.toml`
gains enforcement without being edited.

Waivers exist because the alternative is worse: a developer facing an
unsupported signature otherwise has one way to make CI pass, which is to delete
the annotation and the security requirement with it. They are deliberately
awkward to write — an empty `analyses` list is refused rather than read as
waiving everything, a missing `reason` is refused, strict mode wants an `expires`
date or an explicit `never_expires`, a malformed or impossible date
(`2027-02-31`, which has no February 31st) is a configuration error rather than
a waiver that never lapses, and a waiver naming no active declaration is
reported as stale.

Stale configuration blocks, because a typo, a renamed function and a removed one
look identical from the configuration's side. `allow_inactive_config = true` is
for the one case where they do not: a single `trace-check.toml` deliberately
serving several feature variants, where entries for contracts the selected build
does not compile are then reported `INACTIVE` rather than blocking. It has to be
written down because only a developer knows which situation it is.

**A waiver waives the obligation to perform an analysis. It never waives or
erases what an analysis found.** It is applied before anything runs, evidence is
folded in afterwards, and a detected leak overwrites a waived status — never the
reverse. Waived obligations are also excluded from the checked total, so a waiver
cannot inflate the proportion actually checked.

#### What a complete inventory does and does not mean

It means every record was extracted from the selected compiled artifact. It does
**not** mean every source file was compiled, every feature combination checked,
every dependency inventoried, or any function constant-time. Discovery is scoped
to one library target under one feature selection, and an inventory records which
compilation it describes.

M8 enforces *declared* obligations. It does not discover functions that ought to
carry a declaration, and a function with no annotation is not accounted for at
all. That sentence is in every report.

See [docs/MILESTONE-08.md](docs/MILESTONE-08.md) for the method and its limits,
and [docs/spikes/m8-contract-inventory/](docs/spikes/m8-contract-inventory/README.md)
for the reproducible feasibility experiments — including the two findings that
shaped the mechanism: `llvm-objcopy --dump-section` silently loses records, and
an LTO rlib holds bitcode rather than ELF.

### Auditing somebody else's library (M9)

Everything above analyzes code written in this repository.
[`examples/crypto-bigint-audit`](examples/crypto-bigint-audit/README.md) analyzes
[RustCrypto `crypto-bigint`](https://github.com/RustCrypto/crypto-bigint)
`0.7.10`, consumed as an ordinary pinned crates.io dependency with **no upstream
source change**:

```sh
cargo trace-check check --all-contracts --ci \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml
```

Thin adapters decode a declared-secret `&[u8; 32]` with the library's own
`U256::from_be_slice`, call the library's own operation, and fold all 32 result
bytes. Three operations are covered: `U256::wrapping_add`,
`CtSelect::ct_select`, and `ConstMontyForm::mul` modulo the P-256 prime. A
contract covers that **whole invocation** — decoding, the library's types, its
operation, and the result consumption — so a clean result on the adapter, read
alone, is indistinguishable from a harness that marked nothing.

Seven controls are what make it mean something, and all seven are detected: a
branch on a decoded limb, on an interior limb, on the final secret byte alone,
on the `Limb` carry `Uint::carrying_add` *returned*, a load address derived from
the decoded sum, and a selection written with an `if` instead of `CtSelect`.
They are declared `expected_outcome = "LEAK_DETECTED"`, so if one stops being
detected the run fails on an unmet expectation rather than reporting a clean
sweep.

That last pair is the demonstration worth looking at first: the library's
selection compiles to four `test`/`cmovne` pairs through the `cmov` crate and
is clean, while the same function written with a branch is found. And nothing is
read as a security result before `cargo test` passes — 1012 vectors whose
expected values were computed in Python's arbitrary-precision integers, which
share no code with the library under audit, compared at the operation's full
32-byte width rather than through the lossy output sink.

The decisive evidence is that changing the **library**, not the harness, flips
the verdict. Three mutations do, in three different files:

```sh
python3 ci/mutate-m9.py --mutation mutation-c-indexed-reduction \
  --contract cbaudit::monty::mul_secret_left \
  --expect-outcome LEAK_DETECTED --expect-frame src/modular/mul.rs \
  --expect-class address --verify-reproducer --compare-clean
```

The driver stages the pinned source into an isolated copy, applies an explicit
patch, requires the adapter's own functional tests to still pass, and runs the
unchanged contract. For the one above, the finding's leaf frame is
`montgomery_multiply_inner (src/modular/mul.rs:106)` — upstream source, at the
patched line — classified as a secret-dependent **address**, with its
reproducer replayed against the same artifact. A branch in `Uint::carrying_add`
and a branch inside the library's own `CtSelect` are the other two.

`--expect-class` is not decoration: a tool that modelled only control flow
would report that secret-indexed load as clean. And the clean and mutated
artifact hashes must differ or the run fails. A stale patch and a mutation in a
function that is never called both fail as invalid experiments instead of being
reported as clean.

The same eighteen contracts also go through the **symbolic** backend, and all
eighteen settle with zero `INCONCLUSIVE` — including 256-bit Montgomery
multiplication, in four seconds. Relational verification of branchless code is
cheap no matter how wide the arithmetic is: the cost scales with paths and
observations, not with term size, and constant-time code has one path. Reaching
that took fixing a real blocker — the freestanding artifact failed to link with
`undefined symbol: rust_eh_personality` for any library with more than one
dependency, which no in-repo example could have surfaced. See
[docs/audits/crypto-bigint/symbolic-feasibility.md](docs/audits/crypto-bigint/symbolic-feasibility.md).

Input discovery was measured too, on fixtures where the leak hides behind a
*public* predicate: `m6-default` finds 2 of 5, `m6-random-10x` finds **1** (ten
times the budget, random-only, so it never generates the boundary value one
gate needs), `m7-explore` finds 3, and the symbolic backend finds all 5. The two
rows no dynamic strategy reaches are declared as such, so the limits stay
measured — one is an exact 32-bit equality that region coverage has no gradient
toward, and the other is the *same* gate as a fixture M7 does find, missed only
because its public surface is 35 bytes instead of 3.

The one integration hazard this turned up: two adapters whose bodies compile
identically are folded to one symbol, and a finding in either then cannot be
attributed — reported as `INCONCLUSIVE`, never as clean. See
[docs/MILESTONE-09.md](docs/MILESTONE-09.md) for that and the other four
findings, [docs/adapter-guide.md](docs/adapter-guide.md) for how to write an
adapter for a different library,
[docs/audits/crypto-bigint/adoption.md](docs/audits/crypto-bigint/adoption.md)
for what the whole thing cost and the five engineering changes it points to,
and [docs/audits/crypto-bigint/](docs/audits/crypto-bigint/threat-model.md) for
the analysis boundary. **None of it is a claim that `crypto-bigint` is
secure:** it is three operations, under two modeled observations, on one
artifact.

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

### `verify --contract` — verifying the real functions in your library

```sh
cargo trace-check verify --contract crypto::tag::verify_tag \
  --manifest-path crypto/Cargo.toml
cargo trace-check verify --all-contracts --manifest-path crypto/Cargo.toml
cargo trace-check verify --all-contracts --format json
cargo trace-check verify --all-contracts --artifact-dir ./evidence
```

This is the form that analyzes **your** code. You keep one implementation,
annotated as M3 already requires:

```rust
#[constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}
```

and add a `trace-check.toml` beside your `Cargo.toml` for the bounds and the
observation model, which cannot be inferred from an annotation:

```toml
schema_version = 1

[verify."crypto::tag::verify_tag"]
max_depth = 8000
checks = ["control-flow", "memory-access"]
expected_outcome = "VERIFIED_BOUNDED"
```

The configuration never restates which parameters are secret. Roles come from
the annotation, and a configuration that tries to assign one is **rejected**
rather than honored — a second description of the contract is exactly the drift
this avoids. Public parameters are symbolic and held equal between the paired
executions by default; nothing is silently fixed to a convenient value.

`trace-check` then reads the contract descriptor the annotation emitted,
generates a freestanding `no_std` harness around your real function, links your
library into it through Cargo, resolves the contract to exactly one compiled
symbol, and hands the artifact to the same analyzer M4 uses:

```text
Verifying crypto::tag::verify_tag

Library:
  Package:        crypto-library 0.1.0
  Contract:       crypto::tag::verify_tag  (/…/crypto/src/tag.rs:18)
  Cargo features: (default)
  Lockfile:       sha256 9819fe81…

Compilation:
  rustc:          rustc 1.97.0 (2d8144b78 2026-07-07)
  Target:         x86_64-unknown-linux-gnu
  Profile:        release: opt-level=3, debug=true, lto=off, codegen-units=1
  Panic strategy: abort

Analyzed function:
  Resolved symbol: _RNvNtCshFxKWjWxWCA_6crypto3tag10verify_tag
  Address:         0x201520
  Target reached:  yes, at 0x201520 from tc_verify_entry (analyzer-reported)
  Call shape:      laundered function pointer (out-of-line instance)

Verification executable:
  Harness sha256:    6be0682e…
  Artifact sha256:   bbdee307…
  Production binary: not analyzed: …

Input domain:
  expected   secret  &[u8; 16]    128 bits, all symbolic
  supplied   public  &[u8; 16]    128 bits, symbolic and held equal

Result: VERIFIED_BOUNDED
```

Generated harnesses and the executables built from them live in a private
directory created for the run and removed afterwards — a result is pinned to its
artifact's **hash**, not to a path, and every report says whether the path it
records still exists. Pass `--artifact-dir DIR` to keep the evidence bundle;
each run still gets its own freshly created directory inside `DIR`.

If your library is `no_std` and carries no dynamic tests, annotate with
`#[constant_time(secret = "key", dynamic = false)]`. That drops the
`#[cfg(test)]` adapter M3 uses — the part that needs `trace-check-test` and
`std` — so `cargo test` still compiles with the macro crate as your only
dependency. It is opt-out rather than opt-in on purpose: a contract without the
adapter also disappears from `cargo trace-check test`'s coverage accounting, and
that should take a deliberate keystroke.

**What this is and is not.** The *function* analyzed is compiled from the single
definition in your library — change its body and the verdict changes, which is
the project's standing regression for this claim. Its *surroundings* are not
production: the harness is freestanding, its inputs are globals, the build uses
no LTO, and the target is called through a laundered function pointer so
cross-crate inlining cannot dissolve it. That last one is a deliberate trade:
without it a small library function leaves no symbol at all and nothing can be
attributed to it, but it means the verified instance is an out-of-line copy. The
report states all of this, and never claims a production binary was analyzed.

Supported signatures are deliberately narrow: `u8`/`u16`/`u32`/`u64`,
`[u8; N]` and `&[u8; N]` with a **literal** `N`, and `bool` for a public
parameter; return types are scalars or `bool`. A `bool` input gets a *generated*
domain restriction, reported alongside your own assumptions and kept separate
from them — BINSEC reasons about machine bytes, and a symbolic byte has 256
values where Rust's `bool` has two. Anything else is an actionable
error naming the parameter and its type — including `&[u8; TAG_LEN]`, because a
proc macro sees the token `TAG_LEN`, not its value, and a guessed width marked
into the analysis would make a verified result meaningless. See
[docs/MILESTONE-05.md](docs/MILESTONE-05.md) and
[examples/crypto-library/README.md](examples/crypto-library/README.md).

### `verify` — bounded relational verification of bundled cases (experimental)

```sh
cargo trace-check verify                        # every bundled case
cargo trace-check verify --case table-lookup    # one case
cargo trace-check verify --format json
cargo trace-check verify --cases path/to/cases.json
cargo trace-check verify --container-runtime docker
```

These are M4's hand-written standalone targets, kept because they isolate
analyzer behavior from Cargo linkage. Both forms share one engine: the
classification, witness extraction and fail-closed rules below apply to
`--contract` runs identically.

Builds `examples/symbolic/src/targets.rs` as an optimized freestanding
`x86_64` ELF, then runs BINSEC's relational symbolic execution (`-checkct`) over
it. Each case declares which globals are secret, which are public, where
analysis starts and halts, any `assume` constraints on the input domain, and
the outcome it expects.

```text
Case: trip-count
  secret-dependent loop trip count: a branch that survives optimization

Function:
  secret_trip_count
  reached at 0x2016c0 from tc_harness_trip_count

Observation model:
  checked:     control-flow noninterference, memory-address noninterference
  NOT checked: (nothing -- every modeled property was checked)

Result:
  LEAK_DETECTED
  7 divergence site(s): 7 secret-dependent branch(es), 0 secret-dependent memory access(es)

Divergence:
  Secret-dependent control flow at 0x2016c4
    secret_trip_count (targets.rs:78)
  ... 6 more, one per surviving iteration

Witness:
  concrete inputs: solver_counterexample
    the values below are the solver's own model, read back from the analyzer's cached query
  TC_SECRET = #xfe vs #xff  (from query_10.smt2)

Analysis:
  paths 8 of 8 explored, 0 pending
  checks: 8 / 15 control flow, 35 / 35 memory access
  unknown solver answers 0, depth bound 2000, max depth reached 30
  exploration complete: true
```

Classification is **fail-closed**. A clean verdict becomes `VERIFIED_BOUNDED`
only if the run also shows complete exploration, zero `unknown` solver answers,
every requested class of obligation fully discharged, and analyzer-produced
evidence that the declared function was reached. Anything else is
`INCONCLUSIVE`.

Three things that follow from that, worth knowing before reading a result:

* **A result is attributed to a function only on evidence.** Each script
  carries a `reach <function>` directive; without the analyzer's matching
  "reached address" line, a case naming a function the harness never calls is
  `INCONCLUSIVE` rather than inheriting the harness's verdict.
* **A result is only as strong as its declared observation model.**
  `secret_lookup`'s instruction path is genuinely secret-independent, so under
  control-flow checks alone it reports `secure` — a legitimate but narrow
  result. Every report prints what was checked and what was not.
* **Counterexamples come from the solver, where one exists.** `-smt-dir` makes
  the analyzer cache each query with its model; a query over both a secret and
  its `mirror_` copy is the relational one, and that pair is the witness. Leaks
  the analyzer settles by taint analysis without a satisfiability query have no
  model, and the report says so instead of inventing a pair.

This is the one backend whose result is a statement about *all* secrets in a
domain. It is also the narrowest in scope: see
[docs/MILESTONE-04.md](docs/MILESTONE-04.md) and
[examples/symbolic/README.md](examples/symbolic/README.md).

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
| `0` | `demo`: every declared expectation reproduced. `screen`: every declaration held and the census did not drift. `compare`: `NO_DIFFERENCE_OBSERVED`. `verify`: every selected case met its declared expectation. |
| `1` | `demo`: an expectation was not reproduced. `screen`: a finding, an unmet declaration, or baseline drift. `compare`: `DIFFERENCE_DETECTED`. `verify`: a violation was found where none was expected. |
| `2` | Error or `INCONCLUSIVE`: missing backend, build failure, timeout, trap, unparseable trace, missing symbol, invalid case file. |

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
  src/symbolic.rs                BINSEC relational verification backend
  src/symbolic_report.rs         symbolic text and JSON reporting
  src/contract.rs                contract descriptors and trace-check.toml
  src/harness.rs                 generating and linking a verification harness
                                 around a real Cargo library function
  src/library_report.rs          contract verification text and JSON reporting
  src/generate.rs                deterministic typed input generation (M6)
  src/coverage.rs                per-case LLVM coverage from the discovery artifact (M7)
  src/explore.rs                 coverage-guided mutation, seed queue and selection (M7)
  src/inventory.rs               compiler-derived contract inventory, ar + ELF reader (M8)
  src/enforcement.rs             required analyses, statuses, policy and waivers (M8)
  src/coverage_report.rs         the contract matrix and the CI decision (M8)
  src/dynamic_harness.rs         generating a std harness around a real library
                                 function, and batched Memcheck execution
  src/check.rs                   batching, failure isolation and shrinking
  src/reproducer.rs              persisted reproducers and replay
  src/check_report.rs            generated-testing reporting and CI policy
crates/trace-check-secret/       secret marking for Memcheck (C shim)
crates/trace-check-test/         developer API: assert_constant_time!, ct_test
crates/trace-check-macros/       the ct_test and constant_time attributes
crates/cargo-trace-check/        the `cargo trace-check test`, `check` and
                                 `verify` subcommands
  tests/integration.rs           fixture and end-to-end tests
  tests/fixtures/                compact captured traces
examples/mac-compare/            the example, its cases.json, screen.json
                                 and committed artifact-baseline.json
examples/table-lookup/           the secret-indexed address-leak example
examples/native-cases.json       native case manifest with expectations
examples/consumer-crate/         using trace-check as a dependency (M3)
examples/symbolic/               freestanding targets + cases.json for `verify`
examples/crypto-library/         an ordinary no_std library whose real functions
                                 are both dynamically tested and symbolically
                                 verified, plus its trace-check.toml (M5)
examples/external-library/       the same workflow for a crate outside this
                                 workspace, with its own lockfile (M5)
examples/crypto-bigint-audit/    audit adapters over RustCrypto crypto-bigint
                                 0.7.10, consumed unmodified as a pinned
                                 dependency, with the propagation controls and
                                 1012 independently computed vectors (M9)
examples/legacy-branch-demo/     original proof of concept, kept for context
docs/                            milestone plan, methodology, limitations
docs/audits/crypto-bigint/       the M9 target selection, threat model,
                                 integration report, findings and the
                                 symbolic feasibility matrix
docs/spikes/m6-generated-harness/ the recorded M6.1 feasibility spike
docs/spikes/m7-coverage-feedback/ the recorded M7.1 feasibility spike
docs/spikes/m8-contract-inventory/ the recorded M8.1 feasibility spike
ci/verify-m3-consumer.py         asserts the M3 consumer report, not its exit code
ci/verify-m4-symbolic.py         asserts the M4 symbolic report, not its exit code
ci/verify-m5-library.py          asserts the M5 contract report, not its exit code
ci/verify-m6-generated.py        asserts the M6 generated report, not its exit code
ci/verify-m7-explore.py          asserts the M7 coverage-guided report, not its exit code
ci/benchmark-m7.py               M6-versus-M7 discovery benchmark and acceptance threshold
ci/verify-m8-contracts.py        asserts the M8 coverage report, not its exit code
ci/benchmark-m8.py               contract-discovery overhead at 0/10/50/100 declarations
ci/benchmark-m6.py               generated vs hand-written effectiveness benchmark
ci/gen-m9-vectors.py             the independent Python oracle for the M9
                                 adapters; --check guards fixture drift
ci/benchmark-m9.py               M6 against M7 on the external integration
ci/mutate-m9.py                  one upstream-mutation experiment, with the
                                 validity checks that make its outcome earned
ci/verify-m9-integration.py      asserts the M9 audit report, not its exit code
ci/mutations/                    the explicit patches those experiments apply
docs/adapter-guide.md            writing an audit adapter for another library
.github/workflows/ci.yml         pinned Linux CI (M1-M3/M6-M9 job + M4/M5 analyzer job)
```

## Development

```sh
cargo test --workspace --lib --bins       # fast suite, no backends needed
cargo test --workspace                    # 653 tests; backend tests skip without WABT/Valgrind
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
