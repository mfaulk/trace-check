# Milestone 05 — Verification of real Rust library functions

**Status:** Implemented — see [Implementation status](#implementation-status)
**Backend:** BINSEC relational symbolic execution, reused unchanged from M4
**New capability:** the function analyzed symbolically is the one the developer
ships, compiled from the single definition in their library

## Objective

M4 proved the analysis works on optimized native Rust. What it analyzed was
`examples/symbolic/src/targets.rs` — a purpose-built `no_std` file holding both
the verification targets *and* their harnesses. A developer could not point it
at their own code.

M3 independently gave developers a way to *declare* a constant-time contract:

```rust
#[constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool { … }
```

M5 connects the two. After it:

```sh
cargo trace-check test                              # M3: dynamic, Valgrind
cargo trace-check verify --contract crypto::tag::verify_tag   # M5: symbolic
```

both analyze code compiled from **one** definition of `verify_tag`.

### The three levels, and which one M5 delivers

| Level | What is analyzed | M5 |
| --- | --- | --- |
| Same algorithm | a rewritten approximation | **rejected** |
| Same Rust implementation | the original library function, compiled and linked into a verification harness | **delivered** |
| Same deployed machine code | the exact instructions in the production binary | future work |

The distinction is not pedantry. A freestanding verification harness makes the
compiler emit different machine code from a production executable — and in one
specific way M5 *deliberately* causes, documented under
[The artifact boundary](#the-artifact-boundary). The milestone is to record that
difference, not to imply it away.

## What M5 reuses

Nothing in the symbolic engine changed. `symbolic.rs` builds a BINSEC script,
runs the analyzer in the digest-pinned container, parses its output, classifies
fail-closed, and extracts witnesses. M5 adds a **second artifact source** in
front of it and a **second report** behind it.

```text
                         ┌──────────────────────────────────┐
  M4: examples/symbolic  │                                  │
      rustc one file ───►│  symbolic.rs                     │──► symbolic_report.rs
                         │  BINSEC · checks · classify ·    │
  M5: a Cargo library    │  witnesses · provenance          │──► library_report.rs
      generated harness ►│                                  │
      + cargo build      └──────────────────────────────────┘
```

Two explicit artifact-building paths over one verification engine, as the plan
directs — not a generic compiler abstraction.

## Checkpoint 1 — cross-crate feasibility (gate, passed)

Run before writing any generator, against the same pinned analyzer M4 uses
(`binsec 0.11.2`, image digest
`sha256:19a0ff4b…f62967`) and `rustc 1.97.0`. A hand-written `no_std` harness
crate took the library as an ordinary Cargo path dependency; its source contained
no copy of any algorithm.

### Experiment A — compile and link an ordinary Cargo library

A two-package layout — library + `#![no_std] #![no_main]` harness binary —
built with

```sh
cargo build --release --target x86_64-unknown-linux-gnu
```

and `rustflags = ["-C","panic=abort","-C","relocation-model=static",
"-C","link-arg=-nostdlib","-C","link-arg=-static"]`, produced a 7.7 KB static
ELF with exactly seven symbols: the three globals, `_start`, the entry, the halt
symbol, and `crypto::verify_tag`. BINSEC reported:

```text
[sse:result] Path 0 reached address 0x2012b0 (<_RNvCs35547BFpf74_6crypto10verify_tag>) (0 to go)
[checkct:result] Program status is : secure (0.038)
[checkct:info] 1 / 1 control flow checks pass
[checkct:info] 82 / 82 memory access checks pass
             total paths  1 / completed 1 / pending 0 / max depth 88
```

**A real Cargo library function verified through the M4 engine.** Four findings
shaped everything after it.

**A1. `--target` must be passed explicitly.** Cargo only applies
`[target.<triple>].rustflags` to target-kind units when the target is named, so
without it the freestanding link flags would also hit host build scripts and
proc-macro crates. Naming the triple is also what makes the recorded target
provenance true rather than assumed.

**A2. The artifact path is read from Cargo, never constructed.** The development
machine has a global `CARGO_TARGET_DIR`; a guessed
`target/<triple>/release/<name>` path did not exist. The executable comes from
`--message-format=json`, the same discipline `discover.rs` already uses for test
binaries.

**A3. `_start` must exist and must reach the entry.** `#![no_main]` plus
`-nostdlib` leaves the linker with no entry symbol, and anything `_start` does
not reach is dropped as dead code. The first multi-entry harness silently lost
two entry symbols that way. M5 therefore generates **one harness package per
contract**, with a single entry `_start` tail-calls.

**A4. SSE code is fine.** `subtle`'s `ct_eq` over `[u8; 16]` vectorizes to
`pcmpeqb` / `pmovmskb`. BINSEC modeled it and discharged 221 memory-access
obligations, so a third-party `no_std` dependency inside the analyzed artifact
is not a problem.

### Experiment B — the original function is reached, and its bug is found

Rebuilding the same harness against a library whose `verify_tag` had a
secret-dependent early exit:

```text
[sse:result] Path 0 reached address 0x2012b0 (<…6crypto10verify_tag>) (0 to go)
[checkct:result] Instruction 0x2012b5 has control flow leak
…15 sites…
[checkct:result] Program status is : insecure
[checkct:info] 16 / 31 control flow checks pass
             total paths 16 / completed 16 / pending 0
```

Finding a symbol with the right name is not the evidence; `reach <symbol>` plus
the analyzer's own `reached address` line is, exactly as in M4.

**B1. The symbol name cannot be predicted.** `crypto::verify_tag` compiles to
`_RNvCs35547BFpf74_6crypto10verify_tag` — v0 mangling with a crate
disambiguator hash that moves when the package version, path or metadata
changes. It is also a **local** symbol (`t`, not `T`), so it is not reachable by
linker name. M5 resolves it by demangling the artifact's symbol table
(`nm -C`) and matching the qualified contract identity exactly. Zero matches and
more than one match are both explicit errors.

**B2. Small library functions are inlined across crates, and vanish.**
`substitute_indexed` — a four-instruction secret-indexed load — left **no symbol
at all**. This is not LTO: rustc marks small non-generic functions
cross-crate-inlinable by default, so the library's MIR is available to the
harness's codegen unit. A verifier that trusted the function name would have
reported on the harness.

The fix keeps the library's source untouched. The generated harness reifies the
target as a function pointer and launders it:

```rust
let f: fn(&[u8; 16], &[u8; 16]) -> bool = crypto::verify_tag;
core::hint::black_box(f)(&expected, &supplied)
```

Taking the address forces a distinct, callable instance to be emitted, and the
`black_box` stops the optimizer from recovering the direct call. It holds even
for `#[inline(always)]`, which was checked. BINSEC resolves the indirect call
concretely — the pointer is a link-time constant — so path counts and check
counts are unaffected.

This is the explicit design decision the plan asks for: **M5 does not add
`#[inline(never)]` to production functions**, and it does not rely on the hint
either. It makes the *harness* responsible for keeping the target callable, and
pays for it in the artifact boundary below.

### Experiment C — the verdict follows the library

The regression that defines the milestone. With the harness, the configuration
and the generated script all unchanged, only `verify_tag`'s body was rewritten:

| Library implementation | Analyzer verdict | Outcome |
| --- | --- | --- |
| fold every byte, no early exit | `secure`, 1/1 cf, 82/82 mem | `VERIFIED_BOUNDED` |
| early exit on the first differing byte | `insecure`, 15 control-flow sites | `LEAK_DETECTED` |

Nothing but the library changed. The result cannot be keyed on a case name, a
declared expectation, or a copy of the algorithm, because there is no copy to
key on.

**C1. The compiler erased the naive early exit — again.** Written plainly,
without volatile reads, `verify_tag_early_exit` vectorizes at `opt-level = 3`
into the same branchless `pcmpeqb` sequence as the constant-time version, and
BINSEC correctly reports `secure`. This is the **fifth** recorded instance in
this project (WASM in M1, native SIMD in M2, M3's calibration probe, M4's
`erased-branch`). The vulnerable library variant therefore keeps its volatile
reads and says so in its doc comment; the erased variant is kept as an
educational case with `VERIFIED_BOUNDED` as its *declared* expectation.

**C2. A closed-form loop is not a branch either.** A first attempt at a
"final secret byte only" control used the final byte as a loop trip count.
LLVM solved `diff += 1` repeated `n` times in closed form and emitted no
branch — `secure`. The surviving final-byte control uses the byte as a **load
index** instead, which produces a memory-access divergence at `0x20178b`:

```text
[checkct:result] Instruction 0x20178b has memory access leak
[checkct:result] Program status is : insecure
```

That case is the one that catches a harness which marked only the pointer, only
the first byte, or the wrong width.

**Gate verdict: passed.** All three experiments work, so the milestone proceeds
to automatic generation.

## The artifact boundary

Three differences separate the analyzed executable from a production build of
the same library. All three are recorded in every report, and none is glossed.

| Difference | Why it exists | Consequence |
| --- | --- | --- |
| The target is called through a laundered function pointer | otherwise cross-crate inlining dissolves it and nothing can be attributed (B2) | the verified instance is an **out-of-line** copy. A production caller that inlines the function gets code this run did not analyze |
| The surroundings are a freestanding `no_std` binary whose inputs are `static mut` globals | BINSEC declares its security lattice by symbol name, and there is no runtime to explore | the *function* is ordinary optimized Rust; its callers and its memory layout are not |
| No LTO, `panic = "abort"`, `relocation-model=static`, `-nostdlib -static` | needed to link freestanding and to keep the target out of line | a production profile with `lto = true` is a different artifact and must be re-verified |

Every report says this in words as well as fields, and the JSON carries
`production_artifact: "not analyzed"` alongside the hashes of what was.

## The developer-facing workflow

An ordinary library crate:

```rust
// crypto/src/tag.rs
use trace_check_macros::constant_time;

#[constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}
```

Its `trace-check.toml`, next to `Cargo.toml`:

```toml
schema_version = 1

[verify."crypto::tag::verify_tag"]
max_depth = 8000
solver_timeout_secs = 30
checks = ["control-flow", "memory-access"]
expected_outcome = "VERIFIED_BOUNDED"
assumptions = []

[verify."crypto::tag::verify_tag".inputs]
supplied = "public-symbolic"
```

The configuration **never restates the secret**. Roles come from the
annotation, and a config that tries to assign one is rejected rather than
honored — see [Roles are not configurable](#roles-are-not-configurable).

```sh
cargo trace-check verify --contract crypto::tag::verify_tag \
  --manifest-path crypto/Cargo.toml
```

```text
Verifying crypto::tag::verify_tag

Library:
  Package:        crypto-library 0.1.0
  Contract:       crypto::tag::verify_tag  (/…/crypto-library/src/tag.rs:18)
  Cargo features: (default)
  Lockfile:       sha256 3f0a…

Compilation:
  rustc:          rustc 1.97.0 (2d8144b78 2026-07-07)
  Target:         x86_64-unknown-linux-gnu
  Profile:        release, opt-level=3, debug=true, lto=off
  Panic strategy: abort
  Link:           -nostdlib -static, relocation-model=static

Analyzed function:
  Contract:       crypto::tag::verify_tag
  Resolved symbol: _RNvCs35547BFpf74_6crypto3tag10verify_tag
  Address:        0x2012b0
  Target reached: yes (analyzer-reported)
  Call shape:     laundered function pointer (out-of-line instance)

Verification executable:
  Harness sha256:  a19c…      (generated, not written into your source tree)
  Artifact sha256: 7d41…
  Production binary: NOT analyzed

Input domain:
  expected  secret  [u8; 16]   128 bits, all symbolic
  supplied  public  [u8; 16]   128 bits, symbolic and held equal

Observation model:
  checked:     control-flow noninterference, memory-address noninterference
  NOT checked: (nothing — every modeled property was checked)

Result: VERIFIED_BOUNDED
```

## Contract metadata

M3's annotation knew the function's identity and which parameters were secret.
M5 needs widths, positions, representations and a return shape, and must get
them from the **declaration itself** so they cannot drift.

### Where the metadata lives

`#[constant_time]` now emits, *unconditionally* and beside the verbatim
function, three `#[doc(hidden)]` constants whose visibility matches the
function's:

```rust
#[doc(hidden)] pub const __TRACE_CHECK_MODULE_verify_tag: &str = module_path!();
#[doc(hidden)] pub const __TRACE_CHECK_SITE_verify_tag: &str = concat!(file!(), ":", line!());
#[doc(hidden)] pub const __TRACE_CHECK_CONTRACT_verify_tag: &str = "{…}";
```

The JSON is built by the macro from the parsed signature. A `&'static str`
const costs nothing: it is not emitted unless something reads it, so a
production build of the library is byte-identical to one compiled without M5.

This is the answer to M3's `#[cfg(test)]` problem. The contract adapter, the
invocation counter and the metadata *test* stay test-only — they are M3's
dynamic-coverage machinery and have no business in a library build. The
*descriptor* does not, so it is always there, and the verification harness links
the ordinary library build.

### How the verifier reads it

A generated single-expression probe crate takes the library as a path
dependency and prints the two constants:

```rust
fn main() {
    print!("{}\u{1}{}\u{1}{}",
        crypto::tag::__TRACE_CHECK_MODULE_verify_tag,
        crypto::tag::__TRACE_CHECK_SITE_verify_tag,
        crypto::tag::__TRACE_CHECK_CONTRACT_verify_tag);
}
```

A `\u{1}` separator rather than nesting the descriptor inside more JSON: the
descriptor is already JSON and the other two fields are a module path and a
`file:line`, so a byte none of them can contain is simpler than another layer
of escaping.

`cargo run` on it either prints authoritative metadata or fails to compile, and
each failure is a different actionable error:

| Probe failure | Reported as |
| --- | --- |
| no such constant | `crypto::tag::verify_tag has no #[constant_time] contract` |
| constant not visible | `the contract must be `pub` to be verified from outside its crate` |
| no such module path | `no module `crypto::crypt` in package crypto-library` |

Source parsing was rejected as the alternative: `cfg`, macros and `include!`
make a text scan either wrong or a second parser to maintain.

### The harness is bound to the metadata it was generated from

The generated harness embeds the exact descriptor it was built from and compares
it against the library's own at compile time:

```rust
const CONTRACT: &str = "{…}";
const _: () = {
    let (a, b) = (CONTRACT.as_bytes(), crypto::__TRACE_CHECK_CONTRACT_verify_tag.as_bytes());
    assert!(a.len() == b.len());
    let mut i = 0;
    while i < a.len() { assert!(a[i] == b[i]); i += 1; }
};
```

If the library's signature changes between the probe and the harness build, the
harness does not compile. Combined with the call itself — written with the real
parameter types, so a wrong length or a wrong order is a type error — the Rust
compiler, not this tool, is what certifies the argument mapping.

### Supported shapes

Deliberately small for the first version.

| Parameter type | M5 | Symbolic representation |
| --- | --- | --- |
| `u8`, `u16`, `u32`, `u64` | supported | fixed-width symbolic global |
| `&[u8; N]`, literal `N` | supported | `N` symbolic bytes; the pointer is public and stable |
| `[u8; N]` by value, literal `N` | supported | `N` symbolic bytes passed by value |
| `bool` | supported as a **public** parameter only | one symbolic byte, with a *generated* `<= 1` constraint — see [Modeling Rust's valid values](#modeling-rusts-valid-values) |
| several secret parameters | supported | independent symbolic objects |
| `&[u8]` | deferred | needs a pointer/length model |
| `Vec<u8>`, `String` | deferred | needs heap and ownership modeling |
| structs, references to structs | deferred | needs layout and alias analysis |
| generics, trait methods, `async`, methods | rejected by the macro | already rejected in M3 |

Return types: integer scalars and `bool`. Anything else is an actionable
verifier error.

Named constants in array lengths (`&[u8; TAG_LEN]`) are **deferred**: a proc
macro sees the token `TAG_LEN`, not `32`, and guessing is worse than refusing.
The error names the parameter and suggests the literal. `examples/consumer-crate`
keeps using `TAG_LEN` and keeps working under M3; it is simply not verifiable
symbolically yet, which the error says.

An unsupported *shape* is rejected by the verifier rather than by the macro, so
an existing M3 contract keeps compiling. The macro records such a parameter as
`{"repr":"unsupported","rust_type":"&[u8]"}` and the verifier refuses the run,
naming the parameter and its type.

### Roles are not configurable

`[verify."…".inputs]` accepts `"public-symbolic"` — the default, which may be
stated explicitly — and nothing else. In particular `"secret-symbolic"` is an
error:

```text
error: trace-check.toml maps `expected` to "secret-symbolic", but parameter roles
       come from #[constant_time(secret = …)] on the function, not from
       configuration. Declared secrets: expected. Remove the override.
```

A configuration file that could promote or demote a secret would be a second
description of the contract, which is the drift the milestone forbids. Public
parameters are symbolic and **held equal** between the paired executions by
default; nothing is silently fixed to zero.

### Modeling Rust's valid values

BINSEC reasons about machine bytes; Rust's types do not all use every byte
pattern. `bool` is the case that matters here: one byte, two valid values. An
unconstrained symbolic byte would let the analyzer reason about 256, so the
reported input domain would not be the domain that was searched — and
`read_volatile::<bool>` on an invalid byte is undefined behavior the compiled
program can never actually perform.

The generator therefore emits a domain restriction per such input and the
report names it, separately from the developer's own assumptions so those stay
verbatim:

```text
  enabled    public  bool         8 bits, symbolic and held equal
  generated: TC_PUBLIC_ENABLED <= 1  (so the analyzed domain is Rust's valid values)
```

Generated restrictions are placed ahead of declared ones in the script, so the
analyzer never sees a state the program cannot be in. `ci/verify-m5-library.py`
requires every `bool` input to carry one, requires it to appear in
`generated_domain`, and requires it to appear as an `assume` in the script the
analyzer was actually given — three independent places, because the field
alone could be decorative.

Every other supported representation uses all of its bytes, so no restriction
is emitted and an unexplained one is a validator failure.

## Where generated files live

A verification run writes a Cargo manifest, a `.cargo/config.toml`, a Rust
source file and a linked executable. The first revision put them under
`/tmp/trace-check-contract-verify-<pid>`, which is guessable: on a shared
machine another user can pre-create that directory or plant a symlink there and
have those writes follow it, and stale files from an earlier run can be picked
up by a later one. The same class of problem was closed in the dynamic
backends; it is closed the same way here.

| | |
| --- | --- |
| **Default** | a private directory created atomically by `tempfile` and chmod'ed `0700`, removed when the run ends. A result is pinned to its artifact's **hash**, so nothing is lost. |
| `--artifact-dir DIR` | a freshly created, randomly named run directory *inside* `DIR`. The caller owns `DIR`; the run directory is still created atomically, so nothing pre-existing there is reused or written through, and two runs never collide. |

Per-contract subdirectories use `create_dir`, not `create_dir_all`: inside an
atomically created private root nothing can pre-exist, so an `AlreadyExists`
means two contracts collided on a name and is reported rather than written
into.

Because the default workspace does not survive the run, every report states
whether the artifact path it records still exists — `path_retained` — so a
reader is never invited to trust a dangling path. M4's `verify` build directory
was derived from the process id in the same way and is now created the same
way.

## Generated harnesses

One package per contract, in a temporary directory. The generator never writes
to the user's source tree, and its output is deterministic — same contract, same
configuration, same bytes, so the harness hash is a meaningful provenance field.

A generated harness must:

1. declare one `#[no_mangle] pub static mut` global per supported parameter,
   named `TC_SECRET_<PARAM>` or `TC_PUBLIC_<PARAM>`, typed exactly as the
   parameter's owned form;
2. give referenced arrays their own non-overlapping storage;
3. read each global through `read_volatile` into a local, so the value genuinely
   comes from the memory BINSEC made symbolic;
4. pass each secret into **its** parameter slot, positionally, in a call written
   with the real types;
5. reify and launder the call so the target stays out of line (B2);
6. write the return value to `TC_OUT` through `write_volatile` so the call
   cannot be optimized away;
7. halt at `tc_halt`, and keep the entry alive from `_start`;
8. contain no copy of any part of the library's implementation.

Requirement 8 is enforced by Experiment C as a standing test, not by inspection:
if the harness contained the algorithm, changing the library would not change
the verdict.

For `&[u8; N]` the secret is the array's **contents**. All `N` bytes are
declared `secret global`; the pointer is public and stable, because its value is
an address the attacker already knows. `controls::tail_byte_probe` is the control
that proves the marking is complete rather than nominal — it branches on nothing
but byte 15, and reports `secure` under any harness that marks only the pointer
or only the leading byte.

## Attribution

M4's guarantees are kept and extended. For a contract to earn
`VERIFIED_BOUNDED`:

* the contract resolves to **exactly one** symbol in the artifact — zero is
  `missing symbol`, more than one is `ambiguous`, and both are explicit errors
  rather than a choice;
* the generated call type-checks against the real signature, and the embedded
  descriptor matches the library's own (both compile-time). Argument *order*
  comes from the descriptor's declared positions; where two parameters share a
  type, rustc cannot catch a swap, so that is pinned by
  `parameters_are_ordered_by_position` and
  `the_generated_call_is_positional_and_typed` rather than by the compiler;
* the analyzer reported reaching that symbol (`reach <symbol>`, M4's mechanism
  unchanged);
* exploration completed, no pending paths, no `unknown` answers, every requested
  obligation class fully discharged, the depth bound not reached;
* the checked observation classes are named, and the unchecked ones too.

A verifier that analyzed the wrong function cannot return `VERIFIED_BOUNDED`:
the `safe-wrapper` regression pairs a vulnerable contract with an entry that
calls something else and requires `INCONCLUSIVE`, as M4's does.

## Reports

`library_report.rs`, beside `symbolic_report.rs` rather than merged into it. The
evidence differs: a case report names a hand-written target source, a contract
report names a package, a lockfile, a feature set, a resolved mangled symbol and
a generated harness.

Added to M4's fields:

| Field | Meaning |
| --- | --- |
| `library.package`, `library.version` | the package the implementation came from |
| `library.source_file`, `library.source_line` | where the annotation is |
| `library.features` | Cargo features active for the verification build |
| `library.lockfile_sha256` | dependency-resolution fingerprint |
| `compilation.profile`, `.flags`, `.panic`, `.lto` | the build this result describes |
| `symbol.contract`, `.mangled`, `.address`, `.reached` | contract-to-instruction binding |
| `harness.sha256`, `harness.source` | the generated wrapper, verbatim |
| `inputs[].role`, `.repr`, `.bits`, `.domain` | roles, widths and any generated restriction, as transferred into the analysis |
| `input_domain` / `generated_domain` | the developer's `assume` constraints, verbatim, kept apart from the generator's |
| `artifact.path_retained` | whether the recorded path outlived the run |
| `production_artifact` | always `not analyzed`, with the reason |

**Report-level provenance names the analyzer and nothing it analyzed.** A run
builds one executable per contract, so there is no single artifact a report can
describe: `analyzer` carries the analyzer, its build, the pinned image, the
solver, the container runtime, the compiler and the platform, and the artifact
hash, build flags, lockfile fingerprint and resolved symbol live on each
contract. The first revision put M4's `SymbolicProvenance` at report level,
which advertised the **last** contract's executable — and M4's direct-`rustc`
build flags, which this path does not use — as though they described the whole
run.

`harness.source`, the BINSEC script, the descriptor and the solver output
together form the evidence bundle: enough to re-run the analysis by hand without
this tool.

## Outcomes

Unchanged vocabulary. `VERIFIED_BOUNDED` keeps M4's meaning and M4's
fail-closed conditions, plus the M5-specific ones:

| New condition | Result |
| --- | --- |
| contract has no `#[constant_time]` annotation | error |
| contract resolves to zero symbols (inlined, removed, misnamed) | error — nothing to analyze |
| contract resolves to more than one symbol | error — ambiguous |
| a parameter's shape is unsupported | error, naming parameter and type |
| configuration tries to assign a role | error |
| harness or library fails to compile | error, with rustc's own diagnostics |
| analyzer never reached the resolved symbol | `INCONCLUSIVE` |

An error is an infrastructure failure, exit 2, and never a verdict. The
distinction matters: `INCONCLUSIVE` says the analysis ran and established
nothing; an error says no analysis happened.

### Validation order

The analyzer is prepared **lazily**, immediately before the first query it is
needed for. Everything else is checked first, in the order it becomes
decidable:

| Stage | Needs | Example failure |
| --- | --- | --- |
| manifest, configuration, selection | nothing but the filesystem | a misspelled contract name |
| annotation, roles, signature | the library compiled | a contract with no `#[constant_time]`; a secret the configuration tried to make public |
| compiled symbol | the artifact linked | inlined away, removed, or ambiguous |
| exploration | **the analyzer** | a missing image |

This took two passes, and the second miss is instructive. The first revision
prepared the backend up front, so a misspelled contract name reported "cannot
obtain the analyzer image"; moving the *selection* check ahead of it fixed that
case and left two more behind. A contract that is configured but carries no
annotation also reported a missing image, because reaching that diagnosis needs
the library compiled and compilation still came after the backend check. **A
problem with the contract must be reported as a problem with the contract**, so
the backend moved to the end instead.

The cost is that a developer without the analyzer waits for one probe and one
harness build before being told to install it. That is the right trade: being
told the truth about the contract matters more than being told about the
backend sooner.

#### Why the first local reproduction was not one

Setting `TRACE_CHECK_CONTAINER_RUNTIME=docker` on a machine where docker holds
no image looked like a faithful stand-in for CI, and was not: the library entry
point takes an explicit runtime and never reads the environment, so podman
still served the image and the ordering was never exercised. The variable only
made the *gated* tests skip. That is exactly why these two cases passed locally
and failed in CI.

The tests now make the backend absent by construction — they name a runtime
that cannot exist — so they exercise the ordering on any machine.
`contract_errors_survive_an_unreachable_analyzer` requires the contract problem
to win; `an_unreachable_analyzer_is_reported_when_it_is_the_problem` requires a
*sound* contract in the same environment to fail on the analyzer, which keeps
the first from passing vacuously. Restoring eager preparation makes the first
fail, which was checked rather than assumed. Every contract-level error test
additionally calls `assert_not_a_backend_error`, so the whole class fails
loudly if this regresses again.

## Examples

`examples/crypto-library` is an ordinary Cargo library — not a harness, not a
manifest, no trace-check machinery in its public API. Each implementation is
defined once.

| Contract | What it is | Declared outcome |
| --- | --- | --- |
| `tag::verify_tag` | `subtle::ConstantTimeEq` over `[u8; 16]` | `VERIFIED_BOUNDED` |
| `tag::verify_tag_early_exit` | naive early exit, written plainly | `VERIFIED_BOUNDED`, educational — the compiler erased it (C1) |
| `tag::verify_tag_volatile_early_exit` | early exit the optimizer cannot vectorize | `LEAK_DETECTED` (control flow) |
| `controls::tail_byte_probe` | a load address keyed on byte 15 of the secret only | `LEAK_DETECTED` (memory access) — the per-byte control |
| `lookup::substitute` | branchless full-table scan | `VERIFIED_BOUNDED` |
| `lookup::substitute_indexed` | `SBOX[secret & 15]` | `LEAK_DETECTED` (memory access) |
| `lookup::substitute_mode` | the leak behind a public mode | `LEAK_DETECTED` (memory access) |
| `controls::public_branch` | branches on a public input only | `VERIFIED_BOUNDED` |
| `reduce::reduce_once` | conditional subtraction, `u32` secret, written with a branch | `VERIFIED_BOUNDED` — the compiler used a conditional move |
| `reduce::reduce_once_masked` | the same reduction with a mask | `VERIFIED_BOUNDED` |

`reduce_once` is the stretch case: it exercises a scalar secret wider than a
byte and a computation that is not byte-oriented. Its declared expectation was
established by running it, not predicted — the `if` became a conditional move,
which is the fifth-and-a-half instance of the same lesson. This project does
not manufacture expected findings.

The library's M3 dynamic checks live in a `#[cfg(test)]` module in `src/lib.rs`
rather than in `tests/`: the generated contract adapter is `#[cfg(test)]` on the
library crate itself, so an integration test — which links the library as an
ordinary dependency — cannot see it. One annotation still drives both commands.

**Two of the expectations are findings about the compiler.**
`verify_tag_early_exit` is `VERIFIED_BOUNDED` symbolically and
`LEAK_DETECTED` dynamically, from the same source: the `memcheck` profile
enables LTO and keeps the per-byte branch, while the freestanding verification
build vectorizes it away. One source, two artifacts, two honest verdicts — the
clearest possible argument for pinning the build in every report.

## Required test matrix

| Scenario | Required result |
| --- | --- |
| constant-time library function | `VERIFIED_BOUNDED` |
| library function with a secret-dependent branch | `LEAK_DETECTED` |
| library function with a secret-dependent address | `LEAK_DETECTED` |
| branch on a public input only | no secret-dependent finding |
| leak behind an untested public mode | found symbolically |
| library changed, harness and config unchanged | verdict changes |
| wrong function named in the configuration | explicit error |
| the symbol exists but a different function is called | no verified result |
| secret mapped as public in configuration | rejected |
| secret applied to the wrong parameter | compile error where the types differ; otherwise the positional generator, pinned by tests |
| the secret array's final byte causes a branch | `LEAK_DETECTED` |
| unsupported signature | actionable error |
| missing function symbol | explicit error |
| target inlined beyond identification | explicit error, not a verdict — reached through `resolve_symbol`, since the reified call means no bundled contract actually vanishes |
| compiler changes the generated code | new artifact, provenance updated |
| exploration exceeds its bound | `INCONCLUSIVE` |
| solver returns unknown | `INCONCLUSIVE` — M4's classifier, shared unchanged |
| incomplete analyzer output | `INCONCLUSIVE` — M4's classifier, shared unchanged |
| the M3 assertion for the same function | still works |
| M4's standalone cases | still work |

## Non-goals

By instruction: no general Rust program verification, no arbitrary `std`
libraries, no heap or dynamic allocation, no variable-length slices, no
recursive structures, no trait objects, no arbitrary generics, no `async`, no
multithreading, no symbolic filesystem or network state, no microarchitectural
timing model. Also deferred: symbolic performance work, statistical hardware
timing, and multi-compiler regression matrices.

By scope: M5 does not verify the production binary, and does not claim to.

## Known limitations

* **The analyzed instance is out of line.** See
  [The artifact boundary](#the-artifact-boundary). This is the sharpest gap
  between M5 and level three, and it is caused by M5 itself.
* **Array lengths must be literals.** `&[u8; TAG_LEN]` is refused, not guessed.
* **`no_std`-compatible libraries only.** A library that needs `std` cannot be
  linked into the freestanding artifact; the dependency graph is validated and
  the failure is explicit.
* **One contract per run.** Verification is per contract, and per contract the
  cost is a probe build, a harness build and an analyzer run.
* **M4's limitations all carry over** — bounded domains, declared observation
  classes, partial witnesses, coarse attribution, no cache or speculation
  modeling, x86-64 Linux only.

## Acceptance criteria

- [x] A separate ordinary Rust library holds the implementations, defined once.
- [x] One annotated function is both dynamically tested (M3) and symbolically
      verified (M4 backend).
- [x] Harnesses are generated automatically for the supported signatures.
- [x] Roles and widths transfer from the contract into the analysis.
- [x] Linkage and function reachability are established from evidence.
- [x] Changing only the library can change the verdict.
- [x] Both secret-dependent branches and addresses are found in library code.
- [x] At least one meaningful library function earns `VERIFIED_BOUNDED`.
- [x] Unsupported signatures, wrong mappings, missing symbols and incomplete
      analyses cannot produce a verified result.
- [x] The CLI works from a separate consumer crate.
- [x] Reports distinguish the analyzed executable from a production binary.
- [x] The workflow runs reproducibly in CI.
- [x] M1–M4 retain their behavior and coverage.

## Implementation status

All ten configured contracts in `examples/crypto-library` reproduce their
declared outcomes against the pinned analyzer. `cargo trace-check verify
--all-contracts` exits 0; the observed run:

| Contract | Outcome | Paths | Checks (cf / mem) | Depth | Reached at | Witness |
| --- | --- | --- | --- | --- | --- | --- |
| `tag::verify_tag` | `VERIFIED_BOUNDED` | 1 / 1 | 19 / 19 · 193 / 193 | 267 | `0x201520` | n/a |
| `tag::verify_tag_early_exit` | `VERIFIED_BOUNDED` | 1 / 1 | 2 / 2 · 84 / 84 | 91 | yes | n/a |
| `tag::verify_tag_volatile_early_exit` | `LEAK_DETECTED` (15 control flow) | 16 / 16 | 17 / 32 · 157 / 157 | 133 | yes | 128-bit pair |
| `lookup::substitute` | `VERIFIED_BOUNDED` | 1 / 1 | 2 / 2 · 29 / 29 | 100 | yes | n/a |
| `lookup::substitute_indexed` | `LEAK_DETECTED` (1 memory access) | 1 / 1 | 2 / 2 · 8 / 9 | 12 | yes | none — no solver query |
| `lookup::substitute_mode` | `LEAK_DETECTED` (1 memory access) | 2 / 2 | 4 / 4 · 30 / 31 | 89 | yes | none — no solver query |
| `controls::tail_byte_probe` | `LEAK_DETECTED` (1 memory access) | 1 / 1 | 2 / 2 · 91 / 92 | 114 | yes | none — no solver query |
| `controls::public_branch` | `VERIFIED_BOUNDED` | 1 / 1 | 2 / 2 · 10 / 10 | 17 | yes | n/a |
| `reduce::reduce_once` | `VERIFIED_BOUNDED` | 1 / 1 | 2 / 2 · 9 / 9 | 16 | yes | n/a |
| `reduce::reduce_once_masked` | `VERIFIED_BOUNDED` | 1 / 1 | 2 / 2 · 9 / 9 | 17 | yes | n/a |

Warm, the ten contracts take about **9 s** end to end — a probe build, a harness
build and an analyzer run each — so CI verifies all of them. Every finding is
attributed to the developer's own source line (`tag.rs:55`, `lookup.rs:37`,
`lookup.rs:51`, `controls.rs:32`), never to the generated harness.

`examples/external-library`, outside this workspace and with its own lockfile,
verifies its three contracts through the same CLI — including `mix_when`, whose
public `bool` exercises the generated domain restriction. Its contracts say
`dynamic = false`, so its ordinary `cargo test` compiles with no
dev-dependency at all; CI asserts that.

### What the counterexample shows

For `verify_tag_volatile_early_exit` the solver's own model is a pair of
**128-bit** values:

```text
TC_SECRET_EXPECTED = (_ bv340282366920938463463374607431768211454 128)
                 vs  (_ bv340282366920938463463374607431768211455 128)
```

`0xFF…FE` against `0xFF…FF` — identical in the first fifteen bytes and
differing in the last. That is the whole-array secret in one field: a harness
that had marked only the pointer, or only the leading byte, could not produce
it.

### Deviations from the plan

* **Configuration is TOML, as proposed, but `inputs` has exactly one accepted
  value.** `"public-symbolic"` restates the default; anything else — including
  `"secret-symbolic"` — is an error naming the annotation as the source of
  truth. A half-implemented input-fixing feature would have been worse than
  none, and a configuration able to assign roles is the drift the milestone
  forbids.
* **The descriptor is read by running a generated probe, not by parsing
  source.** `cfg`, macros and `include!` make a text scan either wrong or a
  second parser to maintain. The probe's compile failures are translated into
  three distinct actionable messages.
* **The harness is bound to its descriptor by a `const` assertion.** rustc,
  not this tool, certifies that the generated call matches the signature it was
  generated against.
* **One artifact per contract, sharing one Cargo target directory.** Separate
  target directories rebuilt `core`, `subtle` and the library for every
  contract and left 836 MB behind for a ten-contract run; sharing brought that
  to 122 MB and the wall clock from 30 s to 9 s. Each generated package is
  named after its contract so the binaries do not collide, which is also what
  lets each report name the exact executable its result describes.
* **Cargo must run *inside* the generated package.** `.cargo/config.toml`
  discovery is relative to the working directory, not to `--manifest-path`. With
  the manifest named instead, the freestanding link flags were silently dropped
  and the link failed on a duplicate `_start` against the C runtime's
  `Scrt1.o`.
* **`reduce_once` earns `VERIFIED_BOUNDED`.** Its source has a secret-dependent
  `if`; the compiler emitted a conditional move. Recorded as observed rather
  than reshaped into the expected finding.
* **M5 found and fixed a pre-existing M3 defect.** Memcheck attribution
  compared only the final `::` segment of a frame name, so every
  `#[ct_test(target = "module::function")]` was unattributable: a detected leak
  *inside* the declared function was reported as belonging to other code, and
  the run went `INCONCLUSIVE` instead of naming it. Matching is now a
  common-path-suffix comparison, with
  `a_module_qualified_target_matches_its_own_frame_only` as the regression. The
  defect was invisible before this milestone because the only module-qualified
  contracts in the repository were M5's.

### Corrected after review

Five findings from review of the first revision, in the order they were fixed:

1. **A missing analyzer masked contract errors.** Fixed in two passes: the
   first moved selection validation ahead of the backend, and CI caught two
   further cases that needed the library compiled before they could be
   diagnosed. The analyzer is now prepared lazily, at the point of first use.
   See [Validation order](#validation-order), including why the original local
   reproduction was not one.
2. **Generated files went to a predictable path under `/tmp`.** Replaced with
   an atomically created private directory, plus `--artifact-dir` for keeping
   the evidence bundle. See [Where generated files live](#where-generated-files-live).
   M4's build directory was hardened the same way.
3. **An annotated library could not run `cargo test`.** The attribute always
   emitted `#[cfg(test)]` code calling into `trace-check-test`, so a crate that
   declared only the macro dependency failed to build its own test targets.
   `dynamic = false` drops that machinery. Deliberately opt-**out**: a contract
   with no metadata test disappears from M3's coverage accounting, and a
   contract that quietly stops being accounted for is the failure mode this
   project exists to prevent, so the safe behavior is the default.
4. **Report-level provenance described one artifact out of several.** Split into
   analyzer identity at report level and artifact identity per contract; see
   [Reports](#reports).
5. **A public `bool` was documented as constrained and was not.** The
   constraint is now generated, reported, and checked in three places; see
   [Modeling Rust's valid values](#modeling-rusts-valid-values).

### What validates the validator

`ci/verify-m5-library.py` checks the report, not the exit code. A
`VERIFIED_BOUNDED` contract must show complete exploration, zero pending paths,
zero `unknown` answers, a non-zero number of discharged checks, a depth bound
that was not reached, no divergences and no unchecked property; a
`LEAK_DETECTED` contract must name an address and attribute at least one
finding to the right file in the library. Every contract must carry its
package, its declaration site, a resolved symbol naming its function, the
analyzer's own reached-evidence, a 64-hex artifact and lockfile hash, the
generated harness verbatim, a secret input of the **declared width**, and the
statement that no production binary was analyzed. No two contracts may share an
artifact.

Each of those was confirmed by tampering with a passing report before being
relied on. Fourteen mutations were tried and all fourteen were caught:
narrowing a secret's width to 8 bits, relabelling it public, marking a verified
contract unreached, zeroing its discharged-check counts, removing the harness
source, re-attributing a finding to the harness, claiming the production binary
was analyzed, pointing two contracts at one artifact, reintroducing
report-level artifact provenance, hanging an artifact hash on the analyzer
object, dropping the path-retention statement, inventing an unexplained
generated restriction, adding a `bool` input with no restriction, and listing a
restriction that never reached the script.

### Where the strongest guarantees live

| Claim | What enforces it |
| --- | --- |
| there is no second copy of the algorithm | `the_verdict_follows_the_library_implementation`, plus the CI step that mutates the checkout |
| the argument mapping is correct | rustc: the generated call is typed, and a `const` assertion binds the harness to the descriptor |
| all bytes of an array secret are symbolic | `controls::tail_byte_probe`, and the 128-bit counterexample |
| a role cannot be reassigned | `configuration_cannot_reassign_a_role` |
| an unsupported shape cannot be verified | `an_unsupported_signature_is_an_actionable_error`, against `examples/consumer-crate`'s `&[u8; TAG_LEN]` |
| a missing symbol is not a verdict | `a_missing_symbol_is_an_explicit_error` |
| a partial exploration is not a verdict | `exceeding_the_depth_bound_is_inconclusive` |
| a narrow model does not read like a broad one | `a_narrow_observation_model_is_named_as_such` |
| a selection error is not masked by a missing backend | `a_selection_error_is_reported_without_any_backend`, with an emptied `PATH` |
| no contract error is masked by a missing backend | `contract_errors_survive_an_unreachable_analyzer` and its companion, plus `assert_not_a_backend_error` in every contract-level error test |
| generated files are not written through a planted path | `an_ephemeral_workspace_is_private_and_removed`, `a_kept_workspace_never_reuses_an_existing_entry`, `a_contract_directory_is_not_reused` |
| a multi-contract report names no shared artifact | `a_multi_contract_report_claims_no_shared_artifact` |
| a `bool`'s analyzed domain is Rust's valid values | `a_public_bool_is_restricted_in_the_generated_script`, which checks the script the analyzer was given |
| an annotation does not break `cargo test` | `cargo_test_compiles_for_an_annotated_library` |
