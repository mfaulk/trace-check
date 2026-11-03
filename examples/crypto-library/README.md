# crypto-library — one implementation, several analyses

An ordinary `no_std` Rust library. Nothing in it is a verification harness and
nothing in it is written for an analyzer: each function is defined once, in
`src/`, and every backend analyzes code compiled from that source.

```sh
# M3: dynamic, under Valgrind Memcheck. Runs the inputs the tests chose.
cargo trace-check test

# M6: dynamic, under Valgrind Memcheck. Generates the inputs itself.
cargo trace-check check --all-configured

# M7: the same, with coverage feedback choosing which inputs to analyze.
cargo trace-check check --contract crypto::hidden::nested_modes --explore

# M5: symbolic, under BINSEC. Searches a declared domain for a secret
# assignment that leaks.
cargo trace-check verify --all-contracts
```

Both are driven by the same annotation:

```rust
#[constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    expected.ct_eq(supplied).unwrap_u8() == 1
}
```

## Which invocation demonstrates what

The library deliberately contains vulnerable implementations alongside the
correct ones, so a **full** run of either command exits nonzero by design.

| Command | Exit | Why |
| --- | --- | --- |
| `cargo trace-check test --filter is_constant_time` | 0 | only the clean contracts are selected |
| `cargo trace-check test` | 1 | the vulnerable contracts are detected, as intended |
| `cargo trace-check verify --all-contracts` | 0 | every contract **declares** its expected outcome, and all of them are reproduced |
| `cargo trace-check verify --contract crypto::tag::verify_tag` | 0 | `VERIFIED_BOUNDED`, as declared |
| `cargo trace-check check --all-configured --ci` | 0 | the clean contracts are security contracts that pass; the vulnerable ones are declared `analyzer-regression`, so detecting their planted leaks is those fixtures passing |
| `cargo trace-check check --contract crypto::lookup::substitute_mode` | 0 | `LEAK_DETECTED`, as that fixture declares |
| `cargo trace-check check --contract crypto::hidden::nested_modes --no-explore` | 2 | `NO_LEAK_OBSERVED`: the leak is real and on a path generated inputs cannot construct, so the fixture's declared `LEAK_DETECTED` goes unmet |
| `cargo trace-check check --contract crypto::hidden::nested_modes --explore` | 0 | coverage feedback reaches it, and Memcheck confirms it |

`verify` exits 0 on a reproduced `LEAK_DETECTED` because the declared
expectation was met: the security of the function and the pass/fail of the
regression fixture are separate questions. `test` has no such declaration, so a
detected leak is a failure there.

`check` makes that distinction explicit rather than implicit. Every `[check]`
entry states whether it is a `security-contract` — where a leak fails the build
— or an `analyzer-regression`, where detecting a known leak is the point. A
security contract **cannot** declare an expected outcome, so no configuration in
this file can make a real leak acceptable. To see the other side of the split:

```sh
# The same function, declared as a real contract instead of a fixture. Exits 1.
printf 'schema_version = 1\n\n[check."crypto::lookup::substitute_mode"]\n' \
    > /tmp/security.toml
cargo trace-check check --contract crypto::lookup::substitute_mode \
    --config /tmp/security.toml
```

## The contract `check` exists for

`substitute_mode` takes a public `mode`, and its leak is only on the `mode = 1`
path. The hand-written `#[ct_test]` for it passes `mode = 0` and observes
nothing — which is honest, and useless. `check` generates inputs from the
annotation and reaches the other path without anyone naming it, then narrows the
finding back to the single input that caused it.

## The contract `--explore` exists for

`substitute_mode` needs one public value, and M6's boundary stage supplies it.
`hidden::nested_modes` needs **three** at once, and two of the three are not
`u8` boundary values at all — so boundary generation, which moves one parameter
away from base, and pairwise generation, which moves two, cannot construct a
reaching input **at any budget**. `crates/trace-check/tests/baseline.rs` proves
that rather than assuming it.

Coverage feedback gets there because it does not have to satisfy all three at
once: satisfying the first predicate reaches a region nothing else reached, so
that input is kept as a seed and the search for the second starts from it. The
conjunction is climbed one conjunct at a time.

`hidden::nested_modes_clean` is the control that keeps this honest — the same
three-predicate shape guarding a *safe* region. Exploration reaches it just as
deeply and the security backend still reports `NO_LEAK_OBSERVED`.

`hidden::header_gate` is the same class in a different representation, and
harder: its three conditions are fields of a *single* byte-array parameter, and
boundary generation sets such a parameter to whole patterns — so one pattern
would have to satisfy all three at once, and none satisfies even the first. The
pairwise stage varies two *parameters*, which does not help when all three
conditions live in one.

`hidden::magic_gate` is the recorded limit. Region coverage offers no gradient
toward an exact 32-bit equality, so it is declared
`expected_outcome = "NO_LEAK_OBSERVED"`: the gap is asserted rather than left
implicit, and CI fails if it changes in either direction.

## The contracts

| Contract | What it is | Symbolic outcome |
| --- | --- | --- |
| `tag::verify_tag` | `subtle::ConstantTimeEq` over `[u8; 16]` | `VERIFIED_BOUNDED` |
| `tag::verify_tag_early_exit` | the naive early exit, written plainly | `VERIFIED_BOUNDED` — the compiler erased it |
| `tag::verify_tag_volatile_early_exit` | an early exit the optimizer cannot vectorize | `LEAK_DETECTED`, control flow |
| `lookup::substitute` | branchless full-table scan | `VERIFIED_BOUNDED` |
| `lookup::substitute_indexed` | `SBOX[secret & 15]` | `LEAK_DETECTED`, memory address |
| `lookup::substitute_mode` | the leak behind a public mode | `LEAK_DETECTED`, memory address |
| `controls::tail_byte_probe` | a leak keyed on **byte 15** of the secret only | `LEAK_DETECTED`, memory address |
| `controls::public_branch` | branches on a public input only | `VERIFIED_BOUNDED` |
| `reduce::reduce_once` | conditional subtraction over a `u32` secret, with a branch | `VERIFIED_BOUNDED` — the compiler used a conditional move |
| `reduce::reduce_once_masked` | the same reduction with a mask | `VERIFIED_BOUNDED` |

The `hidden` module is M7's benchmark corpus, written before the
coverage-guided algorithm so the algorithm could not be tailored to it. It is
not verified symbolically:

| Contract | What it is | Reached by |
| --- | --- | --- |
| `hidden::nested_modes` | a leak behind three public predicates | coverage feedback only |
| `hidden::header_gate` | a leak behind three fields of one `[u8; 8]` header | coverage feedback only |
| `hidden::nested_modes_clean` | the same shape, safe region | false-positive control |
| `hidden::magic_gate` | a leak behind `token == 0x5a17c0de` | neither strategy |
| `hidden::threshold_window` | a leak above a power-of-two threshold | M6 boundaries, and M7 must not lose it |
| `hidden::secret_gated` | a leak reachable only for some secret values | keeps secret mutation honest |

### Two of these are findings about the compiler, not about the source

`verify_tag_early_exit` is written with a per-byte branch on the secret. At
`opt-level = 3` it vectorizes into the same branchless `pcmpeqb` / `pmovmskb`
sequence as `verify_tag`, so the compiled code has no secret-dependent control
flow and `VERIFIED_BOUNDED` is the honest verdict. It is kept rather than
rewritten into a manufactured leak.

The M3 dynamic backend **does** report a branch for the same function, because
its build is a different artifact: the `memcheck` profile enables LTO and the
loop survives. One source, two artifacts, two verdicts — which is exactly why
every report pins the build it describes.

`reduce_once` is the same lesson for arithmetic: the `if` became a conditional
move.

### `controls::tail_byte_probe` is the per-byte control

It folds the first fifteen secret bytes into an accumulator and lets **only
byte 15** reach a load address. A harness that declared just the pointer
secret, just the leading byte, or the wrong width reports it as `secure`, so it
is what proves the array marking is complete rather than nominal. A
control-flow formulation of the same idea was tried first — the final byte as a
loop trip count — and the optimizer solved the loop in closed form, leaving no
branch.

## `trace-check.toml`

Per-contract bounds and the observation model, which cannot be inferred from an
annotation. It never restates which parameters are secret: roles come from
`#[constant_time]`, and a configuration that tries to assign one is rejected.
See the comments in the file.

## Why `#![cfg_attr(not(test), no_std)]`

Symbolic verification links this library into a freestanding static ELF with no
libc and no runtime, so there is nothing but the primitive to explore. `std` is
enabled under `cfg(test)` because the M3 dynamic checks need Valgrind client
requests and the ordinary test harness — and because the annotation's test-only
analysis adapter calls into `trace-check-test`, which is a dev-dependency for
that reason.

The annotation macro itself is a **regular** dependency. A proc-macro crate is
compiled for the host and contributes nothing to the target binary, which is
what lets a `no_std` library carry the annotation without pulling `std` into
its verification artifact.

## What a verified result covers

The *function* is the library's own, compiled from the single definition in
`src/`. Its *surroundings* are not production code: the harness is freestanding,
its inputs are named globals, the build uses no LTO, and the target is called
through a laundered function pointer so cross-crate inlining cannot dissolve it.
Every report records all of it and states that no production binary was
analyzed. See [../../docs/MILESTONE-05.md](../../docs/MILESTONE-05.md).
