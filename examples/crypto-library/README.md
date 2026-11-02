# crypto-library — one implementation, two analyses

An ordinary `no_std` Rust library. Nothing in it is a verification harness and
nothing in it is written for an analyzer: each function is defined once, in
`src/`, and both backends analyze code compiled from that source.

```sh
# M3: dynamic, under Valgrind Memcheck. Runs the inputs the tests chose.
cargo trace-check test

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

`verify` exits 0 on a reproduced `LEAK_DETECTED` because the declared
expectation was met: the security of the function and the pass/fail of the
regression fixture are separate questions. `test` has no such declaration, so a
detected leak is a failure there.

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
