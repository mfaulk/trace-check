# symbolic — bounded relational verification targets

Freestanding `no_std` x86-64 targets analyzed by BINSEC relational symbolic
execution. Unlike the dynamic backends, this one **searches** for a secret
assignment that leaks instead of running inputs you chose.

```sh
cargo trace-check verify                        # every case
cargo trace-check verify --case table-lookup    # one
cargo trace-check verify --format json
```

## Why these targets look the way they do

Inputs are `#[no_mangle] pub static mut` globals because BINSEC declares the
security lattice by **symbol name** (`secret global TC_SECRET`). Analysis starts
at a `tc_harness_*` symbol and halts at `tc_halt`, so program startup is never
explored — and because the artifact is `no_std` with no libc, there is no
runtime to explore in the first place.

## Cases

| Case | Target | Declared | Why |
| --- | --- | --- | --- |
| `table-lookup` | `secret_lookup` | `LEAK_DETECTED` | secret selects a load address |
| `trip-count` | `secret_trip_count` | `LEAK_DETECTED` | secret sets a loop bound |
| `masked-scan` | `masked_scan` | `VERIFIED_BOUNDED` | full scan, mask select |
| `public-branch` | `public_branch` | `VERIFIED_BOUNDED` | branches on public input only |
| `conditional-lookup` | `conditional_lookup` | `LEAK_DETECTED` | leak behind a public mode |
| `erased-branch` | `erased_branch` | `VERIFIED_BOUNDED` | compiler removed the branch |
| `depth-bounded` | `public_loop` | `INCONCLUSIVE` | exceeds a small bound |

`conditional-lookup` is the one worth understanding. A dynamic M3 test that only
exercises `public_mode = 0` reports `NO_LEAK_OBSERVED` and is not wrong — that
path really is the constant-time scan. The vulnerability lives on the path no
test visited, and finding it requires searching the public domain.

`erased-branch` is declared `VERIFIED_BOUNDED` on purpose. Its source has a
secret-dependent `if`, but at `-O` that becomes `shr` plus `sub` with zero
conditional jumps, so there is genuinely nothing to find in the compiled code.
Declaring a leak there would be manufacturing one.

## What a `VERIFIED_BOUNDED` result means

Exploration completed and every relational obligation was discharged — within
the declared input domain, the exploration bound, and the modeled observations
(control flow and memory addresses). It is not a claim about other domains,
other artifacts, or unmodeled effects such as cache behavior, operand latency,
or speculation. See `docs/limitations.md`.

## Not a Cargo package

There is no `Cargo.toml` here on purpose. The artifact is a `#![no_std]`
`#![no_main]` binary compiled directly by `rustc` with the flags recorded in
each report, so it is not a workspace member and `cargo fmt --all` does not
reach it. CI runs `rustfmt --edition 2021 --check` on `src/targets.rs`
separately.

## Requirements

A container runtime (podman or docker) with the analyzer image pinned by
digest. The solver is linked into the analyzer binary rather than invoked as a
subprocess, so one digest pins both:

```sh
podman pull docker.io/binsec/binsec@sha256:19a0ff4b0278906bd6f00a5752cab19e8cad7153715cecf32d4f885826f62967
```

`verify` refuses to run without it; it never skips and reports success.

## Adding a case

1. Add an `#[inline(never)] #[no_mangle] pub extern "C"` target to
   `src/targets.rs` and a `tc_harness_*` entry point for it via the `harness!`
   macro. `_start` must keep dispatching to every harness, or the linker drops
   the unreachable ones.
2. Add an entry to `cases.json` naming the function, its entry and halt
   symbols, the secret and public globals, a depth bound, and the outcome you
   expect with a `rationale` for it.
3. Run `cargo trace-check verify --case <id>`.

A case is rejected before analysis if it declares no secret, names a global as
both secret and public, uses a symbol name that is not a plain identifier, sets
`max_depth` to zero, or expects `NO_LEAK_OBSERVED` — which only the dynamic
backend produces. An entry, halt, or target symbol missing from the built
artifact is an explicit error, never an analysis attempt.

**Declare what the artifact does, not what the source suggests.** `erased-branch`
exists because those differ, and the expectation that matches the compiled code
is the correct one.
