# external-library — the workflow for a crate outside this workspace

This crate is **not** a workspace member. It has its own `Cargo.lock`, its own
dependency resolution, and no knowledge of trace-check's layout. Its only
dependency is the annotation macro, which is a proc-macro crate and therefore
compiled for the host — it contributes nothing to the verification artifact.

```sh
cargo trace-check verify --all-contracts \
  --manifest-path examples/external-library/Cargo.toml
```

| Contract | What it is | Outcome |
| --- | --- | --- |
| `select` | constant-time selection between two words | `VERIFIED_BOUNDED` |
| `digest_nibble` | the secret's low nibble selects a load address | `LEAK_DETECTED`, memory address |
| `mix_when` | selection driven by a **public `bool`** | `VERIFIED_BOUNDED` |

Each contract declares its expected outcome in `trace-check.toml`, so the run
exits 0 when the analyzer reproduces them.

## `dynamic = false`, and why `cargo test` still works

`#[constant_time]` emits a `#[cfg(test)]` analysis adapter for the M3 dynamic
checks, and that adapter calls into `trace-check-test`, which needs `std` and
has to be a dev-dependency. This crate wants only its contracts *verified*, so
its annotations say:

```rust
#[constant_time(secret = "first", dynamic = false)]
```

which drops that machinery. Ordinary `cargo test` therefore compiles here with
no dev-dependency at all — adding a verification annotation must not make an
otherwise valid Rust library unable to build its own test suite. CI asserts
exactly that, and lints this crate with `--all-targets`.

It is opt-**out**, not opt-in: a contract with no metadata test disappears from
`cargo trace-check test`'s coverage accounting, and a contract that quietly
stops being accounted for is the failure mode this project exists to prevent.
So the safe behavior is the default. A library that wants both — like
`examples/crypto-library` — keeps the default, declares the dev-dependency, and
writes `#![cfg_attr(not(test), no_std)]`.

## The public `bool`

`mix_when` takes `enabled: bool`. BINSEC reasons about machine bytes, and a
symbolic byte has 256 values where Rust's `bool` has two. The generated harness
therefore emits a domain restriction and the report names it:

```text
  enabled    public  bool         8 bits, symbolic and held equal
  generated: TC_PUBLIC_ENABLED <= 1  (so the analyzed domain is Rust's valid values)
```

Without it the analyzer would explore states the compiled program can never be
in, and the reported input domain would not be the one that was searched. The
developer's own `assume` constraints are listed separately, and stay verbatim.
