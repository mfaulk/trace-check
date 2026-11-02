# external-library — the workflow for a crate outside this workspace

This crate is **not** a workspace member. It has its own `Cargo.lock`, its own
dependency resolution, and no knowledge of trace-check's layout. Its only
dependency is the annotation macro, which is a proc-macro crate and therefore
compiled for the host — it contributes nothing to the verification artifact.

```sh
cargo trace-check verify --all-contracts \
  --manifest-path examples/external-library/Cargo.toml
```

```text
Verifying external_library::select     → VERIFIED_BOUNDED
Verifying external_library::digest_nibble → LEAK_DETECTED (memory address)
Every declared expectation was reproduced.
```

Both contracts declare their expected outcome in `trace-check.toml`, so the run
exits 0 when the analyzer reproduces them.

## Why it carries no dynamic tests

`#[constant_time]` emits a `#[cfg(test)]` analysis adapter that calls into
`trace-check-test`, which needs `std`. A library that wants the M3 dynamic
checks as well must declare that dev-dependency and write
`#![cfg_attr(not(test), no_std)]` — which is what `examples/crypto-library`
does. This one is `#![no_std]` unconditionally and has no tests, so only its
library target compiles. That is the target verification builds, which is the
point: it is the minimum a crate needs to be verifiable.

CI lints it with `cargo clippy --lib --manifest-path …` for the same reason;
`--all-targets` would try to build a test harness that has nothing to call
into.
