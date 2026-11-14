# cargo-trace-check

**trace-check — Automated side-channel security analysis for Rust**

An open-source security testing framework that detects secret-dependent control
flow and memory accesses in compiled cryptographic software. Integrates dynamic
analysis, generated regression tests, and bounded symbolic verification into
Cargo and CI workflows.

Check security properties declared with `#[constant_time]` annotations in Rust.
Generated inputs and targeted tests detect secret-dependent branches and memory
accesses in compiled code under Valgrind Memcheck.

```sh
cargo install cargo-trace-check --version 0.1.0 --locked
cargo trace-check check --all-contracts --ci
cargo trace-check test
```

Add `trace-check-test = "=0.1.0"` to the analyzed library's dependencies to use
annotations and security tests. Native checks require Linux x86-64, Valgrind
3.28.0 or newer, its client-request headers, and a C compiler. Install the headers
before compiling the library's support crates.

Generated harnesses use the matching registry version of `trace-check-test`.
`TRACE_CHECK_TEST_PATH` can override it for local development. Symbolic `verify`
requires a container runtime and the pinned BINSEC image; standalone bundled
cases additionally require a checkout passed through `--workspace-root`.

A passing dynamic check means no modeled leak was observed; it is not a proof
of constant-time security.

Requires Rust 1.97 or newer (the minimum tested version). Licensed under
MIT OR Apache-2.0; see the included license files.

See the [project README](https://github.com/mfaulk/trace-check#readme),
[technical reference](https://github.com/mfaulk/trace-check/blob/main/docs/technical-reference.md),
and [limitations](https://github.com/mfaulk/trace-check/blob/main/docs/limitations.md).
