# trace-check

Analysis engine for constant-time contracts in compiled Rust and WebAssembly.
It supports generated Memcheck checks, bounded relational verification with
BINSEC, static WASM screening, and differential execution tracing.

For the Cargo workflow, install `cargo-trace-check` and annotate your library
with `trace-check-test`. The `trace-check` binary also exposes repository demo
commands; these require a source checkout and `--workspace-root /path/to/trace-check`.

A clean dynamic check reports no modeled leak on the paths exercised, not proof
of constant-time security. Native analysis requires Linux x86-64 and Valgrind
3.28.0 or newer. Other backends have additional prerequisites.

Requires Rust 1.97 or newer (the minimum tested version). Licensed under
MIT OR Apache-2.0; see the included license files.

See the [project README](https://github.com/mfaulk/trace-check#readme),
[technical reference](https://github.com/mfaulk/trace-check/blob/main/docs/technical-reference.md),
and [limitations](https://github.com/mfaulk/trace-check/blob/main/docs/limitations.md).
