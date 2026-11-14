# trace-check-secret

Low-level secret marking for Valgrind Memcheck. Marking makes secret bytes
undefined in Memcheck's shadow state without changing their actual values.
Secret-dependent branches and addresses can then produce diagnostics.

```rust
let key = [0u8; 32];
let secret = trace_check_secret::Secret::new(&key);
// Analyze uses of the marked bytes here.
drop(secret);
```

The guard restores shadow definedness on drop. `declassify` restores the bytes
of a result before ordinary use; it does not recursively traverse heap data.
Use `trace-check-test` for optimizer barriers, controls, and security tests.

Instrumentation supports Linux x86-64 and requires a C compiler plus Valgrind's
client-request headers at build time. `VALGRIND_INCLUDE` may name the directory
containing `valgrind/memcheck.h`. Without headers or on unsupported platforms,
the crate builds a stub and `run_mode()` reports `Unsupported`; outside
Valgrind it reports `Native`. Neither state is evidence of a successful check.

Requires Rust 1.97 or newer (the minimum tested version). Licensed under
MIT OR Apache-2.0; see the included license files.

See the [project README](https://github.com/mfaulk/trace-check#readme),
[technical reference](https://github.com/mfaulk/trace-check/blob/main/docs/technical-reference.md),
and [limitations](https://github.com/mfaulk/trace-check/blob/main/docs/limitations.md).
