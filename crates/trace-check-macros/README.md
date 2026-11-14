# trace-check-macros

Attribute macros for `trace-check` constant-time contracts and security tests.
Most users should depend on `trace-check-test`, which re-exports these macros
along with the runtime support needed by analysis adapters.

Libraries that cannot depend on the runtime can use an annotation-only contract:

```rust
#[trace_check_macros::constant_time(secret = "key", dynamic = false)]
pub fn combine(key: u32, public: u32) -> u32 {
    key ^ public
}
```

The annotation preserves the function body and emits a contract descriptor for
the analyzer. `dynamic = false` omits the test adapter, allowing macro-only and
`no_std` consumers; it does not itself verify the function.

Requires Rust 1.97 or newer (the minimum tested version). Licensed under
MIT OR Apache-2.0; see the included license files.

See the [project README](https://github.com/mfaulk/trace-check#readme),
[technical reference](https://github.com/mfaulk/trace-check/blob/main/docs/technical-reference.md),
and [limitations](https://github.com/mfaulk/trace-check/blob/main/docs/limitations.md).
