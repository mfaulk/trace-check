# trace-check-test

Declare constant-time contracts and write targeted security tests in Rust.

```toml
[dependencies]
trace-check-test = "=0.1.0"
subtle = "2.6"
```

```rust
#[trace_check_test::constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    use subtle::ConstantTimeEq;
    expected.ct_eq(supplied).unwrap_u8() == 1
}
```

Install `cargo-trace-check`, then run `cargo trace-check check --all-contracts --ci`
from your library. Targeted `#[ct_test]` tests run with `cargo trace-check test`;
ordinary `cargo test` reports them as ignored. The generated `<function>_ct`
adapter marks the declared secret and calls the original function.

Native analysis requires Linux x86-64, Valgrind 3.28.0 or newer, its client-request
headers, and a C compiler. Without instrumentation, analysis fails rather than
reporting success. A passing check is scoped to its compiled artifact and tested
paths, not every hardware timing effect.

Requires Rust 1.97 or newer (the minimum tested version). Licensed under
MIT OR Apache-2.0; see the included license files.

See the [project README](https://github.com/mfaulk/trace-check#readme),
[technical reference](https://github.com/mfaulk/trace-check/blob/main/docs/technical-reference.md),
and [limitations](https://github.com/mfaulk/trace-check/blob/main/docs/limitations.md).
