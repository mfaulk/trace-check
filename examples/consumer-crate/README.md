# consumer-crate — using trace-check from your own project

A minimal, self-contained example of `trace-check` used **as a dependency**,
with constant-time checks written as ordinary Rust unit tests. No harness
binary, no JSON manifest.

Copy this crate's `Cargo.toml` wiring and `src/lib.rs` test module as a starting
point.

## Setup

```toml
[dependencies]
# Only needed if you use `#[constant_time]` on items in your library, since the
# attribute must resolve when the library itself is compiled. It expands to the
# function verbatim plus `#[cfg(test)]` metadata, so a production build of your
# crate contains nothing from trace-check.
trace-check-test = { path = "…/crates/trace-check-test" }

[dev-dependencies]
# Enough on its own if you only write `#[ct_test]` assertions.
trace-check-test = { path = "…/crates/trace-check-test" }
```

## Writing a check

```rust
use trace_check_test::{assert_constant_time, ct_test};

#[ct_test(target = "verify_tag")]
fn verify_tag_is_constant_time() {
    let supplied = [0u8; 32];

    // `verify_tag_ct` is the adapter `#[constant_time]` generates. It counts
    // the call and delegates to the untouched `verify_tag`, which is how the
    // runner proves this test actually exercised the contract rather than
    // merely naming it. Calling `verify_tag` directly fails the test.
    let accepted = assert_constant_time!(
        secret = secret_tag(),
        call = |expected| verify_tag_ct(expected, &supplied),
    );

    // The macro evaluates to the call's return value, so ordinary functional
    // assertions still work alongside the security check.
    assert!(!accepted);
}
```

The secret is passed **by value** and handed back as a reference. That is not
stylistic: if the closure captured your own binding, the optimizer could see its
value, pass an immediate, and never read the marked storage — reporting "no
leak" for code that is demonstrably vulnerable. Letting `trace-check` own the
storage removes the binding it was folding from.

Supported secret forms:

| Form | Use for |
| --- | --- |
| `secret = value` | `[u8; N]` and integer scalars, by value |
| `secrets = (a, b)` | two owned secrets |
| `secret_bytes = slice` | a `&[u8]`, e.g. `vec.as_slice()` |

`Vec<u8>` and `String` are **rejected at compile time**: marking a `Vec` would
mark its pointer, length and capacity and none of the heap data. The compiler
error tells you to pass `.as_slice()`.

## Running

```sh
cargo trace-check test                          # everything
cargo trace-check test --filter constant_time   # just the clean cases
cargo trace-check test --format json            # machine-readable
cargo trace-check list                          # what would run
```

Plain `cargo test` keeps working without Valgrind. The checks are `#[ignore]`d,
so libtest reports them as:

```text
test tests::verify_tag_is_constant_time ... ignored, trace-check constant-time
    check; run `cargo trace-check test`
```

An unrun security check must never look like a passing one.

## What this crate demonstrates

| Test | Expected |
| --- | --- |
| `verify_tag_is_constant_time` | `NO_LEAK_OBSERVED` — `subtle::ConstantTimeEq` |
| `table_scan_is_constant_time` | `NO_LEAK_OBSERVED` — masked full-table scan |
| `arithmetic_on_a_secret_is_permitted` | `NO_LEAK_OBSERVED` — secrecy through arithmetic is fine |
| `vulnerable_tag_compare_leaks` | `LEAK_DETECTED` — secret-dependent **branch** |
| `vulnerable_table_lookup_leaks` | `LEAK_DETECTED` — secret-dependent **address** |
| `leak_in_a_helper_is_detected` | `LEAK_DETECTED` — attributed to the helper, not the caller |
| `heap_secret_is_marked_through_a_slice` | `LEAK_DETECTED` — heap secret marked via `secret_bytes` |

The `vulnerable_*` tests are **expected to be detected**, so a full run exits 1
by design. That is the demonstration, not a defect. For a run that exits 0, use
`--filter constant_time`.

`cargo trace-check test --features untested-contract` adds a `#[constant_time]`
function with no test covering it, and shows the runner reporting it as
`untested` and exiting 2. An annotation never counts as verified without
coverage — and a test that names a contract without invoking it is reported
`claimed-not-invoked` rather than covered.

## What a passing check means

That no modeled secret-dependent behavior was observed **on the paths that test
exercised**, in one optimized test binary, on Linux x86-64. It is not a proof of
constant-time behavior for all inputs, and the analyzed binary is not your
production artifact. See `docs/limitations.md`.
