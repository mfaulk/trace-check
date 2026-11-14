# trace-check — Automated side-channel security analysis for Rust

An open-source security testing framework that detects secret-dependent control
flow and memory accesses in compiled cryptographic software. Integrates dynamic
analysis, generated regression tests, and bounded symbolic verification into
Cargo and CI workflows.

Declare security properties with annotations and check them like unit tests.
Ordinary tests check the answer; `trace-check` examines how the optimized program
executes. A passing check is scoped to its artifact and modeled observations,
not proof of constant-time security. The project is experimental.

## Quick start

The native checker requires **Linux x86-64**, **Valgrind 3.28.0 or newer**, its
client-request headers, and a C compiler. Install these before building. Rust
and its components are pinned in [rust-toolchain.toml](rust-toolchain.toml);
`rustup` installs them automatically.

```sh
git clone https://github.com/mfaulk/trace-check.git
cd trace-check
cargo build --workspace
cargo test --workspace --lib --bins
cargo install --path crates/cargo-trace-check --locked
```

Run the checker on a bundled authentication-tag comparison:

```sh
cargo trace-check check --contract crypto::tag::verify_tag \
  --manifest-path examples/crypto-library/Cargo.toml
```

The example also includes intentionally vulnerable functions for testing the
checker. Keep the checkout when using this source installation; its support
crates are used by generated checks.
See the [technical reference](docs/technical-reference.md#prerequisites) for
backend-specific setup, including WebAssembly and symbolic analysis.

## Declare and test a security property

The crates are not published yet. In a library beside the `trace-check` checkout,
add these dependencies to `Cargo.toml` (adjust the path for your layout):

```toml
[dependencies]
trace-check-test = { path = "../trace-check/crates/trace-check-test" }
subtle = "2.6"
```

In `src/lib.rs`, declare that execution must not depend on `expected` when
`supplied` is held fixed. The annotation leaves the function body unchanged:

```rust
#[trace_check_test::constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    use subtle::ConstantTimeEq;
    expected.ct_eq(supplied).unwrap_u8() == 1
}
```

From your library's directory, generate inputs and check the compiled function,
or enforce every declared contract in CI. Replace `my_crate` with your library's
Rust crate name:

```sh
cargo trace-check check --contract my_crate::verify_tag
cargo trace-check check --all-contracts --ci
```

For a specific regression case, add a test that calls the generated analysis
adapter, `verify_tag_ct`, which marks the secret before invoking the function:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Checks that rejecting a mismatching tag has no observed secret-dependent execution.
    #[trace_check_test::ct_test(target = "verify_tag")]
    fn verify_tag_is_constant_time() {
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert!(!verify_tag_ct(expected, &[0u8; 16]));
    }
}
```

Run it with `cargo trace-check test`. Plain `cargo test` reports these security
checks as ignored, since they need the analysis runner.

## Interpreting results

| Result | Meaning |
| --- | --- |
| `LEAK_DETECTED` | A modeled secret-dependent branch or memory access was detected. |
| `NO_LEAK_OBSERVED` | No modeled leak was seen for the inputs and paths tested. |
| `VERIFIED_BOUNDED` | Symbolic analysis found no leak within the declared domain and bounds. |
| `INCONCLUSIVE` | The analysis could not establish a trustworthy result. |

Detected violations and incomplete analyses exit nonzero. Results apply to a
particular compiled artifact and modeled observations, not
every hardware timing effect. See [methodology](docs/methodology.md) and
[limitations](docs/limitations.md) for the scope of these claims.

## Examples and documentation

For a first run on a standalone crate, with an insecure and a constant-time
tag comparison side by side, see [first-check](examples/first-check/README.md).
Then read the [consumer crate](examples/consumer-crate/README.md) or
[cryptographic example library](examples/crypto-library/README.md). Practical
audits cover [RustCrypto `crypto-bigint`](docs/audits/crypto-bigint/findings.md),
[ML-KEM](docs/audits/ml-kem/findings.md), and
[kyberlib](docs/audits/kyberlib/findings.md), with
[controls against documented RSA and ML-DSA weaknesses](docs/audits/controls.md).
These are scoped analyses, not security certifications.

See the [technical reference](docs/technical-reference.md) for commands and
development instructions, and the [audit adapter guide](docs/adapter-guide.md)
for integrating another library. Research notes and development history live
in [docs/](docs/).

Release validation and the publishing procedure are in [docs/publishing.md](docs/publishing.md).
Licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
