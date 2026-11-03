# enforcement-fixture — the smallest library M8 has to handle

The subject of M8's contract-discovery mutation test. Deliberately as small as a
library can be while still being the case the milestone claims to handle:

* **`no_std`**, so inventory discovery cannot depend on `std`;
* every contract **`dynamic = false`**, so there is no `#[ct_test]` and no M3
  metadata test to discover them through — the asymmetry M8 closes;
* **no `trace-check.toml` at all**, so nothing configures these contracts and
  the only way to find them is the compiler-derived inventory.

Its one dependency is the macro crate. A proc-macro crate is compiled for the
host and contributes nothing to the target binary, so this stays `no_std` and
needs no dev-dependency on `trace-check-test`.

```sh
cargo trace-check list --contracts --manifest-path examples/enforcement-fixture/Cargo.toml
cargo trace-check check --all-contracts --ci --manifest-path examples/enforcement-fixture/Cargo.toml
```

Both functions here are constant-time, so the second command exits 0.

## Why it is outside the workspace

The mutation test copies this library and **rewrites its source**, appending an
annotated function with a secret-indexed load. A workspace member whose source
changed mid-test would disturb `cargo test --workspace`, so this has its own
`[workspace]` table — the same reason `examples/discovery-hazard` does.

## What the mutation test establishes

1. `check --all-contracts --ci` passes: two declarations, both clean.
2. A leaking annotated function is appended. **No configuration is edited.**
3. The inventory grows to three declarations, the dynamic checker finds the leak
   in the developer's own source, and CI exits 1.
4. The annotation is removed and the inventory shrinks back.

The test asserts at every step that no `trace-check.toml` exists. Without that,
it would prove nothing: the whole claim is that a declaration cannot escape
enforcement by not being configured.
