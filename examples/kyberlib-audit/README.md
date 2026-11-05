# `kyberlib-audit`

Audit adapters that expose [`kyberlib`](https://crates.io/crates/kyberlib)
`0.0.11` ML-KEM-768 decapsulation to `trace-check`. The second discovery target
of M11; the dependency is a pinned, unmodified crates.io release.

```sh
# ten contracts, every expectation reproduced, exit 0
cargo trace-check check --all-configured --ci --jobs 12 \
  --manifest-path examples/kyberlib-audit/Cargo.toml
```

About 137 s and 158 MB. Outside the workspace, with its own lockfile.

## What is claimed, and why it matches the other audit

The secret is a 64-byte key-generation seed, key generation runs on a
declassified copy of it, and only `sk_pke` and `z` are marked for the
decapsulation. That is deliberately identical to `examples/ml-kem-audit`:
varying the implementation and nothing else is what makes the two results
comparable. The reasoning lives in
[`docs/audits/ml-kem/threat-model.md`](../../docs/audits/ml-kem/threat-model.md)
and is not restated here.

Two things differ, both forced by the library:

* key generation and encapsulation take an RNG rather than explicit randomness,
  so `fixture::FixedRng` supplies the seed and `m`;
* `MlKem768DecapKey` lends out its storage through `as_bytes`, so the marking
  covers the buffer the library actually reads — cleaner than the round trip
  through a serialized encoding the `ml-kem` adapters need.

## The result worth knowing about

`seedlevel::keygen_and_decaps` reports two **attributed** secret-dependent
branches in `reference::indcpa::rej_uniform`, called from `gen_matrix`. They are
taint-model artifacts: the sampler branches on `ρ`, which the protocol
publishes. The same algorithmic step in `ml-kem` is reported as *unattributable*
diagnostics, so the pair of targets is what localizes that provenance loss to
`ml-kem`'s XOF path rather than to sponges in general.

[`docs/audits/kyberlib/findings.md`](../../docs/audits/kyberlib/findings.md) has
the stacks and the triage.

## Functional evidence

`tests/functional.rs` runs the NIST ACVP fixture from the `ml-kem` audit's
directory — 25 key-generation and 10 decapsulation vectors — and `kyberlib`
reproduces all of them, on both paths through the FO transform. Worth knowing
because the crate's `derive` documentation cites *draft-schwabe-cfrg-kyber*
rather than FIPS 203: on NIST's own vectors, its default `kyber768` build is
ML-KEM-768.
