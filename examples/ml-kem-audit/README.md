# `ml-kem-audit`

Audit adapters that expose RustCrypto [`ml-kem`](https://crates.io/crates/ml-kem)
`0.3.4` decapsulation (ML-KEM-768) to `trace-check`. The dependency is a pinned,
unmodified crates.io release; nothing here reimplements a cryptographic
operation.

```sh
# thirteen contracts, every expectation reproduced, exit 0
cargo trace-check check --all-contracts --ci --jobs 12 \
  --manifest-path examples/ml-kem-audit/Cargo.toml

# one contract, with the analyzed executable kept for disassembly
cargo trace-check check --contract mlkemaudit::decaps::decaps_valid_ciphertext \
  --artifact-dir /tmp/m11 --manifest-path examples/ml-kem-audit/Cargo.toml
```

A run takes about 90 s and peaks around 157 MB. `--all-contracts` rather than
`--all-configured`, because the claim is about every declaration the compiled
library carries — and because it is the only path `--jobs` affects. The crate is
outside the workspace and carries its own lockfile, so it resolves its own
dependency graph.

## What is being claimed

The secret is a **64-byte key-generation seed**, not a decapsulation key: FIPS
203 defines `d ‖ z` as the input to deterministic key generation, so every
secret the audit analyzes is a genuine key. Generated 2400-byte keys would not
be — being a key includes `H(ek)` matching `ek`, which no input constraint
expresses.

A decapsulation key is not uniformly secret, so the adapters draw a
classification boundary on FIPS 203's expanded encoding:

```text
offset     0        1152           2336   2368   2400
           | dk_pke  |      ek      | H(ek) |  z  |
           |<-- secret -->|<-- public -->|<- secret ->|
```

Key generation runs on a **declassified copy** of the seed, so `ρ` and the
rejection sampling it drives stay public; only `dk_pke` and `z` are re-marked
for the decapsulation itself.

[`docs/audits/ml-kem/threat-model.md`](../../docs/audits/ml-kem/threat-model.md)
justifies that boundary and
[`integration-report.md`](../../docs/audits/ml-kem/integration-report.md) is the
measurement.

## Layout

```text
src/layout.rs     the expanded key's offsets, checked against the library's own accessors
src/fixture.rs    key derivation, the declassification boundary, valid and corrupted ciphertexts
src/decaps.rs     the three audit targets, one per path through the FO transform
src/seedlevel.rs  the seed-level encoding, kept as a measurement
src/controls.rs   nine controls -- six expected detected, two expected clean, one measured
src/sink.rs       the fixed-work 32-byte fold
trace-check.toml  description, rationale and expected outcome per contract
```

## The crate deliberately contains leaking functions

Everything in `controls.rs` exists to be detected, or to be *not* detected. The
pair that matters most:

* `secret_component_branch` must stay **detected** — if it ever reads as public,
  the boundary has declassified genuine key material and every clean result here
  is worthless;
* `shared_key_branch` must stay **detected** — it is the sensitivity control,
  and it is what says a leak late in the FO transform would be attributed rather
  than merely failing closed.
