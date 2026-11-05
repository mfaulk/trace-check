# M11.0 — Target selection and source pinning

**Date of record:** 2026-11-05
**Resolved against:** crates.io API and the RustSec advisory database
**Platform:** Linux x86-64, Rust 1.97.0 (pinned by `rust-toolchain.toml`)

Every target below is resolved to an exact published version. The rule M11
adopted after the proposal's first draft is that **nothing may be cited as a
target that has not been resolved to a crates.io version**, and §4 records why.

---

## 1. The primary discovery target

| | |
| --- | --- |
| Crate | `ml-kem` |
| Version | **0.3.4**, published 2026-10-31 |
| Parameter set | ML-KEM-768 |
| Standard | FIPS 203 |
| License | Apache-2.0 OR MIT |
| Repository | `RustCrypto/KEMs` |
| Downloads | 14,249,355 at time of record |
| RustSec advisories | **none** — `crates/ml-kem` does not exist in the advisory database |
| Audit status, in the crate's own words | "The implementation contained in this crate has never been independently audited! USE AT YOUR OWN RISK!" |

Pinned in [`examples/ml-kem-audit/Cargo.toml`](../../../examples/ml-kem-audit/Cargo.toml)
as `=0.3.4` with `default-features = false`, and the resolved graph is committed
in that crate's own `Cargo.lock`. The exact-version requirement is deliberate:
a caret requirement would let a patch release change the compiled code a
recorded finding refers to.

`default-features = false` drops `alloc`, so the decapsulation key's components
are stored inline rather than boxed. Nothing in the audit needs a heap.

### What is reachable, and what that costs

`ml-kem` 0.3.4 declares `mod algebra`, `mod compress`, `mod crypto`, `mod pke`
and `mod param` — **all private**. The `hazmat` feature un-hides the
documentation of `EncapsulationKey::encapsulate_deterministic`; it exposes no
additional API.

So the only operations an external audit can point at are key generation,
encapsulation and decapsulation. There is no reachable leaf — no modular
reduction, no compression, no constant-time comparison — and that decides the
shape of the whole milestone:

* the dynamic Memcheck backend analyzes whole operations, which is what it is
  good at;
* the symbolic backend has nothing in range. M11's plan scoped it to "leaf
  operations where it can realistically settle", and the measured answer is
  that the library exposes none. That is a property of the target's API
  surface, not a limit of the analyzer, and
  [`symbolic-feasibility.md`](symbolic-feasibility.md) records it with the
  evidence.

### The operations under audit

| Target | Operation | Why |
| --- | --- | --- |
| A | `DecapsulationKey768::decapsulate`, valid ciphertext | the successful FO path: re-encryption agrees, the constant-time selection returns the true shared key |
| B | the same, one public byte of a valid ciphertext flipped | the implicit-rejection path — what a decapsulation oracle attacks |
| C | the same, arbitrary supplied ciphertext | the attacker's actual position; decapsulation is total, so no input-domain restriction applies |
| D | `DecapsulationKey768::from_seed` followed by decapsulation | the seed-level encoding, kept as a measurement of the classification boundary rather than as a separate claim |

`decapsulate` is confirmed present in the analyzed artifact as a distinct
out-of-line symbol; [`integration-report.md`](integration-report.md) has the
disassembly.

---

## 2. The second discovery target

| Crate | Version | Downloads | License | Deterministic key generation | Note |
| --- | --- | --- | --- | --- | --- |
| **`kyberlib`** | 0.0.11, 2026-10-26 | 10,055 | MIT OR Apache-2.0 | `derive(seed: &[u8])`, 64 bytes split `(d, z)` | describes itself as "a robust, audit-friendly Rust implementation of FIPS 203 ML-KEM". Carries both a `reference` and an `avx2` implementation path, and a `fips` feature |
| `mlkem-rs` | 0.12.0, 2026-05-04 | 2,904 | MIT OR Apache-2.0 | not established | 0.10.0 through 0.12.0 all published on one day; claims NIST-KAT verification |
| `pqc-ml-kem` | 0.8.0, 2025-05-20 | 3,744 | MIT | not established | |
| `rustpq` | 0.3.0, 2025-12-07 | 1,456 | Apache-2.0 OR MIT | not established | a suite rather than a single primitive |

`kyberlib` is the selected second target: it is the only candidate with a
documented deterministic key-generation entry point, which is what the secret
input domain in [`threat-model.md`](threat-model.md) requires, and the only one
that states an auditability goal of its own.

One caveat recorded now rather than discovered later: `derive`'s documentation
says "as specified in draft-schwabe-cfrg-kyber", not FIPS 203, and the crate has
a separate `fips` feature. Whether its derived key agrees byte-for-byte with
`ml-kem`'s for the same `(d, z)` is therefore **not** assumed, and the audit does
not use one implementation as the other's oracle. Both are checked against NIST
ACVP vectors instead.

The portable `reference` path is the target. `avx2` is out of scope for M11, and
the adapter must not enable it.

---

## 3. External controls

These calibrate the audit. Neither can count as a discovery.

### Positive — `rsa`, RUSTSEC-2023-0071

| | |
| --- | --- |
| Advisory | RUSTSEC-2023-0071, dated 2023-11-22, category `crypto-failure` |
| Affects | `rsa` 0.9.10 (latest stable) and 0.10.0-rc.18 |
| Patched versions | **none** |
| Defect | the Marvin attack: key-dependent timing in RSA decryption, observable over a network |

Valuable precisely because it is unpatched: the defect is in current published
source, so the control does not depend on pinning an old release. `rsa`'s latest
stable is 0.9.10 and its pre-release line has advanced to 0.10.0-rc.20
(2026-11-03), which the control's pin must name explicitly.

### Negative — `ml-dsa`, RUSTSEC-2025-0144

| | |
| --- | --- |
| Advisory | RUSTSEC-2025-0144, reported 2025-12-12, issued 2026-01-27 |
| Aliases | CVE-2026-22705, GHSA-hcp2-x6j4-29j7 |
| Affects | `< 0.1.0-rc.3`; patched in 0.1.0-rc.3, published 2026-01-10 |
| Defect | `decompose` performed `r1.0 /= TwoGamma2::U32` — a variable-latency hardware division on values derived from the secret `s2` and `t0` during signing |
| Current version | 0.1.2, 2026-10-31 |

The affected revisions are still published and unyanked, so the control pins one
of them. This is the control this project has never had: the leak is
**instruction latency**, which the observation model does not include, so a
correct run reports nothing. The control's job is to demonstrate that miss —
and its first obligation is to show the division is actually in the analyzed
machine code, because a compiler that strength-reduces a division by a constant
removes the vulnerability and makes the clean result meaningless.
[`controls.md`](controls.md) records both.

---

## 4. Removed from the plan: `crypto-pq-ml-kem`

The milestone was proposed with `crypto-pq-ml-kem` 0.1.0 as its first
investigation, on the strength of a stated release date and a documented
claim to avoid secret-dependent branching.

**No such crate exists.** `https://crates.io/api/v1/crates/crypto-pq-ml-kem`
returns HTTP 404, and a crates.io search returns no crate by that name. Search
indexes can retain documentation for things that are not retrievable, and a
target that cannot be fetched and checksummed cannot be audited.

Hence the rule at the top of this file. The four candidates in §2 were each
resolved through the crates.io API before being written down, and the two in §3
through the advisory database.
