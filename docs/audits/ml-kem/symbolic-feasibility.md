# M11.3 — Bounded symbolic verification against ML-KEM-768

The plan scoped the symbolic backend to "leaf operations where it can
realistically settle". The measured answer is that `ml-kem` 0.3.4 exposes none,
so the attempt was made against the smallest thing its public API offers —
key generation plus a whole decapsulation — and this file records what happened,
including two link blockers that had to be cleared before any analysis ran at
all.

---

## 1. There is no leaf to point at

`ml-kem` declares `mod algebra`, `mod compress`, `mod crypto`, `mod pke` and
`mod param`, all private. The `hazmat` feature un-hides one doc comment and
exposes no API. So no modular reduction, no compression, no `ct_eq`, no
conditional selection is reachable from outside the crate.

That is a statement about the target's API surface, not about the analyzer. A
library that wanted bounded verification of its arithmetic would have to expose
it, which is a real tension with keeping internals private — and worth saying
plainly, because "the symbolic backend did not verify ML-KEM" invites the wrong
inference.

## 2. Two blockers, cleared in order

### The audit crate cannot be verified at all

`examples/ml-kem-audit` depends on `trace-check-secret` to draw its
classification boundary, and that crate links `std`. The verification artifact
is freestanding, so:

```text
error[E0152]: found duplicate lang item `panic_impl`
  = note: the lang item is first defined in crate `std`
          (which `mlkemaudit` depends on)
```

That failure is about this repository's adapter, not about `ml-kem`. A symbolic
result has to be attributable to the target, so the attempt moved to
`examples/ml-kem-symbolic`: `no_std`, `ml-kem` with `default-features = false`,
the proc macro, nothing else. The cost is that no declassification is available
there, so the symbolic attempt is necessarily the **seed-level** encoding.

### `undefined symbol: memcpy`

With a `no_std` adapter the link still failed:

```text
rust-lld: error: undefined symbol: memcpy
  >>> referenced by crypto.rs:0  (ml-kem-0.3.4/src/crypto.rs)
  >>> referenced by algebra.rs:176  (<Polynomial as Ntt>::ntt)
  >>> referenced by algebra.rs:415  (module-lattice-0.2.4)
```

rustc lowers a large move to a `memcpy` call rather than to inline code, and the
artifact links `libcompiler_builtins` without its `mem` feature, so nothing
defines the symbol. Every earlier example moved values small enough to be copied
inline; `ml-kem` moves kilobyte-sized polynomial arrays and does not.

This is the same shape of blocker as M9's `rust_eh_personality` — bounded
verification was unavailable to an entire class of library, and nothing in this
repository could have shown it. The generated harness now defines `memcpy`,
`memmove`, `memset`, `memcmp` and `bcmp` as byte loops, with a regression test
in `harness.rs`.

Two things about those definitions are deliberate, and both were found by
measurement rather than by design:

* **The accesses are volatile.** Without that, LLVM's loop-idiom recognition
  rewrites each body into a call to the intrinsic it implements.
* **`bcmp` does not delegate to `memcmp`.** When it did, the two were mutually
  inlinable and `rustc` died with `SIGSEGV` inside LLVM, with the
  `RUST_MIN_STACK` hint that marks a stack overflow in an optimizer pass.

A crate-wide `#![no_builtins]` also stops the first problem and was **rejected**:
it changes how cross-crate-inlined library code compiles in the harness crate,
which flipped M5's `crypto::tag::verify_tag_early_exit` from `VERIFIED_BOUNDED`
to `LEAK_DETECTED`. A shim must not change the shape of the code under analysis.
That near-miss is the most useful thing this part of M11 produced: the regression
was caught by an existing expectation, on a contract from six milestones ago.

---

## 3. What the analyzer did with a whole decapsulation

```sh
cargo trace-check verify --contract mlkemsym::keygen_and_decaps \
  --manifest-path examples/ml-kem-symbolic/Cargo.toml
```

| | |
| --- | --- |
| Analyzer | binsec 0.11.2, `-checkct` relational symbolic execution, build `dfe4739` |
| Solver | bitwuzla 1.0.6, CaDiCaL 2.1.2 |
| Target reached | **yes**, at `0x20b8b0` from `tc_verify_entry`, analyzer-reported |
| Input domain | `seed` secret, 512 bits all symbolic; `ciphertext` public, 8704 bits symbolic and held equal |
| Checks discharged | **43 / 43** control flow, **7297 / 7297** memory access |
| Paths | **0 of 4 finished**, 0 pending |
| Depth | max reached 11044, bound 2,000,000 |
| Unknown solver answers | 0 |
| Result | **INCONCLUSIVE** — the analyzer reported `unknown` |
| Cost | 8.2 s wall, 172.6 MB peak RSS |

So the backend reaches ML-KEM-768 key generation and decapsulation, discharges
7340 noninterference checks over a fully symbolic 512-bit secret without finding
a violation, and then fails to complete a single path. Nothing is verified. The
outcome is `INCONCLUSIVE`, which is what the configuration declares, and it is
recorded as an expectation so a future analyzer that *does* settle it surfaces as
a change rather than passing unnoticed.

Two readings to avoid:

* **7340 clean checks are not a verification.** No path finished, so the
  exploration that would have to be exhaustive over the declared domain never
  completed. `VERIFIED_BOUNDED` is the only outcome that means anything
  quantified, and this is not it.
* **`unknown` is not evidence of a leak.** The analyzer declined to answer, in
  the fail-closed direction.

### A diagnosability gap

The run does not say *why* exploration stopped: depth is three orders of
magnitude below the bound, no solver query came back unknown, and no path is
pending. The most likely causes are an unmodeled instruction or an internal
analyzer limit, and distinguishing them needs the analyzer's own trace — which
the tool does not retain, even under `--artifact-dir`, and which cannot be
reconstructed from the report. Keeping the analyzer's log beside the artifact is
the smallest change that would make this answerable, and it is recorded as an
adoption item rather than as a conclusion.

---

## 4. What this means for the audit

The dynamic backend carries the whole audit for `ml-kem`. The symbolic result
contributes exactly one thing: it establishes that the target is *reachable* by
bounded verification and that the obstacle is path completion, not integration —
which is a better-defined starting point than the link errors it began with.

Coverage, stated without inflation: three decapsulation contracts
`NO_LEAK_OBSERVED` over 192 generated cases under Memcheck; one contract
`INCONCLUSIVE` under BINSEC with 7340 individual checks clean and no path
finished; no `VERIFIED_BOUNDED` anywhere in this audit.
