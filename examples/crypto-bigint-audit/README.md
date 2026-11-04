# crypto-bigint-audit — auditing somebody else's cryptographic library

This crate analyzes [RustCrypto `crypto-bigint`](https://github.com/RustCrypto/crypto-bigint)
`0.7.10`, consumed as an ordinary pinned crates.io dependency. **No upstream
source is modified in the clean integration.** Nothing here reimplements a
cryptographic operation: each adapter decodes trace-check's supported input
shapes into the library's own types, calls the library's own function, and
consumes the whole result.

```sh
cargo trace-check check --all-contracts --ci \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml
```

Eighteen declarations, 100% enforcement, exit 0 — because every declaration's
expected outcome is recorded in `trace-check.toml`, including the two the tool
is *not* expected to find. About 317 s and 187 MB on one x86-64 host.

| Contract | What it is | Outcome |
| --- | --- | --- |
| `add::wrapping_add_secret_left` | **Target A:** `U256::wrapping_add`, secret left operand | `NO_LEAK_OBSERVED` |
| `add::wrapping_add_both_secret` | the same, both operands secret | `NO_LEAK_OBSERVED` |
| `select::ct_select` | **Target B:** `CtSelect::ct_select`, all three inputs secret | `NO_LEAK_OBSERVED` |
| `monty::mul_secret_left` | **Target C:** `ConstMontyForm::mul` mod p-256 | `NO_LEAK_OBSERVED` |
| `monty::mul_both_secret` | the same, both operands secret | `NO_LEAK_OBSERVED` |
| `controls::pre_decode_first_byte` | B1: branch on `secret[0]` before decoding | `LEAK_DETECTED` |
| `controls::decoded_high_limb_branch` | B2: branch on decoded `secret[0..8]` | `LEAK_DETECTED` |
| `controls::decoded_interior_limb_branch` | B3: branch on decoded `secret[8..16]` | `LEAK_DETECTED` |
| `controls::decoded_last_byte_branch` | B4: branch on `secret[31]` alone | `LEAK_DETECTED` |
| `controls::carry_branch` | B5: branch on the carry the library returned | `LEAK_DETECTED` |
| `controls::decoded_address_probe` | B6: secret-derived load address | `LEAK_DETECTED`, address |
| `controls::branch_selected` | B7: Target B's selection written with an `if` | `LEAK_DETECTED` |
| `controls::public_operand_branch` | negative control: public operand only | `NO_LEAK_OBSERVED` |
| `hidden::boundary_gate` | leak behind an all-ones public operand | `LEAK_DETECTED` |
| `hidden::nested_modes` | leak behind three public predicates | `LEAK_DETECTED`, needs `--explore` |
| `hidden::nested_modes_wide` | the same, diluted by a public 32-byte operand | `NO_LEAK_OBSERVED` |
| `hidden::magic_gate` | leak behind an exact 32-bit equality | `NO_LEAK_OBSERVED` |
| `hidden::nested_modes_clean` | false-positive control, same nested shape | `NO_LEAK_OBSERVED` |

The last five are the M9.7 input-discovery fixtures, and two of them are
`NO_LEAK_OBSERVED` for a leak that is really there. Those rows are declared, so
the limit stays measured rather than implicit — see
[`docs/audits/crypto-bigint/exploration.md`](../../docs/audits/crypto-bigint/exploration.md).
The symbolic backend finds all four.

`select::ct_select` clean beside `controls::branch_selected` detected is the
pair worth looking at first: the library's selection compiles to four
`test`/`cmovne` pairs through the `cmov` crate, and the same function written
with a branch is found.

## Why the controls are the point

A contract here covers the **whole adapter invocation** — decoding, the
library's types, the library's operation, and the result consumption. So a
clean result on `wrapping_add_secret_left`, read alone, is indistinguishable
from a harness that marked nothing or a secret that stopped being tracked at
the first type conversion.

The seven controls are what make it mean something. B2–B6 are driven by values
the *library* produced from the secret bytes — decoded limbs, and in B5 the
`Limb` carry returned by `Uint::carrying_add`. B1 is deliberately listed first
and deliberately weak: it only shows the array was marked at all. B7 is the
branchy counterexample to Target B rather than a propagation control.

They are declared `expected_outcome = "LEAK_DETECTED"`, so if one ever stops
being detected the run fails on an unmet expectation instead of reporting a
clean sweep.

## Mutating the real library

The decisive evidence is that changing the *library* — not the harness —
changes the verdict. Three mutations do, in three different upstream files:

| Mutation | Where | Contract | Finding |
| --- | --- | --- | --- |
| A | a branch on the carry in `Uint::carrying_add` (`src/uint/add.rs`) | `add::wrapping_add_secret_left` | branch, at `src/uint/add.rs:31` |
| B | a branch inside the library's own `CtSelect` (`src/uint/ct.rs`) | `select::ct_select` | branch, at `src/uint/ct.rs:78` |
| C | a secret-indexed load in the Montgomery reduction (`src/modular/mul.rs`) | `monty::mul_secret_left` | **address**, at `src/modular/mul.rs:106` |

```sh
python3 ci/mutate-m9.py --mutation mutation-c-indexed-reduction \
  --contract cbaudit::monty::mul_secret_left \
  --expect-outcome LEAK_DETECTED --expect-frame src/modular/mul.rs \
  --expect-class address --verify-reproducer --compare-clean
```

The driver stages the pinned source into an isolated copy, applies the patch,
runs this crate's own functional tests against the mutated dependency, and
checks the **unchanged** contract. Each finding's leaf frame is upstream
source, at the patched line; the adapter appears only as its caller. The clean
and mutated artifact hashes must differ, or the run fails.

`--expect-class` earns its place on C. Every secret executes the same
instruction sequence through a secret-indexed load, so a tool that modelled
only control flow would report that mutated library clean — which is why the
acceptance criterion is "at least one address finding", not "three findings".

Two negative controls guard the experiment itself:
`negative-stale-patch.patch` must fail to apply, and
`negative-unreached-branch.patch` puts the same branch in a function the
adapters never call, so it reports `NO_LEAK_OBSERVED` and cannot be claimed as
a detection.

## The same contracts, verified symbolically

```sh
cargo trace-check verify --all-contracts \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml
```

Eighteen contracts, every declared expectation reproduced, **zero
`INCONCLUSIVE`**, 18 s and 184 MB for the whole matrix — including 256-bit
Montgomery multiplication, which M9's plan did not require to complete at all.
`VERIFIED_BOUNDED` quantifies over the whole declared secret domain rather than
over 64 generated inputs.

It also finds every planted `hidden` leak, including the two no dynamic
strategy reaches: the gate bytes are symbolic, so a solver does not guess a
32-bit constant, it solves for one.

It is cheap because the cost scales with paths and observations, not with term
size: the analyzer never reasons about what a 256-bit product equals, only about
whether an address can differ. Constant-time code is branchless, so it has one
path. `controls::decoded_address_probe` is the row worth reading — one path,
4/4 control-flow checks passed, 256 of 257 *memory* checks — a leak with no
branch divergence anywhere.

Measurements and caveats in
[`docs/audits/crypto-bigint/symbolic-feasibility.md`](../../docs/audits/crypto-bigint/symbolic-feasibility.md).
Needs `podman` or `docker`: the analyzer runs in a pinned container.

## The sink, and why it is not decoration

The generated checker returns one scalar and a 256-bit result does not fit in
one. Whatever reduces it decides what the compiler may discard: a sink reading
four of the thirty-two bytes licenses the optimizer to compute one limb, and
then the artifact no longer contains the operation the contract names.

`sink::consume_all_bytes` folds all 32 bytes with `acc * 31 + byte`.
Multiplying by 31 is invertible mod 256, so no byte's contribution can be
cancelled, and `every_byte_changes_the_result` asserts exactly that. It is not
a hash and carries no cryptographic property.

## Two contracts, one operation, and a lesson about symbols

`wrapping_add_secret_left` and `wrapping_add_both_secret` differ only in which
parameters are *declared* secret, and a declaration does not change codegen.
Written identically they compiled to one function with both symbols at one
address, and a leak inside the dependency then came back `INCONCLUSIVE`: the
finding was correct and correctly located, but Valgrind named the other
contract's folded symbol, so attribution refused it.

Each adapter now xors a distinct compile-time constant into its result — no
branch, no address dependency, one instruction. The general rule: **an adapter
set must be distinguishable in the compiled artifact, not just in its source.**
Measurements in
[`docs/audits/crypto-bigint/integration-report.md`](../../docs/audits/crypto-bigint/integration-report.md).

## Layout

| File | |
| --- | --- |
| `src/add.rs` | Target A, `U256::wrapping_add`, two secret roles |
| `src/select.rs` | Target B, `CtSelect::ct_select` for `U256` |
| `src/monty.rs` | Target C, `ConstMontyForm::mul` modulo the P-256 prime |
| `src/controls.rs` | the seven controls and the negative control |
| `src/hidden.rs` | the M9.7 fixtures: leaks behind public predicates |
| `src/sink.rs` | the fixed-work 32-byte fold |
| `tests/functional.rs` | all three operations against the independent oracle, at full width |
| `tests/vectors/generated.rs` | 1012 committed vectors, from `ci/gen-m9-vectors.py` |
| `trace-check.toml` | per-contract description, rationale and expected outcome |
| `Cargo.lock` | committed; the audit's claim is about one resolved graph |

`cargo test` runs the functional and structural tests: 1012 vectors whose
expected values were computed in Python's arbitrary-precision integers, a
schoolbook addition reference, the limb layout of a big-endian decode, the
P-256 prime assembled arithmetically rather than copied from the hex literal,
and the sink's all-bytes property. **No side-channel result in this example is
interpreted before those pass** — an adapter that mishandles byte order or
builds the wrong Montgomery value leaves the checker reporting on a function
nobody asked about.

The vectors compare the operation's **complete 32-byte result**, not the
adapter's one-byte return value. The sink maps 2^256 results onto 256 values
and, being linear, admits exact cancellation between two byte changes — so each
operation has a helper (`add::wrapping_add_bytes`, `select::ct_select_bytes`,
`monty::mul_bytes`) returning the full result, the annotated adapter folds that
helper's output, and the tests compare the helper. One code path, two
consumers.

Regenerate the fixture with `python3 ci/gen-m9-vectors.py`; CI runs
`--check` so it cannot drift from the generator.

`dynamic = false` on every annotation: this crate wants its contracts *checked*
by `cargo trace-check check`, which needs no hand-written `#[ct_test]`, so it
carries no dev-dependency on `trace-check-test` and stays `no_std` outside its
own test build.

## Scope

All three operations are implemented and analyzed, and all three upstream
mutations are in place. What is outstanding is the symbolic feasibility spike
(M9.6), the M6-versus-M7 detection comparison (M9.7) and the adoption report
(M9.8). See [`docs/adapter-guide.md`](../../docs/adapter-guide.md) for how to write an
adapter for a different library,
[`docs/MILESTONE-09.md`](../../docs/MILESTONE-09.md) for the state of each work
package, and
[`docs/audits/crypto-bigint/threat-model.md`](../../docs/audits/crypto-bigint/threat-model.md)
for what the results do and do not establish — in particular, that none of this
is a claim that `crypto-bigint` is secure.
