# Findings

Everything recorded here is either a **deliberately introduced** leak — a
control in the adapter, or a patch applied to a disposable copy of the
dependency — or a clean result. **No side channel was found in unmodified
`crypto-bigint` 0.7.10 by this work**, and that sentence is bounded by
[`threat-model.md`](threat-model.md): three operations, two modeled
observations, one artifact, 64 generated inputs each.

Backend `generated-memcheck` / Valgrind 3.28.0, Rust 1.97.0,
`x86_64-unknown-linux-gnu`, `crypto-bigint =0.7.10` with no default features.
Reproduce with:

```sh
cargo trace-check check --all-contracts --ci \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml
```

## Clean results on unmodified library code

| Contract | Operation | Secrets | Outcome |
| --- | --- | --- | --- |
| `add::wrapping_add_secret_left` | `U256::wrapping_add` | `left` | `NO_LEAK_OBSERVED` |
| `add::wrapping_add_both_secret` | `U256::wrapping_add` | `left`, `right` | `NO_LEAK_OBSERVED` |
| `select::ct_select` | `CtSelect::ct_select` for `U256` | all three | `NO_LEAK_OBSERVED` |
| `monty::mul_secret_left` | `ConstMontyForm::mul` mod p-256 | `left` | `NO_LEAK_OBSERVED` |
| `monty::mul_both_secret` | `ConstMontyForm::mul` mod p-256 | `left`, `right` | `NO_LEAK_OBSERVED` |
| `controls::public_operand_branch` | negative control | `secret` | `NO_LEAK_OBSERVED` |

Each is `NO_LEAK_OBSERVED` over the inputs that were generated and the paths
they took. None is a proof.

What the artifacts contain, from `objdump -d -l`:

* **Addition** — `Uint<4>::from_be_slice` (`uint/encoding.rs:49`), eight
  `bswap`, then `primitives::carrying_add` (`primitives.rs:15`) as a four-limb
  `add`/`adc` chain, then `EncodedUint<4>::new_be` (`uint/encoding.rs:471`).
  No conditional jump in the adapter.
* **Selection** — `Choice::from_u8_lsb` (`ctutils-0.4.8/src/choice.rs:119`)
  compiles to `and $0x1,%dl`, and the selection to four
  `test`/`cmovne` pairs through `<u64 as cmov::Cmov>::cmovnz`
  (`cmov-0.5.4/src/backends/x86.rs:16`) — a conditional move per limb, so no
  branch and no secret-derived address.
* **Montgomery multiplication** — `crypto_bigint::modular::mul::mul_montgomery_form::<4>`
  is a distinct out-of-line symbol, 1199 bytes, called three times (both
  conversions in and the multiply itself). Its instruction mix is 28 `mul`,
  41 `adc`, 45 `add` and **no conditional jumps**, covering
  `modular/mul.rs:96–148` — the multiplication and the reduction. The adapter
  around it is likewise branch-free.

## Deliberately introduced: adapter-local controls

All seven were detected, and every one was attributed to a line in
`src/controls.rs` with no `crypto-bigint` frame in its stack. That is the half
of M9.1's Experiment D which requires an adapter-local leak not to be
misreported as an upstream one.

| Control | Driven by | Class | Leaf frame |
| --- | --- | --- | --- |
| `pre_decode_first_byte` | `secret[0]`, before decoding | branch | `controls.rs:55` |
| `decoded_high_limb_branch` | decoded limb 3 = `secret[0..8]` | branch | `controls.rs:73` |
| `decoded_interior_limb_branch` | decoded limb 2 = `secret[8..16]` | branch | `controls.rs:88` |
| `decoded_last_byte_branch` | decoded limb 0, masked to `secret[31]` | branch | `controls.rs:104` |
| `carry_branch` | the `Limb` carry `Uint::carrying_add` returned | branch | `controls.rs:121` |
| `decoded_address_probe` | load index from the decoded sum | **address** | `read_volatile` from `controls.rs:139` |
| `branch_selected` | `choice`, selecting with an `if` | branch | `controls.rs:164` |

`pre_decode_first_byte` is the weak one and is listed first for that reason: it
shows the array was marked, nothing more. The four that establish propagation
are B2–B5, and `carry_branch` is the strongest — the value it branches on is a
return value of upstream code.

`branch_selected` is the pair to `select::ct_select`'s clean result, and
together they are the most direct statement this work produces for a
cryptographic developer: the constant-time selection idiom is checkable, and
abandoning it is detected.

## Deliberately introduced: mutations to the library

Applied to an isolated copy of the pinned source. The adapter, its contract and
its generated inputs are unchanged.

### Mutation A — a branch on the carry inside `Uint::carrying_add`

`ci/mutations/mutation-a-carry-branch.patch`, against `src/uint/add.rs`.
Preserves the arithmetic result; the adapter's whole functional suite passes
against the mutated dependency.

| | |
| --- | --- |
| Contract | `cbaudit::add::wrapping_add_secret_left`, unchanged |
| Clean dependency tree | `814cb6a994fd9b74…` → `NO_LEAK_OBSERVED` |
| Mutated dependency tree | `cb85a782ae1dd6f3…` → `LEAK_DETECTED` |
| Classification | secret-dependent branch |
| Leaf frame | `carrying_add<4> (src/uint/add.rs:31)` |
| Caller | `wrapping_add<4> (src/uint/add.rs:52)` |
| Contract `site` | `add.rs:38` — the **adapter's** frame, not the leak's |

The mutation needs `core::hint::black_box` in the taken arm. Without it the
branch becomes a `cmov` at `opt-level = 3` and there is nothing to detect — the
sixth time this project has recorded the compiler erasing a secret-dependent
branch.

**Attribution caveat.** The leaf frame is upstream and the adapter appears only
as its caller, so the two cases are distinguishable. But the per-contract
`site` field names the contract's frame, so reading `site` alone would place
this finding in the adapter. The full stack is the disambiguation; the
basenames alone are not, since `src/uint/add.rs` and the adapter's `add.rs`
collide.

### Mutation B — a branch inside the library's own `CtSelect`

`ci/mutations/mutation-b-branch-select.patch`, against `src/uint/ct.rs`.
Replaces the per-limb conditional move with `if choice.to_bool_vartime()` —
the accessor whose own name says it is not constant-time. Same returned value.

| | |
| --- | --- |
| Contract | `cbaudit::select::ct_select`, unchanged |
| Clean dependency tree | `814cb6a994fd9b74…` → `NO_LEAK_OBSERVED` |
| Mutated dependency tree | `85aa2897287dc215…` → `LEAK_DETECTED` |
| Classification | secret-dependent branch |
| Leaf frame | `ct_select<4> (src/uint/ct.rs:78)` |
| Caller | `cbaudit::select::ct_select (select.rs:40)` |

This is the most legible of the three for a cryptographic developer: the
library's own constant-time selection is replaced with the obvious
implementation, nothing else changes, and the audit notices.

### Mutation C — a secret-indexed load inside the Montgomery reduction

`ci/mutations/mutation-c-indexed-reduction.patch`, against
`src/modular/mul.rs`. Routes the low nibble of the Montgomery factor `u`
through a 16-entry identity table, so `M9_IDENTITY[n] == n` and the arithmetic
is unchanged — but the load's address now depends on a secret-derived value.

| | |
| --- | --- |
| Contract | `cbaudit::monty::mul_secret_left`, unchanged |
| Clean dependency tree | `814cb6a994fd9b74…` → `NO_LEAK_OBSERVED` |
| Mutated dependency tree | `a8017eeb080cc67d…` → `LEAK_DETECTED` |
| Classification | **secret-dependent address** (`secret_dependent_value`) |
| Leaf frame | `montgomery_multiply_inner (src/modular/mul.rs:106)` |
| Caller | `mul_montgomery_form::<4> (src/modular/mul.rs:147)` |
| Reproducer | replayed, `reproduced` against the same artifact |

Every secret executes the same instruction sequence here, so a tool that
modelled only control flow would report this mutated library clean. That is why
M9.5 requires an address finding and not merely three findings, and why
`ci/mutate-m9.py --expect-class` checks the classification rather than the
outcome alone.

A `const` table rather than a `static`, because `montgomery_multiply_inner` is
a `const fn` and a `const fn` body may not read a `static`. The same constraint
rules out `black_box` and `read_volatile` as barriers here — which is why this
mutation had to be built out of a data dependency the optimizer keeps rather
than an explicit barrier.

### Acceptance

M9.5 asks for three independently designed upstream mutations, at least one
branch finding and at least one address finding, with the adapter unchanged.
A, B and C satisfy that: three different files, three different contracts, two
branch findings and one address finding, and the adapter and its
`trace-check.toml` are byte-identical across all six runs.

## A tooling finding

Not a side channel, but the most consequential thing M9.1 turned up.

**Two adapters with bit-identical bodies are folded to one symbol, and a
finding in either becomes unattributable.** Role variants over the same
operation differ only in a `secret = …` declaration, which does not change
codegen, so they hit this immediately. Before the fix, Mutation A reported:

```text
INCONCLUSIVE -- 8 secret-dependency finding(s) were observed but none is
attributable to `wrapping_add_secret_left`; they are retained for inspection.
   carrying_add<4> (src/uint/add.rs:31)
   wrapping_add<4> (src/uint/add.rs:52)
   cbaudit::add::wrapping_add_both_secret (add.rs:34)
```

The leak was real, reached and correctly located; the frame named was the other
contract's surviving symbol. Note the failure direction — `INCONCLUSIVE`, not
`CHECKED`. The tool declined to claim a result it could not attribute rather
than reporting a clean one.

Fixed in the adapters with one `xor` against a per-contract constant, and
generalized in [`docs/adapter-guide.md`](../../adapter-guide.md).
