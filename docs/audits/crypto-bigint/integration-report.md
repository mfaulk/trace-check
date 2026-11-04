# M9.1 — the feasibility gate, and what it measured

**Status:** passed, on `x86_64-unknown-linux-gnu`, Rust `1.97.0`, Valgrind
`3.28.0`, against `crypto-bigint` `0.7.10` (see
[`target-selection.md`](target-selection.md) for the pin).

The gate exists because of one risk, and it is not whether an adapter compiles:

> Does a secret declared as `&[u8; 32]` still read as secret after
> `crypto-bigint` has decoded it into a `Uint<4>` and done multi-limb
> arithmetic with it?

If the answer were no, a clean result on a real operation would be worthless
and accepting `U256` directly as an annotated parameter would not have fixed
it. The answer is yes, and the rest of this document is the evidence.

Reproduce the whole thing:

```sh
cargo trace-check check --all-contracts --ci \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml

python3 ci/mutate-m9.py --mutation mutation-a-carry-branch \
  --contract cbaudit::add::wrapping_add_secret_left \
  --expect-outcome LEAK_DETECTED --expect-frame src/uint/add.rs --compare-clean
```

---

## Experiment A — a real `U256`, built from a declared secret

`cbaudit::add::wrapping_add_secret_left` decodes both operands with the
library's own `U256::from_be_slice`, calls the library's own `wrapping_add`,
and folds all 32 result bytes. Seventeen lines of adapter code outside its
tests; no upstream source change; no `assume` constraint, because the operation
is total over its inputs.

Result: `NO_LEAK_OBSERVED` over 64 generated cases, with
`controls: calibration confirmed, secret binding confirmed`. On its own that
sentence means nothing, which is what Experiment B is for.

## Experiment B — propagation through the cryptographic type

Six controls, each a one-line injection into an otherwise identical adapter,
each run as its own contract with its own artifact. All six were detected.

| Control | Observation driven by | Detected as | Attributed to |
| --- | --- | --- | --- |
| `pre_decode_first_byte` | `secret[0]`, **before** decoding | branch | `controls.rs:54` |
| `decoded_high_limb_branch` | decoded limb 3 = `secret[0..8]` | branch | `controls.rs:72` |
| `decoded_interior_limb_branch` | decoded limb 2 = `secret[8..16]` | branch | `controls.rs:87` |
| `decoded_last_byte_branch` | decoded limb 0, masked to `secret[31]` | branch | `controls.rs:103` |
| `carry_branch` | the `Limb` carry **the library returned** | branch | `controls.rs:120` |
| `decoded_address_probe` | a load index from the decoded sum | **address** | `controls.rs:139` |

`pre_decode_first_byte` is listed first so no report can cite it as propagation
evidence: it shows the harness marked the array and nothing more. The four that
matter are the ones whose branch is driven by a `Word` the library produced —
and `carry_branch` is the strongest of them, because the value it branches on
is the return value of `Uint::carrying_add`, so the dependency has crossed into
upstream code and come back.

The first, interior and last-byte controls are detected independently, which is
what rules out partial marking: a harness that marked only the pointer, only
the leading bytes, or the wrong width would pass some of these and fail others.

`controls::public_operand_branch` — a branch on the **public** operand with the
secret consumed by the library's arithmetic — reported `NO_LEAK_OBSERVED`. A
finding there would have been wrong in the direction that makes the tool
useless.

## Experiment C — the library's code is in the artifact

From `objdump -d -l` over the analyzed executable, inside the adapter's own
symbol. Every frame below is upstream source, inlined (`from_be_slice` and
`carrying_add` are `#[inline(always)]` generics, instantiated in the adapter's
codegen unit):

```text
<crypto_bigint::uint::Uint<4>>::from_be_slice:
  .../crypto-bigint-0.7.10/src/uint/encoding.rs:49
    mov (%rdi),%rcx          ; operands loaded at run time, not folded
    ...
    bswap %rcx  bswap %r8  bswap %rax  bswap %r9      ; left,  4 limbs
    bswap %rdi  bswap %r10  bswap %r11  bswap %rdx    ; right, 4 limbs

crypto_bigint::primitives::carrying_add:
  .../crypto-bigint-0.7.10/src/primitives.rs:15
    add %r9,%rdx   adc $0x0,%rax   setb %sil
    add %r11,%rax  adc %r8,%rsi    setb %r8b
    add %r10,%rsi  adc %rcx,%r8
    add %rdi,%r8                                      ; 4-limb carry chain

<crypto_bigint::uint::encoding::EncodedUint<4>>::new_be:
  .../crypto-bigint-0.7.10/src/uint/encoding.rs:471
    ...                                               ; result written out
    call *...                                         ; cbaudit::sink::consume_all_bytes
```

Which answers each of the questions the gate asks:

* **the original implementation is called** — upstream frames for decoding, the
  carry chain, and the encoding of the result;
* **it is not dead-code-eliminated** — all four limbs of both operands are
  loaded, swapped, added and written back;
* **the inputs are not constant-folded** — they are loaded from `(%rdi)` and
  `(%rsi)` at run time;
* **the whole result is consumed** — `new_be` materializes 32 bytes and the
  call to `consume_all_bytes` reads them; `sink.rs`'s
  `every_byte_changes_the_result` test independently establishes that no byte
  of that fold is dead;
* **the mutated code is present** when a mutation is applied — the finding in
  Experiment D names the patched line.

The operation is inlined and has no distinct function symbol of its own, which
is acceptable and expected. What is *not* acceptable is describing an inlined
operation as if a symbol had been located, so this is what was actually
compiled.

### The finding this experiment turned up: identical bodies are folded

`wrapping_add_secret_left` and `wrapping_add_both_secret` differ only in which
parameters are **declared** secret, and a declaration does not change codegen.
Written identically, they compiled to one function and both symbols resolved to
one address:

```text
0000000000019bd0 T cbaudit::add::wrapping_add_both_secret
0000000000019bd0 T cbaudit::add::wrapping_add_secret_left
```

This is silent while everything is clean — there is no finding to attribute, so
both contracts passed. It becomes visible the moment a leak exists. The first
run of Experiment D, before the fix, reported:

```text
outcome: INCONCLUSIVE
8 secret-dependency finding(s) were observed but none is attributable to
`wrapping_add_secret_left`; they are retained for inspection.
   carrying_add<4> (src/uint/add.rs:31)
   wrapping_add<4> (src/uint/add.rs:52)
   cbaudit::add::wrapping_add_both_secret (add.rs:34)   <- the folded symbol
```

The leak was real, reached and correctly located in upstream code; the frame
Valgrind named was the *other* contract's symbol, so attribution refused it.
Note the direction of the failure — `INCONCLUSIVE`, not `CHECKED`. The tool
declined to claim a result it could not attribute rather than reporting a
clean one, which is the behavior M8's fail-closed accounting is supposed to
produce, confirmed here on a case nobody designed for it.

The fix is one `xor` with a distinct compile-time constant per contract
(`add.rs`), which keeps the bodies distinct and cannot change what the contract
observes. The general rule it implies belongs in the adapter guide: **two
adapters that compile to identical bodies cannot be told apart in a finding**,
so an adapter set must be distinguishable in the compiled artifact, not merely
in its source.

## Experiment D — telling the adapter apart from the library

Two leaks, one in each place, and the requirement is that neither is reported
as the other.

**A leak confined to the adapter.** All six controls in Experiment B are
adapter-local. Every one was attributed to a `controls.rs` line, and no
finding's stack contains a `crypto-bigint` frame. None was misattributed
upstream.

**A leak confined to the library.** `ci/mutations/mutation-a-carry-branch.patch`
adds a branch on the running carry inside `Uint::carrying_add`
(`src/uint/add.rs`), preserving the arithmetic result. The adapter, its
contract and the generated inputs are unchanged. The result:

```text
[clean]   artifact:   2ca895f248a1…   outcome: NO_LEAK_OBSERVED
[mutated] artifact:   6c7305aeca33…   outcome: LEAK_DETECTED
[mutated] attributed: carrying_add<4> (src/uint/add.rs:31)
[mutated]             via wrapping_add<4> (src/uint/add.rs:52)
```

The leaf frame is upstream source at the patched line; the adapter appears only
as its caller. So the two cases are distinguishable, in the only place that can
distinguish them.

One caveat the reports have to carry: the per-contract `site` field is
`add.rs:38` for this finding — the contract's own frame, which is what the
contract is attributed to. Reading `site` alone would place an upstream leak in
the adapter. The stack is what locates the leaking instruction, and the two
paths are distinguishable there (`src/uint/add.rs` for upstream frames against
a bare `add.rs` for the adapter's) but the basenames collide, so the
disambiguation is the full frame, not the file name.

## Validity controls on the experiment itself

Three ways a mutation run could claim an outcome it did not earn, and what
happens instead:

| Hazard | Fixture | Observed |
| --- | --- | --- |
| the patch silently fails to apply | `negative-stale-patch.patch` | `FAIL: … does not apply to crypto-bigint 0.7.10`, before anything is built |
| the mutation lands somewhere never executed | `negative-unreached-branch.patch` (the same branch, in `saturating_add`) | `NO_LEAK_OBSERVED`, so claiming it as a detection exits 1 |
| the mutated build is not the one analyzed | `--compare-clean` | the two artifact hashes must differ, and the run fails if they match |

A fourth is covered by the adapter's own test suite: `cargo test` runs against
the *mutated* dependency inside `ci/mutate-m9.py`, so a mutation that changed
the arithmetic is rejected as an invalid experiment rather than reported as a
side channel.

Two notes on what the hashes mean. The **dependency tree digest** is stable
across runs and machines (`814cb6a9…` clean, `cb85a782…` mutated) and is the
reproducible identity of what was compiled. The **artifact hash** is not
comparable across invocations, because the staging directory's absolute path is
baked into the debug info the harness build keeps on purpose; it is compared
within a single `--compare-clean` run, which is the comparison that matters.

## M9.2 — the other two targets, and the oracle

Targets B and C were added after the gate passed, with no change to the
machinery above. `objdump` evidence for both, and the full outcome table, are
in [`findings.md`](findings.md); the parts worth repeating here are the two
that could have gone differently.

**Selection compiles to conditional moves, not branches.**
`Choice::from_u8_lsb` is `and $0x1,%dl`, and the per-limb selection is four
`test`/`cmovne` pairs through `<u64 as cmov::Cmov>::cmovnz`. So the idiom
survives `opt-level = 3` — which is not automatic, and is the kind of thing a
source review cannot establish. `controls::branch_selected`, the same function
written with an `if`, is detected. That pair is the clearest demonstration this
work produces.

**Montgomery multiplication has a distinct symbol.**
`crypto_bigint::modular::mul::mul_montgomery_form::<4>` is out of line, 1199
bytes, called three times per adapter invocation, with 28 `mul` / 41 `adc` /
45 `add` and no conditional jumps. Experiment C is easiest here: there is a
named upstream symbol to point at rather than an inlining argument to make.

**No input domain needed restricting.** `ConstMontyForm::new` reduces its
argument, so every 256-bit value is valid for Target C, and `ct_select`
constrains nothing. All three adapters are total, there is no `assume`
constraint anywhere in the example, and no adapter carries a validity branch.
`U256::add_mod`, whose precondition would have forced one, is deliberately not
a target.

**The arithmetic is checked against something that is not the library.**
`ci/gen-m9-vectors.py` computes 1012 expected values in Python's
arbitrary-precision integers — the carry, reduction and limb-edge boundaries
crossed with each other, plus a SHA-256 counter stream over a fixed seed — and
`tests/functional.rs` checks all three operations against them. Both
statements of the P-256 prime (a hex literal in `monty.rs`, an arithmetic
expression in the generator) are required to agree. All 1012 pass, which is
what licenses reading the side-channel results at all.

## Cost, measured

| | |
| --- | --- |
| Adapter code, three targets, outside tests | 17 + 16 + 27 lines |
| Sink | 15 lines, with 3 tests |
| Controls | seven controls and one negative control |
| Upstream source changes in the clean integration | **0** |
| Manual configuration entries | 13 (`trace-check.toml`), none of which assigns a secret role |
| Independent oracle vectors | 1012, all passing |
| `check --all-contracts --ci`, 13 contracts, 64 cases each | 107 s wall, 174 MB peak RSS |
| Unsupported Rust constructs encountered | none |
| Compiler or dependency configuration changes | none beyond `default-features = false` |

The one real integration cost was not a type-system limitation. It was the
identical-bodies problem in Experiment C, which took a disassembly pass to
diagnose because the symptom (`INCONCLUSIVE` with eight correctly located
findings) does not point at its cause.

## What this does not establish

* Nothing about `crypto-bigint`'s security. One total operation, under two
  modeled observations, on one artifact, over 64 generated inputs.
* Nothing about operations no adapter reaches.
* Nothing about a production build of the library in another calling context,
  which would inline differently and is a different artifact.
* `NO_LEAK_OBSERVED` is not a proof, and the 64 cases are generated, not
  exhaustive.
