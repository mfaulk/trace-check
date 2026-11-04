# M9.6 — symbolic feasibility, and the assumption it overturned

M9's plan treats bounded relational verification of a real cryptographic
library as an experiment that might well end in `INCONCLUSIVE`, and explicitly
does not require 256-bit Montgomery multiplication to complete.

It completes in **4 seconds**.

```sh
cargo trace-check verify --all-contracts \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml
```

All eighteen contracts, every declared expectation reproduced, **zero
`INCONCLUSIVE`**, 18 s wall and 184 MB peak RSS for the whole matrix.

| Contract | Outcome | Paths | Control-flow checks | Memory checks | Max depth |
| --- | --- | --- | --- | --- | --- |
| `add::wrapping_add_secret_left` | `VERIFIED_BOUNDED` | 1 | 4 / 4 | 254 / 254 | 413 |
| `add::wrapping_add_both_secret` | `VERIFIED_BOUNDED` | 1 | 4 / 4 | 254 / 254 | 413 |
| `select::ct_select` | `VERIFIED_BOUNDED` | 1 | 4 / 4 | 257 / 257 | 415 |
| `monty::mul_secret_left` | `VERIFIED_BOUNDED` | 1 | 7 / 7 | 479 / 479 | 1511 |
| `monty::mul_both_secret` | `VERIFIED_BOUNDED` | 1 | 7 / 7 | 479 / 479 | 1511 |
| `controls::public_operand_branch` | `VERIFIED_BOUNDED` | 2 | 9 / 9 | 320 / 320 | 434 |
| `hidden::nested_modes_clean` | `VERIFIED_BOUNDED` | 4 | 10 / 10 | 291 / 291 | 501 |
| `controls::pre_decode_first_byte` | `LEAK_DETECTED` | 2 | 8 / 9 | 313 / 313 | 424 |
| `controls::decoded_high_limb_branch` | `LEAK_DETECTED` | 2 | 8 / 9 | 320 / 320 | 434 |
| `controls::decoded_interior_limb_branch` | `LEAK_DETECTED` | 2 | 8 / 9 | 320 / 320 | 434 |
| `controls::decoded_last_byte_branch` | `LEAK_DETECTED` | 2 | 8 / 9 | 320 / 320 | 434 |
| `controls::carry_branch` | `LEAK_DETECTED` | 2 | 8 / 9 | 310 / 310 | 428 |
| `controls::branch_selected` | `LEAK_DETECTED` | 2 | 8 / 9 | 331 / 331 | 392 |
| `controls::decoded_address_probe` | `LEAK_DETECTED` | 1 | 4 / 4 | **256 / 257** | 418 |
| `hidden::boundary_gate` | `LEAK_DETECTED` | 2 | 8 / 8 | **298 / 299** | 421 |
| `hidden::magic_gate` | `LEAK_DETECTED` | 2 | 8 / 8 | **299 / 300** | 421 |
| `hidden::nested_modes` | `LEAK_DETECTED` | 4 | 10 / 10 | **291 / 292** | 439 |
| `hidden::nested_modes_wide` | `LEAK_DETECTED` | 4 | 10 / 10 | **291 / 292** | 440 |

`unknown_queries` is 0 for every row: the solver never gave up on a query, so
no result rests on an unresolved one.

## Why it is cheap, and why that was not obvious

The cost of relational verification here scales with **paths and observations**,
not with the size of the symbolic terms. The analyzer never has to reason about
what a 256-bit Montgomery product *equals*. It has to decide, 479 times, whether
an effective address can differ between two executions that share their public
inputs — and each of those queries is about a small expression over the secret,
not about the product.

Constant-time cryptographic code is branchless by construction. Branchless code
has one path. So the thing that would make symbolic execution explode is exactly
the thing a constant-time implementation does not do. The 256-bit multiply has
**more** checks than the addition (479 against 254) and a deeper path (1511
against 413), and both are seconds of work.

This cuts the other way too, and it is the honest caveat: a result this cheap is
cheap *because* the code was already branchless. An implementation with
secret-dependent control flow would fan out, and the method would get expensive
precisely where it is most needed. `controls::branch_selected` is the smallest
version of that — one injected branch doubles the path count.

## The rows that carry the evidence

**`decoded_address_probe` — 1 path, 4/4 control-flow checks passed, 256 of 257
memory checks.** No branch divergence at all; a single failed memory-access
query. A tool that modelled only control flow would call this clean. It is the
sharpest demonstration in the project that the address half of the observation
model is doing independent work.

**`public_operand_branch` — 2 paths, 9/9 control-flow checks passed.** A branch
on a public input creates a second path and no divergence, because public inputs
are symbolic and held equal between the paired executions. The negative control
behaves correctly at the level of the mechanism, not just the verdict.

**The five propagation controls — `LEAK_DETECTED`, every one.** This matters
more than the clean rows. A `VERIFIED_BOUNDED` on any of them would mean the
secret stopped being symbolic somewhere in `U256::from_be_slice`, and then every
clean result in the table would be worthless. On every contract whose
vulnerable path the dynamic backend's inputs actually reach, the two backends
agree — two artifacts, two methods, no disagreement about any code they both
executed. They differ only on the four `hidden` fixtures, and that is a
difference about which inputs were reached, not about what the code does.

**The four `hidden` fixtures — `LEAK_DETECTED`, all of them, including the two
no dynamic strategy reaches.** The gate bytes are symbolic and held equal
between the paired executions, so the analyzer *explores* the guarded paths
rather than guessing inputs that reach them. A solver does not guess the
32-bit constant `magic_gate` demands, it solves for one; and
`nested_modes_wide`'s wide public operand costs nothing, because dilution is a
property of mutation-based search and not of symbolic exploration. All four
findings are address findings with every control-flow check passing — the
bolded rows in the table above.

**`select::ct_select` — `VERIFIED_BOUNDED` over 520 symbolic secret bits.** The
open question was whether the analyzer models the `cmovne` that the `cmov`
crate's inline assembly emits. It does, and the per-limb conditional move is
verified rather than reported as an unmodeled instruction.

## The blocker that had to be fixed first

The first attempt did not reach the analyzer at all:

```text
rust-lld: error: undefined symbol: rust_eh_personality
  >>> referenced by core.940e698046960fd5-cgu.0
```

The verification artifact is a freestanding static ELF linked with `-nostdlib`,
and the precompiled `libcore` carries unwind tables. A codegen unit with a
landing pad references `rust_eh_personality` through a DWARF reference, and
under `-nostdlib` there is nothing to resolve it — even with `panic = "abort"`,
because the reference is in the unwind data rather than in reachable code.

Every earlier example is a single crate plus the macro, and never pulled in such
a codegen unit, so the link had always succeeded. `crypto-bigint` with its four
dependencies does. The generated harness now defines the symbol — it is never
called, the panic handler loops forever — with a regression test in
`harness.rs`. `examples/crypto-library` and `examples/external-library`
reproduce their existing expectations unchanged afterwards.

This was the single most valuable thing M9.6 produced: a one-line blocker that
made the whole symbolic backend unavailable to any library with more than one
dependency, and that no in-repo example could have surfaced.

## What a bounded result here does and does not mean

Everything in the table is scoped to the **verification artifact**, which is not
a production binary:

* the target is called through a laundered function pointer, so the verified
  instance is an out-of-line copy — a caller that inlines the operation gets
  code this run did not analyze;
* the surroundings are a freestanding `no_std` executable whose inputs are named
  globals;
* the profile is `panic = "abort"`, `lto = off`, static relocation; a production
  profile with `lto = true` is a different artifact and must be re-verified;
* only control flow and effective addresses are modeled — no cache, no
  speculation, no operand latency, no power;
* the claim is over the declared input domain and the depth bound, and nothing
  outside them.

`VERIFIED_BOUNDED` is a stronger claim than the dynamic backend's
`NO_LEAK_OBSERVED` — it quantifies over the whole declared domain rather than
over 64 generated inputs. It is still not a proof about `crypto-bigint` as
shipped, and no row in that table should be quoted as one.
