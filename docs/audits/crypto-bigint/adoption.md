# Adoption report — what it cost, and what it could not do

M9.8 asks a different question from the rest of the milestone. Not "did the
tool find the leak", but "what would a cryptography developer or an auditor
actually have to do, and what would they get".

Everything below is measured on one x86-64 host: Rust 1.97.0, Valgrind 3.28.0,
BINSEC pinned by digest, `crypto-bigint =0.7.10`.

## What it cost

| | |
| --- | --- |
| Upstream source changes in the clean integration | **0** |
| Adapter code, five real-operation contracts, outside tests | 60 lines (17 + 16 + 27) |
| Controls | 92 lines for seven controls and one negative control |
| Input-discovery fixtures | 5 contracts |
| Output sink | 15 lines, 3 tests |
| Configuration entries | 18 `[check]` + 18 `[verify]`, none assigning a secret role |
| Independent oracle vectors | 1012, all passing |
| Unsupported Rust constructs encountered | **none** |
| Compiler or dependency configuration changes | none beyond `default-features = false` |
| Changes to trace-check itself | one: the `rust_eh_personality` link fix |
| `check --all-contracts --ci`, 18 contracts | 317 s, 187 MB peak RSS |
| `benchmark-m9.py`, three configurations × 7 fixtures | ~26 min |
| `verify --all-contracts`, 18 contracts | 18 s, 184 MB peak RSS |
| `cargo test` (functional oracle, 1012 vectors) | under 1 s |
| One mutation experiment with `--compare-clean` | ~3 min (two staged builds, two Memcheck runs) |

The adapters are small because they are *only* adapters. Sixty lines of
decode-call-consume across three operations is the whole integration surface;
everything else in the crate is evidence that the sixty lines mean something.

## Three kinds of difficulty, separated

The milestone asks for this split deliberately, because conflating the three is
how a tool gets blamed for cryptography or credited for plumbing.

### Integration difficulty — low, and lower than expected

Adapting `U256`, `Choice` and `ConstMontyForm` to `&[u8; 32]` and `u8`
parameters needed no extension to the annotation's type system, which was an
explicit M9 non-goal and turned out not to be a constraint at all. The library
supplies its own decoder (`from_be_slice`), its own encoder (`to_be_bytes`) and
its own `Choice` constructor (`from_u8_lsb`), so the adapter never has to
construct a cryptographic value by hand.

The one real cost was discovering the **output sink** requirement. The checker
returns one scalar, a 256-bit result does not fit in one, and whatever reduces
it decides what the compiler may delete. That is not obvious, and getting it
wrong is silent: a sink reading four of thirty-two bytes would license the
optimizer to compute one limb, and the artifact would no longer contain the
operation the contract names. It is now rule two of
[`docs/adapter-guide.md`](../../adapter-guide.md), with a test pattern.

### Analysis difficulty — one hazard, found twice

Secret propagation was the risk the whole milestone was designed around, and it
was a non-issue: declared secrets survive `U256::from_be_slice`, multi-limb
arithmetic, and `Uint::carrying_add`'s return value, under both backends.

The hazard that *did* bite is attribution, and it bit twice:

1. `wrapping_add_secret_left` and `wrapping_add_both_secret` differ only in a
   `secret = …` declaration, which does not change codegen. They compiled to
   one function with both symbols at one address, and a real leak in the
   dependency came back `INCONCLUSIVE` — eight findings, correctly located in
   `src/uint/add.rs`, none attributable.
2. The same mistake with `hidden::nested_modes` and `nested_modes_wide`, caught
   later by the *symbolic* backend, whose refusal is better than the dynamic
   one's: `resolves to 2 symbols in the verification artifact. trace-check
   refuses to choose` names the cause outright.

Both failures are fail-closed — neither reported a clean result for a leaking
function — but neither points at its cause either, and the first took a
disassembly pass to diagnose. One `xor` with a per-contract constant fixes it.
**This is the finding most likely to cost another adopter a day.**

The secondary attribution issue: a finding's one-line `site` field names the
*contract's* frame, not the leaking instruction's. For a leak inside the
dependency those differ (`add.rs:38` against `src/uint/add.rs:31`), so `site`
read alone places an upstream finding in the adapter. The stack is where the
answer is.

### Cryptographic difficulty — not automatable, and not attempted

Three judgments had to be made by a person, and no tool could have made them:

* **Which parameters are secret.** `add` has two contracts because "secret left
  operand, public right" and "both secret" are different requirements; the
  Montgomery modulus is public because that is the usual situation, and a
  secret modulus is a different threat model that is not audited here.
* **Whether the inputs are valid.** `ConstMontyForm::new` multiplies by
  `R^2 mod p` and therefore reduces, so every 256-bit value is a legitimate
  operand — which had to be read out of the pinned source. `U256::add_mod`,
  whose documented precondition is that the unbounded sum is below twice the
  modulus, is **not** a target for exactly this reason: feeding it unrestricted
  generated bytes would produce behavior that says nothing about valid usage.
* **What a clean result means.** `NO_LEAK_OBSERVED` over 64 generated inputs,
  `VERIFIED_BOUNDED` over a declared domain and depth bound, both on an
  artifact that is not a production binary. Knowing which of those is worth
  anything for a given claim is the auditor's job.

An audit tool should support cryptographic judgment, not pretend to replace it.
Nothing in M9 tries to.

## Answering the milestone's seven questions

**1. What could be checked without modifying upstream?** All of it. Three
operations, five real-operation contracts, both backends, three upstream
mutation experiments, and a complete contract inventory — with zero changes to
`crypto-bigint`'s source in the clean integration. The mutations modify a
disposable copy, from an explicit patch.

**2. What required adapters?** Every operation, because `#[constant_time]`
takes scalars and fixed-size byte arrays and `crypto-bigint` takes `Uint<4>`,
`Choice` and `ConstMontyForm`. Sixty lines total, no upstream change, no
type-system extension.

**3. What could not be checked?** Anything no adapter reaches — which is almost
all of `crypto-bigint`. `U256::add_mod` and its relatives, which have real
input preconditions, would need a documented restricted domain first. Nothing
is said about other feature selections, other targets, or other toolchains.

**4. Which tool limitations prevented further analysis?**

* The freestanding symbolic artifact could not link a multi-crate dependency
  graph at all (`undefined symbol: rust_eh_personality`). **Fixed.**
* Identical adapter bodies defeat per-contract attribution. Worked around in
  the adapter, not in the tool — a better fix would be for the tool to notice
  that a contract's symbol is shared and say so by name.
* Coverage-guided discovery is sensitive to how much of the signature is
  public, not only to how deep the gate is. The same three-predicate gate is
  found when the public surface is 3 bytes and missed when it is 35, at the
  same budget. See [`exploration.md`](exploration.md).
* Region coverage offers no gradient toward an exact 32-bit equality, so
  `hidden::magic_gate` is unreachable for the dynamic backend at any budget.
  The symbolic backend solves it.
* `site` attribution cannot distinguish an upstream finding from an adapter
  finding without reading the stack.

**5. Which types of real vulnerability were detected?** Both modeled classes,
in upstream code, with the adapter and its contract unchanged: secret-dependent
**branches** (a carry test in `Uint::carrying_add`; a branchy `CtSelect`) and a
secret-dependent **address** (an indexed load in the Montgomery reduction). The
address case matters disproportionately — every secret executes the same
instruction sequence, so a tool modelling only control flow would have reported
that mutated library clean.

**6. How much did the process cost?** The table above. In CI terms: about five
minutes for the dynamic matrix, twenty seconds for the symbolic matrix, and
roughly three minutes per mutation experiment. Peak memory stays under 200 MB
throughout, so this is laptop-scale work.

**7. Which engineering changes would most improve practical usefulness?** In
order of how much they would have saved here:

1. **Detect a shared contract symbol and name it.** The dynamic backend should
   say "this contract's symbol is folded with `X`" rather than returning
   `INCONCLUSIVE` with correctly located findings. The symbolic backend already
   does something close.
2. **Report the leaking frame, not only the contract frame.** `site` should
   name the innermost frame that is attributable, with the contract's frame
   beside it, so an upstream finding reads as upstream without manual stack
   inspection.
3. **Weight public mutation by parameter, not by byte.** A narrow mode byte
   next to a wide public array is an ordinary cryptographic signature, and
   spreading the public budget uniformly across bytes is what loses
   `nested_modes_wide`.
4. **Comparison feedback for exact equalities.** The one fixture neither
   dynamic strategy reaches is a 32-bit constant. Instrumenting comparisons,
   rather than only regions, is the known technique.
5. **A declared output-sink helper.** Every adapter for a wide result needs the
   same fixed-work fold with the same all-bytes test. Shipping it would remove
   the one integration subtlety that is both non-obvious and silent when wrong.

## What an adopter should take away

A developer with an unsupported cryptographic type can write a short adapter,
declare which inputs are secret, and get both a dynamic check and a bounded
symbolic result against their real implementation, without touching it. What
they must also do — and what this example exists to show — is write the
controls. A clean result is worth exactly as much as the evidence that a leak
would have been found, and that evidence has to be built deliberately, after
the secret has crossed into the library's own types.
