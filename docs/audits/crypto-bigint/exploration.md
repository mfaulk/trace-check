# M9.7 — does input discovery find more vulnerable paths here?

The question is **not** whether coverage guidance reaches more source regions.
It is whether it finds additional *vulnerable execution paths* in an external
integration, where the adapter signatures are shaped by somebody else's API and
the secret reaches the vulnerable path through the library's own multi-limb
arithmetic.

```sh
python3 ci/benchmark-m9.py            # the full comparison
python3 ci/benchmark-m9.py --quick    # the three fixtures that decide it
```

Every configuration uses the same security backend, the same artifact profile
and the same per-fixture case budget. The only variable is how the corpus was
chosen. Two clean fixtures run in every configuration, because a strategy that
"finds" something there is manufacturing evidence.

## The fixtures

`src/hidden.rs`. Same secret handling as the rest of the crate — decode with
`U256::from_be_slice`, add with the library's own `wrapping_add` — with the
leak behind a **public** predicate. The spread is deliberate and two rows are
expected to be found by nothing.

| Fixture | Gate |
| --- | --- |
| `boundary_gate` | the public operand's top limb is all-ones |
| `nested_modes` | three public predicates, each its own early return, public surface 3 bytes |
| `nested_modes_wide` | the same three predicates, public surface 35 bytes |
| `magic_gate` | one exact 32-bit public equality |
| `nested_modes_clean` | the same three predicates, constant-time body |

## Results

| Configuration | Planted found | Which | Total time |
| --- | --- | --- | --- |
| `m6-default` | **2 / 5** | `boundary_gate`, `decoded_address_probe` | 93 s |
| `m6-random-10x` | **1 / 5** | `decoded_address_probe` | 280 s |
| `m7-explore` | **3 / 5** | the above plus `nested_modes` | 1185 s |

No configuration reported a finding on either clean fixture.

**Gained by exploration:** `hidden::nested_modes`.
**Found by no dynamic strategy:** `hidden::magic_gate`, `hidden::nested_modes_wide`.
**Found by the symbolic backend:** all **five** planted leaks, in 18 s for the
whole 18-contract matrix.

### More random budget is worse, not better

`m6-random-10x` gets **ten times** the cases and finds **fewer** leaks than
`m6-default` — it loses `boundary_gate`. The configuration is random-only, so
it never generates the all-ones operand that opens that gate, and no amount of
uniform random sampling over 32 bytes will.

That is the clearest statement in this benchmark of why the generator spends
its budget boundaries-first and why a coverage-guided run must not drop the
mandatory boundary cases in favour of its own candidates. `boundary_gate`
exists to keep that regression covered, and `m7-explore` does find it.

### What exploration actually bought, and what it cost

| Fixture | Candidates | Seeds retained | New regions | Discovery time | Found |
| --- | --- | --- | --- | --- | --- |
| `nested_modes` | 768 | 3 | 14 | 1.8 s | **yes** |
| `nested_modes_clean` | 768 | 3 | 20 | 1.8 s | nothing to find |
| `nested_modes_wide` | 1280 | 2 | 6 | 2.7 s | no |
| `magic_gate` | 512 | 0 | 0 | 1.4 s | no |
| `boundary_gate` | 512 | 0 | 0 | 1.4 s | yes, from boundaries |

`nested_modes_clean` is the row that makes the others trustworthy: exploration
reached the guarded region — 3 seeds retained, **20** new regions, more than
the leaky twin — and the security backend still observed nothing. Discovery
reaching a region is not evidence about that region's security, and here the
two artifacts say so independently.

The **coverage search itself is cheap**: 1.4–2.7 s per contract. The 12×
wall-clock difference between `m6-default` and `m7-explore` is almost entirely
the second, `-C instrument-coverage` artifact that has to be built per
contract. Per-row times in the measurement range from 16.6 s to 290 s for the
same work, which is build caching rather than analysis, so the totals above are
reported as what happened on one host and not as a cost model.

## The finding: coverage guidance is sensitive to public surface, not only depth

`nested_modes` and `nested_modes_wide` have the **same three predicates**, the
same leak, and the same budget. The only difference is that `nested_modes`
declares its second 32-byte operand secret, leaving 3 public bytes, while
`nested_modes_wide` leaves it public, giving 35.

| | public surface | candidates | retained | new regions | outcome |
| --- | --- | --- | --- | --- | --- |
| `nested_modes` | 3 bytes | 768 | 3 | 14 | `LEAK_DETECTED` |
| `nested_modes_wide` | 35 bytes | 1280 | 2 | 6 | `NO_LEAK_OBSERVED` |

The mutator spends its public budget across all 35 bytes, almost all of it on
array bytes that cannot open any gate, and converges — eight consecutive rounds
with no new coverage — before climbing the third predicate. It is not a budget
problem: `nested_modes_wide` attempted *more* candidates and retained fewer
seeds.

This was discovered by accident. The first version of `nested_modes` had a
public 32-byte operand and was not found, which looked like the fixture being
too hard; making the operand secret found it in 768 candidates. Rather than
delete the failed variant, both are kept as contracts, so the asymmetry stays
measured.

It matters because a narrow mode byte beside a wide public parameter is an
ordinary cryptographic signature. The improvement it points to is in
[`adoption.md`](adoption.md): weight public mutation per *parameter* rather
than per byte.

### A second thing the fixture taught

The first `nested_modes` wrote its gate as one expression:

```rust
if a == MODE_A && b == MODE_B && c == MODE_C {
```

The compiler merged the three byte comparisons into a single test. With no
intermediate region to reach, coverage feedback had nothing to climb and the
result was indistinguishable from `magic_gate`. Three separate early returns
give each conjunct its own region, and then the search climbs them.

So a coverage-guided search is sensitive to how the *compiler* laid out the
predicate, not to how the source spelled it — which is the same lesson, in a
different place, as a control whose branch the optimizer erases not being a
control.

## The honest limits

**`magic_gate` is unreachable for the dynamic backend at any budget.** Region
coverage gives no gradient toward one 32-bit constant: 512 candidates, 0
retained, 0 new regions. Every token but one reaches the same regions. The
known fix is comparison instrumentation, which a stable toolchain does not
expose.

**`nested_modes_wide` is unreachable at this budget for a different reason** —
not an absent gradient, but a public surface wide enough that the gradient is
never sampled. Both failures look identical in the report (`NO_LEAK_OBSERVED`)
and have different fixes.

**Both are found by the symbolic backend.** A solver does not guess a 32-bit
constant, it solves for one. On this integration the symbolic backend strictly
dominates both dynamic strategies on detection — 5/5 planted leaks against 3/5
— and it is also the faster of the two by an order of magnitude, 18 s against
317 s for the whole matrix. That ordering is specific to *branchless*
cryptographic code, where there is one path per contract; see
[`symbolic-feasibility.md`](symbolic-feasibility.md) for why, and for the
caveat that it inverts as soon as the code under test has secret-dependent
control flow.

**The coverage artifact and the security artifact stay separate.** M7 builds an
instrumented binary to decide which inputs are worth analyzing; every security
conclusion still comes from the uninstrumented Memcheck artifact, and the
report names both hashes. A newly reached LLVM region is not evidence that the
corresponding path was checked.
