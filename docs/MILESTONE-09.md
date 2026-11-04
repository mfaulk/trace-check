# Milestone 09 — Real-World Cryptography Integration and Audit Validation

**Status:** M9.0–M9.6 implemented; M9.7 and M9.8 outstanding
**Branch:** `feat/m9-real-world-crypto`
**Prerequisite:** Milestone 8, merged
**Reference library:** RustCrypto `crypto-bigint` `0.7.10`
**Primary platform:** Linux x86-64, pinned Rust toolchain

---

## 1. What M9 is for

M1–M8 analyzed code written in this repository. The question M9 asks is whether
any of that transfers to cryptographic software somebody else wrote:

1. Can trace-check analyze operations in an independently developed Rust
   cryptographic library without rewriting their implementations?
2. Does a declared secret survive byte decoding, a custom cryptographic type,
   multi-limb arithmetic, and function boundaries?
3. Does the compiled artifact genuinely contain the library's operation?
4. Can a deliberately introduced side channel *inside that operation* be
   detected?
5. What does the whole thing cost?

M9 does not claim `crypto-bigint` is secure or insecure. It establishes how
effectively trace-check can investigate real cryptographic code.

---

## 2. The mandatory gate, and the findings that came out of M9

M9.1 is a gate, not a milestone phase: the plan forbids proceeding to the
remaining work packages until it passes. It passed. Full measurements in
[`docs/audits/crypto-bigint/integration-report.md`](audits/crypto-bigint/integration-report.md);
the summary is that the risk the gate exists to test did not materialize.

> **Secret dependencies survive decoding into `Uint<4>` and multi-limb
> arithmetic.** A branch on a decoded limb, on an interior limb, on the final
> secret byte alone, and on the carry `Uint::carrying_add` *returned* are all
> detected, as is a load address derived from the decoded sum.

That is the result that mattered, because the alternative had no workaround:
if Memcheck's dependency tracking had stopped at the first type conversion,
accepting `U256` directly as an annotated parameter would not have fixed it,
and no amount of adapter engineering would either.

Five things M9 turned up that the plan did not anticipate. Four came from
the gate; the fifth is a tool bug no in-repo example could have surfaced.

### Finding one: identical adapter bodies are folded, and attribution then fails

Two contracts over the same operation — one secret operand, both secret — differ
only in a `#[constant_time(secret = …)]` declaration, and a declaration does not
change codegen. Written identically they compiled to one function:

```text
0000000000019bd0 T cbaudit::add::wrapping_add_both_secret
0000000000019bd0 T cbaudit::add::wrapping_add_secret_left
```

Harmless while clean — no finding, nothing to attribute, both contracts pass.
With a leak present, the mutation experiment returned `INCONCLUSIVE`: eight
findings, correctly located in `src/uint/add.rs`, none attributable, because the
frame Valgrind named was the *other* contract's surviving symbol.

The direction of that failure is worth stating. It did not report a clean
result for a leaking function; it declined to claim a result it could not
attribute. That is what M8's fail-closed accounting is for, observed on a case
nobody designed for it.

The fix is one `xor` with a per-contract compile-time constant. The rule it
implies is general, and is now one of the rules in
[`docs/adapter-guide.md`](adapter-guide.md): **an adapter set must be
distinguishable in the compiled artifact, not merely in its source.**

### Finding two: `site` names the contract, the stack names the leak

The per-contract `site` field is the contract's own frame — `add.rs:38` for a
leak whose actual instruction is at `src/uint/add.rs:31`. Reading `site` alone
would place an upstream finding in the adapter. The stack distinguishes them,
but the basenames collide (`src/uint/add.rs` upstream against a bare `add.rs`
for the adapter), so the disambiguation is the full frame.

### Finding three: the chosen operations need no input-domain restriction

`ConstMontyForm::new` is a Montgomery multiplication by `R^2 mod p`, which
reduces its argument — checked against the pinned source, not assumed. So all
three targets are *total* over their adapters' input types, there is no `assume`
constraint anywhere in the example, and the whole class of "was this input even
valid" question does not arise. `U256::add_mod`, which the plan flags for its
explicit range precondition, is not a target and no adapter reaches it.

### Finding four: a cheap mutation needs an optimization barrier

A source-level `if` on a secret carry inside `carrying_add` becomes a `cmov` at
`opt-level = 3` and there is nothing left to detect — the sixth time this
project has recorded the compiler erasing a secret-dependent branch. The
mutation uses `core::hint::black_box` in the taken arm, which cannot be
if-converted. The controls in `src/controls.rs` use a volatile write for the
same reason. A control whose branch the compiler erases is not a control.

### Finding five: the symbolic backend could not link a multi-crate library

The first symbolic run never reached the analyzer:

```text
rust-lld: error: undefined symbol: rust_eh_personality
  >>> referenced by core.940e698046960fd5-cgu.0
```

The verification artifact is a freestanding static ELF linked with `-nostdlib`,
and the precompiled `libcore` carries unwind tables. A codegen unit with a
landing pad references `rust_eh_personality` through a DWARF reference, which
`-nostdlib` has nothing to resolve — even under `panic = "abort"`, because the
reference is in the unwind data rather than in reachable code.

Every earlier example is one crate plus the proc-macro, and never pulled in
such a codegen unit, so the link had always succeeded. `crypto-bigint` with its
four dependencies does. The generated harness now defines the symbol (never
called — the panic handler loops), with a regression test in `harness.rs`, and
`examples/crypto-library` and `examples/external-library` reproduce their
existing expectations unchanged.

This is the only change M9 made outside `examples/` and `ci/`, and it is the
most valuable thing the milestone produced for the tool itself: bounded
verification was unavailable to **any** library with more than one dependency,
and nothing in this repository could have shown that.

---

## 3. What was built

```text
examples/crypto-bigint-audit/     an out-of-workspace crate, own lockfile
  src/add.rs                      Target A: U256::wrapping_add, two secret roles
  src/select.rs                   Target B: CtSelect::ct_select for U256
  src/monty.rs                    Target C: ConstMontyForm::mul mod the P-256 prime
  src/controls.rs                 seven controls + one negative control
  src/sink.rs                     the fixed-work 32-byte fold
  tests/functional.rs             all three operations against the oracle
  tests/vectors/generated.rs      1012 committed vectors
  trace-check.toml                description, rationale, expected outcome per contract

ci/gen-m9-vectors.py              the independent oracle; --check guards drift
ci/mutate-m9.py                   one upstream-mutation experiment, with validity checks
ci/verify-m9-integration.py       validates the report's own audit claims
ci/mutations/
  mutation-a-carry-branch.patch         a branch on the carry inside Uint::carrying_add
  mutation-b-branch-select.patch        a branch inside the library's own CtSelect
  mutation-c-indexed-reduction.patch    a secret-indexed load in the Montgomery reduction
  negative-stale-patch.patch            must fail to apply
  negative-unreached-branch.patch       the same branch, in a function never called

docs/adapter-guide.md             how to write an adapter for another library
docs/audits/crypto-bigint/
  target-selection.md             the pin, the three targets, the rejected operation
  threat-model.md                 the analysis boundary and what is out of scope
  integration-report.md           the gate's measurements and M9.2's additions
  findings.md                     every outcome, with its attribution
  symbolic-feasibility.md         M9.6: the full symbolic matrix, and a link blocker
```

There is no separate `limitations.md`: scope limits live in `threat-model.md`
and per-result limits in `findings.md`, and a third file restating them would
be the one that goes stale.

### The analysis boundary, in one picture

```text
generated harness --> audit adapter --> crypto-bigint 0.7.10 --> adapter --> harness
                      (decode)          (the operation)          (consume)
```

A contract covers that whole invocation. A finding is therefore a statement
about one of four stages, and which one is a question only the stack answers.

### Using it

```sh
# thirteen contracts, 100% enforcement, exit 0
cargo trace-check check --all-contracts --ci \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml

# change the library, not the harness, and watch the verdict flip
python3 ci/mutate-m9.py --mutation mutation-c-indexed-reduction \
  --contract cbaudit::monty::mul_secret_left \
  --expect-outcome LEAK_DETECTED --expect-frame src/modular/mul.rs \
  --expect-class address --verify-reproducer --compare-clean
```

---

## 4. Measured results

| | |
| --- | --- |
| Upstream source changes in the clean integration | **0** |
| Adapter code, three targets, outside tests | 17 + 16 + 27 lines |
| Configuration entries, none assigning a secret role | 13 |
| Independent oracle vectors | 1012, all passing |
| `check --all-contracts --ci`, 13 contracts × 64 cases | 107 s wall, 174 MB peak RSS |
| Operations clean on unmodified library code | 5 contracts over 3 operations |
| Controls detected | 7 of 7, covering first / interior / last secret byte, a library-produced carry, an address, and a branchy selection |
| Negative control | `NO_LEAK_OBSERVED`, as required |
| Upstream mutations detected | 3 of 3 — two branch findings, one address finding |
| Unsupported Rust constructs encountered | none |
| Symbolic: contracts settled / `INCONCLUSIVE` | 13 / 0, in 13.3 s and 186 MB |

Experiment C's disassembly evidence is in
[`findings.md`](audits/crypto-bigint/findings.md): the inlined `from_be_slice`
and four-limb `add`/`adc` chain for Target A; `Choice::from_u8_lsb` as
`and $0x1,%dl` and four `test`/`cmovne` pairs through the `cmov` crate for
Target B; and `mul_montgomery_form::<4>` as a distinct 1199-byte out-of-line
symbol with 28 `mul`, 41 `adc` and no conditional jumps for Target C.

The pair worth singling out is `select::ct_select` clean beside
`controls::branch_selected` detected. The library's selection survives
`opt-level = 3` as conditional moves — which is not automatic and is not
something a source review establishes — and the same function written with an
`if` is found.

---

## 5. Limitations

* The artifact hash is not comparable across invocations, because the staging
  directory's path is in the debug info the harness build keeps deliberately.
  The dependency tree digest *is* stable and is the reproducible identity.
* Everything is one target, one toolchain, one feature selection.
* `NO_LEAK_OBSERVED` over 64 generated cases is not a proof, and none of this
  is an audit of `crypto-bigint`.

---

## 6. Work packages

| PR | Package | State |
| --- | --- | --- |
| M9.0 | Target selection and source pinning | **done** |
| M9.1 | Secret-propagation feasibility gate | **done** — passed |
| M9.2 | Three adapters, functional oracles, adapter guide | **done** |
| M9.3 | Real-library dynamic checks and M8 enforcement | **done** for all three targets; no M7 exploration yet |
| M9.4 | Mutation infrastructure | **done** — isolation, provenance and validity checks in place |
| M9.5 | Three upstream mutation regressions | **done** — 2 branch, 1 address |
| M9.6 | Symbolic feasibility spike | **done** — 13 of 13, zero INCONCLUSIVE |
| M9.7 | M6-versus-M7 detection comparison and benchmarks | not started |
| M9.8 | CI integration and adoption report | Level 1 CI only |

---

## 7. Definition of done

- [x] `crypto-bigint` pinned to an exact version, with a committed lockfile and
      a recorded tarball checksum.
- [x] An external audit crate invokes the original implementation without
      rewriting it.
- [x] The clean integration requires no upstream changes.
- [x] Three meaningfully different operations covered — multi-limb addition,
      constant-time selection, Montgomery modular multiplication.
- [x] Input and output adapters have independent functional tests — 1012
      vectors from a Python oracle, plus the sink's all-bytes property.
- [x] Input-domain assumptions documented and validated — all three targets are
      total, so none is restricted.
- [x] Secret marking works through the library's own cryptographic type.
- [x] Controls cover the first, an interior, and the last secret byte.
- [x] The library's operation is confirmed present and executed in the analyzed
      artifact, by disassembly.
- [x] Adapter findings and upstream findings are distinguished, with the
      ambiguity in `site` recorded rather than papered over.
- [x] Three deliberately vulnerable upstream changes detected, in three
      different files, against three different contracts.
- [x] At least one branch leak and one address leak injected upstream — two
      branch findings and one address finding.
- [x] Mutations leave the adapter and its contract unchanged.
- [x] Every mutation reproducible from a pinned source and an explicit patch,
      with validity controls for a stale patch, an unexecuted mutation and a
      reused artifact.
- [ ] M6 versus M7 detection effectiveness measured on this integration.
- [x] Symbolic feasibility evaluated — all thirteen contracts, every
      expectation reproduced, zero `INCONCLUSIVE`, including 256-bit Montgomery
      multiplication the plan did not require to complete.
- [x] CI validates artifact identity, instrumentation, findings and
      completion, at both levels. `ci/verify-m9-integration.py` checks the
      report's own claims; `ci/mutate-m9.py` checks artifact difference,
      finding class, upstream attribution and reproducer replay.
- [x] Developer integration cost and analysis performance measured for what
      exists.
- [x] The reports document limitations without claiming full security.
- [x] M1–M8 tests remain green.
