# Milestone 09 — Real-World Cryptography Integration and Audit Validation

**Status:** M9.0 and M9.1 implemented; M9.2–M9.8 outstanding
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

## 2. The mandatory gate, and the four findings that came out of it

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

Four things the gate turned up that the plan did not anticipate.

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
implies is general and belongs in M9.2's adapter guide: **an adapter set must
be distinguishable in the compiled artifact, not merely in its source.**

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

---

## 3. What was built

```text
examples/crypto-bigint-audit/     an out-of-workspace crate, own lockfile
  src/add.rs                      Target A: U256::wrapping_add, two secret roles
  src/controls.rs                 six propagation controls + one negative control
  src/sink.rs                     the fixed-work 32-byte fold
  trace-check.toml                description, rationale, expected outcome per contract

ci/mutate-m9.py                   one upstream-mutation experiment, with validity checks
ci/mutations/
  mutation-a-carry-branch.patch         a branch on the carry inside Uint::carrying_add
  negative-stale-patch.patch            must fail to apply
  negative-unreached-branch.patch       the same branch, in a function never called

docs/audits/crypto-bigint/
  target-selection.md             the pin, the three targets, the rejected operation
  threat-model.md                 the analysis boundary and what is out of scope
  integration-report.md           the gate's measurements
```

### The analysis boundary, in one picture

```text
generated harness --> audit adapter --> crypto-bigint 0.7.10 --> adapter --> harness
                      (decode)          (the operation)          (consume)
```

A contract covers that whole invocation. A finding is therefore a statement
about one of four stages, and which one is a question only the stack answers.

### Using it

```sh
# nine contracts, 100% enforcement, exit 0
cargo trace-check check --all-contracts --ci \
  --manifest-path examples/crypto-bigint-audit/Cargo.toml

# change the library, not the harness, and watch the verdict flip
python3 ci/mutate-m9.py --mutation mutation-a-carry-branch \
  --contract cbaudit::add::wrapping_add_secret_left \
  --expect-outcome LEAK_DETECTED --expect-frame src/uint/add.rs --compare-clean
```

---

## 4. Measured results

| | |
| --- | --- |
| Upstream source changes in the clean integration | **0** |
| Adapter code for Target A, outside tests | 17 lines |
| Configuration entries, none assigning a secret role | 9 |
| `check --all-contracts --ci`, 9 contracts × 64 cases | 77 s wall, 173 MB peak RSS |
| Controls detected | 6 of 6, covering first / interior / last secret byte, a library-produced carry, and an address |
| Negative control | `NO_LEAK_OBSERVED`, as required |
| Upstream mutations detected | 1 of 1 attempted (M9.5 requires three) |
| Unsupported Rust constructs encountered | none for Target A |

Experiment C's disassembly evidence — the inlined `from_be_slice`, the four-limb
`add`/`adc` chain from `primitives::carrying_add`, and `EncodedUint::new_be` —
is reproduced in the integration report.

---

## 5. Limitations

* One operation of three. `CtSelect` and `ConstMontyForm::mul` are M9.2.
* One upstream mutation of the three M9.5 requires, and it is a branch
  mutation; the address-dependency mutation does not exist yet.
* The symbolic backend was not exercised: BINSEC is not installed on the
  development host, so M9.6 has not started.
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
| M9.2 | Three adapters, functional oracles, adapter guide | outstanding |
| M9.3 | Real-library dynamic checks and M8 enforcement | partly done for Target A |
| M9.4 | Mutation infrastructure | **done** for one mutation; isolation and validity checks in place |
| M9.5 | Three upstream mutation regressions | 1 of 3 |
| M9.6 | Symbolic feasibility spike | not started (no BINSEC on this host) |
| M9.7 | M6-versus-M7 detection comparison and benchmarks | not started |
| M9.8 | CI integration and adoption report | Level 1 CI only |

---

## 7. Definition of done

- [x] `crypto-bigint` pinned to an exact version, with a committed lockfile and
      a recorded tarball checksum.
- [x] An external audit crate invokes the original implementation without
      rewriting it.
- [x] The clean integration requires no upstream changes.
- [ ] Three meaningfully different operations covered. *(1 of 3)*
- [x] Input and output adapters have independent functional tests.
- [x] Input-domain assumptions documented and validated — all three targets are
      total, so none is restricted.
- [x] Secret marking works through the library's own cryptographic type.
- [x] Controls cover the first, an interior, and the last secret byte.
- [x] The library's operation is confirmed present and executed in the analyzed
      artifact, by disassembly.
- [x] Adapter findings and upstream findings are distinguished, with the
      ambiguity in `site` recorded rather than papered over.
- [ ] Three deliberately vulnerable upstream changes detected. *(1 of 3)*
- [ ] At least one branch leak and one address leak injected upstream.
      *(branch only; both exist as adapter-local controls)*
- [x] Mutations leave the adapter and its contract unchanged.
- [x] Every mutation reproducible from a pinned source and an explicit patch,
      with validity controls for a stale patch, an unexecuted mutation and a
      reused artifact.
- [ ] M6 versus M7 detection effectiveness measured on this integration.
- [ ] Symbolic feasibility evaluated.
- [ ] CI validates artifact identity, instrumentation, findings and completion.
      *(Level 1 only)*
- [x] Developer integration cost and analysis performance measured for what
      exists.
- [x] The reports document limitations without claiming full security.
- [x] M1–M8 tests remain green.
