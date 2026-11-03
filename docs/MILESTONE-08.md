# Milestone 08 — Complete Contract Coverage and Enforcement

**Status:** Implemented
**Branch:** `feat/m8-contract-coverage`
**Prerequisite:** Milestone 7, merged
**Primary platform:** Linux x86-64, pinned Rust toolchain

---

## 1. What M8 changed, in one paragraph

Before M8, `--all-configured` selected configuration keys. A `#[constant_time]`
declaration with no `trace-check.toml` entry was not merely unchecked — it was
**invisible**, and a run that never considered it reported success. M8 inverts
that: `#[constant_time]` emits a record into the compiled library,
`cargo trace-check check --all-contracts --ci` reads every record back, and
configuration decides only *how* each declaration is analyzed. A new annotation
is enforced from the moment it compiles.

The invariant, which the implementation enforces structurally:

> **Every applicable contract is accounted for, even when the tool cannot
> analyze it.**

---

## 2. The mandatory gate, and the two findings that shaped it

Recorded reproducibly in
[`docs/spikes/m8-contract-inventory/`](spikes/m8-contract-inventory/README.md).

A procedural attribute macro sees one item at a time and cannot enumerate the
rest of the crate. A source parser cannot know which items survived `cfg`,
feature selection, macro expansion or target choice. So the inventory comes from
the compilation: `#[constant_time]` emits a `#[used]` static into
`.trace_check.contracts`, framed as

```text
magic(8) = "TCCONTR1" | schema(u16 LE) | length(u32 LE) | payload(UTF-8 JSON)
```

and the reader parses the `ar` archive and the ELF objects inside it.

The spike passes the whole matrix, including the four prerequisites singled out
as blocking: `dynamic = false`, `no_std`, feature gating, and multiple codegen
units. 23 records survive being split across 16 objects and being collapsed into
1; a library with no annotations yields a valid empty inventory; every malformed
record is refused.

### Finding one: the convenient tool loses records

`llvm-objcopy --dump-section .trace_check.contracts=out.bin` writes raw bytes and
needs no parsing. It returns only the **first** section with a given name, and a
Rust object routinely holds several named `.trace_check.contracts` — one per
`#[used]` static. The debug profile puts the whole crate in one object, so the
first measurement reported **1 of 23 records** and looked like a success:

```
### debug profile ###
  v1 spike::beta::probe
  total: 1
```

For a mechanism whose entire value is completeness, under-reporting while
claiming success is the worst available failure, and it is invisible without a
known-good count to compare against. `llvm-objdump -s -j` shows every occurrence
but only as hex text to be scraped.

So [`inventory.rs`](../crates/trace-check/src/inventory.rs) parses `ar` and ELF
in process. Both formats are small and fully specified for what is needed — 60
bytes of ASCII per archive member, and a header plus two tables for an ELF64
section lookup — and doing it directly removes an external-tool dependency,
removes the scraping, and makes "every section with this name" the
straightforward reading rather than the careful one.

### Finding two: LTO fills the rlib with bitcode

Applied to this repository's own `examples/crypto-library`, the reader found
**zero** records. The workspace release profile sets `lto = true`, and under fat
LTO rustc puts LLVM bitcode in the rlib's `.o` members:

```
$ head -c 4 crypto-....rcgu.o | od -An -tx1
 42 43 c0 de          # "BC\xc0\xde"
```

An ELF walk correctly finds nothing there — and "nothing" is indistinguishable
from "this library declares no contracts" unless the reader says otherwise.
Reading it as an empty inventory would have cleared all 18 of the library's
contracts.

Two consequences, both implemented:

1. **The inventory build is trace-check's own build.** Its own target
   directory, `lto = off` forced via `CARGO_PROFILE_RELEASE_LTO`, and the flags
   recorded in the build identity — exactly as M5, M6 and M7 each build an
   artifact with a pinned profile and record it.
2. **An archive with object members but none readable is an error**, naming LTO
   as the likely cause. Object members and readable members are counted
   separately, so a caller can always tell "nothing declared" from "nothing
   read".

That distinction is the module's discipline throughout. Every malformed record —
length past the section end, unknown schema, truncated header, non-UTF-8,
non-JSON, missing field, unusable descriptor — refuses the **whole inventory**
rather than being skipped.

---

## 3. One parse of the signature, embedded twice

The record's payload is assembled by `concat!` at the expansion site, because
`module_path!()`, `file!()` and `line!()` are only meaningful there. It embeds
the **same** `describe_contract` output the descriptor constant already uses, so
there is one parse of the signature rather than a second description that could
drift from the first.

The record text lives inside an anonymous `const _: () = { … }` block, so it
never reaches crate metadata. `lib.rmeta` sits in the same archive and carries no
such section, which is what makes "find the section" an exact question rather
than a byte search that could match a copy of the text held elsewhere.

`analyse_one` compares the inventory record's descriptor against the one probed
out of the analysis artifact and refuses to continue if they disagree: a
difference means the artifact the inventory describes is not the artifact about
to be analyzed.

---

## 4. Identity

A contract is identified by its **crate-qualified module path plus function**,
never by a bare name. `crypto::shadow::left::probe` and
`crypto::shadow::right::probe` are distinct declarations with opposite
behaviour, and M7's attribution control exists for exactly that reason.

Build identity travels with every inventory: package, version, library target,
features, target triple, compiler version, profile flags, artifact hash and an
inventory content hash. Declarations are sorted by identity, so an inventory does
not depend on codegen-unit layout, and the content hash changes when a
declaration does and not otherwise.

An inventory describes **one compilation**. Two feature selections of one package
produce different `variant()` names and different inventory identities, and
nothing merges their evidence.

---

## 5. Enforcement: two dimensions, never one boolean

[`enforcement.rs`](../crates/trace-check/src/enforcement.rs) keeps apart:

* an **enforcement status** per required analysis — selected, runnable, waived,
  completed; and
* **evidence** — what a backend actually observed.

| Status | Meaning |
|---|---|
| `CHECKED` | the required analysis completed and passed |
| `LEAK_DETECTED` | the required security property was violated |
| `INCONCLUSIVE` | it ran but did not establish the required outcome |
| `UNSUPPORTED` | the declared function cannot be analyzed by that backend |
| `NOT_SELECTED` | applicable, and left out of the requested run |
| `NOT_ANALYZED` | required, runnable, and no backend reported a result |
| `BACKEND_UNAVAILABLE` | the analyzer or instrumentation is absent |
| `EXEMPTED` | an explicit, policy-approved waiver of the obligation |
| `INACTIVE` | belongs to another build variant |
| `INVENTORY_ERROR` | completeness or integrity could not be established |

`NO_LEAK_OBSERVED` and `VERIFIED_BOUNDED` are claims about different things, so
`Analysis::discharged_by` is the single place the vocabulary is mapped and a
generated run can never discharge a symbolic requirement.

**Nothing in the module names Valgrind or BINSEC.** Requirements and evidence are
generic, so a future build-profile or hardware-timing check participates by
producing evidence for an analysis rather than by another redesign of discovery
and enforcement.

### The hole that `NOT_ANALYZED` exists to close

An un-analyzed requirement originally had **no entry** in the status map, and
`gaps()` only inspected entries that existed. A contract requiring both
`generated` and `symbolic`, given a generated run alone, reported no gaps and
**passed**.

The map is now total over the requirements: everything starts as `NOT_ANALYZED`
and a backend overwrites it. A requirement that can escape the accounting by not
being there is precisely the failure this milestone exists to prevent, so it has
its own regression test.

### The policy resolver runs first

`Plan::resolve` is a pure function of the inventory, the configuration, the
selection, the available backends and the date. It runs **before** any
heavyweight backend, so these are all reported up front:

* an unsupported signature — the same conditions `dynamic_harness::generate`
  enforces, asked before anything is built;
* a missing analyzer;
* a `symbolic` requirement with no `[verify."…"]` entry, since a bounded search
  needs a declared depth and observation model that cannot be inferred from a
  signature;
* a `dynamic` requirement against a `dynamic = false` declaration, which has no
  test adapter to cover it;
* a contract left out of the requested run.

### M6's expectation split is preserved, not reinterpreted

Holding every declaration to the property made the example library — which
deliberately contains vulnerable fixtures — permanently unpassable, and worse,
erased the distinction between "this function must be constant-time" and
"trace-check must detect this planted leak".

A declared `analyzer-regression` fixture passes by producing its declared
outcome and fails by not producing it; a `security-contract` fails on a leak.
Only an explicit `expectation = "analyzer-regression"` reaches that branch,
because `CheckSettings::validate` already refuses an `expected_outcome` on a
security contract. Both directions are tested over the *same* evidence.

---

## 6. Exemptions waive obligations, never evidence

Without waivers, a developer facing an unsupported signature has one way to make
CI pass: delete the annotation, which removes the security requirement along with
the complaint. With unrestricted waivers the tool means nothing. So waivers exist
and are deliberately awkward to write:

```toml
[[policy.exemptions]]
contract = "crypto::legacy::operation"
analyses = ["generated"]
reason = "unsupported field-element parameter type"
tracking = "https://github.com/example/project/issues/42"
expires = "2027-03-01"
```

| Rule | Why |
|---|---|
| empty `analyses` is refused | a blanket waiver has to be written out, not inferred from an omission |
| a missing `reason` is refused | a waiver without one is indistinguishable from an unenforced contract |
| strict mode requires `expires` or `never_expires = true` | so a temporary waiver cannot quietly become permanent |
| a malformed date is a configuration error | otherwise a typo is a waiver that never lapses |
| an expired waiver is the gap it always was | reported with its reason and the date it lapsed |
| a waiver naming no active declaration is **stale** | it waives nothing, and only the developer knows whether that is a typo or a feature-gated contract |
| waived obligations are excluded from the checked total | a waiver cannot inflate the proportion actually checked |

**The central rule:** a waiver is applied at plan time, where no analysis has
run and so no leak can yet be known. Evidence is folded afterwards, and a
detected leak overwrites a waived status — never the reverse. A waiver can excuse
*not looking*; it cannot excuse what looking found. Nothing overwrites a recorded
leak.

---

## 7. Using it

```sh
# Enforce every declaration in the selected build.
cargo trace-check check --all-contracts --ci

# The compiler-derived inventory, without running anything.
cargo trace-check list --contracts

# Which required analyses each contract has, without running anything.
cargo trace-check coverage
cargo trace-check coverage --format json

# One feature selection at a time.
cargo trace-check check --manifest-path crypto/Cargo.toml --features fast \
    --all-contracts --ci
```

`--all-configured` is **unchanged** and still emits schema 1. The two cover
different things — configuration keys versus compiler-derived declarations — and
reinterpreting the first would silently change what an existing CI job enforces,
so `--all-contracts` goes through its own orchestration and emits schema 2.

```toml
[policy]
mode = "strict"                   # or "advisory"
default_required = ["generated"]  # symbolic is not required of everything
allow_empty_inventory = false

[policy.contracts."crypto::tag::verify_tag"]
required = ["generated", "symbolic"]
```

`generated` is the only default requirement. Requiring symbolic verification of
everything would make a container image a prerequisite for annotating a function,
which is a good way to make developers stop annotating.

Absent a `[policy]` table the defaults apply, so an existing `trace-check.toml`
gains enforcement without being edited. The policy is validated **at load**, so a
reasonless exemption or a requirement that establishes nothing is reported before
a backend starts.

### What `check --all-contracts` runs

The generated family: `generated`, and `explore` where configured or required.
`symbolic` evidence comes from `cargo trace-check verify` and `dynamic` from
`cargo trace-check test`; a requirement for either is reported as outstanding
rather than silently satisfied.

| Exit | Meaning |
|---|---|
| `0` | every required analysis satisfied its policy |
| `1` | a security requirement has an observed leak |
| `2` | incomplete inventory, unmet requirement, unsupported requirement, unaccounted contract, invalid configuration, stale configuration, or an unmet regression expectation |

A leak and an incomplete analysis can both be present; the report keeps both and
the exit code names the more serious.

---

## 8. Measured results

On `examples/crypto-library`, `check --all-contracts --ci`:

```
  Declared:          18
  Fully checked:     18
  Violations:        0
  Lacking evidence:  0
  Exempted:          0
  Requirements:      18 owed, 18 met, 0 waived
  Enforcement:       100%
Result: PASS
```

All 18 declarations are discovered from the compiled artifact, with no
configuration naming them for discovery purposes.

### Discovery overhead

`python3 ci/benchmark-m8.py`, this machine, libraries generated with 0/10/50/100
declarations:

| Declarations | Cold | Warm | Marginal |
|---|---|---|---|
| 0 | 1.65 s | 1.57 s | — |
| 10 | 1.67 s | 1.58 s | 1.6 ms |
| 50 | 1.71 s | 1.62 s | 1.1 ms |
| 100 | 1.74 s | 1.72 s | 1.5 ms |

Discovery is dominated by the fixed cost of asking Cargo whether the library is
up to date, not by the number of annotations: the marginal cost of a declaration
is about **1.5 ms**. The inventory is built once per invocation and reused across
every selected contract, so it is paid once rather than per contract. Against a
Valgrind process at roughly 0.6 s, discovery is a rounding error on the work it
schedules.

---

## 9. Limitations

* **ELF only.** One object format, one target triple. Mach-O and COFF would each
  need their own section-table reading.
* **One library target, one feature selection, per invocation.** An inventory
  describes the compilation it was read from. Nothing aggregates feature
  combinations, and a waiver for one variant does not apply to another.
* **Declared contracts only.** M8 enforces declared obligations. It does **not**
  discover functions that ought to carry a declaration, and a function with no
  annotation is not accounted for at all. That distinction is in every report.
* **Dependencies are not inventoried.** Only the selected library target is read.
* **A complete inventory is not a security claim.** It means every record was
  extracted from the selected artifacts. It does not mean every source file was
  compiled, every feature combination checked, or any function constant-time.
* **An enforcement status is not a security outcome.** `CHECKED` means a required
  analysis completed and passed; how strong that is depends entirely on which
  analysis it was. A generated dynamic check is `NO_LEAK_OBSERVED` over the
  inputs it ran, never a proof.
* **The enforcement rate is about obligations, not inputs.** It is the proportion
  of declared requirements met, excluding waived ones from both sides. It is not
  the proportion of secret inputs proven safe, and it is reported as absent rather
  than 100 % when nothing was owed.
* **`dynamic` requirements are not run by `check`.** They need
  `cargo trace-check test`, and are reported outstanding rather than assumed.

---

## 10. Tests

| File | Covers |
|---|---|
| unit tests in `inventory.rs` | record framing, padding between records, a length past the section end, a truncated header, a future schema, an unusable descriptor, a missing field, a non-archive, a bitcode archive, an rmeta-only archive, sorting, identity |
| `crates/trace-check/tests/inventory.rs` | the emission/extraction boundary against the real libraries: all 18 declarations named individually, sibling modules, declaration sites checked against the source, `dynamic = false`, determinism, build identity, feature gating, an empty inventory, a non-archive, the LTO refusal, and that nothing is executed |
| unit tests in `enforcement.rs` | defaults, requirement discharge and non-discharge, status totality, up-front settling, exemption validity and expiry, a leak over a waiver, stale configuration, empty and incomplete inventories, advisory mode, the rate, M6's expectation split both ways |
| unit tests in `coverage_report.rs` | exit codes, the matrix, the three JSON sections, a rate over no obligations |
| `crates/cargo-trace-check/tests/contracts.rs` | the mutation test, both unsupported paths, listing, exemptions valid/expired/stale/reasonless, feature variants, the JSON report |
| `ci/verify-m8-contracts.py` | the report's own claims, rather than the exit code |
| `ci/benchmark-m8.py` | discovery overhead at 0/10/50/100 declarations |

### The defining test

`adding_a_leaking_annotation_fails_ci_with_no_configuration_change`:

1. A library of two constant-time functions, `no_std`, every contract
   `dynamic = false`, **no `trace-check.toml`**. `check --all-contracts --ci`
   passes.
2. Append an annotated function containing a secret-indexed load. Change nothing
   else.
3. The inventory grows from two declarations to three; the dynamic checker finds
   the leak in the developer's own source; CI exits 1.
4. Remove the annotation and the inventory shrinks back.

The test asserts at every step that no `trace-check.toml` exists, because
without that it proves nothing.

---

## 11. Definition of done

- [x] A compiler-derived inventory enumerates active `#[constant_time]`
      declarations.
- [x] No hand-maintained registry.
- [x] No user tests executed — asserted against `examples/discovery-hazard`,
      whose ordinary unit test writes a sentinel and fails.
- [x] `dynamic = false` declarations remain visible.
- [x] `no_std` libraries supported.
- [x] Feature-gated contracts follow the selected compilation, with variants
      distinguishable.
- [x] Stable qualified identities and declaration locations.
- [x] Versioned, validated, tied to a named artifact.
- [x] Missing, corrupt, ambiguous or stale evidence fails explicitly — including
      the bitcode case that would otherwise read as an empty inventory.
- [x] `--all-contracts` selects declarations, not configuration keys.
- [x] A newly added annotated function is automatically considered.
- [x] Required unsupported functions cannot silently pass.
- [x] Required inconclusive analyses cannot silently pass, including the
      `NOT_ANALYZED` hole.
- [x] Observed leaks always remain visible and fail security-contract
      enforcement.
- [x] Exemptions are scoped, documented, expiring and reported.
- [x] Exemptions cannot erase detected vulnerabilities.
- [x] Per-contract coverage distinguishes inventory status from evidence.
- [x] JSON and text reports provide a complete contract matrix.
- [x] M1–M7 commands and tests remain compatible; `--all-configured` still emits
      schema 1.
- [x] The mutation test demonstrates a new leaking annotation failing CI with no
      configuration change.
- [x] Overhead measured and documented.
- [x] This document records the method, its limits, the policy and evidence from
      real runs.

**Not done, deliberately:** multi-variant aggregation (§10 of the proposal).
Per-variant inventories are independently identified and the data model supports
comparing them, but no command aggregates several feature selections. The
proposal asks for that only once the per-variant implementation is complete, and
merging evidence across variants is exactly where an unsound claim would be easy
to make.

---

## 12. Future direction

The inventory and policy model deliberately knows nothing about Valgrind or
BINSEC. A future analysis — build-profile regression, hardware-timing
measurement, a richer side-channel model — participates by adding an `Analysis`
variant and producing `AnalysisEvidence`, without touching discovery or
enforcement.

The natural next step is multi-variant coverage: inventory several feature
selections, keep their evidence separate, and report which declarations are
enforced in which variants. The identities needed for that are already recorded.
