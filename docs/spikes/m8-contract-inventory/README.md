# M8.1 feasibility spike — a compiler-backed contract inventory

Recorded evidence for [`docs/MILESTONE-08.md`](../../MILESTONE-08.md). This is a
**spike**, not a maintained example: it is hand-written to stand in for what
M8.2 would generate, it is outside the workspace, and CI does not run it.

It answers the milestone's mandatory gate — *can every applicable
`#[constant_time]` declaration be enumerated from a compiled Rust artifact,
without a hand-maintained registry and without executing the library's tests?*

## Requirements

The pinned toolchain. **No external tools** — not `llvm-objdump`, not
`llvm-objcopy`, not `nm`. That is a result rather than a constraint; see below.

```sh
./run.sh
```

## The mechanism

`#[constant_time]` would emit, alongside the function, a `#[used]` static placed
in a dedicated section:

```rust
const _: () = {
    const TEXT: &str = /* the record, built from the same parsed signature */;
    #[used]
    #[link_section = ".trace_check.contracts"]
    static RECORD: [u8; 14 + TEXT.len()] = { /* const-evaluated copy */ };
};
```

Framing, because records are concatenated by the linker:

```text
magic(8) = "TCCONTR1" | schema(u16 LE) | length(u32 LE) | payload(length bytes, UTF-8 JSON)
```

The reader parses the `ar` archive, then the ELF objects inside it, and scans
each `.trace_check.contracts` section for the magic.

Three details are load-bearing:

* **The record text is private to an anonymous `const _: () = { … }` block**, so
  it does not become part of the crate's exported metadata. `lib.rmeta` is also
  an ELF container inside the same archive, and it carries no such section — the
  record exists only as object data belonging to the `#[used]` static. That is
  what makes "find the section" an exact question rather than a text search that
  could double-count.
* **The length is in the record, and the reader scans for the magic** rather
  than assuming records are back to back. Alignment padding between statics
  therefore cannot desynchronize the parse.
* **The inventory is read from the library's own `rlib`**, not from a linked
  executable, so final-link garbage collection never gets the chance to discard
  records.

## Results

| Scenario | Required | Observed |
|---|---|---|
| One public annotated function | exactly one record | ✅ |
| Functions in separate modules | every active declaration | ✅ 23 of 23 |
| Two modules, same function name | separate qualified records | ✅ `spike::alpha::probe`, `spike::beta::probe` |
| `dynamic = false` | record without a test adapter | ✅ emitted unconditionally |
| `#![no_std]` library | no `std` required | ✅ the spike library is `no_std` |
| `#[cfg(feature = "fast")]` active | record appears | ✅ |
| …inactive | record absent | ✅ |
| Macro-generated annotated function | discovered when compiled | ✅ `spike::generated::woven` |
| Several codegen units | nothing lost or duplicated | ✅ 23 records across 16 objects |
| Release optimization | records retained | ✅ |
| Debug profile | records retained | ✅ 23 records from **1** object |
| No annotated functions | valid empty inventory | ✅ `total: 0`, not an error |
| Length past the section end | explicit error | ✅ |
| Unknown schema version | explicit error | ✅ |
| Truncated header | explicit error | ✅ |
| Payload that is not JSON | explicit error | ✅ |

```
== Release profile, default features ==
  ... total: 23
  object files in the archive: 16

== Debug profile ==
  ... total: 23
  object files in the archive: 1

== A feature-gated declaration follows the selected compilation ==
  inactive: spike::gated::fast is absent without --features fast
  active:   spike::gated::fast appears with --features fast

== A library with no declarations ==
  total: 0

== Malformed and future records are refused ==
  a well-formed record             -> accepted: x::y
  a length past the section end    -> refused: a record claims 541 payload bytes but only 41 are present
  an unknown schema version        -> refused: record schema version 99 is not understood
  a truncated header               -> refused: a record header is truncated
  payload that is not JSON         -> refused: Expecting property name enclosed in double quotes
```

## The finding that decided the extraction mechanism

The obvious reader is `llvm-objcopy --dump-section
.trace_check.contracts=out.bin`, which writes raw bytes and needs no parsing.
It was tried first and **silently loses records**.

`llvm-objcopy --dump-section` returns only the **first** section with a given
name. A single Rust object file routinely contains *several* sections named
`.trace_check.contracts` — one per `#[used]` static — and the debug profile puts
the whole crate in one object, so the first measurement of it reported **1 of 23
records** and looked like a successful extraction:

```
### debug profile ###
  v1 spike::beta::probe
  total: 1
```

For an inventory whose entire purpose is completeness, under-reporting while
claiming success is the worst available failure mode. It is also invisible
without a known-good count to compare against, which is why the spike builds the
same library at three profiles and compares.

`llvm-objdump -s -j <section>` does show every occurrence, but only as formatted
hex text that has to be scraped.

So the reader parses `ar` and ELF directly. Both formats are small and
completely specified for what is needed here — archive member headers are
60 bytes of ASCII, and an ELF64 section lookup is a header, a section table and
a string table — and doing it in-process removes an external-tool dependency,
removes the text-scraping, and makes "every section with this name" the
straightforward reading rather than the careful one.

## Go / no-go

**Go.** The mechanism satisfies every gate the milestone sets, including the four
the milestone's implementation note singles out as prerequisites:
`dynamic = false`, `no_std`, feature gating, and multiple codegen units.

Decisions recorded against the evidence:

1. **Records come from a `#[used]` static in `.trace_check.contracts`**, derived
   from the same macro-parsed signature as the existing descriptor — not from a
   second description that could drift.
2. **Extraction is pure in-process `ar` + ELF parsing**, because the convenient
   tool loses records and the alternative scrapes hex.
3. **The read target is the library's `rlib`**, identified from Cargo's
   structured build output, never a path guessed under `target/`.
4. **Anything unreadable is an error**, never a skipped record.

## Limitations of this spike

* **ELF only.** One object format, one target triple
  (`x86_64-unknown-linux-gnu`), one toolchain. Mach-O and COFF would each need
  their own section-table reading; the milestone's platform is Linux x86-64.
* **One library target, one feature selection.** An inventory describes the
  compilation it was read from. Nothing here aggregates feature combinations,
  and the production reader must record build identity so two variants are never
  confused.
* **Declared contracts only.** This enumerates `#[constant_time]` annotations
  that were compiled. It says nothing about functions that *should* have been
  annotated, and nothing about whether any of them is constant-time.
* **The spike's records are hand-written.** It validates the mechanism, not the
  macro. M8.2 emits them for real, and the boundary between emission and
  extraction gets its own tests on both sides.
