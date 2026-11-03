#!/usr/bin/env python3
"""Reads contract-inventory records out of a compiled Rust `rlib`.

The spike's reader. It parses the `ar` archive and the ELF objects inside it
directly, with no external tools, which is what the production reader in
`crates/trace-check/src/inventory.rs` does too. Two findings make that the
right mechanism rather than a preference:

* `llvm-objcopy --dump-section` returns only the **first** section with a given
  name, and a single Rust object file routinely contains *several* sections
  named `.trace_check.contracts` -- one per `#[used]` static. Using it silently
  dropped records, which for an inventory is the worst possible failure.
* `llvm-objdump -s -j <section>` does show every occurrence, but only as
  formatted hex text that has to be scraped.

Usage: read.py <path-to-rlib> [--json]
"""

import json
import struct
import sys

# Section the `#[used]` statics are placed in.
SECTION = ".trace_check.contracts"

# Record framing: magic, schema version (u16 LE), payload length (u32 LE),
# then that many bytes of UTF-8 JSON.
MAGIC = b"TCCONTR1"
HEADER = len(MAGIC) + 2 + 4
SCHEMA = 1

# Section type SHT_NOBITS: occupies no file space, so its "contents" are not
# there to read.
SHT_NOBITS = 8


def ar_members(data):
    """Yields (name, bytes) for each member of a GNU `ar` archive."""
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    at, longnames = 8, b""
    while at + 60 <= len(data):
        header = data[at : at + 60]
        if header[58:60] != b"`\n":
            raise ValueError(f"bad archive member header at offset {at}")
        raw = header[0:16].rstrip()
        size = int(header[48:58].decode().strip())
        body = data[at + 60 : at + 60 + size]
        if len(body) != size:
            raise ValueError(f"member at {at} claims {size} bytes, {len(body)} present")
        if raw == b"//":
            # GNU long-name string table.
            longnames = body
        elif raw.startswith(b"/") and raw[1:].isdigit():
            offset = int(raw[1:])
            end = longnames.find(b"/\n", offset)
            yield longnames[offset:end].decode(), body
        elif raw not in (b"/", b"/SYM64/"):
            yield raw.rstrip(b"/").decode(), body
        # Members are padded to an even offset.
        at += 60 + size + (size & 1)


def elf_sections(data, want):
    """Yields the bytes of *every* section named `want` in an ELF64 object."""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if e_shoff == 0 or e_shnum == 0:
        return

    def header(index):
        base = e_shoff + index * e_shentsize
        name, kind = struct.unpack_from("<II", data, base)
        offset, size = struct.unpack_from("<QQ", data, base + 0x18)
        return name, kind, offset, size

    _, _, str_offset, str_size = header(e_shstrndx)
    strtab = data[str_offset : str_offset + str_size]
    for index in range(e_shnum):
        name, kind, offset, size = header(index)
        end = strtab.find(b"\0", name)
        if strtab[name:end].decode() != want or kind == SHT_NOBITS:
            continue
        if offset + size > len(data):
            raise ValueError(f"section {index} runs past the end of the object")
        yield data[offset : offset + size]


def records(blob):
    """Yields each framed record in a section's bytes.

    Scans for the magic rather than assuming records are back to back, so
    alignment padding between statics cannot desynchronize the parse.
    """
    at = 0
    while True:
        at = blob.find(MAGIC, at)
        if at < 0:
            return
        if at + HEADER > len(blob):
            raise ValueError("a record header is truncated")
        version, length = struct.unpack_from("<HI", blob, at + len(MAGIC))
        if version != SCHEMA:
            raise ValueError(f"record schema version {version} is not understood")
        if at + HEADER + length > len(blob):
            raise ValueError(
                f"a record claims {length} payload bytes but only "
                f"{len(blob) - at - HEADER} are present"
            )
        payload = blob[at + HEADER : at + HEADER + length]
        yield json.loads(payload.decode())
        at += HEADER + length


def inventory(path):
    found = []
    archive = open(path, "rb").read()
    for name, body in ar_members(archive):
        # `lib.rmeta` is also an ELF container, and deliberately carries no
        # such section: the record lives in the `#[used]` static's object data,
        # not in crate metadata.
        if not name.endswith(".o"):
            continue
        for blob in elf_sections(body, SECTION):
            found.extend(records(blob))
    found.sort(key=lambda record: record["id"])
    return found


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    found = inventory(sys.argv[1])
    if "--json" in sys.argv:
        print(json.dumps(found, indent=2, sort_keys=True))
        return 0
    for record in found:
        print(f"  v{SCHEMA} {record['id']}")
    print(f"  total: {len(found)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
