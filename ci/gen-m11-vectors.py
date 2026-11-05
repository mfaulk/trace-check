#!/usr/bin/env python3
"""Extracts the M11 audit adapters' functional test vectors from NIST ACVP files.

Side-channel testing is not functional testing, and conflating them is how an
audit ends up analyzing code that computes the wrong thing. The M11 adapters
derive a key from a seed, draw a classification boundary on a byte range of the
expanded encoding, reconstruct the key, build a ciphertext, and decapsulate. Any
one of those steps could be wrong in a way that leaves trace-check reporting
confidently about an operation that is not ML-KEM-768.

So the expected values here come from NIST's ACVP vectors, which share no code
with `ml-kem` or with this repository. The adapter cannot cancel a mistake
against the implementation under audit, because the reference is not an
implementation at all -- it is published data.

The two source files are the ones RustCrypto's own test suite uses; they are
excluded from the published crate, so this script reads them from a local
directory and verifies their SHA-256 against the pins below. The extracted
vectors are committed, so `cargo test` needs neither the network nor the
originals.

Fetch them with:

    curl -O https://raw.githubusercontent.com/RustCrypto/KEMs/master/ml-kem/tests/key-gen.json
    curl -O https://raw.githubusercontent.com/RustCrypto/KEMs/master/ml-kem/tests/encap-decap.json

Usage:
    ci/gen-m11-vectors.py --acvp-dir DIR            # rewrite the committed fixture
    ci/gen-m11-vectors.py --acvp-dir DIR --check    # fail if the fixture is out of date
    ci/gen-m11-vectors.py --check-digest            # hermetic: fixture vs its recorded hash
"""

import argparse
import hashlib
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = REPO / "examples/ml-kem-audit/tests/vectors/acvp.rs"

PARAMETER_SET = "ML-KEM-768"

# The exact files this fixture was extracted from. A different revision of the
# upstream test data is a different fixture, and the audit's functional evidence
# names the bytes it came from.
SOURCES = {
    "key-gen.json": "0fdca41ed30f49c828af80c73a6424ece3accc1e3430ae14492363aaadeb0e48",
    "encap-decap.json": "4b5afd6c7075b1ffebc099a70dcf907b189daadd42921223127732e3ec83c333",
}

# The digest of the committed extraction, recorded when it was generated from
# the sources above.
#
# `--check` needs those sources and so cannot run in a hermetic CI job;
# `--check-digest` needs nothing but the repository, and catches the failure
# that actually matters -- a fixture edited by hand to agree with an adapter,
# which is the one thing an independent oracle must never do. Both are real
# checks and neither replaces the other: this one says "the committed bytes are
# the bytes somebody generated and reviewed", and `--check` says "those bytes
# are what NIST's files produce".
FIXTURE_SHA256 = "9efb3554ab60976bf2238de27badedb07a9da9239002a2360f983d82e6d44365"

# Widths of the ML-KEM-768 encodings, in bytes. A vector whose field is the
# wrong width is a vector for another parameter set, and silently accepting one
# would produce a fixture that tests nothing.
WIDTHS = {
    "d": 32,
    "z": 32,
    "dk": 2400,
    "ek": 1184,
    "c": 1088,
    "k": 32,
    "m": 32,
}


def read_source(directory: pathlib.Path, name: str) -> dict:
    path = directory / name
    if not path.is_file():
        sys.exit(
            f"{path} not found. See this script's docstring for the two URLs, "
            "or pass --acvp-dir pointing at a directory holding both files."
        )
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SOURCES[name]:
        sys.exit(
            f"{name} has SHA-256 {digest}, expected {SOURCES[name]}.\n"
            "The upstream test data changed. Review the new vectors, then update "
            "SOURCES in this script in the same commit that regenerates the fixture."
        )
    return json.loads(raw)


def groups(document: dict, function: str | None):
    for group in document["testGroups"]:
        if group.get("parameterSet") != PARAMETER_SET:
            continue
        if function is not None and group.get("function") != function:
            continue
        yield group


def field(holder: dict, name: str) -> str:
    """Reads one hex field from a test or a group, checking its width."""
    value = holder[name]
    if len(value) != 2 * WIDTHS[name]:
        where = holder.get("tcId", holder.get("tgId", "?"))
        sys.exit(
            f"{where}: `{name}` is {len(value) // 2} bytes, "
            f"expected {WIDTHS[name]} for {PARAMETER_SET}"
        )
    return value.lower()


def collect(directory: pathlib.Path):
    key_gen = read_source(directory, "key-gen.json")
    encap_decap = read_source(directory, "encap-decap.json")

    keygen = [
        (test["tcId"], field(test, "d"), field(test, "z"), field(test, "dk"), field(test, "ek"))
        for group in groups(key_gen, None)
        for test in group["tests"]
    ]
    encap = [
        (test["tcId"], field(test, "ek"), field(test, "m"), field(test, "c"), field(test, "k"))
        for group in groups(encap_decap, "encapsulation")
        for test in group["tests"]
    ]
    # ACVP's decapsulation groups are `VAL`: the key lives on the *group* and the
    # tests vary only the ciphertext. That shape is what the fixture needs --
    # one key, valid and modified ciphertexts under it -- so the group's `dk` is
    # attached to each row rather than looked up later.
    decap = [
        (
            test["tcId"],
            field(group, "dk"),
            field(test, "c"),
            field(test, "k"),
            test.get("reason", "unspecified"),
        )
        for group in groups(encap_decap, "decapsulation")
        for test in group["tests"]
    ]

    if not (keygen and encap and decap):
        sys.exit(f"no {PARAMETER_SET} vectors found in one of the two sources")

    # The decapsulation group is the one that matters most, because it is NIST's
    # own evidence that both paths through the FO transform are exercised. A
    # fixture holding only one kind would let a clean result stand for an
    # operation half of which never ran.
    modified = sum(1 for row in decap if row[4] != "no modification")
    unmodified = len(decap) - modified
    if not (modified and unmodified):
        sys.exit(
            "the decapsulation vectors must contain both modified and unmodified "
            f"ciphertexts; got {modified} modified and {unmodified} unmodified"
        )
    return keygen, encap, decap, modified, unmodified


def render(keygen, encap, decap, modified, unmodified) -> str:
    out = [
        "// @generated by ci/gen-m11-vectors.py -- do not edit.",
        "//",
        "// NIST ACVP vectors for ML-KEM-768, extracted from the two files",
        "// RustCrypto's own test suite uses. They share no code with `ml-kem` and",
        "// none with this repository, so an adapter mistake cannot cancel against",
        "// the implementation under audit.",
        "//",
        f"// key generation: {len(keygen)} vector(s), (d, z) -> dk, ek",
        f"// encapsulation:  {len(encap)} vector(s), (ek, m) -> c, K",
        f"// decapsulation:  {len(decap)} vector(s), (dk, c) -> K"
        f" -- {unmodified} unmodified and {modified} modified ciphertext(s), which is",
        "//                 NIST's own evidence that both paths through the FO",
        "//                 transform are covered",
        "//",
        "// Source digests are pinned in the generator. Lowercase hex, decoded by",
        "// `tests/functional.rs`.",
        "",
        "/// `(tcId, d, z, dk, ek)`",
        "pub const KEY_GEN: &[(u32, &str, &str, &str, &str)] = &[",
    ]
    for tc, d, z, dk, ek in keygen:
        out.append(f'    ({tc}, "{d}", "{z}", "{dk}", "{ek}"),')
    out += [
        "];",
        "",
        "/// `(tcId, ek, m, c, K)`",
        "pub const ENCAPSULATION: &[(u32, &str, &str, &str, &str)] = &[",
    ]
    for tc, ek, m, c, k in encap:
        out.append(f'    ({tc}, "{ek}", "{m}", "{c}", "{k}"),')
    out += [
        "];",
        "",
        "/// `(tcId, dk, c, K, reason)`",
        "pub const DECAPSULATION: &[(u32, &str, &str, &str, &str)] = &[",
    ]
    for tc, dk, c, k, reason in decap:
        out.append(f'    ({tc}, "{dk}", "{c}", "{k}", "{reason}"),')
    out += ["];", ""]
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acvp-dir",
        type=pathlib.Path,
        help="directory holding key-gen.json and encap-decap.json",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed fixture differs from the extraction",
    )
    parser.add_argument(
        "--check-digest",
        action="store_true",
        help="verify the committed fixture against its recorded SHA-256, with no "
        "need for the ACVP sources. Hermetic, and what CI runs",
    )
    args = parser.parse_args()

    if args.check_digest:
        if not FIXTURE.is_file():
            print(f"{FIXTURE} is missing", file=sys.stderr)
            return 1
        digest = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
        if digest != FIXTURE_SHA256:
            print(
                f"{FIXTURE} has SHA-256 {digest}, expected {FIXTURE_SHA256}.\n"
                "The committed vectors are not the ones that were extracted and "
                "reviewed. Regenerate from the pinned ACVP sources with --acvp-dir "
                "and update FIXTURE_SHA256 in the same commit; do not edit the "
                "fixture by hand.",
                file=sys.stderr,
            )
            return 1
        print(f"{FIXTURE} matches its recorded digest ({len(SOURCES)} pinned source(s))")
        return 0

    if args.acvp_dir is None:
        parser.error("--acvp-dir is required unless --check-digest is given")

    rendered = render(*collect(args.acvp_dir))

    if args.check:
        if not FIXTURE.is_file():
            print(f"{FIXTURE} is missing", file=sys.stderr)
            return 1
        if FIXTURE.read_text() != rendered:
            print(
                f"{FIXTURE} is out of date; rerun without --check and review the diff",
                file=sys.stderr,
            )
            return 1
        print(f"{FIXTURE} is up to date")
        return 0

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(rendered)
    digest = hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    print(f"wrote {FIXTURE} ({len(rendered)} bytes)")
    if digest != FIXTURE_SHA256:
        print(f"set FIXTURE_SHA256 = \"{digest}\" in this script, in this commit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
