#!/usr/bin/env python3
"""Asserts the premise of M11.6's negative control.

The control was meant to demonstrate that trace-check cannot see
RUSTSEC-2025-0144's variable-latency division. It cannot demonstrate that,
because on Linux x86-64 under rustc 1.97 at `opt-level = 3` the division is not
in the compiled code at all: `TwoGamma2::U32` is a compile-time constant, so
`r1.0 /= TwoGamma2::U32` is strength-reduced to a multiply and a shift.

`docs/audits/controls.md` records the control as *unavailable* on that basis, and
this script is what keeps that reading honest. It disassembles the monomorphized
signing path in each half of the control and requires:

* the signing symbol to be present, so the measurement is about code that
  exists;
* no division in it, in **either** version.

If a future toolchain or target emits the division, this fails -- and the right
response is to rewrite `controls.md`, which would then be able to make the
demonstration it currently cannot, rather than to relax the check.

Usage:
    ci/verify-m11-controls.py
"""

import json
import pathlib
import re
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

HALVES = {
    "vulnerable": "mldsavuln",
    "patched": "mldsafixed",
}

SIGNING_SYMBOL = "raw_sign_deterministic"
DIVISIONS = ("div", "idiv", "divl", "idivl", "divq", "idivq", "divw")


def build(half: str, lib_name: str) -> pathlib.Path:
    """Builds one half and returns the rlib holding its monomorphized code.

    The rlib is the control crate's own, not `ml-dsa`'s: the signing path is
    generic over the parameter set, so its machine code appears where it is
    instantiated. `cargo` reports the artifact under the `[lib]` name rather
    than the package name.
    """
    manifest = REPO / f"examples/ml-dsa-control-{half}/Cargo.toml"
    result = subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--message-format=json",
            "--manifest-path",
            str(manifest),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.exit(f"building the {half} half failed:\n{result.stderr[-2000:]}")

    for line in result.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        if message.get("target", {}).get("name") != lib_name:
            continue
        for filename in message.get("filenames", []):
            if filename.endswith(".rlib"):
                return pathlib.Path(filename)
    sys.exit(f"no rlib reported for {lib_name}; cargo's output did not name one")


def functions(objdump: str) -> dict[str, list[str]]:
    """Splits `objdump -d` output into symbol -> instruction mnemonics."""
    out: dict[str, list[str]] = {}
    current = None
    for line in objdump.splitlines():
        header = re.match(r"^[0-9a-f]+ <(.+)>:$", line)
        if header:
            current = header.group(1)
            out[current] = []
        elif current is not None and re.match(r"^\s+[0-9a-f]+:\t", line):
            mnemonic = line.split("\t")[-1].strip().split(" ")[0]
            if mnemonic:
                out[current].append(mnemonic)
    return out


def main() -> int:
    if shutil.which("objdump") is None:
        sys.exit("objdump not found; it is what this check reads")

    problems: list[str] = []
    summary: list[str] = []

    for half, lib_name in HALVES.items():
        rlib = build(half, lib_name)
        disassembly = subprocess.run(
            ["objdump", "-d", "--no-show-raw-insn", "-C", str(rlib)],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        symbols = functions(disassembly)

        signing = [name for name in symbols if SIGNING_SYMBOL in name]
        if not signing:
            problems.append(
                f"{half}: no symbol containing {SIGNING_SYMBOL!r} in {rlib.name}. "
                "The control's measurement is about code that must be present"
            )
            continue

        divisions = 0
        for name in signing:
            divisions += sum(1 for m in symbols[name] if m in DIVISIONS)
        if divisions:
            problems.append(
                f"{half}: {divisions} division instruction(s) in the signing path. "
                "The advisory's division is now in the compiled code, so "
                "docs/audits/controls.md's 'unavailable' verdict is wrong and the "
                "negative control can be made properly -- rewrite it rather than "
                "relaxing this check"
            )
        summary.append(
            f"{half}: {len(signing)} signing symbol(s), "
            f"{sum(len(symbols[n]) for n in signing)} instruction(s), "
            f"{divisions} division(s)"
        )

    if problems:
        print("M11.6 negative control premise does NOT hold:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("M11.6 negative control premise holds (division absent in both halves):")
    for line in summary:
        print(f"  - {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
