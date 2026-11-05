#!/usr/bin/env python3
"""Asserts the premise of M11.6's negative control.

The control was meant to demonstrate that trace-check cannot see
RUSTSEC-2025-0144's variable-latency division. It cannot demonstrate that,
because on Linux x86-64 under rustc 1.97 at `opt-level = 3` the division is not
in the compiled code at all: `TwoGamma2::U32` is a compile-time constant, so
`r1.0 /= TwoGamma2::U32` is strength-reduced to a multiply and a shift.

`docs/audits/controls.md` records the control as *unavailable* on that basis, and
this script is what keeps that reading honest. It disassembles **the executable
trace-check actually analyzed** -- not the crate's rlib, where inlining differs
-- and requires, for both halves of the control:

* the monomorphized signing symbol to be present, so the measurement is about
  code that exists;
* **no division inside it.** `decompose`, `high_bits` and `low_bits` have no
  symbols of their own in that artifact: they are inlined into
  `raw_sign_deterministic`, so its body is where the advisory's division would
  be;
* no division anywhere else in the library's code except at sites that have
  been read and argued. Checking the signing symbol alone would miss its
  out-of-line callees, and a bare count would miss a new division appearing
  while a reviewed one disappeared -- so every division is matched against
  ALLOWED below, by symbol and by the instructions around it.

If a division turns up that is not on that list, this fails. The right response
is to read it and then rewrite `controls.md` -- which would at that point be
able to make the demonstration it currently cannot -- rather than to extend the
allowlist to make CI quiet.

Usage:
    ci/verify-m11-controls.py
"""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent

HALVES = {
    "vulnerable": "mldsavuln",
    "patched": "mldsafixed",
}

SIGNING_SYMBOL = "raw_sign_deterministic"
DIVISIONS = ("div", "idiv", "divl", "idivl", "divq", "idivq", "divw")

# Divisions in the library's code that have been read, with why each is not the
# advisory's. Keyed by a substring of the containing symbol.
#
# Every reviewed site computes `256 / n` where `n` is a loop stride or a chunk
# length -- public structural data, identical for every key -- and each is
# preceded by `mov $0x100,%eax`, which is what the pattern matches. A division
# on a secret coefficient would not look like this.
ALLOWED = (
    {
        "symbol": "as ml_dsa::ntt::Ntt>::ntt",
        "pattern": "$0x100,%eax",
        "why": "256 / butterfly stride in the NTT's loop structure, on a public length",
    },
    {
        "symbol": "ml_dsa::ntt::NttInverse>::ntt_inverse",
        "pattern": "$0x100,%eax",
        "why": "the same, in the inverse NTT",
    },
    {
        "symbol": "core::iter::adapters::zip::Zip",
        "pattern": "$0x100,%eax",
        "why": "core's Chunks/ChunksMut iterator dividing by a public chunk length, "
        "monomorphized over an ml_dsa element type",
    },
)


def analyzed_executable(half: str, lib_name: str, into: pathlib.Path) -> pathlib.Path:
    """Runs the contract and returns the executable Memcheck analyzed."""
    manifest = REPO / f"examples/ml-dsa-control-{half}/Cargo.toml"
    result = subprocess.run(
        [
            "cargo",
            "run",
            "--locked",
            "--release",
            "-p",
            "cargo-trace-check",
            "--",
            "check",
            "--contract",
            f"{lib_name}::sign_secret_seed",
            "--cases",
            "25",
            "--artifact-dir",
            str(into),
            "--manifest-path",
            str(manifest),
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    # The contract is expected to be INCONCLUSIVE, which is a non-zero exit. The
    # premise this script checks is about the artifact, not the verdict, so only
    # a missing artifact is fatal.
    prefix = f"tc-check-{lib_name.replace('_', '-')}"
    candidates = [
        path
        for path in into.rglob(f"{prefix}*")
        if path.is_file() and os.access(path, os.X_OK)
    ]
    if not candidates:
        sys.exit(
            f"no analyzed executable kept for the {half} half.\n"
            f"stdout:\n{result.stdout[-1500:]}\nstderr:\n{result.stderr[-1500:]}"
        )
    return max(candidates, key=lambda path: path.stat().st_size)


def functions(objdump: str) -> dict[str, list[str]]:
    """Splits `objdump -d` output into symbol -> instruction text."""
    out: dict[str, list[str]] = {}
    current = None
    for line in objdump.splitlines():
        header = re.match(r"^[0-9a-f]+ <(.+)>:$", line)
        if header:
            current = header.group(1)
            out[current] = []
        elif current is not None and re.match(r"^\s+[0-9a-f]+:\t", line):
            out[current].append(line.split("\t")[-1].strip())
    return out


def allowed(symbol: str, context: list[str]) -> dict | None:
    for entry in ALLOWED:
        if entry["symbol"] in symbol and any(
            entry["pattern"] in line for line in context
        ):
            return entry
    return None


def main() -> int:
    if shutil.which("objdump") is None:
        sys.exit("objdump not found; it is what this check reads")

    problems: list[str] = []
    summary: list[str] = []

    for half, lib_name in HALVES.items():
        with tempfile.TemporaryDirectory(prefix=f"m11-control-{half}-") as scratch:
            executable = analyzed_executable(half, lib_name, pathlib.Path(scratch))
            disassembly = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", "-C", str(executable)],
                capture_output=True,
                text=True,
                check=False,
            ).stdout
        symbols = functions(disassembly)

        signing = [name for name in symbols if SIGNING_SYMBOL in name]
        if not signing:
            problems.append(
                f"{half}: no symbol containing {SIGNING_SYMBOL!r} in the analyzed "
                "executable. The control's measurement is about code that must exist"
            )
            continue

        in_signing = 0
        reviewed = 0
        for name, instructions in symbols.items():
            for index, instruction in enumerate(instructions):
                if instruction.split(" ")[0] not in DIVISIONS:
                    continue
                if SIGNING_SYMBOL in name:
                    in_signing += 1
                    problems.append(
                        f"{half}: a division inside {SIGNING_SYMBOL}, which is where "
                        "the inlined decompose lives. The advisory's defect may now be "
                        "in the analyzed code: read it and rewrite "
                        "docs/audits/controls.md rather than relaxing this check"
                    )
                    continue
                if "ml_dsa" not in name:
                    continue  # std, backtrace and demangling code, in both halves
                context = instructions[max(0, index - 6) : index + 1]
                if allowed(name, context) is None:
                    problems.append(
                        f"{half}: an unreviewed division in {name[:90]}. Every division "
                        "in the library's code must be read and listed in ALLOWED with "
                        "why it is not the advisory's"
                    )
                else:
                    reviewed += 1

        summary.append(
            f"{half}: {SIGNING_SYMBOL} present, "
            f"{sum(len(symbols[name]) for name in signing)} instruction(s), "
            f"{in_signing} division(s) inside it; {reviewed} reviewed division(s) "
            "elsewhere in the library's code"
        )

    if problems:
        print("M11.6 negative control premise does NOT hold:")
        for problem in dict.fromkeys(problems):
            print(f"  - {problem}")
        return 1

    print("M11.6 negative control premise holds (no division in either signing path):")
    for line in summary:
        print(f"  - {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
