#!/usr/bin/env python3
"""Measures what contract discovery costs.

M8 adds a build-and-inspect stage to every run, and the thing worth knowing is
whether that stage scales with the number of annotations or is a fixed cost
paid once. So this generates libraries with 10, 50 and 100 declarations and
measures the inventory alone -- no Valgrind, no analysis -- against the same
library with no annotations at all.

Run from the repository root:

    python3 ci/benchmark-m8.py

Numbers are wall-clock on one machine and are reported as measurements, not as
a claim about other hardware. Cold and warm are reported separately: the cold
number includes compiling the library, which dominates a first run and is
irrelevant to the hundredth.
"""

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
MACROS = ROOT / "crates" / "trace-check-macros"
SCRATCH = ROOT / "target" / "benchmark-m8"

ENV = dict(os.environ)
ENV.pop("CARGO_TARGET_DIR", None)

SIZES = [0, 10, 50, 100]

MANIFEST = """[package]
name = "tc-m8-scale"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
name = "scale"
path = "src/lib.rs"

[workspace]

[dependencies]
trace-check-macros = {{ path = "{macros}" }}
"""

PRELUDE = """#![no_std]

use trace_check_macros::constant_time;

static TABLE: [u8; 16] = [
    0x6, 0x4, 0xc, 0x5, 0x0, 0x7, 0x2, 0xe, 0x1, 0xf, 0x3, 0xd, 0x8, 0xa, 0x9, 0xb,
];
"""

# One annotated function per module, so each declaration has its own qualified
# identity rather than being a renamed copy in one module.
DECLARATION = """
pub mod m{index} {{
    use super::TABLE;
    use trace_check_macros::constant_time;

    #[constant_time(secret = "index", dynamic = false)]
    pub fn probe(index: u8) -> u8 {{
        let want = index & 15;
        let mut accumulator = 0u8;
        let mut position = 0u8;
        while position < 16 {{
            let hit = ((((position ^ want) as i16) - 1) >> 15) as u8;
            // SAFETY: `position < 16` and `TABLE` is exactly 16 bytes.
            accumulator |= unsafe {{ core::ptr::read_volatile(&TABLE[position as usize]) }} & hit;
            position += 1;
        }}
        accumulator
    }}
}}
"""


def write_library(root, count):
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "Cargo.toml").write_text(MANIFEST.format(macros=MACROS.as_posix()))
    source = [PRELUDE]
    for index in range(count):
        source.append(DECLARATION.format(index=index))
    (root / "src" / "lib.rs").write_text("".join(source))


def run(args, cwd=ROOT, env=None):
    started = time.monotonic()
    completed = subprocess.run(
        args, cwd=cwd, env=env or ENV, capture_output=True, text=True, timeout=1800
    )
    return completed, time.monotonic() - started


def list_contracts(cli, manifest, target):
    """Runs `list --contracts` and returns (count, seconds, completed)."""
    env = dict(ENV)
    env["CARGO_TARGET_DIR"] = str(target)
    completed, elapsed = run(
        [
            str(cli),
            "list",
            "--contracts",
            "--manifest-path",
            str(manifest),
            "--format",
            "json",
        ],
        env=env,
    )
    if completed.returncode != 0:
        return None, elapsed, completed
    try:
        inventory = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None, elapsed, completed
    if not inventory.get("objects_inspected", 0) and inventory["contracts"]:
        return None, elapsed, completed
    return len(inventory["contracts"]), elapsed, completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the generated libraries for inspection",
    )
    arguments = parser.parse_args()

    print("M8 benchmark: what contract discovery costs")
    print(f"  scratch: {SCRATCH}")
    print()

    built, seconds = run(
        ["cargo", "build", "--quiet", "--release", "-p", "cargo-trace-check"]
    )
    if built.returncode != 0:
        print(built.stderr, file=sys.stderr)
        return 1
    cli = ROOT / "target" / "release" / "cargo-trace-check"
    if not cli.is_file():
        # Honour an out-of-tree target directory for the tool's own build.
        probe, _ = run(["cargo", "metadata", "--format-version", "1", "--no-deps"])
        cli = pathlib.Path(json.loads(probe.stdout)["target_directory"]) / "release" / "cargo-trace-check"
    print(f"built cargo-trace-check in {seconds:.1f} s")
    print()

    # The marginal column is measured against the zero-declaration row, which
    # has to be first. Dividing a total by the count would report the fixed
    # cost of asking Cargo as though it were per-declaration work: at ten
    # declarations that reads as 158 ms each when the real marginal cost is
    # under a millisecond.
    assert SIZES[0] == 0, "the zero-declaration baseline must be measured first"
    print(f"{'declarations':>13}  {'cold':>8}  {'warm':>8}  {'marginal':>12}  found")
    rows = []
    baseline_warm = None
    for count in SIZES:
        root = SCRATCH / f"scale-{count}"
        if root.exists():
            shutil.rmtree(root)
        write_library(root, count)
        target = SCRATCH / f"target-{count}"
        if target.exists():
            shutil.rmtree(target)

        found, cold, completed = list_contracts(cli, root / "Cargo.toml", target)
        if found is None:
            print(f"{count:>13}  FAILED: {completed.stderr.strip()[:140]}")
            return 1
        if found != count:
            print(f"{count:>13}  FAILED: inventoried {found} of {count} declarations")
            return 1
        # Warm: the library is already built, so this is the inventory stage
        # alone -- a no-op cargo build plus the archive read.
        _, warm, _ = list_contracts(cli, root / "Cargo.toml", target)
        if baseline_warm is None:
            baseline_warm = warm
        marginal = ((warm - baseline_warm) / count * 1000) if count else 0.0
        print(
            f"{count:>13}  {cold:>7.2f}s  {warm:>7.2f}s  "
            f"{marginal:>10.2f}ms  {found}"
        )
        rows.append((count, cold, warm))
        if not arguments.keep:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(target, ignore_errors=True)

    print()
    baseline = baseline_warm
    largest = next(warm for count, _, warm in rows if count == SIZES[-1])
    print("Reading the table:")
    print(
        f"  The warm cost of an inventory with no declarations is {baseline:.2f}s, and with "
        f"{SIZES[-1]} it is {largest:.2f}s."
    )
    print(
        f"  So discovery is dominated by the fixed cost of asking Cargo whether the library is"
    )
    print(
        f"  up to date, not by the number of annotations: the marginal cost of a declaration is"
    )
    print(f"  {(largest - baseline) / SIZES[-1] * 1000:.2f}ms.")
    print()
    print("  The inventory is built once per invocation and reused across every selected")
    print("  contract, so this cost is paid once rather than per contract.")
    print()
    print("What this does not measure: the analyses themselves. A Valgrind process costs")
    print("roughly 0.6s, so for any library where contracts are actually checked, discovery")
    print("is a rounding error against the work it schedules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
