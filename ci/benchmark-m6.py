#!/usr/bin/env python3
"""Compares generated constant-time testing against the hand-written approach.

Measures the thing M6 claims to improve: leaks found per unit of developer
effort and CI time. The baseline is the example library's own `#[ct_test]` for
`crypto::lookup::substitute_mode`, which passes `mode = 0` and honestly observes
nothing -- the leak is on a path it never visits.

Run from the repository root:

    python3 ci/benchmark-m6.py

Numbers are wall-clock on one machine and are reported as measurements, not as a
claim about other hardware. Warm runs only: every configuration is run once
first to populate the Cargo target directory, so what is measured is analysis
cost rather than compilation.
"""

import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIBRARY = ROOT / "examples" / "crypto-library"
CONTRACT = "crypto::lookup::substitute_mode"

# One shared target directory, so a configuration is not charged for the
# previous one's build. An existing CARGO_TARGET_DIR is honored, so CI can reuse
# the cache it already has rather than rebuilding the world for a measurement.
ENV = dict(os.environ)
ENV.setdefault("CARGO_TARGET_DIR", str(ROOT / "target" / "benchmark-m6"))


def run(args, cwd):
    started = time.monotonic()
    completed = subprocess.run(
        args, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=3600
    )
    return completed, time.monotonic() - started


def cargo_check(extra):
    """Runs `cargo trace-check check` with JSON output and returns its report."""
    args = [
        "cargo",
        "run",
        "--quiet",
        "--release",
        "-p",
        "cargo-trace-check",
        "--",
        "check",
        "--manifest-path",
        str(LIBRARY / "Cargo.toml"),
        "--contract",
        CONTRACT,
        "--format",
        "json",
        *extra,
    ]
    completed, elapsed = run(args, ROOT)
    if not completed.stdout.strip():
        print(completed.stderr[:2000], file=sys.stderr)
        raise SystemExit(f"check produced no report for {extra}")
    return json.loads(completed.stdout), elapsed


def generated(label, extra):
    report, elapsed = cargo_check(extra)
    entry = report["contracts"][0]
    check = entry["check"]
    findings = check["findings"]
    # Unique *sites*, so one defect reported from several cases is not counted
    # as several discoveries.
    sites = {
        (f["fingerprint"]["classification"], f["fingerprint"].get("location"))
        for f in findings
    }
    isolated = sum(
        1 for f in findings if f["isolation"]["kind"] in ("case", "single")
    )
    return {
        "approach": label,
        "leaks": 1 if check["outcome"] == "LEAK_DETECTED" else 0,
        "sites": len(sites),
        "cases": check["cases_completed"],
        "runs": check["analyzer_runs"],
        "reproducible": isolated,
        "seconds": elapsed,
        "outcome": check["outcome"],
    }


def hand_written():
    """The baseline: the library's own `#[ct_test]` for this contract."""
    args = [
        "cargo",
        "run",
        "--quiet",
        "--release",
        "-p",
        "cargo-trace-check",
        "--",
        "test",
        "--filter",
        "substitute_mode",
        "--format",
        "json",
    ]
    completed, elapsed = run(args, LIBRARY)
    if not completed.stdout.strip():
        print(completed.stderr[:2000], file=sys.stderr)
        raise SystemExit("the hand-written check produced no report")
    report = json.loads(completed.stdout)
    tests = report["tests"]
    leaks = sum(1 for t in tests if t["outcome"] == "LEAK_DETECTED")
    return {
        "approach": "hand-written #[ct_test]",
        "leaks": leaks,
        "sites": leaks,
        # One hand-written test exercises one chosen input.
        "cases": len(tests),
        "runs": len(tests),
        "reproducible": leaks,
        "seconds": elapsed,
        "outcome": tests[0]["outcome"] if tests else "NONE",
    }


def main():
    # 43 is this contract's boundary floor: two `u8` parameters sweep to
    # 1 + 21 + 21 distinct cases, and a smaller budget is refused rather than
    # silently skipping them.
    configurations = [
        ("generated: boundaries only", ["--cases", "43", "--no-shrink"]),
        ("generated: boundaries + random", ["--cases", "64", "--no-shrink"]),
        ("generated: default (+ shrinking)", ["--cases", "64"]),
    ]

    print("warming the target directory...", file=sys.stderr)
    hand_written()
    cargo_check(["--cases", "43", "--no-shrink"])

    rows = [hand_written()]
    for label, extra in configurations:
        rows.append(generated(label, extra))

    header = (
        f"{'approach':34} {'outcome':18} {'leaks':>5} {'sites':>5} "
        f"{'cases':>6} {'runs':>5} {'repro':>5} {'secs':>7}"
    )
    print()
    print(f"Contract: {CONTRACT}")
    print()
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['approach']:34} {row['outcome']:18} {row['leaks']:5} "
            f"{row['sites']:5} {row['cases']:6} {row['runs']:5} "
            f"{row['reproducible']:5} {row['seconds']:7.2f}"
        )
    print()

    baseline = rows[0]
    best = max(rows[1:], key=lambda row: row["leaks"])
    if baseline["leaks"] == 0 and best["leaks"] > 0:
        print(
            "Result: generated testing found a leak the hand-written check does not. "
            "That is the milestone's success criterion."
        )
    else:
        print(
            "Result: generated testing did NOT improve on the hand-written check "
            f"(baseline {baseline['leaks']}, best generated {best['leaks']})."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
