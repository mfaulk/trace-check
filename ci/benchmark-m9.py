#!/usr/bin/env python3
"""Measures M6 against M7 on the real-library integration.

`ci/benchmark-m7.py` asks the same question about this repository's own
`examples/crypto-library`. This script asks it where it is harder to answer: an
external dependency, adapters whose signatures are shaped by somebody else's
API, and secrets that reach the vulnerable path through the library's own
multi-limb arithmetic.

The question is **not** whether coverage guidance reaches more source regions.
It is whether it finds additional *vulnerable execution paths*. So every
configuration below uses the same security backend, the same artifact profile
and the same per-fixture case budget; the only variable is how the corpus was
chosen. A clean fixture is included in every run, because a strategy that
"finds" something there is manufacturing evidence rather than discovering it.

One fixture is expected to be found by neither strategy, and one by M6 alone.
A table where coverage guidance wins every row would be measuring the fixtures.

The acceptance properties are **asserted**, not printed: m7-explore must find
strictly more planted vulnerabilities than m6-default, must lose none that
either M6 baseline found, must detect `nested_modes` specifically, and no
configuration may report a finding on a clean fixture. m6-default must *not*
detect `nested_modes`, or the fixture has stopped isolating what coverage
guidance adds.

Run from the repository root:

    python3 ci/benchmark-m9.py            # the full comparison
    python3 ci/benchmark-m9.py --quick    # the three fixtures that decide it

Wall-clock numbers are measurements on one machine, not a claim about other
hardware.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIBRARY = ROOT / "examples" / "crypto-bigint-audit"

ENV = dict(os.environ)
ENV.setdefault("CARGO_TARGET_DIR", str(ROOT / "target" / "benchmark-m9"))

# (contract, cases, planted, core, note)
#
# `planted` records what the fixture is for, so "proportion found" is about
# planted vulnerabilities rather than about however many findings appeared.
# `core` is the reduced set `--quick` uses: the fixture M6 finds, the fixture
# only M7 finds, and the clean control.
#
# Budgets are each fixture's boundary floor plus room, not round numbers. Two
# 32-byte arrays and three `u8` parameters put the floor well above 100, and a
# budget below the floor is refused rather than silently dropping boundaries.
FIXTURES = [
    ("cbaudit::hidden::boundary_gate", 200, True, True, "leak behind an all-ones public operand"),
    ("cbaudit::hidden::nested_modes", 200, True, True, "leak behind three public predicates"),
    (
        "cbaudit::hidden::nested_modes_wide",
        200,
        True,
        False,
        "the same, diluted by a public 32-byte operand",
    ),
    ("cbaudit::hidden::magic_gate", 200, True, False, "leak behind an exact 32-bit equality"),
    (
        "cbaudit::hidden::nested_modes_clean",
        200,
        False,
        True,
        "clean control, same nested shape",
    ),
    (
        "cbaudit::controls::decoded_address_probe",
        64,
        True,
        False,
        "unguarded address leak, found by anything",
    ),
    ("cbaudit::select::ct_select", 64, False, False, "clean control, the library's CtSelect"),
]

# The fixture the improvement is demonstrated with, and the one the quick set
# exists to exercise. Named here so the acceptance check is about *this* gap
# and not about a count that some other fixture could compensate for.
DEMONSTRATION = "cbaudit::hidden::nested_modes"

# The milestone's baselines. `m6-random-10x` gets ten times the budget on
# purpose: the claim has to be that coverage guidance beats M6 given *more*
# budget, not given less.
CONFIGURATIONS = [
    ("m6-default", ["--no-explore"], None, 1),
    ("m6-random-10x", ["--no-explore"], ["random"], 10),
    ("m7-explore", ["--explore"], None, 1),
]


def fixtures(quick):
    return [entry for entry in FIXTURES if entry[3]] if quick else FIXTURES


def temp_config(selected, strategies, multiplier):
    """The configuration one benchmark configuration runs under.

    Deliberately *without* `expected_outcome`: a declared outcome would turn
    "this strategy did not find it" into a configuration error rather than the
    measurement this script exists to take.
    """
    scratch = ROOT / "target" / "benchmark-m9-config"
    scratch.mkdir(parents=True, exist_ok=True)
    name = "-".join(strategies or ["default"])
    path = scratch / f"trace-check-{name}-{multiplier}.toml"
    lines = ["schema_version = 1", ""]
    for contract, cases, _, _, _ in selected:
        lines.append(f'[check."{contract}"]')
        lines.append(f"cases = {cases * multiplier}")
        if strategies is not None:
            listed = ", ".join(f'"{value}"' for value in strategies)
            lines.append(f"strategies = [{listed}]")
        lines.append("")
        lines.append(f'[check."{contract}".explore]')
        lines.append("enabled = true")
        lines.append("candidate_budget = 4000")
        lines.append("security_case_budget = 128")
        lines.append("")
    path.write_text("\n".join(lines))
    return path


def check(contract, config, flags):
    started = time.monotonic()
    completed = subprocess.run(
        [
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
            "--config",
            str(config),
            "--contract",
            contract,
            "--format",
            "json",
            *flags,
        ],
        cwd=ROOT,
        env=ENV,
        capture_output=True,
        text=True,
        timeout=3600,
    )
    seconds = time.monotonic() - started
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        sys.exit(
            f"FAIL: {contract} produced no report under {flags}:\n"
            f"{completed.stdout[-2000:]}\n{completed.stderr[-2000:]}"
        )
    return report["contracts"][0], seconds


def sites(evidence):
    """Distinct confirmed leakage sites, by fingerprint.

    Counting findings would reward a strategy that reported the same site from
    twenty inputs. Counting *sites* is the metric the milestone asks for.
    """
    return {
        (
            finding["fingerprint"]["classification"],
            finding["fingerprint"]["function"],
            finding["fingerprint"]["location"],
        )
        for finding in evidence.get("findings") or []
    }


def invalid(contract, evidence):
    """Reasons this measurement cannot be compared, rather than silently used."""
    problems = []
    if evidence.get("calibration") != "confirmed":
        problems.append(f"calibration {evidence.get('calibration')!r}")
    if evidence.get("binding") != "confirmed":
        problems.append(f"binding {evidence.get('binding')!r}")
    if evidence.get("cases_completed") != evidence.get("cases_planned"):
        problems.append(
            f"{evidence.get('cases_completed')} of {evidence.get('cases_planned')} cases ran"
        )
    if evidence.get("unattributed"):
        problems.append(f"{len(evidence['unattributed'])} unattributed finding(s)")
    return [f"{contract}: {problem}" for problem in problems]


def measure(name, flags, strategies, multiplier, selected):
    config = temp_config(selected, strategies, multiplier)
    rows = []
    problems = []
    for contract, _, planted, _, note in selected:
        evidence, seconds = check(contract, config, flags)
        check_record = evidence["check"]
        discovery = evidence.get("discovery") or {}
        problems += invalid(contract, check_record)
        rows.append(
            {
                "contract": contract,
                "note": note,
                "planted": planted,
                "outcome": check_record["outcome"],
                "sites": len(sites(check_record)),
                "cases_analyzed": check_record.get("cases_completed"),
                "valgrind_runs": check_record.get("analyzer_runs"),
                "seconds": round(seconds, 1),
                "candidates": discovery.get("candidates_attempted"),
                "retained": discovery.get("candidates_retained"),
                "regions_added": discovery.get("regions_added"),
                "discovery_ms": discovery.get("elapsed_ms"),
            }
        )
    return {"configuration": name, "rows": rows, "problems": problems}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quick",
        action="store_true",
        help="run only the three fixtures that decide the comparison",
    )
    parser.add_argument("--json", help="write the full measurement here")
    arguments = parser.parse_args()

    selected = fixtures(arguments.quick)
    results = [
        measure(name, flags, strategies, multiplier, selected)
        for name, flags, strategies, multiplier in CONFIGURATIONS
    ]

    problems = [problem for result in results for problem in result["problems"]]
    if problems:
        for problem in problems:
            print(f"INVALID: {problem}", file=sys.stderr)
        sys.exit("FAIL: a measurement did not meet its own validity conditions")

    planted = [entry[0] for entry in selected if entry[2]]
    clean = [entry[0] for entry in selected if not entry[2]]

    width = max(len(row["contract"]) for result in results for row in result["rows"])
    for result in results:
        print(f"\n### {result['configuration']}")
        for row in result["rows"]:
            extra = ""
            if row["candidates"] is not None:
                extra = (
                    f"  cand {row['candidates']:>5} retained {row['retained']:>2}"
                    f" +regions {row['regions_added']:>3}"
                    f" discovery {row['discovery_ms']:>6} ms"
                )
            print(
                f"  {row['contract']:<{width}}  {row['outcome']:<17}"
                f" sites {row['sites']}  cases {row['cases_analyzed']:>4}"
                f"  valgrind {row['valgrind_runs']:>3}  {row['seconds']:>6}s{extra}"
            )
        found = [
            row["contract"]
            for row in result["rows"]
            if row["planted"] and row["outcome"] == "LEAK_DETECTED"
        ]
        false_positives = [
            row["contract"]
            for row in result["rows"]
            if not row["planted"] and row["outcome"] != "NO_LEAK_OBSERVED"
        ]
        total = sum(row["seconds"] for row in result["rows"])
        print(
            f"  => {len(found)}/{len(planted)} planted found, "
            f"{len(false_positives)} false positive(s) over {len(clean)} clean "
            f"fixture(s), {total:.1f}s total"
        )
        if false_positives:
            sys.exit(f"FAIL: a clean fixture reported a finding: {false_positives}")

    # The acceptance property, asserted rather than printed: coverage guidance
    # must find *strictly more* planted vulnerabilities than either M6
    # baseline, must lose none of theirs, and must find the specific fixture
    # the improvement is demonstrated with.
    #
    # Printing `gained` without checking it was the original mistake here: a
    # regression to M6-equivalent detection would have left the CI job named
    # "coverage guidance finds more vulnerable paths" green.
    by_name = {
        result["configuration"]: {
            row["contract"]
            for row in result["rows"]
            if row["planted"] and row["outcome"] == "LEAK_DETECTED"
        }
        for result in results
    }
    explore = by_name["m7-explore"]
    for baseline in ("m6-default", "m6-random-10x"):
        lost = by_name[baseline] - explore
        if lost:
            sys.exit(
                f"FAIL: {baseline} found {sorted(lost)} and m7-explore did not. "
                "Coverage guidance must not lose a detection it replaces"
            )

    print(
        f"\nm7-explore finds {len(explore)} of {len(planted)} planted "
        f"vulnerabilities; m6-default finds {len(by_name['m6-default'])}, "
        f"m6-random-10x finds {len(by_name['m6-random-10x'])}."
    )
    gained = sorted(explore - by_name["m6-default"])
    print(f"gained by exploration: {gained or 'nothing'}")
    not_found = sorted(set(planted) - explore)
    print(f"found by no strategy:  {not_found or 'nothing'}")

    if not gained:
        sys.exit(
            "FAIL: m7-explore found nothing m6-default did not. The milestone's "
            "claim is that coverage guidance reaches additional vulnerable "
            "paths, and an M6-equivalent result does not support it"
        )
    if DEMONSTRATION not in explore:
        sys.exit(
            f"FAIL: {DEMONSTRATION} was not detected by m7-explore. It is the "
            "fixture the improvement is demonstrated with -- a conjunction over "
            "three public predicates that boundary and pairwise generation "
            "cannot satisfy at any budget -- so losing it is a regression even "
            "if some other fixture compensates in the count"
        )
    if DEMONSTRATION in by_name["m6-default"]:
        sys.exit(
            f"FAIL: m6-default detected {DEMONSTRATION}, so the fixture no "
            "longer isolates what coverage guidance adds. Check whether its "
            "gate became reachable by boundary or pairwise generation"
        )

    if arguments.json:
        pathlib.Path(arguments.json).write_text(json.dumps(results, indent=1))
        print(f"wrote {arguments.json}")


if __name__ == "__main__":
    main()
