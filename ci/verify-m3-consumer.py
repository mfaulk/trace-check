#!/usr/bin/env python3
"""Verify the M3 consumer example produced exactly the declared outcomes.

Used by CI. Checking the JSON report rather than just the exit code is what
catches a run that failed for the wrong reason -- for example every check
coming back INCONCLUSIVE, which also exits nonzero.
"""

import json
import sys

EXPECTED = {
    "verify_tag_is_constant_time": "NO_LEAK_OBSERVED",
    "table_scan_is_constant_time": "NO_LEAK_OBSERVED",
    "arithmetic_on_a_secret_is_permitted": "NO_LEAK_OBSERVED",
    "vulnerable_tag_compare_leaks": "LEAK_DETECTED",
    "vulnerable_table_lookup_leaks": "LEAK_DETECTED",
    "leak_in_a_helper_is_detected": "LEAK_DETECTED",
    "heap_secret_is_marked_through_a_slice": "LEAK_DETECTED",
}


def main(path: str) -> int:
    report = json.load(open(path))
    outcomes = {t["test"].rsplit("::", 1)[-1]: t for t in report["tests"]}

    failures = []
    for name, want in EXPECTED.items():
        test = outcomes.get(name)
        if test is None:
            failures.append(f"{name}: not executed")
            continue
        if test["outcome"] != want:
            failures.append(f"{name}: expected {want}, got {test['outcome']}")
        # A clean result is only meaningful if marking was proven to work.
        if test["calibration"] != "confirmed":
            failures.append(f"{name}: positive control {test['calibration']}")

    if report["executed"] == 0:
        failures.append("no checks were executed")
    if report["schema_version"] != 1:
        failures.append(f"unexpected schema_version {report['schema_version']}")
    if not report["provenance"]["artifact_sha256"]:
        failures.append("report carries no artifact hash")

    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        return 1

    print(f"M3 consumer: {len(EXPECTED)} checks, all outcomes and controls as declared")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: verify-m3-consumer.py REPORT.json", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
