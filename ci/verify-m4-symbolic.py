#!/usr/bin/env python3
"""Verify the M4 symbolic report establishes what it claims.

Used by CI. Exit code 0 only says every case met its declared expectation; it
does not say the analysis was complete, that the analyzer was the pinned one,
or that a VERIFIED_BOUNDED verdict discharged any obligation at all. Those are
exactly the ways a verification job passes while verifying nothing, so they are
checked here against the report rather than inferred from the exit status.
"""

import json
import os
import sys

EXPECTED = {
    "table-lookup": "LEAK_DETECTED",
    "trip-count": "LEAK_DETECTED",
    "conditional-lookup": "LEAK_DETECTED",
    "masked-scan": "VERIFIED_BOUNDED",
    "public-branch": "VERIFIED_BOUNDED",
    "erased-branch": "VERIFIED_BOUNDED",
    "depth-bounded": "INCONCLUSIVE",
}


def main(path: str) -> int:
    report = json.load(open(path))
    failures = []

    if report.get("backend") != "binsec-relational-symbolic":
        failures.append(f"unexpected backend {report.get('backend')!r}")
    if report.get("executed", 0) == 0:
        failures.append("no cases were analyzed")
    if report.get("executed") != report.get("selected"):
        failures.append(
            f"{report.get('selected')} selected but {report.get('executed')} executed"
        )

    provenance = report.get("provenance", {})
    image = provenance.get("analyzer_image", "")
    if "@sha256:" not in image:
        failures.append(f"analyzer image is not digest-pinned: {image!r}")
    pinned = os.environ.get("ANALYZER_IMAGE")
    if pinned and image != pinned:
        failures.append(f"analyzer image {image!r} is not the pinned {pinned!r}")
    if len(provenance.get("artifact_sha256", "")) != 64:
        failures.append("no artifact hash recorded")
    if not provenance.get("rustc_version"):
        failures.append("no compiler recorded")
    if not provenance.get("solver"):
        failures.append("no solver recorded")

    cases = {case["case"]: case for case in report.get("cases", [])}
    for name, want in EXPECTED.items():
        case = cases.get(name)
        if case is None:
            failures.append(f"{name}: not analyzed")
            continue
        if case["outcome"] != want:
            failures.append(f"{name}: expected {want}, got {case['outcome']}")
        if not case["expectation"]["met"]:
            failures.append(f"{name}: declared expectation not met")

        exploration = case["exploration"]
        if want == "VERIFIED_BOUNDED":
            # A clean verdict drawn from a partial exploration, or one that
            # discharged no relational obligation, verifies nothing.
            if exploration.get("total_paths") != exploration.get("completed_paths"):
                failures.append(f"{name}: verified on an incomplete exploration")
            if exploration.get("pending_paths") != 0:
                failures.append(f"{name}: verified with paths still pending")
            if exploration.get("unknown_queries") != 0:
                failures.append(f"{name}: verified with unknown solver answers")
            checks = (exploration.get("control_flow_checks_total") or 0) + (
                exploration.get("memory_checks_total") or 0
            )
            if checks == 0:
                failures.append(f"{name}: verified with zero checks performed")
            if case.get("divergences"):
                failures.append(f"{name}: verified despite reported divergences")
        if want == "LEAK_DETECTED":
            divergences = case.get("divergences") or []
            if not divergences:
                failures.append(f"{name}: a leak with no divergence site reported")
            for divergence in divergences:
                if not divergence.get("instruction", "").startswith("0x"):
                    failures.append(f"{name}: divergence without an address")

    extra = sorted(set(cases) - set(EXPECTED))
    if extra:
        failures.append(f"unexpected cases in the report: {extra}")

    if not report.get("limitations"):
        failures.append("the report states no limitations on its claim")
    if not report.get("summary", {}).get("expectations_reproduced"):
        failures.append("the summary does not report expectations as reproduced")

    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"ok: {report['executed']} case(s) matched their declared outcomes")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <report.json>", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
