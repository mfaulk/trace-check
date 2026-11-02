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

# Cases whose leak the analyzer settles with a relational satisfiability query,
# so a solver-produced counterexample must be present. The others are settled
# by taint analysis or preprocessing and have no model to extract; the report
# must say so rather than invent one.
WITNESS_REQUIRED = {"trip-count"}


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
    # Regression: the runtime that holds the image must be the one used. CI
    # pulls into Docker only while Podman probes first, so a tool-selection
    # regression shows up here rather than as a confusing "not present".
    expected_runtime = os.environ.get("EXPECTED_CONTAINER_RUNTIME")
    if expected_runtime and provenance.get("container_tool") != expected_runtime:
        failures.append(
            f"analyzed with {provenance.get('container_tool')!r}, "
            f"expected {expected_runtime!r}"
        )

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

        # A result must be attributed to the function it names, with the
        # analyzer's own evidence that exploration reached it.
        target = case.get("target") or {}
        if want != "INCONCLUSIVE" and not target.get("reached"):
            failures.append(
                f"{name}: outcome {want} without evidence that "
                f"{target.get('function')!r} was reached"
            )

        # A result is only as strong as the observation classes it checked.
        if not case.get("checked_features"):
            failures.append(f"{name}: no observation model recorded")
        if want == "VERIFIED_BOUNDED" and case.get("unchecked_properties"):
            failures.append(
                f"{name}: verified while leaving {case['unchecked_properties']} unchecked; "
                "the bundled suite checks every modeled class"
            )

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

            counterexamples = case.get("counterexamples") or []
            if name in WITNESS_REQUIRED:
                if case.get("witness") != "solver_counterexample":
                    failures.append(
                        f"{name}: expected a solver counterexample, "
                        f"got witness={case.get('witness')!r}"
                    )
                if not counterexamples:
                    failures.append(f"{name}: no counterexample pair reported")
            elif case.get("witness") != "unavailable_from_analyzer":
                failures.append(
                    f"{name}: witness={case.get('witness')!r} but no model is expected"
                )
            for pair in counterexamples:
                # An identical pair witnesses nothing.
                if pair.get("left") == pair.get("right"):
                    failures.append(f"{name}: counterexample pair is identical")
                if not pair.get("query"):
                    failures.append(f"{name}: counterexample names no source query")
        else:
            if case.get("counterexamples"):
                failures.append(
                    f"{name}: a {want} result must not carry a counterexample"
                )

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
