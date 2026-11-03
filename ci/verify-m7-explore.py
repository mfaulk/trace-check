#!/usr/bin/env python3
"""Checks the M7 coverage-guided report, not the exit code.

A run can exit 0 for reasons that have nothing to do with a search having
happened, so CI validates the report's own claims. The properties here are the
ones that would make M7 misleading rather than merely ineffective:

* exploration actually ran, against a *separate* instrumented artifact whose
  hash differs from the one the security result describes;
* that artifact marked nothing, so it cannot be the source of a security claim;
* the reported feedback granularity is the one this build implements, and says
  what is unavailable;
* no candidate's coverage was silently unmeasurable;
* every M6 case survived into the analyzed corpus;
* the planted hidden-path leak was found, and by the uninstrumented backend;
* the clean control with the same shape was reached and still found clean.

Usage: verify-m7-explore.py <report.json>
"""

import json
import pathlib
import sys

# Fixtures whose leak is reachable only with coverage feedback. Finding these is
# the milestone's acceptance claim.
HIDDEN_PATH = {"crypto::hidden::nested_modes", "crypto::hidden::header_gate"}

# Fixtures reached by exploration whose guarded region is *safe*. A finding here
# would mean discovery had begun manufacturing evidence.
CLEAN_CONTROLS = {"crypto::hidden::nested_modes_clean"}

# The fixture coverage feedback is expected NOT to reach, recorded so the gap is
# asserted rather than left implicit. See docs/MILESTONE-07.md section on
# comparison guidance.
NOT_REACHABLE_BY_REGIONS = {"crypto::hidden::magic_gate"}

EXPECTED_FEEDBACK = "llvm-regions"


def fail(message):
    print(f"verify-m7-explore: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    if len(sys.argv) != 2:
        fail("usage: verify-m7-explore.py <report.json>")
    report = json.loads(pathlib.Path(sys.argv[1]).read_text())

    if report.get("schema_version") != 1:
        fail(f"unexpected report schema version {report.get('schema_version')!r}")
    contracts = report.get("contracts") or []
    if not contracts:
        fail("the report contains no contracts, so nothing was checked")

    explored = [entry for entry in contracts if entry.get("discovery")]
    if not explored:
        fail(
            "no contract reports an exploration section, so this run did not explore. "
            "A missing search must never be reported as a successful M7 check"
        )

    by_id = {entry["contract"]: entry for entry in contracts}

    for entry in explored:
        name = entry["contract"]
        discovery = entry["discovery"]

        # Two artifacts, two hashes. A report that advertised one as
        # representing both analyses would be the central claim of the
        # milestone being false.
        security_hash = entry.get("artifact_sha256")
        discovery_hash = discovery.get("artifact_sha256")
        if not security_hash or not discovery_hash:
            fail(f"{name}: an artifact hash is missing")
        if security_hash == discovery_hash:
            fail(
                f"{name}: the discovery and security artifacts report the same hash "
                f"{security_hash[:12]}, so the two analyses are not separate"
            )
        if "instrument-coverage" not in (discovery.get("instrumentation") or ""):
            fail(f"{name}: the discovery artifact does not record its instrumentation")

        # The discovery artifact marks nothing. This is what makes it incapable
        # of producing secret-dependence evidence.
        if discovery.get("marked_bytes") != 0:
            fail(
                f"{name}: the discovery artifact reports marking "
                f"{discovery.get('marked_bytes')} byte(s); it must mark none"
            )

        # Granularity is reported, and reports what is missing.
        if discovery.get("feedback") != EXPECTED_FEEDBACK:
            fail(
                f"{name}: feedback is {discovery.get('feedback')!r}, expected "
                f"{EXPECTED_FEEDBACK!r}"
            )
        granularity = discovery.get("granularity") or ""
        if "region" not in granularity:
            fail(f"{name}: the granularity does not name regions: {granularity!r}")
        if "unavailable" not in granularity:
            fail(
                f"{name}: the granularity does not say what is unavailable, so a reader "
                f"could take it for edge or comparison coverage: {granularity!r}"
            )
        if not discovery.get("coverage_map_id"):
            fail(f"{name}: no coverage-map identity was recorded")

        # Unmeasurable candidates are a failure, not a detail. An empty region
        # set reads as "reached nothing new", so a silent decode failure would
        # make a search that did nothing look like a search that found nothing.
        failures = discovery.get("failures") or []
        if failures:
            fail(f"{name}: {len(failures)} candidate(s) produced no usable coverage: {failures[:3]}")

        # The search must have finished what it was asked to do.
        if discovery.get("termination") not in {"budget-exhausted", "converged", "queue-empty"}:
            fail(
                f"{name}: exploration stopped as {discovery.get('termination')!r}: "
                f"{discovery.get('termination_detail')}"
            )

        # Every M6 case survives into the analyzed corpus. Exploration must
        # never be able to reduce security checking.
        selection = discovery.get("selection") or {}
        mandatory = selection.get("mandatory")
        baseline = discovery.get("baseline_cases")
        if mandatory != baseline:
            fail(
                f"{name}: {mandatory} of {baseline} baseline case(s) were selected; "
                f"exploration must add to M6's corpus, never replace it"
            )
        if selection.get("total", 0) < mandatory:
            fail(f"{name}: the selected total {selection.get('total')} is below the mandatory count")
        if entry.get("check", {}).get("cases_planned", 0) < mandatory:
            fail(
                f"{name}: the analyzed corpus has "
                f"{entry['check'].get('cases_planned')} case(s), fewer than the "
                f"{mandatory} mandatory one(s)"
            )

        # The security side is unchanged: both controls still mandatory.
        check = entry.get("check", {})
        if check.get("calibration") != "confirmed" or check.get("binding") != "confirmed":
            fail(
                f"{name}: a positive control did not confirm (calibration "
                f"{check.get('calibration')}, binding {check.get('binding')}), so no security "
                f"conclusion here means anything"
            )
        if check.get("cases_completed") != check.get("cases_planned"):
            fail(
                f"{name}: {check.get('cases_completed')} of {check.get('cases_planned')} "
                f"case(s) completed"
            )
        # And the security result carries no coverage of its own.
        if "regions_reached" in check:
            fail(f"{name}: the security result carries a coverage number")

    # The acceptance claim: the hidden path is found, and attributed.
    for name in sorted(HIDDEN_PATH):
        entry = by_id.get(name)
        if entry is None:
            fail(f"{name} was not checked, so the acceptance claim is untested")
        if not entry.get("discovery"):
            fail(f"{name} was checked without exploration, so the claim is untested")
        if entry["check"].get("outcome") != "LEAK_DETECTED":
            fail(
                f"{name}: expected LEAK_DETECTED from coverage-guided discovery, got "
                f"{entry['check'].get('outcome')}. {entry['check'].get('message')}"
            )
        findings = entry["check"].get("findings") or []
        if not findings:
            fail(f"{name}: LEAK_DETECTED with no attributed finding")
        # Attributed to the library's own function, from the security artifact.
        if not any(finding.get("attributed") for finding in findings):
            fail(f"{name}: no finding is attributable to the contract's function")
        # And traceable back to the candidate that produced it.
        provenance = {
            record["case_id"]: record
            for record in entry["discovery"].get("selected_provenance") or []
        }
        triggering = []
        for finding in findings:
            isolation = finding.get("isolation") or {}
            triggering.extend(isolation.get("ids") or [])
            if "id" in isolation:
                triggering.append(isolation["id"])
        if not any(case_id in provenance for case_id in triggering):
            fail(
                f"{name}: no triggering case has recorded provenance, so a developer cannot "
                f"be told where the input came from"
            )
        explored_origin = any(
            provenance[case_id]["origin"].get("kind") == "mutated"
            for case_id in triggering
            if case_id in provenance
        )
        if not explored_origin:
            fail(
                f"{name}: the triggering input came from the baseline corpus, which "
                f"contradicts crates/trace-check/tests/baseline.rs"
            )

    # The false-positive control: reached just as deeply, still clean.
    for name in sorted(CLEAN_CONTROLS):
        entry = by_id.get(name)
        if entry is None:
            continue
        if not entry.get("discovery"):
            fail(f"{name} was checked without exploration, so the control proves nothing")
        if entry["discovery"].get("regions_added", 0) <= 0:
            fail(
                f"{name}: exploration added no regions, so this is not a false-positive "
                f"control -- it is a path nothing visited"
            )
        if entry["check"].get("outcome") != "NO_LEAK_OBSERVED":
            fail(
                f"{name}: a clean control produced {entry['check'].get('outcome')}. "
                f"Exploration must not manufacture findings"
            )

    # The recorded gap, asserted so it cannot quietly close or quietly widen.
    for name in sorted(NOT_REACHABLE_BY_REGIONS):
        entry = by_id.get(name)
        if entry is None:
            continue
        outcome = entry["check"].get("outcome")
        if outcome == "LEAK_DETECTED":
            fail(
                f"{name}: region coverage reached an exact 32-bit constant. That is good news, "
                f"but docs/MILESTONE-07.md's analysis of comparison guidance and "
                f"examples/crypto-library/trace-check.toml both have to be revised"
            )
        if outcome != "NO_LEAK_OBSERVED":
            fail(f"{name}: expected NO_LEAK_OBSERVED, got {outcome}")

    # The run's own verdict must agree with all of the above.
    summary = report.get("summary") or {}
    if not summary.get("ok"):
        fail(f"the report does not call this run a success: {summary.get('blocking_reasons')}")

    explored_names = sorted(entry["contract"] for entry in explored)
    print(
        f"verify-m7-explore: {len(explored)} contract(s) explored and checked "
        f"({', '.join(explored_names)})"
    )
    print(
        "verify-m7-explore: discovery and security artifacts are distinct, the discovery "
        "artifact marked nothing, and every finding came from the uninstrumented backend"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
