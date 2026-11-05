#!/usr/bin/env python3
"""Checks the M8 contract-coverage report, not the exit code.

A run can exit 0 for reasons that have nothing to do with the contracts having
been accounted for, so CI validates the report's own claims. The properties
here are the ones that would make M8 *misleading* rather than merely
incomplete:

* the inventory is complete, and read from a named artifact;
* the inventory is not empty, and its count matches what the library declares;
* every declaration has a status for every analysis required of it -- none can
  escape the accounting by being absent;
* nothing is `NOT_SELECTED` under `--all-contracts`;
* no exemption is hiding a detected leak;
* exemptions are excluded from the checked total;
* the report restates what it does not show.

Usage: verify-m8-contracts.py <report.json> [--expect-declared N]
"""

import json
import pathlib
import sys

EXPECTED_SCHEMA = 3

# Statuses that discharge an obligation. Everything else is a gap or a
# violation.
SATISFYING = {"CHECKED", "EXEMPTED"}

# Enforcement states this validator knows. An unrecognized one means the tool
# grew a state and this script was not updated, which must fail rather than be
# ignored.
KNOWN = SATISFYING | {
    "LEAK_DETECTED",
    "INCONCLUSIVE",
    "UNSUPPORTED",
    "NOT_SELECTED",
    "NOT_ANALYZED",
    "BACKEND_UNAVAILABLE",
    "INACTIVE",
    "INVENTORY_ERROR",
}

# `state` as serialized, lowercase kebab, mapped to the display name.
STATE_NAMES = {
    "checked": "CHECKED",
    "leak-detected": "LEAK_DETECTED",
    "inconclusive": "INCONCLUSIVE",
    "unsupported": "UNSUPPORTED",
    "not-selected": "NOT_SELECTED",
    "not-analyzed": "NOT_ANALYZED",
    "backend-unavailable": "BACKEND_UNAVAILABLE",
    "exempted": "EXEMPTED",
    "inactive": "INACTIVE",
    "inventory-error": "INVENTORY_ERROR",
}


def fail(message):
    print(f"verify-m8-contracts: {message}", file=sys.stderr)
    raise SystemExit(1)


def state_of(status):
    raw = status.get("state")
    name = STATE_NAMES.get(raw)
    if name is None:
        fail(f"unknown enforcement state {raw!r}; this validator needs updating")
    return name


def main():
    if len(sys.argv) < 2:
        fail("usage: verify-m8-contracts.py <report.json> [--expect-declared N]")
    report = json.loads(pathlib.Path(sys.argv[1]).read_text())

    expect_declared = None
    if "--expect-declared" in sys.argv:
        expect_declared = int(sys.argv[sys.argv.index("--expect-declared") + 1])

    if report.get("schema_version") != EXPECTED_SCHEMA:
        fail(
            f"unexpected schema_version {report.get('schema_version')!r}; this validator "
            f"reads the M8 coverage report (schema {EXPECTED_SCHEMA}), not M6's check report"
        )

    # --- the inventory ---------------------------------------------------
    inventory = report.get("inventory") or {}
    if not inventory.get("complete"):
        fail(
            f"the inventory is not complete: {inventory.get('objects_read')} of "
            f"{inventory.get('objects_inspected')} object member(s) read. Declarations may be "
            f"missing entirely, so nothing below can be trusted"
        )
    if not inventory.get("artifact_sha256"):
        fail("the inventory names no artifact, so it describes no particular build")
    if "lto=off" not in (inventory.get("profile") or ""):
        fail(
            "the inventory build does not record `lto=off`. Under link-time optimization an "
            "rlib holds bitcode and carries no ELF sections, which would yield an empty "
            "inventory rather than an error"
        )
    declared = inventory.get("contracts_declared")
    if not declared:
        fail(
            "the inventory declares no contracts. A library with none is legitimate, but this "
            "run is supposed to cover a library that has them"
        )
    if expect_declared is not None and declared != expect_declared:
        fail(
            f"the inventory declares {declared} contract(s), expected {expect_declared}. "
            f"Either a declaration was added or removed without updating CI, or discovery is "
            f"short"
        )
    contracts = report.get("contracts") or []
    if len(contracts) != declared:
        fail(
            f"{len(contracts)} contract(s) in the matrix against {declared} declared: the "
            f"report and the inventory disagree"
        )

    # --- per-contract accounting -----------------------------------------
    selection = report.get("selection") or ""
    all_contracts = "--all-contracts" in selection
    for entry in contracts:
        name = entry.get("id") or "(unnamed)"
        if not entry.get("site"):
            fail(f"{name}: no declaration site, so a developer cannot find it")
        required = entry.get("required") or []
        if not required:
            fail(
                f"{name}: no analysis is required of it. Under the default policy every "
                f"declaration owes a generated check, so an empty requirement means the policy "
                f"resolved to nothing"
            )
        status = entry.get("status") or {}
        # Totality: the property the `NOT_ANALYZED` state exists to guarantee.
        for analysis in required:
            if analysis not in status:
                fail(
                    f"{name}: `{analysis}` is required and has no status at all. A requirement "
                    f"that is absent from the accounting is the exact failure this milestone "
                    f"exists to prevent"
                )
        states = {analysis: state_of(status[analysis]) for analysis in required}
        for analysis, state in states.items():
            if state not in KNOWN:
                fail(f"{name}: `{analysis}` has unknown state {state}")
            if all_contracts and state == "NOT_SELECTED":
                fail(
                    f"{name}: `{analysis}` is NOT_SELECTED under --all-contracts, which is "
                    f"supposed to select every declaration"
                )

        # An exemption must never be covering a detected leak.
        leaked = any(
            evidence.get("outcome") == "LEAK_DETECTED"
            for evidence in entry.get("evidence") or []
        )
        waived = [analysis for analysis, state in states.items() if state == "EXEMPTED"]
        if leaked and waived:
            # Per analysis as of M10.1: a fixture may declare that generated
            # inputs will not reach its gate while a solver will, so the
            # question is whether *the backend that found the leak* predicted
            # it. A declaration for another backend excuses nothing here.
            declared = entry.get("regression_expectations") or {}
            predicted = {
                evidence["analysis"]
                for evidence in entry.get("evidence") or []
                if evidence.get("outcome") == "LEAK_DETECTED"
                and declared.get(evidence.get("analysis")) == "LEAK_DETECTED"
            }
            unpredicted = {
                evidence["analysis"]
                for evidence in entry.get("evidence") or []
                if evidence.get("outcome") == "LEAK_DETECTED"
            } - predicted
            if unpredicted:
                fail(
                    f"{name}: {sorted(unpredicted)} observed a leak and `{waived[0]}` is "
                    f"EXEMPTED. A waiver may excuse not performing an analysis; it may never "
                    f"suppress what one found"
                )

        # Evidence is reported in the backends' own vocabulary.
        for evidence in entry.get("evidence") or []:
            outcome = evidence.get("outcome")
            if outcome not in {
                "LEAK_DETECTED",
                "NO_LEAK_OBSERVED",
                "VERIFIED_BOUNDED",
                "INCONCLUSIVE",
                "DIFFERENCE_DETECTED",
                "NO_DIFFERENCE_OBSERVED",
            }:
                fail(f"{name}: unknown evidence outcome {outcome!r}")
            if not evidence.get("artifact_sha256"):
                fail(
                    f"{name}: an evidence record names no artifact, so it does not say which "
                    f"build it describes"
                )

    # --- the summary -----------------------------------------------------
    summary = report.get("summary") or {}
    counts = {
        key: summary.get(key)
        for key in (
            "declared",
            "checked",
            "violations",
            "exempted",
            "lacking_evidence",
            "requirements",
            "requirements_checked",
            "requirements_exempted",
        )
    }
    for key, value in counts.items():
        if value is None:
            fail(f"the summary has no `{key}` count")
    if counts["declared"] != declared:
        fail(
            f"the summary declares {counts['declared']} contract(s) against the inventory's "
            f"{declared}"
        )
    bucketed = counts["checked"] + counts["violations"] + counts["exempted"] + counts["lacking_evidence"]
    if bucketed != declared:
        fail(
            f"the summary buckets {bucketed} contract(s) but {declared} are declared, so some "
            f"declaration is in no bucket at all"
        )
    # A waived obligation must not be counted as met.
    if counts["requirements_exempted"] and counts["requirements_checked"] + counts[
        "requirements_exempted"
    ] > counts["requirements"]:
        fail("waived obligations are being counted as met as well as waived")

    # --- the limits ------------------------------------------------------
    limitations = " ".join(report.get("limitations") or [])
    for required_text in (
        "does not discover functions",
        "not a security outcome",
        "never a proof",
        "never suppresses a detected leak",
    ):
        if required_text not in limitations:
            fail(f"the report does not restate its limits: {required_text!r} is missing")
    if "not the proportion of secret inputs" not in (
        summary.get("enforcement_caveat") or ""
    ):
        fail("the enforcement rate is reported without saying what it is not")

    # --- the verdict -----------------------------------------------------
    if not summary.get("ok"):
        fail(f"the report does not call this run a success: {summary.get('blocking_reasons')}")

    print(
        f"verify-m8-contracts: {declared} declaration(s) accounted for -- "
        f"{counts['checked']} checked, {counts['violations']} violation(s), "
        f"{counts['exempted']} exempted, {counts['lacking_evidence']} lacking evidence"
    )
    print(
        "verify-m8-contracts: the inventory is complete and artifact-bound, every requirement "
        "has a status, and no waiver is covering a detected leak"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
