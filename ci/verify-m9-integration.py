#!/usr/bin/env python3
"""Checks the M9 real-library report, not the exit code.

`verify-m8-contracts.py` already establishes that the inventory is complete and
that every declaration has a status. This script checks the things specific to
auditing somebody else's library -- the ones that would make the report
*misleading* rather than merely incomplete:

* every contract this integration declares is present, and no extra one is
  reported without an expectation here;
* the expected outcome per contract, including the seven controls that must be
  LEAK_DETECTED -- a control that stops being detected means a clean result on
  the real operations establishes nothing;
* at least one branch finding and one address finding among the controls, so
  both halves of the observation model are shown working;
* secret marking was calibrated and bound for every contract, so no clean
  result came from a harness that marked nothing;
* every planned case actually completed, so a clean result is not a truncated
  run;
* every finding is attributed, and none is retained-but-unattributable;
* the report still carries its own limitations.

Usage: verify-m9-integration.py <report.json>
"""

import json
import pathlib
import sys

EXPECTED_SCHEMA = 2

# The contracts this integration declares, and what each one must report.
# Written here rather than read from the report: a validator that learns its
# expectations from the thing it validates checks nothing.
EXPECTED = {
    # The real operations. A clean result here is the audit evidence.
    "cbaudit::add::wrapping_add_secret_left": "NO_LEAK_OBSERVED",
    "cbaudit::add::wrapping_add_both_secret": "NO_LEAK_OBSERVED",
    "cbaudit::select::ct_select": "NO_LEAK_OBSERVED",
    "cbaudit::monty::mul_secret_left": "NO_LEAK_OBSERVED",
    "cbaudit::monty::mul_both_secret": "NO_LEAK_OBSERVED",
    # The negative control: a branch on a public input is not a leak.
    "cbaudit::controls::public_operand_branch": "NO_LEAK_OBSERVED",
    # The propagation gate. Each must be detected.
    "cbaudit::controls::pre_decode_first_byte": "LEAK_DETECTED",
    "cbaudit::controls::decoded_high_limb_branch": "LEAK_DETECTED",
    "cbaudit::controls::decoded_interior_limb_branch": "LEAK_DETECTED",
    "cbaudit::controls::decoded_last_byte_branch": "LEAK_DETECTED",
    "cbaudit::controls::carry_branch": "LEAK_DETECTED",
    "cbaudit::controls::decoded_address_probe": "LEAK_DETECTED",
    "cbaudit::controls::branch_selected": "LEAK_DETECTED",
}

# The controls that establish propagation *through* the library's own types,
# as opposed to merely establishing that the input array was marked.
PROPAGATION_CONTROLS = {
    "cbaudit::controls::decoded_high_limb_branch",
    "cbaudit::controls::decoded_interior_limb_branch",
    "cbaudit::controls::decoded_last_byte_branch",
    "cbaudit::controls::carry_branch",
    "cbaudit::controls::decoded_address_probe",
}

BRANCH = "secret_dependent_branch"
ADDRESS = "secret_dependent_value"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        fail("usage: verify-m9-integration.py <report.json>")
    report = json.loads(pathlib.Path(sys.argv[1]).read_text())

    schema = report.get("schema_version")
    if schema != EXPECTED_SCHEMA:
        fail(f"report schema {schema}, expected {EXPECTED_SCHEMA}")

    outcomes = {}
    classes = {}
    for contract in report.get("contracts", []):
        identity = contract["id"]
        evidence = contract.get("evidence") or []
        if not evidence:
            fail(f"{identity} carries no evidence")
        for entry in evidence:
            outcomes[identity] = entry["outcome"]
            check = entry.get("check")
            if check is None:
                fail(f"{identity} has an outcome with no check record behind it")

            # A clean result from a harness that never marked anything is the
            # failure mode the whole design exists to prevent.
            if check.get("calibration") != "confirmed":
                fail(f"{identity}: calibration is {check.get('calibration')!r}")
            if check.get("binding") != "confirmed":
                fail(f"{identity}: secret binding is {check.get('binding')!r}")
            if not check.get("marked_bytes"):
                fail(f"{identity}: no secret bytes were marked")

            planned = check.get("cases_planned")
            completed = check.get("cases_completed")
            if planned != completed:
                fail(
                    f"{identity}: {completed} of {planned} case(s) completed, so "
                    "this result describes a truncated run"
                )

            unattributed = check.get("unattributed") or []
            if unattributed:
                fail(
                    f"{identity}: {len(unattributed)} finding(s) could not be "
                    f"attributed (first at {unattributed[0]['stack'][0]}). A "
                    "retained finding is not a clean result"
                )
            for finding in check.get("findings") or []:
                if not finding.get("attributed"):
                    fail(f"{identity}: a finding is not attributed to the contract")
                classes.setdefault(identity, set()).add(finding["classification"])

    missing = sorted(set(EXPECTED) - set(outcomes))
    if missing:
        fail(f"contracts declared by this integration but absent from the report: {missing}")
    extra = sorted(set(outcomes) - set(EXPECTED))
    if extra:
        fail(
            f"contracts in the report with no expectation in this validator: {extra}. "
            "Add them here rather than letting an unchecked declaration pass"
        )

    for identity, expected in sorted(EXPECTED.items()):
        if outcomes[identity] != expected:
            hint = (
                " -- the propagation gate has stopped working, so a clean result "
                "on the real operations establishes nothing"
                if identity in PROPAGATION_CONTROLS
                else ""
            )
            fail(f"{identity} is {outcomes[identity]}, expected {expected}{hint}")

    observed = set().union(*classes.values()) if classes else set()
    if BRANCH not in observed:
        fail("no control produced a branch finding")
    if ADDRESS not in observed:
        fail(
            "no control produced an address finding, so only half the observation "
            "model is shown working"
        )

    if not report.get("limitations"):
        fail("the report states no limitations")

    detected = sum(1 for value in EXPECTED.values() if value == "LEAK_DETECTED")
    clean = len(EXPECTED) - detected
    print(
        f"verify-m9-integration: {len(EXPECTED)} contract(s) -- {detected} control(s) "
        f"detected, {clean} clean, both observation classes exercised"
    )
    print(
        "verify-m9-integration: marking calibrated and bound for every contract, "
        "every planned case completed, every finding attributed"
    )


if __name__ == "__main__":
    main()
