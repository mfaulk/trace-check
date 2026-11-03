#!/usr/bin/env python3
"""Checks the M6 generated-testing report, not the exit code.

A run can exit 0 for reasons that have nothing to do with the analysis having
happened, so CI validates the report's own claims: that every configured
contract was checked, that both positive controls confirmed for each one, that
the clean contracts are security contracts which passed, and that the
deliberately vulnerable ones are analyzer-regression fixtures whose planted
leaks were found and attributed to an input.

Usage: verify-m6-generated.py <report.json>
"""

import json
import pathlib
import sys

# Contracts whose implementations are constant-time. These must be *security*
# contracts, because that is the policy a developer's own function gets.
CLEAN = {
    "crypto::tag::verify_tag",
    "crypto::lookup::substitute",
    "crypto::controls::public_branch",
    "crypto::reduce::reduce_once",
    "crypto::reduce::reduce_once_masked",
    # M7's false-positive control: the same three-predicate shape as
    # `hidden::nested_modes` guarding a *safe* region. Exploration reaches it
    # just as deeply and must still find nothing.
    "crypto::hidden::nested_modes_clean",
    # M7's attribution control: a `probe` that is safe, beside a `probe` in a
    # sibling module that is not.
    "crypto::shadow::left::probe",
}

# Contracts the library contains on purpose so trace-check can be held to
# detecting them. Each must be declared as an analyzer regression, never as a
# security contract with a convenient expectation.
#
# Four of these are reached only because the library's configuration enables
# coverage-guided exploration for them: `hidden::nested_modes` and
# `hidden::header_gate` are unreachable by M6's generator at any budget (proved
# in crates/trace-check/tests/baseline.rs), so with `--no-explore` they
# honestly report NO_LEAK_OBSERVED and their declared outcome goes unmet. This
# validator therefore describes a run made with the library's own
# configuration, which is what CI produces.
VULNERABLE = {
    "crypto::tag::verify_tag_early_exit",
    "crypto::tag::verify_tag_volatile_early_exit",
    "crypto::lookup::substitute_indexed",
    "crypto::lookup::substitute_mode",
    "crypto::controls::tail_byte_probe",
    "crypto::hidden::nested_modes",
    "crypto::hidden::header_gate",
    "crypto::hidden::threshold_window",
    "crypto::hidden::secret_gated",
    "crypto::shadow::right::probe",
}

# Contracts that are vulnerable but that this toolchain's analysis is **not
# expected to reach**, declared so the gap is asserted rather than left
# implicit. `hidden::magic_gate` hides its leak behind an exact 32-bit
# equality, and LLVM source-region feedback offers no gradient toward one
# constant -- measured in docs/spikes/m7-coverage-feedback.
#
# A third category rather than a special case in the second: "we detect this"
# and "we have recorded that we do not detect this" are different claims, and
# collapsing them would let a real regression hide as a declared limitation.
RECORDED_GAP = {
    "crypto::hidden::magic_gate",
}


def fail(message):
    print(f"verify-m6-generated: {message}", file=sys.stderr)
    raise SystemExit(1)


def main():
    if len(sys.argv) != 2:
        fail("usage: verify-m6-generated.py <report.json>")
    report = json.loads(pathlib.Path(sys.argv[1]).read_text())

    if report.get("schema_version") != 1:
        fail(f"unexpected schema_version {report.get('schema_version')!r}")
    if report.get("backend") != "generated-memcheck":
        fail(f"unexpected backend {report.get('backend')!r}")

    entries = {entry["contract"]: entry for entry in report["contracts"]}
    overlap = (CLEAN & VULNERABLE) | (CLEAN & RECORDED_GAP) | (VULNERABLE & RECORDED_GAP)
    if overlap:
        fail(f"these contracts are classified twice by this validator: {sorted(overlap)}")
    expected = CLEAN | VULNERABLE | RECORDED_GAP
    missing = expected - entries.keys()
    if missing:
        fail(f"these contracts were not checked: {sorted(missing)}")
    unexpected = entries.keys() - expected
    if unexpected:
        fail(
            "these contracts were checked but this validator does not know what "
            f"to expect of them: {sorted(unexpected)}"
        )

    # `--ci` was passed, so nothing may have been skipped.
    if report.get("not_selected"):
        fail(f"contracts were skipped under --ci: {report['not_selected']}")

    for name, entry in sorted(entries.items()):
        check = entry["check"]

        # A clean result from an uninstrumented or uncalibrated run proves
        # nothing, so both controls are required of every contract -- including
        # the ones that leak.
        if check["calibration"] != "confirmed":
            fail(f"{name}: calibration did not confirm ({check['calibration']})")
        if check["binding"] != "confirmed":
            fail(
                f"{name}: the secret-binding control did not confirm "
                f"({check['binding']}), so the marked bytes were not shown to "
                "reach the function"
            )
        if check["cases_completed"] == 0:
            fail(f"{name}: no generated case completed")
        if check["cases_completed"] != check["cases_planned"]:
            fail(
                f"{name}: {check['cases_completed']} of {check['cases_planned']} "
                "cases completed"
            )
        if check["other_diagnostics"]:
            fail(f"{name}: unresolved non-secret diagnostics were reported")
        if check["unattributed"]:
            fail(f"{name}: secret-dependency findings were not attributable")

        # Input-strategy coverage has to be stated, or "N cases completed" means
        # nothing.
        coverage = entry["corpus"]["strategy_coverage"]
        if not coverage:
            fail(f"{name}: no input-strategy coverage was reported")
        if not entry["corpus"]["sha256"]:
            fail(f"{name}: the corpus was not fingerprinted")

        # Boundary coverage is a hard guarantee: a budget that cannot cover a
        # contract's boundary values is refused outright, so a completed run may
        # never report boundary cases dropped for budget. Pairwise may be
        # truncated -- it is quadratic and explicitly best-effort.
        for entry_coverage in coverage:
            if entry_coverage["strategy"] != "boundaries":
                continue
            dropped = (
                entry_coverage["planned"]
                - entry_coverage["emitted"]
                - entry_coverage["duplicates"]
            )
            if dropped > 0:
                fail(
                    f"{name}: {dropped} boundary case(s) were dropped for budget, but the "
                    "boundary floor is supposed to make that impossible"
                )

        if name in RECORDED_GAP:
            # A declared limitation. It must be an analyzer regression -- a
            # security contract cannot declare that a leak is acceptable -- and
            # it must still produce the outcome it declares. If it starts being
            # detected that is good news, and it requires
            # docs/MILESTONE-07.md and the configuration to be revised rather
            # than silently absorbed.
            if entry["expectation"] != "analyzer-regression":
                fail(
                    f"{name} records a known gap and must be an analyzer regression, not "
                    f"{entry['expectation']!r}"
                )
            if check["outcome"] == "LEAK_DETECTED":
                fail(
                    f"{name} was detected. That is an improvement, not a pass: this validator, "
                    "examples/crypto-library/trace-check.toml and the comparison-guidance "
                    "analysis in docs/MILESTONE-07.md all have to be updated"
                )
            if check["outcome"] != "NO_LEAK_OBSERVED":
                fail(f"{name}: expected NO_LEAK_OBSERVED, got {check['outcome']}")
            if entry["policy"] != "satisfied":
                fail(f"{name}: {entry['policy']} -- {entry['policy_detail']}")
        elif name in CLEAN:
            if entry["expectation"] != "security-contract":
                fail(
                    f"{name} is constant-time and must be checked as a security "
                    f"contract, not as {entry['expectation']!r}"
                )
            if "expected_outcome" in entry:
                fail(
                    f"{name}: a security contract must not declare an expected "
                    "outcome"
                )
            if check["outcome"] != "NO_LEAK_OBSERVED":
                fail(f"{name}: expected NO_LEAK_OBSERVED, got {check['outcome']}")
            if entry["policy"] != "satisfied":
                fail(f"{name}: {entry['policy']} -- {entry['policy_detail']}")
        else:
            if entry["expectation"] != "analyzer-regression":
                fail(
                    f"{name} is deliberately vulnerable and must be declared an "
                    f"analyzer regression, not {entry['expectation']!r}. A "
                    "security contract cannot be allowed to expect a leak"
                )
            if check["outcome"] != "LEAK_DETECTED":
                fail(f"{name}: expected LEAK_DETECTED, got {check['outcome']}")
            if not check["findings"]:
                fail(f"{name}: LEAK_DETECTED with no findings recorded")
            for finding in check["findings"]:
                if not finding["attributed"]:
                    fail(f"{name}: a finding was not attributed to the contract")
                # Every finding must reduce to an input or a preserved
                # sequence; a finding that could not be attributed to either
                # would have been silently useless.
                kind = finding["isolation"]["kind"]
                if kind not in ("case", "single", "sequence"):
                    fail(f"{name}: unknown isolation kind {kind!r}")
                if kind == "sequence":
                    if not finding["isolation"]["ids"]:
                        fail(f"{name}: a sequence-dependent finding kept no cases")

    # The report must restate what it does not show.
    limitations = " ".join(report["limitations"])
    for required in ("not a proof", "Execution coverage", "not the production binary"):
        if required not in limitations:
            fail(f"the report does not state its limits: {required!r} is missing")

    summary = report["summary"]
    if summary["leaks_detected"] != 0:
        fail(
            "a planted leak in an analyzer-regression fixture was counted as a "
            "security failure"
        )
    if not summary["ok"]:
        fail(f"the run is not ok: {summary['blocking_reasons']}")

    print(
        f"verify-m6-generated: {len(entries)} contract(s) checked, "
        f"{len(CLEAN)} clean, {len(VULNERABLE)} detected and "
        f"{len(RECORDED_GAP)} recorded gap(s), all as declared"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
