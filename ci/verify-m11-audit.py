#!/usr/bin/env python3
"""Asserts the M11 ml-kem audit's own claims against a `check` report.

An exit code says the run finished, not that it established what the audit says
it established. This script checks the claims the audit's conclusions actually
rest on, so a quiet regression in any of them fails CI instead of being written
up again next time:

* every declared contract was checked -- a report covering a subset would make
  "no leak found" a statement about an unknown fraction of the audit;
* the three real decapsulation contracts are clean;
* the five positive controls are detected, **with the right observation class**:
  an address control that starts reporting a branch is not the control it was;
* `shared_key_branch` is detected. This is the sensitivity control, and without
  it the clean results are compatible with the analysis having gone blind in
  the middle of the Fujisaki-Okamoto transform;
* `secret_component_branch` and `secret_component_address` are detected. If
  either reads as public, the classification boundary has declassified genuine
  key material and every clean result in the audit is worthless;
* `public_component_branch` is clean **with no diagnostics at all**, while the
  same branch on the same byte under the seed-level encoding is not clean. The
  pair is the only evidence that the boundary moved the classification line
  where it claims to;
* the seed-level contracts are INCONCLUSIVE with at least one diagnostic
  attributed to `ml_kem::algebra::rej_uniform`, which is finding A. A run that
  stopped producing them would mean either the library or the tool changed, and
  either way the audit's write-up no longer describes reality;
* each contract records an artifact hash, because a result describes a build.

Usage:
    cargo trace-check check --all-configured --ci --format json \\
        --manifest-path examples/ml-kem-audit/Cargo.toml > report.json
    ci/verify-m11-audit.py report.json
"""

import json
import pathlib
import sys

CLEAN = "NO_LEAK_OBSERVED"
DETECTED = "LEAK_DETECTED"
INCONCLUSIVE = "INCONCLUSIVE"

BRANCH = "secret_dependent_branch"
# Memcheck reports a secret-derived load as a use of an undefined *value*, and
# the tool classifies it that way. The address control is still an address
# control -- the observation is the load's effective address -- but asserting a
# class the tool never emits would make this script vacuous.
VALUE = "secret_dependent_value"

# contract -> (expected outcome, expected finding classification or None)
EXPECTED = {
    "mlkemaudit::decaps::decaps_valid_ciphertext": (CLEAN, None),
    "mlkemaudit::decaps::decaps_corrupted_ciphertext": (CLEAN, None),
    "mlkemaudit::decaps::decaps_supplied_ciphertext": (CLEAN, None),
    "mlkemaudit::controls::no_planted_leak": (CLEAN, None),
    "mlkemaudit::controls::public_component_branch": (CLEAN, None),
    "mlkemaudit::controls::pre_keygen_seed_byte": (DETECTED, BRANCH),
    "mlkemaudit::controls::secret_component_branch": (DETECTED, BRANCH),
    "mlkemaudit::controls::secret_component_address": (DETECTED, VALUE),
    "mlkemaudit::controls::derived_arithmetic_branch": (DETECTED, BRANCH),
    "mlkemaudit::controls::shared_key_branch": (DETECTED, BRANCH),
    "mlkemaudit::controls::public_component_branch_seed_level": (INCONCLUSIVE, None),
    "mlkemaudit::seedlevel::keygen_and_decaps": (INCONCLUSIVE, None),
}

# The boundary pair, and the control whose failure would invalidate everything.
BOUNDARY_PUBLIC = "mlkemaudit::controls::public_component_branch"
BOUNDARY_SEED = "mlkemaudit::controls::public_component_branch_seed_level"
OVER_DECLASSIFICATION = (
    "mlkemaudit::controls::secret_component_branch",
    "mlkemaudit::controls::secret_component_address",
)
SENSITIVITY = "mlkemaudit::controls::shared_key_branch"

# Finding A's upstream frame.
REJ_UNIFORM = "ml_kem::algebra::rej_uniform"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: ci/verify-m11-audit.py <report.json>", file=sys.stderr)
        return 2

    report = json.loads(pathlib.Path(sys.argv[1]).read_text())
    contracts = {entry["contract"]: entry for entry in report.get("contracts", [])}
    problems: list[str] = []

    missing = sorted(set(EXPECTED) - set(contracts))
    if missing:
        problems.append(f"contracts absent from the report: {missing}")

    extra = sorted(set(contracts) - set(EXPECTED))
    if extra:
        problems.append(
            f"contracts in the report that this script does not know about: {extra}. "
            "Add them here in the same commit that adds them to the audit"
        )

    for name, (expected_outcome, expected_class) in EXPECTED.items():
        entry = contracts.get(name)
        if entry is None:
            continue
        check = entry.get("check") or {}
        outcome = check.get("outcome")
        if outcome != expected_outcome:
            problems.append(f"{name}: expected {expected_outcome}, observed {outcome}")
            continue

        findings = check.get("findings") or []
        if expected_class is not None:
            classes = {finding.get("classification") for finding in findings}
            if expected_class not in classes:
                problems.append(
                    f"{name}: detected, but no finding classified {expected_class} "
                    f"(saw {sorted(c for c in classes if c)})"
                )
            if not all(finding.get("attributed") for finding in findings):
                problems.append(f"{name}: a finding was not attributed to the contract")
        elif expected_outcome == CLEAN and findings:
            problems.append(f"{name}: reported clean with {len(findings)} finding(s)")

        if not entry.get("artifact_sha256"):
            problems.append(f"{name}: no artifact hash recorded")

    # The boundary pair. `public_component_branch` must be clean with *nothing*
    # reported, not merely with no attributed finding.
    public = (contracts.get(BOUNDARY_PUBLIC) or {}).get("check") or {}
    if public.get("other_diagnostics"):
        problems.append(
            f"{BOUNDARY_PUBLIC}: clean but with "
            f"{len(public['other_diagnostics'])} diagnostic(s); the key-level boundary "
            "is supposed to leave this branch entirely unobserved"
        )
    seed = (contracts.get(BOUNDARY_SEED) or {}).get("check") or {}
    if seed.get("outcome") == CLEAN:
        problems.append(
            f"{BOUNDARY_SEED}: clean. The same branch on the same byte is clean under "
            "both encodings, so the boundary is not doing what the audit says"
        )

    # Finding A, by frame rather than by count.
    for name in (BOUNDARY_SEED, "mlkemaudit::seedlevel::keygen_and_decaps"):
        check = (contracts.get(name) or {}).get("check") or {}
        frames = {
            (diagnostic.get("fingerprint") or {}).get("function")
            for diagnostic in check.get("other_diagnostics") or []
        }
        if REJ_UNIFORM not in frames:
            problems.append(
                f"{name}: no diagnostic in {REJ_UNIFORM}. Finding A is the recorded "
                "explanation for this contract's INCONCLUSIVE and no longer applies"
            )

    # Restate the two controls everything else depends on, so a reader of CI
    # output sees them named rather than having to infer them from a pass.
    for name in (*OVER_DECLASSIFICATION, SENSITIVITY):
        check = (contracts.get(name) or {}).get("check") or {}
        if check.get("outcome") != DETECTED:
            problems.append(
                f"{name}: not detected. This is a load-bearing control; the audit's "
                "clean results mean nothing without it"
            )

    if problems:
        print("M11 ml-kem audit report did NOT establish what it claims:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    detected = sum(
        1 for name, (outcome, _) in EXPECTED.items() if outcome == DETECTED
    )
    clean = sum(1 for name, (outcome, _) in EXPECTED.items() if outcome == CLEAN)
    print(
        f"M11 audit report checked: {len(EXPECTED)} contract(s), {clean} clean, "
        f"{detected} control(s) detected with the declared observation class, "
        "2 inconclusive with finding A's frame present, boundary pair intact"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
