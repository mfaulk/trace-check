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

# One table per audited target, selected by the namespace the report contains.
# contract -> (expected outcome, expected finding classification or None)
ML_KEM = {
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

# kyberlib's seed-level contract reports the *same* rejection-sampling branches
# as ml-kem's, attributed rather than unattributable, because provenance
# survives its XOF. Asserting LEAK_DETECTED here and INCONCLUSIVE there is what
# keeps that comparison from silently decaying into agreement.
KYBERLIB = {
    "kyberaudit::decaps::decaps_valid_ciphertext": (CLEAN, None),
    "kyberaudit::decaps::decaps_corrupted_ciphertext": (CLEAN, None),
    "kyberaudit::decaps::decaps_supplied_ciphertext": (CLEAN, None),
    "kyberaudit::controls::no_planted_leak": (CLEAN, None),
    "kyberaudit::controls::public_component_branch": (CLEAN, None),
    "kyberaudit::controls::pre_keygen_seed_byte": (DETECTED, BRANCH),
    "kyberaudit::controls::secret_component_branch": (DETECTED, BRANCH),
    "kyberaudit::controls::secret_component_address": (DETECTED, VALUE),
    "kyberaudit::controls::shared_secret_branch": (DETECTED, BRANCH),
    "kyberaudit::seedlevel::keygen_and_decaps": (DETECTED, BRANCH),
}

TARGETS = {"mlkemaudit": ML_KEM, "kyberaudit": KYBERLIB}

# Per-target: the boundary pair, the controls whose failure invalidates
# everything, and the upstream frame the seed-level outcome is explained by.
SETTINGS = {
    "mlkemaudit": {
        "boundary_public": "mlkemaudit::controls::public_component_branch",
        "boundary_seed": "mlkemaudit::controls::public_component_branch_seed_level",
        "load_bearing": (
            "mlkemaudit::controls::secret_component_branch",
            "mlkemaudit::controls::secret_component_address",
            "mlkemaudit::controls::shared_key_branch",
        ),
        # Finding A: unattributable diagnostics, so the frame is looked for
        # among `other_diagnostics`.
        "artifact_frame": "ml_kem::algebra::rej_uniform",
        "artifact_in": "other_diagnostics",
        "artifact_contracts": (
            "mlkemaudit::controls::public_component_branch_seed_level",
            "mlkemaudit::seedlevel::keygen_and_decaps",
        ),
    },
    "kyberaudit": {
        "boundary_public": "kyberaudit::controls::public_component_branch",
        "boundary_seed": "kyberaudit::seedlevel::keygen_and_decaps",
        "load_bearing": (
            "kyberaudit::controls::secret_component_branch",
            "kyberaudit::controls::secret_component_address",
            "kyberaudit::controls::shared_secret_branch",
        ),
        # Finding A-prime: the same step, attributed, so the frame is looked
        # for among the findings themselves.
        "artifact_frame": "rej_uniform",
        "artifact_in": "findings",
        "artifact_contracts": ("kyberaudit::seedlevel::keygen_and_decaps",),
    },
}


def check_report(report: dict) -> tuple[list[str], str, int]:
    """Returns (problems, target namespace, contracts checked)."""
    contracts = {entry["contract"]: entry for entry in report.get("contracts", [])}
    problems: list[str] = []

    namespaces = {name.split("::", 1)[0] for name in contracts}
    known = namespaces & set(TARGETS)
    if len(known) != 1:
        return (
            [
                "the report must contain exactly one audited target's contracts; "
                f"saw namespaces {sorted(namespaces)}"
            ],
            "?",
            0,
        )
    target = known.pop()
    expected = TARGETS[target]
    settings = SETTINGS[target]

    missing = sorted(set(expected) - set(contracts))
    if missing:
        problems.append(f"contracts absent from the report: {missing}")

    extra = sorted(set(contracts) - set(expected))
    if extra:
        problems.append(
            f"contracts in the report that this script does not know about: {extra}. "
            "Add them here in the same commit that adds them to the audit"
        )

    for name, (expected_outcome, expected_class) in expected.items():
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

    # The boundary pair. The clean half must report *nothing*, not merely no
    # attributed finding.
    public_name = settings["boundary_public"]
    public = (contracts.get(public_name) or {}).get("check") or {}
    if public.get("other_diagnostics"):
        problems.append(
            f"{public_name}: clean but with {len(public['other_diagnostics'])} "
            "diagnostic(s); the key-level boundary is supposed to leave this branch "
            "entirely unobserved"
        )
    seed_name = settings["boundary_seed"]
    seed = (contracts.get(seed_name) or {}).get("check") or {}
    if seed.get("outcome") == CLEAN:
        problems.append(
            f"{seed_name}: clean. The seed-level encoding is supposed to observe what "
            "the key-level boundary declassifies, so the boundary is not doing what "
            "the audit says"
        )

    # The upstream rejection-sampling frame that explains the seed-level outcome.
    for name in settings["artifact_contracts"]:
        check = (contracts.get(name) or {}).get("check") or {}
        entries = check.get(settings["artifact_in"]) or []
        frames = {(item.get("fingerprint") or {}).get("function") for item in entries}
        if not any(
            frame and settings["artifact_frame"] in frame for frame in frames
        ):
            problems.append(
                f"{name}: nothing in {settings['artifact_frame']} among its "
                f"{settings['artifact_in']}. The recorded explanation for this "
                "contract's outcome no longer applies"
            )

    # Named explicitly so CI output shows them rather than implying them.
    for name in settings["load_bearing"]:
        check = (contracts.get(name) or {}).get("check") or {}
        if check.get("outcome") != DETECTED:
            problems.append(
                f"{name}: not detected. This is a load-bearing control; the audit's "
                "clean results mean nothing without it"
            )

    return problems, target, len(expected)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: ci/verify-m11-audit.py <report.json>", file=sys.stderr)
        return 2

    report = json.loads(pathlib.Path(sys.argv[1]).read_text())
    problems, target, count = check_report(report)

    if problems:
        print(f"M11 {target} audit report did NOT establish what it claims:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    expected = TARGETS[target]
    clean = sum(1 for outcome, _ in expected.values() if outcome == CLEAN)
    detected = sum(1 for outcome, _ in expected.values() if outcome == DETECTED)
    inconclusive = sum(
        1 for outcome, _ in expected.values() if outcome == INCONCLUSIVE
    )
    print(
        f"M11 {target} audit report checked: {count} contract(s), {clean} clean, "
        f"{detected} detected with the declared observation class, "
        f"{inconclusive} inconclusive, boundary pair intact, "
        "rejection-sampling frame present"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
