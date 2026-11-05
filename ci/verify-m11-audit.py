#!/usr/bin/env python3
"""Asserts an M11 audit's own claims against a unified `check --all-contracts` report.

An exit code says the run finished, not that it established what the audit says
it established. This script checks the claims the audit's conclusions actually
rest on, so a quiet regression in any of them fails CI instead of being written
up again next time.

It reads the **schema 3** report produced by `check --all-contracts`, not
`--all-configured`, for two reasons. The inventory in that report is derived
from the compiled library rather than from `trace-check.toml`, so a
`#[constant_time]` declaration nobody configured cannot hide from it. And
`--jobs` only takes effect on that path, so the audits' published timings are
measurements of what their command lines say.

What is asserted:

* the inventory is **complete** and every declaration was checked, with no
  violation and nothing lacking evidence -- M8's accounting, not a count of
  whatever the configuration happened to name;
* the contract set is exactly the one this script knows about, so a new
  declaration has to be added here deliberately;
* the three real decapsulation contracts are clean;
* the positive controls are detected **with the right observation class**: an
  address control that starts reporting a branch is not the control it was;
* **both** sensitivity controls are detected. They cover the
  Fujisaki-Okamoto transform's two data paths -- a valid ciphertext's shared
  key depends on the decryption key and not on `z`, a rejected one on `z` and
  not on the decryption -- so neither stands in for the other;
* the over-declassification controls are detected. If either reads as public,
  the classification boundary has declassified genuine key material and every
  clean result in the audit is worthless;
* the boundary pair really is a pair: the key-level half is clean **with no
  diagnostics at all**, and the seed-level half reports its *own planted
  branch*. Requiring only "not clean" there would pass even if the planted
  branch vanished, because the library's rejection sampling produces unrelated
  diagnostics under seed-level marking on its own;
* each contract's case budget, completion count, calibration and secret
  binding match what the audit published, so coverage cannot shrink while the
  outcomes stay the same.

`--self-test` mutates a real report and requires each mutation to be caught,
which is how this script is kept from passing vacuously. Finding one of M11's
review was exactly that: the boundary pair's seed-level half could pass on the
library's unrelated sampling diagnostics even if its own planted branch had
disappeared.

Usage:
    cargo trace-check check --all-contracts --ci --jobs 12 --format json \\
        --manifest-path examples/ml-kem-audit/Cargo.toml > report.json
    ci/verify-m11-audit.py report.json
    ci/verify-m11-audit.py --self-test report.json
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

# contract -> (expected outcome, expected finding class or None, planned cases)
ML_KEM = {
    "mlkemaudit::decaps::decaps_valid_ciphertext": (CLEAN, None, 48),
    "mlkemaudit::decaps::decaps_corrupted_ciphertext": (CLEAN, None, 96),
    "mlkemaudit::decaps::decaps_supplied_ciphertext": (CLEAN, None, 48),
    "mlkemaudit::controls::no_planted_leak": (CLEAN, None, 32),
    "mlkemaudit::controls::public_component_branch": (CLEAN, None, 32),
    "mlkemaudit::controls::pre_keygen_seed_byte": (DETECTED, BRANCH, 32),
    "mlkemaudit::controls::secret_component_branch": (DETECTED, BRANCH, 32),
    "mlkemaudit::controls::secret_component_address": (DETECTED, VALUE, 32),
    "mlkemaudit::controls::derived_arithmetic_branch": (DETECTED, BRANCH, 32),
    "mlkemaudit::controls::shared_key_branch": (DETECTED, BRANCH, 32),
    "mlkemaudit::controls::rejected_shared_key_branch": (DETECTED, BRANCH, 96),
    "mlkemaudit::controls::public_component_branch_seed_level": (INCONCLUSIVE, None, 32),
    "mlkemaudit::seedlevel::keygen_and_decaps": (INCONCLUSIVE, None, 32),
}

# kyberlib's seed-level contract reports the *same* rejection-sampling branches
# as ml-kem's, attributed rather than unattributable, because provenance
# survives its XOF. Asserting LEAK_DETECTED here and INCONCLUSIVE there is what
# keeps that comparison from silently decaying into agreement.
KYBERLIB = {
    "kyberaudit::decaps::decaps_valid_ciphertext": (CLEAN, None, 48),
    "kyberaudit::decaps::decaps_corrupted_ciphertext": (CLEAN, None, 96),
    "kyberaudit::decaps::decaps_supplied_ciphertext": (CLEAN, None, 48),
    "kyberaudit::controls::no_planted_leak": (CLEAN, None, 32),
    "kyberaudit::controls::public_component_branch": (CLEAN, None, 32),
    "kyberaudit::controls::pre_keygen_seed_byte": (DETECTED, BRANCH, 32),
    "kyberaudit::controls::secret_component_branch": (DETECTED, BRANCH, 32),
    "kyberaudit::controls::secret_component_address": (DETECTED, VALUE, 32),
    "kyberaudit::controls::shared_secret_branch": (DETECTED, BRANCH, 32),
    "kyberaudit::controls::rejected_shared_secret_branch": (DETECTED, BRANCH, 96),
    "kyberaudit::seedlevel::keygen_and_decaps": (DETECTED, BRANCH, 32),
}

TARGETS = {"mlkemaudit": ML_KEM, "kyberaudit": KYBERLIB}

SETTINGS = {
    "mlkemaudit": {
        "boundary_public": "mlkemaudit::controls::public_component_branch",
        "boundary_seed": "mlkemaudit::controls::public_component_branch_seed_level",
        # The seed-level half's own planted branch, by the frame it reports
        # rather than by a count. Without this the boundary pair passes on the
        # library's unrelated sampling diagnostics alone.
        "planted_frame": "public_component_branch_seed_level",
        "load_bearing": (
            "mlkemaudit::controls::secret_component_branch",
            "mlkemaudit::controls::secret_component_address",
            "mlkemaudit::controls::shared_key_branch",
            "mlkemaudit::controls::rejected_shared_key_branch",
        ),
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
        # Attributed here, so this contract's own planted branch is its
        # rejection-sampling finding -- covered by `artifact_frame` below.
        "planted_frame": None,
        "load_bearing": (
            "kyberaudit::controls::secret_component_branch",
            "kyberaudit::controls::secret_component_address",
            "kyberaudit::controls::shared_secret_branch",
            "kyberaudit::controls::rejected_shared_secret_branch",
        ),
        "artifact_frame": "rej_uniform",
        "artifact_in": "findings",
        "artifact_contracts": ("kyberaudit::seedlevel::keygen_and_decaps",),
    },
}


def generated(entry: dict) -> dict:
    """The generated-analysis evidence for one schema 3 contract entry."""
    for evidence in entry.get("evidence") or []:
        if evidence.get("analysis") == "generated":
            return evidence
    return {}


def mentions(items, needle: str) -> bool:
    """Whether any finding or diagnostic names `needle` in its frames."""
    for item in items or []:
        fingerprint = item.get("fingerprint") or {}
        if needle in (fingerprint.get("function") or ""):
            return True
        if needle in (fingerprint.get("location") or ""):
            return True
        if needle in (item.get("site") or ""):
            return True
        for frame in item.get("stack") or []:
            if needle in frame:
                return True
    return False


def check_report(report: dict) -> tuple[list[str], str, int]:
    problems: list[str] = []

    if report.get("schema_version") != 3:
        return (
            [
                "expected the unified schema 3 report, saw schema "
                f"{report.get('schema_version')}. Run `check --all-contracts`, not "
                "`--all-configured`: only the former carries the compiler-derived "
                "inventory this script checks"
            ],
            "?",
            0,
        )

    contracts = {entry["id"]: entry for entry in report.get("contracts") or []}
    namespaces = {name.split("::", 1)[0] for name in contracts}
    known = namespaces & set(TARGETS)
    if len(known) != 1:
        return (
            [f"expected exactly one audited target; saw namespaces {sorted(namespaces)}"],
            "?",
            0,
        )
    target = known.pop()
    expected = TARGETS[target]
    settings = SETTINGS[target]

    # M8's accounting, read from the compiled library rather than from the
    # configuration.
    inventory = report.get("inventory") or {}
    if not inventory.get("complete"):
        problems.append(
            "the contract inventory is not complete, so 'every declaration was "
            "checked' cannot be read from this report"
        )
    selection = report.get("selection") or ""
    if "all-contracts" not in selection:
        problems.append(
            f"selection is {selection!r}; the audit's claim is about every declaration "
            "in the inventory, not a configured subset"
        )
    summary = report.get("summary") or {}
    if summary.get("declared") != len(expected):
        problems.append(
            f"the library declares {summary.get('declared')} contract(s) but this "
            f"script knows {len(expected)}. A new declaration must be added here in "
            "the same commit that adds it to the audit"
        )
    for field in ("violations", "lacking_evidence", "exempted"):
        if summary.get(field):
            problems.append(f"summary.{field} is {summary[field]}, expected 0")
    if summary.get("checked") != summary.get("declared"):
        problems.append(
            f"{summary.get('checked')} of {summary.get('declared')} declaration(s) checked"
        )

    missing = sorted(set(expected) - set(contracts))
    if missing:
        problems.append(f"contracts absent from the report: {missing}")
    extra = sorted(set(contracts) - set(expected))
    if extra:
        problems.append(f"contracts this script does not know about: {extra}")

    for name, (outcome_expected, class_expected, cases_expected) in expected.items():
        entry = contracts.get(name)
        if entry is None:
            continue
        evidence = generated(entry)
        if not evidence:
            problems.append(f"{name}: no generated-analysis evidence in the report")
            continue
        outcome = evidence.get("outcome")
        if outcome != outcome_expected:
            problems.append(f"{name}: expected {outcome_expected}, observed {outcome}")
            continue
        if not evidence.get("artifact_sha256"):
            problems.append(f"{name}: no artifact hash recorded")

        check = evidence.get("check") or {}

        # Coverage, so a budget cannot shrink while the outcome stays the same.
        planned = check.get("cases_planned")
        if planned != cases_expected:
            problems.append(
                f"{name}: {planned} case(s) planned, the audit reports {cases_expected}"
            )
        if check.get("cases_completed") != check.get("cases_executed"):
            problems.append(
                f"{name}: {check.get('cases_completed')} of "
                f"{check.get('cases_executed')} executed case(s) completed"
            )
        for control in ("calibration", "binding"):
            state = check.get(control)
            if isinstance(state, dict):
                state = state.get("state") or state.get("outcome")
            if state is not None and "confirm" not in str(state).lower():
                problems.append(f"{name}: {control} is {state!r}, not confirmed")

        findings = check.get("findings") or []
        if class_expected is not None:
            classes = {finding.get("classification") for finding in findings}
            if class_expected not in classes:
                problems.append(
                    f"{name}: detected, but no finding classified {class_expected} "
                    f"(saw {sorted(c for c in classes if c)})"
                )
            if not all(finding.get("attributed") for finding in findings):
                problems.append(f"{name}: a finding was not attributed to the contract")
        elif outcome_expected == CLEAN and findings:
            problems.append(f"{name}: reported clean with {len(findings)} finding(s)")

    # The boundary pair. The clean half must report *nothing*.
    public_name = settings["boundary_public"]
    public_check = (generated(contracts.get(public_name) or {}) or {}).get("check") or {}
    if public_check.get("other_diagnostics"):
        problems.append(
            f"{public_name}: clean but with {len(public_check['other_diagnostics'])} "
            "diagnostic(s); the key-level boundary is supposed to leave this branch "
            "entirely unobserved"
        )

    seed_name = settings["boundary_seed"]
    seed_check = (generated(contracts.get(seed_name) or {}) or {}).get("check") or {}
    if seed_check.get("outcome") == CLEAN:
        problems.append(
            f"{seed_name}: clean. The seed-level encoding is supposed to observe what "
            "the key-level boundary declassifies"
        )
    planted = settings["planted_frame"]
    if planted is not None:
        seen = mentions(seed_check.get("other_diagnostics"), planted) or mentions(
            seed_check.get("findings"), planted
        )
        if not seen:
            problems.append(
                f"{seed_name}: its own planted branch ({planted}) appears in neither "
                "its findings nor its diagnostics. The seed-level half of the boundary "
                "pair is passing on the library's unrelated sampling diagnostics alone, "
                "which it must not"
            )

    # The upstream rejection-sampling frame that explains the seed-level outcome.
    for name in settings["artifact_contracts"]:
        check = (generated(contracts.get(name) or {}) or {}).get("check") or {}
        if not mentions(check.get(settings["artifact_in"]), settings["artifact_frame"]):
            problems.append(
                f"{name}: nothing in {settings['artifact_frame']} among its "
                f"{settings['artifact_in']}. The recorded explanation for this "
                "contract's outcome no longer applies"
            )

    # Named explicitly so CI output shows them rather than implying them.
    for name in settings["load_bearing"]:
        if generated(contracts.get(name) or {}).get("outcome") != DETECTED:
            problems.append(
                f"{name}: not detected. This is a load-bearing control; the audit's "
                "clean results mean nothing without it"
            )

    return problems, target, len(expected)


def strip_frames(report: dict, contract_id: str, needle: str) -> dict:
    """A copy of `report` with every finding and diagnostic naming `needle`
    removed from one contract. Used only by `--self-test`."""
    copy = json.loads(json.dumps(report))
    for entry in copy.get("contracts") or []:
        if entry["id"] != contract_id:
            continue
        check = generated(entry).get("check") or {}
        for field in ("findings", "other_diagnostics"):
            check[field] = [
                item for item in check.get(field) or [] if not mentions([item], needle)
            ]
    return copy


def self_test(report: dict) -> int:
    """Requires the checks above to fail when the evidence they rest on is removed.

    A validator that passes on a report with its load-bearing evidence deleted
    is not validating anything, and the only way to know is to delete it.
    """
    problems, target, _ = check_report(report)
    if problems:
        print("self-test needs a passing baseline report; this one fails:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    settings = SETTINGS[target]
    expected = TARGETS[target]

    mutations = []

    if settings["planted_frame"]:
        mutations.append(
            (
                "the seed-level boundary control's own planted branch removed, "
                "key generation's diagnostics kept",
                strip_frames(
                    report, settings["boundary_seed"], settings["planted_frame"]
                ),
            )
        )

    mutations.append(
        (
            "the upstream rejection-sampling evidence removed",
            strip_frames(
                report, settings["artifact_contracts"][0], settings["artifact_frame"]
            ),
        )
    )

    shrunk = json.loads(json.dumps(report))
    victim = settings["load_bearing"][0]
    for entry in shrunk.get("contracts") or []:
        if entry["id"] == victim:
            check = generated(entry).get("check") or {}
            check["cases_planned"] = (check.get("cases_planned") or 2) // 2
    mutations.append((f"{victim}'s case budget halved", shrunk))

    flipped = json.loads(json.dumps(report))
    for entry in flipped.get("contracts") or []:
        if entry["id"] == settings["load_bearing"][-1]:
            generated(entry)["outcome"] = CLEAN
    mutations.append(
        (f"{settings['load_bearing'][-1]} flipped to clean", flipped)
    )

    incomplete = json.loads(json.dumps(report))
    (incomplete.get("inventory") or {})["complete"] = False
    mutations.append(("the inventory marked incomplete", incomplete))

    undeclared = json.loads(json.dumps(report))
    (undeclared.get("summary") or {})["declared"] = len(expected) + 1
    mutations.append(("an unaccounted-for declaration", undeclared))

    survived = []
    for description, mutated in mutations:
        caught, _, _ = check_report(mutated)
        if not caught:
            survived.append(description)

    if survived:
        print("verify-m11-audit.py passed on reports it must reject:")
        for description in survived:
            print(f"  - {description}")
        return 1

    print(
        f"verify-m11-audit.py self-test: baseline passes and all "
        f"{len(mutations)} mutation(s) are caught"
    )
    return 0


def main() -> int:
    argv = sys.argv[1:]
    mode_self_test = False
    if argv and argv[0] == "--self-test":
        mode_self_test = True
        argv = argv[1:]
    if len(argv) != 1:
        print(
            "usage: ci/verify-m11-audit.py [--self-test] <report.json>",
            file=sys.stderr,
        )
        return 2

    report = json.loads(pathlib.Path(argv[0]).read_text())
    if mode_self_test:
        return self_test(report)
    problems, target, count = check_report(report)

    if problems:
        print(f"M11 {target} audit report did NOT establish what it claims:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    expected = TARGETS[target]
    clean = sum(1 for outcome, _, _ in expected.values() if outcome == CLEAN)
    detected = sum(1 for outcome, _, _ in expected.values() if outcome == DETECTED)
    inconclusive = sum(1 for outcome, _, _ in expected.values() if outcome == INCONCLUSIVE)
    cases = sum(budget for _, _, budget in expected.values())
    print(
        f"M11 {target} audit: inventory complete, {count} declaration(s) all checked, "
        f"{clean} clean, {detected} detected with the declared observation class, "
        f"{inconclusive} inconclusive, {cases} planned case(s) accounted for, "
        "boundary pair intact with its own planted branch observed, "
        "both sensitivity controls detected"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
