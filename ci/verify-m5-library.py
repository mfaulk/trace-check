#!/usr/bin/env python3
"""Verify the M5 contract-verification report establishes what it claims.

Used by CI. Exit code 0 only says every contract met its declared expectation.
It does not say the analyzed function was the library's own, that the symbolic
inputs carried the declared widths, that the analyzer reached the resolved
symbol, or that a VERIFIED_BOUNDED verdict discharged any obligation at all.
Those are exactly the ways a verification job passes while verifying nothing,
so they are checked here against the report rather than inferred from the exit
status.

Each check below was confirmed by tampering with a passing report before being
relied on: narrowing an input's width, marking a verified contract unreached,
emptying its discharged-check counts, and claiming the production binary was
analyzed all make this script fail.
"""

import json
import os
import sys

EXPECTED = {
    "crypto::tag::verify_tag": "VERIFIED_BOUNDED",
    "crypto::tag::verify_tag_early_exit": "VERIFIED_BOUNDED",
    "crypto::tag::verify_tag_volatile_early_exit": "LEAK_DETECTED",
    "crypto::lookup::substitute": "VERIFIED_BOUNDED",
    "crypto::lookup::substitute_indexed": "LEAK_DETECTED",
    "crypto::lookup::substitute_mode": "LEAK_DETECTED",
    "crypto::controls::tail_byte_probe": "LEAK_DETECTED",
    "crypto::controls::public_branch": "VERIFIED_BOUNDED",
    "crypto::reduce::reduce_once": "VERIFIED_BOUNDED",
    "crypto::reduce::reduce_once_masked": "VERIFIED_BOUNDED",
}

# The secret parameter and its full width, in bits, as declared by the
# annotation. A harness that marked only a pointer or only a leading byte would
# still produce a clean-looking report, so the widths are asserted rather than
# trusted.
SECRET_WIDTHS = {
    "crypto::tag::verify_tag": ("expected", 128),
    "crypto::tag::verify_tag_early_exit": ("expected", 128),
    "crypto::tag::verify_tag_volatile_early_exit": ("expected", 128),
    "crypto::controls::tail_byte_probe": ("expected", 128),
    "crypto::lookup::substitute": ("index", 8),
    "crypto::lookup::substitute_indexed": ("index", 8),
    "crypto::lookup::substitute_mode": ("index", 8),
    "crypto::controls::public_branch": ("secret", 8),
    "crypto::reduce::reduce_once": ("value", 32),
    "crypto::reduce::reduce_once_masked": ("value", 32),
}

# Source file each finding must be attributed to: the developer's own library,
# never a generated harness.
LEAK_SOURCES = {
    "crypto::tag::verify_tag_volatile_early_exit": "tag.rs",
    "crypto::lookup::substitute_indexed": "lookup.rs",
    "crypto::lookup::substitute_mode": "lookup.rs",
    "crypto::controls::tail_byte_probe": "controls.rs",
}


def main(path: str) -> int:
    report = json.load(open(path))
    failures = []

    if report.get("backend") != "binsec-relational-symbolic":
        failures.append(f"unexpected backend {report.get('backend')!r}")
    if report.get("executed", 0) == 0:
        failures.append("no contracts were analyzed")
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
    expected_runtime = os.environ.get("EXPECTED_CONTAINER_RUNTIME")
    if expected_runtime and provenance.get("container_tool") != expected_runtime:
        failures.append(
            f"analyzer ran under {provenance.get('container_tool')!r}, expected "
            f"{expected_runtime!r}"
        )

    seen = {}
    artifacts = {}
    for entry in report.get("contracts", []):
        contract = entry.get("contract")
        analysis = entry.get("analysis", {})
        outcome = analysis.get("outcome")
        seen[contract] = outcome
        name = f"{contract} ({outcome})"

        # The implementation came from a real package, and the report names
        # where the developer declared the contract.
        library = entry.get("library", {})
        if library.get("package") != "crypto-library":
            failures.append(f"{name}: unexpected package {library.get('package')!r}")
        if not library.get("lib_name"):
            failures.append(f"{name}: no library crate recorded")
        if ".rs:" not in entry.get("declared_at", ""):
            failures.append(f"{name}: no declaration site recorded")

        # Contract-to-instruction binding, with the analyzer's own evidence.
        symbol = entry.get("symbol", {})
        if not symbol.get("mangled"):
            failures.append(f"{name}: no resolved symbol")
        if entry.get("function", "") not in symbol.get("mangled", ""):
            failures.append(
                f"{name}: resolved symbol {symbol.get('mangled')!r} does not name the "
                f"contract's function"
            )
        if not symbol.get("reached"):
            failures.append(f"{name}: the analyzer never reached the resolved symbol")
        if not symbol.get("address", "").startswith("0x"):
            failures.append(f"{name}: no symbol address recorded")

        # Provenance that ties the result to one build and disclaims others.
        compilation = entry.get("compilation", {})
        if compilation.get("lto") is not False:
            failures.append(f"{name}: LTO must be off for the verification build")
        if compilation.get("panic") != "abort":
            failures.append(f"{name}: unexpected panic strategy")
        if not compilation.get("rustc"):
            failures.append(f"{name}: no compiler recorded")
        artifact = entry.get("artifact", {})
        for field in ("sha256", "lockfile_sha256"):
            if len(artifact.get(field, "")) != 64:
                failures.append(f"{name}: no {field} recorded")
        if "not analyzed" not in artifact.get("production_artifact", ""):
            failures.append(
                f"{name}: the report must state that no production binary was analyzed"
            )
        artifacts.setdefault(artifact.get("sha256"), []).append(contract)
        harness = entry.get("harness", {})
        if len(harness.get("sha256", "")) != 64:
            failures.append(f"{name}: no harness hash recorded")
        if "fn tc_verify_entry" not in harness.get("source", ""):
            failures.append(f"{name}: the generated harness is not recorded verbatim")

        # Roles and widths, as transferred from the annotation.
        inputs = {item["parameter"]: item for item in entry.get("inputs", [])}
        if contract in SECRET_WIDTHS:
            parameter, bits = SECRET_WIDTHS[contract]
            declared = inputs.get(parameter)
            if declared is None:
                failures.append(f"{name}: no symbolic input for secret `{parameter}`")
            else:
                if declared.get("role") != "secret":
                    failures.append(
                        f"{name}: `{parameter}` is {declared.get('role')!r}, expected secret"
                    )
                if declared.get("bits") != bits:
                    failures.append(
                        f"{name}: `{parameter}` is {declared.get('bits')} bits, expected {bits}"
                    )
        if not any(item.get("role") == "secret" for item in entry.get("inputs", [])):
            failures.append(f"{name}: no secret input, so there is no relational property")

        if outcome == "VERIFIED_BOUNDED":
            exploration = analysis.get("exploration", {})
            total = exploration.get("total_paths")
            completed = exploration.get("completed_paths")
            if total is None or completed is None or total != completed:
                failures.append(
                    f"{name}: exploration incomplete ({completed} of {total} paths)"
                )
            if exploration.get("pending_paths") != 0:
                failures.append(f"{name}: pending paths remain")
            if exploration.get("unknown_queries") != 0:
                failures.append(f"{name}: solver queries returned unknown")
            if exploration.get("max_path_depth") is None:
                failures.append(f"{name}: no maximum path depth, so the bound is unproven")
            elif exploration["max_path_depth"] >= entry.get("max_depth", 0):
                failures.append(f"{name}: exploration reached its depth bound")
            discharged = 0
            for key in ("control_flow", "memory"):
                passed = exploration.get(f"{key}_checks_passed")
                asked = exploration.get(f"{key}_checks_total")
                if passed is None or asked is None:
                    continue
                if passed != asked:
                    failures.append(f"{name}: only {passed} of {asked} {key} checks passed")
                discharged += asked
            if discharged == 0:
                failures.append(f"{name}: no relational obligation was discharged")
            if analysis.get("divergences"):
                failures.append(f"{name}: a verified contract reports divergences")
            if analysis.get("unchecked_properties"):
                failures.append(
                    f"{name}: left {analysis['unchecked_properties']} unchecked, so the "
                    f"bundled run does not cover the full model"
                )

        if outcome == "LEAK_DETECTED":
            divergences = analysis.get("divergences", [])
            if not divergences:
                failures.append(f"{name}: a leak with no divergence site")
            for divergence in divergences:
                if not divergence.get("instruction", "").startswith("0x"):
                    failures.append(f"{name}: a divergence with no instruction address")
            wanted = LEAK_SOURCES.get(contract)
            if wanted and not any(
                wanted in (divergence.get("source") or "") for divergence in divergences
            ):
                failures.append(
                    f"{name}: no finding attributed to the library's own {wanted}; "
                    f"got {[d.get('source') for d in divergences]}"
                )
            # Where the analyzer issued a relational query, the pair must be a
            # genuine pair. Where it did not, the report must say so rather
            # than invent one.
            if analysis.get("witness") == "solver_counterexample":
                for counterexample in analysis.get("counterexamples", []):
                    if counterexample["left"] == counterexample["right"]:
                        failures.append(f"{name}: identical counterexample values")
            elif analysis.get("counterexamples"):
                failures.append(f"{name}: counterexamples without a solver witness")

    for contract, expected in EXPECTED.items():
        if contract not in seen:
            failures.append(f"{contract} is missing from the report")
        elif seen[contract] != expected:
            failures.append(f"{contract}: expected {expected}, observed {seen[contract]}")

    # One executable per contract. A shared artifact would mean a result named
    # an executable that also contains other contracts' entry points.
    for digest, sharing in artifacts.items():
        if len(sharing) > 1:
            failures.append(f"artifact {digest} is shared by {sharing}")

    summary = report.get("summary", {})
    if not summary.get("expectations_reproduced"):
        failures.append(f"unmet expectations: {summary.get('unmet_expectations')}")

    if len(report.get("limitations", [])) < 10:
        failures.append("the report does not carry its limitations")

    if failures:
        print("M5 contract verification report did NOT establish what it claims:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"M5 report checked: {len(seen)} contract(s), "
        f"{summary.get('verified_bounded')} verified bounded, "
        f"{summary.get('leaks_detected')} leak detected, "
        f"{summary.get('inconclusive')} inconclusive"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <report.json>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
