#!/usr/bin/env python3
"""Checks the M10.0 unified report, not the exit code.

The feasibility gate asks one question: can a single invocation run two
different backends over one contract and keep their evidence from being
confused? A report that merely *passes* does not answer it -- a unified run
that quietly used one backend's result for both obligations would pass too.

So this script checks the things that would make the unified result
*misleading*:

* the compiler-derived inventory is complete and covers every declaration,
  because the set of obligations is only trustworthy if the set of contracts is;
* the spike contract owes both `generated` and `symbolic`, and both are CHECKED;
* each obligation is discharged by its own backend's outcome -- NO_LEAK_OBSERVED
  for the generated one, VERIFIED_BOUNDED for the symbolic one -- and never by
  the other's;
* the two results carry **different** artifact hashes, because they are
  different executables and a shared hash would mean one result is describing a
  binary it never analyzed;
* the symbolic evidence retains the conditions it was established under: the
  symbol it was attributed to, the evidence the analyzer reached it, the
  observation classes checked, the input domain and the depth bound;
* the generated evidence retains its own case counts and positive controls, so
  a clean dynamic result is not a truncated or uncalibrated run;
* no contract requiring symbolic verification was reported satisfied without
  symbolic evidence;
* the report still carries its own limitations.

Usage: verify-m10-feasibility.py <report.json> [contract]
"""

import json
import pathlib
import sys

SPIKE_CONTRACT = "cbaudit::monty::mul_both_secret"

# What discharges what. The one mapping this script trusts; everything else is
# read out of the report.
DISCHARGED_BY = {
    "generated": "NO_LEAK_OBSERVED",
    "explore": "NO_LEAK_OBSERVED",
    "dynamic": "NO_LEAK_OBSERVED",
    "symbolic": "VERIFIED_BOUNDED",
}


def main(argv):
    if not 2 <= len(argv) <= 3:
        print(__doc__, file=sys.stderr)
        return 2
    report = json.loads(pathlib.Path(argv[1]).read_text())
    contract_id = argv[2] if len(argv) == 3 else SPIKE_CONTRACT

    problems = []

    def require(condition, message):
        if not condition:
            problems.append(message)

    # ---- inventory ----------------------------------------------------
    inventory = report.get("inventory", {})
    require(
        inventory.get("complete") is True,
        f"the contract inventory is not complete: {inventory!r}. The set of obligations "
        "cannot be trusted when the set of declarations is unknown",
    )
    declared = inventory.get("contracts_declared", inventory.get("declared"))
    require(
        isinstance(declared, int) and declared > 0,
        f"the inventory declares no contracts: {inventory!r}",
    )
    require(
        len(report.get("contracts", [])) == declared,
        f"{declared} declarations inventoried but {len(report.get('contracts', []))} "
        "reported; every declaration must get a row",
    )

    # ---- the spike contract -------------------------------------------
    rows = {entry["id"]: entry for entry in report.get("contracts", [])}
    contract = rows.get(contract_id)
    if contract is None:
        problems.append(
            f"`{contract_id}` is absent from the report; present: {sorted(rows)}"
        )
        return finish(problems)

    required = contract.get("required", [])
    require(
        set(required) >= {"generated", "symbolic"},
        f"`{contract_id}` must owe both generated and symbolic analysis, owes {required}",
    )

    status = contract.get("status", {})
    for analysis in ("generated", "symbolic"):
        state = status.get(analysis, {}).get("state")
        require(
            state == "checked",
            f"`{contract_id}`'s {analysis} requirement is {state!r}, not checked",
        )

    evidence = {item["analysis"]: item for item in contract.get("evidence", [])}
    for analysis in ("generated", "symbolic"):
        require(
            analysis in evidence,
            f"`{contract_id}` reports {analysis} as checked with no {analysis} evidence; "
            "a status without evidence is the failure this milestone exists to prevent",
        )
    if {"generated", "symbolic"} - set(evidence):
        return finish(problems)

    # Each obligation discharged by its own backend's vocabulary.
    for analysis, item in evidence.items():
        expected = DISCHARGED_BY.get(analysis)
        require(
            item["outcome"] == expected,
            f"{analysis} evidence reports {item['outcome']}, which does not discharge a "
            f"{analysis} requirement (needs {expected})",
        )

    # ---- every result names what it analyzed --------------------------
    #
    # A status is only as trustworthy as the identity it rests on. These are
    # the fields that decide *which* executable a result describes; a result
    # missing any of them cannot be compared to an obligation or to another
    # result.
    REQUIRED_IDENTITY = (
        "contract",
        "descriptor_sha256",
        "library_package",
        "library_version",
        "target",
        "toolchain",
        "profile",
        "artifact_sha256",
        "lockfile_sha256",
        "harness_sha256",
        "backend",
        "backend_version",
    )
    for analysis, item in evidence.items():
        identity = item.get("artifact")
        if identity is None:
            problems.append(
                f"{analysis} evidence carries no artifact identity, so nothing says which "
                "executable it describes beyond a bare hash"
            )
            continue
        for field in REQUIRED_IDENTITY:
            require(
                identity.get(field) not in (None, "", []),
                f"{analysis} identity is missing {field!r}",
            )
        require(
            identity.get("contract") == contract_id,
            f"{analysis} identity is about {identity.get('contract')!r}, not {contract_id!r}",
        )
        require(
            identity.get("artifact_sha256") == item.get("artifact_sha256"),
            f"{analysis} evidence and its identity name different artifacts: "
            f"{item.get('artifact_sha256')!r} vs {identity.get('artifact_sha256')!r}",
        )
        # The compiler must be a measured version, not a placeholder. A
        # recorded compiler that is not the one that compiled the code makes
        # the whole identity untrustworthy.
        rustc = (identity.get("toolchain") or {}).get("rustc_version", "")
        require(
            rustc.startswith("rustc ") and "unavailable" not in rustc,
            f"{analysis} identity records {rustc!r} as its compiler",
        )

    # Only the symbolic backend depends on a container image, and it must name
    # it by digest: the image is the analyzer and its bundled solver, so a
    # result is reproducible only against that exact one.
    symbolic_image = (evidence["symbolic"].get("artifact") or {}).get("analyzer_image")
    require(
        symbolic_image and "@sha256:" in symbolic_image,
        f"the symbolic identity must pin its analyzer image by digest: {symbolic_image!r}",
    )
    require(
        (evidence["generated"].get("artifact") or {}).get("analyzer_image") is None,
        "the generated backend uses no analyzer image and must not claim one",
    )

    # ---- two backends, two executables --------------------------------
    generated_artifact = evidence["generated"].get("artifact_sha256", "")
    symbolic_artifact = evidence["symbolic"].get("artifact_sha256", "")
    require(
        generated_artifact and symbolic_artifact,
        "both results must name the executable they describe: "
        f"generated={generated_artifact!r} symbolic={symbolic_artifact!r}",
    )
    require(
        generated_artifact != symbolic_artifact,
        "the generated and symbolic results carry the same artifact hash "
        f"({generated_artifact}). They analyze different executables built from "
        "different harnesses with different flags; one hash means one of them is "
        "describing a binary it did not analyze",
    )

    # ---- symbolic evidence keeps its conditions ------------------------
    symbolic = evidence["symbolic"].get("symbolic")
    if symbolic is None:
        problems.append(
            "the symbolic evidence is an outcome with no record. VERIFIED_BOUNDED without "
            "its input domain, observation model and depth bound is not an actionable or "
            "checkable claim"
        )
    else:
        require(
            symbolic.get("contract") == contract_id,
            f"the symbolic record is about {symbolic.get('contract')!r}, not {contract_id!r}",
        )
        symbol = symbolic.get("symbol", {})
        require(
            symbol.get("contract") == contract_id,
            f"the symbolic record's symbol binding resolved {symbol.get('contract')!r}",
        )
        require(
            symbol.get("reached") is True,
            "the analyzer did not report reaching the contract's symbol, so the result is "
            "attributed to a function it never analyzed",
        )
        require(
            symbolic.get("artifact", {}).get("sha256") == symbolic_artifact,
            "the symbolic record and its evidence name different artifacts",
        )
        checked = symbolic.get("analysis", {}).get("checked_features", [])
        require(
            set(checked) == {"control-flow", "memory-access"},
            f"the symbolic result covers {checked}; a contract configured for both "
            "observation classes is not discharged by one of them",
        )
        exploration = symbolic.get("analysis", {}).get("exploration", {})
        require(
            exploration.get("total_paths") == exploration.get("completed_paths"),
            f"exploration did not complete: {exploration!r}",
        )
        require(
            exploration.get("unknown_queries") == 0,
            f"unresolved solver queries remain: {exploration!r}",
        )
        require(
            isinstance(symbolic.get("max_depth"), int) and symbolic["max_depth"] > 0,
            "the symbolic record carries no depth bound, so the result's scope is unstated",
        )
        require(
            symbolic.get("inputs"),
            "the symbolic record carries no input roles, so what was held secret is unstated",
        )
        require(
            symbolic.get("artifact", {}).get("production_artifact"),
            "the symbolic record must keep its production-binary caveat",
        )

    # ---- generated evidence keeps its controls -------------------------
    check = evidence["generated"].get("check")
    if check is None:
        problems.append(
            "the generated evidence carries no check record, so its case counts and "
            "positive controls cannot be read"
        )
    else:
        controls = json.dumps(check)
        require(
            "calibration" in controls or "calibrated" in controls,
            "the generated record does not report calibration; a clean result from a "
            "harness that marked nothing is not a clean result",
        )

    # ---- nothing passed a required analysis without matching evidence
    #
    # A security contract is discharged by what its backend establishes. An
    # analyzer-regression fixture is discharged by reproducing what it declared
    # -- per analysis, so a fixture may be NO_LEAK_OBSERVED to generated
    # testing and LEAK_DETECTED to symbolic execution. Either way the status
    # must rest on evidence that actually says so.
    for row in report.get("contracts", []):
        declared = row.get("regression_expectations") or {}
        for analysis in row.get("required", []):
            if row.get("status", {}).get(analysis, {}).get("state") != "checked":
                continue
            outcomes = [
                item["outcome"]
                for item in row.get("evidence", [])
                if item["analysis"] == analysis
            ]
            wanted = declared.get(analysis) or DISCHARGED_BY.get(analysis)
            require(
                outcomes == [wanted],
                f"`{row['id']}` reports {analysis} as checked on evidence {outcomes!r}, "
                f"which is not the {wanted} it is discharged by",
            )

    # ---- at least one fixture must prove the backends are judged separately
    disagreeing = [
        row["id"]
        for row in report.get("contracts", [])
        if len(set((row.get("regression_expectations") or {}).values())) > 1
    ]
    require(
        disagreeing,
        "no contract in this report declares different outcomes for different backends, so "
        "nothing here would notice if one backend's result were judged against another's "
        "declaration -- the failure per-analysis expectations exist to prevent",
    )
    for name in disagreeing:
        row = next(r for r in report["contracts"] if r["id"] == name)
        declared = row["regression_expectations"]
        for analysis, expected in declared.items():
            if analysis not in row.get("required", []):
                continue
            state = row.get("status", {}).get(analysis, {}).get("state")
            require(
                state == "checked",
                f"`{name}` declares {expected} for {analysis} and reports {state!r}; a "
                f"fixture that reproduces its declaration must pass",
            )
        # A violation surfaces as LEAK_DETECTED in the enforcement dimension,
        # so that is what is asserted -- there is no `violated` field to read,
        # and a check against a missing key would quietly pass.
        violated = [
            analysis
            for analysis, state in (row.get("status") or {}).items()
            if state.get("state") == "leak-detected"
        ]
        require(
            not violated,
            f"`{name}` is a declared fixture reproducing its declarations, and {violated} "
            "is reported as a violation",
        )

    # ---- the execution plan, and the deduplication claim ---------------
    #
    # `explore` is not a separate proof level: coverage feedback chooses which
    # inputs to analyze and the security conclusion still comes from the same
    # uninstrumented artifact. Requiring both must therefore plan *one*
    # Memcheck workflow per contract, and the two requirements must be marked
    # as sharing it so nothing reads them as two independent observations.
    execution = report.get("execution")
    require(
        execution is not None,
        "an executing run must report what it executed, or the deduplication claim is "
        "unverifiable",
    )
    if execution:
        per_contract = {}
        for job in execution.get("jobs", []):
            require(
                job.get("discharges"),
                f"a planned job for `{job.get('contract')}` discharges nothing, so it spent a "
                "backend to produce a result nothing uses",
            )
            if job.get("backend") == "generated":
                per_contract.setdefault(job["contract"], []).append(job)
        for name, jobs in per_contract.items():
            require(
                len(jobs) == 1,
                f"`{name}` planned {len(jobs)} Memcheck workflows; requiring `generated` and "
                "`explore` must share one",
            )

        # A requirement sharing an execution says so, in both directions.
        for row in report.get("contracts", []):
            shared = {
                item["analysis"]: set(item.get("shared_with") or [])
                for item in row.get("evidence", [])
            }
            for analysis, partners in shared.items():
                for partner in partners:
                    require(
                        analysis in shared.get(partner, set()),
                        f"`{row['id']}`: {analysis} claims to share an execution with "
                        f"{partner}, which does not say the same",
                    )

    # The unified report is meant to become the standard CI interface, so the
    # caveats that keep two results from reading as one must survive in it.
    limitations = " ".join(report.get("limitations") or [])
    require(limitations, "the report must carry its own limitations")
    for text in (
        "artifact_sha256",
        "Neither is the production binary",
        "declared input domain",
    ):
        require(
            text in limitations,
            f"the report drops a caveat the unified result needs: {text!r} is missing",
        )

    return finish(problems)


def finish(problems):
    if problems:
        print("M10.0 feasibility check FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("M10.0 feasibility check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
