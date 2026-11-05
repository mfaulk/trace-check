#!/usr/bin/env python3
"""Requires two unified reports to agree on every security-relevant field.

Used to check that `--jobs 2` reaches the same answer as `--jobs 1`. That claim
is what makes the flag offerable: scheduling must trade machine time and
nothing else.

Compared field by field rather than as whole documents, because a report
legitimately carries things that differ between two runs of the same work --
artifact *paths* under a fresh temporary directory, wall-clock figures, the
retained-path flag. What must not differ is anything a decision rests on:

* the execution plan, which is a function of the policy and not of the
  scheduler;
* the contract order, so the report is deterministic;
* each contract's per-analysis statuses;
* each piece of evidence: its analysis, its outcome, the artifact *hash* it
  describes, and which other requirements shared its execution;
* the blocking reasons and the summary verdict.

Usage: compare-m10-runs.py <a.json> <b.json>
"""

import json
import pathlib
import sys


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    left = json.loads(pathlib.Path(argv[1]).read_text())
    right = json.loads(pathlib.Path(argv[2]).read_text())

    problems = []

    def require(condition, message):
        if not condition:
            problems.append(message)

    # --- the plan is a function of the policy ---------------------------
    require(
        left.get("execution") == right.get("execution"),
        "the execution plan differs between the two runs, so the scheduler is deciding what "
        "runs rather than only when it runs",
    )

    # --- deterministic ordering -----------------------------------------
    order = [row["id"] for row in left.get("contracts", [])]
    require(
        order == [row["id"] for row in right.get("contracts", [])],
        "the contracts are reported in a different order, so the report depends on completion "
        "order",
    )
    if order != [row["id"] for row in right.get("contracts", [])]:
        return finish(problems)

    # --- statuses and evidence ------------------------------------------
    for a, b in zip(left.get("contracts", []), right.get("contracts", [])):
        name = a["id"]
        require(
            a.get("status") == b.get("status"),
            f"`{name}` was judged differently: {a.get('status')} vs {b.get('status')}",
        )
        require(
            a.get("required") == b.get("required"),
            f"`{name}` owes different requirements in the two runs",
        )
        require(
            a.get("regression_expectations") == b.get("regression_expectations"),
            f"`{name}` carries different declared expectations in the two runs",
        )

        def summarize(row):
            return [
                (
                    item.get("analysis"),
                    item.get("outcome"),
                    item.get("artifact_sha256"),
                    tuple(item.get("shared_with") or []),
                )
                for item in row.get("evidence", [])
            ]

        require(
            summarize(a) == summarize(b),
            f"`{name}` produced different evidence: {summarize(a)} vs {summarize(b)}",
        )

    # --- the verdict -----------------------------------------------------
    for field in ("ok", "blocking_reasons"):
        require(
            left.get("summary", {}).get(field) == right.get("summary", {}).get(field),
            f"the runs disagree on summary.{field}",
        )
    require(
        left.get("stale") == right.get("stale"),
        "the runs report different stale configuration",
    )

    return finish(problems)


def finish(problems):
    if problems:
        print("the two runs do not agree:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("compare-m10-runs: both runs reached the same security outcomes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
