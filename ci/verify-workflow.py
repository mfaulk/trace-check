#!/usr/bin/env python3
"""Checks the CI workflow for one specific, repeatable mistake.

Several `examples/` crates are deliberately **their own workspace** — that is
the property they exist to demonstrate: trace-check has to work for a crate it
knows nothing about, with its own lockfile and its own dependency resolution.

A step that sets `working-directory` to one of them and then runs
`cargo … -p <workspace package>` cannot work, because the package is not in
*that* workspace:

    error: package(s) `cargo-trace-check` not found in workspace
           `/…/examples/crypto-bigint-audit`

It is an easy mistake to make by analogy, since the steps for
`examples/crypto-library` — a workspace *member* — use exactly that shape. It
is also invisible locally, where one naturally runs from the repository root
with `--manifest-path`. This check caught it after it had already reached
`main` once.

The fix is always the same: run from the root and pass `--manifest-path`.

Usage: verify-workflow.py [.github/workflows/ci.yml]
"""

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"


def own_workspace_examples():
    """Example crates that are their own workspace root."""
    roots = set()
    for manifest in sorted((REPO / "examples").glob("*/Cargo.toml")):
        text = manifest.read_text()
        # A bare `[workspace]` table with no `members` makes the crate its own
        # root and excludes it from the repository workspace.
        if re.search(r"^\[workspace\]\s*$", text, re.MULTILINE):
            roots.add(f"examples/{manifest.parent.name}")
    return roots


def steps(workflow):
    """`(working_directory, run_body)` for every step that has a `run`.

    Deliberately a small line scanner rather than a YAML parse: the check has
    to run before anything is installed, and it only needs two keys.
    """
    found = []
    current_dir = None
    body = []
    collecting = False
    for line in workflow.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("- name:") or stripped.startswith("- uses:"):
            if collecting:
                found.append((current_dir, "\n".join(body)))
            current_dir, body, collecting = None, [], False
            continue
        if stripped.startswith("working-directory:"):
            current_dir = stripped.split(":", 1)[1].strip()
            continue
        if stripped.startswith("run:"):
            collecting = True
            remainder = stripped[4:].strip()
            if remainder and remainder != "|":
                body.append(remainder)
            continue
        if collecting:
            body.append(stripped)
    if collecting:
        found.append((current_dir, "\n".join(body)))
    return found


def main():
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WORKFLOW
    if not path.is_file():
        sys.exit(f"FAIL: no such workflow: {path}")

    standalone = own_workspace_examples()
    if not standalone:
        sys.exit(
            "FAIL: no out-of-workspace example found, so this check is not "
            "looking at what it thinks it is. Did examples/ move?"
        )

    problems = []
    for directory, body in steps(path):
        if directory not in standalone:
            continue
        for line in body.splitlines():
            if re.search(r"\bcargo\b.*(^|\s)-p\s", line) or "--package" in line:
                problems.append(
                    f"step in `{directory}` runs `{line.strip()}` — that example is "
                    "its own workspace, so a workspace package cannot be selected "
                    "from inside it. Run from the repository root and pass "
                    "--manifest-path instead"
                )

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        sys.exit(1)

    print(
        f"verify-workflow: {len(standalone)} out-of-workspace example(s) "
        f"({', '.join(sorted(standalone))}); no step selects a workspace package "
        "from inside one"
    )


if __name__ == "__main__":
    main()
