#!/usr/bin/env python3
"""Runs one upstream-mutation experiment against the pinned crypto-bigint.

The point of the experiment is that the **adapter and its contract do not
change**. A leak is introduced into the dependency's own source, the same
`cargo trace-check check --contract …` runs, and the verdict has to flip. A
mutation that only changes the adapter proves nothing about whether the
analyzed artifact contains the library's code.

So this script is mostly validity checks. Each one guards against a way the
experiment could report a security outcome it did not earn:

* the pinned source is located through Cargo's own resolution, not a guessed
  registry path, so the tree being mutated is the one the audit depends on;
* the mutation runs in an isolated copy -- never in the shared registry
  checkout, which other builds are reading;
* `patch` must apply cleanly and the named file must actually differ
  afterwards, so a stale patch fails the run instead of silently producing a
  "clean" result;
* the adapter's own functional tests must still pass, so a mutation that
  changed the arithmetic is rejected rather than reported as a side channel;
* the clean and mutated analyzed artifacts must have different hashes, so a
  cached build cannot be mistaken for a mutated one;
* the finding's stack must name the upstream source file the patch touched,
  which is what makes it a statement about library code rather than about the
  adapter.

Usage:
    ci/mutate-m9.py --mutation mutation-a-carry-branch \\
        --contract cbaudit::add::wrapping_add_secret_left \\
        --expect-outcome LEAK_DETECTED \\
        --expect-frame src/uint/add.rs
    ci/mutate-m9.py --mutation … --expect-outcome NO_LEAK_OBSERVED --clean
"""

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
ADAPTER = REPO / "examples" / "crypto-bigint-audit"
MUTATIONS = REPO / "ci" / "mutations"
DEPENDENCY = "crypto-bigint"
PINNED_VERSION = "0.7.10"


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, text=True, **kwargs)


def pinned_source():
    """The dependency's source tree, as Cargo resolved it for the adapter."""
    result = run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=ADAPTER,
    )
    if result.returncode != 0:
        fail(f"cargo metadata failed:\n{result.stderr}")
    for package in json.loads(result.stdout)["packages"]:
        if package["name"] == DEPENDENCY:
            if package["version"] != PINNED_VERSION:
                fail(
                    f"{DEPENDENCY} resolved to {package['version']}, "
                    f"expected {PINNED_VERSION}: the audit's claim is about one "
                    "exact release"
                )
            return pathlib.Path(package["manifest_path"]).parent
    fail(f"{DEPENDENCY} is not in the adapter's dependency graph")


def tree_digest(root):
    """A stable digest over a source tree, for recording what was analyzed."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def stage_dependency(work, source, patch):
    """Copies the pinned source and applies the mutation to the copy."""
    staged = work / DEPENDENCY
    shutil.copytree(source, staged)
    for path in staged.rglob("*"):
        path.chmod(path.stat().st_mode | 0o200)
    before = tree_digest(staged)

    if patch is None:
        return staged, before, before

    applied = run(["patch", "-p1", "--batch", "-i", str(patch)], cwd=staged)
    if applied.returncode != 0:
        fail(
            f"{patch.name} does not apply to {DEPENDENCY} {PINNED_VERSION}:\n"
            f"{applied.stdout}{applied.stderr}"
        )
    after = tree_digest(staged)
    if after == before:
        fail(f"{patch.name} applied but changed nothing -- the mutation is a no-op")
    return staged, before, after


def stage_adapter(work, dependency):
    """Copies the adapter and repoints it at the staged dependency.

    A path dependency rather than `[patch.crates-io]`: the generated harness is
    its own workspace root and would not honor a `[patch]` table written here,
    but it does follow a path dependency transitively. The rewrite is also the
    one place the experiment deviates from the committed configuration, so
    keeping it to a single line keeps it reviewable.
    """
    staged = work / "adapter"
    staged.mkdir()
    shutil.copytree(ADAPTER / "src", staged / "src")
    shutil.copy(ADAPTER / "trace-check.toml", staged / "trace-check.toml")

    manifest = (ADAPTER / "Cargo.toml").read_text()
    pinned_line = (
        f'{DEPENDENCY} = {{ version = "={PINNED_VERSION}", default-features = false }}'
    )
    if pinned_line not in manifest:
        fail(
            "the adapter manifest no longer contains the pinned dependency line "
            "this script rewrites; update ci/mutate-m9.py together with it"
        )
    manifest = manifest.replace(
        pinned_line,
        f'{DEPENDENCY} = {{ path = "{dependency}", default-features = false }}',
    )
    manifest = manifest.replace(
        'path = "../../crates/trace-check-macros"',
        f'path = "{REPO / "crates" / "trace-check-macros"}"',
    )
    (staged / "Cargo.toml").write_text(manifest)
    return staged


def functional_tests(adapter, mutated):
    """The arithmetic must survive the mutation, or the run is invalid."""
    result = run(["cargo", "test", "--quiet"], cwd=adapter)
    if result.returncode != 0:
        subject = "mutated dependency" if mutated else "staged dependency"
        fail(
            f"the adapter's functional tests fail against the {subject}, so the "
            "mutation changed the computation rather than only its observable "
            f"behavior:\n{result.stdout}{result.stderr}"
        )


def check_contract(manifest, contract, reproducer_dir=None):
    command = [
        "cargo",
        "run",
        "--release",
        "--quiet",
        "-p",
        "cargo-trace-check",
        "--",
        "check",
        "--contract",
        contract,
        "--manifest-path",
        str(manifest),
        "--format",
        "json",
    ]
    if reproducer_dir is not None:
        command += ["--reproducer-dir", str(reproducer_dir)]
    result = run(command, cwd=REPO)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail(f"the checker produced no report:\n{result.stdout}\n{result.stderr}")
    if not report.get("contracts"):
        fail(f"the report selected no contract for {contract}")
    return report["contracts"][0]


def replay_reproducer(manifest, reproducer_dir, label):
    """A finding has to be replayable against the build it was found in.

    A reproducer that does not reproduce is worse than none: it reads as an
    actionable diagnostic and is not one. The replay also has to report the
    *same artifact* -- reproducing against a different build would say nothing
    about the one the finding came from.
    """
    saved = sorted(pathlib.Path(reproducer_dir).glob("*.json"))
    if not saved:
        fail(f"[{label}] the run wrote no reproducer to replay")
    for path in saved:
        replayed = check_replay(manifest, path)
        verdict = replayed.get("verdict")
        if verdict != "reproduced":
            fail(
                f"[{label}] replaying {path.name} gave {verdict!r}, not "
                f"'reproduced': {replayed.get('message')}"
            )
        if not replayed.get("same_artifact"):
            fail(
                f"[{label}] {path.name} reproduced against a different artifact "
                f"({replayed.get('recorded_artifact_sha256', '?')[:12]} recorded, "
                f"{replayed.get('replayed_artifact_sha256', '?')[:12]} replayed)"
            )
        print(
            f"[{label}] replayed:    {path.name} -> reproduced against "
            f"{replayed['replayed_artifact_sha256'][:12]}"
        )


def check_replay(manifest, reproducer):
    result = run(
        [
            "cargo",
            "run",
            "--release",
            "--quiet",
            "-p",
            "cargo-trace-check",
            "--",
            "check",
            "--replay",
            str(reproducer),
            "--manifest-path",
            str(manifest),
            "--format",
            "json",
        ],
        cwd=REPO,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        fail(f"replaying {reproducer} produced no report:\n{result.stdout}{result.stderr}")


def experiment(work, source, patch, contract, label, reproducers=False):
    """Stages one dependency tree, checks one contract, returns the evidence."""
    dependency, before, after = stage_dependency(work, source, patch)
    print(f"[{label}] staged:      {dependency}")
    print(f"[{label}] tree sha256: {before} -> {after}")
    if patch:
        print(f"[{label}] mutation:    {patch.name}")

    adapter = stage_adapter(work, dependency)
    functional_tests(adapter, mutated=patch is not None)
    print(f"[{label}] functional:  the staged dependency computes the same values")

    reproducer_dir = work / "reproducers" if reproducers else None
    reported = check_contract(adapter / "Cargo.toml", contract, reproducer_dir)
    evidence = reported["check"]
    print(f"[{label}] artifact:    {reported['artifact_sha256']}")
    print(f"[{label}] outcome:     {evidence['outcome']}")
    print(f"[{label}] message:     {evidence['message']}")
    return reported["artifact_sha256"], evidence, adapter / "Cargo.toml", reproducer_dir


def require_class(evidence, expected, label):
    """A branch mutation must produce a branch finding, not merely a finding.

    The distinction is the whole reason the address half of the observation
    model exists: a tool that only saw branches would report a secret-indexed
    load as clean.
    """
    # `secret_dependent_value` is what the backend calls a secret-derived value
    # reaching an address or a syscall -- the address half of the model.
    wanted = {
        "branch": "secret_dependent_branch",
        "address": "secret_dependent_value",
    }[expected]
    classes = sorted({f["classification"] for f in evidence.get("findings") or []})
    if wanted not in classes:
        fail(
            f"[{label}] expected a {expected} finding ({wanted}); the run "
            f"produced {classes or 'none'}"
        )
    print(f"[{label}] class:       {wanted}")


def require_outcome(evidence, expected, label):
    outcome = evidence["outcome"]
    if outcome == expected:
        return
    unattributed = evidence.get("unattributed") or []
    extra = (
        f" ({len(unattributed)} unattributed finding(s); first at "
        f"{unattributed[0]['stack'][0]})"
        if unattributed
        else ""
    )
    fail(f"[{label}] expected {expected}, got {outcome}{extra}")


def require_frame(evidence, frame, label):
    """The finding must name the upstream file the patch touched.

    Without this the experiment cannot distinguish "the library leaks" from
    "the adapter leaks": a contract covers the whole invocation, and only the
    stack says which part of it the finding came from.
    """
    findings = evidence.get("findings") or []
    if not findings:
        fail(f"[{label}] no finding to attribute, so {frame} cannot be confirmed")
    for finding in findings:
        stack = "\n".join(finding["stack"])
        if frame in stack:
            print(f"[{label}] attributed:  {finding['stack'][0]}")
            print(f"[{label}]              via {finding['stack'][1]}")
            return
    joined = "\n---\n".join("\n".join(f["stack"]) for f in findings)
    fail(
        f"[{label}] no finding names {frame}, so this is not evidence about "
        f"upstream code:\n{joined}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutation", required=True, help="patch name under ci/mutations")
    parser.add_argument("--contract", required=True)
    parser.add_argument("--expect-outcome", required=True)
    parser.add_argument(
        "--expect-frame",
        help="source path that must appear in the finding's stack, e.g. src/uint/add.rs",
    )
    parser.add_argument(
        "--expect-class",
        choices=["branch", "address"],
        help="which half of the observation model the finding must come from",
    )
    parser.add_argument(
        "--verify-reproducer",
        action="store_true",
        help="save the finding's reproducer and replay it against the same build",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="stage the pinned source without applying the patch, for the baseline alone",
    )
    parser.add_argument(
        "--compare-clean",
        action="store_true",
        help="also run the unpatched baseline, requiring it clean and a different artifact",
    )
    parser.add_argument(
        "--baseline-outcome",
        default="NO_LEAK_OBSERVED",
        help="what the unpatched baseline must report under --compare-clean",
    )
    parser.add_argument("--keep", help="write the staged trees here instead of a temp dir")
    arguments = parser.parse_args()

    patch = MUTATIONS / f"{arguments.mutation}.patch"
    if not patch.is_file():
        fail(f"no such mutation: {patch}")

    source = pinned_source()
    print(f"dependency:   {DEPENDENCY} {PINNED_VERSION}")
    print(f"source:       {source}")

    root = pathlib.Path(arguments.keep) if arguments.keep else None
    if root:
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        context = None
    else:
        context = tempfile.TemporaryDirectory(prefix="m9-mutation-")
        root = pathlib.Path(context.name)

    try:
        if arguments.clean:
            _, evidence, _, _ = experiment(
                root / "clean", source, None, arguments.contract, "clean"
            )
            require_outcome(evidence, arguments.expect_outcome, "clean")
            print("PASS")
            return

        baseline_artifact = None
        if arguments.compare_clean:
            # A separate staging directory per run: never a shared tree that
            # another build could be reading, and never a target directory the
            # two runs could trade cache entries through.
            baseline_artifact, baseline, _, _ = experiment(
                root / "clean", source, None, arguments.contract, "clean"
            )
            require_outcome(baseline, arguments.baseline_outcome, "clean")

        mutated_artifact, mutated, manifest, reproducer_dir = experiment(
            root / "mutated",
            source,
            patch,
            arguments.contract,
            "mutated",
            reproducers=arguments.verify_reproducer,
        )
        require_outcome(mutated, arguments.expect_outcome, "mutated")
        if arguments.expect_class:
            require_class(mutated, arguments.expect_class, "mutated")
        if arguments.expect_frame:
            require_frame(mutated, arguments.expect_frame, "mutated")
        if arguments.verify_reproducer:
            replay_reproducer(manifest, reproducer_dir, "mutated")

        if baseline_artifact is not None:
            if baseline_artifact == mutated_artifact:
                fail(
                    "the clean and mutated runs analyzed the same artifact hash, so "
                    "the mutated build was not actually analyzed"
                )
            print(f"artifacts:    {baseline_artifact[:12]} != {mutated_artifact[:12]}")

        print("PASS")
    finally:
        if context:
            context.cleanup()


if __name__ == "__main__":
    main()
