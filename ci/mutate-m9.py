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
* the adapter's own tests must still pass -- including the 1012
  independent-oracle vectors, which compare the operation's *complete* 32-byte
  result, so a mutation that changed the arithmetic is rejected rather than
  reported as a side channel. The oracle tests are checked by name, because a
  suite that silently stopped running them would otherwise report a weak check
  as a strong one;
* the staged crate carries the committed lockfile and builds `--locked`, so the
  transitive graph is the audited one, and the clean and mutated runs must
  resolve *identical* dependency graphs -- the patch is meant to be the only
  variable;
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

`--unified` runs the mutation through `check --all-contracts --ci` instead,
with a policy requiring both generated and symbolic analysis of the affected
contract. The exit code and the survival of *both* analyses are what it checks:
a run that stopped at the first failure would report one backend and leave the
other un-analyzed.

    ci/mutate-m9.py --mutation mutation-a-carry-branch \
        --contract cbaudit::add::wrapping_add_secret_left \
        --expect-outcome LEAK_DETECTED --unified --expect-exit 1
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


def staged_lockfile():
    """The committed lockfile, with `crypto-bigint` turned into a path entry.

    Without this the staged crate resolves its *transitive* graph afresh —
    `ctutils`, `cmov`, `cpubits`, `num-traits` — so the clean and mutated runs
    would not be guaranteed to compile the same supporting code, and the
    experiment's whole claim is a difference between two compiled
    implementations. Cargo rejects a `source`/`checksum` on a path dependency,
    so those two lines are dropped from that one package entry and every other
    pin is preserved verbatim.
    """
    lines = (ADAPTER / "Cargo.lock").read_text().splitlines()
    out = []
    inside = False
    dropped = 0
    for line in lines:
        if line.strip() == "[[package]]":
            inside = False
        if line.strip() == f'name = "{DEPENDENCY}"':
            inside = True
        if inside and line.startswith(("source = ", "checksum = ")):
            dropped += 1
            continue
        out.append(line)
    if dropped != 2:
        fail(
            f"expected to drop a source and a checksum line for {DEPENDENCY} in "
            f"the committed lockfile, dropped {dropped}. The lockfile layout "
            "changed; update ci/mutate-m9.py with it"
        )
    return "\n".join(out) + "\n"


def dependency_graph(adapter):
    """`(name, version)` for every package in the staged lockfile.

    Compared between the clean and mutated runs. If they differ, the two
    artifacts differ by more than the patch and nothing downstream is a
    controlled comparison.
    """
    graph = []
    name = None
    for line in (adapter / "Cargo.lock").read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith('name = "'):
            name = stripped.split('"')[1]
        elif stripped.startswith('version = "') and name:
            graph.append((name, stripped.split('"')[1]))
            name = None
    graph.sort()
    digest = hashlib.sha256(repr(graph).encode()).hexdigest()
    return graph, digest


def stage_adapter(work, dependency):
    """Copies the adapter and repoints it at the staged dependency.

    A path dependency rather than `[patch.crates-io]`: the generated harness is
    its own workspace root and would not honor a `[patch]` table written here,
    but it does follow a path dependency transitively. The rewrite is also the
    one place the experiment deviates from the committed configuration, so
    keeping it to a single line keeps it reviewable.

    `tests/` comes too. Without it `cargo test` runs only the adapters' inline
    unit tests and the 1012 independent-oracle vectors never execute, which
    would make "the arithmetic survived the mutation" a much weaker claim than
    the one this script prints.
    """
    staged = work / "adapter"
    staged.mkdir()
    shutil.copytree(ADAPTER / "src", staged / "src")
    shutil.copytree(ADAPTER / "tests", staged / "tests")
    shutil.copy(ADAPTER / "trace-check.toml", staged / "trace-check.toml")
    (staged / "Cargo.lock").write_text(staged_lockfile())

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


# The oracle tests, by name. Named rather than counted so a suite that silently
# stops running them fails here instead of reporting a weaker check as a
# stronger one.
ORACLE_TESTS = (
    "wrapping_add_matches_the_oracle",
    "ct_select_matches_the_oracle",
    "montgomery_multiplication_matches_the_oracle",
    "the_adapter_and_the_oracle_share_a_modulus",
)


def functional_tests(adapter, mutated):
    """The arithmetic must survive the mutation, or the run is invalid.

    `--locked` so the transitive graph is the committed one; `--all-targets`
    and an explicit check that the oracle tests ran, because the claim being
    made is about the 1012 independently computed vectors and not about the
    inline unit tests alone.
    """
    # `--no-fail-fast` so a failing lib target does not hide whether the
    # oracle caught the same mutation; the report names every failure.
    result = run(
        ["cargo", "test", "--locked", "--all-targets", "--no-fail-fast"], cwd=adapter
    )
    subject = "mutated dependency" if mutated else "staged dependency"
    if result.returncode != 0:
        fail(
            f"the adapter's functional tests fail against the {subject}, so the "
            "mutation changed the computation rather than only its observable "
            f"behavior:\n{result.stdout}{result.stderr}"
        )
    missing = [name for name in ORACLE_TESTS if name not in result.stdout]
    if missing:
        fail(
            f"the independent-oracle tests did not run against the {subject}: "
            f"{missing} absent from the test output. A mutation cannot be "
            "accepted on the strength of the inline unit tests alone"
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


def check_unified(manifest, contract, policy_path):
    """Runs the *unified* enforcement command over one staged adapter.

    M10's acceptance experiment C: declare the mutated operation a security
    contract requiring both generated and symbolic analysis, and require one
    command to exit 1 when either backend establishes a leak -- with both
    analyses preserved in the report rather than the first failure ending the
    run.

    Returns `(exit_code, contract_row)`. The exit code is the point, so it is
    returned rather than asserted on here: a leak must outrank an incomplete
    analysis, and only the caller knows which it expected.
    """
    command = [
        "cargo",
        "run",
        "--release",
        "--quiet",
        "-p",
        "cargo-trace-check",
        "--",
        "check",
        "--all-contracts",
        "--ci",
        "--config",
        str(policy_path),
        "--manifest-path",
        str(manifest),
        "--format",
        "json",
    ]
    result = run(command, cwd=REPO)
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail(f"the unified checker produced no report:\n{result.stdout}\n{result.stderr}")
    rows = [row for row in report.get("contracts", []) if row["id"] == contract]
    if not rows:
        fail(f"the unified report does not mention {contract}")
    return result.returncode, rows[0], report


def unified_policy(work, contract, base_config):
    """Writes the staged adapter's configuration with a unified policy on top.

    Overlaid rather than replacing it: the `[check]` and `[verify]` entries the
    audit already carries are what make both backends runnable, and rewriting
    them would make this experiment test a different configuration from the one
    the project ships.

    Every *other* contract is given a requirement this build cannot satisfy, so
    the run schedules only the contract under test. Eighteen generated checks
    and three symbolic verifications to observe one mutation would be a slow
    way to learn nothing extra -- and the contracts are all `dynamic = false`,
    so `dynamic` settles as UNSUPPORTED without running anything.
    """
    text = base_config.read_text()
    text += (
        "\n[policy]\nmode = \"strict\"\n"
        "default_required = [\"dynamic\"]\n\n"
        f'[policy.contracts."{contract}"]\n'
        'required = ["generated", "symbolic"]\n'
        'observations = ["control-flow", "memory-access"]\n'
    )
    path = work / "unified-trace-check.toml"
    path.write_text(text)
    return path


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


def require_unified(run, expect_outcome, expect_exit):
    """Holds a unified run to the outcome, the exit code, and both analyses.

    The exit code is checked separately from the outcomes because it encodes a
    priority the outcomes do not: a detected leak must outrank an incomplete
    analysis, so a run where one backend found a leak and the other was
    inconclusive still exits 1.
    """
    row = run.unified_row
    by_analysis = {item["analysis"]: item for item in row.get("evidence", [])}
    outcomes = {name: item["outcome"] for name, item in by_analysis.items()}
    if expect_outcome not in outcomes.values():
        fail(
            f"[mutated] no backend reported {expect_outcome}; the unified run saw {outcomes}"
        )
    # Every analysis that reported is still in the report: a backend failing
    # must not discard what another established.
    for analysis in ("generated", "symbolic"):
        if analysis not in by_analysis:
            fail(f"[mutated] {analysis} evidence is missing from the report")
    states = {name: value["state"] for name, value in (row.get("status") or {}).items()}
    if expect_outcome == "LEAK_DETECTED" and "leak-detected" not in states.values():
        fail(
            f"[mutated] a leak was reported as evidence but no requirement is "
            f"leak-detected: {states}"
        )
    if expect_exit is not None and run.unified_exit != expect_exit:
        fail(
            f"[mutated] the unified run exited {run.unified_exit}, expected {expect_exit}. "
            "A detected leak must outrank an incomplete analysis"
        )
    print(f"[mutated] statuses:    {states}")
    print(f"[mutated] both analyses preserved, exit {run.unified_exit}")


class Run:
    """One staged experiment's results, so callers compare like with like."""

    def __init__(
        self,
        artifact,
        evidence,
        manifest,
        reproducer_dir,
        graph_digest,
        unified_exit=None,
        unified_row=None,
    ):
        self.artifact = artifact
        self.evidence = evidence
        self.manifest = manifest
        self.reproducer_dir = reproducer_dir
        self.graph_digest = graph_digest
        # Set only by a `--unified` run: the process exit code, and the
        # contract's whole row so a caller can inspect both analyses.
        self.unified_exit = unified_exit
        self.unified_row = unified_row


def experiment(work, source, patch, contract, label, reproducers=False, unified=False):
    """Stages one dependency tree, checks one contract, returns the evidence."""
    dependency, before, after = stage_dependency(work, source, patch)
    print(f"[{label}] staged:      {dependency}")
    print(f"[{label}] tree sha256: {before} -> {after}")
    if patch:
        print(f"[{label}] mutation:    {patch.name}")

    adapter = stage_adapter(work, dependency)
    graph, graph_digest = dependency_graph(adapter)
    print(f"[{label}] graph:       {len(graph)} package(s), sha256 {graph_digest[:12]}")
    functional_tests(adapter, mutated=patch is not None)
    print(
        f"[{label}] functional:  inline tests and the 1012 oracle vectors pass "
        "against the staged dependency"
    )

    if unified:
        policy = unified_policy(work, contract, adapter / "trace-check.toml")
        code, row, _report = check_unified(adapter / "Cargo.toml", contract, policy)
        by_analysis = {item["analysis"]: item for item in row.get("evidence", [])}
        # Both analyses must be present. A run that stopped at the first
        # failure would report one and leave the other un-analyzed, which is
        # the behaviour M10 forbids by default.
        for analysis in ("generated", "symbolic"):
            if analysis not in by_analysis:
                fail(
                    f"[{label}] the unified run produced no {analysis} evidence, so a backend "
                    f"was skipped: {sorted(by_analysis)}"
                )
            print(
                f"[{label}] {analysis}: {by_analysis[analysis]['outcome']} in "
                f"{by_analysis[analysis]['artifact_sha256'][:12]}"
            )
        if by_analysis["generated"]["artifact_sha256"] == by_analysis["symbolic"]["artifact_sha256"]:
            fail(f"[{label}] both analyses report one artifact, so one of them is misattributed")
        print(f"[{label}] exit code:   {code}")
        return Run(
            artifact=by_analysis["generated"]["artifact_sha256"],
            evidence=by_analysis["generated"].get("check") or by_analysis["generated"],
            manifest=adapter / "Cargo.toml",
            reproducer_dir=None,
            graph_digest=graph_digest,
            unified_exit=code,
            unified_row=row,
        )

    reproducer_dir = work / "reproducers" if reproducers else None
    reported = check_contract(adapter / "Cargo.toml", contract, reproducer_dir)
    evidence = reported["check"]
    print(f"[{label}] artifact:    {reported['artifact_sha256']}")
    print(f"[{label}] outcome:     {evidence['outcome']}")
    print(f"[{label}] message:     {evidence['message']}")
    return Run(
        artifact=reported["artifact_sha256"],
        evidence=evidence,
        manifest=adapter / "Cargo.toml",
        reproducer_dir=reproducer_dir,
        graph_digest=graph_digest,
    )


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
    parser.add_argument(
        "--unified",
        action="store_true",
        help=(
            "run the mutation through `check --all-contracts --ci` with a policy requiring "
            "both generated and symbolic analysis, instead of the standalone check"
        ),
    )
    parser.add_argument(
        "--expect-exit",
        type=int,
        help="exit code the unified run must produce (1 for a detected leak)",
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
            baseline = experiment(
                root / "clean", source, None, arguments.contract, "clean"
            )
            require_outcome(baseline.evidence, arguments.expect_outcome, "clean")
            print("PASS")
            return

        baseline = None
        if arguments.compare_clean:
            # A separate staging directory per run: never a shared tree that
            # another build could be reading, and never a target directory the
            # two runs could trade cache entries through.
            baseline = experiment(
                root / "clean", source, None, arguments.contract, "clean"
            )
            require_outcome(baseline.evidence, arguments.baseline_outcome, "clean")

        mutated = experiment(
            root / "mutated",
            source,
            patch,
            arguments.contract,
            "mutated",
            reproducers=arguments.verify_reproducer,
            unified=arguments.unified,
        )
        if arguments.unified:
            require_unified(mutated, arguments.expect_outcome, arguments.expect_exit)
            print("PASS")
            return
        require_outcome(mutated.evidence, arguments.expect_outcome, "mutated")
        if arguments.expect_class:
            require_class(mutated.evidence, arguments.expect_class, "mutated")
        if arguments.expect_frame:
            require_frame(mutated.evidence, arguments.expect_frame, "mutated")
        if arguments.verify_reproducer:
            replay_reproducer(mutated.manifest, mutated.reproducer_dir, "mutated")

        if baseline is not None:
            if baseline.artifact == mutated.artifact:
                fail(
                    "the clean and mutated runs analyzed the same artifact hash, so "
                    "the mutated build was not actually analyzed"
                )
            # The *dependency graph* must be identical where the artifact must
            # differ: the patch is meant to be the only variable.
            if baseline.graph_digest != mutated.graph_digest:
                fail(
                    "the clean and mutated runs resolved different dependency "
                    f"graphs ({baseline.graph_digest[:12]} against "
                    f"{mutated.graph_digest[:12]}), so the comparison is not "
                    "controlled"
                )
            print(f"artifacts:    {baseline.artifact[:12]} != {mutated.artifact[:12]}")
            print(f"graphs:       {baseline.graph_digest[:12]} == identical")

        print("PASS")
    finally:
        if context:
            context.cleanup()


if __name__ == "__main__":
    main()
