#!/usr/bin/env python3
"""Measures what unifying the backends costs, and what `--jobs` buys.

Four configurations over the same work -- eighteen generated checks and three
symbolic verifications of the `crypto-bigint` audit contracts:

1. **standalone**: `check --all-configured` then `verify --contract …` for the
   three symbolic contracts. The "coordinate it by hand" baseline M10 replaces.
2. **unified, one worker**: `check --all-contracts --ci --jobs 1`.
3. **unified, two workers**: the same at `--jobs 2`.
4. **dedup**: a contract requiring `generated` *and* `explore`, asserting the
   plan schedules one Memcheck workflow rather than two.

The same analyses in every row, deliberately. Comparing a unified run over
eighteen contracts against a standalone run over three would measure the
selection, not the orchestration.

# What is measured, and what is not

Wall clock and peak RSS come from the OS. Backend-invocation and distinct-
artifact counts come from the report itself, which is the only place that knows
what the run actually scheduled.

Per-phase timings -- inventory build, harness build, Memcheck execution, solver
time -- are **not** measured here. They would need the tool to instrument and
emit them, and inventing them from the outside by diffing wall clocks across
configurations would produce numbers that look precise and are not. The
milestone asks for them; this records that they are missing rather than
estimating them.

Usage:
  benchmark-m10.py [--warm-only] [--json out.json]
"""

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
ADAPTER = REPO / "examples/crypto-bigint-audit"
OVERLAY = REPO / "docs/spikes/m10-unified-verification/policy.toml"

# The contracts the committed overlay requires symbolic analysis of. Kept in
# step with the overlay rather than restated loosely: a standalone baseline that
# verified a different set would not be the same work.
SYMBOLIC = [
    "cbaudit::hidden::magic_gate",
    "cbaudit::hidden::nested_modes_wide",
    "cbaudit::monty::mul_both_secret",
]


def fail(message):
    print(f"benchmark-m10: {message}", file=sys.stderr)
    sys.exit(1)


def timed(command, cwd, env=None):
    """Runs a command, returning (seconds, peak RSS kB, exit code, stdout)."""
    start = time.monotonic()
    result = subprocess.run(
        ["/usr/bin/time", "-f", "%M", *command],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
    )
    elapsed = time.monotonic() - start
    # `/usr/bin/time -f %M` prints the peak RSS on the last line of stderr.
    rss = 0
    tail = result.stderr.strip().splitlines()
    if tail and re.fullmatch(r"\d+", tail[-1]):
        rss = int(tail[-1])
    return elapsed, rss, result.returncode, result.stdout


def cargo_release_binary():
    """Builds the CLI once, so no measurement includes building the tool."""
    built = subprocess.run(
        ["cargo", "build", "--release", "-p", "cargo-trace-check", "--message-format=json"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if built.returncode != 0:
        fail(f"could not build the CLI:\n{built.stderr[-2000:]}")
    for line in built.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("reason") == "compiler-artifact" and message.get("executable"):
            return message["executable"]
    fail("cargo reported no executable for cargo-trace-check")


def overlay_config(work):
    """The audit configuration plus the committed policy overlay."""
    text = (ADAPTER / "trace-check.toml").read_text() + "\n" + OVERLAY.read_text()
    path = work / "unified.toml"
    path.write_text(text)
    return path


def report_counts(stdout):
    """Backend invocations and distinct artifacts, from the report itself."""
    report = json.loads(stdout)
    execution = report.get("execution") or {}
    jobs = execution.get("jobs", [])
    artifacts = {
        item["artifact_sha256"]
        for row in report.get("contracts", [])
        for item in row.get("evidence", [])
    }
    return {
        "memcheck_jobs": sum(1 for job in jobs if job.get("backend") == "generated"),
        "symbolic_jobs": sum(1 for job in jobs if job.get("backend") == "symbolic"),
        "requirements": report.get("summary", {}).get("requirements"),
        "requirements_checked": report.get("summary", {}).get("requirements_checked"),
        "distinct_artifacts": len(artifacts),
        "ok": report.get("summary", {}).get("ok"),
    }


def run_unified(binary, config, jobs, cold_target=None):
    env = None
    if cold_target is not None:
        env = {**__import__("os").environ, "CARGO_TARGET_DIR": str(cold_target)}
    seconds, rss, code, stdout = timed(
        [
            binary,
            "trace-check",
            "check",
            "--all-contracts",
            "--ci",
            "--jobs",
            str(jobs),
            "--config",
            str(config),
            "--format",
            "json",
        ],
        cwd=ADAPTER,
        env=env,
    )
    if code != 0:
        fail(f"the unified run at --jobs {jobs} exited {code}")
    return seconds, rss, report_counts(stdout)


def run_standalone(binary, config):
    """`check --all-configured` plus `verify` for the symbolic contracts."""
    generated_s, generated_rss, code, _ = timed(
        [
            binary,
            "trace-check",
            "check",
            "--all-configured",
            "--config",
            str(config),
            "--format",
            "json",
        ],
        cwd=ADAPTER,
    )
    # The audit's controls are declared to leak, so a non-zero exit is the
    # expected result here and not a failure of the measurement.
    if code not in (0, 1):
        fail(f"the standalone check exited {code}")
    verify = [binary, "trace-check", "verify", "--format", "json"]
    for contract in SYMBOLIC:
        verify += ["--contract", contract]
    symbolic_s, symbolic_rss, code, _ = timed(verify, cwd=ADAPTER)
    if code not in (0, 1):
        fail(f"the standalone verify exited {code}")
    return generated_s + symbolic_s, max(generated_rss, symbolic_rss)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--warm-only",
        action="store_true",
        help="skip the cold-cache row, which dominates the measurement with compilation",
    )
    parser.add_argument("--json", help="also write the measurements here")
    arguments = parser.parse_args(argv)

    binary = cargo_release_binary()
    context = tempfile.TemporaryDirectory(prefix="m10-benchmark-")
    work = pathlib.Path(context.name)
    config = overlay_config(work)
    rows = {}

    try:
        # Warm every cache first, so no row pays for another's compilation.
        run_unified(binary, config, 1)

        standalone_s, standalone_rss = run_standalone(binary, config)
        rows["standalone"] = {"seconds": standalone_s, "rss_kb": standalone_rss}

        for jobs in (1, 2):
            seconds, rss, counts = run_unified(binary, config, jobs)
            rows[f"unified_jobs{jobs}"] = {
                "seconds": seconds,
                "rss_kb": rss,
                **counts,
            }

        if not arguments.warm_only:
            cold = work / "cold-target"
            seconds, rss, counts = run_unified(binary, config, 2, cold_target=cold)
            rows["unified_jobs2_cold"] = {"seconds": seconds, "rss_kb": rss, **counts}
            shutil.rmtree(cold, ignore_errors=True)
    finally:
        context.cleanup()

    one = rows["unified_jobs1"]
    two = rows["unified_jobs2"]
    base = rows["standalone"]

    print(f"{'configuration':<24} {'wall':>8} {'rss':>9}  invocations")
    print(f"{'-' * 24} {'-' * 8} {'-' * 9}  {'-' * 24}")
    print(
        f"{'standalone check+verify':<24} {base['seconds']:>7.1f}s "
        f"{base['rss_kb'] // 1024:>8}M  (not reported)"
    )
    for name in ("unified_jobs1", "unified_jobs2", "unified_jobs2_cold"):
        row = rows.get(name)
        if row is None:
            continue
        print(
            f"{name:<24} {row['seconds']:>7.1f}s {row['rss_kb'] // 1024:>8}M  "
            f"{row['memcheck_jobs']} memcheck, {row['symbolic_jobs']} symbolic, "
            f"{row['distinct_artifacts']} artifacts"
        )

    overhead = (one["seconds"] - base["seconds"]) / base["seconds"] * 100
    speedup = one["seconds"] / two["seconds"]
    print()
    print(f"orchestration overhead (unified 1 worker vs standalone): {overhead:+.1f}%")
    print(f"two workers against one:                                 {speedup:.2f}x")

    # The deduplication claim, read from the plan rather than from a stopwatch.
    # One Memcheck workflow per contract is the invariant; the overlay requires
    # `generated` and `explore` of one of them.
    problems = []
    if one["memcheck_jobs"] != 18:
        problems.append(
            f"18 contracts but {one['memcheck_jobs']} Memcheck workflows planned; requiring "
            "`generated` and `explore` must share one"
        )
    if one != {k: v for k, v in two.items() if k in one} and (
        one["memcheck_jobs"],
        one["symbolic_jobs"],
        one["requirements_checked"],
        one["ok"],
    ) != (
        two["memcheck_jobs"],
        two["symbolic_jobs"],
        two["requirements_checked"],
        two["ok"],
    ):
        problems.append("the two worker counts scheduled or satisfied different work")

    if arguments.json:
        pathlib.Path(arguments.json).write_text(json.dumps(rows, indent=2) + "\n")

    if problems:
        for problem in problems:
            print(f"benchmark-m10: {problem}", file=sys.stderr)
        return 1
    print("\nbenchmark-m10: the unified run schedules one Memcheck workflow per contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
