#!/usr/bin/env python3
"""Compares coverage-guided discovery against M6's generated inputs.

Measures the thing M7 claims to improve: *which* inputs get analyzed. The
security backend, the artifact profile and the controls are identical in every
configuration below; the only variable is how the corpus was chosen.

Run from the repository root:

    python3 ci/benchmark-m7.py

The primary metric is the milestone's detection efficiency -- distinct confirmed
leakage sites per second of end-to-end time -- reported alongside the proportion
of benchmark vulnerabilities found, because a fast strategy that finds only the
easy leaks would otherwise look best.

Numbers are wall-clock on one machine and are reported as measurements, not as a
claim about other hardware. Both cold and warm costs are reported: the cold
number includes compiling two artifacts, which dominates a first run and is
irrelevant to the hundredth.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIBRARY = ROOT / "examples" / "crypto-library"
CONFIG = LIBRARY / "trace-check.toml"

# One shared target directory, so a configuration is not charged for the
# previous one's build. An existing CARGO_TARGET_DIR is honored so CI can reuse
# the cache it already has.
ENV = dict(os.environ)
ENV.setdefault("CARGO_TARGET_DIR", str(ROOT / "target" / "benchmark-m7"))

# The benchmark corpus. `leaky` records what the fixture is for, so the
# proportion-found metric is about planted vulnerabilities rather than about
# however many findings happened to appear. `core` is the reduced set `--quick`
# uses, chosen to cover each distinct property exactly once.
#
# Case budgets are each fixture's boundary floor plus a little, not a round
# number: Valgrind dominates the wall clock, and a larger corpus measures more
# of the same thing. The floor is 1 + the sum over parameters of (boundary
# values - 1) -- 22 for a `u8`, 94 for a `u32`, 13 for an eight-byte array --
# and a smaller budget is *refused* rather than silently skipping the
# boundaries, so these numbers are not free to round down.
FIXTURES = [
    # (contract, cases, leaky, core, note)
    ("crypto::lookup::substitute_mode", 64, True, True, "leak behind a public mode"),
    ("crypto::hidden::nested_modes", 96, True, True, "leak behind three public predicates"),
    ("crypto::hidden::header_gate", 64, True, True, "leak behind three fields of one header"),
    ("crypto::hidden::nested_modes_clean", 96, False, True, "clean control, same nested shape"),
    ("crypto::hidden::magic_gate", 128, True, True, "leak behind an exact 32-bit equality"),
    ("crypto::hidden::threshold_window", 128, True, False, "leak in a window above a threshold"),
    ("crypto::hidden::secret_gated", 64, True, False, "leak reachable only for some secrets"),
    ("crypto::controls::tail_byte_probe", 64, True, False, "only the last secret byte leaks"),
    ("crypto::tag::verify_tag_volatile_early_exit", 64, True, False, "early exit surviving -O3"),
    ("crypto::controls::public_branch", 64, False, False, "clean control, public-only branch"),
    ("crypto::lookup::substitute", 64, False, False, "clean control, masked full-table scan"),
]

# The configurations compared. Each is the milestone's baseline list, with the
# *same* case budget per fixture so a difference is about input selection and
# not about how much was spent.
CONFIGURATIONS = [
    ("m6-boundaries", ["--no-explore"], ["boundaries"]),
    ("m6-default", ["--no-explore"], None),
    ("m6-random-10x", ["--no-explore"], ["random"]),
    ("m7-explore", ["--explore"], None),
]


def run(args, cwd=ROOT):
    started = time.monotonic()
    completed = subprocess.run(
        args, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=3600
    )
    return completed, time.monotonic() - started


def fixtures(quick):
    return [entry for entry in FIXTURES if entry[3]] if quick else FIXTURES


def temp_config(selected, strategies, multiplier):
    """Writes the configuration one benchmark configuration runs under.

    The `m6-random-10x` configuration is the milestone's "M6 with a larger
    random budget" baseline. It gets ten times the cases, which is a deliberate
    handicap in its favour: the point is that M7 wins against M6 given *more*
    budget, not against M6 given less.
    """
    scratch = ROOT / "target" / "benchmark-m7-config"
    scratch.mkdir(parents=True, exist_ok=True)
    path = scratch / f"trace-check-{'-'.join(strategies or ['default'])}-{multiplier}.toml"
    lines = ["schema_version = 1", ""]
    for contract, cases, _, _, _ in selected:
        lines.append(f'[check."{contract}"]')
        # Analyzer-regression fixtures declare an outcome, and a declared
        # outcome would turn "did not find it" into a configuration error
        # rather than a measurement. Every entry here is held to the property.
        lines.append(f"cases = {cases * multiplier}")
        if strategies is not None:
            listed = ", ".join(f'"{name}"' for name in strategies)
            lines.append(f"strategies = [{listed}]")
        lines.append("")
        lines.append(f'[check."{contract}".explore]')
        lines.append("enabled = true")
        lines.append("candidate_budget = 1500")
        lines.append("security_case_budget = 128")
        lines.append("")
    path.write_text("\n".join(lines))
    return path


def check(contract, config, flags):
    """Runs one contract under one configuration and returns (report, seconds)."""
    args = [
        "cargo",
        "run",
        "--quiet",
        "--release",
        "-p",
        "cargo-trace-check",
        "--",
        "check",
        "--manifest-path",
        str(LIBRARY / "Cargo.toml"),
        "--config",
        str(config),
        "--contract",
        contract,
        "--format",
        "json",
        *flags,
    ]
    completed, elapsed = run(args)
    try:
        return json.loads(completed.stdout), elapsed, completed
    except json.JSONDecodeError:
        return None, elapsed, completed


def sites(report):
    """Distinct confirmed leakage sites in a report.

    A site, not a finding count: Memcheck consolidates repeated diagnostics, so
    counting errors would measure batching rather than vulnerabilities. The
    fingerprint the check backend already computes -- classification plus the
    attributed function plus the source location -- is the right identity.
    """
    found = set()
    for entry in report.get("contracts", []):
        for finding in entry.get("check", {}).get("findings", []):
            fingerprint = finding.get("fingerprint", {})
            found.add(
                (
                    entry["contract"],
                    fingerprint.get("classification"),
                    fingerprint.get("function"),
                    fingerprint.get("location"),
                )
            )
    return found


def discovery(report):
    """The exploration section, when one is present."""
    for entry in report.get("contracts", []):
        if entry.get("discovery"):
            return entry["discovery"]
    return None


def measure(name, flags, strategies, multiplier, selected, warm):
    config = temp_config(selected, strategies, multiplier)
    total_seconds = 0.0
    found = set()
    detected_leaky = set()
    false_positives = []
    incomplete = []
    explored_ms = 0
    for contract, _, leaky, _, _ in selected:
        report, elapsed, completed = check(contract, config, flags)
        total_seconds += elapsed
        if report is None:
            # A configuration error here invalidates the comparison rather than
            # costing one data point: the fixture was not measured at all.
            incomplete.append(
                f"{contract}: no JSON report ({completed.stderr.strip()[:160]})"
            )
            continue
        found_here = sites(report)
        found |= found_here
        if found_here:
            if leaky:
                detected_leaky.add(contract)
            else:
                # A finding on a clean control is the failure that would make
                # the whole comparison worthless, so it is surfaced rather than
                # folded into a count.
                false_positives.append(contract)
        evidence = discovery(report)
        if evidence:
            explored_ms += evidence.get("elapsed_ms", 0)
            if not warm and evidence.get("failures"):
                incomplete.append(f"{contract}: {len(evidence['failures'])} unmeasured candidate(s)")
    leaky_total = sum(1 for entry in selected if entry[2])
    return {
        "name": name,
        "seconds": total_seconds,
        "sites": len(found),
        "site_keys": found,
        "vulnerabilities_found": len(detected_leaky),
        "vulnerabilities_total": leaky_total,
        "detected": detected_leaky,
        "false_positives": false_positives,
        "incomplete": incomplete,
        "explore_seconds": explored_ms / 1000.0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-cold",
        action="store_true",
        help="skip the cold measurement, which rebuilds both artifacts",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="use the reduced fixture set, which covers each property once. "
        "What CI runs: Valgrind dominates the wall clock and the full set is "
        "mostly more of the same measurement",
    )
    arguments = parser.parse_args()
    selected = fixtures(arguments.quick)

    print("M7 benchmark: coverage-guided discovery against M6 generated inputs")
    print(f"  target dir: {ENV['CARGO_TARGET_DIR']}")
    print(f"  fixtures:   {len(selected)} "
          f"({sum(1 for entry in selected if entry[2])} with planted leaks)"
          f"{' [reduced set]' if arguments.quick else ''}")
    print()

    # The tool itself is built once, so no configuration is charged for it.
    built, seconds = run(["cargo", "build", "--quiet", "--release", "-p", "cargo-trace-check"])
    if built.returncode != 0:
        print(built.stderr, file=sys.stderr)
        return 1
    print(f"built cargo-trace-check in {seconds:.1f} s")

    if not arguments.skip_cold:
        print("Cold run (M7, including both artifact builds per contract):")
        cold = measure("m7-explore-cold", ["--explore"], None, 1, selected, warm=False)
        print(f"  {cold['seconds']:.1f} s end to end, "
              f"{cold['explore_seconds']:.1f} s of it exploring")
        print()

    # One warming pass, not one per configuration. The artifacts depend on the
    # contract and not on the corpus, so a single M7 pass builds everything
    # every configuration below needs -- warming each of them separately was
    # doubling the benchmark's runtime for nothing.
    print("Warming (building both artifacts for each fixture)...", flush=True)
    measure("warm", ["--explore"], None, 1, selected, warm=True)

    print()
    print("Warm runs:", flush=True)
    results = []
    for name, flags, strategies in CONFIGURATIONS:
        multiplier = 10 if name == "m6-random-10x" else 1
        result = measure(name, flags, strategies, multiplier, selected, warm=True)
        results.append(result)
        efficiency = result["sites"] / result["seconds"] if result["seconds"] else 0.0
        print(f"  {name:16s} {result['seconds']:7.1f} s  "
              f"{result['sites']:2d} site(s)  "
              f"{result['vulnerabilities_found']}/{result['vulnerabilities_total']} fixture(s)  "
              f"{efficiency:.3f} site(s)/s", flush=True)
        if result["false_positives"]:
            print(f"      FALSE POSITIVE on {', '.join(result['false_positives'])}")
        for note in result["incomplete"]:
            print(f"      INCOMPLETE {note}")

    baseline = next(r for r in results if r["name"] == "m6-default")
    explored = next(r for r in results if r["name"] == "m7-explore")
    extra = explored["detected"] - baseline["detected"]

    print()
    print("Acceptance threshold (milestone section 12):")
    print(f"  M6 default found:   {sorted(baseline['detected'])}")
    print(f"  M7 found:           {sorted(explored['detected'])}")
    print(f"  additional:         {sorted(extra)} ({len(extra)})")
    lost = baseline["detected"] - explored["detected"]
    if lost:
        print(f"  REGRESSION: M7 lost {sorted(lost)}")
    met = (
        len(extra) >= 2
        and not lost
        and not explored["false_positives"]
        and not explored["incomplete"]
        and not baseline["incomplete"]
    )
    print(f"  threshold (>= 2 additional, none lost, no false positives, "
          f"nothing unmeasured): {'MET' if met else 'NOT MET'}")
    if explored["incomplete"] or baseline["incomplete"]:
        print("  a fixture was not measured, so the comparison is void, not merely weaker")
    print()
    print("Coverage is not a metric here. What is reported above is confirmed leakage")
    print("sites from the uninstrumented Memcheck artifact; the region counts in each")
    print("report describe a different build and verify nothing.")
    return 0 if met else 1


if __name__ == "__main__":
    sys.exit(main())
