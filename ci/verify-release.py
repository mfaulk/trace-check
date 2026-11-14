#!/usr/bin/env python3
"""Validate release archives and installed behavior without uploading any crates."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parent.parent
CRATES = (
    "trace-check-macros",
    "trace-check-secret",
    "trace-check-test",
    "trace-check",
    "cargo-trace-check",
)


def run(args, *, cwd=ROOT, env=None, expected=0):
    print("+ " + " ".join(map(str, args)), flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode != expected:
        raise RuntimeError(
            f"Expected exit {expected}, got {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    print(result.stdout, end="", flush=True)
    print(result.stderr, end="", flush=True)
    return result.stdout


def check_archive(path, destination, name, version):
    with tarfile.open(path) as archive:
        archive.extractall(destination, filter="data")
    package = destination / f"{name}-{version}"
    manifest = tomllib.loads((package / "Cargo.toml").read_text())
    metadata = manifest["package"]
    assert metadata["name"] == name
    assert metadata["version"] == version
    assert metadata["license"] == "MIT OR Apache-2.0"
    assert metadata["repository"] == "https://github.com/mfaulk/trace-check"
    supported_rust = "1.88" if name == "trace-check-macros" else "1.97"
    assert metadata["rust-version"] == supported_rust
    assert metadata["publish"] == ["crates-io"]
    assert (package / metadata["readme"]).is_file()
    for license_name in ("LICENSE-MIT", "LICENSE-APACHE"):
        assert (package / license_name).read_bytes() == (ROOT / license_name).read_bytes()
    for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
        for dependency, spec in manifest.get(kind, {}).items():
            assert "path" not in spec, (name, dependency, spec)
            if dependency in CRATES:
                assert spec["version"] == f"={version}", (name, dependency, spec)
    if name == "trace-check-secret":
        assert (package / "csrc/shim.c").is_file()
    assert path.stat().st_size < 10 * 1024 * 1024, "crate exceeds crates.io size limit"
    return package


def smoke_test(packages, work, version):
    cargo_home = work / "cargo-home"
    cargo_home.mkdir()
    existing_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    # Reuse downloaded dependencies without modifying the user's configuration.
    if (existing_home / "registry").exists():
        (cargo_home / "registry").symlink_to(existing_home / "registry", target_is_directory=True)
    patches = "[patch.crates-io]\n" + "".join(
        f"{name} = {{ path = {json.dumps(str(package))} }}\n"
        for name, package in packages.items()
    )
    (cargo_home / "config.toml").write_text(patches)
    env = dict(os.environ, CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(work / "target"))
    env.pop("TRACE_CHECK_TEST_PATH", None)
    installed = work / "installed"
    # Patches replace unpublished registry dependencies with extracted archives;
    # allow Cargo to update their lockfile sources during this staging install.
    run([
        "cargo", "install", "--path", str(packages["cargo-trace-check"]),
        "--root", str(installed),
    ], cwd=work, env=env)
    env["PATH"] = str(installed / "bin") + os.pathsep + env["PATH"]
    consumer = work / "consumer"
    (consumer / "src").mkdir(parents=True)
    (consumer / "Cargo.toml").write_text(
        '[package]\nname = "release-consumer"\nversion = "0.0.0"\nedition = "2021"\n'
        f'\n[dependencies]\ntrace-check-test = "={version}"\nsubtle = "2.6"\n'
    )
    shutil.copyfile(ROOT / "rust-toolchain.toml", consumer / "rust-toolchain.toml")
    fixture = packages["cargo-trace-check"] / "tests/fixtures/publish-consumer.rs"
    source = fixture.read_text()
    (consumer / "src/lib.rs").write_text(source)
    clean = run([
        "cargo", "trace-check", "check", "--contract", "release_consumer::verify_tag",
    ], cwd=consumer, env=env)
    assert "NO_LEAK_OBSERVED" in clean
    leak = run([
        "cargo", "trace-check", "check", "--contract", "release_consumer::lookup",
    ], cwd=consumer, env=env, expected=1)
    assert "LEAK_DETECTED" in leak
    run(["cargo", "trace-check", "check", "--all-contracts", "--ci"],
        cwd=consumer, env=env, expected=1)
    # Leave only the clean contract for successful CI and targeted-test checks.
    source = source.replace('#[trace_check_test::constant_time(secret = "index")]', "")
    (consumer / "src/lib.rs").write_text(source)
    run(["cargo", "trace-check", "check", "--all-contracts", "--ci"],
        cwd=consumer, env=env)
    run(["cargo", "trace-check", "test"], cwd=consumer, env=env)
    plain = run(["cargo", "test"], cwd=consumer, env=env)
    assert "ignored" in plain


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-dirty", action="store_true",
                        help="validate uncommitted changes during development")
    args = parser.parse_args()
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    version = manifest["workspace"]["package"]["version"]
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--no-deps", "--format-version", "1",
    ], cwd=ROOT, text=True))
    members = set(metadata["workspace_members"])
    publishable = {package["name"] for package in metadata["packages"]
                   if package["id"] in members and package["publish"] != []}
    assert publishable == set(CRATES), publishable
    # Package verification builds binaries too. Keep them out of the checkout's
    # target directory so concurrent tests never execute an extracted CLI build.
    target = Path(metadata["target_directory"]) / "release-validation"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    command = ["cargo", "publish", "--dry-run", "--workspace"]
    if args.allow_dirty:
        command.append("--allow-dirty")
    run(command, env=env)
    package = ["cargo", "package", "--no-verify"]
    for name in CRATES:
        package.extend(["--package", name])
    if args.allow_dirty:
        package.append("--allow-dirty")
    run(package, env=env)
    archives = target / "package"
    with tempfile.TemporaryDirectory(prefix="trace-check-release-") as temporary:
        work = Path(temporary)
        packages = {
            name: check_archive(archives / f"{name}-{version}.crate", work, name, version)
            for name in CRATES
        }
        smoke_test(packages, work, version)
    print("Release validation passed; no crates were uploaded.")


if __name__ == "__main__":
    main()
