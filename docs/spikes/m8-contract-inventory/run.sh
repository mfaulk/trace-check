#!/usr/bin/env bash
# M8.1 feasibility spike. Reproduces the results recorded in README.md.
#
#   ./run.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="${TMPDIR:-/tmp}/tc-spike-inventory"
mkdir -p "$work"
export SPIKE_DIR="$here"

# `--target-dir` is passed explicitly and CARGO_TARGET_DIR unset, so a shared
# build cache in the environment cannot silently become the artifact under
# measurement.
build() {
    local out="$1"
    shift
    ( cd "$here" && env -u CARGO_TARGET_DIR cargo build --target-dir "$out" -q "$@" )
}

read_inventory() {
    python3 "$here/read.py" "$1"
}

# Object members of an archive, to show records survive being split across
# codegen units.
objects() {
    python3 "$here/count_objects.py" "$1"
}

echo "== What a declaration emits =="
echo "  section:  .trace_check.contracts"
echo "  framing:  magic(8) | schema(u16 LE) | length(u32 LE) | payload(length)"
echo

echo "== Release profile, default features =="
build "$work/release" --release
read_inventory "$work/release/release/libspike.rlib"
echo "  object files in the archive: $(objects "$work/release/release/libspike.rlib")"
echo

echo "== Debug profile =="
echo "  The case that exposed the extraction bug: rustc puts several same-named"
echo "  sections in one object, and llvm-objcopy --dump-section returns only the"
echo "  first of them."
build "$work/debug"
read_inventory "$work/debug/debug/libspike.rlib"
echo "  object files in the archive: $(objects "$work/debug/debug/libspike.rlib")"
echo

echo "== A feature-gated declaration follows the selected compilation =="
if read_inventory "$work/release/release/libspike.rlib" | grep -q 'gated::fast'; then
    echo "  FAIL: an inactive declaration was inventoried"
    exit 1
fi
echo "  inactive: spike::gated::fast is absent without --features fast"
build "$work/fast" --release --features fast
if ! read_inventory "$work/fast/release/libspike.rlib" | grep -q 'gated::fast'; then
    echo "  FAIL: an active declaration was not inventoried"
    exit 1
fi
echo "  active:   spike::gated::fast appears with --features fast"
echo

echo "== A library with no declarations =="
echo "  A valid empty inventory, not a parse failure."
( cd "$here/empty" && env -u CARGO_TARGET_DIR cargo build --release \
    --target-dir "$work/empty" -q )
read_inventory "$work/empty/release/libempty.rlib"
echo

echo "== Malformed and future records are refused =="
python3 "$here/refuse.py"
