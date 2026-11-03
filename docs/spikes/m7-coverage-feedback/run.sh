#!/usr/bin/env bash
# M7.1 feasibility spike. Reproduces the measurements recorded in README.md.
#
#   ./run.sh experiment-a     # per-input coverage from the real library
#   ./run.sh experiment-b     # per-input cost, three approaches
#   ./run.sh experiment-c     # feedback quality on three fixtures
#   ./run.sh all
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="${TMPDIR:-/tmp}/tc-spike-coverage"
# `--target-dir` is passed explicitly and CARGO_TARGET_DIR unset, so a shared
# build cache in the environment cannot silently become the artifact under
# measurement.
target="$work/target"
llvm="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin"

if [[ ! -x "$llvm/llvm-profdata" || ! -x "$llvm/llvm-cov" ]]; then
    echo "need the llvm-tools component from the pinned toolchain:" >&2
    echo "  rustup component add llvm-tools" >&2
    exit 1
fi

mkdir -p "$work"
build() {
    # The harness calls __llvm_profile_* directly, so this build does not link
    # without instrumentation. That is deliberate: see README.md.
    ( cd "$here" && env -u CARGO_TARGET_DIR RUSTFLAGS="-C instrument-coverage" \
        cargo build --release --target-dir "$target" -q )
}
bin="$target/release/tc-spike-coverage"

# Prints the library-only covered region set for each of N per-case profiles.
decode() {
    local dir="$1" count="$2"
    python3 - "$llvm" "$bin" "$dir" "$count" <<'PY'
import json, subprocess, sys
llvm, binary, directory, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])

def regions(index):
    raw = f"{directory}/case-{index}.profraw"
    data = f"{directory}/case-{index}.profdata"
    subprocess.run([f"{llvm}/llvm-profdata", "merge", "-sparse", "-o", data, raw], check=True)
    exported = subprocess.run(
        [f"{llvm}/llvm-cov", "export", "--instr-profile", data, binary],
        check=True, capture_output=True,
    )
    covered = set()
    for export in json.loads(exported.stdout)["data"]:
        for function in export.get("functions", []):
            for region in function["regions"]:
                name = function["filenames"][region[5]]
                # Only the developer's library counts as target coverage;
                # harness and std regions are excluded by file identity.
                if "crypto-library" not in name:
                    continue
                if region[4] > 0:
                    covered.add((name.split("/")[-1], *region[0:4], region[7]))
    return frozenset(covered)

sets = [regions(index) for index in range(count)]
distinct = {}
for index, covered in enumerate(sets):
    distinct.setdefault(covered, []).append(index)
print(f"  {count} input(s) -> {len(distinct)} distinct coverage set(s)")
seen = set()
for index, covered in enumerate(sets):
    fresh = covered - seen
    seen |= covered
    print(f"    case {index:3d}: {len(covered):3d} region(s), {len(fresh):3d} new")
PY
}

experiment_a() {
    echo "== Experiment A: per-input coverage from the real library function =="
    build
    local dir="$work/a"; rm -rf "$dir"; mkdir -p "$dir"
    # The nested_modes predicate ladder: 0, 1, 2 and 3 conjuncts satisfied.
    printf '0 0 0 7\n10 0 0 7\n10 48 0 7\n10 48 90 7\n' > "$work/ladder.txt"
    "$bin" persistent "$dir" "$work/ladder.txt" > /dev/null
    echo "  per-case profile sizes (every file must hold exactly one record):"
    ls -l "$dir"/case-*.profraw | awk '{print "    "$5, $9}'
    decode "$dir" 4
    echo "  A5 -- a profile offered against the wrong executable:"
    "$llvm/llvm-cov" export --instr-profile="$dir/case-0.profdata" /bin/true 2>&1 | sed 's/^/    /' || true
    echo "  A5 -- a truncated profile:"
    head -c 400 "$dir/case-0.profraw" > "$dir/bad.profraw"
    "$llvm/llvm-profdata" merge -sparse -o "$dir/bad.profdata" "$dir/bad.profraw" 2>&1 | sed 's/^/    /' || true
}

experiment_b() {
    echo "== Experiment B: per-input feedback cost =="
    build
    local count=512
    python3 -c "
import random
random.seed(11)
print('\n'.join(' '.join(str(random.randrange(256)) for _ in range(4)) for _ in range($count)))
" > "$work/cases.txt"

    echo "  approach 1 -- one process and one profile per input:"
    local dir1="$work/b1"; rm -rf "$dir1"; mkdir -p "$dir1"
    /usr/bin/time -f "    execute: %e s" bash -c '
        index=0
        while read -r a b c d; do
            LLVM_PROFILE_FILE="'"$dir1"'/case-$index.profraw" "'"$bin"'" once "$a" "$b" "$c" "$d" > /dev/null
            index=$((index + 1))
        done < "'"$work"'/cases.txt"' 2>&1 | tail -1

    echo "  approach 2 -- one persistent process, counters reset between inputs:"
    local dir2="$work/b2"; rm -rf "$dir2"; mkdir -p "$dir2"
    /usr/bin/time -f "    execute: %e s" "$bin" persistent "$dir2" "$work/cases.txt" \
        2>&1 > /dev/null | tail -1

    echo "  decode (shared by both approaches):"
    /usr/bin/time -f "    serial:        %e s" bash -c '
        for index in $(seq 0 '"$((count - 1))"'); do
            "'"$llvm"'/llvm-profdata" merge -sparse -o "'"$dir2"'/s$index.profdata" "'"$dir2"'/case-$index.profraw"
            "'"$llvm"'/llvm-cov" export --instr-profile="'"$dir2"'/s$index.profdata" "'"$bin"'" > /dev/null
        done' 2>&1 | tail -1
    /usr/bin/time -f "    16-way parallel: %e s" bash -c '
        seq 0 '"$((count - 1))"' | xargs -P 16 -I{} sh -c \
          "\"'"$llvm"'/llvm-profdata\" merge -sparse -o \"'"$dir2"'/p{}.profdata\" \"'"$dir2"'/case-{}.profraw\" && \
           \"'"$llvm"'/llvm-cov\" export --instr-profile=\"'"$dir2"'/p{}.profdata\" \"'"$bin"'\" > /dev/null"' 2>&1 | tail -1

    echo "  approach 3 -- SanitizerCoverage / libFuzzer on the pinned toolchain:"
    echo 'fn main() {}' > "$work/probe.rs"
    rustc -Zsanitizer-coverage-trace-pc-guard -O "$work/probe.rs" -o "$work/probe" 2>&1 |
        head -1 | sed 's/^/    /' || true

    echo "  build cost:"
    rm -rf "$work/cold"
    /usr/bin/time -f "    cold instrumented build: %e s" bash -c \
        "cd '$here' && env -u CARGO_TARGET_DIR RUSTFLAGS='-C instrument-coverage' cargo build --release --target-dir '$work/cold' -q" 2>&1 | tail -1
    touch "$here/src/main.rs"
    /usr/bin/time -f "    warm instrumented build: %e s" bash -c \
        "cd '$here' && env -u CARGO_TARGET_DIR RUSTFLAGS='-C instrument-coverage' cargo build --release --target-dir '$work/cold' -q" 2>&1 | tail -1
    echo "    without instrumentation the harness does not link:"
    ( cd "$here" && env -u CARGO_TARGET_DIR cargo build --release --target-dir "$work/plain" 2>&1 |
        grep -i 'undefined symbol' | head -3 | sed 's/^/      /' ) || true
}

experiment_c() {
    echo "== Experiment C: feedback quality =="
    build
    echo "  C1 -- public-branch exploration (substitute_mode, mode = 0,1,2,3,255):"
    local c1="$work/c1"; rm -rf "$c1"; mkdir -p "$c1"
    printf '0 7\n1 7\n2 7\n3 7\n255 7\n' > "$work/c1.txt"
    "$bin" mode "$c1" "$work/c1.txt" > /dev/null
    decode "$c1" 5

    echo "  C2 -- nested public predicates (the ladder, repeated from A)"
    echo "       see Experiment A: each additional conjunct adds new regions."

    echo "  C3 -- magic 32-bit equality (16 random tokens, then the magic one):"
    local c3="$work/c3"; rm -rf "$c3"; mkdir -p "$c3"
    python3 -c "
import random
random.seed(3)
for _ in range(16):
    print(random.randrange(2 ** 32), 7)
print(0x5a17c0de, 7)
" > "$work/c3.txt"
    "$bin" magic "$c3" "$work/c3.txt" > /dev/null
    decode "$c3" 17
}

case "${1:-all}" in
    experiment-a) experiment_a ;;
    experiment-b) experiment_b ;;
    experiment-c) experiment_c ;;
    all) experiment_a; echo; experiment_b; echo; experiment_c ;;
    *) echo "usage: $0 experiment-a|experiment-b|experiment-c|all" >&2; exit 2 ;;
esac
