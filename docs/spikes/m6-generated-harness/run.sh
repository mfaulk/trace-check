#!/usr/bin/env bash
# Runs the spike harness under Memcheck with the same flags the existing native
# backend uses, then summarizes the XML: one line per error with its kind,
# origin sentence, and the first few primary-stack frames.
set -uo pipefail

SPIKE_DIR="$(cd "$(dirname "$0")" && pwd)"
# Read the artifact path from Cargo rather than constructing it: CARGO_TARGET_DIR
# is set on this machine, so `target/release/<name>` does not exist. The same
# hazard is already handled in native.rs and harness.rs.
BIN="$(cd "$SPIKE_DIR" && cargo build --release --message-format=json-render-diagnostics 2>/dev/null \
    | python3 -c "
import sys, json
path = None
for line in sys.stdin:
    try: m = json.loads(line)
    except Exception: continue
    if m.get('reason') == 'compiler-artifact' and m.get('executable'):
        path = m['executable']
print(path or '')
")"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "could not locate the spike binary" >&2
    exit 2
fi
XML="$(mktemp -d)/memcheck.xml"

start=$(date +%s.%N)
valgrind \
    --tool=memcheck \
    --track-origins=yes \
    --num-callers=24 \
    --leak-check=no \
    --errors-for-leak-kinds=none \
    --show-leak-kinds=none \
    --error-exitcode=42 \
    --xml=yes \
    --xml-file="$XML" \
    "$BIN" "$@" > "$XML.stdout" 2> "$XML.stderr"
code=$?
end=$(date +%s.%N)

echo "--- invocation: $* "
echo "exit=$code  wall=$(printf '%.2f' "$(echo "$end - $start" | bc)")s"
echo "--- harness stdout (markers only)"
grep -E "tc-spike-|trace-check-harness" "$XML.stdout" | head -40
echo "--- memcheck errors"
python3 - "$XML" <<'PY'
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
root = tree.getroot()
errors = root.findall('error')
print(f"total errors: {len(errors)}")
for i, err in enumerate(errors):
    kind = err.findtext('kind')
    what = err.findtext('what') or err.findtext('xwhat/text') or ''
    aux = [a.text or '' for a in err.findall('auxwhat')]
    stacks = err.findall('stack')
    frames = []
    if stacks:
        for f in stacks[0].findall('frame')[:4]:
            fn = f.findtext('fn') or '?'
            fl = f.findtext('file')
            ln = f.findtext('line')
            frames.append(f"{fn}" + (f" ({fl}:{ln})" if fl else ""))
    print(f"[{i}] kind={kind}")
    print(f"    what={what}")
    print(f"    origin={aux[0] if aux else '(none)'}")
    for fr in frames:
        print(f"    at {fr}")
state = root.findtext('status/state')
print(f"final status element present: {state is not None}")
PY
