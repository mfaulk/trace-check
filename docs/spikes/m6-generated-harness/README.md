# M6.1 feasibility spike — a generated-style dynamic harness

Recorded evidence for [`docs/MILESTONE-06.md`](../../MILESTONE-06.md). This is a
**spike**, not a maintained example: it is hand-written to stand in for what
M6.3 would generate, it is outside the workspace, and CI does not run it.

It answers one question — can a dynamic harness that links a developer's real
Cargo library find a leak that the library's own hand-written `#[ct_test]`
misses? — and it records the cost of doing so.

## What it does

`src/main.rs` takes the real `crypto::lookup` functions as an ordinary path
dependency and, per case: decodes runtime inputs, launders and marks the
declared secret, calls the **real** function with the declared positional
argument mapping, drops the marking, declassifies the result, and prints a
completion marker. It contains no copy of the library's algorithm.

Inputs arrive through `argv` on purpose. A compile-time constant would let the
optimizer pass an immediate and never read the marked storage — the false
negative `trace_check_test::analyze1` documents.

## Running it

Needs Valgrind with its client-request headers (so `trace-check-secret` builds
its shim) on `x86_64-unknown-linux-gnu`.

```sh
./run.sh <target> <call-form> <index>:<mode> [<index>:<mode> ...]
```

* `target` — `substitute_mode`, `substitute`, or `substitute_indexed`
* `call-form` — `direct` (plain cross-crate call), `reified` (function pointer
  laundered through `black_box`), or `decoy` (the target-binding control:
  marks a different byte and passes the real index **unmarked**)

```sh
./run.sh substitute_mode direct 42:0    # safe public mode: calibration only
./run.sh substitute_mode direct 42:1    # leaky public mode: finding in the library
./run.sh substitute_indexed decoy 42:0  # control: calibration fires, target does not
```

`run.sh` invokes Memcheck with the same flags `trace_check::native::
shared_valgrind_args` uses and summarizes the XML: one line per error with its
kind, origin sentence, and primary-stack frames.

It reads the binary's path from Cargo's JSON output rather than constructing
`target/release/<name>`, because `CARGO_TARGET_DIR` may be set — the same hazard
already handled in `native.rs` and `harness.rs`.

## Results

See [Phase A results](../../MILESTONE-06.md#4-phase-a--feasibility-spike-results)
in the milestone document. Summary: the leak behind `mode = 1` is found, the
constant-time scan produces no false finding, attribution survives the direct
cross-crate call, and batching is ~100x faster per case but cannot attribute a
finding to an input.
