//! Native harness for the table-lookup example and the instrumentation
//! controls.
//!
//! One case per invocation, so each Memcheck run has exactly one function under
//! test and findings attribute unambiguously. The harness prints a structured
//! `trace-check-harness:` line that the backend parses to confirm
//! instrumentation was actually active — a clean run with inert marking proves
//! nothing and must never be read as a pass.
//!
//! Every secret-derived result is declassified before printing. Skipping that
//! produces Memcheck findings inside `core::fmt` which belong to the harness,
//! not to the code under test.

use std::hint::black_box;

use table_lookup::{
    lookup_constant_time_scan, lookup_secret_index, permitted_arithmetic, synthetic_table,
};
use trace_check_secret::{declassify, run_mode, Secret};

/// Deterministic synthetic secret. Never a real key; see the project's
/// no-key-management constraint.
const SECRET_INDEX: u8 = 42;
const PUBLIC_BYTE: u8 = 0x11;

fn main() {
    let case = std::env::args().nth(1).unwrap_or_default();
    println!("trace-check-harness: run_mode={} case={case}", run_mode());

    match case.as_str() {
        "secret_index" => secret_index(),
        "constant_time_scan" => constant_time_scan(),
        "permitted_arithmetic" => permitted_arithmetic_case(),
        "declassified_output" => declassified_output(),
        "unmarked_secret" => unmarked_secret(),
        "genuine_memory_error" => genuine_memory_error(),
        "unrelated_undefined_value" => unrelated_undefined_value(),
        other => {
            eprintln!("unknown case {other:?}");
            std::process::exit(64);
        }
    }
}

/// Vulnerable: the secret becomes part of a load address.
fn secret_index() {
    let table = synthetic_table();
    let secret = SECRET_INDEX;
    let guard = Secret::new(&secret);
    let selected = black_box(lookup_secret_index(black_box(&table), black_box(secret)));
    guard.declassify_now();
    declassify(&selected);
    println!("selected={selected}");
}

/// Control: reads the whole table and selects with a mask.
fn constant_time_scan() {
    let table = synthetic_table();
    let secret = SECRET_INDEX;
    let guard = Secret::new(&secret);
    let selected = black_box(lookup_constant_time_scan(
        black_box(&table),
        black_box(secret),
    ));
    guard.declassify_now();
    declassify(&selected);
    println!("selected={selected}");
}

/// Control: the secret flows through arithmetic only, never into a branch or an
/// address. Propagating secrecy through computation is expected and permitted.
fn permitted_arithmetic_case() {
    let secret = SECRET_INDEX;
    let guard = Secret::new(&secret);
    let mixed = black_box(permitted_arithmetic(
        black_box(secret),
        black_box(PUBLIC_BYTE),
    ));
    guard.declassify_now();
    declassify(&mixed);
    println!("mixed={mixed}");
}

/// Control: a secret-derived value is declassified and then used in ordinary
/// branching and printing. There must be no finding, which is what proves
/// declassification works rather than merely being called.
fn declassified_output() {
    let secret = SECRET_INDEX;
    let guard = Secret::new(&secret);
    let derived = black_box(permitted_arithmetic(
        black_box(secret),
        black_box(PUBLIC_BYTE),
    ));
    guard.declassify_now();
    declassify(&derived);

    // Branching on the declassified value must be silent.
    let parity = if derived.is_multiple_of(2) {
        "even"
    } else {
        "odd"
    };
    println!("derived={derived} parity={parity}");
}

/// Instrumentation control: the same vulnerable call with **no** marking. Zero
/// findings here is what demonstrates that detection is caused by the marking
/// and not by something incidental in the binary.
fn unmarked_secret() {
    let table = synthetic_table();
    let selected = black_box(lookup_secret_index(
        black_box(&table),
        black_box(SECRET_INDEX),
    ));
    println!("selected={selected}");
}

/// Control: an ordinary uninitialized-variable bug, with no secret marked.
///
/// Memcheck reports `UninitCondition` here exactly as it does for a marked
/// secret, so error kind alone cannot tell the two apart. The origin can:
/// this value reports "created by a heap allocation" rather than "created by
/// a client request". The analysis must therefore classify it as an unrelated
/// undefined value and return INCONCLUSIVE, not LEAK_DETECTED.
fn unrelated_undefined_value() {
    use std::alloc::{alloc, dealloc, Layout};

    let layout = Layout::from_size_align(16, 1).expect("valid layout");
    // SAFETY: deliberately reads uninitialized heap memory to produce a
    // genuine UninitCondition. The allocation is non-zero-sized, the read is
    // in bounds, and the block is freed exactly once.
    let branched = unsafe {
        let pointer = alloc(layout);
        assert!(!pointer.is_null(), "allocation failed");
        // Volatile so the read is not elided.
        let uninitialized = core::ptr::read_volatile(pointer.add(4));
        let taken = if uninitialized > 128 { 1u8 } else { 0u8 };
        dealloc(pointer, layout);
        taken
    };
    println!("branched={}", black_box(branched));
}

/// A genuine memory error, unrelated to secrecy. The backend must report this
/// as a memory error and return INCONCLUSIVE, never classify it as a timing
/// leak.
///
/// Use-after-free through an explicit allocation, read with `read_volatile`.
///
/// Two earlier attempts failed and are worth recording. Reading past a small
/// `Vec` often lands inside another live block, so Memcheck reports nothing. A
/// plain dereference after `drop` is undefined behaviour, so LLVM elides the
/// load entirely and the access never happens. A volatile read of an
/// explicitly freed block cannot be elided, and Memcheck keeps freed blocks in
/// a quarantine, so the `InvalidRead` is deterministic.
fn genuine_memory_error() {
    use std::alloc::{alloc, dealloc, Layout};

    let layout = Layout::from_size_align(4, 1).expect("valid layout");
    // SAFETY: deliberately unsound — this case exists only to produce an
    // InvalidRead so the classifier can be shown to distinguish memory errors
    // from secret-dependency findings. The layout is non-zero-sized, the write
    // is in bounds, and the pointer is freed exactly once.
    let after_free = unsafe {
        let pointer = alloc(layout);
        assert!(!pointer.is_null(), "allocation failed");
        pointer.write(7);
        dealloc(pointer, layout);
        // Volatile so the read survives optimization.
        core::ptr::read_volatile(pointer)
    };
    println!("after_free={}", black_box(after_free));
}
