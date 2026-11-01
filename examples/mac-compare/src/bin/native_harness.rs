//! Native harness for the M1 tag-comparison verifiers, reused unchanged.
//!
//! The same three functions M1 traces in WASM are analyzed here as native
//! x86-64, which is what makes the two backends comparable. Every case holds
//! the public supplied tag fixed and rejects, so a finding cannot be confounded
//! with an accept-versus-reject difference.

use std::hint::black_box;

use mac_compare::{verify_constant_time, verify_early_exit, verify_early_exit_opaque, TAG_LEN};
use trace_check_secret::{declassify, run_mode, Secret};

/// Synthetic expected tag mismatching at the last byte, matching M1's case B.
fn secret_expected_tag() -> [u8; TAG_LEN] {
    let mut tag = [0u8; TAG_LEN];
    tag[TAG_LEN - 1] = 1;
    tag
}

fn main() {
    let case = std::env::args().nth(1).unwrap_or_default();
    println!("trace-check-harness: run_mode={} case={case}", run_mode());

    let verifier: fn(&[u8; TAG_LEN], &[u8; TAG_LEN]) -> bool = match case.as_str() {
        "early_exit" => verify_early_exit,
        "early_exit_opaque" => verify_early_exit_opaque,
        "constant_time" => verify_constant_time,
        other => {
            eprintln!("unknown case {other:?}");
            std::process::exit(64);
        }
    };

    let supplied = [0u8; TAG_LEN];
    let expected = secret_expected_tag();

    let guard = Secret::new(&expected);
    let accepted = black_box(verifier(black_box(&expected), black_box(&supplied)));
    guard.declassify_now();
    // The decision is secret-derived; declassify before printing or asserting.
    declassify(&accepted);

    // Every case must reject. Asserting here keeps a wrong decision from being
    // reported as a clean security result.
    assert!(!accepted, "case {case} must reject the supplied tag");
    println!("accepted={}", accepted as u8);
}
