//! Compile-fail tests: the API must reject what it cannot soundly support.
//!
//! These matter more than usual here. A secret representation that compiles but
//! is not actually marked would report `NO_LEAK_OBSERVED` for unanalyzed data,
//! and a contract naming a parameter that does not exist would claim coverage
//! it does not have. Both must be compile errors, not runtime surprises.

/// Unsupported secret types and invalid annotations are rejected at compile
/// time rather than silently accepted.
#[test]
fn unsupported_inputs_are_rejected() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile-fail/*.rs");
}
