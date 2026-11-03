//! Two functions with the *same name* in different modules.
//!
//! An attribution control, not a vulnerability class. Coverage records and
//! Memcheck findings are both matched against a contract's identity, and a
//! match that ignored the module path would make these two indistinguishable:
//! one is a full-table scan and the other is a secret-indexed load, so
//! confusing them is the difference between a clean result and a leak.
//!
//! The pair is deliberately minimal and deliberately asymmetric. `left::probe`
//! is safe, `right::probe` leaks, and both are named `probe`.

pub mod left;
pub mod right;
