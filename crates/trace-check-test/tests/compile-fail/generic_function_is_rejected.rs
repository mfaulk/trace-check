//! A generic function's compiled code depends on its instantiation, so a
//! contract on the generic definition would not describe any single artifact.

#[trace_check_test::constant_time(secret = "value")]
pub fn verify<T: PartialEq>(value: &T, other: &T) -> bool {
    value == other
}

fn main() {}
