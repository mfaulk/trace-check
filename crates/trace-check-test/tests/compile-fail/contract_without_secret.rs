//! A contract with no declared secret states nothing, so it is an error rather
//! than a vacuously satisfied annotation.

#[trace_check_test::constant_time]
pub fn verify(expected: &[u8; 32], supplied: &[u8; 32]) -> bool {
    expected == supplied
}

fn main() {}
