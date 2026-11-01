//! `secret = "..."` must name a real parameter. A typo would otherwise declare
//! a contract that covers nothing while appearing to cover something.

#[trace_check_test::constant_time(secret = "expceted")]
pub fn verify(expected: &[u8; 32], supplied: &[u8; 32]) -> bool {
    expected == supplied
}

fn main() {}
