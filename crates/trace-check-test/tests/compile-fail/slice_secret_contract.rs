//! A declared secret must be something the contract adapter can own.
//!
//! `&[u8]` has no owned form to mark, so a contract on it could not bind
//! marking to the parameter. The error points at the two supported routes.

#[trace_check_test::constant_time(secret = "key")]
pub fn verify(key: &[u8], supplied: &[u8]) -> bool {
    key == supplied
}

fn main() {}
