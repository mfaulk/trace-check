//! A `Vec<u8>` must not be usable as a secret.
//!
//! Marking a `Vec`'s storage marks its pointer, length and capacity and not one
//! byte of the heap buffer. Accepting it would report "no leak" for data that
//! was never marked, so `MarkSecret` is deliberately not implemented for it.
//! The fix is `secret_bytes = vec.as_slice()`.

fn consume(_bytes: &Vec<u8>) -> bool {
    false
}

fn main() {
    let secret: Vec<u8> = vec![1, 2, 3];
    let _ = trace_check_test::assert_constant_time!(
        secret = secret,
        call = |value| consume(value),
    );
}
