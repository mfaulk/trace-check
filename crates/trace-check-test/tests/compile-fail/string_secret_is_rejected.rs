//! A `String` is heap-indirect for the same reason a `Vec` is, so it is not a
//! supported secret representation.

fn consume(_text: &String) -> usize {
    0
}

fn main() {
    let secret = String::from("key");
    let _ = trace_check_test::assert_constant_time!(
        secret = secret,
        call = |value| consume(value),
    );
}
