#[trace_check_test::constant_time(secret = "expected")]
pub fn verify_tag(expected: &[u8; 16], supplied: &[u8; 16]) -> bool {
    use subtle::ConstantTimeEq;
    expected.ct_eq(supplied).unwrap_u8() == 1
}

#[trace_check_test::constant_time(secret = "index")]
pub fn lookup(index: u8) -> u8 {
    static TABLE: [u8; 16] = [0x5a; 16];
    // SAFETY: the mask keeps the index within this table.
    unsafe { std::ptr::read_volatile(&TABLE[(index & 15) as usize]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A declassified comparison result can be asserted on without leaking in the test.
    #[trace_check_test::ct_test(target = "verify_tag")]
    fn rejects_mismatch() {
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert!(!super::verify_tag_ct(expected, &[0u8; 16]));
    }
}
