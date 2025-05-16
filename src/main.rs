
// Example: secret-dependent branch (not constant-time)
fn check_secret(byte: u8) -> u8 {
    if byte == 0 {
        // Branch taken if secret byte is 0
        0
    } else {
        // Branch taken if secret byte is non-zero
        1
    }
}

fn main() {
    // Read secret value from command-line (for demonstration)
    let args: Vec<String> = std::env::args().collect();
    let secret = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0u8);
    let result = check_secret(secret);
    println!("Result: {}", result);
}
