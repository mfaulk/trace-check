# Changelog

## 0.1.0 — unreleased

- Declare constant-time contracts with Rust annotations and check them with a
  Cargo subcommand, generated inputs, or targeted security tests.
- Analyze secret-dependent branches and memory accesses under Valgrind Memcheck.
- Support bounded relational verification with BINSEC, static WebAssembly
  screening, and differential execution tracing.
- Enforce declared analysis requirements in CI and retain replayable findings.
- Include worked cryptographic audit adapters and documented analysis limits.

Release preparation adds registry-compatible packages and installed-CLI checks.
The initial release has not been published to crates.io.
