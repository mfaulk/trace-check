//! Audit adapters for RustCrypto `crypto-bigint`.
//!
//! Nothing here reimplements a cryptographic operation. Each adapter decodes
//! trace-check's supported input shapes into the library's own types, calls the
//! library's own function, and consumes the whole result so the compiler cannot
//! discard it. The dependency is a pinned, unmodified crates.io release.
//!
//! ```sh
//! cargo trace-check check --all-contracts --ci \
//!   --manifest-path examples/crypto-bigint-audit/Cargo.toml
//! ```
//!
//! # The analysis boundary
//!
//! A contract covers the **whole adapter invocation**: byte decoding, the
//! construction of the library's types, the library operation, and the result
//! consumption. A finding is therefore not automatically a statement about
//! upstream arithmetic — it is a statement about one of those four things, and
//! which one is a question for the finding's own source attribution.
//! `docs/audits/crypto-bigint/` records that distinction per finding.
//!
//! # The crate deliberately contains leaking functions
//!
//! Everything in [`controls`] exists to be detected, or to be *not* detected.
//! They are the evidence that declared secrets survive decoding into the
//! library's `Uint` representation; without them a clean result on a real
//! operation would be indistinguishable from a harness that marked nothing.
#![cfg_attr(not(test), no_std)]

pub mod add;
pub mod controls;
pub mod hidden;
pub mod monty;
pub mod select;
pub mod sink;
