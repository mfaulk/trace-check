//! Audit adapters for RustCrypto `ml-kem` 0.3.4, ML-KEM-768.
//!
//! Nothing here reimplements a cryptographic operation. Each adapter derives a
//! genuine key from a seed with the library's own `from_seed`, builds a
//! ciphertext with the library's own deterministic encapsulation, calls the
//! library's own `decapsulate`, and folds the whole shared key so the compiler
//! cannot discard it. The dependency is a pinned, unmodified crates.io release.
//!
//! ```sh
//! cargo trace-check check --all-contracts --ci \
//!   --manifest-path examples/ml-kem-audit/Cargo.toml
//! ```
//!
//! # Two classifications of the same key
//!
//! A decapsulation key is not uniformly secret: FIPS 203 packs `dk_pke ‖ ek ‖
//! H(ek) ‖ z`, and the middle two are public. So this crate carries both
//! encodings deliberately —
//!
//! * [`decaps`] marks only `dk_pke` and `z`, with key generation run on a
//!   declassified copy of the seed. Findings here are about protected data.
//! * [`seedlevel`] marks the seed and declassifies nothing. Findings here may
//!   be about `ρ`, which this encoding makes secret and the protocol does not.
//!
//! Neither is "the right one": the pair is the measurement.
//! [`controls::public_component_branch`] and
//! [`controls::public_component_branch_seed_level`] plant the same branch on the
//! same byte under each, and the audit's claims rest on those two disagreeing.
//!
//! # The analysis boundary
//!
//! A contract covers the whole adapter invocation: key derivation, ciphertext
//! construction, the library's decapsulation, and the fold. A finding is a
//! statement about one of those, and which one is a question for its source
//! attribution — `site` names the contract's own frame, so the stack is what
//! distinguishes an upstream finding from an adapter one.
//!
//! # The crate deliberately contains leaking functions
//!
//! Everything in [`controls`] exists to be detected, or to be *not* detected.
//! Without them a clean result on a real operation would be indistinguishable
//! from a boundary that declassified the key.

pub mod controls;
pub mod decaps;
pub mod fixture;
pub mod layout;
pub mod seedlevel;
pub mod sink;
