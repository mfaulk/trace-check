//! Audit adapters for `kyberlib` 0.0.11, ML-KEM-768.
//!
//! The second discovery target. Everything structural is deliberately the same
//! as the `ml-kem` audit next door — the secret is a 64-byte key-generation
//! seed, key generation runs on a declassified copy of it, and only the secret
//! components of the derived key are re-marked for the decapsulation — because
//! the point of a second target is to vary the *implementation* and nothing
//! else.
//!
//! ```sh
//! cargo trace-check check --all-configured --ci \
//!   --manifest-path examples/kyberlib-audit/Cargo.toml
//! ```
//!
//! Two differences from the `ml-kem` adapters, both forced by the library:
//!
//! * deterministic key generation is only available through `kyberlib::derive`,
//!   which belongs to the blob API the crate soft-deprecated in 0.0.7 in favour
//!   of its typed `MlKem768DecapKey`. The typed API has no seed constructor, so
//!   the adapter derives through the deprecated function and decapsulates
//!   through the typed one;
//! * encapsulation takes an RNG rather than explicit randomness, so
//!   [`fixture::FixedRng`] supplies the public `m` and the audit keeps
//!   deterministic ciphertexts.

pub mod controls;
pub mod decaps;
pub mod fixture;
pub mod seedlevel;
pub mod sink;
