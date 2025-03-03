//! # zkaleido-sp1-adapter
//!
//! This crate integrates the [SP1](https://docs.succinct.xyz/docs/sp1/introduction) zero-knowledge proof
//! framework with the zkVM environment provided by [zkaleido](https://github.com/novifinancial/zkaleido).
//! It enables both the generation of SP1 proofs and the verification of SP1-based Groth16
//! proofs within a zkVM context.
//!
//! ## Features
//!
//! - **`prover`**: Enables proof generation via the RISC0 host and proof input builder. If you only
//!   need to perform verification, you can disable this feature.
//! - **`mock`**: When enabled, the proof verification methods (`verify_native_proof` and
//!   `verify_groth16_receipt`) become no-ops. This is useful for testing or local development where
//!   you don't need to run the actual cryptographic verification:

mod host;
pub use host::SP1Host;

mod input;
mod proof;

mod groth16_verifier;
pub use groth16_verifier::*;

#[cfg(feature = "perf")]
mod perf;

mod prover;
mod verifier;
