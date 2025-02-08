//! # zkaleido-sp1-adapter
//!
//! This crate integrates the [SP1](https://docs.succinct.xyz/docs/introduction) zero-knowledge proof
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

#[cfg(feature = "prover")]
mod host;
#[cfg(feature = "prover")]
pub use host::SP1Host;

#[cfg(feature = "prover")]
mod input;
#[cfg(feature = "prover")]
mod proof;

#[cfg(feature = "zkvm")]
mod env;
#[cfg(feature = "zkvm")]
pub use env::Sp1ZkVmEnv;

mod groth16_verifier;
pub use groth16_verifier::*;

mod perf;
