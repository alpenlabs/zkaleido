//! # zkaleido-sp1-adapter
//!
//! This crate integrates the [SP1](https://docs.succinct.xyz/docs/introduction) zero-knowledge proof
//! framework with the zkVM environment provided by [zkaleido](https://github.com/novifinancial/zkaleido).
//! It enables both the generation of SP1 proofs and the verification of SP1-based Groth16
//! proofs within a zkVM context.
//!
//! ## Features
//!
//! - **`prover`**: Enables proof generation via the SP1 host and proof input builder.
//! - **`zkvm`**: Required for in the guest program to pass the input and commit the output.
//! - **`zkvm-recursion`**: Required if the guest program needs to recursively verify other proofs.
//!   Enable `zkvm-mock-recursion` for local development and testing.
//! - **`zkvm-mock-recursion`**: When enabled, the proof verification methods `verify_native_proof`
//!   become no-ops. This is useful for testing or local development where you don't need to run the
//!   actual cryptographic verification:
//! - **`perf`**: Enables reporting of performance metrics

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

#[cfg(feature = "prover")]
mod prover;
#[cfg(feature = "prover")]
mod verifier;
